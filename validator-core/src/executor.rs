//! Block execution and transaction replay for stateless validation.
//!
//! This module provides the core execution logic for validating blocks in a stateless
//! manner. It handles EVM environment setup, transaction replay, and state change
//! computation that feeds into the broader validation pipeline.
//!
//! ## Key Functions
//!
//! - [`validate_block`]: Main validation entry point that orchestrates witness
//!   verification, transaction replay, and state root comparison
//! - [`create_evm_env`]: Creates EVM execution environment from block header and
//!   chain specification
//! - [`replay_block`]: Replays block transactions to compute state changes
//!
//! ## Validation Process
//!
//! 1. Verify witness proof against previous state root
//! 2. Create witness database for transaction execution
//! 3. Replay all transactions in the block using EVM
//! 4. Compute new state root from execution results
//! 5. Compare computed state root with claimed state root
//!
//! The module integrates with the Salt witness system for state reconstruction
//! and uses Revm for transaction execution.

use alloy_consensus::transaction::Recovered;
use alloy_evm::{
    EvmEnv, EvmFactory as AlloyEvmFactory,
    block::{BlockExecutor, BlockExecutorFactory as AlloyBlockExecutorFactory},
};
use alloy_network_primitives::TransactionResponse;
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use alloy_primitives::{BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, BlockTransactions, Header};
use mega_evm::{BlockExecutionCtx, BlockExecutorFactory, EvmFactory, SpecId};
use op_alloy_rpc_types::Transaction as OpTransaction;
use op_revm::L1BlockInfo;
use revm::{
    context::{BlockEnv, CfgEnv, ContextTr},
    database::states::StateBuilder,
    handler::EvmTr,
    primitives::{B256, KECCAK_EMPTY, U256},
    state::Bytecode,
};
use salt::{EphemeralSaltState, SaltWitness, StateRoot, Witness};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::SystemTime};
use thiserror::Error;

use crate::{
    chain_spec::{BLOB_GASPRICE_UPDATE_FRACTION, ChainSpec, MEGA_CHAIN_ID},
    data_types::{Account, PlainKey, PlainValue},
    database::WitnessDatabase,
};

/// Errors that can occur during block validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Witness proof verification failed: {0}")]
    WitnessVerificationFailed(#[source] salt::ProofError),

    #[error("Expecting full transaction data, only found hashes")]
    BlockIncomplete,

    #[error("Block replay failed during transaction execution: {0}")]
    BlockReplayFailed(#[source] alloy_evm::block::BlockExecutionError),

    #[error("Failed to update salt state: {0}")]
    StateUpdateFailed(#[source] salt::SaltError),

    #[error("Failed to update salt trie: {0}")]
    TrieUpdateFailed(#[source] salt::SaltError),

    #[error("Pre-state root mismatch: expecting {expected:?}, got {actual:?}")]
    PreStateRootMismatch {
        /// The post-state root of the parent block
        expected: B256,
        /// The pre-state root of the witness
        actual: B256,
    },

    #[error("State root mismatch: claimed {claimed}, got {actual}")]
    StateRootMismatch {
        /// The computed state root from transaction execution
        actual: B256,
        /// The claimed state root from the block header
        claimed: B256,
    },
}

/// Represents the result of a validation operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// The pre-state root from the witness before block execution
    pub pre_state_root: B256,
    /// The post-state root after block execution (from block header)
    pub post_state_root: B256,
    /// The block number that was validated
    pub block_number: BlockNumber,
    /// The block hash that was validated
    pub block_hash: BlockHash,
    /// Whether the validation was successful
    pub success: bool,
    /// Any error message if validation failed
    pub error_message: Option<String>,
    /// Timestamp when validation completed
    pub completed_at: SystemTime,
}

/// Creates an EVM execution environment from a block header and chain specification.
///
/// This function configures the EVM environment with the appropriate chain settings,
/// block parameters, and gas pricing for transaction execution.
///
/// # Arguments
///
/// * `header` - Block header containing execution parameters (number, timestamp, gas limits, etc.)
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
///
/// # Returns
///
/// Returns an `EvmEnv` configured for executing transactions in the given block context.
/// The environment includes:
/// - Chain configuration with appropriate spec ID for the block number
/// - Block environment with gas limits, timestamps, and fee parameters
/// - Blob gas pricing if excess blob gas is present in the header
fn create_evm_env(header: &Header, chain_spec: &ChainSpec) -> EvmEnv<SpecId> {
    let cfg_env = CfgEnv::new_with_spec(chain_spec.spec_id_at_timestamp(header.timestamp))
        .with_chain_id(MEGA_CHAIN_ID);

    let mut block_env = BlockEnv {
        number: U256::from(header.number),
        beneficiary: header.beneficiary,
        timestamp: U256::from(header.timestamp),
        gas_limit: header.gas_limit,
        basefee: header.base_fee_per_gas.unwrap_or_default(),
        difficulty: header.difficulty,
        prevrandao: Some(header.mix_hash),
        blob_excess_gas_and_price: None,
    };

    if let Some(excess_blob_gas) = header.excess_blob_gas {
        block_env.set_blob_excess_gas_and_price(excess_blob_gas, BLOB_GASPRICE_UPDATE_FRACTION);
    }

    EvmEnv::new(cfg_env, block_env)
}

/// Replays all transactions in a block to compute state changes.
///
/// This function executes each transaction in the block using the EVM, collecting
/// all state changes (account updates and storage modifications) and returning
/// them as key-value pairs for state root computation.
///
/// # Arguments
///
/// * `block` - Block containing full transaction data to replay
/// * `db` - Witness database providing the necessary state data for execution
///
/// # Returns
///
/// Returns a `HashMap` of state updates where:
/// - Keys are encoded storage keys (accounts and storage slots)
/// - Values are `Some(encoded_value)` for updates or `None` for deletions
///
/// # Errors
///
/// - `ValidationError::BlockIncomplete` if the block contains only transaction hashes
/// - `ValidationError::BlockReplayFailed` if transaction execution fails
///
/// # Process
///
/// 1. Creates a state builder with the witness database
/// 2. Configures block executor with Optimism-specific parameters
/// 3. Applies pre-execution changes (deposits, etc.)
/// 4. Executes each transaction in sequence
/// 5. Applies post-execution changes
/// 6. Flattens REVM's cache format into plain key-value pairs
fn replay_block(
    chain_spec: ChainSpec,
    block: &Block<OpTransaction>,
    db: &WitnessDatabase<'_>,
) -> Result<HashMap<Vec<u8>, Option<Vec<u8>>>, ValidationError> {
    // Extract full transaction data
    let BlockTransactions::Full(transactions) = &block.transactions else {
        return Err(ValidationError::BlockIncomplete);
    };

    // Setup execution environment
    let mut state = StateBuilder::new().with_database_ref(db).build();
    let evm_env = create_evm_env(&block.header, &chain_spec);

    let executor_factory = BlockExecutorFactory::new(
        chain_spec,
        EvmFactory::default(),
        OpAlloyReceiptBuilder::default(),
    );

    let execution_context = BlockExecutionCtx {
        parent_hash: block.header.parent_hash,
        parent_beacon_block_root: block.header.parent_beacon_block_root,
        extra_data: block.header.extra_data.clone(),
    };

    // Create EVM with L1 block info configuration
    let mut evm = executor_factory
        .evm_factory()
        .create_evm(&mut state, evm_env);

    // Configure L1 block info to fix operator fee expectations
    let mut l1_info = L1BlockInfo::default();
    l1_info.operator_fee_scalar = Some(U256::ZERO);
    l1_info.operator_fee_constant = Some(U256::ZERO);
    *evm.ctx_mut().chain_mut() = l1_info;

    let mut executor = executor_factory.create_executor(evm, execution_context);

    // Execute block transactions
    executor
        .apply_pre_execution_changes()
        .map_err(ValidationError::BlockReplayFailed)?;

    for tx in transactions {
        let tx_envelope = tx.inner.clone().into_inner();
        let recovered_tx = Recovered::new_unchecked(&tx_envelope, tx.from());
        executor
            .execute_transaction(recovered_tx)
            .map_err(ValidationError::BlockReplayFailed)?;
    }

    executor
        .apply_post_execution_changes()
        .map_err(ValidationError::BlockReplayFailed)?;

    // Flatten Revm's CacheAccount format into plain key-value pairs
    let mut state_updates = HashMap::default();
    for (address, cached_account) in state.cache.accounts {
        let (Some((account_info, storage)), _) = cached_account.into_components() else {
            continue;
        };

        // Process account changes
        let account = Account {
            nonce: account_info.nonce,
            balance: account_info.balance,
            codehash: (account_info.code_hash != KECCAK_EMPTY).then_some(account_info.code_hash),
        };

        let account_key = PlainKey::Account(address).encode();
        let account_value = (!account.is_empty()).then(|| PlainValue::Account(account).encode());
        state_updates.insert(account_key, account_value);

        // Process storage changes
        for (slot, value) in storage {
            let storage_key = PlainKey::Storage(address, B256::new(slot.to_be_bytes())).encode();
            let storage_value = (!value.is_zero()).then(|| PlainValue::Storage(value).encode());
            state_updates.insert(storage_key, storage_value);
        }
    }

    Ok(state_updates)
}

/// Validates a block by creating a witness, replaying transactions, and comparing state roots.
///
/// This function performs the core validation logic:
/// 1. Creates a Witness from the provided SaltWitness
/// 2. Verifies the witness proof
/// 3. Replays the block transactions using the witness database
/// 4. Computes the new state root and compares it with the expected one
///
/// # Arguments
///
/// * `block` - The block to validate containing transactions and header information
/// * `salt_witness` - The salt witness data needed for state reconstruction
/// * `contracts` - Contract bytecode cache for transaction execution
///
/// # Returns
///
/// Returns `Ok(())` if validation succeeds (computed state root matches expected).
/// Returns `Err(ValidationError)` with the specific validation failure.
pub fn validate_block(
    chain_spec: ChainSpec,
    block: &Block<OpTransaction>,
    salt_witness: SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<(), ValidationError> {
    // Verify witness proof against the current state root
    let witness = Witness::from(salt_witness);
    witness
        .verify()
        .map_err(ValidationError::WitnessVerificationFailed)?;

    // Replay block transactions
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &witness,
        contracts,
    };
    let kv_updates = replay_block(chain_spec, block, &witness_db)?;

    // Update the SALT state
    let state_updates = EphemeralSaltState::new(&witness)
        .update(&kv_updates)
        .map_err(ValidationError::StateUpdateFailed)?;

    // Update the state root
    let (state_root, _) = StateRoot::new(&witness)
        .update_fin(state_updates)
        .map_err(ValidationError::TrieUpdateFailed)?;

    // Check if computed state root matches claimed state root
    let state_root = B256::from(state_root);
    match state_root == block.header.state_root {
        true => Ok(()),
        false => Err(ValidationError::StateRootMismatch {
            actual: state_root,
            claimed: block.header.state_root,
        }),
    }
}
