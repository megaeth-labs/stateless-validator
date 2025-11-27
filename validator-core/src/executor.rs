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

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{proofs::calculate_receipt_root, transaction::Recovered};
use alloy_evm::{
    EvmEnv,
    block::{BlockExecutor, ExecutableTx},
};
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use alloy_primitives::{Address, BlockHash, BlockNumber, map::HashMap};
use alloy_rpc_types_eth::{Block, BlockTransactions, Header};
use alloy_trie::root::ordered_trie_root_with_encoder;
use eyre::{Result, ensure, eyre};
use mega_evm::{
    BlockLimits, ExternalEnvFactory, MegaBlockExecutionCtx, MegaBlockExecutorFactory,
    MegaEvmFactory, MegaSpecId,
};
use op_alloy_network::{TransactionResponse, eip2718::Encodable2718};
use op_alloy_rpc_types::Transaction as OpTransaction;
use revm::{
    DatabaseRef,
    context::{BlockEnv, CfgEnv},
    database::states::{CacheAccount, StateBuilder},
    inspector::inspectors::TracerEip3155,
    primitives::{B256, KECCAK_EMPTY, U256},
    state::Bytecode,
};
use salt::{EphemeralSaltState, SaltValue, SaltWitness, StateRoot, StateUpdates, Witness};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::{collections::BTreeMap, fmt::Debug, time::SystemTime};
use thiserror::Error;

use crate::{
    chain_spec::{BLOB_GASPRICE_UPDATE_FRACTION, ChainSpec},
    data_types::{Account, PlainKey, PlainValue},
    database::{WitnessDatabase, WitnessDatabaseError, WitnessExternalEnv},
    withdrawals::{self, ADDRESS_L2_TO_L1_MESSAGE_PASSER, MptWitness},
};

/// Errors that can occur during block validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Witness proof verification failed: {0}")]
    WitnessVerificationFailed(#[source] salt::ProofError),

    #[error("Failed to validate changes to the withdrawal contract: {0}")]
    WithdrawalValidationFailed(#[source] withdrawals::WithdrawalValidationError),

    #[error("Failed to construct mega-evm environment oracle: {0}")]
    EnvOracleConstructionFailed(#[source] WitnessDatabaseError),

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

    #[error("Pre-withdrawals root mismatch: expecting {expected:?}, got {actual:?}")]
    PreWithdrawalsRootMismatch {
        /// The post-withdrawals root of the parent block
        expected: B256,
        /// The pre-withdrawals root of the witness
        actual: B256,
    },

    #[error("State root mismatch: claimed {claimed}, got {actual}")]
    StateRootMismatch {
        /// The computed state root from transaction execution
        actual: B256,
        /// The claimed state root from the block header
        claimed: B256,
    },

    #[error("Receipts root mismatch: claimed {claimed}, got {actual}")]
    ReceiptsRootMismatch {
        /// The computed receipts root from transaction execution
        actual: B256,
        /// The claimed receipts root from the block header
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
    /// The pre-withdrawl root from the mpt witness before block execution
    pub pre_withdrawals_root: B256,
    /// The post-withdrawal root after block execution (from block header)
    pub post_withdrawals_root: B256,
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
fn create_evm_env(header: &Header, chain_spec: &ChainSpec) -> EvmEnv<MegaSpecId> {
    let cfg_env = CfgEnv::new_with_spec(chain_spec.spec_id_at_timestamp(header.timestamp))
        .with_chain_id(chain_spec.chain_id);

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
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
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
/// 7. Builds the receipts root from all transaction receipts
pub fn replay_block<DB, ENV, E>(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    db: &DB,
    env_oracle: ENV,
    trace_writer: Option<Box<dyn Write>>,
) -> Result<(HashMap<Address, CacheAccount>, B256), ValidationError>
where
    DB: DatabaseRef<Error = E> + Debug,
    ENV: ExternalEnvFactory + Clone,
    E: std::error::Error + Send + Sync + 'static,
{
    // Extract full transaction data
    let BlockTransactions::Full(transactions) = &block.transactions else {
        return Err(ValidationError::BlockIncomplete);
    };

    // Setup execution environment
    let mut state = StateBuilder::new().with_database_ref(db).build();
    let evm_env = create_evm_env(&block.header, chain_spec);

    let executor_factory = MegaBlockExecutorFactory::new(
        chain_spec.clone(),
        MegaEvmFactory::new().with_external_env_factory(env_oracle),
        OpAlloyReceiptBuilder::default(),
    );

    let execution_context = MegaBlockExecutionCtx::new(
        block.header.parent_hash,
        block.header.parent_beacon_block_root,
        block.header.extra_data.clone(),
        BlockLimits::from_evm_env(&evm_env),
    );

    let receipts_root = if let Some(writer) = trace_writer {
        let executor = executor_factory.create_executor_with_inspector(
            &mut state,
            execution_context,
            evm_env,
            TracerEip3155::new(writer),
        );
        execute_transactions(executor, transactions)?
    } else {
        let executor = executor_factory.create_executor(&mut state, execution_context, evm_env);
        execute_transactions(executor, transactions)?
    };

    Ok((state.cache.accounts, receipts_root))
}

/// Executes transactions using the given block executor.
fn execute_transactions<E, T>(
    mut executor: E,
    transactions: &[OpTransaction<T>],
) -> Result<B256, ValidationError>
where
    E: BlockExecutor<Transaction = T>,
    E::Receipt: Encodable2718,
    T: Clone,
    OpTransaction<T>: TransactionResponse,
    for<'a> Recovered<&'a T>: ExecutableTx<E>,
{
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

    let execution_result = executor
        .apply_post_execution_changes()
        .map_err(ValidationError::BlockReplayFailed)?;

    Ok(calculate_receipt_root(&execution_result.receipts))
}

/// Validates a block by creating a witness, replaying transactions, and comparing state roots.
///
/// This function performs the core validation logic:
/// 1. Creates a Witness from the provided SaltWitness
/// 2. Verifies the witness proof
/// 3. Replays the block transactions using the witness database
/// 4. Check if computed withdrawals root matches the claimed one
/// 5. Verify receipts root matches the block header
/// 6. Computes the new state root and compares it with the expected one
///
/// # Arguments
///
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
/// * `block` - The block to validate containing transactions and header information
/// * `salt_witness` - The salt witness data needed for state validation
/// * `mpt_witness` - The MPT witness data for withdrawal verification
/// * `contracts` - Contract bytecode cache for transaction execution
/// * `writer` - Optional writer for EIP-3155 trace output. When provided, enables
///   step-by-step EVM execution tracing in EIP-3155 format.
///
/// # Returns
///
/// Returns `Ok(())` if validation succeeds (computed state root matches expected).
/// Returns `Err(ValidationError)` with the specific validation failure.
pub fn validate_block(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    salt_witness: SaltWitness,
    mpt_witness: MptWitness,
    contracts: &std::collections::HashMap<B256, Bytecode>,
    writer: Option<Box<dyn Write>>,
) -> Result<(), ValidationError> {
    // Create external environment oracle from salt witness
    let ext_env = WitnessExternalEnv::new(&salt_witness, block.header.number)
        .map_err(ValidationError::EnvOracleConstructionFailed)?;

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
    let (accounts, receipts_root) = replay_block(chain_spec, block, &witness_db, ext_env, writer)?;

    // Filter out changes within the message passer contract
    let withdrawal_contract = accounts.get(&ADDRESS_L2_TO_L1_MESSAGE_PASSER).cloned();

    // Flatten Revm's CacheAccount format into plain key-value pairs
    let mut kv_updates: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
    for (address, cached_account) in accounts {
        let (Some((account_info, storage)), _) = cached_account.into_components() else {
            // Skip cached accounts with no account info or storage changes.
            //
            // Revm creates these cache entries in two cases:
            // 1. Read-only access to non-existent accounts (balance checks, code reads, etc.)
            // 2. SELFDESTRUCT execution clearing an account from state
            //
            // Since mega-evm disables SELFDESTRUCT, case 2 would fail during transaction
            // execution above, never reaching here. We only see case 1: read-only operations
            // that don't generate state changes.
            //
            // Skipping these is correct - they represent cache entries without modifications.
            // Only accounts with actual changes need to be written to the state trie.
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
        kv_updates.insert(account_key, account_value);

        // Process storage changes
        for (slot, value) in storage {
            let storage_key = PlainKey::Storage(address, B256::new(slot.to_be_bytes())).encode();
            let storage_value = (!value.is_zero()).then(|| PlainValue::Storage(value).encode());
            kv_updates.insert(storage_key, storage_value);
        }
    }

    // Update the SALT state: Apply updates first, then inserts/deletes in deterministic key
    // order (same as Witness::create). This ordering is critical: inserts/deletes may trigger
    // key displacement or bucket expansion, invalidating the witness's direct lookup table.
    let mut witness_state = EphemeralSaltState::new(&witness);
    let mut state_updates = StateUpdates::default();
    let mut inserts_or_deletes = BTreeMap::new();

    for (plain_key, opt_plain_value) in kv_updates {
        if let (Ok(Some((salt_key, old_value))), Some(new_value)) =
            (witness_state.find(&plain_key), &opt_plain_value)
        {
            // Update operation: key exists and new value is not None
            witness_state.update_value(
                &mut state_updates,
                salt_key,
                Some(old_value),
                Some(SaltValue::new(&plain_key, new_value)),
            );
        } else {
            inserts_or_deletes.insert(plain_key, opt_plain_value);
        }
    }
    state_updates.merge(
        witness_state
            .update_fin(&inserts_or_deletes)
            .map_err(ValidationError::StateUpdateFailed)?,
    );

    // Update the state root
    let (state_root, _) = StateRoot::new(&witness)
        .update_fin(&state_updates)
        .map_err(ValidationError::TrieUpdateFailed)?;

    // Check if computed withdrawals root matches the claimed one
    mpt_witness
        .verify(&block.header, withdrawal_contract)
        .map_err(ValidationError::WithdrawalValidationFailed)?;

    // Verify receipts root matches the block header
    if receipts_root != block.header.receipts_root {
        return Err(ValidationError::ReceiptsRootMismatch {
            actual: receipts_root,
            claimed: block.header.receipts_root,
        });
    }

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

/// Verifies the structural integrity and cryptographic consistency of a block.
///
/// # Arguments
///
/// * `block` - The block to verify, containing header and transaction data
///
/// # Returns
///
/// Returns `Ok(())` if all integrity checks pass, otherwise returns an error
/// describing which check failed.
///
/// # Validation Checks
///
/// 1. **Block Hash**: Verifies that the block's header hash matches the computed
///    hash from the header fields
/// 2. **Transaction Hashes**: For each transaction, verifies that the transaction
///    hash matches its computed hash
/// 3. **Transaction Signers**: Recovers and verifies the signer for each transaction
///    matches the claimed `from` address
/// 4. **Transactions Root**: Computes the Merkle root of all transactions and
///    verifies it matches the `transactions_root` in the block header
pub fn verify_block_integrity(block: &Block<OpTransaction>) -> Result<()> {
    // Verify block hash matches the computed hash from header
    ensure!(
        block.header.hash_slow() == block.header.hash,
        "Block hash mismatch: expected {:?}, computed {:?}",
        block.header.hash,
        block.header.hash_slow()
    );

    // Verify transaction hashes and transactions root
    if let BlockTransactions::Full(ref transactions) = block.transactions {
        for tx in transactions {
            let tx_envelope = tx.inner.clone().into_inner();
            ensure!(
                tx_envelope.trie_hash() == *tx_envelope.hash(),
                "Transaction hash mismatch: expected {:?}, computed {:?}",
                tx_envelope.hash(),
                tx_envelope.trie_hash()
            );

            let recovered = tx_envelope
                .recover_signer()
                .map_err(|err| eyre!("Failed to recover signer: {}", err))?;

            ensure!(
                recovered == tx.from(),
                "Transaction signer mismatch: expected {:?}, got {:?}",
                tx.from(),
                recovered
            );
        }

        let computed_tx_root = ordered_trie_root_with_encoder(transactions, |tx, buf| {
            tx.inner.clone().into_inner().encode_2718(buf)
        });
        ensure!(
            computed_tx_root == block.header.transactions_root,
            "Transactions root mismatch: expected {:?}, computed {:?}",
            block.header.transactions_root,
            computed_tx_root
        );
    }

    Ok(())
}
