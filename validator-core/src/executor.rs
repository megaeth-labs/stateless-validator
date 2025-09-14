//! Block execution logic for replaying transactions using REVM.

use alloy_consensus::transaction::Recovered;
use alloy_evm::{
    EvmEnv, EvmFactory as AlloyEvmFactory,
    block::{BlockExecutor, BlockExecutorFactory as AlloyBlockExecutorFactory},
};
use alloy_network_primitives::TransactionResponse;
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use alloy_rpc_types_eth::{Block, BlockTransactions, Header};
use mega_evm::{BlockExecutionCtx, BlockExecutorFactory, EvmFactory, SpecId};
use op_alloy_rpc_types::Transaction as OpTransaction;
use op_revm::L1BlockInfo;
use revm::{
    context::{BlockEnv, CfgEnv, ContextTr},
    database::states::StateBuilder,
    handler::EvmTr,
    primitives::{B256, HashMap, KECCAK_EMPTY, U256},
    state::Bytecode,
};
use salt::{EphemeralSaltState, SaltWitness, StateRoot, Witness};
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
    StateUpdateFailed(&'static str),

    #[error("Failed to update salt trie: {0}")]
    TrieUpdateFailed(&'static str),

    #[error("State root mismatch: claimed {claimed}, got {actual}")]
    StateRootMismatch {
        /// The computed state root from transaction execution
        actual: B256,
        /// The claimed state root from the block header
        claimed: B256,
    },
}

/// Replays a block's transactions and returns state updates in plain key-value format.
///
/// This function simulates the execution of all transactions within a block using the provided
/// witness-backed database. It configures a REVM instance with Optimism-specific settings,
/// applies each transaction sequentially, and converts the resulting state changes to a plain
/// key-value format suitable for state trie operations.
///
/// # Arguments
///
/// * `block` - The `Block` to be replayed, containing full transaction details.
/// * `db` - A `WitnessDatabase` that provides the necessary pre-state for transaction execution.
///
/// # Returns
///
/// Returns `Ok(HashMap<Vec<u8>, Option<Vec<u8>>>)` containing the state updates in plain format:
/// - Keys are encoded account addresses or storage slot identifiers
/// - Values are encoded account data or storage values (`None` indicates deletion)
///
/// Returns `Err(ValidationError)` if any part of the replay process fails.
fn replay_block(
    block: &Block<OpTransaction>,
    db: &WitnessDatabase<'_>,
) -> Result<HashMap<Vec<u8>, Option<Vec<u8>>>, ValidationError> {
    let BlockTransactions::Full(transactions) = block.transactions.clone() else {
        return Err(ValidationError::BlockIncomplete);
    };

    let mut state = StateBuilder::new().with_database_ref(db).build();

    let block_executor_factory = BlockExecutorFactory::new(
        ChainSpec,
        EvmFactory::default(),
        OpAlloyReceiptBuilder::default(),
    );

    let op_block_execution_ctx = BlockExecutionCtx {
        parent_hash: block.header.parent_hash,
        parent_beacon_block_root: block.header.parent_beacon_block_root,
        extra_data: block.header.extra_data.clone(),
    };

    let evm_env = create_evm_env(&block.header, &ChainSpec);

    let mut l1_block_info = L1BlockInfo::default();
    l1_block_info.operator_fee_scalar = Some(U256::ZERO);
    l1_block_info.operator_fee_constant = Some(U256::ZERO);

    let mut evm = block_executor_factory
        .evm_factory()
        .create_evm(&mut state, evm_env);

    // Set L1 block info to fix operator_fee_scalar.expect() when setting blockhash
    *evm.ctx_mut().chain_mut() = l1_block_info;

    let mut block_executor = block_executor_factory.create_executor(evm, op_block_execution_ctx);

    block_executor
        .apply_pre_execution_changes()
        .map_err(ValidationError::BlockReplayFailed)?;

    for tx in transactions {
        let signer = tx.from();
        let op_tx_envelope = tx.inner.into_inner();
        let recovered = Recovered::new_unchecked(&op_tx_envelope, signer);
        block_executor
            .execute_transaction(recovered)
            .map_err(ValidationError::BlockReplayFailed)?;
    }

    block_executor
        .apply_post_execution_changes()
        .map_err(ValidationError::BlockReplayFailed)?;

    // Flatten REVM's CacheAccount format into plain key-value pairs
    let mut kv_updates = HashMap::default();
    for (address, cache_account) in state.cache.accounts {
        if let (Some((info, storage)), _) = cache_account.into_components() {
            // Handle account
            let account = Account {
                nonce: info.nonce,
                balance: info.balance,
                codehash: (info.code_hash != KECCAK_EMPTY).then_some(info.code_hash),
            };

            let account_value =
                (!account.is_empty()).then(|| PlainValue::Account(account).encode());
            kv_updates.insert(PlainKey::Account(address).encode(), account_value);

            // Handle storage
            for (slot, value) in storage {
                let storage_value = (!value.is_zero()).then(|| PlainValue::Storage(value).encode());
                kv_updates.insert(
                    PlainKey::Storage(address, B256::new(slot.to_be_bytes())).encode(),
                    storage_value,
                );
            }
        }
    }

    Ok(kv_updates)
}

/// Creates an EvmEnv with Optimism-specific configurations for the given block header.
///
/// This combines both the CfgEnv (chain configuration) and BlockEnv (block-specific data)
/// into a single EvmEnv ready for use with REVM execution.
fn create_evm_env(header: &Header, chain_spec: &ChainSpec) -> EvmEnv<SpecId> {
    let cfg_env = CfgEnv::new_with_spec(chain_spec.spec_id_at_block(header.number))
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

/// Validates a block by creating a witness, replaying transactions, and comparing state roots.
///
/// This function performs the core validation logic:
/// 1. Creates a Witness from the provided SaltWitness
/// 2. Verifies the witness proof against the old state root
/// 3. Replays the block transactions using the witness database
/// 4. Computes the new state root and compares it with the expected one
///
/// # Arguments
///
/// * `block` - The block to validate containing transactions and header information
/// * `salt_witness` - The salt witness data needed for state reconstruction
/// * `old_state_root` - The previous block's state root for proof verification
/// * `contracts` - Contract bytecode cache for transaction execution
///
/// # Returns
///
/// Returns `Ok(())` if validation succeeds (computed state root matches expected).
/// Returns `Err(ValidationError)` with the specific validation failure.
pub fn validate_block(
    block: &Block<OpTransaction>,
    salt_witness: SaltWitness,
    old_state_root: B256,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<(), ValidationError> {
    // Verify witness proof against the current state root
    let witness = Witness::from(salt_witness);
    witness
        .verify(*old_state_root)
        .map_err(ValidationError::WitnessVerificationFailed)?;

    // Replay block transactions
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &witness,
        contracts,
    };
    let kv_updates = replay_block(block, &witness_db)?;

    // Update ephemeral salt state
    let state_updates = EphemeralSaltState::new(&witness)
        .update(&kv_updates)
        .map_err(ValidationError::StateUpdateFailed)?;

    // Update state root trie
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
