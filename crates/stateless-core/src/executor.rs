//! Block execution and transaction replay for stateless validation.
//!
//! This module provides the core execution logic for validating blocks in a stateless
//! manner. It handles EVM environment setup, transaction replay, and state change
//! computation that feeds into the broader validation pipeline.
//!
//! ## Key Functions
//!
//! - [`validate_block`]: Main validation entry point that orchestrates witness verification,
//!   transaction replay, and state root comparison
//! - [`create_evm_env`]: Creates EVM execution environment from block header and chain
//!   specification
//! - [`replay_block`]: Replays block transactions to compute state changes
//!
//! [`replay_block`] / [`validate_block`] are generic over [`BlockInput`], the minimal block
//! projection they consume (the in-repo impl is the RPC `Block`; embedders supply their own).
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

use std::{boxed::Box, collections::BTreeMap, fmt::Debug, sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::{io::Write, time::Instant};

use alloy_consensus::{TxReceipt, proofs::calculate_receipt_root, transaction::Recovered};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    EvmEnv,
    block::{BlockExecutor, ExecutableTx},
};
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use alloy_primitives::{
    Address, Bloom, keccak256,
    map::{B256Map, HashMap},
};
use alloy_rpc_types_eth::{Block, BlockTransactions};
use mega_evm::{
    BlockLimits, ExternalEnvFactory, MegaBlockExecutionCtx, MegaBlockExecutorFactory,
    MegaEvmFactory, MegaHardforks, MegaSpecId,
};
use op_alloy_consensus::OpTxEnvelope;
use op_alloy_rpc_types::Transaction as OpTransaction;
#[cfg(feature = "std")]
use revm::inspector::inspectors::TracerEip3155;
use revm::{
    DatabaseRef,
    context::{BlockEnv, CfgEnv},
    database::states::{BundleAccount, StateBuilder, bundle_state::BundleRetention},
    primitives::{B256, KECCAK_EMPTY, U256},
    state::Bytecode,
};
use salt::{EphemeralSaltState, SaltValue, SaltWitness, StateRoot, StateUpdates, Witness};
use thiserror::Error;
use tracing::debug;

use crate::{
    chain_spec::{BLOB_GASPRICE_UPDATE_FRACTION, ChainSpec},
    data_types::{Account, PlainKey, PlainValue},
    evm_database::{WitnessDatabase, WitnessDatabaseError, WitnessExternalEnv},
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

    #[error("Logs bloom mismatch: claimed {claimed}, got {actual}")]
    LogsBloomMismatch {
        /// The computed logs bloom from transaction execution
        actual: Box<Bloom>,
        /// The claimed logs bloom from the block header
        claimed: Box<Bloom>,
    },

    #[error("Gas used mismatch: claimed {claimed}, got {actual}")]
    GasUsedMismatch {
        /// The computed gas used from transaction execution
        actual: u64,
        /// The claimed gas used from the block header
        claimed: u64,
    },
}

/// Results from executing block transactions.
///
/// Contains the computed values needed to verify block header fields.
#[derive(Debug, Clone)]
pub struct BlockExecutionOutput {
    /// The computed receipts root from transaction execution
    pub receipts_root: B256,
    /// The aggregated logs bloom from all receipts
    pub logs_bloom: Bloom,
    /// The total gas used by all transactions
    pub gas_used: u64,
    /// Number of accounts/storage slots read during execution
    pub state_reads: usize,
    /// Number of accounts/storage slots changed
    pub state_writes: usize,
}

/// Statistics collected during block validation for metrics.
///
/// The `*_time` fields are measured with `std::time::Instant` and are always `0.0` in
/// `no_std` builds (no monotonic clock available). Consumers that meter or log these
/// values should treat `0.0` as "not measured" when running without the `std` feature.
#[derive(Debug, Clone, Default)]
pub struct ValidationStats {
    /// Number of accounts/storage slots read during execution
    pub state_reads: usize,
    /// Number of accounts/storage slots changed
    pub state_writes: usize,
    /// Time spent verifying the witness proof (seconds; `0.0` in `no_std` builds)
    pub witness_verification_time: f64,
    /// Time spent replaying block transactions (seconds; `0.0` in `no_std` builds)
    pub block_replay_time: f64,
    /// Time spent updating SALT state (seconds; `0.0` in `no_std` builds)
    pub salt_update_time: f64,
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
///
/// Creates an EVM environment from a block header and chain specification.
///
/// This function sets up the configuration and block environment needed for EVM execution.
pub fn create_evm_env(
    header: &alloy_consensus::Header,
    chain_spec: &ChainSpec,
) -> EvmEnv<MegaSpecId> {
    let cfg_env = CfgEnv::new_with_spec(chain_spec.spec_id(header.timestamp))
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

/// Minimal projection of a block that [`replay_block`] / [`validate_block`] need: the consensus
/// header (every execution/validation field lives there), the block hash (diagnostics only), and
/// the recovered `(transaction, sender)` pairs.
///
/// Abstracting over this lets the same replay path consume either an RPC
/// [`Block<OpTransaction>`] (standalone validator, debug-trace-server) or a host's
/// already-recovered block, without a per-tx rebuild into RPC form. The trait is dependency-clean:
/// the only impl here is for the RPC block; reth-backed impls live in the embedder that already
/// depends on reth.
pub trait BlockInput {
    /// The consensus header carrying all replay/validation fields.
    fn consensus_header(&self) -> &alloy_consensus::Header;
    /// The block hash (used only for diagnostics).
    fn block_hash(&self) -> B256;
    /// Whether full transaction bodies are present. An RPC block carrying only hashes returns
    /// `false`, which [`replay_block`] maps to [`ValidationError::BlockIncomplete`].
    fn is_complete(&self) -> bool;
    /// Recovered `(transaction, sender)` pairs, borrowed — no clone, no signature re-recovery.
    fn txs_recovered(&self) -> impl Iterator<Item = Recovered<&OpTxEnvelope>> + '_;
}

impl BlockInput for Block<OpTransaction> {
    fn consensus_header(&self) -> &alloy_consensus::Header {
        &self.header.inner
    }

    fn block_hash(&self) -> B256 {
        self.header.hash
    }

    fn is_complete(&self) -> bool {
        matches!(self.transactions, BlockTransactions::Full(_))
    }

    fn txs_recovered(&self) -> impl Iterator<Item = Recovered<&OpTxEnvelope>> + '_ {
        // Borrow each `Recovered<OpTxEnvelope>` in place via `as_recovered_ref()` — clone-free.
        // The hashes-only case yields `&[]`, but `is_complete()` is checked first so it surfaces
        // as `BlockIncomplete`.
        let full = match &self.transactions {
            BlockTransactions::Full(txs) => txs.as_slice(),
            _ => &[],
        };
        full.iter().map(|tx| tx.inner.inner.as_recovered_ref())
    }
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
/// Returns a tuple containing:
/// - A `HashMap` of cached account states from transaction execution
/// - A `BlockExecutionOutput` with receipts root, logs bloom, and gas used
///
/// # Errors
///
/// - `ValidationError::BlockIncomplete` if the block contains only transaction hashes
/// - `ValidationError::BlockReplayFailed` if transaction execution fails
///
/// # Process
///
/// 1. Creates a state builder with the witness database and bundle update tracking
/// 2. Configures block executor with Optimism-specific parameters
/// 3. Applies pre-execution changes (deposits, etc.)
/// 4. Executes each transaction in sequence
/// 5. Applies post-execution changes
/// 6. Merges state transitions into bundle state
/// 7. Returns bundle accounts and execution output (receipts root, logs bloom, gas used)
pub fn replay_block<B, DB, ENV, E>(
    chain_spec: &ChainSpec,
    block: &B,
    db: &DB,
    env_oracle: ENV,
    #[cfg(feature = "std")] trace_writer: Option<Box<dyn Write>>,
) -> Result<(HashMap<Address, BundleAccount>, BlockExecutionOutput), ValidationError>
where
    B: BlockInput,
    DB: DatabaseRef<Error = E> + Debug,
    ENV: ExternalEnvFactory + Clone,
    E: core::error::Error + Send + Sync + 'static,
{
    // A block carrying only transaction hashes can't be replayed.
    if !block.is_complete() {
        return Err(ValidationError::BlockIncomplete);
    }
    let header = block.consensus_header();

    // Setup execution environment
    let mut state = StateBuilder::new().with_database_ref(db).with_bundle_update().build();
    let evm_env = create_evm_env(header, chain_spec);

    let executor_factory = MegaBlockExecutorFactory::new(
        chain_spec.clone(),
        MegaEvmFactory::new().with_external_env_factory(env_oracle),
        OpAlloyReceiptBuilder::default(),
    );

    let hardfork = chain_spec.hardfork(header.timestamp);
    debug!(
        "Replay block: block_number={}, block_hash={:?}, hardfork={:?}",
        header.number,
        block.block_hash(),
        hardfork
    );
    let block_limits = if let Some(hardfork) = hardfork {
        BlockLimits::from_hardfork_and_block_gas_limit(hardfork, header.gas_limit)
    } else {
        BlockLimits::no_limits().with_block_gas_limit(header.gas_limit)
    };

    let execution_context = MegaBlockExecutionCtx::new(
        header.parent_hash,
        header.parent_beacon_block_root,
        header.extra_data.clone(),
        block_limits,
    );

    // Plain execution path, shared by the non-tracer std branch and the no_std build.
    // Extracted as a closure so the body lives in one place — any future change to the
    // non-tracer path only needs to be made here.
    let run_plain = |state: &mut _, ctx, env| {
        let executor = executor_factory.create_executor(state, ctx, env);
        execute_transactions(executor, block.txs_recovered())
    };

    #[cfg(feature = "std")]
    let (receipts_root, logs_bloom, gas_used) = if let Some(writer) = trace_writer {
        let executor = executor_factory.create_executor_with_inspector(
            &mut state,
            execution_context,
            evm_env,
            TracerEip3155::new(writer),
        );
        execute_transactions(executor, block.txs_recovered())?
    } else {
        run_plain(&mut state, execution_context, evm_env)?
    };
    #[cfg(not(feature = "std"))]
    let (receipts_root, logs_bloom, gas_used) = run_plain(&mut state, execution_context, evm_env)?;

    // Merge transitions into bundle_state
    state.merge_transitions(BundleRetention::PlainState);

    let total_accessed: usize = state
        .cache
        .accounts
        .values()
        .map(|a| 1 + a.account.as_ref().map_or(0, |a| a.storage.len()))
        .sum();

    let state_writes: usize = state
        .bundle_state
        .state
        .values()
        .map(|a| {
            (a.info != a.original_info) as usize +
                a.storage.values().filter(|s| s.is_changed()).count()
        })
        .sum();

    Ok((
        state.bundle_state.state,
        BlockExecutionOutput {
            receipts_root,
            logs_bloom,
            gas_used,
            state_reads: total_accessed.saturating_sub(state_writes),
            state_writes,
        },
    ))
}

/// Executes a stream of recovered transactions using the given block executor.
fn execute_transactions<'a, E, I>(
    mut executor: E,
    transactions: I,
) -> Result<(B256, Bloom, u64), ValidationError>
where
    E: BlockExecutor<Transaction = OpTxEnvelope>,
    E::Receipt: Encodable2718 + TxReceipt,
    I: Iterator<Item = Recovered<&'a OpTxEnvelope>>,
    for<'b> Recovered<&'b OpTxEnvelope>: ExecutableTx<E>,
{
    executor.apply_pre_execution_changes().map_err(ValidationError::BlockReplayFailed)?;

    for recovered_tx in transactions {
        executor.execute_transaction(recovered_tx).map_err(ValidationError::BlockReplayFailed)?;
    }

    let execution_result =
        executor.apply_post_execution_changes().map_err(ValidationError::BlockReplayFailed)?;

    // Compute logs bloom by ORing all receipt blooms together
    let logs_bloom =
        execution_result.receipts.iter().fold(Bloom::ZERO, |acc, receipt| acc | receipt.bloom());

    // Gas used is the cumulative gas used of the last receipt
    let gas_used = execution_result.receipts.last().map(|r| r.cumulative_gas_used()).unwrap_or(0);

    let receipts_root = calculate_receipt_root(&execution_result.receipts);

    Ok((receipts_root, logs_bloom, gas_used))
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
/// * `writer` - Optional writer for EIP-3155 trace output. When provided, enables step-by-step EVM
///   execution tracing in EIP-3155 format.
///
/// # Returns
///
/// Returns `Ok(ValidationStats)` if validation succeeds, containing state access metrics.
/// Returns `Err(ValidationError)` with the specific validation failure.
pub fn validate_block<B: BlockInput>(
    chain_spec: &ChainSpec,
    block: &B,
    salt_witness: SaltWitness,
    mpt_witness: MptWitness,
    contracts: &HashMap<B256, Arc<Bytecode>>,
    #[cfg(feature = "std")] writer: Option<Box<dyn Write>>,
) -> Result<ValidationStats, ValidationError> {
    let header = block.consensus_header();

    // Create external environment oracle from salt witness
    let ext_env = WitnessExternalEnv::new(&salt_witness, header.number)
        .map_err(ValidationError::EnvOracleConstructionFailed)?;

    // Verify witness proof against the current state root
    #[cfg(feature = "std")]
    let start = Instant::now();
    let witness = Witness::from(salt_witness);
    witness.verify().map_err(ValidationError::WitnessVerificationFailed)?;
    #[cfg(feature = "std")]
    let witness_verification_time = start.elapsed().as_secs_f64();
    #[cfg(not(feature = "std"))]
    let witness_verification_time = 0.0_f64; // no_std: timing unavailable

    // Replay block transactions
    let witness_db = WitnessDatabase { header, witness: &witness, contracts };
    let (accounts, output) = replay_block(
        chain_spec,
        block,
        &witness_db,
        ext_env,
        #[cfg(feature = "std")]
        writer,
    )?;
    #[cfg(feature = "std")]
    let block_replay_time = start.elapsed().as_secs_f64() - witness_verification_time;
    #[cfg(not(feature = "std"))]
    let block_replay_time = 0.0_f64; // no_std: timing unavailable

    // Extract and hash storage updates (only changed values)
    let withdrawal_storage: B256Map<U256> = accounts
        .get(&ADDRESS_L2_TO_L1_MESSAGE_PASSER)
        .map(|a| {
            a.storage
                .iter()
                .filter(|(_, v)| v.previous_or_original_value != v.present_value)
                .map(|(&slot, v)| (keccak256(B256::from(slot)), v.present_value))
                .collect()
        })
        .unwrap_or_default();

    // Flatten Revm's BundleAccount format into plain key-value pairs
    let mut kv_updates: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
    for (address, bundle_account) in accounts {
        if bundle_account.info != bundle_account.original_info {
            // Process account changes
            let account = bundle_account.info.map(|info| Account {
                nonce: info.nonce,
                balance: info.balance,
                codehash: (info.code_hash != KECCAK_EMPTY).then_some(info.code_hash),
            });

            let account_key = PlainKey::Account(address).encode();
            let account_value = account.and_then(|account| {
                (!account.is_empty()).then(|| PlainValue::Account(account).encode())
            });
            kv_updates.insert(account_key, account_value);
        }

        // Process storage changes
        for (slot, value) in bundle_account.storage {
            if value.previous_or_original_value != value.present_value {
                let storage_key =
                    PlainKey::Storage(address, B256::new(slot.to_be_bytes())).encode();
                let storage_value = (!value.present_value.is_zero())
                    .then(|| PlainValue::Storage(value.present_value).encode());
                kv_updates.insert(storage_key, storage_value);
            }
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
    #[cfg(feature = "std")]
    let salt_update_time =
        start.elapsed().as_secs_f64() - witness_verification_time - block_replay_time;
    #[cfg(not(feature = "std"))]
    let salt_update_time = 0.0_f64; // no_std: timing unavailable

    // Check if computed withdrawals root matches the claimed one
    mpt_witness
        .verify(header, withdrawal_storage)
        .map_err(ValidationError::WithdrawalValidationFailed)?;

    // Verify receipts root matches the block header
    if output.receipts_root != header.receipts_root {
        return Err(ValidationError::ReceiptsRootMismatch {
            actual: output.receipts_root,
            claimed: header.receipts_root,
        });
    }

    // Verify logs bloom matches the block header
    if output.logs_bloom != header.logs_bloom {
        return Err(ValidationError::LogsBloomMismatch {
            actual: Box::new(output.logs_bloom),
            claimed: Box::new(header.logs_bloom),
        });
    }

    // Verify gas used matches the block header
    if output.gas_used != header.gas_used {
        return Err(ValidationError::GasUsedMismatch {
            actual: output.gas_used,
            claimed: header.gas_used,
        });
    }

    // Check if computed state root matches claimed state root
    let state_root = B256::from(state_root);
    if state_root != header.state_root {
        return Err(ValidationError::StateRootMismatch {
            actual: state_root,
            claimed: header.state_root,
        });
    }

    Ok(ValidationStats {
        state_reads: output.state_reads,
        state_writes: output.state_writes,
        witness_verification_time,
        block_replay_time,
        salt_update_time,
    })
}

#[cfg(test)]
mod tests {
    use stateless_test_utils::fixtures::TestFixtures;

    use super::*;

    /// Print `stateless_core` debug logs (everything else at warn).
    /// std-only: `set_default` and its guard live behind tracing's `std` feature.
    #[cfg(feature = "std")]
    fn init_test_logging() -> tracing::subscriber::DefaultGuard {
        use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::new("warn").add_directive("stateless_core=debug".parse().unwrap()),
            )
            .set_default()
    }

    #[test]
    fn validate_block_mainnet_fixtures() {
        #[cfg(feature = "std")]
        let _logging = init_test_logging();
        let fx = TestFixtures::mainnet();
        let chain_spec = ChainSpec::from_genesis(fx.load_genesis().unwrap());
        let paired = fx.paired_blocks();
        assert!(!paired.is_empty(), "no paired mainnet fixtures in test_data/mainnet");
        for (number, hash) in paired {
            validate_block(
                &chain_spec,
                &fx.blocks[&hash],
                fx.salt_witnesses[&hash].clone(),
                fx.mpt_witness(&hash),
                &fx.contracts,
                #[cfg(feature = "std")]
                None,
            )
            .unwrap_or_else(|e| panic!("validate_block failed for {number} ({hash}): {e:?}"));
        }
    }
}
