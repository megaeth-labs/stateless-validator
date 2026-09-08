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
//! - [`validate_block_deriving_updates`]: Variant returning the replay-derived SALT state updates
//!   for embedders that compare against an independently verified per-block changeset
//! - [`create_block_execution_env`]: Single home for the per-block execution environment —
//!   [`EvmEnv`], block executor factory, and hardfork-derived block limits — shared by
//!   [`replay_block`] and the debug-trace-server's tracing executor ([`create_evm_env`] is its
//!   EvmEnv sub-step)
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

use std::{boxed::Box, collections::BTreeMap, fmt::Debug, vec::Vec};
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
    BlockLimits, ExternalEnvFactory, MegaBlockExecutionCtx, MegaBlockExecutor,
    MegaBlockExecutorFactory, MegaContext, MegaEvm, MegaEvmFactory, MegaHardforks, MegaSpecId,
};
use op_alloy_consensus::OpTxEnvelope;
use op_alloy_rpc_types::Transaction as OpTransaction;
#[cfg(feature = "std")]
use revm::inspector::inspectors::TracerEip3155;
use revm::{
    DatabaseRef,
    context::{BlockEnv, CfgEnv},
    database::{
        State,
        states::{BundleAccount, StateBuilder, bundle_state::BundleRetention},
    },
    primitives::{B256, KECCAK_EMPTY, U256, eip4844::BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN},
    state::Bytecode,
};
use salt::{EphemeralSaltState, SaltValue, SaltWitness, StateRoot, StateUpdates, Witness};
use thiserror::Error;
use tracing::debug;

use crate::{
    chain_spec::ChainSpec,
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
    /// Time spent updating SALT state (seconds; `0.0` in `no_std` builds).
    ///
    /// In [`validate_block`] this covers deriving the state updates **and** the SALT trie root
    /// update; in [`validate_block_deriving_updates`] it covers only the state-update derivation
    /// (no trie math happens there).
    pub salt_update_time: f64,
}

/// Caller policy for [`validate_block_deriving_updates`]: how the witnesses are bound to the
/// canonical chain before the derived updates are handed back.
///
/// Both witness proofs are always verified (the SALT witness's IPA proof, the MPT witness's
/// Merkle proof); the anchor is an *additional* binding. Build with [`Self::anchored`] — the
/// standard form — or [`Self::unanchored`], an explicit opt-out; there is deliberately no
/// `Default`, so skipping the parent binding must be spelled out at the call site.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidationOptions {
    /// When set (via [`Self::anchored`]), require each witness's own pre-root to equal the
    /// parent block's matching post root before any other work: the SALT witness's state root
    /// against [`ParentAnchor::state_root`] (failing with
    /// [`ValidationError::PreStateRootMismatch`]), then the MPT witness's storage root against
    /// [`ParentAnchor::withdrawals_root`] (failing with
    /// [`ValidationError::PreWithdrawalsRootMismatch`]).
    ///
    /// This is the only check that binds the MPT witness's *pre*-state to the chain:
    /// [`MptWitness::verify`] proves the witness against its own claimed `storage_root` and
    /// binds the *post* root to the block header, which exposes a fabricated pre-state only
    /// when the fabrication survives into the post root — a fabrication confined to slots
    /// this block rewrites converges to the correct post root and passes verify. The anchor
    /// also fails fast, before any replay work, with the precise pre-root diagnosis rather
    /// than a post-root error that reads like a replay fault.
    pub parent_anchor: Option<ParentAnchor>,
}

/// The parent block's post-root pair that [`validate_block_deriving_updates`] anchors the witnesses
/// to — the same `(state root, withdrawals root)` pair the standalone pipeline's continuity
/// check enforces between consecutive blocks.
///
/// The pair is anchored atomically: real callers take both roots from the same parent header
/// (or stored block meta) and never hold one without the other, so there is deliberately no
/// way to anchor half of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentAnchor {
    /// The parent block's post state root, matched against the SALT witness's own root.
    pub state_root: B256,
    /// The parent block's post withdrawals root, matched against the MPT witness's storage
    /// root.
    pub withdrawals_root: B256,
}

impl ValidationOptions {
    /// Anchors both witnesses to the parent block's post-root pair — the standard way to
    /// build the options (see [`Self::parent_anchor`]).
    pub fn anchored(state_root: B256, withdrawals_root: B256) -> Self {
        Self { parent_anchor: Some(ParentAnchor { state_root, withdrawals_root }) }
    }

    /// No parent anchoring: the returned updates are bound to the canonical chain only by
    /// the caller's own changeset comparison. Reserve this for callers that genuinely lack
    /// a parent header — skipping the anchor is deliberately spelled out, never a default.
    pub fn unanchored() -> Self {
        Self { parent_anchor: None }
    }
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
        block_env
            .set_blob_excess_gas_and_price(excess_blob_gas, BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN);
    }

    EvmEnv::new(cfg_env, block_env)
}

/// The assembled per-block execution environment — [`create_block_execution_env`]'s output,
/// named so the assembled shape is spelled once and callers hold one value instead of
/// respelling the factory's generics.
pub struct BlockExecutionEnv<ENV> {
    /// EVM configuration + block environment.
    pub evm_env: EvmEnv<MegaSpecId>,
    /// Block executor factory wired with the chain spec and the external-env factory.
    pub executor_factory:
        MegaBlockExecutorFactory<ChainSpec, MegaEvmFactory<ENV>, OpAlloyReceiptBuilder>,
    /// Execution context carrying parent linkage, extra data, and the hardfork-derived
    /// [`BlockLimits`].
    pub ctx: MegaBlockExecutionCtx,
}

/// The block executor [`BlockExecutionEnv::start_executor_with_inspector`] produces: a
/// [`MegaBlockExecutor`] over the caller's `state` and `inspector`, wired to the env's
/// external-env factory.
pub type EnvExecutor<'a, DB, I, ENV> = MegaBlockExecutor<
    ChainSpec,
    MegaEvm<&'a mut State<DB>, I, <ENV as ExternalEnvFactory>::EnvTypes>,
    OpAlloyReceiptBuilder,
>;

impl<ENV> BlockExecutionEnv<ENV>
where
    ENV: ExternalEnvFactory + Clone,
{
    /// Creates a block executor over `state` with `inspector` and applies the pre-execution
    /// changes — the executor prologue shared by every tracing dispatch arm (validation's
    /// transaction replay runs the same prologue inline). Living here, the executor's
    /// concrete type is spelled once next to the env that produces it; callers bind the
    /// result by inference.
    pub fn start_executor_with_inspector<'a, DB, I>(
        &self,
        state: &'a mut State<DB>,
        inspector: I,
    ) -> Result<EnvExecutor<'a, DB, I, ENV>, ValidationError>
    where
        DB: alloy_evm::Database + 'a,
        I: revm::Inspector<MegaContext<&'a mut State<DB>, ENV::EnvTypes>> + 'a,
    {
        let mut executor = self.executor_factory.create_executor_with_inspector(
            state,
            self.ctx.clone(),
            self.evm_env.clone(),
            inspector,
        );
        executor.apply_pre_execution_changes().map_err(ValidationError::BlockReplayFailed)?;
        Ok(executor)
    }
}

/// Builds the full mega-evm execution environment for one block: the [`EvmEnv`], the block
/// executor factory, and the execution context carrying the hardfork-derived [`BlockLimits`].
///
/// This is the single home of the hardfork → limits mapping, shared by [`replay_block`] and
/// the debug-trace-server's tracing executor, so validation and tracing cannot drift apart.
/// Without an active MegaETH hardfork the limits fall back to unlimited *except* the header's
/// own gas limit — execution enforces the block's declared gas ceiling either way.
pub fn create_block_execution_env<ENV>(
    chain_spec: &ChainSpec,
    header: &alloy_consensus::Header,
    ext_env: ENV,
) -> BlockExecutionEnv<ENV>
where
    ENV: ExternalEnvFactory + Clone,
{
    let evm_env = create_evm_env(header, chain_spec);
    let executor_factory = MegaBlockExecutorFactory::new(
        chain_spec.clone(),
        MegaEvmFactory::new().with_external_env_factory(ext_env),
        OpAlloyReceiptBuilder::default(),
    );

    let block_limits = if let Some(hardfork) = chain_spec.hardfork(header.timestamp) {
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

    BlockExecutionEnv { evm_env, executor_factory, ctx: execution_context }
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
    ///
    /// Callers must check [`Self::is_complete`] first: an incomplete block yields an empty
    /// iterator here, not an error.
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
    debug!(
        block_number = header.number,
        block_hash = ?block.block_hash(),
        hardfork = ?chain_spec.hardfork(header.timestamp),
        "Replay block"
    );
    let BlockExecutionEnv { evm_env, executor_factory, ctx: execution_context } =
        create_block_execution_env(chain_spec, header, env_oracle);

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

/// Extracts the withdrawal-contract storage updates (only changed slots) from the replayed
/// accounts, keyed by the hashed slot as [`MptWitness::verify`] expects.
fn withdrawal_storage(accounts: &HashMap<Address, BundleAccount>) -> B256Map<U256> {
    accounts
        .get(&ADDRESS_L2_TO_L1_MESSAGE_PASSER)
        .map(|a| {
            a.storage
                .iter()
                .filter(|(_, v)| v.previous_or_original_value != v.present_value)
                .map(|(&slot, v)| (keccak256(B256::from(slot)), v.present_value))
                .collect()
        })
        .unwrap_or_default()
}

/// Derives the canonical SALT [`StateUpdates`] for a block from the replayed account states,
/// by flattening Revm's `BundleAccount` format into plain key-value pairs and applying them to
/// an ephemeral SALT state built over the witness.
///
/// The result is the net `{key ↦ (old, new)}` map between the block's pre- and post-states —
/// the same map the SALT trie update consumes and the sequencer's `SaltDeltas` are derived from.
fn derive_state_updates(
    witness: &Witness,
    accounts: HashMap<Address, BundleAccount>,
) -> Result<StateUpdates, ValidationError> {
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
    let mut witness_state = EphemeralSaltState::new(witness);
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

    Ok(state_updates)
}

/// Verifies the replayed block's outputs against the header's claims: the withdrawals root
/// (via the MPT witness over the changed withdrawal-contract slots), the receipts root, the
/// logs bloom, and the total gas used.
fn verify_replay_outputs(
    header: &alloy_consensus::Header,
    output: &BlockExecutionOutput,
    withdrawal_storage: B256Map<U256>,
    mpt_witness: &MptWitness,
) -> Result<(), ValidationError> {
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

    Ok(())
}

/// Runs the fallible `f` and returns its success value together with the elapsed wall-clock
/// seconds — `0.0` in `no_std` builds, where no monotonic clock is available ("not
/// measured"). On error the elapsed time is discarded with the stage's result.
fn timed<T, E>(f: impl FnOnce() -> Result<T, E>) -> Result<(T, f64), E> {
    #[cfg(feature = "std")]
    let start = Instant::now();
    let result = f()?;
    #[cfg(feature = "std")]
    let elapsed = start.elapsed().as_secs_f64();
    #[cfg(not(feature = "std"))]
    let elapsed = 0.0_f64;
    Ok((result, elapsed))
}

/// Output of [`verify_and_replay`], the stages shared by [`validate_block`] and
/// [`validate_block_deriving_updates`].
struct VerifiedReplay {
    /// The proof-verified witness the block was replayed over.
    witness: Witness,
    /// Net per-account state changes from the replay.
    accounts: HashMap<Address, BundleAccount>,
    /// Execution outputs claimed by the header, plus state access counts.
    output: BlockExecutionOutput,
    /// Stats for the completed stages; [`ValidationStats::salt_update_time`] is left `0.0`
    /// for the caller's own final stage.
    stats: ValidationStats,
}

/// Verifies the witness IPA proof and replays the block's transactions over it — the front
/// half shared by [`validate_block`] and [`validate_block_deriving_updates`]. Callers gate on
/// [`BlockInput::is_complete`] first.
fn verify_and_replay<B: BlockInput>(
    chain_spec: &ChainSpec,
    block: &B,
    salt_witness: SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
    #[cfg(feature = "std")] writer: Option<Box<dyn Write>>,
) -> Result<VerifiedReplay, ValidationError> {
    let header = block.consensus_header();

    // Create external environment oracle from salt witness
    let ext_env = WitnessExternalEnv::new(&salt_witness, header.number)
        .map_err(ValidationError::EnvOracleConstructionFailed)?;

    // Verify witness proof against its internal state root
    let (witness, witness_verification_time) = timed(|| {
        let witness = Witness::from(salt_witness);
        witness.verify().map_err(ValidationError::WitnessVerificationFailed)?;
        Ok::<_, ValidationError>(witness)
    })?;

    // Replay block transactions
    let ((accounts, output), block_replay_time) = timed(|| {
        let witness_db = WitnessDatabase { header, witness: &witness, contracts };
        replay_block(
            chain_spec,
            block,
            &witness_db,
            ext_env,
            #[cfg(feature = "std")]
            writer,
        )
    })?;

    let stats = ValidationStats {
        state_reads: output.state_reads,
        state_writes: output.state_writes,
        witness_verification_time,
        block_replay_time,
        salt_update_time: 0.0,
    };
    Ok(VerifiedReplay { witness, accounts, output, stats })
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
    contracts: &HashMap<B256, Bytecode>,
    #[cfg(feature = "std")] writer: Option<Box<dyn Write>>,
) -> Result<ValidationStats, ValidationError> {
    // A block carrying only transaction hashes can't be replayed — fail fast before paying
    // the witness proof verification. `replay_block` re-checks for direct callers.
    if !block.is_complete() {
        return Err(ValidationError::BlockIncomplete);
    }
    let header = block.consensus_header();

    // Verify the witness proof and replay the block's transactions over it
    let VerifiedReplay { witness, accounts, output, mut stats } = verify_and_replay(
        chain_spec,
        block,
        salt_witness,
        contracts,
        #[cfg(feature = "std")]
        writer,
    )?;

    // Extract and hash storage updates (only changed values)
    let withdrawal_storage = withdrawal_storage(&accounts);

    // Derive the net SALT state updates from the replayed accounts and roll them into the
    // trie to compute the post state root
    let (state_root, salt_update_time) = timed(|| {
        let state_updates = derive_state_updates(&witness, accounts)?;
        let (state_root, _) = StateRoot::new(&witness)
            .update_fin(&state_updates)
            .map_err(ValidationError::TrieUpdateFailed)?;
        Ok::<_, ValidationError>(state_root)
    })?;
    stats.salt_update_time = salt_update_time;

    // Verify the replayed outputs against the header's claims
    verify_replay_outputs(header, &output, withdrawal_storage, &mpt_witness)?;

    // Check if computed state root matches claimed state root
    let state_root = B256::from(state_root);
    if state_root != header.state_root {
        return Err(ValidationError::StateRootMismatch {
            actual: state_root,
            claimed: header.state_root,
        });
    }

    Ok(stats)
}

/// Validates a block by replaying its transactions over the witness and returning the derived
/// SALT [`StateUpdates`] instead of computing the post state root.
///
/// This is the entry point for embedders that already hold an independently verified per-block
/// changeset for the same block (e.g. a MegaETH full node, whose state sync persists the
/// sequencer's hash-verified `SaltDeltas`): comparing the returned net update map against that
/// changeset replaces the SALT trie/commitment recompute that [`validate_block`] performs.
///
/// Differences from [`validate_block`]:
/// - Returns the replay-derived [`StateUpdates`] (the net `{key ↦ (old, new)}` map between the
///   block's pre- and post-states); **no post state root is computed or checked** — the caller owns
///   that comparison. The map carries account and storage records only: newly deployed bytecode is
///   not derivable from it, so a changeset comparison does not cover the embedder's `codes` and
///   bytecode integrity must be enforced at ingest.
/// - [`ValidationOptions::parent_anchor`], when provided, is checked against both witnesses' own
///   pre-roots before any other work, anchoring them to the canonical parent block — see its field
///   docs for what each half binds and which error it raises.
///
/// Both witness proofs (the SALT witness's IPA proof before replay, the MPT witness's Merkle
/// proof on the replay outputs) are always verified, exactly as in [`validate_block`].
/// On success, [`ValidationStats::salt_update_time`] holds the state-update derivation time
/// (there is no trie update here).
pub fn validate_block_deriving_updates<B: BlockInput>(
    chain_spec: &ChainSpec,
    block: &B,
    salt_witness: SaltWitness,
    mpt_witness: MptWitness,
    contracts: &HashMap<B256, Bytecode>,
    options: ValidationOptions,
    #[cfg(feature = "std")] writer: Option<Box<dyn Write>>,
) -> Result<(StateUpdates, ValidationStats), ValidationError> {
    // A block carrying only transaction hashes can't be replayed — fail fast before paying
    // the witness proof verification. `replay_block` re-checks for direct callers.
    if !block.is_complete() {
        return Err(ValidationError::BlockIncomplete);
    }
    let header = block.consensus_header();

    // Anchor both witnesses to the canonical parent block before any other work.
    if let Some(anchor) = options.parent_anchor {
        let actual = B256::from(
            salt_witness.state_root().map_err(ValidationError::WitnessVerificationFailed)?,
        );
        if actual != anchor.state_root {
            return Err(ValidationError::PreStateRootMismatch {
                expected: anchor.state_root,
                actual,
            });
        }
        if mpt_witness.storage_root != anchor.withdrawals_root {
            return Err(ValidationError::PreWithdrawalsRootMismatch {
                expected: anchor.withdrawals_root,
                actual: mpt_witness.storage_root,
            });
        }
    }

    // Verify the witness proof and replay the block's transactions over it
    let VerifiedReplay { witness, accounts, output, mut stats } = verify_and_replay(
        chain_spec,
        block,
        salt_witness,
        contracts,
        #[cfg(feature = "std")]
        writer,
    )?;

    // Check the header's claims (withdrawals root, receipts root, logs bloom, gas used)
    // before the more expensive state-update derivation.
    verify_replay_outputs(header, &output, withdrawal_storage(&accounts), &mpt_witness)?;

    // Derive the net SALT state updates from the replayed accounts
    let (state_updates, salt_update_time) = timed(|| derive_state_updates(&witness, accounts))?;
    stats.salt_update_time = salt_update_time;

    Ok((state_updates, stats))
}

#[cfg(test)]
mod tests {
    use salt::METADATA_KEYS_RANGE;
    use stateless_test_utils::{fixtures::TestFixtures, logging::init_test_logging};

    use super::*;

    /// Chain spec for the mainnet fixtures. Parsed per call: the 1.8 KB genesis is noise
    /// next to the witness work every caller performs, and a memoizing `static` would need
    /// real-std machinery (`LazyLock`) that `no_std` test builds cannot name (see lib.rs).
    fn chain_spec() -> ChainSpec {
        ChainSpec::from_genesis(TestFixtures::mainnet_shared().load_genesis().unwrap())
    }

    /// Runs [`validate_block_deriving_updates`] for one fixture block over the given witness.
    fn run_updates(
        fx: &TestFixtures,
        block: &Block<OpTransaction>,
        salt_witness: SaltWitness,
        hash: B256,
        options: ValidationOptions,
    ) -> Result<(StateUpdates, ValidationStats), ValidationError> {
        validate_block_deriving_updates(
            &chain_spec(),
            block,
            salt_witness,
            fx.mpt_witness(&hash),
            &fx.contracts,
            options,
            #[cfg(feature = "std")]
            None,
        )
    }

    /// Runs [`validate_block`] for one fixture block over the given witness.
    fn run_block(
        fx: &TestFixtures,
        block: &Block<OpTransaction>,
        salt_witness: SaltWitness,
        hash: B256,
    ) -> Result<ValidationStats, ValidationError> {
        validate_block(
            &chain_spec(),
            block,
            salt_witness,
            fx.mpt_witness(&hash),
            &fx.contracts,
            #[cfg(feature = "std")]
            None,
        )
    }

    /// Empty-witness external env for tests that only exercise environment assembly.
    fn empty_ext_env(block_number: u64) -> WitnessExternalEnv {
        WitnessExternalEnv::from_light_witness(&crate::LightWitness::default(), block_number)
            .unwrap()
    }

    /// Without an active MegaETH hardfork, `create_block_execution_env` must still cap
    /// execution by the header's own gas limit (everything else unlimited). The trace server
    /// once drifted to fully-unlimited on this branch; both binaries now share this mapping.
    #[test]
    fn execution_env_no_hardfork_fallback_caps_block_gas() {
        let header =
            alloy_consensus::Header { gas_limit: 12_345, ..alloy_consensus::Header::default() };
        // `ChainSpec::default()` schedules no hardforks → the fallback branch.
        let ctx = create_block_execution_env(
            &ChainSpec::default(),
            &header,
            empty_ext_env(header.number),
        )
        .ctx;
        assert_eq!(
            ctx.block_limits,
            BlockLimits::no_limits().with_block_gas_limit(12_345),
            "fallback limits must be unlimited except the header's own gas limit",
        );
    }

    /// With an active hardfork, the limits must be exactly the hardfork-derived set.
    #[test]
    fn execution_env_uses_hardfork_limits_when_active() {
        let spec = chain_spec();
        // Far-future timestamp: every hardfork scheduled by the fixture genesis is active.
        let header = alloy_consensus::Header {
            timestamp: u64::MAX,
            gas_limit: 30_000_000,
            ..alloy_consensus::Header::default()
        };
        let hardfork =
            spec.hardfork(header.timestamp).expect("fixture genesis schedules hardforks");
        let ctx = create_block_execution_env(&spec, &header, empty_ext_env(header.number)).ctx;
        assert_eq!(
            ctx.block_limits,
            BlockLimits::from_hardfork_and_block_gas_limit(hardfork, header.gas_limit),
        );
    }

    /// `start_executor_with_inspector` is the executor prologue shared with the trace
    /// server's dispatch arms; run it over an empty state from core's own tests so the
    /// wiring (executor construction + pre-execution changes) is exercised here, not only
    /// through the trace-server binary.
    #[test]
    fn execution_env_starts_executor_with_inspector() {
        // Far-future timestamp: the fixture genesis's hardforks (incl. Regolith, which
        // mega-evm asserts is active) are all in effect.
        let header = alloy_consensus::Header {
            timestamp: u64::MAX,
            gas_limit: 30_000_000,
            // Post-Cancun headers must carry it; the EIP-4788 pre-execution call reads it.
            parent_beacon_block_root: Some(B256::ZERO),
            ..alloy_consensus::Header::default()
        };
        let env = create_block_execution_env(&chain_spec(), &header, empty_ext_env(header.number));
        let mut state = StateBuilder::new()
            .with_database_ref(revm::database::EmptyDB::default())
            .with_bundle_update()
            .build();
        let executor = env
            .start_executor_with_inspector(&mut state, revm::inspector::NoOpInspector)
            .expect("executor prologue over an empty state must succeed");
        drop(executor);
    }

    /// The fixture witness for `hash` with the first byte of one witnessed (non-metadata)
    /// value flipped, re-encoded through [`SaltValue::new`] so the entry stays structurally
    /// valid and nothing short of the proof check can notice.
    fn tampered_witness(fx: &TestFixtures, hash: B256) -> SaltWitness {
        let mut salt_witness = fx.salt_witnesses[&hash].clone();
        let value = salt_witness
            .kvs
            .iter_mut()
            .filter(|(key, _)| !METADATA_KEYS_RANGE.contains(key))
            .find_map(|(_, value)| value.as_mut().filter(|v| !v.value().is_empty()))
            .expect("fixture witness must hold a non-metadata value");
        let key = value.key().to_vec();
        let mut tampered = value.value().to_vec();
        tampered[0] ^= 0x01;
        *value = SaltValue::new(&key, &tampered);
        salt_witness
    }

    /// The first paired fixture block with its transactions stripped down to hashes only.
    fn hashes_only_block(fx: &TestFixtures) -> (B256, Block<OpTransaction>) {
        let (_, hash) = *fx.paired_blocks().first().expect("paired mainnet fixtures");
        let mut block = fx.blocks[&hash].clone();
        block.transactions = BlockTransactions::Hashes(Default::default());
        (hash, block)
    }

    /// Asserts that replay-derived `updates` reproduce the block header's state root when fed
    /// through the SALT trie update (read directly off the borrowed witness).
    fn assert_updates_reproduce_state_root(
        salt_witness: &SaltWitness,
        updates: &StateUpdates,
        block: &Block<OpTransaction>,
        number: u64,
        hash: B256,
    ) {
        let (state_root, _) = StateRoot::new(salt_witness)
            .update_fin(updates)
            .unwrap_or_else(|e| panic!("trie update failed for {number} ({hash}): {e:?}"));
        assert_eq!(
            B256::from(state_root),
            block.consensus_header().state_root,
            "updates from {number} ({hash}) must reproduce the header state root"
        );
    }

    /// Locks the `BlockInput` projection for RPC blocks: completeness, hash/header passthrough,
    /// and clone-free recovered senders (including the empty projection of a hashes-only block).
    #[test]
    fn block_input_projection_for_rpc_block() {
        let fx = TestFixtures::mainnet_shared();
        let (number, hash) = *fx.paired_blocks().first().expect("paired mainnet fixtures");
        let block = &fx.blocks[&hash];

        assert!(block.is_complete());
        assert_eq!(BlockInput::block_hash(block), hash);
        assert_eq!(block.consensus_header().number, number);

        let BlockTransactions::Full(txs) = &block.transactions else {
            panic!("fixture block must carry full transactions");
        };
        assert_eq!(block.txs_recovered().count(), txs.len());
        for (recovered, tx) in block.txs_recovered().zip(txs) {
            assert_eq!(
                recovered.signer(),
                tx.inner.inner.signer(),
                "borrowed projection must keep the RPC-recovered sender"
            );
        }

        let mut hashes_only = block.clone();
        hashes_only.transactions = BlockTransactions::Hashes(Default::default());
        assert!(!hashes_only.is_complete());
        assert_eq!(hashes_only.txs_recovered().count(), 0);
    }

    /// A block carrying only transaction hashes must be rejected as `BlockIncomplete` by the
    /// `is_complete()` gate before any witness verification or replay work.
    #[test]
    fn validate_block_rejects_hashes_only_block() {
        let fx = TestFixtures::mainnet_shared();
        let (hash, block) = hashes_only_block(fx);

        let err = run_block(fx, &block, fx.salt_witnesses[&hash].clone(), hash).unwrap_err();
        assert!(matches!(err, ValidationError::BlockIncomplete), "{err:?}");
    }

    #[test]
    fn validate_block_mainnet_fixtures() {
        let _logging = init_test_logging("stateless_core");
        let fx = TestFixtures::mainnet_shared();
        let paired = fx.paired_blocks();
        assert!(!paired.is_empty(), "no paired mainnet fixtures in test_data/mainnet");
        for (number, hash) in paired {
            let block = &fx.blocks[&hash];
            run_block(fx, block, fx.salt_witnesses[&hash].clone(), hash)
                .unwrap_or_else(|e| panic!("validate_block failed for {number} ({hash}): {e:?}"));
        }
    }

    /// `validate_block_deriving_updates` must succeed on every paired mainnet fixture — anchored to
    /// the parent whenever it is in the fixture set, the embedder's real call shape — and the
    /// returned updates must reproduce the header's state root when fed through the SALT trie
    /// update, locking its equivalence with the `validate_block` path the helpers were
    /// extracted from.
    #[test]
    fn validate_block_deriving_updates_mainnet_fixtures() {
        let _logging = init_test_logging("stateless_core");
        let fx = TestFixtures::mainnet_shared();
        let paired = fx.paired_blocks();
        assert!(!paired.is_empty(), "no paired mainnet fixtures in test_data/mainnet");
        for (number, hash) in paired {
            let block = &fx.blocks[&hash];
            let options = match fx.blocks.get(&block.consensus_header().parent_hash) {
                Some(parent) => ValidationOptions::anchored(
                    parent.header.inner.state_root,
                    parent.header.inner.withdrawals_root.unwrap_or_else(|| {
                        panic!("parent of {number} ({hash}) lacks a withdrawals root")
                    }),
                ),
                None => ValidationOptions::unanchored(),
            };
            let (updates, stats) =
                run_updates(fx, block, fx.salt_witnesses[&hash].clone(), hash, options)
                    .unwrap_or_else(|e| {
                        panic!(
                            "validate_block_deriving_updates failed for {number} ({hash}): {e:?}"
                        )
                    });
            // `no_std` builds have no monotonic clock — every timing reads 0.0 ("not measured"),
            // so the timed-verification expectation only holds with `std` enabled.
            assert!(
                stats.witness_verification_time > 0.0 || cfg!(not(feature = "std")),
                "witness verification must be timed in std builds"
            );

            // Cross-check: the returned updates must yield the header's state root.
            assert_updates_reproduce_state_root(
                &fx.salt_witnesses[&hash],
                &updates,
                block,
                number,
                hash,
            );
        }
    }

    /// The parent anchor must match the parent header's post-root pair on every paired
    /// fixture, and reject a mismatch on either half with that half's error — before any
    /// witness verification or replay work.
    #[test]
    fn validate_block_deriving_updates_anchors_to_parent() {
        let fx = TestFixtures::mainnet_shared();

        // Every paired fixture witness must carry the parent header's post-root pair — the
        // exact values the anchor compares. Near-free: no validation runs; the anchored
        // accept path is exercised by `validate_block_deriving_updates_mainnet_fixtures`.
        let mut anchored = None;
        for (number, hash) in fx.paired_blocks() {
            let block = &fx.blocks[&hash];
            let Some(parent) = fx.blocks.get(&block.consensus_header().parent_hash) else {
                continue;
            };

            let state_root = parent.header.inner.state_root;
            let withdrawals_root =
                parent.header.inner.withdrawals_root.unwrap_or_else(|| {
                    panic!("parent of {number} ({hash}) lacks a withdrawals root")
                });
            assert_eq!(
                B256::from(fx.salt_witnesses[&hash].state_root().unwrap()),
                state_root,
                "witness root for {number} ({hash}) must be the parent's post state root"
            );
            assert_eq!(
                fx.mpt_witness::<MptWitness>(&hash).storage_root,
                withdrawals_root,
                "MPT witness root for {number} ({hash}) must be the parent's post withdrawals root"
            );
            anchored.get_or_insert((hash, state_root, withdrawals_root));
        }
        let Some((hash, state_root, withdrawals_root)) = anchored else {
            panic!("no fixture block has its parent in the set — anchor untested");
        };
        let block = &fx.blocks[&hash];

        // Reject each mismatched half with its own exactly-field-checked error. The witness
        // is tampered (it would fail proof verification), so the anchor error surfacing at
        // all also proves the anchor runs before any proof or replay work — its fail-fast
        // contract.
        let bogus = B256::repeat_byte(0xAB);
        let options = ValidationOptions::anchored(bogus, withdrawals_root);
        let err = run_updates(fx, block, tampered_witness(fx, hash), hash, options).unwrap_err();
        match err {
            ValidationError::PreStateRootMismatch { expected, actual } => {
                assert_eq!(expected, bogus);
                assert_eq!(actual, state_root);
            }
            other => panic!("expected PreStateRootMismatch, got {other:?}"),
        }

        // The matching state half must pass through to the withdrawals check.
        let options = ValidationOptions::anchored(state_root, bogus);
        let err = run_updates(fx, block, tampered_witness(fx, hash), hash, options).unwrap_err();
        match err {
            ValidationError::PreWithdrawalsRootMismatch { expected, actual } => {
                assert_eq!(expected, bogus);
                assert_eq!(actual, withdrawals_root);
            }
            other => panic!("expected PreWithdrawalsRootMismatch, got {other:?}"),
        }
    }

    /// A block carrying only transaction hashes must be rejected as `BlockIncomplete` before
    /// the parent anchor or any witness work.
    #[test]
    fn validate_block_deriving_updates_rejects_hashes_only_block() {
        let fx = TestFixtures::mainnet_shared();
        let (hash, block) = hashes_only_block(fx);

        let witness = fx.salt_witnesses[&hash].clone();
        let err =
            run_updates(fx, &block, witness, hash, ValidationOptions::unanchored()).unwrap_err();
        assert!(matches!(err, ValidationError::BlockIncomplete), "{err:?}");
    }

    /// Corrupting a single witnessed value must fail both entry points with
    /// `WitnessVerificationFailed` — the IPA proof check is unconditional, with no knob to
    /// skip it.
    #[test]
    fn tampered_witness_fails_proof_verification() {
        let fx = TestFixtures::mainnet_shared();
        let (_, hash) = *fx.paired_blocks().first().expect("paired mainnet fixtures");
        let block = &fx.blocks[&hash];

        let tampered = tampered_witness(fx, hash);
        let err =
            run_updates(fx, block, tampered, hash, ValidationOptions::unanchored()).unwrap_err();
        assert!(matches!(err, ValidationError::WitnessVerificationFailed(_)), "{err:?}");

        let err = run_block(fx, block, tampered_witness(fx, hash), hash).unwrap_err();
        assert!(matches!(err, ValidationError::WitnessVerificationFailed(_)), "{err:?}");
    }
}
