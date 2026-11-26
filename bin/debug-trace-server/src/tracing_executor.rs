//! Tracing Executor for Debug and Trace RPC Methods
//!
//! This module provides tracing capabilities for block and transaction execution,
//! enabling the `debug_*` and `trace_*` RPC methods in the debug-trace-server.
//!
//! # Architecture
//! The tracing executor uses a witness-backed database to replay transactions
//! without requiring access to the full state database. This enables:
//! - Historical block tracing at any height
//! - Stateless execution using SALT witness data
//! - Support for multiple tracer types (Geth and Parity styles)
//!
//! # Supported Tracer Types
//! ## Geth-style (debug_* methods)
//! - `CallTracer` - Nested call frame traces
//! - `PreStateTracer` - Pre/post state diff
//! - `FourByteTracer` - Function selector statistics
//! - `NoopTracer` - No-op for testing
//! - `MuxTracer` - Multiple tracers combined
//! - `FlatCallTracer` - Flat call traces
//! - `JsTracer` - Custom JavaScript tracers
//! - Default struct logger - Detailed opcode-level traces
//!
//! ## Parity-style (trace_* methods)
//! - `LocalizedTransactionTrace` - Flat call traces with block/tx context

use alloy_consensus::{Transaction, transaction::Recovered};
use alloy_evm::{Evm as EvmTrait, block::BlockExecutor};
use alloy_primitives::{B256, map::HashMap};
use alloy_rpc_types_eth::{Block, BlockTransactions, TransactionInfo};
use alloy_rpc_types_trace::{
    geth::{
        FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType,
        GethDebugTracingOptions, GethTrace, NoopFrame, TraceResult,
        mux::MuxConfig,
        pre_state::{AccountState, PreStateConfig, PreStateFrame},
    },
    parity::LocalizedTransactionTrace,
};
use eyre::Result;
use mega_evm::{ExternalEnvFactory, MegaTransaction};
use op_alloy_consensus::OpTxEnvelope;
use op_alloy_network::TransactionResponse;
use op_alloy_rpc_types::Transaction as OpTransaction;
use revm::{
    DatabaseCommit, DatabaseRef,
    context::TxEnv,
    context_interface::{
        Block as BlockEnvTr, ContextTr,
        result::{HaltReasonTr, ResultAndState},
    },
    database::{CacheDB, State},
    handler::EvmTr,
    inspector::NoOpInspector,
    state::{Bytecode, EvmState},
};
use revm_inspectors::tracing::{
    DebugInspector, DebugInspectorError, FourByteInspector, MuxInspector, TracingInspector,
    TracingInspectorConfig, TransactionContext, js::JsInspector,
};
use stateless_core::{
    chain_spec::ChainSpec,
    evm_database::{WitnessDatabase, WitnessExternalEnv},
    executor::{BlockExecutionEnv, ValidationError, create_block_execution_env},
    light_witness::{LightWitness, LightWitnessExecutor},
};
use tracing::{instrument, trace, warn};

/// Returns distinct contract code hashes referenced by the witness, sorted for stable ordering.
pub fn extract_code_hashes(witness: &LightWitness) -> Vec<B256> {
    stateless_core::collect_code_hashes(&witness.kvs)
}

// TracerKind - Unified enum for TracingInspector-based tracers
/// Represents a tracer variant that uses `TracingInspector` under the hood.
///
/// Unifies PreStateTracer and the default struct logger to reduce code duplication in
/// `trace_block` and `trace_transaction`. The call, flat-call and mux tracers render through
/// [`DebugInspector`] instead, see [`debug_inspector_result`].
enum TracerKind {
    PreState(PreStateConfig),
    Default(GethDebugTracingOptions),
}

impl TracerKind {
    fn inspector_config(&self) -> TracingInspectorConfig {
        match self {
            Self::PreState(cfg) => TracingInspectorConfig::from_geth_prestate_config(cfg),
            Self::Default(opts) => TracingInspectorConfig::from_geth_config(&opts.config),
        }
    }

    fn create_inspector(&self) -> TracingInspector {
        TracingInspector::new(self.inspector_config())
    }
}

// Fast Tracing Environment Setup (for LightWitness)
/// Pre-built execution environment for fast tracing operations.
struct TracingEnv<'a> {
    transactions: &'a [OpTransaction],
    /// Shared with `replay_block`: the same env, factory, hardfork → limits mapping, and
    /// extra_data (system transactions) the validator executes with.
    exec: BlockExecutionEnv<WitnessExternalEnv>,
    /// Witness DB built from the consensus header of the block this env was built from —
    /// the single projection point, so it can never be paired with a different block's header.
    db: WitnessDatabase<'a, LightWitnessExecutor>,
}

impl<'a> TracingEnv<'a> {
    fn new(
        chain_spec: &ChainSpec,
        block: &'a Block<OpTransaction>,
        witness: &'a LightWitnessExecutor,
        contracts: &'a HashMap<B256, Bytecode>,
    ) -> Result<Self, ValidationError> {
        let BlockTransactions::Full(transactions) = &block.transactions else {
            return Err(ValidationError::BlockIncomplete);
        };

        let ext_env =
            WitnessExternalEnv::from_light_witness(witness.light_witness(), block.header.number)
                .map_err(ValidationError::EnvOracleConstructionFailed)?;

        let exec = create_block_execution_env(chain_spec, &block.header.inner, ext_env);

        let db = WitnessDatabase { header: &block.header.inner, witness, contracts };

        Ok(Self { transactions, exec, db })
    }
}

fn tx_info_at(block: &Block<OpTransaction>, tx: &OpTransaction, index: usize) -> TransactionInfo {
    TransactionInfo {
        hash: Some(tx.inner.tx_hash()),
        index: Some(index as u64),
        block_hash: Some(block.header.hash),
        block_number: Some(block.header.number),
        base_fee: block.header.base_fee_per_gas,
        block_timestamp: Some(block.header.timestamp),
    }
}

/// Why a trace failed — the discriminant the RPC layer keys cache hygiene off.
///
/// Only [`Self::Data`] may evict the block's entry from the block-data cache: the block's
/// witness/env failed to replay, so the cached data itself is bad and must be refetched.
/// [`Self::Request`] failures (invalid tracer configs, tracer construction or output
/// errors) say nothing about the data — evicting on them would let any client drop hot
/// entries at will with one cheap invalid request, since mux/JS shapes bypass the
/// response cache.
#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    /// The request is at fault; the block data is fine.
    #[error("{0}")]
    Request(String),
    /// The block's data failed to replay (bad or incomplete witness, env mismatch).
    #[error(transparent)]
    Data(#[from] ValidationError),
}

/// Request-attributable error: tracer config parsing, inspector construction, or tracer
/// output — nothing about the block's data. New sites pick a constructor by failure kind
/// instead of hand-assembling a [`TraceError`] variant.
fn request_error(context: &str, e: impl std::fmt::Debug) -> TraceError {
    TraceError::Request(format!("{context}: {e:?}"))
}

/// Data-attributable error for a trace frame that failed to build: the prestate/mux frame
/// builders fail only on witness/DB reads (`DB::Error`), so a failure indicates bad block
/// data just like a replay failure.
fn frame_build_error(context: &str, e: impl std::fmt::Debug) -> ValidationError {
    ValidationError::BlockReplayFailed(alloy_evm::block::BlockExecutionError::msg(format!(
        "{context}: {e:?}"
    )))
}

/// Logs and types a per-transaction replay failure. A canonical block's transactions
/// always execute (reverts included) against correct state, so a replay failure means the
/// witness/env data is bad — callers abort the trace with this data-attributable error so
/// the RPC layer drops the poisoned data, instead of returning a cacheable `Ok` full of
/// `TraceResult::Error` entries.
fn tx_replay_failure(
    index: usize,
    tx_hash: B256,
    e: alloy_evm::block::BlockExecutionError,
) -> ValidationError {
    warn!(tx_index = index, tx_hash = %tx_hash, %e, "Transaction trace failed");
    ValidationError::BlockReplayFailed(e)
}

/// The tracer `opts` selects: `None` for the default struct logger, which an empty tracer
/// name selects as an absent one does, as in `revm-inspectors`' `DebugInspector::new`.
///
/// The one reading of `opts.tracer` for the request gate, the response-cache
/// classification and both dispatchers, so a request is classified as the tracer it runs.
pub(crate) fn requested_tracer(opts: &GethDebugTracingOptions) -> Option<&GethDebugTracerType> {
    opts.tracer.as_ref().filter(|tracer| !tracer.as_str().is_empty())
}

/// Parses the call tracer's `tracerConfig` strictly and builds its inspector, rendered
/// through [`debug_inspector_result`].
fn call_inspector(tracer_config: &GethDebugTracerConfig) -> Result<DebugInspector, TraceError> {
    let config = tracer_config
        .clone()
        .into_call_config()
        .map_err(|e| request_error("invalid callTracer tracerConfig", e))?;
    let inspector = TracingInspector::new(TracingInspectorConfig::from_geth_call_config(&config));
    Ok(DebugInspector::CallTracer(inspector, config))
}

/// Parses the flat-call tracer's `tracerConfig` strictly and builds its inspector, rendered
/// through [`debug_inspector_result`].
fn flat_call_inspector(
    tracer_config: &GethDebugTracerConfig,
) -> Result<DebugInspector, TraceError> {
    let config = tracer_config
        .clone()
        .into_flat_call_config()
        .map_err(|e| request_error("invalid flatCallTracer tracerConfig", e))?;
    let inspector = TracingInspector::new(TracingInspectorConfig::from_flat_call_config(&config));
    Ok(DebugInspector::FlatCallTracer(inspector))
}

/// Parses the mux `tracerConfig` and builds its inspector, rendered through
/// [`debug_inspector_result`] — the one home for the mux construction path shared by the
/// block and transaction dispatchers.
///
/// The inspector keeps the compiled children only, with an empty [`MuxConfig`] beside them:
/// [`DebugInspector::get_result`] renders from the compiled children, and the raw config is
/// read only by [`DebugInspector::fuse`], which this module never calls. A per-transaction copy
/// ([`fresh_inspector`]) therefore copies no child config JSON.
///
/// Defense in depth, like [`builtin_tracer_kind`]: `RequestShape::classify` already
/// rejects a mux with an unsupported child (-32602) before any block data is fetched, and
/// this rejects the `stateGasTracer` child again, which the inspector itself would
/// accept. The inspector rejects an `erc7562Tracer` child on its own.
fn mux_inspector(tracer_config: &GethDebugTracerConfig) -> Result<DebugInspector, TraceError> {
    let config = tracer_config
        .clone()
        .into_mux_config()
        .map_err(|e| request_error("invalid muxTracer tracerConfig", e))?;
    if config.0.contains_key(&GethDebugTracerType::BuiltInTracer(
        GethDebugBuiltInTracerType::StateGasTracer,
    )) {
        return Err(request_error("invalid muxTracer tracerConfig", "unsupported stateGasTracer"));
    }
    // Since alloy 2.x, an unknown tracer name inside a mux config parses (as a JS
    // tracer key) and is only rejected here by the inspector — still config-attributable,
    // so the context matches the serde-failure wording.
    let inspector = MuxInspector::try_from_config(config)
        .map_err(|e| request_error("invalid muxTracer tracerConfig", e))?;
    Ok(DebugInspector::Mux(inspector, MuxConfig::default()))
}

/// A fresh copy of `pristine`, an inspector that has traced nothing, for the next transaction.
fn fresh_inspector(pristine: &DebugInspector) -> Result<DebugInspector, TraceError> {
    pristine.try_clone().map_err(|e| request_error("tracer reset failed", e))
}

/// Renders the transaction `inspector` traced through [`DebugInspector::get_result`], as
/// the node does, given `tx_env`, the transaction environment the EVM executed.
///
/// `get_result` completes the root of each call and flat-call trace, standalone or in a mux,
/// from `tx_env`: the root reports the transaction's gas limit and caller. A transaction
/// that ran out of gas before its first frame records no root; its call trace, standalone or
/// in a mux, and its flat-call trace in a mux get one with its caller, destination and
/// `out of gas`, and its standalone flat-call trace reports its caller.
fn debug_inspector_result<DB>(
    mut inspector: DebugInspector,
    tx_env: &MegaTransaction,
    block_env: &impl BlockEnvTr,
    result_and_state: &ResultAndState<impl HaltReasonTr>,
    info: &TransactionInfo,
    mut db: DB,
) -> Result<GethTrace, TraceError>
where
    DB: DatabaseRef,
    DB::Error: std::fmt::Debug,
{
    inspector
        .get_result(Some(make_tx_ctx(info)), tx_env, block_env, result_and_state, &mut db)
        .map_err(|e| match e {
            // The frame builders fail on a database read only: the witness is at fault, as
            // on the plain prestate path.
            DebugInspectorError::Database(e) => {
                frame_build_error("trace frame creation failed", e).into()
            }
            e => request_error("trace frame creation failed", e),
        })
}

/// Parses a config-reading builtin's `tracerConfig` into its [`TracerKind`] — the one
/// home for the strict-parse contract shared by the block and transaction dispatchers.
///
/// Defense in depth: RPC handlers already reject malformed configs via
/// `RequestShape::classify` (-32602) before the executor runs, so from the current entry
/// points this rejection is unreachable — but a malformed config must never silently
/// trace with default settings if a future entry point skips the boundary gate. The
/// executor guarantees only that much: its rejection surfaces as a request-attributable
/// [`TraceError`], not as the gate's `-32602` wire code.
fn builtin_tracer_kind(
    builtin: GethDebugBuiltInTracerType,
    tracer_config: &GethDebugTracerConfig,
) -> Result<TracerKind, TraceError> {
    let config = tracer_config.clone();
    match builtin {
        GethDebugBuiltInTracerType::PreStateTracer => config
            .into_pre_state_config()
            .map(TracerKind::PreState)
            .map_err(|e| request_error("invalid prestateTracer tracerConfig", e)),
        // Unsupported: normally rejected by `RequestShape::classify` (-32602) before
        // the executor runs; the dispatchers route it here so the message has one home.
        GethDebugBuiltInTracerType::Erc7562Tracer => {
            Err(request_error("Unsupported tracer", "erc7562Tracer"))
        }
        GethDebugBuiltInTracerType::StateGasTracer => {
            Err(request_error("Unsupported tracer", "stateGasTracer"))
        }
        // Not `TracerKind` tracers: the dispatchers execute these in their own arms (call
        // via `call_inspector`, flat call via `flat_call_inspector`, mux via
        // `mux_inspector`) and never route them here; kept total — a request error rather
        // than a panic.
        GethDebugBuiltInTracerType::CallTracer |
        GethDebugBuiltInTracerType::FlatCallTracer |
        GethDebugBuiltInTracerType::FourByteTracer |
        GethDebugBuiltInTracerType::NoopTracer |
        GethDebugBuiltInTracerType::MuxTracer => {
            Err(request_error("tracer takes no typed tracerConfig here", builtin))
        }
    }
}

/// Builds a [`JsInspector`] for one transaction context (request-attributable on failure).
fn js_inspector(
    code: String,
    config: serde_json::Value,
    ctx: TransactionContext,
) -> Result<JsInspector, TraceError> {
    JsInspector::with_transaction_context(code, config, ctx)
        .map_err(|e| request_error("Failed to create JsInspector", e))
}

fn make_tx_ctx(info: &TransactionInfo) -> TransactionContext {
    TransactionContext {
        block_hash: info.block_hash,
        tx_hash: info.hash,
        tx_index: info.index.map(|i| i as usize),
    }
}

/// Replays the transactions of `transactions` preceding `tx_index` through `executor`
/// (discarding their output) so the target transaction executes against its true
/// intra-block prestate.
fn replay_preceding_txs<E>(
    executor: &mut E,
    transactions: &[OpTransaction],
    tx_index: usize,
) -> Result<(), ValidationError>
where
    E: BlockExecutor,
    for<'t> &'t Recovered<OpTxEnvelope>: alloy_evm::block::ExecutableTx<E>,
{
    for tx in transactions.iter().take(tx_index) {
        executor
            .execute_transaction(&tx.inner.inner)
            .map_err(ValidationError::BlockReplayFailed)?;
    }
    Ok(())
}

// TracingInspector-based helpers (shared by PreState and Default)
/// Extracts the traced transaction's frame from the executor's inspector — the one
/// home for the two `TracerKind` frame builders, shared by the block and
/// single-transaction paths.
///
/// Evaluates to `Result<GethTrace, ValidationError>`. Both arms leave the recorded
/// inspector in place for the caller to reset.
macro_rules! extract_trace_frame {
    ($executor:ident, $tracer:expr, $result_and_state:expr, $tx_gas_limit:expr) => {{
        let result_and_state = &$result_and_state;
        match $tracer {
            TracerKind::PreState(prestate_config) => {
                $executor.inspector_mut().set_transaction_gas_limit($tx_gas_limit);
                let frame_result = {
                    let db = $executor.evm.db();
                    let inspector = $executor.inspector();
                    inspector.geth_builder().geth_prestate_traces(
                        result_and_state,
                        prestate_config,
                        db,
                    )
                };
                match frame_result {
                    Ok(frame) => {
                        let final_frame = if prestate_config.is_diff_mode() {
                            let db = $executor.evm.db();
                            add_accessed_unchanged_accounts(frame, &result_and_state.state, db)
                        } else {
                            frame
                        };
                        Ok(GethTrace::from(final_frame))
                    }
                    Err(e) => Err(frame_build_error("PreState trace failed", e)),
                }
            }
            TracerKind::Default(opts) => {
                let gas_used = result_and_state.result.tx_gas_used();
                let return_value = result_and_state.result.output().cloned().unwrap_or_default();
                let inspector = $executor.inspector_mut();
                inspector.set_transaction_gas_limit($tx_gas_limit);
                // alloy-rpc-types-trace 2.x serializes `returnValue` with a "0x" prefix
                // on both sides, so the frame is emitted as-is (the 1.x era needed a
                // prefix-stripping shim to match mega-reth).
                Ok(GethTrace::from(inspector.geth_builder().geth_traces(
                    gas_used,
                    return_value,
                    opts.config,
                )))
            }
        }
    }};
}

/// Traces all transactions in a block using a `TracingInspector`-based tracer.
///
/// Handles executor creation, pre-execution, tx loop, trace extraction, inspector
/// reset, and state commit for any `TracerKind` variant.
fn trace_block_with_tracing_inspector(
    env: &TracingEnv<'_>,
    state: &mut State<
        revm::database::WrapDatabaseRef<&CacheDB<&WitnessDatabase<'_, LightWitnessExecutor>>>,
    >,
    tracer: &TracerKind,
) -> Result<Vec<TraceResult>, ValidationError> {
    let mut executor = env.exec.start_executor_with_inspector(state, tracer.create_inspector())?;

    let mut results = Vec::with_capacity(env.transactions.len());
    for (index, tx) in env.transactions.iter().enumerate() {
        let tx_hash = tx.inner.tx_hash();
        let recovered_tx = &tx.inner.inner;
        trace!(tx_index = index, tx_hash = %tx_hash, "Tracing transaction");

        match executor.run_transaction(recovered_tx) {
            Ok(outcome) => {
                let result_and_state = outcome.inner.result_and_state;
                let trace_result =
                    extract_trace_frame!(executor, tracer, result_and_state, tx.inner.gas_limit())?;

                results.push(TraceResult::Success { result: trace_result, tx_hash: Some(tx_hash) });

                *executor.inspector_mut() = tracer.create_inspector();
                executor.evm.db_mut().commit(result_and_state.state);
            }
            Err(e) => return Err(tx_replay_failure(index, tx_hash, e)),
        }
    }
    Ok(results)
}

/// Traces a single transaction using a `TracingInspector`-based tracer.
///
/// Creates executor, applies pre-execution, replays preceding txs (without
/// recording), installs the real tracer, runs the target tx, and extracts the trace.
fn trace_tx_with_tracing_inspector(
    env: &TracingEnv<'_>,
    state: &mut State<
        revm::database::WrapDatabaseRef<&CacheDB<&WitnessDatabase<'_, LightWitnessExecutor>>>,
    >,
    tx_index: usize,
    tracer: &TracerKind,
) -> Result<GethTrace, TraceError> {
    // Preceding transactions only rebuild state; a none-config inspector skips
    // recording their every step just to discard it.
    let mut executor = env.exec.start_executor_with_inspector(
        state,
        TracingInspector::new(TracingInspectorConfig::none()),
    )?;
    replay_preceding_txs(&mut executor, env.transactions, tx_index)?;

    *executor.inspector_mut() = tracer.create_inspector();

    let target_tx = &env.transactions[tx_index];
    let recovered_target = &target_tx.inner.inner;
    let tx_gas_limit = target_tx.inner.gas_limit();

    let outcome =
        executor.run_transaction(recovered_target).map_err(ValidationError::BlockReplayFailed)?;

    extract_trace_frame!(executor, tracer, outcome.inner.result_and_state, tx_gas_limit)
        .map_err(TraceError::from)
}

/// Traces `transactions`, the transactions of `block`, with copies of `pristine`, rendering
/// each through [`debug_inspector_result`] with the transaction environment the EVM executed,
/// which the EVM context keeps until the next transaction.
fn trace_block_with_debug_inspector<ENV, DB>(
    exec: &BlockExecutionEnv<ENV>,
    block: &Block<OpTransaction>,
    transactions: &[OpTransaction],
    state: &mut State<DB>,
    pristine: DebugInspector,
) -> Result<Vec<TraceResult>, TraceError>
where
    ENV: ExternalEnvFactory + Clone,
    DB: alloy_evm::Database + DatabaseRef,
{
    let mut executor = exec.start_executor_with_inspector(state, fresh_inspector(&pristine)?)?;

    let mut results = Vec::with_capacity(transactions.len());
    for (index, tx) in transactions.iter().enumerate() {
        let tx_hash = tx.inner.tx_hash();
        trace!(tx_index = index, tx_hash = %tx_hash, "Tracing transaction");

        let outcome = executor
            .run_transaction(&tx.inner.inner)
            .map_err(|e| tx_replay_failure(index, tx_hash, e))?;
        let result_and_state = outcome.inner.result_and_state;
        let next = if index + 1 < transactions.len() {
            fresh_inspector(&pristine)?
        } else {
            DebugInspector::Noop(NoOpInspector)
        };
        let inspector = core::mem::replace(executor.inspector_mut(), next);
        let trace = debug_inspector_result(
            inspector,
            executor.evm.ctx_ref().tx(),
            executor.evm.block(),
            &result_and_state,
            &tx_info_at(block, tx, index),
            executor.evm.db(),
        )?;
        executor.evm.db_mut().commit(result_and_state.state);
        results.push(TraceResult::Success { result: trace, tx_hash: Some(tx_hash) });
    }
    Ok(results)
}

/// Traces the transaction at `tx_index` of `transactions`, the transactions of `block`, with
/// `inspector`, after replaying the preceding transactions without recording, and renders it
/// through [`debug_inspector_result`] with the transaction environment the EVM executed.
fn trace_tx_with_debug_inspector<ENV, DB>(
    exec: &BlockExecutionEnv<ENV>,
    block: &Block<OpTransaction>,
    transactions: &[OpTransaction],
    state: &mut State<DB>,
    tx_index: usize,
    inspector: DebugInspector,
) -> Result<GethTrace, TraceError>
where
    ENV: ExternalEnvFactory + Clone,
    DB: alloy_evm::Database + DatabaseRef,
{
    let mut executor =
        exec.start_executor_with_inspector(state, DebugInspector::Noop(NoOpInspector))?;
    replay_preceding_txs(&mut executor, transactions, tx_index)?;
    *executor.inspector_mut() = inspector;

    let target_tx = &transactions[tx_index];
    let outcome = executor
        .run_transaction(&target_tx.inner.inner)
        .map_err(ValidationError::BlockReplayFailed)?;
    let result_and_state = outcome.inner.result_and_state;
    let inspector =
        core::mem::replace(executor.inspector_mut(), DebugInspector::Noop(NoOpInspector));
    debug_inspector_result(
        inspector,
        executor.evm.ctx_ref().tx(),
        executor.evm.block(),
        &result_and_state,
        &tx_info_at(block, target_tx, tx_index),
        executor.evm.db(),
    )
}

// Public API - Geth-style Tracing
/// Traces a block execution with detailed inspector data.
///
/// Uses a **single executor** for all transactions to preserve the DynamicGasCost
/// bucket cache across transactions, matching the validator's single-executor
/// behaviour.
#[instrument(skip_all, name = "trace_block", fields(block_number = block.header.number, block_hash = %block.header.hash))]
pub fn trace_block(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    witness: &LightWitnessExecutor,
    contracts: &HashMap<B256, Bytecode>,
    opts: GethDebugTracingOptions,
) -> Result<Vec<TraceResult>, TraceError> {
    let env = TracingEnv::new(chain_spec, block, witness, contracts)?;

    trace!(tx_count = env.transactions.len(), "Starting block trace");

    let cache_db = CacheDB::new(&env.db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    let tracer_config = &opts.tracer_config;

    let results = if let Some(tracer) = requested_tracer(&opts) {
        match tracer {
            GethDebugTracerType::BuiltInTracer(builtin) => match builtin {
                GethDebugBuiltInTracerType::NoopTracer => env
                    .transactions
                    .iter()
                    .map(|tx| TraceResult::Success {
                        result: GethTrace::NoopTracer(NoopFrame::default()),
                        tx_hash: Some(tx.inner.tx_hash()),
                    })
                    .collect(),

                // Strict parse in `builtin_tracer_kind` — see its doc for why the
                // executor re-rejects what the boundary gate already screens. The
                // unsupported erc7562Tracer and stateGasTracer error there before any
                // execution.
                GethDebugBuiltInTracerType::CallTracer => trace_block_with_debug_inspector(
                    &env.exec,
                    block,
                    env.transactions,
                    &mut state,
                    call_inspector(tracer_config)?,
                )?,

                GethDebugBuiltInTracerType::FlatCallTracer => trace_block_with_debug_inspector(
                    &env.exec,
                    block,
                    env.transactions,
                    &mut state,
                    flat_call_inspector(tracer_config)?,
                )?,

                GethDebugBuiltInTracerType::PreStateTracer |
                GethDebugBuiltInTracerType::StateGasTracer |
                GethDebugBuiltInTracerType::Erc7562Tracer => trace_block_with_tracing_inspector(
                    &env,
                    &mut state,
                    &builtin_tracer_kind(*builtin, tracer_config)?,
                )?,

                GethDebugBuiltInTracerType::FourByteTracer => {
                    let mut executor = env
                        .exec
                        .start_executor_with_inspector(&mut state, FourByteInspector::default())?;

                    let mut results = Vec::with_capacity(env.transactions.len());
                    for (index, tx) in env.transactions.iter().enumerate() {
                        let tx_hash = tx.inner.tx_hash();
                        let recovered_tx = &tx.inner.inner;
                        trace!(tx_index = index, tx_hash = %tx_hash, "Tracing transaction");

                        match executor.run_transaction(recovered_tx) {
                            Ok(outcome) => {
                                let frame = FourByteFrame::from(executor.inspector());
                                *executor.inspector_mut() = FourByteInspector::default();
                                executor.evm.db_mut().commit(outcome.inner.result_and_state.state);
                                results.push(TraceResult::Success {
                                    result: frame.into(),
                                    tx_hash: Some(tx_hash),
                                });
                            }
                            Err(e) => return Err(tx_replay_failure(index, tx_hash, e).into()),
                        }
                    }
                    results
                }

                GethDebugBuiltInTracerType::MuxTracer => trace_block_with_debug_inspector(
                    &env.exec,
                    block,
                    env.transactions,
                    &mut state,
                    mux_inspector(tracer_config)?,
                )?,
            },

            GethDebugTracerType::JsTracer(code) => {
                let config_json = tracer_config.clone().into_json();

                if env.transactions.is_empty() {
                    return Ok(vec![]);
                }

                let first_info = tx_info_at(block, &env.transactions[0], 0);
                let inspector =
                    js_inspector(code.clone(), config_json.clone(), make_tx_ctx(&first_info))?;

                let mut executor = env.exec.start_executor_with_inspector(&mut state, inspector)?;

                let mut results = Vec::with_capacity(env.transactions.len());
                for (index, tx) in env.transactions.iter().enumerate() {
                    let tx_hash = tx.inner.tx_hash();
                    let recovered_tx = &tx.inner.inner;
                    trace!(tx_index = index, tx_hash = %tx_hash, "Tracing transaction");

                    if index > 0 {
                        let info = tx_info_at(block, tx, index);
                        match JsInspector::with_transaction_context(
                            code.clone(),
                            config_json.clone(),
                            make_tx_ctx(&info),
                        ) {
                            Ok(insp) => *executor.inspector_mut() = insp,
                            Err(e) => {
                                results.push(TraceResult::Error {
                                    error: format!("Failed to create JsInspector: {:?}", e),
                                    tx_hash: Some(tx_hash),
                                });
                                continue;
                            }
                        }
                    }

                    match executor.run_transaction(recovered_tx) {
                        Ok(outcome) => {
                            let result_and_state = outcome.inner.result_and_state;
                            let state_changes = result_and_state.state.clone();

                            let evm_env_ref = env.exec.evm_env.clone();
                            let tx_env = TxEnv::default();
                            let json_result = {
                                let (db, js_inspector, _) =
                                    EvmTrait::components_mut(&mut executor.evm);
                                js_inspector.json_result(
                                    result_and_state,
                                    &tx_env,
                                    &evm_env_ref.block_env,
                                    &*db,
                                )
                            };

                            executor.evm.db_mut().commit(state_changes);

                            match json_result {
                                Ok(json_value) => {
                                    results.push(TraceResult::Success {
                                        result: GethTrace::JS(json_value),
                                        tx_hash: Some(tx_hash),
                                    });
                                }
                                Err(e) => {
                                    results.push(TraceResult::Error {
                                        error: format!("JS tracer execution failed: {:?}", e),
                                        tx_hash: Some(tx_hash),
                                    });
                                }
                            }
                        }
                        Err(e) => return Err(tx_replay_failure(index, tx_hash, e).into()),
                    }
                }
                results
            }
        }
    } else {
        trace_block_with_tracing_inspector(&env, &mut state, &TracerKind::Default(opts))?
    };

    trace!(traced_count = results.len(), "Block trace completed");

    Ok(results)
}

/// Traces a single transaction execution using LightWitness.
///
/// Uses a **single executor** for pre-execution changes, preceding transactions,
/// and the target transaction to preserve the DynamicGasCost bucket cache,
/// matching the validator's single-executor behaviour.
#[instrument(skip_all, name = "trace_tx", fields(block_number = block.header.number, tx_index))]
pub fn trace_transaction(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    tx_index: usize,
    witness: &LightWitnessExecutor,
    contracts: &HashMap<B256, Bytecode>,
    opts: GethDebugTracingOptions,
) -> Result<GethTrace, TraceError> {
    let env = TracingEnv::new(chain_spec, block, witness, contracts)?;

    if tx_index >= env.transactions.len() {
        return Err(ValidationError::BlockIncomplete.into());
    }

    let target_tx = &env.transactions[tx_index];
    trace!(
        tx_hash = %target_tx.inner.tx_hash(),
        "Starting transaction trace"
    );

    let cache_db = CacheDB::new(&env.db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    let tracer_config = &opts.tracer_config;
    let recovered_target = &target_tx.inner.inner;
    let info = tx_info_at(block, target_tx, tx_index);

    if let Some(tracer) = requested_tracer(&opts) {
        return match tracer {
            GethDebugTracerType::BuiltInTracer(builtin) => match builtin {
                GethDebugBuiltInTracerType::NoopTracer => {
                    Ok(GethTrace::NoopTracer(NoopFrame::default()))
                }

                // Strict parse in `builtin_tracer_kind` — see its doc for why the
                // executor re-rejects what the boundary gate already screens. The
                // unsupported erc7562Tracer and stateGasTracer error there before any
                // execution.
                GethDebugBuiltInTracerType::CallTracer => trace_tx_with_debug_inspector(
                    &env.exec,
                    block,
                    env.transactions,
                    &mut state,
                    tx_index,
                    call_inspector(tracer_config)?,
                ),

                GethDebugBuiltInTracerType::FlatCallTracer => trace_tx_with_debug_inspector(
                    &env.exec,
                    block,
                    env.transactions,
                    &mut state,
                    tx_index,
                    flat_call_inspector(tracer_config)?,
                ),

                GethDebugBuiltInTracerType::PreStateTracer |
                GethDebugBuiltInTracerType::StateGasTracer |
                GethDebugBuiltInTracerType::Erc7562Tracer => trace_tx_with_tracing_inspector(
                    &env,
                    &mut state,
                    tx_index,
                    &builtin_tracer_kind(*builtin, tracer_config)?,
                ),

                GethDebugBuiltInTracerType::FourByteTracer => {
                    let mut executor = env
                        .exec
                        .start_executor_with_inspector(&mut state, FourByteInspector::default())?;
                    replay_preceding_txs(&mut executor, env.transactions, tx_index)?;

                    *executor.inspector_mut() = FourByteInspector::default();

                    executor
                        .run_transaction(recovered_target)
                        .map_err(ValidationError::BlockReplayFailed)?;
                    let frame = FourByteFrame::from(executor.inspector());
                    Ok(frame.into())
                }

                GethDebugBuiltInTracerType::MuxTracer => trace_tx_with_debug_inspector(
                    &env.exec,
                    block,
                    env.transactions,
                    &mut state,
                    tx_index,
                    mux_inspector(tracer_config)?,
                ),
            },

            GethDebugTracerType::JsTracer(code) => {
                let config_json = tracer_config.clone().into_json();
                let inspector =
                    js_inspector(code.clone(), config_json.clone(), make_tx_ctx(&info))?;

                let mut executor = env.exec.start_executor_with_inspector(&mut state, inspector)?;
                replay_preceding_txs(&mut executor, env.transactions, tx_index)?;

                *executor.inspector_mut() =
                    js_inspector(code.clone(), config_json, make_tx_ctx(&info))?;

                let outcome = executor
                    .run_transaction(recovered_target)
                    .map_err(ValidationError::BlockReplayFailed)?;
                let result_and_state = outcome.inner.result_and_state;

                let evm_env_ref = env.exec.evm_env.clone();
                let tx_env = TxEnv::default();
                let (db, js_inspector, _) = EvmTrait::components_mut(&mut executor.evm);
                js_inspector
                    .json_result(result_and_state, &tx_env, &evm_env_ref.block_env, &*db)
                    .map(GethTrace::JS)
                    .map_err(|e| request_error("JS tracer execution failed", e))
            }
        };
    }

    // Default: struct logger tracer
    trace_tx_with_tracing_inspector(&env, &mut state, tx_index, &TracerKind::Default(opts))
}

// Public API - Parity-style Tracing
/// Computes Parity-style traces for all transactions in a block using LightWitness.
///
/// Uses a **single executor** for all transactions to preserve the DynamicGasCost
/// bucket cache, matching the validator's single-executor behaviour.
#[instrument(skip_all, name = "parity_trace_block_light", fields(block_number = block.header.number))]
pub fn parity_trace_block(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    witness: &LightWitnessExecutor,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<Vec<LocalizedTransactionTrace>, TraceError> {
    let env = TracingEnv::new(chain_spec, block, witness, contracts)?;

    let cache_db = CacheDB::new(&env.db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    let inspector = TracingInspector::new(TracingInspectorConfig::default_parity());
    let mut executor = env.exec.start_executor_with_inspector(&mut state, inspector)?;

    let mut all_traces = Vec::new();

    for (index, tx) in env.transactions.iter().enumerate() {
        let recovered_tx = &tx.inner.inner;
        let info = tx_info_at(block, tx, index);

        match executor.run_transaction(recovered_tx) {
            Ok(outcome) => {
                let state_changes = outcome.inner.result_and_state.state;
                // Taking the inspector (rather than cloning its recorded trace arena)
                // doubles as the per-tx reset.
                let traces = core::mem::replace(
                    executor.inspector_mut(),
                    TracingInspector::new(TracingInspectorConfig::default_parity()),
                )
                .into_parity_builder()
                .into_localized_transaction_traces(info);
                all_traces.extend(traces);

                executor.evm.db_mut().commit(state_changes);
            }
            Err(e) => {
                return Err(ValidationError::BlockReplayFailed(e).into());
            }
        }
    }

    Ok(all_traces)
}

/// Traces a single transaction with Parity-style tracing using LightWitness.
///
/// Uses a **single executor** for pre-execution changes, preceding transactions,
/// and the target transaction to preserve the DynamicGasCost bucket cache.
#[instrument(skip_all, name = "parity_trace_tx_light", fields(block_number = block.header.number, tx_index))]
pub fn parity_trace_transaction(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    tx_index: usize,
    witness: &LightWitnessExecutor,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<Vec<LocalizedTransactionTrace>, TraceError> {
    let env = TracingEnv::new(chain_spec, block, witness, contracts)?;

    if tx_index >= env.transactions.len() {
        return Err(ValidationError::BlockIncomplete.into());
    }

    let cache_db = CacheDB::new(&env.db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    // Preceding transactions only rebuild state; a none-config inspector skips
    // recording their every step just to discard it.
    let inspector = TracingInspector::new(TracingInspectorConfig::none());
    let mut executor = env.exec.start_executor_with_inspector(&mut state, inspector)?;
    replay_preceding_txs(&mut executor, env.transactions, tx_index)?;

    *executor.inspector_mut() = TracingInspector::new(TracingInspectorConfig::default_parity());

    let target_tx = &env.transactions[tx_index];
    let recovered_tx = &target_tx.inner.inner;
    let info = tx_info_at(block, target_tx, tx_index);

    match executor.run_transaction(recovered_tx) {
        Ok(_outcome) => {
            // Take the inspector rather than cloning its recorded trace arena; this
            // executor serves no further transactions.
            let traces = core::mem::replace(
                executor.inspector_mut(),
                TracingInspector::new(TracingInspectorConfig::default_parity()),
            )
            .into_parity_builder()
            .into_localized_transaction_traces(info);
            Ok(traces)
        }
        Err(e) => Err(ValidationError::BlockReplayFailed(e).into()),
    }
}

// Internal Helper
/// Adds accounts that were accessed but not modified to the prestate diff trace.
///
/// In mega-reth, accounts that are accessed during transaction execution (e.g., fee recipients
/// with zero balance increment) appear in the diff trace with their pre-state and an empty
/// post-state `{}`. The `geth_prestate_diff_traces` function in revm-inspectors removes these
/// accounts via `retain_changed()` because their pre and post states are identical.
///
/// This function restores those accounts to match mega-reth behavior.
fn add_accessed_unchanged_accounts<DB: DatabaseRef>(
    frame: PreStateFrame,
    state_changes: &EvmState,
    db: &DB,
) -> PreStateFrame {
    match frame {
        PreStateFrame::Diff(mut diff) => {
            for (addr, account) in state_changes.iter() {
                if diff.pre.contains_key(addr) || diff.post.contains_key(addr) {
                    continue;
                }

                if !account.is_touched() {
                    continue;
                }

                if let Ok(Some(account_info)) = db.basic_ref(*addr) {
                    let code = account_info.code.as_ref().map(|c| c.original_bytes());
                    let pre_state = AccountState::from_account_info(
                        account_info.nonce,
                        account_info.balance,
                        code,
                    );
                    diff.pre.insert(*addr, pre_state);
                    diff.post.insert(*addr, AccountState::default());
                }
            }
            PreStateFrame::Diff(diff)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_tracer() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::NoopTracer,
            )),
            ..Default::default()
        };
        assert!(opts.tracer.is_some());
    }

    #[test]
    fn test_call_tracer_config() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            ..Default::default()
        };
        let config = opts.tracer_config.clone().into_call_config();
        assert!(config.is_ok());
    }

    #[test]
    fn test_prestate_tracer_config() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::PreStateTracer,
            )),
            ..Default::default()
        };
        let config = opts.tracer_config.clone().into_pre_state_config();
        assert!(config.is_ok());
    }

    #[test]
    fn test_fourbye_tracer() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::FourByteTracer,
            )),
            ..Default::default()
        };
        assert!(opts.tracer.is_some());
    }

    #[test]
    fn test_flat_call_tracer_config() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::FlatCallTracer,
            )),
            ..Default::default()
        };
        let config = opts.tracer_config.clone().into_flat_call_config();
        assert!(config.is_ok());
    }

    #[test]
    fn test_js_tracer() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::JsTracer(
                "{ result: function() { return {}; } }".to_string(),
            )),
            ..Default::default()
        };
        assert!(matches!(opts.tracer, Some(GethDebugTracerType::JsTracer(_))));
    }

    #[test]
    fn test_default_struct_logger() {
        let opts = GethDebugTracingOptions::default();
        assert!(opts.tracer.is_none());
        let _config = TracingInspectorConfig::from_geth_config(&opts.config);
    }

    /// The error discriminant the RPC layer keys cache hygiene off: a replay failure
    /// (here: every bytecode missing from the contracts map) aborts the block trace with
    /// [`TraceError::Data`] instead of returning `Ok` full of `TraceResult::Error`
    /// entries, while an unparsable mux config over healthy data is
    /// [`TraceError::Request`].
    #[test]
    fn trace_block_discriminates_data_and_request_errors() {
        use stateless_test_utils::fixtures::TestFixtures;

        use crate::data_provider::{BlockData, test_support::fixture_block_data};

        let chain_spec = ChainSpec::from_genesis(
            TestFixtures::synthetic_shared().load_genesis().expect("genesis"),
        );
        let BlockData { block, witness, contracts } = fixture_block_data();

        let err = trace_block(
            &chain_spec,
            &block,
            &witness,
            &HashMap::default(),
            GethDebugTracingOptions::default(),
        )
        .expect_err("missing bytecode must fail the replay");
        assert!(matches!(err, TraceError::Data(_)), "got: {err:?}");

        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::MuxTracer)),
            tracer_config: GethDebugTracerConfig(serde_json::json!({"bogusTracer": {}})),
            ..Default::default()
        };
        let err = trace_block(&chain_spec, &block, &witness, &contracts, opts)
            .expect_err("an unparsable mux config must be rejected");
        assert!(matches!(err, TraceError::Request(_)), "got: {err:?}");
    }

    /// Past the boundary gate, the executor still refuses every unsupported tracer, on its own
    /// or as a `muxTracer` child, as a [`TraceError::Request`] on healthy block data, for both
    /// the block and the transaction dispatchers.
    #[test]
    fn executor_refuses_unsupported_tracers() {
        use stateless_test_utils::fixtures::TestFixtures;

        use crate::data_provider::{BlockData, test_support::fixture_block_data};

        let chain_spec = ChainSpec::from_genesis(
            TestFixtures::synthetic_shared().load_genesis().expect("genesis"),
        );
        let BlockData { block, witness, contracts } = fixture_block_data();
        let builtin = |tracer| Some(GethDebugTracerType::BuiltInTracer(tracer));
        let mux = |config| GethDebugTracingOptions {
            tracer: builtin(GethDebugBuiltInTracerType::MuxTracer),
            tracer_config: GethDebugTracerConfig(config),
            ..Default::default()
        };
        for opts in [
            GethDebugTracingOptions {
                tracer: builtin(GethDebugBuiltInTracerType::StateGasTracer),
                ..Default::default()
            },
            GethDebugTracingOptions {
                tracer: builtin(GethDebugBuiltInTracerType::Erc7562Tracer),
                ..Default::default()
            },
            mux(serde_json::json!({"stateGasTracer": null})),
            mux(serde_json::json!({"callTracer": {}, "stateGasTracer": null})),
            mux(serde_json::json!({"erc7562Tracer": {}})),
        ] {
            let err = trace_block(&chain_spec, &block, &witness, &contracts, opts.clone())
                .expect_err("an unsupported tracer must fail the block trace");
            assert!(matches!(err, TraceError::Request(_)), "{opts:?}: {err:?}");
            let err = trace_transaction(&chain_spec, &block, 0, &witness, &contracts, opts)
                .expect_err("an unsupported tracer must fail the tx trace");
            assert!(matches!(err, TraceError::Request(_)), "{err:?}");
        }
    }

    /// Options selecting `tracer`, with `tracer_config`.
    fn tracer_opts(
        tracer: GethDebugTracerType,
        tracer_config: serde_json::Value,
    ) -> GethDebugTracingOptions {
        GethDebugTracingOptions {
            tracer: Some(tracer),
            tracer_config: GethDebugTracerConfig(tracer_config),
            ..Default::default()
        }
    }

    fn call_tracer_opts() -> GethDebugTracingOptions {
        tracer_opts(
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            serde_json::Value::Null,
        )
    }

    fn mux_call_tracer_opts() -> GethDebugTracingOptions {
        tracer_opts(
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::MuxTracer),
            serde_json::json!({"callTracer": {}}),
        )
    }

    /// The call frame of a mux frame.
    fn mux_call_child(trace: &GethTrace) -> &GethTrace {
        let GethTrace::MuxTracer(frame) = trace else { panic!("expected a mux frame: {trace:?}") };
        &frame.0[&GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer)]
    }

    /// For every transaction of every fixture block, the call tracer's frame is the same on
    /// its own and as a `muxTracer` child, on the block and the transaction paths, and its
    /// root reports the transaction's sender and gas limit. That includes the MegaETH system
    /// transactions, which the EVM executes as deposits.
    #[test]
    fn mux_call_frame_matches_the_standalone_call_frame() {
        use stateless_test_utils::fixtures::TestFixtures;

        let fixtures = TestFixtures::synthetic_shared();
        let chain_spec = ChainSpec::from_genesis(fixtures.load_genesis().expect("genesis"));
        let contracts: HashMap<B256, Bytecode> =
            fixtures.contracts.iter().map(|(hash, code)| (*hash, code.clone())).collect();

        let mut compared = 0usize;
        let mut system_txs = 0usize;
        for (number, hash) in fixtures.paired_blocks() {
            let block = &fixtures.blocks[&hash];
            let witness =
                LightWitnessExecutor::from(LightWitness::from(&fixtures.salt_witnesses[&hash]));
            let BlockTransactions::Full(transactions) = &block.transactions else {
                panic!("block {number}: fixture blocks carry full transactions");
            };
            let trace = |opts: GethDebugTracingOptions| {
                trace_block(&chain_spec, block, &witness, &contracts, opts)
                    .unwrap_or_else(|e| panic!("block {number}: {e:?}"))
            };
            let standalone = trace(call_tracer_opts());
            let muxed = trace(mux_call_tracer_opts());
            for (index, tx) in transactions.iter().enumerate() {
                let (
                    TraceResult::Success { result: standalone, .. },
                    TraceResult::Success { result: muxed, .. },
                ) = (&standalone[index], &muxed[index])
                else {
                    panic!("block {number} tx {index}: trace failed");
                };
                assert_eq!(mux_call_child(muxed), standalone, "block {number} tx {index}");
                let GethTrace::CallTracer(frame) = standalone else {
                    panic!("expected a call frame")
                };
                assert_eq!(
                    frame.gas,
                    alloy_primitives::U256::from(tx.inner.gas_limit()),
                    "block {number} tx {index}"
                );
                assert_eq!(frame.from, tx.inner.inner.signer(), "block {number} tx {index}");
                system_txs += (tx.inner.inner.signer() == mega_evm::MEGA_SYSTEM_ADDRESS) as usize;
                let single = trace_transaction(
                    &chain_spec,
                    block,
                    index,
                    &witness,
                    &contracts,
                    mux_call_tracer_opts(),
                )
                .unwrap_or_else(|e| panic!("block {number} tx {index}: {e:?}"));
                assert_eq!(&single, muxed, "block {number} tx {index}");
                compared += 1;
            }
        }
        assert!(compared > 0);
        assert!(system_txs > 0, "no fixture block carries a MegaETH system transaction");
    }

    /// For every transaction of every fixture block, the flat-call tracer's trace is the same on
    /// its own, as the one child of a `muxTracer` and beside a call tracer in one, on the block
    /// and the transaction paths, and its root reports the transaction's gas limit. The call
    /// child of the mixed mux is the standalone call frame.
    #[test]
    fn mux_flat_call_trace_matches_the_standalone_flat_call_trace() {
        use alloy_rpc_types_trace::parity::Action;
        use stateless_test_utils::fixtures::TestFixtures;

        let fixtures = TestFixtures::synthetic_shared();
        let chain_spec = ChainSpec::from_genesis(fixtures.load_genesis().expect("genesis"));
        let contracts: HashMap<B256, Bytecode> =
            fixtures.contracts.iter().map(|(hash, code)| (*hash, code.clone())).collect();
        let builtin = GethDebugTracerType::BuiltInTracer;
        let flat_opts = tracer_opts(
            builtin(GethDebugBuiltInTracerType::FlatCallTracer),
            serde_json::Value::Null,
        );
        let mux_opts = |config| tracer_opts(builtin(GethDebugBuiltInTracerType::MuxTracer), config);
        let flat_only = mux_opts(serde_json::json!({"flatCallTracer": {}}));
        let mixed = mux_opts(serde_json::json!({"flatCallTracer": {}, "callTracer": {}}));
        let child = |trace: &GethTrace, tracer| {
            let GethTrace::MuxTracer(frame) = trace else {
                panic!("expected a mux frame: {trace:?}")
            };
            frame.0[&builtin(tracer)].clone()
        };

        let mut compared = 0usize;
        for (number, hash) in fixtures.paired_blocks() {
            let block = &fixtures.blocks[&hash];
            let witness =
                LightWitnessExecutor::from(LightWitness::from(&fixtures.salt_witnesses[&hash]));
            let BlockTransactions::Full(transactions) = &block.transactions else {
                panic!("block {number}: fixture blocks carry full transactions");
            };
            let trace = |opts: &GethDebugTracingOptions| {
                trace_block(&chain_spec, block, &witness, &contracts, opts.clone())
                    .unwrap_or_else(|e| panic!("block {number}: {e:?}"))
            };
            let traces = [&flat_opts, &flat_only, &mixed, &call_tracer_opts()].map(trace);
            for (index, tx) in transactions.iter().enumerate() {
                let [flat, flat_only_mux, mixed_mux, call] = traces.each_ref().map(|traces| {
                    let TraceResult::Success { result, .. } = &traces[index] else {
                        panic!("block {number} tx {index}: trace failed");
                    };
                    result
                });
                let at = format!("block {number} tx {index}");
                assert_eq!(
                    &child(flat_only_mux, GethDebugBuiltInTracerType::FlatCallTracer),
                    flat,
                    "{at}"
                );
                assert_eq!(
                    &child(mixed_mux, GethDebugBuiltInTracerType::FlatCallTracer),
                    flat,
                    "{at}"
                );
                assert_eq!(&child(mixed_mux, GethDebugBuiltInTracerType::CallTracer), call, "{at}");
                let gas = match &flat_root(flat).trace.action {
                    Action::Call(call) => call.gas,
                    Action::Create(create) => create.gas,
                    action => panic!("{at}: unexpected root action {action:?}"),
                };
                assert_eq!(gas, tx.inner.gas_limit(), "{at}");
                for (opts, block_trace) in [(&flat_only, flat_only_mux), (&mixed, mixed_mux)] {
                    let single = trace_transaction(
                        &chain_spec,
                        block,
                        index,
                        &witness,
                        &contracts,
                        opts.clone(),
                    )
                    .unwrap_or_else(|e| panic!("{at}: {e:?}"));
                    assert_eq!(&single, block_trace, "{at}");
                }
                compared += 1;
            }
        }
        assert!(compared > 0);
    }

    /// SALT buckets ten times the minimum size, so creating an account costs nine times the
    /// base new-account storage gas.
    #[derive(Debug)]
    struct CrowdedBuckets;

    impl mega_evm::SaltEnv for CrowdedBuckets {
        type Error = std::convert::Infallible;

        fn get_bucket_capacity(&self, _: mega_evm::BucketId) -> Result<u64, Self::Error> {
            Ok(mega_evm::MIN_BUCKET_SIZE as u64 * 10)
        }

        fn bucket_id_for_account(_: alloy_primitives::Address) -> mega_evm::BucketId {
            0
        }

        fn bucket_id_for_slot(
            _: alloy_primitives::Address,
            _: alloy_primitives::U256,
        ) -> mega_evm::BucketId {
            0
        }
    }

    const SENDER: alloy_primitives::Address = alloy_primitives::Address::with_last_byte(0xab);
    const DEST: alloy_primitives::Address = alloy_primitives::Address::with_last_byte(0xcd);

    /// The [`ExternalEnvFactory`] of a chain whose SALT buckets are all [`CrowdedBuckets`].
    #[derive(Debug, Clone)]
    struct CrowdedEnv;

    impl ExternalEnvFactory for CrowdedEnv {
        type EnvTypes = (CrowdedBuckets, mega_evm::EmptyExternalEnv);

        fn external_envs(&self, _: u64) -> mega_evm::ExternalEnvs<Self::EnvTypes> {
            mega_evm::ExternalEnvs {
                salt_env: CrowdedBuckets,
                oracle_env: mega_evm::EmptyExternalEnv,
            }
        }
    }

    /// Block 1 of the synthetic chain with REX4 active from genesis and [`CrowdedBuckets`], whose
    /// one transaction is a legacy transaction from [`SENDER`] to [`DEST`] with `gas_limit` and
    /// `value`, with `code` at [`DEST`] (`None` leaves it a new account). Returns the block's
    /// execution env, the block and a fresh state for it.
    fn crowded_block(
        code: Option<&'static [u8]>,
        gas_limit: u64,
        value: alloy_primitives::U256,
    ) -> (
        BlockExecutionEnv<CrowdedEnv>,
        Block<OpTransaction>,
        impl Fn() -> State<CacheDB<revm::database::EmptyDB>>,
    ) {
        use alloy_consensus::{SignableTransaction, TxLegacy};
        use alloy_primitives::{Signature, TxKind, U256};
        use revm::{database::EmptyDB, state::AccountInfo};
        use stateless_test_utils::fixtures::TestFixtures;

        let mut genesis = TestFixtures::synthetic_shared().load_genesis().expect("genesis");
        genesis.config.extra_fields.insert("rex4Time".to_string(), serde_json::json!(0));
        let chain_spec = ChainSpec::from_genesis(genesis);
        let header = alloy_consensus::Header {
            number: 1,
            timestamp: 1,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1),
            parent_beacon_block_root: Some(B256::ZERO),
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
            ..Default::default()
        };
        let exec = create_block_execution_env(&chain_spec, &header, CrowdedEnv);
        assert_eq!(exec.evm_env.cfg_env.spec, mega_evm::MegaSpecId::REX4);

        let tx = TxLegacy {
            gas_price: 3,
            gas_limit,
            to: TxKind::Call(DEST),
            value,
            ..Default::default()
        };
        let tx = Recovered::new_unchecked(
            OpTxEnvelope::Legacy(tx.into_signed(Signature::test_signature())),
            SENDER,
        );
        let hash = B256::repeat_byte(0x42);
        let tx = OpTransaction {
            inner: alloy_rpc_types_eth::Transaction {
                inner: tx,
                block_hash: Some(hash),
                block_number: Some(header.number),
                transaction_index: Some(0),
                effective_gas_price: Some(3),
                block_timestamp: Some(header.timestamp),
            },
            deposit_nonce: None,
            deposit_receipt_version: None,
        };
        let block = Block {
            header: alloy_rpc_types_eth::Header { hash, inner: header, ..Default::default() },
            transactions: BlockTransactions::Full(vec![tx]),
            ..Default::default()
        };

        let state = move || {
            let mut db = CacheDB::new(EmptyDB::default());
            db.insert_account_info(
                SENDER,
                AccountInfo { balance: U256::from(1_000_000_000u64), ..Default::default() },
            );
            if let Some(code) = code {
                let code = Bytecode::new_legacy(alloy_primitives::Bytes::from_static(code));
                db.insert_account_info(
                    DEST,
                    AccountInfo { code: Some(code), ..Default::default() },
                );
            }
            State::builder().with_database(db).build()
        };
        (exec, block, state)
    }

    /// Traces the one transaction of [`crowded_block`]`(code, gas_limit, value)` with
    /// `inspector()` through the block and the transaction dispatchers, which must agree, and
    /// returns its execution result and its trace.
    fn trace_crowded_transfer(
        inspector: impl Fn() -> Result<DebugInspector, TraceError>,
        code: Option<&'static [u8]>,
        gas_limit: u64,
        value: alloy_primitives::U256,
    ) -> (revm::context::result::ExecutionResult<mega_evm::HaltReason>, GethTrace) {
        let (exec, block, state) = crowded_block(code, gas_limit, value);
        let BlockTransactions::Full(transactions) = &block.transactions else { unreachable!() };

        let mut block_state = state();
        let traces = trace_block_with_debug_inspector(
            &exec,
            &block,
            transactions,
            &mut block_state,
            inspector().expect("supported tracer"),
        )
        .expect("the block traces");
        let [TraceResult::Success { result: trace, .. }] = &traces[..] else {
            panic!("{traces:?}")
        };
        let mut tx_state = state();
        let single = trace_tx_with_debug_inspector(
            &exec,
            &block,
            transactions,
            &mut tx_state,
            0,
            inspector().expect("supported tracer"),
        )
        .expect("the transaction traces");
        assert_eq!(&single, trace);

        let mut result_state = state();
        let mut executor = exec
            .start_executor_with_inspector(&mut result_state, NoOpInspector)
            .expect("pre-execution");
        let result = executor
            .run_transaction(&transactions[0].inner.inner)
            .expect("the transaction executes")
            .inner
            .result_and_state
            .result;
        (result, single)
    }

    fn null_config() -> GethDebugTracerConfig {
        GethDebugTracerConfig(serde_json::Value::Null)
    }

    /// A REX4 value transfer whose gas covers the intrinsic gas but not the storage gas of
    /// creating its recipient, the first case, halts out of gas before its first frame, so no
    /// root frame is recorded. Its call frame, standalone and as a mux child, still reports the
    /// transaction's caller, destination, gas limit and `out of gas`, through the dispatchers.
    /// An ordinary revert inside the frame is the control: its recorded root renders the same
    /// way on both.
    #[test]
    fn call_frame_of_a_transaction_halted_before_its_first_frame_reports_the_transaction() {
        use alloy_primitives::U256;

        for (code, gas_limit, value, error) in [
            (None, 80_000, U256::from(1), "out of gas"),
            (Some(&[0x60, 0x00, 0x60, 0x00, 0xfd][..]), 150_000, U256::ZERO, "execution reverted"),
        ] {
            let (result, standalone) =
                trace_crowded_transfer(|| call_inspector(&null_config()), code, gas_limit, value);
            if code.is_none() {
                assert!(
                    matches!(
                        &result,
                        revm::context::result::ExecutionResult::Halt { reason, .. }
                            if *reason == mega_evm::HaltReason::from(
                                revm::context::result::HaltReason::OutOfGas(
                                    revm::context::result::OutOfGasError::Basic
                                )
                            )
                    ),
                    "{result:?}"
                );
            } else {
                assert!(matches!(result, revm::context::result::ExecutionResult::Revert { .. }));
            }
            let GethTrace::CallTracer(frame) = &standalone else { panic!("{standalone:?}") };
            assert_eq!(frame.from, SENDER, "{error}");
            assert_eq!(frame.to, Some(DEST), "{error}");
            assert_eq!(frame.gas, U256::from(gas_limit), "{error}");
            assert_eq!(frame.error.as_deref(), Some(error));

            let (_, muxed) = trace_crowded_transfer(
                || mux_inspector(&GethDebugTracerConfig(serde_json::json!({"callTracer": {}}))),
                code,
                gas_limit,
                value,
            );
            assert_eq!(mux_call_child(&muxed), &standalone, "{error}");
        }
    }

    /// The root of a flat-call trace, the first trace of the transaction.
    fn flat_root(trace: &GethTrace) -> &alloy_rpc_types_trace::parity::LocalizedTransactionTrace {
        let GethTrace::FlatCallTracer(traces) = trace else {
            panic!("expected flat calls: {trace:?}")
        };
        let root = traces.first().expect("a root trace");
        assert!(root.trace.trace_address.is_empty(), "{root:?}");
        root
    }

    /// The flat-call trace of a transaction halted before its first frame, as in
    /// [`call_frame_of_a_transaction_halted_before_its_first_frame_reports_the_transaction`],
    /// reports the transaction's sender and gas limit at its root, through the dispatchers, as
    /// the ordinary revert does.
    #[test]
    fn flat_call_trace_of_a_transaction_halted_before_its_first_frame_reports_its_sender() {
        use alloy_primitives::U256;
        use alloy_rpc_types_trace::parity::Action;

        for (code, gas_limit, value) in [
            (None, 80_000, U256::from(1)),
            (Some(&[0x60, 0x00, 0x60, 0x00, 0xfd][..]), 150_000, U256::ZERO),
        ] {
            let (_, trace) = trace_crowded_transfer(
                || flat_call_inspector(&null_config()),
                code,
                gas_limit,
                value,
            );
            let Action::Call(call) = &flat_root(&trace).trace.action else { panic!("{trace:?}") };
            assert_eq!(call.from, SENDER, "{code:?}");
            assert_eq!(call.gas, gas_limit, "{code:?}");
        }
    }

    /// An empty tracer name runs the default struct logger, as an omitted one does, on the
    /// block and the transaction paths; a non-empty JS tracer still runs as JS.
    #[test]
    fn empty_tracer_name_runs_the_struct_logger() {
        use stateless_test_utils::fixtures::TestFixtures;

        use crate::data_provider::{BlockData, test_support::fixture_block_data};

        let chain_spec = ChainSpec::from_genesis(
            TestFixtures::synthetic_shared().load_genesis().expect("genesis"),
        );
        let BlockData { block, witness, contracts } = fixture_block_data();
        let omitted = GethDebugTracingOptions::default();
        let empty =
            tracer_opts(GethDebugTracerType::JsTracer(String::new()), serde_json::Value::Null);

        let expected = trace_block(&chain_spec, &block, &witness, &contracts, omitted.clone())
            .expect("struct logs");
        let traces = trace_block(&chain_spec, &block, &witness, &contracts, empty.clone())
            .expect("an empty tracer name traces");
        assert_eq!(traces, expected);
        let TraceResult::Success { result: GethTrace::Default(_), .. } = &traces[0] else {
            panic!("expected struct logs: {:?}", traces[0]);
        };
        let single = trace_transaction(&chain_spec, &block, 0, &witness, &contracts, empty)
            .expect("an empty tracer name traces");
        let expected_single =
            trace_transaction(&chain_spec, &block, 0, &witness, &contracts, omitted)
                .expect("struct logs");
        assert_eq!(single, expected_single);

        let js = tracer_opts(
            GethDebugTracerType::JsTracer(
                "{ result: function() { return 7; }, fault: function() {} }".to_string(),
            ),
            serde_json::Value::Null,
        );
        let trace = trace_transaction(&chain_spec, &block, 0, &witness, &contracts, js)
            .expect("a JS tracer traces");
        assert_eq!(trace, GethTrace::JS(serde_json::json!(7)));
    }

    /// `trace_transaction` replays the preceding transactions under a recording-free
    /// inspector and only then installs the real tracer, while `trace_block` keeps the tracer
    /// installed throughout. The frame for transaction `k` must come out byte-identical either
    /// way, for every transaction of every fixture block and on every inspector-based path —
    /// the preceding replay may not leave anything behind in the executor that the recording
    /// inspector would have shaped differently.
    #[test]
    fn single_transaction_trace_is_byte_identical_to_its_block_trace_frame() {
        use stateless_test_utils::fixtures::TestFixtures;

        let fixtures = TestFixtures::synthetic_shared();
        let chain_spec = ChainSpec::from_genesis(fixtures.load_genesis().expect("genesis"));
        let contracts: HashMap<B256, Bytecode> =
            fixtures.contracts.iter().map(|(hash, code)| (*hash, code.clone())).collect();

        let builtin = |tracer| GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(tracer)),
            ..Default::default()
        };
        let geth_options = [
            // The bare default is the struct logger.
            GethDebugTracingOptions::default(),
            builtin(GethDebugBuiltInTracerType::CallTracer),
            builtin(GethDebugBuiltInTracerType::PreStateTracer),
            builtin(GethDebugBuiltInTracerType::FlatCallTracer),
        ];

        let mut compared = 0usize;
        let mut multi_tx_blocks = 0usize;
        for (number, hash) in fixtures.paired_blocks() {
            let block = &fixtures.blocks[&hash];
            let witness =
                LightWitnessExecutor::from(LightWitness::from(&fixtures.salt_witnesses[&hash]));
            multi_tx_blocks += (block.transactions.len() > 1) as usize;

            for opts in &geth_options {
                let traces = trace_block(&chain_spec, block, &witness, &contracts, opts.clone())
                    .unwrap_or_else(|e| panic!("block {number}: trace_block: {e:?}"));
                for (index, entry) in traces.iter().enumerate() {
                    let TraceResult::Success { result, .. } = entry else {
                        panic!("block {number} tx {index}: block trace failed: {entry:?}");
                    };
                    let single = trace_transaction(
                        &chain_spec,
                        block,
                        index,
                        &witness,
                        &contracts,
                        opts.clone(),
                    )
                    .unwrap_or_else(|e| panic!("block {number} tx {index}: {e:?}"));
                    assert_eq!(
                        serde_json::to_string(&single).unwrap(),
                        serde_json::to_string(result).unwrap(),
                        "block {number} tx {index}: tracer {:?}",
                        opts.tracer
                    );
                    compared += 1;
                }
            }

            // The Parity path replays its preceding transactions the same way.
            let block_parity = parity_trace_block(&chain_spec, block, &witness, &contracts)
                .unwrap_or_else(|e| panic!("block {number}: parity_trace_block: {e:?}"));
            for index in 0..block.transactions.len() {
                let single =
                    parity_trace_transaction(&chain_spec, block, index, &witness, &contracts)
                        .unwrap_or_else(|e| panic!("block {number} tx {index}: parity: {e:?}"));
                let from_block: Vec<_> = block_parity
                    .iter()
                    .filter(|trace| trace.transaction_position == Some(index as u64))
                    .collect();
                assert_eq!(
                    serde_json::to_string(&single.iter().collect::<Vec<_>>()).unwrap(),
                    serde_json::to_string(&from_block).unwrap(),
                    "block {number} tx {index}: parity"
                );
                compared += 1;
            }
        }

        // Vacuity guard: the comparison must reach transactions that have predecessors.
        assert!(multi_tx_blocks > 0, "no fixture block carries more than one transaction");
        assert!(compared > 0, "nothing was compared");
    }

    /// Defense in depth behind the RPC boundary gate: a type-malformed `tracerConfig` on
    /// a config-reading builtin is rejected with [`TraceError::Request`] by the executor
    /// itself — on both the block and the single-transaction paths — never silently
    /// traced with default settings, while a well-formed config still traces. (The RPC
    /// layer's own `-32602` rejection is pinned by
    /// `invalid_tracer_config_maps_to_invalid_params` in `rpc_service`.)
    #[test]
    fn malformed_tracer_config_is_rejected_not_defaulted() {
        use stateless_test_utils::fixtures::TestFixtures;

        use crate::data_provider::{BlockData, test_support::fixture_block_data};

        let chain_spec = ChainSpec::from_genesis(
            TestFixtures::synthetic_shared().load_genesis().expect("genesis"),
        );
        let BlockData { block, witness, contracts } = fixture_block_data();

        let malformed = [
            (GethDebugBuiltInTracerType::CallTracer, serde_json::json!({"onlyTopCall": "yes"})),
            (GethDebugBuiltInTracerType::PreStateTracer, serde_json::json!({"diffMode": "yes"})),
            (
                GethDebugBuiltInTracerType::FlatCallTracer,
                serde_json::json!({"convertParityErrors": "yes"}),
            ),
            (GethDebugBuiltInTracerType::MuxTracer, serde_json::json!({"notATracer": {}})),
        ];
        for (tracer, config) in malformed {
            let opts = GethDebugTracingOptions {
                tracer: Some(GethDebugTracerType::BuiltInTracer(tracer)),
                tracer_config: GethDebugTracerConfig(config),
                ..Default::default()
            };

            let err = trace_block(&chain_spec, &block, &witness, &contracts, opts.clone())
                .expect_err("malformed config must fail the block trace");
            assert!(
                matches!(&err, TraceError::Request(msg) if msg.contains("tracerConfig")),
                "got: {err:?}"
            );

            let err = trace_transaction(&chain_spec, &block, 0, &witness, &contracts, opts)
                .expect_err("malformed config must fail the tx trace");
            assert!(
                matches!(&err, TraceError::Request(msg) if msg.contains("tracerConfig")),
                "got: {err:?}"
            );
        }

        // Control: a well-formed config on the same inputs still traces.
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            tracer_config: GethDebugTracerConfig(serde_json::json!({"onlyTopCall": true})),
            ..Default::default()
        };
        trace_block(&chain_spec, &block, &witness, &contracts, opts)
            .expect("a well-formed config must trace");
    }
}
