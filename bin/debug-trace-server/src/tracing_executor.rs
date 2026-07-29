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

use alloy_consensus::Transaction;
use alloy_evm::{Evm as EvmTrait, block::BlockExecutor};
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use alloy_primitives::{B256, map::HashMap};
use alloy_rpc_types_eth::{Block, BlockTransactions, TransactionInfo};
use alloy_rpc_types_trace::{
    geth::{
        FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType,
        GethDebugTracingOptions, GethTrace, NoopFrame, TraceResult,
        call::{CallConfig, FlatCallConfig},
        mux::MuxConfig,
        pre_state::{AccountState, PreStateConfig, PreStateFrame},
    },
    parity::LocalizedTransactionTrace,
};
use eyre::Result;
use mega_evm::{
    BlockLimits, MegaBlockExecutionCtx, MegaBlockExecutorFactory, MegaEvmFactory, MegaHardforks,
};
use op_alloy_network::TransactionResponse;
use op_alloy_rpc_types::Transaction as OpTransaction;
use revm::{
    DatabaseCommit, DatabaseRef,
    context::TxEnv,
    database::{CacheDB, State},
    state::{Bytecode, EvmState},
};
use revm_inspectors::tracing::{
    FourByteInspector, MuxInspector, TracingInspector, TracingInspectorConfig, TransactionContext,
    js::JsInspector,
};
use stateless_core::{
    chain_spec::ChainSpec,
    evm_database::{WitnessDatabase, WitnessExternalEnv},
    executor::{ValidationError, create_evm_env},
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
/// Unifies CallTracer, PreStateTracer, FlatCallTracer, and the default struct logger
/// to reduce code duplication in `trace_block` and `trace_transaction`.
enum TracerKind {
    Call(CallConfig),
    PreState(PreStateConfig),
    FlatCall(FlatCallConfig),
    Default(GethDebugTracingOptions),
}

impl TracerKind {
    fn inspector_config(&self) -> TracingInspectorConfig {
        match self {
            Self::Call(cfg) => TracingInspectorConfig::from_geth_call_config(cfg),
            Self::PreState(cfg) => TracingInspectorConfig::from_geth_prestate_config(cfg),
            Self::FlatCall(cfg) => TracingInspectorConfig::from_flat_call_config(cfg),
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
    /// Consensus header of the block this env was built from — the single projection point,
    /// so the witness DB can never be paired with a different block's header.
    header: &'a alloy_consensus::Header,
    transactions: &'a [OpTransaction],
    executor_factory: MegaBlockExecutorFactory<
        ChainSpec,
        MegaEvmFactory<WitnessExternalEnv>,
        OpAlloyReceiptBuilder,
    >,
    block_ctx: MegaBlockExecutionCtx,
    evm_env: alloy_evm::EvmEnv<mega_evm::MegaSpecId>,
    light_witness_executor: LightWitnessExecutor,
}

impl<'a> TracingEnv<'a> {
    fn new(
        chain_spec: &ChainSpec,
        block: &'a Block<OpTransaction>,
        light_witness: LightWitness,
    ) -> Result<Self, ValidationError> {
        let BlockTransactions::Full(transactions) = &block.transactions else {
            return Err(ValidationError::BlockIncomplete);
        };

        let ext_env = WitnessExternalEnv::from_light_witness(&light_witness, block.header.number)
            .map_err(ValidationError::EnvOracleConstructionFailed)?;

        let light_witness_executor = LightWitnessExecutor::from(light_witness);
        let evm_env = create_evm_env(&block.header.inner, chain_spec);

        let evm_factory = MegaEvmFactory::new().with_external_env_factory(ext_env);
        let executor_factory = MegaBlockExecutorFactory::new(
            chain_spec.clone(),
            evm_factory,
            OpAlloyReceiptBuilder::default(),
        );

        let hardfork = chain_spec.hardfork(block.header.timestamp);
        let block_limits = if let Some(hardfork) = hardfork {
            BlockLimits::from_hardfork_and_block_gas_limit(hardfork, block.header.gas_limit)
        } else {
            BlockLimits::no_limits()
        };

        // Use actual extra_data (contains system transactions) to match validator behavior.
        let block_ctx = MegaBlockExecutionCtx::new(
            block.header.parent_hash,
            block.header.parent_beacon_block_root,
            block.header.extra_data.clone(),
            block_limits,
        );

        Ok(Self {
            header: &block.header.inner,
            transactions,
            executor_factory,
            block_ctx,
            evm_env,
            light_witness_executor,
        })
    }

    fn create_witness_db<'b>(
        &'b self,
        contracts: &'b HashMap<B256, Bytecode>,
    ) -> WitnessDatabase<'b, LightWitnessExecutor> {
        WitnessDatabase { header: self.header, witness: &self.light_witness_executor, contracts }
    }
}

fn tx_info_at(block: &Block<OpTransaction>, tx: &OpTransaction, index: usize) -> TransactionInfo {
    TransactionInfo {
        hash: Some(tx.inner.tx_hash()),
        index: Some(index as u64),
        block_hash: Some(block.header.hash),
        block_number: Some(block.header.number),
        base_fee: block.header.base_fee_per_gas,
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

/// Builds a [`MuxInspector`] from an already-parsed config (request-attributable on
/// failure).
fn mux_inspector(config: MuxConfig) -> Result<MuxInspector, TraceError> {
    MuxInspector::try_from_config(config)
        .map_err(|e| request_error("MuxInspector creation failed", e))
}

/// Parses the mux `tracerConfig` and builds its inspector — the one home for the mux
/// construction path shared by the block and transaction dispatchers.
fn mux_config_and_inspector(
    tracer_config: &GethDebugTracerConfig,
) -> Result<(MuxConfig, MuxInspector), TraceError> {
    let config = tracer_config
        .clone()
        .into_mux_config()
        .map_err(|_| TraceError::Request("Invalid mux tracer config".into()))?;
    let inspector = mux_inspector(config.clone())?;
    Ok((config, inspector))
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

macro_rules! setup_executor {
    ($env:expr, $state:expr, $inspector:expr => $executor:ident) => {
        let mut $executor = $env.executor_factory.create_executor_with_inspector(
            $state,
            $env.block_ctx.clone(),
            $env.evm_env.clone(),
            $inspector,
        );
        $executor.apply_pre_execution_changes().map_err(ValidationError::BlockReplayFailed)?;
    };
}

macro_rules! replay_preceding_txs {
    ($executor:expr, $env:expr, $tx_index:expr) => {
        for tx in $env.transactions.iter().take($tx_index) {
            $executor
                .execute_transaction(&tx.inner.inner)
                .map_err(ValidationError::BlockReplayFailed)?;
        }
    };
}

// TracingInspector-based helpers (shared by Call, PreState, FlatCall, Default)
/// Traces all transactions in a block using a `TracingInspector`-based tracer.
///
/// Handles executor creation, pre-execution, tx loop, trace extraction, inspector
/// reset, and state commit for any `TracerKind` variant.
fn trace_block_with_tracing_inspector(
    env: &TracingEnv<'_>,
    block: &Block<OpTransaction>,
    state: &mut State<
        revm::database::WrapDatabaseRef<&CacheDB<&WitnessDatabase<'_, LightWitnessExecutor>>>,
    >,
    tracer: &TracerKind,
) -> Result<Vec<TraceResult>, ValidationError> {
    setup_executor!(env, state, tracer.create_inspector() => executor);

    let mut results = Vec::with_capacity(env.transactions.len());
    for (index, tx) in env.transactions.iter().enumerate() {
        let tx_hash = tx.inner.tx_hash();
        let recovered_tx = &tx.inner.inner;
        trace!(tx_index = index, tx_hash = %tx_hash, "Tracing transaction");

        match executor.run_transaction(recovered_tx) {
            Ok(outcome) => {
                let state_changes = outcome.inner.state.clone();

                let trace_result = match tracer {
                    TracerKind::Call(call_config) => {
                        let gas_used = outcome.inner.result.gas_used();
                        let inspector = executor.inspector_mut();
                        inspector.set_transaction_gas_limit(tx.inner.gas_limit());
                        let frame =
                            inspector.geth_builder().geth_call_traces(*call_config, gas_used);
                        GethTrace::from(frame)
                    }
                    TracerKind::PreState(prestate_config) => {
                        let result_and_state = revm::context::result::ResultAndState {
                            result: outcome.inner.result,
                            state: outcome.inner.state,
                        };
                        executor.inspector_mut().set_transaction_gas_limit(tx.inner.gas_limit());
                        let frame_result = {
                            let db = executor.evm.db();
                            let inspector = executor.inspector();
                            inspector.geth_builder().geth_prestate_traces(
                                &result_and_state,
                                prestate_config,
                                db,
                            )
                        };
                        match frame_result {
                            Ok(frame) => {
                                let final_frame = if prestate_config.is_diff_mode() {
                                    let db = executor.evm.db();
                                    add_accessed_unchanged_accounts(frame, &state_changes, db)
                                } else {
                                    frame
                                };
                                GethTrace::from(final_frame)
                            }
                            Err(e) => return Err(frame_build_error("PreState trace failed", e)),
                        }
                    }
                    TracerKind::FlatCall(_) => {
                        let info = tx_info_at(block, tx, index);
                        let frame: alloy_rpc_types_trace::geth::call::FlatCallFrame = executor
                            .inspector()
                            .clone()
                            .with_transaction_gas_limit(tx.inner.gas_limit())
                            .into_parity_builder()
                            .into_localized_transaction_traces(info);
                        GethTrace::from(frame)
                    }
                    TracerKind::Default(opts) => {
                        let gas_used = outcome.inner.result.gas_used();
                        let return_value =
                            outcome.inner.result.output().cloned().unwrap_or_default();
                        let inspector = executor.inspector_mut();
                        inspector.set_transaction_gas_limit(tx.inner.gas_limit());
                        let frame = inspector.geth_builder().geth_traces(
                            gas_used,
                            return_value,
                            opts.config,
                        );

                        // Convert DefaultFrame to JSON and fix returnValue serialization.
                        // alloy-rpc-types-trace 1.1.2 serializes Bytes with "0x" prefix,
                        // but mega-reth uses v1.0.23 which serializes without prefix.
                        let mut frame_value = serde_json::to_value(frame).unwrap();
                        if let Some(rv) = frame_value.get_mut("returnValue") &&
                            let Some(s) = rv.as_str()
                        {
                            *rv = serde_json::Value::String(
                                s.strip_prefix("0x").unwrap_or(s).to_string(),
                            );
                        }
                        GethTrace::JS(frame_value)
                    }
                };

                results.push(TraceResult::Success { result: trace_result, tx_hash: Some(tx_hash) });

                *executor.inspector_mut() = tracer.create_inspector();
                executor.evm.db_mut().commit(state_changes);
            }
            Err(e) => return Err(tx_replay_failure(index, tx_hash, e)),
        }
    }
    Ok(results)
}

/// Traces a single transaction using a `TracingInspector`-based tracer.
///
/// Creates executor, applies pre-execution, replays preceding txs, resets
/// inspector, runs the target tx, and extracts the trace.
fn trace_tx_with_tracing_inspector(
    env: &TracingEnv<'_>,
    block: &Block<OpTransaction>,
    state: &mut State<
        revm::database::WrapDatabaseRef<&CacheDB<&WitnessDatabase<'_, LightWitnessExecutor>>>,
    >,
    tx_index: usize,
    tracer: &TracerKind,
) -> Result<GethTrace, TraceError> {
    setup_executor!(env, state, tracer.create_inspector() => executor);
    replay_preceding_txs!(executor, env, tx_index);

    *executor.inspector_mut() = tracer.create_inspector();

    let target_tx = &env.transactions[tx_index];
    let recovered_target = &target_tx.inner.inner;
    let tx_gas_limit = target_tx.inner.gas_limit();

    let outcome =
        executor.run_transaction(recovered_target).map_err(ValidationError::BlockReplayFailed)?;

    match tracer {
        TracerKind::Call(call_config) => {
            let gas_used = outcome.inner.result.gas_used();
            let inspector = executor.inspector_mut();
            inspector.set_transaction_gas_limit(tx_gas_limit);
            let frame = inspector.geth_builder().geth_call_traces(*call_config, gas_used);
            Ok(frame.into())
        }
        TracerKind::PreState(prestate_config) => {
            let state_changes = outcome.inner.state.clone();
            let result_and_state = revm::context::result::ResultAndState {
                result: outcome.inner.result,
                state: outcome.inner.state,
            };

            executor.inspector_mut().set_transaction_gas_limit(tx_gas_limit);
            let frame_result = {
                let db = executor.evm.db();
                let inspector = executor.inspector();
                inspector.geth_builder().geth_prestate_traces(
                    &result_and_state,
                    prestate_config,
                    db,
                )
            };

            match frame_result {
                Ok(frame) => {
                    let final_frame = if prestate_config.is_diff_mode() {
                        let db = executor.evm.db();
                        add_accessed_unchanged_accounts(frame, &state_changes, db)
                    } else {
                        frame
                    };
                    Ok(final_frame.into())
                }
                Err(e) => Err(frame_build_error("PreState trace failed", e).into()),
            }
        }
        TracerKind::FlatCall(_) => {
            let info = tx_info_at(block, target_tx, tx_index);
            let frame: alloy_rpc_types_trace::geth::call::FlatCallFrame = executor
                .inspector()
                .clone()
                .with_transaction_gas_limit(tx_gas_limit)
                .into_parity_builder()
                .into_localized_transaction_traces(info);
            Ok(frame.into())
        }
        TracerKind::Default(opts) => {
            let gas_used = outcome.inner.result.gas_used();
            let return_value = outcome.inner.result.output().cloned().unwrap_or_default();

            let inspector = executor.inspector_mut();
            inspector.set_transaction_gas_limit(tx_gas_limit);
            let frame = inspector.geth_builder().geth_traces(gas_used, return_value, opts.config);

            let mut frame_value = serde_json::to_value(frame).unwrap();
            if let Some(rv) = frame_value.get_mut("returnValue") &&
                let Some(s) = rv.as_str()
            {
                *rv = serde_json::Value::String(s.strip_prefix("0x").unwrap_or(s).to_string());
            }
            Ok(GethTrace::JS(frame_value))
        }
    }
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
    witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
    opts: GethDebugTracingOptions,
) -> Result<Vec<TraceResult>, TraceError> {
    let env = TracingEnv::new(chain_spec, block, witness)?;

    trace!(tx_count = env.transactions.len(), "Starting block trace");

    let witness_db = env.create_witness_db(contracts);
    let cache_db = CacheDB::new(&witness_db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    let GethDebugTracingOptions { tracer, tracer_config, .. } = &opts;

    let results = if let Some(tracer) = tracer {
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

                // The `unwrap_or_default()` on these three config parses is unreachable in
                // practice: RPC handlers reject malformed configs via
                // `RequestShape::classify` (-32602) before reaching the executor.
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config.clone().into_call_config().unwrap_or_default();
                    trace_block_with_tracing_inspector(
                        &env,
                        block,
                        &mut state,
                        &TracerKind::Call(call_config),
                    )?
                }

                GethDebugBuiltInTracerType::PreStateTracer => {
                    let prestate_config =
                        tracer_config.clone().into_pre_state_config().unwrap_or_default();
                    trace_block_with_tracing_inspector(
                        &env,
                        block,
                        &mut state,
                        &TracerKind::PreState(prestate_config),
                    )?
                }

                GethDebugBuiltInTracerType::FlatCallTracer => {
                    let flat_call_config =
                        tracer_config.clone().into_flat_call_config().unwrap_or_default();
                    trace_block_with_tracing_inspector(
                        &env,
                        block,
                        &mut state,
                        &TracerKind::FlatCall(flat_call_config),
                    )?
                }

                GethDebugBuiltInTracerType::FourByteTracer => {
                    setup_executor!(&env, &mut state, FourByteInspector::default() => executor);

                    let mut results = Vec::with_capacity(env.transactions.len());
                    for (index, tx) in env.transactions.iter().enumerate() {
                        let tx_hash = tx.inner.tx_hash();
                        let recovered_tx = &tx.inner.inner;
                        trace!(tx_index = index, tx_hash = %tx_hash, "Tracing transaction");

                        match executor.run_transaction(recovered_tx) {
                            Ok(outcome) => {
                                let frame = FourByteFrame::from(executor.inspector());
                                *executor.inspector_mut() = FourByteInspector::default();
                                executor.evm.db_mut().commit(outcome.inner.state);
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

                GethDebugBuiltInTracerType::MuxTracer => {
                    let (mux_config, inspector) = mux_config_and_inspector(tracer_config)?;

                    setup_executor!(&env, &mut state, inspector => executor);

                    let mut results = Vec::with_capacity(env.transactions.len());
                    for (index, tx) in env.transactions.iter().enumerate() {
                        let tx_hash = tx.inner.tx_hash();
                        let recovered_tx = &tx.inner.inner;
                        let info = tx_info_at(block, tx, index);
                        trace!(tx_index = index, tx_hash = %tx_hash, "Tracing transaction");

                        match executor.run_transaction(recovered_tx) {
                            Ok(outcome) => {
                                let result = outcome.inner.result;
                                let state_changes = outcome.inner.state.clone();
                                let result_and_state = revm::context::result::ResultAndState {
                                    result,
                                    state: outcome.inner.state,
                                };

                                let mux_result = {
                                    let db = executor.evm.db();
                                    let inspector = executor.inspector();
                                    inspector.try_into_mux_frame(&result_and_state, db, info)
                                };

                                *executor.inspector_mut() =
                                    MuxInspector::try_from_config(mux_config.clone()).unwrap();
                                executor.evm.db_mut().commit(state_changes);

                                match mux_result {
                                    Ok(frame) => {
                                        results.push(TraceResult::Success {
                                            result: frame.into(),
                                            tx_hash: Some(tx_hash),
                                        });
                                    }
                                    // The mux frame builder fails only via `DB::Error`
                                    // (witness reads), so this aborts as data, like the
                                    // plain prestate path.
                                    Err(e) => {
                                        return Err(frame_build_error(
                                            "MuxFrame creation failed",
                                            e,
                                        )
                                        .into());
                                    }
                                }
                            }
                            Err(e) => return Err(tx_replay_failure(index, tx_hash, e).into()),
                        }
                    }
                    results
                }
            },

            GethDebugTracerType::JsTracer(code) => {
                let config_json = tracer_config.clone().into_json();

                if env.transactions.is_empty() {
                    return Ok(vec![]);
                }

                let first_info = tx_info_at(block, &env.transactions[0], 0);
                let inspector =
                    js_inspector(code.clone(), config_json.clone(), make_tx_ctx(&first_info))?;

                setup_executor!(&env, &mut state, inspector => executor);

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
                            let result = outcome.inner.result;
                            let state_changes = outcome.inner.state.clone();
                            let result_and_state = revm::context::result::ResultAndState {
                                result,
                                state: outcome.inner.state,
                            };

                            let evm_env_ref = env.evm_env.clone();
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
        trace_block_with_tracing_inspector(&env, block, &mut state, &TracerKind::Default(opts))?
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
    light_witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
    opts: GethDebugTracingOptions,
) -> Result<GethTrace, TraceError> {
    let env = TracingEnv::new(chain_spec, block, light_witness)?;

    if tx_index >= env.transactions.len() {
        return Err(ValidationError::BlockIncomplete.into());
    }

    let target_tx = &env.transactions[tx_index];
    trace!(
        tx_hash = %target_tx.inner.tx_hash(),
        "Starting transaction trace"
    );

    let witness_db = env.create_witness_db(contracts);
    let cache_db = CacheDB::new(&witness_db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    let GethDebugTracingOptions { tracer, tracer_config, .. } = &opts;
    let target_tx = &env.transactions[tx_index];
    let recovered_target = &target_tx.inner.inner;
    let info = tx_info_at(block, target_tx, tx_index);

    if let Some(tracer) = tracer {
        return match tracer {
            GethDebugTracerType::BuiltInTracer(builtin) => match builtin {
                GethDebugBuiltInTracerType::NoopTracer => {
                    Ok(GethTrace::NoopTracer(NoopFrame::default()))
                }

                // The `unwrap_or_default()` on these three config parses is unreachable in
                // practice: RPC handlers reject malformed configs via
                // `RequestShape::classify` (-32602) before reaching the executor.
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config.clone().into_call_config().unwrap_or_default();
                    trace_tx_with_tracing_inspector(
                        &env,
                        block,
                        &mut state,
                        tx_index,
                        &TracerKind::Call(call_config),
                    )
                }

                GethDebugBuiltInTracerType::PreStateTracer => {
                    let prestate_config =
                        tracer_config.clone().into_pre_state_config().unwrap_or_default();
                    trace_tx_with_tracing_inspector(
                        &env,
                        block,
                        &mut state,
                        tx_index,
                        &TracerKind::PreState(prestate_config),
                    )
                }

                GethDebugBuiltInTracerType::FlatCallTracer => {
                    let flat_call_config =
                        tracer_config.clone().into_flat_call_config().unwrap_or_default();
                    trace_tx_with_tracing_inspector(
                        &env,
                        block,
                        &mut state,
                        tx_index,
                        &TracerKind::FlatCall(flat_call_config),
                    )
                }

                GethDebugBuiltInTracerType::FourByteTracer => {
                    setup_executor!(&env, &mut state, FourByteInspector::default() => executor);
                    replay_preceding_txs!(executor, &env, tx_index);

                    *executor.inspector_mut() = FourByteInspector::default();

                    executor
                        .run_transaction(recovered_target)
                        .map_err(ValidationError::BlockReplayFailed)?;
                    let frame = FourByteFrame::from(executor.inspector());
                    Ok(frame.into())
                }

                GethDebugBuiltInTracerType::MuxTracer => {
                    let (mux_config, inspector) = mux_config_and_inspector(tracer_config)?;

                    setup_executor!(&env, &mut state, inspector => executor);
                    replay_preceding_txs!(executor, &env, tx_index);

                    *executor.inspector_mut() = mux_inspector(mux_config)?;

                    let outcome = executor
                        .run_transaction(recovered_target)
                        .map_err(ValidationError::BlockReplayFailed)?;
                    let result = outcome.inner.result;
                    let result_and_state = revm::context::result::ResultAndState {
                        result,
                        state: outcome.inner.state,
                    };

                    let db = executor.evm.db();
                    let inspector = executor.inspector();
                    // Data-attributable: the mux frame builder fails only via
                    // `DB::Error` (witness reads), like the plain prestate path.
                    inspector
                        .try_into_mux_frame(&result_and_state, db, info)
                        .map(|frame| frame.into())
                        .map_err(|e| frame_build_error("MuxFrame creation failed", e).into())
                }
            },

            GethDebugTracerType::JsTracer(code) => {
                let config_json = tracer_config.clone().into_json();
                let inspector =
                    js_inspector(code.clone(), config_json.clone(), make_tx_ctx(&info))?;

                setup_executor!(&env, &mut state, inspector => executor);
                replay_preceding_txs!(executor, &env, tx_index);

                *executor.inspector_mut() =
                    js_inspector(code.clone(), config_json, make_tx_ctx(&info))?;

                let outcome = executor
                    .run_transaction(recovered_target)
                    .map_err(ValidationError::BlockReplayFailed)?;
                let result = outcome.inner.result;
                let result_and_state =
                    revm::context::result::ResultAndState { result, state: outcome.inner.state };

                let evm_env_ref = env.evm_env.clone();
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
    trace_tx_with_tracing_inspector(&env, block, &mut state, tx_index, &TracerKind::Default(opts))
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
    light_witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<Vec<LocalizedTransactionTrace>, TraceError> {
    let env = TracingEnv::new(chain_spec, block, light_witness)?;

    let witness_db = env.create_witness_db(contracts);
    let cache_db = CacheDB::new(&witness_db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    let inspector = TracingInspector::new(TracingInspectorConfig::default_parity());
    setup_executor!(&env, &mut state, inspector => executor);

    let mut all_traces = Vec::new();

    for (index, tx) in env.transactions.iter().enumerate() {
        let recovered_tx = &tx.inner.inner;
        let info = tx_info_at(block, tx, index);

        match executor.run_transaction(recovered_tx) {
            Ok(outcome) => {
                let state_changes = outcome.inner.state;
                let traces = executor
                    .inspector()
                    .clone()
                    .into_parity_builder()
                    .into_localized_transaction_traces(info);
                all_traces.extend(traces);

                *executor.inspector_mut() =
                    TracingInspector::new(TracingInspectorConfig::default_parity());
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
    light_witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<Vec<LocalizedTransactionTrace>, TraceError> {
    let env = TracingEnv::new(chain_spec, block, light_witness)?;

    if tx_index >= env.transactions.len() {
        return Err(ValidationError::BlockIncomplete.into());
    }

    let witness_db = env.create_witness_db(contracts);
    let cache_db = CacheDB::new(&witness_db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    let inspector = TracingInspector::new(TracingInspectorConfig::default_parity());
    setup_executor!(&env, &mut state, inspector => executor);
    replay_preceding_txs!(executor, &env, tx_index);

    *executor.inspector_mut() = TracingInspector::new(TracingInspectorConfig::default_parity());

    let target_tx = &env.transactions[tx_index];
    let recovered_tx = &target_tx.inner.inner;
    let info = tx_info_at(block, target_tx, tx_index);

    match executor.run_transaction(recovered_tx) {
        Ok(_outcome) => {
            let traces = executor
                .inspector()
                .clone()
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
    /// entries, while an unparseable mux config over healthy data is
    /// [`TraceError::Request`].
    #[test]
    fn trace_block_discriminates_data_and_request_errors() {
        use stateless_test_utils::fixtures::TestFixtures;

        use crate::data_provider::{BlockData, test_support::fixture_block_data};

        let chain_spec =
            ChainSpec::from_genesis(TestFixtures::synthetic().load_genesis().expect("genesis"));
        let BlockData { block, witness, contracts } = fixture_block_data();

        let err = trace_block(
            &chain_spec,
            &block,
            witness.clone(),
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
        let err = trace_block(&chain_spec, &block, witness, &contracts, opts)
            .expect_err("an unparseable mux config must be rejected");
        assert!(matches!(err, TraceError::Request(_)), "got: {err:?}");
    }
}
