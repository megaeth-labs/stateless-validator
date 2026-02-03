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

use std::collections::HashMap;

use alloy_consensus::{Transaction, transaction::Recovered};
use alloy_evm::{Evm as EvmTrait, block::BlockExecutor};
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_eth::{Block, BlockTransactions, TransactionInfo};
use alloy_rpc_types_trace::{
    geth::{
        FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
        GethTrace, NoopFrame, TraceResult,
        call::FlatCallFrame,
        pre_state::{AccountState, PreStateFrame},
    },
    parity::LocalizedTransactionTrace,
};
use eyre::Result;
use mega_evm::{
    BlockLimits, MegaBlockExecutionCtx, MegaBlockExecutorFactory, MegaEvmFactory, MegaHardforks,
    op_alloy_consensus::OpTxEnvelope,
};
use op_alloy_network::TransactionResponse;
use op_alloy_rpc_types::Transaction as OpTransaction;
use revm::{
    DatabaseCommit, DatabaseRef,
    context::TxEnv,
    database::{CacheDB, State},
    primitives::KECCAK_EMPTY,
    state::{Bytecode, EvmState},
};
use revm_inspectors::tracing::{
    FourByteInspector, MuxInspector, TracingInspector, TracingInspectorConfig, TransactionContext,
    js::JsInspector,
};
use tracing::{instrument, trace, warn};

use crate::{
    chain_spec::ChainSpec,
    data_types::{PlainKey, PlainValue},
    database::{WitnessDatabase, WitnessExternalEnv},
    executor::{ValidationError, create_evm_env},
    light_witness::{LightWitness, LightWitnessExecutor},
};

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Extracts all contract code hashes from a SALT witness.
///
/// This function scans the witness for accounts with non-empty bytecode and returns
/// their code hashes. These hashes can then be used to fetch the actual bytecode
/// from an RPC provider.
///
/// # Arguments
/// * `witness` - The SALT witness containing account state
///
/// # Returns
/// A vector of unique code hashes (B256) that need to be fetched
pub fn extract_code_hashes(witness: &LightWitness) -> Vec<B256> {
    let mut code_hashes: Vec<B256> = witness
        .kvs
        .values()
        .filter_map(|salt_val| salt_val.as_ref())
        .filter_map(|val| match (PlainKey::decode(val.key()), PlainValue::decode(val.value())) {
            (PlainKey::Account(_), PlainValue::Account(acc)) => {
                acc.codehash.filter(|&codehash| codehash != KECCAK_EMPTY)
            }
            _ => None,
        })
        .collect();

    code_hashes.sort();
    code_hashes.dedup();
    code_hashes
}

// ---------------------------------------------------------------------------
// Fast Tracing Environment Setup (for LightWitness)
// ---------------------------------------------------------------------------

/// Pre-built execution environment for fast tracing operations.
///
/// This is the fast version of `TracingEnv` that uses `LightWitnessExecutor`
/// instead of `salt::Witness` for improved deserialization performance.
struct TracingEnv<'a> {
    /// Transactions from the block (full transaction data required).
    transactions: &'a [OpTransaction],
    /// Factory for creating block executors with optional inspectors.
    executor_factory: MegaBlockExecutorFactory<
        ChainSpec,
        MegaEvmFactory<WitnessExternalEnv>,
        OpAlloyReceiptBuilder,
    >,
    /// Block execution context (parent hash, beacon root, limits).
    block_ctx: MegaBlockExecutionCtx,
    /// EVM environment (block env, spec ID).
    evm_env: alloy_evm::EvmEnv<mega_evm::MegaSpecId>,
    /// Owned fast witness data - kept alive for State's lifetime.
    light_witness_executor: LightWitnessExecutor,
}

impl<'a> TracingEnv<'a> {
    /// Creates a new fast tracing environment from block data.
    fn new(
        chain_spec: &ChainSpec,
        block: &'a Block<OpTransaction>,
        light_witness: LightWitness,
    ) -> Result<Self, ValidationError> {
        let BlockTransactions::Full(transactions) = &block.transactions else {
            return Err(ValidationError::BlockIncomplete);
        };

        // Create external environment oracle from fast witness
        let ext_env = WitnessExternalEnv::from_light_witness(&light_witness, block.header.number)
            .map_err(ValidationError::EnvOracleConstructionFailed)?;

        // Create fast witness executor
        let light_witness_executor = LightWitnessExecutor::from(light_witness);

        // Create EVM environment
        let evm_env = create_evm_env(&block.header, chain_spec);

        // Create block executor factory
        let evm_factory = MegaEvmFactory::new().with_external_env_factory(ext_env);
        let executor_factory = MegaBlockExecutorFactory::new(
            chain_spec.clone(),
            evm_factory,
            OpAlloyReceiptBuilder::default(),
        );

        // Determine block limits based on hardfork
        let hardfork = chain_spec.hardfork(block.header.timestamp);
        let block_limits = if let Some(hardfork) = hardfork {
            BlockLimits::from_hardfork_and_block_gas_limit(hardfork, block.header.gas_limit)
        } else {
            BlockLimits::no_limits()
        };

        // Create block context
        let block_ctx = MegaBlockExecutionCtx::new(
            block.header.parent_hash,
            block.header.parent_beacon_block_root,
            Bytes::new(),
            block_limits,
        );

        Ok(Self { transactions, executor_factory, block_ctx, evm_env, light_witness_executor })
    }

    /// Creates a witness database that borrows from this environment.
    fn create_witness_db<'b>(
        &'b self,
        header: &'b alloy_rpc_types_eth::Header,
        contracts: &'b HashMap<B256, Bytecode>,
    ) -> WitnessDatabase<'b, LightWitnessExecutor> {
        WitnessDatabase { header, witness: &self.light_witness_executor, contracts }
    }

    /// Replays transactions before the target index without tracing.
    fn replay_preceding_transactions<DB>(
        &self,
        state: &mut State<DB>,
        tx_index: usize,
    ) -> Result<(), ValidationError>
    where
        DB: alloy_evm::Database + revm::DatabaseRef<Error = <DB as revm::Database>::Error>,
    {
        for tx in self.transactions.iter().take(tx_index) {
            let mut executor = self.executor_factory.create_executor(
                state,
                self.block_ctx.clone(),
                self.evm_env.clone(),
            );

            let recovered_tx = &tx.inner.inner;
            executor
                .execute_transaction(recovered_tx)
                .map_err(ValidationError::BlockReplayFailed)?;
        }
        Ok(())
    }

    /// Executes a transaction with Parity-style tracing.
    fn execute_with_parity_tracing<DB>(
        &self,
        state: &mut State<DB>,
        tx: &Recovered<OpTxEnvelope>,
        info: TransactionInfo,
    ) -> Result<(Vec<LocalizedTransactionTrace>, EvmState), ValidationError>
    where
        DB: alloy_evm::Database + revm::DatabaseRef<Error = <DB as revm::Database>::Error>,
    {
        let inspector = TracingInspector::new(TracingInspectorConfig::default_parity());

        let mut executor = self.executor_factory.create_executor_with_inspector(
            state,
            self.block_ctx.clone(),
            self.evm_env.clone(),
            inspector,
        );

        match executor.run_transaction(tx) {
            Ok(outcome) => {
                let state_changes = outcome.inner.state;
                let traces = executor
                    .inspector()
                    .clone()
                    .into_parity_builder()
                    .into_localized_transaction_traces(info);
                Ok((traces, state_changes))
            }
            Err(e) => Err(ValidationError::BlockReplayFailed(
                alloy_evm::block::BlockExecutionError::msg(e.to_string()),
            )),
        }
    }
}

/// Creates a `TransactionInfo` for a transaction at the given index within the block.
///
/// This info is used by tracers to include block/transaction context in their output.
fn tx_info_at(block: &Block<OpTransaction>, tx: &OpTransaction, index: usize) -> TransactionInfo {
    TransactionInfo {
        hash: Some(tx.inner.tx_hash()),
        index: Some(index as u64),
        block_hash: Some(block.header.hash),
        block_number: Some(block.header.number),
        base_fee: block.header.base_fee_per_gas,
    }
}

// ---------------------------------------------------------------------------
// Public API - Geth-style Tracing
// ---------------------------------------------------------------------------

/// Traces a block execution with detailed inspector data.
///
/// This function replays all transactions in a block and collects execution traces
/// using revm-inspectors. It follows the mega-reth trace_block pattern.
///
/// # Arguments
/// * `chain_spec` - Chain specification
/// * `block` - Block to trace
/// * `witness` - SALT witness for state access
/// * `contracts` - Contract bytecode cache
/// * `opts` - Tracing options
///
/// # Returns
/// Returns a vector of trace results for each transaction in the block
#[instrument(skip_all, name = "trace_block", fields(block_number = block.header.number, block_hash = %block.header.hash))]
pub fn trace_block(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
    opts: GethDebugTracingOptions,
) -> Result<Vec<TraceResult>, ValidationError> {
    let env = TracingEnv::new(chain_spec, block, witness)?;

    trace!(tx_count = env.transactions.len(), "Starting block trace");

    // Create witness database and wrap it with CacheDB, then State.
    // CacheDB tracks all accessed accounts (not just modified), which is required
    // for prestateTracer+diff to return consistent results with mega-reth.
    // State wraps CacheDB to provide the interface expected by MegaBlockExecutor.
    let witness_db = env.create_witness_db(&block.header, contracts);
    let cache_db = CacheDB::new(&witness_db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    // Apply pre-execution changes (system contract calls) before tracing transactions.
    // This ensures system contracts are loaded into the cache, which is required
    // for prestateTracer to return consistent results with mega-reth.
    {
        let mut executor = env.executor_factory.create_executor(
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
        );
        executor.apply_pre_execution_changes().map_err(ValidationError::BlockReplayFailed)?;
    }

    let mut results = Vec::with_capacity(env.transactions.len());

    for (index, tx) in env.transactions.iter().enumerate() {
        let tx_hash = tx.inner.tx_hash();
        let recovered_tx = &tx.inner.inner;
        let info = tx_info_at(block, tx, index);

        let tx_ctx = TxTracingContext {
            tx: recovered_tx,
            tx_gas_limit: tx.inner.gas_limit(),
            tx_info: info,
        };

        trace!(
            tx_index = index,
            tx_hash = %tx_hash,
            "Tracing transaction"
        );

        let (trace_result, state_changes) = trace_transaction_inner(
            &env.executor_factory,
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
            tx_ctx,
            &opts,
        );

        match trace_result {
            Ok(trace) => {
                results.push(TraceResult::Success { result: trace, tx_hash: Some(tx_hash) });
            }
            Err(error) => {
                warn!(
                    tx_index = index,
                    tx_hash = %tx_hash,
                    %error,
                    "Transaction trace failed"
                );
                results.push(TraceResult::Error { error, tx_hash: Some(tx_hash) });
            }
        }

        // Commit state changes for subsequent transactions
        if index < env.transactions.len() - 1 {
            state.commit(state_changes);
        }
    }

    trace!(traced_count = results.len(), "Block trace completed");

    Ok(results)
}

/// Traces a single transaction execution using LightWitness.
#[instrument(skip_all, name = "trace_tx", fields(block_number = block.header.number, tx_index))]
pub fn trace_transaction(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    tx_index: usize,
    light_witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
    opts: GethDebugTracingOptions,
) -> Result<GethTrace, ValidationError> {
    let env = TracingEnv::new(chain_spec, block, light_witness)?;

    if tx_index >= env.transactions.len() {
        return Err(ValidationError::BlockIncomplete);
    }

    let target_tx = &env.transactions[tx_index];
    trace!(
        tx_hash = %target_tx.inner.tx_hash(),
        "Starting transaction trace"
    );

    let witness_db = env.create_witness_db(&block.header, contracts);
    let cache_db = CacheDB::new(&witness_db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    // Apply pre-execution changes
    {
        let mut executor = env.executor_factory.create_executor(
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
        );
        executor.apply_pre_execution_changes().map_err(ValidationError::BlockReplayFailed)?;
    }

    // Replay preceding transactions without tracing
    if tx_index > 0 {
        trace!(preceding_tx_count = tx_index, "Replaying preceding transactions");
    }
    env.replay_preceding_transactions(&mut state, tx_index)?;

    // Trace the target transaction
    let recovered_tx = &target_tx.inner.inner;
    let info = tx_info_at(block, target_tx, tx_index);

    let tx_ctx = TxTracingContext {
        tx: recovered_tx,
        tx_gas_limit: target_tx.inner.gas_limit(),
        tx_info: info,
    };

    let (trace_result, _) = trace_transaction_inner(
        &env.executor_factory,
        &mut state,
        env.block_ctx.clone(),
        env.evm_env.clone(),
        tx_ctx,
        &opts,
    );

    trace_result.map_err(|e| {
        ValidationError::BlockReplayFailed(alloy_evm::block::BlockExecutionError::msg(e))
    })
}

/// Computes Parity-style traces for all transactions in a block using LightWitness.
#[instrument(skip_all, name = "parity_trace_block_light", fields(block_number = block.header.number))]
pub fn parity_trace_block(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    light_witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<Vec<LocalizedTransactionTrace>, ValidationError> {
    let env = TracingEnv::new(chain_spec, block, light_witness)?;

    let witness_db = env.create_witness_db(&block.header, contracts);
    let cache_db = CacheDB::new(&witness_db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    // Apply pre-execution changes
    {
        let mut executor = env.executor_factory.create_executor(
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
        );
        executor.apply_pre_execution_changes().map_err(ValidationError::BlockReplayFailed)?;
    }

    let mut all_traces = Vec::new();

    for (index, tx) in env.transactions.iter().enumerate() {
        let recovered_tx = &tx.inner.inner;
        let info = tx_info_at(block, tx, index);

        let (traces, state_changes) =
            env.execute_with_parity_tracing(&mut state, recovered_tx, info)?;

        all_traces.extend(traces);

        if index < env.transactions.len() - 1 {
            state.commit(state_changes);
        }
    }

    Ok(all_traces)
}

/// Traces a single transaction with Parity-style tracing using LightWitness.
#[instrument(skip_all, name = "parity_trace_tx_light", fields(block_number = block.header.number, tx_index))]
pub fn parity_trace_transaction(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    tx_index: usize,
    light_witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<Vec<LocalizedTransactionTrace>, ValidationError> {
    let env = TracingEnv::new(chain_spec, block, light_witness)?;

    if tx_index >= env.transactions.len() {
        return Err(ValidationError::BlockIncomplete);
    }

    let witness_db = env.create_witness_db(&block.header, contracts);
    let cache_db = CacheDB::new(&witness_db);
    let mut state = State::builder().with_database_ref(&cache_db).build();

    // Apply pre-execution changes
    {
        let mut executor = env.executor_factory.create_executor(
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
        );
        executor.apply_pre_execution_changes().map_err(ValidationError::BlockReplayFailed)?;
    }

    // Replay preceding transactions
    if tx_index > 0 {
        env.replay_preceding_transactions(&mut state, tx_index)?;
    }

    // Trace the target transaction
    let target_tx = &env.transactions[tx_index];
    let recovered_tx = &target_tx.inner.inner;
    let info = tx_info_at(block, target_tx, tx_index);

    let (traces, _) = env.execute_with_parity_tracing(&mut state, recovered_tx, info)?;

    Ok(traces)
}

// ---------------------------------------------------------------------------
// Internal Tracer Dispatch
// ---------------------------------------------------------------------------

/// Context for tracing a single transaction.
///
/// Groups transaction-related parameters to reduce function argument count
/// and improve code readability.
struct TxTracingContext<'a> {
    /// The recovered (signature-verified) transaction to trace.
    tx: &'a Recovered<OpTxEnvelope>,
    /// Gas limit from the transaction (used for gas accounting in traces).
    tx_gas_limit: u64,
    /// Transaction context info (hash, index, block info) for trace output.
    tx_info: TransactionInfo,
}

/// Internal helper function to trace a transaction with the appropriate tracer.
///
/// This function dispatches to the correct tracer based on the tracing options.
/// It handles all built-in tracer types (CallTracer, PreStateTracer, etc.) as well
/// as custom JavaScript tracers. Returns both the trace result and state changes
/// so the caller can commit state for subsequent transactions.
///
/// # Tracer Selection
/// - If `opts.tracer` is `Some`, uses the specified tracer type
/// - If `opts.tracer` is `None`, uses the default struct logger tracer
///
/// # Returns
/// Tuple of (trace_result, state_changes) where trace_result may be an error string
/// This function matches the logic of mega-reth's trace_transaction helper function (debug.rs:717).
/// It handles all tracer types.
#[allow(clippy::too_many_arguments)]
fn trace_transaction_inner<DB, ExtEnvFactory>(
    executor_factory: &MegaBlockExecutorFactory<
        ChainSpec,
        MegaEvmFactory<ExtEnvFactory>,
        OpAlloyReceiptBuilder,
    >,
    state: &mut State<DB>,
    block_ctx: MegaBlockExecutionCtx,
    evm_env: alloy_evm::EvmEnv<mega_evm::MegaSpecId>,
    tx_ctx: TxTracingContext<'_>,
    opts: &GethDebugTracingOptions,
) -> (Result<GethTrace, String>, EvmState)
where
    DB: alloy_evm::Database + revm::DatabaseRef<Error = <DB as revm::Database>::Error>,
    ExtEnvFactory: mega_evm::ExternalEnvFactory + Clone,
{
    let TxTracingContext { tx, tx_gas_limit, tx_info } = tx_ctx;
    let GethDebugTracingOptions { config, tracer, tracer_config, .. } = opts;

    // Handle different tracer types
    if let Some(tracer) = tracer {
        return match tracer {
            GethDebugTracerType::BuiltInTracer(builtin) => match builtin {
                // NoopTracer - doesn't need execution
                GethDebugBuiltInTracerType::NoopTracer => {
                    (Ok(GethTrace::NoopTracer(NoopFrame::default())), Default::default())
                }

                // FourByteTracer
                GethDebugBuiltInTracerType::FourByteTracer => {
                    let inspector = FourByteInspector::default();
                    let mut executor = executor_factory
                        .create_executor_with_inspector(state, block_ctx, evm_env, inspector);

                    match executor.run_transaction(tx) {
                        Ok(outcome) => {
                            let inspector = executor.inspector();
                            let frame = FourByteFrame::from(inspector);
                            let state_changes = outcome.inner.state;
                            (Ok(frame.into()), state_changes)
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                // CallTracer
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config.clone().into_call_config().unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_call_config(&call_config),
                    );

                    let mut executor = executor_factory
                        .create_executor_with_inspector(state, block_ctx, evm_env, inspector);

                    match executor.run_transaction(tx) {
                        Ok(outcome) => {
                            let gas_used = outcome.inner.result.gas_used();
                            let state_changes = outcome.inner.state;

                            let inspector = executor.inspector_mut();
                            inspector.set_transaction_gas_limit(tx_gas_limit);
                            let frame =
                                inspector.geth_builder().geth_call_traces(call_config, gas_used);

                            (Ok(frame.into()), state_changes)
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                // PreStateTracer
                GethDebugBuiltInTracerType::PreStateTracer => {
                    let prestate_config =
                        tracer_config.clone().into_pre_state_config().unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_prestate_config(&prestate_config),
                    );

                    let mut executor = executor_factory
                        .create_executor_with_inspector(state, block_ctx, evm_env, inspector);

                    match executor.run_transaction(tx) {
                        Ok(outcome) => {
                            let result = outcome.inner.result;
                            let state_changes = outcome.inner.state.clone();

                            // Build ResultAndState for prestate traces
                            let result_and_state = revm::context::result::ResultAndState {
                                result,
                                state: outcome.inner.state,
                            };

                            // First set the gas limit on the inspector
                            executor.inspector_mut().set_transaction_gas_limit(tx_gas_limit);

                            // Then get the builder and db separately
                            let frame_result = {
                                let db = executor.evm.db();
                                let inspector = executor.inspector();
                                inspector.geth_builder().geth_prestate_traces(
                                    &result_and_state,
                                    &prestate_config,
                                    db,
                                )
                            };

                            match frame_result {
                                Ok(frame) => {
                                    // For diff mode, add accounts that were accessed but not
                                    // modified This matches
                                    // mega-reth behavior where such accounts appear with
                                    // pre state and empty post state {}
                                    let final_frame = if prestate_config.is_diff_mode() {
                                        let db = executor.evm.db();
                                        add_accessed_unchanged_accounts(frame, &state_changes, db)
                                    } else {
                                        frame
                                    };
                                    (Ok(final_frame.into()), state_changes)
                                }
                                Err(e) => {
                                    (Err(format!("PreState trace failed: {:?}", e)), state_changes)
                                }
                            }
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                // MuxTracer
                GethDebugBuiltInTracerType::MuxTracer => {
                    let mux_config = match tracer_config.clone().into_mux_config() {
                        Ok(cfg) => cfg,
                        Err(_) => {
                            return (
                                Err("Invalid mux tracer config".to_string()),
                                Default::default(),
                            );
                        }
                    };

                    let inspector = match MuxInspector::try_from_config(mux_config) {
                        Ok(insp) => insp,
                        Err(e) => {
                            return (
                                Err(format!("MuxInspector creation failed: {:?}", e)),
                                Default::default(),
                            );
                        }
                    };

                    let mut executor = executor_factory
                        .create_executor_with_inspector(state, block_ctx, evm_env, inspector);

                    match executor.run_transaction(tx) {
                        Ok(outcome) => {
                            let result = outcome.inner.result;
                            let state_changes = outcome.inner.state.clone();

                            // Build ResultAndState for mux traces
                            let result_and_state = revm::context::result::ResultAndState {
                                result,
                                state: outcome.inner.state,
                            };

                            // Get database reference
                            let db = executor.evm.db();
                            let inspector = executor.inspector();

                            match inspector.try_into_mux_frame(&result_and_state, db, tx_info) {
                                Ok(frame) => (Ok(frame.into()), state_changes),
                                Err(e) => (
                                    Err(format!("MuxFrame creation failed: {:?}", e)),
                                    state_changes,
                                ),
                            }
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                // FlatCallTracer (Parity-style)
                GethDebugBuiltInTracerType::FlatCallTracer => {
                    let flat_call_config =
                        tracer_config.clone().into_flat_call_config().unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_flat_call_config(&flat_call_config),
                    );

                    let mut executor = executor_factory
                        .create_executor_with_inspector(state, block_ctx, evm_env, inspector);

                    match executor.run_transaction(tx) {
                        Ok(outcome) => {
                            let state_changes = outcome.inner.state;

                            let inspector = executor.inspector();
                            let frame: FlatCallFrame = inspector
                                .clone()
                                .with_transaction_gas_limit(tx_gas_limit)
                                .into_parity_builder()
                                .into_localized_transaction_traces(tx_info);

                            (Ok(frame.into()), state_changes)
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }
            },

            // JS Tracer - execute custom JavaScript tracer
            GethDebugTracerType::JsTracer(code) => {
                let config = tracer_config.clone().into_json();

                // Convert TransactionInfo to TransactionContext
                let tx_context = TransactionContext {
                    block_hash: tx_info.block_hash,
                    tx_hash: tx_info.hash,
                    tx_index: tx_info.index.map(|i| i as usize),
                };

                // Create JS inspector with transaction context
                let inspector =
                    match JsInspector::with_transaction_context(code.clone(), config, tx_context) {
                        Ok(insp) => insp,
                        Err(e) => {
                            return (
                                Err(format!("Failed to create JsInspector: {:?}", e)),
                                Default::default(),
                            );
                        }
                    };

                let mut executor = executor_factory.create_executor_with_inspector(
                    state,
                    block_ctx,
                    evm_env.clone(),
                    inspector,
                );

                match executor.run_transaction(tx) {
                    Ok(outcome) => {
                        let result = outcome.inner.result;
                        let state_changes = outcome.inner.state.clone();

                        // Build ResultAndState for JS tracer
                        let result_and_state = revm::context::result::ResultAndState {
                            result,
                            state: outcome.inner.state,
                        };

                        // Get the JS tracer result
                        // Use components_mut to split borrows between db and inspector
                        let tx_env = TxEnv::default();
                        let (db, inspector, _) = EvmTrait::components_mut(&mut executor.evm);
                        match inspector.json_result(
                            result_and_state,
                            &tx_env,
                            &evm_env.block_env,
                            &*db,
                        ) {
                            Ok(json_value) => (Ok(GethTrace::JS(json_value)), state_changes),
                            Err(e) => {
                                (Err(format!("JS tracer execution failed: {:?}", e)), state_changes)
                            }
                        }
                    }
                    Err(e) => (Err(e.to_string()), Default::default()),
                }
            }
        };
    }

    // Default: struct logger tracer
    let inspector_config = TracingInspectorConfig::from_geth_config(config);
    let inspector = TracingInspector::new(inspector_config);

    let mut executor =
        executor_factory.create_executor_with_inspector(state, block_ctx, evm_env, inspector);

    match executor.run_transaction(tx) {
        Ok(outcome) => {
            let gas_used = outcome.inner.result.gas_used();
            let return_value = outcome.inner.result.output().cloned().unwrap_or_default();
            let state_changes = outcome.inner.state;

            let inspector = executor.inspector_mut();
            inspector.set_transaction_gas_limit(tx_gas_limit);
            let frame = inspector.geth_builder().geth_traces(gas_used, return_value, *config);

            // Convert DefaultFrame to JSON and fix returnValue serialization.
            // alloy-rpc-types-trace 1.1.2 serializes Bytes with "0x" prefix,
            // but mega-reth uses v1.0.23 which serializes without prefix.
            let mut frame_value = serde_json::to_value(frame).unwrap();
            if let Some(rv) = frame_value.get_mut("returnValue") &&
                let Some(s) = rv.as_str()
            {
                *rv = serde_json::Value::String(s.strip_prefix("0x").unwrap_or(s).to_string());
            }

            (Ok(GethTrace::JS(frame_value)), state_changes)
        }
        Err(e) => (Err(e.to_string()), Default::default()),
    }
}

/// Adds accounts that were accessed but not modified to the prestate diff trace.
///
/// In mega-reth, accounts that are accessed during transaction execution (e.g., fee recipients
/// with zero balance increment) appear in the diff trace with their pre-state and an empty
/// post-state `{}`. The `geth_prestate_diff_traces` function in revm-inspectors removes these
/// accounts via `retain_changed()` because their pre and post states are identical.
///
/// This function restores those accounts to match mega-reth behavior:
/// - For each account in `state_changes` that is not in the diff result
/// - Only add accounts that were actually touched during execution
/// - Add the account's pre-state from the database
/// - Add an empty post-state `{}`
fn add_accessed_unchanged_accounts<DB: DatabaseRef>(
    frame: PreStateFrame,
    state_changes: &EvmState,
    db: &DB,
) -> PreStateFrame {
    match frame {
        PreStateFrame::Diff(mut diff) => {
            for (addr, account) in state_changes.iter() {
                // Skip if already in the result
                if diff.pre.contains_key(addr) || diff.post.contains_key(addr) {
                    continue;
                }

                // Only add accounts that were actually touched during execution.
                // Accounts that were only loaded but not touched (e.g., for reading code)
                // should not appear in the prestate diff.
                if !account.is_touched() {
                    continue;
                }

                // Get the account's original state from the database
                if let Ok(Some(account_info)) = db.basic_ref(*addr) {
                    // Add pre-state with account info
                    let code = account_info.code.as_ref().map(|c| c.original_bytes());
                    let pre_state = AccountState::from_account_info(
                        account_info.nonce,
                        account_info.balance,
                        code,
                    );
                    diff.pre.insert(*addr, pre_state);

                    // Add empty post-state (account was accessed but not modified)
                    diff.post.insert(*addr, AccountState::default());
                }
            }
            PreStateFrame::Diff(diff)
        }
        // For non-diff mode, return as-is
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
        // Default should use struct logger config
        let _config = TracingInspectorConfig::from_geth_config(&opts.config);
    }
}
