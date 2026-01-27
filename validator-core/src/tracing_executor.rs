//! Tracing executor for debug and trace RPC methods.
//!
//! This module provides tracing capabilities for block and transaction execution,
//! matching the mega-reth debug.rs implementation pattern.

use std::collections::HashMap;

use alloy_consensus::{Transaction, transaction::Recovered};
use alloy_evm::Evm as EvmTrait;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_rpc_types_eth::{Block, BlockTransactions, TransactionInfo, TransactionRequest};
use alloy_rpc_types_trace::geth::{
    call::FlatCallFrame, FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType,
    GethDebugTracingOptions, GethTrace, NoopFrame, TraceResult,
};
use alloy_rpc_types_trace::parity::{TraceResults, TraceType};
use alloy_primitives::map::HashSet;
use alloy_rpc_types_trace::parity::LocalizedTransactionTrace;
use alloy_evm::block::BlockExecutor;
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use eyre::Result;
use mega_evm::op_alloy_consensus::OpTxEnvelope;
use op_alloy_network::TransactionResponse;
use op_alloy_rpc_types::Transaction as OpTransaction;
use revm::{
    context::TxEnv,
    database::State,
    state::{Bytecode, EvmState},
    DatabaseCommit,
};
use revm_inspectors::tracing::{
    FourByteInspector, MuxInspector, TracingInspector, TracingInspectorConfig,
    TransactionContext, js::JsInspector,
};
use salt::SaltWitness;

use crate::{
    chain_spec::ChainSpec,
    database::{WitnessDatabase, WitnessExternalEnv},
    executor::{ValidationError, create_evm_env},
};
use mega_evm::{BlockLimits, MegaBlockExecutionCtx, MegaBlockExecutorFactory, MegaEvmFactory, MegaHardforks, MegaTransaction};

// ---------------------------------------------------------------------------
// Common tracing environment setup
// ---------------------------------------------------------------------------

/// Pre-built execution environment for tracing operations.
///
/// Encapsulates the common setup shared by both `trace_block` and `trace_transaction`,
/// avoiding duplicated environment construction code.
struct TracingEnv<'a> {
    transactions: &'a [OpTransaction],
    executor_factory: MegaBlockExecutorFactory<
        ChainSpec,
        MegaEvmFactory<WitnessExternalEnv>,
        OpAlloyReceiptBuilder,
    >,
    block_ctx: MegaBlockExecutionCtx,
    evm_env: alloy_evm::EvmEnv<mega_evm::MegaSpecId>,
    // Hold owned data so references stay valid
    _salt_witness: salt::Witness,
}

impl<'a> TracingEnv<'a> {
    /// Creates a new tracing environment from block data.
    ///
    /// Performs all common setup: witness conversion, database creation,
    /// EVM environment setup, executor factory, hardfork detection, and block context.
    fn new(
        chain_spec: &ChainSpec,
        block: &'a Block<OpTransaction>,
        witness: &SaltWitness,
        _contracts: &'a HashMap<B256, Bytecode>,
    ) -> Result<Self, ValidationError> {
        let BlockTransactions::Full(transactions) = &block.transactions else {
            return Err(ValidationError::BlockIncomplete);
        };

        // Create external environment oracle from salt witness
        let ext_env = WitnessExternalEnv::new(witness, block.header.number)
            .map_err(ValidationError::EnvOracleConstructionFailed)?;

        // Create witness (owned, kept alive for State's lifetime)
        let salt_witness_obj = salt::Witness::from(witness.clone());

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

        Ok(Self {
            transactions,
            executor_factory,
            block_ctx,
            evm_env,
            _salt_witness: salt_witness_obj,
        })
    }
}

/// Creates a `TransactionInfo` for a transaction at the given index within the block.
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
// Public API
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
pub fn trace_block(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    witness: &SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
    opts: GethDebugTracingOptions,
) -> Result<Vec<TraceResult>, ValidationError> {
    let env = TracingEnv::new(chain_spec, block, witness, contracts)?;

    // Create witness database and State
    let salt_witness_obj = salt::Witness::from(witness.clone());
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &salt_witness_obj,
        contracts,
    };
    let mut state = State::builder()
        .with_database_ref(&witness_db)
        .build();

    let mut results = Vec::with_capacity(env.transactions.len());

    for (index, tx) in env.transactions.iter().enumerate() {
        let tx_hash = tx.inner.tx_hash();
        let recovered_tx = &tx.inner.inner;
        let info = tx_info_at(block, tx, index);

        let (trace_result, state_changes) = trace_transaction_inner(
            &env.executor_factory,
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
            recovered_tx,
            tx.inner.gas_limit(),
            &opts,
            info,
        );

        match trace_result {
            Ok(trace) => {
                results.push(TraceResult::Success {
                    result: trace,
                    tx_hash: Some(tx_hash),
                });
            }
            Err(error) => {
                results.push(TraceResult::Error {
                    error,
                    tx_hash: Some(tx_hash),
                });
            }
        }

        // Commit state changes for subsequent transactions
        if index < env.transactions.len() - 1 {
            state.commit(state_changes);
        }
    }

    Ok(results)
}

/// Traces a single transaction execution.
///
/// Replays all transactions before the target index (without tracing), then traces
/// the target transaction with the configured inspector. This mirrors the pattern
/// in `crates/rpc/rpc/src/debug.rs:202` where block data is fetched once and the
/// target transaction is traced in-place.
///
/// # Arguments
/// * `chain_spec` - Chain specification
/// * `block` - Block containing the transaction
/// * `tx_index` - Index of the transaction in the block
/// * `witness` - SALT witness for state access
/// * `contracts` - Contract bytecode cache
/// * `opts` - Tracing options
///
/// # Returns
/// Returns the transaction trace data
pub fn trace_transaction(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    tx_index: usize,
    witness: &SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
    opts: GethDebugTracingOptions,
) -> Result<GethTrace, ValidationError> {
    let env = TracingEnv::new(chain_spec, block, witness, contracts)?;

    if tx_index >= env.transactions.len() {
        return Err(ValidationError::BlockIncomplete);
    }

    // Create witness database and State
    let salt_witness_obj = salt::Witness::from(witness.clone());
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &salt_witness_obj,
        contracts,
    };
    let mut state = State::builder()
        .with_database_ref(&witness_db)
        .build();

    // Replay preceding transactions without tracing
    for tx in env.transactions.iter().take(tx_index) {
        let mut executor = env.executor_factory.create_executor(
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
        );

        let recovered_tx = &tx.inner.inner;
        executor.execute_transaction(recovered_tx)
            .map_err(ValidationError::BlockReplayFailed)?;
    }

    // Trace the target transaction
    let target_tx = &env.transactions[tx_index];
    let recovered_tx = &target_tx.inner.inner;
    let info = tx_info_at(block, target_tx, tx_index);

    let (trace_result, _state_changes) = trace_transaction_inner(
        &env.executor_factory,
        &mut state,
        env.block_ctx.clone(),
        env.evm_env.clone(),
        recovered_tx,
        target_tx.inner.gas_limit(),
        &opts,
        info,
    );

    trace_result.map_err(|e| ValidationError::BlockReplayFailed(
        alloy_evm::block::BlockExecutionError::msg(e)
    ))
}

/// Traces a call request (like eth_call) with debug tracing options.
///
/// This function executes a call against the state at the parent block (the block prior to
/// the given block) and returns a Geth-style trace. It mirrors the `debug_traceCall` RPC method.
///
/// # Arguments
/// * `chain_spec` - Chain specification
/// * `block` - Block whose parent state we execute against
/// * `witness` - SALT witness for state access
/// * `contracts` - Contract bytecode cache
/// * `call` - The call request to trace
/// * `opts` - Debug tracing options
///
/// # Returns
/// Returns the Geth trace result
pub fn trace_call(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    witness: &SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
    call: &TransactionRequest,
    opts: GethDebugTracingOptions,
) -> Result<GethTrace, ValidationError> {
    // Create external environment oracle from salt witness
    let ext_env = WitnessExternalEnv::new(witness, block.header.number)
        .map_err(ValidationError::EnvOracleConstructionFailed)?;

    // Create witness database and State
    let salt_witness_obj = salt::Witness::from(witness.clone());
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &salt_witness_obj,
        contracts,
    };
    let mut state = State::builder()
        .with_database_ref(&witness_db)
        .build();

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

    // Build TxEnv from TransactionRequest
    let tx_env = build_tx_env_from_request(call, &evm_env);
    let tx_gas_limit = tx_env.gas_limit;

    // Create TransactionInfo for the call (no real hash/index since it's a simulated call)
    let tx_info = TransactionInfo {
        hash: None,
        index: None,
        block_hash: Some(block.header.hash),
        block_number: Some(block.header.number),
        base_fee: block.header.base_fee_per_gas,
    };

    let (trace_result, _state_changes) = trace_call_inner(
        &executor_factory,
        &mut state,
        block_ctx,
        evm_env,
        tx_env,
        tx_gas_limit,
        &opts,
        tx_info,
    );

    trace_result.map_err(|e| ValidationError::BlockReplayFailed(
        alloy_evm::block::BlockExecutionError::msg(e)
    ))
}

/// Traces a call with Parity-style trace types.
///
/// This function executes a call against the state at the parent block and returns
/// Parity-style traces (trace, vmTrace, stateDiff). It mirrors the `trace_call` RPC method.
///
/// # Arguments
/// * `chain_spec` - Chain specification
/// * `block` - Block whose parent state we execute against
/// * `witness` - SALT witness for state access
/// * `contracts` - Contract bytecode cache
/// * `call` - The call request to trace
/// * `trace_types` - Which trace types to include
///
/// # Returns
/// Returns the Parity TraceResults
pub fn parity_trace_call(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    witness: &SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
    call: &TransactionRequest,
    trace_types: HashSet<TraceType>,
) -> Result<TraceResults, ValidationError> {
    // Create external environment oracle from salt witness
    let ext_env = WitnessExternalEnv::new(witness, block.header.number)
        .map_err(ValidationError::EnvOracleConstructionFailed)?;

    // Create witness database and State
    let salt_witness_obj = salt::Witness::from(witness.clone());
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &salt_witness_obj,
        contracts,
    };
    let mut state = State::builder()
        .with_database_ref(&witness_db)
        .build();

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

    // Build TxEnv from TransactionRequest
    let tx_env = build_tx_env_from_request(call, &evm_env);
    let tx_gas_limit = tx_env.gas_limit;

    // Create TransactionInfo for the call
    let tx_info = TransactionInfo {
        hash: None,
        index: None,
        block_hash: Some(block.header.hash),
        block_number: Some(block.header.number),
        base_fee: block.header.base_fee_per_gas,
    };

    let result = parity_trace_call_inner(
        &executor_factory,
        &mut state,
        block_ctx,
        evm_env,
        tx_env,
        tx_gas_limit,
        &trace_types,
        tx_info,
    );

    result.map_err(|e| ValidationError::BlockReplayFailed(
        alloy_evm::block::BlockExecutionError::msg(e)
    ))
}

/// Gets the nonce (transaction count) of an address at a specific block.
///
/// This function reads the account state from the witness and returns the nonce.
/// It mirrors the `debug_getHistoryTransactionCount` method.
///
/// # Arguments
/// * `block` - Block to query state at
/// * `witness` - SALT witness for state access
/// * `contracts` - Contract bytecode cache
/// * `address` - The address to query
///
/// # Returns
/// Returns the nonce (transaction count) for the address
pub fn get_history_transaction_count(
    block: &Block<OpTransaction>,
    witness: &SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
    address: Address,
) -> Result<U256, ValidationError> {
    // Create witness database
    let salt_witness_obj = salt::Witness::from(witness.clone());
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &salt_witness_obj,
        contracts,
    };

    // Read the account from the witness database
    use revm::DatabaseRef;
    match witness_db.basic_ref(address) {
        Ok(Some(account)) => Ok(U256::from(account.nonce)),
        Ok(None) => Ok(U256::ZERO), // Account doesn't exist, nonce is 0
        Err(e) => Err(ValidationError::EnvOracleConstructionFailed(e)),
    }
}

/// Builds a TxEnv from a TransactionRequest.
fn build_tx_env_from_request(
    call: &TransactionRequest,
    evm_env: &alloy_evm::EvmEnv<mega_evm::MegaSpecId>,
) -> TxEnv {
    let mut tx_env = TxEnv::default();

    // Set caller (from)
    if let Some(from) = call.from {
        tx_env.caller = from;
    }

    // Set kind (to) - call.to is already Option<TxKind>
    if let Some(to) = call.to {
        tx_env.kind = to;
    } else {
        tx_env.kind = TxKind::Create;
    }

    // Set value
    if let Some(value) = call.value {
        tx_env.value = value;
    }

    // Set data (input)
    if let Some(ref input) = call.input.input {
        tx_env.data = input.clone();
    }

    // Set gas limit
    if let Some(gas) = call.gas {
        tx_env.gas_limit = gas;
    } else {
        // Use block gas limit as default
        tx_env.gas_limit = evm_env.block_env.gas_limit;
    }

    // Set gas price (convert from u128 to u128)
    if let Some(gas_price) = call.gas_price {
        tx_env.gas_price = gas_price;
    } else if let Some(max_fee) = call.max_fee_per_gas {
        tx_env.gas_price = max_fee;
    } else {
        tx_env.gas_price = evm_env.block_env.basefee as u128;
    }

    // Set priority fee
    if let Some(priority_fee) = call.max_priority_fee_per_gas {
        tx_env.gas_priority_fee = Some(priority_fee);
    }

    // Set nonce (nonce is u64, not Option<u64>)
    if let Some(nonce) = call.nonce {
        tx_env.nonce = nonce;
    }

    // Set access list
    if let Some(ref access_list) = call.access_list {
        tx_env.access_list = access_list.clone();
    }

    tx_env
}

/// Traces a block execution and returns Parity-style localized transaction traces.
///
/// This function is specifically for the `trace_block` RPC method which returns
/// a flat list of `LocalizedTransactionTrace` objects, not wrapped in `TraceResult`.
///
/// # Arguments
/// * `chain_spec` - Chain specification
/// * `block` - Block to trace
/// * `witness` - SALT witness for state access
/// * `contracts` - Contract bytecode cache
///
/// # Returns
/// Returns a flat vector of localized transaction traces for all transactions in the block
pub fn parity_trace_block(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    witness: &SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<Vec<LocalizedTransactionTrace>, ValidationError> {
    let env = TracingEnv::new(chain_spec, block, witness, contracts)?;

    // Create witness database and State
    let salt_witness_obj = salt::Witness::from(witness.clone());
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &salt_witness_obj,
        contracts,
    };
    let mut state = State::builder()
        .with_database_ref(&witness_db)
        .build();

    let mut all_traces = Vec::new();

    for (index, tx) in env.transactions.iter().enumerate() {
        let recovered_tx = &tx.inner.inner;
        let info = tx_info_at(block, tx, index);

        let inspector = TracingInspector::new(
            TracingInspectorConfig::default_parity(),
        );

        let mut executor = env.executor_factory.create_executor_with_inspector(
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
            inspector,
        );

        match executor.run_transaction(recovered_tx) {
            Ok(outcome) => {
                let state_changes = outcome.inner.state;

                // Get traces without setting transaction_gas_limit - the inspector
                // already tracks the correct gas (after intrinsic gas deduction)
                let inspector = executor.inspector();
                let traces: Vec<LocalizedTransactionTrace> = inspector
                    .clone()
                    .into_parity_builder()
                    .into_localized_transaction_traces(info);

                all_traces.extend(traces);

                // Commit state changes for subsequent transactions
                if index < env.transactions.len() - 1 {
                    state.commit(state_changes);
                }
            }
            Err(e) => {
                return Err(ValidationError::BlockReplayFailed(
                    alloy_evm::block::BlockExecutionError::msg(e.to_string())
                ));
            }
        }
    }

    Ok(all_traces)
}

/// Traces a single transaction and returns Parity-style localized transaction traces.
///
/// This function is specifically for the `trace_transaction` RPC method which returns
/// a list of `LocalizedTransactionTrace` objects for a single transaction.
///
/// # Arguments
/// * `chain_spec` - Chain specification
/// * `block` - Block containing the transaction
/// * `tx_index` - Index of the transaction in the block
/// * `witness` - SALT witness for state access
/// * `contracts` - Contract bytecode cache
///
/// # Returns
/// Returns a vector of localized transaction traces for the specified transaction
pub fn parity_trace_transaction(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    tx_index: usize,
    witness: &SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
) -> Result<Vec<LocalizedTransactionTrace>, ValidationError> {
    let env = TracingEnv::new(chain_spec, block, witness, contracts)?;

    if tx_index >= env.transactions.len() {
        return Err(ValidationError::BlockIncomplete);
    }

    // Create witness database and State
    let salt_witness_obj = salt::Witness::from(witness.clone());
    let witness_db = WitnessDatabase {
        header: &block.header,
        witness: &salt_witness_obj,
        contracts,
    };
    let mut state = State::builder()
        .with_database_ref(&witness_db)
        .build();

    // Replay preceding transactions without tracing
    for tx in env.transactions.iter().take(tx_index) {
        let mut executor = env.executor_factory.create_executor(
            &mut state,
            env.block_ctx.clone(),
            env.evm_env.clone(),
        );

        let recovered_tx = &tx.inner.inner;
        executor.execute_transaction(recovered_tx)
            .map_err(ValidationError::BlockReplayFailed)?;
    }

    // Trace the target transaction
    let target_tx = &env.transactions[tx_index];
    let recovered_tx = &target_tx.inner.inner;
    let info = tx_info_at(block, target_tx, tx_index);

    let inspector = TracingInspector::new(
        TracingInspectorConfig::default_parity(),
    );

    let mut executor = env.executor_factory.create_executor_with_inspector(
        &mut state,
        env.block_ctx.clone(),
        env.evm_env.clone(),
        inspector,
    );

    match executor.run_transaction(recovered_tx) {
        Ok(_outcome) => {
            // Get traces without setting transaction_gas_limit - the inspector
            // already tracks the correct gas (after intrinsic gas deduction)
            let inspector = executor.inspector();
            let traces: Vec<LocalizedTransactionTrace> = inspector
                .clone()
                .into_parity_builder()
                .into_localized_transaction_traces(info);

            Ok(traces)
        }
        Err(e) => {
            Err(ValidationError::BlockReplayFailed(
                alloy_evm::block::BlockExecutionError::msg(e.to_string())
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Internal tracer dispatch
// ---------------------------------------------------------------------------

/// Internal helper function to trace a transaction and return both the trace and state changes.
///
/// This function matches the logic of mega-reth's trace_transaction helper function (debug.rs:717).
/// It handles all tracer types.
fn trace_transaction_inner<DB, ExtEnvFactory>(
    executor_factory: &MegaBlockExecutorFactory<
        ChainSpec,
        MegaEvmFactory<ExtEnvFactory>,
        OpAlloyReceiptBuilder,
    >,
    state: &mut State<DB>,
    block_ctx: MegaBlockExecutionCtx,
    evm_env: alloy_evm::EvmEnv<mega_evm::MegaSpecId>,
    tx: &Recovered<OpTxEnvelope>,
    tx_gas_limit: u64,
    opts: &GethDebugTracingOptions,
    tx_info: TransactionInfo,
) -> (Result<GethTrace, String>, EvmState)
where
    DB: alloy_evm::Database + revm::DatabaseRef<Error = <DB as revm::Database>::Error>,
    ExtEnvFactory: mega_evm::ExternalEnvFactory + Clone,
{
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
                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

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
                    let call_config = tracer_config
                        .clone()
                        .into_call_config()
                        .unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_call_config(&call_config)
                    );

                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

                    match executor.run_transaction(tx) {
                        Ok(outcome) => {
                            let gas_used = outcome.inner.result.gas_used();
                            let state_changes = outcome.inner.state;

                            let inspector = executor.inspector_mut();
                            inspector.set_transaction_gas_limit(tx_gas_limit);
                            let frame = inspector
                                .geth_builder()
                                .geth_call_traces(call_config, gas_used);

                            (Ok(frame.into()), state_changes)
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                // PreStateTracer
                GethDebugBuiltInTracerType::PreStateTracer => {
                    let prestate_config = tracer_config
                        .clone()
                        .into_pre_state_config()
                        .unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_prestate_config(&prestate_config)
                    );

                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

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
                                inspector.geth_builder().geth_prestate_traces(&result_and_state, &prestate_config, db)
                            };

                            match frame_result {
                                Ok(frame) => (Ok(frame.into()), state_changes),
                                Err(e) => (Err(format!("PreState trace failed: {:?}", e)), state_changes),
                            }
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                // MuxTracer
                GethDebugBuiltInTracerType::MuxTracer => {
                    let mux_config = match tracer_config.clone().into_mux_config() {
                        Ok(cfg) => cfg,
                        Err(_) => return (Err("Invalid mux tracer config".to_string()), Default::default()),
                    };

                    let inspector = match MuxInspector::try_from_config(mux_config) {
                        Ok(insp) => insp,
                        Err(e) => return (Err(format!("MuxInspector creation failed: {:?}", e)), Default::default()),
                    };

                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

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
                                Err(e) => (Err(format!("MuxFrame creation failed: {:?}", e)), state_changes),
                            }
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                // FlatCallTracer (Parity-style)
                GethDebugBuiltInTracerType::FlatCallTracer => {
                    let flat_call_config = tracer_config
                        .clone()
                        .into_flat_call_config()
                        .unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_flat_call_config(&flat_call_config),
                    );

                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

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
                let inspector = match JsInspector::with_transaction_context(
                    code.clone(),
                    config,
                    tx_context,
                ) {
                    Ok(insp) => insp,
                    Err(e) => return (Err(format!("Failed to create JsInspector: {:?}", e)), Default::default()),
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
                        match inspector.json_result(result_and_state, &tx_env, &evm_env.block_env, &*db) {
                            Ok(json_value) => (Ok(GethTrace::JS(json_value)), state_changes),
                            Err(e) => (Err(format!("JS tracer execution failed: {:?}", e)), state_changes),
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

    let mut executor = executor_factory.create_executor_with_inspector(
        state,
        block_ctx,
        evm_env,
        inspector,
    );

    match executor.run_transaction(tx) {
        Ok(outcome) => {
            let gas_used = outcome.inner.result.gas_used();
            let return_value = outcome.inner.result.output().cloned().unwrap_or_default();
            let state_changes = outcome.inner.state;

            let inspector = executor.inspector_mut();
            inspector.set_transaction_gas_limit(tx_gas_limit);
            let frame = inspector
                .geth_builder()
                .geth_traces(gas_used, return_value, *config);

            (Ok(frame.into()), state_changes)
        }
        Err(e) => (Err(e.to_string()), Default::default()),
    }
}

/// Internal helper function to trace a call request with TxEnv.
///
/// This is similar to `trace_transaction_inner` but takes a TxEnv directly
/// instead of a recovered transaction.
fn trace_call_inner<DB, ExtEnvFactory>(
    executor_factory: &MegaBlockExecutorFactory<
        ChainSpec,
        MegaEvmFactory<ExtEnvFactory>,
        OpAlloyReceiptBuilder,
    >,
    state: &mut State<DB>,
    block_ctx: MegaBlockExecutionCtx,
    evm_env: alloy_evm::EvmEnv<mega_evm::MegaSpecId>,
    tx_env: TxEnv,
    tx_gas_limit: u64,
    opts: &GethDebugTracingOptions,
    tx_info: TransactionInfo,
) -> (Result<GethTrace, String>, EvmState)
where
    DB: alloy_evm::Database + revm::DatabaseRef<Error = <DB as revm::Database>::Error>,
    ExtEnvFactory: mega_evm::ExternalEnvFactory + Clone,
{
    let GethDebugTracingOptions { config, tracer, tracer_config, .. } = opts;

    // Handle different tracer types
    if let Some(tracer) = tracer {
        return match tracer {
            GethDebugTracerType::BuiltInTracer(builtin) => match builtin {
                GethDebugBuiltInTracerType::NoopTracer => {
                    (Ok(GethTrace::NoopTracer(NoopFrame::default())), Default::default())
                }

                GethDebugBuiltInTracerType::FourByteTracer => {
                    let inspector = FourByteInspector::default();
                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

                    // Create MegaTransaction and execute
                    let mut mega_tx = MegaTransaction::new(tx_env);
                    mega_tx.enveloped_tx = Some(Bytes::new());
                    match alloy_evm::Evm::transact_raw(&mut executor.evm, mega_tx) {
                        Ok(outcome) => {
                            let inspector = executor.inspector();
                            let frame = FourByteFrame::from(inspector);
                            let state_changes = outcome.state;
                            (Ok(frame.into()), state_changes)
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .clone()
                        .into_call_config()
                        .unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_call_config(&call_config)
                    );

                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

                    // Create MegaTransaction and execute
                    let mut mega_tx = MegaTransaction::new(tx_env);
                    mega_tx.enveloped_tx = Some(Bytes::new());
                    match alloy_evm::Evm::transact_raw(&mut executor.evm, mega_tx) {
                        Ok(outcome) => {
                            let gas_used = outcome.result.gas_used();
                            let state_changes = outcome.state;

                            let inspector = executor.inspector_mut();
                            inspector.set_transaction_gas_limit(tx_gas_limit);
                            let frame = inspector
                                .geth_builder()
                                .geth_call_traces(call_config, gas_used);

                            (Ok(frame.into()), state_changes)
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                GethDebugBuiltInTracerType::PreStateTracer => {
                    let prestate_config = tracer_config
                        .clone()
                        .into_pre_state_config()
                        .unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_prestate_config(&prestate_config)
                    );

                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

                    // Create MegaTransaction and execute
                    let mut mega_tx = MegaTransaction::new(tx_env);
                    mega_tx.enveloped_tx = Some(Bytes::new());
                    match alloy_evm::Evm::transact_raw(&mut executor.evm, mega_tx) {
                        Ok(outcome) => {
                            let result = outcome.result;
                            let state_changes = outcome.state.clone();

                            let result_and_state = revm::context::result::ResultAndState {
                                result,
                                state: outcome.state,
                            };

                            executor.inspector_mut().set_transaction_gas_limit(tx_gas_limit);

                            let frame_result = {
                                let db = executor.evm.db();
                                let inspector = executor.inspector();
                                inspector.geth_builder().geth_prestate_traces(&result_and_state, &prestate_config, db)
                            };

                            match frame_result {
                                Ok(frame) => (Ok(frame.into()), state_changes),
                                Err(e) => (Err(format!("PreState trace failed: {:?}", e)), state_changes),
                            }
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                GethDebugBuiltInTracerType::MuxTracer => {
                    let mux_config = match tracer_config.clone().into_mux_config() {
                        Ok(cfg) => cfg,
                        Err(_) => return (Err("Invalid mux tracer config".to_string()), Default::default()),
                    };

                    let inspector = match MuxInspector::try_from_config(mux_config) {
                        Ok(insp) => insp,
                        Err(e) => return (Err(format!("MuxInspector creation failed: {:?}", e)), Default::default()),
                    };

                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

                    // Create MegaTransaction and execute
                    let mut mega_tx = MegaTransaction::new(tx_env);
                    mega_tx.enveloped_tx = Some(Bytes::new());
                    match alloy_evm::Evm::transact_raw(&mut executor.evm, mega_tx) {
                        Ok(outcome) => {
                            let result = outcome.result;
                            let state_changes = outcome.state.clone();

                            let result_and_state = revm::context::result::ResultAndState {
                                result,
                                state: outcome.state,
                            };

                            let db = executor.evm.db();
                            let inspector = executor.inspector();

                            match inspector.try_into_mux_frame(&result_and_state, db, tx_info) {
                                Ok(frame) => (Ok(frame.into()), state_changes),
                                Err(e) => (Err(format!("MuxFrame creation failed: {:?}", e)), state_changes),
                            }
                        }
                        Err(e) => (Err(e.to_string()), Default::default()),
                    }
                }

                GethDebugBuiltInTracerType::FlatCallTracer => {
                    let flat_call_config = tracer_config
                        .clone()
                        .into_flat_call_config()
                        .unwrap_or_default();

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_flat_call_config(&flat_call_config),
                    );

                    let mut executor = executor_factory.create_executor_with_inspector(
                        state,
                        block_ctx,
                        evm_env,
                        inspector,
                    );

                    // Create MegaTransaction and execute
                    let mut mega_tx = MegaTransaction::new(tx_env);
                    mega_tx.enveloped_tx = Some(Bytes::new());
                    match alloy_evm::Evm::transact_raw(&mut executor.evm, mega_tx) {
                        Ok(outcome) => {
                            let state_changes = outcome.state;

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

            GethDebugTracerType::JsTracer(code) => {
                let config = tracer_config.clone().into_json();

                let tx_context = TransactionContext {
                    block_hash: tx_info.block_hash,
                    tx_hash: tx_info.hash,
                    tx_index: tx_info.index.map(|i| i as usize),
                };

                let inspector = match JsInspector::with_transaction_context(
                    code.clone(),
                    config,
                    tx_context,
                ) {
                    Ok(insp) => insp,
                    Err(e) => return (Err(format!("Failed to create JsInspector: {:?}", e)), Default::default()),
                };

                let mut executor = executor_factory.create_executor_with_inspector(
                    state,
                    block_ctx,
                    evm_env.clone(),
                    inspector,
                );

                // Create MegaTransaction and execute
                let mut mega_tx = MegaTransaction::new(tx_env.clone());
                mega_tx.enveloped_tx = Some(Bytes::new());
                match alloy_evm::Evm::transact_raw(&mut executor.evm, mega_tx) {
                    Ok(outcome) => {
                        let result = outcome.result;
                        let state_changes = outcome.state.clone();

                        let result_and_state = revm::context::result::ResultAndState {
                            result,
                            state: outcome.state,
                        };

                        let (db, inspector, _) = EvmTrait::components_mut(&mut executor.evm);
                        match inspector.json_result(result_and_state, &tx_env, &evm_env.block_env, &*db) {
                            Ok(json_value) => (Ok(GethTrace::JS(json_value)), state_changes),
                            Err(e) => (Err(format!("JS tracer execution failed: {:?}", e)), state_changes),
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

    let mut executor = executor_factory.create_executor_with_inspector(
        state,
        block_ctx,
        evm_env,
        inspector,
    );

    // Create MegaTransaction and execute
    let mut mega_tx = MegaTransaction::new(tx_env);
    mega_tx.enveloped_tx = Some(Bytes::new());
    match alloy_evm::Evm::transact_raw(&mut executor.evm, mega_tx) {
        Ok(outcome) => {
            let gas_used = outcome.result.gas_used();
            let return_value = outcome.result.output().cloned().unwrap_or_default();
            let state_changes = outcome.state;

            let inspector = executor.inspector_mut();
            inspector.set_transaction_gas_limit(tx_gas_limit);
            let frame = inspector
                .geth_builder()
                .geth_traces(gas_used, return_value, *config);

            (Ok(frame.into()), state_changes)
        }
        Err(e) => (Err(e.to_string()), Default::default()),
    }
}

/// Internal helper function to trace a call with Parity-style trace types.
fn parity_trace_call_inner<DB, ExtEnvFactory>(
    executor_factory: &MegaBlockExecutorFactory<
        ChainSpec,
        MegaEvmFactory<ExtEnvFactory>,
        OpAlloyReceiptBuilder,
    >,
    state: &mut State<DB>,
    block_ctx: MegaBlockExecutionCtx,
    evm_env: alloy_evm::EvmEnv<mega_evm::MegaSpecId>,
    tx_env: TxEnv,
    tx_gas_limit: u64,
    trace_types: &HashSet<TraceType>,
    _tx_info: TransactionInfo,
) -> Result<TraceResults, String>
where
    DB: alloy_evm::Database + revm::DatabaseRef<Error = <DB as revm::Database>::Error>,
    ExtEnvFactory: mega_evm::ExternalEnvFactory + Clone,
{
    let inspector_config = TracingInspectorConfig::from_parity_config(trace_types);
    let inspector = TracingInspector::new(inspector_config);

    let mut executor = executor_factory.create_executor_with_inspector(
        state,
        block_ctx,
        evm_env,
        inspector,
    );

    // Create MegaTransaction and execute
    let mut mega_tx = MegaTransaction::new(tx_env);
    mega_tx.enveloped_tx = Some(Bytes::new());
    match alloy_evm::Evm::transact_raw(&mut executor.evm, mega_tx) {
        Ok(outcome) => {
            let result_and_state = revm::context::result::ResultAndState {
                result: outcome.result,
                state: outcome.state,
            };

            let db = executor.evm.db();
            let inspector = executor.inspector();

            inspector
                .clone()
                .with_transaction_gas_limit(tx_gas_limit)
                .into_parity_builder()
                .into_trace_results_with_state(&result_and_state, trace_types, db)
                .map_err(|e| format!("Parity trace failed: {:?}", e))
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_tracer() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::NoopTracer
            )),
            ..Default::default()
        };
        assert!(opts.tracer.is_some());
    }

    #[test]
    fn test_call_tracer_config() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer
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
                GethDebugBuiltInTracerType::PreStateTracer
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
                GethDebugBuiltInTracerType::FourByteTracer
            )),
            ..Default::default()
        };
        assert!(opts.tracer.is_some());
    }

    #[test]
    fn test_flat_call_tracer_config() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::FlatCallTracer
            )),
            ..Default::default()
        };
        let config = opts.tracer_config.clone().into_flat_call_config();
        assert!(config.is_ok());
    }

    #[test]
    fn test_js_tracer() {
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::JsTracer("{ result: function() { return {}; } }".to_string())),
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
