//! RPC Service Module
//!
//! Contains all RPC method registration and request handling logic.
//! Separates RPC concerns from the main server initialization.

use std::{sync::Arc, time::Duration, time::Instant};

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockNumberOrTag;
use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use eyre::Result;
use jsonrpsee::server::RpcModule;
use tracing::{debug, trace, warn};
use validator_core::chain_spec::ChainSpec;

use crate::data_provider::{BlockData, DataProvider};
use crate::metrics;
use crate::response_cache::{CachedResource, ResponseCache, ResponseVariant};

// ---------------------------------------------------------------------------
// RPC Method Name Constants
// ---------------------------------------------------------------------------

const DEBUG_TRACE_BLOCK_BY_NUMBER: &str = "debug_traceBlockByNumber";
const DEBUG_TRACE_BLOCK_BY_HASH: &str = "debug_traceBlockByHash";
const DEBUG_TRACE_TRANSACTION: &str = "debug_traceTransaction";
const TRACE_BLOCK: &str = "trace_block";
const TRACE_TRANSACTION: &str = "trace_transaction";
const DEBUG_GET_CACHE_STATUS: &str = "debug_getCacheStatus";

/// Slow request threshold for logging warnings.
const SLOW_REQUEST_THRESHOLD: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// RPC Context
// ---------------------------------------------------------------------------

/// Shared context for all RPC handlers.
#[derive(Clone)]
pub struct RpcContext {
    /// Data provider for fetching block data (DB -> RPC with single-flight).
    data_provider: Arc<DataProvider>,
    /// Chain specification containing hardfork activation rules.
    chain_spec: Arc<ChainSpec>,
    /// Response cache for HTTP layer caching.
    response_cache: ResponseCache,
}

impl RpcContext {
    /// Creates a new RPC context.
    pub fn new(
        data_provider: Arc<DataProvider>,
        chain_spec: Arc<ChainSpec>,
        response_cache: ResponseCache,
    ) -> Self {
        Self {
            data_provider,
            chain_spec,
            response_cache,
        }
    }
}

// ---------------------------------------------------------------------------
// Error Helpers
// ---------------------------------------------------------------------------

/// Creates a JSON-RPC internal error with the given message.
fn rpc_err(msg: String) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(-32000, msg, None::<()>)
}

// ---------------------------------------------------------------------------
// Trace Computation Helpers
// ---------------------------------------------------------------------------

/// Computes debug trace for a block (Geth-style).
async fn compute_debug_trace_block(
    chain_spec: &ChainSpec,
    data: &BlockData,
    opts: GethDebugTracingOptions,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    let results = validator_core::trace_block(
        chain_spec,
        &data.block,
        &data.salt_witness,
        &data.contracts,
        opts,
    )
    .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

    serde_json::to_value(results).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
}

/// Computes parity trace for a block.
async fn compute_parity_trace_block(
    chain_spec: &ChainSpec,
    data: &BlockData,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    let results = validator_core::parity_trace_block(
        chain_spec,
        &data.block,
        &data.salt_witness,
        &data.contracts,
    )
    .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

    serde_json::to_value(results).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
}

// ---------------------------------------------------------------------------
// Block-Level Cached Trace Helper
// ---------------------------------------------------------------------------

/// Parameters for cached block trace execution.
struct CachedTraceParams {
    resource: CachedResource,
    block_num: u64,
    block_hash: B256,
    variant: ResponseVariant,
    method_name: &'static str,
    start: Instant,
}

/// Executes a block-level trace with caching.
///
/// This helper reduces code duplication for cached block traces by:
/// - Looking up or computing the trace result
/// - Handling cache hit/miss logic
/// - Recording metrics
/// - Logging slow requests
#[allow(clippy::too_many_arguments)]
async fn execute_cached_block_trace<F, Fut>(
    ctx: &RpcContext,
    params: CachedTraceParams,
    compute: F,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>>,
{
    let result = ctx
        .response_cache
        .get_or_compute(params.resource, params.block_num, params.block_hash, params.variant.clone(), compute)
        .await?;

    let elapsed = params.start.elapsed();
    metrics::record_rpc_request(params.method_name, elapsed.as_secs_f64());

    // Slow request warning
    if elapsed > SLOW_REQUEST_THRESHOLD {
        warn!(
            method = params.method_name,
            block_number = params.block_num,
            elapsed_ms = elapsed.as_millis() as u64,
            threshold_ms = SLOW_REQUEST_THRESHOLD.as_millis() as u64,
            "RPC request exceeded threshold"
        );
    }

    debug!(
        method = params.method_name,
        block_number = params.block_num,
        elapsed_ms = elapsed.as_millis() as u64,
        "Request completed"
    );

    Ok(result)
}

// ---------------------------------------------------------------------------
// RPC Method Registration
// ---------------------------------------------------------------------------

/// Registers all RPC methods on the module.
pub fn register_all_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    register_debug_methods(module)?;
    register_trace_methods(module)?;
    register_cache_methods(module)?;
    Ok(())
}

/// Registers all debug_* RPC methods (Geth-style).
fn register_debug_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // debug_traceBlockByNumber
    module.register_async_method(DEBUG_TRACE_BLOCK_BY_NUMBER, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let block_tag: BlockNumberOrTag = seq.next()?;
        let opts: GethDebugTracingOptions = seq.optional_next()?.unwrap_or_default();

        let block_num = ctx
            .data_provider
            .resolve_block_number(block_tag)
            .await
            .map_err(|e| rpc_err(format!("Failed to resolve block number: {e}")))?;

        trace!(
            block_number = block_num,
            method = DEBUG_TRACE_BLOCK_BY_NUMBER,
            "Processing request"
        );

        let data = ctx
            .data_provider
            .get_block_data(block_num)
            .await
            .map_err(|e| rpc_err(format!("Failed to fetch block data: {e}")))?;

        let block_hash = data.block.header.hash;
        let variant = ResponseVariant::from_geth_options(&opts);

        execute_cached_block_trace(
            &ctx,
            CachedTraceParams {
                resource: CachedResource::DebugTraceBlock,
                block_num,
                block_hash,
                variant,
                method_name: DEBUG_TRACE_BLOCK_BY_NUMBER,
                start,
            },
            || compute_debug_trace_block(&ctx.chain_spec, &data, opts),
        )
        .await
    })?;

    // debug_traceBlockByHash
    module.register_async_method(DEBUG_TRACE_BLOCK_BY_HASH, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let block_hash: B256 = seq.next()?;
        let opts: GethDebugTracingOptions = seq.optional_next()?.unwrap_or_default();

        trace!(
            block_hash = %block_hash,
            method = DEBUG_TRACE_BLOCK_BY_HASH,
            "Processing request"
        );

        let data = ctx
            .data_provider
            .get_block_data_by_hash(block_hash)
            .await
            .map_err(|e| rpc_err(format!("Failed to fetch block data: {e}")))?;

        let block_num = data.block.header.number;
        let variant = ResponseVariant::from_geth_options(&opts);

        execute_cached_block_trace(
            &ctx,
            CachedTraceParams {
                resource: CachedResource::DebugTraceBlock,
                block_num,
                block_hash,
                variant,
                method_name: DEBUG_TRACE_BLOCK_BY_HASH,
                start,
            },
            || compute_debug_trace_block(&ctx.chain_spec, &data, opts),
        )
        .await
    })?;

    // debug_traceTransaction (not cached - depends on tx index)
    module.register_async_method(DEBUG_TRACE_TRANSACTION, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let tx_hash: B256 = seq.next()?;
        let opts: GethDebugTracingOptions = seq.optional_next()?.unwrap_or_default();

        trace!(
            tx_hash = %tx_hash,
            method = DEBUG_TRACE_TRANSACTION,
            "Processing request"
        );

        let (data, tx_index) = ctx
            .data_provider
            .get_block_data_for_tx(tx_hash)
            .await
            .map_err(|e| rpc_err(format!("Failed to get block data for tx {tx_hash:?}: {e}")))?;

        let result = validator_core::trace_transaction(
            &ctx.chain_spec,
            &data.block,
            tx_index,
            &data.salt_witness,
            &data.contracts,
            opts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        let elapsed = start.elapsed();
        metrics::record_rpc_request(DEBUG_TRACE_TRANSACTION, elapsed.as_secs_f64());

        // Slow request warning
        if elapsed > SLOW_REQUEST_THRESHOLD {
            warn!(
                method = DEBUG_TRACE_TRANSACTION,
                tx_hash = %tx_hash,
                block_number = data.block.header.number,
                elapsed_ms = elapsed.as_millis() as u64,
                threshold_ms = SLOW_REQUEST_THRESHOLD.as_millis() as u64,
                "RPC request exceeded threshold"
            );
        }

        debug!(
            method = DEBUG_TRACE_TRANSACTION,
            tx_hash = %tx_hash,
            block_number = data.block.header.number,
            tx_index,
            elapsed_ms = elapsed.as_millis() as u64,
            "Request completed"
        );

        serde_json::to_value(&result).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    })?;

    Ok(())
}

/// Registers all trace_* RPC methods (Parity/OpenEthereum-style).
fn register_trace_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // trace_block
    module.register_async_method(TRACE_BLOCK, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let block_tag: BlockNumberOrTag = seq.next()?;

        let block_num = ctx
            .data_provider
            .resolve_block_number(block_tag)
            .await
            .map_err(|e| rpc_err(format!("Failed to resolve block number: {e}")))?;

        trace!(
            block_number = block_num,
            method = TRACE_BLOCK,
            "Processing request"
        );

        let data = ctx
            .data_provider
            .get_block_data(block_num)
            .await
            .map_err(|e| rpc_err(format!("Failed to fetch block data: {e}")))?;

        let block_hash = data.block.header.hash;

        execute_cached_block_trace(
            &ctx,
            CachedTraceParams {
                resource: CachedResource::TraceBlock,
                block_num,
                block_hash,
                variant: ResponseVariant::Default,
                method_name: TRACE_BLOCK,
                start,
            },
            || compute_parity_trace_block(&ctx.chain_spec, &data),
        )
        .await
    })?;

    // trace_transaction (not cached - depends on tx index)
    module.register_async_method(TRACE_TRANSACTION, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let tx_hash: B256 = seq.next()?;

        trace!(
            tx_hash = %tx_hash,
            method = TRACE_TRANSACTION,
            "Processing request"
        );

        let (data, tx_index) = ctx
            .data_provider
            .get_block_data_for_tx(tx_hash)
            .await
            .map_err(|e| rpc_err(format!("Failed to get block data for tx {tx_hash:?}: {e}")))?;

        let result = validator_core::parity_trace_transaction(
            &ctx.chain_spec,
            &data.block,
            tx_index,
            &data.salt_witness,
            &data.contracts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        let elapsed = start.elapsed();
        metrics::record_rpc_request(TRACE_TRANSACTION, elapsed.as_secs_f64());

        // Slow request warning
        if elapsed > SLOW_REQUEST_THRESHOLD {
            warn!(
                method = TRACE_TRANSACTION,
                tx_hash = %tx_hash,
                block_number = data.block.header.number,
                elapsed_ms = elapsed.as_millis() as u64,
                threshold_ms = SLOW_REQUEST_THRESHOLD.as_millis() as u64,
                "RPC request exceeded threshold"
            );
        }

        debug!(
            method = TRACE_TRANSACTION,
            tx_hash = %tx_hash,
            block_number = data.block.header.number,
            tx_index,
            elapsed_ms = elapsed.as_millis() as u64,
            "Request completed"
        );

        serde_json::to_value(&result).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    })?;

    Ok(())
}

/// Registers cache management RPC methods.
fn register_cache_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // debug_getCacheStatus
    module.register_async_method(DEBUG_GET_CACHE_STATUS, |_params, ctx, _| async move {
        let stats = ctx.response_cache.stats();

        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(serde_json::json!({
            "responseCache": {
                "entryCount": stats.entry_count,
                "totalBytes": stats.total_bytes,
                "totalBytesMB": format!("{:.2}", stats.total_bytes as f64 / 1024.0 / 1024.0),
                "hits": stats.hits,
                "misses": stats.misses,
                "hitRate": format!("{:.1}%", stats.hit_rate())
            }
        }))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_err() {
        let err = rpc_err("test error".to_string());
        assert_eq!(err.code(), -32000);
        assert_eq!(err.message(), "test error");
    }

    #[test]
    fn test_method_name_constants() {
        assert_eq!(DEBUG_TRACE_BLOCK_BY_NUMBER, "debug_traceBlockByNumber");
        assert_eq!(DEBUG_TRACE_BLOCK_BY_HASH, "debug_traceBlockByHash");
        assert_eq!(DEBUG_TRACE_TRANSACTION, "debug_traceTransaction");
        assert_eq!(TRACE_BLOCK, "trace_block");
        assert_eq!(TRACE_TRANSACTION, "trace_transaction");
        assert_eq!(DEBUG_GET_CACHE_STATUS, "debug_getCacheStatus");
    }

    #[test]
    fn test_cached_trace_params() {
        let params = CachedTraceParams {
            resource: CachedResource::DebugTraceBlock,
            block_num: 12345,
            block_hash: B256::ZERO,
            variant: ResponseVariant::Default,
            method_name: DEBUG_TRACE_BLOCK_BY_NUMBER,
            start: Instant::now(),
        };

        assert_eq!(params.block_num, 12345);
        assert_eq!(params.method_name, "debug_traceBlockByNumber");
    }

    #[test]
    fn test_rpc_err_with_long_message() {
        let long_msg = "A".repeat(1000);
        let err = rpc_err(long_msg.clone());
        assert_eq!(err.code(), -32000);
        assert_eq!(err.message(), long_msg);
    }

    #[test]
    fn test_cached_trace_params_variants() {
        // Test different resource types
        let debug_params = CachedTraceParams {
            resource: CachedResource::DebugTraceBlock,
            block_num: 100,
            block_hash: B256::from([1u8; 32]),
            variant: ResponseVariant::Default,
            method_name: DEBUG_TRACE_BLOCK_BY_NUMBER,
            start: Instant::now(),
        };

        let trace_params = CachedTraceParams {
            resource: CachedResource::TraceBlock,
            block_num: 100,
            block_hash: B256::from([1u8; 32]),
            variant: ResponseVariant::Default,
            method_name: TRACE_BLOCK,
            start: Instant::now(),
        };

        assert!(matches!(debug_params.resource, CachedResource::DebugTraceBlock));
        assert!(matches!(trace_params.resource, CachedResource::TraceBlock));
    }

    #[test]
    fn test_slow_request_threshold() {
        assert_eq!(SLOW_REQUEST_THRESHOLD.as_secs(), 5);
    }
}
