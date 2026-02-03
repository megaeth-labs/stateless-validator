//! RPC Service Module
//!
//! Contains all RPC method registration and request handling logic.
//! Separates RPC concerns from the main server initialization.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockNumberOrTag;
use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use eyre::Result;
use jsonrpsee::server::RpcModule;
use tracing::{trace, warn};
use validator_core::chain_spec::ChainSpec;

use crate::{
    data_provider::{BlockData, DataProvider},
    metrics,
    response_cache::{CachedResource, ResponseCache, ResponseVariant},
};

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
        Self { data_provider, chain_spec, response_cache }
    }
}

// ---------------------------------------------------------------------------
// Error Helpers
// ---------------------------------------------------------------------------

/// Error code for resource not found (matches mega-reth).
const ERROR_CODE_RESOURCE_NOT_FOUND: i32 = -32001;

/// Error code for internal errors.
const ERROR_CODE_INTERNAL: i32 = -32000;

/// Creates a JSON-RPC "resource not found" error (code -32001).
/// Used for block not found, transaction not found, etc.
fn rpc_err_not_found(msg: String) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(ERROR_CODE_RESOURCE_NOT_FOUND, msg, None::<()>)
}

/// Creates a JSON-RPC internal error (code -32000).
/// Used for execution failures, serialization errors, etc.
fn rpc_err(msg: String) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(ERROR_CODE_INTERNAL, msg, None::<()>)
}

/// Converts a block data fetch error to an appropriate RPC error.
/// Returns "block not found" for missing blocks/witnesses, internal error otherwise.
fn block_data_err(block_num: u64, e: eyre::Report) -> jsonrpsee::types::ErrorObjectOwned {
    let err_str = e.to_string().to_lowercase();
    // Check for "not found" or "timeout" patterns - treat as resource not found
    if err_str.contains("not found") || err_str.contains("timeout") {
        rpc_err_not_found(format!("block not found: {:#x}", block_num))
    } else {
        rpc_err("internal error".to_string())
    }
}

/// Converts a block data fetch error (by hash) to an appropriate RPC error.
fn block_data_err_by_hash(block_hash: B256, e: eyre::Report) -> jsonrpsee::types::ErrorObjectOwned {
    let err_str = e.to_string().to_lowercase();
    if err_str.contains("not found") || err_str.contains("timeout") {
        rpc_err_not_found(format!("block not found: hash {}", block_hash))
    } else {
        rpc_err("internal error".to_string())
    }
}

/// Converts a transaction lookup error to an appropriate RPC error.
fn tx_data_err(e: eyre::Report) -> jsonrpsee::types::ErrorObjectOwned {
    let err_str = e.to_string().to_lowercase();
    if err_str.contains("not found") || err_str.contains("timeout") || err_str.contains("pending") {
        rpc_err_not_found("transaction not found".to_string())
    } else {
        rpc_err("internal error".to_string())
    }
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
    let start = Instant::now();

    let results = validator_core::trace_block(
        chain_spec,
        &data.block,
        data.witness.clone(),
        &data.contracts,
        opts,
    )
    .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

    let trace_ms = start.elapsed().as_millis();

    let value = serde_json::to_value(&results)
        .map_err(|e| rpc_err(format!("Serialization failed: {e}")))?;

    let serialize_ms = start.elapsed().as_millis() - trace_ms;
    let response_size = value.to_string().len();

    tracing::debug!(
        block_number = data.block.header.number,
        tx_count = data.block.transactions.len(),
        trace_ms,
        serialize_ms,
        response_size_kb = response_size / 1024,
        "Trace computation timing"
    );

    Ok(value)
}

/// Computes parity trace for a block.
async fn compute_parity_trace_block(
    chain_spec: &ChainSpec,
    data: &BlockData,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    let results = validator_core::parity_trace_block(
        chain_spec,
        &data.block,
        data.witness.clone(),
        &data.contracts,
    )
    .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

    serde_json::to_value(results).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
}

// ---------------------------------------------------------------------------
// Cache Helper Functions
// ---------------------------------------------------------------------------

/// Checks cache by block number and returns cached value if found.
/// Records metrics and logs cache hit on success.
fn check_cache_by_number(
    cache: &ResponseCache,
    resource: CachedResource,
    block_num: u64,
    variant: &ResponseVariant,
    method_name: &'static str,
    start: Instant,
) -> Option<serde_json::Value> {
    let cached_value = cache.get(resource, block_num, variant.clone())?;

    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    metrics::record_rpc_request(method_name, total_ms / 1000.0);

    trace!(
        method = method_name,
        block = block_num,
        total_ms = format!("{:.2}", total_ms),
        cache_hit = true,
        "Cache hit - returning cached result"
    );

    Some(cached_value)
}

/// Checks cache by block hash and returns cached value if found.
/// Records metrics and logs cache hit on success.
fn check_cache_by_hash(
    cache: &ResponseCache,
    resource: CachedResource,
    block_hash: B256,
    variant: &ResponseVariant,
    method_name: &'static str,
    start: Instant,
) -> Option<serde_json::Value> {
    let (cached_value, block_num) = cache.get_by_hash(resource, block_hash, variant.clone())?;

    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    metrics::record_rpc_request(method_name, total_ms / 1000.0);

    trace!(
        method = method_name,
        block = block_num,
        block_hash = %block_hash,
        total_ms = format!("{:.2}", total_ms),
        cache_hit = true,
        "Cache hit - returning cached result"
    );

    Some(cached_value)
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
    tx_count: usize,
}

/// Executes a block-level trace (cache miss case) and stores the result.
///
/// This function is called only when cache has already been checked and missed.
/// It computes the trace, stores it in cache, and records metrics.
async fn execute_cached_block_trace<F, Fut>(
    ctx: &RpcContext,
    params: CachedTraceParams,
    compute: F,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>
where
    F: FnOnce() -> Fut,
    Fut:
        std::future::Future<Output = Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>>,
{
    let value = compute().await?;

    ctx.response_cache.insert(
        params.resource,
        params.block_num,
        params.block_hash,
        params.variant,
        value.clone(),
    );

    let total_ms = params.start.elapsed().as_secs_f64() * 1000.0;
    metrics::record_rpc_request(params.method_name, total_ms / 1000.0);

    trace!(
        method = params.method_name,
        block = params.block_num,
        tx_count = params.tx_count,
        total_ms = format!("{:.2}", total_ms),
        cache_hit = false,
        "Cache miss - computed and stored result"
    );

    if params.start.elapsed() > SLOW_REQUEST_THRESHOLD {
        warn!(
            method = params.method_name,
            block_number = params.block_num,
            elapsed_ms = total_ms as u64,
            threshold_ms = SLOW_REQUEST_THRESHOLD.as_millis() as u64,
            "RPC request exceeded threshold"
        );
    }

    trace!(
        method = params.method_name,
        block_number = params.block_num,
        elapsed_ms = total_ms as u64,
        "Request completed"
    );

    Ok(value)
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

        let variant = ResponseVariant::from_geth_options(&opts);

        // Check cache before fetching block data
        if let Some(cached) = check_cache_by_number(
            &ctx.response_cache,
            CachedResource::DebugTraceBlock,
            block_num,
            &variant,
            DEBUG_TRACE_BLOCK_BY_NUMBER,
            start,
        ) {
            return Ok::<_, jsonrpsee::types::ErrorObjectOwned>(cached);
        }

        // Fetch block data (DB -> RPC fallback)
        let data = ctx
            .data_provider
            .get_block_data(block_num)
            .await
            .map_err(|e| block_data_err(block_num, e))?;
        let block_hash = data.block.header.hash;
        let result = compute_debug_trace_block(&ctx.chain_spec, &data, opts.clone()).await?;

        // Store result in cache and return
        let total_ms = start.elapsed().as_secs_f64() * 1000.0;
        metrics::record_rpc_request(DEBUG_TRACE_BLOCK_BY_NUMBER, total_ms / 1000.0);

        // Cache the result for future requests
        ctx.response_cache.insert(
            CachedResource::DebugTraceBlock,
            block_num,
            block_hash,
            variant,
            result.clone(),
        );

        Ok(result)
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

        let variant = ResponseVariant::from_geth_options(&opts);

        // Check cache before fetching block data
        if let Some(cached) = check_cache_by_hash(
            &ctx.response_cache,
            CachedResource::DebugTraceBlock,
            block_hash,
            &variant,
            DEBUG_TRACE_BLOCK_BY_HASH,
            start,
        ) {
            return Ok::<_, jsonrpsee::types::ErrorObjectOwned>(cached);
        }

        // Fetch block data (DB -> RPC fallback)
        let data = ctx
            .data_provider
            .get_block_data_by_hash(block_hash)
            .await
            .map_err(|e| block_data_err_by_hash(block_hash, e))?;
        let block_num = data.block.header.number;
        let tx_count = data.block.transactions.len();
        let result = compute_debug_trace_block(&ctx.chain_spec, &data, opts.clone()).await?;

        // Store result in cache and return
        let total_ms = start.elapsed().as_secs_f64() * 1000.0;
        metrics::record_rpc_request(DEBUG_TRACE_BLOCK_BY_HASH, total_ms / 1000.0);

        // Cache the result for future requests
        ctx.response_cache.insert(
            CachedResource::DebugTraceBlock,
            block_num,
            block_hash,
            variant,
            result.clone(),
        );

        trace!(
            method = DEBUG_TRACE_BLOCK_BY_HASH,
            block = block_num,
            tx_count,
            total_ms = format!("{:.2}", total_ms),
            cache_hit = false,
            "Cache miss - computed and stored result"
        );

        if start.elapsed() > SLOW_REQUEST_THRESHOLD {
            warn!(
                method = DEBUG_TRACE_BLOCK_BY_HASH,
                block_number = block_num,
                elapsed_ms = total_ms as u64,
                threshold_ms = SLOW_REQUEST_THRESHOLD.as_millis() as u64,
                "RPC request exceeded threshold"
            );
        }

        Ok(result)
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

        let (data, tx_index) =
            ctx.data_provider.get_block_data_for_tx(tx_hash).await.map_err(tx_data_err)?;

        let result = validator_core::trace_transaction(
            &ctx.chain_spec,
            &data.block,
            tx_index,
            data.witness.clone(),
            &data.contracts,
            opts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        let elapsed = start.elapsed();
        metrics::record_rpc_request(DEBUG_TRACE_TRANSACTION, elapsed.as_secs_f64());

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

        trace!(
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

        trace!(block_number = block_num, method = TRACE_BLOCK, "Processing request");

        // Check cache before fetching block data
        if let Some(cached) = check_cache_by_number(
            &ctx.response_cache,
            CachedResource::TraceBlock,
            block_num,
            &ResponseVariant::Default,
            TRACE_BLOCK,
            start,
        ) {
            return Ok(cached);
        }

        // Fetch block data (DB -> RPC fallback)
        let data = ctx
            .data_provider
            .get_block_data(block_num)
            .await
            .map_err(|e| block_data_err(block_num, e))?;

        execute_cached_block_trace(
            &ctx,
            CachedTraceParams {
                resource: CachedResource::TraceBlock,
                block_num,
                block_hash: data.block.header.hash,
                variant: ResponseVariant::Default,
                method_name: TRACE_BLOCK,
                start,
                tx_count: data.block.transactions.len(),
            },
            || compute_parity_trace_block(&ctx.chain_spec, &data),
        )
        .await
    })?;

    // trace_transaction (not cached - depends on tx index)
    // Note: Returns null (not error) when transaction is not found, matching mega-reth behavior
    module.register_async_method(TRACE_TRANSACTION, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let tx_hash: B256 = seq.next()?;

        trace!(
            tx_hash = %tx_hash,
            method = TRACE_TRANSACTION,
            "Processing request"
        );

        // For trace_transaction, return null instead of error when tx not found
        let (data, tx_index) = match ctx.data_provider.get_block_data_for_tx(tx_hash).await {
            Ok(result) => result,
            Err(e) => {
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("not found") ||
                    err_str.contains("pending") ||
                    err_str.contains("timeout")
                {
                    // Return null for not found, matching mega-reth behavior
                    return Ok(serde_json::Value::Null);
                }
                return Err(rpc_err("internal error".to_string()));
            }
        };

        let result = validator_core::parity_trace_transaction(
            &ctx.chain_spec,
            &data.block,
            tx_index,
            data.witness.clone(),
            &data.contracts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        let elapsed = start.elapsed();
        metrics::record_rpc_request(TRACE_TRANSACTION, elapsed.as_secs_f64());

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

        trace!(
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
            tx_count: 5,
        };

        assert_eq!(params.block_num, 12345);
        assert_eq!(params.method_name, "debug_traceBlockByNumber");
        assert_eq!(params.tx_count, 5);
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
        let debug_params = CachedTraceParams {
            resource: CachedResource::DebugTraceBlock,
            block_num: 100,
            block_hash: B256::from([1u8; 32]),
            variant: ResponseVariant::Default,
            method_name: DEBUG_TRACE_BLOCK_BY_NUMBER,
            start: Instant::now(),
            tx_count: 10,
        };

        let trace_params = CachedTraceParams {
            resource: CachedResource::TraceBlock,
            block_num: 100,
            block_hash: B256::from([1u8; 32]),
            variant: ResponseVariant::Default,
            method_name: TRACE_BLOCK,
            start: Instant::now(),
            tx_count: 3,
        };

        assert!(matches!(debug_params.resource, CachedResource::DebugTraceBlock));
        assert!(matches!(trace_params.resource, CachedResource::TraceBlock));
    }

    #[test]
    fn test_slow_request_threshold() {
        assert_eq!(SLOW_REQUEST_THRESHOLD.as_secs(), 5);
    }
}
