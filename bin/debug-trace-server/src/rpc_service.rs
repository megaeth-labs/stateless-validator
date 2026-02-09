//! RPC Service Module
//!
//! Contains all RPC method definitions and request handling logic using jsonrpsee proc-macros.
//! Separates RPC concerns from the main server initialization.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockNumberOrTag;
use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use dashmap::DashMap;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use tracing::{trace, warn};
use validator_core::chain_spec::ChainSpec;

use crate::{
    data_provider::{BlockData, DataProvider},
    metrics::{
        self, RpcGlobalMetrics, TracingMetrics, METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
        METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, METHOD_DEBUG_TRACE_TRANSACTION, METHOD_TRACE_BLOCK,
        METHOD_TRACE_TRANSACTION,
    },
    response_cache::{CachedResource, ResponseCache, ResponseVariant},
};

/// Slow request threshold for logging warnings.
const SLOW_REQUEST_THRESHOLD: Duration = Duration::from_secs(5);

/// Slow stage threshold: any individual stage exceeding this triggers a warn log.
const SLOW_STAGE_THRESHOLD_MS: u128 = 1000;

// ---------------------------------------------------------------------------
// RPC Trait Definitions (proc-macro)
// ---------------------------------------------------------------------------

/// Geth-style debug tracing RPC methods.
#[rpc(server, namespace = "debug")]
pub trait DebugTraceRpc {
    /// Trace block execution by block number.
    #[method(name = "traceBlockByNumber")]
    async fn trace_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<serde_json::Value>;

    /// Trace block execution by block hash.
    #[method(name = "traceBlockByHash")]
    async fn trace_block_by_hash(
        &self,
        block_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<serde_json::Value>;

    /// Trace a single transaction execution.
    #[method(name = "traceTransaction")]
    async fn trace_transaction(
        &self,
        tx_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<serde_json::Value>;

    /// Query current response cache status.
    #[method(name = "getCacheStatus")]
    async fn get_cache_status(&self) -> RpcResult<serde_json::Value>;
}

/// Parity/OpenEthereum-style trace RPC methods.
#[rpc(server, namespace = "trace")]
pub trait TraceRpc {
    /// Parity-style block tracing (flat call traces).
    #[method(name = "block")]
    async fn trace_block(&self, block_number: BlockNumberOrTag) -> RpcResult<serde_json::Value>;

    /// Parity-style transaction tracing.
    /// Returns null (not error) when transaction is not found, matching mega-reth behavior.
    #[method(name = "transaction")]
    async fn trace_parity_transaction(&self, tx_hash: B256) -> RpcResult<serde_json::Value>;
}

// ---------------------------------------------------------------------------
// RPC Watch Dog
// ---------------------------------------------------------------------------

/// Tracks in-flight RPC requests and logs warnings for long-running ones.
#[derive(Clone)]
pub struct RpcWatchDog {
    /// Active requests: request_id -> (method, params_summary, start_time)
    active_requests: Arc<DashMap<u64, (&'static str, String, Instant)>>,
    /// Monotonically increasing request ID counter.
    next_id: Arc<AtomicU64>,
    /// Prometheus metrics for inflight request tracking.
    global_metrics: RpcGlobalMetrics,
}

impl RpcWatchDog {
    /// Creates a new watch dog instance.
    pub fn new() -> Self {
        Self {
            active_requests: Arc::new(DashMap::new()),
            next_id: Arc::new(AtomicU64::new(0)),
            global_metrics: RpcGlobalMetrics::create(),
        }
    }

    /// Registers a new in-flight request. Returns a guard that automatically
    /// deregisters the request when dropped.
    fn start_request(&self, method: &'static str, params: String) -> WatchDogGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active_requests.insert(id, (method, params, Instant::now()));
        self.global_metrics.inc_inflight();
        WatchDogGuard {
            active_requests: Arc::clone(&self.active_requests),
            global_metrics: self.global_metrics.clone(),
            id,
        }
    }

    /// Background task that periodically checks for long-running requests.
    /// Logs a warning for any request exceeding the given threshold.
    pub async fn run_checker(&self, interval: Duration, warn_threshold: Duration) {
        loop {
            tokio::time::sleep(interval).await;
            let now = Instant::now();
            for entry in self.active_requests.iter() {
                let (method, params, start) = entry.value();
                let elapsed = now.duration_since(*start);
                if elapsed > warn_threshold {
                    warn!(
                        method = %method,
                        params = %params,
                        elapsed_secs = elapsed.as_secs(),
                        threshold_secs = warn_threshold.as_secs(),
                        "Long-running RPC request detected"
                    );
                }
            }
        }
    }
}

/// RAII guard that deregisters an in-flight request when dropped.
struct WatchDogGuard {
    active_requests: Arc<DashMap<u64, (&'static str, String, Instant)>>,
    global_metrics: RpcGlobalMetrics,
    id: u64,
}

impl Drop for WatchDogGuard {
    fn drop(&mut self) {
        self.active_requests.remove(&self.id);
        self.global_metrics.dec_inflight();
    }
}

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
    /// Watch dog for tracking in-flight requests.
    watch_dog: RpcWatchDog,
}

impl RpcContext {
    /// Creates a new RPC context.
    pub fn new(
        data_provider: Arc<DataProvider>,
        chain_spec: Arc<ChainSpec>,
        response_cache: ResponseCache,
    ) -> Self {
        Self { data_provider, chain_spec, response_cache, watch_dog: RpcWatchDog::new() }
    }

    /// Returns a reference to the watch dog for spawning the checker task.
    pub fn watch_dog(&self) -> &RpcWatchDog {
        &self.watch_dog
    }

    /// Creates the merged RPC module containing all methods.
    pub fn into_rpc_module(self) -> eyre::Result<jsonrpsee::server::RpcModule<()>> {
        let mut module = jsonrpsee::server::RpcModule::new(());
        module.merge(DebugTraceRpcServer::into_rpc(self.clone()))?;
        module.merge(TraceRpcServer::into_rpc(self))?;
        Ok(module)
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
    if err_str.contains("not found") || err_str.contains("timeout") || err_str.contains("witness") {
        rpc_err_not_found(format!("block not found: {:#x}", block_num))
    } else {
        rpc_err("internal error".to_string())
    }
}

/// Converts a block data fetch error (by hash) to an appropriate RPC error.
fn block_data_err_by_hash(block_hash: B256, e: eyre::Report) -> jsonrpsee::types::ErrorObjectOwned {
    let err_str = e.to_string().to_lowercase();
    if err_str.contains("not found") ||
        err_str.contains("timeout") ||
        err_str.contains("Failed to get witness")
    {
        rpc_err_not_found(format!("block not found: hash {}", block_hash))
    } else {
        rpc_err("internal error".to_string())
    }
}

/// Converts a transaction lookup error to an appropriate RPC error.
fn tx_data_err(e: eyre::Report) -> jsonrpsee::types::ErrorObjectOwned {
    let err_str = e.to_string().to_lowercase();
    if err_str.contains("not found") ||
        err_str.contains("timeout") ||
        err_str.contains("pending") ||
        err_str.contains("witness")
    {
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
    let tracing_metrics = TracingMetrics::new_for_tracer("geth");

    let results = validator_core::trace_block(
        chain_spec,
        &data.block,
        data.witness.clone(),
        &data.contracts,
        opts,
    )
    .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

    let trace_ms = start.elapsed().as_millis();
    tracing_metrics.record_block(data.block.transactions.len(), start.elapsed().as_secs_f64());

    let value = serde_json::to_value(&results)
        .map_err(|e| rpc_err(format!("Serialization failed: {e}")))?;

    let serialize_ms = start.elapsed().as_millis() - trace_ms;
    let response_size = value.to_string().len();

    if trace_ms >= SLOW_STAGE_THRESHOLD_MS || serialize_ms >= SLOW_STAGE_THRESHOLD_MS {
        warn!(
            block_number = data.block.header.number,
            tx_count = data.block.transactions.len(),
            trace_ms = trace_ms as u64,
            serialize_ms = serialize_ms as u64,
            response_size_kb = response_size / 1024,
            "compute_debug_trace_block slow stages detected"
        );
    }

    Ok(value)
}

/// Computes parity trace for a block.
async fn compute_parity_trace_block(
    chain_spec: &ChainSpec,
    data: &BlockData,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    let start = Instant::now();
    let tracing_metrics = TracingMetrics::new_for_tracer("parity");

    let results = validator_core::parity_trace_block(
        chain_spec,
        &data.block,
        data.witness.clone(),
        &data.contracts,
    )
    .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

    tracing_metrics.record_block(data.block.transactions.len(), start.elapsed().as_secs_f64());

    serde_json::to_value(results).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
}

// ---------------------------------------------------------------------------
// Cache Helper Functions
// ---------------------------------------------------------------------------

/// Checks cache by block number and returns cached value if found.
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

/// Records metrics and logs for a completed request.
fn record_request_completion(method_name: &'static str, block_num: u64, start: Instant) {
    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    metrics::record_rpc_request(method_name, total_ms / 1000.0);

    if start.elapsed() > SLOW_REQUEST_THRESHOLD {
        warn!(
            method = method_name,
            block_number = block_num,
            elapsed_ms = total_ms as u64,
            threshold_ms = SLOW_REQUEST_THRESHOLD.as_millis() as u64,
            "RPC request exceeded threshold"
        );
    }
}

// ---------------------------------------------------------------------------
// DebugTraceRpc Implementation
// ---------------------------------------------------------------------------

#[jsonrpsee::core::async_trait]
impl DebugTraceRpcServer for RpcContext {
    #[tracing::instrument(level = "trace", skip(self, opts), fields(block_number))]
    async fn trace_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<serde_json::Value> {
        let _guard = self
            .watch_dog
            .start_request(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, format!("{block_number}"));
        let start = Instant::now();
        let opts = opts.unwrap_or_default();

        // Stage 1: Resolve block number
        let t0 = Instant::now();
        let block_num =
            self.data_provider.resolve_block_number(block_number).await.map_err(|e| {
                metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
                rpc_err(format!("Failed to resolve block number: {e}"))
            })?;
        let resolve_ms = t0.elapsed().as_millis();

        let variant = ResponseVariant::from_geth_options(&opts);

        // Stage 2: Check cache
        if let Some(cached) = check_cache_by_number(
            &self.response_cache,
            CachedResource::DebugTraceBlock,
            block_num,
            &variant,
            METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
            start,
        ) {
            return Ok(cached);
        }

        // Stage 3: Fetch block data (DB -> RPC fallback)
        let t2 = Instant::now();
        let data = self.data_provider.get_block_data(block_num).await.map_err(|e| {
            metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
            block_data_err(block_num, e)
        })?;
        let fetch_ms = t2.elapsed().as_millis();
        let block_hash = data.block.header.hash;
        let tx_count = data.block.transactions.len();

        // Stage 4: Execute trace
        let t3 = Instant::now();
        let result =
            compute_debug_trace_block(&self.chain_spec, &data, opts).await.inspect_err(|_| {
                metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
            })?;
        let trace_ms = t3.elapsed().as_millis();

        // Stage 5: Cache result
        let t4 = Instant::now();
        self.response_cache.insert(
            CachedResource::DebugTraceBlock,
            block_num,
            block_hash,
            variant,
            result.clone(),
        );
        let cache_insert_ms = t4.elapsed().as_millis();

        let total_ms = start.elapsed().as_millis();
        record_request_completion(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, block_num, start);

        if resolve_ms >= SLOW_STAGE_THRESHOLD_MS ||
            fetch_ms >= SLOW_STAGE_THRESHOLD_MS ||
            trace_ms >= SLOW_STAGE_THRESHOLD_MS ||
            cache_insert_ms >= SLOW_STAGE_THRESHOLD_MS
        {
            warn!(
                block_number = block_num,
                tx_count,
                resolve_ms = resolve_ms as u64,
                fetch_data_ms = fetch_ms as u64,
                trace_ms = trace_ms as u64,
                cache_insert_ms = cache_insert_ms as u64,
                total_ms = total_ms as u64,
                "debug_traceBlockByNumber slow stages detected"
            );
        }

        Ok(result)
    }

    #[tracing::instrument(level = "trace", skip(self, opts))]
    async fn trace_block_by_hash(
        &self,
        block_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<serde_json::Value> {
        let _guard =
            self.watch_dog.start_request(METHOD_DEBUG_TRACE_BLOCK_BY_HASH, format!("{block_hash}"));
        let start = Instant::now();
        let opts = opts.unwrap_or_default();

        let variant = ResponseVariant::from_geth_options(&opts);

        // Check cache
        if let Some(cached) = check_cache_by_hash(
            &self.response_cache,
            CachedResource::DebugTraceBlock,
            block_hash,
            &variant,
            METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
            start,
        ) {
            return Ok(cached);
        }

        // Fetch block data (DB -> RPC fallback)
        let data = self.data_provider.get_block_data_by_hash(block_hash).await.map_err(|e| {
            metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
            block_data_err_by_hash(block_hash, e)
        })?;
        let block_num = data.block.header.number;
        let result =
            compute_debug_trace_block(&self.chain_spec, &data, opts).await.inspect_err(|_| {
                metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
            })?;

        // Cache and record metrics
        self.response_cache.insert(
            CachedResource::DebugTraceBlock,
            block_num,
            block_hash,
            variant,
            result.clone(),
        );
        record_request_completion(METHOD_DEBUG_TRACE_BLOCK_BY_HASH, block_num, start);

        Ok(result)
    }

    #[tracing::instrument(level = "trace", skip(self, opts))]
    async fn trace_transaction(
        &self,
        tx_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<serde_json::Value> {
        let _guard =
            self.watch_dog.start_request(METHOD_DEBUG_TRACE_TRANSACTION, format!("{tx_hash}"));
        let start = Instant::now();
        let opts = opts.unwrap_or_default();

        let (data, tx_index) =
            self.data_provider.get_block_data_for_tx(tx_hash).await.map_err(|e| {
                metrics::record_rpc_error(METHOD_DEBUG_TRACE_TRANSACTION);
                tx_data_err(e)
            })?;

        let result = validator_core::trace_transaction(
            &self.chain_spec,
            &data.block,
            tx_index,
            data.witness.clone(),
            &data.contracts,
            opts,
        )
        .map_err(|e| {
            metrics::record_rpc_error(METHOD_DEBUG_TRACE_TRANSACTION);
            rpc_err(format!("Trace execution failed: {e}"))
        })?;

        let elapsed = start.elapsed();
        metrics::record_rpc_request(METHOD_DEBUG_TRACE_TRANSACTION, elapsed.as_secs_f64());
        TracingMetrics::new_for_tracer("geth").record_transaction(elapsed.as_secs_f64());

        if elapsed > SLOW_REQUEST_THRESHOLD {
            warn!(
                method = METHOD_DEBUG_TRACE_TRANSACTION,
                tx_hash = %tx_hash,
                block_number = data.block.header.number,
                elapsed_ms = elapsed.as_millis() as u64,
                threshold_ms = SLOW_REQUEST_THRESHOLD.as_millis() as u64,
                "RPC request exceeded threshold"
            );
        }

        serde_json::to_value(&result).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    }

    async fn get_cache_status(&self) -> RpcResult<serde_json::Value> {
        let stats = self.response_cache.stats();

        Ok(serde_json::json!({
            "responseCache": {
                "entryCount": stats.entry_count,
                "totalBytes": stats.total_bytes,
                "totalBytesMB": format!("{:.2}", stats.total_bytes as f64 / 1024.0 / 1024.0),
                "hits": stats.hits,
                "misses": stats.misses,
                "hitRate": format!("{:.1}%", stats.hit_rate())
            }
        }))
    }
}

// ---------------------------------------------------------------------------
// TraceRpc Implementation
// ---------------------------------------------------------------------------

#[jsonrpsee::core::async_trait]
impl TraceRpcServer for RpcContext {
    #[tracing::instrument(level = "trace", skip(self), fields(block_number))]
    async fn trace_block(&self, block_number: BlockNumberOrTag) -> RpcResult<serde_json::Value> {
        let _guard = self.watch_dog.start_request(METHOD_TRACE_BLOCK, format!("{block_number}"));
        let start = Instant::now();

        let block_num =
            self.data_provider.resolve_block_number(block_number).await.map_err(|e| {
                metrics::record_rpc_error(METHOD_TRACE_BLOCK);
                rpc_err(format!("Failed to resolve block number: {e}"))
            })?;

        tracing::Span::current().record("block_number", block_num);

        // Check cache
        if let Some(cached) = check_cache_by_number(
            &self.response_cache,
            CachedResource::TraceBlock,
            block_num,
            &ResponseVariant::Default,
            METHOD_TRACE_BLOCK,
            start,
        ) {
            return Ok(cached);
        }

        // Fetch block data (DB -> RPC fallback)
        let data = self.data_provider.get_block_data(block_num).await.map_err(|e| {
            metrics::record_rpc_error(METHOD_TRACE_BLOCK);
            block_data_err(block_num, e)
        })?;

        let block_hash = data.block.header.hash;
        let result =
            compute_parity_trace_block(&self.chain_spec, &data).await.inspect_err(|_| {
                metrics::record_rpc_error(METHOD_TRACE_BLOCK);
            })?;

        // Cache and record metrics
        self.response_cache.insert(
            CachedResource::TraceBlock,
            block_num,
            block_hash,
            ResponseVariant::Default,
            result.clone(),
        );
        record_request_completion(METHOD_TRACE_BLOCK, block_num, start);

        Ok(result)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    async fn trace_parity_transaction(&self, tx_hash: B256) -> RpcResult<serde_json::Value> {
        let _guard = self.watch_dog.start_request(METHOD_TRACE_TRANSACTION, format!("{tx_hash}"));
        let start = Instant::now();

        // Return null instead of error when tx not found, matching mega-reth behavior
        let (data, tx_index) = match self.data_provider.get_block_data_for_tx(tx_hash).await {
            Ok(result) => result,
            Err(e) => {
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("not found") ||
                    err_str.contains("pending") ||
                    err_str.contains("timeout")
                {
                    return Ok(serde_json::Value::Null);
                }
                metrics::record_rpc_error(METHOD_TRACE_TRANSACTION);
                return Err(rpc_err("internal error".to_string()));
            }
        };

        let result = validator_core::parity_trace_transaction(
            &self.chain_spec,
            &data.block,
            tx_index,
            data.witness.clone(),
            &data.contracts,
        )
        .map_err(|e| {
            metrics::record_rpc_error(METHOD_TRACE_TRANSACTION);
            rpc_err(format!("Trace execution failed: {e}"))
        })?;

        let elapsed = start.elapsed();
        metrics::record_rpc_request(METHOD_TRACE_TRANSACTION, elapsed.as_secs_f64());
        TracingMetrics::new_for_tracer("parity").record_transaction(elapsed.as_secs_f64());

        if elapsed > SLOW_REQUEST_THRESHOLD {
            warn!(
                method = METHOD_TRACE_TRANSACTION,
                tx_hash = %tx_hash,
                block_number = data.block.header.number,
                elapsed_ms = elapsed.as_millis() as u64,
                threshold_ms = SLOW_REQUEST_THRESHOLD.as_millis() as u64,
                "RPC request exceeded threshold"
            );
        }

        serde_json::to_value(&result).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    fn test_rpc_err_not_found() {
        let err = rpc_err_not_found("block not found".to_string());
        assert_eq!(err.code(), -32001);
        assert_eq!(err.message(), "block not found");
    }

    #[test]
    fn test_rpc_err_with_long_message() {
        let long_msg = "A".repeat(1000);
        let err = rpc_err(long_msg.clone());
        assert_eq!(err.code(), -32000);
        assert_eq!(err.message(), long_msg);
    }

    #[test]
    fn test_slow_request_threshold() {
        assert_eq!(SLOW_REQUEST_THRESHOLD.as_secs(), 5);
    }
}
