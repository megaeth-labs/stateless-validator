//! RPC Service Module
//!
//! Contains all RPC method definitions and request handling logic using jsonrpsee proc-macros.
//! Separates RPC concerns from the main server initialization.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockNumberOrTag;
use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use dashmap::DashMap;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use stateless_core::chain_spec::ChainSpec;
use tracing::{trace, warn};

use crate::{
    data_provider::{BlockData, DataProvider, DataProviderError, SLOW_STAGE_THRESHOLD_MS},
    metrics::{
        self, DataSourceMetrics, EvmExecutionMetrics, METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
        METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, METHOD_DEBUG_TRACE_TRANSACTION, METHOD_TRACE_BLOCK,
        METHOD_TRACE_TRANSACTION, ResponseSizeMetrics, RpcGlobalMetrics, SingleFlightMetrics,
    },
    response_cache::{CachedResource, RequestShape, ResponseCache, ResponseVariant},
};

/// Slow request threshold for logging warnings.
const SLOW_REQUEST_THRESHOLD: Duration = Duration::from_secs(5);

// RPC Trait Definitions (proc-macro)
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

// RPC Watch Dog
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

// RPC Context
/// Shared context for all RPC handlers.
#[derive(Clone)]
pub struct RpcContext {
    /// Data provider for fetching block data (DB -> RPC with single-flight).
    data_provider: Arc<DataProvider>,
    /// Chain specification containing hardfork activation rules.
    chain_spec: Arc<ChainSpec>,
    /// Response cache for HTTP layer caching (None = disabled).
    response_cache: Option<ResponseCache>,
    /// Watch dog for tracking in-flight requests.
    watch_dog: RpcWatchDog,
}

impl RpcContext {
    /// Creates a new RPC context.
    pub fn new(
        data_provider: Arc<DataProvider>,
        chain_spec: Arc<ChainSpec>,
        response_cache: Option<ResponseCache>,
    ) -> Self {
        Self { data_provider, chain_spec, response_cache, watch_dog: RpcWatchDog::new() }
    }

    /// Returns a reference to the watch dog for spawning the checker task.
    pub fn watch_dog(&self) -> &RpcWatchDog {
        &self.watch_dog
    }

    /// Creates the merged RPC module containing all methods.
    ///
    /// Also registers `timed_` prefixed aliases for every method, so that
    /// e.g. `timed_debug_traceBlockByNumber` routes to the same handler as
    /// `debug_traceBlockByNumber`.
    pub fn into_rpc_module(self) -> eyre::Result<jsonrpsee::server::RpcModule<()>> {
        let mut module = jsonrpsee::server::RpcModule::new(());
        module.merge(DebugTraceRpcServer::into_rpc(self.clone()))?;
        module.merge(TraceRpcServer::into_rpc(self))?;

        // Register timed_ aliases for all methods
        for &(alias, existing) in metrics::TIMED_METHOD_ALIASES {
            module.register_alias(alias, existing)?;
        }

        Ok(module)
    }

    /// The shared by-number prelude, encoding the reorg-safety invariant once for both
    /// by-number handlers: resolve tag -> number -> canonical hash (local index first)
    /// *before* the cache lookup, all on one request deadline; on a miss, fetch block data
    /// by the resolved hash on the remaining budget.
    async fn lookup_block_by_number(
        &self,
        method: &'static str,
        resource: CachedResource,
        variant: Option<ResponseVariant>,
        block_number: BlockNumberOrTag,
        start: Instant,
    ) -> Result<BlockLookup, jsonrpsee::types::ErrorObjectOwned> {
        // One wall-clock budget for the whole request: tag resolution, canonical-hash
        // resolution, and the block-data fetch all share it.
        let deadline = self.data_provider.fetch_deadline();

        let t0 = Instant::now();
        let block_num =
            self.data_provider.resolve_block_number(block_number, deadline).await.map_err(|e| {
                metrics::record_rpc_error(method);
                rpc_err(format!("Failed to resolve block number: {e}"))
            })?;
        let resolve_ms = t0.elapsed().as_millis();
        tracing::Span::current().record("block_number", block_num);

        // Resolve number -> canonical hash (local index first, upstream fallback) BEFORE
        // the cache lookup — this is what makes number-keyed hits reorg-safe.
        let t1 = Instant::now();
        let block_hash =
            self.data_provider.resolve_canonical_hash(block_num, deadline).await.map_err(|e| {
                metrics::record_rpc_error(method);
                data_provider_error_to_rpc_error(&e)
            })?;
        let resolve_hash_ms = t1.elapsed().as_millis();

        if let Some(cached) =
            check_cache(&self.response_cache, resource, block_hash, variant, method, start)
        {
            return Ok(BlockLookup::Cached(cached));
        }

        let t2 = Instant::now();
        let data = self
            .data_provider
            .get_block_data_by_hash_with_deadline(block_hash, deadline)
            .await
            .map_err(|e| {
                metrics::record_rpc_error(method);
                data_provider_error_to_rpc_error(&e)
            })?;
        let fetch_ms = t2.elapsed().as_millis();

        Ok(BlockLookup::Fetched {
            block_num,
            block_hash,
            data,
            resolve_ms,
            resolve_hash_ms,
            fetch_ms,
        })
    }
}

/// Outcome of [`RpcContext::lookup_block_by_number`].
enum BlockLookup {
    /// Served straight from the response cache.
    Cached(serde_json::Value),
    /// Cache miss: block data fetched and ready to trace, with per-stage timings for the
    /// caller's slow-stage warning.
    Fetched {
        block_num: u64,
        block_hash: B256,
        data: Arc<BlockData>,
        resolve_ms: u128,
        resolve_hash_ms: u128,
        fetch_ms: u128,
    },
}

// Error Helpers
/// Error code for internal errors.
const ERROR_CODE_INTERNAL: i32 = -32000;
/// Error code for "resource not found" (used for missing blocks / pending txs / deadline).
const ERROR_CODE_NOT_FOUND: i32 = -32001;

/// Creates a JSON-RPC internal error (code -32000).
/// Used for execution failures, serialization errors, etc.
fn rpc_err(msg: String) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(ERROR_CODE_INTERNAL, msg, None::<()>)
}

/// Creates a JSON-RPC invalid-params error (code -32602).
fn invalid_params_err(msg: String) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        msg,
        None::<()>,
    )
}

/// Classifies `opts`, records the request-shape metric, and rejects a type-malformed
/// `tracerConfig` on a config-reading builtin with `-32602 invalid params` — before any
/// block data is fetched or executed. Returns the cache variant (`Some` only for
/// cacheable shapes).
fn classify_and_gate(
    method_name: &'static str,
    opts: &GethDebugTracingOptions,
) -> Result<Option<ResponseVariant>, jsonrpsee::types::ErrorObjectOwned> {
    let shape = RequestShape::classify(opts);
    metrics::record_request_shape(method_name, shape.label());
    if let RequestShape::InvalidTracerConfig { label, error } = &shape {
        metrics::record_rpc_error(method_name);
        return Err(invalid_params_err(format!("invalid tracerConfig for {label}: {error}")));
    }
    Ok(shape.cache_variant())
}

/// Maps a [`DataProviderError`] to a JSON-RPC error object.
///
/// Classification strategy: anything that could plausibly be a client mistake ("block doesn't
/// exist upstream", "tx pending", "upstream too slow") surfaces as `-32001 resource not found`.
/// Genuine internal failures (transport decode, DB corruption) fall through to `-32000`.
fn data_provider_error_to_rpc_error(e: &DataProviderError) -> jsonrpsee::types::ErrorObjectOwned {
    use jsonrpsee::types::ErrorObjectOwned;
    match e {
        DataProviderError::TransactionNotFound(_) |
        DataProviderError::TransactionPending(_) |
        DataProviderError::Timeout { .. } => {
            ErrorObjectOwned::owned(ERROR_CODE_NOT_FOUND, e.to_string(), None::<()>)
        }
        DataProviderError::Internal(_) => {
            ErrorObjectOwned::owned(ERROR_CODE_INTERNAL, "internal error".to_string(), None::<()>)
        }
    }
}

// Trace Computation Helpers
/// Computes debug trace for a block (Geth-style).
async fn compute_debug_trace_block(
    chain_spec: &ChainSpec,
    data: &BlockData,
    opts: GethDebugTracingOptions,
    method_name: &'static str,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    let start = Instant::now();

    let results = crate::tracing_executor::trace_block(
        chain_spec,
        &data.block,
        data.witness.clone(),
        &data.contracts,
        opts,
    )
    .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

    let trace_ms = start.elapsed().as_millis();
    EvmExecutionMetrics::new_for_method(method_name)
        .record(start.elapsed().as_secs_f64(), data.block.transactions.len());

    let value = serde_json::to_value(&results)
        .map_err(|e| rpc_err(format!("Serialization failed: {e}")))?;

    let serialize_ms = start.elapsed().as_millis() - trace_ms;
    let response_size = value.to_string().len();
    ResponseSizeMetrics::new_for_method(method_name).record(response_size);

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
    method_name: &'static str,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    let start = Instant::now();

    let results = crate::tracing_executor::parity_trace_block(
        chain_spec,
        &data.block,
        data.witness.clone(),
        &data.contracts,
    )
    .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

    EvmExecutionMetrics::new_for_method(method_name)
        .record(start.elapsed().as_secs_f64(), data.block.transactions.len());

    let value =
        serde_json::to_value(results).map_err(|e| rpc_err(format!("Serialization failed: {e}")))?;
    ResponseSizeMetrics::new_for_method(method_name).record(value.to_string().len());

    Ok(value)
}

// Cache Helper Functions
/// Checks the cache for `(resource, block_hash, variant)`; a hit records request metrics
/// and returns the pre-serialized response. A `None` variant marks a non-cacheable request
/// shape and bypasses the lookup entirely (no hit/miss accounting). By-number callers
/// resolve the canonical hash *before* calling this, so a hit is correct by construction —
/// there is no serve-time canonicality validation anymore.
fn check_cache(
    cache: &Option<ResponseCache>,
    resource: CachedResource,
    block_hash: B256,
    variant: Option<ResponseVariant>,
    method_name: &'static str,
    start: Instant,
) -> Option<serde_json::Value> {
    let cached_value = cache.as_ref()?.get(resource, block_hash, variant?)?;

    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    metrics::record_rpc_request(method_name, total_ms / 1000.0);
    DataSourceMetrics::new_for_source("cache").record();
    SingleFlightMetrics::new_for_type("bypassed").record();

    trace!(
        method = method_name,
        block_hash = %block_hash,
        total_ms = format!("{:.2}", total_ms),
        cache_hit = true,
        "Cache hit - returning cached result"
    );

    Some(cached_value)
}

/// Inserts a computed response under the hash of the block it was computed for; a no-op
/// when the cache is disabled or the request shape is not cacheable (`variant` is `None`).
fn insert_cache(
    cache: &Option<ResponseCache>,
    resource: CachedResource,
    block_hash: B256,
    variant: Option<ResponseVariant>,
    result: &serde_json::Value,
) {
    if let (Some(cache), Some(variant)) = (cache, variant) {
        cache.insert(resource, block_hash, variant, result);
    }
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

// DebugTraceRpc Implementation
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
        let variant = classify_and_gate(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, &opts)?;

        let (block_num, block_hash, data, resolve_ms, resolve_hash_ms, fetch_ms) = match self
            .lookup_block_by_number(
                METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
                CachedResource::DebugTraceBlock,
                variant,
                block_number,
                start,
            )
            .await?
        {
            BlockLookup::Cached(cached) => return Ok(cached),
            BlockLookup::Fetched {
                block_num,
                block_hash,
                data,
                resolve_ms,
                resolve_hash_ms,
                fetch_ms,
            } => (block_num, block_hash, data, resolve_ms, resolve_hash_ms, fetch_ms),
        };
        let tx_count = data.block.transactions.len();

        // Execute trace
        let t3 = Instant::now();
        let result = compute_debug_trace_block(
            &self.chain_spec,
            &data,
            opts,
            METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
        )
        .await
        .inspect_err(|_| {
            metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
        })?;
        let trace_ms = t3.elapsed().as_millis();

        // Cache result under the hash it was computed for
        let t4 = Instant::now();
        insert_cache(
            &self.response_cache,
            CachedResource::DebugTraceBlock,
            block_hash,
            variant,
            &result,
        );
        let cache_insert_ms = t4.elapsed().as_millis();

        let total_ms = start.elapsed().as_millis();
        record_request_completion(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, block_num, start);

        if resolve_ms >= SLOW_STAGE_THRESHOLD_MS ||
            resolve_hash_ms >= SLOW_STAGE_THRESHOLD_MS ||
            fetch_ms >= SLOW_STAGE_THRESHOLD_MS ||
            trace_ms >= SLOW_STAGE_THRESHOLD_MS ||
            cache_insert_ms >= SLOW_STAGE_THRESHOLD_MS
        {
            warn!(
                block_number = block_num,
                tx_count,
                resolve_ms = resolve_ms as u64,
                resolve_hash_ms = resolve_hash_ms as u64,
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
        let variant = classify_and_gate(METHOD_DEBUG_TRACE_BLOCK_BY_HASH, &opts)?;

        // Check cache — the requested hash IS the key; no resolution step.
        if let Some(cached) = check_cache(
            &self.response_cache,
            CachedResource::DebugTraceBlock,
            block_hash,
            variant,
            METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
            start,
        ) {
            return Ok(cached);
        }

        // Fetch block data (DB -> RPC fallback)
        let data = self.data_provider.get_block_data_by_hash(block_hash).await.map_err(|e| {
            metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
            data_provider_error_to_rpc_error(&e)
        })?;
        let block_num = data.block.header.number;
        let result = compute_debug_trace_block(
            &self.chain_spec,
            &data,
            opts,
            METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
        )
        .await
        .inspect_err(|_| {
            metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
        })?;

        // Cache and record metrics. An entry for a non-canonical hash is still the correct
        // answer for that hash — exactly what geth serves — and is unreachable by-number.
        insert_cache(
            &self.response_cache,
            CachedResource::DebugTraceBlock,
            block_hash,
            variant,
            &result,
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
        // Shape metric + malformed-config rejection; tx-level responses are not cached, so
        // the cache variant itself is unused.
        let _ = classify_and_gate(METHOD_DEBUG_TRACE_TRANSACTION, &opts)?;

        let (data, tx_index) =
            self.data_provider.get_block_data_for_tx(tx_hash).await.map_err(|e| {
                metrics::record_rpc_error(METHOD_DEBUG_TRACE_TRANSACTION);
                data_provider_error_to_rpc_error(&e)
            })?;

        let evm_start = Instant::now();
        let result = crate::tracing_executor::trace_transaction(
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
        EvmExecutionMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION)
            .record(evm_start.elapsed().as_secs_f64(), 1);

        let elapsed = start.elapsed();
        metrics::record_rpc_request(METHOD_DEBUG_TRACE_TRANSACTION, elapsed.as_secs_f64());

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

        let value = serde_json::to_value(&result)
            .map_err(|e| rpc_err(format!("Serialization failed: {e}")))?;
        ResponseSizeMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION)
            .record(value.to_string().len());
        Ok(value)
    }

    async fn get_cache_status(&self) -> RpcResult<serde_json::Value> {
        let Some(cache) = &self.response_cache else {
            return Ok(serde_json::json!({
                "responseCache": {
                    "status": "disabled"
                }
            }));
        };

        let stats = cache.stats();
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

// TraceRpc Implementation
#[jsonrpsee::core::async_trait]
impl TraceRpcServer for RpcContext {
    #[tracing::instrument(level = "trace", skip(self), fields(block_number))]
    async fn trace_block(&self, block_number: BlockNumberOrTag) -> RpcResult<serde_json::Value> {
        let _guard = self.watch_dog.start_request(METHOD_TRACE_BLOCK, format!("{block_number}"));
        let start = Instant::now();

        // `trace_block` takes no tracer options, so its variant is always `Default`.
        let (block_num, block_hash, data) = match self
            .lookup_block_by_number(
                METHOD_TRACE_BLOCK,
                CachedResource::TraceBlock,
                Some(ResponseVariant::Default),
                block_number,
                start,
            )
            .await?
        {
            BlockLookup::Cached(cached) => return Ok(cached),
            BlockLookup::Fetched { block_num, block_hash, data, .. } => {
                (block_num, block_hash, data)
            }
        };

        let result = compute_parity_trace_block(&self.chain_spec, &data, METHOD_TRACE_BLOCK)
            .await
            .inspect_err(|_| {
                metrics::record_rpc_error(METHOD_TRACE_BLOCK);
            })?;

        // Cache and record metrics
        insert_cache(
            &self.response_cache,
            CachedResource::TraceBlock,
            block_hash,
            Some(ResponseVariant::Default),
            &result,
        );
        record_request_completion(METHOD_TRACE_BLOCK, block_num, start);

        Ok(result)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    async fn trace_parity_transaction(&self, tx_hash: B256) -> RpcResult<serde_json::Value> {
        let _guard = self.watch_dog.start_request(METHOD_TRACE_TRANSACTION, format!("{tx_hash}"));
        let start = Instant::now();

        // Return null instead of error when tx not found or unreachable (matches mega-reth);
        // surface genuine Internal failures as -32000. Branches on the typed variant so any
        // future `DataProviderError` addition must be classified explicitly at compile time.
        let (data, tx_index) = match self.data_provider.get_block_data_for_tx(tx_hash).await {
            Ok(result) => result,
            Err(
                DataProviderError::TransactionNotFound(_) |
                DataProviderError::TransactionPending(_) |
                DataProviderError::Timeout { .. },
            ) => return Ok(serde_json::Value::Null),
            Err(DataProviderError::Internal(_)) => {
                metrics::record_rpc_error(METHOD_TRACE_TRANSACTION);
                return Err(rpc_err("internal error".to_string()));
            }
        };

        let evm_start = Instant::now();
        let result = crate::tracing_executor::parity_trace_transaction(
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
        EvmExecutionMetrics::new_for_method(METHOD_TRACE_TRANSACTION)
            .record(evm_start.elapsed().as_secs_f64(), 1);

        let elapsed = start.elapsed();
        metrics::record_rpc_request(METHOD_TRACE_TRANSACTION, elapsed.as_secs_f64());

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

        let value = serde_json::to_value(&result)
            .map_err(|e| rpc_err(format!("Serialization failed: {e}")))?;
        ResponseSizeMetrics::new_for_method(METHOD_TRACE_TRANSACTION)
            .record(value.to_string().len());
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response_cache::ResponseCacheConfig;

    #[test]
    fn test_rpc_err() {
        let err = rpc_err("test error".to_string());
        assert_eq!(err.code(), -32000);
        assert_eq!(err.message(), "test error");
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

    /// Each `DataProviderError` variant maps to a specific JSON-RPC error code. Missing /
    /// timeout cases must surface as `-32001` (resource not found); `Internal` falls through
    /// to `-32000`. Lives here rather than in `data_provider.rs` because the data layer
    /// shouldn't import `jsonrpsee` types.
    #[test]
    fn data_provider_error_to_rpc_error_code_mapping() {
        use crate::data_provider::TimeoutStage;

        let tx_hash = B256::from([0x11; 32]);

        let not_found_variants: [DataProviderError; 4] = [
            DataProviderError::TransactionNotFound(tx_hash),
            DataProviderError::TransactionPending(tx_hash),
            DataProviderError::Timeout {
                stage: TimeoutStage::Witness,
                elapsed: Duration::from_secs(8),
            },
            DataProviderError::Timeout {
                stage: TimeoutStage::Block,
                elapsed: Duration::from_secs(13),
            },
        ];

        for variant in not_found_variants {
            let err = data_provider_error_to_rpc_error(&variant);
            assert_eq!(err.code(), -32001, "variant {variant:?} must map to resource-not-found");
            assert_eq!(err.message(), variant.to_string().as_str());
        }

        let internal: DataProviderError = eyre::eyre!("boom").into();
        let err = data_provider_error_to_rpc_error(&internal);
        assert_eq!(err.code(), -32000);
        assert_eq!(err.message(), "internal error");
    }

    #[test]
    fn test_timed_alias_registration() {
        // Create a module and register dummy methods matching the real method names,
        // then register timed_ aliases the same way into_rpc_module does.
        let mut module = jsonrpsee::server::RpcModule::new(());

        // Register dummy methods for all known RPC methods
        let methods = [
            metrics::METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
            metrics::METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
            metrics::METHOD_DEBUG_TRACE_TRANSACTION,
            metrics::METHOD_DEBUG_GET_CACHE_STATUS,
            metrics::METHOD_TRACE_BLOCK,
            metrics::METHOD_TRACE_TRANSACTION,
        ];
        for method in methods {
            module
                .register_method(method, |_, _, _| serde_json::Value::Null)
                .expect("failed to register method");
        }

        // Register timed_ aliases
        for &(alias, existing) in metrics::TIMED_METHOD_ALIASES {
            module.register_alias(alias, existing).expect("failed to register alias");
        }

        let names: Vec<&str> = module.method_names().collect();

        // Verify all original methods are present
        for method in methods {
            assert!(names.contains(&method), "Missing original method: {}", method);
        }

        // Verify all timed_ aliases are present
        for &(alias, _) in metrics::TIMED_METHOD_ALIASES {
            assert!(names.contains(&alias), "Missing timed alias: {}", alias);
        }
    }

    /// A disabled cache (`None`) always reports a bypass, for both cacheable and
    /// non-cacheable variants.
    #[test]
    fn check_cache_disabled_returns_none() {
        for variant in [Some(ResponseVariant::Default), None] {
            let result = check_cache(
                &None,
                CachedResource::DebugTraceBlock,
                B256::ZERO,
                variant,
                "test_method",
                Instant::now(),
            );
            assert!(result.is_none());
        }
    }

    /// A `None` variant (non-cacheable shape) bypasses the lookup entirely — no value and
    /// no hit/miss accounting, even when an entry exists under the same hash.
    #[test]
    fn check_cache_bypasses_on_non_cacheable_variant() {
        let hash = B256::from([1u8; 32]);
        let cache = ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100));
        cache.insert(
            CachedResource::DebugTraceBlock,
            hash,
            ResponseVariant::Default,
            &serde_json::json!({"cached": true}),
        );
        let cache = Some(cache);

        let result = check_cache(
            &cache,
            CachedResource::DebugTraceBlock,
            hash,
            None,
            "test_method",
            Instant::now(),
        );
        assert!(result.is_none());

        let stats = cache.as_ref().unwrap().stats();
        assert_eq!((stats.hits, stats.misses), (0, 0), "bypass must not touch accounting");
    }

    /// A hit returns the cached value and counts as a hit; a lookup under a different hash
    /// misses — there is no number indirection left to go stale.
    #[test]
    fn check_cache_hit_returns_and_counts() {
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);
        let cache = ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100));
        cache.insert(
            CachedResource::DebugTraceBlock,
            h1,
            ResponseVariant::Default,
            &serde_json::json!({"v": 1}),
        );
        let cache = Some(cache);

        let hit = check_cache(
            &cache,
            CachedResource::DebugTraceBlock,
            h1,
            Some(ResponseVariant::Default),
            "test_method",
            Instant::now(),
        );
        assert_eq!(hit, Some(serde_json::json!({"v": 1})));

        let miss = check_cache(
            &cache,
            CachedResource::DebugTraceBlock,
            h2,
            Some(ResponseVariant::Default),
            "test_method",
            Instant::now(),
        );
        assert!(miss.is_none());

        let stats = cache.as_ref().unwrap().stats();
        assert_eq!((stats.hits, stats.misses), (1, 1));
    }

    #[test]
    fn insert_cache_skips_non_cacheable_variants() {
        let cache = Some(ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100)));
        let result = serde_json::json!([{"txHash": "0x01"}]);
        let hash = B256::from([1u8; 32]);

        insert_cache(&cache, CachedResource::DebugTraceBlock, hash, None, &result);
        assert_eq!(cache.as_ref().unwrap().len(), 0);

        insert_cache(
            &cache,
            CachedResource::DebugTraceBlock,
            hash,
            Some(ResponseVariant::Default),
            &result,
        );
        assert_eq!(cache.as_ref().unwrap().len(), 1);
    }

    /// A type-malformed `tracerConfig` on a config-reading builtin maps to `-32602 invalid
    /// params` with the tracer's label and the serde error in the message; a valid config
    /// passes the gate and yields a cacheable variant.
    #[test]
    fn invalid_tracer_config_maps_to_invalid_params() {
        let opts: GethDebugTracingOptions = serde_json::from_value(serde_json::json!({
            "tracer": "callTracer",
            "tracerConfig": {"onlyTopCall": "yes-please"},
        }))
        .unwrap();
        let err = classify_and_gate("test_method", &opts).unwrap_err();
        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(
            err.message().contains("invalid tracerConfig for call_tracer"),
            "message: {}",
            err.message(),
        );

        let opts: GethDebugTracingOptions = serde_json::from_value(serde_json::json!({
            "tracer": "callTracer",
            "tracerConfig": {"onlyTopCall": true},
        }))
        .unwrap();
        assert!(classify_and_gate("test_method", &opts).unwrap().is_some());
    }

    #[test]
    fn test_timed_alias_duplicate_rejected() {
        // Registering the same alias twice should fail
        let mut module = jsonrpsee::server::RpcModule::new(());
        module
            .register_method(metrics::METHOD_TRACE_BLOCK, |_, _, _| serde_json::Value::Null)
            .unwrap();
        module
            .register_alias(metrics::TIMED_METHOD_TRACE_BLOCK, metrics::METHOD_TRACE_BLOCK)
            .unwrap();

        // Second registration of the same alias should error
        let result =
            module.register_alias(metrics::TIMED_METHOD_TRACE_BLOCK, metrics::METHOD_TRACE_BLOCK);
        assert!(result.is_err(), "Duplicate alias registration should fail");
    }
}
