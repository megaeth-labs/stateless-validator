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
        self, BlockDataEvictionMetrics, CacheStats, DataSourceMetrics, EvmExecutionMetrics,
        METHOD_DEBUG_TRACE_BLOCK_BY_HASH, METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
        METHOD_DEBUG_TRACE_TRANSACTION, METHOD_TRACE_BLOCK, METHOD_TRACE_TRANSACTION,
        ResponseSizeMetrics, RpcGlobalMetrics, SingleFlightMetrics,
    },
    response_cache::{CachedResource, RequestShape, ResponseCache, ResponseVariant},
    tracing_executor::TraceError,
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

    /// Bookkeeping for a failed trace: records the per-method error metric, and — only for
    /// data-attributable failures ([`TraceError::Data`]) — drops the block's cached data,
    /// so a decodable-but-wrong witness is refetched on the next request instead of
    /// staying pinned until eviction. Request-attributable failures (invalid tracer
    /// configs, tracer construction/output errors) never evict: mux/JS shapes bypass the
    /// response cache, so evicting on them would let any client drop hot entries at will.
    /// Every handler that executes a trace must route its failure path through here.
    fn on_trace_failure(&self, method: &'static str, block_hash: &B256, error: &TraceError) {
        metrics::record_rpc_error(method);
        if matches!(error, TraceError::Data(_)) && self.data_provider.evict_block_data(block_hash) {
            BlockDataEvictionMetrics::new_for_method(method).record();
        }
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
    /// by the resolved hash on the remaining budget. Slow prelude stages are warned about
    /// here, where they are measured; trace/serialize timing lives in
    /// [`compute_block_trace`] and cache-insert timing in [`insert_cache`].
    async fn lookup_block_by_number(
        &self,
        method: &'static str,
        resource: CachedResource,
        variant: Option<ResponseVariant>,
        block_number: BlockNumberOrTag,
        start: Instant,
    ) -> Result<BlockLookup, jsonrpsee::types::ErrorObjectOwned> {
        let deadline = self.data_provider.fetch_deadline();

        let t0 = Instant::now();
        let block_num =
            self.data_provider.resolve_block_number(block_number, deadline).await.map_err(|e| {
                metrics::record_rpc_error(method);
                rpc_err(format!("Failed to resolve block number: {e}"))
            })?;
        let resolve_ms = t0.elapsed().as_millis();
        tracing::Span::current().record("block_number", block_num);

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

        if resolve_ms >= SLOW_STAGE_THRESHOLD_MS ||
            resolve_hash_ms >= SLOW_STAGE_THRESHOLD_MS ||
            fetch_ms >= SLOW_STAGE_THRESHOLD_MS
        {
            warn!(
                method,
                block_number = block_num,
                resolve_ms = resolve_ms as u64,
                resolve_hash_ms = resolve_hash_ms as u64,
                fetch_data_ms = fetch_ms as u64,
                "by-number lookup slow stages detected"
            );
        }

        Ok(BlockLookup::Fetched(data))
    }

    /// Runs the geth-style block-trace executor over `data` via [`compute_block_trace`] —
    /// the one place the executor call shape lives for both debug block handlers.
    fn compute_debug_trace(
        &self,
        data: &BlockData,
        method: &'static str,
        opts: GethDebugTracingOptions,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
        compute_block_trace(data, method, || {
            crate::tracing_executor::trace_block(
                &self.chain_spec,
                &data.block,
                data.witness.clone(),
                &data.contracts,
                opts,
            )
        })
        .inspect_err(|e| self.on_trace_failure(method, &data.block.header.hash, e))
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))
    }
}

/// Outcome of [`RpcContext::lookup_block_by_number`].
enum BlockLookup {
    /// Served straight from the response cache.
    Cached(serde_json::Value),
    /// Cache miss: block data fetched by the resolved canonical hash, ready to trace.
    Fetched(Arc<BlockData>),
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
/// Runs a block-trace executor closure and wraps the scaffolding shared by every
/// block-level handler: EVM timing + metrics, JSON serialization, the response-size
/// metric, and the slow-stage warning. Returns the typed [`TraceError`] so the caller can
/// key cache hygiene off its data-vs-request discriminant before rendering an RPC error.
fn compute_block_trace<T: serde::Serialize>(
    data: &BlockData,
    method_name: &'static str,
    run: impl FnOnce() -> Result<T, TraceError>,
) -> Result<serde_json::Value, TraceError> {
    let start = Instant::now();

    let results = run()?;

    let trace_ms = start.elapsed().as_millis();
    EvmExecutionMetrics::new_for_method(method_name)
        .record(start.elapsed().as_secs_f64(), data.block.transactions.len());

    let value = serde_json::to_value(&results)
        .map_err(|e| TraceError::Request(format!("Serialization failed: {e}")))?;

    let serialize_ms = start.elapsed().as_millis() - trace_ms;
    let response_size = value.to_string().len();
    ResponseSizeMetrics::new_for_method(method_name).record(response_size);

    if trace_ms >= SLOW_STAGE_THRESHOLD_MS || serialize_ms >= SLOW_STAGE_THRESHOLD_MS {
        warn!(
            method = method_name,
            block_number = data.block.header.number,
            tx_count = data.block.transactions.len(),
            trace_ms = trace_ms as u64,
            serialize_ms = serialize_ms as u64,
            response_size_kb = response_size / 1024,
            "block trace slow stages detected"
        );
    }

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
/// Serializing a multi-MB response into the cache can be slow, so the insert is timed and
/// warned about here, where it happens.
fn insert_cache(
    cache: &Option<ResponseCache>,
    resource: CachedResource,
    block_hash: B256,
    variant: Option<ResponseVariant>,
    method_name: &'static str,
    result: &serde_json::Value,
) {
    let (Some(cache), Some(variant)) = (cache, variant) else {
        return;
    };
    let t = Instant::now();
    cache.insert(resource, block_hash, variant, result);
    let insert_ms = t.elapsed().as_millis();
    if insert_ms >= SLOW_STAGE_THRESHOLD_MS {
        warn!(
            method = method_name,
            block_hash = %block_hash,
            cache_insert_ms = insert_ms as u64,
            "slow response-cache insert"
        );
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

        let data = match self
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
            BlockLookup::Fetched(data) => data,
        };

        let result = self.compute_debug_trace(&data, METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, opts)?;

        insert_cache(
            &self.response_cache,
            CachedResource::DebugTraceBlock,
            data.block.header.hash,
            variant,
            METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
            &result,
        );
        record_request_completion(
            METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
            data.block.header.number,
            start,
        );

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

        let data = self.data_provider.get_block_data_by_hash(block_hash).await.map_err(|e| {
            metrics::record_rpc_error(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
            data_provider_error_to_rpc_error(&e)
        })?;
        let block_num = data.block.header.number;
        let result = self.compute_debug_trace(&data, METHOD_DEBUG_TRACE_BLOCK_BY_HASH, opts)?;

        // An entry for a non-canonical hash is still the correct answer for that hash —
        // exactly what geth serves — and is unreachable by-number.
        insert_cache(
            &self.response_cache,
            CachedResource::DebugTraceBlock,
            block_hash,
            variant,
            METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
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
            self.on_trace_failure(METHOD_DEBUG_TRACE_TRANSACTION, &data.block.header.hash, &e);
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
        Ok(serde_json::json!({
            "responseCache": cache_section(self.response_cache.as_ref().map(ResponseCache::stats)),
            "blockDataCache": cache_section(self.data_provider.block_data_cache_stats()),
        }))
    }
}

/// Renders one cache's `debug_getCacheStatus` JSON section: its [`CacheStats`], or
/// `{"status": "disabled"}` when the cache is off.
fn cache_section(stats: Option<CacheStats>) -> serde_json::Value {
    match stats {
        Some(stats) => serde_json::json!({
            "entryCount": stats.entry_count,
            "totalBytes": stats.total_bytes,
            "totalBytesMB": format!("{:.2}", stats.total_bytes as f64 / 1024.0 / 1024.0),
            "hits": stats.hits,
            "misses": stats.misses,
            "hitRate": format!("{:.1}%", stats.hit_rate())
        }),
        None => serde_json::json!({"status": "disabled"}),
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
        let data = match self
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
            BlockLookup::Fetched(data) => data,
        };

        let result = compute_block_trace(&data, METHOD_TRACE_BLOCK, || {
            crate::tracing_executor::parity_trace_block(
                &self.chain_spec,
                &data.block,
                data.witness.clone(),
                &data.contracts,
            )
        })
        .inspect_err(|e| self.on_trace_failure(METHOD_TRACE_BLOCK, &data.block.header.hash, e))
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        insert_cache(
            &self.response_cache,
            CachedResource::TraceBlock,
            data.block.header.hash,
            Some(ResponseVariant::Default),
            METHOD_TRACE_BLOCK,
            &result,
        );
        record_request_completion(METHOD_TRACE_BLOCK, data.block.header.number, start);

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
            self.on_trace_failure(METHOD_TRACE_TRANSACTION, &data.block.header.hash, &e);
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
    /// no hit/miss accounting, even when an entry exists under the same hash. A cacheable
    /// variant hits under the inserted hash and misses under any other — there is no
    /// number indirection left to go stale.
    #[test]
    fn check_cache_hit_miss_and_bypass() {
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
        let check = |hash, variant| {
            check_cache(&cache, CachedResource::DebugTraceBlock, hash, variant, "m", Instant::now())
        };
        let stats = || {
            let s = cache.as_ref().unwrap().stats();
            (s.hits, s.misses)
        };

        assert!(check(h1, None).is_none());
        assert_eq!(stats(), (0, 0), "bypass must not touch accounting");

        assert_eq!(check(h1, Some(ResponseVariant::Default)), Some(serde_json::json!({"v": 1})));
        assert!(check(h2, Some(ResponseVariant::Default)).is_none());
        assert_eq!(stats(), (1, 1));
    }

    /// Builds an `RpcContext` around a never-called upstream, with the given block-data
    /// cache, response cache, and chain spec.
    fn test_context(
        block_data_cache: Option<Arc<crate::block_data_cache::BlockDataCache>>,
        response_cache: Option<ResponseCache>,
        chain_spec: ChainSpec,
    ) -> RpcContext {
        use stateless_common::{RpcClient, RpcClientConfig};
        use stateless_core::ContractStore;
        use stateless_db::ContractCache;

        use crate::data_provider::{
            DEFAULT_WITNESS_TIMEOUT_SECS, NoopContractStore, WitnessFetchConfig,
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::mem::forget(listener);
        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let contract_cache =
            Arc::new(ContractCache::new(Arc::new(NoopContractStore) as Arc<dyn ContractStore>));
        let provider = Arc::new(DataProvider::new(
            rpc_client,
            None,
            block_data_cache,
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(1),
            1024,
        ));
        RpcContext::new(provider, Arc::new(chain_spec), response_cache)
    }

    /// [`test_context`] with the block-data cache merely toggled, for the cache-status
    /// tests.
    fn cache_status_context(
        block_data_cache: bool,
        response_cache: Option<ResponseCache>,
    ) -> RpcContext {
        use crate::block_data_cache::BlockDataCache;

        test_context(
            block_data_cache.then(|| Arc::new(BlockDataCache::new(1024 * 1024))),
            response_cache,
            ChainSpec::default(),
        )
    }

    /// The eviction rule at `on_trace_failure`: a data-attributable failure (a witness
    /// that cannot replay the block) drops the cached block data, while a
    /// request-attributable one (a mux tracer config that fails to parse) must not —
    /// mux/JS shapes bypass the response cache, so evicting on them would let any client
    /// drop hot entries at will.
    #[tokio::test]
    async fn trace_failure_evicts_block_data_only_for_data_errors() {
        use alloy_rpc_types_trace::geth::{
            GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType,
        };
        use stateless_test_utils::fixtures::TestFixtures;

        use crate::{
            block_data_cache::BlockDataCache, data_provider::test_support::fixture_block_data,
            server_db::test_support::empty_light_witness,
        };

        let chain_spec = ChainSpec::from_genesis(
            TestFixtures::synthetic().load_genesis().expect("fixture genesis"),
        );

        // Request-attributable: healthy cached data plus an unparseable mux config.
        let cache = Arc::new(BlockDataCache::new(64 * 1024 * 1024));
        let data = fixture_block_data();
        let hash = data.block.header.hash;
        cache.insert(hash, Arc::new(data));
        let ctx = test_context(Some(Arc::clone(&cache)), None, chain_spec.clone());
        let opts = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::MuxTracer)),
            tracer_config: GethDebugTracerConfig(serde_json::json!({"bogusTracer": {}})),
            ..Default::default()
        };
        ctx.trace_block_by_hash(hash, Some(opts)).await.unwrap_err();
        assert_eq!(cache.stats().entry_count, 1, "a request error must not evict");

        // Data-attributable: the same block cached with a witness that cannot replay it.
        let cache = Arc::new(BlockDataCache::new(64 * 1024 * 1024));
        let data = fixture_block_data();
        let hash = data.block.header.hash;
        cache.insert(
            hash,
            Arc::new(BlockData {
                block: data.block,
                witness: empty_light_witness(),
                contracts: data.contracts,
            }),
        );
        let ctx = test_context(Some(Arc::clone(&cache)), None, chain_spec);
        ctx.trace_block_by_hash(hash, None).await.unwrap_err();
        assert_eq!(cache.stats().entry_count, 0, "a data error must evict the poisoned entry");
    }

    /// `debug_getCacheStatus` must always report both cache sections, each independently
    /// enabled or `{"status": "disabled"}`.
    #[tokio::test]
    async fn get_cache_status_reports_block_data_cache_section() {
        let ctx = cache_status_context(true, None);
        let status = ctx.get_cache_status().await.unwrap();
        assert_eq!(status["responseCache"]["status"], "disabled");
        assert_eq!(status["blockDataCache"]["entryCount"], 0);
        assert_eq!(status["blockDataCache"]["hits"], 0);

        let ctx = cache_status_context(
            false,
            Some(ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100))),
        );
        let status = ctx.get_cache_status().await.unwrap();
        assert_eq!(status["blockDataCache"]["status"], "disabled");
        assert_eq!(status["responseCache"]["entryCount"], 0);
    }

    #[test]
    fn insert_cache_skips_non_cacheable_variants() {
        let cache = Some(ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100)));
        let result = serde_json::json!([{"txHash": "0x01"}]);
        let hash = B256::from([1u8; 32]);

        insert_cache(&cache, CachedResource::DebugTraceBlock, hash, None, "m", &result);
        assert_eq!(cache.as_ref().unwrap().len(), 0);

        insert_cache(
            &cache,
            CachedResource::DebugTraceBlock,
            hash,
            Some(ResponseVariant::Default),
            "m",
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
