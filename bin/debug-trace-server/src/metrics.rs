//! Prometheus Metrics for Debug-Trace-Server
//!
//! This module provides metrics collection and export for monitoring the debug-trace-server.
//! Metrics are exposed via HTTP endpoint for Prometheus scraping.
//!
//! Uses `metrics-derive` for declarative metric definitions following mega-reth patterns.

use std::net::SocketAddr;

use eyre::Result;
use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
pub use stateless_common::{
    DEFAULT_METRICS_PORT,
    metrics::{BYTE_BUCKETS, REORG_DEPTH_BUCKETS},
};

/// Prefix for timed RPC method aliases.
pub const TIMED_PREFIX: &str = "timed_";

/// RPC method name for debug_traceBlockByNumber.
pub const METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER: &str = "debug_traceBlockByNumber";
/// RPC method name for debug_traceBlockByHash.
pub const METHOD_DEBUG_TRACE_BLOCK_BY_HASH: &str = "debug_traceBlockByHash";
/// RPC method name for debug_traceTransaction.
pub const METHOD_DEBUG_TRACE_TRANSACTION: &str = "debug_traceTransaction";
/// RPC method name for debug_getCacheStatus.
pub const METHOD_DEBUG_GET_CACHE_STATUS: &str = "debug_getCacheStatus";
/// RPC method name for trace_block.
pub const METHOD_TRACE_BLOCK: &str = "trace_block";
/// RPC method name for trace_transaction.
pub const METHOD_TRACE_TRANSACTION: &str = "trace_transaction";

/// Timed alias for debug_traceBlockByNumber.
pub const TIMED_METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER: &str = "timed_debug_traceBlockByNumber";
/// Timed alias for debug_traceBlockByHash.
pub const TIMED_METHOD_DEBUG_TRACE_BLOCK_BY_HASH: &str = "timed_debug_traceBlockByHash";
/// Timed alias for debug_traceTransaction.
pub const TIMED_METHOD_DEBUG_TRACE_TRANSACTION: &str = "timed_debug_traceTransaction";
/// Timed alias for debug_getCacheStatus.
pub const TIMED_METHOD_DEBUG_GET_CACHE_STATUS: &str = "timed_debug_getCacheStatus";
/// Timed alias for trace_block.
pub const TIMED_METHOD_TRACE_BLOCK: &str = "timed_trace_block";
/// Timed alias for trace_transaction.
pub const TIMED_METHOD_TRACE_TRANSACTION: &str = "timed_trace_transaction";

/// All (timed_alias, original_method) pairs for registering aliases.
pub const TIMED_METHOD_ALIASES: &[(&str, &str)] = &[
    (TIMED_METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER),
    (TIMED_METHOD_DEBUG_TRACE_BLOCK_BY_HASH, METHOD_DEBUG_TRACE_BLOCK_BY_HASH),
    (TIMED_METHOD_DEBUG_TRACE_TRANSACTION, METHOD_DEBUG_TRACE_TRANSACTION),
    (TIMED_METHOD_DEBUG_GET_CACHE_STATUS, METHOD_DEBUG_GET_CACHE_STATUS),
    (TIMED_METHOD_TRACE_BLOCK, METHOD_TRACE_BLOCK),
    (TIMED_METHOD_TRACE_TRANSACTION, METHOD_TRACE_TRANSACTION),
];

/// Cache type for debug trace block responses.
pub const CACHE_TYPE_DEBUG_TRACE: &str = "debug_trace_block";
/// Cache type for parity trace block responses.
pub const CACHE_TYPE_TRACE: &str = "trace_block";

// All known RPC methods (for resolving &str → &'static str)
const ALL_METHODS: &[&str] = &[
    METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
    METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
    METHOD_DEBUG_TRACE_TRANSACTION,
    METHOD_DEBUG_GET_CACHE_STATUS,
    METHOD_TRACE_BLOCK,
    METHOD_TRACE_TRANSACTION,
];

fn resolve_method(method: &str) -> &'static str {
    ALL_METHODS.iter().find(|&&m| m == method).copied().unwrap_or("unknown")
}

/// RPC method metrics with method label.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct RpcMethodMetrics {
    /// Total number of RPC requests
    rpc_requests_total: Counter,
    /// Total number of RPC errors
    rpc_errors_total: Counter,
    /// Duration of RPC method calls in seconds
    request_duration_seconds: Histogram,
}

impl RpcMethodMetrics {
    /// Creates metrics for a specific RPC method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Records a successful request.
    pub fn record_request(&self, duration_secs: f64) {
        self.rpc_requests_total.increment(1);
        self.request_duration_seconds.record(duration_secs);
    }

    /// Records an RPC error.
    pub fn record_error(&self) {
        self.rpc_errors_total.increment(1);
    }
}

/// Global RPC metrics (singleton).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct RpcGlobalMetrics {
    /// Number of currently in-flight RPC requests
    inflight_requests: Gauge,
}

impl RpcGlobalMetrics {
    /// Creates global RPC metrics.
    pub fn create() -> Self {
        Self::new_with_labels(&[("scope", "global")])
    }

    /// Increments the in-flight request count.
    pub fn inc_inflight(&self) {
        self.inflight_requests.increment(1.0);
    }

    /// Decrements the in-flight request count.
    pub fn dec_inflight(&self) {
        self.inflight_requests.decrement(1.0);
    }
}

/// Response size metrics with method label.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct ResponseSizeMetrics {
    /// Response size in bytes
    response_size_bytes: Histogram,
}

impl ResponseSizeMetrics {
    /// Creates metrics for a specific method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Records a response size.
    pub fn record(&self, size: usize) {
        self.response_size_bytes.record(size as f64);
    }
}

/// CPU execution time per request (global, no method label).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct CpuTimeMetrics {
    /// CPU execution time per request in seconds
    cpu_time_seconds: Histogram,
}

impl CpuTimeMetrics {
    /// Creates global CPU time metrics.
    pub fn create() -> Self {
        Self::new_with_labels(&[] as &[(&str, &str)])
    }

    /// Records a CPU time measurement.
    pub fn record(&self, seconds: f64) {
        self.cpu_time_seconds.record(seconds);
    }
}

/// Response cache metrics with cache type label.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct CacheMetrics {
    /// Total cache hits
    cache_hits_total: Counter,
    /// Total cache misses
    cache_misses_total: Counter,
    /// Current number of entries in cache
    cache_entries: Gauge,
    /// Current cache data size in bytes
    cache_bytes: Gauge,
}

impl CacheMetrics {
    /// Creates metrics for a specific cache type.
    pub fn new_for_cache(cache_type: &'static str) -> Self {
        Self::new_with_labels(&[("type", cache_type)])
    }

    /// Records a cache hit.
    pub fn record_hit(&self) {
        self.cache_hits_total.increment(1);
    }

    /// Records a cache miss.
    pub fn record_miss(&self) {
        self.cache_misses_total.increment(1);
    }

    /// Sets the current cache size.
    pub fn set_size(&self, entry_count: usize, data_bytes: usize) {
        self.cache_entries.set(entry_count as f64);
        self.cache_bytes.set(data_bytes as f64);
    }
}

/// Tracks which source provided block data (cache/db/witness_generator).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct DataSourceMetrics {
    /// Total block data fetches by source
    block_data_fetches_total: Counter,
}

impl DataSourceMetrics {
    /// Creates metrics for a specific data source.
    pub fn new_for_source(source: &'static str) -> Self {
        Self::new_with_labels(&[("source", source)])
    }

    /// Records a block data fetch from this source.
    pub fn record(&self) {
        self.block_data_fetches_total.increment(1);
    }
}

/// Single-flight coalescing metrics (new/coalesced/bypassed).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct SingleFlightMetrics {
    /// Total single-flight events by type
    single_flight_total: Counter,
}

impl SingleFlightMetrics {
    /// Creates metrics for a specific single-flight event type.
    pub fn new_for_type(event_type: &'static str) -> Self {
        Self::new_with_labels(&[("type", event_type)])
    }

    /// Records a single-flight event.
    pub fn record(&self) {
        self.single_flight_total.increment(1);
    }
}

/// Upstream RPC metrics with method label.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct UpstreamMetrics {
    /// Total upstream RPC requests
    upstream_requests_total: Counter,
    /// Total upstream RPC errors
    upstream_errors_total: Counter,
    /// Duration of upstream RPC requests in seconds
    upstream_duration_seconds: Histogram,
}

impl UpstreamMetrics {
    /// Creates metrics for a specific upstream RPC method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Records an upstream RPC request.
    pub fn record_request(&self, success: bool, duration_secs: f64) {
        self.upstream_requests_total.increment(1);
        if !success {
            self.upstream_errors_total.increment(1);
        }
        self.upstream_duration_seconds.record(duration_secs);
    }
}

/// Witness fetch metrics by source.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct WitnessSourceMetrics {
    /// Total witness fetch requests
    witness_requests_total: Counter,
    /// Total witness fetch errors
    witness_errors_total: Counter,
    /// Duration of witness fetch in seconds
    witness_duration_seconds: Histogram,
    /// Witness response size in bytes
    witness_bytes: Histogram,
}

impl WitnessSourceMetrics {
    /// Creates metrics for a specific witness source.
    pub fn new_for_source(source: &'static str) -> Self {
        Self::new_with_labels(&[("source", source)])
    }

    /// Records a witness fetch request.
    pub fn record_request(&self, success: bool, duration_secs: f64) {
        self.witness_requests_total.increment(1);
        if !success {
            self.witness_errors_total.increment(1);
        }
        self.witness_duration_seconds.record(duration_secs);
    }

    /// Records witness response size.
    pub fn record_size(&self, bytes: usize) {
        self.witness_bytes.record(bytes as f64);
    }
}

/// EVM execution metrics with method label.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct EvmExecutionMetrics {
    /// EVM execution duration in seconds
    evm_execution_seconds: Histogram,
    /// Number of transactions per traced block
    evm_block_tx_count: Histogram,
}

impl EvmExecutionMetrics {
    /// Creates metrics for a specific method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Records an EVM execution.
    pub fn record(&self, duration_secs: f64, tx_count: usize) {
        self.evm_execution_seconds.record(duration_secs);
        self.evm_block_tx_count.record(tx_count as f64);
    }
}

/// Chain sync metrics (singleton).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct ChainSyncMetrics {
    /// Depth of chain reorgs
    reorg_depth: Histogram,
    /// Duration of DB read operations in seconds
    db_read_duration_seconds: Histogram,
    /// Distance of requested block from chain tip
    block_distance_from_tip: Histogram,
    /// Earliest block number in validator DB
    db_earliest_block: Gauge,
    /// Latest block number in validator DB
    db_latest_block: Gauge,
    /// Database file size in bytes
    db_size_bytes: Gauge,
    /// Local chain tip block number (updated on every advance)
    local_chain_height: Gauge,
}

impl ChainSyncMetrics {
    /// Creates chain sync metrics.
    pub fn create() -> Self {
        Self::new_with_labels(&[("scope", "chain_sync")])
    }

    /// Records a reorg event.
    pub fn record_reorg(&self, depth: u64) {
        self.reorg_depth.record(depth as f64);
    }

    /// Records a DB read duration.
    pub fn record_db_read(&self, duration_secs: f64) {
        self.db_read_duration_seconds.record(duration_secs);
    }

    /// Records block distance from tip.
    pub fn record_block_distance(&self, distance: u64) {
        self.block_distance_from_tip.record(distance as f64);
    }

    /// Sets the earliest and latest block numbers in the validator DB.
    pub fn set_db_block_range(&self, earliest: u64, latest: u64) {
        self.db_earliest_block.set(earliest as f64);
        self.db_latest_block.set(latest as f64);
    }

    /// Sets the database file size in bytes.
    pub fn set_db_size(&self, bytes: u64) {
        self.db_size_bytes.set(bytes as f64);
    }

    /// Updates the local chain height gauge.
    pub fn set_chain_height(&self, height: u64) {
        self.local_chain_height.set(height as f64);
    }
}

/// Pre-registers all metrics so they appear in Prometheus from startup (with zero values).
fn pre_register_all_metrics() {
    // Request Layer: RPC method metrics
    let _ = RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
    let _ = RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
    let _ = RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION);
    let _ = RpcMethodMetrics::new_for_method(METHOD_TRACE_BLOCK);
    let _ = RpcMethodMetrics::new_for_method(METHOD_TRACE_TRANSACTION);

    // Request Layer: global
    let _ = RpcGlobalMetrics::create();

    // Request Layer: response size (per method)
    let _ = ResponseSizeMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
    let _ = ResponseSizeMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
    let _ = ResponseSizeMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION);
    let _ = ResponseSizeMetrics::new_for_method(METHOD_TRACE_BLOCK);
    let _ = ResponseSizeMetrics::new_for_method(METHOD_TRACE_TRANSACTION);

    // Request Layer: CPU time (global)
    let _ = CpuTimeMetrics::create();

    // Cache Layer
    let _ = CacheMetrics::new_for_cache(CACHE_TYPE_DEBUG_TRACE);
    let _ = CacheMetrics::new_for_cache(CACHE_TYPE_TRACE);

    // Data Fetch Layer: data source
    let _ = DataSourceMetrics::new_for_source("cache");
    let _ = DataSourceMetrics::new_for_source("db");
    let _ = DataSourceMetrics::new_for_source("witness_generator");

    // Data Fetch Layer: single-flight
    let _ = SingleFlightMetrics::new_for_type("new");
    let _ = SingleFlightMetrics::new_for_type("coalesced");
    let _ = SingleFlightMetrics::new_for_type("bypassed");

    // Data Fetch Layer: upstream RPC
    let _ = UpstreamMetrics::new_for_method("eth_getHeaderByHash");
    let _ = UpstreamMetrics::new_for_method("eth_getBlockByHash");
    let _ = UpstreamMetrics::new_for_method("mega_getWitness");
    let _ = UpstreamMetrics::new_for_method("eth_getCodeByHash");

    // Witness Layer
    let _ = WitnessSourceMetrics::new_for_source("witness_generator");

    // Execution Layer (per method)
    let _ = EvmExecutionMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
    let _ = EvmExecutionMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
    let _ = EvmExecutionMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION);
    let _ = EvmExecutionMetrics::new_for_method(METHOD_TRACE_BLOCK);
    let _ = EvmExecutionMetrics::new_for_method(METHOD_TRACE_TRANSACTION);

    // Infrastructure
    let _ = ChainSyncMetrics::create();
}

/// Transaction count per traced block (~ 1–500).
const TX_COUNT_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0];

/// Block distance from chain tip (~ 0–1000 blocks).
const BLOCK_DISTANCE_BUCKETS: &[f64] = &[0.0, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0];

/// (metric_name, buckets) pairs applied via `set_buckets_for_metric` at startup.
const BUCKET_SPECS: &[(&str, &[f64])] = &[
    ("debug_trace_evm_block_tx_count", TX_COUNT_BUCKETS),
    ("debug_trace_block_distance_from_tip", BLOCK_DISTANCE_BUCKETS),
    ("debug_trace_reorg_depth", REORG_DEPTH_BUCKETS),
    ("debug_trace_witness_bytes", BYTE_BUCKETS),
];

/// Initializes the Prometheus metrics exporter.
pub fn init_metrics(addr: SocketAddr) -> Result<()> {
    let builder = BUCKET_SPECS.iter().fold(PrometheusBuilder::new(), |b, &(name, buckets)| {
        b.set_buckets_for_metric(Matcher::Full(name.to_owned()), buckets)
            .expect("valid bucket config")
    });

    builder
        .with_http_listener(addr)
        .install()
        .map_err(|e| eyre::eyre!("Failed to install metrics exporter: {}", e))?;

    // Pre-register all metrics
    pre_register_all_metrics();

    Ok(())
}

/// Strips the `timed_` prefix from a method name if present.
pub fn strip_timed_prefix(method: &str) -> &str {
    method.strip_prefix(TIMED_PREFIX).unwrap_or(method)
}

/// Records a successful RPC request.
pub fn record_rpc_request(method: &str, duration_secs: f64) {
    let method = resolve_method(strip_timed_prefix(method));
    RpcMethodMetrics::new_for_method(method).record_request(duration_secs);
}

/// Records an RPC error for a specific method.
pub fn record_rpc_error(method: &str) {
    let method = resolve_method(strip_timed_prefix(method));
    RpcMethodMetrics::new_for_method(method).record_error();
}

/// Maps an [`RpcMethod`] to the `method` label used by [`UpstreamMetrics`].
///
/// The existing dashboard labels (`eth_getHeaderByHash`, `eth_getBlockByHash`, etc.)
/// encode the trace-server-specific call flavor. Since [`RpcMethod`] is coarser
/// (no ByHash/ByNumber split), we keep the existing labels for the hot-path
/// methods and fall back to [`RpcMethod::as_str`] for the others.
fn upstream_label_for(method: stateless_common::metrics::RpcMethod) -> &'static str {
    use stateless_common::metrics::RpcMethod;
    match method {
        RpcMethod::EthGetHeader => "eth_getHeaderByHash",
        RpcMethod::EthGetBlock => "eth_getBlockByHash",
        RpcMethod::MegaGetBlockWitness => "mega_getWitness",
        RpcMethod::EthGetCodeByHash => "eth_getCodeByHash",
        other => other.as_str(),
    }
}

/// [`stateless_common::RpcMetrics`] adapter that forwards every per-attempt RPC
/// event to [`UpstreamMetrics`], keyed by method label.
///
/// Wired via [`stateless_common::RpcClientConfig::with_metrics`] so that the
/// per-attempt duration and success/failure counters recorded inside
/// `round_robin_with_backoff` land on the same dashboards the trace server has
/// always exposed — even though `get_block` / `get_header` / `get_witness` no
/// longer surface their per-call success status at the caller level.
#[derive(Default)]
pub struct TraceRpcMetrics;

impl stateless_common::RpcMetrics for TraceRpcMetrics {
    fn on_rpc_complete(
        &self,
        method: stateless_common::metrics::RpcMethod,
        success: bool,
        duration_secs: Option<f64>,
    ) {
        let label = upstream_label_for(method);
        // `new_for_method` is just a label binding — no allocation beyond what
        // the metrics crate deduplicates internally.
        UpstreamMetrics::new_for_method(label)
            .record_request(success, duration_secs.unwrap_or(0.0));
    }

    fn on_rpc_retry(&self, _method: stateless_common::metrics::RpcMethod) {
        // `on_rpc_complete(_, false, _)` fires alongside `on_rpc_retry` in the
        // retry loop, so the error/request counters already capture retries.
    }

    fn on_witness_fetch(&self, _breakdown: stateless_common::witness_size::WitnessSizeBreakdown) {
        // Witness size/source metrics are recorded by `fetch_witness_with_timeout`
        // at the outer timeout boundary (distinct semantics from per-attempt).
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_timed_prefix_with_prefix() {
        assert_eq!(
            strip_timed_prefix("timed_debug_traceBlockByNumber"),
            "debug_traceBlockByNumber"
        );
        assert_eq!(strip_timed_prefix("timed_trace_block"), "trace_block");
    }

    #[test]
    fn test_strip_timed_prefix_without_prefix() {
        assert_eq!(strip_timed_prefix("debug_traceBlockByNumber"), "debug_traceBlockByNumber");
        assert_eq!(strip_timed_prefix("unknown_method"), "unknown_method");
    }

    #[test]
    fn test_resolve_method_known() {
        assert_eq!(resolve_method("debug_traceBlockByNumber"), "debug_traceBlockByNumber");
        assert_eq!(resolve_method("trace_block"), "trace_block");
    }

    #[test]
    fn test_resolve_method_unknown() {
        assert_eq!(resolve_method("nonexistent"), "unknown");
    }

    #[test]
    fn test_timed_aliases_consistency() {
        for &(alias, _original) in TIMED_METHOD_ALIASES {
            assert!(alias.starts_with(TIMED_PREFIX));
        }
    }

    #[test]
    fn test_timed_aliases_match_originals() {
        for &(alias, original) in TIMED_METHOD_ALIASES {
            assert_eq!(strip_timed_prefix(alias), original);
        }
    }
}
