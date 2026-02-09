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
use metrics_exporter_prometheus::PrometheusBuilder;

/// Default port for Prometheus metrics HTTP endpoint.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

// ---------------------------------------------------------------------------
// RPC Method Name Constants
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Cache Type Constants
// ---------------------------------------------------------------------------

/// Cache type for debug trace block responses.
pub const CACHE_TYPE_DEBUG_TRACE: &str = "debug_trace_block";
/// Cache type for parity trace block responses.
pub const CACHE_TYPE_TRACE: &str = "trace_block";

// ---------------------------------------------------------------------------
// Metric Structs (using metrics-derive)
// ---------------------------------------------------------------------------

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

/// Global RPC metrics (uses "global" label to distinguish from per-method).
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
    /// Creates metrics for a specific cache type (e.g., "debug_trace_block", "trace_block").
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

/// Tracing execution metrics with tracer type label.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct TracingMetrics {
    /// Total transactions traced
    transactions_traced_total: Counter,
    /// Total blocks traced
    blocks_traced_total: Counter,
    /// Duration of tracing execution in seconds
    tracing_duration_seconds: Histogram,
}

impl TracingMetrics {
    /// Creates metrics for a specific tracer type (e.g., "geth", "parity").
    pub fn new_for_tracer(tracer: &'static str) -> Self {
        Self::new_with_labels(&[("tracer", tracer)])
    }

    /// Records a block trace completion.
    pub fn record_block(&self, tx_count: usize, duration_secs: f64) {
        self.blocks_traced_total.increment(1);
        self.transactions_traced_total.increment(tx_count as u64);
        self.tracing_duration_seconds.record(duration_secs);
    }

    /// Records a single transaction trace.
    pub fn record_transaction(&self, duration_secs: f64) {
        self.transactions_traced_total.increment(1);
        self.tracing_duration_seconds.record(duration_secs);
    }
}

/// Chain sync metrics.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct ChainSyncMetrics {
    /// Depth of chain reorgs
    reorg_depth: Histogram,
    /// Current remote chain height
    remote_chain_height: Gauge,
    /// Duration of DB read operations in seconds
    db_read_duration_seconds: Histogram,
    /// Distance of requested block from chain tip
    block_distance_from_tip: Histogram,
    /// Earliest block number in validator DB
    db_earliest_block: Gauge,
    /// Latest block number in validator DB
    db_latest_block: Gauge,
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

    /// Sets the remote chain height.
    pub fn set_remote_height(&self, height: u64) {
        self.remote_chain_height.set(height as f64);
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
}

// ---------------------------------------------------------------------------
// Pre-initialized Metric Instances
// ---------------------------------------------------------------------------

/// Collection of all debug-trace-server metrics.
/// Used for pre-registration to ensure metrics are visible before first use.
#[derive(Clone)]
#[allow(dead_code)]
pub struct DebugTraceMetrics {
    // RPC method metrics
    pub debug_trace_block_by_number: RpcMethodMetrics,
    pub debug_trace_block_by_hash: RpcMethodMetrics,
    pub debug_trace_transaction: RpcMethodMetrics,
    pub trace_block: RpcMethodMetrics,
    pub trace_transaction: RpcMethodMetrics,

    // Global RPC metrics
    pub rpc_global: RpcGlobalMetrics,

    // Cache metrics by type
    pub cache_debug_trace: CacheMetrics,
    pub cache_trace: CacheMetrics,

    // Chain sync metrics
    pub chain_sync: ChainSyncMetrics,
}

impl Default for DebugTraceMetrics {
    fn default() -> Self {
        Self {
            debug_trace_block_by_number: RpcMethodMetrics::new_for_method(
                METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
            ),
            debug_trace_block_by_hash: RpcMethodMetrics::new_for_method(
                METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
            ),
            debug_trace_transaction: RpcMethodMetrics::new_for_method(
                METHOD_DEBUG_TRACE_TRANSACTION,
            ),
            trace_block: RpcMethodMetrics::new_for_method(METHOD_TRACE_BLOCK),
            trace_transaction: RpcMethodMetrics::new_for_method(METHOD_TRACE_TRANSACTION),
            rpc_global: RpcGlobalMetrics::create(),
            cache_debug_trace: CacheMetrics::new_for_cache(CACHE_TYPE_DEBUG_TRACE),
            cache_trace: CacheMetrics::new_for_cache(CACHE_TYPE_TRACE),
            chain_sync: ChainSyncMetrics::create(),
        }
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initializes the Prometheus metrics exporter.
///
/// Starts an HTTP server on the specified address that exposes metrics
/// in Prometheus text format at the `/metrics` endpoint.
pub fn init_metrics(addr: SocketAddr) -> Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| eyre::eyre!("Failed to install metrics exporter: {}", e))?;

    // Pre-register all metrics by creating default instances
    // This ensures metrics are visible even before first use
    let _ = DebugTraceMetrics::default();

    Ok(())
}

// ---------------------------------------------------------------------------
// Backward-compatible helper functions
// ---------------------------------------------------------------------------

/// Strips the `timed_` prefix from a method name if present.
/// Returns the original method name (without prefix) for metrics recording.
pub fn strip_timed_prefix(method: &str) -> &str {
    method.strip_prefix(TIMED_PREFIX).unwrap_or(method)
}

/// Records a successful RPC request (backward-compatible helper).
///
/// Handles both original and `timed_`-prefixed method names by stripping the
/// prefix before recording metrics, so timed variants share the same counters.
pub fn record_rpc_request(method: &str, duration_secs: f64) {
    let method = strip_timed_prefix(method);
    match method {
        METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER => {
            RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER)
                .record_request(duration_secs)
        }
        METHOD_DEBUG_TRACE_BLOCK_BY_HASH => {
            RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH)
                .record_request(duration_secs)
        }
        METHOD_DEBUG_TRACE_TRANSACTION => {
            RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION)
                .record_request(duration_secs)
        }
        METHOD_TRACE_BLOCK => {
            RpcMethodMetrics::new_for_method(METHOD_TRACE_BLOCK).record_request(duration_secs)
        }
        METHOD_TRACE_TRANSACTION => {
            RpcMethodMetrics::new_for_method(METHOD_TRACE_TRANSACTION).record_request(duration_secs)
        }
        _ => {
            tracing::warn!(method = method, "Unknown RPC method in metrics");
        }
    }
}

/// Records an RPC error for a specific method (backward-compatible helper).
///
/// Handles both original and `timed_`-prefixed method names.
pub fn record_rpc_error(method: &str) {
    let method = strip_timed_prefix(method);
    match method {
        METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER => {
            RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER).record_error()
        }
        METHOD_DEBUG_TRACE_BLOCK_BY_HASH => {
            RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH).record_error()
        }
        METHOD_DEBUG_TRACE_TRANSACTION => {
            RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION).record_error()
        }
        METHOD_TRACE_BLOCK => RpcMethodMetrics::new_for_method(METHOD_TRACE_BLOCK).record_error(),
        METHOD_TRACE_TRANSACTION => {
            RpcMethodMetrics::new_for_method(METHOD_TRACE_TRANSACTION).record_error()
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        assert_eq!(strip_timed_prefix("timed_trace_transaction"), "trace_transaction");
    }

    #[test]
    fn test_strip_timed_prefix_without_prefix() {
        assert_eq!(strip_timed_prefix("debug_traceBlockByNumber"), "debug_traceBlockByNumber");
        assert_eq!(strip_timed_prefix("trace_block"), "trace_block");
        assert_eq!(strip_timed_prefix("unknown_method"), "unknown_method");
    }

    #[test]
    fn test_strip_timed_prefix_edge_cases() {
        assert_eq!(strip_timed_prefix("timed_"), "");
        assert_eq!(strip_timed_prefix(""), "");
        assert_eq!(
            strip_timed_prefix("TIMED_debug_traceBlockByNumber"),
            "TIMED_debug_traceBlockByNumber"
        );
        // Only strips once
        assert_eq!(strip_timed_prefix("timed_timed_trace_block"), "timed_trace_block");
    }

    #[test]
    fn test_timed_aliases_consistency() {
        // Every alias must start with the TIMED_PREFIX
        for &(alias, _original) in TIMED_METHOD_ALIASES {
            assert!(
                alias.starts_with(TIMED_PREFIX),
                "Alias '{}' does not start with '{}'",
                alias,
                TIMED_PREFIX
            );
        }
    }

    #[test]
    fn test_timed_aliases_match_originals() {
        // Stripping the prefix from each alias must yield the original method name
        for &(alias, original) in TIMED_METHOD_ALIASES {
            assert_eq!(
                strip_timed_prefix(alias),
                original,
                "Alias '{}' does not map back to '{}'",
                alias,
                original
            );
        }
    }

    #[test]
    fn test_timed_aliases_cover_all_methods() {
        let all_methods = [
            METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
            METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
            METHOD_DEBUG_TRACE_TRANSACTION,
            METHOD_DEBUG_GET_CACHE_STATUS,
            METHOD_TRACE_BLOCK,
            METHOD_TRACE_TRANSACTION,
        ];
        let aliased_originals: Vec<&str> =
            TIMED_METHOD_ALIASES.iter().map(|&(_, orig)| orig).collect();
        for method in all_methods {
            assert!(
                aliased_originals.contains(&method),
                "Method '{}' has no timed_ alias in TIMED_METHOD_ALIASES",
                method
            );
        }
    }
}
