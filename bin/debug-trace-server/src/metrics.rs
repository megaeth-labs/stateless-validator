//! Prometheus Metrics for Debug-Trace-Server
//!
//! This module provides metrics collection and export for monitoring the debug-trace-server.
//! Metrics are exposed via HTTP endpoint for Prometheus scraping.
//!
//! # Exported Metrics
//!
//! ## RPC Metrics
//! - `debug_trace_rpc_requests_total` - Counter of total RPC requests by method
//! - `debug_trace_rpc_errors_total` - Counter of RPC errors by method
//! - `debug_trace_request_duration_seconds` - Histogram of request durations by method
//!
//! ## Cache Metrics
//! - `debug_trace_cache_hits_total` - Counter of cache hits by cache type
//! - `debug_trace_cache_misses_total` - Counter of cache misses by cache type
//! - `debug_trace_cache_size` - Current number of entries in cache by type
//!
//! ## Upstream RPC Metrics
//! - `debug_trace_upstream_requests_total` - Counter of upstream RPC requests by method
//! - `debug_trace_upstream_errors_total` - Counter of upstream RPC errors by method
//! - `debug_trace_upstream_duration_seconds` - Histogram of upstream request durations
//!
//! ## Tracing Metrics
//! - `debug_trace_transactions_traced_total` - Counter of transactions traced
//! - `debug_trace_blocks_traced_total` - Counter of blocks traced
//! - `debug_trace_tracing_duration_seconds` - Histogram of tracing execution time

use std::net::SocketAddr;

use eyre::Result;
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

/// Default port for Prometheus metrics HTTP endpoint.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Metric name constants for debug-trace-server.
pub mod names {
    // RPC metrics
    pub const RPC_REQUESTS_TOTAL: &str = "debug_trace_rpc_requests_total";
    pub const RPC_ERRORS_TOTAL: &str = "debug_trace_rpc_errors_total";
    pub const REQUEST_DURATION: &str = "debug_trace_request_duration_seconds";

    // Cache metrics
    pub const CACHE_HITS_TOTAL: &str = "debug_trace_cache_hits_total";
    pub const CACHE_MISSES_TOTAL: &str = "debug_trace_cache_misses_total";
    pub const CACHE_SIZE: &str = "debug_trace_cache_size";

    // Upstream RPC metrics
    pub const UPSTREAM_REQUESTS_TOTAL: &str = "debug_trace_upstream_requests_total";
    pub const UPSTREAM_ERRORS_TOTAL: &str = "debug_trace_upstream_errors_total";
    pub const UPSTREAM_DURATION: &str = "debug_trace_upstream_duration_seconds";

    // Tracing metrics
    pub const TRANSACTIONS_TRACED: &str = "debug_trace_transactions_traced_total";
    pub const BLOCKS_TRACED: &str = "debug_trace_blocks_traced_total";
    pub const TRACING_DURATION: &str = "debug_trace_tracing_duration_seconds";
}

/// Initializes the Prometheus metrics exporter.
///
/// Starts an HTTP server on the specified address that exposes metrics
/// in Prometheus text format at the `/metrics` endpoint.
///
/// # Arguments
/// * `addr` - Socket address to bind the metrics HTTP server
///
/// # Returns
/// * `Ok(())` - Metrics exporter successfully installed
/// * `Err` - If the exporter fails to start (e.g., port already in use)
pub fn init_metrics(addr: SocketAddr) -> Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| eyre::eyre!("Failed to install metrics exporter: {}", e))?;

    // Register metric descriptions
    // RPC metrics
    describe_counter!(names::RPC_REQUESTS_TOTAL, "Total number of RPC requests");
    describe_counter!(names::RPC_ERRORS_TOTAL, "Total number of RPC errors");
    describe_histogram!(names::REQUEST_DURATION, "Duration of RPC method calls");

    // Cache metrics
    describe_counter!(names::CACHE_HITS_TOTAL, "Total cache hits");
    describe_counter!(names::CACHE_MISSES_TOTAL, "Total cache misses");
    describe_gauge!(names::CACHE_SIZE, "Current cache size");

    // Upstream RPC metrics
    describe_counter!(
        names::UPSTREAM_REQUESTS_TOTAL,
        "Total upstream RPC requests"
    );
    describe_counter!(names::UPSTREAM_ERRORS_TOTAL, "Total upstream RPC errors");
    describe_histogram!(
        names::UPSTREAM_DURATION,
        "Duration of upstream RPC requests"
    );

    // Tracing metrics
    describe_counter!(names::TRANSACTIONS_TRACED, "Total transactions traced");
    describe_counter!(names::BLOCKS_TRACED, "Total blocks traced");
    describe_histogram!(names::TRACING_DURATION, "Duration of tracing execution");

    Ok(())
}

// ---------------------------------------------------------------------------
// RPC Method Metrics
// ---------------------------------------------------------------------------

/// Records a successful RPC request.
///
/// Increments the request counter and records the duration in the histogram.
/// Both metrics are labeled with the RPC method name.
///
/// # Arguments
/// * `method` - RPC method name (e.g., "debug_traceBlockByNumber")
/// * `duration_secs` - Request duration in seconds
pub fn record_rpc_request(method: &str, duration_secs: f64) {
    counter!(names::RPC_REQUESTS_TOTAL, "method" => method.to_string()).increment(1);
    histogram!(names::REQUEST_DURATION, "method" => method.to_string()).record(duration_secs);
}

/// Records an RPC error.
///
/// Increments the error counter labeled with the RPC method name.
///
/// # Arguments
/// * `method` - RPC method name that encountered the error
#[allow(dead_code)]
pub fn record_rpc_error(method: &str) {
    counter!(names::RPC_ERRORS_TOTAL, "method" => method.to_string()).increment(1);
}

// ---------------------------------------------------------------------------
// Cache Metrics
// ---------------------------------------------------------------------------

/// Cache types for metrics labeling.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum CacheType {
    /// LRU memory cache for block data
    BlockLru,
    /// Local database cache
    Database,
    /// Contract bytecode cache
    Contract,
}

impl CacheType {
    fn as_str(&self) -> &'static str {
        match self {
            CacheType::BlockLru => "block_lru",
            CacheType::Database => "database",
            CacheType::Contract => "contract",
        }
    }
}

/// Records a cache hit.
#[allow(dead_code)]
pub fn record_cache_hit(cache_type: CacheType) {
    counter!(names::CACHE_HITS_TOTAL, "type" => cache_type.as_str()).increment(1);
}

/// Records a cache miss.
#[allow(dead_code)]
pub fn record_cache_miss(cache_type: CacheType) {
    counter!(names::CACHE_MISSES_TOTAL, "type" => cache_type.as_str()).increment(1);
}

/// Sets the current cache size.
#[allow(dead_code)]
pub fn set_cache_size(cache_type: CacheType, size: usize) {
    gauge!(names::CACHE_SIZE, "type" => cache_type.as_str()).set(size as f64);
}

// ---------------------------------------------------------------------------
// Upstream RPC Metrics
// ---------------------------------------------------------------------------

/// Upstream RPC method types for metrics.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum UpstreamMethod {
    Block,
    Witness,
    Code,
    BlockNumber,
    TransactionReceipt,
}

impl UpstreamMethod {
    fn as_str(&self) -> &'static str {
        match self {
            UpstreamMethod::Block => "eth_getBlockByNumber",
            UpstreamMethod::Witness => "mega_getBlockWitness",
            UpstreamMethod::Code => "eth_getCodeByHash",
            UpstreamMethod::BlockNumber => "eth_blockNumber",
            UpstreamMethod::TransactionReceipt => "eth_getTransactionReceipt",
        }
    }
}

/// Records an upstream RPC request completion.
#[allow(dead_code)]
pub fn record_upstream_request(method: UpstreamMethod, success: bool, duration_secs: f64) {
    let method_str = method.as_str();
    counter!(names::UPSTREAM_REQUESTS_TOTAL, "method" => method_str).increment(1);
    if !success {
        counter!(names::UPSTREAM_ERRORS_TOTAL, "method" => method_str).increment(1);
    }
    histogram!(names::UPSTREAM_DURATION, "method" => method_str).record(duration_secs);
}

// ---------------------------------------------------------------------------
// Tracing Metrics
// ---------------------------------------------------------------------------

/// Records a block trace completion.
#[allow(dead_code)]
pub fn record_block_traced(tx_count: usize, duration_secs: f64) {
    counter!(names::BLOCKS_TRACED).increment(1);
    counter!(names::TRANSACTIONS_TRACED).increment(tx_count as u64);
    histogram!(names::TRACING_DURATION, "type" => "block").record(duration_secs);
}

/// Records a single transaction trace completion.
#[allow(dead_code)]
pub fn record_transaction_traced(duration_secs: f64) {
    counter!(names::TRANSACTIONS_TRACED).increment(1);
    histogram!(names::TRACING_DURATION, "type" => "transaction").record(duration_secs);
}
