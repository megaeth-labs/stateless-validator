//! Prometheus Metrics for Debug-Trace-Server
//!
//! This module provides metrics collection and export for monitoring the debug-trace-server.
//! Metrics are exposed via HTTP endpoint for Prometheus scraping.
//!
//! # Exported Metrics
//! - `debug_trace_rpc_requests_total` - Counter of total RPC requests by method
//! - `debug_trace_rpc_errors_total` - Counter of RPC errors by method
//! - `debug_trace_request_duration_seconds` - Histogram of request durations by method

use std::net::SocketAddr;

use eyre::Result;
use metrics::{counter, describe_counter, describe_histogram, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

/// Default port for Prometheus metrics HTTP endpoint.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

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
    describe_counter!(
        "debug_trace_rpc_requests_total",
        "Total number of RPC requests"
    );
    describe_counter!("debug_trace_rpc_errors_total", "Total number of RPC errors");
    describe_histogram!(
        "debug_trace_request_duration_seconds",
        "Duration of RPC method calls"
    );

    Ok(())
}

/// Records a successful RPC request.
///
/// Increments the request counter and records the duration in the histogram.
/// Both metrics are labeled with the RPC method name.
///
/// # Arguments
/// * `method` - RPC method name (e.g., "debug_traceBlockByNumber")
/// * `duration_secs` - Request duration in seconds
pub fn record_rpc_request(method: &str, duration_secs: f64) {
    counter!("debug_trace_rpc_requests_total", "method" => method.to_string()).increment(1);
    histogram!("debug_trace_request_duration_seconds", "method" => method.to_string())
        .record(duration_secs);
}

/// Records an RPC error.
///
/// Increments the error counter labeled with the RPC method name.
/// Currently unused but available for future error tracking.
///
/// # Arguments
/// * `method` - RPC method name that encountered the error
#[allow(dead_code)]
pub fn record_rpc_error(method: &str) {
    counter!("debug_trace_rpc_errors_total", "method" => method.to_string()).increment(1);
}
