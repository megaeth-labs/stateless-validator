//! Metrics collection for debug-trace-server.

use std::net::SocketAddr;

use eyre::Result;
use metrics::{counter, describe_counter, describe_histogram, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

/// Default metrics port.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Initialize the Prometheus metrics exporter.
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

/// Record an RPC request.
pub fn record_rpc_request(method: &str, duration_secs: f64) {
    counter!("debug_trace_rpc_requests_total", "method" => method.to_string()).increment(1);
    histogram!("debug_trace_request_duration_seconds", "method" => method.to_string())
        .record(duration_secs);
}

/// Record an RPC error.
#[allow(dead_code)]
pub fn record_rpc_error(method: &str) {
    counter!("debug_trace_rpc_errors_total", "method" => method.to_string()).increment(1);
}
