//! Prometheus-compatible metrics for the stateless validator.
//!
//! This module provides Prometheus-compatible metrics for monitoring the validator's
//! performance, health, and resource utilization. Metrics are exposed via an HTTP
//! endpoint that can be scraped by Prometheus or compatible monitoring systems.
//!
//! ## Metric Categories
//!
//! - **Validation**: Block validation timing, success/failure rates, throughput
//! - **Worker**: Task processing statistics
//! - **Chain**: Chain progression, gaps, reorg tracking
//! - **RPC**: Request latency, error rates, fetch timing
//! - **Database**: Cache statistics
//!
//! Enable via `--metrics-enabled --metrics-port 9090` or environment variables.
//! Metrics available at `http://0.0.0.0:<port>/metrics`

use eyre::Result;
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use tracing::info;

/// Default port for Prometheus metrics HTTP endpoint
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Metric names as constants for consistency
pub mod names {
    macro_rules! metric {
        ($name:ident, $suffix:expr) => {
            pub const $name: &str = concat!("stateless_validator_", $suffix);
        };
    }

    // Validation
    metric!(BLOCKS_VALIDATED_TOTAL, "blocks_validated_total");
    metric!(BLOCKS_FAILED_TOTAL, "blocks_failed_total");
    metric!(
        BLOCK_VALIDATION_DURATION,
        "block_validation_duration_seconds"
    );
    metric!(TRANSACTIONS_PER_BLOCK, "transactions_per_block");
    metric!(GAS_USED_PER_BLOCK, "gas_used_per_block");

    // Worker
    metric!(WORKER_TASKS_COMPLETED, "worker_tasks_completed_total");
    metric!(WORKER_TASKS_FAILED, "worker_tasks_failed_total");

    // Chain
    metric!(CANONICAL_CHAIN_HEIGHT, "canonical_chain_height");
    metric!(REMOTE_CHAIN_HEIGHT, "remote_chain_height");
    metric!(CHAIN_GAP, "chain_gap");
    metric!(BLOCKS_ADVANCED, "blocks_advanced_total");
    metric!(REORGS_DETECTED, "reorgs_detected_total");
    metric!(REORG_DEPTH, "reorg_depth");

    // RPC
    metric!(RPC_REQUESTS_TOTAL, "rpc_requests_total");
    metric!(RPC_ERRORS_TOTAL, "rpc_errors_total");
    metric!(RPC_LATENCY, "rpc_latency_seconds");
    metric!(BLOCK_FETCH_DURATION, "block_fetch_duration_seconds");
    metric!(WITNESS_FETCH_DURATION, "witness_fetch_duration_seconds");
    metric!(CODE_FETCH_DURATION, "code_fetch_duration_seconds");

    // Database
    metric!(CONTRACT_CACHE_HITS, "contract_cache_hits_total");
    metric!(CONTRACT_CACHE_MISSES, "contract_cache_misses_total");
    metric!(BLOCKS_PRUNED, "blocks_pruned_total");
}

/// Initialize the Prometheus metrics exporter.
///
/// Sets up an HTTP server that exposes metrics at `/metrics` endpoint.
/// The server runs in the background and is automatically cleaned up
/// when the process exits.
pub fn init_metrics(addr: SocketAddr) -> Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| eyre::eyre!("Failed to install Prometheus exporter: {}", e))?;

    register_metric_descriptions();
    info!("[Metrics] Prometheus exporter listening on {}", addr);
    Ok(())
}

/// Register descriptions for all metrics.
///
/// This provides human-readable descriptions that appear in Prometheus
/// and monitoring UIs.
fn register_metric_descriptions() {
    // Validation
    describe_counter!(
        names::BLOCKS_VALIDATED_TOTAL,
        "Blocks successfully validated"
    );
    describe_counter!(names::BLOCKS_FAILED_TOTAL, "Blocks that failed validation");
    describe_histogram!(
        names::BLOCK_VALIDATION_DURATION,
        "Block validation time (s)"
    );
    describe_histogram!(names::TRANSACTIONS_PER_BLOCK, "Transactions per block");
    describe_histogram!(names::GAS_USED_PER_BLOCK, "Gas used per block");

    // Worker
    describe_counter!(names::WORKER_TASKS_COMPLETED, "Tasks completed by workers");
    describe_counter!(names::WORKER_TASKS_FAILED, "Tasks that failed");

    // Chain
    describe_gauge!(
        names::CANONICAL_CHAIN_HEIGHT,
        "Local canonical chain height"
    );
    describe_gauge!(names::REMOTE_CHAIN_HEIGHT, "Remote chain height");
    describe_gauge!(names::CHAIN_GAP, "Gap between remote and canonical heights");
    describe_counter!(names::BLOCKS_ADVANCED, "Blocks advanced on canonical chain");
    describe_counter!(names::REORGS_DETECTED, "Chain reorganizations detected");
    describe_histogram!(names::REORG_DEPTH, "Reorg depth");

    // RPC
    describe_counter!(names::RPC_REQUESTS_TOTAL, "RPC requests made");
    describe_counter!(names::RPC_ERRORS_TOTAL, "RPC errors encountered");
    describe_histogram!(names::RPC_LATENCY, "RPC latency (s)");
    describe_histogram!(names::BLOCK_FETCH_DURATION, "Block fetch time (s)");
    describe_histogram!(names::WITNESS_FETCH_DURATION, "Witness fetch time (s)");
    describe_histogram!(names::CODE_FETCH_DURATION, "Code fetch time (s)");

    // Database
    describe_counter!(names::CONTRACT_CACHE_HITS, "Contract cache hits");
    describe_counter!(names::CONTRACT_CACHE_MISSES, "Contract cache misses");
    describe_counter!(names::BLOCKS_PRUNED, "Blocks pruned from history");
}

// Validation metrics
pub fn record_block_validated(duration_secs: f64, tx_count: u64, gas_used: u64) {
    counter!(names::BLOCKS_VALIDATED_TOTAL).increment(1);
    histogram!(names::BLOCK_VALIDATION_DURATION).record(duration_secs);
    histogram!(names::TRANSACTIONS_PER_BLOCK).record(tx_count as f64);
    histogram!(names::GAS_USED_PER_BLOCK).record(gas_used as f64);
}

pub fn record_block_failed(error_type: &str) {
    counter!(names::BLOCKS_FAILED_TOTAL, "error_type" => error_type.to_string()).increment(1);
}

// Worker metrics
pub fn record_worker_task_completed(worker_id: usize) {
    counter!(names::WORKER_TASKS_COMPLETED, "worker_id" => worker_id.to_string()).increment(1);
}

pub fn record_worker_task_failed(worker_id: usize) {
    counter!(names::WORKER_TASKS_FAILED, "worker_id" => worker_id.to_string()).increment(1);
}

// Chain metrics
pub fn set_chain_heights(canonical: u64, remote: u64) {
    gauge!(names::CANONICAL_CHAIN_HEIGHT).set(canonical as f64);
    gauge!(names::REMOTE_CHAIN_HEIGHT).set(remote as f64);
    gauge!(names::CHAIN_GAP).set((remote.saturating_sub(canonical)) as f64);
}

pub fn record_blocks_advanced(count: u64) {
    counter!(names::BLOCKS_ADVANCED).increment(count);
}

pub fn record_reorg(depth: u64) {
    counter!(names::REORGS_DETECTED).increment(1);
    histogram!(names::REORG_DEPTH).record(depth as f64);
}

// RPC metrics
pub fn record_rpc_request(method: &str, duration_secs: f64, success: bool) {
    let method = method.to_string();
    counter!(names::RPC_REQUESTS_TOTAL, "method" => method.clone()).increment(1);
    histogram!(names::RPC_LATENCY, "method" => method.clone()).record(duration_secs);
    if !success {
        counter!(names::RPC_ERRORS_TOTAL, "method" => method).increment(1);
    }
}

pub fn record_block_fetch(duration_secs: f64) {
    histogram!(names::BLOCK_FETCH_DURATION).record(duration_secs);
}

pub fn record_witness_fetch(duration_secs: f64) {
    histogram!(names::WITNESS_FETCH_DURATION).record(duration_secs);
}

pub fn record_code_fetch(duration_secs: f64, count: usize) {
    histogram!(names::CODE_FETCH_DURATION).record(duration_secs);
    if count > 1 {
        histogram!(names::CODE_FETCH_DURATION, "type" => "per_code")
            .record(duration_secs / count as f64);
    }
}

pub fn record_contract_cache_hits(count: u64) {
    if count > 0 {
        counter!(names::CONTRACT_CACHE_HITS).increment(count);
    }
}

pub fn record_contract_cache_misses(count: u64) {
    if count > 0 {
        counter!(names::CONTRACT_CACHE_MISSES).increment(count);
    }
}

pub fn record_blocks_pruned(count: u64) {
    counter!(names::BLOCKS_PRUNED).increment(count);
}
