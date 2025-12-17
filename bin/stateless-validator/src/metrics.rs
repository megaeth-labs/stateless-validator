//! Prometheus metrics for the stateless validator.
//!
//! Exposes metrics at `http://0.0.0.0:<port>/metrics` for Prometheus scraping.
//! Enable via `--metrics-enabled --metrics-port 9090`.

use std::net::SocketAddr;

use eyre::Result;
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use tracing::info;

/// Default metrics port.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Metric name constants.
pub mod names {
    macro_rules! metric {
        ($name:ident, $suffix:expr) => {
            pub const $name: &str = concat!("stateless_validator_", $suffix);
        };
    }

    // Validation
    metric!(BLOCK_VALIDATION_TIME, "block_validation_time_seconds");
    metric!(
        WITNESS_VERIFICATION_TIME,
        "witness_verification_time_seconds"
    );
    metric!(BLOCK_REPLAY_TIME, "block_replay_time_seconds");
    metric!(SALT_UPDATE_TIME, "salt_update_time_seconds");
    metric!(TRANSACTIONS_TOTAL, "transactions_total");
    metric!(GAS_USED_TOTAL, "gas_used_total");
    metric!(BLOCK_STATE_READS, "block_state_reads");
    metric!(BLOCK_STATE_WRITES, "block_state_writes");

    // Worker
    metric!(WORKER_TASKS_COMPLETED, "worker_tasks_completed_total");
    metric!(WORKER_TASKS_FAILED, "worker_tasks_failed_total");

    // Chain
    metric!(LOCAL_CHAIN_HEIGHT, "local_chain_height");
    metric!(REMOTE_CHAIN_HEIGHT, "remote_chain_height");
    metric!(VALIDATION_LAG, "validation_lag");
    metric!(REORGS_DETECTED, "reorgs_detected_total");
    metric!(REORG_DEPTH, "reorg_depth");

    // RPC
    metric!(RPC_REQUESTS_TOTAL, "rpc_requests_total");
    metric!(RPC_ERRORS_TOTAL, "rpc_errors_total");
    metric!(BLOCK_FETCH_TIME, "block_fetch_time_seconds");
    metric!(WITNESS_FETCH_TIME, "witness_fetch_time_seconds");
    metric!(CODE_FETCH_TIME, "code_fetch_time_seconds");

    // Database
    metric!(CONTRACT_CACHE_HITS, "contract_cache_hits_total");
    metric!(CONTRACT_CACHE_MISSES, "contract_cache_misses_total");
    metric!(BLOCKS_PRUNED, "blocks_pruned_total");

    // Witness
    metric!(SALT_WITNESS_SIZE, "salt_witness_size_bytes");
    metric!(SALT_WITNESS_KEYS, "salt_witness_keys");
    metric!(SALT_WITNESS_KVS_SIZE, "salt_witness_kvs_bytes");
    metric!(MPT_WITNESS_SIZE, "mpt_witness_size_bytes");
}

/// Initialize the Prometheus metrics exporter at the given address.
pub fn init_metrics(addr: SocketAddr) -> Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| eyre::eyre!("Failed to install Prometheus exporter: {}", e))?;

    register_metric_descriptions();
    info!("[Metrics] Prometheus exporter listening on {}", addr);
    Ok(())
}

/// Register metric descriptions for Prometheus.
fn register_metric_descriptions() {
    // Validation
    describe_histogram!(names::BLOCK_VALIDATION_TIME, "Block validation time (s)");
    describe_histogram!(
        names::WITNESS_VERIFICATION_TIME,
        "Witness verification time (s)"
    );
    describe_histogram!(names::BLOCK_REPLAY_TIME, "EVM execution time (s)");
    describe_histogram!(names::SALT_UPDATE_TIME, "SALT update time (s)");
    describe_counter!(names::TRANSACTIONS_TOTAL, "Total transactions validated");
    describe_counter!(names::GAS_USED_TOTAL, "Total gas used in validated blocks");
    describe_histogram!(names::BLOCK_STATE_READS, "Plain kvs reads per block");
    describe_histogram!(names::BLOCK_STATE_WRITES, "Plain kvs writes per block");

    // Worker
    describe_counter!(names::WORKER_TASKS_COMPLETED, "Tasks completed by workers");
    describe_counter!(names::WORKER_TASKS_FAILED, "Tasks that failed");

    // Chain
    describe_gauge!(names::LOCAL_CHAIN_HEIGHT, "Local chain height");
    describe_gauge!(names::REMOTE_CHAIN_HEIGHT, "Remote chain height");
    describe_gauge!(
        names::VALIDATION_LAG,
        "Blocks pending validation (remote - local)"
    );
    describe_counter!(names::REORGS_DETECTED, "Chain reorgs detected");
    describe_histogram!(names::REORG_DEPTH, "Reorg depth");

    // RPC
    describe_counter!(names::RPC_REQUESTS_TOTAL, "RPC requests made");
    describe_counter!(names::RPC_ERRORS_TOTAL, "RPC errors encountered");
    describe_histogram!(names::BLOCK_FETCH_TIME, "Block fetch time (s)");
    describe_histogram!(names::WITNESS_FETCH_TIME, "Witness fetch time (s)");
    describe_histogram!(names::CODE_FETCH_TIME, "Code fetch time (s)");

    // Database
    describe_counter!(names::CONTRACT_CACHE_HITS, "Contract cache hits");
    describe_counter!(names::CONTRACT_CACHE_MISSES, "Contract cache misses");
    describe_counter!(names::BLOCKS_PRUNED, "Blocks pruned from history");

    // Witness
    describe_histogram!(names::SALT_WITNESS_SIZE, "Salt witness size (bytes)");
    describe_histogram!(names::MPT_WITNESS_SIZE, "MPT witness size (bytes)");
    describe_histogram!(names::SALT_WITNESS_KEYS, "Salt witness key count");
    describe_histogram!(
        names::SALT_WITNESS_KVS_SIZE,
        "Salt witness KVs size (bytes)"
    );
}

/// Record validation timing and block statistics after successful validation.
#[allow(clippy::too_many_arguments)]
pub fn on_validation_success(
    duration: f64,
    wit_verify: f64,
    replay: f64,
    salt_update: f64,
    tx_count: u64,
    gas_used: u64,
    state_reads: usize,
    state_writes: usize,
) {
    histogram!(names::BLOCK_VALIDATION_TIME).record(duration);
    histogram!(names::WITNESS_VERIFICATION_TIME).record(wit_verify);
    histogram!(names::BLOCK_REPLAY_TIME).record(replay);
    histogram!(names::SALT_UPDATE_TIME).record(salt_update);
    counter!(names::TRANSACTIONS_TOTAL).increment(tx_count);
    counter!(names::GAS_USED_TOTAL).increment(gas_used);
    histogram!(names::BLOCK_STATE_READS).record(state_reads as f64);
    histogram!(names::BLOCK_STATE_WRITES).record(state_writes as f64);
}

// Worker metrics
pub fn on_worker_task_done(worker_id: usize, success: bool) {
    let worker = worker_id.to_string();
    if success {
        counter!(names::WORKER_TASKS_COMPLETED, "worker_id" => worker).increment(1);
    } else {
        counter!(names::WORKER_TASKS_FAILED, "worker_id" => worker).increment(1);
    }
}

// Chain metrics
pub fn set_chain_heights(local: u64, remote: u64) {
    gauge!(names::LOCAL_CHAIN_HEIGHT).set(local as f64);
    gauge!(names::REMOTE_CHAIN_HEIGHT).set(remote as f64);
    gauge!(names::VALIDATION_LAG).set((remote.saturating_sub(local)) as f64);
}

pub fn on_chain_reorg(depth: u64) {
    counter!(names::REORGS_DETECTED).increment(1);
    histogram!(names::REORG_DEPTH).record(depth as f64);
}

/// RPC method types for metrics tracking.
#[derive(Debug, Clone, Copy)]
pub enum RpcMethod {
    EthGetCodeByHash,
    EthGetBlockByNumber,
    EthBlockNumber,
    MegaGetBlockWitness,
    MegaSetValidatedBlocks,
}

// RPC metrics
pub fn on_rpc_complete(method: RpcMethod, success: bool, duration_secs: Option<f64>) {
    let method_str = match method {
        RpcMethod::EthGetCodeByHash => "eth_getCodeByHash",
        RpcMethod::EthGetBlockByNumber => "eth_getBlockByNumber",
        RpcMethod::EthBlockNumber => "eth_blockNumber",
        RpcMethod::MegaGetBlockWitness => "mega_getBlockWitness",
        RpcMethod::MegaSetValidatedBlocks => "mega_setValidatedBlocks",
    };
    counter!(names::RPC_REQUESTS_TOTAL, "method" => method_str).increment(1);
    if !success {
        counter!(names::RPC_ERRORS_TOTAL, "method" => method_str).increment(1);
    }

    if let Some(duration) = duration_secs {
        match method {
            RpcMethod::EthGetCodeByHash => {
                histogram!(names::CODE_FETCH_TIME).record(duration);
            }
            RpcMethod::EthGetBlockByNumber => {
                histogram!(names::BLOCK_FETCH_TIME).record(duration);
            }
            RpcMethod::MegaGetBlockWitness => {
                histogram!(names::WITNESS_FETCH_TIME).record(duration);
            }
            _ => {}
        }
    }
}

pub fn on_contract_cache_read(hits: u64, misses: u64) {
    if hits > 0 {
        counter!(names::CONTRACT_CACHE_HITS).increment(hits);
    }
    if misses > 0 {
        counter!(names::CONTRACT_CACHE_MISSES).increment(misses);
    }
}

pub fn on_blocks_pruned(count: u64) {
    counter!(names::BLOCKS_PRUNED).increment(count);
}

// Witness metrics
pub fn on_witness_stats(salt_size: usize, keys_count: usize, kvs_size: usize, mpt_size: usize) {
    histogram!(names::SALT_WITNESS_SIZE).record(salt_size as f64);
    histogram!(names::SALT_WITNESS_KEYS).record(keys_count as f64);
    histogram!(names::SALT_WITNESS_KVS_SIZE).record(kvs_size as f64);
    histogram!(names::MPT_WITNESS_SIZE).record(mpt_size as f64);
}
