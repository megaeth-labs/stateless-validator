//! Chain synchronization utilities shared by both binaries.
//!
//! This module provides:
//! - [`ChainSyncConfig`]: Configuration for chain synchronization behavior.
//! - [`find_divergence_point`]: Finds where the local chain diverges from the remote RPC node.
//! - [`block_fetcher`]: Generic RPC block fetcher, shared by both binaries.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, BlockId};
use eyre::{Result, anyhow};
use futures::future;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, instrument, warn};

use crate::{ChainDataProvider, withdrawals::MptWitness};

/// Configuration for chain synchronization behavior.
#[derive(Debug, Clone)]
pub struct ChainSyncConfig {
    /// Number of parallel validation workers to spawn.
    pub concurrent_workers: usize,
    /// Time to wait between main sync cycles.
    pub sync_poll_interval: Duration,
    /// Optional block height to sync to; None for infinite sync.
    pub sync_target: Option<u64>,
    /// Time to wait between remote chain tracker cycles.
    pub tracker_poll_interval: Duration,
    /// Number of recent blocks to retain from current tip.
    /// Used by `chain_monitor` for stale data detection.
    pub pruner_blocks_to_keep: u64,
    /// Time to wait when remote tracker encounters RPC/DB errors.
    pub tracker_error_sleep: Duration,
    /// Enable reporting of validated blocks to upstream node.
    pub report_validation_results: bool,
    /// Enable Prometheus metrics endpoint.
    pub metrics_enabled: bool,
    /// Port for Prometheus metrics HTTP endpoint.
    pub metrics_port: u16,

    // --- Streaming pipeline settings (used by block_fetcher / chain_advancer) ---
    /// Channel capacity for the fetch→worker pipeline.
    pub fetch_channel_capacity: usize,
    /// Channel capacity for the worker→advancer pipeline.
    pub result_channel_capacity: usize,
    /// Number of blocks to fetch in parallel per batch.
    pub fetcher_batch_size: usize,
    /// Maximum RPC retry backoff for the fetcher.
    pub fetcher_max_backoff: Duration,
}

impl Default for ChainSyncConfig {
    fn default() -> Self {
        let workers = num_cpus::get();
        Self {
            concurrent_workers: workers,
            sync_poll_interval: Duration::from_secs(1),
            sync_target: None,
            tracker_poll_interval: Duration::from_millis(100),
            pruner_blocks_to_keep: 1000,
            tracker_error_sleep: Duration::from_secs(1),
            report_validation_results: false,
            metrics_enabled: false,
            metrics_port: 9090,
            fetch_channel_capacity: 2 * workers,
            result_channel_capacity: 2 * workers,
            fetcher_batch_size: workers,
            fetcher_max_backoff: Duration::from_secs(30),
        }
    }
}

/// Finds where the local chain diverges from the remote RPC node.
///
/// Uses exponential search (efficient for near-tip reorgs) followed by binary search
/// to locate the exact divergence point.
///
/// Backend-agnostic: takes closures for local chain lookups so it works with
/// any `dyn ChainStore` implementation (both `ValidatorDB` and `ServerDB`).
#[instrument(skip_all, name = "find_divergence")]
pub async fn find_divergence_point<C: ChainDataProvider>(
    client: &C,
    get_hash: &(dyn Fn(u64) -> eyre::Result<Option<BlockHash>> + Send + Sync),
    get_earliest: &(dyn Fn() -> eyre::Result<Option<(BlockNumber, BlockHash)>> + Send + Sync),
    mismatch_block: u64,
) -> Result<u64> {
    let earliest_local = get_earliest()?.expect("Local chain cannot be empty");

    // Safety check: verify earliest block matches remote chain
    let earliest_remote_hash = client.get_block_hash(earliest_local.0).await?;
    if earliest_remote_hash != earliest_local.1 {
        return Err(anyhow!(
            "Catastrophic reorg: earliest local block {} hash mismatch (local: {:?}, remote: {:?})",
            earliest_local.0,
            earliest_local.1,
            earliest_remote_hash
        ));
    }

    // Exponential search backward from mismatch point
    let mut step = 1u64;
    let mut last_mismatch = mismatch_block;
    let mut search_start = earliest_local.0;

    while last_mismatch > earliest_local.0 {
        let check_block = last_mismatch.saturating_sub(step).max(earliest_local.0);
        let local_hash = get_hash(check_block)?.unwrap();
        let remote_hash = client.get_block_hash(check_block).await?;

        if remote_hash == local_hash {
            search_start = check_block;
            break;
        } else {
            last_mismatch = check_block;
            step *= 2;
        }
    }

    // Binary search between search_start and last_mismatch
    let (mut left, mut right, mut last_matching) = (search_start, last_mismatch, search_start);
    while left <= right {
        let mid = left + (right - left) / 2;
        let local_hash = get_hash(mid)?.unwrap();
        let remote_hash = client.get_block_hash(mid).await?;
        if remote_hash == local_hash {
            last_matching = mid;
            left = mid + 1;
        } else {
            right = mid.saturating_sub(1);
        }
    }

    debug!(divergence_point = last_matching, mismatch_block, "Found divergence point");
    Ok(last_matching)
}

/// Continuously fetches blocks from RPC and sends them through a channel.
///
/// Generic over the output type `T` — the `transform` function converts raw RPC
/// data `(Block, SaltWitness, MptWitness)` into whatever the consumer needs.
/// Backpressure is provided by the bounded channel.
///
/// On RPC error, retries with exponential backoff. On channel closure or shutdown, returns.
pub async fn block_fetcher<T: Send + 'static, C: ChainDataProvider + 'static, F, G>(
    client: Arc<C>,
    tx: kanal::Sender<T>,
    start_block: u64,
    config: Arc<ChainSyncConfig>,
    shutdown: CancellationToken,
    transform: F,
    on_remote_height: Option<G>,
) -> Result<()>
where
    F: Fn(Block<Transaction>, SaltWitness, MptWitness) -> T + Send + Sync + 'static,
    G: Fn(u64) + Send + Sync,
{
    let transform = Arc::new(transform);
    let tx = tx.to_async();
    info!(start_block = start_block, batch_size = config.fetcher_batch_size, "[Fetcher] Starting");

    let mut next_block = start_block;
    let mut backoff = Duration::from_secs(1);
    let mut block_error_counts: HashMap<u64, usize> = HashMap::new();

    loop {
        if shutdown.is_cancelled() {
            info!("[Fetcher] Shutting down gracefully");
            return Ok(());
        }

        // Check sync target
        if let Some(target) = config.sync_target &&
            next_block > target
        {
            info!(target = target, "[Fetcher] Reached sync target, stopping");
            return Ok(());
        }

        // Wait until there's data to fetch (check chain latest)
        let chain_latest = match client.get_latest_block_number().await {
            Ok(n) => {
                if let Some(ref cb) = on_remote_height {
                    cb(n);
                }
                n
            }
            Err(e) => {
                warn!(error = %e, "[Fetcher] Failed to get chain latest, retrying");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.cancelled() => return Ok(()),
                }
                backoff = (backoff * 2).min(config.fetcher_max_backoff);
                continue;
            }
        };

        if next_block > chain_latest {
            tokio::select! {
                _ = tokio::time::sleep(config.tracker_poll_interval) => {}
                _ = shutdown.cancelled() => return Ok(()),
            }
            continue;
        }

        // Calculate batch size
        let blocks_available = chain_latest - next_block + 1;
        let batch_size = (config.fetcher_batch_size as u64).min(blocks_available);

        debug!(
            next_block = next_block,
            batch_size = batch_size,
            chain_latest = chain_latest,
            "[Fetcher] Fetching batch"
        );

        // Fetch blocks in parallel
        let fetch_start = Instant::now();
        let results = future::join_all((next_block..next_block + batch_size).map(|block_number| {
            let client = client.clone();
            let transform = Arc::clone(&transform);
            async move {
                let block_hash = client.get_block_hash(block_number).await?;
                let (salt_witness, mpt_witness) =
                    client.get_witness(block_number, block_hash).await?;
                let block = client.get_block(BlockId::Number(block_number.into()), true).await?;
                Ok::<_, eyre::Error>(transform(block, salt_witness, mpt_witness))
            }
            .instrument(info_span!("fetch_block", block_number = block_number))
        }))
        .await;

        // Process results in order, stop on first error
        let mut fetched = 0u64;
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(item) => {
                    block_error_counts.remove(&(next_block + i as u64));
                    if tx.send(item).await.is_err() {
                        info!("[Fetcher] Channel closed, stopping");
                        return Ok(());
                    }
                    fetched += 1;
                }
                Err(e) => {
                    let block_number = next_block + i as u64;
                    let count = block_error_counts.entry(block_number).or_insert(0);
                    *count += 1;
                    if *count > 5 {
                        error!(
                            block_number = block_number,
                            attempt = *count,
                            error = %e,
                            "[Fetcher] Block fetch error (repeated)"
                        );
                    }
                    break;
                }
            }
        }

        if fetched > 0 {
            info!(
                blocks = fetched,
                start = next_block,
                end = next_block + fetched - 1,
                ms = fetch_start.elapsed().as_millis() as u64,
                "[Fetcher] Batch sent to pipeline"
            );
            next_block += fetched;
            backoff = Duration::from_secs(1);
        } else {
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = shutdown.cancelled() => return Ok(()),
            }
            backoff = (backoff * 2).min(config.fetcher_max_backoff);
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_sync_config_default_uses_cpu_count() {
        let config = ChainSyncConfig::default();
        let cpus = num_cpus::get();
        assert_eq!(config.concurrent_workers, cpus);
        assert_eq!(config.fetch_channel_capacity, 2 * cpus);
        assert_eq!(config.result_channel_capacity, 2 * cpus);
        assert_eq!(config.fetcher_batch_size, cpus);
    }
}
