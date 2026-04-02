//! Chain synchronization utilities for stateless validation.
//!
//! This module provides shared chain synchronization logic used by both
//! stateless-validator and debug-trace-server.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockId;
use eyre::Result;
use futures::future;
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::RpcClient;

/// Default metrics port for Prometheus endpoint.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Configuration for chain synchronization behavior.
#[derive(Debug, Clone)]
pub struct ChainSyncConfig {
    /// Number of parallel validation workers to spawn.
    pub concurrent_workers: usize,
    /// Time to wait between main sync cycles.
    pub sync_poll_interval: Duration,
    /// Optional block height to sync to; None for infinite sync.
    pub sync_target: Option<u64>,
    /// Number of blocks to maintain as lookahead buffer.
    pub tracker_lookahead_blocks: u64,
    /// Time to wait between remote chain tracker cycles.
    pub tracker_poll_interval: Duration,
    /// Time to wait between history pruning cycles.
    pub pruner_interval: Duration,
    /// Number of recent blocks to retain from current tip.
    pub pruner_blocks_to_keep: u64,
    /// Time to wait when validation workers have no tasks.
    pub worker_idle_sleep: Duration,
    /// Time to wait when validation workers encounter errors.
    pub worker_error_sleep: Duration,
    /// Time to wait when remote tracker encounters RPC/DB errors.
    pub tracker_error_sleep: Duration,
    /// Enable reporting of validated blocks to upstream node.
    pub report_validation_results: bool,
    /// Enable Prometheus metrics endpoint.
    pub metrics_enabled: bool,
    /// Port for Prometheus metrics HTTP endpoint.
    pub metrics_port: u16,
    /// Auto-advance local tip when fetching blocks (skip validation).
    /// Enable for debug-trace-server where blocks are trusted from upstream RPC.
    /// Disable for stateless-validator where validation workers advance the tip.
    pub auto_advance_local_tip: bool,

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
            tracker_lookahead_blocks: 80,
            tracker_poll_interval: Duration::from_millis(100),
            pruner_interval: Duration::from_secs(300),
            pruner_blocks_to_keep: 1000,
            worker_idle_sleep: Duration::from_millis(500),
            worker_error_sleep: Duration::from_millis(1000),
            tracker_error_sleep: Duration::from_secs(1),
            report_validation_results: false,
            metrics_enabled: false,
            metrics_port: DEFAULT_METRICS_PORT,
            auto_advance_local_tip: false,
            fetch_channel_capacity: 2 * workers,
            result_channel_capacity: 2 * workers,
            fetcher_batch_size: workers,
            fetcher_max_backoff: Duration::from_secs(30),
        }
    }
}

/// Result of a single fetch_blocks_batch iteration.
#[derive(Debug)]
pub struct FetchResult {
    /// Number of blocks successfully fetched and stored.
    pub blocks_fetched: u64,
    /// Whether the tracker should sleep due to sufficient lookahead.
    pub should_wait: bool,
    /// Whether an error occurred during fetching.
    pub had_error: bool,
    /// Block hashes that were reverted due to reorg (empty if no reorg).
    pub reverted_hashes: Vec<B256>,
    /// Latest block number on the remote chain (if fetched).
    pub remote_chain_height: Option<u64>,
}

// ===========================================================================
// Streaming pipeline functions (used by stateless-validator memory-based mode)
// ===========================================================================

use std::collections::BTreeMap;

use tokio_util::sync::CancellationToken;

use crate::memory_db::{
    ChainTip, PersistentStore, ValidatedBlock, ValidationFailure, ValidationTask,
};

/// Continuously fetches blocks from RPC and sends them through a channel.
///
/// Fetches blocks sequentially starting from `start_block`, sending each
/// `ValidationTask` to the channel. Backpressure is provided by the bounded channel.
///
/// On RPC error, retries with exponential backoff. On channel closure or shutdown, returns.
pub async fn block_fetcher(
    client: Arc<RpcClient>,
    tx: kanal::Sender<ValidationTask>,
    start_block: u64,
    config: Arc<ChainSyncConfig>,
    shutdown: CancellationToken,
) -> Result<()> {
    let tx = tx.to_async();
    info!(
        start_block = start_block,
        batch_size = config.fetcher_batch_size,
        "Starting block fetcher"
    );

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
            Ok(n) => n,
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
            // At chain tip, wait for new blocks
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
            async move {
                let block_hash = client.get_block_hash(block_number).await?;
                let (salt_witness, mpt_witness) =
                    client.get_witness(block_number, block_hash).await?;
                let block = client.get_block(BlockId::Number(block_number.into()), true).await?;
                Ok::<_, eyre::Error>(ValidationTask { block, salt_witness, mpt_witness })
            }
            .instrument(info_span!("fetch_block", block_number = block_number))
        }))
        .await;

        // Process results in order, stop on first error
        let mut fetched = 0u64;
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(task) => {
                    block_error_counts.remove(&(next_block + i as u64));

                    // Send to channel (blocks if full — backpressure)
                    if tx.send(task).await.is_err() {
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
            let elapsed = fetch_start.elapsed();
            info!(
                blocks = fetched,
                start = next_block,
                end = next_block + fetched - 1,
                ms = elapsed.as_millis() as u64,
                "[Fetcher] Batch sent to pipeline"
            );
            next_block += fetched;
            backoff = Duration::from_secs(1); // reset backoff on success
        } else {
            // All blocks in batch failed, backoff
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = shutdown.cancelled() => return Ok(()),
            }
            backoff = (backoff * 2).min(config.fetcher_max_backoff);
        }
    }
}

/// Collects validation results and advances the canonical chain in block-number order.
///
/// Receives results from workers (potentially out of order), buffers them,
/// and advances the canonical tip in strict sequence. Batches multiple consecutive
/// blocks into a single persistence write.
///
/// If any validation fails, returns `Err` immediately (process should exit).
pub async fn chain_advancer(
    rx: kanal::Receiver<std::result::Result<ValidatedBlock, ValidationFailure>>,
    store: Arc<PersistentStore>,
    initial_tip: ChainTip,
    shutdown: CancellationToken,
) -> Result<()> {
    let rx = rx.to_async();
    let mut next_expected = initial_tip.block_number + 1;
    let mut current_tip = initial_tip;
    let mut buffer: BTreeMap<u64, ValidatedBlock> = BTreeMap::new();

    info!(start_block = next_expected, "[Advancer] Starting chain advancer");

    loop {
        // Receive next result
        let result = tokio::select! {
            r = rx.recv() => match r {
                Ok(r) => r,
                Err(_) => {
                    info!("[Advancer] Channel closed, stopping");
                    return Ok(());
                }
            },
            _ = shutdown.cancelled() => {
                info!("[Advancer] Shutting down gracefully");
                return Ok(());
            }
        };

        match result {
            Err(failure) => {
                error!(
                    block_number = failure.block_number,
                    block_hash = %failure.block_hash,
                    error = %failure.error,
                    "[Advancer] Validation failed, terminating"
                );
                return Err(eyre::eyre!(
                    "Block {} ({}) validation failed: {}",
                    failure.block_number,
                    failure.block_hash,
                    failure.error
                ));
            }
            Ok(validated) => {
                debug!(
                    block_number = validated.block_number,
                    "[Advancer] Received validated block"
                );
                buffer.insert(validated.block_number, validated);
            }
        }

        // Drain consecutive blocks from buffer
        let mut advanced = 0u64;
        while let Some(validated) = buffer.remove(&next_expected) {
            // Verify state root continuity
            if validated.pre_state_root != current_tip.post_state_root {
                return Err(eyre::eyre!(
                    "Block {} pre_state_root mismatch: expected {:?}, got {:?}",
                    validated.block_number,
                    current_tip.post_state_root,
                    validated.pre_state_root
                ));
            }
            if validated.pre_withdrawals_root != current_tip.post_withdrawals_root {
                return Err(eyre::eyre!(
                    "Block {} pre_withdrawals_root mismatch: expected {:?}, got {:?}",
                    validated.block_number,
                    current_tip.post_withdrawals_root,
                    validated.pre_withdrawals_root
                ));
            }

            current_tip = ChainTip {
                block_number: validated.block_number,
                block_hash: validated.block_hash,
                post_state_root: validated.post_state_root,
                post_withdrawals_root: validated.post_withdrawals_root,
            };
            next_expected += 1;
            advanced += 1;
        }

        // Batch-persist the new tip if any blocks were advanced
        if advanced > 0 {
            store.set_canonical_tip(&current_tip)?;
            info!(
                tip = current_tip.block_number,
                advanced = advanced,
                buffered = buffer.len(),
                "[Advancer] Chain advanced"
            );
        }
    }
}
