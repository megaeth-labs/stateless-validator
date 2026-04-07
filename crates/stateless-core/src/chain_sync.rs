//! Chain synchronization utilities for stateless validation.
//!
//! This module provides:
//! - [`block_fetcher`]: Generic RPC block fetcher, shared by both binaries.
//! - [`chain_advancer`]: Streaming validation pipeline for `stateless-validator`.
//! - [`chain_monitor`] / [`trace_chain_advancer`]: Pipeline for `debug-trace-server`, using
//!   [`BlockStore`] / [`ChainStore`] traits to decouple from concrete DB implementations.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, BlockId};
use eyre::{Result, anyhow};
use futures::future;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, instrument, warn};

use crate::{
    LightWitness, RpcClient,
    db::{BlockMeta, BlockStore, ChainStore, ValidatedBlock, ValidationFailure},
    withdrawals::MptWitness,
};

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
            metrics_port: DEFAULT_METRICS_PORT,
            fetch_channel_capacity: 2 * workers,
            result_channel_capacity: 2 * workers,
            fetcher_batch_size: workers,
            fetcher_max_backoff: Duration::from_secs(30),
        }
    }
}

// ---------------------------------------------------------------------------
// Debug-trace-server pipeline (trait-based)
// ---------------------------------------------------------------------------

/// Events sent from [`chain_monitor`] to [`trace_chain_advancer`] through a channel.
pub enum ChainSyncEvent {
    /// New blocks fetched from RPC, ready to store and advance.
    NewBlocks(Vec<(Block<Transaction>, LightWitness)>),
    /// Chain reorg detected — advancer must roll back and invalidate caches.
    Reorg { rollback_to: BlockNumber, reverted_hashes: Vec<B256> },
    /// Local data is too stale — reset the anchor to this block.
    ResetAnchor {
        block_number: BlockNumber,
        block_hash: alloy_primitives::BlockHash,
        state_root: B256,
        withdrawals_root: B256,
    },
}

/// Chain monitor for `debug-trace-server`.
///
/// Manages the [`block_fetcher`] lifecycle, detects reorgs and stale data,
/// and forwards fetched blocks as [`ChainSyncEvent`]s to the advancer.
/// All DB access is read-only via [`ChainStore`].
pub async fn chain_monitor(
    client: Arc<RpcClient>,
    db: Arc<dyn ChainStore>,
    advancer_tx: kanal::Sender<ChainSyncEvent>,
    config: Arc<ChainSyncConfig>,
    shutdown: CancellationToken,
) -> Result<()> {
    let advancer_tx = advancer_tx.to_async();
    info!("[Monitor] Starting chain monitor");

    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }

        // Determine where to start fetching from DB tip
        let start_block = match db.get_canonical_tip()? {
            Some(tip) => tip.block_number + 1,
            None => return Err(anyhow!("Local chain is empty")),
        };

        // Spawn a block_fetcher with LightWitness transform
        let (fetch_tx, fetch_rx) =
            kanal::bounded::<(Block<Transaction>, LightWitness)>(config.fetch_channel_capacity);
        let fetch_rx = fetch_rx.to_async();
        let fetcher_shutdown = CancellationToken::new();
        let mut fetcher_handle = tokio::task::spawn(block_fetcher(
            Arc::clone(&client),
            fetch_tx,
            start_block,
            Arc::clone(&config),
            fetcher_shutdown.clone(),
            |block, salt_witness, _mpt_witness| (block, LightWitness::from(salt_witness)),
            None::<fn(u64)>,
        ));

        info!(start_block, "[Monitor] Fetcher spawned");

        // Inner loop: forward blocks + periodic reorg check
        let mut last_reorg_check = Instant::now();
        let reorg_check_interval = config.tracker_poll_interval * 10;
        let mut restart = false;

        loop {
            // Receive next fetched block, or detect fetcher crash/error
            let item = tokio::select! {
                r = fetch_rx.recv() => match r {
                    Ok(item) => Some(item),
                    Err(_) => {
                        // Channel closed — check if fetcher errored
                        if let Ok(Err(e)) = fetcher_handle.await {
                            error!(error = %e, "[Monitor] Fetcher exited with error");
                        }
                        break;
                    }
                },
                r = &mut fetcher_handle => {
                    // Fetcher task completed (error or panic)
                    match r {
                        Ok(Err(e)) => error!(error = %e, "[Monitor] Fetcher exited with error"),
                        Err(e) => error!(error = %e, "[Monitor] Fetcher panicked"),
                        Ok(Ok(())) => info!("[Monitor] Fetcher exited cleanly"),
                    }
                    break;
                },
                _ = tokio::time::sleep(config.tracker_poll_interval) => None,
                _ = shutdown.cancelled() => {
                    fetcher_shutdown.cancel();
                    return Ok(());
                }
            };

            // Accumulate batch from channel
            let mut batch = Vec::new();
            if let Some(item) = item {
                batch.push(item);
                // Drain any additional ready items
                while let Ok(Some(item)) = fetch_rx.try_recv() {
                    batch.push(item);
                }
            }

            // Forward batch to advancer
            if !batch.is_empty() {
                advancer_tx
                    .send(ChainSyncEvent::NewBlocks(batch))
                    .await
                    .map_err(|_| anyhow!("Advancer channel closed"))?;
            }

            // Periodic reorg/stale check
            if last_reorg_check.elapsed() < reorg_check_interval {
                continue;
            }
            last_reorg_check = Instant::now();

            // Stale data detection
            let Some(canonical_tip) = db.get_canonical_tip()? else {
                continue;
            };
            let (tip_number, tip_hash) = (canonical_tip.block_number, canonical_tip.block_hash);

            let chain_latest = match client.get_latest_block_number().await {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, "[Monitor] Failed to get chain latest");
                    continue;
                }
            };

            if chain_latest > tip_number + config.pruner_blocks_to_keep {
                warn!(
                    tip_number,
                    chain_latest, "[Monitor] Local data is too stale, resetting anchor"
                );
                fetcher_shutdown.cancel();
                let header = client.get_header(BlockId::latest(), false).await?;
                advancer_tx
                    .send(ChainSyncEvent::ResetAnchor {
                        block_number: header.number,
                        block_hash: header.hash,
                        state_root: header.state_root,
                        withdrawals_root: header.withdrawals_root.unwrap_or_default(),
                    })
                    .await
                    .map_err(|_| anyhow!("Advancer channel closed"))?;
                restart = true;
                break;
            }

            // Reorg detection
            match client.get_block_hash(tip_number).await {
                Ok(hash) if hash != tip_hash => {
                    warn!(
                        block_number = tip_number,
                        expected_hash = %tip_hash,
                        actual_hash = %hash,
                        "[Monitor] Hash mismatch, resolving reorg"
                    );
                    fetcher_shutdown.cancel();
                    let rollback_to = find_divergence_point(
                        &client,
                        &|n| db.get_block_hash(n),
                        &|| db.get_earliest_block(),
                        tip_number,
                    )
                    .await?;

                    let mut reverted_hashes = Vec::new();
                    for n in (rollback_to + 1)..=tip_number {
                        if let Ok(Some(h)) = db.get_block_hash(n) {
                            reverted_hashes.push(h);
                        }
                    }

                    advancer_tx
                        .send(ChainSyncEvent::Reorg { rollback_to, reverted_hashes })
                        .await
                        .map_err(|_| anyhow!("Advancer channel closed"))?;
                    restart = true;
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "[Monitor] Network error validating tip");
                }
                _ => {}
            }
        }

        if !restart {
            // Fetcher ended unexpectedly, wait before restarting
            tokio::select! {
                _ = tokio::time::sleep(config.tracker_error_sleep) => {}
                _ = shutdown.cancelled() => return Ok(()),
            }
        }

        // Brief pause before restarting to let advancer process events
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// DB-write side of the debug-trace-server chain sync pipeline.
///
/// Receives [`ChainSyncEvent`]s from the fetcher, stores blocks, advances the
/// canonical chain, and handles reorgs. All DB mutations go through [`BlockStore`].
pub async fn trace_chain_advancer<F>(
    db: Arc<dyn BlockStore>,
    rx: kanal::Receiver<ChainSyncEvent>,
    on_reorg: Option<F>,
    shutdown: CancellationToken,
) -> Result<()>
where
    F: Fn(&[B256]) + Send + Sync,
{
    let rx = rx.to_async();
    info!("[TraceAdvancer] Starting");

    loop {
        let event = tokio::select! {
            r = rx.recv() => match r {
                Ok(event) => event,
                Err(_) => {
                    info!("[TraceAdvancer] Channel closed, stopping");
                    return Ok(());
                }
            },
            _ = shutdown.cancelled() => {
                info!("[TraceAdvancer] Shutting down gracefully");
                return Ok(());
            }
        };

        match event {
            ChainSyncEvent::NewBlocks(blocks) => {
                let count = blocks.len();
                let start = Instant::now();

                db.store_block_data(&blocks)?;

                // Build BlockMetas from block headers for chain advancement
                let chain_tips: Vec<BlockMeta> = blocks
                    .iter()
                    .map(|(block, _)| BlockMeta {
                        block_number: block.header.number,
                        block_hash: block.header.hash,
                        post_state_root: block.header.state_root,
                        post_withdrawals_root: block.header.withdrawals_root.unwrap_or_default(),
                    })
                    .collect();
                db.advance_chain(&chain_tips)?;

                info!(
                    blocks = count,
                    ms = start.elapsed().as_millis() as u64,
                    "[TraceAdvancer] Stored and advanced"
                );
            }
            ChainSyncEvent::Reorg { rollback_to, reverted_hashes } => {
                warn!(
                    rollback_to,
                    reverted = reverted_hashes.len(),
                    "[TraceAdvancer] Processing reorg"
                );
                db.rollback_chain(rollback_to)?;
                if let Some(ref callback) = on_reorg {
                    callback(&reverted_hashes);
                }
            }
            ChainSyncEvent::ResetAnchor {
                block_number,
                block_hash,
                state_root,
                withdrawals_root,
            } => {
                info!(block_number, %block_hash, "[TraceAdvancer] Resetting anchor");
                db.reset_to_anchor(&BlockMeta {
                    block_number,
                    block_hash,
                    post_state_root: state_root,
                    post_withdrawals_root: withdrawals_root,
                })?;
            }
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
pub async fn find_divergence_point(
    client: &RpcClient,
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

/// Result of reorg detection — signals the validator to restart its pipeline.
#[derive(Debug)]
pub struct ReorgEvent {
    /// Block number to roll back to (inclusive).
    pub rollback_to: BlockNumber,
    /// Depth of the reorg (number of reverted blocks).
    pub depth: u64,
}

/// Monitors the validator's canonical chain for reorgs.
///
/// Periodically compares the local canonical tip hash with the remote RPC.
/// On mismatch, finds the divergence point, rolls back the chain, and returns
/// a [`ReorgEvent`] signaling the caller to restart the pipeline.
pub async fn validator_reorg_monitor(
    client: Arc<RpcClient>,
    store: Arc<dyn ChainStore>,
    check_interval: Duration,
    shutdown: CancellationToken,
) -> Result<ReorgEvent> {
    info!("[ReorgMonitor] Starting");

    loop {
        tokio::select! {
            _ = tokio::time::sleep(check_interval) => {}
            _ = shutdown.cancelled() => {
                return Err(anyhow!("Shutdown requested"));
            }
        }

        let Some(tip) = store.get_canonical_tip()? else {
            continue;
        };

        // Compare local tip hash with RPC
        let remote_hash = match client.get_block_hash(tip.block_number).await {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "[ReorgMonitor] Failed to get remote hash, retrying");
                continue;
            }
        };

        if remote_hash == tip.block_hash {
            continue; // chain is consistent
        }

        warn!(
            block_number = tip.block_number,
            local_hash = %tip.block_hash,
            remote_hash = %remote_hash,
            "[ReorgMonitor] Hash mismatch detected, resolving reorg"
        );

        let rollback_to = find_divergence_point(
            &client,
            &|n| store.get_block_hash(n),
            &|| store.get_earliest_block(),
            tip.block_number,
        )
        .await?;

        let depth = tip.block_number.saturating_sub(rollback_to);
        warn!(rollback_to, depth, "[ReorgMonitor] Rolling back chain");

        store.rollback_chain(rollback_to)?;

        return Ok(ReorgEvent { rollback_to, depth });
    }
}

/// Continuously fetches blocks from RPC and sends them through a channel.
///
/// Generic over the output type `T` — the `transform` function converts raw RPC
/// data `(Block, SaltWitness, MptWitness)` into whatever the consumer needs.
/// Backpressure is provided by the bounded channel.
///
/// On RPC error, retries with exponential backoff. On channel closure or shutdown, returns.
pub async fn block_fetcher<T: Send + 'static, F, G>(
    client: Arc<RpcClient>,
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

/// Collects validation results and advances the canonical chain in block-number order.
///
/// Receives results from workers (potentially out of order), buffers them,
/// and advances the canonical tip in strict sequence. Batches multiple consecutive
/// blocks into a single persistence write.
///
/// The optional `on_advance` callback is invoked after each batch of blocks is
/// persisted, receiving the new tip block number. Use this to update metrics or
/// notify external systems.
///
/// If any validation fails, returns `Err` immediately (process should exit).
pub async fn chain_advancer<F>(
    rx: kanal::Receiver<std::result::Result<ValidatedBlock, ValidationFailure>>,
    store: Arc<dyn ChainStore>,
    initial_tip: BlockMeta,
    shutdown: CancellationToken,
    on_advance: Option<F>,
) -> Result<()>
where
    F: Fn(u64) + Send + Sync,
{
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
        let mut new_blocks = Vec::new();
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

            current_tip = BlockMeta {
                block_number: validated.block_number,
                block_hash: validated.block_hash,
                post_state_root: validated.post_state_root,
                post_withdrawals_root: validated.post_withdrawals_root,
            };
            new_blocks.push(current_tip.clone());
            next_expected += 1;
        }

        // Batch-persist new blocks and update tip
        if !new_blocks.is_empty() {
            let advanced = new_blocks.len();
            store.advance_chain(&new_blocks)?;
            if let Some(ref callback) = on_advance {
                callback(current_tip.block_number);
            }
            info!(
                tip = current_tip.block_number,
                advanced = advanced,
                buffered = buffer.len(),
                "[Advancer] Chain advanced"
            );
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::db::{
        BlockMeta, BlockStore, ChainStore, ContractStore, ValidatedBlock, ValidationFailure,
    };

    // -----------------------------------------------------------------------
    // In-memory mock ChainStore for testing pipeline logic without redb
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockChainStoreInner {
        chain: BTreeMap<u64, BlockMeta>,
        anchor: Option<BlockMeta>,
        blocks:
            Vec<(alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction>, crate::LightWitness)>,
    }

    struct MockChainStore {
        inner: Mutex<MockChainStoreInner>,
    }

    impl MockChainStore {
        fn with_anchor(anchor: BlockMeta) -> Self {
            let mut inner = MockChainStoreInner::default();
            inner.chain.insert(anchor.block_number, anchor.clone());
            inner.anchor = Some(anchor);
            Self { inner: Mutex::new(inner) }
        }

        fn tip(&self) -> Option<BlockMeta> {
            let inner = self.inner.lock().unwrap();
            inner.chain.values().last().cloned()
        }

        fn chain_len(&self) -> usize {
            self.inner.lock().unwrap().chain.len()
        }

        fn stored_blocks_count(&self) -> usize {
            self.inner.lock().unwrap().blocks.len()
        }
    }

    impl ContractStore for MockChainStore {
        fn get_contracts(
            &self,
            _hashes: &[B256],
        ) -> eyre::Result<(HashMap<B256, revm::state::Bytecode>, Vec<B256>)> {
            Ok((HashMap::new(), vec![]))
        }

        fn add_contracts(&self, _codes: &[(B256, revm::state::Bytecode)]) -> eyre::Result<()> {
            Ok(())
        }
    }

    impl ChainStore for MockChainStore {
        fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
            Ok(self.tip())
        }

        fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
            Ok(self.inner.lock().unwrap().anchor.clone())
        }

        fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            for block in blocks {
                inner.chain.insert(block.block_number, block.clone());
            }
            Ok(())
        }

        fn get_block_hash(&self, block_number: BlockNumber) -> eyre::Result<Option<BlockHash>> {
            Ok(self.inner.lock().unwrap().chain.get(&block_number).map(|b| b.block_hash))
        }

        fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .chain
                .values()
                .next()
                .map(|b| (b.block_number, b.block_hash)))
        }

        fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.chain.retain(|&n, _| n <= to_block);
            Ok(())
        }

        fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.chain.clear();
            inner.chain.insert(anchor.block_number, anchor.clone());
            inner.anchor = Some(anchor.clone());
            Ok(())
        }

        fn prune_chain(&self, before_block: BlockNumber) -> eyre::Result<u64> {
            let mut inner = self.inner.lock().unwrap();
            let before: Vec<u64> =
                inner.chain.keys().filter(|&&n| n < before_block).copied().collect();
            let count = before.len() as u64;
            for n in before {
                inner.chain.remove(&n);
            }
            Ok(count)
        }
    }

    impl BlockStore for MockChainStore {
        fn store_block_data(
            &self,
            blocks: &[(
                alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction>,
                crate::LightWitness,
            )],
        ) -> eyre::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            for b in blocks {
                inner.blocks.push(b.clone());
            }
            Ok(())
        }

        fn get_block_and_witness(
            &self,
            _block_hash: BlockHash,
        ) -> eyre::Result<(
            alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction>,
            crate::LightWitness,
        )> {
            Err(eyre::eyre!("not implemented in mock"))
        }
    }

    // -----------------------------------------------------------------------
    // Helper to build ValidatedBlock with state-root continuity
    // -----------------------------------------------------------------------

    fn make_validated_block(number: u64, pre_state: B256, pre_withdrawals: B256) -> ValidatedBlock {
        ValidatedBlock {
            block_number: number,
            block_hash: BlockHash::from([number as u8; 32]),
            post_state_root: B256::from([(number + 100) as u8; 32]),
            post_withdrawals_root: B256::from([(number + 200) as u8; 32]),
            pre_state_root: pre_state,
            pre_withdrawals_root: pre_withdrawals,
        }
    }

    fn make_initial_tip(number: u64) -> BlockMeta {
        BlockMeta {
            block_number: number,
            block_hash: BlockHash::from([number as u8; 32]),
            post_state_root: B256::from([(number + 100) as u8; 32]),
            post_withdrawals_root: B256::from([(number + 200) as u8; 32]),
        }
    }

    // -----------------------------------------------------------------------
    // chain_advancer tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_chain_advancer_sequential_delivery() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Send blocks 11, 12, 13 in order
        let block11 = make_validated_block(
            11,
            initial_tip.post_state_root,
            initial_tip.post_withdrawals_root,
        );
        let block12 =
            make_validated_block(12, block11.post_state_root, block11.post_withdrawals_root);
        let block13 =
            make_validated_block(13, block12.post_state_root, block12.post_withdrawals_root);

        tx.send(Ok(block11)).unwrap();
        tx.send(Ok(block12)).unwrap();
        tx.send(Ok(block13)).unwrap();

        // Close channel to let advancer finish
        drop(tx);
        handle.await.unwrap().unwrap();

        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 13);
    }

    #[tokio::test]
    async fn test_chain_advancer_out_of_order_delivery() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Build a chain: 11 -> 12 -> 13
        let block11 = make_validated_block(
            11,
            initial_tip.post_state_root,
            initial_tip.post_withdrawals_root,
        );
        let block12 =
            make_validated_block(12, block11.post_state_root, block11.post_withdrawals_root);
        let block13 =
            make_validated_block(13, block12.post_state_root, block12.post_withdrawals_root);

        // Send out of order: 13, 12, 11
        tx.send(Ok(block13)).unwrap();
        tx.send(Ok(block12)).unwrap();

        // After sending 13, 12 — neither should be advanced yet (missing 11)
        tokio::time::sleep(Duration::from_millis(50)).await;
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 10, "tip should still be 10 until block 11 arrives");

        // Now send 11 — all three should drain
        tx.send(Ok(block11)).unwrap();
        drop(tx);
        handle.await.unwrap().unwrap();

        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 13);
    }

    #[tokio::test]
    async fn test_chain_advancer_state_root_mismatch() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Send block 11 with wrong pre_state_root
        let bad_block = ValidatedBlock {
            block_number: 11,
            block_hash: BlockHash::from([11u8; 32]),
            post_state_root: B256::from([0xAAu8; 32]),
            post_withdrawals_root: B256::from([0xBBu8; 32]),
            pre_state_root: B256::from([0xFFu8; 32]), // wrong!
            pre_withdrawals_root: initial_tip.post_withdrawals_root,
        };

        tx.send(Ok(bad_block)).unwrap();
        drop(tx);

        let result = handle.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("pre_state_root mismatch"));
    }

    #[tokio::test]
    async fn test_chain_advancer_validation_failure_propagation() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Send a validation failure
        tx.send(Err(ValidationFailure {
            block_number: 11,
            block_hash: BlockHash::from([11u8; 32]),
            error: "execution reverted".to_string(),
        }))
        .unwrap();
        drop(tx);

        let result = handle.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("execution reverted"));
    }

    #[tokio::test]
    async fn test_chain_advancer_shutdown() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (_tx, rx) =
            kanal::bounded::<std::result::Result<ValidatedBlock, ValidationFailure>>(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip,
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Cancel shutdown — advancer should exit cleanly
        shutdown.cancel();
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // trace_chain_advancer tests
    // -----------------------------------------------------------------------

    /// Helper to create a minimal Block with the given number and hash.
    fn make_test_block(
        number: u64,
        hash: B256,
        state_root: B256,
        withdrawals_root: B256,
    ) -> alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction> {
        let mut header = alloy_rpc_types_eth::Header::<alloy_consensus::Header>::default();
        header.inner.number = number;
        header.hash = hash;
        header.inner.state_root = state_root;
        header.inner.withdrawals_root = Some(withdrawals_root);
        alloy_rpc_types_eth::Block { header, ..Default::default() }
    }

    /// Helper to create an empty LightWitness.
    fn empty_light_witness() -> crate::LightWitness {
        crate::LightWitness {
            kvs: std::collections::BTreeMap::new(),
            levels: rustc_hash::FxHashMap::default(),
        }
    }

    #[tokio::test]
    async fn test_trace_chain_advancer_new_blocks() {
        let anchor = BlockMeta {
            block_number: 10,
            block_hash: BlockHash::from([10u8; 32]),
            post_state_root: B256::from([110u8; 32]),
            post_withdrawals_root: B256::from([210u8; 32]),
        };
        let store = Arc::new(MockChainStore::with_anchor(anchor));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store) as Arc<dyn BlockStore>;
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(trace_chain_advancer::<fn(&[B256])>(
            store_clone,
            rx,
            None,
            shutdown_clone,
        ));

        let block = make_test_block(
            11,
            B256::from([11u8; 32]),
            B256::from([111u8; 32]),
            B256::from([211u8; 32]),
        );
        let witness = empty_light_witness();

        tx.send(ChainSyncEvent::NewBlocks(vec![(block, witness)])).unwrap();
        drop(tx);

        handle.await.unwrap().unwrap();

        // Chain should have advanced to block 11
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 11);
        assert_eq!(store.stored_blocks_count(), 1);
    }

    #[tokio::test]
    async fn test_trace_chain_advancer_reorg() {
        let anchor = BlockMeta {
            block_number: 5,
            block_hash: BlockHash::from([5u8; 32]),
            post_state_root: B256::from([105u8; 32]),
            post_withdrawals_root: B256::from([205u8; 32]),
        };
        let store = Arc::new(MockChainStore::with_anchor(anchor));

        // Advance chain to block 10
        let blocks: Vec<BlockMeta> = (6..=10)
            .map(|n| BlockMeta {
                block_number: n,
                block_hash: BlockHash::from([n as u8; 32]),
                post_state_root: B256::from([(n + 100) as u8; 32]),
                post_withdrawals_root: B256::from([(n + 200) as u8; 32]),
            })
            .collect();
        store.advance_chain(&blocks).unwrap();

        let shutdown = CancellationToken::new();
        let (tx, rx) = kanal::bounded(16);

        let reorged = Arc::new(Mutex::new(Vec::<B256>::new()));
        let reorged_clone = Arc::clone(&reorged);
        let on_reorg = move |hashes: &[B256]| {
            reorged_clone.lock().unwrap().extend_from_slice(hashes);
        };

        let store_clone = Arc::clone(&store) as Arc<dyn BlockStore>;
        let shutdown_clone = shutdown.clone();
        let handle =
            tokio::spawn(trace_chain_advancer(store_clone, rx, Some(on_reorg), shutdown_clone));

        // Send reorg event: rollback to block 7, reverting blocks 8, 9, 10
        let reverted_hashes: Vec<B256> = (8..=10).map(|n| B256::from([n as u8; 32])).collect();
        tx.send(ChainSyncEvent::Reorg { rollback_to: 7, reverted_hashes: reverted_hashes.clone() })
            .unwrap();
        drop(tx);

        handle.await.unwrap().unwrap();

        // Chain should be rolled back to block 7
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 7);

        // Callback should have been invoked with reverted hashes
        let reorged = reorged.lock().unwrap();
        assert_eq!(reorged.len(), 3);
    }

    #[tokio::test]
    async fn test_trace_chain_advancer_reset_anchor() {
        let anchor = BlockMeta {
            block_number: 5,
            block_hash: BlockHash::from([5u8; 32]),
            post_state_root: B256::from([105u8; 32]),
            post_withdrawals_root: B256::from([205u8; 32]),
        };
        let store = Arc::new(MockChainStore::with_anchor(anchor));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store) as Arc<dyn BlockStore>;
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(trace_chain_advancer::<fn(&[B256])>(
            store_clone,
            rx,
            None,
            shutdown_clone,
        ));

        // Send reset anchor event
        tx.send(ChainSyncEvent::ResetAnchor {
            block_number: 100,
            block_hash: B256::from([100u8; 32]),
            state_root: B256::from([200u8; 32]),
            withdrawals_root: B256::from([201u8; 32]),
        })
        .unwrap();
        drop(tx);

        handle.await.unwrap().unwrap();

        // Chain should be reset to the new anchor
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 100);
        assert_eq!(store.chain_len(), 1);
    }

    // -----------------------------------------------------------------------
    // ChainSyncConfig tests
    // -----------------------------------------------------------------------

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
