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
use alloy_rpc_types_eth::{Block, BlockId};
use eyre::{Result, anyhow};
use futures::future;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use tracing::{Instrument, debug, error, info, info_span, instrument, warn};

use crate::{RpcClient, ValidatorDB, withdrawals::MptWitness};

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
}

impl Default for ChainSyncConfig {
    fn default() -> Self {
        Self {
            concurrent_workers: num_cpus::get(),
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
}

/// Fetches a batch of blocks from RPC and stores them in the database.
///
/// This function encapsulates the core logic from remote_chain_tracker:
/// - Calculate gap between local tip and remote tip
/// - Stop if gap >= tracker_lookahead_blocks
/// - Fetch blocks in parallel with witness data
/// - Store in ValidatorDB via add_validation_tasks() and grow_remote_chain()
///
/// # Arguments
/// * `client` - RPC client for fetching blocks from remote blockchain
/// * `db` - Database interface for chain management
/// * `config` - Configuration for tracker behavior
/// * `block_error_counts` - Mutable map tracking error counts per block
///
/// # Returns
/// * `Ok(FetchResult)` - Result containing fetch statistics
/// * `Err(eyre::Error)` - On critical failures
#[instrument(skip_all, name = "chain_sync")]
pub async fn fetch_blocks_batch(
    client: &RpcClient,
    db: &ValidatorDB,
    config: &ChainSyncConfig,
    block_error_counts: &mut HashMap<u64, usize>,
) -> Result<FetchResult> {
    let batch_start = Instant::now();

    // Calculate how far behind our local chain is from remote
    let db_tip_start = Instant::now();
    let local_tip = db.get_local_tip()?.ok_or_else(|| anyhow!("Local chain is empty"))?;
    let remote_tip = db.get_remote_tip()?.unwrap_or(local_tip);
    let db_tip_elapsed = db_tip_start.elapsed();

    debug!(
        local_tip = local_tip.0,
        remote_tip = remote_tip.0,
        db_tip_ms = db_tip_elapsed.as_millis() as u64,
        "Got tips from DB"
    );

    // Check if local data is too stale (chain has moved far ahead)
    // This happens when service was stopped for a long time
    // Only applies in auto_advance mode (debug-trace-server) to avoid affecting stateless-validator
    if config.auto_advance_local_tip {
        let chain_latest = client.get_latest_block_number().await?;
        let stale_threshold = config.pruner_blocks_to_keep;
        if chain_latest > remote_tip.0 + stale_threshold {
            warn!(
                local_remote_tip = remote_tip.0,
                chain_latest = chain_latest,
                stale_threshold = stale_threshold,
                "Local data is too stale, resetting to latest block"
            );

            // Fetch latest block and reset anchor
            let latest_block = client.get_block(BlockId::latest(), false).await?;
            db.reset_anchor_block(
                latest_block.header.number,
                latest_block.header.hash,
                latest_block.header.state_root,
                latest_block.header.withdrawals_root.unwrap_or_default(),
            )?;

            info!(
                new_anchor = latest_block.header.number,
                block_hash = %latest_block.header.hash,
                "Reset to latest block due to stale data"
            );

            return Ok(FetchResult {
                blocks_fetched: 0,
                should_wait: false,
                had_error: false,
                reverted_hashes: Vec::new(),
            });
        }
    }

    let gap = remote_tip.0.saturating_sub(local_tip.0);

    // Detect and resolve chain reorgs
    match client.get_block(BlockId::Number(remote_tip.0.into()), false).await {
        Ok(block) if block.header.hash != remote_tip.1 => {
            warn!(
                block_number = remote_tip.0,
                expected_hash = %remote_tip.1,
                actual_hash = %block.header.hash,
                "Hash mismatch detected, resolving chain divergence"
            );

            match find_divergence_point(client, db, remote_tip.0).await {
                Ok(rollback_to) => {
                    let reorg_depth = remote_tip.0.saturating_sub(rollback_to);
                    warn!(
                        rollback_to = rollback_to,
                        reorg_depth = reorg_depth,
                        "Rolling back chain"
                    );

                    // Collect block hashes before rollback for cache invalidation
                    let mut reverted_hashes = Vec::with_capacity(reorg_depth as usize);
                    for block_num in (rollback_to + 1)..=remote_tip.0 {
                        if let Ok(Some(hash)) = db.get_block_hash(block_num) {
                            reverted_hashes.push(hash);
                        }
                    }

                    db.rollback_chain(rollback_to)?;
                    return Ok(FetchResult {
                        blocks_fetched: 0,
                        should_wait: false,
                        had_error: false,
                        reverted_hashes,
                    });
                }
                Err(e) => {
                    error!(error = %e, "Failed to find divergence point");
                    return Err(e);
                }
            }
        }
        Err(e) => {
            warn!(
                block_hash = %remote_tip.1,
                error = %e,
                "Network error validating tip"
            );
        }
        _ => {}
    }

    // In auto-advance mode, promote existing remote chain blocks to canonical chain first
    // This handles the case where we have pending blocks from a previous run
    if config.auto_advance_local_tip && gap > 0 {
        let promoted = gap.min(config.tracker_lookahead_blocks);
        for _ in 0..promoted {
            if !db.promote_remote_to_canonical()? {
                break;
            }
        }
        // Don't return early - continue to fetch more blocks
    }

    // Stop if we already have sufficient lookahead (only for validation mode)
    // In auto-advance mode, we always want to fetch more blocks
    if !config.auto_advance_local_tip && gap >= config.tracker_lookahead_blocks {
        return Ok(FetchResult {
            blocks_fetched: 0,
            should_wait: true,
            had_error: false,
            reverted_hashes: Vec::new(),
        });
    }

    // Calculate how many blocks to fetch (bounded by latest available)
    let latest_start = Instant::now();
    let chain_latest = client.get_latest_block_number().await?;
    let latest_elapsed = latest_start.elapsed();

    debug!(
        chain_latest = chain_latest,
        remote_tip = remote_tip.0,
        latest_fetch_ms = latest_elapsed.as_millis() as u64,
        "Got chain latest"
    );

    let blocks_to_fetch =
        (config.tracker_lookahead_blocks - gap).min(chain_latest.saturating_sub(remote_tip.0));

    if blocks_to_fetch == 0 {
        debug!(
            chain_latest = chain_latest,
            remote_tip = remote_tip.0,
            gap = gap,
            "No blocks to fetch - at chain tip"
        );
        return Ok(FetchResult {
            blocks_fetched: 0,
            should_wait: true,
            had_error: false,
            reverted_hashes: Vec::new(),
        });
    }

    let start_block = remote_tip.0 + 1;

    info!(
        start_block = start_block,
        end_block = start_block + blocks_to_fetch - 1,
        blocks_to_fetch = blocks_to_fetch,
        chain_latest = chain_latest,
        gap_behind = chain_latest.saturating_sub(start_block),
        "Starting block fetch batch"
    );

    // Fetch blocks in parallel
    let fetch_start = Instant::now();
    let tasks =
        future::join_all((start_block..start_block + blocks_to_fetch).map(|block_number| {
            let client = client.clone();
            async move {
                let block = client.get_block(BlockId::Number(block_number.into()), false).await?;
                let (salt_witness, mpt_witness) =
                    client.get_witness(block.header.number, block.header.hash).await?;
                let block = client.get_block(BlockId::Number(block_number.into()), true).await?;

                Ok::<(Block<Transaction>, SaltWitness, MptWitness), eyre::Error>((
                    block,
                    salt_witness,
                    mpt_witness,
                ))
            }
            .instrument(info_span!("fetch_block", block_number = block_number))
        }))
        .await
        .into_iter()
        .enumerate()
        // Stop on first error to maintain block sequence contiguity
        .take_while(|(i, result)| match result {
            Ok(_) => {
                block_error_counts.remove(&(start_block + *i as u64));
                true
            }
            Err(e) => {
                let block_number = start_block + *i as u64;
                let count = block_error_counts.entry(block_number).or_insert(0);
                *count += 1;

                // Only log errors after repeated failures (witness delay is expected)
                if *count > 5 {
                    error!(
                        block_number = block_number,
                        attempt = *count,
                        error = %e,
                        "Block fetch error (repeated)"
                    );
                }
                false
            }
        })
        .filter_map(|(_, result)| result.ok())
        .collect::<Vec<_>>();

    let fetched_count = tasks.len() as u64;
    let had_error = fetched_count < blocks_to_fetch;
    let fetch_elapsed = fetch_start.elapsed();

    info!(
        blocks_fetched = fetched_count,
        blocks_requested = blocks_to_fetch,
        fetch_ms = fetch_elapsed.as_millis() as u64,
        had_error = had_error,
        "Parallel fetch completed"
    );

    // Store block data and witnesses
    // In stateless-validator mode: add to validation task queue
    // In debug-trace-server mode: only store data for trace RPCs (no validation)
    let db_start = Instant::now();
    if config.auto_advance_local_tip {
        // Convert SaltWitness to LightWitness for efficient storage
        let light_tasks: Vec<_> = tasks
            .iter()
            .map(|(block, salt_witness, _)| {
                (block.clone(), crate::LightWitness::from(salt_witness.clone()))
            })
            .collect();
        db.store_block_data(&light_tasks)?;
    } else {
        db.add_validation_tasks(&tasks)?;
    }
    let add_tasks_elapsed = db_start.elapsed();

    let grow_chain_start = Instant::now();
    db.grow_remote_chain(tasks.iter().map(|(block, _, _)| &block.header))?;
    let grow_chain_elapsed = grow_chain_start.elapsed();

    info!(
        add_tasks_ms = add_tasks_elapsed.as_millis() as u64,
        grow_chain_ms = grow_chain_elapsed.as_millis() as u64,
        "DB operations completed"
    );

    // Auto-advance local tip if configured (for debug-trace-server mode)
    // This skips validation and trusts blocks from upstream RPC
    if config.auto_advance_local_tip && fetched_count > 0 {
        let new_local_tip = start_block + fetched_count - 1;
        let promote_start = Instant::now();
        for _ in 0..fetched_count {
            db.promote_remote_to_canonical()?;
        }
        let promote_elapsed = promote_start.elapsed();

        // Get the earliest block in DB for logging
        let earliest = db.get_earliest_local_block()?.map(|(n, _)| n).unwrap_or(0);

        // Calculate blocks per second using total batch time
        let total_elapsed = batch_start.elapsed();
        let total_ms = total_elapsed.as_millis() as f64;
        let blocks_per_sec =
            if total_ms > 0.0 { (fetched_count as f64 * 1000.0) / total_ms } else { 0.0 };

        info!(
            db_start = earliest,
            db_end = new_local_tip,
            synced_blocks = fetched_count,
            total_ms = total_ms as u64,
            fetch_ms = fetch_elapsed.as_millis() as u64,
            db_write_ms = (add_tasks_elapsed.as_millis() + grow_chain_elapsed.as_millis()) as u64,
            promote_ms = promote_elapsed.as_millis() as u64,
            blocks_per_sec = format!("{:.2}", blocks_per_sec),
            "Chain synced"
        );
    }

    Ok(FetchResult {
        blocks_fetched: fetched_count,
        should_wait: false,
        had_error,
        reverted_hashes: Vec::new(),
    })
}

/// Remote chain tracker that maintains a lookahead of unvalidated blocks.
///
/// Runs in an infinite loop, monitoring the gap between local canonical tip and remote
/// tip to maintain a sufficient buffer of unvalidated blocks for validation workers.
/// Infrastructure errors (RPC failures, network issues) are logged and contained.
///
/// # Arguments
/// * `client` - RPC client for fetching blocks from remote blockchain
/// * `validator_db` - Database interface for chain management
/// * `config` - Configuration for tracker behavior
/// * `on_reorg` - Optional callback invoked when a chain reorg is detected, receives reverted block
///   hashes
///
/// # Returns
/// * Never returns under normal operation - runs indefinitely until externally terminated
pub async fn remote_chain_tracker<F>(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
    on_reorg: Option<F>,
) -> Result<()>
where
    F: Fn(&[B256]) + Send + Sync,
{
    info!(lookahead_blocks = config.tracker_lookahead_blocks, "Starting remote chain tracker");

    // Track error counts for each block
    let mut block_error_counts: HashMap<u64, usize> = HashMap::new();

    loop {
        match fetch_blocks_batch(&client, &validator_db, &config, &mut block_error_counts).await {
            Ok(result) => {
                // Call reorg callback if a reorg occurred
                if !result.reverted_hashes.is_empty() &&
                    let Some(ref callback) = on_reorg
                {
                    callback(&result.reverted_hashes);
                }

                if result.had_error {
                    tokio::time::sleep(config.tracker_error_sleep).await;
                } else if result.should_wait || result.blocks_fetched == 0 {
                    tokio::time::sleep(config.tracker_poll_interval).await;
                }
            }
            Err(e) => {
                warn!(error = %e, "Sync iteration failed");
                tokio::time::sleep(config.tracker_error_sleep).await;
            }
        }
    }
}

/// Finds where the local chain diverges from the remote RPC node using exponential search.
///
/// Uses exponential search to efficiently locate where the local canonical chain diverges
/// from the remote chain. Exponential search is more efficient than binary search for reorgs
/// since they typically occur near the chain tip (non-uniform distribution).
/// The algorithm first exponentially expands backward to find a known-matching block,
/// then binary searches in that range.
#[instrument(skip(client, db), name = "find_divergence")]
async fn find_divergence_point(
    client: &RpcClient,
    db: &ValidatorDB,
    mismatch_block: u64,
) -> Result<u64> {
    let earliest_local = db.get_earliest_local_block()?.expect("Local chain cannot be empty");

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

    // Exponential search: find a matching block by exponentially increasing distance from tip
    let mut step = 1u64;
    let mut last_mismatch = mismatch_block;
    let mut search_start = earliest_local.0;

    while last_mismatch > earliest_local.0 {
        let check_block = last_mismatch.saturating_sub(step).max(earliest_local.0);
        let local_hash = db.get_block_hash(check_block)?.unwrap();
        let remote_hash = client.get_block_hash(check_block).await?;

        if remote_hash == local_hash {
            // Found a matching block, search between here and last_mismatch
            search_start = check_block;
            break;
        } else {
            // Keep expanding backwards
            last_mismatch = check_block;
            step *= 2;
        }
    }

    // Binary search between search_start and last_mismatch
    let (mut left, mut right, mut last_matching) = (search_start, last_mismatch, search_start);
    while left <= right {
        let mid = left + (right - left) / 2;
        let local_hash = db.get_block_hash(mid)?.unwrap();
        let remote_hash = client.get_block_hash(mid).await?;
        if remote_hash == local_hash {
            last_matching = mid;
            left = mid + 1;
        } else {
            right = mid.saturating_sub(1);
        }
    }

    debug!(
        divergence_point = last_matching,
        mismatch_block = mismatch_block,
        "Found divergence point"
    );

    Ok(last_matching)
}
