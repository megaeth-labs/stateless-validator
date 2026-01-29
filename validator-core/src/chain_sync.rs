//! Chain synchronization utilities for stateless validation.
//!
//! This module provides shared chain synchronization logic used by both
//! stateless-validator and debug-trace-server.

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy_rpc_types_eth::{Block, BlockId};
use eyre::{Result, anyhow};
use futures::future;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use tracing::{debug, error, warn};

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
    /// Number of blocks rolled back due to reorg (0 if no reorg).
    pub reorg_depth: u64,
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
/// * `validator_db` - Database interface for chain management
/// * `config` - Configuration for tracker behavior
/// * `block_error_counts` - Mutable map tracking error counts per block
///
/// # Returns
/// * `Ok(FetchResult)` - Result containing fetch statistics
/// * `Err(eyre::Error)` - On critical failures
pub async fn fetch_blocks_batch(
    client: &RpcClient,
    validator_db: &ValidatorDB,
    config: &ChainSyncConfig,
    block_error_counts: &mut HashMap<u64, usize>,
) -> Result<FetchResult> {
    // Calculate how far behind our local chain is from remote
    let local_tip = validator_db
        .get_local_tip()?
        .ok_or_else(|| anyhow!("Local chain is empty"))?;
    let remote_tip = validator_db.get_remote_tip()?.unwrap_or(local_tip);
    let gap = remote_tip.0.saturating_sub(local_tip.0);

    debug!(
        "[ChainSync] local={}, remote={}, gap={}",
        local_tip.0, remote_tip.0, gap
    );

    // Detect and resolve chain reorgs
    match client
        .get_block(BlockId::Number(remote_tip.0.into()), false)
        .await
    {
        Ok(block) if block.header.hash != remote_tip.1 => {
            warn!(
                "[ChainSync] Hash mismatch! Expected {}, got {}. Resolving chain divergence.",
                remote_tip.1, block.header.hash
            );
            match find_divergence_point(client, validator_db, remote_tip.0).await {
                Ok(rollback_to) => {
                    let reorg_depth = remote_tip.0.saturating_sub(rollback_to);
                    warn!(
                        "[ChainSync] Rolling back to block {rollback_to} (reorg depth: {reorg_depth})"
                    );
                    validator_db.rollback_chain(rollback_to)?;
                    return Ok(FetchResult {
                        blocks_fetched: 0,
                        should_wait: false,
                        had_error: false,
                        reorg_depth,
                    });
                }
                Err(e) => {
                    error!("[ChainSync] Failed to find divergence point: {e}");
                    return Err(e);
                }
            }
        }
        Err(e) => warn!(
            "[ChainSync] Network error validating tip {}: {}",
            remote_tip.1, e
        ),
        _ => {}
    }

    // Stop if we already have sufficient lookahead
    if gap >= config.tracker_lookahead_blocks {
        return Ok(FetchResult {
            blocks_fetched: 0,
            should_wait: true,
            had_error: false,
            reorg_depth: 0,
        });
    }

    // Calculate how many blocks to fetch (bounded by latest available)
    let blocks_to_fetch = (config.tracker_lookahead_blocks - gap).min(
        client
            .get_latest_block_number()
            .await?
            .saturating_sub(remote_tip.0),
    );

    if blocks_to_fetch == 0 {
        return Ok(FetchResult {
            blocks_fetched: 0,
            should_wait: true,
            had_error: false,
            reorg_depth: 0,
        });
    }

    debug!(
        "[ChainSync] Fetching {} blocks starting from {}",
        blocks_to_fetch,
        remote_tip.0 + 1
    );

    // Fetch blocks in parallel
    let tasks = future::join_all((remote_tip.0 + 1..remote_tip.0 + 1 + blocks_to_fetch).map(
        |block_number| {
            let client = client.clone();
            tokio::spawn(async move {
                let block = client
                    .get_block(BlockId::Number(block_number.into()), false)
                    .await?;
                let (salt_witness, mpt_witness) = client
                    .get_witness(block.header.number, block.header.hash)
                    .await?;
                let block = client
                    .get_block(BlockId::Number(block_number.into()), true)
                    .await?;

                Ok::<(Block<Transaction>, SaltWitness, MptWitness), eyre::Error>((
                    block,
                    salt_witness,
                    mpt_witness,
                ))
            })
        },
    ))
    .await
    .into_iter()
    .enumerate()
    // Stop on first error to maintain block sequence contiguity
    .take_while(|(i, result)| match result {
        Ok(Ok(_)) => {
            block_error_counts.remove(&(remote_tip.0 + 1 + *i as u64));
            true
        }
        Ok(Err(e)) => {
            let block_number = remote_tip.0 + 1 + *i as u64;
            let count = block_error_counts.entry(block_number).or_insert(0);
            *count += 1;

            if *count > 5 {
                error!(
                    "[ChainSync] DB or RPC error at block {block_number} (attempt {count}): {e}"
                );
            } else {
                debug!(
                    "[ChainSync] DB or RPC error at block {block_number} (attempt {count}): {e}"
                );
            }
            false
        }
        Err(e) => {
            error!(
                "[ChainSync] Task join error at block {}: {e}",
                remote_tip.0 + 1 + *i as u64
            );
            false
        }
    })
    .filter_map(|(_, result)| result.ok().and_then(|r| r.ok()))
    .collect::<Vec<_>>();

    let fetched_count = tasks.len() as u64;
    let had_error = fetched_count < blocks_to_fetch;

    // Add successfully fetched headers to remote chain
    validator_db.add_validation_tasks(&tasks)?;
    validator_db.grow_remote_chain(tasks.iter().map(|(block, _, _)| &block.header))?;

    Ok(FetchResult {
        blocks_fetched: fetched_count,
        should_wait: false,
        had_error,
        reorg_depth: 0,
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
/// * `on_reorg` - Optional callback invoked when a chain reorg is detected, receives reorg depth
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
    F: Fn(u64) + Send + Sync,
{
    tracing::info!(
        "[ChainSync] Starting remote chain tracker with {} block lookahead",
        config.tracker_lookahead_blocks
    );

    // Track error counts for each block
    let mut block_error_counts: HashMap<u64, usize> = HashMap::new();

    loop {
        match fetch_blocks_batch(&client, &validator_db, &config, &mut block_error_counts).await {
            Ok(result) => {
                // Call reorg callback if a reorg occurred
                if result.reorg_depth > 0
                    && let Some(ref callback) = on_reorg
                {
                    callback(result.reorg_depth);
                }

                if result.had_error {
                    tokio::time::sleep(config.tracker_error_sleep).await;
                } else if result.should_wait || result.blocks_fetched == 0 {
                    tokio::time::sleep(config.tracker_poll_interval).await;
                }
            }
            Err(e) => {
                warn!("[ChainSync] Iteration failed: {}", e);
                tokio::time::sleep(config.tracker_error_sleep).await;
            }
        }
    }
}

/// Finds where the local chain diverges from the remote RPC node using binary search.
///
/// Uses binary search to efficiently locate where the local canonical chain diverges
/// from the remote chain. The algorithm is guaranteed to terminate in O(log N) time
/// and return a block number between the earliest local block and `mismatch_block`.
async fn find_divergence_point(
    client: &RpcClient,
    validator_db: &ValidatorDB,
    mismatch_block: u64,
) -> Result<u64> {
    let earliest_local = validator_db
        .get_earliest_local_block()?
        .expect("Local chain cannot be empty");

    // Safety check: verify earliest block matches remote chain
    let earliest_remote = client
        .get_block(BlockId::Number(earliest_local.0.into()), false)
        .await?;
    if earliest_remote.header.hash != earliest_local.1 {
        panic!(
            "Catastrophic reorg: earliest local block {} hash mismatch (local: {:?}, remote: {:?})",
            earliest_local.0, earliest_local.1, earliest_remote.header.hash
        );
    }

    // Binary search for divergence point
    let (mut left, mut right, mut last_matching) =
        (earliest_local.0, mismatch_block, earliest_local.0);
    while left <= right {
        let mid = left + (right - left) / 2;
        let local_hash = validator_db.get_block_hash(mid)?.unwrap();
        let remote_hash = client
            .get_block(BlockId::Number(mid.into()), false)
            .await?
            .header
            .hash;
        if remote_hash == local_hash {
            last_matching = mid;
            left = mid + 1;
        } else {
            right = mid.saturating_sub(1);
        }
    }
    Ok(last_matching)
}
