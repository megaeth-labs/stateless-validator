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

use crate::{RpcClient, withdrawals::MptWitness};

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

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use alloy_primitives::{B256, BlockHash};

    use super::*;

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

    // -----------------------------------------------------------------------
    // find_divergence_point tests
    // -----------------------------------------------------------------------

    /// Starts a minimal mock RPC server that responds to `eth_getHeaderByNumber`
    /// with headers whose hash is derived from `remote_hashes`.
    async fn start_mock_rpc(
        remote_hashes: HashMap<u64, BlockHash>,
    ) -> (jsonrpsee::server::ServerHandle, String) {
        use jsonrpsee::{RpcModule, server::ServerBuilder};

        let mut module = RpcModule::new(remote_hashes);
        module
            .register_method("eth_getHeaderByNumber", |params, ctx, _| {
                let (hex_number,): (String,) = params.parse().unwrap();
                let block_number =
                    u64::from_str_radix(hex_number.strip_prefix("0x").unwrap_or(&hex_number), 16)
                        .unwrap();
                let hash = ctx.get(&block_number).copied().unwrap_or_default();
                Ok::<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>(serde_json::json!({
                    "hash": hash,
                    "number": format!("0x{block_number:x}"),
                    "parentHash": B256::ZERO,
                    "timestamp": "0x0",
                    "stateRoot": B256::ZERO,
                    "transactionsRoot": B256::ZERO,
                    "receiptsRoot": B256::ZERO,
                    "logsBloom": alloy_primitives::Bloom::ZERO,
                    "gasUsed": "0x0",
                    "gasLimit": "0x0",
                    "mixHash": B256::ZERO,
                    "nonce": "0x0000000000000000",
                    "extraData": "0x",
                    "difficulty": "0x0",
                    "sha3Uncles": B256::ZERO,
                    "miner": alloy_primitives::Address::ZERO,
                    "baseFeePerGas": "0x0"
                }))
            })
            .unwrap();

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        let handle = server.start(module);
        (handle, url)
    }

    /// Helper to create local and remote hash maps for divergence tests.
    /// Blocks `earliest..=diverge_at` have matching hashes, blocks
    /// `(diverge_at+1)..=tip` differ.
    fn make_divergence_chains(
        earliest: u64,
        tip: u64,
        diverge_at: u64,
    ) -> (HashMap<u64, BlockHash>, HashMap<u64, BlockHash>) {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        for n in earliest..=tip {
            if n <= diverge_at {
                // Matching hashes
                let hash = BlockHash::from([n as u8; 32]);
                local.insert(n, hash);
                remote.insert(n, hash);
            } else {
                // Divergent hashes
                local.insert(n, BlockHash::from([n as u8; 32]));
                remote.insert(n, BlockHash::from([(n + 128) as u8; 32]));
            }
        }
        (local, remote)
    }

    #[tokio::test]
    async fn test_find_divergence_single_block_reorg() {
        // Blocks 1..=10 match, block 10 is tip but remote disagrees on block 10
        let (local, remote) = make_divergence_chains(1, 10, 9);
        let (handle, url) = start_mock_rpc(remote).await;
        let client = crate::RpcClient::new(&url, &url).unwrap();

        let result = find_divergence_point(
            &client,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            10, // mismatch at tip
        )
        .await
        .unwrap();

        assert_eq!(result, 9);
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_find_divergence_multi_block_reorg() {
        // Blocks 1..=10, divergence at block 5 (blocks 6-10 differ)
        let (local, remote) = make_divergence_chains(1, 10, 5);
        let (handle, url) = start_mock_rpc(remote).await;
        let client = crate::RpcClient::new(&url, &url).unwrap();

        let result = find_divergence_point(
            &client,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            10,
        )
        .await
        .unwrap();

        assert_eq!(result, 5);
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_find_divergence_to_earliest() {
        // Blocks 5..=10, divergence right at earliest (block 5 matches, 6+ differ)
        let (local, remote) = make_divergence_chains(5, 10, 5);
        let (handle, url) = start_mock_rpc(remote).await;
        let client = crate::RpcClient::new(&url, &url).unwrap();

        let result = find_divergence_point(
            &client,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((5, *local.get(&5).unwrap()))),
            10,
        )
        .await
        .unwrap();

        assert_eq!(result, 5);
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_find_divergence_catastrophic_reorg() {
        // Even the earliest block differs — should return error
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        for n in 1..=5 {
            local.insert(n, BlockHash::from([n as u8; 32]));
            remote.insert(n, BlockHash::from([(n + 128) as u8; 32]));
        }

        let (handle, url) = start_mock_rpc(remote).await;
        let client = crate::RpcClient::new(&url, &url).unwrap();

        let result = find_divergence_point(
            &client,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            5,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Catastrophic reorg"));
        handle.stop().unwrap();
    }

    // -----------------------------------------------------------------------
    // block_fetcher tests
    // -----------------------------------------------------------------------

    /// Starts a mock RPC that serves `eth_blockNumber` (with configurable latest).
    async fn start_block_number_rpc(latest: u64) -> (jsonrpsee::server::ServerHandle, String) {
        use jsonrpsee::{RpcModule, server::ServerBuilder};

        let mut module = RpcModule::new(latest);
        module
            .register_method("eth_blockNumber", |_params, ctx, _| {
                Ok::<String, jsonrpsee::types::ErrorObjectOwned>(format!("0x{:x}", *ctx))
            })
            .unwrap();

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        let handle = server.start(module);
        (handle, url)
    }

    #[tokio::test]
    async fn test_block_fetcher_sync_target_already_reached() {
        // sync_target=5, start_block=6 → fetcher should exit immediately
        let (handle, url) = start_block_number_rpc(100).await;
        let client = Arc::new(crate::RpcClient::new(&url, &url).unwrap());

        let (tx, _rx) = kanal::bounded::<u64>(16);
        let config =
            Arc::new(ChainSyncConfig { sync_target: Some(5), ..ChainSyncConfig::default() });
        let shutdown = CancellationToken::new();

        let result = block_fetcher(
            client,
            tx,
            6, // already past target
            config,
            shutdown,
            |_block, _salt, _mpt| unreachable!("should not fetch any blocks"),
            None::<fn(u64)>,
        )
        .await;

        assert!(result.is_ok());
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_block_fetcher_shutdown_immediate() {
        let (handle, url) = start_block_number_rpc(100).await;
        let client = Arc::new(crate::RpcClient::new(&url, &url).unwrap());

        let (tx, _rx) = kanal::bounded::<u64>(16);
        let config = Arc::new(ChainSyncConfig::default());
        let shutdown = CancellationToken::new();

        // Cancel before starting
        shutdown.cancel();

        let result = block_fetcher(
            client,
            tx,
            1,
            config,
            shutdown,
            |_block, _salt, _mpt| unreachable!("should not fetch any blocks"),
            None::<fn(u64)>,
        )
        .await;

        assert!(result.is_ok());
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_block_fetcher_invokes_on_remote_height() {
        // Remote reports latest=42, start_block=100 (ahead of chain) so fetcher
        // enters the "wait for new blocks" path. We cancel shutdown after it has
        // called eth_blockNumber and invoked the callback.
        let (handle, url) = start_block_number_rpc(42).await;
        let client = Arc::new(crate::RpcClient::new(&url, &url).unwrap());

        let (tx, _rx) = kanal::bounded::<u64>(16);
        let config = Arc::new(ChainSyncConfig {
            tracker_poll_interval: Duration::from_secs(60), // long sleep so shutdown fires first
            ..ChainSyncConfig::default()
        });
        let shutdown = CancellationToken::new();

        let remote_height = Arc::new(Mutex::new(0u64));
        let cb = {
            let h = Arc::clone(&remote_height);
            move |n: u64| {
                *h.lock().unwrap() = n;
            }
        };

        // Cancel after a short delay to let the fetcher call eth_blockNumber
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            shutdown_clone.cancel();
        });

        let result = block_fetcher(
            client,
            tx,
            100, // ahead of chain_latest(42) → enters wait loop → shutdown fires
            config,
            shutdown,
            |_block, _salt, _mpt| unreachable!(),
            Some(cb),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(*remote_height.lock().unwrap(), 42);
        handle.stop().unwrap();
    }
}
