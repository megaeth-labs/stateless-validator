//! Generic chain sync pipeline shared by both binaries.
//!
//! Provides:
//! - [`PipelineConfig`]: Configuration for pipeline behavior.
//! - [`block_fetcher`]: Generic RPC block fetcher.
//! - [`find_divergence_point`]: Finds where the local chain diverges from the remote.
//! - [`run_pipeline`]: Outer loop: fetch → process → advance, with reorg restart + stale detection.
//!
//! Binary-specific logic is plugged in via traits:
//! - [`BlockProcessor`]: Processing stage (validation or pass-through).
//! - [`PipelineHooks`]: Callbacks for advance/reorg/stale events.
//! - [`ProcessedBlock`]: Output of the processing stage.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::{Result, anyhow};
use futures::future;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, instrument, warn};

use crate::{ChainDataProvider, ChainStore, db::BlockMeta, withdrawals::MptWitness};

/// Configuration for the chain sync pipeline.
///
/// Contains only the fields used by the pipeline itself (within `stateless-core`).
/// Binary-specific settings (metrics, reporting, pruner) live in binary CLI args.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Number of parallel processing workers.
    pub concurrent_workers: usize,
    /// Optional block height to sync to; `None` for infinite sync.
    pub sync_target: Option<u64>,
    /// Time to wait between fetcher poll cycles when ahead of chain.
    pub poll_interval: Duration,
    /// Time to wait when pipeline encounters errors before restarting.
    pub error_restart_delay: Duration,

    // --- Channel / fetcher settings ---
    /// Channel capacity for the fetch→worker pipeline.
    pub fetch_channel_capacity: usize,
    /// Channel capacity for the worker→advancer pipeline.
    pub result_channel_capacity: usize,
    /// Number of blocks to fetch in parallel per batch.
    pub fetcher_batch_size: usize,
    /// Maximum RPC retry backoff for the fetcher.
    pub fetcher_max_backoff: Duration,

    // --- Stale detection ---
    /// If local tip falls behind remote by more than this, reset anchor.
    /// `None` = disabled (validator). `Some(N)` = enabled (trace server).
    pub stale_reset_threshold: Option<u64>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        let workers = num_cpus::get();
        Self {
            concurrent_workers: workers,
            sync_target: None,
            poll_interval: Duration::from_millis(100),
            error_restart_delay: Duration::from_secs(1),
            fetch_channel_capacity: 2 * workers,
            result_channel_capacity: 2 * workers,
            fetcher_batch_size: workers,
            fetcher_max_backoff: Duration::from_secs(30),
            stale_reset_threshold: None,
        }
    }
}

/// Outcome of a single pipeline cycle (returned by [`chain_advancer`]).
#[derive(Debug)]
pub enum PipelineOutcome {
    /// Clean shutdown (cancellation token fired or channel closed normally).
    Shutdown,
    /// Reorg detected — caller should rollback and restart.
    Reorg(ReorgEvent),
}

/// Details of a detected chain reorganization.
#[derive(Debug)]
pub struct ReorgEvent {
    /// Block number to roll back to (inclusive — this block stays).
    pub rollback_to: BlockNumber,
    /// Number of blocks being reverted.
    pub depth: u64,
    /// Hashes of blocks being reverted (for cache invalidation).
    pub reverted_hashes: Vec<BlockHash>,
}

/// A block that has been processed and is ready for chain advancement.
///
/// Both `ValidatedBlock` (validator) and pass-through types (trace server)
/// implement this trait.
pub trait ProcessedBlock: Send + 'static {
    /// Block number.
    fn block_number(&self) -> BlockNumber;
    /// Block hash.
    fn block_hash(&self) -> BlockHash;
    /// Parent block hash (used for reorg detection).
    fn parent_hash(&self) -> BlockHash;
    /// Convert to [`BlockMeta`] for chain persistence.
    fn to_block_meta(&self) -> BlockMeta;

    /// Optional continuity check against the previous chain tip.
    ///
    /// The validator overrides this to verify that `pre_state_root` matches
    /// the previous tip's `post_state_root`. Default: no-op.
    fn verify_continuity(&self, _previous_tip: &BlockMeta) -> Result<()> {
        Ok(())
    }
}

/// Processing stage of the pipeline.
///
/// For the validator: validates blocks with EVM execution.
/// For the trace server: passes through block metadata (no processing).
pub trait BlockProcessor: Send + Sync + 'static {
    /// Input type received from the fetcher (after transform).
    type Input: Send + 'static;
    /// Output type sent to the chain advancer.
    type Output: ProcessedBlock;
    /// Error type for processing failures.
    type Error: Display + Send + 'static;

    /// Process a single block.
    /// Called from N worker tasks in parallel.
    fn process(
        &self,
        input: Self::Input,
    ) -> impl Future<Output = std::result::Result<Self::Output, Self::Error>> + Send;

    /// Called after each task completes in a worker.
    /// Use this for per-worker metrics (e.g., task success/failure counters).
    /// Default: no-op.
    fn on_task_done(&self, _worker_id: usize, _success: bool) {}
}

/// Hooks for binary-specific behavior during chain advancement.
///
/// All methods have default no-op implementations.
pub trait PipelineHooks: Send + Sync + 'static {
    /// The processed block type (must match the processor's output).
    type Output: ProcessedBlock;

    /// Called with a batch of processed blocks *before* `advance_chain()`.
    ///
    /// Use this to persist additional data (e.g., `store_block_data` for trace server).
    fn pre_advance(&self, _items: &[Self::Output]) -> Result<()> {
        Ok(())
    }

    /// Called *after* `advance_chain()` with the new tip.
    fn post_advance(&self, _new_tip: &BlockMeta) -> Result<()> {
        Ok(())
    }

    /// Called when a reorg is detected, before rollback.
    fn on_reorg(
        &self,
        _rollback_to: BlockNumber,
        _depth: u64,
        _reverted_hashes: &[BlockHash],
    ) -> Result<()> {
        Ok(())
    }

    /// Called when stale data is detected and anchor is about to be reset.
    fn on_stale_reset(&self, _new_anchor: &BlockMeta) -> Result<()> {
        Ok(())
    }
}

/// Runs the full pipeline: fetch → process → advance.
///
/// Handles reorg restart and optional stale-data detection in the outer loop.
/// Returns when `shutdown` is cancelled, `sync_target` is reached, or a fatal error occurs.
#[allow(clippy::too_many_arguments)]
pub async fn run_pipeline<C, S, P, H, F, G>(
    client: Arc<C>,
    store: Arc<S>,
    processor: Arc<P>,
    hooks: Arc<H>,
    config: Arc<PipelineConfig>,
    shutdown: CancellationToken,
    transform: F,
    on_remote_height: Option<G>,
) -> Result<()>
where
    C: ChainDataProvider + 'static,
    S: ChainStore + 'static,
    P: BlockProcessor,
    H: PipelineHooks<Output = P::Output>,
    F: Fn(Block<Transaction>, SaltWitness, MptWitness) -> P::Input + Send + Sync + Clone + 'static,
    G: Fn(u64) + Send + Sync + Clone + 'static,
{
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }

        // Determine start block from current chain state
        let initial_tip = match store.get_canonical_tip()? {
            Some(tip) => tip,
            None => store.get_anchor()?.ok_or_else(|| anyhow!("No anchor or tip in database"))?,
        };
        let start_block = initial_tip.block_number + 1;

        info!(start_block, "[Pipeline] Starting cycle");

        // --- Stage 1: Fetch ---
        let (fetch_tx, fetch_rx) = kanal::bounded(config.fetch_channel_capacity);
        let fetcher_shutdown = CancellationToken::new();
        let fetcher_handle = tokio::spawn(block_fetcher(
            client.clone(),
            fetch_tx,
            start_block,
            config.clone(),
            fetcher_shutdown.clone(),
            transform.clone(),
            on_remote_height.clone(),
        ));

        // --- Stage 2: Process (N workers) ---
        let (result_tx, result_rx) = kanal::bounded(config.result_channel_capacity);
        let worker_handles =
            spawn_workers(processor.clone(), fetch_rx, result_tx, config.concurrent_workers);

        // --- Stage 3: Advance ---
        let outcome =
            chain_advancer(&*client, &*store, &*hooks, result_rx, initial_tip, shutdown.clone())
                .await;

        // --- Teardown ---
        fetcher_shutdown.cancel();
        await_handles(fetcher_handle, worker_handles).await;

        match outcome {
            Ok(PipelineOutcome::Shutdown) => {
                info!("[Pipeline] Shutting down");
                return Ok(());
            }

            Ok(PipelineOutcome::Reorg(event)) => {
                warn!(
                    rollback_to = event.rollback_to,
                    depth = event.depth,
                    "[Pipeline] Reorg detected, restarting"
                );
                hooks.on_reorg(event.rollback_to, event.depth, &event.reverted_hashes)?;
                store.rollback_chain(event.rollback_to)?;
                // Brief pause before restart
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                    _ = shutdown.cancelled() => return Ok(()),
                }
                continue;
            }

            Err(e) => {
                error!(error = %e, "[Pipeline] Cycle ended with error");

                // --- Stale detection (optional) ---
                if let Some(threshold) = config.stale_reset_threshold &&
                    let Ok(chain_latest) = client.get_latest_block_number().await &&
                    let Ok(Some(tip)) = store.get_canonical_tip() &&
                    chain_latest > tip.block_number + threshold
                {
                    warn!(
                        tip = tip.block_number,
                        chain_latest, threshold, "[Pipeline] Local data is stale, resetting anchor"
                    );
                    // Fetch latest block to get state roots
                    match client.get_block(BlockId::Number(BlockNumberOrTag::Latest), false).await {
                        Ok(block) => {
                            let new_anchor = BlockMeta {
                                block_number: block.header.number,
                                block_hash: block.header.hash,
                                post_state_root: block.header.state_root,
                                post_withdrawals_root: block
                                    .header
                                    .withdrawals_root
                                    .unwrap_or_default(),
                            };
                            hooks.on_stale_reset(&new_anchor)?;
                            store.reset_to_anchor(&new_anchor)?;
                            continue; // restart from new anchor
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "[Pipeline] Failed to fetch latest block for anchor reset"
                            );
                        }
                    }
                }

                // Wait before restarting
                tokio::select! {
                    _ = tokio::time::sleep(config.error_restart_delay) => {}
                    _ = shutdown.cancelled() => return Ok(()),
                }
                continue;
            }
        }
    }
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
    config: Arc<PipelineConfig>,
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
                _ = tokio::time::sleep(config.poll_interval) => {}
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

/// Receives processed blocks, reorders them, verifies parent-hash continuity,
/// and advances the canonical chain.
///
/// Returns [`PipelineOutcome::Reorg`] when a parent-hash mismatch is detected,
/// or [`PipelineOutcome::Shutdown`] on clean shutdown / channel closure.
async fn chain_advancer<C, S, H>(
    client: &C,
    store: &S,
    hooks: &H,
    result_rx: kanal::Receiver<std::result::Result<H::Output, String>>,
    initial_tip: BlockMeta,
    shutdown: CancellationToken,
) -> Result<PipelineOutcome>
where
    C: ChainDataProvider,
    S: ChainStore,
    H: PipelineHooks,
{
    let rx = result_rx.to_async();
    let mut next_expected = initial_tip.block_number + 1;
    let mut current_tip = initial_tip;
    let mut buffer: BTreeMap<u64, H::Output> = BTreeMap::new();

    loop {
        // Receive next result (or shutdown)
        let item = tokio::select! {
            r = rx.recv() => match r {
                Ok(Ok(item)) => item,
                Ok(Err(e)) => {
                    return Err(anyhow!("Block processing failed: {e}"));
                }
                Err(_) => {
                    // Channel closed — fetcher finished (sync target reached or error)
                    return Ok(PipelineOutcome::Shutdown);
                }
            },
            _ = shutdown.cancelled() => return Ok(PipelineOutcome::Shutdown),
        };

        buffer.insert(item.block_number(), item);

        // Drain consecutive blocks from buffer
        let mut batch = Vec::new();
        while let Some(item) = buffer.remove(&next_expected) {
            // Verify parent hash continuity
            if item.parent_hash() != current_tip.block_hash {
                debug!(
                    block = next_expected,
                    expected_parent = ?current_tip.block_hash,
                    actual_parent = ?item.parent_hash(),
                    "[Advancer] Parent hash mismatch — reorg detected"
                );

                let rollback_to = find_divergence_point(
                    client,
                    &|n| store.get_block_hash(n),
                    &|| store.get_earliest_block(),
                    current_tip.block_number,
                )
                .await?;

                let depth = current_tip.block_number.saturating_sub(rollback_to);

                // Collect reverted block hashes for hooks
                let mut reverted_hashes = Vec::new();
                for n in (rollback_to + 1)..=current_tip.block_number {
                    if let Ok(Some(hash)) = store.get_block_hash(n) {
                        reverted_hashes.push(hash);
                    }
                }

                return Ok(PipelineOutcome::Reorg(ReorgEvent {
                    rollback_to,
                    depth,
                    reverted_hashes,
                }));
            }

            // Optional continuity check (validator checks state roots)
            item.verify_continuity(&current_tip)?;

            // Update tip tracking
            current_tip = item.to_block_meta();
            next_expected += 1;
            batch.push(item);
        }

        if !batch.is_empty() {
            // Pre-advance hook (e.g., store_block_data for trace server)
            hooks.pre_advance(&batch)?;

            // Persist chain advancement
            let metas: Vec<BlockMeta> = batch.iter().map(|b| b.to_block_meta()).collect();
            store.advance_chain(&metas)?;

            debug!(
                tip = current_tip.block_number,
                advanced = metas.len(),
                buffered = buffer.len(),
                "[Advancer] Chain advanced"
            );

            // Post-advance hook (e.g., update metrics)
            hooks.post_advance(&current_tip)?;
        }
    }
}

/// Spawns N worker tasks that consume from `fetch_rx`, process via `processor`,
/// and send results to `result_tx`.
fn spawn_workers<P: BlockProcessor>(
    processor: Arc<P>,
    fetch_rx: kanal::Receiver<P::Input>,
    result_tx: kanal::Sender<std::result::Result<P::Output, String>>,
    count: usize,
) -> Vec<JoinHandle<()>> {
    (0..count)
        .map(|worker_id| {
            let processor = processor.clone();
            let fetch_rx = fetch_rx.clone();
            let result_tx = result_tx.clone();
            tokio::spawn(async move {
                let fetch_rx = fetch_rx.to_async();
                let result_tx = result_tx.to_async();
                loop {
                    let input = match fetch_rx.recv().await {
                        Ok(input) => input,
                        Err(_) => {
                            debug!(worker_id, "[Worker] Fetch channel closed, stopping");
                            return;
                        }
                    };

                    let result = match processor.process(input).await {
                        Ok(output) => {
                            processor.on_task_done(worker_id, true);
                            Ok(output)
                        }
                        Err(e) => {
                            processor.on_task_done(worker_id, false);
                            Err(e.to_string())
                        }
                    };

                    if result_tx.send(result).await.is_err() {
                        debug!(worker_id, "[Worker] Result channel closed, stopping");
                        return;
                    }
                }
            })
        })
        .collect()
}

/// Waits for the fetcher and all workers to finish (with timeout).
async fn await_handles(fetcher: JoinHandle<Result<()>>, workers: Vec<JoinHandle<()>>) {
    let timeout = Duration::from_secs(3);

    tokio::select! {
        _ = async {
            if let Err(e) = fetcher.await {
                warn!(error = %e, "[Pipeline] Fetcher task panicked");
            }
            for handle in workers {
                if let Err(e) = handle.await {
                    warn!(error = %e, "[Pipeline] Worker task panicked");
                }
            }
        } => {}
        _ = tokio::time::sleep(timeout) => {
            warn!("[Pipeline] Timed out waiting for background tasks");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy_primitives::B256;

    use super::*;

    // PipelineConfig tests
    #[test]
    fn test_pipeline_config_default_uses_cpu_count() {
        let config = PipelineConfig::default();
        let cpus = num_cpus::get();
        assert_eq!(config.concurrent_workers, cpus);
        assert_eq!(config.fetch_channel_capacity, 2 * cpus);
        assert_eq!(config.result_channel_capacity, 2 * cpus);
        assert_eq!(config.fetcher_batch_size, cpus);
    }

    #[test]
    fn test_pipeline_config_default_stale_disabled() {
        assert!(PipelineConfig::default().stale_reset_threshold.is_none());
    }

    // Mock types for chain_advancer / find_divergence tests
    /// Simple processed block for tests.
    #[derive(Clone, Debug)]
    struct MockBlock {
        number: u64,
        hash: BlockHash,
        parent: BlockHash,
        state_root: B256,
    }

    impl ProcessedBlock for MockBlock {
        fn block_number(&self) -> BlockNumber {
            self.number
        }
        fn block_hash(&self) -> BlockHash {
            self.hash
        }
        fn parent_hash(&self) -> BlockHash {
            self.parent
        }
        fn to_block_meta(&self) -> BlockMeta {
            BlockMeta {
                block_number: self.number,
                block_hash: self.hash,
                post_state_root: self.state_root,
                post_withdrawals_root: B256::ZERO,
            }
        }
    }

    /// No-op hooks.
    struct NoopHooks;
    impl PipelineHooks for NoopHooks {
        type Output = MockBlock;
    }

    /// Mock ChainStore backed by a BTreeMap.
    struct MockStore {
        chain: std::sync::Mutex<BTreeMap<u64, BlockMeta>>,
        anchor: BlockMeta,
    }

    impl MockStore {
        fn new(anchor: BlockMeta) -> Self {
            let mut chain = BTreeMap::new();
            chain.insert(anchor.block_number, anchor.clone());
            Self { chain: std::sync::Mutex::new(chain), anchor }
        }
    }

    impl crate::ContractStore for MockStore {
        fn get_contracts(
            &self,
            _: &[B256],
        ) -> eyre::Result<(HashMap<B256, revm::state::Bytecode>, Vec<B256>)> {
            Ok((HashMap::new(), vec![]))
        }
        fn add_contracts(&self, _: &[(B256, revm::state::Bytecode)]) -> eyre::Result<()> {
            Ok(())
        }
    }

    impl crate::ChainStore for MockStore {
        fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
            Ok(self.chain.lock().unwrap().values().next_back().cloned())
        }
        fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
            Ok(Some(self.anchor.clone()))
        }
        fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()> {
            let mut chain = self.chain.lock().unwrap();
            for b in blocks {
                chain.insert(b.block_number, b.clone());
            }
            Ok(())
        }
        fn get_block_hash(&self, n: BlockNumber) -> eyre::Result<Option<BlockHash>> {
            Ok(self.chain.lock().unwrap().get(&n).map(|m| m.block_hash))
        }
        fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
            Ok(self.chain.lock().unwrap().first_key_value().map(|(&n, m)| (n, m.block_hash)))
        }
        fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()> {
            self.chain.lock().unwrap().retain(|&n, _| n <= to_block);
            Ok(())
        }
        fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
            let mut chain = self.chain.lock().unwrap();
            chain.clear();
            chain.insert(anchor.block_number, anchor.clone());
            Ok(())
        }
    }

    /// Mock ChainDataProvider backed by a HashMap of block hashes.
    struct MockRpc {
        hashes: HashMap<u64, BlockHash>,
    }

    impl ChainDataProvider for MockRpc {
        async fn get_latest_block_number(&self) -> Result<u64> {
            Ok(*self.hashes.keys().max().unwrap_or(&0))
        }
        async fn get_block_hash(&self, n: u64) -> Result<B256> {
            self.hashes.get(&n).copied().ok_or_else(|| anyhow!("Block {n} not found"))
        }
        async fn get_witness(&self, _: u64, _: B256) -> Result<(SaltWitness, MptWitness)> {
            unimplemented!()
        }
        async fn get_block(&self, _: BlockId, _: bool) -> Result<Block<Transaction>> {
            unimplemented!()
        }
    }

    fn make_hash(n: u64) -> BlockHash {
        BlockHash::from([n as u8; 32])
    }

    fn make_block(number: u64, parent: BlockHash) -> MockBlock {
        MockBlock {
            number,
            hash: make_hash(number),
            parent,
            state_root: B256::from([number as u8 + 1; 32]),
        }
    }

    fn make_tip(n: u64) -> BlockMeta {
        BlockMeta {
            block_number: n,
            block_hash: make_hash(n),
            post_state_root: B256::from([n as u8 + 1; 32]),
            post_withdrawals_root: B256::ZERO,
        }
    }

    // chain_advancer tests

    /// Helper: sends blocks then drops sender, calls chain_advancer directly.
    async fn run_advancer(
        tip: BlockMeta,
        rpc_hashes: HashMap<u64, BlockHash>,
        blocks: Vec<std::result::Result<MockBlock, String>>,
    ) -> (Result<PipelineOutcome>, MockStore) {
        let store = MockStore::new(tip.clone());
        let rpc = MockRpc { hashes: rpc_hashes };
        let hooks = NoopHooks;
        let (tx, rx) = kanal::bounded(16);

        // Pre-fill channel
        {
            let tx_async = tx.to_async();
            for b in blocks {
                tx_async.send(b).await.unwrap();
            }
        }

        let result = chain_advancer(&rpc, &store, &hooks, rx, tip, CancellationToken::new()).await;
        (result, store)
    }

    #[tokio::test]
    async fn test_chain_advancer_sequential() {
        let tip = make_tip(10);
        let blocks = vec![
            Ok(make_block(11, make_hash(10))),
            Ok(make_block(12, make_hash(11))),
            Ok(make_block(13, make_hash(12))),
        ];
        let (result, store) = run_advancer(tip, HashMap::new(), blocks).await;
        assert!(matches!(result.unwrap(), PipelineOutcome::Shutdown));
        assert_eq!(store.get_canonical_tip().unwrap().unwrap().block_number, 13);
    }

    #[tokio::test]
    async fn test_chain_advancer_out_of_order() {
        let tip = make_tip(10);
        // Send out of order: 13, 12, 11
        let blocks = vec![
            Ok(make_block(13, make_hash(12))),
            Ok(make_block(12, make_hash(11))),
            Ok(make_block(11, make_hash(10))),
        ];
        let (result, store) = run_advancer(tip, HashMap::new(), blocks).await;
        assert!(matches!(result.unwrap(), PipelineOutcome::Shutdown));
        assert_eq!(store.get_canonical_tip().unwrap().unwrap().block_number, 13);
    }

    #[tokio::test]
    async fn test_chain_advancer_processing_error() {
        let tip = make_tip(10);
        let blocks = vec![Err("validation failed".to_string())];
        let (result, _) = run_advancer(tip, HashMap::new(), blocks).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("validation failed"));
    }

    #[tokio::test]
    async fn test_chain_advancer_shutdown() {
        let tip = make_tip(10);
        let store = MockStore::new(tip.clone());
        let rpc = MockRpc { hashes: HashMap::new() };
        let hooks = NoopHooks;
        let (_tx, rx) = kanal::bounded::<std::result::Result<MockBlock, String>>(16);
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let outcome = chain_advancer(&rpc, &store, &hooks, rx, tip, shutdown).await.unwrap();
        assert!(matches!(outcome, PipelineOutcome::Shutdown));
    }

    #[tokio::test]
    async fn test_chain_advancer_reorg_detected() {
        let tip = make_tip(10);
        let mut rpc_hashes = HashMap::new();
        rpc_hashes.insert(10, make_hash(10)); // RPC agrees on block 10

        let bad_block = MockBlock {
            number: 11,
            hash: make_hash(11),
            parent: BlockHash::from([0xFF; 32]), // doesn't match tip
            state_root: B256::ZERO,
        };
        let (result, _) = run_advancer(tip, rpc_hashes, vec![Ok(bad_block)]).await;
        match result.unwrap() {
            PipelineOutcome::Reorg(event) => assert_eq!(event.rollback_to, 10),
            other => panic!("Expected Reorg, got {other:?}"),
        }
    }

    // find_divergence_point tests

    #[tokio::test]
    async fn test_find_divergence_single_block_reorg() {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        // Blocks 1..=9 match, block 10 differs
        for n in 1..=10 {
            local.insert(n, make_hash(n));
            if n <= 9 {
                remote.insert(n, make_hash(n));
            } else {
                remote.insert(n, BlockHash::from([0xFF; 32]));
            }
        }

        let rpc = MockRpc { hashes: remote };
        let result = find_divergence_point(
            &rpc,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            10,
        )
        .await
        .unwrap();

        assert_eq!(result, 9);
    }

    #[tokio::test]
    async fn test_find_divergence_multi_block_reorg() {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        for n in 1..=10 {
            if n <= 5 {
                let hash = make_hash(n);
                local.insert(n, hash);
                remote.insert(n, hash);
            } else {
                local.insert(n, make_hash(n));
                remote.insert(n, BlockHash::from([(n + 128) as u8; 32]));
            }
        }

        let rpc = MockRpc { hashes: remote };
        let result = find_divergence_point(
            &rpc,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            10,
        )
        .await
        .unwrap();

        assert_eq!(result, 5);
    }

    #[tokio::test]
    async fn test_find_divergence_catastrophic() {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        for n in 1..=5 {
            local.insert(n, make_hash(n));
            remote.insert(n, BlockHash::from([(n + 128) as u8; 32]));
        }

        let rpc = MockRpc { hashes: remote };
        let result = find_divergence_point(
            &rpc,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            5,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Catastrophic reorg"));
    }

    // spawn_workers tests

    struct DoubleProcessor;
    impl BlockProcessor for DoubleProcessor {
        type Input = u64;
        type Output = MockBlock;
        type Error = String;

        async fn process(&self, input: u64) -> std::result::Result<MockBlock, String> {
            Ok(MockBlock {
                number: input,
                hash: make_hash(input),
                parent: make_hash(input - 1),
                state_root: B256::ZERO,
            })
        }
    }

    #[tokio::test]
    async fn test_spawn_workers_processes_all() {
        let processor = Arc::new(DoubleProcessor);
        let (fetch_tx, fetch_rx) = kanal::bounded::<u64>(16);
        let (result_tx, result_rx) = kanal::bounded(16);

        let handles = spawn_workers(processor, fetch_rx, result_tx, 2);

        let fetch_tx = fetch_tx.to_async();
        for i in 1..=5 {
            fetch_tx.send(i).await.unwrap();
        }
        drop(fetch_tx);

        // Collect results
        let result_rx = result_rx.to_async();
        let mut results = Vec::new();
        while let Ok(r) = result_rx.recv().await {
            results.push(r.unwrap().number);
        }

        results.sort();
        assert_eq!(results, vec![1, 2, 3, 4, 5]);

        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_spawn_workers_propagates_error() {
        struct FailProcessor;
        impl BlockProcessor for FailProcessor {
            type Input = u64;
            type Output = MockBlock;
            type Error = String;

            async fn process(&self, _: u64) -> std::result::Result<MockBlock, String> {
                Err("boom".to_string())
            }
        }

        let processor = Arc::new(FailProcessor);
        let (fetch_tx, fetch_rx) = kanal::bounded::<u64>(16);
        let (result_tx, result_rx) = kanal::bounded(16);

        let _handles = spawn_workers(processor, fetch_rx, result_tx, 1);

        let fetch_tx = fetch_tx.to_async();
        fetch_tx.send(1).await.unwrap();
        drop(fetch_tx);

        let result_rx = result_rx.to_async();
        let result = result_rx.recv().await.unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "boom");
    }
}
