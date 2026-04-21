//! Generic chain sync pipeline.
//!
//! Three-stage pipeline: fetch → process → advance, with automatic reorg restart
//! and optional stale-data detection.
//!
//! ## Traits
//!
//! - [`BlockFetcher`]: Pluggable data source (replaces hardcoded RPC sequence).
//! - [`BlockProcessor`]: Processing stage (validation or pass-through).
//! - [`PipelineHooks`]: Callbacks for advance/reorg/stale events.
//! - [`ProcessedBlock`]: Output of the processing stage.
//!
//! ## Entry Point
//!
//! [`run_pipeline`] orchestrates the full lifecycle.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Display,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{BlockHash, BlockNumber};
use eyre::{Result, anyhow};
use tokio::task::{Id, JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, instrument, warn};

use crate::{ChainStore, db::BlockMeta};

/// Configuration for the chain sync pipeline.
///
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
    /// Channel capacity for the fetch→worker pipeline.
    pub fetch_channel_capacity: usize,
    /// Channel capacity for the worker→advancer pipeline.
    pub result_channel_capacity: usize,
    /// Maximum number of in-flight block fetches.
    pub fetcher_max_in_flight: usize,
    /// Maximum RPC retry backoff for the fetcher.
    pub fetcher_max_backoff: Duration,
    /// If local tip falls behind remote by more than this, reset anchor.
    /// `None` = disabled (validator). `Some(N)` = enabled (trace server).
    pub stale_reset_threshold: Option<u64>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        // Physical cores: workers are CPU-bound (EVM + IPA), hyperthreads don't help.
        let workers = num_cpus::get_physical();
        Self {
            concurrent_workers: workers,
            sync_target: None,
            poll_interval: Duration::from_millis(100),
            error_restart_delay: Duration::from_secs(1),
            fetch_channel_capacity: 2 * workers,
            result_channel_capacity: 2 * workers,
            fetcher_max_in_flight: workers,
            fetcher_max_backoff: Duration::from_secs(30),
            stale_reset_threshold: None,
        }
    }
}

/// Outcome of a single pipeline cycle.
#[derive(Debug)]
pub enum PipelineOutcome {
    /// Clean shutdown (cancellation token fired or channel closed).
    Shutdown,
    /// Reorg detected — caller should rollback and restart.
    Reorg(ReorgEvent),
    /// Deterministic failure (e.g., validation mismatch) — halt, no point retrying.
    Fatal(String),
}

/// Whether a processing error is worth retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorAction {
    /// Transient error (RPC timeout, network issue) — restart pipeline, retry later.
    Retry,
    /// Deterministic failure (validation mismatch) — halt immediately.
    Halt,
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

/// Pluggable data source for the pipeline.
///
/// Each binary provides its own implementation that decides *how* to fetch a block
/// (which RPC calls, what transformations, what metrics to record).
/// The pipeline only calls these four methods — it never touches network types directly.
pub trait BlockFetcher: Send + Sync + 'static {
    /// Data produced per block, fed into [`BlockProcessor::process`].
    type Output: Send + 'static;

    /// Fetch a complete block at the given number.
    fn fetch(&self, block_number: u64) -> impl Future<Output = Result<Self::Output>> + Send;

    /// Current chain tip height (used by the fetcher poll loop).
    fn latest_block_number(&self) -> impl Future<Output = Result<u64>> + Send;

    /// Hash for a given block number (used by [`find_divergence_point`]).
    fn block_hash(&self, block_number: u64) -> impl Future<Output = Result<BlockHash>> + Send;

    /// Metadata of the latest block (used by stale anchor reset).
    fn latest_block_meta(&self) -> impl Future<Output = Result<BlockMeta>> + Send;
}

/// Blanket implementation so `Arc<F>` also implements `BlockFetcher`.
impl<F: BlockFetcher> BlockFetcher for Arc<F> {
    type Output = F::Output;
    fn fetch(&self, block_number: u64) -> impl Future<Output = Result<Self::Output>> + Send {
        (**self).fetch(block_number)
    }
    fn latest_block_number(&self) -> impl Future<Output = Result<u64>> + Send {
        (**self).latest_block_number()
    }
    fn block_hash(&self, block_number: u64) -> impl Future<Output = Result<BlockHash>> + Send {
        (**self).block_hash(block_number)
    }
    fn latest_block_meta(&self) -> impl Future<Output = Result<BlockMeta>> + Send {
        (**self).latest_block_meta()
    }
}

/// A block that has been processed and is ready for chain advancement.
pub trait ProcessedBlock: Send + 'static {
    fn block_number(&self) -> BlockNumber;
    fn block_hash(&self) -> BlockHash;
    /// Parent block hash (used for reorg detection).
    fn parent_hash(&self) -> BlockHash;
    /// Convert to [`BlockMeta`] for chain persistence.
    fn to_block_meta(&self) -> BlockMeta;

    /// Optional continuity check against the previous chain tip.
    /// The validator overrides this to verify state root continuity. Default: no-op.
    fn verify_continuity(&self, _previous_tip: &BlockMeta) -> Result<()> {
        Ok(())
    }
}

/// Processing stage of the pipeline.
pub trait BlockProcessor: Send + Sync + 'static {
    /// Input type from the fetcher.
    type Input: Send + 'static;
    /// Output type sent to the chain advancer.
    type Output: ProcessedBlock;
    /// Error type for processing failures.
    type Error: Display + Send + 'static;

    /// Process a single block (called from N worker tasks in parallel).
    fn process(
        &self,
        input: Self::Input,
    ) -> impl Future<Output = std::result::Result<Self::Output, Self::Error>> + Send;

    /// Classify whether an error is transient (worth retrying) or fatal (should halt).
    /// Default: all errors are fatal (conservative — unknown errors don't silently loop).
    fn error_action(&self, _error: &Self::Error) -> ErrorAction {
        ErrorAction::Halt
    }

    /// Called after each task completes. Use for per-worker metrics. Default: no-op.
    fn on_task_done(&self, _worker_id: usize, _success: bool) {}
}

/// Hooks for binary-specific behavior during chain advancement.
/// All methods have default no-op implementations.
pub trait PipelineHooks: Send + Sync + 'static {
    type Output: ProcessedBlock;

    /// Called with a batch of processed blocks *before* `advance_chain()`.
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
pub async fn run_pipeline<F, S, P, H>(
    fetcher: Arc<F>,
    store: Arc<S>,
    processor: Arc<P>,
    hooks: Arc<H>,
    config: Arc<PipelineConfig>,
    shutdown: CancellationToken,
) -> Result<()>
where
    F: BlockFetcher<Output = P::Input>,
    S: ChainStore + 'static,
    P: BlockProcessor,
    H: PipelineHooks<Output = P::Output>,
{
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }

        let initial_tip = match store.get_canonical_tip()? {
            Some(tip) => tip,
            None => store.get_anchor()?.ok_or_else(|| anyhow!("No anchor or tip in database"))?,
        };
        let start_block = initial_tip.block_number + 1;
        info!(start_block, "[Pipeline] Starting cycle");

        // Stage 1: Fetch
        let (fetch_tx, fetch_rx) = kanal::bounded(config.fetch_channel_capacity);
        let fetcher_shutdown = CancellationToken::new();
        let fetcher_handle = tokio::spawn(block_fetcher(
            fetcher.clone(),
            fetch_tx,
            start_block,
            config.clone(),
            fetcher_shutdown.clone(),
        ));

        // Stage 2: Process (N workers)
        let (result_tx, result_rx) = kanal::bounded::<
            std::result::Result<P::Output, (String, ErrorAction)>,
        >(config.result_channel_capacity);
        let worker_handles =
            spawn_workers(processor.clone(), fetch_rx, result_tx, config.concurrent_workers);

        // Stage 3: Advance
        let outcome =
            chain_advancer(&*fetcher, &*store, &*hooks, result_rx, initial_tip, shutdown.clone())
                .await;

        // Teardown
        fetcher_shutdown.cancel();
        await_handles(fetcher_handle, worker_handles).await;

        match outcome {
            Ok(PipelineOutcome::Shutdown) => {
                info!("[Pipeline] Shutting down");
                return Ok(());
            }
            Ok(PipelineOutcome::Fatal(msg)) => {
                error!(error = %msg, "[Pipeline] Fatal error, halting");
                return Err(anyhow!("Pipeline halted: {msg}"));
            }
            Ok(PipelineOutcome::Reorg(event)) => {
                warn!(
                    rollback_to = event.rollback_to,
                    depth = event.depth,
                    "[Pipeline] Reorg detected, restarting"
                );
                hooks.on_reorg(event.rollback_to, event.depth, &event.reverted_hashes)?;
                store.rollback_chain(event.rollback_to)?;
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                    _ = shutdown.cancelled() => return Ok(()),
                }
                continue;
            }
            Err(e) => {
                error!(error = %e, "[Pipeline] Cycle ended with error");

                // Stale detection (optional)
                if let Some(threshold) = config.stale_reset_threshold &&
                    let Ok(chain_latest) = fetcher.latest_block_number().await &&
                    let Ok(Some(tip)) = store.get_canonical_tip() &&
                    chain_latest > tip.block_number + threshold
                {
                    warn!(
                        tip = tip.block_number,
                        chain_latest, threshold, "[Pipeline] Local data is stale, resetting anchor"
                    );
                    match fetcher.latest_block_meta().await {
                        Ok(new_anchor) => {
                            hooks.on_stale_reset(&new_anchor)?;
                            store.reset_to_anchor(&new_anchor)?;
                            continue;
                        }
                        Err(e) => {
                            warn!(error = %e, "[Pipeline] Failed to fetch latest block for anchor reset");
                        }
                    }
                }

                tokio::select! {
                    _ = tokio::time::sleep(config.error_restart_delay) => {}
                    _ = shutdown.cancelled() => return Ok(()),
                }
                continue;
            }
        }
    }
}

/// Invariant: every block in `[base_block, next_block)` is in exactly one of
/// `in_flight_blocks`, `sent`, or `failed`. All mutations go through the methods below.
struct FetcherState<F: BlockFetcher> {
    /// Lowest block not yet sent downstream.
    base_block: u64,
    /// Next block to spawn fresh.
    next_block: u64,
    tasks: JoinSet<(u64, Result<F::Output>)>,
    /// Task id → block, for panic recovery (`JoinError` only carries the id).
    task_to_block: HashMap<Id, u64>,
    /// Mirror of `task_to_block.values()` for O(1) block-in-flight lookup.
    in_flight_blocks: HashSet<u64>,
    /// Successful blocks, waiting for `base_block` to catch up.
    sent: HashSet<u64>,
    /// Blocks awaiting retry.
    failed: HashSet<u64>,
    /// Per-block attempt count for log escalation (near-tip blocks often fail a few times).
    error_counts: HashMap<u64, usize>,
}

impl<F: BlockFetcher> FetcherState<F> {
    fn new(start_block: u64) -> Self {
        Self {
            base_block: start_block,
            next_block: start_block,
            tasks: JoinSet::new(),
            task_to_block: HashMap::new(),
            in_flight_blocks: HashSet::new(),
            sent: HashSet::new(),
            failed: HashSet::new(),
            error_counts: HashMap::new(),
        }
    }

    fn in_flight_len(&self) -> usize {
        self.tasks.len()
    }

    fn window_exhausted(&self, tip: u64) -> bool {
        self.next_block > tip
    }

    /// Width of the outstanding fetch window — the memory bound for `sent` + in-flight + failed.
    fn window_width(&self) -> u64 {
        self.next_block - self.base_block
    }

    fn target_reached(&self, target: Option<u64>) -> bool {
        target.is_some_and(|t| self.base_block > t)
    }

    fn next_past_target(&self, target: Option<u64>) -> bool {
        target.is_some_and(|t| self.next_block > t)
    }

    fn spawn(&mut self, fetcher: &Arc<F>, bn: u64) {
        let fetcher = fetcher.clone();
        let span = info_span!("fetch_block", block_number = bn);
        let handle =
            self.tasks.spawn(async move { (bn, fetcher.fetch(bn).await) }.instrument(span));
        self.task_to_block.insert(handle.id(), bn);
        self.in_flight_blocks.insert(bn);
    }

    fn spawn_next(&mut self, fetcher: &Arc<F>) {
        let bn = self.next_block;
        self.spawn(fetcher, bn);
        self.next_block += 1;
    }

    fn pop_failed(&mut self) -> Option<u64> {
        let bn = *self.failed.iter().next()?;
        self.failed.remove(&bn);
        Some(bn)
    }

    fn on_success(&mut self, id: Id, bn: u64) {
        self.task_to_block.remove(&id);
        self.in_flight_blocks.remove(&bn);
        self.error_counts.remove(&bn);
        self.sent.insert(bn);
    }

    /// Returns the cumulative attempt count (for log escalation).
    fn on_failure(&mut self, id: Id, bn: u64) -> usize {
        self.task_to_block.remove(&id);
        self.in_flight_blocks.remove(&bn);
        self.failed.insert(bn);
        let count = self.error_counts.entry(bn).or_insert(0);
        *count += 1;
        *count
    }

    /// Re-enqueues the panicked task's block. Returns `None` if the id is unknown
    /// (shouldn't happen — would leak the block from `in_flight_blocks`).
    fn on_panic(&mut self, id: Id) -> Option<u64> {
        let bn = self.task_to_block.remove(&id)?;
        self.in_flight_blocks.remove(&bn);
        self.failed.insert(bn);
        Some(bn)
    }

    /// Drains the contiguous-sent prefix starting at `base_block`. In steady state this
    /// keeps `sent` around `max_in_flight`; if `base_block` stalls on a persistently-
    /// failing block, `sent` grows until the spawn-window cap (see `block_fetcher`) stops
    /// further enqueues.
    fn advance_base(&mut self) {
        while self.sent.remove(&self.base_block) {
            self.base_block += 1;
        }
    }

    /// Defense in depth: re-enqueue any block in `[base_block, next_block)` that slipped
    /// out of all three tracking sets. No-op under correct bookkeeping.
    fn recover_gaps(&mut self) {
        for bn in self.base_block..self.next_block {
            if !self.sent.contains(&bn) &&
                !self.in_flight_blocks.contains(&bn) &&
                !self.failed.contains(&bn)
            {
                self.failed.insert(bn);
            }
        }
    }
}

/// Cached chain tip with rate-limited refresh and failure backoff.
struct TipTracker {
    /// `None` forces a refresh (also keeps `start_block == 0` correct vs. a `0` sentinel).
    latest: Option<u64>,
    /// Rate-limits `latest_block_number()` calls (otherwise near-tip retries hammer
    /// `eth_blockNumber` at 10+ RPS).
    last_refresh: Instant,
    backoff: Duration,
}

impl TipTracker {
    fn new(poll_interval: Duration) -> Self {
        Self {
            latest: None,
            last_refresh: Instant::now() - poll_interval,
            backoff: Duration::from_secs(1),
        }
    }

    fn value(&self) -> Option<u64> {
        self.latest
    }

    fn refresh_due(&self, poll_interval: Duration) -> bool {
        self.last_refresh.elapsed() >= poll_interval
    }

    fn set(&mut self, value: u64) {
        self.latest = Some(value);
        self.last_refresh = Instant::now();
        self.backoff = Duration::from_secs(1);
    }

    fn backoff(&self) -> Duration {
        self.backoff
    }

    fn inflate_backoff(&mut self, max: Duration) {
        self.backoff = (self.backoff * 2).min(max);
    }
}

/// Continuously fetches blocks and streams them through a channel.
///
/// Spawns [`BlockFetcher::fetch`] calls onto a bounded [`JoinSet`] and forwards each result
/// downstream as it completes — so a slow fetch does not delay faster ones in the same window.
/// Results arrive out-of-order; [`chain_advancer`] reorders them via its `BTreeMap` buffer.
/// Provides backpressure via the bounded output channel. On error, the block is re-enqueued;
/// on repeated chain-tip lookup failure, backs off exponentially.
pub async fn block_fetcher<F: BlockFetcher>(
    fetcher: Arc<F>,
    tx: kanal::Sender<F::Output>,
    start_block: u64,
    config: Arc<PipelineConfig>,
    shutdown: CancellationToken,
) -> Result<()> {
    /// Cap on `next_block - base_block`, as a multiple of `max_in_flight`. Bounds memory
    /// when a persistently-failing block stalls `base_block` while the chain advances.
    const FETCH_WINDOW_MULTIPLIER: u64 = 4;

    let tx = tx.to_async();
    let max_in_flight = config.fetcher_max_in_flight;
    let max_window = (max_in_flight as u64) * FETCH_WINDOW_MULTIPLIER;
    info!(start_block, max_in_flight, max_window, "[Fetcher] Starting");

    let mut state = FetcherState::<F>::new(start_block);
    let mut tip = TipTracker::new(config.poll_interval);

    loop {
        if shutdown.is_cancelled() {
            info!("[Fetcher] Shutting down gracefully");
            return Ok(());
        }

        if state.target_reached(config.sync_target) {
            info!(target = ?config.sync_target, "[Fetcher] Reached sync target, stopping");
            return Ok(());
        }

        // Refresh tip only when we've run past the cached value AND `poll_interval` has
        // elapsed — the time gate alone would let retry-heavy loops hammer `eth_blockNumber`.
        let window_exhausted = tip.value().is_none_or(|c| state.window_exhausted(c));
        if window_exhausted && tip.refresh_due(config.poll_interval) {
            match fetcher.latest_block_number().await {
                Ok(n) => tip.set(n),
                Err(e) => {
                    warn!(error = %e, "[Fetcher] Failed to get chain latest, retrying");
                    tokio::select! {
                        _ = tokio::time::sleep(tip.backoff()) => {}
                        _ = shutdown.cancelled() => return Ok(()),
                    }
                    tip.inflate_backoff(config.fetcher_max_backoff);
                    continue;
                }
            }
        }
        // No tip yet — can't proceed.
        let Some(chain_latest) = tip.value() else {
            tokio::select! {
                _ = tokio::time::sleep(config.poll_interval) => {}
                _ = shutdown.cancelled() => return Ok(()),
            }
            continue;
        };

        // Retry failed blocks first, then fill remaining slots with fresh ones (bounded
        // by window cap so a stalled block can't grow the collections indefinitely).
        while state.in_flight_len() < max_in_flight &&
            let Some(bn) = state.pop_failed()
        {
            state.spawn(&fetcher, bn);
        }
        while state.in_flight_len() < max_in_flight &&
            state.next_block <= chain_latest &&
            state.window_width() < max_window &&
            !state.next_past_target(config.sync_target)
        {
            state.spawn_next(&fetcher);
        }

        if state.in_flight_len() == 0 {
            // Caught up — wait for chain to advance.
            tokio::select! {
                _ = tokio::time::sleep(config.poll_interval) => {}
                _ = shutdown.cancelled() => return Ok(()),
            }
            continue;
        }

        // `_with_id` so a panicked task's `JoinError` maps back to its block number.
        let joined = tokio::select! {
            r = state.tasks.join_next_with_id() => r,
            _ = shutdown.cancelled() => return Ok(()),
        };

        match joined {
            Some(Ok((id, (bn, Ok(item))))) => {
                state.on_success(id, bn);
                if tx.send(item).await.is_err() {
                    info!("[Fetcher] Channel closed, stopping");
                    return Ok(());
                }
                debug!(block_number = bn, "[Fetcher] Block sent to pipeline");
            }
            Some(Ok((id, (bn, Err(e))))) => {
                // Near-tip blocks routinely fail while the witness is being generated;
                // stay quiet for the first few attempts, then escalate.
                let attempt = state.on_failure(id, bn);
                if (4..=5).contains(&attempt) {
                    warn!(block_number = bn, attempt, error = %e, "[Fetcher] Block fetch error");
                } else if attempt > 5 {
                    error!(block_number = bn, attempt, error = %e, "[Fetcher] Block fetch error (repeated)");
                }
            }
            Some(Err(join_err)) => {
                let id = join_err.id();
                if let Some(bn) = state.on_panic(id) {
                    error!(block_number = bn, error = %join_err, "[Fetcher] Fetch task panicked, re-enqueueing");
                } else {
                    error!(error = %join_err, "[Fetcher] Fetch task panicked with unknown task id");
                }
            }
            None => {
                // JoinSet drained unexpectedly — tolerable; loop will refill.
            }
        }

        state.advance_base();
        state.recover_gaps();
    }
}

/// Errors from [`find_divergence_point`], classified for the pipeline.
#[derive(Debug, thiserror::Error)]
pub enum DivergenceError {
    /// Earliest local block doesn't match remote — reorg deeper than our history.
    /// Requires manual restart with a new `--start-block`.
    #[error(
        "Catastrophic reorg: earliest local block {block_number} hash mismatch \
         (local: {local_hash:?}, remote: {remote_hash:?}). Manual restart required."
    )]
    CatastrophicReorg { block_number: BlockNumber, local_hash: BlockHash, remote_hash: BlockHash },

    /// A block that should exist locally is missing — database is inconsistent.
    /// Requires manual restart with a new `--start-block`.
    #[error(
        "Local chain corrupt: block {block_number} missing during reorg resolution. \
         Manual restart required."
    )]
    LocalChainCorrupt { block_number: BlockNumber },

    /// Transient error during divergence search (e.g., RPC timeout).
    #[error(transparent)]
    Transient(#[from] eyre::Error),
}

impl DivergenceError {
    /// Whether this error is fatal (no point retrying).
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::CatastrophicReorg { .. } | Self::LocalChainCorrupt { .. })
    }
}

/// Finds where the local chain diverges from the remote.
///
/// Uses exponential search (efficient for near-tip reorgs) followed by binary search.
/// Backend-agnostic: takes closures for local chain lookups.
#[instrument(skip_all, fields(mismatch_block), name = "find_divergence")]
pub async fn find_divergence_point<F: BlockFetcher>(
    fetcher: &F,
    get_hash: &(dyn Fn(u64) -> eyre::Result<Option<BlockHash>> + Send + Sync),
    get_earliest: &(dyn Fn() -> eyre::Result<Option<(BlockNumber, BlockHash)>> + Send + Sync),
    mismatch_block: u64,
) -> std::result::Result<u64, DivergenceError> {
    let earliest_local = get_earliest()?.expect("Local chain cannot be empty");

    let earliest_remote_hash = fetcher.block_hash(earliest_local.0).await?;
    if earliest_remote_hash != earliest_local.1 {
        return Err(DivergenceError::CatastrophicReorg {
            block_number: earliest_local.0,
            local_hash: earliest_local.1,
            remote_hash: earliest_remote_hash,
        });
    }

    // Exponential search backward from mismatch point
    let mut step = 1u64;
    let mut last_mismatch = mismatch_block;
    let mut search_start = earliest_local.0;

    while last_mismatch > earliest_local.0 {
        let check_block = last_mismatch.saturating_sub(step).max(earliest_local.0);
        let local_hash = get_hash(check_block)?
            .ok_or(DivergenceError::LocalChainCorrupt { block_number: check_block })?;
        let remote_hash = fetcher.block_hash(check_block).await?;

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
        let local_hash =
            get_hash(mid)?.ok_or(DivergenceError::LocalChainCorrupt { block_number: mid })?;
        let remote_hash = fetcher.block_hash(mid).await?;
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

/// Receives processed blocks, reorders, verifies parent-hash continuity,
/// and advances the canonical chain.
async fn chain_advancer<F, S, H>(
    fetcher: &F,
    store: &S,
    hooks: &H,
    result_rx: kanal::Receiver<std::result::Result<H::Output, (String, ErrorAction)>>,
    initial_tip: BlockMeta,
    shutdown: CancellationToken,
) -> Result<PipelineOutcome>
where
    F: BlockFetcher,
    S: ChainStore,
    H: PipelineHooks,
{
    let rx = result_rx.to_async();
    let mut next_expected = initial_tip.block_number + 1;
    let mut current_tip = initial_tip;
    let mut buffer: BTreeMap<u64, H::Output> = BTreeMap::new();

    loop {
        let item = tokio::select! {
            r = rx.recv() => match r {
                Ok(Ok(item)) => item,
                Ok(Err((msg, ErrorAction::Halt))) => {
                    error!(error = %msg, "[Advancer] Fatal processing error, halting");
                    return Ok(PipelineOutcome::Fatal(msg));
                }
                Ok(Err((msg, ErrorAction::Retry))) => {
                    warn!(error = %msg, "[Advancer] Transient processing error, restarting cycle");
                    return Err(anyhow!("{msg}"));
                }
                Err(_) => return Ok(PipelineOutcome::Shutdown),
            },
            _ = shutdown.cancelled() => return Ok(PipelineOutcome::Shutdown),
        };

        buffer.insert(item.block_number(), item);

        // Drain consecutive blocks
        let mut batch = Vec::new();
        let mut metas = Vec::new();
        while let Some(item) = buffer.remove(&next_expected) {
            if item.parent_hash() != current_tip.block_hash {
                debug!(
                    block = next_expected,
                    expected_parent = ?current_tip.block_hash,
                    actual_parent = ?item.parent_hash(),
                    "[Advancer] Parent hash mismatch — reorg detected"
                );

                let rollback_to = match find_divergence_point(
                    fetcher,
                    &|n| store.get_block_hash(n),
                    &|| store.get_earliest_block(),
                    current_tip.block_number,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) if e.is_fatal() => {
                        return Ok(PipelineOutcome::Fatal(e.to_string()));
                    }
                    Err(e) => return Err(e.into()),
                };

                let depth = current_tip.block_number.saturating_sub(rollback_to);
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

            if let Err(e) = item.verify_continuity(&current_tip) {
                error!(
                    block = next_expected,
                    error = %e,
                    "[Advancer] State continuity check failed, halting"
                );
                return Ok(PipelineOutcome::Fatal(e.to_string()));
            }
            current_tip = item.to_block_meta();
            next_expected += 1;
            metas.push(current_tip.clone());
            batch.push(item);
        }

        if !batch.is_empty() {
            hooks.pre_advance(&batch)?;
            store.advance_chain(&metas)?;
            debug!(
                tip = current_tip.block_number,
                advanced = metas.len(),
                buffered = buffer.len(),
                "[Advancer] Chain advanced"
            );
            hooks.post_advance(&current_tip)?;
        }
    }
}

/// Spawns N worker tasks: fetch_rx → processor.process() → result_tx.
fn spawn_workers<P: BlockProcessor>(
    processor: Arc<P>,
    fetch_rx: kanal::Receiver<P::Input>,
    result_tx: kanal::Sender<std::result::Result<P::Output, (String, ErrorAction)>>,
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
                            let action = processor.error_action(&e);
                            Err((e.to_string(), action))
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

    #[test]
    fn test_pipeline_config_default_uses_cpu_count() {
        let config = PipelineConfig::default();
        let cpus = num_cpus::get_physical();
        assert_eq!(config.concurrent_workers, cpus);
        assert_eq!(config.fetch_channel_capacity, 2 * cpus);
        assert_eq!(config.result_channel_capacity, 2 * cpus);
        assert_eq!(config.fetcher_max_in_flight, cpus);
    }

    #[test]
    fn test_pipeline_config_default_stale_disabled() {
        assert!(PipelineConfig::default().stale_reset_threshold.is_none());
    }

    // Mock types for tests
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

    struct NoopHooks;
    impl PipelineHooks for NoopHooks {
        type Output = MockBlock;
    }

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

    /// Mock fetcher that only provides block hashes (for advancer/divergence tests).
    struct MockFetcher {
        hashes: HashMap<u64, BlockHash>,
    }

    impl BlockFetcher for MockFetcher {
        type Output = ();

        async fn fetch(&self, _: u64) -> Result<()> {
            unimplemented!("not used in advancer/divergence tests")
        }
        async fn latest_block_number(&self) -> Result<u64> {
            Ok(*self.hashes.keys().max().unwrap_or(&0))
        }
        async fn block_hash(&self, n: u64) -> Result<BlockHash> {
            self.hashes.get(&n).copied().ok_or_else(|| anyhow!("Block {n} not found"))
        }
        async fn latest_block_meta(&self) -> Result<BlockMeta> {
            unimplemented!("not used in advancer/divergence tests")
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

    async fn run_advancer(
        tip: BlockMeta,
        rpc_hashes: HashMap<u64, BlockHash>,
        blocks: Vec<std::result::Result<MockBlock, (String, ErrorAction)>>,
    ) -> (Result<PipelineOutcome>, MockStore) {
        let store = MockStore::new(tip.clone());
        let fetcher = MockFetcher { hashes: rpc_hashes };
        let hooks = NoopHooks;
        let (tx, rx) = kanal::bounded(16);

        {
            let tx_async = tx.to_async();
            for b in blocks {
                tx_async.send(b).await.unwrap();
            }
        }

        let result =
            chain_advancer(&fetcher, &store, &hooks, rx, tip, CancellationToken::new()).await;
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
    async fn test_chain_advancer_fatal_error_halts() {
        let tip = make_tip(10);
        let blocks = vec![Err(("state root mismatch".to_string(), ErrorAction::Halt))];
        let (result, _) = run_advancer(tip, HashMap::new(), blocks).await;
        match result.unwrap() {
            PipelineOutcome::Fatal(msg) => assert!(msg.contains("state root mismatch")),
            other => panic!("Expected Fatal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_chain_advancer_transient_error_returns_err() {
        let tip = make_tip(10);
        let blocks = vec![Err(("RPC timeout".to_string(), ErrorAction::Retry))];
        let (result, _) = run_advancer(tip, HashMap::new(), blocks).await;
        // Retry errors are returned as Err (not PipelineOutcome), triggering restart
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("RPC timeout"));
    }

    #[tokio::test]
    async fn test_chain_advancer_shutdown() {
        let tip = make_tip(10);
        let store = MockStore::new(tip.clone());
        let fetcher = MockFetcher { hashes: HashMap::new() };
        let hooks = NoopHooks;
        let (_tx, rx) = kanal::bounded::<std::result::Result<MockBlock, (String, ErrorAction)>>(16);
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let outcome = chain_advancer(&fetcher, &store, &hooks, rx, tip, shutdown).await.unwrap();
        assert!(matches!(outcome, PipelineOutcome::Shutdown));
    }

    #[tokio::test]
    async fn test_chain_advancer_reorg_detected() {
        let tip = make_tip(10);
        let mut rpc_hashes = HashMap::new();
        rpc_hashes.insert(10, make_hash(10));

        let bad_block = MockBlock {
            number: 11,
            hash: make_hash(11),
            parent: BlockHash::from([0xFF; 32]),
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
        for n in 1..=10 {
            local.insert(n, make_hash(n));
            if n <= 9 {
                remote.insert(n, make_hash(n));
            } else {
                remote.insert(n, BlockHash::from([0xFF; 32]));
            }
        }

        let fetcher = MockFetcher { hashes: remote };
        let result = find_divergence_point(
            &fetcher,
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

        let fetcher = MockFetcher { hashes: remote };
        let result = find_divergence_point(
            &fetcher,
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

        let fetcher = MockFetcher { hashes: remote };
        let result = find_divergence_point(
            &fetcher,
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
        let (msg, action) = result.unwrap_err();
        assert_eq!(msg, "boom");
        // Default error_action is Halt
        assert_eq!(action, ErrorAction::Halt);
    }

    /// Streaming regression: with the previous `join_all` batching all 4 blocks in a batch
    /// completed together, so a slow block held everyone back. With `JoinSet` streaming, the
    /// 3 fast blocks must be sent downstream before the slow one.
    #[tokio::test]
    async fn test_block_fetcher_streams_out_of_order() {
        /// Returns `block_number` as Output; delays exactly `slow_block` by `slow_delay`.
        struct SlowFetcher {
            latest: u64,
            slow_block: u64,
            slow_delay: Duration,
        }

        impl BlockFetcher for SlowFetcher {
            type Output = u64;
            async fn fetch(&self, bn: u64) -> eyre::Result<u64> {
                if bn == self.slow_block {
                    tokio::time::sleep(self.slow_delay).await;
                }
                Ok(bn)
            }
            async fn latest_block_number(&self) -> eyre::Result<u64> {
                Ok(self.latest)
            }
            async fn block_hash(&self, _: u64) -> eyre::Result<BlockHash> {
                unreachable!()
            }
            async fn latest_block_meta(&self) -> eyre::Result<BlockMeta> {
                unreachable!()
            }
        }

        let (start, slow) = (100u64, 102u64);
        let fetcher = Arc::new(SlowFetcher {
            latest: start + 3,
            slow_block: slow,
            slow_delay: Duration::from_millis(200),
        });
        let (tx, rx) = kanal::bounded::<u64>(8);
        let config = Arc::new(PipelineConfig {
            fetcher_max_in_flight: 4,     // window holds all 4 blocks
            sync_target: Some(start + 3), // fetcher exits cleanly after block 103
            poll_interval: Duration::from_millis(10),
            ..PipelineConfig::default()
        });
        let handle =
            tokio::spawn(block_fetcher(fetcher, tx, start, config, CancellationToken::new()));

        // First 3 results must be the fast blocks (slow block must NOT be among them).
        let rx = rx.to_async();
        let recv = async || {
            tokio::time::timeout(Duration::from_millis(150), rx.recv()).await.unwrap().unwrap()
        };
        let mut first_three = [recv().await, recv().await, recv().await];
        first_three.sort();
        assert_eq!(first_three, [start, start + 1, start + 3], "streaming broken: {first_three:?}");

        // The 4th (final) result is the slow block.
        let last =
            tokio::time::timeout(Duration::from_millis(500), rx.recv()).await.unwrap().unwrap();
        assert_eq!(last, slow);

        // Fetcher exits cleanly after sync_target.
        assert!(tokio::time::timeout(Duration::from_secs(1), handle).await.is_ok());
    }

    /// Regression: a persistently-failing block must not let the fetch window grow
    /// unboundedly while the chain advances. The spawn-window cap bounds the highest
    /// block we ever attempt to `stuck + max_window - 1` (since `base_block` can reach
    /// `stuck` itself via contiguous-sent drain below it).
    #[tokio::test]
    async fn test_block_fetcher_bounded_window_under_stall() {
        use std::sync::atomic::{AtomicU64, Ordering};

        /// Fails block `stuck`; records the highest `bn` ever requested.
        struct StallFetcher(u64, u64, Arc<AtomicU64>); // (latest, stuck, highest)

        impl BlockFetcher for StallFetcher {
            type Output = u64;
            async fn fetch(&self, bn: u64) -> eyre::Result<u64> {
                self.2.fetch_max(bn, Ordering::Relaxed);
                if bn == self.1 { Err(eyre::eyre!("stuck")) } else { Ok(bn) }
            }
            async fn latest_block_number(&self) -> eyre::Result<u64> {
                Ok(self.0)
            }
            async fn block_hash(&self, _: u64) -> eyre::Result<BlockHash> {
                unreachable!()
            }
            async fn latest_block_meta(&self) -> eyre::Result<BlockMeta> {
                unreachable!()
            }
        }

        let (start, stuck, latest) = (100u64, 105u64, 10_100u64);
        let max_in_flight = 4;
        let max_window = 4 * max_in_flight as u64; // matches FETCH_WINDOW_MULTIPLIER
        let highest = Arc::new(AtomicU64::new(0));

        let (tx, rx) = kanal::bounded::<u64>(1024);
        let config = Arc::new(PipelineConfig {
            fetcher_max_in_flight: max_in_flight,
            poll_interval: Duration::from_millis(10),
            ..PipelineConfig::default()
        });
        let shutdown = CancellationToken::new();

        // Drain so `tx.send` never blocks — isolate the window cap as the sole limiter.
        let drain = tokio::spawn(async move {
            let rx = rx.to_async();
            while rx.recv().await.is_ok() {}
        });
        let fetcher = tokio::spawn(block_fetcher(
            Arc::new(StallFetcher(latest, stuck, highest.clone())),
            tx,
            start,
            config,
            shutdown.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(500)).await;
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), fetcher).await;
        drain.abort();

        let h = highest.load(Ordering::Relaxed);
        let ceiling = stuck + max_window;
        assert!(
            h < ceiling,
            "attempted {h}, expected < {ceiling}; without cap would reach ~{latest}"
        );
    }
}
