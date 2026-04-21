//! Fetcher stage: parallel block fetching with bounded windowing and retry.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use eyre::Result;
use tokio::task::{Id, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::pipeline::{config::PipelineConfig, traits::BlockFetcher};

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
/// Results arrive out-of-order; the chain advancer reorders them via its `BTreeMap` buffer.
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
