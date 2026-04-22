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

use crate::{
    BackoffPolicy,
    pipeline::{config::PipelineConfig, traits::BlockFetcher},
};

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
    /// Earliest `Instant` at which a failed block may be re-spawned. Missing entries
    /// mean "retry now". Populated only when `on_failure` is called with a delay
    /// (near-tip mode); catch-up mode leaves this empty for immediate retry.
    retry_at: HashMap<u64, Instant>,
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
            retry_at: HashMap::new(),
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

    /// Returns a failed block whose retry delay (if any) has elapsed. Blocks with
    /// a pending `retry_at` in the future are skipped and stay in `failed`.
    fn pop_ready_failed(&mut self, now: Instant) -> Option<u64> {
        let bn = *self.failed.iter().find(|bn| self.retry_at.get(bn).is_none_or(|t| *t <= now))?;
        self.failed.remove(&bn);
        self.retry_at.remove(&bn);
        Some(bn)
    }

    fn on_success(&mut self, id: Id, bn: u64) {
        self.task_to_block.remove(&id);
        self.in_flight_blocks.remove(&bn);
        self.error_counts.remove(&bn);
        self.sent.insert(bn);
    }

    /// Records a failed fetch attempt and returns the cumulative attempt count
    /// (for log escalation). If `retry_delay` is `Some`, the block cannot be
    /// re-spawned until `now + retry_delay` has elapsed.
    fn on_failure(&mut self, id: Id, bn: u64, retry_delay: Option<Duration>) -> usize {
        self.task_to_block.remove(&id);
        self.in_flight_blocks.remove(&bn);
        self.failed.insert(bn);
        if let Some(d) = retry_delay {
            self.retry_at.insert(bn, Instant::now() + d);
        } else {
            self.retry_at.remove(&bn);
        }
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
    /// out of all three tracking sets. No-op under correct bookkeeping; returns the
    /// number recovered so the caller can surface a bookkeeping bug via `warn!`.
    fn recover_gaps(&mut self) -> usize {
        let mut recovered = 0;
        for bn in self.base_block..self.next_block {
            if !self.sent.contains(&bn) &&
                !self.in_flight_blocks.contains(&bn) &&
                !self.failed.contains(&bn)
            {
                self.failed.insert(bn);
                recovered += 1;
            }
        }
        recovered
    }
}

/// Cached chain tip with rate-limited refresh and failure backoff.
struct TipTracker<'a> {
    /// `None` forces a refresh (also keeps `start_block == 0` correct vs. a `0` sentinel).
    latest: Option<u64>,
    /// Rate-limits `latest_block_number()` calls (otherwise near-tip retries hammer
    /// `eth_blockNumber` at 10+ RPS).
    last_refresh: Instant,
    backoff: Duration,
    policy: &'a BackoffPolicy,
}

impl<'a> TipTracker<'a> {
    fn new(poll_interval: Duration, policy: &'a BackoffPolicy) -> Self {
        Self {
            latest: None,
            last_refresh: Instant::now() - poll_interval,
            backoff: policy.initial,
            policy,
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
        self.backoff = self.policy.initial;
    }

    fn backoff(&self) -> Duration {
        self.backoff
    }

    fn inflate_backoff(&mut self) {
        self.backoff = (self.backoff * 2).min(self.policy.max);
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
    let max_in_flight = config.fetcher_max_in_flight();
    let max_window = (max_in_flight as u64) * FETCH_WINDOW_MULTIPLIER;
    // Safety margin below the remote tip: never spawn fetches within `tip_buffer` of the tip.
    // `None` (near-tip mode disabled) means no buffer.
    let tip_buffer = config.near_tip.as_ref().map(|nt| nt.tip_buffer).unwrap_or(0);
    info!(start_block, max_in_flight, max_window, tip_buffer, "Starting");

    let mut state = FetcherState::<F>::new(start_block);
    let mut tip = TipTracker::new(config.poll_interval, &config.fetcher_tip_backoff);

    loop {
        if shutdown.is_cancelled() {
            info!("Shutting down gracefully");
            return Ok(());
        }

        if state.target_reached(config.sync_target) {
            info!(target = ?config.sync_target, "Reached sync target, stopping");
            return Ok(());
        }

        // Refresh tip only when we've run past the usable ceiling AND `poll_interval` has
        // elapsed — the time gate alone would let retry-heavy loops hammer `eth_blockNumber`.
        // The usable ceiling is `tip - tip_buffer`; otherwise a fresh tip that's still within
        // the buffer would stall refresh forever.
        let window_exhausted =
            tip.value().is_none_or(|c| state.window_exhausted(c.saturating_sub(tip_buffer)));
        if window_exhausted && tip.refresh_due(config.poll_interval) {
            match fetcher.latest_block_number().await {
                Ok(n) => tip.set(n),
                Err(e) => {
                    warn!(error = %e, "Failed to get chain latest, retrying");
                    tokio::select! {
                        _ = tokio::time::sleep(tip.backoff()) => {}
                        _ = shutdown.cancelled() => return Ok(()),
                    }
                    tip.inflate_backoff();
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
        let spawn_ceiling = chain_latest.saturating_sub(tip_buffer);

        // Retry failed blocks first, then fill remaining slots with fresh ones (bounded
        // by window cap so a stalled block can't grow the collections indefinitely).
        // `pop_ready_failed` skips blocks whose near-tip retry delay hasn't elapsed yet —
        // they stay in `failed` and will be picked up on a subsequent iteration (after the
        // next task completion, or after the idle-loop `poll_interval` expires).
        let now = Instant::now();
        while state.in_flight_len() < max_in_flight &&
            let Some(bn) = state.pop_ready_failed(now)
        {
            state.spawn(&fetcher, bn);
        }
        while state.in_flight_len() < max_in_flight &&
            state.next_block <= spawn_ceiling &&
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
                    info!("Channel closed, stopping");
                    return Ok(());
                }
                debug!(block_number = bn, "Block sent to pipeline");
            }
            Some(Ok((id, (bn, Err(e))))) => {
                // Two modes: catch-up (lag >= threshold) retries immediately and follows the
                // standard 4/6 escalation; near-tip (lag < threshold) delays retries so we
                // don't hammer the endpoint while the upstream witness is still being
                // generated, and stays quiet at DEBUG for the first few attempts.
                // `config.near_tip = None` disables near-tip mode entirely.
                let lag = chain_latest.saturating_sub(state.base_block);
                let (near_tip, retry_delay) = match &config.near_tip {
                    Some(nt) if lag < nt.lag_threshold => (true, Some(nt.retry_delay)),
                    _ => (false, None),
                };
                let attempt = state.on_failure(id, bn, retry_delay);
                // Both modes share the 4/6 WARN/ERROR escalation. They differ only in
                // the sub-4 band: catch-up is silent (failures there are unusual), near-tip
                // is DEBUG (failures are expected while the upstream witness is being built).
                if near_tip && attempt <= 3 {
                    debug!(block_number = bn, attempt, error = %e, "Near-tip fetch failed, will retry");
                } else if (4..=5).contains(&attempt) {
                    warn!(block_number = bn, attempt, error = %e, "Block fetch error");
                } else if attempt > 5 {
                    error!(block_number = bn, attempt, error = %e, "Block fetch error (repeated)");
                }
            }
            Some(Err(join_err)) => {
                let id = join_err.id();
                if let Some(bn) = state.on_panic(id) {
                    error!(block_number = bn, error = %join_err, "Fetch task panicked, re-enqueueing");
                } else {
                    error!(error = %join_err, "Fetch task panicked with unknown task id");
                }
            }
            None => {
                // JoinSet drained unexpectedly — tolerable; loop will refill.
            }
        }

        state.advance_base();
        let recovered = state.recover_gaps();
        if recovered > 0 {
            warn!(recovered, "Recovered gap blocks — bookkeeping bug");
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::BlockHash;
    use eyre::{Result, bail};
    use tokio::task::JoinSet;

    use super::*;
    use crate::db::BlockMeta;

    struct StubFetcher;

    impl BlockFetcher for StubFetcher {
        type Output = ();
        async fn fetch(&self, _: u64) -> Result<()> {
            bail!("unused")
        }
        async fn latest_block_number(&self) -> Result<u64> {
            bail!("unused")
        }
        async fn block_hash(&self, _: u64) -> Result<BlockHash> {
            bail!("unused")
        }
        async fn latest_block_meta(&self) -> Result<BlockMeta> {
            bail!("unused")
        }
    }

    /// Spawns a dummy task so we can obtain a real `task::Id` to drive `on_failure` /
    /// `on_success`, which expect an id that came out of the `JoinSet`.
    async fn fresh_task_id(tasks: &mut JoinSet<(u64, Result<()>)>, bn: u64) -> Id {
        let handle = tasks.spawn(async move { (bn, Ok(())) });
        handle.id()
    }

    #[tokio::test]
    async fn on_failure_without_delay_retries_immediately() {
        let mut state = FetcherState::<StubFetcher>::new(100);
        let id = fresh_task_id(&mut state.tasks, 100).await;
        state.in_flight_blocks.insert(100);
        state.task_to_block.insert(id, 100);

        let attempt = state.on_failure(id, 100, None);
        assert_eq!(attempt, 1);
        assert!(state.failed.contains(&100));
        assert!(!state.retry_at.contains_key(&100), "catch-up mode: no retry delay");

        let popped = state.pop_ready_failed(Instant::now());
        assert_eq!(popped, Some(100), "immediate retry when no delay set");
    }

    #[tokio::test]
    async fn on_failure_with_delay_defers_retry() {
        let mut state = FetcherState::<StubFetcher>::new(100);
        let id = fresh_task_id(&mut state.tasks, 100).await;
        state.in_flight_blocks.insert(100);
        state.task_to_block.insert(id, 100);

        let before = Instant::now();
        state.on_failure(id, 100, Some(Duration::from_millis(500)));

        // retry_at is in the future: pop_ready_failed refuses.
        assert_eq!(state.pop_ready_failed(before), None);
        assert!(state.failed.contains(&100), "stays in failed until delay elapses");

        // Past the deadline: pop_ready_failed releases it and clears retry_at.
        let after = before + Duration::from_millis(600);
        assert_eq!(state.pop_ready_failed(after), Some(100));
        assert!(!state.retry_at.contains_key(&100));
        assert!(!state.failed.contains(&100));
    }

    #[tokio::test]
    async fn on_failure_accumulates_attempt_count() {
        let mut state = FetcherState::<StubFetcher>::new(100);

        for expected in 1..=4 {
            let id = fresh_task_id(&mut state.tasks, 100).await;
            state.in_flight_blocks.insert(100);
            state.task_to_block.insert(id, 100);
            let attempt = state.on_failure(id, 100, None);
            assert_eq!(attempt, expected);
        }
    }

    /// `recover_gaps` must re-enqueue any block in `[base_block, next_block)` that
    /// slipped out of all three tracking sets — a bookkeeping bug that would otherwise
    /// stall `base_block` permanently.
    #[tokio::test]
    async fn recover_gaps_re_enqueues_missing_blocks() {
        let mut state = FetcherState::<StubFetcher>::new(100);
        // Pretend we've spawned blocks 100..104 but lost 101 and 103 from all tracking sets.
        state.next_block = 104;
        state.sent.insert(100);
        state.sent.insert(102);
        // 101 and 103 are deliberately absent.

        let recovered = state.recover_gaps();
        assert_eq!(recovered, 2, "both gaps must be recovered");
        assert!(state.failed.contains(&101));
        assert!(state.failed.contains(&103));

        // Idempotent: a second call with nothing missing recovers zero.
        let again = state.recover_gaps();
        assert_eq!(again, 0);
    }

    #[tokio::test]
    async fn recover_gaps_noop_when_bookkeeping_correct() {
        let mut state = FetcherState::<StubFetcher>::new(100);
        state.next_block = 103;
        state.sent.insert(100);
        state.in_flight_blocks.insert(101);
        state.failed.insert(102);

        assert_eq!(state.recover_gaps(), 0);
    }

    /// `on_panic` maps the panicked task's id back to its block number and re-enqueues
    /// it as failed. Unknown ids return `None` (and the block would be picked up by
    /// `recover_gaps` as defense in depth).
    #[tokio::test]
    async fn on_panic_re_enqueues_known_task() {
        let mut state = FetcherState::<StubFetcher>::new(100);
        let id = fresh_task_id(&mut state.tasks, 100).await;
        state.in_flight_blocks.insert(100);
        state.task_to_block.insert(id, 100);

        let bn = state.on_panic(id);
        assert_eq!(bn, Some(100));
        assert!(state.failed.contains(&100));
        assert!(!state.in_flight_blocks.contains(&100));
        assert!(!state.task_to_block.contains_key(&id));
    }

    #[tokio::test]
    async fn on_panic_unknown_id_returns_none() {
        // An id that was never recorded in `task_to_block` — e.g. a stale id from a prior
        // cycle. `on_panic` must not touch any state in that case.
        let mut state = FetcherState::<StubFetcher>::new(100);
        let id = fresh_task_id(&mut state.tasks, 100).await;
        // Note: we did NOT populate task_to_block with this id.
        assert!(state.on_panic(id).is_none());
        assert!(state.failed.is_empty());
    }
}
