//! Pipeline configuration and outcome types.

use std::time::Duration;

use alloy_primitives::{BlockHash, BlockNumber};

/// Configuration for the chain sync pipeline.
///
/// Binary-specific settings (metrics, reporting, pruner) live in binary CLI args.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PipelineConfig {
    /// Number of parallel processing workers.
    pub concurrent_workers: usize,
    /// Optional block height to sync to; `None` for infinite sync.
    pub sync_target: Option<u64>,
    /// Time to wait between fetcher poll cycles when ahead of chain.
    pub poll_interval: Duration,
    /// Time to wait when pipeline encounters errors before restarting.
    pub error_restart_delay: Duration,
    /// Safety margin below the remote tip: the fetcher will not spawn fetches for blocks
    /// `> chain_latest - tip_buffer`. Gives the upstream witness generator headroom to finish
    /// the very block we'd otherwise race it for. `0` disables the buffer.
    pub tip_buffer: u64,
    /// Per-cycle shutdown timeout for fetcher + workers (`await_handles`).
    /// Heavy-block validation can take >1s; tight values cause spurious "did not drain" warnings.
    pub await_handles_timeout: Duration,
    /// If local tip falls behind remote by more than this, reset anchor.
    /// `None` = disabled (validator). `Some(N)` = enabled (trace server).
    pub stale_reset_threshold: Option<u64>,
    /// Multiplier on `concurrent_workers` that derives both the fetcher in-flight window
    /// and the channel capacities (fetch→worker and worker→advancer). Default: 2. Fetchers
    /// are I/O-bound, so a small multiplier over the CPU-bound worker count keeps the
    /// pipeline fed; bound a run-away provider with `--data-max-concurrent-requests` /
    /// `--witness-max-concurrent-requests` instead.
    pub in_flight_multiplier: usize,
    /// Multiplier on the in-flight window that bounds `next_block - base_block` in the
    /// fetcher. Caps memory when a persistently-failing block stalls `base_block` while the
    /// chain advances. Default: 4 — combined with `in_flight_multiplier = 2` that gives a
    /// ceiling of `8 × concurrent_workers` outstanding blocks.
    pub fetch_window_multiplier: u64,
}

impl PipelineConfig {
    /// Fetcher in-flight window: number of concurrent `BlockFetcher::fetch` tasks the
    /// fetcher stage may have outstanding at once. Derived from `concurrent_workers ×
    /// in_flight_multiplier`.
    pub fn fetcher_max_in_flight(&self) -> usize {
        self.concurrent_workers * self.in_flight_multiplier
    }

    /// Capacity of both the fetch→worker and worker→advancer channels. Matched to the
    /// fetcher in-flight window so a slow worker stage provides backpressure against the
    /// fetcher instead of unboundedly buffering in the channel.
    pub fn channel_capacity(&self) -> usize {
        self.fetcher_max_in_flight()
    }

    /// Upper bound on `next_block - base_block` inside the fetcher. Bounds memory when a
    /// persistently-failing block stalls `base_block` while the chain advances.
    pub fn fetch_window(&self) -> u64 {
        (self.fetcher_max_in_flight() as u64) * self.fetch_window_multiplier
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        // Physical cores: workers are CPU-bound (EVM + IPA), hyperthreads don't help.
        Self {
            concurrent_workers: num_cpus::get_physical(),
            sync_target: None,
            poll_interval: Duration::from_millis(100),
            error_restart_delay: Duration::from_secs(1),
            // Disabled by default. Callers that race the upstream witness generator (the
            // validator and the trace server's chain sync) should set this to the number of
            // blocks they want to stay behind the remote tip.
            tip_buffer: 0,
            await_handles_timeout: Duration::from_secs(30),
            stale_reset_threshold: None,
            in_flight_multiplier: 2,
            fetch_window_multiplier: 4,
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
    /// Transient failure (RPC timeout, integrity check, etc.) — caller should sleep and
    /// restart the cycle. Carries the stringified reason for operator-visible logging.
    ///
    /// Before this variant existed, `chain_advancer` signalled the retry case by returning
    /// `Err(anyhow!(..))`, and the outer loop caught any `Err` as "retry after sleep." That
    /// conflated genuine retry requests with genuinely-unexpected errors (panics caught at
    /// task join, etc.). Having an explicit variant makes the signalling exhaustive.
    Retry(String),
}

/// Whether a processing error is worth retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorAction {
    /// Transient error (RPC timeout, network issue) — restart pipeline, retry later.
    Retry,
    /// Deterministic failure (validation mismatch) — halt immediately.
    Halt,
}

/// Per-item result flowing from worker → advancer. The error carries an erased source
/// (`Arc<dyn Error + Send + Sync>`) plus an `ErrorAction`. `Arc` rather than `Box` because
/// the advancer logs once and drops; sharing across threads via refcount is cheap and the
/// type stays `Clone` if a future consumer wants to fan out.
pub(crate) type WorkerResult<T> =
    std::result::Result<T, (std::sync::Arc<dyn std::error::Error + Send + Sync>, ErrorAction)>;

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
