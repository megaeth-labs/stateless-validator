//! Pipeline configuration and outcome types.

use std::time::Duration;

use alloy_primitives::{BlockHash, BlockNumber};

use crate::BackoffPolicy;

/// Near-tip mode parameters. When the fetcher's lag vs remote tip is below `lag_threshold`,
/// failed block fetches are delayed by `retry_delay` before re-spawn. This avoids hammering
/// the endpoint while it's still generating the very witness we're asking for.
#[derive(Debug, Clone)]
pub struct NearTipConfig {
    /// Lag threshold (in blocks) below which near-tip mode activates.
    pub lag_threshold: u64,
    /// Delay before re-spawning a failed fetch while in near-tip mode.
    /// Witness generation upstream lags block production by ~1-2s.
    pub retry_delay: Duration,
    /// Safety margin below the remote tip: the fetcher will not spawn fetches for blocks
    /// `> chain_latest - tip_buffer`. Gives the upstream witness generator headroom to finish
    /// the very block we'd otherwise race it for. `0` disables the buffer.
    pub tip_buffer: u64,
}

impl Default for NearTipConfig {
    fn default() -> Self {
        Self { lag_threshold: 10, retry_delay: Duration::from_millis(500), tip_buffer: 1 }
    }
}

/// Configuration for the chain sync pipeline.
///
/// Binary-specific settings (metrics, reporting, pruner) live in binary CLI args.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Number of parallel processing workers. Also derives the fetcher's in-flight window
    /// and both channel capacities (each set to `2 * concurrent_workers`).
    pub concurrent_workers: usize,
    /// Optional block height to sync to; `None` for infinite sync.
    pub sync_target: Option<u64>,
    /// Time to wait between fetcher poll cycles when ahead of chain.
    pub poll_interval: Duration,
    /// Time to wait when pipeline encounters errors before restarting.
    pub error_restart_delay: Duration,
    /// Exponential-backoff policy for the fetcher's chain-tip lookup failures.
    /// Unbounded: the polling loop retries forever.
    pub fetcher_tip_backoff: BackoffPolicy,
    /// Near-tip mode parameters. `None` disables near-tip mode (always catch-up semantics:
    /// immediate retry, standard log escalation).
    pub near_tip: Option<NearTipConfig>,
    /// Per-cycle shutdown timeout for fetcher + workers (`await_handles`).
    /// Heavy-block validation can take >1s; tight values cause spurious "did not drain" warnings.
    pub await_handles_timeout: Duration,
    /// If local tip falls behind remote by more than this, reset anchor.
    /// `None` = disabled (validator). `Some(N)` = enabled (trace server).
    pub stale_reset_threshold: Option<u64>,
}

impl PipelineConfig {
    /// Fetcher in-flight window and both channel capacities are all sized to `2 × workers`.
    /// Fetchers are I/O-bound so their concurrency exceeds the CPU-bound worker count;
    /// bound a run-away provider with `--data-max-concurrent-requests` /
    /// `--witness-max-concurrent-requests` instead.
    pub fn fetcher_max_in_flight(&self) -> usize {
        2 * self.concurrent_workers
    }

    /// Capacity of both the fetch→worker and worker→advancer channels.
    pub fn channel_capacity(&self) -> usize {
        2 * self.concurrent_workers
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
            fetcher_tip_backoff: BackoffPolicy::unbounded(
                Duration::from_millis(200),
                Duration::from_secs(30),
            ),
            near_tip: Some(NearTipConfig::default()),
            await_handles_timeout: Duration::from_secs(30),
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
