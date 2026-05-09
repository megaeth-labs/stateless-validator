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

mod advancer;
mod config;
mod divergence;
mod fetcher;
mod traits;
mod worker;

use std::{sync::Arc, time::Duration};

use advancer::chain_advancer;
use config::WorkerResult;
pub use config::{ErrorAction, PipelineConfig, PipelineOutcome, ReorgEvent};
pub use divergence::{DivergenceError, DivergenceLookups, find_divergence_point};
use eyre::{Result, anyhow};
pub use fetcher::block_fetcher;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
pub use traits::{BlockFetcher, BlockProcessor, PipelineHooks, ProcessedBlock};
use worker::spawn_workers;

use crate::ChainStore;

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
        info!(start_block, "Starting cycle");

        let channel_capacity = config.channel_capacity();
        let (fetch_tx, fetch_rx) = kanal::bounded(channel_capacity);
        let fetcher_shutdown = CancellationToken::new();
        let fetcher_handle = tokio::spawn(block_fetcher(
            fetcher.clone(),
            fetch_tx,
            start_block,
            config.clone(),
            fetcher_shutdown.clone(),
        ));

        let (result_tx, result_rx) = kanal::bounded::<WorkerResult<P::Output>>(channel_capacity);
        let worker_handles =
            spawn_workers(processor.clone(), fetch_rx, result_tx, config.concurrent_workers);

        let outcome =
            chain_advancer(&*fetcher, &*store, &*hooks, result_rx, initial_tip, shutdown.clone())
                .await;

        fetcher_shutdown.cancel();
        await_handles(fetcher_handle, worker_handles, config.await_handles_timeout).await;

        let transient_reason: String = match outcome {
            Ok(PipelineOutcome::Shutdown) => {
                info!("Shutting down");
                return Ok(());
            }
            Ok(PipelineOutcome::Fatal(msg)) => {
                error!(error = %msg, "Fatal error, halting");
                return Err(anyhow!("Pipeline halted: {msg}"));
            }
            Ok(PipelineOutcome::Reorg(event)) => {
                warn!(
                    rollback_to = event.rollback_to,
                    depth = event.depth,
                    "Reorg detected, restarting"
                );
                hooks.on_reorg(event.rollback_to, event.depth, &event.reverted_hashes)?;
                store.rollback_chain(event.rollback_to)?;
                // Restart immediately. The fresh fetcher's tip refresh is gated by
                // `poll_interval`, and a recurring reorg requires another full
                // chain_advancer round-trip — neither path can spin tight here.
                continue;
            }
            Ok(PipelineOutcome::Retry(msg)) => {
                warn!(reason = %msg, "Cycle ended with retry signal");
                msg
            }
            Err(e) => {
                // Any `Err` at this level is unexpected (every intentional transient/fatal
                // case returns `Ok(PipelineOutcome::..)`). Log and fall into the same
                // stale-detect + sleep + continue recovery path as `Retry`.
                error!(error = %e, "Cycle ended with unexpected error");
                e.to_string()
            }
        };

        if handle_transient_restart(
            transient_reason,
            &*fetcher,
            &*store,
            &*hooks,
            &config,
            &shutdown,
        )
        .await?
        {
            return Ok(());
        }
    }
}

/// Runs the common recovery path for transient cycle endings (`PipelineOutcome::Retry` or
/// an unexpected `Err`): optional stale-anchor reset, then sleep + restart.
///
/// Returns `Ok(true)` if the outer caller should return `Ok(())` (shutdown fired); otherwise
/// returns `Ok(false)` so the outer loop `continue`s. Propagates `Err` only for store /
/// hook failures the caller can't meaningfully recover from.
async fn handle_transient_restart<F, S, H>(
    _reason: String,
    fetcher: &F,
    store: &S,
    hooks: &H,
    config: &PipelineConfig,
    shutdown: &CancellationToken,
) -> Result<bool>
where
    F: BlockFetcher,
    S: ChainStore,
    H: PipelineHooks,
{
    // Stale detection (optional). Both `latest_block_number` and `latest_block_meta` delegate
    // to the RPC client's unbounded retry loop, so without a shutdown select they'd hang
    // graceful shutdown whenever upstream is down at the moment the stale check runs.
    if let Some(threshold) = config.stale_reset_threshold {
        let chain_latest = tokio::select! {
            r = fetcher.latest_block_number() => r,
            _ = shutdown.cancelled() => return Ok(true),
        };
        if let (Ok(chain_latest), Ok(Some(tip))) = (chain_latest, store.get_canonical_tip()) &&
            chain_latest > tip.block_number + threshold
        {
            warn!(
                tip = tip.block_number,
                chain_latest, threshold, "Local data is stale, resetting anchor"
            );
            let meta = tokio::select! {
                r = fetcher.latest_block_meta() => r,
                _ = shutdown.cancelled() => return Ok(true),
            };
            match meta {
                Ok(new_anchor) => {
                    hooks.on_stale_reset(&new_anchor)?;
                    store.reset_to_anchor(&new_anchor)?;
                    return Ok(false);
                }
                Err(e) => {
                    warn!(error = %e, "Failed to fetch latest block for anchor reset");
                }
            }
        }
    }

    tokio::select! {
        _ = tokio::time::sleep(config.error_restart_delay) => Ok(false),
        _ = shutdown.cancelled() => Ok(true),
    }
}

/// Waits for the fetcher and all workers to finish (with timeout).
async fn await_handles(
    fetcher: JoinHandle<Result<()>>,
    workers: Vec<JoinHandle<()>>,
    timeout: Duration,
) {
    tokio::select! {
        _ = async {
            if let Err(e) = fetcher.await {
                warn!(error = %e, "Fetcher task panicked");
            }
            for handle in workers {
                if let Err(e) = handle.await {
                    warn!(error = %e, "Worker task panicked");
                }
            }
        } => {}
        _ = tokio::time::sleep(timeout) => {
            warn!(?timeout, "Timed out waiting for background tasks");
        }
    }
}

#[cfg(test)]
mod tests;
