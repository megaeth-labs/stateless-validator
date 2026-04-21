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
pub use config::{ErrorAction, PipelineConfig, PipelineOutcome, ReorgEvent};
pub use divergence::{DivergenceError, find_divergence_point};
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
        info!(start_block, "[Pipeline] Starting cycle");

        let (fetch_tx, fetch_rx) = kanal::bounded(config.fetch_channel_capacity);
        let fetcher_shutdown = CancellationToken::new();
        let fetcher_handle = tokio::spawn(block_fetcher(
            fetcher.clone(),
            fetch_tx,
            start_block,
            config.clone(),
            fetcher_shutdown.clone(),
        ));

        let (result_tx, result_rx) = kanal::bounded::<
            std::result::Result<P::Output, (String, ErrorAction)>,
        >(config.result_channel_capacity);
        let worker_handles =
            spawn_workers(processor.clone(), fetch_rx, result_tx, config.concurrent_workers);

        let outcome =
            chain_advancer(&*fetcher, &*store, &*hooks, result_rx, initial_tip, shutdown.clone())
                .await;

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
mod tests;
