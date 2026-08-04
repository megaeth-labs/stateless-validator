//! Advancer stage: reorders processed blocks, detects reorgs, persists progress.

use std::collections::BTreeMap;

use eyre::Result;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::{
    ChainStore,
    db::BlockMeta,
    pipeline::{
        config::{ErrorAction, PipelineOutcome, ReorgEvent, WorkerResult},
        divergence::{DivergenceLookups, find_divergence_point},
        traits::{BlockFetcher, PipelineHooks, ProcessedBlock},
    },
};

/// Outcome of a [`ReorgResolver::resolve`] call: the rollback floor, or a reason the cycle must
/// end without rolling back.
#[derive(Debug, Clone)]
pub enum ReorgResolution {
    /// Roll back to this block (inclusive — it stays), then restart the cycle.
    Floor(u64),
    /// Deterministic failure — halt the pipeline (no point retrying).
    Fatal(String),
    /// Transient failure — sleep and restart the cycle.
    Retry(String),
}

/// The pipeline's reorg seam: given a detected parent-hash mismatch, decide the rollback floor.
///
/// This is the single shared abstraction over the scenarios' different reorg models. Each scenario
/// supplies the resolver matching how it maintains its chain, and passes it to
/// [`run_pipeline`](crate::pipeline::run_pipeline):
/// - History-owning scenarios (standalone validator, debug-trace-server) use the core
///   [`BisectResolver`], which walks their [`DivergenceLookups`] against the remote fetcher.
/// - The mega-reth FullNode implements this trait in its own bin, returning the floor its host
///   (state-sync) already published — it never bisects and never touches the fetcher.
pub trait ReorgResolver<F, S>: Send + Sync {
    /// Resolve the rollback floor for the reorg the advancer just detected. `persisted_tip` is
    /// the highest block durably written by `advance_chain` (the upper bound a bisection may read
    /// from the store).
    ///
    /// Desugared to `impl Future + Send` (rather than `async fn`) so the returned future carries a
    /// `Send` bound — the pipeline drives it on a multi-threaded runtime.
    fn resolve(
        &self,
        fetcher: &F,
        store: &S,
        persisted_tip: u64,
    ) -> impl core::future::Future<Output = Result<ReorgResolution>> + Send;
}

/// Bisection resolver for history-owning stores: walks local history against the remote via
/// [`find_divergence_point`]. Requires `S: DivergenceLookups`. Lives in core because both
/// history-owning scenarios reuse it verbatim over the shared `find_divergence_point` algorithm.
pub struct BisectResolver;

impl<F, S> ReorgResolver<F, S> for BisectResolver
where
    F: BlockFetcher,
    S: DivergenceLookups + Send + Sync,
{
    async fn resolve(&self, fetcher: &F, store: &S, persisted_tip: u64) -> Result<ReorgResolution> {
        match find_divergence_point(fetcher, store, persisted_tip).await {
            Ok(v) => Ok(ReorgResolution::Floor(v)),
            Err(e) if e.is_fatal() => Ok(ReorgResolution::Fatal(e.to_string())),
            // A non-fatal divergence error is a transport hiccup during the bisection fetches —
            // an *intentional* transient signal, so route it through `Retry` (warn + sleep +
            // restart) instead of leaking an `Err` the outer loop logs as "unexpected error".
            Err(e) => Ok(ReorgResolution::Retry(e.to_string())),
        }
    }
}

/// Receives processed blocks, reorders, verifies parent-hash continuity,
/// and advances the canonical chain.
pub(crate) async fn chain_advancer<F, S, H, R>(
    fetcher: &F,
    store: &S,
    hooks: &H,
    resolver: &R,
    result_rx: kanal::Receiver<WorkerResult<H::Output>>,
    initial_tip: BlockMeta,
    shutdown: CancellationToken,
) -> Result<PipelineOutcome>
where
    F: BlockFetcher,
    S: ChainStore,
    H: PipelineHooks,
    R: ReorgResolver<F, S>,
{
    let rx = result_rx.to_async();
    let mut next_expected = initial_tip.block_number + 1;
    // `current_tip` is the projected head while we thread intra-batch parent-hash checks;
    // `persisted_tip` trails it and only advances after a successful `store.advance_chain`.
    // The divergence search and reorg reporting must use `persisted_tip` — querying
    // `store.get_block_hash` past that returns `None` and raises `LocalChainCorrupt`.
    let mut persisted_tip = initial_tip.block_number;
    let mut current_tip = initial_tip;
    let mut buffer: BTreeMap<u64, H::Output> = BTreeMap::new();
    // Reused across iterations to avoid per-iteration allocations; typical batch
    // size is small (<= `concurrent_workers`) and stable.
    let mut batch: Vec<H::Output> = Vec::new();
    let mut metas: Vec<BlockMeta> = Vec::new();

    loop {
        let item = tokio::select! {
            r = rx.recv() => match r {
                Ok(Ok(item)) => item,
                Ok(Err((err, ErrorAction::Halt))) => {
                    // `%err` via the `Error` trait prints the full cause chain so operators
                    // see the root cause, not just the top-level message.
                    error!(error = %err, "Fatal processing error, halting");
                    return Ok(PipelineOutcome::Fatal(err.to_string()));
                }
                Ok(Err((err, ErrorAction::Retry))) => {
                    warn!(error = %err, "Transient processing error, restarting cycle");
                    return Ok(PipelineOutcome::Retry(err.to_string()));
                }
                Err(_) => return Ok(PipelineOutcome::Shutdown),
            },
            _ = shutdown.cancelled() => return Ok(PipelineOutcome::Shutdown),
        };

        buffer.insert(item.block_number(), item);

        batch.clear();
        metas.clear();
        while let Some(item) = buffer.remove(&next_expected) {
            if item.parent_hash() != current_tip.block_hash {
                debug!(
                    block = next_expected,
                    expected_parent = ?current_tip.block_hash,
                    actual_parent = ?item.parent_hash(),
                    "Parent hash mismatch — reorg detected"
                );

                // Strategy is scenario-supplied (see `ReorgResolver`); `Floor` rolls back,
                // `Fatal`/`Retry` end the cycle.
                let rollback_to = match resolver.resolve(fetcher, store, persisted_tip).await? {
                    ReorgResolution::Floor(floor) => {
                        debug!(block = next_expected, floor, "Resolved reorg floor");
                        floor
                    }
                    ReorgResolution::Fatal(msg) => return Ok(PipelineOutcome::Fatal(msg)),
                    ReorgResolution::Retry(msg) => return Ok(PipelineOutcome::Retry(msg)),
                };

                let depth = persisted_tip.saturating_sub(rollback_to);
                let mut reverted_hashes = Vec::new();
                for n in (rollback_to + 1)..=persisted_tip {
                    match store.get_block_hash(n) {
                        Ok(Some(hash)) => reverted_hashes.push(hash),
                        Ok(None) => {}
                        Err(e) => warn!(
                            block_number = n,
                            error = %e,
                            "Failed to read block hash for reorg event",
                        ),
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
                    "State continuity check failed, halting"
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
            persisted_tip = current_tip.block_number;
            debug!(
                tip = current_tip.block_number,
                advanced = metas.len(),
                buffered = buffer.len(),
                "Chain advanced"
            );
            hooks.post_advance(&current_tip)?;
        }
    }
}
