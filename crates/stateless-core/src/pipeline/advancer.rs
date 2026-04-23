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
        divergence::find_divergence_point,
        traits::{BlockFetcher, PipelineHooks, ProcessedBlock},
    },
};

/// Receives processed blocks, reorders, verifies parent-hash continuity,
/// and advances the canonical chain.
pub(crate) async fn chain_advancer<F, S, H>(
    fetcher: &F,
    store: &S,
    hooks: &H,
    result_rx: kanal::Receiver<WorkerResult<H::Output>>,
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

                let rollback_to = match find_divergence_point(fetcher, store, persisted_tip).await {
                    Ok(v) => v,
                    Err(e) if e.is_fatal() => {
                        return Ok(PipelineOutcome::Fatal(e.to_string()));
                    }
                    Err(e) => return Err(e.into()),
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
