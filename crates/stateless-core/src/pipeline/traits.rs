//! Pluggable traits that customize pipeline behavior per binary.

use std::{future::Future, sync::Arc};

use alloy_primitives::{BlockHash, BlockNumber};
use eyre::Result;

use crate::{db::BlockMeta, pipeline::config::ErrorAction};

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

    /// Hash for a given block number (used by `find_divergence_point`).
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
    /// Error type for processing failures. Must implement `std::error::Error` so the
    /// advancer can log the chained source while the channel carries it as
    /// `Arc<dyn Error + Send + Sync>` (see [`crate::pipeline::WorkerResult`]).
    type Error: std::error::Error + Send + Sync + 'static;

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
