//! Finds the point where the local chain diverges from the remote.

use alloy_primitives::{BlockHash, BlockNumber};
use tracing::{debug, instrument};

use crate::{
    ChainStore,
    db::{StoreError, StoreResult},
    pipeline::traits::BlockFetcher,
};

/// Minimal lookup surface that [`find_divergence_point`] needs from the local chain store.
///
/// Extracted from `ChainStore` so tests can implement a lightweight in-memory backend
/// without having to stub every `ChainStore` method. Every `ChainStore` blanket-implements
/// this trait automatically.
pub trait DivergenceLookups {
    /// Hash for the block at `block_number`, or `None` if it's not in local history.
    fn get_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>>;
    /// The oldest (lowest-number, highest-depth) block still in local history.
    fn get_earliest(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>>;
}

impl<S: ChainStore + ?Sized> DivergenceLookups for S {
    fn get_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>> {
        ChainStore::get_block_hash(self, block_number)
    }
    fn get_earliest(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
        ChainStore::get_earliest_block(self)
    }
}

/// Errors from [`find_divergence_point`], classified for the pipeline.
///
/// Two categories: the structured `CatastrophicReorg` / `LocalChainCorrupt` variants are
/// fatal (operator must intervene); `Transient` wraps everything else (RPC timeout, store
/// error, etc.). The previous split of `Rpc` vs `Store` was dropped — the advancer's only
/// distinction was `is_fatal()`, and it was round-tripping both back through `eyre::Error`
/// anyway, so the extra variant didn't earn its keep.
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

    /// Transient error during divergence search — RPC timeout, store I/O, etc. Caller
    /// retries the cycle.
    #[error(transparent)]
    Transient(#[from] eyre::Error),
}

impl From<StoreError> for DivergenceError {
    fn from(e: StoreError) -> Self {
        DivergenceError::Transient(e.into())
    }
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
/// Backend-agnostic: takes a [`DivergenceLookups`] for local chain reads (implemented
/// automatically for every [`ChainStore`]); remote reads go through the
/// `BlockFetcher`'s `eyre::Result`. [`DivergenceError`] wraps both.
#[instrument(skip_all, fields(mismatch_block), name = "find_divergence")]
pub async fn find_divergence_point<F, L>(
    fetcher: &F,
    lookups: &L,
    mismatch_block: u64,
) -> std::result::Result<u64, DivergenceError>
where
    F: BlockFetcher,
    L: DivergenceLookups + ?Sized,
{
    // Empty-chain is not reachable when the advancer calls us (it only triggers a reorg
    // after `current_tip` is set), but returning a typed fatal error keeps a future caller
    // from panicking the pipeline task.
    let earliest_local = lookups
        .get_earliest()?
        .ok_or(DivergenceError::LocalChainCorrupt { block_number: mismatch_block })?;

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
        let local_hash = lookups
            .get_hash(check_block)?
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
        let local_hash = lookups
            .get_hash(mid)?
            .ok_or(DivergenceError::LocalChainCorrupt { block_number: mid })?;
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
