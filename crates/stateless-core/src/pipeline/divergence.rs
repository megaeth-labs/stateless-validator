//! Finds the point where the local chain diverges from the remote.

use alloy_primitives::{BlockHash, BlockNumber};
use tracing::{debug, instrument};

use crate::{db::StoreError, pipeline::traits::BlockFetcher};

/// Errors from [`find_divergence_point`], classified for the pipeline.
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

    /// Transient RPC error during divergence search (e.g., timeout).
    #[error(transparent)]
    Rpc(#[from] eyre::Error),

    /// Transient local-store error during divergence search.
    #[error(transparent)]
    Store(#[from] StoreError),
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
/// Backend-agnostic: takes closures for local chain lookups that return [`StoreResult`],
/// while remote lookups use the `BlockFetcher`'s `eyre::Result`.
/// [`DivergenceError`] converts from both via `#[from]`.
#[instrument(skip_all, fields(mismatch_block), name = "find_divergence")]
pub async fn find_divergence_point<F: BlockFetcher>(
    fetcher: &F,
    get_hash: &(dyn Fn(u64) -> crate::db::StoreResult<Option<BlockHash>> + Send + Sync),
    get_earliest: &(
         dyn Fn() -> crate::db::StoreResult<Option<(BlockNumber, BlockHash)>> + Send + Sync
     ),
    mismatch_block: u64,
) -> std::result::Result<u64, DivergenceError> {
    let earliest_local = get_earliest()?.expect("Local chain cannot be empty");

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
        let local_hash = get_hash(check_block)?
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
        let local_hash =
            get_hash(mid)?.ok_or(DivergenceError::LocalChainCorrupt { block_number: mid })?;
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
