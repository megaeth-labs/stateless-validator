//! Abstract persistence traits and data types — the **shared** storage contract every embedder
//! relies on. Only genuinely-common traits live here:
//! - [`ContractStore`]: Contract bytecode persistence (wrapped by the shared `ContractCache`).
//! - [`ChainStore`]: Chain-cursor management the pipeline drives on every scenario.
//!
//! Scenario-specific storage is implemented directly in the owning binary, NOT abstracted here:
//! genesis persistence (stateless-validator), block/witness storage + history pruning
//! (debug-trace-server), and reorg-floor resolution (mega-reth FullNode, via the pipeline's
//! [`ReorgResolver`](crate::pipeline::ReorgResolver) seam). The bisection contract for
//! history-owning stores is [`DivergenceLookups`](crate::pipeline::DivergenceLookups).
//!
//! Concrete implementations live in their respective binaries;
//! shared redb helpers live in the `stateless-db` crate.

use std::{boxed::Box, fmt, string::String, vec::Vec};

use alloy_primitives::{B256, BlockHash, BlockNumber, map::HashMap};
use revm::state::Bytecode;
use thiserror::Error;

/// Represents a point on the chain with its state roots.
///
/// Used for both the trusted anchor block and the canonical chain tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMeta {
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
    pub post_state_root: B256,
    pub post_withdrawals_root: B256,
}

impl BlockMeta {
    /// Projects an RPC header into the meta of the block it seals — a header's roots are that
    /// block's post-state. A missing `withdrawals_root` defaults to zero, the tip-observation
    /// policy both binaries use; callers that must instead *reject* such headers (e.g. anchor
    /// initialization from an operator-supplied hash) build the meta explicitly.
    pub fn from_header(header: &alloy_rpc_types_eth::Header) -> Self {
        Self {
            block_number: header.number,
            block_hash: header.hash,
            post_state_root: header.state_root,
            post_withdrawals_root: header.withdrawals_root.unwrap_or_default(),
        }
    }
}

/// Errors returned by persistence trait methods.
///
/// This is the single typed error at the library/binary boundary: every
/// [`ChainStore`] / … method returns `Result<_, StoreError>`.
/// Binary code converts to `eyre::Report` automatically via `?`.
///
/// Backend errors (redb, bincode, serde_json, lz4, …) are wrapped as an opaque
/// [`StoreError::Backend`] — the source chain is preserved via
/// [`core::error::Error::source`], so `%err` / `{:#}` logs show the root cause
/// without the trait layer needing to know the concrete backend type.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Backend(Box<dyn core::error::Error + Send + Sync + 'static>),

    #[error("missing {kind} for block {block_hash}")]
    MissingData { kind: MissingDataKind, block_hash: BlockHash },

    #[error("corrupt data: {0}")]
    Corrupt(String),
}

pub type StoreResult<T> = core::result::Result<T, StoreError>;

/// Adapter for turning any concrete backend error into [`StoreError::Backend`].
///
/// Use at boundary call sites that previously relied on `?` via a `#[from]` impl,
/// e.g. `database.begin_read().store_err()?`.
pub trait StoreResultExt<T> {
    fn store_err(self) -> StoreResult<T>;
}

impl<T, E: core::error::Error + Send + Sync + 'static> StoreResultExt<T>
    for core::result::Result<T, E>
{
    fn store_err(self) -> StoreResult<T> {
        self.map_err(|e| StoreError::Backend(Box::new(e)))
    }
}

/// Tag for [`StoreError::MissingData`] identifying which record is absent.
#[derive(Clone, Copy, Debug)]
pub enum MissingDataKind {
    Block,
    Witness,
}

impl fmt::Display for MissingDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MissingDataKind::Block => "block",
            MissingDataKind::Witness => "witness",
        })
    }
}

/// Result of a contract bytecode lookup: `(found, missing)`.
pub type ContractLookup = (HashMap<B256, Bytecode>, Vec<B256>);

/// Contract bytecode persistence.
///
/// Values are exchanged as plain `Bytecode`, not `Arc<Bytecode>`: `Bytecode` is already
/// internally reference-counted (its `Bytes` buffer and `JumpTable` are both `Arc`-backed),
/// so cloning is an O(1) refcount bump that shares the same allocation. An outer `Arc` would
/// only add a redundant layer of indirection and a second heap allocation per contract.
pub trait ContractStore: Send + Sync {
    fn get_contracts(&self, hashes: &[B256]) -> StoreResult<ContractLookup>;
    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> StoreResult<()>;
}

/// Chain-cursor management — the storage surface the pipeline drives on **every** scenario.
///
/// Holds only operations the generic pipeline calls directly: read the tip/anchor, append a
/// validated batch, read a block hash (for reorg reporting), roll back, and reset to
/// an anchor (stale-reset path). How a reorg *floor* is decided is NOT here — that's the
/// pipeline's [`ReorgResolver`](crate::pipeline::ReorgResolver) seam, which each scenario supplies.
/// History-owning stores additionally implement
/// [`DivergenceLookups`](crate::pipeline::DivergenceLookups) so the pipeline can bisect them.
/// Deliberately independent of [`ContractStore`]: a chain-cursor store (e.g. an embedder whose
/// bytecode integrity is enforced at ingest) need not stub contract persistence.
pub trait ChainStore: Send + Sync {
    fn get_canonical_tip(&self) -> StoreResult<Option<BlockMeta>>;
    fn get_anchor(&self) -> StoreResult<Option<BlockMeta>>;
    fn advance_chain(&self, blocks: &[BlockMeta]) -> StoreResult<()>;
    fn get_block_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>>;
    fn rollback_chain(&self, to_block: BlockNumber) -> StoreResult<()>;
    /// Reset anchor + tip to `anchor`. Called by the pipeline only on the stale-reset path
    /// (enabled via `PipelineConfig::stale_reset_threshold`); a trivial cursor write for stores
    /// that don't use it.
    fn reset_to_anchor(&self, anchor: &BlockMeta) -> StoreResult<()>;
}

#[cfg(test)]
mod tests {
    use std::string::ToString;

    use super::*;

    /// Minimal `core::error::Error` impl for tests that exercise `Backend` wrapping
    /// without pulling `std::io::Error` (which doesn't exist under no_std).
    #[derive(Debug)]
    struct TestErr(&'static str);
    impl fmt::Display for TestErr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    impl core::error::Error for TestErr {}

    #[test]
    fn test_block_meta_equality() {
        let a = BlockMeta {
            block_number: 10,
            block_hash: BlockHash::from([10u8; 32]),
            post_state_root: B256::from([11u8; 32]),
            post_withdrawals_root: B256::from([12u8; 32]),
        };
        let b = a.clone();
        let c = BlockMeta { block_number: 11, ..a.clone() };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_block_meta_clone() {
        let meta = BlockMeta {
            block_number: 5,
            block_hash: BlockHash::from([5u8; 32]),
            post_state_root: B256::from([6u8; 32]),
            post_withdrawals_root: B256::from([7u8; 32]),
        };
        assert_eq!(meta, meta.clone());
    }

    #[test]
    fn missing_data_kind_display() {
        assert_eq!(MissingDataKind::Block.to_string(), "block");
        assert_eq!(MissingDataKind::Witness.to_string(), "witness");
    }

    #[test]
    fn store_error_missing_data_display_includes_kind_and_hash() {
        let hash = BlockHash::from([0xAB; 32]);
        let err = StoreError::MissingData { kind: MissingDataKind::Witness, block_hash: hash };
        let s = err.to_string();
        assert!(s.contains("witness"), "missing kind tag: {s}");
        assert!(s.contains("0xab"), "missing hash hex: {s}");
    }

    #[test]
    fn store_error_corrupt_display() {
        let err = StoreError::Corrupt("bad bytes".into());
        assert_eq!(err.to_string(), "corrupt data: bad bytes");
    }

    #[test]
    fn store_error_backend_display_forwards_transparently() {
        // `#[error(transparent)]` makes Backend's Display delegate to the wrapped error —
        // no prefix, just the inner message.
        let inner = TestErr("disk full");
        let err: StoreError = Err::<(), _>(inner).store_err().unwrap_err();
        assert_eq!(err.to_string(), "disk full");
        assert!(matches!(err, StoreError::Backend(_)));
    }

    #[test]
    fn store_result_ext_passes_through_ok() {
        let r: StoreResult<u32> = Ok::<_, TestErr>(42).store_err();
        assert_eq!(r.unwrap(), 42);
    }
}
