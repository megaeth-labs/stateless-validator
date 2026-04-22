//! Abstract persistence traits and data types for stateless validation.
//!
//! Defines the public API contract used by both binaries:
//! - [`ContractStore`]: Contract bytecode persistence
//! - [`GenesisStore`]: Genesis configuration persistence
//! - [`ChainStore`]: Core chain state management (shared by both binaries)
//! - [`BlockStore`]: Block/witness storage extension (debug-trace-server only)
//!
//! Concrete implementations live in their respective binaries;
//! shared redb helpers live in the `stateless-db` crate.

use std::{collections::HashMap, fmt, sync::Arc};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use thiserror::Error;

use crate::LightWitness;

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

/// Errors returned by persistence trait methods.
///
/// This is the single typed error at the library/binary boundary: every
/// [`ChainStore`] / [`BlockStore`] / … method returns `Result<_, StoreError>`.
/// Binary code converts to `eyre::Report` automatically via `?`.
///
/// Backend errors (redb, bincode, serde_json, lz4, …) are wrapped as an opaque
/// [`StoreError::Backend`] — the source chain is preserved via
/// [`std::error::Error::source`], so `%err` / `{:#}` logs show the root cause
/// without the trait layer needing to know the concrete backend type.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Backend(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("missing {kind} for block {block_hash}")]
    MissingData { kind: MissingDataKind, block_hash: BlockHash },

    #[error("corrupt data: {0}")]
    Corrupt(String),
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;

/// Adapter for turning any concrete backend error into [`StoreError::Backend`].
///
/// Use at boundary call sites that previously relied on `?` via a `#[from]` impl,
/// e.g. `database.begin_read().store_err()?`.
pub trait StoreResultExt<T> {
    fn store_err(self) -> StoreResult<T>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> StoreResultExt<T>
    for std::result::Result<T, E>
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
pub type ContractLookup = (HashMap<B256, Arc<Bytecode>>, Vec<B256>);

/// Contract bytecode persistence.
///
/// Values are exchanged as `Arc<Bytecode>` so the in-memory `ContractCache` and
/// downstream consumers (e.g. revm execution via `WitnessDatabase`) can share a
/// single allocation instead of deep-cloning bytecode on every cache hit.
pub trait ContractStore: Send + Sync {
    fn get_contracts(&self, hashes: &[B256]) -> StoreResult<ContractLookup>;
    fn add_contracts(&self, codes: &[(B256, Arc<Bytecode>)]) -> StoreResult<()>;
}

/// Genesis configuration persistence.
pub trait GenesisStore: Send + Sync {
    fn store_genesis(&self, genesis: &Genesis) -> StoreResult<()>;
    fn load_genesis(&self) -> StoreResult<Option<Genesis>>;
}

/// Core chain state management (shared by both binaries).
pub trait ChainStore: ContractStore {
    fn get_canonical_tip(&self) -> StoreResult<Option<BlockMeta>>;
    fn get_anchor(&self) -> StoreResult<Option<BlockMeta>>;
    fn advance_chain(&self, blocks: &[BlockMeta]) -> StoreResult<()>;
    fn get_block_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>>;
    fn get_earliest_block(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>>;
    fn rollback_chain(&self, to_block: BlockNumber) -> StoreResult<()>;
    fn reset_to_anchor(&self, anchor: &BlockMeta) -> StoreResult<()>;
}

/// History pruning (debug-trace-server only, where explicit pruning is needed).
///
/// `ValidatorDB` does not implement this because it uses inline pruning
/// in [`ChainStore::advance_chain`] instead.
pub trait PrunableChainStore: ChainStore {
    fn prune_chain(&self, before_block: BlockNumber) -> StoreResult<u64>;
}

/// Block/witness storage extension (debug-trace-server only).
pub trait BlockStore: PrunableChainStore {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()>;
    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> StoreResult<(Block<Transaction>, LightWitness)>;
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let io = std::io::Error::other("disk full");
        let err: StoreError = Err::<(), _>(io).store_err().unwrap_err();
        assert_eq!(err.to_string(), "disk full");
        assert!(matches!(err, StoreError::Backend(_)));
    }

    #[test]
    fn store_result_ext_passes_through_ok() {
        let r: StoreResult<u32> = Ok::<_, std::io::Error>(42).store_err();
        assert_eq!(r.unwrap(), 42);
    }
}
