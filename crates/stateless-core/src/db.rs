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

use std::{collections::HashMap, fmt};

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
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("redb database: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("redb transaction: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("redb table: {0}")]
    Table(#[from] redb::TableError),
    #[error("redb storage: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("redb commit: {0}")]
    Commit(#[from] redb::CommitError),

    #[error("bincode decode: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),
    #[error("bincode encode: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),
    #[error("serde_json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("missing {kind} for block {block_hash}")]
    MissingData { kind: MissingDataKind, block_hash: BlockHash },

    #[error("corrupt data: {0}")]
    Corrupt(String),
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;

/// Tag for [`StoreError::MissingData`] identifying which record is absent.
#[derive(Clone, Copy, Debug)]
pub enum MissingDataKind {
    BlockData,
    Witness,
}

impl fmt::Display for MissingDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MissingDataKind::BlockData => "block data",
            MissingDataKind::Witness => "witness",
        })
    }
}

/// Contract bytecode persistence.
pub trait ContractStore: Send + Sync {
    fn get_contracts(&self, hashes: &[B256]) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)>;
    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> StoreResult<()>;
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
}
