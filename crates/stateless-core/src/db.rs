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

use std::collections::HashMap;

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;

use crate::{LightWitness, withdrawals::MptWitness};

// ===========================================================================
// Data types
// ===========================================================================

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
    /// Converts to a raw tuple for redb storage.
    pub fn to_tuple(&self) -> (u64, [u8; 32], [u8; 32], [u8; 32]) {
        (self.block_number, self.block_hash.0, self.post_state_root.0, self.post_withdrawals_root.0)
    }

    /// Reconstructs from a raw redb tuple.
    pub fn from_tuple(t: (u64, [u8; 32], [u8; 32], [u8; 32])) -> Self {
        Self {
            block_number: t.0,
            block_hash: BlockHash::from(t.1),
            post_state_root: B256::from(t.2),
            post_withdrawals_root: B256::from(t.3),
        }
    }
}

/// Block with all data needed for validation, flowing through the fetch→worker channel.
#[derive(Clone, Debug)]
pub struct ValidationTask {
    pub block: Block<Transaction>,
    pub salt_witness: SaltWitness,
    pub mpt_witness: MptWitness,
}

/// Result of successfully validating a block, flowing through the worker→advancer channel.
#[derive(Debug, Clone)]
pub struct ValidatedBlock {
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
    pub post_state_root: B256,
    pub post_withdrawals_root: B256,
    pub pre_state_root: B256,
    pub pre_withdrawals_root: B256,
}

/// Validation failure sent from worker to advancer.
#[derive(Debug)]
pub struct ValidationFailure {
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
    pub error: String,
}

// ===========================================================================
// Traits
// ===========================================================================

/// Contract bytecode persistence.
pub trait ContractStore: Send + Sync {
    fn get_contracts(&self, hashes: &[B256]) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)>;
    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()>;
}

/// Genesis configuration persistence.
pub trait GenesisStore: Send + Sync {
    fn store_genesis(&self, genesis: &Genesis) -> eyre::Result<()>;
    fn load_genesis(&self) -> eyre::Result<Option<Genesis>>;
}

/// Core chain state management (shared by both binaries).
pub trait ChainStore: ContractStore {
    fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>>;
    fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>>;
    fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()>;
    fn get_block_hash(&self, block_number: BlockNumber) -> eyre::Result<Option<BlockHash>>;
    fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>>;
    fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()>;
    fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()>;
}

/// History pruning (debug-trace-server only, where explicit pruning is needed).
///
/// `ValidatorDB` does not implement this because it uses inline pruning
/// in [`ChainStore::advance_chain`] instead.
pub trait PrunableChainStore: ChainStore {
    fn prune_chain(&self, before_block: BlockNumber) -> eyre::Result<u64>;
}

/// Block/witness storage extension (debug-trace-server only).
pub trait BlockStore: PrunableChainStore {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> eyre::Result<()>;
    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> eyre::Result<(Block<Transaction>, LightWitness)>;
}
