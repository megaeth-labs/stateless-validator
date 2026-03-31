//! Storage trait abstractions for `ValidatorDB`.
//!
//! These traits decouple consumers from the concrete `redb`-backed `ValidatorDB` implementation,
//! enabling alternative backends (e.g., in-memory for testing) without changing consumer code.

use std::collections::HashMap;

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, Header};
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;

use crate::{
    executor::ValidationResult, light_witness::LightWitness, validator_db::ValidationDbResult,
    withdrawals::MptWitness,
};

/// Chain state management: tips, growth, rollback, genesis, anchor, and pruning.
///
/// Encapsulates the full lifecycle of chain state from initialization (genesis/anchor)
/// through synchronization (remote/local chain growth) to maintenance (rollback/pruning).
pub trait ChainState {
    /// Returns the highest block in the local canonical chain, or `None` if empty.
    fn get_local_tip(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>>;

    /// Returns the highest block in the remote (unvalidated) chain, or `None` if empty.
    fn get_remote_tip(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>>;

    /// Extends the remote chain with a consecutive sequence of unvalidated block headers.
    ///
    /// Each header's parent hash must match the current remote chain tip.
    fn grow_remote_chain(&self, headers: &[Header]) -> ValidationDbResult<()>;

    /// Extends the canonical chain with the next validated block from the remote chain.
    ///
    /// Returns `true` if a block was advanced, `false` if no work to do.
    fn grow_local_chain(&self) -> ValidationDbResult<bool>;

    /// Promotes the first remote chain block to canonical without validation.
    ///
    /// Used by debug-trace-server where blocks are trusted from upstream RPC.
    /// Returns `true` if a block was promoted, `false` if remote chain is empty.
    fn promote_remote_to_canonical(&self) -> ValidationDbResult<bool>;

    /// Rolls back both canonical and remote chains to the given block number.
    fn rollback_chain(&self, to_block: BlockNumber) -> ValidationDbResult<()>;

    /// Looks up a block hash by number in canonical chain first, then remote chain.
    fn get_block_hash(&self, block_number: BlockNumber) -> ValidationDbResult<Option<BlockHash>>;

    /// Returns the earliest (lowest) block in the canonical chain.
    fn get_earliest_local_block(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>>;

    /// Resets the chain to start from a trusted anchor block, clearing all chain state.
    fn reset_anchor_block(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        post_state_root: B256,
        post_withdrawals_root: B256,
    ) -> ValidationDbResult<()>;

    /// Returns the stored anchor block, or `None` if not set.
    fn get_anchor_block(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>>;

    /// Persists the genesis configuration.
    fn store_genesis(&self, genesis: &Genesis) -> ValidationDbResult<()>;

    /// Loads the genesis configuration, or `None` if not stored yet.
    fn load_genesis(&self) -> ValidationDbResult<Option<Genesis>>;

    /// Removes chain data older than the given block number.
    ///
    /// Returns the number of blocks pruned.
    fn prune_history(&self, before_block: BlockNumber) -> ValidationDbResult<u64>;
}

/// Validation task lifecycle: creation, claiming, and recovery.
///
/// Manages the queue of blocks pending validation, including both the full-validation
/// path (stateless-validator) and the data-only path (debug-trace-server).
pub trait TaskQueue {
    /// Queues blocks with full witness data for validation workers.
    fn add_validation_tasks(
        &self,
        tasks: &[(Block<Transaction>, SaltWitness, MptWitness)],
    ) -> ValidationDbResult<()>;

    /// Stores block data and light witnesses without creating validation tasks.
    ///
    /// Used by debug-trace-server where blocks are served for tracing, not validated.
    fn store_block_data(
        &self,
        tasks: &[(Block<Transaction>, LightWitness)],
    ) -> ValidationDbResult<()>;

    /// Atomically claims the next pending validation task.
    ///
    /// Returns `None` when no tasks are available.
    fn get_next_task(
        &self,
    ) -> ValidationDbResult<Option<(Block<Transaction>, SaltWitness, MptWitness)>>;

    /// Moves interrupted (in-progress) tasks back to the pending queue.
    fn recover_interrupted_tasks(&self) -> ValidationDbResult<()>;
}

/// Block and witness data retrieval, plus contract bytecode cache.
pub trait BlockDataStore {
    /// Retrieves block data and light witness for a given block hash.
    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> ValidationDbResult<(Block<Transaction>, LightWitness)>;

    /// Retrieves cached contract bytecodes.
    ///
    /// Returns `(found, missing)` where `found` maps code hashes to bytecodes and
    /// `missing` lists code hashes not present in the cache.
    fn get_contract_codes(
        &self,
        code_hashes: &[B256],
    ) -> ValidationDbResult<(HashMap<B256, Bytecode>, Vec<B256>)>;

    /// Stores contract bytecodes in the cache.
    fn add_contract_codes(&self, bytecodes: &[(B256, Bytecode)]) -> ValidationDbResult<()>;
}

/// Validation result storage and lookup.
pub trait ValidationResultStore {
    /// Records a completed validation and removes the task from the in-progress queue.
    fn complete_validation(&self, result: ValidationResult) -> ValidationDbResult<()>;

    /// Retrieves the validation result for a block, or `None` if not yet validated.
    fn get_validation_result(
        &self,
        block_hash: BlockHash,
    ) -> ValidationDbResult<Option<ValidationResult>>;
}
