//! InMemoryValidatorDB - Central coordination database for stateless blockchain validation
//!
//! This module implements the core database layer that coordinates between the chain synchronizer
//! and validation workers in the stateless validator architecture. It manages the complete
//! workflow from task creation to result, enabling parallel validation of blockchain blocks.
//!
//! ## Architecture Overview
//!
//! The InMemoryValidatorDB serves as the central workspace with two primary user types:
//! - **Chain Synchronizer**: Creates validation tasks, tracks chain progression, manages finality
//! - **Validation Workers**: Pull tasks, perform validation, store results
//!
//! ## Database Schema
//!
//! The database consists of 9 specialized tables:
//! - `task_list`: Queue of pending validation tasks (BlockNumber, BlockHash) → ()
//! - `block_data`: Complete block data required for validation (BlockHash → Block)
//! - `witnesses`: Cryptographic witness data for stateless validation (BlockHash → SaltWitness)
//! - `mpt_witnesses`: MPT witness data for withdrawal validation (BlockHash → MptWitness)
//! - `canonical_chain`: Local view of the canonical blockchain (BlockNumber → (BlockHash, PostStateRoot, PostWithdrawalsRoot))
//! - `remote_chain`: Remote chain used to guide chain advancement (BlockNumber → BlockHash)
//! - `block_records`: Complete history including forks for efficient pruning (BlockNumber, BlockHash) → ()
//! - `validation_results`: Outcomes with block identifiers and status (BlockHash → ValidationResult)
//! - `contracts`: On-demand contract bytecode cache (CodeHash → Bytecode)
//!
//! ## Chain Synchronization
//!
//! The system maintains two chains for efficient synchronization:
//! - **CANONICAL_CHAIN**: The locally confirmed canonical chain (validated blocks only)
//! - **REMOTE_CHAIN**: A lookahead chain with unvalidated blocks that stays ahead of CANONICAL_CHAIN
//!
//! **Workflow:**
//! 1. New blocks are received and added to REMOTE_CHAIN via `grow_remote_chain()` (unvalidated)
//! 2. Validation tasks are created for blocks in REMOTE_CHAIN
//! 3. Once validated successfully, blocks move from REMOTE_CHAIN to CANONICAL_CHAIN via `grow_local_chain()`
//! 4. Failed validations keep blocks in REMOTE_CHAIN until rollback or retry
//!
//! This architecture allows the chain synchronizer to receive and track new blocks while
//! validation happens asynchronously in the background.
//!
//! ## Key Operations
//!
//! **For Chain Synchronizer:**
//! - `grow_remote_chain()` - Add newly received unvalidated blocks to remote chain
//! - `add_validation_task()` - Queue blocks from remote chain for validation with witness data
//! - `grow_local_chain()` - Move successfully validated blocks from remote chain to canonical chain
//! - `rollback_chain()` - Handle chain reorganizations by rolling back both chains
//! - `get_validation_result()` - Retrieve validation outcomes for chain progression decisions
//! - `get_local_tip()` - Get the current local chain head
//! - `prune_history()` - Remove old block data to control storage usage
//! - `recover_interrupted_tasks()` - Move crashed worker tasks back to pending queue
//!
//! **For Validation Workers:**
//! - `get_next_task()` - Claim next validation task atomically with block and witness data
//! - `complete_validation()` - Store validation results and mark task as finished
//! - `add_contract_codes()` - Cache contract bytecodes needed during validation in batch
//! - `get_contract_codes()` - Retrieve cached contract bytecodes by code hashes in batch
use std::collections::{BTreeMap, HashMap};

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, Header};
use crossbeam_queue::SegQueue;
use dashmap::DashMap;
use op_alloy_rpc_types::Transaction;
use parking_lot::RwLock;
use quick_cache::sync::Cache;
use revm::state::Bytecode;
use salt::SaltWitness;

use crate::{
    executor::ValidationResult,
    validator_db::{MissingDataKind, ValidationDbError, ValidationDbResult},
    withdrawals::MptWitness,
};

/// High-performance in-memory storage backend for the stateless validator.
///
/// Uses lock-free and fine-grained concurrent data structures to eliminate
/// the single-writer bottleneck present in redb when multiple validation
/// workers contend for database access.
pub struct InMemoryValidatorDB {
    // Task coordination (lock-free)
    /// Queue of pending validation tasks - workers pop from this atomically
    task_list: SegQueue<(BlockNumber, BlockHash)>,

    // Block storage (sharded, concurrent)
    /// Complete block data required for validation
    block_data: DashMap<BlockHash, Block<Transaction>>,
    /// Cryptographic witness data for stateless validation
    witnesses: DashMap<BlockHash, SaltWitness>,
    /// MPT witness data for withdrawal validation
    mpt_witnesses: DashMap<BlockHash, MptWitness>,

    // Chain state (single writer, many readers)
    /// Local view of the canonical chain: BlockNumber -> (BlockHash, PostStateRoot, PostWithdrawalsRoot)
    canonical_chain: RwLock<BTreeMap<BlockNumber, (BlockHash, B256, B256)>>,
    /// Remote chain with unvalidated blocks
    remote_chain: RwLock<BTreeMap<BlockNumber, BlockHash>>,
    /// Complete record of all known blocks including forks
    block_records: DashMap<(BlockNumber, BlockHash), ()>,

    // Results & cache
    /// Outcomes of completed block validation attempts
    validation_results: DashMap<BlockHash, ValidationResult>,
    /// LRU cache of contract bytecode (max 1000 entries)
    contracts: Cache<B256, Bytecode>,
}

impl Default for InMemoryValidatorDB {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryValidatorDB {
    /// Create a new in-memory database instance.
    pub fn new() -> Self {
        Self {
            task_list: SegQueue::new(),
            block_data: DashMap::new(),
            witnesses: DashMap::new(),
            mpt_witnesses: DashMap::new(),
            canonical_chain: RwLock::new(BTreeMap::new()),
            remote_chain: RwLock::new(BTreeMap::new()),
            block_records: DashMap::new(),
            validation_results: DashMap::new(),
            contracts: Cache::new(1000),
        }
    }

    /// Queues blocks for validation by workers.
    ///
    /// This method stores blocks and their witness data, making them available
    /// for validation workers to process.
    ///
    /// # Arguments
    /// * `tasks` - A slice of tuples, each containing:
    ///   - `Block<Transaction>` - The complete block data including header and transactions
    ///   - `SaltWitness` - The SALT-based execution witness required for stateless validation
    ///   - `MptWitness` - The MPT-based witness required for withdrawal validation
    pub fn add_validation_tasks(&self, tasks: &[(Block<Transaction>, SaltWitness, MptWitness)]) {
        for (block, salt_witness, mpt_witness) in tasks {
            let block_number = block.header.number;
            let block_hash = block.header.hash;

            // Store block data and witnesses
            self.block_data.insert(block_hash, block.clone());
            self.witnesses.insert(block_hash, salt_witness.clone());
            self.mpt_witnesses.insert(block_hash, mpt_witness.clone());

            // Record the block and add to task queue
            self.block_records.insert((block_number, block_hash), ());
            self.task_list.push((block_number, block_hash));
        }
    }

    /// Stores multiple contract bytecodes in the cache
    ///
    /// Workers call this to populate the cache when they fetch new bytecodes,
    /// so future validations can retrieve it via get_contract_codes() instead
    /// of fetching externally. The code hash is computed automatically from
    /// the bytecode to ensure data integrity.
    pub fn add_contract_codes<'a>(&self, bytecodes: impl IntoIterator<Item = &'a Bytecode>) {
        for bytecode in bytecodes {
            let code_hash = bytecode.hash_slow();
            self.contracts.insert(code_hash, bytecode.clone());
        }
    }

    /// Extends the canonical chain with the next validated block
    ///
    /// Automatically gets the first block from the remote chain, verifies it has been
    /// successfully validated, and moves it to the canonical chain. Performs all necessary
    /// validations including parent hash matching and state root continuity.
    ///
    /// Returns `Ok(true)` if a block was advanced, `Ok(false)` if no work to do.
    pub fn grow_local_chain(&self) -> ValidationDbResult<bool> {
        let mut canonical_chain = self.canonical_chain.write();
        let mut remote_chain = self.remote_chain.write();

        // Get first remote block
        let (block_number, block_hash) = match remote_chain.first_key_value() {
            Some((&num, &hash)) => (num, hash),
            None => return Ok(false),
        };

        // Load block header and verify
        let block = self
            .block_data
            .get(&block_hash)
            .ok_or(ValidationDbError::MissingData {
                kind: MissingDataKind::BlockData,
                block_hash,
            })?;
        let header = &block.header;

        assert_eq!(header.number, block_number);
        assert_eq!(header.hash, block_hash);

        // Ensure block validation succeeded
        let result = match self.validation_results.get(&block_hash) {
            Some(data) => data.clone(),
            None => return Ok(false), // Validation not complete yet
        };

        if !result.success {
            return Err(ValidationDbError::FailedValidation(
                result.error_message.unwrap_or_else(|| {
                    "Validation failed but no error message was provided".to_string()
                }),
            ));
        }

        // Verify parent chain extension for non-genesis blocks
        if header.number > 0 {
            let (parent_post_state, parent_post_withdrawals) = canonical_chain
                .get(&(header.number - 1))
                .map(|(_, state, withdrawals)| (*state, *withdrawals))
                .expect("parent block must exist in canonical chain");

            if result.pre_state_root != parent_post_state {
                return Err(ValidationDbError::FailedValidation(format!(
                    "Pre-state root mismatch: expected {:?}, actual {:?}",
                    parent_post_state, result.pre_state_root
                )));
            }

            if result.pre_withdrawals_root != parent_post_withdrawals {
                return Err(ValidationDbError::FailedValidation(format!(
                    "Pre-withdrawals root mismatch: expected {:?}, actual {:?}",
                    parent_post_withdrawals, result.pre_withdrawals_root
                )));
            }
        }

        // Move block from remote to canonical chain
        canonical_chain.insert(
            header.number,
            (
                header.hash,
                result.post_state_root,
                result.post_withdrawals_root,
            ),
        );
        remote_chain.remove(&header.number);

        Ok(true)
    }

    /// Extends the remote chain with a sequence of unvalidated blocks.
    ///
    /// Adds newly received blocks to the remote chain for future validation.
    /// Verifies that each block's parent_hash matches the current remote chain
    /// tip to ensure proper chain extension.
    ///
    /// # Arguments
    /// * `headers` - A consecutive sequence of blocks to append.
    pub fn grow_remote_chain<'a, I>(&self, headers: I) -> ValidationDbResult<()>
    where
        I: IntoIterator<Item = &'a Header>,
    {
        let canonical_chain = self.canonical_chain.read();
        let mut remote_chain = self.remote_chain.write();

        // Compute parent block
        let (mut parent_number, mut parent_hash) =
            if let Some((&num, &hash)) = remote_chain.last_key_value() {
                (num, hash)
            } else if let Some((&num, (hash, _, _))) = canonical_chain.last_key_value() {
                (num, *hash)
            } else {
                (0, BlockHash::ZERO)
            };

        // Validate chain structure and insert each header
        for header in headers {
            if header.number != parent_number + 1 || header.parent_hash != parent_hash {
                return Err(ValidationDbError::InvalidChainExtension {
                    block_number: header.number,
                    expected_parent_hash: header.parent_hash,
                    actual_parent_hash: parent_hash,
                });
            }

            remote_chain.insert(header.number, header.hash);
            (parent_number, parent_hash) = (header.number, header.hash);
        }

        Ok(())
    }

    /// Rolls back the local chain view in response to chain reorg
    ///
    /// Removes blocks from both the remote chain and canonical chain when a reorg
    /// occurs, reverting to the specified block number.
    pub fn rollback_chain(&self, to_block: BlockNumber) {
        let mut canonical_chain = self.canonical_chain.write();
        let mut remote_chain = self.remote_chain.write();

        // Rollback canonical chain
        let canonical_to_remove: Vec<_> = canonical_chain
            .range((to_block + 1)..)
            .map(|(&k, _)| k)
            .collect();
        for block_number in canonical_to_remove {
            canonical_chain.remove(&block_number);
        }

        // Rollback remote chain
        let remote_to_remove: Vec<_> = remote_chain
            .range((to_block + 1)..)
            .map(|(&k, _)| k)
            .collect();
        for block_number in remote_to_remove {
            remote_chain.remove(&block_number);
        }
    }

    /// Records the completion of a validation task
    ///
    /// Called by workers when they finish validating a block. Stores the validation
    /// result and marks the task as complete.
    pub fn complete_validation(&self, result: ValidationResult) {
        self.validation_results.insert(result.block_hash, result);
    }

    /// Claims the next validation task atomically
    ///
    /// Workers call this to get the next block that needs validation. The method
    /// atomically moves the lowest block number task from the pending queue to the
    /// in-progress state, preventing other workers from claiming the same task.
    ///
    /// # Behavior:
    /// - Returns tasks in ascending block number order (lowest first)
    /// - Skips tasks with block numbers ≤ current canonical chain tip (stale tasks)
    /// - Stale tasks remain in TASK_LIST for potential reorg recovery
    /// - Atomically moves task from TASK_LIST to ONGOING_TASKS
    /// - Loads and deserializes the complete block data and witness
    /// - Returns None if no suitable tasks are available
    ///
    /// # Workflow:
    /// After claiming a task, workers should validate the block and call
    /// `complete_validation()` to record the result and mark the task finished.
    /// If a worker crashes, use `recover_interrupted_tasks()` to recover incomplete work.
    ///
    /// # Returns:
    /// - `Ok(Some((block, witness)))` - Next task with all required validation data
    /// - `Ok(None)` - No tasks available, worker should wait or exit
    /// - `Err(...)` - Database error, serialization failure, or missing block/witness data
    pub fn get_next_task(
        &self,
    ) -> ValidationDbResult<Option<(Block<Transaction>, SaltWitness, MptWitness)>> {
        // Get canonical tip to filter stale tasks
        let canonical_tip = self
            .canonical_chain
            .read()
            .last_key_value()
            .map(|(&k, _)| k);

        // Try to pop tasks until we find a valid one
        loop {
            let task = match self.task_list.pop() {
                Some(t) => t,
                None => return Ok(None),
            };

            let (block_number, block_hash) = task;

            // Skip stale tasks (already in canonical chain)
            if let Some(tip) = canonical_tip
                && block_number <= tip
            {
                continue;
            }

            // Load block data
            let block = self
                .block_data
                .get(&block_hash)
                .ok_or(ValidationDbError::MissingData {
                    kind: MissingDataKind::BlockData,
                    block_hash,
                })?
                .clone();

            // Load witness
            let witness = self
                .witnesses
                .get(&block_hash)
                .ok_or(ValidationDbError::MissingData {
                    kind: MissingDataKind::Witness,
                    block_hash,
                })?
                .clone();

            // Load MPT witness
            let mpt_witness = self
                .mpt_witnesses
                .get(&block_hash)
                .ok_or(ValidationDbError::MissingData {
                    kind: MissingDataKind::MptWitness,
                    block_hash,
                })?
                .clone();

            return Ok(Some((block, witness, mpt_witness)));
        }
    }

    /// Retrieves the validation result for a block
    ///
    /// Returns the validation outcome if available, or None if the block
    /// hasn't been validated yet.
    pub fn get_validation_result(&self, block_hash: BlockHash) -> Option<ValidationResult> {
        self.validation_results.get(&block_hash).map(|r| r.clone())
    }

    /// Gets the latest block in the local chain
    ///
    /// Returns the highest block number and hash currently considered local canonical,
    /// or None if the chain is empty.
    pub fn get_local_tip(&self) -> Option<(BlockNumber, BlockHash)> {
        self.canonical_chain
            .read()
            .last_key_value()
            .map(|(&num, (hash, _, _))| (num, *hash))
    }

    /// Gets the latest block in the remote chain
    ///
    /// Returns the highest block number and hash currently in the remote chain,
    /// or None if the remote chain is empty.
    pub fn get_remote_tip(&self) -> Option<(BlockNumber, BlockHash)> {
        self.remote_chain
            .read()
            .last_key_value()
            .map(|(&num, &hash)| (num, hash))
    }

    /// Resets the chain anchor point and clears all chain state
    ///
    /// This method resets the validator to start from a specific trusted block.
    /// It clears both the canonical chain and remote chain, then sets the new
    /// anchor block as the sole entry in the canonical chain. This ensures
    /// a clean slate. Useful for initialization from a trusted block.
    pub fn reset_anchor_block(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        post_state_root: B256,
        post_withdrawals_root: B256,
    ) {
        let mut canonical_chain = self.canonical_chain.write();
        let mut remote_chain = self.remote_chain.write();

        canonical_chain.clear();
        canonical_chain.insert(
            block_number,
            (block_hash, post_state_root, post_withdrawals_root),
        );
        remote_chain.clear();
    }

    /// Retrieves multiple cached contract bytecodes
    ///
    /// Returns a tuple of (found_contracts, missing_hashes) where:
    /// - `found_contracts`: HashMap mapping code hash to bytecode for all found contracts
    /// - `missing_hashes`: Vec of code hashes that were not found in the cache
    pub fn get_contract_codes(
        &self,
        code_hashes: impl IntoIterator<Item = B256>,
    ) -> (HashMap<B256, Bytecode>, Vec<B256>) {
        let mut found = HashMap::new();
        let mut missing = Vec::new();

        for code_hash in code_hashes {
            match self.contracts.get(&code_hash) {
                Some(bytecode) => {
                    found.insert(code_hash, bytecode);
                }
                None => missing.push(code_hash),
            }
        }

        (found, missing)
    }

    /// Cleans up old block data to save storage space
    ///
    /// Removes canonical chain entries, validation records, block data, and witnesses
    /// for blocks older than the specified block number.
    ///
    /// Returns the number of blocks that were actually pruned.
    pub fn prune_history(&self, before_block: BlockNumber) -> ValidationDbResult<u64> {
        let mut canonical_chain = self.canonical_chain.write();

        // Collect keys to remove
        let keys_to_remove: Vec<_> = self
            .block_records
            .iter()
            .filter(|entry| entry.key().0 < before_block)
            .map(|entry| *entry.key())
            .collect();

        let pruned_count = keys_to_remove.len() as u64;

        for (block_number, block_hash) in keys_to_remove {
            canonical_chain.remove(&block_number);
            self.block_records.remove(&(block_number, block_hash));
            self.block_data.remove(&block_hash);
            self.witnesses.remove(&block_hash);
            self.mpt_witnesses.remove(&block_hash);
            self.validation_results.remove(&block_hash);
        }

        Ok(pruned_count)
    }

    /// Retrieves the block hash for a specific block number from the local view
    ///
    /// Searches the local view which consists of two sequential, non-overlapping chains:
    /// - CANONICAL_CHAIN: Lower block numbers (validated blocks)
    /// - REMOTE_CHAIN: Higher block numbers (unvalidated blocks extending canonical)
    ///
    /// # Parameters
    /// * `block_number` - The block number to look up in the local view
    ///
    /// # Returns
    /// * `Ok(Some(block_hash))` - Block found at the specified number
    /// * `Ok(None)` - No block exists at this number in the local view
    /// * `Err(...)` - Database error during lookup
    pub fn get_block_hash(&self, block_number: BlockNumber) -> Option<BlockHash> {
        // Check canonical chain first
        if let Some((hash, _, _)) = self.canonical_chain.read().get(&block_number) {
            return Some(*hash);
        }

        // Then check remote chain
        self.remote_chain.read().get(&block_number).copied()
    }

    /// Retrieves the earliest block in the canonical chain
    ///
    /// Returns the lowest block number and its hash currently stored in the canonical
    /// chain. This is useful for reorg detection and determining the local chain's
    /// starting point. Only includes blocks that have been successfully validated.
    ///
    /// # Returns
    /// * `Ok(Some((block_number, block_hash)))` - Earliest block found with its number and hash
    /// * `Ok(None)` - Canonical chain is empty (no validated blocks)
    /// * `Err(...)` - Database error during lookup
    pub fn get_earliest_local_block(&self) -> Option<(BlockNumber, BlockHash)> {
        self.canonical_chain
            .read()
            .first_key_value()
            .map(|(&num, (hash, _, _))| (num, *hash))
    }
}
