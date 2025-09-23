//! ValidatorDB2 - Central coordination database for stateless blockchain validation
//!
//! This module implements the core database layer that coordinates between the chain synchronizer
//! and validation workers in the stateless validator architecture. It manages the complete
//! workflow from task creation to result storage, enabling parallel validation of blockchain blocks.
//!
//! ## Architecture Overview
//!
//! The ValidatorDB2 serves as the central workspace with two primary user types:
//! - **Chain Synchronizer**: Creates validation tasks, tracks chain progression, manages finality
//! - **Validation Workers**: Pull tasks, perform validation, store results
//!
//! ## Database Schema
//!
//! The database consists of 8 specialized tables:
//! - `CANONICAL_CHAIN`: Local view of the canonical blockchain (BlockNumber → BlockHash)
//! - `REMOTE_CHAIN`: Remote chain used to guide chain advancement (BlockNumber → BlockHash)
//! - `TASK_LIST`: Queue of pending validation tasks (BlockNumber, BlockHash) → ()
//! - `ONGOING_TASKS`: Tasks currently being processed by workers
//! - `BLOCK_DATA`: Complete block data required for validation (BlockHash → Block)
//! - `WITNESSES`: Cryptographic witness data for stateless validation (BlockHash → SaltWitness)
//! - `VALIDATION_RESULTS`: Outcomes with block identifiers and status (BlockHash → ValidationResult)
//! - `BLOCK_RECORDS`: Complete history including forks for efficient pruning (BlockNumber, BlockHash) → ()
//! - `CONTRACTS`: On-demand contract bytecode cache (CodeHash → Bytecode)
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
//! - `add_contract_code()` - Cache contract bytecode needed during validation
//! - `get_contract_code()` - Retrieve cached contract bytecode by code hash

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, Header};
use eyre::{Result, anyhow};
use op_alloy_rpc_types::Transaction;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use revm::state::Bytecode;
use salt::SaltWitness;
use serde::{Deserialize, Serialize};
use serde_json;

/// Stores our local view of the canonical chain.
///
/// **Schema:** Maps BlockNumber (u64) to BlockHash ([u8; 32])
/// - Key: Block height as BlockNumber (u64)
/// - Value: Hash of the canonical block at that height as BlockHash ([u8; 32])
///
/// Updated by main orchestrator via grow_local_chain() and rollback_chain().
/// Only successfully validated blocks can be added to this chain.
const CANONICAL_CHAIN: TableDefinition<u64, [u8; 32]> = TableDefinition::new("canonical_chain");

/// Stores the remote chain with unvalidated blocks used to guide chain advancement.
///
/// **Schema:** Maps BlockNumber (u64) to BlockHash ([u8; 32])
/// - Key: Block height as BlockNumber (u64)
/// - Value: Hash of the remote block at that height as BlockHash ([u8; 32])
///
/// Contains newly received blocks that have not yet been validated. The chain synchronizer
/// maintains this table to stay a few blocks ahead of CANONICAL_CHAIN. Once blocks in
/// REMOTE_CHAIN are validated, they can be moved to CANONICAL_CHAIN via grow_local_chain().
/// Updated via grow_remote_chain() (add unvalidated blocks) and rollback_chain().
const REMOTE_CHAIN: TableDefinition<u64, [u8; 32]> = TableDefinition::new("remote_chain");

/// Queue of validation tasks awaiting processing by workers.
///
/// **Schema:** Maps (BlockNumber, BlockHash) as (u64, [u8; 32]) to unit type (())
/// - Key: (Block number, Block hash) as (BlockNumber as u64, BlockHash as [u8; 32])
/// - Value: Unit type (()) - presence in table indicates pending task
///
/// Tasks are automatically ordered by block number. Workers call get_next_task()
/// to atomically move tasks from here to ONGOING_TASKS. Added by main orchestrator
/// via add_validation_task().
const TASK_LIST: TableDefinition<(u64, [u8; 32]), ()> = TableDefinition::new("task_list");

/// Tasks currently being processed by validation workers.
///
/// **Schema:** Maps (BlockNumber, BlockHash) as (u64, [u8; 32]) to unit type (())
/// - Key: (Block number, Block hash) as (BlockNumber as u64, BlockHash as [u8; 32])
/// - Value: Unit type (()) - presence in table indicates task in progress
///
/// Prevents duplicate work on the same block. Tasks moved here from TASK_LIST
/// during get_next_task() and removed on completion. Moved back to TASK_LIST
/// during crash recovery via recover_interrupted_tasks().
const ONGOING_TASKS: TableDefinition<(u64, [u8; 32]), ()> = TableDefinition::new("ongoing_tasks");

/// Complete block data required for validation execution.
///
/// **Schema:** Maps BlockHash ([u8; 32]) to serialized Block<Transaction> (Vec<u8>)
/// - Key: Block hash as BlockHash ([u8; 32])
/// - Value: Serialized Block<Transaction> data as Vec<u8>
///
/// Stores serialized Block<Transaction> data including headers and transactions.
/// Retrieved by workers during validation and pruned via prune_history()
/// to control storage usage.
const BLOCK_DATA: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("block_data");

/// Witness data required for stateless blockchain validation.
///
/// **Schema:** Maps BlockHash ([u8; 32]) to serialized SaltWitness (Vec<u8>)
/// - Key: Block hash as BlockHash ([u8; 32])
/// - Value: Serialized SaltWitness data as Vec<u8>
///
/// Contains cryptographic proofs and state information that enables validation
/// without full blockchain state. Retrieved alongside block data during
/// get_next_task() for validation execution.
const WITNESSES: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("witnesses");

/// Outcomes of completed block validation attempts.
///
/// **Schema:** Maps BlockHash ([u8; 32]) to serialized ValidationResult (Vec<u8>)
/// - Key: Block hash as BlockHash ([u8; 32])
/// - Value: Serialized ValidationResult struct as Vec<u8>
///
/// Records success/failure, block identifiers, and error details. Written by
/// workers via complete_validation() and read by orchestrator to make chain
/// progression decisions.
const VALIDATION_RESULTS: TableDefinition<[u8; 32], Vec<u8>> =
    TableDefinition::new("validation_results");

/// Complete record of all known blocks, including forks.
///
/// **Schema:** Maps (BlockNumber, BlockHash) as (u64, [u8; 32]) to unit type (())
/// - Key: (Block number, Block hash) as (BlockNumber as u64, BlockHash as [u8; 32])
/// - Value: Unit type (()) - presence in table indicates known block
///
/// Tracks multiple blocks at the same height during forks. Used for
/// efficient pruning operations and fork handling. CANONICAL_CHAIN
/// entries are a subset of this table.
const BLOCK_RECORDS: TableDefinition<(u64, [u8; 32]), ()> = TableDefinition::new("block_records");

/// Cache of contract bytecode fetched on-demand during validation.
///
/// **Schema:** Maps code hash as B256 ([u8; 32]) to serialized Bytecode (Vec<u8>)
/// - Key: Contract code hash as B256 ([u8; 32])
/// - Value: Serialized contract Bytecode as Vec<u8>
///
/// Improves performance by avoiding repeated fetches of the same contracts.
/// Populated by workers via add_contract_code() when new bytecode is needed
/// and retrieved via get_contract_code().
const CONTRACTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("contracts");

/// Represents the result of a validation operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// The pre-state root from the witness before block execution
    pub pre_state_root: B256,
    /// The post-state root after block execution (from block header)
    pub post_state_root: B256,
    /// The block number that was validated
    pub block_number: BlockNumber,
    /// The block hash that was validated
    pub block_hash: BlockHash,
    /// Whether the validation was successful
    pub success: bool,
    /// Any error message if validation failed
    pub error_message: Option<String>,
    /// Timestamp when validation completed
    pub completed_at: u64,
}

/// ValidatorDB2 - The central workspace for coordination between components
///
/// Provides the database interface according to the design document for:
/// - Main orchestrator to store validation tasks and retrieve results
/// - Validation workers to pull tasks and store results
pub struct ValidatorDB2 {
    /// The embedded redb database
    database: Database,
}

impl ValidatorDB2 {
    /// Create a new redb instance or open an existing one.
    ///
    /// Opens the database file at the given path. If the file already contains
    /// a valid redb database, it will be opened preserving all existing data.
    /// If the file doesn't exist or is empty, a new database will be created
    /// and initialized with all required tables.
    pub fn new(db_path: impl AsRef<std::path::Path>) -> Result<Self> {
        let database = Database::create(db_path)?;

        // Initialize all tables in a single write transaction
        let write_txn = database.begin_write()?;
        {
            // The table initialization process is safe for existing databases - it
            // ensures all required tables exist but does not overwrite existing data.
            let _canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let _remote_chain = write_txn.open_table(REMOTE_CHAIN)?;
            let _task_list = write_txn.open_table(TASK_LIST)?;
            let _ongoing_tasks = write_txn.open_table(ONGOING_TASKS)?;
            let _block_data = write_txn.open_table(BLOCK_DATA)?;
            let _witnesses = write_txn.open_table(WITNESSES)?;
            let _validation_results = write_txn.open_table(VALIDATION_RESULTS)?;
            let _block_records = write_txn.open_table(BLOCK_RECORDS)?;
            let _contracts = write_txn.open_table(CONTRACTS)?;
        }
        write_txn.commit()?;

        Ok(Self { database })
    }

    /// Queues a block for validation by workers
    ///
    /// This method stores a block and its witness data, making them available
    /// for validation workers to process.
    ///
    /// # Arguments:
    /// * `block` - The complete block data including header and transactions
    /// * `witness` - The execution witness required for stateless validation
    pub fn add_validation_task(
        &self,
        block: &Block<Transaction>,
        witness: &SaltWitness,
    ) -> Result<()> {
        let block_number = block.header.number;
        let block_hash = block.header.hash.0;

        let write_txn = self.database.begin_write()?;
        {
            // Adds the block to the validation task queue (TASK_LIST)
            let mut task_list = write_txn.open_table(TASK_LIST)?;
            task_list.insert((block_number, block_hash), ())?;

            // Stores the complete block data for worker access (BLOCK_DATA)
            let mut block_data = write_txn.open_table(BLOCK_DATA)?;
            let serialized_block = encode_block_to_vec(block)?;
            block_data.insert(block_hash, serialized_block)?;

            // ... and the cryptographic witness (WITNESSES)
            let mut witnesses = write_txn.open_table(WITNESSES)?;
            let serialized_witness = encode_to_vec(witness)?;
            witnesses.insert(block_hash, serialized_witness)?;

            // Records the block in the block registry (BLOCK_RECORDS)
            let mut block_records = write_txn.open_table(BLOCK_RECORDS)?;
            block_records.insert((block_number, block_hash), ())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Stores contract bytecode in the cache
    ///
    /// Workers call this to populate the cache when they fetch new bytecode,
    /// so future validations can retrieve it via get_contract_code() instead
    /// of fetching externally. The code hash is computed automatically from
    /// the bytecode to ensure data integrity.
    pub fn add_contract_code(&self, bytecode: &Bytecode) -> Result<()> {
        let code_hash = bytecode.hash_slow();

        let write_txn = self.database.begin_write()?;
        {
            let mut contracts = write_txn.open_table(CONTRACTS)?;
            let serialized_bytecode = encode_to_vec(bytecode)?;
            contracts.insert(code_hash.0, serialized_bytecode)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Extends the canonical chain with the next validated block
    ///
    /// Automatically gets the first block from the remote chain, verifies it has been
    /// successfully validated, and moves it to the canonical chain. Performs all necessary
    /// validations including parent hash matching and state root continuity.
    pub fn grow_local_chain(&self) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let mut remote_chain = write_txn.open_table(REMOTE_CHAIN)?;
            let validation_results = write_txn.open_table(VALIDATION_RESULTS)?;
            let block_data = write_txn.open_table(BLOCK_DATA)?;

            // Get the first block from remote chain (next block to advance)
            let (first_block_number, first_block_hash) = {
                let first_remote_entry = remote_chain
                    .first()?
                    .ok_or_else(|| anyhow!("Remote chain is empty"))?;
                (first_remote_entry.0.value(), first_remote_entry.1.value())
            };

            let block_hash = BlockHash::from(first_block_hash);

            // Load the block data to get the header
            let serialized_block = block_data
                .get(first_block_hash)?
                .ok_or_else(|| anyhow!("Block data not found for hash {block_hash}"))?;
            let block: Block<Transaction> = decode_block_from_slice(&serialized_block.value())?;
            let header = block.header;

            // Verify the header matches the remote chain entry
            if header.number != first_block_number {
                return Err(anyhow!(
                    "Block number mismatch: header has {}, remote chain has {first_block_number}",
                    header.number
                ));
            }

            if header.hash != first_block_hash {
                return Err(anyhow!(
                    "Block hash mismatch: header has {}, remote chain has {block_hash}",
                    header.hash
                ));
            }

            // Ensure block is successfully validated
            let serialized_result = validation_results
                .get(block_hash.0)?
                .ok_or_else(|| anyhow!("Block {block_hash} not validated"))?;
            let result: ValidationResult = decode_from_slice(&serialized_result.value())?;

            if !result.success {
                return Err(anyhow!("Cannot grow chain with failed validation"));
            }

            // Verify parent chain extension for canonical chain
            if header.number > 0 {
                let parent_hash = canonical_chain
                    .get(header.number - 1)?
                    .ok_or_else(|| anyhow!("Parent block not in canonical chain"))?
                    .value();

                if header.parent_hash != parent_hash {
                    return Err(anyhow!("Block parent_hash mismatch"));
                }

                // Verify pre-state root matches parent block's post-state root
                let parent_result_data = validation_results
                    .get(parent_hash)?
                    .ok_or_else(|| anyhow!("Parent block validation result not found"))?;
                let parent_result: ValidationResult =
                    decode_from_slice(&parent_result_data.value())?;

                // The parent's post-state root should match this block's pre-state root
                if result.pre_state_root != parent_result.post_state_root {
                    return Err(anyhow!(
                        "State root continuity broken: block expects pre-state {}, parent computed {}",
                        result.pre_state_root,
                        parent_result.post_state_root
                    ));
                }
            }

            // Move block from remote chain to canonical chain
            canonical_chain.insert(header.number, block_hash.0)?;
            remote_chain.remove(header.number)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Grows the remote chain with an unvalidated block
    ///
    /// Adds a newly received block to the remote chain for future validation.
    /// The block does not need to be validated yet - validation happens later.
    /// Verifies that the block's parent_hash matches the current remote chain tip
    /// or canonical chain tip to ensure proper chain extension.
    pub fn grow_remote_chain(&self, header: &Header) -> Result<()> {
        let block_hash = BlockHash::from(header.hash);

        let write_txn = self.database.begin_write()?;
        {
            let canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let mut remote_chain = write_txn.open_table(REMOTE_CHAIN)?;

            // Compute parent block (from remote chain if not empty, otherwise canonical chain)
            let (parent_number, parent_hash) = if let Some(last_remote) = remote_chain.last()? {
                (last_remote.0.value(), last_remote.1.value())
            } else if let Some(last_canonical) = canonical_chain.last()? {
                (last_canonical.0.value(), last_canonical.1.value())
            } else {
                return Err(anyhow!("Cannot extend from empty chains"));
            };

            // Validate extension
            if header.number != parent_number + 1 || header.parent_hash != parent_hash {
                return Err(anyhow!(
                    "Block does not properly extend from parent (number: {number}, expected: {expected})",
                    number = header.number,
                    expected = parent_number + 1
                ));
            }

            remote_chain.insert(header.number, block_hash.0)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Rolls back the local chain view in response to chain reorg
    ///
    /// Removes blocks from both the remote chain and canonical chain when a reorg
    /// occurs, reverting to the specified block number.
    pub fn rollback_chain(&self, to_block: BlockNumber) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let mut remote_chain = write_txn.open_table(REMOTE_CHAIN)?;

            // Rollback canonical chain to specified block
            let canonical_blocks_to_remove = canonical_chain
                .range((to_block + 1)..)?
                .map(|result| result.map(|(block_number, _)| block_number.value()))
                .collect::<Result<Vec<_>, _>>()?;

            for block_number in canonical_blocks_to_remove {
                canonical_chain.remove(block_number)?;
            }

            // Rollback remote chain to specified block
            let remote_blocks_to_remove = remote_chain
                .range((to_block + 1)..)?
                .map(|result| result.map(|(block_number, _)| block_number.value()))
                .collect::<Result<Vec<_>, _>>()?;

            for block_number in remote_blocks_to_remove {
                remote_chain.remove(block_number)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Records the completion of a validation task
    ///
    /// Called by workers when they finish validating a block. Stores the validation
    /// result and marks the task as complete.
    pub fn complete_validation(&self, result: ValidationResult) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            // Store validation result
            let mut validation_results = write_txn.open_table(VALIDATION_RESULTS)?;
            validation_results.insert(result.block_hash.0, encode_to_vec(&result)?)?;

            // Remove from ongoing tasks
            let mut ongoing_tasks = write_txn.open_table(ONGOING_TASKS)?;
            ongoing_tasks.remove((result.block_number, result.block_hash.0))?;
        }
        write_txn.commit()?;
        Ok(())
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
    pub fn get_next_task(&self) -> Result<Option<(Block<Transaction>, SaltWitness)>> {
        let write_txn = self.database.begin_write()?;

        let result = {
            let mut task_list = write_txn.open_table(TASK_LIST)?;
            let mut ongoing_tasks = write_txn.open_table(ONGOING_TASKS)?;
            let canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;

            // Get first task that's ahead of canonical tip using range query
            let range_start = match canonical_chain.last()?.map(|(bn, _)| bn.value()) {
                Some(tip_block) => (tip_block + 1, [0u8; 32]),
                None => (0u64, [0u8; 32]),
            };

            // Find first valid task
            let next_task = task_list
                .range(range_start..)?
                .next()
                .transpose()?
                .map(|(task_key, _)| task_key.value());

            match next_task {
                Some(block_num_hash) => {
                    let (_, block_hash) = block_num_hash;

                    // Move task to ongoing
                    task_list.remove(block_num_hash)?;
                    ongoing_tasks.insert(block_num_hash, ())?;

                    // Load block data and witness
                    let block_data = write_txn.open_table(BLOCK_DATA)?;
                    let witnesses = write_txn.open_table(WITNESSES)?;

                    let block = decode_block_from_slice(
                        &block_data
                            .get(block_hash)?
                            .ok_or_else(|| anyhow!("Block data not found"))?
                            .value(),
                    )?;
                    let witness = decode_from_slice(
                        &witnesses
                            .get(block_hash)?
                            .ok_or_else(|| anyhow!("Witness not found"))?
                            .value(),
                    )?;

                    Some((block, witness))
                }
                None => None,
            }
        };

        write_txn.commit()?;
        Ok(result)
    }

    /// Retrieves the validation result for a block
    ///
    /// Returns the validation outcome if available, or None if the block
    /// hasn't been validated yet.
    pub fn get_validation_result(&self, block_hash: BlockHash) -> Result<Option<ValidationResult>> {
        let read_txn = self.database.begin_read()?;
        let validation_results = read_txn.open_table(VALIDATION_RESULTS)?;

        match validation_results.get(block_hash.0)? {
            Some(serialized_result) => Ok(Some(decode_from_slice(&serialized_result.value())?)),
            None => Ok(None),
        }
    }

    /// Gets the latest block in the local chain
    ///
    /// Returns the highest block number and hash currently considered local canonical,
    /// or None if the chain is empty.
    pub fn get_local_tip(&self) -> Result<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let canonical_chain = read_txn.open_table(CANONICAL_CHAIN)?;

        match canonical_chain.last()? {
            Some((block_number, block_hash)) => {
                Ok(Some((block_number.value(), block_hash.value().into())))
            }
            None => Ok(None),
        }
    }

    /// Gets the latest block in the remote chain
    ///
    /// Returns the highest block number and hash currently in the remote chain,
    /// or None if the remote chain is empty.
    pub fn get_remote_tip(&self) -> Result<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let remote_chain = read_txn.open_table(REMOTE_CHAIN)?;

        match remote_chain.last()? {
            Some((block_number, block_hash)) => {
                Ok(Some((block_number.value(), block_hash.value().into())))
            }
            None => Ok(None),
        }
    }

    /// Sets the local chain tip manually
    ///
    /// This method allows setting the local chain tip to a specific block.
    /// Useful for initialization and testing scenarios.
    pub fn set_local_tip(&self, block_number: BlockNumber, block_hash: BlockHash) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            canonical_chain.insert(block_number, block_hash.0)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieves cached contract bytecode
    ///
    /// Returns the bytecode for a contract if it's been cached, or None if not found.
    /// Used by validation workers to avoid repeatedly fetching the same contracts.
    pub fn get_contract_code(&self, code_hash: B256) -> Result<Option<Bytecode>> {
        let read_txn = self.database.begin_read()?;
        let contracts = read_txn.open_table(CONTRACTS)?;

        match contracts.get(code_hash.0)? {
            Some(serialized_bytecode) => Ok(Some(decode_from_slice(&serialized_bytecode.value())?)),
            None => Ok(None),
        }
    }

    /// Cleans up old block data to save storage space
    ///
    /// Removes canonical chain entries, validation records, block data, and witnesses
    /// for blocks older than the specified block number.
    pub fn prune_history(&self, before_block: BlockNumber) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let mut block_records = write_txn.open_table(BLOCK_RECORDS)?;
            let mut block_data = write_txn.open_table(BLOCK_DATA)?;
            let mut witnesses = write_txn.open_table(WITNESSES)?;
            let mut validation_results = write_txn.open_table(VALIDATION_RESULTS)?;

            // Collect keys to remove (blocks older than before_block)
            let keys_to_remove = block_records
                .range(..(before_block, [0u8; 32]))?
                .map(|result| result.map(|(key, _)| key.value()))
                .collect::<Result<Vec<_>, _>>()?;

            for (block_number, block_hash) in keys_to_remove {
                // Remove from all relevant tables
                canonical_chain.remove(block_number)?;
                block_records.remove((block_number, block_hash))?;
                block_data.remove(block_hash)?;
                witnesses.remove(block_hash)?;
                validation_results.remove(block_hash)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Recovers tasks that were interrupted by a crash
    ///
    /// Moves any tasks that were being processed back to the queue so they can be
    /// retried. Use this during startup to handle unfinished work from crashes.
    pub fn recover_interrupted_tasks(&self) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut task_list = write_txn.open_table(TASK_LIST)?;
            let mut ongoing_tasks = write_txn.open_table(ONGOING_TASKS)?;

            while let Some((task, _)) = ongoing_tasks.pop_first()? {
                task_list.insert(task.value(), ())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}

/// Helper method to serialize data using bincode with legacy config
fn encode_to_vec<T: serde::Serialize>(data: &T) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(data, bincode::config::legacy())
        .map_err(|e| anyhow!("Failed to serialize data: {e}"))
}

/// Helper method to deserialize data using bincode with legacy config
fn decode_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
        .map_err(|e| anyhow!("Failed to deserialize data: {e}"))
        .map(|(data, _)| data)
}

/// Helper method to serialize Block<Transaction> using JSON
fn encode_block_to_vec(block: &Block<Transaction>) -> Result<Vec<u8>> {
    serde_json::to_vec(block).map_err(|e| anyhow!("Failed to serialize block to JSON: {e}"))
}

/// Helper method to deserialize Block<Transaction> using JSON
fn decode_block_from_slice(bytes: &[u8]) -> Result<Block<Transaction>> {
    serde_json::from_slice(bytes).map_err(|e| anyhow!("Failed to deserialize block from JSON: {e}"))
}
