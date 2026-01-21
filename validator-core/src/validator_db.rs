//! ValidatorDB - Central coordination database for stateless blockchain validation
//!
//! This module implements the core database layer that coordinates between the chain synchronizer
//! and validation workers in the stateless validator architecture. It manages the complete
//! workflow from task creation to result storage, enabling parallel validation of blockchain blocks.
//!
//! ## Architecture Overview
//!
//! The ValidatorDB serves as the central workspace with two primary user types:
//! - **Chain Synchronizer**: Creates validation tasks, tracks chain progression, manages finality
//! - **Validation Workers**: Pull tasks, perform validation, store results
//!
//! ## Database Schema
//!
//! The database consists of 9 specialized tables:
//! - `CANONICAL_CHAIN`: Local view of the canonical blockchain (BlockNumber → (BlockHash, PostStateRoot, PostWithdrawalsRoot))
//! - `REMOTE_CHAIN`: Remote chain used to guide chain advancement (BlockNumber → BlockHash)
//! - `TASK_LIST`: Queue of pending validation tasks (BlockNumber, BlockHash) → ()
//! - `ONGOING_TASKS`: Tasks currently being processed by workers
//! - `BLOCK_DATA`: Complete block data required for validation (BlockHash → Block)
//! - `WITNESSES`: Cryptographic witness data for stateless validation (BlockHash → SaltWitness)
//! - `VALIDATION_RESULTS`: Outcomes with block identifiers and status (BlockHash → ValidationResult)
//! - `BLOCK_RECORDS`: Complete history including forks for efficient pruning (BlockNumber, BlockHash) → ()
//! - `CONTRACTS`: On-demand contract bytecode cache (CodeHash → Bytecode)
//! - `GENESIS_CONFIG`: Genesis configuration stored on first run (singleton key → Genesis JSON)
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

use std::{collections::HashMap, fmt};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, Header};
use op_alloy_rpc_types::Transaction;
use rayon::prelude::*;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use revm::state::Bytecode;
use salt::SaltWitness;
use serde_json;
use thiserror::Error;

pub mod in_memory_db;
pub mod writer;

use crate::withdrawals::MptWitness;

/// Stores our local view of the canonical chain.
///
/// **Schema:** Maps BlockNumber (u64) to (BlockHash, PostStateRoot, PostWithdrawalsRoot) as ([u8; 32], [u8; 32], [u8; 32])
/// - Key: Block height as BlockNumber (u64)
/// - Value: (Block hash as [u8; 32], Post-state root as [u8; 32], Post-withdrawals root as [u8; 32])
///
/// Updated by main orchestrator via grow_local_chain() and rollback_chain().
/// Only successfully validated blocks can be added to this chain.
#[allow(clippy::type_complexity)]
const CANONICAL_CHAIN: TableDefinition<u64, ([u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("canonical_chain");

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

/// MPT witness data required for validating withdrawal transactions.
///
/// **Schema:** Maps BlockHash ([u8; 32]) to serialized MPT witness data (Vec<u8>)
/// - Key: Block hash as BlockHash ([u8; 32])
/// - Value: Serialized MPT witness data as Vec<u8>
///
/// Contains cryptographic proofs and state information that enables withdrawal validation
/// without full blockchain state. Always used alongside with the [`WITNESSES`] table.
const MPT_WITNESSES: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("mpt_witnesses");

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
/// Populated by workers via add_contract_codes() when new bytecode is needed
/// and retrieved via get_contract_codes().
const CONTRACTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("contracts");

/// Genesis configuration for the chain.
///
/// **Schema:** Maps a singleton key (&str) to serialized Genesis (Vec<u8>)
/// - Key: String "genesis" as &str
/// - Value: Serialized Genesis JSON as Vec<u8>
///
/// Stores the genesis configuration on first run. Subsequent runs load from this table
/// instead of requiring the genesis file again. Provides better UX and portability.
const GENESIS_CONFIG: TableDefinition<&str, Vec<u8>> = TableDefinition::new("genesis_config");

/// Initial trusted block that validation started from.
///
/// **Schema:** Maps a singleton key (&str) to (BlockNumber, BlockHash) as (u64, [u8; 32])
/// - Key: String "anchor" as &str
/// - Value: (Block number as u64, Block hash as [u8; 32])
const ANCHOR_BLOCK: TableDefinition<&str, (u64, [u8; 32])> = TableDefinition::new("anchor_block");

#[derive(Debug, Error)]
pub enum ValidationDbError {
    #[error("Database error: {0}")]
    Database(String),

    #[error(transparent)]
    Serialization(#[from] SerializationError),

    #[error("missing {kind} for block {block_hash:?}")]
    MissingData {
        kind: MissingDataKind,
        block_hash: BlockHash,
    },

    #[error("Block validation failed: {0}")]
    FailedValidation(String),

    #[error(
        "block {block_number} must extend parent block with hash {expected_parent_hash:?}, found {actual_parent_hash:?}"
    )]
    InvalidChainExtension {
        block_number: BlockNumber,
        expected_parent_hash: BlockHash,
        actual_parent_hash: BlockHash,
    },
}

// Macro to generate From implementations for all redb error types
macro_rules! impl_database_error_from {
    ($($error_type:ty),*) => {
        $(
            impl From<$error_type> for ValidationDbError {
                fn from(err: $error_type) -> Self {
                    Self::Database(err.to_string())
                }
            }
        )*
    };
}

impl_database_error_from!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

#[derive(Clone, Copy, Debug)]
pub enum MissingDataKind {
    BlockData,
    Witness,
    MptWitness,
}

impl fmt::Display for MissingDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            MissingDataKind::BlockData => "block data",
            MissingDataKind::Witness => "witness",
            MissingDataKind::MptWitness => "mpt witness",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Error)]
pub enum SerializationError {
    #[error(transparent)]
    BincodeEncode(#[from] bincode::error::EncodeError),
    #[error(transparent)]
    BincodeDecode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// ValidatorDB - The central workspace for coordination between components
///
/// Provides the database interface according to the design document for:
/// - Main orchestrator to store validation tasks and retrieve results
/// - Validation workers to pull tasks and store results
pub struct ValidatorDB {
    /// The embedded redb database
    database: Database,
}

type Result<T, E = ValidationDbError> = std::result::Result<T, E>;
pub type ValidationDbResult<T> = Result<T>;

impl ValidatorDB {
    /// Create a new redb instance or open an existing one.
    ///
    /// Opens the database file at the given path. If the file already contains
    /// a valid redb database, it will be opened preserving all existing data.
    /// If the file doesn't exist or is empty, a new database will be created
    /// and initialized with all required tables.
    pub fn new(db_path: impl AsRef<std::path::Path>) -> ValidationDbResult<Self> {
        let database = Database::create(db_path)?;

        // Initialize all tables in a single write transaction
        let write_txn = database.begin_write()?;
        {
            // The table initialization process is safe for existing databases - it
            // ensures all required tables exist but does not overwrite existing data.
            let _canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let _block_data = write_txn.open_table(BLOCK_DATA)?;
            let _witnesses = write_txn.open_table(WITNESSES)?;
            let _mpt_witnesses = write_txn.open_table(MPT_WITNESSES)?;
            let _block_records = write_txn.open_table(BLOCK_RECORDS)?;
            let _contracts = write_txn.open_table(CONTRACTS)?;
            let _anchor_block = write_txn.open_table(ANCHOR_BLOCK)?;
        }
        write_txn.commit()?;

        Ok(Self { database })
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
    pub fn store_validation_data(
        &self,
        tasks: Vec<(Block<Transaction>, SaltWitness, MptWitness)>,
    ) -> ValidationDbResult<()> {
        if tasks.is_empty() {
            return Ok(());
        }

        let tasks = tasks
            .par_iter()
            .map(|(block, salt_witness, mpt_witness)| {
                Ok::<_, ValidationDbError>((
                    block.header.number,
                    block.header.hash.0,
                    encode_block_to_vec(block)?,
                    encode_to_vec(salt_witness)?,
                    encode_to_vec(mpt_witness)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let write_txn = self.database.begin_write()?;
        {
            let mut block_data = write_txn.open_table(BLOCK_DATA)?;
            let mut witnesses = write_txn.open_table(WITNESSES)?;
            let mut mpt_witnesses = write_txn.open_table(MPT_WITNESSES)?;
            let mut block_records = write_txn.open_table(BLOCK_RECORDS)?;

            for (block_number, block_hash, block, salt_witness, mpt_witness) in tasks {
                // Stores the complete block data for worker access (BLOCK_DATA)
                block_data.insert(block_hash, block)?;
                // ... and the witness data (WITNESSES and MPT_WITNESSES)
                witnesses.insert(block_hash, salt_witness)?;
                mpt_witnesses.insert(block_hash, mpt_witness)?;
                // Records the block in the block registry (BLOCK_RECORDS)
                block_records.insert((block_number, block_hash), ())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Stores multiple contract bytecodes in the cache
    ///
    /// Workers call this to populate the cache when they fetch new bytecodes,
    /// so future validations can retrieve it via get_contract_codes() instead
    /// of fetching externally. The code hash is computed automatically from
    /// the bytecode to ensure data integrity.
    pub fn store_contract_codes(&self, bytecodes: Vec<Bytecode>) -> ValidationDbResult<()> {
        if bytecodes.is_empty() {
            return Ok(());
        }

        let bytecodes = bytecodes
            .par_iter()
            .map(|bytecode| {
                Ok::<_, ValidationDbError>((bytecode.hash_slow(), encode_to_vec(bytecode)?))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let write_txn = self.database.begin_write()?;
        {
            let mut contracts = write_txn.open_table(CONTRACTS)?;
            for (code_hash, serialized_bytecode) in bytecodes {
                contracts.insert(code_hash.0, serialized_bytecode)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Stores the genesis configuration in the database
    ///
    /// Serializes the Genesis object to JSON and stores it in the GENESIS_CONFIG table.
    /// This is typically called on first run when --genesis-file is provided.
    ///
    /// # Arguments
    /// * `genesis` - The Genesis configuration to store
    ///
    /// # Returns
    /// * `Ok(())` - Genesis successfully stored
    /// * `Err(ValidationDbError)` - Database or serialization error
    pub fn store_genesis(&self, genesis: &Genesis) -> ValidationDbResult<()> {
        let serialized_genesis = serde_json::to_vec(genesis).map_err(SerializationError::Json)?;

        let write_txn = self.database.begin_write()?;
        {
            let mut genesis_table = write_txn.open_table(GENESIS_CONFIG)?;
            genesis_table.insert("genesis", serialized_genesis)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Loads the genesis configuration from the database
    ///
    /// Retrieves and deserializes the Genesis object from the GENESIS_CONFIG table.
    /// Returns None if no genesis has been stored yet.
    ///
    /// # Returns
    /// * `Ok(Some(Genesis))` - Genesis successfully loaded
    /// * `Ok(None)` - No genesis stored in database
    /// * `Err(ValidationDbError)` - Database or deserialization error
    pub fn load_genesis(&self) -> ValidationDbResult<Option<Genesis>> {
        let read_txn = self.database.begin_read()?;
        let genesis_table = read_txn.open_table(GENESIS_CONFIG)?;

        genesis_table
            .get("genesis")?
            .map(|s| serde_json::from_slice(&s.value()).map_err(SerializationError::Json))
            .transpose()
            .map_err(Into::into)
    }

    /// Retrieves the initial trusted block.
    ///
    /// # Returns
    /// * `Ok(Some((block_number, block_hash)))` - Anchor block found
    /// * `Ok(None)` - No anchor block has been set
    /// * `Err(ValidationDbError)` - Database error
    pub fn get_anchor_block(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let anchor_block_table = read_txn.open_table(ANCHOR_BLOCK)?;

        Ok(anchor_block_table.get("anchor")?.map(|v| {
            let (block_number, block_hash) = v.value();
            (block_number, BlockHash::from(block_hash))
        }))
    }

    /// Extends the canonical chain with the next validated block
    ///
    /// Automatically gets the first block from the remote chain, verifies it has been
    /// successfully validated, and moves it to the canonical chain. Performs all necessary
    /// validations including parent hash matching and state root continuity.
    ///
    /// Returns `Ok(true)` if a block was advanced, `Ok(false)` if no work to do.
    pub fn store_canonical_entries(
        &self,
        entries: Vec<(BlockNumber, BlockHash, B256, B256)>,
    ) -> ValidationDbResult<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;

            // Move block from remote to canonical chain
            for (block_number, block_hash, post_state_root, post_withdrawals_root) in entries {
                canonical_chain.insert(
                    block_number,
                    (block_hash.0, post_state_root.0, post_withdrawals_root.0),
                )?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Rolls back the local chain view in response to chain reorg
    ///
    /// Removes blocks from both the remote chain and canonical chain when a reorg
    /// occurs, reverting to the specified block number.
    pub fn rollback_chain(&self, to_block: BlockNumber) -> ValidationDbResult<()> {
        let read_txn = self.database.begin_read()?;
        let canonical_chain = read_txn.open_table(CANONICAL_CHAIN)?;

        // Rollback canonical chain to specified block
        let canonical_blocks_to_remove = canonical_chain
            .range((to_block + 1)..)?
            .map(|result| result.map(|(key, _)| key.value()))
            .collect::<Result<Vec<_>, _>>()?;

        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;

            for block_number in canonical_blocks_to_remove {
                canonical_chain.remove(block_number)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Gets the latest block in the local chain
    ///
    /// Returns the highest block number and hash currently considered local canonical,
    /// or None if the chain is empty.
    pub fn get_local_tip(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let canonical_chain = read_txn.open_table(CANONICAL_CHAIN)?;

        match canonical_chain.last()? {
            Some((canonical_key, canonical_value)) => {
                let block_number = canonical_key.value();
                let (block_hash, _, _) = canonical_value.value();
                Ok(Some((block_number, block_hash.into())))
            }
            None => Ok(None),
        }
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
    ) -> ValidationDbResult<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut anchor_block_table = write_txn.open_table(ANCHOR_BLOCK)?;
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;

            anchor_block_table.insert("anchor", (block_number, block_hash.0))?;
            canonical_chain.retain(|_, _| false)?;
            canonical_chain.insert(
                block_number,
                (block_hash.0, post_state_root.0, post_withdrawals_root.0),
            )?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieves multiple cached contract bytecodes
    ///
    /// Returns a tuple of (found_contracts, missing_hashes) where:
    /// - `found_contracts`: HashMap mapping code hash to bytecode for all found contracts
    /// - `missing_hashes`: Vec of code hashes that were not found in the cache
    pub fn get_contract_codes(
        &self,
        code_hashes: impl IntoIterator<Item = B256>,
    ) -> ValidationDbResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
        let read_txn = self.database.begin_read()?;
        let contracts = read_txn.open_table(CONTRACTS)?;

        code_hashes.into_iter().try_fold(
            (HashMap::new(), Vec::new()),
            |(mut found, mut missing), code_hash| {
                match contracts.get(code_hash.0)? {
                    Some(bytes) => {
                        found.insert(code_hash, decode_from_slice(&bytes.value()));
                    }
                    None => missing.push(code_hash),
                }
                Ok::<_, ValidationDbError>((found, missing))
            },
        )
    }

    /// Retrieves all cached contract bytecodes from the database
    ///
    /// Returns a Vec of all bytecodes stored in the contracts table.
    /// Used during initialization to preload contracts into memory cache.
    pub fn get_all_contracts(&self) -> ValidationDbResult<Vec<Bytecode>> {
        let read_txn = self.database.begin_read()?;
        let contracts = read_txn.open_table(CONTRACTS)?;

        contracts
            .iter()?
            .map(|result| {
                let (_, value) = result?;
                Ok(decode_from_slice(&value.value()))
            })
            .collect()
    }

    /// Cleans up old block data to save storage space
    ///
    /// Removes canonical chain entries, validation records, block data, and witnesses
    /// for blocks older than the specified block number.
    ///
    /// Returns the number of blocks that were actually pruned.
    pub fn prune_history(&self, before_block: BlockNumber) -> ValidationDbResult<u64> {
        let read_txn = self.database.begin_read()?;
        let block_records = read_txn.open_table(BLOCK_RECORDS)?;

        // Collect keys to remove (blocks older than before_block)
        let keys_to_remove = block_records
            .range(..(before_block, [0u8; 32]))?
            .map(|result| result.map(|(key, _)| key.value()))
            .collect::<Result<Vec<_>, _>>()?;

        let pruned_count = keys_to_remove.len() as u64;

        let write_txn = self.database.begin_write()?;
        let blocks_pruned = {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let mut block_records = write_txn.open_table(BLOCK_RECORDS)?;
            let mut block_data = write_txn.open_table(BLOCK_DATA)?;
            let mut witnesses = write_txn.open_table(WITNESSES)?;
            let mut mpt_witnesses = write_txn.open_table(MPT_WITNESSES)?;

            for (block_number, block_hash) in keys_to_remove {
                // Remove from all relevant tables
                canonical_chain.remove(block_number)?;
                block_records.remove((block_number, block_hash))?;
                block_data.remove(block_hash)?;
                witnesses.remove(block_hash)?;
                mpt_witnesses.remove(block_hash)?;
            }

            pruned_count
        };
        write_txn.commit()?;
        Ok(blocks_pruned)
    }

    // /// Retrieves the block hash for a specific block number from the local view
    // ///
    // /// Searches the local view which consists of two sequential, non-overlapping chains:
    // /// - CANONICAL_CHAIN: Lower block numbers (validated blocks)
    // /// - REMOTE_CHAIN: Higher block numbers (unvalidated blocks extending canonical)
    // ///
    // /// # Parameters
    // /// * `block_number` - The block number to look up in the local view
    // ///
    // /// # Returns
    // /// * `Ok(Some(block_hash))` - Block found at the specified number
    // /// * `Ok(None)` - No block exists at this number in the local view
    // /// * `Err(...)` - Database error during lookup
    // pub fn get_block_hash(
    //     &self,
    //     block_number: BlockNumber,
    // ) -> ValidationDbResult<Option<BlockHash>> {
    //     let read_txn = self.database.begin_read()?;
    //     let canonical_chain = read_txn.open_table(CANONICAL_CHAIN)?;

    //     // Check canonical chain first, then remote chain (sequential, no overlap)
    //     if let Some(value) = canonical_chain.get(block_number)? {
    //         return Ok(Some(value.value().0.into()));
    //     }
    //     Ok(None)
    // }

    pub fn get_block_header(&self, block_hash: BlockHash) -> ValidationDbResult<Option<Header>> {
        let read_txn = self.database.begin_read()?;
        let block_data = read_txn.open_table(BLOCK_DATA)?;

        Ok(block_data
            .get(block_hash.0)?
            .map(|v| decode_block_from_slice(&v.value()).header))
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
    pub fn get_earliest_local_block(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let canonical_chain = read_txn.open_table(CANONICAL_CHAIN)?;

        Ok(canonical_chain.first()?.map(|(key, value)| {
            let block_number = key.value();
            let (block_hash, _, _) = value.value();
            (block_number, block_hash.into())
        }))
    }
}

/// Helper method to serialize data using bincode with legacy config
fn encode_to_vec<T: serde::Serialize>(data: &T) -> Result<Vec<u8>> {
    let encoded = bincode::serde::encode_to_vec(data, bincode::config::legacy())
        .map_err(SerializationError::from)?;
    Ok(encoded)
}

/// Helper method to deserialize data using bincode with legacy config
fn decode_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    let (decoded, _) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
        .expect("serialization of previously stored data must succeed");
    decoded
}

/// Helper method to serialize Block<Transaction> using JSON
fn encode_block_to_vec(block: &Block<Transaction>) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(block).map_err(SerializationError::from)?;
    Ok(encoded)
}

/// Helper method to deserialize Block<Transaction> using JSON
fn decode_block_from_slice(bytes: &[u8]) -> Block<Transaction> {
    serde_json::from_slice(bytes)
        .expect("serialization of previously stored block data must succeed")
}
