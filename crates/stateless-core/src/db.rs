//! Unified persistence module for stateless validation.
//!
//! Contains two database implementations:
//! - [`ValidatorDB`]: Lightweight tip/contract/genesis storage for `stateless-validator`
//! - [`ServerDB`]: Block storage and chain tracking for `debug-trace-server`
//!
//! Also defines the abstract persistence traits that decouple consumers from
//! concrete database implementations:
//! - [`ContractStore`]: Contract bytecode persistence
//! - [`GenesisStore`]: Genesis configuration persistence
//! - [`ChainStore`]: Core chain state management (shared by both binaries)
//! - [`BlockStore`]: Block/witness storage extension (debug-trace-server only)

use std::{
    collections::HashMap,
    fmt,
    path::Path,
    sync::{Arc, atomic::AtomicU64},
};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use dashmap::DashMap;
use op_alloy_rpc_types::Transaction;
use rayon::prelude::*;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use revm::state::Bytecode;
use salt::SaltWitness;
use thiserror::Error;

use crate::{LightWitness, withdrawals::MptWitness};

// ===========================================================================
// Shared table definitions
// ===========================================================================

/// Trusted anchor block. Singleton key "anchor".
/// Value: (block_number, block_hash, post_state_root, post_withdrawals_root).
/// Used by both [`ValidatorDB`] and [`ServerDB`].
#[allow(clippy::type_complexity)]
const ANCHOR_BLOCK: TableDefinition<&str, (u64, [u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("anchor_block");

/// Canonical chain. Maps BlockNumber → (BlockHash, PostStateRoot, PostWithdrawalsRoot).
/// Used by both [`ValidatorDB`] and [`ServerDB`].
#[allow(clippy::type_complexity)]
const CANONICAL_CHAIN: TableDefinition<u64, ([u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("canonical_chain");

/// Contract bytecode cache. Key: code_hash, Value: bincode+lz4 serialized Bytecode.
/// Used by both [`ValidatorDB`] and [`ServerDB`].
const CONTRACTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("contracts");

/// Genesis configuration (write-once). Singleton key "genesis", Value: JSON bytes.
/// Used by [`ValidatorDB`] only.
const GENESIS_CONFIG: TableDefinition<&str, Vec<u8>> = TableDefinition::new("genesis_config");

// ===========================================================================
// ServerDB-specific table definitions
// ===========================================================================

/// Complete block data. Maps BlockHash → serialized Block<Transaction>.
const BLOCK_DATA: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("block_data");

/// Light witness data. Maps BlockHash → serialized LightWitness.
const WITNESSES: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("witnesses");

/// Block registry for pruning. Maps (BlockNumber, BlockHash) → ().
const BLOCK_RECORDS: TableDefinition<(u64, [u8; 32]), ()> = TableDefinition::new("block_records");

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
    fn to_tuple(&self) -> (u64, [u8; 32], [u8; 32], [u8; 32]) {
        (self.block_number, self.block_hash.0, self.post_state_root.0, self.post_withdrawals_root.0)
    }

    fn from_tuple(t: (u64, [u8; 32], [u8; 32], [u8; 32])) -> Self {
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
// Error types (ServerDB)
// ===========================================================================

#[derive(Debug, Error)]
pub enum ValidationDbError {
    #[error("Database error: {0}")]
    Database(String),

    #[error(transparent)]
    Serialization(#[from] SerializationError),

    #[error("missing {kind} for block {block_hash:?}")]
    MissingData { kind: MissingDataKind, block_hash: BlockHash },

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
}

impl fmt::Display for MissingDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            MissingDataKind::BlockData => "block data",
            MissingDataKind::Witness => "witness",
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
    #[error("lz4 decompression failed: {0}")]
    Lz4(#[from] lz4_flex::block::DecompressError),
}

type Result<T, E = ValidationDbError> = std::result::Result<T, E>;
pub type ValidationDbResult<T> = Result<T>;

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

// ===========================================================================
// Shared serialization helpers
// ===========================================================================

/// Marker byte prepended to lz4-compressed bincode data.
const BINCODE_LZ4_MARKER: u8 = 0x01;

/// Helper method to serialize data using bincode + lz4 compression
/// Format: [marker byte][lz4 compressed bincode data]
fn encode_to_vec<T: serde::Serialize>(data: &T) -> Result<Vec<u8>> {
    let encoded = bincode::serde::encode_to_vec(data, bincode::config::standard())
        .map_err(SerializationError::from)?;

    // Compress with lz4
    let compressed = lz4_flex::compress_prepend_size(&encoded);

    // Prepend version marker
    let mut result = Vec::with_capacity(1 + compressed.len());
    result.push(BINCODE_LZ4_MARKER);
    result.extend(compressed);
    Ok(result)
}

/// Deserializes lz4-compressed bincode data written by [`encode_to_vec`].
fn decode_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() {
        return Err(ValidationDbError::Database("cannot deserialize empty data".into()));
    }
    if bytes[0] != BINCODE_LZ4_MARKER {
        return Err(ValidationDbError::Database(format!(
            "unknown serialization marker: {:#04x}",
            bytes[0]
        )));
    }
    let decompressed =
        lz4_flex::decompress_size_prepended(&bytes[1..]).map_err(SerializationError::from)?;
    let (decoded, _) =
        bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())
            .map_err(SerializationError::from)?;
    Ok(decoded)
}

/// Helper method to serialize Block<Transaction> using JSON
/// Note: We use JSON instead of Bincode because Block<Transaction> has serde attributes
/// (like #[serde(default)]) that are incompatible with bincode's legacy config.
fn encode_block_to_vec(block: &Block<Transaction>) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(block).map_err(SerializationError::from)?;
    Ok(encoded)
}

/// Helper method to deserialize Block<Transaction> using JSON
fn decode_block_from_slice(bytes: &[u8]) -> Block<Transaction> {
    serde_json::from_slice(bytes)
        .expect("deserialization of previously stored block data must succeed")
}

// ===========================================================================
// Shared database helpers (operate on raw `&Database`)
// ===========================================================================

/// Reads the canonical tip (highest block) from CANONICAL_CHAIN.
fn db_get_canonical_tip(database: &Database) -> eyre::Result<Option<BlockMeta>> {
    let read_txn = database.begin_read()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN)?;
    Ok(chain.last()?.map(|(k, v)| {
        let (hash, state_root, withdrawals_root) = v.value();
        BlockMeta {
            block_number: k.value(),
            block_hash: BlockHash::from(hash),
            post_state_root: B256::from(state_root),
            post_withdrawals_root: B256::from(withdrawals_root),
        }
    }))
}

/// Reads the anchor block from ANCHOR_BLOCK.
fn db_get_anchor(database: &Database) -> eyre::Result<Option<BlockMeta>> {
    let read_txn = database.begin_read()?;
    let table = read_txn.open_table(ANCHOR_BLOCK)?;
    Ok(table.get("anchor")?.map(|v| BlockMeta::from_tuple(v.value())))
}

/// Looks up a single block hash from CANONICAL_CHAIN.
fn db_get_block_hash(
    database: &Database,
    block_number: BlockNumber,
) -> eyre::Result<Option<BlockHash>> {
    let read_txn = database.begin_read()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN)?;
    Ok(chain.get(block_number)?.map(|v| BlockHash::from(v.value().0)))
}

/// Returns the earliest (lowest block number) entry in CANONICAL_CHAIN.
fn db_get_earliest_block(database: &Database) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
    let read_txn = database.begin_read()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN)?;
    Ok(chain.first()?.map(|(k, v)| (k.value(), BlockHash::from(v.value().0))))
}

/// Appends blocks to CANONICAL_CHAIN in a single write transaction.
fn db_advance_chain(database: &Database, blocks: &[BlockMeta]) -> eyre::Result<()> {
    if blocks.is_empty() {
        return Ok(());
    }
    let write_txn = database.begin_write()?;
    {
        let mut chain = write_txn.open_table(CANONICAL_CHAIN)?;
        for block in blocks {
            chain.insert(
                block.block_number,
                (block.block_hash.0, block.post_state_root.0, block.post_withdrawals_root.0),
            )?;
        }
    }
    write_txn.commit()?;
    Ok(())
}

/// Removes all CANONICAL_CHAIN entries above `to_block`.
fn db_rollback_chain(database: &Database, to_block: BlockNumber) -> eyre::Result<()> {
    let write_txn = database.begin_write()?;
    {
        let mut chain = write_txn.open_table(CANONICAL_CHAIN)?;
        let to_remove: Vec<u64> = chain
            .range((to_block + 1)..)?
            .map(|r| r.map(|(k, _)| k.value()))
            .collect::<std::result::Result<_, _>>()?;
        for n in to_remove {
            chain.remove(n)?;
        }
    }
    write_txn.commit()?;
    Ok(())
}

/// Clears the canonical chain and sets anchor as the sole entry.
fn db_reset_to_anchor(database: &Database, anchor: &BlockMeta) -> eyre::Result<()> {
    let write_txn = database.begin_write()?;
    {
        let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK)?;
        anchor_table.insert("anchor", anchor.to_tuple())?;

        let mut chain = write_txn.open_table(CANONICAL_CHAIN)?;
        chain.retain(|_, _| false)?;
        chain.insert(
            anchor.block_number,
            (anchor.block_hash.0, anchor.post_state_root.0, anchor.post_withdrawals_root.0),
        )?;
    }
    write_txn.commit()?;
    Ok(())
}

/// Retrieves cached contract bytecodes. Returns `(found, missing)`.
fn db_get_contracts(
    database: &Database,
    hashes: &[B256],
) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
    let read_txn = database.begin_read()?;
    let table = read_txn.open_table(CONTRACTS)?;

    let mut found = HashMap::new();
    let mut missing = Vec::new();

    for &hash in hashes {
        match table.get(hash.0)? {
            Some(data) => {
                found.insert(hash, decode_from_slice(data.value().as_slice())?);
            }
            None => missing.push(hash),
        }
    }

    Ok((found, missing))
}

/// Stores contract bytecodes in the CONTRACTS table.
fn db_add_contracts(database: &Database, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
    if codes.is_empty() {
        return Ok(());
    }
    let write_txn = database.begin_write()?;
    {
        let mut table = write_txn.open_table(CONTRACTS)?;
        for (hash, bytecode) in codes {
            let encoded = encode_to_vec(bytecode)?;
            table.insert(hash.0, encoded)?;
        }
    }
    write_txn.commit()?;
    Ok(())
}

// ===========================================================================
// ValidatorDB
// ===========================================================================

/// Default maximum number of entries to retain in CANONICAL_CHAIN.
const DEFAULT_MAX_CHAIN_LENGTH: u64 = 1000;

/// Minimal persistent storage backed by redb.
///
/// Only stores data that must survive restarts: anchor block, canonical tip,
/// contract bytecodes, and genesis configuration.
///
/// CANONICAL_CHAIN is bounded to `max_chain_length` entries; older entries are
/// pruned inline during [`ChainStore::advance_chain`].
pub struct ValidatorDB {
    database: Database,
    max_chain_length: AtomicU64,
}

impl ValidatorDB {
    /// Creates or opens a persistent store at the given path.
    pub fn new(db_path: impl AsRef<Path>) -> eyre::Result<Self> {
        let database = Database::create(db_path)?;

        // Initialize all tables
        let write_txn = database.begin_write()?;
        {
            let _ = write_txn.open_table(ANCHOR_BLOCK)?;
            let _ = write_txn.open_table(CONTRACTS)?;
            let _ = write_txn.open_table(GENESIS_CONFIG)?;
            let _ = write_txn.open_table(CANONICAL_CHAIN)?;
        }
        write_txn.commit()?;

        Ok(Self { database, max_chain_length: AtomicU64::new(DEFAULT_MAX_CHAIN_LENGTH) })
    }

    /// Sets the maximum number of entries to retain in CANONICAL_CHAIN.
    pub fn set_max_chain_length(&self, max: u64) {
        self.max_chain_length.store(max, std::sync::atomic::Ordering::Relaxed);
    }

    // -- Anchor block --

    /// Returns the stored anchor block, or `None` if not set.
    pub fn get_anchor_block(&self) -> eyre::Result<Option<BlockMeta>> {
        db_get_anchor(&self.database)
    }

    /// Stores the anchor block.
    pub fn set_anchor_block(&self, tip: &BlockMeta) -> eyre::Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(ANCHOR_BLOCK)?;
            table.insert("anchor", tip.to_tuple())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // -- Canonical tip --

    /// Returns the last validated canonical tip (highest block in the chain), or `None` if empty.
    pub fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
        db_get_canonical_tip(&self.database)
    }

    // -- Contracts --

    /// Retrieves cached contract bytecodes.
    ///
    /// Returns `(found, missing)` where `found` maps code hashes to bytecodes
    /// and `missing` lists code hashes not in the cache.
    pub fn get_contracts(
        &self,
        hashes: &[B256],
    ) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
        db_get_contracts(&self.database, hashes)
    }

    /// Stores contract bytecodes in the cache.
    pub fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
        db_add_contracts(&self.database, codes)
    }

    // -- Genesis --

    /// Persists the genesis configuration as JSON.
    pub fn store_genesis(&self, genesis: &Genesis) -> eyre::Result<()> {
        let json_bytes = serde_json::to_vec(genesis)?;
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(GENESIS_CONFIG)?;
            table.insert("genesis", json_bytes)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Loads the genesis configuration, or `None` if not stored yet.
    pub fn load_genesis(&self) -> eyre::Result<Option<Genesis>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(GENESIS_CONFIG)?;
        match table.get("genesis")? {
            Some(data) => {
                let genesis: Genesis = serde_json::from_slice(data.value().as_slice())?;
                Ok(Some(genesis))
            }
            None => Ok(None),
        }
    }

    // -- Reset --

    /// Resets the store to a new anchor, setting the canonical tip to match the anchor.
    /// Clears the canonical chain history and writes the anchor as the sole entry.
    pub fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
        db_reset_to_anchor(&self.database, anchor)
    }
}

// ---------------------------------------------------------------------------
// ContractStore impl for ValidatorDB
// ---------------------------------------------------------------------------

impl ContractStore for ValidatorDB {
    fn get_contracts(&self, hashes: &[B256]) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
        db_get_contracts(&self.database, hashes)
    }

    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
        db_add_contracts(&self.database, codes)
    }
}

// ---------------------------------------------------------------------------
// GenesisStore impl for ValidatorDB
// ---------------------------------------------------------------------------

impl GenesisStore for ValidatorDB {
    fn store_genesis(&self, genesis: &Genesis) -> eyre::Result<()> {
        ValidatorDB::store_genesis(self, genesis)
    }

    fn load_genesis(&self) -> eyre::Result<Option<Genesis>> {
        ValidatorDB::load_genesis(self)
    }
}

// ---------------------------------------------------------------------------
// ChainStore impl for ValidatorDB
// ---------------------------------------------------------------------------

impl ChainStore for ValidatorDB {
    fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
        db_get_canonical_tip(&self.database)
    }

    fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
        db_get_anchor(&self.database)
    }

    fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let max_len = self.max_chain_length.load(std::sync::atomic::Ordering::Relaxed);
        let write_txn = self.database.begin_write()?;
        {
            let mut chain = write_txn.open_table(CANONICAL_CHAIN)?;
            for block in blocks {
                chain.insert(
                    block.block_number,
                    (block.block_hash.0, block.post_state_root.0, block.post_withdrawals_root.0),
                )?;
            }

            // Inline pruning: remove oldest entries that exceed the max chain length
            let len = chain.len()?;
            if len > max_len {
                let excess = len - max_len;
                let to_remove: Vec<u64> = chain
                    .iter()?
                    .take(excess as usize)
                    .map(|r| r.map(|(k, _)| k.value()))
                    .collect::<std::result::Result<_, _>>()?;
                for n in to_remove {
                    chain.remove(n)?;
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn get_block_hash(&self, block_number: BlockNumber) -> eyre::Result<Option<BlockHash>> {
        db_get_block_hash(&self.database, block_number)
    }

    fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
        db_get_earliest_block(&self.database)
    }

    fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()> {
        db_rollback_chain(&self.database, to_block)
    }

    fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
        db_reset_to_anchor(&self.database, anchor)
    }
}

// ===========================================================================
// ServerDB
// ===========================================================================

/// ServerDB - Block storage and chain tracking database for debug-trace-server.
///
/// Provides the database interface for:
/// - Main orchestrator to store validation tasks and retrieve results
/// - Validation workers to pull tasks and store results
pub struct ServerDB {
    /// The embedded redb database
    database: Database,
}

impl ServerDB {
    /// Create a new redb instance or open an existing one.
    ///
    /// Opens the database file at the given path. If the file already contains
    /// a valid redb database, it will be opened preserving all existing data.
    /// If the file doesn't exist or is empty, a new database will be created
    /// and initialized with all required tables.
    pub fn new(db_path: impl AsRef<Path>) -> ValidationDbResult<Self> {
        let database = Database::create(db_path)?;

        // Initialize all tables in a single write transaction
        let write_txn = database.begin_write()?;
        {
            let _canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let _block_data = write_txn.open_table(BLOCK_DATA)?;
            let _witnesses = write_txn.open_table(WITNESSES)?;
            let _block_records = write_txn.open_table(BLOCK_RECORDS)?;
            let _contracts = write_txn.open_table(CONTRACTS)?;
            let _anchor_block = write_txn.open_table(ANCHOR_BLOCK)?;
        }
        write_txn.commit()?;

        Ok(Self { database })
    }

    /// Stores block data and witnesses.
    ///
    /// This is used by debug-trace-server to store block data for serving trace RPCs
    /// without requiring validation. Unlike `add_validation_tasks`, this does NOT add
    /// blocks to the TASK_LIST queue.
    ///
    /// Stores `LightWitness` (without cryptographic proofs) instead of `SaltWitness`
    /// for better storage efficiency and faster deserialization on read.
    ///
    /// # Arguments
    /// * `tasks` - A slice of tuples, each containing:
    ///   - `Block<Transaction>` - The complete block data including header and transactions
    ///   - `LightWitness` - The light witness containing state data for execution
    pub fn store_block_data(
        &self,
        tasks: &[(Block<Transaction>, LightWitness)],
    ) -> ValidationDbResult<()> {
        if tasks.is_empty() {
            return Ok(());
        }

        let tasks = tasks
            .par_iter()
            .map(|(block, light_witness)| {
                Ok::<_, ValidationDbError>((
                    block.header.number,
                    block.header.hash.0,
                    encode_block_to_vec(block)?,
                    encode_to_vec(light_witness)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let write_txn = self.database.begin_write()?;
        {
            let mut block_data = write_txn.open_table(BLOCK_DATA)?;
            let mut witnesses = write_txn.open_table(WITNESSES)?;
            let mut block_records = write_txn.open_table(BLOCK_RECORDS)?;

            for (number, hash, block, light_witness) in tasks {
                block_data.insert(hash, block)?;
                witnesses.insert(hash, light_witness)?;
                block_records.insert((number, hash), ())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Gets the latest block in the local chain.
    ///
    /// Returns the highest block number and hash currently considered local canonical,
    /// or None if the chain is empty.
    pub fn get_local_tip(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN)?;
        Ok(chain.last()?.map(|(k, v)| {
            let (hash, _, _) = v.value();
            (k.value(), BlockHash::from(hash))
        }))
    }

    /// Resets the chain anchor point and clears all chain state.
    pub fn reset_anchor_block(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        post_state_root: B256,
        post_withdrawals_root: B256,
    ) -> ValidationDbResult<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK)?;
            anchor_table.insert(
                "anchor",
                (block_number, block_hash.0, post_state_root.0, post_withdrawals_root.0),
            )?;
            let mut chain = write_txn.open_table(CANONICAL_CHAIN)?;
            chain.retain(|_, _| false)?;
            chain
                .insert(block_number, (block_hash.0, post_state_root.0, post_withdrawals_root.0))?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Cleans up old block data to save storage space.
    ///
    /// Removes canonical chain entries, validation records, block data, and witnesses
    /// for blocks older than the specified block number.
    ///
    /// Returns the number of blocks that were actually pruned.
    pub fn prune_history(&self, before_block: BlockNumber) -> ValidationDbResult<u64> {
        let read_txn = self.database.begin_read()?;
        let block_records = read_txn.open_table(BLOCK_RECORDS)?;

        let keys_to_remove = block_records
            .range(..(before_block, [0u8; 32]))?
            .map(|result| result.map(|(key, _)| key.value()))
            .collect::<Result<Vec<_>, _>>()?;
        let pruned_count = keys_to_remove.len() as u64;

        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let mut block_records = write_txn.open_table(BLOCK_RECORDS)?;
            let mut block_data = write_txn.open_table(BLOCK_DATA)?;
            let mut witnesses = write_txn.open_table(WITNESSES)?;

            for (block_number, block_hash) in keys_to_remove {
                canonical_chain.remove(block_number)?;
                block_records.remove((block_number, block_hash))?;
                block_data.remove(block_hash)?;
                witnesses.remove(block_hash)?;
            }

            // Clean up orphaned CANONICAL_CHAIN entries not tracked in BLOCK_RECORDS
            // (e.g., anchor blocks inserted by reset_anchor_block)
            loop {
                let block_number = match canonical_chain.first()? {
                    Some(entry) => {
                        let n = entry.0.value();
                        if n >= before_block {
                            break;
                        }
                        n
                    }
                    None => break,
                };
                canonical_chain.remove(block_number)?;
            }
        }
        write_txn.commit()?;
        Ok(pruned_count)
    }

    /// Retrieves the block hash for a specific block number from the canonical chain.
    pub fn get_block_hash(
        &self,
        block_number: BlockNumber,
    ) -> ValidationDbResult<Option<BlockHash>> {
        let read_txn = self.database.begin_read()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN)?;
        Ok(chain.get(block_number)?.map(|v| BlockHash::from(v.value().0)))
    }

    /// Retrieves the earliest block in the canonical chain.
    pub fn get_earliest_local_block(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN)?;
        Ok(chain.first()?.map(|(k, v)| (k.value(), BlockHash::from(v.value().0))))
    }

    /// Retrieves block data and witness for a specific block hash.
    ///
    /// Uses `LightWitness` for deserialization, which skips expensive elliptic curve
    /// point validation (~240ms -> ~10-20ms). This is safe when reading from our own
    /// trusted database where we don't need cryptographic proof verification.
    pub fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> ValidationDbResult<(Block<Transaction>, LightWitness)> {
        let start = std::time::Instant::now();

        let read_txn = self.database.begin_read()?;
        let block_data = read_txn.open_table(BLOCK_DATA)?;
        let witnesses = read_txn.open_table(WITNESSES)?;
        let txn_ms = start.elapsed().as_millis();

        let block_bytes = block_data.get(block_hash.0)?.ok_or(ValidationDbError::MissingData {
            kind: MissingDataKind::BlockData,
            block_hash,
        })?;
        let block_bytes_value = block_bytes.value();
        let block_bytes_len = block_bytes_value.len();
        let db_read_block_ms = start.elapsed().as_millis();

        let block = decode_block_from_slice(&block_bytes_value);
        let block_decode_ms = start.elapsed().as_millis();

        let witness_bytes = witnesses
            .get(block_hash.0)?
            .ok_or(ValidationDbError::MissingData { kind: MissingDataKind::Witness, block_hash })?;
        let witness_bytes_value = witness_bytes.value();
        let witness_bytes_len = witness_bytes_value.len();
        let db_read_witness_ms = start.elapsed().as_millis();

        let witness: LightWitness = decode_from_slice(&witness_bytes_value)?;
        let witness_decode_ms = start.elapsed().as_millis();

        tracing::debug!(
            txn_ms = txn_ms,
            db_read_block_ms = db_read_block_ms - txn_ms,
            block_decode_ms = block_decode_ms - db_read_block_ms,
            db_read_witness_ms = db_read_witness_ms - block_decode_ms,
            witness_decode_ms = witness_decode_ms - db_read_witness_ms,
            total_ms = witness_decode_ms,
            block_bytes_len = block_bytes_len,
            witness_bytes_len = witness_bytes_len,
            "get_block_and_witness timing breakdown"
        );

        Ok((block, witness))
    }
}

// ---------------------------------------------------------------------------
// ContractStore impl for ServerDB
// ---------------------------------------------------------------------------

impl ContractStore for ServerDB {
    fn get_contracts(&self, hashes: &[B256]) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
        db_get_contracts(&self.database, hashes)
    }

    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
        db_add_contracts(&self.database, codes)
    }
}

// ---------------------------------------------------------------------------
// ChainStore impl for ServerDB
// ---------------------------------------------------------------------------

impl ChainStore for ServerDB {
    fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
        db_get_canonical_tip(&self.database)
    }

    fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
        db_get_anchor(&self.database)
    }

    fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()> {
        db_advance_chain(&self.database, blocks)
    }

    fn get_block_hash(&self, block_number: BlockNumber) -> eyre::Result<Option<BlockHash>> {
        db_get_block_hash(&self.database, block_number)
    }

    fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
        db_get_earliest_block(&self.database)
    }

    fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()> {
        db_rollback_chain(&self.database, to_block)
    }

    fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
        db_reset_to_anchor(&self.database, anchor)
    }
}

// ---------------------------------------------------------------------------
// PrunableChainStore impl for ServerDB
// ---------------------------------------------------------------------------

impl PrunableChainStore for ServerDB {
    fn prune_chain(&self, before_block: BlockNumber) -> eyre::Result<u64> {
        Ok(ServerDB::prune_history(self, before_block)?)
    }
}

// ---------------------------------------------------------------------------
// BlockStore impl for ServerDB
// ---------------------------------------------------------------------------

impl BlockStore for ServerDB {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> eyre::Result<()> {
        Ok(ServerDB::store_block_data(self, blocks)?)
    }

    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> eyre::Result<(Block<Transaction>, LightWitness)> {
        Ok(ServerDB::get_block_and_witness(self, block_hash)?)
    }
}

// ===========================================================================
// ContractCache — DashMap with persistent write-through
// ===========================================================================

/// In-memory contract bytecode cache backed by persistent storage.
///
/// Reads check the in-memory `DashMap` first, falling back to the persistent store.
/// Writes go to both memory and disk (write-through).
pub struct ContractCache {
    memory: DashMap<B256, Bytecode>,
    store: Arc<dyn ContractStore>,
}

impl ContractCache {
    /// Creates a new contract cache backed by the given persistent store.
    pub fn new(store: Arc<dyn ContractStore>) -> Self {
        Self { memory: DashMap::new(), store }
    }

    /// Retrieves contract bytecodes, checking memory first then persistent store.
    ///
    /// Returns `(found, missing)`.
    pub fn get(&self, hashes: &[B256]) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
        let mut found = HashMap::new();
        let mut not_in_memory = Vec::new();

        for &hash in hashes {
            if let Some(entry) = self.memory.get(&hash) {
                found.insert(hash, entry.value().clone());
            } else {
                not_in_memory.push(hash);
            }
        }

        if not_in_memory.is_empty() {
            return Ok((found, Vec::new()));
        }

        // Check persistent store for remaining
        let (from_disk, missing) = self.store.get_contracts(&not_in_memory)?;

        // Populate memory cache with disk hits
        for (hash, bytecode) in &from_disk {
            self.memory.insert(*hash, bytecode.clone());
        }
        found.extend(from_disk);

        Ok((found, missing))
    }

    /// Adds contract bytecodes to both memory cache and persistent store (write-through).
    pub fn insert(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
        if codes.is_empty() {
            return Ok(());
        }

        // Write to persistent store first
        self.store.add_contracts(codes)?;

        // Then update memory cache
        for (hash, bytecode) in codes {
            self.memory.insert(*hash, bytecode.clone());
        }

        Ok(())
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, ValidatorDB) {
        let dir = tempfile::tempdir().unwrap();
        let store = ValidatorDB::new(dir.path().join("test.redb")).unwrap();
        (dir, store)
    }

    #[test]
    fn test_anchor_block_roundtrip() {
        let (_dir, store) = temp_store();

        assert!(store.get_anchor_block().unwrap().is_none());

        let tip = BlockMeta {
            block_number: 42,
            block_hash: BlockHash::from([1u8; 32]),
            post_state_root: B256::from([2u8; 32]),
            post_withdrawals_root: B256::from([3u8; 32]),
        };
        store.set_anchor_block(&tip).unwrap();

        let loaded = store.get_anchor_block().unwrap().unwrap();
        assert_eq!(loaded, tip);
    }

    #[test]
    fn test_canonical_tip_roundtrip() {
        let (_dir, store) = temp_store();

        assert!(store.get_canonical_tip().unwrap().is_none());

        let tip = BlockMeta {
            block_number: 100,
            block_hash: BlockHash::from([10u8; 32]),
            post_state_root: B256::from([20u8; 32]),
            post_withdrawals_root: B256::from([30u8; 32]),
        };
        ChainStore::advance_chain(&store, std::slice::from_ref(&tip)).unwrap();

        let loaded = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(loaded, tip);

        // Update tip
        let tip2 = BlockMeta { block_number: 101, ..tip };
        ChainStore::advance_chain(&store, std::slice::from_ref(&tip2)).unwrap();
        let loaded2 = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(loaded2.block_number, 101);
    }

    #[test]
    fn test_contracts_roundtrip() {
        let (_dir, store) = temp_store();

        let hash1 = B256::from([1u8; 32]);
        let hash2 = B256::from([2u8; 32]);
        let hash3 = B256::from([3u8; 32]);

        let bytecode1 = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x00]));
        let bytecode2 = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x01]));

        store.add_contracts(&[(hash1, bytecode1.clone()), (hash2, bytecode2.clone())]).unwrap();

        let (found, missing) = store.get_contracts(&[hash1, hash2, hash3]).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(missing, vec![hash3]);
        assert_eq!(found[&hash1].bytes_slice(), bytecode1.bytes_slice());
        assert_eq!(found[&hash2].bytes_slice(), bytecode2.bytes_slice());
    }

    #[test]
    fn test_genesis_roundtrip() {
        let (_dir, store) = temp_store();

        assert!(store.load_genesis().unwrap().is_none());

        let genesis = Genesis::default();
        store.store_genesis(&genesis).unwrap();

        let loaded = store.load_genesis().unwrap().unwrap();
        assert_eq!(loaded.config.chain_id, genesis.config.chain_id);
    }

    #[test]
    fn test_reset_to_anchor() {
        let (_dir, store) = temp_store();

        let anchor = BlockMeta {
            block_number: 50,
            block_hash: BlockHash::from([5u8; 32]),
            post_state_root: B256::from([6u8; 32]),
            post_withdrawals_root: B256::from([7u8; 32]),
        };

        // Set an advanced tip
        let tip = BlockMeta { block_number: 100, ..anchor.clone() };
        ChainStore::advance_chain(&store, &[tip]).unwrap();

        // Reset to anchor
        store.reset_to_anchor(&anchor).unwrap();

        let loaded_anchor = store.get_anchor_block().unwrap().unwrap();
        let loaded_tip = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(loaded_anchor, anchor);
        assert_eq!(loaded_tip, anchor);
    }

    #[test]
    fn test_contract_cache_memory_hit() {
        let (_dir, store) = temp_store();
        let cache = ContractCache::new(Arc::new(store));

        let hash = B256::from([1u8; 32]);
        let bytecode = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x00]));

        cache.insert(&[(hash, bytecode.clone())]).unwrap();

        // Should hit memory, not disk
        let (found, missing) = cache.get(&[hash]).unwrap();
        assert_eq!(found.len(), 1);
        assert!(missing.is_empty());
        assert_eq!(found[&hash].bytes_slice(), bytecode.bytes_slice());
    }

    #[test]
    fn test_contract_cache_disk_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");

        let hash = B256::from([1u8; 32]);
        let bytecode = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x00]));

        // Write directly to persistent store
        {
            let store = ValidatorDB::new(&db_path).unwrap();
            store.add_contracts(&[(hash, bytecode.clone())]).unwrap();
        }

        // Create new cache (empty memory) backed by same store
        let store = Arc::new(ValidatorDB::new(&db_path).unwrap());
        let cache = ContractCache::new(store);

        // Should fall back to disk
        let (found, missing) = cache.get(&[hash]).unwrap();
        assert_eq!(found.len(), 1);
        assert!(missing.is_empty());

        // Second lookup should hit memory
        let (found2, _) = cache.get(&[hash]).unwrap();
        assert_eq!(found2.len(), 1);
    }

    // -----------------------------------------------------------------------
    // ValidatorDB ChainStore trait tests
    // -----------------------------------------------------------------------

    fn make_block_meta(number: u64) -> BlockMeta {
        BlockMeta {
            block_number: number,
            block_hash: BlockHash::from([number as u8; 32]),
            post_state_root: B256::from([(number + 100) as u8; 32]),
            post_withdrawals_root: B256::from([(number + 200) as u8; 32]),
        }
    }

    #[test]
    fn test_get_block_hash() {
        let (_dir, store) = temp_store();

        let blocks: Vec<BlockMeta> = (10..=13).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();

        // Existing blocks
        for b in &blocks {
            let hash = ChainStore::get_block_hash(&store, b.block_number).unwrap();
            assert_eq!(hash, Some(b.block_hash));
        }

        // Non-existent block
        assert!(ChainStore::get_block_hash(&store, 99).unwrap().is_none());
    }

    #[test]
    fn test_get_earliest_block() {
        let (_dir, store) = temp_store();

        // Empty chain
        assert!(ChainStore::get_earliest_block(&store).unwrap().is_none());

        let blocks: Vec<BlockMeta> = (5..=8).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();

        let (number, hash) = ChainStore::get_earliest_block(&store).unwrap().unwrap();
        assert_eq!(number, 5);
        assert_eq!(hash, blocks[0].block_hash);
    }

    #[test]
    fn test_rollback_chain() {
        let (_dir, store) = temp_store();

        let blocks: Vec<BlockMeta> = (10..=15).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();

        // Rollback to block 12 (should remove 13, 14, 15)
        ChainStore::rollback_chain(&store, 12).unwrap();

        let tip = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(tip.block_number, 12);

        // Block 13+ should be gone
        assert!(ChainStore::get_block_hash(&store, 13).unwrap().is_none());
        assert!(ChainStore::get_block_hash(&store, 14).unwrap().is_none());
        assert!(ChainStore::get_block_hash(&store, 15).unwrap().is_none());

        // Block 10-12 should still exist
        assert!(ChainStore::get_block_hash(&store, 10).unwrap().is_some());
        assert!(ChainStore::get_block_hash(&store, 12).unwrap().is_some());
    }

    #[test]
    fn test_prune_chain() {
        let (_dir, db) = temp_server_db();

        // Populate via store_block_data so BLOCK_RECORDS is populated
        let blocks_data: Vec<_> = (1..=10)
            .map(|n| {
                let block = make_test_block(n, B256::from([n as u8; 32]));
                let witness = empty_light_witness();
                (block, witness)
            })
            .collect();
        db.store_block_data(&blocks_data).unwrap();

        let metas: Vec<BlockMeta> = (1..=10).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &metas).unwrap();

        // Prune blocks before block 6 (should remove 1-5)
        let pruned = PrunableChainStore::prune_chain(&db, 6).unwrap();
        assert_eq!(pruned, 5);

        // Blocks 1-5 should be gone
        for n in 1..=5 {
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_none());
        }
        // Blocks 6-10 should remain
        for n in 6..=10 {
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_some());
        }
    }

    #[test]
    fn test_advance_chain_inline_pruning() {
        let (_dir, store) = temp_store();
        store.set_max_chain_length(5);

        // Insert 5 blocks — no pruning yet
        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();
        assert!(ChainStore::get_block_hash(&store, 1).unwrap().is_some());

        // Insert 3 more — should prune oldest to keep 5
        let blocks: Vec<BlockMeta> = (6..=8).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();

        // Blocks 1-3 should be pruned, 4-8 should remain
        for n in 1..=3 {
            assert!(
                ChainStore::get_block_hash(&store, n).unwrap().is_none(),
                "block {n} should be pruned"
            );
        }
        for n in 4..=8 {
            assert!(
                ChainStore::get_block_hash(&store, n).unwrap().is_some(),
                "block {n} should exist"
            );
        }

        let tip = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(tip.block_number, 8);
    }

    #[test]
    fn test_advance_chain_empty_is_noop() {
        let (_dir, store) = temp_store();

        // Advancing with empty slice should not error
        ChainStore::advance_chain(&store, &[]).unwrap();
        assert!(store.get_canonical_tip().unwrap().is_none());
    }

    #[test]
    fn test_reset_to_anchor_clears_chain() {
        let (_dir, store) = temp_store();

        // Build a chain 1..=10
        let blocks: Vec<BlockMeta> = (1..=10).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();

        // Reset to a new anchor at block 50
        let anchor = make_block_meta(50);
        ChainStore::reset_to_anchor(&store, &anchor).unwrap();

        // Old blocks should be gone
        for n in 1..=10 {
            assert!(ChainStore::get_block_hash(&store, n).unwrap().is_none());
        }

        // Only the anchor block should exist
        let tip = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(tip, anchor);
        let stored_anchor = ChainStore::get_anchor(&store).unwrap().unwrap();
        assert_eq!(stored_anchor, anchor);
    }

    // -----------------------------------------------------------------------
    // ServerDB tests
    // -----------------------------------------------------------------------

    fn temp_server_db() -> (tempfile::TempDir, ServerDB) {
        let dir = tempfile::tempdir().unwrap();
        let db = ServerDB::new(dir.path().join("server.redb")).unwrap();
        (dir, db)
    }

    #[test]
    fn test_server_db_local_tip() {
        let (_dir, db) = temp_server_db();

        // Empty chain
        assert!(db.get_local_tip().unwrap().is_none());

        // Advance chain through ChainStore trait
        let blocks: Vec<BlockMeta> = (1..=3).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        let (number, hash) = db.get_local_tip().unwrap().unwrap();
        assert_eq!(number, 3);
        assert_eq!(hash, blocks[2].block_hash);
    }

    #[test]
    fn test_server_db_rollback() {
        let (_dir, db) = temp_server_db();

        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        db.rollback_chain(3).unwrap();
        let (number, _) = db.get_local_tip().unwrap().unwrap();
        assert_eq!(number, 3);

        // Block 4 and 5 should be gone
        assert!(db.get_block_hash(4).unwrap().is_none());
        assert!(db.get_block_hash(5).unwrap().is_none());
    }

    #[test]
    fn test_server_db_reset_anchor_block() {
        let (_dir, db) = temp_server_db();

        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        let anchor = make_block_meta(100);
        ChainStore::reset_to_anchor(&db, &anchor).unwrap();

        // Old blocks gone
        assert!(db.get_block_hash(1).unwrap().is_none());

        // Anchor is the sole entry
        let (number, hash) = db.get_local_tip().unwrap().unwrap();
        assert_eq!(number, 100);
        assert_eq!(hash, anchor.block_hash);
    }

    #[test]
    fn test_server_db_contract_codes() {
        let (_dir, db) = temp_server_db();

        let hash1 = B256::from([1u8; 32]);
        let hash2 = B256::from([2u8; 32]);
        let bytecode = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x00]));

        // Add via ContractStore trait
        ContractStore::add_contracts(&db, &[(hash1, bytecode.clone())]).unwrap();

        let (found, missing) = ContractStore::get_contracts(&db, &[hash1, hash2]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(missing, vec![hash2]);
        assert_eq!(found[&hash1].bytes_slice(), bytecode.bytes_slice());
    }

    #[test]
    fn test_server_db_chain_store_trait() {
        let (_dir, db) = temp_server_db();

        // Test through ChainStore trait
        assert!(ChainStore::get_canonical_tip(&db).unwrap().is_none());
        assert!(ChainStore::get_anchor(&db).unwrap().is_none());

        let blocks: Vec<BlockMeta> = (10..=12).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        let tip = ChainStore::get_canonical_tip(&db).unwrap().unwrap();
        assert_eq!(tip.block_number, 12);

        let earliest = ChainStore::get_earliest_block(&db).unwrap().unwrap();
        assert_eq!(earliest.0, 10);

        let hash = ChainStore::get_block_hash(&db, 11).unwrap().unwrap();
        assert_eq!(hash, blocks[1].block_hash);

        // Rollback via trait
        ChainStore::rollback_chain(&db, 10).unwrap();
        let tip = ChainStore::get_canonical_tip(&db).unwrap().unwrap();
        assert_eq!(tip.block_number, 10);

        // Reset via trait
        let anchor = make_block_meta(50);
        ChainStore::reset_to_anchor(&db, &anchor).unwrap();
        let tip = ChainStore::get_canonical_tip(&db).unwrap().unwrap();
        assert_eq!(tip, anchor);
    }

    #[test]
    fn test_server_db_prune_history() {
        let (_dir, db) = temp_server_db();

        // Use store_block_data to populate BLOCK_RECORDS along with block data
        // We need real-ish blocks for this, so let's test via the chain store prune
        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        // prune_history prunes via BLOCK_RECORDS, but we haven't populated those.
        // However, it also cleans orphaned CANONICAL_CHAIN entries.
        let pruned = db.prune_history(3).unwrap();
        // No BLOCK_RECORDS entries, so pruned count is 0 from that path
        assert_eq!(pruned, 0);

        // But the orphaned canonical chain cleanup should have removed blocks 1, 2
        assert!(db.get_block_hash(1).unwrap().is_none());
        assert!(db.get_block_hash(2).unwrap().is_none());
        // Block 3+ should remain
        assert!(db.get_block_hash(3).unwrap().is_some());
    }

    // -----------------------------------------------------------------------
    // Serialization roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_decode_roundtrip() {
        // Test with a simple Bytecode value
        let bytecode = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[
            0x60, 0x00, 0x60, 0x01, 0x01,
        ]));
        let encoded = encode_to_vec(&bytecode).unwrap();

        // Verify marker byte
        assert_eq!(encoded[0], BINCODE_LZ4_MARKER);

        let decoded: Bytecode = decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded.bytes_slice(), bytecode.bytes_slice());
    }

    #[test]
    fn test_block_meta_tuple_roundtrip() {
        let meta = make_block_meta(42);
        let tuple = meta.to_tuple();
        let roundtripped = BlockMeta::from_tuple(tuple);
        assert_eq!(meta, roundtripped);
    }

    // -----------------------------------------------------------------------
    // decode_from_slice error path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_from_slice_empty_data() {
        let result = decode_from_slice::<Bytecode>(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty data"));
    }

    #[test]
    fn test_decode_from_slice_wrong_marker() {
        let result = decode_from_slice::<Bytecode>(&[0xFF, 0x00]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown serialization marker"));
    }

    #[test]
    fn test_decode_from_slice_corrupted_lz4() {
        // Correct marker byte but garbage lz4 payload
        let result = decode_from_slice::<Bytecode>(&[BINCODE_LZ4_MARKER, 0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("lz4"));
    }

    // -----------------------------------------------------------------------
    // ServerDB BlockStore roundtrip tests
    // -----------------------------------------------------------------------

    fn make_test_block(
        number: u64,
        hash: B256,
    ) -> alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction> {
        let mut header = alloy_rpc_types_eth::Header::<alloy_consensus::Header>::default();
        header.inner.number = number;
        header.hash = hash;
        header.inner.withdrawals_root = Some(B256::ZERO);
        alloy_rpc_types_eth::Block { header, ..Default::default() }
    }

    fn empty_light_witness() -> crate::LightWitness {
        crate::LightWitness {
            kvs: std::collections::BTreeMap::new(),
            levels: rustc_hash::FxHashMap::default(),
        }
    }

    #[test]
    fn test_server_db_store_and_get_block_and_witness() {
        let (_dir, db) = temp_server_db();

        let block_hash = B256::from([42u8; 32]);
        let block = make_test_block(10, block_hash);
        let witness = empty_light_witness();

        // Store block + witness
        db.store_block_data(&[(block.clone(), witness)]).unwrap();

        // Retrieve and verify
        let (retrieved_block, _retrieved_witness) =
            db.get_block_and_witness(BlockHash::from(block_hash)).unwrap();
        assert_eq!(retrieved_block.header.number, 10);
        assert_eq!(retrieved_block.header.hash, block_hash);
    }

    #[test]
    fn test_server_db_get_block_and_witness_missing() {
        let (_dir, db) = temp_server_db();

        let missing_hash = BlockHash::from([0xFFu8; 32]);
        let result = db.get_block_and_witness(missing_hash);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            ValidationDbError::MissingData { kind: MissingDataKind::BlockData, block_hash } => {
                assert_eq!(block_hash, missing_hash);
            }
            other => panic!("expected MissingData error, got: {other}"),
        }
    }

    #[test]
    fn test_server_db_prune_history_with_block_records() {
        let (_dir, db) = temp_server_db();

        // Store blocks via store_block_data which populates BLOCK_RECORDS
        let blocks_data: Vec<_> = (1..=5)
            .map(|n| {
                let block = make_test_block(n, B256::from([n as u8; 32]));
                let witness = empty_light_witness();
                (block, witness)
            })
            .collect();
        db.store_block_data(&blocks_data).unwrap();

        // Also advance canonical chain so prune_history can clean those entries
        let metas: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &metas).unwrap();

        // Prune blocks before block 3 (should remove blocks 1 and 2)
        let pruned = db.prune_history(3).unwrap();
        assert_eq!(pruned, 2);

        // Blocks 1 and 2 should be gone from block data
        let result = db.get_block_and_witness(BlockHash::from(B256::from([1u8; 32])));
        assert!(result.is_err());
        let result = db.get_block_and_witness(BlockHash::from(B256::from([2u8; 32])));
        assert!(result.is_err());

        // Block 3 and beyond should still be accessible
        let (block, _witness) =
            db.get_block_and_witness(BlockHash::from(B256::from([3u8; 32]))).unwrap();
        assert_eq!(block.header.number, 3);
    }

    #[test]
    fn test_server_db_store_empty_blocks() {
        let (_dir, db) = temp_server_db();

        // Storing empty slice should be a no-op
        db.store_block_data(&[]).unwrap();
    }

    #[test]
    fn test_server_db_rollback_chain_via_trait() {
        let (_dir, db) = temp_server_db();

        // Store blocks via store_block_data to populate BLOCK_DATA
        let blocks_data: Vec<_> = (1..=5)
            .map(|n| {
                let block = make_test_block(n, B256::from([n as u8; 32]));
                let witness = empty_light_witness();
                (block, witness)
            })
            .collect();
        db.store_block_data(&blocks_data).unwrap();

        let metas: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &metas).unwrap();

        // Rollback to block 3
        ChainStore::rollback_chain(&db, 3).unwrap();

        // Tip should be 3
        let (number, _) = db.get_local_tip().unwrap().unwrap();
        assert_eq!(number, 3);

        // Blocks 4, 5 should still exist in BLOCK_DATA (rollback only affects canonical chain)
        // but canonical chain entries are gone
        assert!(db.get_block_hash(4).unwrap().is_none());
        assert!(db.get_block_hash(5).unwrap().is_none());
    }

    #[test]
    fn test_genesis_load_when_none_stored() {
        let (_dir, store) = temp_store();
        // No genesis stored — should return None
        assert!(store.load_genesis().unwrap().is_none());
    }
}
