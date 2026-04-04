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

use std::{collections::HashMap, fmt, path::Path, sync::Arc};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use dashmap::DashMap;
use op_alloy_rpc_types::Transaction;
use rayon::prelude::*;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use revm::state::Bytecode;
use salt::SaltWitness;
use thiserror::Error;

use crate::{LightWitness, withdrawals::MptWitness};

// ===========================================================================
// Shared table definitions
// ===========================================================================

/// Trusted anchor block. Singleton key "anchor".
/// Value: (block_number, block_hash, post_state_root, post_withdrawals_root).
/// Used by both [`ServerDB`] and [`ServerDB`].
#[allow(clippy::type_complexity)]
const ANCHOR_BLOCK: TableDefinition<&str, (u64, [u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("anchor_block");

/// Canonical chain. Maps BlockNumber → (BlockHash, PostStateRoot, PostWithdrawalsRoot).
/// Used by both [`ServerDB`] and [`ServerDB`].
#[allow(clippy::type_complexity)]
const CANONICAL_CHAIN: TableDefinition<u64, ([u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("canonical_chain");

/// Contract bytecode cache. Key: code_hash, Value: bincode+lz4 serialized Bytecode.
/// Used by both [`ServerDB`] and [`ServerDB`].
const CONTRACTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("contracts");

/// Genesis configuration (write-once). Singleton key "genesis", Value: JSON bytes.
/// Used by [`ServerDB`] only.
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
    fn prune_chain(&self, before_block: BlockNumber) -> eyre::Result<u64>;
}

/// Block/witness storage extension (debug-trace-server only).
pub trait BlockStore: ChainStore {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> eyre::Result<()>;
    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> eyre::Result<(Block<Transaction>, LightWitness)>;
}

// ===========================================================================
// Shared serialization helpers
// ===========================================================================

/// Version markers for serialization format
const BINCODE_STANDARD_MARKER: u8 = 0x01;
const BINCODE_LZ4_MARKER: u8 = 0x02;

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

/// Helper method to deserialize data using bincode
/// Supports lz4 compressed (new), standard (old), and legacy formats for backwards compatibility
fn decode_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    if bytes.is_empty() {
        panic!("cannot deserialize empty data");
    }

    match bytes[0] {
        BINCODE_LZ4_MARKER => {
            // New format: lz4 compressed + standard config
            let decompressed = lz4_flex::decompress_size_prepended(&bytes[1..])
                .expect("lz4 decompression must succeed");
            let (decoded, _) =
                bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())
                    .expect("deserialization of lz4+standard format data must succeed");
            decoded
        }
        BINCODE_STANDARD_MARKER => {
            // Standard format (uncompressed)
            let (decoded, _) =
                bincode::serde::decode_from_slice(&bytes[1..], bincode::config::standard())
                    .expect("deserialization of standard format data must succeed");
            decoded
        }
        _ => {
            // Legacy format: legacy config (no marker)
            let (decoded, _) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
                .expect("deserialization of legacy format data must succeed");
            decoded
        }
    }
}

/// Helper method to deserialize LightWitness using bincode
/// Supports lz4 compressed format (the only format used for LightWitness storage)
fn decode_light_witness_from_slice(bytes: &[u8]) -> LightWitness {
    if bytes.is_empty() {
        panic!("cannot deserialize empty data");
    }

    match bytes[0] {
        BINCODE_LZ4_MARKER => {
            // lz4 compressed + standard config
            let decompressed = lz4_flex::decompress_size_prepended(&bytes[1..])
                .expect("lz4 decompression must succeed");
            let (decoded, _): (LightWitness, _) =
                bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())
                    .expect(
                        "LightWitness deserialization of lz4+standard format data must succeed",
                    );
            decoded
        }
        BINCODE_STANDARD_MARKER => {
            // Standard format (uncompressed)
            let (decoded, _): (LightWitness, _) =
                bincode::serde::decode_from_slice(&bytes[1..], bincode::config::standard())
                    .expect("LightWitness deserialization of standard format data must succeed");
            decoded
        }
        _ => {
            // Legacy format: legacy config (no marker)
            let (decoded, _): (LightWitness, _) =
                bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
                    .expect("LightWitness deserialization of legacy format data must succeed");
            decoded
        }
    }
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
// ValidatorDB
// ===========================================================================

/// Minimal persistent storage backed by redb.
///
/// Only stores data that must survive restarts: anchor block, canonical tip,
/// contract bytecodes, and genesis configuration.
pub struct ValidatorDB {
    database: Database,
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

        Ok(Self { database })
    }

    // -- Anchor block --

    /// Returns the stored anchor block, or `None` if not set.
    pub fn get_anchor_block(&self) -> eyre::Result<Option<BlockMeta>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(ANCHOR_BLOCK)?;
        Ok(table.get("anchor")?.map(|v| BlockMeta::from_tuple(v.value())))
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
        let read_txn = self.database.begin_read()?;
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

    // -- Contracts --

    /// Retrieves cached contract bytecodes.
    ///
    /// Returns `(found, missing)` where `found` maps code hashes to bytecodes
    /// and `missing` lists code hashes not in the cache.
    pub fn get_contracts(
        &self,
        hashes: &[B256],
    ) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(CONTRACTS)?;

        let mut found = HashMap::new();
        let mut missing = Vec::new();

        for &hash in hashes {
            match table.get(hash.0)? {
                Some(data) => {
                    found.insert(hash, decode_from_slice(data.value().as_slice()));
                }
                None => missing.push(hash),
            }
        }

        Ok((found, missing))
    }

    /// Stores contract bytecodes in the cache.
    pub fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
        if codes.is_empty() {
            return Ok(());
        }
        let write_txn = self.database.begin_write()?;
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
        let write_txn = self.database.begin_write()?;
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
}

// ---------------------------------------------------------------------------
// ContractStore impl for ValidatorDB
// ---------------------------------------------------------------------------

impl ContractStore for ValidatorDB {
    fn get_contracts(&self, hashes: &[B256]) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
        ValidatorDB::get_contracts(self, hashes)
    }

    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
        ValidatorDB::add_contracts(self, codes)
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
        ValidatorDB::get_canonical_tip(self)
    }

    fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
        self.get_anchor_block()
    }

    fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let write_txn = self.database.begin_write()?;
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

    fn get_block_hash(&self, block_number: BlockNumber) -> eyre::Result<Option<BlockHash>> {
        let read_txn = self.database.begin_read()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN)?;
        Ok(chain.get(block_number)?.map(|v| BlockHash::from(v.value().0)))
    }

    fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN)?;
        Ok(chain.first()?.map(|(k, v)| (k.value(), BlockHash::from(v.value().0))))
    }

    fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()> {
        let write_txn = self.database.begin_write()?;
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

    fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
        ValidatorDB::reset_to_anchor(self, anchor)
    }

    fn prune_chain(&self, before_block: BlockNumber) -> eyre::Result<u64> {
        let read_txn = self.database.begin_read()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN)?;
        let to_remove: Vec<u64> = chain
            .range(..before_block)?
            .map(|r| r.map(|(k, _)| k.value()))
            .collect::<std::result::Result<_, _>>()?;
        let count = to_remove.len() as u64;
        drop(chain);
        drop(read_txn);

        if count > 0 {
            let write_txn = self.database.begin_write()?;
            {
                let mut chain = write_txn.open_table(CANONICAL_CHAIN)?;
                for n in &to_remove {
                    chain.remove(*n)?;
                }
            }
            write_txn.commit()?;
        }
        Ok(count)
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

    /// Rolls back the local canonical chain to the specified block number.
    ///
    /// Removes blocks from the canonical chain when a reorg occurs,
    /// reverting to the specified block number.
    pub fn rollback_chain(&self, to_block: BlockNumber) -> ValidationDbResult<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;

            let canonical_blocks_to_remove = canonical_chain
                .range((to_block + 1)..)?
                .map(|result| result.map(|(key, _)| key.value()))
                .collect::<Result<Vec<_>, _>>()?;

            for block_number in canonical_blocks_to_remove {
                canonical_chain.remove(block_number)?;
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

    /// Resets the chain anchor point and clears all chain state.
    ///
    /// This method resets the validator to start from a specific trusted block.
    /// It clears the canonical chain, then sets the new anchor block as the sole
    /// entry in the canonical chain.
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

            anchor_block_table.insert(
                "anchor",
                (block_number, block_hash.0, post_state_root.0, post_withdrawals_root.0),
            )?;
            canonical_chain.retain(|_, _| false)?;
            canonical_chain
                .insert(block_number, (block_hash.0, post_state_root.0, post_withdrawals_root.0))?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieves multiple cached contract bytecodes.
    ///
    /// Returns a tuple of (found_contracts, missing_hashes).
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
        let canonical_chain = read_txn.open_table(CANONICAL_CHAIN)?;

        Ok(canonical_chain.get(block_number)?.map(|value| value.value().0.into()))
    }

    /// Retrieves the earliest block in the canonical chain.
    pub fn get_earliest_local_block(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let canonical_chain = read_txn.open_table(CANONICAL_CHAIN)?;

        Ok(canonical_chain.first()?.map(|(key, value)| {
            let block_number = key.value();
            let (block_hash, _, _) = value.value();
            (block_number, block_hash.into())
        }))
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

        let witness = decode_light_witness_from_slice(&witness_bytes_value);
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
        Ok(ServerDB::get_contract_codes(self, hashes.iter().copied())?)
    }

    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
        if codes.is_empty() {
            return Ok(());
        }
        let write_txn = self.database.begin_write()?;
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
}

// ---------------------------------------------------------------------------
// ChainStore impl for ServerDB
// ---------------------------------------------------------------------------

impl ChainStore for ServerDB {
    fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
        let read_txn = self.database.begin_read()?;
        let canonical_chain = read_txn.open_table(CANONICAL_CHAIN)?;

        match canonical_chain.last()? {
            Some((key, value)) => {
                let block_number = key.value();
                let (block_hash, state_root, withdrawals_root) = value.value();
                Ok(Some(BlockMeta {
                    block_number,
                    block_hash: BlockHash::from(block_hash),
                    post_state_root: B256::from(state_root),
                    post_withdrawals_root: B256::from(withdrawals_root),
                }))
            }
            None => Ok(None),
        }
    }

    fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(ANCHOR_BLOCK)?;
        Ok(table.get("anchor")?.map(|v| BlockMeta::from_tuple(v.value())))
    }

    fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            for block in blocks {
                canonical_chain.insert(
                    block.block_number,
                    (block.block_hash.0, block.post_state_root.0, block.post_withdrawals_root.0),
                )?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn get_block_hash(&self, block_number: BlockNumber) -> eyre::Result<Option<BlockHash>> {
        Ok(ServerDB::get_block_hash(self, block_number)?)
    }

    fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
        Ok(ServerDB::get_earliest_local_block(self)?)
    }

    fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()> {
        Ok(ServerDB::rollback_chain(self, to_block)?)
    }

    fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
        Ok(ServerDB::reset_anchor_block(
            self,
            anchor.block_number,
            anchor.block_hash,
            anchor.post_state_root,
            anchor.post_withdrawals_root,
        )?)
    }

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
}
