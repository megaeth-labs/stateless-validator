//! Shared redb persistence layer for stateless validation.
//!
//! Provides table definitions, serialization helpers, and common database
//! operations used by both `ValidatorDB` (stateless-validator) and
//! `ServerDB` (debug-trace-server).
//!
//! Also contains [`ContractCache`], an in-memory write-through cache
//! backed by any [`ContractStore`] implementation.

use std::{collections::HashMap, fmt, sync::Arc};

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use dashmap::DashMap;
use op_alloy_rpc_types::Transaction;
pub use redb::Database;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use revm::state::Bytecode;
use stateless_core::db::{BlockMeta, ContractStore};
use thiserror::Error;

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

pub type ValidationDbResult<T> = std::result::Result<T, ValidationDbError>;

/// Trusted anchor block. Singleton key "anchor".
/// Value: (block_number, block_hash, post_state_root, post_withdrawals_root).
/// Used by both `ValidatorDB` and `ServerDB`.
#[allow(clippy::type_complexity)]
pub const ANCHOR_BLOCK: TableDefinition<&str, (u64, [u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("anchor_block");

/// Canonical chain. Maps BlockNumber → (BlockHash, PostStateRoot, PostWithdrawalsRoot).
/// Used by both `ValidatorDB` and `ServerDB`.
#[allow(clippy::type_complexity)]
pub const CANONICAL_CHAIN: TableDefinition<u64, ([u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("canonical_chain");

/// Contract bytecode cache. Key: code_hash, Value: bincode+lz4 serialized Bytecode.
/// Used by both `ValidatorDB` and `ServerDB`.
pub const CONTRACTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("contracts");

/// Genesis configuration (write-once). Singleton key "genesis", Value: JSON bytes.
/// Used by `ValidatorDB` only.
pub const GENESIS_CONFIG: TableDefinition<&str, Vec<u8>> = TableDefinition::new("genesis_config");

/// Complete block data. Maps BlockHash → serialized Block<Transaction>.
/// Used by `ServerDB` only.
pub const BLOCK_DATA: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("block_data");

/// Light witness data. Maps BlockHash → serialized LightWitness.
/// Used by `ServerDB` only.
pub const WITNESSES: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("witnesses");

/// Block registry for pruning. Maps (BlockNumber, BlockHash) → ().
/// Used by `ServerDB` only.
pub const BLOCK_RECORDS: TableDefinition<(u64, [u8; 32]), ()> =
    TableDefinition::new("block_records");

/// Default maximum number of entries to retain in CANONICAL_CHAIN.
pub const DEFAULT_MAX_CHAIN_LENGTH: u64 = 1000;

/// Converts a [`BlockMeta`] to a raw tuple for redb storage.
pub fn block_meta_to_tuple(meta: &BlockMeta) -> (u64, [u8; 32], [u8; 32], [u8; 32]) {
    (meta.block_number, meta.block_hash.0, meta.post_state_root.0, meta.post_withdrawals_root.0)
}

/// Reconstructs a [`BlockMeta`] from a raw redb tuple.
pub fn block_meta_from_tuple(t: (u64, [u8; 32], [u8; 32], [u8; 32])) -> BlockMeta {
    BlockMeta {
        block_number: t.0,
        block_hash: BlockHash::from(t.1),
        post_state_root: B256::from(t.2),
        post_withdrawals_root: B256::from(t.3),
    }
}

/// Marker byte prepended to lz4-compressed bincode data.
pub const BINCODE_LZ4_MARKER: u8 = 0x01;

/// Serializes data using bincode + lz4 compression.
/// Format: [marker byte][lz4 compressed bincode data]
pub fn encode_to_vec<T: serde::Serialize>(data: &T) -> ValidationDbResult<Vec<u8>> {
    let encoded = bincode::serde::encode_to_vec(data, bincode::config::standard())
        .map_err(SerializationError::from)?;

    let compressed = lz4_flex::compress_prepend_size(&encoded);

    let mut result = Vec::with_capacity(1 + compressed.len());
    result.push(BINCODE_LZ4_MARKER);
    result.extend(compressed);
    Ok(result)
}

/// Deserializes lz4-compressed bincode data written by [`encode_to_vec`].
pub fn decode_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> ValidationDbResult<T> {
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

/// Serializes Block<Transaction> using JSON.
pub fn encode_block_to_vec(block: &Block<Transaction>) -> ValidationDbResult<Vec<u8>> {
    let encoded = serde_json::to_vec(block).map_err(SerializationError::from)?;
    Ok(encoded)
}

/// Deserializes Block<Transaction> from JSON bytes.
pub fn decode_block_from_slice(bytes: &[u8]) -> Result<Block<Transaction>, SerializationError> {
    serde_json::from_slice(bytes).map_err(SerializationError::Json)
}

/// Reads the canonical tip (highest block) from CANONICAL_CHAIN.
pub fn db_get_canonical_tip(database: &Database) -> eyre::Result<Option<BlockMeta>> {
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
pub fn db_get_anchor(database: &Database) -> eyre::Result<Option<BlockMeta>> {
    let read_txn = database.begin_read()?;
    let table = read_txn.open_table(ANCHOR_BLOCK)?;
    Ok(table.get("anchor")?.map(|v| block_meta_from_tuple(v.value())))
}

/// Looks up a single block hash from CANONICAL_CHAIN.
pub fn db_get_block_hash(
    database: &Database,
    block_number: BlockNumber,
) -> eyre::Result<Option<BlockHash>> {
    let read_txn = database.begin_read()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN)?;
    Ok(chain.get(block_number)?.map(|v| BlockHash::from(v.value().0)))
}

/// Returns the earliest (lowest block number) entry in CANONICAL_CHAIN.
pub fn db_get_earliest_block(
    database: &Database,
) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
    let read_txn = database.begin_read()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN)?;
    Ok(chain.first()?.map(|(k, v)| (k.value(), BlockHash::from(v.value().0))))
}

/// Appends blocks to CANONICAL_CHAIN in a single write transaction.
pub fn db_advance_chain(database: &Database, blocks: &[BlockMeta]) -> eyre::Result<()> {
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
pub fn db_rollback_chain(database: &Database, to_block: BlockNumber) -> eyre::Result<()> {
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
pub fn db_reset_to_anchor(database: &Database, anchor: &BlockMeta) -> eyre::Result<()> {
    let write_txn = database.begin_write()?;
    {
        let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK)?;
        anchor_table.insert("anchor", block_meta_to_tuple(anchor))?;

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
pub fn db_get_contracts(
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
pub fn db_add_contracts(database: &Database, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
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

        let (from_disk, missing) = self.store.get_contracts(&not_in_memory)?;

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

        self.store.add_contracts(codes)?;

        for (hash, bytecode) in codes {
            self.memory.insert(*hash, bytecode.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let bytecode = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[
            0x60, 0x00, 0x60, 0x01, 0x01,
        ]));
        let encoded = encode_to_vec(&bytecode).unwrap();

        assert_eq!(encoded[0], BINCODE_LZ4_MARKER);

        let decoded: Bytecode = decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded.bytes_slice(), bytecode.bytes_slice());
    }

    #[test]
    fn test_block_meta_tuple_roundtrip() {
        let meta = BlockMeta {
            block_number: 42,
            block_hash: BlockHash::from([42u8; 32]),
            post_state_root: B256::from([142u8; 32]),
            post_withdrawals_root: B256::from([242u8; 32]),
        };
        let tuple = block_meta_to_tuple(&meta);
        let roundtripped = block_meta_from_tuple(tuple);
        assert_eq!(meta, roundtripped);
    }

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
        let result = decode_from_slice::<Bytecode>(&[BINCODE_LZ4_MARKER, 0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("lz4"));
    }
}
