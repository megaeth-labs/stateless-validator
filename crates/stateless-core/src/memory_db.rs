//! Memory-based pipeline database for stateless validation.
//!
//! This module provides a lightweight persistence layer and in-memory data structures
//! for the streaming validation pipeline. Only three categories of data are persisted:
//! - **Anchor block**: The trusted starting point for validation
//! - **Canonical tip**: The last successfully validated block
//! - **Contracts**: Immutable bytecode cache (content-addressed, grows monotonically)
//!
//! Block and witness data flows through in-memory channels and is never written to disk.

use std::{collections::HashMap, path::Path, sync::Arc};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use dashmap::DashMap;
use eyre::Result;
use op_alloy_rpc_types::Transaction;
use redb::{Database, ReadableDatabase, TableDefinition};
use revm::state::Bytecode;
use salt::SaltWitness;

use crate::withdrawals::MptWitness;

// ---------------------------------------------------------------------------
// redb table definitions (4 tables total)
// ---------------------------------------------------------------------------

/// Trusted anchor block. Singleton key "anchor".
/// Value: (block_number, block_hash, post_state_root, post_withdrawals_root)
#[allow(clippy::type_complexity)]
const ANCHOR_BLOCK: TableDefinition<&str, (u64, [u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("anchor_block");

/// Last successfully validated block. Singleton key "tip".
/// Value: (block_number, block_hash, post_state_root, post_withdrawals_root)
#[allow(clippy::type_complexity)]
const CANONICAL_TIP: TableDefinition<&str, (u64, [u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("canonical_tip");

/// Contract bytecode cache. Key: code_hash, Value: bincode+lz4 serialized Bytecode.
const CONTRACTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("contracts");

/// Genesis configuration (write-once). Singleton key "genesis", Value: JSON bytes.
const GENESIS_CONFIG: TableDefinition<&str, Vec<u8>> = TableDefinition::new("genesis_config");

// ---------------------------------------------------------------------------
// ChainTip — shared type for anchor and canonical tip
// ---------------------------------------------------------------------------

/// Represents a point on the chain with its state roots.
///
/// Used for both the trusted anchor block and the canonical chain tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
    pub post_state_root: B256,
    pub post_withdrawals_root: B256,
}

impl ChainTip {
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

// ---------------------------------------------------------------------------
// Pipeline data types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Serialization helpers (bincode + lz4, matching validator_db.rs format)
// ---------------------------------------------------------------------------

const BINCODE_LZ4_MARKER: u8 = 0x02;

fn encode_bytecode(bytecode: &Bytecode) -> Result<Vec<u8>> {
    let encoded = bincode::serde::encode_to_vec(bytecode, bincode::config::standard())
        .map_err(|e| eyre::eyre!("bincode encode: {e}"))?;
    let compressed = lz4_flex::compress_prepend_size(&encoded);
    let mut result = Vec::with_capacity(1 + compressed.len());
    result.push(BINCODE_LZ4_MARKER);
    result.extend(compressed);
    Ok(result)
}

fn decode_bytecode(bytes: &[u8]) -> Bytecode {
    assert!(!bytes.is_empty(), "cannot deserialize empty bytecode data");
    match bytes[0] {
        BINCODE_LZ4_MARKER => {
            let decompressed = lz4_flex::decompress_size_prepended(&bytes[1..])
                .expect("lz4 decompression must succeed");
            let (decoded, _) =
                bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())
                    .expect("bytecode deserialization must succeed");
            decoded
        }
        0x01 => {
            // standard (uncompressed) format
            let (decoded, _) =
                bincode::serde::decode_from_slice(&bytes[1..], bincode::config::standard())
                    .expect("bytecode deserialization must succeed");
            decoded
        }
        _ => {
            // legacy format
            let (decoded, _) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
                .expect("bytecode deserialization must succeed");
            decoded
        }
    }
}

// ---------------------------------------------------------------------------
// PersistentStore
// ---------------------------------------------------------------------------

/// Minimal persistent storage backed by redb.
///
/// Only stores data that must survive restarts: anchor block, canonical tip,
/// contract bytecodes, and genesis configuration.
pub struct PersistentStore {
    database: Database,
}

impl PersistentStore {
    /// Creates or opens a persistent store at the given path.
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let database = Database::create(db_path)?;

        // Initialize all tables
        let write_txn = database.begin_write()?;
        {
            let _ = write_txn.open_table(ANCHOR_BLOCK)?;
            let _ = write_txn.open_table(CANONICAL_TIP)?;
            let _ = write_txn.open_table(CONTRACTS)?;
            let _ = write_txn.open_table(GENESIS_CONFIG)?;
        }
        write_txn.commit()?;

        Ok(Self { database })
    }

    // -- Anchor block --

    /// Returns the stored anchor block, or `None` if not set.
    pub fn get_anchor_block(&self) -> Result<Option<ChainTip>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(ANCHOR_BLOCK)?;
        Ok(table.get("anchor")?.map(|v| ChainTip::from_tuple(v.value())))
    }

    /// Stores the anchor block.
    pub fn set_anchor_block(&self, tip: &ChainTip) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(ANCHOR_BLOCK)?;
            table.insert("anchor", tip.to_tuple())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // -- Canonical tip --

    /// Returns the last validated canonical tip, or `None` if not set.
    pub fn get_canonical_tip(&self) -> Result<Option<ChainTip>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(CANONICAL_TIP)?;
        Ok(table.get("tip")?.map(|v| ChainTip::from_tuple(v.value())))
    }

    /// Updates the canonical tip to the given validated block.
    pub fn set_canonical_tip(&self, tip: &ChainTip) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(CANONICAL_TIP)?;
            table.insert("tip", tip.to_tuple())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // -- Contracts --

    /// Retrieves cached contract bytecodes.
    ///
    /// Returns `(found, missing)` where `found` maps code hashes to bytecodes
    /// and `missing` lists code hashes not in the cache.
    pub fn get_contracts(&self, hashes: &[B256]) -> Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(CONTRACTS)?;

        let mut found = HashMap::new();
        let mut missing = Vec::new();

        for &hash in hashes {
            match table.get(hash.0)? {
                Some(data) => {
                    found.insert(hash, decode_bytecode(data.value().as_slice()));
                }
                None => missing.push(hash),
            }
        }

        Ok((found, missing))
    }

    /// Stores contract bytecodes in the cache.
    pub fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> Result<()> {
        if codes.is_empty() {
            return Ok(());
        }
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(CONTRACTS)?;
            for (hash, bytecode) in codes {
                let encoded = encode_bytecode(bytecode)?;
                table.insert(hash.0, encoded)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    // -- Genesis --

    /// Persists the genesis configuration as JSON.
    pub fn store_genesis(&self, genesis: &Genesis) -> Result<()> {
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
    pub fn load_genesis(&self) -> Result<Option<Genesis>> {
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
    pub fn reset_to_anchor(&self, anchor: &ChainTip) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK)?;
            anchor_table.insert("anchor", anchor.to_tuple())?;

            let mut tip_table = write_txn.open_table(CANONICAL_TIP)?;
            tip_table.insert("tip", anchor.to_tuple())?;
        }
        write_txn.commit()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ContractCache — DashMap with persistent write-through
// ---------------------------------------------------------------------------

/// In-memory contract bytecode cache backed by persistent storage.
///
/// Reads check the in-memory `DashMap` first, falling back to the persistent store.
/// Writes go to both memory and disk (write-through).
pub struct ContractCache {
    memory: DashMap<B256, Bytecode>,
    store: Arc<PersistentStore>,
}

impl ContractCache {
    /// Creates a new contract cache backed by the given persistent store.
    pub fn new(store: Arc<PersistentStore>) -> Self {
        Self { memory: DashMap::new(), store }
    }

    /// Retrieves contract bytecodes, checking memory first then persistent store.
    ///
    /// Returns `(found, missing)`.
    pub fn get(&self, hashes: &[B256]) -> Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
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
    pub fn insert(&self, codes: &[(B256, Bytecode)]) -> Result<()> {
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, PersistentStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistentStore::new(dir.path().join("test.redb")).unwrap();
        (dir, store)
    }

    #[test]
    fn test_anchor_block_roundtrip() {
        let (_dir, store) = temp_store();

        assert!(store.get_anchor_block().unwrap().is_none());

        let tip = ChainTip {
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

        let tip = ChainTip {
            block_number: 100,
            block_hash: BlockHash::from([10u8; 32]),
            post_state_root: B256::from([20u8; 32]),
            post_withdrawals_root: B256::from([30u8; 32]),
        };
        store.set_canonical_tip(&tip).unwrap();

        let loaded = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(loaded, tip);

        // Update tip
        let tip2 = ChainTip { block_number: 101, ..tip };
        store.set_canonical_tip(&tip2).unwrap();
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

        let anchor = ChainTip {
            block_number: 50,
            block_hash: BlockHash::from([5u8; 32]),
            post_state_root: B256::from([6u8; 32]),
            post_withdrawals_root: B256::from([7u8; 32]),
        };

        // Set an advanced tip
        let tip = ChainTip { block_number: 100, ..anchor.clone() };
        store.set_canonical_tip(&tip).unwrap();

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
            let store = PersistentStore::new(&db_path).unwrap();
            store.add_contracts(&[(hash, bytecode.clone())]).unwrap();
        }

        // Create new cache (empty memory) backed by same store
        let store = Arc::new(PersistentStore::new(&db_path).unwrap());
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
