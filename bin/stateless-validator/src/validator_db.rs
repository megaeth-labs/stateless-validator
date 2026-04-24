//! Minimal persistent storage backed by redb for the stateless validator.
//!
//! Only stores data that must survive restarts: anchor block, canonical tip,
//! contract bytecodes, and genesis configuration.
//!
//! CANONICAL_CHAIN is bounded to `max_chain_length` entries; older entries are
//! pruned inline during [`ChainStore::advance_chain`].

use std::{path::Path, sync::Arc};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber, map::HashMap};
use redb::ReadableDatabase;
use revm::state::Bytecode;
use stateless_core::db::{
    BlockMeta, ChainStore, ContractStore, GenesisStore, StoreResult, StoreResultExt,
};
use stateless_db::{
    ANCHOR_BLOCK, CANONICAL_CHAIN, CONTRACTS, DEFAULT_MAX_CHAIN_LENGTH, Database, GENESIS_CONFIG,
    read_anchor, read_block_hash, read_canonical_tip, read_contracts, read_earliest_block,
    write_add_contracts, write_advance_chain, write_reset_to_anchor, write_rollback_chain,
};

/// Minimal persistent storage backed by redb.
pub struct ValidatorDB {
    database: Database,
    /// Soft cap on the number of rows retained in `CANONICAL_CHAIN`. Oldest rows are pruned
    /// inline during `advance_chain` when the table exceeds this.
    max_chain_length: u64,
}

impl ValidatorDB {
    /// Creates or opens a persistent store at the given path, using [`DEFAULT_MAX_CHAIN_LENGTH`]
    /// as the canonical-chain retention cap. Use [`ValidatorDB::with_max_chain_length`] to
    /// override the cap.
    pub fn new(db_path: impl AsRef<Path>) -> StoreResult<Self> {
        Self::with_max_chain_length(db_path, DEFAULT_MAX_CHAIN_LENGTH)
    }

    /// Creates or opens a persistent store at the given path with an explicit
    /// canonical-chain retention cap.
    pub fn with_max_chain_length(
        db_path: impl AsRef<Path>,
        max_chain_length: u64,
    ) -> StoreResult<Self> {
        let database = Database::create(db_path).store_err()?;

        // Initialize all tables
        let write_txn = database.begin_write().store_err()?;
        {
            let _ = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
            let _ = write_txn.open_table(CONTRACTS).store_err()?;
            let _ = write_txn.open_table(GENESIS_CONFIG).store_err()?;
            let _ = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
        }
        write_txn.commit().store_err()?;

        Ok(Self { database, max_chain_length })
    }

    #[cfg(test)]
    fn set_anchor_block(&self, tip: &BlockMeta) -> StoreResult<()> {
        use stateless_db::block_meta_to_tuple;
        let write_txn = self.database.begin_write().store_err()?;
        {
            let mut table = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
            table.insert("anchor", block_meta_to_tuple(tip)).store_err()?;
        }
        write_txn.commit().store_err()?;
        Ok(())
    }
}

impl ContractStore for ValidatorDB {
    fn get_contracts(
        &self,
        hashes: &[B256],
    ) -> StoreResult<(HashMap<B256, Arc<Bytecode>>, Vec<B256>)> {
        read_contracts(&self.database, hashes)
    }

    fn add_contracts(&self, codes: &[(B256, Arc<Bytecode>)]) -> StoreResult<()> {
        write_add_contracts(&self.database, codes)
    }
}

impl GenesisStore for ValidatorDB {
    fn store_genesis(&self, genesis: &Genesis) -> StoreResult<()> {
        let json_bytes = serde_json::to_vec(genesis).store_err()?;
        let write_txn = self.database.begin_write().store_err()?;
        {
            let mut table = write_txn.open_table(GENESIS_CONFIG).store_err()?;
            table.insert("genesis", json_bytes).store_err()?;
        }
        write_txn.commit().store_err()?;
        Ok(())
    }

    fn load_genesis(&self) -> StoreResult<Option<Genesis>> {
        let read_txn = self.database.begin_read().store_err()?;
        let table = read_txn.open_table(GENESIS_CONFIG).store_err()?;
        match table.get("genesis").store_err()? {
            Some(data) => {
                let genesis: Genesis =
                    serde_json::from_slice(data.value().as_slice()).store_err()?;
                Ok(Some(genesis))
            }
            None => Ok(None),
        }
    }
}

impl ChainStore for ValidatorDB {
    fn get_canonical_tip(&self) -> StoreResult<Option<BlockMeta>> {
        read_canonical_tip(&self.database)
    }

    fn get_anchor(&self) -> StoreResult<Option<BlockMeta>> {
        read_anchor(&self.database)
    }

    fn advance_chain(&self, blocks: &[BlockMeta]) -> StoreResult<()> {
        // Delegate to the shared helper; validator applies its retention cap inline,
        // so the helper does the pruning in the same write transaction as the insert.
        write_advance_chain(&self.database, blocks, Some(self.max_chain_length))
    }

    fn get_block_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>> {
        read_block_hash(&self.database, block_number)
    }

    fn get_earliest_block(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
        read_earliest_block(&self.database)
    }

    fn rollback_chain(&self, to_block: BlockNumber) -> StoreResult<()> {
        write_rollback_chain(&self.database, to_block)
    }

    fn reset_to_anchor(&self, anchor: &BlockMeta) -> StoreResult<()> {
        write_reset_to_anchor(&self.database, anchor)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use stateless_db::ContractCache;

    use super::*;

    fn temp_store() -> (tempfile::TempDir, ValidatorDB) {
        let dir = tempfile::tempdir().unwrap();
        let store = ValidatorDB::new(dir.path().join("test.redb")).unwrap();
        (dir, store)
    }

    fn make_block_meta(number: u64) -> BlockMeta {
        BlockMeta {
            block_number: number,
            block_hash: BlockHash::from([number as u8; 32]),
            post_state_root: B256::from([(number + 100) as u8; 32]),
            post_withdrawals_root: B256::from([(number + 200) as u8; 32]),
        }
    }

    #[test]
    fn test_anchor_block_roundtrip() {
        let (_dir, store) = temp_store();

        assert!(ChainStore::get_anchor(&store).unwrap().is_none());

        let tip = BlockMeta {
            block_number: 42,
            block_hash: BlockHash::from([1u8; 32]),
            post_state_root: B256::from([2u8; 32]),
            post_withdrawals_root: B256::from([3u8; 32]),
        };
        store.set_anchor_block(&tip).unwrap();

        let loaded = ChainStore::get_anchor(&store).unwrap().unwrap();
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

        let bytecode1 =
            Arc::new(Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x00])));
        let bytecode2 =
            Arc::new(Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x01])));

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

        let tip = BlockMeta { block_number: 100, ..anchor.clone() };
        ChainStore::advance_chain(&store, &[tip]).unwrap();

        ChainStore::reset_to_anchor(&store, &anchor).unwrap();

        let loaded_anchor = ChainStore::get_anchor(&store).unwrap().unwrap();
        let loaded_tip = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(loaded_anchor, anchor);
        assert_eq!(loaded_tip, anchor);
    }

    #[test]
    fn test_contract_cache_memory_hit() {
        let (_dir, store) = temp_store();
        let cache = ContractCache::new(Arc::new(store));

        let hash = B256::from([1u8; 32]);
        let bytecode =
            Arc::new(Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x00])));

        cache.insert(&[(hash, bytecode.clone())]).unwrap();

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
        let bytecode =
            Arc::new(Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x00])));

        {
            let store = ValidatorDB::new(&db_path).unwrap();
            store.add_contracts(&[(hash, bytecode.clone())]).unwrap();
        }

        let store = Arc::new(ValidatorDB::new(&db_path).unwrap());
        let cache = ContractCache::new(store);

        let (found, missing) = cache.get(&[hash]).unwrap();
        assert_eq!(found.len(), 1);
        assert!(missing.is_empty());

        let (found2, _) = cache.get(&[hash]).unwrap();
        assert_eq!(found2.len(), 1);
    }

    #[test]
    fn test_get_block_hash() {
        let (_dir, store) = temp_store();

        let blocks: Vec<BlockMeta> = (10..=13).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();

        for b in &blocks {
            let hash = ChainStore::get_block_hash(&store, b.block_number).unwrap();
            assert_eq!(hash, Some(b.block_hash));
        }

        assert!(ChainStore::get_block_hash(&store, 99).unwrap().is_none());
    }

    #[test]
    fn test_get_earliest_block() {
        let (_dir, store) = temp_store();

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

        ChainStore::rollback_chain(&store, 12).unwrap();

        let tip = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(tip.block_number, 12);

        assert!(ChainStore::get_block_hash(&store, 13).unwrap().is_none());
        assert!(ChainStore::get_block_hash(&store, 14).unwrap().is_none());
        assert!(ChainStore::get_block_hash(&store, 15).unwrap().is_none());

        assert!(ChainStore::get_block_hash(&store, 10).unwrap().is_some());
        assert!(ChainStore::get_block_hash(&store, 12).unwrap().is_some());
    }

    #[test]
    fn test_advance_chain_inline_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let store = ValidatorDB::with_max_chain_length(dir.path().join("test.redb"), 5).unwrap();

        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();
        assert!(ChainStore::get_block_hash(&store, 1).unwrap().is_some());

        let blocks: Vec<BlockMeta> = (6..=8).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();

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

        ChainStore::advance_chain(&store, &[]).unwrap();
        assert!(store.get_canonical_tip().unwrap().is_none());
    }

    #[test]
    fn test_reset_to_anchor_clears_chain() {
        let (_dir, store) = temp_store();

        let blocks: Vec<BlockMeta> = (1..=10).map(make_block_meta).collect();
        ChainStore::advance_chain(&store, &blocks).unwrap();

        let anchor = make_block_meta(50);
        ChainStore::reset_to_anchor(&store, &anchor).unwrap();

        for n in 1..=10 {
            assert!(ChainStore::get_block_hash(&store, n).unwrap().is_none());
        }

        let tip = store.get_canonical_tip().unwrap().unwrap();
        assert_eq!(tip, anchor);
        let stored_anchor = ChainStore::get_anchor(&store).unwrap().unwrap();
        assert_eq!(stored_anchor, anchor);
    }

    #[test]
    fn test_genesis_load_when_none_stored() {
        let (_dir, store) = temp_store();
        assert!(store.load_genesis().unwrap().is_none());
    }
}
