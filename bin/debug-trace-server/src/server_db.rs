//! Block storage and chain tracking database for `debug-trace-server`.
//!
//! Provides persistent storage of block data, witnesses, and canonical chain state
//! for serving `debug_*` and `trace_*` RPC methods.

use std::path::Path;

use alloy_primitives::{B256, BlockHash, BlockNumber, map::HashMap};
use alloy_rpc_types_eth::Block;
use op_alloy_rpc_types::Transaction;
use rayon::prelude::*;
use redb::{ReadableDatabase, ReadableTable};
use revm::state::Bytecode;
use stateless_core::{
    DivergenceLookups, LightWitness,
    db::{
        BlockMeta, ChainStore, ContractStore, MissingDataKind, StoreError, StoreResult,
        StoreResultExt,
    },
};
use stateless_db::{
    ANCHOR_BLOCK, BLOCK_DATA, BLOCK_RECORDS, CANONICAL_CHAIN, CONTRACTS, Database, WITNESSES,
    decode_block_from_slice, decode_from_slice, encode_block_to_vec, encode_to_vec, read_anchor,
    read_block_hash, read_canonical_tip, read_contracts, read_history_floor, write_add_contracts,
    write_advance_chain, write_canonical_hash_below_floor, write_ensure_history_floor,
    write_reset_to_anchor_preserving_history, write_rollback_chain,
};

/// Block/witness storage + history pruning — **debug-trace-server-only**. This capability is
/// specific to this bin (no other scenario stores raw blocks/witnesses or prunes a per-block
/// chain on a schedule), so it lives here rather than as a stateless-core trait.
///
/// Supertraits: [`ChainStore`] (chain cursors) + [`DivergenceLookups`] (this bin bisects on reorg,
/// and the DB-range metric reads `get_earliest`). Pruning is not part of the trait: the
/// history pruner works on the concrete [`ServerDB`] (inherent
/// `prune_history`), while this trait is the read/append seam shared with `DataProvider`
/// and chain sync.
pub trait BlockStore: ChainStore + DivergenceLookups {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()>;
    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> StoreResult<(Block<Transaction>, LightWitness)>;
    /// Persists an upstream-resolved canonical row, strictly below the history floor —
    /// the lazy write-back that makes the next by-number request for this height resolve
    /// locally. A row at or above the floor is skipped silently: that range is owned by
    /// chain sync (and is what reorg bisection trusts).
    fn record_canonical_hash(&self, meta: &BlockMeta) -> StoreResult<()>;
}

/// Block storage and chain tracking database for debug-trace-server.
pub struct ServerDB {
    database: Database,
}

impl ServerDB {
    /// Create a new redb instance or open an existing one.
    pub fn new(db_path: impl AsRef<Path>) -> StoreResult<Self> {
        let database = Database::create(db_path).store_err()?;

        let write_txn = database.begin_write().store_err()?;
        {
            let _canonical_chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
            let _block_data = write_txn.open_table(BLOCK_DATA).store_err()?;
            let _witnesses = write_txn.open_table(WITNESSES).store_err()?;
            let _block_records = write_txn.open_table(BLOCK_RECORDS).store_err()?;
            let _contracts = write_txn.open_table(CONTRACTS).store_err()?;
            let _anchor_block = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
        }
        write_txn.commit().store_err()?;

        // Open-time invariant, not a caller ritual: legacy databases (created before floor
        // tracking) get their floor row materialized before any lazy write-back can run —
        // written-back rows must stay out of the reorg-bisection range, which starts at
        // the floor. Fresh databases are a no-op (the anchor reset installs the floor).
        let _ = write_ensure_history_floor(&database)?;

        Ok(Self { database })
    }

    /// Stores block data and witnesses.
    pub fn store_block_data(
        &self,
        tasks: &[(Block<Transaction>, LightWitness)],
    ) -> StoreResult<()> {
        if tasks.is_empty() {
            return Ok(());
        }

        let tasks = tasks
            .par_iter()
            .map(|(block, light_witness)| {
                Ok::<_, StoreError>((
                    block.header.number,
                    block.header.hash.0,
                    encode_block_to_vec(block)?,
                    encode_to_vec(light_witness)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let write_txn = self.database.begin_write().store_err()?;
        {
            let mut block_data = write_txn.open_table(BLOCK_DATA).store_err()?;
            let mut witnesses = write_txn.open_table(WITNESSES).store_err()?;
            let mut block_records = write_txn.open_table(BLOCK_RECORDS).store_err()?;

            for (number, hash, block, light_witness) in tasks {
                block_data.insert(hash, block).store_err()?;
                witnesses.insert(hash, light_witness).store_err()?;
                block_records.insert((number, hash), ()).store_err()?;
            }
        }
        write_txn.commit().store_err()?;
        Ok(())
    }

    /// Gets the latest block in the local chain.
    pub fn get_local_tip(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read().store_err()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN).store_err()?;
        Ok(chain.last().store_err()?.map(|(k, v)| {
            let (hash, _, _) = v.value();
            (k.value(), BlockHash::from(hash))
        }))
    }

    /// Cleans up old block bodies to save storage space.
    ///
    /// Removes BLOCK_RECORDS + BLOCK_DATA + WITNESSES rows strictly below `before_block`;
    /// the returned count is the number of BLOCK_RECORDS entries removed. CANONICAL_CHAIN
    /// is deliberately untouched: the number -> hash index is a permanent record backing
    /// canonical-hash resolution for the response cache, and its rows are two orders of
    /// magnitude smaller than the bodies this prune exists to reclaim.
    pub fn prune_history(&self, before_block: BlockNumber) -> StoreResult<u64> {
        // Single write txn: scan + delete under one snapshot so a concurrently-committed
        // row below `before_block` can't slip past the scan and leak as an orphan.
        // Same pattern as `write_rollback_chain` in stateless-db's helpers.
        let write_txn = self.database.begin_write().store_err()?;
        let pruned_count = {
            let mut block_records = write_txn.open_table(BLOCK_RECORDS).store_err()?;
            let mut block_data = write_txn.open_table(BLOCK_DATA).store_err()?;
            let mut witnesses = write_txn.open_table(WITNESSES).store_err()?;

            let keys_to_remove: Vec<(BlockNumber, [u8; 32])> = block_records
                .range(..(before_block, [0u8; 32]))
                .store_err()?
                .map(|result| result.map(|(key, _)| key.value()))
                .collect::<Result<Vec<_>, _>>()
                .store_err()?;
            let pruned_count = keys_to_remove.len() as u64;

            for (block_number, block_hash) in keys_to_remove {
                block_records.remove((block_number, block_hash)).store_err()?;
                block_data.remove(block_hash).store_err()?;
                witnesses.remove(block_hash).store_err()?;
            }

            pruned_count
        };
        write_txn.commit().store_err()?;
        Ok(pruned_count)
    }

    /// Earliest BLOCK_RECORDS entry — the lower edge of body/witness retention. The
    /// canonical index now outlives the bodies, so `get_earliest` no longer reflects what
    /// this reports.
    pub fn get_earliest_block_record(&self) -> StoreResult<Option<BlockNumber>> {
        let read_txn = self.database.begin_read().store_err()?;
        let records = read_txn.open_table(BLOCK_RECORDS).store_err()?;
        Ok(records.first().store_err()?.map(|(k, _)| k.value().0))
    }

    /// Retrieves block data and witness for a specific block hash.
    pub fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> StoreResult<(Block<Transaction>, LightWitness)> {
        let start = std::time::Instant::now();

        let read_txn = self.database.begin_read().store_err()?;
        let block_data = read_txn.open_table(BLOCK_DATA).store_err()?;
        let witnesses = read_txn.open_table(WITNESSES).store_err()?;
        let txn_ms = start.elapsed().as_millis();

        let block_bytes = block_data
            .get(block_hash.0)
            .store_err()?
            .ok_or(StoreError::MissingData { kind: MissingDataKind::Block, block_hash })?;
        let block_bytes_value = block_bytes.value();
        let block_bytes_len = block_bytes_value.len();
        let db_read_block_ms = start.elapsed().as_millis();

        let block = decode_block_from_slice(&block_bytes_value)?;
        let block_decode_ms = start.elapsed().as_millis();

        let witness_bytes = witnesses
            .get(block_hash.0)
            .store_err()?
            .ok_or(StoreError::MissingData { kind: MissingDataKind::Witness, block_hash })?;
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

impl ContractStore for ServerDB {
    fn get_contracts(&self, hashes: &[B256]) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
        read_contracts(&self.database, hashes)
    }

    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> StoreResult<()> {
        write_add_contracts(&self.database, codes)
    }
}

impl ChainStore for ServerDB {
    fn get_canonical_tip(&self) -> StoreResult<Option<BlockMeta>> {
        read_canonical_tip(&self.database)
    }

    fn get_anchor(&self) -> StoreResult<Option<BlockMeta>> {
        read_anchor(&self.database)
    }

    fn advance_chain(&self, blocks: &[BlockMeta]) -> StoreResult<()> {
        // `None`: trace server's retention is handled by the background `history_pruner`
        // task, not inline. See `bin/debug-trace-server/src/main.rs::history_pruner`.
        write_advance_chain(&self.database, blocks, None)
    }

    fn get_block_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>> {
        read_block_hash(&self.database, block_number)
    }

    fn rollback_chain(&self, to_block: BlockNumber) -> StoreResult<()> {
        write_rollback_chain(&self.database, to_block)
    }

    fn reset_to_anchor(&self, anchor: &BlockMeta) -> StoreResult<()> {
        // History-preserving variant: a stale reset must not erase the permanent canonical
        // index — rows below the anchor stay serviceable for number -> hash resolution.
        write_reset_to_anchor_preserving_history(&self.database, anchor)
    }
}

impl DivergenceLookups for ServerDB {
    fn get_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>> {
        // Same as the canonical block-hash read; delegate so the two can't drift.
        ChainStore::get_block_hash(self, block_number)
    }

    fn get_earliest(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
        // The floor, not `chain.first()`: divergence bisection requires a hole-free range
        // up to the tip, and rows below the floor (written-back history, pre-reset islands)
        // don't guarantee that.
        read_history_floor(&self.database)
    }
}

impl BlockStore for ServerDB {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()> {
        ServerDB::store_block_data(self, blocks)
    }

    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> StoreResult<(Block<Transaction>, LightWitness)> {
        ServerDB::get_block_and_witness(self, block_hash)
    }

    fn record_canonical_hash(&self, meta: &BlockMeta) -> StoreResult<()> {
        // Floor gate, TOCTOU safety, and durability choice live in the shared helper —
        // see `write_canonical_hash_below_floor`.
        write_canonical_hash_below_floor(&self.database, meta)
    }
}

/// Block/meta/witness fixtures shared with the `chain_sync` and `main` test modules.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn make_block_meta(number: u64) -> BlockMeta {
        BlockMeta {
            block_number: number,
            block_hash: BlockHash::from([number as u8; 32]),
            post_state_root: B256::from([(number + 100) as u8; 32]),
            post_withdrawals_root: B256::from([(number + 200) as u8; 32]),
        }
    }

    pub(crate) fn make_test_block(number: u64, hash: B256) -> Block<Transaction> {
        let mut header = alloy_rpc_types_eth::Header::<alloy_consensus::Header>::default();
        header.inner.number = number;
        header.hash = hash;
        header.inner.withdrawals_root = Some(B256::ZERO);
        Block { header, ..Default::default() }
    }

    pub(crate) fn empty_light_witness() -> LightWitness {
        LightWitness { kvs: std::collections::BTreeMap::new(), levels: Default::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::*, *};

    fn temp_server_db() -> (tempfile::TempDir, ServerDB) {
        let dir = tempfile::tempdir().unwrap();
        let db = ServerDB::new(dir.path().join("server.redb")).unwrap();
        (dir, db)
    }

    #[test]
    fn test_server_db_local_tip() {
        let (_dir, db) = temp_server_db();

        assert!(db.get_local_tip().unwrap().is_none());

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

        ChainStore::rollback_chain(&db, 3).unwrap();
        let (number, _) = db.get_local_tip().unwrap().unwrap();
        assert_eq!(number, 3);

        assert!(ChainStore::get_block_hash(&db, 4).unwrap().is_none());
        assert!(ChainStore::get_block_hash(&db, 5).unwrap().is_none());
    }

    #[test]
    fn test_server_db_contract_codes() {
        let (_dir, db) = temp_server_db();

        let hash1 = B256::from([1u8; 32]);
        let hash2 = B256::from([2u8; 32]);
        let bytecode = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x60, 0x00]));

        ContractStore::add_contracts(&db, &[(hash1, bytecode.clone())]).unwrap();

        let (found, missing) = ContractStore::get_contracts(&db, &[hash1, hash2]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(missing, vec![hash2]);
        assert_eq!(found[&hash1].bytes_slice(), bytecode.bytes_slice());
    }

    #[test]
    fn test_server_db_chain_store_trait() {
        let (_dir, db) = temp_server_db();

        assert!(ChainStore::get_canonical_tip(&db).unwrap().is_none());
        assert!(ChainStore::get_anchor(&db).unwrap().is_none());

        let blocks: Vec<BlockMeta> = (10..=12).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        let tip = ChainStore::get_canonical_tip(&db).unwrap().unwrap();
        assert_eq!(tip.block_number, 12);

        let earliest = DivergenceLookups::get_earliest(&db).unwrap().unwrap();
        assert_eq!(earliest.0, 10);

        let hash = ChainStore::get_block_hash(&db, 11).unwrap().unwrap();
        assert_eq!(hash, blocks[1].block_hash);

        ChainStore::rollback_chain(&db, 10).unwrap();
        let tip = ChainStore::get_canonical_tip(&db).unwrap().unwrap();
        assert_eq!(tip.block_number, 10);

        let anchor = make_block_meta(50);
        ChainStore::reset_to_anchor(&db, &anchor).unwrap();
        let tip = ChainStore::get_canonical_tip(&db).unwrap().unwrap();
        assert_eq!(tip, anchor);

        // The reset preserves history: the row below the anchor survives as an island,
        // while the floor (`get_earliest`) moves up to the anchor.
        assert_eq!(ChainStore::get_block_hash(&db, 10).unwrap(), Some(blocks[0].block_hash));
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap(), Some((50, anchor.block_hash)));
    }

    /// `prune_history` never touches the canonical index: rows inserted via
    /// `advance_chain` (with no stored bodies) survive a prune untouched.
    #[test]
    fn test_server_db_prune_history_retains_canonical_index() {
        let (_dir, db) = temp_server_db();

        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        let pruned = db.prune_history(3).unwrap();
        assert_eq!(pruned, 0, "no block records existed, so nothing counts as pruned");

        for n in 1..=5 {
            assert!(
                ChainStore::get_block_hash(&db, n).unwrap().is_some(),
                "canonical row {n} must survive pruning"
            );
        }
    }

    #[test]
    fn test_prune_chain() {
        let (_dir, db) = temp_server_db();

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

        let pruned = db.prune_history(6).unwrap();
        assert_eq!(pruned, 5);

        // Bodies below 6 are gone; the canonical index keeps every row.
        for n in 1..=5u64 {
            assert!(db.get_block_and_witness(BlockHash::from([n as u8; 32])).is_err());
        }
        for n in 6..=10u64 {
            assert!(db.get_block_and_witness(BlockHash::from([n as u8; 32])).is_ok());
        }
        for n in 1..=10 {
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_some());
        }
        assert_eq!(db.get_earliest_block_record().unwrap(), Some(6));
    }

    #[test]
    fn test_server_db_store_and_get_block_and_witness() {
        let (_dir, db) = temp_server_db();

        let block_hash = B256::from([42u8; 32]);
        let block = make_test_block(10, block_hash);
        let witness = empty_light_witness();

        db.store_block_data(&[(block.clone(), witness)]).unwrap();

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
            StoreError::MissingData { kind: MissingDataKind::Block, block_hash } => {
                assert_eq!(block_hash, missing_hash);
            }
            other => panic!("expected MissingData error, got: {other}"),
        }
    }

    #[test]
    fn test_server_db_prune_history_with_block_records() {
        let (_dir, db) = temp_server_db();

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

        let pruned = db.prune_history(3).unwrap();
        assert_eq!(pruned, 2);

        let result = db.get_block_and_witness(BlockHash::from(B256::from([1u8; 32])));
        assert!(result.is_err());
        let result = db.get_block_and_witness(BlockHash::from(B256::from([2u8; 32])));
        assert!(result.is_err());

        let (block, _witness) =
            db.get_block_and_witness(BlockHash::from(B256::from([3u8; 32]))).unwrap();
        assert_eq!(block.header.number, 3);
    }

    #[test]
    fn test_server_db_store_empty_blocks() {
        let (_dir, db) = temp_server_db();
        db.store_block_data(&[]).unwrap();
    }

    #[test]
    fn test_server_db_rollback_chain_via_trait() {
        let (_dir, db) = temp_server_db();

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

        ChainStore::rollback_chain(&db, 3).unwrap();

        let (number, _) = db.get_local_tip().unwrap().unwrap();
        assert_eq!(number, 3);

        assert!(ChainStore::get_block_hash(&db, 4).unwrap().is_none());
        assert!(ChainStore::get_block_hash(&db, 5).unwrap().is_none());
    }

    /// Opening a legacy database (chain rows but no floor row) materializes the floor as
    /// an open-time invariant of `ServerDB::new` — and the persisted row then wins over
    /// rows that later appear below it.
    #[test]
    fn reopen_materializes_history_floor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.redb");
        {
            // Simulates a pre-floor database: rows exist, no floor row was ever written
            // (advance_chain alone never writes one; the fresh-DB open found no rows).
            let db = ServerDB::new(&path).unwrap();
            ChainStore::advance_chain(&db, &(8..=9).map(make_block_meta).collect::<Vec<_>>())
                .unwrap();
        }

        let db = ServerDB::new(&path).unwrap();
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 8);

        ChainStore::advance_chain(&db, &[make_block_meta(2)]).unwrap();
        assert_eq!(
            DivergenceLookups::get_earliest(&db).unwrap().unwrap().0,
            8,
            "a row below the floor must not move it"
        );
    }

    /// The lazy write-back only lands strictly below the floor: rows at/above the floor
    /// (chain-sync territory) and writes without any floor are skipped silently, and a
    /// skipped write never mutates an existing row.
    #[test]
    fn record_canonical_hash_only_writes_below_floor() {
        let (_dir, db) = temp_server_db();

        // No floor row at all (fresh DB): nothing is written.
        db.record_canonical_hash(&make_block_meta(5)).unwrap();
        assert_eq!(ChainStore::get_block_hash(&db, 5).unwrap(), None);

        // The anchor-init path installs the floor at 10.
        ChainStore::reset_to_anchor(&db, &make_block_meta(10)).unwrap();

        // Below the floor: written, readable, and the floor/tip cursors stay put.
        db.record_canonical_hash(&make_block_meta(5)).unwrap();
        assert_eq!(
            ChainStore::get_block_hash(&db, 5).unwrap(),
            Some(make_block_meta(5).block_hash)
        );
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 10);
        assert_eq!(db.get_local_tip().unwrap().unwrap().0, 10);

        // Above the tip: skipped — a write here would corrupt the tip cursor.
        db.record_canonical_hash(&make_block_meta(12)).unwrap();
        assert_eq!(ChainStore::get_block_hash(&db, 12).unwrap(), None);
        assert_eq!(db.get_local_tip().unwrap().unwrap().0, 10);

        // At the floor itself with a different hash: skipped, the original row wins.
        let mut forged = make_block_meta(10);
        forged.block_hash = BlockHash::from([0xAA; 32]);
        db.record_canonical_hash(&forged).unwrap();
        assert_eq!(
            ChainStore::get_block_hash(&db, 10).unwrap(),
            Some(make_block_meta(10).block_hash)
        );
    }

    /// Rows below the floor stay readable for canonical-hash resolution even though
    /// `get_earliest` (the bisection contract) reports only the contiguous suffix.
    #[test]
    fn rows_below_floor_serve_hash_lookups() {
        let (_dir, db) = temp_server_db();
        ChainStore::advance_chain(&db, &[make_block_meta(3)]).unwrap();
        ChainStore::reset_to_anchor(&db, &make_block_meta(10)).unwrap();

        assert_eq!(
            DivergenceLookups::get_earliest(&db).unwrap(),
            Some((10, make_block_meta(10).block_hash))
        );
        assert_eq!(
            ChainStore::get_block_hash(&db, 3).unwrap(),
            Some(make_block_meta(3).block_hash)
        );
    }
}
