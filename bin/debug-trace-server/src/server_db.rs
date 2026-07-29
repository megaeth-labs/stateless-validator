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
    ANCHOR_BLOCK, BLOCK_DATA, BLOCK_RECORDS, CANONICAL_CHAIN, CONTRACTS, Database, HASH_ARCHIVE,
    WITNESSES, block_meta_to_tuple, decode_block_from_slice, decode_from_slice,
    encode_block_to_vec, encode_to_vec, read_anchor, read_block_hash, read_canonical_tip,
    read_contracts, read_earliest_block, write_add_contracts, write_advance_chain,
    write_rollback_chain,
};

/// Block/witness storage — **debug-trace-server-only** (no other scenario stores raw
/// blocks/witnesses), so it lives here rather than as a stateless-core trait.
///
/// Supertraits: [`ChainStore`] (chain cursors) + [`DivergenceLookups`] (this bin bisects on
/// reorg, and the DB-range metric reads `get_earliest`). History pruning is not part of the
/// trait — the pruner works on the concrete [`ServerDB`] — leaving this the read/append
/// seam shared with `DataProvider` and chain sync.
pub trait BlockStore: ChainStore + DivergenceLookups {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()>;
    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> StoreResult<(Block<Transaction>, LightWitness)>;
    /// Canonical hash from the HASH_ARCHIVE — heights that have left the bounded
    /// CANONICAL_CHAIN window (pruned/reset locally verified rows, plus lazily
    /// written-back upstream resolutions). Consulted by canonical-hash resolution after
    /// the window misses; never by reorg bisection.
    fn get_archived_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>>;
    /// Archives an upstream-resolved canonical hash — the lazy write-back that makes the
    /// next by-number request for this height resolve locally. Heights at or above the
    /// canonical window's start are skipped silently: they are not depth-final yet, and
    /// the window itself answers them.
    fn record_canonical_hash(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> StoreResult<()>;
}

/// Whether `block_number` lies strictly below the bounded CANONICAL_CHAIN window (i.e. is
/// depth-final). `false` on an empty chain — with no local window there is no depth
/// guarantee to lean on.
fn below_chain_window(
    chain: &impl ReadableTable<u64, ([u8; 32], [u8; 32], [u8; 32])>,
    block_number: BlockNumber,
) -> StoreResult<bool> {
    Ok(matches!(chain.first().store_err()?, Some((k, _)) if block_number < k.value()))
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
            let _hash_archive = write_txn.open_table(HASH_ARCHIVE).store_err()?;
        }
        write_txn.commit().store_err()?;

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

    /// Cleans up old block data to save storage space.
    ///
    /// Removes BLOCK_RECORDS + BLOCK_DATA + WITNESSES + CANONICAL_CHAIN rows strictly
    /// below `before_block`, moving each outgoing chain row's `(number, hash)` into
    /// HASH_ARCHIVE first (same transaction) — the locally verified number -> hash history
    /// keeps serving canonical-hash resolution after the bodies are reclaimed. Returns the
    /// number of BLOCK_RECORDS entries removed; orphaned CANONICAL_CHAIN rows (advanced
    /// but never stored) are archived and removed too, but not counted.
    pub fn prune_history(&self, before_block: BlockNumber) -> StoreResult<u64> {
        // Single write txn: scan + delete under one snapshot so a concurrently-committed
        // row below `before_block` can't slip past the scan and leak as an orphan.
        let write_txn = self.database.begin_write().store_err()?;
        let pruned_count = {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
            let mut archive = write_txn.open_table(HASH_ARCHIVE).store_err()?;
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
                archive.insert(block_number, block_hash).store_err()?;
                canonical_chain.remove(block_number).store_err()?;
                block_records.remove((block_number, block_hash)).store_err()?;
                block_data.remove(block_hash).store_err()?;
                witnesses.remove(block_hash).store_err()?;
            }

            // Archive + remove orphaned CANONICAL_CHAIN entries not tracked in
            // BLOCK_RECORDS, so the chain window stays contiguous-from-its-first-row.
            loop {
                let (block_number, block_hash) = match canonical_chain.first().store_err()? {
                    Some((k, v)) => {
                        let n = k.value();
                        if n >= before_block {
                            break;
                        }
                        (n, v.value().0)
                    }
                    None => break,
                };
                archive.insert(block_number, block_hash).store_err()?;
                canonical_chain.remove(block_number).store_err()?;
            }

            pruned_count
        };
        write_txn.commit().store_err()?;
        Ok(pruned_count)
    }

    /// Earliest BLOCK_RECORDS entry — the lower edge of body/witness retention, distinct
    /// from `get_earliest` (the chain window's start).
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
        // Unlike the validator's plain wipe (`write_reset_to_anchor`), the trace server
        // archives every current chain row's `(number, hash)` before clearing: the rows
        // were locally verified, and a stale reset only fires when the chain lags the
        // remote by at least the retention window, so they are depth-final by
        // construction and stay serviceable for number -> hash resolution.
        let write_txn = self.database.begin_write().store_err()?;
        {
            let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
            anchor_table.insert("anchor", block_meta_to_tuple(anchor)).store_err()?;

            let mut chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
            let mut archive = write_txn.open_table(HASH_ARCHIVE).store_err()?;
            for row in chain.iter().store_err()? {
                let (k, v) = row.store_err()?;
                archive.insert(k.value(), v.value().0).store_err()?;
            }
            chain.retain(|_, _| false).store_err()?;
            chain
                .insert(
                    anchor.block_number,
                    (anchor.block_hash.0, anchor.post_state_root.0, anchor.post_withdrawals_root.0),
                )
                .store_err()?;
        }
        write_txn.commit().store_err()?;
        Ok(())
    }
}

impl DivergenceLookups for ServerDB {
    fn get_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>> {
        // Same as the canonical block-hash read; delegate so the two can't drift.
        ChainStore::get_block_hash(self, block_number)
    }

    fn get_earliest(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
        // The bounded chain window is contiguous by construction (append at tip, prune
        // from below, archive-and-wipe on reset), so its first row is exactly the
        // hole-free lower bound divergence bisection requires. HASH_ARCHIVE rows are
        // deliberately invisible here.
        read_earliest_block(&self.database)
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

    fn get_archived_hash(&self, block_number: BlockNumber) -> StoreResult<Option<BlockHash>> {
        let read_txn = self.database.begin_read().store_err()?;
        let archive = read_txn.open_table(HASH_ARCHIVE).store_err()?;
        Ok(archive.get(block_number).store_err()?.map(|v| BlockHash::from(v.value())))
    }

    /// A read-transaction pre-check filters the skip cases without touching redb's
    /// single-writer lock (above-tip heights arrive constantly, exactly while chain sync
    /// keeps that lock busiest); an actual write re-checks the gate inside its own
    /// transaction. The window start only moves up (append-at-tip, prune-from-below), so
    /// the race is benign in the safe direction. The commit uses
    /// [`redb::Durability::None`] to keep the fsync off the request path: losing the row
    /// to a crash costs one upstream refetch, and any later Immediate commit (chain sync
    /// advances constantly) makes it durable.
    fn record_canonical_hash(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> StoreResult<()> {
        {
            let read_txn = self.database.begin_read().store_err()?;
            let chain = read_txn.open_table(CANONICAL_CHAIN).store_err()?;
            if !below_chain_window(&chain, block_number)? {
                return Ok(());
            }
        }
        let mut write_txn = self.database.begin_write().store_err()?;
        write_txn.set_durability(redb::Durability::None).store_err()?;
        {
            let chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
            if !below_chain_window(&chain, block_number)? {
                // Dropping the uncommitted txn aborts it; nothing is written.
                return Ok(());
            }
            let mut archive = write_txn.open_table(HASH_ARCHIVE).store_err()?;
            archive.insert(block_number, block_hash.0).store_err()?;
        }
        write_txn.commit().store_err()?;
        Ok(())
    }
}

/// Block/meta/witness fixtures and the [`BlockStore`] stub, shared with the
/// `data_provider`, `chain_sync`, and `main` test modules.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// No-op [`BlockStore`] stub whose canonical window answers `get_block_hash` with a
    /// fixed value; everything else is empty.
    pub(crate) struct StaticHashStore(pub Option<BlockHash>);

    impl ContractStore for StaticHashStore {
        fn get_contracts(&self, _: &[B256]) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
            Ok((HashMap::default(), vec![]))
        }
        fn add_contracts(&self, _: &[(B256, Bytecode)]) -> StoreResult<()> {
            Ok(())
        }
    }

    impl ChainStore for StaticHashStore {
        fn get_canonical_tip(&self) -> StoreResult<Option<BlockMeta>> {
            Ok(None)
        }
        fn get_anchor(&self) -> StoreResult<Option<BlockMeta>> {
            Ok(None)
        }
        fn advance_chain(&self, _: &[BlockMeta]) -> StoreResult<()> {
            Ok(())
        }
        fn get_block_hash(&self, _: BlockNumber) -> StoreResult<Option<BlockHash>> {
            Ok(self.0)
        }
        fn rollback_chain(&self, _: BlockNumber) -> StoreResult<()> {
            Ok(())
        }
        fn reset_to_anchor(&self, _: &BlockMeta) -> StoreResult<()> {
            Ok(())
        }
    }

    impl DivergenceLookups for StaticHashStore {
        fn get_hash(&self, _: BlockNumber) -> StoreResult<Option<BlockHash>> {
            Ok(self.0)
        }
        fn get_earliest(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
            Ok(None)
        }
    }

    impl BlockStore for StaticHashStore {
        fn store_block_data(&self, _: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()> {
            Ok(())
        }
        fn get_block_and_witness(
            &self,
            block_hash: BlockHash,
        ) -> StoreResult<(Block<Transaction>, LightWitness)> {
            Err(StoreError::MissingData { kind: MissingDataKind::Block, block_hash })
        }
        fn get_archived_hash(&self, _: BlockNumber) -> StoreResult<Option<BlockHash>> {
            Ok(None)
        }
        fn record_canonical_hash(&self, _: BlockNumber, _: BlockHash) -> StoreResult<()> {
            Ok(())
        }
    }

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

        // The archiving reset: the old row leaves the chain window (so `get_earliest`
        // is the anchor) but stays resolvable via the archive.
        assert_eq!(ChainStore::get_block_hash(&db, 10).unwrap(), None);
        assert_eq!(db.get_archived_hash(10).unwrap(), Some(blocks[0].block_hash));
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap(), Some((50, anchor.block_hash)));
    }

    /// Orphaned chain rows (advanced but never stored as bodies) below the cutoff are
    /// archived and removed even though the counted record-prune is 0.
    #[test]
    fn test_server_db_prune_history_archives_orphans() {
        let (_dir, db) = temp_server_db();

        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        let pruned = db.prune_history(3).unwrap();
        assert_eq!(pruned, 0, "no block records existed, so nothing counts as pruned");

        for n in 1..=2u64 {
            assert_eq!(ChainStore::get_block_hash(&db, n).unwrap(), None);
            assert_eq!(
                db.get_archived_hash(n).unwrap(),
                Some(make_block_meta(n).block_hash),
                "orphan row {n} must be archived"
            );
        }
        for n in 3..=5 {
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_some());
        }
    }

    #[test]
    fn test_prune_history_archives_pruned_range() {
        let (_dir, db) = temp_server_db();

        let blocks_data: Vec<_> = (1..=10)
            .map(|n| (make_test_block(n, B256::from([n as u8; 32])), empty_light_witness()))
            .collect();
        db.store_block_data(&blocks_data).unwrap();

        let metas: Vec<BlockMeta> = (1..=10).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &metas).unwrap();

        let pruned = db.prune_history(6).unwrap();
        assert_eq!(pruned, 5);

        // Bodies and chain rows below 6 are gone; their number -> hash moved to the
        // archive; the remaining window stays contiguous from 6.
        for n in 1..=5u64 {
            assert!(db.get_block_and_witness(BlockHash::from([n as u8; 32])).is_err());
            assert_eq!(ChainStore::get_block_hash(&db, n).unwrap(), None);
            assert_eq!(
                db.get_archived_hash(n).unwrap(),
                Some(make_block_meta(n).block_hash),
                "pruned row {n} must be archived"
            );
        }
        for n in 6..=10u64 {
            assert!(db.get_block_and_witness(BlockHash::from([n as u8; 32])).is_ok());
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_some());
        }
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 6);
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

    /// The lazy write-back archives only heights strictly below the canonical window:
    /// in-window and above-tip heights (and writes on an empty chain) are skipped
    /// silently, and the chain window itself is never mutated by a write-back.
    #[test]
    fn record_canonical_hash_only_archives_below_window() {
        let (_dir, db) = temp_server_db();
        let hash = |n: u64| make_block_meta(n).block_hash;

        // Empty chain: no depth guarantee, nothing is written.
        db.record_canonical_hash(5, hash(5)).unwrap();
        assert_eq!(db.get_archived_hash(5).unwrap(), None);

        // The anchor-init path installs the window at {10}.
        ChainStore::reset_to_anchor(&db, &make_block_meta(10)).unwrap();

        // Below the window: archived; the chain window and its cursors stay put.
        db.record_canonical_hash(5, hash(5)).unwrap();
        assert_eq!(db.get_archived_hash(5).unwrap(), Some(hash(5)));
        assert_eq!(ChainStore::get_block_hash(&db, 5).unwrap(), None);
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 10);
        assert_eq!(db.get_local_tip().unwrap().unwrap().0, 10);

        // At the window start and above the tip: skipped — not depth-final yet.
        db.record_canonical_hash(10, BlockHash::from([0xAA; 32])).unwrap();
        db.record_canonical_hash(12, hash(12)).unwrap();
        assert_eq!(db.get_archived_hash(10).unwrap(), None);
        assert_eq!(db.get_archived_hash(12).unwrap(), None);
        assert_eq!(ChainStore::get_block_hash(&db, 10).unwrap(), Some(hash(10)));
        assert_eq!(db.get_local_tip().unwrap().unwrap().0, 10);
    }
}
