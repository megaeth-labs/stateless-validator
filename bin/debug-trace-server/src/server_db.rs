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
    ANCHOR_BLOCK, BLOCK_DATA, BLOCK_RECORDS, CANONICAL_CHAIN, CONTRACTS, Database,
    HISTORY_FLOOR_KEY, WITNESSES, block_meta_from_tuple, block_meta_to_tuple,
    decode_block_from_slice, decode_from_slice, encode_block_to_vec, encode_to_vec, read_anchor,
    read_block_hash, read_canonical_tip, read_contracts, read_history_floor, write_add_contracts,
    write_advance_chain, write_reset_to_anchor_preserving_history, write_rollback_chain,
};

/// Block/witness storage + history pruning — **debug-trace-server-only**. This capability is
/// specific to this bin (no other scenario stores raw blocks/witnesses or prunes a per-block
/// chain on a schedule), so it lives here rather than as a stateless-core trait.
///
/// Supertraits: [`ChainStore`] (chain cursors) + [`DivergenceLookups`] (this bin bisects on reorg,
/// and the DB-range metric reads `get_earliest`). Pruning is not part of the trait: the
/// history pruner and the backfill task work on the concrete [`ServerDB`] (inherent
/// `prune_history` / `backfill_canonical`), while this trait is the read/append seam shared
/// with `DataProvider` and chain sync.
pub trait BlockStore: ChainStore + DivergenceLookups {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()>;
    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> StoreResult<(Block<Transaction>, LightWitness)>;
}

/// Outcome of a [`ServerDB::backfill_canonical`] batch application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackfillApply {
    /// The batch was written and the floor moved down to the requested `new_floor`.
    Applied,
    /// The persisted floor no longer matches the caller's expectation (a concurrent stale
    /// reset moved it); nothing was written. The caller reseeds from `current`.
    FloorMoved {
        /// The floor actually persisted right now.
        current: BlockMeta,
    },
}

/// Builds a [`BlockMeta`] from a CANONICAL_CHAIN row.
fn chain_row_meta(number: BlockNumber, row: ([u8; 32], [u8; 32], [u8; 32])) -> BlockMeta {
    let (hash, state_root, withdrawals_root) = row;
    BlockMeta {
        block_number: number,
        block_hash: BlockHash::from(hash),
        post_state_root: B256::from(state_root),
        post_withdrawals_root: B256::from(withdrawals_root),
    }
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

    /// Returns the persisted history floor as a full [`BlockMeta`], materializing the
    /// singleton row from the earliest CANONICAL_CHAIN entry when absent (databases from
    /// before floor tracking). `Ok(None)` on a fresh database with no chain rows at all.
    pub fn ensure_history_floor(&self) -> StoreResult<Option<BlockMeta>> {
        let write_txn = self.database.begin_write().store_err()?;
        let floor = {
            let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
            let existing = anchor_table
                .get(HISTORY_FLOOR_KEY)
                .store_err()?
                .map(|v| block_meta_from_tuple(v.value()));
            match existing {
                Some(meta) => Some(meta),
                None => {
                    let chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
                    let earliest = chain
                        .first()
                        .store_err()?
                        .map(|(k, v)| chain_row_meta(k.value(), v.value()));
                    if let Some(meta) = &earliest {
                        anchor_table
                            .insert(HISTORY_FLOOR_KEY, block_meta_to_tuple(meta))
                            .store_err()?;
                    }
                    earliest
                }
            }
        };
        write_txn.commit().store_err()?;
        Ok(floor)
    }

    /// Applies one canonical-index backfill batch atomically. In a single write transaction
    /// committed at `durability`:
    ///
    /// 1. **Floor CAS** — the persisted floor must still be at `expected_floor`; otherwise nothing
    ///    is written and [`BackfillApply::FloorMoved`] returns the current floor so the caller can
    ///    reseed (a concurrent stale reset moved it).
    /// 2. **Shape checks** — `metas` must be a contiguous ascending run starting at `new_floor`
    ///    (equal to `metas[0]`) and ending exactly one below `expected_floor`. Empty `metas` is an
    ///    **island skip**: `new_floor` must be an existing chain row below the floor with a
    ///    matching hash, and the row directly below the floor must exist (the island's top —
    ///    interior contiguity was established by [`Self::scan_contiguous_below`], and rows below
    ///    the floor are never deleted). Violations are [`StoreError::Corrupt`]: caller bugs, not
    ///    races.
    /// 3. **Write** — insert the rows and move the floor down to `new_floor`, atomically.
    ///
    /// Parent-hash linkage of `metas` is the caller's responsibility (the backfill task
    /// verifies recomputed header hashes); this layer checks numeric shape only.
    pub fn backfill_canonical(
        &self,
        expected_floor: BlockNumber,
        metas: &[BlockMeta],
        new_floor: &BlockMeta,
        durability: redb::Durability,
    ) -> StoreResult<BackfillApply> {
        let mut write_txn = self.database.begin_write().store_err()?;
        write_txn.set_durability(durability).store_err()?;
        {
            let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
            let current = anchor_table
                .get(HISTORY_FLOOR_KEY)
                .store_err()?
                .map(|v| block_meta_from_tuple(v.value()))
                .ok_or_else(|| {
                    StoreError::Corrupt("backfill_canonical without a history floor".into())
                })?;
            if current.block_number != expected_floor {
                // Dropping the uncommitted txn aborts it; nothing was written.
                return Ok(BackfillApply::FloorMoved { current });
            }

            let mut chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
            if let Some(first) = metas.first() {
                if first.block_number != new_floor.block_number ||
                    first.block_hash != new_floor.block_hash
                {
                    return Err(StoreError::Corrupt(format!(
                        "backfill new_floor {} does not match the batch start {}",
                        new_floor.block_number, first.block_number
                    )));
                }
                let last = metas.last().expect("non-empty");
                if last.block_number.checked_add(1) != Some(expected_floor) {
                    return Err(StoreError::Corrupt(format!(
                        "backfill batch ends at {} but the floor is {expected_floor}",
                        last.block_number
                    )));
                }
                for pair in metas.windows(2) {
                    if pair[1].block_number != pair[0].block_number + 1 {
                        return Err(StoreError::Corrupt(format!(
                            "backfill batch has a gap between {} and {}",
                            pair[0].block_number, pair[1].block_number
                        )));
                    }
                }
                for meta in metas {
                    chain
                        .insert(
                            meta.block_number,
                            (
                                meta.block_hash.0,
                                meta.post_state_root.0,
                                meta.post_withdrawals_root.0,
                            ),
                        )
                        .store_err()?;
                }
            } else {
                if new_floor.block_number >= expected_floor {
                    return Err(StoreError::Corrupt(format!(
                        "island skip must lower the floor: {} >= {expected_floor}",
                        new_floor.block_number
                    )));
                }
                let target = chain.get(new_floor.block_number).store_err()?.map(|v| v.value().0);
                if target != Some(new_floor.block_hash.0) {
                    return Err(StoreError::Corrupt(format!(
                        "island skip target row {} missing or hash mismatch",
                        new_floor.block_number
                    )));
                }
                if chain.get(expected_floor - 1).store_err()?.is_none() {
                    return Err(StoreError::Corrupt(format!(
                        "island skip without a row adjacent to the floor {expected_floor}"
                    )));
                }
            }
            anchor_table.insert(HISTORY_FLOOR_KEY, block_meta_to_tuple(new_floor)).store_err()?;
        }
        write_txn.commit().store_err()?;
        Ok(BackfillApply::Applied)
    }

    /// Empty transaction committed at [`redb::Durability::Immediate`]: on return, every
    /// batch previously committed at [`redb::Durability::None`] is durable on disk.
    pub fn durability_barrier(&self) -> StoreResult<()> {
        let mut write_txn = self.database.begin_write().store_err()?;
        write_txn.set_durability(redb::Durability::Immediate).store_err()?;
        write_txn.commit().store_err()?;
        Ok(())
    }

    /// Walks the contiguous run of CANONICAL_CHAIN rows directly below `from`, returning
    /// the meta of its lowest row — `None` when `from` is 0 or the row at `from - 1`
    /// doesn't exist. Lets the backfill skip over already-persisted historical islands
    /// instead of refetching them.
    pub fn scan_contiguous_below(&self, from: BlockNumber) -> StoreResult<Option<BlockMeta>> {
        if from == 0 {
            return Ok(None);
        }
        let read_txn = self.database.begin_read().store_err()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN).store_err()?;
        let mut lowest = None;
        let mut expected = from - 1;
        for row in chain.range(..from).store_err()?.rev() {
            let (k, v) = row.store_err()?;
            if k.value() != expected {
                break;
            }
            lowest = Some(chain_row_meta(expected, v.value()));
            if expected == 0 {
                break;
            }
            expected -= 1;
        }
        Ok(lowest)
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
        // up to the tip, and rows below the floor (backfilled history, pre-reset islands)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_server_db() -> (tempfile::TempDir, ServerDB) {
        let dir = tempfile::tempdir().unwrap();
        let db = ServerDB::new(dir.path().join("server.redb")).unwrap();
        (dir, db)
    }

    fn make_block_meta(number: u64) -> BlockMeta {
        BlockMeta {
            block_number: number,
            block_hash: BlockHash::from([number as u8; 32]),
            post_state_root: B256::from([(number + 100) as u8; 32]),
            post_withdrawals_root: B256::from([(number + 200) as u8; 32]),
        }
    }

    fn make_test_block(number: u64, hash: B256) -> Block<Transaction> {
        let mut header = alloy_rpc_types_eth::Header::<alloy_consensus::Header>::default();
        header.inner.number = number;
        header.hash = hash;
        header.inner.withdrawals_root = Some(B256::ZERO);
        Block { header, ..Default::default() }
    }

    fn empty_light_witness() -> LightWitness {
        LightWitness { kvs: std::collections::BTreeMap::new(), levels: Default::default() }
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

    /// `ensure_history_floor` materializes the floor from the earliest chain row once and
    /// then keeps returning the persisted row — it must not chase `chain.first()` after
    /// rows appear below the floor.
    #[test]
    fn ensure_history_floor_materializes_and_persists() {
        let (_dir, db) = temp_server_db();
        assert_eq!(db.ensure_history_floor().unwrap(), None);

        ChainStore::advance_chain(&db, &(8..=9).map(make_block_meta).collect::<Vec<_>>()).unwrap();
        assert_eq!(db.ensure_history_floor().unwrap(), Some(make_block_meta(8)));

        ChainStore::advance_chain(&db, &[make_block_meta(2)]).unwrap();
        assert_eq!(
            db.ensure_history_floor().unwrap(),
            Some(make_block_meta(8)),
            "a row below the floor must not move it"
        );
    }

    /// Happy path: consecutive batches walk the floor down; each application is atomic
    /// (rows + floor in one transaction).
    #[test]
    fn backfill_canonical_applies_and_moves_floor() {
        let (_dir, db) = temp_server_db();
        ChainStore::advance_chain(&db, &[make_block_meta(10), make_block_meta(11)]).unwrap();
        assert_eq!(db.ensure_history_floor().unwrap().unwrap().block_number, 10);

        let batch1: Vec<BlockMeta> = (7..=9).map(make_block_meta).collect();
        assert_eq!(
            db.backfill_canonical(10, &batch1, &batch1[0], redb::Durability::Immediate).unwrap(),
            BackfillApply::Applied
        );
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 7);

        let batch2: Vec<BlockMeta> = (4..=6).map(make_block_meta).collect();
        assert_eq!(
            db.backfill_canonical(7, &batch2, &batch2[0], redb::Durability::Immediate).unwrap(),
            BackfillApply::Applied
        );
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 4);
        for n in 4..=11 {
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_some());
        }
    }

    /// The floor CAS: a batch built against a stale floor is rejected wholesale and
    /// reports the current floor for reseeding.
    #[test]
    fn backfill_canonical_detects_floor_move() {
        let (_dir, db) = temp_server_db();
        ChainStore::advance_chain(&db, &[make_block_meta(10)]).unwrap();
        db.ensure_history_floor().unwrap();

        // A stale reset moves the floor to 20 while a batch against floor 10 is in flight.
        ChainStore::reset_to_anchor(&db, &make_block_meta(20)).unwrap();

        let stale: Vec<BlockMeta> = (5..=9).map(make_block_meta).collect();
        let apply =
            db.backfill_canonical(10, &stale, &stale[0], redb::Durability::Immediate).unwrap();
        assert_eq!(apply, BackfillApply::FloorMoved { current: make_block_meta(20) });
        assert_eq!(
            ChainStore::get_block_hash(&db, 5).unwrap(),
            None,
            "a rejected batch must write nothing"
        );
    }

    /// Shape violations are `Corrupt` errors (caller bugs) and write nothing.
    #[test]
    fn backfill_canonical_rejects_corrupt_shapes() {
        let (_dir, db) = temp_server_db();
        ChainStore::advance_chain(&db, &[make_block_meta(10)]).unwrap();
        db.ensure_history_floor().unwrap();

        let corrupt = |metas: &[BlockMeta], new_floor: &BlockMeta| {
            matches!(
                db.backfill_canonical(10, metas, new_floor, redb::Durability::Immediate),
                Err(StoreError::Corrupt(_))
            )
        };

        // Batch not ending directly below the floor.
        let short: Vec<BlockMeta> = (5..=8).map(make_block_meta).collect();
        assert!(corrupt(&short, &short[0]));
        // Gap inside the batch.
        let gapped: Vec<BlockMeta> = [5u64, 6, 8, 9].map(make_block_meta).to_vec();
        assert!(corrupt(&gapped, &gapped[0]));
        // new_floor not equal to the batch start.
        let run: Vec<BlockMeta> = (5..=9).map(make_block_meta).collect();
        assert!(corrupt(&run, &make_block_meta(6)));
        // Island skip onto a row that doesn't exist.
        assert!(corrupt(&[], &make_block_meta(4)));

        assert_eq!(ChainStore::get_block_hash(&db, 5).unwrap(), None);
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 10);
    }

    /// Island skip: with rows already present below the floor, an empty batch lowers the
    /// floor across them without rewriting anything.
    #[test]
    fn backfill_island_skip_lowers_floor() {
        let (_dir, db) = temp_server_db();
        // Island 3..=6 (pre-reset history), stranded below the floor by a reset to 10.
        ChainStore::advance_chain(&db, &(3..=6).map(make_block_meta).collect::<Vec<_>>()).unwrap();
        ChainStore::reset_to_anchor(&db, &make_block_meta(10)).unwrap();

        // Backfill descends 7..=9, reconnecting to the island top at 6.
        let bridge: Vec<BlockMeta> = (7..=9).map(make_block_meta).collect();
        db.backfill_canonical(10, &bridge, &bridge[0], redb::Durability::Immediate).unwrap();

        let island_bottom = db.scan_contiguous_below(7).unwrap().unwrap();
        assert_eq!(island_bottom, make_block_meta(3));
        assert_eq!(
            db.backfill_canonical(7, &[], &island_bottom, redb::Durability::Immediate).unwrap(),
            BackfillApply::Applied
        );
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 3);
    }

    /// Batches committed at `Durability::None` must survive a reopen once a durability
    /// barrier ran — the barrier is what makes crash loss bounded.
    #[test]
    fn backfill_durability_none_survives_reopen_after_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.redb");
        {
            let db = ServerDB::new(&path).unwrap();
            ChainStore::advance_chain(&db, &[make_block_meta(10)]).unwrap();
            db.ensure_history_floor().unwrap();
            let metas: Vec<BlockMeta> = (5..=9).map(make_block_meta).collect();
            assert_eq!(
                db.backfill_canonical(10, &metas, &metas[0], redb::Durability::None).unwrap(),
                BackfillApply::Applied
            );
            db.durability_barrier().unwrap();
        }
        let db = ServerDB::new(&path).unwrap();
        for n in 5..=10 {
            assert!(
                ChainStore::get_block_hash(&db, n).unwrap().is_some(),
                "row {n} must be durable after the barrier"
            );
        }
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 5);
    }

    #[test]
    fn scan_contiguous_below_edges() {
        let (_dir, db) = temp_server_db();
        assert_eq!(db.scan_contiguous_below(0).unwrap(), None);
        assert_eq!(db.scan_contiguous_below(5).unwrap(), None, "no row directly below");

        // Rows 1..=2 and 4 with a hole at 3: the walk from 5 stops at the hole.
        ChainStore::advance_chain(
            &db,
            &[make_block_meta(1), make_block_meta(2), make_block_meta(4)],
        )
        .unwrap();
        assert_eq!(db.scan_contiguous_below(5).unwrap(), Some(make_block_meta(4)));
        assert_eq!(db.scan_contiguous_below(4).unwrap(), None, "hole at 3 stops the walk");
        assert_eq!(db.scan_contiguous_below(3).unwrap(), Some(make_block_meta(1)));
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
