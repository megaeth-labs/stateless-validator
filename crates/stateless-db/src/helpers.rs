//! Shared redb read/write helpers used by both concrete database implementations.

use alloy_primitives::{B256, BlockHash, BlockNumber, map::HashMap};
use redb::{ReadableDatabase, ReadableTable};
use revm::state::Bytecode;
use stateless_core::db::{BlockMeta, ContractLookup, StoreResult, StoreResultExt};

use crate::{
    serialize::{decode_from_slice, encode_to_vec},
    tables::{
        ANCHOR_BLOCK, CANONICAL_CHAIN, CONTRACTS, Database, block_meta_from_tuple,
        block_meta_to_tuple,
    },
};

/// Reads the canonical tip (highest block) from CANONICAL_CHAIN.
pub fn read_canonical_tip(database: &Database) -> StoreResult<Option<BlockMeta>> {
    let read_txn = database.begin_read().store_err()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN).store_err()?;
    Ok(chain.last().store_err()?.map(|(k, v)| {
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
pub fn read_anchor(database: &Database) -> StoreResult<Option<BlockMeta>> {
    let read_txn = database.begin_read().store_err()?;
    let table = read_txn.open_table(ANCHOR_BLOCK).store_err()?;
    Ok(table.get("anchor").store_err()?.map(|v| block_meta_from_tuple(v.value())))
}

/// Looks up a single block hash from CANONICAL_CHAIN.
pub fn read_block_hash(
    database: &Database,
    block_number: BlockNumber,
) -> StoreResult<Option<BlockHash>> {
    let read_txn = database.begin_read().store_err()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN).store_err()?;
    Ok(chain.get(block_number).store_err()?.map(|v| BlockHash::from(v.value().0)))
}

/// Returns the earliest (lowest block number) entry in CANONICAL_CHAIN.
pub fn read_earliest_block(database: &Database) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
    let read_txn = database.begin_read().store_err()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN).store_err()?;
    Ok(chain.first().store_err()?.map(|(k, v)| (k.value(), BlockHash::from(v.value().0))))
}

/// Appends blocks to CANONICAL_CHAIN in a single write transaction.
///
/// If `max_len` is `Some(n)`, the CANONICAL_CHAIN table is bounded to `n` rows after the
/// insert — the oldest entries exceeding that cap are pruned inline in the same write
/// transaction. Callers that manage retention separately (e.g. `ServerDB`'s background
/// pruner) pass `None`.
pub fn write_advance_chain(
    database: &Database,
    blocks: &[BlockMeta],
    max_len: Option<u64>,
) -> StoreResult<()> {
    use redb::ReadableTableMetadata;

    if blocks.is_empty() {
        return Ok(());
    }
    let write_txn = database.begin_write().store_err()?;
    {
        let mut chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
        for block in blocks {
            insert_chain_row(&mut chain, block)?;
        }

        // Inline pruning: remove oldest entries that exceed the max chain length.
        // Shared by both binaries — the validator passes `Some(cap)` and the trace
        // server passes `None` (a background task prunes there).
        if let Some(max_len) = max_len {
            let len = chain.len().store_err()?;
            if len > max_len {
                let excess = len - max_len;
                let to_remove: Vec<u64> = chain
                    .iter()
                    .store_err()?
                    .take(excess as usize)
                    .map(|r| r.map(|(k, _)| k.value()))
                    .collect::<std::result::Result<_, _>>()
                    .store_err()?;
                for n in to_remove {
                    chain.remove(n).store_err()?;
                }
            }
        }
    }
    write_txn.commit().store_err()?;
    Ok(())
}

/// Removes all CANONICAL_CHAIN entries above `to_block`.
pub fn write_rollback_chain(database: &Database, to_block: BlockNumber) -> StoreResult<()> {
    let write_txn = database.begin_write().store_err()?;
    {
        let mut chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
        remove_chain_rows_above(&mut chain, to_block)?;
    }
    write_txn.commit().store_err()?;
    Ok(())
}

/// ANCHOR_BLOCK key of the persisted **history floor**: the lowest block of the contiguous
/// CANONICAL_CHAIN suffix ending at the tip. Rows may exist below it (immutable historical
/// "islands" left by a stale reset or the lazy write-back), but only the range at or above
/// the floor is guaranteed hole-free — which is what divergence bisection requires of
/// `get_earliest`.
pub const HISTORY_FLOOR_KEY: &str = "history_floor";

/// CANONICAL_CHAIN value tuple: `(block_hash, post_state_root, post_withdrawals_root)`.
type ChainRow = ([u8; 32], [u8; 32], [u8; 32]);

/// Reads the floor row from an open ANCHOR_BLOCK table (read-only or write).
fn read_floor_row(
    anchor_table: &impl ReadableTable<&'static str, (u64, [u8; 32], [u8; 32], [u8; 32])>,
) -> StoreResult<Option<BlockMeta>> {
    Ok(anchor_table.get(HISTORY_FLOOR_KEY).store_err()?.map(|v| block_meta_from_tuple(v.value())))
}

/// Reads the earliest CANONICAL_CHAIN row from an open table as a full [`BlockMeta`].
fn earliest_chain_row(chain: &impl ReadableTable<u64, ChainRow>) -> StoreResult<Option<BlockMeta>> {
    Ok(chain.first().store_err()?.map(|(k, v)| {
        let (hash, state_root, withdrawals_root) = v.value();
        block_meta_from_tuple((k.value(), hash, state_root, withdrawals_root))
    }))
}

/// Inserts `meta` as a CANONICAL_CHAIN row.
fn insert_chain_row(
    chain: &mut redb::Table<'_, u64, ChainRow>,
    meta: &BlockMeta,
) -> StoreResult<()> {
    chain
        .insert(
            meta.block_number,
            (meta.block_hash.0, meta.post_state_root.0, meta.post_withdrawals_root.0),
        )
        .store_err()?;
    Ok(())
}

/// Removes all CANONICAL_CHAIN rows strictly above `above` (scan + delete under the
/// caller's write snapshot).
fn remove_chain_rows_above(
    chain: &mut redb::Table<'_, u64, ChainRow>,
    above: BlockNumber,
) -> StoreResult<()> {
    let to_remove: Vec<u64> = chain
        .range((above + 1)..)
        .store_err()?
        .map(|r| r.map(|(k, _)| k.value()))
        .collect::<std::result::Result<_, _>>()
        .store_err()?;
    for n in to_remove {
        chain.remove(n).store_err()?;
    }
    Ok(())
}

/// Reads the history floor. Falls back to the earliest CANONICAL_CHAIN row when no floor
/// row has been persisted (databases created before floor tracking), preserving the old
/// `get_earliest` semantics for them.
pub fn read_history_floor(database: &Database) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
    let read_txn = database.begin_read().store_err()?;
    let anchor_table = read_txn.open_table(ANCHOR_BLOCK).store_err()?;
    if let Some(meta) = read_floor_row(&anchor_table)? {
        return Ok(Some((meta.block_number, meta.block_hash)));
    }
    let chain = read_txn.open_table(CANONICAL_CHAIN).store_err()?;
    Ok(earliest_chain_row(&chain)?.map(|meta| (meta.block_number, meta.block_hash)))
}

/// Returns the persisted history floor as a full [`BlockMeta`], materializing the
/// singleton row from the earliest CANONICAL_CHAIN entry when absent — the upgrade path
/// for databases created before floor tracking, sharing the fallback rule with
/// [`read_history_floor`]. `Ok(None)` on a fresh database with no chain rows at all.
pub fn write_ensure_history_floor(database: &Database) -> StoreResult<Option<BlockMeta>> {
    let write_txn = database.begin_write().store_err()?;
    let floor = {
        let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
        match read_floor_row(&anchor_table)? {
            Some(meta) => Some(meta),
            None => {
                let chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
                let earliest = earliest_chain_row(&chain)?;
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

/// Persists an upstream-resolved canonical row **strictly below the history floor** — the
/// trace server's lazy write-back. Rows at/above the floor, or writes without any floor,
/// are skipped silently: that range is owned by chain sync and is what reorg bisection
/// trusts.
///
/// A read-transaction pre-check filters the skip cases without touching redb's
/// single-writer lock (heights above the sync tip arrive constantly, exactly while chain
/// sync keeps that lock busiest); an actual write re-checks the floor inside its own
/// transaction, so a concurrent stale reset (which only moves the floor up) cannot
/// interleave a write into the trusted range. The commit uses [`redb::Durability::None`]
/// to keep the fsync off the request path: losing the row to a crash costs one upstream
/// refetch, and any later Immediate commit (chain sync advances constantly) makes it
/// durable.
pub fn write_canonical_hash_below_floor(database: &Database, meta: &BlockMeta) -> StoreResult<()> {
    let below_floor =
        |floor: &Option<BlockMeta>| matches!(floor, Some(f) if meta.block_number < f.block_number);
    {
        let read_txn = database.begin_read().store_err()?;
        let anchor_table = read_txn.open_table(ANCHOR_BLOCK).store_err()?;
        if !below_floor(&read_floor_row(&anchor_table)?) {
            return Ok(());
        }
    }
    let mut write_txn = database.begin_write().store_err()?;
    write_txn.set_durability(redb::Durability::None).store_err()?;
    {
        let anchor_table = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
        if !below_floor(&read_floor_row(&anchor_table)?) {
            // Dropping the uncommitted txn aborts it; nothing is written.
            return Ok(());
        }
        let mut chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
        insert_chain_row(&mut chain, meta)?;
    }
    write_txn.commit().store_err()?;
    Ok(())
}

/// History-preserving variant of [`write_reset_to_anchor`]: installs the new anchor and
/// removes chain rows strictly *above* it (their lineage is unverified against the new
/// anchor), but keeps every row below — accumulated canonical history is immutable and
/// stays serviceable. The anchor also becomes the history floor: the reset leaves a gap
/// right below it, so rows underneath are no longer guaranteed contiguous with the tip.
pub fn write_reset_to_anchor_preserving_history(
    database: &Database,
    anchor: &BlockMeta,
) -> StoreResult<()> {
    let write_txn = database.begin_write().store_err()?;
    {
        let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
        anchor_table.insert("anchor", block_meta_to_tuple(anchor)).store_err()?;
        anchor_table.insert(HISTORY_FLOOR_KEY, block_meta_to_tuple(anchor)).store_err()?;

        let mut chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
        remove_chain_rows_above(&mut chain, anchor.block_number)?;
        insert_chain_row(&mut chain, anchor)?;
    }
    write_txn.commit().store_err()?;
    Ok(())
}

/// Clears the canonical chain and sets anchor as the sole entry.
pub fn write_reset_to_anchor(database: &Database, anchor: &BlockMeta) -> StoreResult<()> {
    let write_txn = database.begin_write().store_err()?;
    {
        let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK).store_err()?;
        anchor_table.insert("anchor", block_meta_to_tuple(anchor)).store_err()?;

        let mut chain = write_txn.open_table(CANONICAL_CHAIN).store_err()?;
        chain.retain(|_, _| false).store_err()?;
        insert_chain_row(&mut chain, anchor)?;
    }
    write_txn.commit().store_err()?;
    Ok(())
}

/// Retrieves cached contract bytecodes. Returns `(found, missing)`.
pub fn read_contracts(database: &Database, hashes: &[B256]) -> StoreResult<ContractLookup> {
    let read_txn = database.begin_read().store_err()?;
    let table = read_txn.open_table(CONTRACTS).store_err()?;

    let mut found: HashMap<B256, Bytecode> = HashMap::default();
    let mut missing = Vec::new();

    for &hash in hashes {
        match table.get(hash.0).store_err()? {
            Some(data) => {
                let bytecode: Bytecode = decode_from_slice(data.value().as_slice())?;
                found.insert(hash, bytecode);
            }
            None => missing.push(hash),
        }
    }

    Ok((found, missing))
}

/// Stores contract bytecodes in the CONTRACTS table.
pub fn write_add_contracts(database: &Database, codes: &[(B256, Bytecode)]) -> StoreResult<()> {
    if codes.is_empty() {
        return Ok(());
    }
    let write_txn = database.begin_write().store_err()?;
    {
        let mut table = write_txn.open_table(CONTRACTS).store_err()?;
        for (hash, bytecode) in codes {
            let encoded = encode_to_vec(bytecode)?;
            table.insert(hash.0, encoded).store_err()?;
        }
    }
    write_txn.commit().store_err()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;

    use super::*;

    fn temp_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let database = Database::create(dir.path().join("test.redb")).unwrap();
        // Pre-create the tables read paths open, mirroring ValidatorDB/ServerDB::new —
        // a redb read transaction cannot open a table that doesn't exist yet.
        let write_txn = database.begin_write().unwrap();
        write_txn.open_table(ANCHOR_BLOCK).unwrap();
        write_txn.open_table(CANONICAL_CHAIN).unwrap();
        write_txn.commit().unwrap();
        (dir, database)
    }

    fn meta(number: u64) -> BlockMeta {
        let byte = number as u8;
        BlockMeta {
            block_number: number,
            block_hash: BlockHash::from([byte; 32]),
            post_state_root: B256::from([byte.wrapping_add(100); 32]),
            post_withdrawals_root: B256::from([byte.wrapping_add(200); 32]),
        }
    }

    #[test]
    fn reset_to_anchor_clears_chain_and_installs_anchor() {
        let (_dir, db) = temp_db();

        write_advance_chain(&db, &[meta(10), meta(11), meta(12)], None).unwrap();
        write_reset_to_anchor(&db, &meta(5)).unwrap();

        let new_anchor = meta(42);
        write_reset_to_anchor(&db, &new_anchor).unwrap();

        assert_eq!(read_anchor(&db).unwrap().as_ref(), Some(&new_anchor));
        assert_eq!(read_canonical_tip(&db).unwrap().as_ref(), Some(&new_anchor));
        assert_eq!(read_earliest_block(&db).unwrap(), Some((42, new_anchor.block_hash)));
        for removed in [5u64, 10, 11, 12] {
            assert_eq!(read_block_hash(&db, removed).unwrap(), None, "stale block {removed}");
        }
    }

    /// The preserving reset keeps rows below the new anchor, drops rows above it, and
    /// installs the anchor as both chain tip and history floor. The plain
    /// `write_reset_to_anchor` (validator behavior) stays wipe-everything — pinned by
    /// `reset_to_anchor_clears_chain_and_installs_anchor` above.
    #[test]
    fn preserving_reset_keeps_history_and_sets_floor() {
        let (_dir, db) = temp_db();

        write_advance_chain(&db, &[meta(10), meta(11), meta(12)], None).unwrap();

        // Forward reset (stale-reset shape: anchor jumps above all local rows).
        let anchor = meta(42);
        write_reset_to_anchor_preserving_history(&db, &anchor).unwrap();

        assert_eq!(read_anchor(&db).unwrap().as_ref(), Some(&anchor));
        assert_eq!(read_canonical_tip(&db).unwrap().as_ref(), Some(&anchor));
        assert_eq!(read_history_floor(&db).unwrap(), Some((42, anchor.block_hash)));
        for kept in [10u64, 11, 12] {
            assert_eq!(
                read_block_hash(&db, kept).unwrap(),
                Some(meta(kept).block_hash),
                "island row {kept} must survive the reset"
            );
        }

        // Reset landing below existing rows: rows above the anchor are unverified against
        // it and must go; rows below stay.
        let anchor = meta(11);
        write_reset_to_anchor_preserving_history(&db, &anchor).unwrap();
        assert_eq!(read_canonical_tip(&db).unwrap().as_ref(), Some(&anchor));
        assert_eq!(read_history_floor(&db).unwrap(), Some((11, anchor.block_hash)));
        assert_eq!(read_block_hash(&db, 10).unwrap(), Some(meta(10).block_hash));
        assert_eq!(read_block_hash(&db, 12).unwrap(), None);
        assert_eq!(read_block_hash(&db, 42).unwrap(), None);
    }

    /// `write_ensure_history_floor` materializes the floor from the earliest chain row
    /// once, and the persisted row then wins over rows appearing below it — the same
    /// fallback rule `read_history_floor` applies read-only.
    #[test]
    fn ensure_history_floor_materializes_once() {
        let (_dir, db) = temp_db();
        assert_eq!(write_ensure_history_floor(&db).unwrap(), None);

        write_advance_chain(&db, &[meta(8), meta(9)], None).unwrap();
        assert_eq!(write_ensure_history_floor(&db).unwrap(), Some(meta(8)));

        write_advance_chain(&db, &[meta(2)], None).unwrap();
        assert_eq!(
            write_ensure_history_floor(&db).unwrap(),
            Some(meta(8)),
            "a row below the floor must not move it"
        );
        assert_eq!(read_history_floor(&db).unwrap(), Some((8, meta(8).block_hash)));
    }

    /// Without a persisted floor row the floor falls back to the earliest chain row; once a
    /// floor row exists it wins even though older island rows sit below it.
    #[test]
    fn read_history_floor_falls_back_to_earliest() {
        let (_dir, db) = temp_db();
        assert_eq!(read_history_floor(&db).unwrap(), None);

        write_advance_chain(&db, &[meta(3), meta(4)], None).unwrap();
        assert_eq!(read_history_floor(&db).unwrap(), Some((3, meta(3).block_hash)));

        write_reset_to_anchor_preserving_history(&db, &meta(7)).unwrap();
        assert_eq!(
            read_history_floor(&db).unwrap(),
            Some((7, meta(7).block_hash)),
            "the floor row must win over the earlier island rows"
        );
        assert_eq!(read_earliest_block(&db).unwrap(), Some((3, meta(3).block_hash)));
    }

    #[test]
    fn advance_chain_inserts_and_enforces_max_len() {
        let (_dir, db) = temp_db();

        let blocks: Vec<_> = (1..=5).map(meta).collect();
        write_advance_chain(&db, &blocks, None).unwrap();
        assert_eq!(read_canonical_tip(&db).unwrap().unwrap().block_number, 5);
        assert_eq!(read_earliest_block(&db).unwrap(), Some((1, blocks[0].block_hash)));
        assert_eq!(read_block_hash(&db, 3).unwrap(), Some(blocks[2].block_hash));

        write_advance_chain(&db, &[], None).unwrap();
        assert_eq!(read_canonical_tip(&db).unwrap().unwrap().block_number, 5);

        write_advance_chain(&db, &[meta(6), meta(7)], Some(3)).unwrap();
        assert_eq!(read_earliest_block(&db).unwrap().unwrap().0, 5);
        assert_eq!(read_canonical_tip(&db).unwrap().unwrap().block_number, 7);
        assert_eq!(read_block_hash(&db, 1).unwrap(), None);
        assert_eq!(read_block_hash(&db, 4).unwrap(), None);
    }

    #[test]
    fn rollback_chain_removes_blocks_above_threshold() {
        let (_dir, db) = temp_db();
        write_advance_chain(&db, &(1..=5).map(meta).collect::<Vec<_>>(), None).unwrap();

        write_rollback_chain(&db, 3).unwrap();

        // `to_block` itself is retained; strictly higher numbers are dropped.
        assert_eq!(read_canonical_tip(&db).unwrap().unwrap().block_number, 3);
        assert!(read_block_hash(&db, 3).unwrap().is_some());
        assert_eq!(read_block_hash(&db, 4).unwrap(), None);
        assert_eq!(read_block_hash(&db, 5).unwrap(), None);
    }

    #[test]
    fn contracts_roundtrip_and_missing_report() {
        let (_dir, db) = temp_db();

        let a = (B256::from([1u8; 32]), Bytecode::new_raw(Bytes::from_static(&[0x60])));
        let b = (B256::from([2u8; 32]), Bytecode::new_raw(Bytes::from_static(&[0x61])));
        let missing_hash = B256::from([3u8; 32]);

        write_add_contracts(&db, &[]).unwrap();
        write_add_contracts(&db, &[a.clone(), b.clone()]).unwrap();

        let (found, missing) = read_contracts(&db, &[a.0, b.0, missing_hash]).unwrap();
        assert_eq!(missing, vec![missing_hash]);
        assert_eq!(found.len(), 2);
        assert_eq!(found[&a.0].bytes_slice(), a.1.bytes_slice());
        assert_eq!(found[&b.0].bytes_slice(), b.1.bytes_slice());
    }
}
