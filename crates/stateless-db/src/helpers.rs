//! Shared redb read/write helpers used by both concrete database implementations.

use std::sync::Arc;

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
            chain
                .insert(
                    block.block_number,
                    (block.block_hash.0, block.post_state_root.0, block.post_withdrawals_root.0),
                )
                .store_err()?;
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
        let to_remove: Vec<u64> = chain
            .range((to_block + 1)..)
            .store_err()?
            .map(|r| r.map(|(k, _)| k.value()))
            .collect::<std::result::Result<_, _>>()
            .store_err()?;
        for n in to_remove {
            chain.remove(n).store_err()?;
        }
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

/// Retrieves cached contract bytecodes. Returns `(found, missing)`.
pub fn read_contracts(database: &Database, hashes: &[B256]) -> StoreResult<ContractLookup> {
    let read_txn = database.begin_read().store_err()?;
    let table = read_txn.open_table(CONTRACTS).store_err()?;

    let mut found: HashMap<B256, Arc<Bytecode>> = HashMap::default();
    let mut missing = Vec::new();

    for &hash in hashes {
        match table.get(hash.0).store_err()? {
            Some(data) => {
                let bytecode: Bytecode = decode_from_slice(data.value().as_slice())?;
                found.insert(hash, Arc::new(bytecode));
            }
            None => missing.push(hash),
        }
    }

    Ok((found, missing))
}

/// Stores contract bytecodes in the CONTRACTS table.
pub fn write_add_contracts(
    database: &Database,
    codes: &[(B256, Arc<Bytecode>)],
) -> StoreResult<()> {
    if codes.is_empty() {
        return Ok(());
    }
    let write_txn = database.begin_write().store_err()?;
    {
        let mut table = write_txn.open_table(CONTRACTS).store_err()?;
        for (hash, bytecode) in codes {
            let encoded = encode_to_vec(bytecode.as_ref())?;
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

        let a = (B256::from([1u8; 32]), Arc::new(Bytecode::new_raw(Bytes::from_static(&[0x60]))));
        let b = (B256::from([2u8; 32]), Arc::new(Bytecode::new_raw(Bytes::from_static(&[0x61]))));
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
