//! Shared redb read/write helpers used by both concrete database implementations.

use alloy_primitives::{B256, BlockHash, BlockNumber, map::HashMap};
use redb::{ReadableDatabase, ReadableTable};
use revm::state::Bytecode;
use stateless_core::db::{BlockMeta, ContractLookup, StoreResult, StoreResultExt};
use tracing::warn;

use crate::{
    serialize::{decode_from_slice, encode_to_vec},
    tables::{
        ANCHOR_BLOCK, CANONICAL_CHAIN, CONTRACTS, Database, block_meta_from_tuple,
        block_meta_to_tuple,
    },
};

/// Opens a table in a read transaction, treating a not-yet-created table as empty —
/// redb only materializes a table on its first write-transaction open, so a freshly
/// created database legitimately lacks the tables its readers ask about. This keeps the
/// read helpers below free of any "constructor must pre-create tables" precondition.
fn open_read_table<K: redb::Key + 'static, V: redb::Value + 'static>(
    read_txn: &redb::ReadTransaction,
    table: redb::TableDefinition<'_, K, V>,
) -> StoreResult<Option<redb::ReadOnlyTable<K, V>>> {
    match read_txn.open_table(table) {
        Ok(table) => Ok(Some(table)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(e).store_err(),
    }
}

/// Reads the canonical tip (highest block) from CANONICAL_CHAIN.
pub fn read_canonical_tip(database: &Database) -> StoreResult<Option<BlockMeta>> {
    let read_txn = database.begin_read().store_err()?;
    let Some(chain) = open_read_table(&read_txn, CANONICAL_CHAIN)? else {
        return Ok(None);
    };
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
    let Some(table) = open_read_table(&read_txn, ANCHOR_BLOCK)? else {
        return Ok(None);
    };
    Ok(table.get("anchor").store_err()?.map(|v| block_meta_from_tuple(v.value())))
}

/// Looks up a single block hash from CANONICAL_CHAIN.
pub fn read_block_hash(
    database: &Database,
    block_number: BlockNumber,
) -> StoreResult<Option<BlockHash>> {
    let read_txn = database.begin_read().store_err()?;
    let Some(chain) = open_read_table(&read_txn, CANONICAL_CHAIN)? else {
        return Ok(None);
    };
    Ok(chain.get(block_number).store_err()?.map(|v| BlockHash::from(v.value().0)))
}

/// Returns the earliest (lowest block number) entry in CANONICAL_CHAIN.
pub fn read_earliest_block(database: &Database) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
    let read_txn = database.begin_read().store_err()?;
    let Some(chain) = open_read_table(&read_txn, CANONICAL_CHAIN)? else {
        return Ok(None);
    };
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

/// CANONICAL_CHAIN value tuple: `(block_hash, post_state_root, post_withdrawals_root)`.
type ChainRow = ([u8; 32], [u8; 32], [u8; 32]);

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
///
/// The disk tier is self-validating: a row that no longer decodes (serde layout drift in
/// an upgraded dependency, on-disk corruption) or whose decoded bytecode no longer hashes
/// back to its key is reported as missing instead of failing the lookup. Both binaries
/// re-fetch misses through the hash-verified RPC tier and write the result back over the
/// stale row, so such rows degrade to a one-time re-fetch instead of halting the node.
/// Storage-engine errors still propagate.
pub fn read_contracts(database: &Database, hashes: &[B256]) -> StoreResult<ContractLookup> {
    let read_txn = database.begin_read().store_err()?;
    let Some(table) = open_read_table(&read_txn, CONTRACTS)? else {
        return Ok((HashMap::default(), hashes.to_vec()));
    };

    let mut found: HashMap<B256, Bytecode> = HashMap::default();
    let mut missing = Vec::new();

    for &hash in hashes {
        let Some(data) = table.get(hash.0).store_err()? else {
            missing.push(hash);
            continue;
        };
        match decode_from_slice::<Bytecode>(data.value().as_slice()) {
            Ok(bytecode) if bytecode.hash_slow() == hash => {
                found.insert(hash, bytecode);
            }
            Ok(_) => {
                warn!(
                    code_hash = %hash,
                    "stored contract bytecode does not hash back to its key; treating as a miss"
                );
                missing.push(hash);
            }
            Err(error) => {
                warn!(
                    code_hash = %hash,
                    %error,
                    "stored contract bytecode failed to decode; treating as a miss"
                );
                missing.push(hash);
            }
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
    use alloy_primitives::{Bytes, b256, keccak256};

    use super::*;
    use crate::serialize::BINCODE_LZ4_MARKER;

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

    /// Keyed the same way the write path verifies: `Bytecode::hash_slow()`.
    fn contract_entry(code: &'static [u8]) -> (B256, Bytecode) {
        let bytecode = Bytecode::new_raw(Bytes::from_static(code));
        (bytecode.hash_slow(), bytecode)
    }

    #[test]
    fn contracts_roundtrip_and_missing_report() {
        let (_dir, db) = temp_db();

        let a = contract_entry(&[0x60]);
        let b = contract_entry(&[0x61]);
        let missing_hash = B256::from([3u8; 32]);

        write_add_contracts(&db, &[]).unwrap();
        write_add_contracts(&db, &[a.clone(), b.clone()]).unwrap();

        let (found, missing) = read_contracts(&db, &[a.0, b.0, missing_hash]).unwrap();
        assert_eq!(missing, vec![missing_hash]);
        assert_eq!(found.len(), 2);
        assert_eq!(found[&a.0].bytes_slice(), a.1.bytes_slice());
        assert_eq!(found[&b.0].bytes_slice(), b.1.bytes_slice());
    }

    /// Inserts a raw pre-encoded row into CONTRACTS, bypassing `write_add_contracts` —
    /// stands in for a row written by an older binary (or corrupted on disk).
    fn insert_raw_contract_row(db: &Database, key: B256, row: Vec<u8>) {
        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(CONTRACTS).unwrap();
            table.insert(key.0, row).unwrap();
        }
        write_txn.commit().unwrap();
    }

    /// Wraps raw bincode bytes into the stored row format (marker byte + lz4), exactly as
    /// `encode_to_vec` would, without re-encoding the payload.
    fn to_stored_row(bincode_bytes: &[u8]) -> Vec<u8> {
        let mut row = vec![BINCODE_LZ4_MARKER];
        row.extend(lz4_flex::compress_prepend_size(bincode_bytes));
        row
    }

    // The two fixtures below are `bincode::serde::encode_to_vec(&Bytecode::new_raw(code),
    // bincode::config::standard())` captured under revm-bytecode 6.2.2 (revm 27.x), whose
    // derived serde enum was ordered `Eip7702 = 0, LegacyAnalyzed = 1`. revm-bytecode 11.x
    // serializes through `BytecodeSerde`, ordered `LegacyAnalyzed = 0, Eip7702 = 1`, so
    // rows persisted by pre-upgrade binaries carry the wrong variant tag today.

    /// revm-bytecode 6.2.2 encoding of `Bytecode::new_raw(&[0x60, 0x80, 0x60, 0x40, 0x52])`.
    /// Under 11.x its `0x01` tag selects `Eip7702`, whose 20-byte address read fails against
    /// the 6-byte (stop-padded) bytecode field: the typical decode-failure shape.
    const REVM6_ROW_TYPICAL: &[u8] = &[
        0x01, 0x06, 0x60, 0x80, 0x60, 0x40, 0x52, 0x00, 0x05, 0x13, 0x62, 0x69, 0x74, 0x76, 0x65,
        0x63, 0x3a, 0x3a, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x3a, 0x3a, 0x4c, 0x73, 0x62, 0x30, 0x08,
        0x00, 0x05, 0x01, 0x00,
    ];
    const REVM6_ROW_TYPICAL_CODE: &[u8] = &[0x60, 0x80, 0x60, 0x40, 0x52];

    /// revm-bytecode 6.2.2 encoding of `Bytecode::new_raw(&[0x5f; 19])`. The 19-byte code is
    /// stop-padded to a 20-byte field, so under 11.x it decodes *successfully* into an
    /// `Eip7702` delegation to a garbage address — only the hash re-check catches it.
    const REVM6_ROW_MISDECODES: &[u8] = &[
        0x01, 0x14, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f,
        0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x00, 0x13, 0x13, 0x62, 0x69, 0x74, 0x76, 0x65, 0x63,
        0x3a, 0x3a, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x3a, 0x3a, 0x4c, 0x73, 0x62, 0x30, 0x08, 0x00,
        0x13, 0x03, 0x00, 0x00, 0x00,
    ];
    const REVM6_ROW_MISDECODES_CODE: &[u8] = &[0x5f; 19];

    #[test]
    fn stale_revm6_contract_row_is_a_miss_not_an_error() {
        let (_dir, db) = temp_db();

        // The pre-upgrade key convention (6.2.2 `hash_slow()`, captured alongside the
        // fixture) is still plain keccak256 of the original bytecode — the key itself
        // survives the upgrade, only the value layout drifted.
        let hash = keccak256(REVM6_ROW_TYPICAL_CODE);
        assert_eq!(hash, b256!("1c3374235d773b2189aed115aa13143020fcdbbe86e38f358cf3e4771b2f0244"));
        let row = to_stored_row(REVM6_ROW_TYPICAL);
        assert!(
            decode_from_slice::<Bytecode>(&row).is_err(),
            "fixture must fail to decode under the current Bytecode serde layout",
        );
        insert_raw_contract_row(&db, hash, row);

        let (found, missing) = read_contracts(&db, &[hash]).unwrap();
        assert!(found.is_empty());
        assert_eq!(missing, vec![hash], "stale row must surface as a miss, not an error");

        // The caller's miss handling re-fetches and writes back; the row then heals.
        let refetched = Bytecode::new_raw(Bytes::from_static(REVM6_ROW_TYPICAL_CODE));
        write_add_contracts(&db, &[(hash, refetched.clone())]).unwrap();
        let (found, missing) = read_contracts(&db, &[hash]).unwrap();
        assert!(missing.is_empty());
        assert_eq!(found[&hash].bytes_slice(), refetched.bytes_slice());
    }

    #[test]
    fn stale_revm6_contract_row_misdecoding_as_eip7702_is_a_miss() {
        let (_dir, db) = temp_db();

        let hash = keccak256(REVM6_ROW_MISDECODES_CODE);
        let row = to_stored_row(REVM6_ROW_MISDECODES);
        // This row *does* decode under the current layout — into an EIP-7702 delegation
        // to a garbage address — so only the hash re-check can reject it.
        let misdecoded = decode_from_slice::<Bytecode>(&row)
            .expect("fixture must silently decode under the current Bytecode serde layout");
        assert_ne!(misdecoded.hash_slow(), hash);
        insert_raw_contract_row(&db, hash, row);

        let (found, missing) = read_contracts(&db, &[hash]).unwrap();
        assert!(found.is_empty());
        assert_eq!(missing, vec![hash], "mis-decoded row must surface as a miss");
    }

    #[test]
    fn hash_mismatched_contract_row_is_a_miss() {
        let (_dir, db) = temp_db();

        // A row that decodes fine but was stored under the wrong key (key corruption, or
        // any future silent mis-decode) is rejected by the hash re-check.
        let wrong_key = B256::from([7u8; 32]);
        let bytecode = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00]));
        write_add_contracts(&db, &[(wrong_key, bytecode)]).unwrap();

        let (found, missing) = read_contracts(&db, &[wrong_key]).unwrap();
        assert!(found.is_empty());
        assert_eq!(missing, vec![wrong_key]);
    }
}
