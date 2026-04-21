//! Shared redb read/write helpers used by both concrete database implementations.

use std::collections::HashMap;

use alloy_primitives::{B256, BlockHash, BlockNumber};
use redb::{ReadableDatabase, ReadableTable};
use revm::state::Bytecode;
use stateless_core::db::{BlockMeta, StoreResult};

use crate::{
    serialize::{decode_from_slice, encode_to_vec},
    tables::{
        ANCHOR_BLOCK, CANONICAL_CHAIN, CONTRACTS, Database, block_meta_from_tuple,
        block_meta_to_tuple,
    },
};

/// Reads the canonical tip (highest block) from CANONICAL_CHAIN.
pub fn db_get_canonical_tip(database: &Database) -> StoreResult<Option<BlockMeta>> {
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
pub fn db_get_anchor(database: &Database) -> StoreResult<Option<BlockMeta>> {
    let read_txn = database.begin_read()?;
    let table = read_txn.open_table(ANCHOR_BLOCK)?;
    Ok(table.get("anchor")?.map(|v| block_meta_from_tuple(v.value())))
}

/// Looks up a single block hash from CANONICAL_CHAIN.
pub fn db_get_block_hash(
    database: &Database,
    block_number: BlockNumber,
) -> StoreResult<Option<BlockHash>> {
    let read_txn = database.begin_read()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN)?;
    Ok(chain.get(block_number)?.map(|v| BlockHash::from(v.value().0)))
}

/// Returns the earliest (lowest block number) entry in CANONICAL_CHAIN.
pub fn db_get_earliest_block(database: &Database) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
    let read_txn = database.begin_read()?;
    let chain = read_txn.open_table(CANONICAL_CHAIN)?;
    Ok(chain.first()?.map(|(k, v)| (k.value(), BlockHash::from(v.value().0))))
}

/// Appends blocks to CANONICAL_CHAIN in a single write transaction.
pub fn db_advance_chain(database: &Database, blocks: &[BlockMeta]) -> StoreResult<()> {
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
pub fn db_rollback_chain(database: &Database, to_block: BlockNumber) -> StoreResult<()> {
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
pub fn db_reset_to_anchor(database: &Database, anchor: &BlockMeta) -> StoreResult<()> {
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
) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
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
pub fn db_add_contracts(database: &Database, codes: &[(B256, Bytecode)]) -> StoreResult<()> {
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
