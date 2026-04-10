//! Block storage and chain tracking database for `debug-trace-server`.
//!
//! Provides persistent storage of block data, witnesses, and canonical chain state
//! for serving `debug_*` and `trace_*` RPC methods.

use std::{collections::HashMap, path::Path};

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use op_alloy_rpc_types::Transaction;
use rayon::prelude::*;
use redb::{ReadableDatabase, ReadableTable};
use revm::state::Bytecode;
use stateless_common::db::{
    ANCHOR_BLOCK, BLOCK_DATA, BLOCK_RECORDS, CANONICAL_CHAIN, CONTRACTS, Database, MissingDataKind,
    ValidationDbError, ValidationDbResult, WITNESSES, db_add_contracts, db_advance_chain,
    db_get_anchor, db_get_block_hash, db_get_canonical_tip, db_get_contracts,
    db_get_earliest_block, db_reset_to_anchor, db_rollback_chain, decode_block_from_slice,
    decode_from_slice, encode_block_to_vec, encode_to_vec,
};
use stateless_core::{
    LightWitness,
    db::{BlockMeta, BlockStore, ChainStore, ContractStore, PrunableChainStore},
};

/// Block storage and chain tracking database for debug-trace-server.
pub struct ServerDB {
    database: Database,
}

impl ServerDB {
    /// Create a new redb instance or open an existing one.
    pub fn new(db_path: impl AsRef<Path>) -> ValidationDbResult<Self> {
        let database = Database::create(db_path)?;

        let write_txn = database.begin_write()?;
        {
            let _canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let _block_data = write_txn.open_table(BLOCK_DATA)?;
            let _witnesses = write_txn.open_table(WITNESSES)?;
            let _block_records = write_txn.open_table(BLOCK_RECORDS)?;
            let _contracts = write_txn.open_table(CONTRACTS)?;
            let _anchor_block = write_txn.open_table(ANCHOR_BLOCK)?;
        }
        write_txn.commit()?;

        Ok(Self { database })
    }

    /// Stores block data and witnesses.
    pub fn store_block_data(
        &self,
        tasks: &[(Block<Transaction>, LightWitness)],
    ) -> ValidationDbResult<()> {
        if tasks.is_empty() {
            return Ok(());
        }

        let tasks = tasks
            .par_iter()
            .map(|(block, light_witness)| {
                Ok::<_, ValidationDbError>((
                    block.header.number,
                    block.header.hash.0,
                    encode_block_to_vec(block)?,
                    encode_to_vec(light_witness)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let write_txn = self.database.begin_write()?;
        {
            let mut block_data = write_txn.open_table(BLOCK_DATA)?;
            let mut witnesses = write_txn.open_table(WITNESSES)?;
            let mut block_records = write_txn.open_table(BLOCK_RECORDS)?;

            for (number, hash, block, light_witness) in tasks {
                block_data.insert(hash, block)?;
                witnesses.insert(hash, light_witness)?;
                block_records.insert((number, hash), ())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Gets the latest block in the local chain.
    pub fn get_local_tip(&self) -> ValidationDbResult<Option<(BlockNumber, BlockHash)>> {
        let read_txn = self.database.begin_read()?;
        let chain = read_txn.open_table(CANONICAL_CHAIN)?;
        Ok(chain.last()?.map(|(k, v)| {
            let (hash, _, _) = v.value();
            (k.value(), BlockHash::from(hash))
        }))
    }

    /// Resets the chain anchor point and clears all chain state.
    pub fn reset_anchor_block(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        post_state_root: B256,
        post_withdrawals_root: B256,
    ) -> ValidationDbResult<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut anchor_table = write_txn.open_table(ANCHOR_BLOCK)?;
            anchor_table.insert(
                "anchor",
                (block_number, block_hash.0, post_state_root.0, post_withdrawals_root.0),
            )?;
            let mut chain = write_txn.open_table(CANONICAL_CHAIN)?;
            chain.retain(|_, _| false)?;
            chain
                .insert(block_number, (block_hash.0, post_state_root.0, post_withdrawals_root.0))?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Cleans up old block data to save storage space.
    pub fn prune_history(&self, before_block: BlockNumber) -> ValidationDbResult<u64> {
        let read_txn = self.database.begin_read()?;
        let block_records = read_txn.open_table(BLOCK_RECORDS)?;

        let keys_to_remove = block_records
            .range(..(before_block, [0u8; 32]))?
            .map(|result| result.map(|(key, _)| key.value()))
            .collect::<Result<Vec<_>, _>>()?;
        let pruned_count = keys_to_remove.len() as u64;

        let write_txn = self.database.begin_write()?;
        {
            let mut canonical_chain = write_txn.open_table(CANONICAL_CHAIN)?;
            let mut block_records = write_txn.open_table(BLOCK_RECORDS)?;
            let mut block_data = write_txn.open_table(BLOCK_DATA)?;
            let mut witnesses = write_txn.open_table(WITNESSES)?;

            for (block_number, block_hash) in keys_to_remove {
                canonical_chain.remove(block_number)?;
                block_records.remove((block_number, block_hash))?;
                block_data.remove(block_hash)?;
                witnesses.remove(block_hash)?;
            }

            // Clean up orphaned CANONICAL_CHAIN entries not tracked in BLOCK_RECORDS
            loop {
                let block_number = match canonical_chain.first()? {
                    Some(entry) => {
                        let n = entry.0.value();
                        if n >= before_block {
                            break;
                        }
                        n
                    }
                    None => break,
                };
                canonical_chain.remove(block_number)?;
            }
        }
        write_txn.commit()?;
        Ok(pruned_count)
    }

    /// Retrieves block data and witness for a specific block hash.
    pub fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> ValidationDbResult<(Block<Transaction>, LightWitness)> {
        let start = std::time::Instant::now();

        let read_txn = self.database.begin_read()?;
        let block_data = read_txn.open_table(BLOCK_DATA)?;
        let witnesses = read_txn.open_table(WITNESSES)?;
        let txn_ms = start.elapsed().as_millis();

        let block_bytes = block_data.get(block_hash.0)?.ok_or(ValidationDbError::MissingData {
            kind: MissingDataKind::BlockData,
            block_hash,
        })?;
        let block_bytes_value = block_bytes.value();
        let block_bytes_len = block_bytes_value.len();
        let db_read_block_ms = start.elapsed().as_millis();

        let block = decode_block_from_slice(&block_bytes_value)?;
        let block_decode_ms = start.elapsed().as_millis();

        let witness_bytes = witnesses
            .get(block_hash.0)?
            .ok_or(ValidationDbError::MissingData { kind: MissingDataKind::Witness, block_hash })?;
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
    fn get_contracts(&self, hashes: &[B256]) -> eyre::Result<(HashMap<B256, Bytecode>, Vec<B256>)> {
        db_get_contracts(&self.database, hashes)
    }

    fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> eyre::Result<()> {
        db_add_contracts(&self.database, codes)
    }
}

impl ChainStore for ServerDB {
    fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
        db_get_canonical_tip(&self.database)
    }

    fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
        db_get_anchor(&self.database)
    }

    fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()> {
        db_advance_chain(&self.database, blocks)
    }

    fn get_block_hash(&self, block_number: BlockNumber) -> eyre::Result<Option<BlockHash>> {
        db_get_block_hash(&self.database, block_number)
    }

    fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
        db_get_earliest_block(&self.database)
    }

    fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()> {
        db_rollback_chain(&self.database, to_block)
    }

    fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
        db_reset_to_anchor(&self.database, anchor)
    }
}

impl PrunableChainStore for ServerDB {
    fn prune_chain(&self, before_block: BlockNumber) -> eyre::Result<u64> {
        Ok(ServerDB::prune_history(self, before_block)?)
    }
}

impl BlockStore for ServerDB {
    fn store_block_data(&self, blocks: &[(Block<Transaction>, LightWitness)]) -> eyre::Result<()> {
        Ok(ServerDB::store_block_data(self, blocks)?)
    }

    fn get_block_and_witness(
        &self,
        block_hash: BlockHash,
    ) -> eyre::Result<(Block<Transaction>, LightWitness)> {
        Ok(ServerDB::get_block_and_witness(self, block_hash)?)
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
        LightWitness {
            kvs: std::collections::BTreeMap::new(),
            levels: rustc_hash::FxHashMap::default(),
        }
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
    fn test_server_db_reset_anchor_block() {
        let (_dir, db) = temp_server_db();

        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        let anchor = make_block_meta(100);
        ChainStore::reset_to_anchor(&db, &anchor).unwrap();

        assert!(ChainStore::get_block_hash(&db, 1).unwrap().is_none());

        let (number, hash) = db.get_local_tip().unwrap().unwrap();
        assert_eq!(number, 100);
        assert_eq!(hash, anchor.block_hash);
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

        let earliest = ChainStore::get_earliest_block(&db).unwrap().unwrap();
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
    }

    #[test]
    fn test_server_db_prune_history() {
        let (_dir, db) = temp_server_db();

        let blocks: Vec<BlockMeta> = (1..=5).map(make_block_meta).collect();
        ChainStore::advance_chain(&db, &blocks).unwrap();

        let pruned = db.prune_history(3).unwrap();
        assert_eq!(pruned, 0);

        assert!(ChainStore::get_block_hash(&db, 1).unwrap().is_none());
        assert!(ChainStore::get_block_hash(&db, 2).unwrap().is_none());
        assert!(ChainStore::get_block_hash(&db, 3).unwrap().is_some());
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

        let pruned = PrunableChainStore::prune_chain(&db, 6).unwrap();
        assert_eq!(pruned, 5);

        for n in 1..=5 {
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_none());
        }
        for n in 6..=10 {
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_some());
        }
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
            ValidationDbError::MissingData { kind: MissingDataKind::BlockData, block_hash } => {
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
}
