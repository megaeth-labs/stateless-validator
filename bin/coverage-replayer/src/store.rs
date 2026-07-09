//! redb-backed persistence for the coverage-replayer dispatcher.
//!
//! All coverage data is namespaced by `binary_id` (a content hash of the
//! running executable): counter ids and dense indices are only meaningful for
//! one exact instrumented build. On mismatch the store refuses to open.

use std::{collections::HashMap, path::Path};

use alloy_primitives::B256;
use eyre::{Result, ensure};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::bitset::BitSet;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const COUNTERS: TableDefinition<u64, &[u8]> = TableDefinition::new("counters");
const PATTERNS: TableDefinition<u64, &[u8]> = TableDefinition::new("patterns");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
const SCHEMA_VERSION: u32 = 1;

/// Info about one coverage counter (id → dense index + provenance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterInfo {
    pub dense: u32,
    pub symbol: String,
    pub func_hash: String,
    pub index: u32,
}

/// One distinct coverage bitmap and its representative block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRecord {
    pub bitmap: BitSet,
    pub bits: u64,
    pub first_block: u64,
    pub last_block: u64,
    pub hit_count: u64,
    /// The lightest (min replay time) block seen exhibiting this pattern — the
    /// best fixture candidate. Re-homed whenever a lighter block appears.
    pub representative: u64,
    /// Replay time of `representative`, to decide re-homing.
    pub representative_elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockStatus {
    /// Replayed cleanly, bitmap ingested.
    Ok,
    /// Executed but header sanity comparison failed — bitmap NOT ingested.
    Divergent,
    /// Replay failed with an error — bitmap NOT ingested.
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    pub hash: B256,
    pub status: BlockStatus,
    /// Pattern key this block's bitmap deduped into (when `status == Ok`).
    pub pattern_key: Option<u64>,
    pub gas_used: u64,
    pub tx_count: u64,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

pub struct Store {
    db: Database,
}

impl Store {
    /// Opens (or creates) the store and enforces the binary-id namespace.
    pub fn open(path: &Path, binary_id: &str) -> Result<Self> {
        let db = Database::create(path)?;

        // Ensure all tables exist, then check/stamp namespace metadata.
        let txn = db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            txn.open_table(COUNTERS)?;
            txn.open_table(PATTERNS)?;
            txn.open_table(BLOCKS)?;

            let existing = meta
                .get("binary_id")?
                .map(|guard| String::from_utf8_lossy(guard.value()).into_owned());
            match existing {
                Some(existing) => {
                    ensure!(
                        existing == binary_id,
                        "store {} belongs to binary_id {existing}, current binary is \
                         {binary_id}. The counter namespace is per-build: move the data-dir \
                         aside (or start a fresh one) and re-sweep.",
                        path.display(),
                    );
                }
                None => {
                    meta.insert("binary_id", binary_id.as_bytes())?;
                    meta.insert("schema_version", SCHEMA_VERSION.to_le_bytes().as_slice())?;
                }
            }
        }
        txn.commit()?;

        Ok(Self { db })
    }

    /// Opens an existing store WITHOUT the binary-id namespace check, for
    /// read-only inspection of data produced by another build (e.g. analyzing
    /// a store copied from a server). Returns the store and its binary_id.
    pub fn open_readonly(path: &Path) -> Result<(Self, String)> {
        ensure!(path.exists(), "store {} does not exist", path.display());
        let db = Database::open(path)?;
        let store = Self { db };
        let txn = store.db.begin_read()?;
        let meta = txn.open_table(META)?;
        let binary_id = meta
            .get("binary_id")?
            .map(|g| String::from_utf8_lossy(g.value()).into_owned())
            .unwrap_or_else(|| "<unset>".into());
        drop(meta);
        drop(txn);
        Ok((store, binary_id))
    }

    /// Loads the whole dispatcher state into memory (counters, patterns, blocks).
    pub fn load(&self) -> Result<StoreSnapshot> {
        let txn = self.db.begin_read()?;

        let mut counters = HashMap::new();
        {
            let t = txn.open_table(COUNTERS)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let (info, _): (CounterInfo, _) =
                    bincode::serde::decode_from_slice(v.value(), BINCODE_CONFIG)
                        .map_err(|e| eyre::eyre!("decode CounterInfo: {e}"))?;
                counters.insert(k.value(), info);
            }
        }

        let mut patterns = HashMap::new();
        {
            let t = txn.open_table(PATTERNS)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let (rec, _): (PatternRecord, _) =
                    bincode::serde::decode_from_slice(v.value(), BINCODE_CONFIG)
                        .map_err(|e| eyre::eyre!("decode PatternRecord: {e}"))?;
                patterns.insert(k.value(), rec);
            }
        }

        let mut blocks = HashMap::new();
        {
            let t = txn.open_table(BLOCKS)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let (rec, _): (BlockRecord, _) =
                    bincode::serde::decode_from_slice(v.value(), BINCODE_CONFIG)
                        .map_err(|e| eyre::eyre!("decode BlockRecord: {e}"))?;
                blocks.insert(k.value(), rec);
            }
        }

        Ok(StoreSnapshot { counters, patterns, blocks })
    }

    /// Persists one judged block: its record, any new counters, and the
    /// created/updated pattern — atomically in one transaction.
    pub fn commit_block(
        &self,
        block: u64,
        record: &BlockRecord,
        new_counters: &[(u64, CounterInfo)],
        pattern: Option<(u64, &PatternRecord)>,
    ) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(BLOCKS)?;
            let bytes = bincode::serde::encode_to_vec(record, BINCODE_CONFIG)
                .map_err(|e| eyre::eyre!("encode BlockRecord: {e}"))?;
            t.insert(block, bytes.as_slice())?;
        }
        if !new_counters.is_empty() {
            let mut t = txn.open_table(COUNTERS)?;
            for (id, info) in new_counters {
                let bytes = bincode::serde::encode_to_vec(info, BINCODE_CONFIG)
                    .map_err(|e| eyre::eyre!("encode CounterInfo: {e}"))?;
                t.insert(*id, bytes.as_slice())?;
            }
        }
        if let Some((key, rec)) = pattern {
            let mut t = txn.open_table(PATTERNS)?;
            let bytes = bincode::serde::encode_to_vec(rec, BINCODE_CONFIG)
                .map_err(|e| eyre::eyre!("encode PatternRecord: {e}"))?;
            t.insert(key, bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Bulk-writes a merged snapshot into a fresh store, in batched
    /// transactions. Used by the `merge` subcommand.
    pub fn write_bulk(&self, snapshot: &StoreSnapshot) -> Result<()> {
        const BATCH: usize = 100_000;

        let counters: Vec<_> = snapshot.counters.iter().collect();
        for chunk in counters.chunks(BATCH) {
            let txn = self.db.begin_write()?;
            {
                let mut t = txn.open_table(COUNTERS)?;
                for (id, info) in chunk {
                    let bytes = bincode::serde::encode_to_vec(info, BINCODE_CONFIG)
                        .map_err(|e| eyre::eyre!("encode CounterInfo: {e}"))?;
                    t.insert(**id, bytes.as_slice())?;
                }
            }
            txn.commit()?;
        }

        let patterns: Vec<_> = snapshot.patterns.iter().collect();
        for chunk in patterns.chunks(BATCH) {
            let txn = self.db.begin_write()?;
            {
                let mut t = txn.open_table(PATTERNS)?;
                for (key, rec) in chunk {
                    let bytes = bincode::serde::encode_to_vec(rec, BINCODE_CONFIG)
                        .map_err(|e| eyre::eyre!("encode PatternRecord: {e}"))?;
                    t.insert(**key, bytes.as_slice())?;
                }
            }
            txn.commit()?;
        }

        let blocks: Vec<_> = snapshot.blocks.iter().collect();
        for chunk in blocks.chunks(BATCH) {
            let txn = self.db.begin_write()?;
            {
                let mut t = txn.open_table(BLOCKS)?;
                for (num, rec) in chunk {
                    let bytes = bincode::serde::encode_to_vec(rec, BINCODE_CONFIG)
                        .map_err(|e| eyre::eyre!("encode BlockRecord: {e}"))?;
                    t.insert(**num, bytes.as_slice())?;
                }
            }
            txn.commit()?;
        }
        Ok(())
    }
}

/// In-memory image of the store, owned by the judge / set-cover.
#[derive(Clone)]
pub struct StoreSnapshot {
    pub counters: HashMap<u64, CounterInfo>,
    pub patterns: HashMap<u64, PatternRecord>,
    pub blocks: HashMap<u64, BlockRecord>,
}

/// Coverage namespace key: a fingerprint of the instrumented mega-evm build,
/// NOT a whole-exe hash. Stays stable across dispatcher/orchestration edits
/// (so the resident mode can continue a store built by `backfill`), and only
/// changes when mega-evm's revision or the toolchain changes — exactly when
/// the counter ids would actually shift. Captured at compile time by build.rs.
pub fn current_binary_id() -> Result<String> {
    use std::hash::Hasher;
    let mega_evm = env!("COVERAGE_MEGA_EVM_REV");
    let rustc = env!("COVERAGE_RUSTC_VERSION");
    let mut h = rustc_hash::FxHasher::default();
    h.write(mega_evm.as_bytes());
    h.write_u8(0xff);
    h.write(rustc.as_bytes());
    Ok(format!("megaevm:{}:fx{:016x}", &mega_evm[..mega_evm.len().min(12)], h.finish()))
}
