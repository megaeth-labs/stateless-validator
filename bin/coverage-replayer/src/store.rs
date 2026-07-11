//! redb-backed persistence for the coverage-replayer dispatcher.
//!
//! All coverage data is namespaced by `binary_id` (a fingerprint of the
//! instrumented mega-evm build: locked git rev + toolchain/host, see
//! [`current_binary_id`]) and by the symbol filter: counter ids and dense
//! indices are only meaningful for one instrumented build, and the filter
//! defines which counters exist. On mismatch the store refuses to open.

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

impl PatternRecord {
    /// Strict domination: `self` covers everything `other` does plus more.
    /// The strictness (`bits >`, never `>=`) is load-bearing — equal-bits
    /// distinct patterns must never dominate each other. Single definition
    /// shared by the judge's archive-skip and set-cover's antichain prune.
    pub fn dominates(&self, other: &Self) -> bool {
        self.bits > other.bits && other.bitmap.is_subset_of(&self.bitmap)
    }
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
    /// Opens (or creates) the store and enforces the coverage namespace:
    /// `binary_id` always, plus the symbol filter when the caller supplies one
    /// (backfill/merge do — the filter defines which counters exist, so mixing
    /// filters in one store would silently blend incompatible universes;
    /// read-only consumers pass `None` to skip the filter check).
    pub fn open(path: &Path, binary_id: &str, symbol_filter: Option<&str>) -> Result<Self> {
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

            if let Some(filter) = symbol_filter {
                let existing = meta
                    .get("symbol_filter")?
                    .map(|guard| String::from_utf8_lossy(guard.value()).into_owned());
                match existing {
                    Some(existing) => {
                        ensure!(
                            existing == filter,
                            "store {} was built with --symbol-filter {existing:?}, this run \
                             uses {filter:?}. The filter defines the counter universe: use a \
                             fresh data-dir for a different filter.",
                            path.display(),
                        );
                    }
                    None => {
                        meta.insert("symbol_filter", filter.as_bytes())?;
                    }
                }
            }
        }
        txn.commit()?;

        Ok(Self { db })
    }

    /// Reads the stamped symbol filter, if any.
    pub fn symbol_filter(&self) -> Result<Option<String>> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        let filter =
            meta.get("symbol_filter")?.map(|g| String::from_utf8_lossy(g.value()).into_owned());
        drop(meta);
        drop(txn);
        Ok(filter)
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
        Ok(StoreSnapshot {
            counters: read_table(&txn, COUNTERS)?,
            patterns: read_table(&txn, PATTERNS)?,
            blocks: read_table(&txn, BLOCKS)?,
        })
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
        self.write_table(COUNTERS, &snapshot.counters)?;
        self.write_table(PATTERNS, &snapshot.patterns)?;
        self.write_table(BLOCKS, &snapshot.blocks)?;
        Ok(())
    }

    /// Writes one `u64 -> bincode(T)` table in batched transactions.
    fn write_table<T: serde::Serialize>(
        &self,
        table: TableDefinition<u64, &[u8]>,
        rows: &HashMap<u64, T>,
    ) -> Result<()> {
        const BATCH: usize = 100_000;
        let rows: Vec<_> = rows.iter().collect();
        for chunk in rows.chunks(BATCH) {
            let txn = self.db.begin_write()?;
            {
                let mut t = txn.open_table(table)?;
                for (key, value) in chunk {
                    let bytes = bincode::serde::encode_to_vec(value, BINCODE_CONFIG)
                        .map_err(|e| eyre::eyre!("encode table row: {e}"))?;
                    t.insert(**key, bytes.as_slice())?;
                }
            }
            txn.commit()?;
        }
        Ok(())
    }
}

/// Reads a whole `u64 -> bincode(T)` table into a map.
fn read_table<T: serde::de::DeserializeOwned>(
    txn: &redb::ReadTransaction,
    table: TableDefinition<u64, &[u8]>,
) -> Result<HashMap<u64, T>> {
    let t = txn.open_table(table)?;
    let mut map = HashMap::new();
    for row in t.iter()? {
        let (k, v) = row?;
        let (value, _): (T, _) = bincode::serde::decode_from_slice(v.value(), BINCODE_CONFIG)
            .map_err(|e| eyre::eyre!("decode table row: {e}"))?;
        map.insert(k.value(), value);
    }
    Ok(map)
}

/// In-memory image of the store, owned by the judge / set-cover.
#[derive(Clone)]
pub struct StoreSnapshot {
    pub counters: HashMap<u64, CounterInfo>,
    pub patterns: HashMap<u64, PatternRecord>,
    pub blocks: HashMap<u64, BlockRecord>,
}

/// Linear-probe step for pattern-key collisions (golden ratio). Lives beside
/// [`pattern_base_key`] and [`resolve_pattern_slot`] — the probing walk must
/// stay byte-identical between the judge and `merge`.
pub const PROBE_STEP: u64 = 0x9E37_79B9_7F4A_7C15;

/// Base pattern key: FxHash64 of the pattern's counter ids in ascending
/// order. The SINGLE keying function shared by the judge (backfill) and
/// `merge` — both must key identically or a merged store diverges from a
/// sequential run. Collisions between differing bitmaps are handled by
/// [`resolve_pattern_slot`]'s linear probing.
pub fn pattern_base_key(sorted_ids: &[u64]) -> u64 {
    use std::hash::Hasher;
    debug_assert!(sorted_ids.is_sorted());
    let mut h = rustc_hash::FxHasher::default();
    for id in sorted_ids {
        h.write_u64(*id);
    }
    h.finish()
}

/// Walks the probe chain for `bitmap` starting at [`pattern_base_key`] of its
/// sorted counter ids: returns `(slot_key, occupied)` where `occupied` means
/// the slot already holds this exact bitmap (the caller merges stats into
/// it); otherwise the slot is vacant and the caller inserts. The SINGLE
/// probing walk shared by the judge and `merge`.
pub fn resolve_pattern_slot(
    patterns: &HashMap<u64, PatternRecord>,
    sorted_ids: &[u64],
    bitmap: &BitSet,
) -> (u64, bool) {
    let mut key = pattern_base_key(sorted_ids);
    loop {
        match patterns.get(&key) {
            None => return (key, false),
            Some(rec) if rec.bitmap == *bitmap => return (key, true),
            Some(_) => key = key.wrapping_add(PROBE_STEP),
        }
    }
}

/// Coverage namespace key: a fingerprint of the instrumented mega-evm build,
/// NOT a whole-exe hash. Stays stable across dispatcher/orchestration edits
/// (so the resident mode can continue a store built by `backfill`), and only
/// changes when mega-evm's revision or the toolchain changes — exactly when
/// the counter ids would actually shift. Captured at compile time by build.rs.
pub fn current_binary_id() -> String {
    use std::hash::Hasher;
    let mega_evm = env!("COVERAGE_MEGA_EVM_REV");
    let rustc = env!("COVERAGE_RUSTC_VERSION");
    let mut h = rustc_hash::FxHasher::default();
    h.write(mega_evm.as_bytes());
    h.write_u8(0xff);
    h.write(rustc.as_bytes());
    format!("megaevm:{}:fx{:016x}", &mega_evm[..mega_evm.len().min(12)], h.finish())
}

/// Sorted-sample summary for per-block worker times: `(avg, p50, p95, max)`.
/// Returns `None` for an empty sample. One definition for the three log
/// sites (backfill summary, set-cover, inspect).
pub fn elapsed_stats(samples: &mut [u64]) -> Option<(f64, u64, u64, u64)> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let avg = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
    Some((
        avg,
        samples[samples.len() / 2],
        samples[(samples.len() * 95 / 100).min(samples.len() - 1)],
        samples[samples.len() - 1],
    ))
}
