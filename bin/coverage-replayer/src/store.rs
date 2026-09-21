//! redb-backed persistence for the coverage-replayer dispatcher.
//!
//! All coverage data is namespaced by `binary_id` (a fingerprint of the
//! instrumented mega-evm build: locked git rev + toolchain/host, see
//! [`current_binary_id`]) and by the universe stamp (what a counter id means
//! and which sources are in scope, see [`crate::llvm::universe_stamp`]):
//! counter ids and dense indices are only meaningful for one instrumented
//! build and one item definition. On mismatch the store refuses to open.

use std::{collections::HashMap, path::Path};

use alloy_primitives::B256;
use eyre::{Result, ensure};
use redb::{
    Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};
use serde::{Deserialize, Serialize};

use crate::bitset::BitSet;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const COUNTERS: TableDefinition<u64, &[u8]> = TableDefinition::new("counters");
const PATTERNS: TableDefinition<u64, &[u8]> = TableDefinition::new("patterns");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
const SCHEMA_VERSION: u32 = 1;

/// Info about one coverage counter (id → dense index + provenance).
///
/// The three provenance fields are written for humans and never read back by
/// any logic, which is why their *meaning* could change without a schema
/// bump: the encoding is positional, so a legacy store (physical counters)
/// still decodes — there `location` holds a PGO symbol, `kind` a function
/// hash and `line` a counter index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterInfo {
    pub dense: u32,
    /// `<source path>:<line>:<col>` of the covered item.
    pub location: String,
    /// `region`, `branch-true` or `branch-false`.
    pub kind: String,
    pub line: u32,
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

/// The redb handle type selects the API: [`Database`] for writers (backfill,
/// set-cover, merge output), [`ReadOnlyDatabase`] for pure readers (inspect,
/// merge inputs) — the write methods do not exist on a read-only store.
pub struct Store<D = Database> {
    db: D,
}

impl Store {
    /// Opens (or creates) the store and enforces the coverage namespace:
    /// `binary_id` always, plus the universe stamp when the caller supplies
    /// one (backfill/merge do — it defines what a counter id means, so mixing
    /// stamps in one store would silently blend incompatible universes;
    /// set-cover passes `None` and consumes whatever universe the store holds).
    pub fn open(path: &Path, binary_id: &str, universe: Option<&str>) -> Result<Self> {
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
                    check_schema_version(&meta, path)?;
                    check_complete(&meta, path)?;
                }
                None => {
                    meta.insert("binary_id", binary_id.as_bytes())?;
                    meta.insert("schema_version", SCHEMA_VERSION.to_le_bytes().as_slice())?;
                }
            }

            if let Some(universe) = universe {
                match stamped_universe(&meta)? {
                    Some(existing) => {
                        ensure!(
                            existing == universe,
                            "store {} holds the counter universe {existing:?}, this run \
                             produces {universe:?}. Counter ids from two universes must never \
                             share a store: use a fresh data-dir.",
                            path.display(),
                        );
                    }
                    None => {
                        meta.insert(UNIVERSE_KEY, universe.as_bytes())?;
                    }
                }
            }
        }
        txn.commit()?;

        Ok(Self { db })
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
    ///
    /// The tables are committed batch by batch, so a store interrupted halfway
    /// is a perfectly valid, correctly stamped database holding a prefix of
    /// the data — and set-cover would publish a cover of that prefix. The
    /// marker set here makes every open refuse the store until the last batch
    /// is in.
    pub fn write_bulk(&self, snapshot: &StoreSnapshot) -> Result<()> {
        self.set_incomplete(true)?;
        self.write_table(COUNTERS, &snapshot.counters)?;
        self.write_table(PATTERNS, &snapshot.patterns)?;
        self.write_table(BLOCKS, &snapshot.blocks)?;
        self.set_incomplete(false)
    }

    fn set_incomplete(&self, incomplete: bool) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            if incomplete {
                meta.insert(INCOMPLETE_KEY, b"bulk write in progress".as_slice())?;
            } else {
                meta.remove(INCOMPLETE_KEY)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Writes one `u64 -> bincode(T)` table in batched transactions.
    fn write_table<T: serde::Serialize>(
        &self,
        table: TableDefinition<u64, &[u8]>,
        rows: &HashMap<u64, T>,
    ) -> Result<()> {
        const BATCH: usize = 100_000;
        // Ascending key order is load-bearing for speed, not correctness: a
        // `HashMap` iterates in random order, and random insertion dirties
        // pages all over the B-tree on every batch, so each commit rewrites
        // a slice of the whole tree. Sorted, every batch lands on the right
        // edge and a commit costs what the batch holds.
        let mut rows: Vec<_> = rows.iter().collect();
        rows.sort_unstable_by_key(|(key, _)| **key);
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

impl Store<ReadOnlyDatabase> {
    /// Opens an existing store WITHOUT the binary-id namespace check, for
    /// read-only inspection of data produced by another build (e.g. analyzing
    /// a store copied from a server). Returns the store and its binary_id.
    ///
    /// The file is opened without write access under a shared lock, so a
    /// store the caller cannot write (e.g. root-owned on a server) opens fine
    /// and is never modified. In exchange, a store held open by a writer or
    /// left unclean by a crash is refused rather than waited on or repaired.
    pub fn open_readonly(path: &Path) -> Result<(Self, String)> {
        ensure!(path.exists(), "store {} does not exist", path.display());
        let db = ReadOnlyDatabase::open(path).map_err(|e| match e {
            redb::DatabaseError::DatabaseAlreadyOpen => eyre::eyre!(
                "store {} is held open read-write (a running backfill?) — wait for it to \
                 exit, or read a copy",
                path.display()
            ),
            redb::DatabaseError::RepairAborted => eyre::eyre!(
                "store {} was not shut down cleanly and needs a repair, which a read-only \
                 open never performs — a read-write open (e.g. the next backfill on this \
                 data-dir) repairs it",
                path.display()
            ),
            e => eyre::eyre!("open store {} read-only: {e}", path.display()),
        })?;
        let store = Self { db };
        let txn = store.db.begin_read()?;
        let meta = txn.open_table(META)?;
        check_schema_version(&meta, path)?;
        check_complete(&meta, path)?;
        let binary_id = meta
            .get("binary_id")?
            .map(|g| String::from_utf8_lossy(g.value()).into_owned())
            .unwrap_or_else(|| "<unset>".into());
        drop(meta);
        drop(txn);
        Ok((store, binary_id))
    }
}

impl<D: ReadableDatabase> Store<D> {
    /// Reads the stamped counter universe, if any (see [`stamped_universe`]).
    pub fn universe(&self) -> Result<Option<String>> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        let universe = stamped_universe(&meta)?;
        drop(meta);
        drop(txn);
        Ok(universe)
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

    /// [`Self::load`] variant for `backfill`: counters and patterns in full
    /// (they are the working set and bounded by the universe), but block
    /// records only for the range being scanned. The BLOCKS table grows by
    /// one row per block ever scanned — a full-history store holds tens of
    /// millions of rows, and the judge only needs the current range's
    /// statuses for its todo filter.
    pub fn load_for_range(&self, blocks: std::ops::RangeInclusive<u64>) -> Result<StoreSnapshot> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(BLOCKS)?;
        let mut in_range = HashMap::new();
        for row in t.range(blocks)? {
            let (k, v) = row?;
            let (value, _): (BlockRecord, _) =
                bincode::serde::decode_from_slice(v.value(), BINCODE_CONFIG)
                    .map_err(|e| eyre::eyre!("decode BlockRecord: {e}"))?;
            in_range.insert(k.value(), value);
        }
        drop(t);
        Ok(StoreSnapshot {
            counters: read_table(&txn, COUNTERS)?,
            patterns: read_table(&txn, PATTERNS)?,
            blocks: in_range,
        })
    }

    /// [`Self::load_for_range`] for an explicit, possibly scattered block
    /// list (`backfill --blocks-file`): one point lookup per requested block
    /// instead of a walk over every row between the extremes — a pool drawn
    /// from the whole history spans tens of millions of rows but names only
    /// tens of thousands of them.
    pub fn load_for_blocks(&self, blocks: &[u64]) -> Result<StoreSnapshot> {
        let requested = self.block_records(blocks)?;
        let txn = self.db.begin_read()?;
        Ok(StoreSnapshot {
            counters: read_table(&txn, COUNTERS)?,
            patterns: read_table(&txn, PATTERNS)?,
            blocks: requested,
        })
    }

    /// Point lookups into the BLOCKS table; blocks never scanned are absent.
    pub fn block_records(&self, blocks: &[u64]) -> Result<HashMap<u64, BlockRecord>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(BLOCKS)?;
        let mut found = HashMap::new();
        for n in blocks {
            if let Some(v) = t.get(n)? {
                let (value, _): (BlockRecord, _) =
                    bincode::serde::decode_from_slice(v.value(), BINCODE_CONFIG)
                        .map_err(|e| eyre::eyre!("decode BlockRecord: {e}"))?;
                found.insert(*n, value);
            }
        }
        Ok(found)
    }

    /// Visits every BLOCKS row in ascending block order without holding the
    /// table: a full-history store has tens of millions of rows, and the
    /// consumers of a full pass (`inspect`) only ever fold them into totals.
    pub fn for_each_block(&self, mut visit: impl FnMut(u64, BlockRecord)) -> Result<()> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(BLOCKS)?;
        for row in t.iter()? {
            let (k, v) = row?;
            let (record, _): (BlockRecord, _) =
                bincode::serde::decode_from_slice(v.value(), BINCODE_CONFIG)
                    .map_err(|e| eyre::eyre!("decode BlockRecord: {e}"))?;
            visit(k.value(), record);
        }
        Ok(())
    }

    /// How many counters the store has ever registered.
    pub fn counter_count(&self) -> Result<usize> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(COUNTERS)?.len()? as usize)
    }

    /// The patterns alone — all set-cover selects from. The BLOCKS table is
    /// one row per block ever scanned; decoding tens of millions of them to
    /// look up a hundred hashes afterwards is most of a full `load`'s memory.
    pub fn load_patterns(&self) -> Result<HashMap<u64, PatternRecord>> {
        let txn = self.db.begin_read()?;
        read_table(&txn, PATTERNS)
    }
}

const INCOMPLETE_KEY: &str = "incomplete";

/// Rejects the output of a bulk write (`merge`) that never finished.
fn check_complete<T>(meta: &T, path: &Path) -> Result<()>
where
    T: redb::ReadableTable<&'static str, &'static [u8]>,
{
    ensure!(
        meta.get(INCOMPLETE_KEY)?.is_none(),
        "store {} is the output of a merge that did not finish — it holds only part of the \
         data. Delete it and run the merge again.",
        path.display(),
    );
    Ok(())
}

const UNIVERSE_KEY: &str = "universe";
/// The stamp stores carried before counters became evaluated items: the
/// substring filter on PGO symbol names that scoped the physical counters.
const LEGACY_SYMBOL_FILTER_KEY: &str = "symbol_filter";

/// The counter universe a store is stamped with. A legacy store has no
/// universe key, only its symbol filter; it is reported under a label of its
/// own, so it never compares equal to a current stamp — a run that would mix
/// physical-counter ids with evaluated-item ids is refused like any other
/// universe mismatch, while merging legacy shards with each other still works.
fn stamped_universe<T>(meta: &T) -> Result<Option<String>>
where
    T: redb::ReadableTable<&'static str, &'static [u8]>,
{
    let read = |key: &str| -> Result<Option<String>> {
        Ok(meta.get(key)?.map(|g| String::from_utf8_lossy(g.value()).into_owned()))
    };
    if let Some(universe) = read(UNIVERSE_KEY)? {
        return Ok(Some(universe));
    }
    Ok(read(LEGACY_SYMBOL_FILTER_KEY)?.map(|filter| format!("physical-counters/v0:{filter}")))
}

/// Rejects a store whose record encoding predates/postdates this binary —
/// otherwise a format change surfaces as opaque bincode decode errors deep
/// inside `read_table` instead of a clean mismatch message. Stores created
/// before versioning are all schema 1.
fn check_schema_version<T>(meta: &T, path: &Path) -> Result<()>
where
    T: redb::ReadableTable<&'static str, &'static [u8]>,
{
    let stored = match meta.get("schema_version")? {
        Some(guard) => u32::from_le_bytes(
            guard
                .value()
                .try_into()
                .map_err(|_| eyre::eyre!("store {}: malformed schema_version", path.display()))?,
        ),
        None => 1,
    };
    ensure!(
        stored == SCHEMA_VERSION,
        "store {} has schema v{stored}, this binary reads v{SCHEMA_VERSION} — re-sweep into a \
         fresh data-dir (or use a binary matching the store)",
        path.display(),
    );
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(bits: &[u32]) -> PatternRecord {
        let bitmap = BitSet::from_indices(bits.iter().copied());
        PatternRecord {
            bits: bitmap.count_ones(),
            bitmap,
            first_block: 1,
            last_block: 1,
            hit_count: 1,
            representative: 1,
            representative_elapsed_ms: 10,
        }
    }

    fn block(status: BlockStatus) -> BlockRecord {
        BlockRecord {
            hash: B256::ZERO,
            status,
            pattern_key: None,
            gas_used: 0,
            tx_count: 0,
            elapsed_ms: 0,
            error: None,
        }
    }

    /// The collision branch of the shared probing walk — the one path whose
    /// judge/merge divergence would silently corrupt merged stores. A
    /// different bitmap at the base key must step by exactly `PROBE_STEP`;
    /// the same bitmap parked one step out must be found as occupied.
    #[test]
    fn probe_collision_walks_probe_step() {
        let ids = [100u64, 200, 300];
        let base = pattern_base_key(&ids);
        let target = rec(&[0, 1, 2]);

        let mut patterns: HashMap<u64, PatternRecord> = [(base, rec(&[7]))].into();
        assert_eq!(
            resolve_pattern_slot(&patterns, &ids, &target.bitmap),
            (base.wrapping_add(PROBE_STEP), false),
            "occupied base slot with a different bitmap must probe one step"
        );

        patterns.insert(base.wrapping_add(PROBE_STEP), target.clone());
        assert_eq!(
            resolve_pattern_slot(&patterns, &ids, &target.bitmap),
            (base.wrapping_add(PROBE_STEP), true),
            "the same bitmap must be found at its probed slot"
        );

        // A second colliding stranger pushes the walk one more step.
        let other = rec(&[3, 4]);
        assert_eq!(
            resolve_pattern_slot(&patterns, &ids, &other.bitmap),
            (base.wrapping_add(PROBE_STEP).wrapping_add(PROBE_STEP), false),
        );
    }

    /// A merge killed between batches leaves a valid, correctly stamped redb
    /// file holding a prefix of the data. Nothing may open it: set-cover
    /// would otherwise publish a cover of that prefix.
    #[test]
    fn interrupted_bulk_write_is_refused_by_every_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        {
            let store = Store::open(&path, "id", None).unwrap();
            store.set_incomplete(true).unwrap(); // what write_bulk does first
        }
        let err = Store::open(&path, "id", None).err().expect("writer open must fail");
        assert!(err.to_string().contains("did not finish"), "open: {err}");
        let err = Store::open_readonly(&path).err().expect("read-only open must fail");
        assert!(err.to_string().contains("did not finish"), "open_readonly: {err}");
    }

    /// The marker must be gone once the last table is in.
    #[test]
    fn completed_bulk_write_opens_normally() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        let snapshot = StoreSnapshot {
            counters: HashMap::new(),
            patterns: [(1, rec(&[0]))].into(),
            blocks: [(5, block(BlockStatus::Ok))].into(),
        };
        Store::open(&path, "id", None).unwrap().write_bulk(&snapshot).unwrap();
        let (store, _) = Store::open_readonly(&path).expect("a finished merge must open");
        assert_eq!(store.load().unwrap().blocks.len(), 1);
    }

    #[test]
    fn open_rejects_binary_id_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        drop(Store::open(&path, "megaevm:aaa:fx1", None).unwrap());
        let err = Store::open(&path, "megaevm:bbb:fx2", None).err().expect("must fail");
        assert!(err.to_string().contains("belongs to binary_id"), "got: {err}");
    }

    #[test]
    fn open_rejects_universe_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        drop(Store::open(&path, "id", Some("regions+branch-arms/v1:/src")).unwrap());
        // Same stamp reopens fine; a different one is refused.
        drop(Store::open(&path, "id", Some("regions+branch-arms/v1:/src")).unwrap());
        let err = Store::open(&path, "id", Some("regions+branch-arms/v1:/other"))
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("counter universe"), "got: {err}");
    }

    /// A store filled before counters became evaluated items carries only the
    /// symbol filter. Its ids are physical counters: a current run must be
    /// refused rather than append evaluated-item ids next to them, yet the
    /// store has to stay readable and mergeable with its own kind.
    #[test]
    fn legacy_physical_counter_store_is_recognized_and_never_mixed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META).unwrap();
                meta.insert("binary_id", "id".as_bytes()).unwrap();
                meta.insert("schema_version", SCHEMA_VERSION.to_le_bytes().as_slice()).unwrap();
                meta.insert("symbol_filter", "mega_evm".as_bytes()).unwrap();
            }
            txn.commit().unwrap();
        }

        let err = Store::open(&path, "id", Some("regions+branch-arms/v1:/src"))
            .err()
            .expect("a current run must not write into a legacy store");
        assert!(err.to_string().contains("physical-counters/v0:mega_evm"), "got: {err}");

        let (store, _) = Store::open_readonly(&path).unwrap();
        assert_eq!(store.universe().unwrap().as_deref(), Some("physical-counters/v0:mega_evm"));
        drop(store);
        // Its own label reopens it (what `merge` stamps a legacy output with).
        drop(Store::open(&path, "id", Some("physical-counters/v0:mega_evm")).unwrap());
    }

    #[test]
    fn open_rejects_schema_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        drop(Store::open(&path, "id", None).unwrap());

        // Tamper: bump the stored schema version behind the API's back.
        {
            let db = Database::open(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META).unwrap();
                meta.insert("schema_version", (SCHEMA_VERSION + 1).to_le_bytes().as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let err = Store::open(&path, "id", None).err().expect("must fail");
        assert!(err.to_string().contains("schema"), "open: {err}");
        let err = Store::open_readonly(&path).err().expect("must fail");
        assert!(err.to_string().contains("schema"), "open_readonly: {err}");
    }

    /// `inspect` and `merge` read stores the caller does not own (root-owned
    /// on a server, a read-only copy): the read-only open must need no write
    /// access and leave the file byte-identical.
    #[cfg(unix)]
    #[test]
    fn open_readonly_needs_no_write_access_and_never_writes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        {
            let store = Store::open(&path, "megaevm:aaa:fx1", Some("universe/x")).unwrap();
            store.commit_block(7, &block(BlockStatus::Ok), &[], None).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        {
            let (store, binary_id) = Store::open_readonly(&path).expect("open a read-only file");
            assert_eq!(binary_id, "megaevm:aaa:fx1");
            assert_eq!(store.universe().unwrap().as_deref(), Some("universe/x"));
            assert_eq!(store.load().unwrap().blocks.len(), 1);
        }
        assert!(std::fs::read(&path).unwrap() == before, "read-only open modified the store");
    }

    /// A live writer holds redb's exclusive lock; the read-only open must be
    /// refused with an actionable message, not a bare lock error.
    #[test]
    fn open_readonly_refuses_store_held_by_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        let _writer = Store::open(&path, "id", None).unwrap();
        let err = Store::open_readonly(&path).err().expect("must fail while a writer holds it");
        assert!(err.to_string().contains("held open read-write"), "got: {err}");
    }

    /// A scattered pool's extremes span the whole history, so `load_for_blocks`
    /// must return exactly the named rows — never the range between them —
    /// while still loading counters and patterns in full.
    #[test]
    fn load_for_blocks_returns_only_named_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.redb"), "id", None).unwrap();
        let pattern = rec(&[0, 1]);
        for n in [5u64, 10, 15, 20] {
            store
                .commit_block(
                    n,
                    &block(BlockStatus::Ok),
                    &[(
                        n,
                        CounterInfo {
                            dense: n as u32,
                            location: "s".into(),
                            kind: "h".into(),
                            line: 0,
                        },
                    )],
                    Some((n, &pattern)),
                )
                .unwrap();
        }

        // 5 and 20 are the extremes; 10 and 15 lie between them and must not
        // come back. 99 was never scanned and is simply absent.
        let snap = store.load_for_blocks(&[5, 20, 99]).unwrap();
        let mut got: Vec<u64> = snap.blocks.keys().copied().collect();
        got.sort_unstable();
        assert_eq!(got, vec![5, 20], "only the named rows, not the span between them");
        assert_eq!(snap.counters.len(), 4, "counters always loaded in full");
        assert_eq!(snap.patterns.len(), 4, "patterns always loaded in full");
    }

    #[test]
    fn load_for_range_limits_blocks_but_not_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.redb"), "id", None).unwrap();
        let pattern = rec(&[0, 1]);
        for n in [5u64, 10, 15, 20] {
            store
                .commit_block(
                    n,
                    &block(BlockStatus::Ok),
                    &[(
                        n,
                        CounterInfo {
                            dense: n as u32,
                            location: "s".into(),
                            kind: "h".into(),
                            line: 0,
                        },
                    )],
                    Some((n, &pattern)),
                )
                .unwrap();
        }

        let snap = store.load_for_range(10..=15).unwrap();
        let mut in_range: Vec<u64> = snap.blocks.keys().copied().collect();
        in_range.sort_unstable();
        assert_eq!(in_range, vec![10, 15], "blocks limited to the range");
        assert_eq!(snap.counters.len(), 4, "counters always loaded in full");
        assert_eq!(snap.patterns.len(), 4, "patterns always loaded in full");
        assert_eq!(store.load().unwrap().blocks.len(), 4, "full load unaffected");
    }
}
