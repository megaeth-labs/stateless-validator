//! redb-backed persistence for the coverage-replayer dispatcher.
//!
//! All coverage data is namespaced by `binary_id` (a fingerprint of the
//! measured build, see [`current_binary_id`]) and by the universe stamp (what
//! a counter id means and which sources are in scope, see
//! [`crate::llvm::universe_stamp`]): counter ids and dense indices are only
//! meaningful for one build and one item definition. On mismatch the store
//! refuses to open.

use std::{collections::HashMap, path::Path};

use alloy_primitives::B256;
use eyre::{Result, ensure};
use redb::{
    Database, Durability, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition,
};
use serde::{Deserialize, Serialize};

use crate::bitset::BitSet;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const COUNTERS: TableDefinition<u64, &[u8]> = TableDefinition::new("counters");
const PATTERNS: TableDefinition<u64, &[u8]> = TableDefinition::new("patterns");
/// One row per block ever scanned — tens of millions in a full-history store,
/// against a working set (counters, patterns) bounded by the universe. So no
/// reader loads it whole unless it must (`merge`): [`Store::blocks`] streams a
/// range, [`Store::block_records`] looks rows up by number.
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
const SCHEMA_VERSION: u32 = 1;

/// Info about one coverage counter (id → dense index + provenance). The
/// provenance fields are written for humans and never read back by any logic.
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
    /// A pattern as one block exhibits it: that block is its whole range and
    /// its representative.
    pub fn first_seen(bitmap: BitSet, block: u64, elapsed_ms: u64) -> Self {
        Self {
            bits: bitmap.count_ones(),
            bitmap,
            first_block: block,
            last_block: block,
            hit_count: 1,
            representative: block,
            representative_elapsed_ms: elapsed_ms,
        }
    }

    /// Folds another record of the same bitmap into this one: hits add up,
    /// the block range widens, and the representative moves to the lighter
    /// block. The judge and `merge` both fold through here, so a merged store
    /// and a sequential scan agree on every statistic whatever order the
    /// blocks arrived in.
    pub fn absorb(&mut self, other: &Self) {
        self.hit_count += other.hit_count;
        self.first_block = self.first_block.min(other.first_block);
        self.last_block = self.last_block.max(other.last_block);
        if other.representative_elapsed_ms < self.representative_elapsed_ms {
            self.representative = other.representative;
            self.representative_elapsed_ms = other.representative_elapsed_ms;
        }
    }

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
/// merge output), [`ReadOnlyDatabase`] for pure readers (set-cover, inspect,
/// merge inputs) — the write methods do not exist on a read-only store.
pub struct Store<D = Database> {
    db: D,
}

impl Store {
    /// Opens (or creates) the store and enforces the coverage namespace: the
    /// `binary_id` and the universe stamp both have to match what the store
    /// was created with (a fresh store is stamped with them), so counter ids
    /// from two builds or two universes can never share it.
    pub fn open(path: &Path, binary_id: &str, universe: &str) -> Result<Self> {
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
                    check_binary_id(path, &existing, binary_id)?;
                    check_schema_version(&meta, path)?;
                    check_complete(&meta, path)?;
                }
                None => {
                    meta.insert("binary_id", binary_id.as_bytes())?;
                    meta.insert("schema_version", SCHEMA_VERSION.to_le_bytes().as_slice())?;
                }
            }

            match read_meta(&meta, UNIVERSE_KEY)? {
                Some(existing) => ensure!(
                    existing == universe,
                    "store {} holds the counter universe {existing:?}, this run produces \
                     {universe:?}. Counter ids from two universes must never share a store: \
                     use a fresh data-dir.",
                    path.display(),
                ),
                None => meta.insert(UNIVERSE_KEY, universe.as_bytes()).map(drop)?,
            }
        }
        txn.commit()?;

        Ok(Self { db })
    }

    /// Persists one judged block: its record, any new counters, and the
    /// created/updated pattern — atomically in one transaction.
    ///
    /// Unless `durable`, the commit skips the flush to disk: it becomes
    /// durable with the next durable commit or [`Self::flush`], and a crash
    /// before either rolls it back, whole — its block is then simply replayed
    /// again. One flush per batch instead of one per block.
    pub fn commit_block(
        &self,
        block: u64,
        record: &BlockRecord,
        new_counters: &[(u64, CounterInfo)],
        pattern: Option<(u64, &PatternRecord)>,
        durable: bool,
    ) -> Result<()> {
        let mut txn = self.db.begin_write()?;
        if !durable {
            txn.set_durability(Durability::None)?;
        }
        txn.open_table(BLOCKS)?.insert(block, encode(record)?.as_slice())?;
        if !new_counters.is_empty() {
            let mut t = txn.open_table(COUNTERS)?;
            for (id, info) in new_counters {
                t.insert(*id, encode(info)?.as_slice())?;
            }
        }
        if let Some((key, rec)) = pattern {
            txn.open_table(PATTERNS)?.insert(key, encode(rec)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Makes every commit so far durable.
    pub fn flush(&self) -> Result<()> {
        self.db.begin_write()?.commit()?;
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
                    t.insert(**key, encode(value)?.as_slice())?;
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
        let binary_id = read_meta(&meta, "binary_id")?.unwrap_or_else(|| "<unset>".into());
        drop(meta);
        drop(txn);
        Ok((store, binary_id))
    }

    /// [`Self::open_readonly`] for readers that interpret the store's dense
    /// indices (set-cover, merge): refuses a store another build filled.
    pub fn open_for_build(path: &Path, binary_id: &str) -> Result<Self> {
        let (store, stored) = Self::open_readonly(path)?;
        check_binary_id(path, &stored, binary_id)?;
        Ok(store)
    }
}

impl<D: ReadableDatabase> Store<D> {
    /// The universe stamp the store was created with.
    pub fn universe(&self) -> Result<String> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        read_meta(&meta, UNIVERSE_KEY)?.ok_or_else(|| {
            eyre::eyre!("store carries no universe stamp — not a store this tool wrote")
        })
    }

    /// Every counter the store has registered, by id.
    pub fn counters(&self) -> Result<HashMap<u64, CounterInfo>> {
        read_table(&self.db.begin_read()?, COUNTERS)
    }

    /// Every pattern, by key.
    pub fn patterns(&self) -> Result<HashMap<u64, PatternRecord>> {
        read_table(&self.db.begin_read()?, PATTERNS)
    }

    /// Visits the block records in `range`, in ascending block order, without
    /// holding them (see [`BLOCKS`]).
    pub fn blocks(
        &self,
        range: impl std::ops::RangeBounds<u64>,
        mut visit: impl FnMut(u64, BlockRecord),
    ) -> Result<()> {
        let txn = self.db.begin_read()?;
        for row in txn.open_table(BLOCKS)?.range(range)? {
            let (k, v) = row?;
            visit(k.value(), decode(v.value())?);
        }
        Ok(())
    }

    /// Point lookups into BLOCKS, for a scattered set of blocks whose range
    /// would span far more rows than it names; blocks never scanned are
    /// absent from the result.
    pub fn block_records(&self, blocks: &[u64]) -> Result<HashMap<u64, BlockRecord>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(BLOCKS)?;
        let mut found = HashMap::new();
        for n in blocks {
            if let Some(v) = t.get(n)? {
                found.insert(*n, decode(v.value())?);
            }
        }
        Ok(found)
    }

    /// The whole store — only `merge` needs the block table in memory.
    pub fn load(&self) -> Result<StoreSnapshot> {
        let mut blocks = HashMap::new();
        self.blocks(.., |n, record| {
            blocks.insert(n, record);
        })?;
        Ok(StoreSnapshot { counters: self.counters()?, patterns: self.patterns()?, blocks })
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

fn read_meta<T>(meta: &T, key: &str) -> Result<Option<String>>
where
    T: redb::ReadableTable<&'static str, &'static [u8]>,
{
    Ok(meta.get(key)?.map(|g| String::from_utf8_lossy(g.value()).into_owned()))
}

fn check_binary_id(path: &Path, stored: &str, binary_id: &str) -> Result<()> {
    ensure!(
        stored == binary_id,
        "store {} belongs to binary_id {stored}, current binary is {binary_id}. The counter \
         namespace is per-build: move the data-dir aside (or start a fresh one) and re-sweep.",
        path.display(),
    );
    Ok(())
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
    let mut map = HashMap::new();
    for row in txn.open_table(table)?.iter()? {
        let (k, v) = row?;
        map.insert(k.value(), decode(v.value())?);
    }
    Ok(map)
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, BINCODE_CONFIG)
        .map_err(|e| eyre::eyre!("encode {}: {e}", std::any::type_name::<T>()))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, _) = bincode::serde::decode_from_slice(bytes, BINCODE_CONFIG)
        .map_err(|e| eyre::eyre!("decode {}: {e}", std::any::type_name::<T>()))?;
    Ok(value)
}

/// In-memory image of a whole store — what `merge` reads and writes.
#[derive(Clone)]
pub struct StoreSnapshot {
    pub counters: HashMap<u64, CounterInfo>,
    pub patterns: HashMap<u64, PatternRecord>,
    pub blocks: HashMap<u64, BlockRecord>,
}

/// Linear-probe step for pattern-key collisions (golden ratio).
const PROBE_STEP: u64 = 0x9E37_79B9_7F4A_7C15;

/// Base pattern key: FxHash64 of the pattern's counter ids in ascending
/// order. Collisions between differing bitmaps are handled by
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
/// the slot already holds this exact bitmap (the caller folds into it with
/// [`PatternRecord::absorb`]); otherwise the slot is vacant and the caller
/// inserts. The judge and `merge` both key through here — they must key
/// identically, or a merged store diverges from a sequential run.
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

/// Coverage namespace key: a fingerprint of the instrumented build being
/// measured, NOT a whole-exe hash. Stays stable across dispatcher edits (so
/// the resident mode can continue a store `backfill` started) and changes
/// exactly when the measured sources or the toolchain do: mega-evm's
/// revision, the locked versions of the measured dependencies, and
/// `rustc -vV`. Captured at compile time by build.rs.
///
/// The dependency versions belong here because they are measured code, not
/// merely linked code: a revm bump with mega-evm unchanged rewrites part of
/// the coverage map. The workspace crates are left out — editing the tool
/// must not orphan a multi-week store — which is why `report` re-derives the
/// covered items rather than trust this id alone.
pub fn current_binary_id() -> String {
    use std::hash::Hasher;
    let mega_evm = env!("COVERAGE_MEGA_EVM_REV");
    let rustc = env!("COVERAGE_RUSTC_VERSION");
    let measured = env!("COVERAGE_MEASURED_CRATES");
    let mut h = rustc_hash::FxHasher::default();
    h.write(mega_evm.as_bytes());
    h.write_u8(0xff);
    h.write(rustc.as_bytes());
    h.write_u8(0xff);
    h.write(measured.as_bytes());
    format!("megaevm:{}:fx{:016x}", &mega_evm[..mega_evm.len().min(12)], h.finish())
}

/// Sorted-sample summary for per-block worker times: `(avg, p50, p95, max)`.
/// Returns `None` for an empty sample. Shared by the backfill summary and
/// `inspect`.
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
        PatternRecord::first_seen(BitSet::from_indices(bits.iter().copied()), 1, 10)
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
            let store = Store::open(&path, "id", "u").unwrap();
            store.set_incomplete(true).unwrap(); // what write_bulk does first
        }
        let err = Store::open(&path, "id", "u").err().expect("writer open must fail");
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
        Store::open(&path, "id", "u").unwrap().write_bulk(&snapshot).unwrap();
        let (store, _) = Store::open_readonly(&path).expect("a finished merge must open");
        assert_eq!(store.load().unwrap().blocks.len(), 1);
    }

    #[test]
    fn open_rejects_binary_id_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        drop(Store::open(&path, "megaevm:aaa:fx1", "u").unwrap());
        let err = Store::open(&path, "megaevm:bbb:fx2", "u").err().expect("must fail");
        assert!(err.to_string().contains("belongs to binary_id"), "got: {err}");
        // Readers that interpret dense indices refuse it the same way.
        let err = Store::open_for_build(&path, "megaevm:bbb:fx2").err().expect("must fail");
        assert!(err.to_string().contains("belongs to binary_id"), "got: {err}");
    }

    #[test]
    fn open_rejects_universe_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        drop(Store::open(&path, "id", "regions+branch-arms/v1:/src").unwrap());
        // Same stamp reopens fine; a different one is refused.
        drop(Store::open(&path, "id", "regions+branch-arms/v1:/src").unwrap());
        let err =
            Store::open(&path, "id", "regions+branch-arms/v1:/other").err().expect("must fail");
        assert!(err.to_string().contains("counter universe"), "got: {err}");
    }

    #[test]
    fn open_rejects_schema_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        drop(Store::open(&path, "id", "u").unwrap());

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

        let err = Store::open(&path, "id", "u").err().expect("must fail");
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
            let store = Store::open(&path, "megaevm:aaa:fx1", "universe/x").unwrap();
            store.commit_block(7, &block(BlockStatus::Ok), &[], None, true).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        {
            let (store, binary_id) = Store::open_readonly(&path).expect("open a read-only file");
            assert_eq!(binary_id, "megaevm:aaa:fx1");
            assert_eq!(store.universe().unwrap(), "universe/x");
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
        let _writer = Store::open(&path, "id", "u").unwrap();
        let err = Store::open_readonly(&path).err().expect("must fail while a writer holds it");
        assert!(err.to_string().contains("held open read-write"), "got: {err}");
    }

    /// A scattered pool's extremes span the whole history, so the point
    /// lookups must return exactly the named rows — never the range between
    /// them — while a range read returns exactly the range.
    #[test]
    fn block_reads_return_exactly_what_was_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.redb"), "id", "u").unwrap();
        for n in [5u64, 10, 15, 20] {
            store.commit_block(n, &block(BlockStatus::Ok), &[], None, true).unwrap();
        }

        // 5 and 20 are the extremes; 10 and 15 lie between them and must not
        // come back. 99 was never scanned and is simply absent.
        let mut named: Vec<u64> = store.block_records(&[5, 20, 99]).unwrap().into_keys().collect();
        named.sort_unstable();
        assert_eq!(named, vec![5, 20], "only the named rows, not the span between them");

        let mut in_range = Vec::new();
        store.blocks(10..=15, |n, _| in_range.push(n)).unwrap();
        assert_eq!(in_range, vec![10, 15], "blocks limited to the range, in order");
        assert_eq!(store.load().unwrap().blocks.len(), 4, "a full load is unaffected");
    }
}
