//! redb-backed pattern store, namespaced by `binary_id` ([`BINARY_ID`]) and the
//! universe stamp ([`crate::llvm::universe_stamp`]): counter ids and dense indices mean
//! something only within one namespace, so a store from another one refuses to open.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use alloy_primitives::B256;
use eyre::{Result, ensure};
use redb::{
    Database, Durability, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition,
};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::bitset::BitSet;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// Counter id → dense bit index. Indices are handed out in order of first sight and never
/// change, so a stored bitmap stays valid as the universe grows.
const COUNTERS: TableDefinition<u64, u32> = TableDefinition::new("counters");
const PATTERNS: TableDefinition<u64, &[u8]> = TableDefinition::new("patterns");
/// One row per block ever scanned; it grows with history, so no reader loads it whole:
/// [`Store::blocks`] streams a range, [`Store::block_records`] looks rows up by number.
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
const SCHEMA_VERSION: u32 = 2;
/// The oldest schema a read-only opener accepts. v2 changed only COUNTERS, which no read-only
/// path reads (the judge is its one reader), so `inspect` still reads v1 stores, the ones whose
/// pools carry a scan across builds.
const OLDEST_READABLE_SCHEMA: u32 = 1;

/// One distinct coverage bitmap and its representative block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRecord {
    pub bitmap: BitSet,
    pub bits: u64,
    pub first_block: u64,
    pub last_block: u64,
    pub hit_count: u64,
    /// The lightest (min replay time, `WorkerResponse::replay_ms`) block seen with this pattern:
    /// the best fixture candidate.
    pub representative: u64,
    pub representative_elapsed_ms: u64,
}

impl PatternRecord {
    /// A pattern as one block exhibits it: that block is its range and representative.
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

    /// Folds in another record of the same bitmap, whatever order the blocks arrived in.
    pub fn absorb(&mut self, other: &Self) {
        self.hit_count += other.hit_count;
        self.first_block = self.first_block.min(other.first_block);
        self.last_block = self.last_block.max(other.last_block);
        if other.representative_elapsed_ms < self.representative_elapsed_ms {
            self.representative = other.representative;
            self.representative_elapsed_ms = other.representative_elapsed_ms;
        }
    }

    /// Strict domination: `self` covers all of `other` and more (`bits >`, never `>=`: equal-bits
    /// patterns must never dominate each other). Shared by the judge's archive skip and set-cover.
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

/// The handle type selects the API: [`Database`] for the writer (backfill),
/// [`ReadOnlyDatabase`] for readers (set-cover, inspect), which lack the write methods.
pub struct Store<D = Database> {
    db: D,
    commits: AtomicU64,
}

/// Block commits between two flushes to disk (see [`Store::commit_block`]).
const COMMITS_PER_FLUSH: u64 = 64;

impl Store {
    /// Opens (or creates and stamps) the store, refusing one stamped with another `binary_id`
    /// or universe: counter ids from two builds or two universes can never share it.
    pub fn open(path: &Path, binary_id: &str, universe: &str) -> Result<Self> {
        let db = Database::create(path)?;

        let txn = db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            match read_meta(&meta, BINARY_ID_KEY)? {
                Some(existing) => {
                    check_binary_id(path, &existing, binary_id)?;
                    check_schema_version(&meta, path, SCHEMA_VERSION)?;
                }
                None => {
                    meta.insert(BINARY_ID_KEY, binary_id.as_bytes())?;
                    meta.insert(SCHEMA_VERSION_KEY, SCHEMA_VERSION.to_le_bytes().as_slice())?;
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
            // Only after the stamps: another schema's tables need not open as this one's types.
            txn.open_table(COUNTERS)?;
            txn.open_table(PATTERNS)?;
            txn.open_table(BLOCKS)?;
        }
        txn.commit()?;

        Ok(Self { db, commits: AtomicU64::new(0) })
    }

    /// Persists one judged block (record, new counters, pattern) in one atomic transaction.
    ///
    /// Only every [`COMMITS_PER_FLUSH`]th commit is flushed to disk; the ones in between become
    /// durable with it or with [`Self::flush`], which a writer calls when done. A crash rolls
    /// them back whole, and their blocks are simply replayed again.
    pub fn commit_block(
        &self,
        block: u64,
        record: &BlockRecord,
        new_counters: &[(u64, u32)],
        pattern: Option<(u64, &PatternRecord)>,
    ) -> Result<()> {
        let mut txn = self.db.begin_write()?;
        let commit = self.commits.fetch_add(1, Ordering::Relaxed) + 1;
        if !commit.is_multiple_of(COMMITS_PER_FLUSH) {
            txn.set_durability(Durability::None)?;
        }
        txn.open_table(BLOCKS)?.insert(block, encode(record)?.as_slice())?;
        if !new_counters.is_empty() {
            let mut t = txn.open_table(COUNTERS)?;
            for &(id, dense) in new_counters {
                t.insert(id, dense)?;
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
}

impl Store<ReadOnlyDatabase> {
    /// Opens an existing store WITHOUT the binary-id check, returning it and its binary_id.
    /// Needs no write access and never writes; in exchange, a store held open by a writer or
    /// left unclean by a crash is refused, not waited on or repaired.
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
        let store = Self { db, commits: AtomicU64::new(0) };
        let txn = store.db.begin_read()?;
        let meta = txn.open_table(META)?;
        check_schema_version(&meta, path, OLDEST_READABLE_SCHEMA)?;
        let binary_id = read_meta(&meta, BINARY_ID_KEY)?.unwrap_or_else(|| "<unset>".into());
        drop(meta);
        drop(txn);
        Ok((store, binary_id))
    }

    /// [`Self::open_readonly`] for readers of dense indices: refuses a store another build filled.
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

    /// Every counter the store has registered: id → dense index.
    pub fn counters(&self) -> Result<FxHashMap<u64, u32>> {
        let txn = self.db.begin_read()?;
        txn.open_table(COUNTERS)?
            .iter()?
            .map(|row| {
                let (id, dense) = row?;
                Ok((id.value(), dense.value()))
            })
            .collect()
    }

    /// Every pattern, by key.
    pub fn patterns(&self) -> Result<HashMap<u64, PatternRecord>> {
        let txn = self.db.begin_read()?;
        txn.open_table(PATTERNS)?
            .iter()?
            .map(|row| {
                let (key, record) = row?;
                Ok((key.value(), decode(record.value())?))
            })
            .collect()
    }

    /// Visits the block records in `range` in ascending order, without holding them.
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

    /// Point lookups for scattered blocks; blocks never scanned are absent from the result.
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
}

const BINARY_ID_KEY: &str = "binary_id";
const SCHEMA_VERSION_KEY: &str = "schema_version";
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

/// Rejects a record encoding outside `oldest..=SCHEMA_VERSION` with a clean message, not opaque
/// bincode decode errors later. A store without a schema stamp is schema 1.
fn check_schema_version<T>(meta: &T, path: &Path, oldest: u32) -> Result<()>
where
    T: redb::ReadableTable<&'static str, &'static [u8]>,
{
    let stored = match meta.get(SCHEMA_VERSION_KEY)? {
        Some(guard) => u32::from_le_bytes(
            guard
                .value()
                .try_into()
                .map_err(|_| eyre::eyre!("store {}: malformed schema_version", path.display()))?,
        ),
        None => 1,
    };
    let accepted = if oldest == SCHEMA_VERSION {
        format!("v{SCHEMA_VERSION}")
    } else {
        format!("v{oldest} to v{SCHEMA_VERSION}")
    };
    ensure!(
        (oldest..=SCHEMA_VERSION).contains(&stored),
        "store {} has schema v{stored}, this binary reads {accepted} here — re-sweep into a \
         fresh data-dir (or use a binary matching the store)",
        path.display(),
    );
    Ok(())
}

/// bincode (`standard`) encoding of the store's rows, also used for spool entries.
pub(crate) fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, BINCODE_CONFIG)
        .map_err(|e| eyre::eyre!("encode {}: {e}", std::any::type_name::<T>()))
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, _) = bincode::serde::decode_from_slice(bytes, BINCODE_CONFIG)
        .map_err(|e| eyre::eyre!("decode {}: {e}", std::any::type_name::<T>()))?;
    Ok(value)
}

/// Linear-probe step for pattern-key collisions (golden ratio).
const PROBE_STEP: u64 = 0x9E37_79B9_7F4A_7C15;

/// Base pattern key: FxHash64 of the ascending counter ids ([`resolve_pattern_slot`] probes).
pub fn pattern_base_key(sorted_ids: &[u64]) -> u64 {
    use std::hash::Hasher;
    debug_assert!(sorted_ids.is_sorted());
    let mut h = rustc_hash::FxHasher::default();
    for id in sorted_ids {
        h.write_u64(*id);
    }
    h.finish()
}

/// Walks the probe chain from [`pattern_base_key`]: returns `(slot_key, occupied)`, where
/// `occupied` means the slot already holds this exact bitmap, and otherwise it is vacant.
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

/// Coverage namespace key: a fingerprint of the measured build, NOT a whole-exe hash, so edits
/// to this tool's code keep a store resumable. It changes whenever what a profile or counter
/// means could: mega-evm's revision, the measured crates and versions, `rustc -vV`, and the
/// Cargo.lock entries of everything this binary compiles — a profile names each measured
/// generic instance by a symbol carrying the cargo metadata of the instantiating crate, which
/// moves with any dependency or version change in its graph, so other dependencies cannot read
/// the archived profiles. Lock entries outside that graph (another workspace member's
/// dependencies) are left out, so their bumps keep a store usable. Computed by build.rs; what it
/// cannot see (features, compiler flags) `report` catches by re-deriving the covered items.
pub const BINARY_ID: &str = env!("COVERAGE_BINARY_ID");

/// Per-block worker times as a value → count histogram: exact percentiles in memory bounded by
/// the distinct millisecond values seen, not by the number of blocks.
#[derive(Debug, Default)]
pub struct ElapsedStats {
    counts: BTreeMap<u64, u64>,
    blocks: u64,
    total_ms: u64,
}

impl ElapsedStats {
    pub fn record(&mut self, elapsed_ms: u64) {
        *self.counts.entry(elapsed_ms).or_default() += 1;
        self.blocks += 1;
        self.total_ms += elapsed_ms;
    }

    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    /// `(avg, p50, p95, max)`; `None` if nothing was recorded.
    pub fn summary(&self) -> Option<(f64, u64, u64, u64)> {
        let max = *self.counts.keys().next_back()?;
        // The value at 0-based `rank` among the sorted samples.
        let at = |rank: u64| {
            let mut through = 0;
            self.counts.iter().find_map(|(&ms, &n)| {
                through += n;
                (through > rank).then_some(ms)
            })
        };
        let n = self.blocks;
        Some((self.total_ms as f64 / n as f64, at(n / 2)?, at((n * 95 / 100).min(n - 1))?, max))
    }
}

/// Record builders the modules' tests share.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use super::*;
    use crate::spool::DataDir;

    /// A fresh data dir with its store; the guard keeps the directory alive.
    pub(crate) fn temp_store() -> (tempfile::TempDir, Arc<DataDir>, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(DataDir::new(tmp.path()));
        dirs.ensure_layout().unwrap();
        let store = Store::open(&dirs.store_path(), "test-id", "f").unwrap();
        (tmp, dirs, store)
    }

    /// A pattern over `bits` (dense indices), first seen at block `rep`.
    pub(crate) fn pattern(bits: &[u32], rep: u64) -> PatternRecord {
        PatternRecord::first_seen(BitSet::from_indices(bits.iter().copied()), rep, 100)
    }

    pub(crate) fn block(status: BlockStatus, pattern_key: Option<u64>) -> BlockRecord {
        BlockRecord {
            hash: B256::ZERO,
            status,
            pattern_key,
            gas_used: 0,
            tx_count: 0,
            elapsed_ms: 0,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::pattern, *};

    fn rec(bits: &[u32]) -> PatternRecord {
        pattern(bits, 1)
    }

    fn block(status: BlockStatus) -> BlockRecord {
        test_support::block(status, None)
    }

    /// Probing steps by exactly `PROBE_STEP` past another bitmap, and finds its own as occupied.
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

        let other = rec(&[3, 4]);
        assert_eq!(
            resolve_pattern_slot(&patterns, &ids, &other.bitmap),
            (base.wrapping_add(PROBE_STEP).wrapping_add(PROBE_STEP), false),
        );
    }

    #[test]
    fn open_rejects_binary_id_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        drop(Store::open(&path, "megaevm:aaa:fx1", "u").unwrap());
        let err = Store::open(&path, "megaevm:bbb:fx2", "u").err().expect("must fail");
        assert!(err.to_string().contains("belongs to binary_id"), "got: {err}");
        let err = Store::open_for_build(&path, "megaevm:bbb:fx2").err().expect("must fail");
        assert!(err.to_string().contains("belongs to binary_id"), "got: {err}");
    }

    #[test]
    fn open_rejects_universe_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        drop(Store::open(&path, "id", "regions+branch-arms/v1:/src").unwrap());
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

    /// A v1 store differs only in COUNTERS: `inspect` reads its patterns and blocks, while the
    /// writer, the one COUNTERS reader, still refuses it.
    #[test]
    fn a_v1_store_opens_read_only_but_not_for_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        {
            let store = Store::open(&path, "id", "u").unwrap();
            store.commit_block(7, &block(BlockStatus::Ok), &[], Some((1, &rec(&[0, 3])))).unwrap();
            store.flush().unwrap();
        }
        {
            let db = Database::open(&path).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(META)
                .unwrap()
                .insert("schema_version", 1u32.to_le_bytes().as_slice())
                .unwrap();
            txn.commit().unwrap();
        }

        let (store, _) = Store::open_readonly(&path).expect("inspect reads a v1 store");
        assert_eq!(store.patterns().unwrap().len(), 1);
        assert_eq!(store.block_records(&[7]).unwrap().len(), 1);
        drop(store);
        let err = Store::open(&path, "id", "u").err().expect("the writer must refuse v1");
        assert!(err.to_string().contains("schema v1"), "{err}");
    }

    /// `inspect` reads stores the caller does not own: no write access, file left byte-identical.
    #[cfg(unix)]
    #[test]
    fn open_readonly_needs_no_write_access_and_never_writes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        {
            let store = Store::open(&path, "megaevm:aaa:fx1", "universe/x").unwrap();
            store.commit_block(7, &block(BlockStatus::Ok), &[], None).unwrap();
            store.flush().unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        {
            let (store, binary_id) = Store::open_readonly(&path).expect("open a read-only file");
            assert_eq!(binary_id, "megaevm:aaa:fx1");
            assert_eq!(store.universe().unwrap(), "universe/x");
            assert_eq!(store.block_records(&[7]).unwrap().len(), 1);
        }
        assert!(std::fs::read(&path).unwrap() == before, "read-only open modified the store");
    }

    /// A live writer's lock refuses the read-only open with an actionable message.
    #[test]
    fn open_readonly_refuses_store_held_by_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        let _writer = Store::open(&path, "id", "u").unwrap();
        let err = Store::open_readonly(&path).err().expect("must fail while a writer holds it");
        assert!(err.to_string().contains("held open read-write"), "got: {err}");
    }

    /// The histogram's percentiles are the sorted samples' own, whatever order they arrive in.
    #[test]
    fn elapsed_stats_are_exact_percentiles() {
        let mut stats = ElapsedStats::default();
        assert_eq!(stats.summary(), None);
        // 1..=100 twice, out of order: p50 is rank 100 of the 200 sorted samples, p95 rank 190.
        for ms in (1..=100).rev().chain(1..=100) {
            stats.record(ms);
        }
        assert_eq!(stats.blocks(), 200);
        assert_eq!(stats.summary(), Some((50.5, 51, 96, 100)));
    }

    /// Point lookups return only the named rows, never the span between; a range, just the range.
    #[test]
    fn block_reads_return_exactly_what_was_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.redb"), "id", "u").unwrap();
        for n in [5u64, 10, 15, 20] {
            store.commit_block(n, &block(BlockStatus::Ok), &[], None).unwrap();
        }

        // 10 and 15 lie between the named extremes; 99 was never scanned.
        let mut named: Vec<u64> = store.block_records(&[5, 20, 99]).unwrap().into_keys().collect();
        named.sort_unstable();
        assert_eq!(named, vec![5, 20], "only the named rows, not the span between them");

        let mut in_range = Vec::new();
        store.blocks(10..=15, |n, _| in_range.push(n)).unwrap();
        assert_eq!(in_range, vec![10, 15], "blocks limited to the range, in order");
    }
}
