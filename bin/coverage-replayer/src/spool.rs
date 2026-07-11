//! On-disk spool entries: everything a worker needs to replay one block.
//!
//! Lifecycle: written by the fetcher, consumed by a worker, deleted after
//! judgment — for every block, including new-pattern representatives. Nothing
//! block-sized is retained: the RPC serves blocks and witnesses for the full
//! history, so resweeps and PR payload assembly re-fetch representatives by
//! block number (recorded in the store). The only per-pattern artifact kept
//! is a small sparse profdata for `report`.

use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use stateless_core::LightWitness;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
/// zstd level for spool entries. The witness payload inside is already
/// compressed, and spool files live for minutes — favor speed.
const SPOOL_ZSTD_LEVEL: i32 = 1;

#[derive(Serialize, Deserialize)]
pub struct SpoolEntry {
    /// The RPC block re-serialized as JSON (`Block<op_alloy_rpc_types::Transaction>`),
    /// the same shape `test_data/mainnet/blocks/*.json` uses.
    pub block_json: Vec<u8>,
    /// Execution witness (kvs + levels only, fast to decode).
    pub light_witness: LightWitness,
    /// Contract code hashes this block needs (resolved via the codes dir).
    pub code_hashes: Vec<B256>,
}

impl SpoolEntry {
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let raw = bincode::serde::encode_to_vec(self, BINCODE_CONFIG)
            .map_err(|e| eyre::eyre!("encode spool entry: {e}"))?;
        // Frame checksum (xxhash, ~free): most of the entry is opaque
        // high-entropy bytes (block_json, witness kvs) where a media-level
        // bit flip would decode "successfully" into wrong data — with the
        // checksum, ANY byte corruption fails `read_from`, which the fetcher
        // treats as delete-and-refetch. Old checksum-less spool files still
        // decode (the flag is per-frame).
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), SPOOL_ZSTD_LEVEL)?;
        encoder.include_checksum(true)?;
        std::io::Write::write_all(&mut encoder, &raw)?;
        let compressed = encoder.finish()?;
        write_atomic(path, &compressed)
    }

    pub fn read_from(path: &Path) -> Result<Self> {
        let compressed =
            fs::read(path).wrap_err_with(|| format!("read spool entry {}", path.display()))?;
        let raw = zstd::decode_all(&compressed[..])?;
        let (entry, _) = bincode::serde::decode_from_slice(&raw, BINCODE_CONFIG)
            .map_err(|e| eyre::eyre!("decode spool entry {}: {e}", path.display()))?;
        Ok(entry)
    }
}

/// Directory layout inside `--data-dir`.
#[derive(Debug, Clone)]
pub struct DataDir {
    pub root: PathBuf,
}

impl DataDir {
    /// Pure path arithmetic — creates nothing. Writers call
    /// [`Self::ensure_layout`]; read-only consumers (inspect, merge's shard
    /// inputs) must not scaffold empty trees in a mistyped or foreign path.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Creates the standard subdirectory layout (idempotent).
    pub fn ensure_layout(&self) -> Result<()> {
        for d in [self.spool(), self.codes(), self.tmp(), self.archive_profiles()] {
            fs::create_dir_all(&d)?;
        }
        Ok(())
    }

    pub fn spool(&self) -> PathBuf {
        self.root.join("spool")
    }
    pub fn codes(&self) -> PathBuf {
        self.root.join("codes")
    }
    pub fn tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }
    pub fn archive_profiles(&self) -> PathBuf {
        self.root.join("archive").join("profiles")
    }
    pub fn store_path(&self) -> PathBuf {
        self.root.join("store.redb")
    }
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    pub fn spool_entry(&self, block: u64) -> PathBuf {
        self.spool().join(format!("{block}.bin"))
    }
    pub fn code_file(&self, hash: &B256) -> PathBuf {
        self.codes().join(format!("{hash:x}.bin"))
    }
    /// Per-pattern sparse profdata (zstd) — only executed functions survive
    /// the `llvm-profdata merge -sparse` conversion, so this is small; raw
    /// profraws carry the whole binary's counter array plus an incompressible
    /// name table (~2 MB even zstd'd) and are never archived.
    ///
    /// Keyed by pattern (not block) so re-homing a pattern's representative to
    /// a lighter block never moves or orphans its profile — the profile is the
    /// same regardless of which block produced it (identical bitmap).
    pub fn archived_profile(&self, pattern_key: u64) -> PathBuf {
        self.archive_profiles().join(format!("{pattern_key:016x}.profdata.zst"))
    }
}

/// Write via unique tmp file + rename so readers never observe partial files,
/// fsynced so the result survives power loss, not just process crashes.
///
/// The fsync-before-rename is load-bearing for the judge's archive-before-
/// commit invariant: redb commits are fsynced, so if archived profiles were
/// only in the page cache a power cut could persist the pattern while losing
/// its profile — an orphan no re-run can repair (the block is already Ok).
/// The same ordering keeps spool entries from surviving truncated.
///
/// The tmp name embeds pid + a counter: concurrent writers of the SAME target
/// (e.g. two fetch tasks resolving one shared contract hash) must not collide
/// on the tmp path — last rename wins and both writers succeed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{
        io::Write as _,
        sync::atomic::{AtomicU64, Ordering},
    };
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "{}.{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    );
    let tmp = path.with_file_name(unique);
    let result = (|| -> Result<()> {
        let mut f = fs::File::create(&tmp).wrap_err_with(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes).wrap_err_with(|| format!("write {}", tmp.display()))?;
        f.sync_all().wrap_err_with(|| format!("fsync {}", tmp.display()))?;
        drop(f);
        fs::rename(&tmp, path).wrap_err_with(|| format!("rename to {}", path.display()))?;
        // Make the rename itself durable. Directory fsync is best-effort:
        // supported on Linux, may be a no-op/error elsewhere (macOS).
        if let Some(parent) = path.parent() &&
            let Ok(dir) = fs::File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        // ENOSPC/rename failure: don't leave the tmp file behind.
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Removes stale `*.tmp` files left by writers killed mid-`write_atomic`
/// (their unique names are never reused, so they accumulate forever
/// otherwise). Non-recursive.
///
/// `min_age` guards live writers: a healthy `write_atomic` holds its tmp for
/// milliseconds, so anything older than the threshold is orphaned. Callers
/// must still only sweep after acquiring the store lock (one backfill per
/// data-dir) — the age filter is the second line of defense for processes
/// that do NOT hold the lock (e.g. a concurrent `report` inflating profiles
/// into the shared tmp dir).
pub fn sweep_stale_tmp(dir: &Path, min_age: std::time::Duration) -> usize {
    let Ok(entries) = fs::read_dir(dir) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().ends_with(".tmp") {
            continue;
        }
        let old_enough = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= min_age);
        if old_enough && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Loads contract bytecodes for the given hashes from the codes dir.
/// Returns the same `HashMap` flavor `WitnessDatabase.contracts` expects.
pub fn load_contracts(
    codes_dir: &Path,
    hashes: &[B256],
) -> Result<alloy_primitives::map::HashMap<B256, revm::state::Bytecode>> {
    let mut map =
        alloy_primitives::map::HashMap::with_capacity_and_hasher(hashes.len(), Default::default());
    for hash in hashes {
        let path = codes_dir.join(format!("{hash:x}.bin"));
        let bytes = fs::read(&path)
            .wrap_err_with(|| format!("missing contract code {}", path.display()))?;
        map.insert(*hash, revm::state::Bytecode::new_raw(bytes.into()));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Any single corrupted byte in a spool file must fail `read_from` (the
    /// zstd frame checksum) — most of the entry is opaque high-entropy bytes
    /// where corruption would otherwise decode into silently wrong data, and
    /// the fetcher's delete-and-refetch self-heal keys off this error.
    #[test]
    fn spool_checksum_rejects_any_byte_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("1.bin");
        let entry = SpoolEntry {
            block_json: vec![0xA5; 4096],
            light_witness: LightWitness { kvs: Default::default(), levels: Default::default() },
            code_hashes: vec![B256::repeat_byte(3)],
        };
        entry.write_to(&path).unwrap();
        assert!(SpoolEntry::read_from(&path).is_ok());

        let clean = fs::read(&path).unwrap();
        // Flip one bit in the middle of the payload region.
        for at in [clean.len() / 2, clean.len() - 8] {
            let mut damaged = clean.clone();
            damaged[at] ^= 0x01;
            fs::write(&path, &damaged).unwrap();
            assert!(SpoolEntry::read_from(&path).is_err(), "byte {at} corruption must not decode");
        }
    }

    #[test]
    fn write_atomic_round_trips_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.bin");
        write_atomic(&target, b"payload").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"payload");
        assert_eq!(sweep_stale_tmp(dir.path(), Duration::ZERO), 0, "no tmp litter after success");
    }

    #[test]
    fn write_atomic_failure_removes_tmp() {
        let dir = tempfile::tempdir().unwrap();
        // A directory at the target path makes the final rename fail.
        let target = dir.path().join("occupied");
        fs::create_dir(&target).unwrap();
        assert!(write_atomic(&target, b"x").is_err());
        assert_eq!(
            sweep_stale_tmp(dir.path(), Duration::ZERO),
            0,
            "failed write must clean its tmp file"
        );
    }

    #[test]
    fn sweep_removes_only_old_tmp_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("stale.bin.123.0.tmp"), b"junk").unwrap();
        fs::write(dir.path().join("keep.bin"), b"data").unwrap();
        // A generous min_age spares the freshly-written (live-looking) tmp…
        assert_eq!(sweep_stale_tmp(dir.path(), Duration::from_secs(3600)), 0);
        assert!(dir.path().join("stale.bin.123.0.tmp").exists());
        // …zero age reaps it, leaving non-tmp files alone.
        assert_eq!(sweep_stale_tmp(dir.path(), Duration::ZERO), 1);
        assert!(dir.path().join("keep.bin").exists());
        assert!(!dir.path().join("stale.bin.123.0.tmp").exists());
    }
}
