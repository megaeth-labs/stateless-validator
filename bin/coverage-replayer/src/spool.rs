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
use alloy_rpc_types_eth::Block;
use eyre::{Context, Result, ensure};
use op_alloy_rpc_types::Transaction as OpTransaction;
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
    #[serde(with = "as_bytes")]
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
        write_scratch(path, &compressed)
    }

    pub fn read_from(path: &Path) -> Result<Self> {
        let compressed =
            fs::read(path).wrap_err_with(|| format!("read spool entry {}", path.display()))?;
        let raw = zstd::decode_all(&compressed[..])?;
        let (entry, _) = bincode::serde::decode_from_slice(&raw, BINCODE_CONFIG)
            .map_err(|e| eyre::eyre!("decode spool entry {}: {e}", path.display()))?;
        Ok(entry)
    }

    /// Reads the entry for `block` and parses its block, checking it is the
    /// one asked for: everything the worker needs before it can replay. A
    /// resumed run opens leftover entries through here too, so an entry the
    /// worker could not use is refetched rather than failing the run.
    pub fn open(path: &Path, block: u64) -> Result<Spooled> {
        let entry = Self::read_from(path)?;
        let parsed: Block<OpTransaction> = serde_json::from_slice(&entry.block_json)
            .wrap_err_with(|| format!("spool entry {} holds no parsable block", path.display()))?;
        ensure!(
            parsed.header.inner.number == block,
            "spool entry {} holds block {}, expected {block}",
            path.display(),
            parsed.header.inner.number,
        );
        Ok(Spooled {
            block: parsed,
            light_witness: entry.light_witness,
            code_hashes: entry.code_hashes,
        })
    }
}

/// `Vec<u8>` through serde's byte-array hooks. bincode writes the same bytes
/// either way — a length, then the bytes — but through the sequence hooks it
/// does so one element at a time, for every byte of a multi-megabyte block.
mod as_bytes {
    use serde::{
        Deserializer, Serializer,
        de::{Error, Visitor},
    };

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct Bytes;
        impl Visitor<'_> for Bytes {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a byte array")
            }
            fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                Ok(bytes.to_vec())
            }
            fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(bytes)
            }
        }
        deserializer.deserialize_byte_buf(Bytes)
    }
}

/// A spool entry opened for replay (see [`SpoolEntry::open`]).
pub struct Spooled {
    pub block: Block<OpTransaction>,
    pub light_witness: LightWitness,
    pub code_hashes: Vec<B256>,
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
    /// Where a worker writes a block's raw profile.
    pub fn block_profraw(&self, block: u64) -> PathBuf {
        self.tmp().join(format!("block_{block}.profraw"))
    }
    /// The sparse profdata a block's raw profile becomes — what the judge
    /// archives when the block's pattern is new.
    pub fn block_profdata(&self, block: u64) -> PathBuf {
        self.tmp().join(format!("block_{block}.profdata"))
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

    /// Archives a new pattern's sparse profdata, zstd'd and durable — the
    /// judge commits the pattern only once this has returned (see
    /// [`write_atomic`]).
    pub fn archive_profile(&self, pattern_key: u64, profdata: &Path) -> Result<()> {
        let bytes =
            fs::read(profdata).wrap_err_with(|| format!("read profile {}", profdata.display()))?;
        write_atomic(&self.archived_profile(pattern_key), &zstd::encode_all(&bytes[..], 3)?)
    }

    /// An archived profile, inflated back to the sparse profdata
    /// `llvm-profdata` merges.
    pub fn read_archived_profile(&self, pattern_key: u64) -> Result<Vec<u8>> {
        let path = self.archived_profile(pattern_key);
        let compressed = fs::read(&path).wrap_err_with(|| {
            format!("archived profile missing for pattern {pattern_key:016x}: {}", path.display())
        })?;
        zstd::decode_all(&compressed[..]).wrap_err_with(|| format!("decompress {}", path.display()))
    }

    /// Removes what a previous run left mid-flight: every per-block file in
    /// `tmp/`, and the `*.tmp` files of writers killed inside `write_atomic`
    /// (unique names, never reused, so they would accumulate forever).
    ///
    /// Only for the holder of the store's write lock: it is the one process
    /// that writes under these directories, so nothing found there is live.
    pub fn clear_leftovers(&self) -> usize {
        let mut removed = remove_files(&self.tmp(), |_| true);
        for dir in [self.spool(), self.codes(), self.archive_profiles()] {
            removed += remove_files(&dir, |name| name.ends_with(".tmp"));
        }
        removed
    }

    /// Loads contract bytecodes for the given hashes from the codes dir.
    /// Returns the same `HashMap` flavor `WitnessDatabase.contracts` expects.
    pub fn load_contracts(
        &self,
        hashes: &[B256],
    ) -> Result<alloy_primitives::map::HashMap<B256, revm::state::Bytecode>> {
        let mut map = alloy_primitives::map::HashMap::with_capacity_and_hasher(
            hashes.len(),
            Default::default(),
        );
        for hash in hashes {
            let path = self.code_file(hash);
            let bytes = fs::read(&path)
                .wrap_err_with(|| format!("missing contract code {}", path.display()))?;
            map.insert(*hash, revm::state::Bytecode::new_raw(bytes.into()));
        }
        Ok(map)
    }
}

/// Write via unique tmp file + rename so readers never observe partial files,
/// fsynced so the result survives power loss, not just process crashes.
///
/// The fsync-before-rename is load-bearing for the judge's archive-before-
/// commit invariant: redb commits are fsynced, so if archived profiles were
/// only in the page cache a power cut could persist the pattern while losing
/// its profile — an orphan no re-run can repair (the block is already Ok).
///
/// The tmp name embeds pid + a counter: concurrent writers of the SAME target
/// (e.g. two fetch tasks resolving one shared contract hash) must not collide
/// on the tmp path — last rename wins and both writers succeed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_renamed(path, bytes, true)
}

/// [`write_atomic`] without the fsyncs, for what a power loss may take with
/// it: spool entries and contract codes, which every run checks before use
/// (the spool's frame checksum and block number, the codes' keccak) and
/// refetches when damaged. Both are written once per block, so the flushes
/// would be most of their cost.
pub fn write_scratch(path: &Path, bytes: &[u8]) -> Result<()> {
    write_renamed(path, bytes, false)
}

fn write_renamed(path: &Path, bytes: &[u8], durable: bool) -> Result<()> {
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
        if durable {
            f.sync_all().wrap_err_with(|| format!("fsync {}", tmp.display()))?;
        }
        drop(f);
        fs::rename(&tmp, path).wrap_err_with(|| format!("rename to {}", path.display()))?;
        // Make the rename itself durable. Directory fsync is best-effort:
        // supported on Linux, may be a no-op/error elsewhere (macOS).
        if durable &&
            let Some(parent) = path.parent() &&
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

/// Removes the files directly in `dir` whose name `matches`; returns how many.
fn remove_files(dir: &Path, matches: impl Fn(&str) -> bool) -> usize {
    let Ok(entries) = fs::read_dir(dir) else { return 0 };
    entries
        .flatten()
        .filter(|e| matches(&e.file_name().to_string_lossy()))
        .filter(|e| fs::remove_file(e.path()).is_ok())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_files(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count()
    }

    fn entry(block_json: &[u8]) -> SpoolEntry {
        SpoolEntry {
            block_json: block_json.to_vec(),
            light_witness: LightWitness { kvs: Default::default(), levels: Default::default() },
            code_hashes: vec![B256::repeat_byte(3)],
        }
    }

    /// Any single corrupted byte in a spool file must fail `read_from` (the
    /// zstd frame checksum) — most of the entry is opaque high-entropy bytes
    /// where corruption would otherwise decode into silently wrong data, and
    /// the fetcher's delete-and-refetch self-heal keys off this error.
    #[test]
    fn spool_checksum_rejects_any_byte_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("1.bin");
        entry(&[0xA5; 4096]).write_to(&path).unwrap();
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

    /// A damaged inner block decodes fine as the envelope's opaque bytes, so
    /// `open` must parse it; and an entry holding another block is not this
    /// block's.
    #[test]
    fn open_rejects_an_unparsable_or_wrong_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("7.bin");
        entry(b"not json").write_to(&path).unwrap();
        assert!(SpoolEntry::open(&path, 7).is_err());

        let fixture = fs::read_dir("../../test_data/mainnet/blocks")
            .expect("fixture dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "json"))
            .expect("at least one block fixture");
        entry(&fs::read(&fixture).unwrap()).write_to(&path).unwrap();
        let n = serde_json::from_slice::<Block<OpTransaction>>(&fs::read(&fixture).unwrap())
            .unwrap()
            .header
            .inner
            .number;
        assert_eq!(SpoolEntry::open(&path, n).unwrap().block.header.inner.number, n);
        let err = SpoolEntry::open(&path, n + 1).err().expect("another block's entry");
        assert!(err.to_string().contains("expected"), "{err}");
    }

    /// The byte-array hooks change how fast `block_json` is written, not what
    /// is written: an entry encoded before them must decode after them.
    #[test]
    fn block_json_bytes_encode_as_the_plain_vec_did() {
        #[derive(Serialize)]
        struct Plain {
            block_json: Vec<u8>,
            light_witness: LightWitness,
            code_hashes: Vec<B256>,
        }
        let e = entry(&[7u8; 300]);
        let plain = Plain {
            block_json: e.block_json.clone(),
            light_witness: LightWitness { kvs: Default::default(), levels: Default::default() },
            code_hashes: e.code_hashes.clone(),
        };
        let as_bytes = bincode::serde::encode_to_vec(&e, BINCODE_CONFIG).unwrap();
        assert_eq!(as_bytes, bincode::serde::encode_to_vec(&plain, BINCODE_CONFIG).unwrap());
        let (back, _): (SpoolEntry, _) =
            bincode::serde::decode_from_slice(&as_bytes, BINCODE_CONFIG).unwrap();
        assert_eq!(back.block_json, e.block_json);
    }

    #[test]
    fn write_atomic_round_trips_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.bin");
        write_atomic(&target, b"payload").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"payload");
        assert_eq!(tmp_files(dir.path()), 0, "no tmp litter after success");
    }

    #[test]
    fn write_atomic_failure_removes_tmp() {
        let dir = tempfile::tempdir().unwrap();
        // A directory at the target path makes the final rename fail.
        let target = dir.path().join("occupied");
        fs::create_dir(&target).unwrap();
        assert!(write_atomic(&target, b"x").is_err());
        assert_eq!(tmp_files(dir.path()), 0, "failed write must clean its tmp file");
    }

    /// Everything in `tmp/` is per-block scratch; elsewhere only orphaned
    /// `write_atomic` temps go, never the data next to them.
    #[test]
    fn clear_leftovers_takes_scratch_and_orphaned_temps_only() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = DataDir::new(dir.path());
        dirs.ensure_layout().unwrap();
        fs::write(dirs.block_profraw(5), b"raw").unwrap();
        fs::write(dirs.block_profraw(5).with_extension("profdata"), b"sparse").unwrap();
        fs::write(dirs.codes().join("ab.bin.123.0.tmp"), b"junk").unwrap();
        fs::write(dirs.code_file(&B256::repeat_byte(1)), b"code").unwrap();
        fs::write(dirs.spool_entry(9), b"entry").unwrap();

        assert_eq!(dirs.clear_leftovers(), 3);
        assert_eq!(fs::read_dir(dirs.tmp()).unwrap().count(), 0);
        assert!(dirs.code_file(&B256::repeat_byte(1)).exists());
        assert!(dirs.spool_entry(9).exists());
    }
}
