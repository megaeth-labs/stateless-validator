//! On-disk spool entries: everything a worker needs to replay one block.
//!
//! Lifecycle: written by the fetcher, consumed by a worker, deleted after
//! judgment — for every block, including new-pattern representatives. Nothing
//! block-sized is retained: the RPC serves blocks and witnesses for the full
//! history, so resweeps and PR payload assembly re-fetch representatives by
//! block number (recorded in the store). The only per-pattern artifact kept
//! is a small sparse profdata for `report`.

use std::{
    collections::BTreeMap,
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
    /// Block hash (redundant with the JSON, kept for cheap access).
    pub block_hash: B256,
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
        let compressed = zstd::encode_all(&raw[..], SPOOL_ZSTD_LEVEL)?;
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
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let dir = Self { root: root.into() };
        for d in [dir.spool(), dir.codes(), dir.tmp(), dir.archive_profiles()] {
            fs::create_dir_all(&d)?;
        }
        Ok(dir)
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

/// Write via unique tmp file + rename so readers never observe partial files.
///
/// The tmp name embeds pid + a counter: concurrent writers of the SAME target
/// (e.g. two fetch tasks resolving one shared contract hash) must not collide
/// on the tmp path — last rename wins and both writers succeed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "{}.{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    );
    let tmp = path.with_file_name(unique);
    fs::write(&tmp, bytes).wrap_err_with(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).wrap_err_with(|| format!("rename to {}", path.display()))?;
    Ok(())
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

/// Extracts sorted, deduped code hashes referenced by a light witness.
pub fn code_hashes_of(witness: &LightWitness) -> Vec<B256> {
    let kvs: &BTreeMap<_, _> = &witness.kvs;
    let mut hashes: Vec<B256> = stateless_core::iter_code_hashes(kvs).collect();
    hashes.sort();
    hashes.dedup();
    hashes
}
