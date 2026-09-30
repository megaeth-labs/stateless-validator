//! Test fixture loading utilities.
//!
//! Each fixture set ships packed as `test_data/<set>.tar.zst` and is parsed straight out of the
//! archive into memory, once per test binary: see [`TestFixtures::mainnet_shared`] and
//! [`TestFixtures::synthetic_shared`]. Nothing is unpacked to disk. Two files stay out of the
//! archive, in `test_data/<set>/`: `genesis.json`, which tests hand to the binaries by path, and
//! `manifest.txt`, one `<number>.<hash>` per paired block the archive must hold, so a repack
//! cannot drop or swap a block unnoticed.
//!
//! `stateless-test-utils` intentionally does NOT depend on `stateless-core` to avoid
//! circular dev-dependencies. Callers that need `MptWitness` or `ChainSpec` can use the
//! generic [`TestFixtures::mpt_witness`] decoder and
//! `ChainSpec::from_genesis(fixtures.load_genesis().unwrap())`.

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber, map::HashMap};
use alloy_rpc_types_eth::Block;
use eyre::{Context, Result};
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// On-disk envelope for `.salt` witness files (bincode-legacy encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessFileContent {
    pub op_attributes_hash: B256,
    pub parent_hash: BlockHash,
    pub salt_witness: SaltWitness,
}

/// Pre-loaded test fixtures, parsed from a packed `test_data/<set>.tar.zst`.
///
/// Archive layout, under `<set>/`: `contracts.txt` (one JSON `[hash, bytecode]` per line),
/// `blocks/<number>[.<hash>].json`, `stateless/witness/<number>.<hash>.{salt,mpt}`
/// (bincode-legacy). `data_dir` is the unpacked `test_data/<set>/`, holding the set's
/// `manifest.txt` and the `genesis.json` that tests read by path (see [`Self::load_genesis`]).
///
/// `mpt_witness_bytes` stores raw bincode-legacy bytes; decode via [`Self::mpt_witness`]
/// in crates that depend on `stateless-core`.
#[derive(Debug, Clone)]
pub struct TestFixtures {
    pub data_dir: PathBuf,
    pub blocks: HashMap<BlockHash, Block<Transaction>>,
    pub block_numbers: BTreeMap<u64, BlockHash>,
    pub salt_witnesses: HashMap<BlockHash, SaltWitness>,
    pub mpt_witness_bytes: HashMap<BlockHash, Vec<u8>>,
    pub contracts: HashMap<B256, Bytecode>,
}

impl TestFixtures {
    /// The mainnet fixtures (`test_data/mainnet.tar.zst`), parsed once per test binary.
    pub fn mainnet_shared() -> &'static Self {
        static FIXTURES: LazyLock<TestFixtures> =
            LazyLock::new(|| TestFixtures::from_archive("mainnet"));
        &FIXTURES
    }

    /// The synthetic fixtures (`test_data/synthetic.tar.zst`), parsed once per test binary.
    pub fn synthetic_shared() -> &'static Self {
        static FIXTURES: LazyLock<TestFixtures> =
            LazyLock::new(|| TestFixtures::from_archive("synthetic"));
        &FIXTURES
    }

    /// Parses `test_data/<set>.tar.zst` entry by entry, straight from the decompressed stream,
    /// so nothing is written to disk. Any entry outside the layout panics: skipping it would
    /// silently shrink the set the fixture sweeps run over.
    fn from_archive(set: &str) -> Self {
        let test_data = workspace_root().join("test_data");
        let archive = test_data.join(format!("{set}.tar.zst"));
        let file =
            File::open(&archive).unwrap_or_else(|e| panic!("open {}: {e}", archive.display()));
        let decoder = zstd::stream::read::Decoder::new(file)
            .unwrap_or_else(|e| panic!("zstd decoder for {}: {e}", archive.display()));

        let mut blocks = HashMap::default();
        let mut block_numbers = BTreeMap::new();
        let mut salt_witnesses = HashMap::default();
        let mut mpt_witness_bytes = HashMap::default();
        let mut contracts = HashMap::default();
        let mut tar = tar::Archive::new(decoder);
        let entries = tar.entries().unwrap_or_else(|e| panic!("read {}: {e}", archive.display()));
        for entry in entries {
            let mut entry = entry.unwrap_or_else(|e| panic!("read {}: {e}", archive.display()));
            if entry.header().entry_type().is_dir() {
                continue;
            }
            let path = entry.path().expect("entry path").to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap_or_else(|e| panic!("read {path}: {e}"));

            let name = path.strip_prefix(set).and_then(|p| p.strip_prefix('/')).unwrap_or("");
            if let Some(file) = name.strip_prefix("blocks/") {
                let number = file
                    .strip_suffix(".json")
                    .and_then(|stem| stem.split('.').next())
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or_else(|| panic!("unexpected block file {path}"));
                let block: Block<Transaction> = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|e| panic!("parse block {path}: {e}"));
                let hash = block.header.hash;
                blocks.insert(hash, block);
                block_numbers.insert(number, hash);
            } else if let Some(file) = name.strip_prefix("stateless/witness/") {
                let (stem, ext) = file
                    .rsplit_once('.')
                    .unwrap_or_else(|| panic!("unexpected witness file {path}"));
                let (_, hash) =
                    parse_block_num_and_hash(stem).unwrap_or_else(|e| panic!("{path}: {e}"));
                match ext {
                    "salt" => {
                        let (content, _): (WitnessFileContent, usize) =
                            bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
                                .unwrap_or_else(|e| panic!("decode SaltWitness {path}: {e}"));
                        salt_witnesses.insert(hash, content.salt_witness);
                    }
                    "mpt" => {
                        mpt_witness_bytes.insert(hash, bytes);
                    }
                    _ => panic!("unexpected witness file {path}"),
                }
            } else if name == "contracts.txt" {
                contracts = parse_contracts(&bytes);
            } else {
                panic!("unexpected entry {path} in {}", archive.display());
            }
        }

        Self {
            data_dir: test_data.join(set),
            blocks,
            block_numbers,
            salt_witnesses,
            mpt_witness_bytes,
            contracts,
        }
    }

    /// Decodes the bincode-legacy MPT witness for `hash`, typically as
    /// `stateless_core::withdrawals::MptWitness` (a type this crate cannot name).
    pub fn mpt_witness<T: DeserializeOwned>(&self, hash: &BlockHash) -> T {
        let bytes = self
            .mpt_witness_bytes
            .get(hash)
            .unwrap_or_else(|| panic!("no MPT witness fixture for {hash}"));
        let (witness, _) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
            .unwrap_or_else(|e| panic!("decode MPT witness for {hash}: {e}"));
        witness
    }

    /// Blocks with both SALT and MPT witnesses, in block-number order.
    pub fn paired_blocks(&self) -> Vec<(u64, BlockHash)> {
        self.block_numbers
            .iter()
            .filter(|(_, h)| {
                self.salt_witnesses.contains_key(*h) && self.mpt_witness_bytes.contains_key(*h)
            })
            .map(|(&n, &h)| (n, h))
            .collect()
    }

    /// The first paired block's `(SaltWitness, MptWitness)` — the standard input for tests
    /// that encode a witness payload. One home so every R2/witness-wire test selects the
    /// same fixture.
    pub fn first_paired_witness<T: DeserializeOwned>(&self) -> (SaltWitness, T) {
        let (_, hash) = *self.paired_blocks().first().expect("fixtures have a paired witness");
        (self.salt_witnesses[&hash].clone(), self.mpt_witness(&hash))
    }

    pub fn load_genesis(&self) -> Result<Genesis> {
        load_json(self.data_dir.join("genesis.json"))
    }

    pub fn min_block(&self) -> (u64, BlockHash) {
        let (&n, &h) = self.block_numbers.first_key_value().expect("no blocks loaded");
        (n, h)
    }

    pub fn max_block(&self) -> (u64, BlockHash) {
        let (&n, &h) = self.block_numbers.last_key_value().expect("no blocks loaded");
        (n, h)
    }
}

/// Workspace root derived from `CARGO_MANIFEST_DIR = <root>/crates/stateless-test-utils`.
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap()
}

/// Parses `"{block_number}.{block_hash}"` from a filename stem.
pub fn parse_block_num_and_hash(input: &str) -> Result<(BlockNumber, BlockHash)> {
    let (n, h) = input.split_once('.').ok_or_else(|| eyre::eyre!("Invalid format: {input}"))?;
    Ok((n.parse()?, h.parse()?))
}

/// Reads and deserializes a JSON file.
pub fn load_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON from {}", path.display()))
}

/// Parses `contracts.txt`: one JSON `[hash, bytecode]` per line.
fn parse_contracts(bytes: &[u8]) -> HashMap<B256, Bytecode> {
    bytes
        .split(|&b| b == b'\n')
        .filter(|line| !line.trim_ascii().is_empty())
        .map(|line| serde_json::from_slice::<(B256, Bytecode)>(line).expect("parse contract"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};

    use super::*;

    /// Each packed set holds exactly the paired blocks its `manifest.txt` lists, and parses
    /// completely: every witness belongs to a loaded block and comes with its other half, every
    /// paired block's parent header is loaded (the anchored validations derive the pre-state
    /// roots from it), and every loaded block is one or the other.
    #[test]
    fn packed_sets_are_complete() {
        for (set, fx) in [
            ("mainnet", TestFixtures::mainnet_shared()),
            ("synthetic", TestFixtures::synthetic_shared()),
        ] {
            let paired = fx.paired_blocks();
            let packed: BTreeSet<(u64, BlockHash)> = paired.iter().copied().collect();
            let listed = manifest(fx);
            let missing: Vec<_> = listed.difference(&packed).collect();
            let unlisted: Vec<_> = packed.difference(&listed).collect();
            assert!(
                missing.is_empty() && unlisted.is_empty(),
                "{set}: archive differs from manifest.txt: missing {missing:?}, unlisted {unlisted:?}",
            );
            assert!(!paired.is_empty(), "{set}: no paired blocks");
            assert_eq!(paired.len(), fx.salt_witnesses.len(), "{set}: unpaired SALT witness");
            assert_eq!(paired.len(), fx.mpt_witness_bytes.len(), "{set}: unpaired MPT witness");
            assert_eq!(fx.blocks.len(), fx.block_numbers.len(), "{set}: duplicate block number");

            let parents: HashSet<BlockHash> =
                paired.iter().map(|(_, hash)| fx.blocks[hash].header.parent_hash).collect();
            for parent in &parents {
                assert!(fx.blocks.contains_key(parent), "{set}: parent {parent} not loaded");
            }
            for hash in fx.blocks.keys() {
                assert!(
                    fx.salt_witnesses.contains_key(hash) || parents.contains(hash),
                    "{set}: block {hash} is neither paired nor a paired block's parent",
                );
            }
            assert!(!fx.contracts.is_empty(), "{set}: no contracts");
        }
    }

    /// Reads the set's `manifest.txt`: one `<number>.<hash>` per line.
    fn manifest(fx: &TestFixtures) -> BTreeSet<(u64, BlockHash)> {
        let path = fx.data_dir.join("manifest.txt");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                parse_block_num_and_hash(line.trim())
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            })
            .collect()
    }
}
