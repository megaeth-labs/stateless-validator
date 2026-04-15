//! Test fixture loading utilities.
//!
//! Loads block, witness, and contract data from the `test_data/` directory layout
//! used by integration tests across the workspace.
//!
//! `stateless-test-utils` intentionally does NOT depend on `stateless-core` to avoid
//! circular dev-dependencies. Callers that need `MptWitness` or `ChainSpec` can decode
//! `mpt_witness_bytes` themselves with
//! `bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())` and
//! `ChainSpec::from_genesis(fixtures.load_genesis().unwrap())`.

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber};
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

/// Pre-loaded test fixtures from a `test_data/` directory.
///
/// Layout: `genesis.json`, `contracts.txt` (one JSON `[hash, bytecode]` per line),
/// `blocks/<number>.json`, `stateless/witness/<number>.<hash>.{salt,mpt}` (bincode-legacy).
///
/// `mpt_witness_bytes` stores raw bincode bytes; decode with
/// `bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())` in crates that
/// depend on `stateless-core`.
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
    /// Load fixtures from a directory following the `test_data/` layout.
    pub fn load(data_dir: &Path) -> Self {
        let mut blocks = HashMap::new();
        let mut block_numbers = BTreeMap::new();
        for path in read_dir_paths(&data_dir.join("blocks")) {
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Some(number) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.split('.').next())
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            let block: Block<Transaction> = load_json(&path).unwrap();
            let hash = BlockHash::from(block.header.hash);
            blocks.insert(hash, block);
            block_numbers.insert(number, hash);
        }

        let mut salt_witnesses = HashMap::new();
        let mut mpt_witness_bytes = HashMap::new();
        for path in read_dir_paths(&data_dir.join("stateless/witness")) {
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else { continue };
            let stem = path.file_stem().unwrap().to_str().unwrap();
            let (_, hash) = parse_block_num_and_hash(stem).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            match ext {
                "salt" => {
                    let (content, _): (WitnessFileContent, usize) =
                        bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
                            .unwrap_or_else(|e| panic!("decode SaltWitness {stem}: {e}"));
                    salt_witnesses.insert(hash, content.salt_witness);
                }
                "mpt" => {
                    mpt_witness_bytes.insert(hash, bytes);
                }
                _ => {}
            }
        }

        Self {
            data_dir: data_dir.to_owned(),
            blocks,
            block_numbers,
            salt_witnesses,
            mpt_witness_bytes,
            contracts: load_contracts(data_dir.join("contracts.txt")),
        }
    }

    /// Load `test_data/mainnet/` relative to the workspace root.
    pub fn mainnet() -> Self {
        Self::load(&workspace_root().join("test_data/mainnet"))
    }

    /// Load `test_data/synthetic/` relative to the workspace root.
    pub fn synthetic() -> Self {
        Self::load(&workspace_root().join("test_data/synthetic"))
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

fn read_dir_paths(dir: &Path) -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
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

/// Loads contract bytecodes from a file (one `[hash, bytecode]` JSON per line).
pub fn load_contracts(path: impl AsRef<Path>) -> HashMap<B256, Bytecode> {
    let path = path.as_ref();
    let file = File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(&l).expect("parse contract"))
        .collect()
}
