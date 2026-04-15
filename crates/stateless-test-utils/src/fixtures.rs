//! Test fixture loading utilities.
//!
//! Loads block, witness, and contract data from the `test_data/` directory layout
//! used by integration tests across the workspace.
//!
//! `stateless-test-utils` intentionally does NOT depend on `stateless-core` to avoid
//! circular dev-dependencies.
//! Callers that need `MptWitness` or `ChainSpec` can decode the raw bytes themselves using
//! `bincode::serde::decode_from_slice(&mpt_witness_bytes[&hash], bincode::config::legacy())`
//! and `ChainSpec::from_genesis(fixtures.load_genesis().unwrap())`.

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

/// Witness file envelope stored on disk (`.salt` files).
///
/// The `.salt` file is a bincode-legacy-encoded `WitnessFileContent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessFileContent {
    /// Hash of operation attributes for execution verification.
    pub op_attributes_hash: B256,
    /// Parent block hash for chain continuity verification.
    pub parent_hash: BlockHash,
    /// Cryptographic witness proving state transitions.
    pub salt_witness: SaltWitness,
}

/// Pre-loaded test fixtures: blocks, witnesses, and contract bytecodes.
///
/// Loaded from the `test_data/` directory layout:
/// ```text
/// <data_dir>/
///   genesis.json
///   contracts.txt             (one JSON `[hash, bytecode]` per line)
///   blocks/
///     <number>.json           (block JSON)
///   stateless/witness/
///     <number>.<hash>.salt    (bincode-legacy WitnessFileContent)
///     <number>.<hash>.mpt     (bincode-legacy MptWitness)
/// ```
///
/// **Decoding MPT witnesses**: `mpt_witness_bytes` stores the raw bincode bytes.
/// Call `bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())` to get
/// `MptWitness` in crates that have `stateless-core` as a dependency.
#[derive(Debug, Clone)]
pub struct TestFixtures {
    /// Root data directory (for `load_genesis()`).
    pub data_dir: PathBuf,
    /// Blocks keyed by hash.
    pub blocks: HashMap<BlockHash, Block<Transaction>>,
    /// Block numbers → block hash, in order.
    pub block_numbers: BTreeMap<u64, BlockHash>,
    /// SALT witnesses keyed by block hash.
    pub salt_witnesses: HashMap<BlockHash, SaltWitness>,
    /// Raw bincode-legacy bytes of each MPT witness, keyed by block hash.
    ///
    /// Decode with `bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())`.
    pub mpt_witness_bytes: HashMap<BlockHash, Vec<u8>>,
    /// Contract bytecodes keyed by code hash.
    pub contracts: HashMap<B256, Bytecode>,
}

impl TestFixtures {
    /// Load fixtures from an arbitrary directory that follows the `test_data/` layout.
    pub fn load(data_dir: &Path) -> Self {
        let block_dir = data_dir.join("blocks");
        let witness_dir = data_dir.join("stateless/witness");
        let contracts_file = data_dir.join("contracts.txt");

        // Load blocks
        let mut blocks = HashMap::new();
        let mut block_numbers = BTreeMap::new();

        for entry in std::fs::read_dir(&block_dir).unwrap_or_else(|e| {
            panic!("Failed to read block directory {}: {e}", block_dir.display())
        }) {
            let file = entry.unwrap();
            let file_name = file.file_name();
            let file_str = file_name.to_string_lossy();
            if !file_str.ends_with(".json") {
                continue;
            }
            if let Some(dot_pos) = file_str.find('.') &&
                let Ok(block_number) = file_str[..dot_pos].parse::<u64>()
            {
                let block: Block<Transaction> = load_json(file.path()).unwrap();
                let block_hash = BlockHash::from(block.header.hash);
                blocks.insert(block_hash, block);
                block_numbers.insert(block_number, block_hash);
            }
        }

        // Load witnesses
        let mut salt_witnesses = HashMap::new();
        let mut mpt_witness_bytes = HashMap::new();

        for entry in std::fs::read_dir(&witness_dir).unwrap_or_else(|e| {
            panic!("Failed to read witness directory {}: {e}", witness_dir.display())
        }) {
            let entry = entry.unwrap();
            let file_path = entry.path();
            let Some(ext) = file_path.extension().and_then(|s| s.to_str()) else {
                continue;
            };

            let stem = file_path.file_stem().unwrap().to_str().unwrap();
            let (_, block_hash) = parse_block_num_and_hash(stem).unwrap();
            let file_data = std::fs::read(&file_path).unwrap();

            match ext {
                "salt" => {
                    let (content, _): (WitnessFileContent, usize) =
                        bincode::serde::decode_from_slice(&file_data, bincode::config::legacy())
                            .unwrap_or_else(|e| panic!("Failed to decode SaltWitness {stem}: {e}"));
                    salt_witnesses.insert(block_hash, content.salt_witness);
                }
                "mpt" => {
                    // Store raw bytes; callers decode with bincode::config::legacy().
                    mpt_witness_bytes.insert(block_hash, file_data);
                }
                _ => {}
            }
        }

        // Load contracts
        let contracts = load_contracts(&contracts_file);

        Self {
            data_dir: data_dir.to_owned(),
            blocks,
            block_numbers,
            salt_witnesses,
            mpt_witness_bytes,
            contracts,
        }
    }

    /// Load mainnet fixtures from `test_data/mainnet/` relative to the workspace root.
    ///
    /// Uses `CARGO_MANIFEST_DIR` at compile time to locate the workspace root from any
    /// working directory.
    pub fn mainnet() -> Self {
        Self::load(&workspace_root().join("test_data/mainnet"))
    }

    /// Load synthetic fixtures from `test_data/synthetic/` relative to the workspace root.
    pub fn synthetic() -> Self {
        Self::load(&workspace_root().join("test_data/synthetic"))
    }

    /// Returns blocks that have both a SALT witness and an MPT witness, in block-number order.
    pub fn paired_blocks(&self) -> Vec<(u64, BlockHash)> {
        self.block_numbers
            .iter()
            .filter(|(_, hash)| {
                self.salt_witnesses.contains_key(*hash) &&
                    self.mpt_witness_bytes.contains_key(*hash)
            })
            .map(|(&num, &hash)| (num, hash))
            .collect()
    }

    /// Loads the `genesis.json` from the data directory.
    pub fn load_genesis(&self) -> Result<Genesis> {
        load_json(self.data_dir.join("genesis.json"))
    }

    /// Returns the lowest block number and its hash.
    pub fn min_block(&self) -> (u64, BlockHash) {
        let (&num, &hash) = self.block_numbers.first_key_value().expect("no blocks loaded");
        (num, hash)
    }

    /// Returns the highest block number and its hash.
    pub fn max_block(&self) -> (u64, BlockHash) {
        let (&num, &hash) = self.block_numbers.last_key_value().expect("no blocks loaded");
        (num, hash)
    }
}

/// Absolute path to the workspace root, derived from `CARGO_MANIFEST_DIR`
/// (`<root>/crates/stateless-test-utils`).
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap()
}

/// Parses `"{block_number}.{block_hash}"` from a filename stem.
pub fn parse_block_num_and_hash(input: &str) -> Result<(BlockNumber, BlockHash)> {
    let (block_str, hash_str) =
        input.split_once('.').ok_or_else(|| eyre::eyre!("Invalid format: {input}"))?;
    Ok((block_str.parse()?, hash_str.parse()?))
}

/// Reads and deserializes a JSON file.
pub fn load_json<T: DeserializeOwned>(file_path: impl AsRef<Path>) -> Result<T> {
    let path = file_path.as_ref();
    let contents =
        std::fs::read(path).with_context(|| format!("Failed to read file {}", path.display()))?;
    serde_json::from_slice(&contents)
        .with_context(|| format!("Failed to parse JSON from {}", path.display()))
}

/// Loads contract bytecodes from a file (one `[hash, bytecode]` JSON per line).
pub fn load_contracts(path: impl AsRef<Path>) -> HashMap<B256, Bytecode> {
    let file = File::open(path.as_ref()).unwrap_or_else(|e| {
        panic!("Failed to open contracts file {}: {e}", path.as_ref().display())
    });
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(&line).expect("Failed to parse contract"))
        .collect()
}
