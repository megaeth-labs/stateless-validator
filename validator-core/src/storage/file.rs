//! This module handles file-based operations for the stateless validator.
//! It manages the persistence of validation status, block data, and contract code.
use crate::{SaltWitnessState, WitnessStatus, deserialized_state_data, serialized_state_data};
use alloy_primitives::{B256, BlockHash, BlockNumber};
use eyre::{Result, anyhow};
use fs2::FileExt;
use rand::Rng;
use revm::{primitives::HashMap, state::Bytecode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{File, OpenOptions, create_dir_all, read_dir},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    str::FromStr,
    time::SystemTime,
};

/// Represents the validation status of a block.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ValidateStatus {
    /// The block has not yet been processed.
    #[default]
    Idle,
    /// The block is currently being validated.
    Processing,
    /// The block failed validation.
    Failed,
    /// The block was successfully validated.
    Success,
}

/// Stores metadata about the validation process for a single block.
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidateInfo {
    /// The current validation status of the block.
    pub status: ValidateStatus,
    /// The hash of the block being validated.
    pub block_hash: BlockHash,
    /// The number of the block being validated.
    pub block_number: BlockNumber,
    /// The resulting state root after validation.
    pub state_root: B256,
    /// A timestamp indicating when a processing lock expires.
    pub lock_time: u64,
    /// A list of blob IDs associated with the block's transactions.
    pub blob_ids: Vec<[u8; 32]>,
}

/// The chain status, which contains the finalized block number, block hash
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    /// The block number of the finalized block
    pub block_number: BlockNumber,
    /// The block hash of the finalized block
    pub block_hash: BlockHash,
}

/// Generic function to load binary data from primary or backup location
fn load_binary_data<T: serde::de::DeserializeOwned>(
    primary_path: impl AsRef<Path>,
    backup_path: impl AsRef<Path>,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> Result<T> {
    let primary_path = primary_path.as_ref();
    let backup_path = backup_path.as_ref();

    if !primary_path.exists() && !backup_path.exists() {
        return Err(anyhow!(
            "No file found for block({block_number}, {block_hash})"
        ));
    }

    let mut file = if let Ok(file) = OpenOptions::new().read(true).open(primary_path) {
        file
    } else {
        OpenOptions::new()
            .read(true)
            .open(backup_path)
            .map_err(|e| anyhow!("block({block_number}): {}", e))?
    };

    let mut contents = vec![];
    file.read_to_end(&mut contents)?;
    let state_data =
        deserialized_state_data(contents).map_err(|e| anyhow!("block({block_number}): {}", e))?;

    let (data, _): (T, usize) =
        bincode::serde::decode_from_slice(&state_data.data, bincode::config::legacy()).map_err(
            |e| {
                anyhow!(
                    "block({block_number}, {block_hash}): Failed to deserialize data: {}",
                    e
                )
            },
        )?;
    Ok(data)
}

/// Loads the `ValidateInfo` for a specific block from a file
/// from validate or backup directory.
/// If the file does not exist, it returns a default `ValidateInfo` instance.
pub fn load_validate_info(
    path: &Path,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> Result<ValidateInfo> {
    let validate_path = path
        .join("validate")
        .join(validate_file_name(block_number, block_hash));
    let backup_path = path.join(crate::backup_file(block_number, block_hash, ".v"));

    if !validate_path.exists() && !backup_path.exists() {
        return Ok(ValidateInfo::default());
    }

    load_binary_data(validate_path, backup_path, block_number, block_hash)
}

/// Loads the `WitnessStatus` for a specific block from a file
/// from witness or backup directory.
pub fn load_from_file_or_backup(
    path: &Path,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> Result<WitnessStatus> {
    let witness_path = path
        .join("witness")
        .join(witness_file_name(block_number, block_hash));
    let backup_path = path.join(crate::backup_file(block_number, block_hash, ".w"));

    load_binary_data(witness_path, backup_path, block_number, block_hash)
}

/// Sets and saves the validation status and other metadata for a block.
///
/// This function loads the existing `ValidateInfo`, updates its fields with the provided
/// values, and then saves it back to a file atomically.
pub fn set_validate_status(
    path: &Path,
    block_number: BlockNumber,
    block_hash: BlockHash,
    status: ValidateStatus,
    state_root: Option<B256>,
    lock_time: Option<u64>,
    blob_ids: Option<Vec<[u8; 32]>>,
) -> Result<()> {
    let mut validate_info = load_validate_info(path, block_number, block_hash)?;
    validate_info.status = status;
    validate_info.block_hash = block_hash;
    validate_info.block_number = block_number;
    if let Some(lock_time) = lock_time {
        validate_info.lock_time = curent_time_to_u64() + lock_time;
    }
    if let Some(state_root) = state_root {
        validate_info.state_root = state_root;
    }
    if let Some(blob_ids) = blob_ids {
        validate_info.blob_ids = blob_ids;
    }

    save_validate_info(path, block_number, block_hash, validate_info)
}

/// Helper function to create JSON file path
fn json_file_path(data_dir: &Path, file_name: &str) -> std::path::PathBuf {
    data_dir.join(file_name)
}

/// Loads and deserializes data from a JSON file.
///
/// This function constructs a file path based on the provided `data_dir`,
/// `block_number`, and `file_name`. It then attempts to open, read, and
/// deserialize the JSON content into the specified generic type `T`.
///
/// # Type Parameters
///
/// * `T`: The type to deserialize the JSON data into. Must implement `DeserializeOwned`.
///
/// # Arguments
///
/// * `data_dir`: The base directory where data files are stored.
/// * `file_name`: The name of the JSON file (without the .json extension).
///
/// # Returns
///
/// Returns `Ok(T)` containing the deserialized data if successful.
/// Returns an `Err` if any step (file opening, reading, or deserialization) fails.
pub fn load_json_file<T: DeserializeOwned>(data_dir: &Path, file_name: &str) -> Result<T> {
    let json_file = json_file_path(data_dir, file_name);

    let mut file = File::open(&json_file)
        .map_err(|e| anyhow!("Failed to open {}: {}", json_file.display(), e))?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| anyhow!("Failed to read {}: {}", json_file.display(), e))?;

    let data: T = simd_json::from_slice(&mut contents)
        .map_err(|e| anyhow!("Failed to parse {}: {}", json_file.display(), e))?;

    Ok(data)
}

/// Serializes data to JSON and stores it in a file.
///
/// This function creates necessary directories if they don't exist.
/// It then serializes the provided `data` into JSON format and writes it to a file.
/// If the file already exists, it will not be overwritten.
///
/// # Type Parameters
///
/// * `T`: The type of data to serialize. Must implement `Serialize`.
///
/// # Arguments
///
/// * `data`: The data to be serialized and stored.
/// * `data_dir`: The base directory where data files will be stored.
/// * `file_name`: The name of the JSON file to be created (without the .json extension).
///
/// # Returns
///
/// Returns `Ok(())` if the data is successfully serialized and written to the file.
/// Returns an `Err` if any step (directory creation, file opening, serialization, or writing)
/// fails.
pub fn store_json_file<T: Serialize>(data: T, data_dir: &Path, file_name: &str) -> Result<()> {
    create_dir_all(data_dir).map_err(|e| anyhow!("Failed to create directory: {}", e))?;

    let json_file = json_file_path(data_dir, file_name);
    if json_file.exists() {
        return Ok(());
    }

    let mut json_fp = File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&json_file)
        .map_err(|e| anyhow!("Failed to open {}: {}", json_file.display(), e))?;

    let json_bytes = simd_json::to_vec(&data).map_err(|e| {
        anyhow!(
            "Failed to serialize data for {}: {}",
            json_file.display(),
            e
        )
    })?;

    json_fp
        .write_all(&json_bytes)
        .map_err(|e| anyhow!("Failed to write {}: {}", json_file.display(), e))?;
    json_fp
        .flush()
        .map_err(|e| anyhow!("Failed to flush {}: {}", json_file.display(), e))?;

    Ok(())
}

/// Write data to a file atomically using temporary file + rename
fn write_atomic(target_path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    let target_path = target_path.as_ref();
    let parent_dir = target_path
        .parent()
        .ok_or_else(|| anyhow!("Target path has no parent directory"))?;

    create_dir_all(parent_dir)?;

    let rand_num: u32 = rand::rng().random();
    let tmp_path = parent_dir.join(format!(
        "{}.{}.tmp",
        target_path.file_name().unwrap().to_string_lossy(),
        rand_num
    ));

    // 1. Write to a temporary file. This operation is not atomic.
    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        FileExt::lock_exclusive(&tmp_file)?;
        tmp_file.write_all(data)?;
        tmp_file.sync_all()?;
        FileExt::unlock(&tmp_file)?;
    }

    // 2. Atomically rename the temporary file to its final name.
    std::fs::rename(tmp_path, target_path).map_err(|e| anyhow!("Failed to rename file: {}", e))?;

    Ok(())
}

/// Saves the `ValidateInfo` to a file atomically.
///
/// This is achieved by writing to a temporary file first and then renaming it to the
/// final destination. This ensures that a reader will never see a partially written file.
fn save_validate_info(
    path: &Path,
    block_number: BlockNumber,
    block_hash: BlockHash,
    validate_info: ValidateInfo,
) -> Result<()> {
    let serialized = bincode::serde::encode_to_vec(&validate_info, bincode::config::legacy())?;
    let serialized = serialized_state_data(serialized)?;

    let final_path = path
        .join("validate")
        .join(validate_file_name(block_number, block_hash));
    write_atomic(final_path, &serialized)
}

/// Reads the block hash for a given block number from a witness file name.
///
/// Witness files are named `{block_number}.{block_hash}.w`. This function scans the witness
/// directory to find a file matching the block number and extracts the hash from its name.
pub fn read_block_hash_by_number_from_file(
    block_number: u64,
    witness_dir: &Path,
) -> Result<Vec<B256>> {
    let block_number_str = block_number.to_string();
    let file_prefix = format!("{}.", block_number_str);
    const FILE_SUFFIX: &str = ".w";

    if !witness_dir.is_dir() {
        return Err(anyhow!("Witness directory not found: {:?}", witness_dir));
    }

    let mut hashes = Vec::new();
    for entry in read_dir(witness_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && let Some(file_name_os_str) = path.file_name()
            && let Some(file_name_str) = file_name_os_str.to_str()
            && file_name_str.starts_with(&file_prefix)
            && file_name_str.ends_with(FILE_SUFFIX)
        {
            let hash_part =
                &file_name_str[file_prefix.len()..(file_name_str.len() - FILE_SUFFIX.len())];

            // Attempt to parse the hash part of the filename.
            match B256::from_str(hash_part) {
                Ok(hash) => hashes.push(hash),
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to parse hash '{}' from file '{}': {}",
                        hash_part,
                        file_name_str,
                        e
                    ));
                }
            }
        }
    }

    if hashes.is_empty() {
        Err(anyhow!(
            "No witness file found for block {} with pattern '{}.HASH.w' in {:?}",
            block_number,
            block_number_str,
            witness_dir
        ))
    } else {
        Ok(hashes)
    }
}

/// Generate a standard file name for block-related files
fn block_file_name(block_num: BlockNumber, block_hash: BlockHash, extension: &str) -> String {
    format!("{}.{}.{}", block_num, block_hash, extension)
}

/// Generates the standard file name for a validation file.
pub fn validate_file_name(block_num: BlockNumber, block_hash: BlockHash) -> String {
    block_file_name(block_num, block_hash, "v")
}

/// Loads contracts from a file where each line is a JSON array `[hash, bytecode]`.
///
/// # Example file content:
/// ["0x...", "0x..."]
/// ["0x...", "0x..."]
pub fn load_contracts_file(data_dir: &Path, file_name: &str) -> Result<HashMap<B256, Bytecode>> {
    let json_file = data_dir.join(file_name);
    if !json_file.exists() {
        return Ok(HashMap::default());
    }

    let file = File::open(&json_file)
        .map_err(|e| anyhow!("Failed to open {} file: {}", json_file.display(), e))?;

    let reader = BufReader::new(file);
    let mut contracts = HashMap::default();

    for line in reader.lines() {
        let line = line.map_err(|e| anyhow!("Failed to read line: {}", e))?;
        if line.trim().is_empty() {
            continue;
        }
        let mut line_bytes = line.into_bytes();
        let (hash, bytecode): (B256, Bytecode) = simd_json::from_slice(&mut line_bytes)
            .map_err(|e| anyhow!("Failed to parse contract line: {}", e))?;
        contracts.insert(hash, bytecode);
    }

    Ok(contracts)
}

/// Appends a serializable item to a file in JSON Lines format.
///
/// The item is serialized to a JSON string and written on a new line.
pub fn append_json_line_to_file<T: Serialize>(
    data: &T,
    data_dir: &Path,
    file_name: &str,
) -> Result<()> {
    create_dir_all(data_dir).map_err(|e| anyhow!("Failed to create directory: {}", e))?;

    let json_file = json_file_path(data_dir, file_name);

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&json_file)
        .map_err(|e| anyhow!("Failed to open {}: {}", json_file.display(), e))?;

    let json_bytes = simd_json::to_vec(data).map_err(|e| {
        anyhow!(
            "Failed to serialize data for {}: {}",
            json_file.display(),
            e
        )
    })?;

    file.write_all(&json_bytes)
        .map_err(|e| anyhow!("Failed to write {}: {}", json_file.display(), e))?;
    file.write_all(b"\n")
        .map_err(|e| anyhow!("Failed to write newline {}: {}", json_file.display(), e))?;
    file.sync_all()?;

    Ok(())
}

/// Convert current time to a u64 timestamp
///
/// Used for lock time management in witness and validation operations.
pub fn curent_time_to_u64() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH!")
        .as_secs()
}

/// Generate witness file name for a block
///
/// Creates a standardized witness file name using the format `{block_number}.{block_hash}.w`
pub fn witness_file_name(block_num: BlockNumber, block_hash: BlockHash) -> String {
    block_file_name(block_num, block_hash, "w")
}

/// Get block witness status by given block number and block hash
///
/// Loads witness status from file or returns default idle status if file doesn't exist.
pub fn get_witness_state(path: &Path, block: &(BlockNumber, BlockHash)) -> Result<WitnessStatus> {
    let path = path
        .join("witness")
        .join(witness_file_name(block.0, block.1));
    if !path.exists() {
        return Ok(WitnessStatus {
            status: SaltWitnessState::Idle,
            block_hash: block.1,
            block_number: block.0,
            parent_hash: BlockHash::default(),
            pre_state_root: B256::default(),
            lock_time: curent_time_to_u64(),
            blob_ids: vec![],
            witness_data: vec![],
        });
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut contents = vec![];
    file.read_to_end(&mut contents)?;
    let state_data =
        deserialized_state_data(contents).map_err(|e| anyhow!("block({:?}): {}", block, e))?;
    let deserialized =
        bincode::serde::decode_from_slice(&state_data.data, bincode::config::legacy()).map_err(
            |e| {
                anyhow!(
                    "block({:?}): Failed to deserialize WitnessStatus: {}",
                    block,
                    e
                )
            },
        )?;
    Ok(deserialized.0)
}

/// Get the chain status from file
///
/// Reads chain status from the `chain.status` file in JSON format.
pub fn get_chain_status(path: &Path) -> Result<ChainStatus> {
    let path = path.join("chain.status");
    let mut file = OpenOptions::new().read(true).open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let status: ChainStatus = serde_json::from_str(&contents)?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use std::{
        fs::{self, File},
        io::Write,
    };
    use tempfile::tempdir;

    fn dummy_block_hash() -> BlockHash {
        B256::from([1u8; 32])
    }

    #[test]
    fn test_load_validate_info_file_not_exist() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let res = load_validate_info(&path, 1, dummy_block_hash());
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), ValidateInfo::default());
    }

    #[test]
    fn test_load_validate_info_main_file_exist() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let validate_dir = path.join("validate");
        fs::create_dir_all(&validate_dir).unwrap();

        let block_number = 1u64;
        let block_hash = dummy_block_hash();
        let file_name = validate_file_name(block_number, block_hash);
        let file_path = validate_dir.join(&file_name);

        // Construct a ValidateInfo and serialize it to the file
        let info = ValidateInfo {
            status: ValidateStatus::Success,
            block_hash,
            block_number,
            state_root: B256::from([2u8; 32]),
            lock_time: 123,
            blob_ids: vec![[3u8; 32]],
        };
        let serialized = bincode::serde::encode_to_vec(&info, bincode::config::legacy()).unwrap();
        let serialized = serialized_state_data(serialized).unwrap();
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&serialized).unwrap();

        let loaded = load_validate_info(&path, block_number, block_hash).unwrap();
        assert_eq!(loaded, info);
    }

    #[test]
    fn test_load_validate_info_backup_file_exist() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let validate_dir = path.join("validate");
        let backup_dir = path.join("backup").join("0");
        fs::create_dir_all(&backup_dir).unwrap();
        fs::create_dir_all(&validate_dir).unwrap();

        let block_number = 2u64;
        let block_hash = dummy_block_hash();
        let backup_file = path.join(crate::backup_file(block_number, block_hash, ".v"));

        // Construct a ValidateInfo and serialize it to the backup file
        let info = ValidateInfo {
            status: ValidateStatus::Processing,
            block_hash,
            block_number,
            state_root: B256::from([4u8; 32]),
            lock_time: 456,
            blob_ids: vec![[5u8; 32]],
        };
        let serialized = bincode::serde::encode_to_vec(&info, bincode::config::legacy()).unwrap();
        let serialized = serialized_state_data(serialized).unwrap();
        let mut file = File::create(&backup_file).unwrap();
        file.write_all(&serialized).unwrap();

        let loaded = load_validate_info(&path, block_number, block_hash).unwrap();
        assert_eq!(loaded, info);
    }
}
