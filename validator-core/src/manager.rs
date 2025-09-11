//! Validation manager for the stateless validator.
//! It manages the persistence of validation status, block data, and contract code.

/// The number of blocks to shift for backup file naming
/// This is used to create a directory structure for backups, allowing for efficient storage
const BACKUP_SHIFT: BlockNumber = 10;
use alloy_primitives::{B256, BlockHash, BlockNumber, hex};
use eyre::{Result, anyhow};
use fs2::FileExt;
use jsonrpsee_types::error::{
    CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
    UNKNOWN_ERROR_CODE,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap as StdHashMap,
    fs::{OpenOptions, create_dir_all, read_dir},
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::SystemTime,
};

/// Block witness Processing state
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SaltWitnessState {
    /// Idle state, no processing
    Idle,
    /// Processing state, the block witness is being generated
    Processing,
    /// Witnessed state, the block witness has been generated
    Witnessed,
    /// Witness verification state, the block witness is Verifying
    Verifying,
    /// Uploading state, the block witness is being uploaded Step 1
    UploadingStep1,
    /// Uploading state, the block witness is being uploaded Step 2
    UploadingStep2,
    /// Completed state, the block witness has been uploaded successfully
    Completed,
}

/// WitnessStatus is used to store the status and state of a block witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessStatus {
    /// restore the block witness status
    pub status: SaltWitnessState,
    /// restore the block hash
    pub block_hash: BlockHash,
    /// restore the block number
    pub block_number: BlockNumber,
    /// restore the pre state root
    /// this is used to verify the block witness
    pub pre_state_root: B256,
    /// restore the parent block hash
    pub parent_hash: BlockHash,
    /// locking the task before the timeout
    pub lock_time: u64,
    /// record the blob ids
    pub blob_ids: Vec<[u8; 32]>,
    /// record the block witness data with bytes
    pub witness_data: Vec<u8>,
}

/// Container for file storage content with BLAKE3 hash verification
///
/// This structure wraps raw data with a cryptographic hash to ensure data integrity
/// during serialization, storage, and deserialization operations.
#[derive(Debug, Deserialize, Serialize)]
pub struct StateData {
    /// BLAKE3 hash for data integrity verification
    pub hash: B256,
    /// Raw data stored as byte vector
    pub data: Vec<u8>,
}

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

/// Manager for validation operations (validation and witness files)
///
/// This struct consolidates all operations that work with block-specific files,
/// providing a cleaner API and eliminating repeated path parameters.
pub struct ValidationManager {
    /// Base path for all block file operations
    base_path: PathBuf,
    /// Path to the validate directory (base_path/validate)
    validate_dir: PathBuf,
    /// Path to the witness directory (base_path/witness)
    witness_dir: PathBuf,
    /// Path to the chain status file (base_path/chain.status)
    chain_status_file: PathBuf,
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

impl ValidationManager {
    /// Create a new ValidationManager for the given base path
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        let base_path = base_path.as_ref().to_path_buf();
        let validate_dir = base_path.join("validate");
        let witness_dir = base_path.join("witness");
        let chain_status_file = base_path.join("chain.status");

        Self {
            base_path,
            validate_dir,
            witness_dir,
            chain_status_file,
        }
    }

    /// Generate a standard validation file name for a block
    fn validate_file_name(&self, block_num: BlockNumber, block_hash: BlockHash) -> String {
        format!("{}.{}.v", block_num, block_hash)
    }

    /// Generate a standard witness file name for a block
    fn witness_file_name(&self, block_num: BlockNumber, block_hash: BlockHash) -> String {
        format!("{}.{}.w", block_num, block_hash)
    }

    /// Loads the `ValidateInfo` for a specific block from a file
    /// from validate or backup directory.
    /// If the file does not exist, it returns a default `ValidateInfo` instance.
    pub fn load_validate_info(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> Result<ValidateInfo> {
        let validate_path = self
            .validate_dir
            .join(self.validate_file_name(block_number, block_hash));
        let backup_path = self.backup_file_path(block_number, block_hash, ".v");

        if !validate_path.exists() && !backup_path.exists() {
            return Ok(ValidateInfo::default());
        }

        load_binary_data(validate_path, backup_path, block_number, block_hash)
    }

    /// Sets and saves the validation status and other metadata for a block.
    ///
    /// This function loads the existing `ValidateInfo`, updates its fields with the provided
    /// values, and then saves it back to a file atomically.
    pub fn set_validate_status(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        status: ValidateStatus,
        state_root: Option<B256>,
        lock_time: Option<u64>,
        blob_ids: Option<Vec<[u8; 32]>>,
    ) -> Result<()> {
        let mut validate_info = self.load_validate_info(block_number, block_hash)?;
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

        self.save_validate_info(block_number, block_hash, validate_info)
    }

    /// Saves the `ValidateInfo` to a file atomically.
    ///
    /// This is achieved by writing to a temporary file first and then renaming it to the
    /// final destination. This ensures that a reader will never see a partially written file.
    fn save_validate_info(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        validate_info: ValidateInfo,
    ) -> Result<()> {
        let serialized = bincode::serde::encode_to_vec(&validate_info, bincode::config::legacy())?;
        let serialized = serialized_state_data(serialized)?;

        let final_path = self
            .validate_dir
            .join(self.validate_file_name(block_number, block_hash));
        write_atomic(final_path, &serialized)
    }

    /// Loads the `WitnessStatus` for a specific block from a file
    /// from witness or backup directory.
    pub fn load_witness_status(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> Result<WitnessStatus> {
        let witness_path = self
            .witness_dir
            .join(self.witness_file_name(block_number, block_hash));
        let backup_path = self.backup_file_path(block_number, block_hash, ".w");

        load_binary_data(witness_path, backup_path, block_number, block_hash)
    }

    /// Get block witness status by given block number and block hash
    ///
    /// Loads witness status from file or returns default idle status if file doesn't exist.
    pub fn get_witness_state(&self, block: &(BlockNumber, BlockHash)) -> Result<WitnessStatus> {
        let path = self
            .witness_dir
            .join(self.witness_file_name(block.0, block.1));
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
            bincode::serde::decode_from_slice(&state_data.data, bincode::config::legacy())
                .map_err(|e| {
                    anyhow!(
                        "block({:?}): Failed to deserialize WitnessStatus: {}",
                        block,
                        e
                    )
                })?;
        Ok(deserialized.0)
    }

    /// Reads the block hash for a given block number from a witness file name.
    ///
    /// Witness files are named `{block_number}.{block_hash}.w`. This function scans the witness
    /// directory to find a file matching the block number and extracts the hash from its name.
    pub fn find_block_hashes(&self, block_number: u64) -> Result<Vec<B256>> {
        let witness_dir = &self.witness_dir;
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
                &self.witness_dir
            ))
        } else {
            Ok(hashes)
        }
    }

    /// Get the chain status from file
    ///
    /// Reads chain status from the `chain.status` file in JSON format.
    pub fn get_chain_status(&self) -> Result<ChainStatus> {
        let path = &self.chain_status_file;
        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let status: ChainStatus = serde_json::from_str(&contents)?;
        Ok(status)
    }

    /// Parse block number and hash from witness file name
    ///
    /// Parses both the block number and block hash from a witness file name with format
    /// `{block_number}.{block_hash}.w`.
    ///
    /// # Arguments
    /// * `filename` - The witness file name to parse
    ///
    /// # Returns
    /// A tuple containing (block_number, block_hash). Returns (0, BlockHash::ZERO) if parsing fails.
    ///
    /// # Example
    /// ```rust
    /// use validator_core::ValidationManager;
    /// use alloy_primitives::BlockHash;
    ///
    /// let (number, hash) = ValidationManager::parse_filename("280.0x03c5cb583df6c35f9dcca041f2aa609fce1ad92e170c96c694ce9a6bd3913df1.w");
    /// assert_eq!(number, 280);
    /// assert_ne!(hash, BlockHash::ZERO);
    ///
    /// let (invalid_num, invalid_hash) = ValidationManager::parse_filename("invalid.w");
    /// assert_eq!(invalid_num, 0);
    /// assert_eq!(invalid_hash, BlockHash::ZERO);
    /// ```
    pub fn parse_filename(filename: &str) -> (BlockNumber, BlockHash) {
        let parts: Vec<&str> = filename.split('.').collect();

        // Extract block number from first part
        let block_number = parts
            .first()
            .and_then(|s| s.parse::<BlockNumber>().ok())
            .unwrap_or(0);

        // Extract block hash from second part
        let block_hash = if let Some(hash_str) = parts.get(1) {
            // Try to decode hex string, handling both with and without 0x prefix
            let hash_bytes = if let Some(stripped) = hash_str.strip_prefix("0x") {
                hex::decode(stripped).unwrap_or_default()
            } else {
                hex::decode(hash_str).unwrap_or_default()
            };

            // Return zero hash if decoding failed or wrong length
            if hash_bytes.len() != 32 {
                BlockHash::ZERO
            } else {
                BlockHash::from_slice(&hash_bytes)
            }
        } else {
            BlockHash::ZERO
        };

        (block_number, block_hash)
    }

    /// Generate backup file path for a block
    ///
    /// Creates a hierarchical backup file path using block number and hash,
    /// organized into directories based on shifted block numbers for efficient storage.
    ///
    /// # Arguments
    /// * `block_num` - The block number
    /// * `block_hash` - The block hash
    /// * `ext` - File extension (e.g., ".w" for witness files)
    ///
    /// # Returns
    /// Backup file path relative to the base path
    ///
    /// # Example
    /// ```rust
    /// use validator_core::ValidationManager;
    /// use alloy_primitives::{BlockHash, B256};
    /// use std::path::Path;
    ///
    /// let mgr = ValidationManager::new(Path::new("/data"));
    /// let hash = BlockHash::from([1u8; 32]);
    /// let path = mgr.backup_file_path(1000, hash, ".w");
    /// assert!(path.to_string_lossy().contains("backup"));
    /// ```
    pub fn backup_file_path(
        &self,
        block_num: BlockNumber,
        block_hash: BlockHash,
        ext: &str,
    ) -> PathBuf {
        self.base_path.join(format!(
            "backup/{}/{}.{:x}{}",
            block_num >> BACKUP_SHIFT,
            block_num,
            block_hash,
            ext
        ))
    }

    /// Generate backup directory path for a block range
    ///
    /// Creates the backup directory path based on shifted block numbers,
    /// used to organize backup files hierarchically.
    ///
    /// # Arguments
    /// * `block_num` - The block number to generate directory path for
    ///
    /// # Returns
    /// Backup directory path relative to the base path
    ///
    /// # Example
    /// ```rust
    /// use validator_core::ValidationManager;
    /// use std::path::Path;
    ///
    /// let mgr = ValidationManager::new(Path::new("/data"));
    /// let dir = mgr.backup_dir_path(1000);
    /// assert!(dir.to_string_lossy().contains("backup"));
    /// ```
    pub fn backup_dir_path(&self, block_num: BlockNumber) -> PathBuf {
        self.base_path
            .join(format!("backup/{}", block_num >> BACKUP_SHIFT))
    }

    /// Retrieve blob IDs for a set of validated blocks.
    ///
    /// This method processes a list of block identifiers (formatted as `"{number}.{hash}"`),
    /// checks their validation status from the local file system, and returns the associated
    /// blob IDs if validation was successful.
    ///
    /// # Arguments
    ///
    /// * `blocks` - A `Vec` of strings, each identifying a block in the format "{number}.{hash}".
    ///
    /// # Returns
    ///
    /// Returns a `HashMap` from the block identifier string to a `Vec` of `B256` blob IDs.
    /// Returns a `jsonrpsee` `ErrorObjectOwned` if any block is invalid, not found, or has
    /// not yet been successfully validated.
    pub fn get_blob_ids(
        &self,
        blocks: Vec<String>,
    ) -> Result<StdHashMap<String, Vec<B256>>, ErrorObjectOwned> {
        let mut results = StdHashMap::new();

        for block in blocks {
            let (block_number, block_hash) = Self::parse_filename(&block);

            // Validate that parsing was successful (not default values)
            if block_number == 0 && block_hash == BlockHash::ZERO {
                return Err(ErrorObject::owned(
                    INVALID_PARAMS_CODE,
                    format!("invalid block identifier format: {}", block),
                    None::<()>,
                ));
            }

            let validation = self
                .load_validate_info(block_number, block_hash)
                .map_err(|e| {
                    ErrorObject::owned(CALL_EXECUTION_FAILED_CODE, e.to_string(), None::<()>)
                })?;

            match validation.status {
                ValidateStatus::Failed => {
                    return Err(ErrorObject::owned(
                        UNKNOWN_ERROR_CODE,
                        format!("This block {block_number} validation failed"),
                        None::<()>,
                    ));
                }
                ValidateStatus::Idle => {
                    return Err(ErrorObject::owned(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("This block {block_number} is too old or not validated yet"),
                        None::<()>,
                    ));
                }
                ValidateStatus::Processing => {
                    return Err(ErrorObject::owned(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("This block {block_number} in processing"),
                        None::<()>,
                    ));
                }
                ValidateStatus::Success => {
                    results.insert(
                        block,
                        validation.blob_ids.into_iter().map(B256::from).collect(),
                    );
                }
            }
        }

        Ok(results)
    }

    /// Get the witness for a block.
    ///
    /// This method parses a block identifier in the format "{number}.{parent_hash}",
    /// finds the corresponding witness file, and returns the witness data as a hex-encoded string.
    ///
    /// # Arguments
    ///
    /// * `block_info` - A string identifying a block in the format "{number}.{parent_hash}".
    ///
    /// # Returns
    ///
    /// Returns the witness data as a hex-encoded string if successful.
    /// Returns a `jsonrpsee` `ErrorObjectOwned` if the block is not found or parsing fails.
    pub fn get_witness(&self, block_info: String) -> Result<String, ErrorObjectOwned> {
        let (block_number, parent_hash) = Self::parse_filename(&block_info);

        // Validate that parsing was successful (not default values)
        if block_number == 0 && parent_hash == BlockHash::ZERO {
            return Err(ErrorObject::owned(
                INVALID_PARAMS_CODE,
                format!("invalid block identifier format: {}", block_info),
                None::<()>,
            ));
        }

        // get the witness from witness directory
        let block_hashes = self.find_block_hashes(block_number).map_err(|_| {
            ErrorObject::owned(
                INVALID_PARAMS_CODE,
                format!("not found block number: {}", block_number),
                None::<()>,
            )
        })?;

        for block_hash in block_hashes {
            let witness = self
                .load_witness_status(block_number, block_hash)
                .map_err(|e| {
                    ErrorObject::owned(
                        INVALID_PARAMS_CODE,
                        format!("block {block_number} err:{e}"),
                        None::<()>,
                    )
                })?;
            if witness.parent_hash == parent_hash {
                // Return the witness data as a hex-encoded string
                return Ok(hex::encode(&witness.witness_data));
            }
        }

        Err(ErrorObject::owned(
            INVALID_PARAMS_CODE,
            format!("not found witness for block {block_info}"),
            None::<()>,
        ))
    }
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

/// Serialize state data to a byte vector with integrity hash
///
/// Creates a `StateData` wrapper around the input data, computes a BLAKE3 hash,
/// and serializes the entire structure using bincode with legacy configuration.
///
/// # Arguments
/// * `data` - Raw data to serialize and protect with hash verification
///
/// # Returns
/// * `Ok(Vec<u8>)` - Serialized StateData with embedded hash
/// * `Err(std::io::Error)` - If serialization fails
///
/// # Example
/// ```rust,no_run
/// use validator_core::serialized_state_data;
///
/// let data = b"Hello, world!".to_vec();
/// let serialized = serialized_state_data(data)?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn serialized_state_data(data: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&data);
    let hash = B256::from_slice(hasher.finalize().as_bytes());

    let state_data = StateData { hash, data };
    bincode::serde::encode_to_vec(&state_data, bincode::config::legacy()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to serde state data: {}", e),
        )
    })
}

/// Deserialize state data from a byte vector with hash verification
///
/// Deserializes a `StateData` structure and verifies the embedded BLAKE3 hash
/// matches the actual data hash to ensure data integrity.
///
/// # Arguments
/// * `data` - Serialized StateData bytes to deserialize and verify
///
/// # Returns
/// * `Ok(StateData)` - Successfully deserialized and verified data
/// * `Err(std::io::Error)` - If deserialization fails or hash verification fails
///
/// # Errors
/// * `InvalidData` - If bincode deserialization fails
/// * `InvalidData` - If hash verification fails (data corruption detected)
///
/// # Example
/// ```rust,no_run
/// use validator_core::{serialized_state_data, deserialized_state_data};
///
/// let original = b"test data".to_vec();
/// let serialized = serialized_state_data(original.clone())?;
/// let state_data = deserialized_state_data(serialized)?;
/// assert_eq!(state_data.data, original);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn deserialized_state_data(data: Vec<u8>) -> std::io::Result<StateData> {
    let deserialized: (StateData, usize) =
        bincode::serde::decode_from_slice(&data, bincode::config::legacy()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize state data: {}", e),
            )
        })?;
    let state_data = deserialized.0;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&state_data.data);
    let hash = B256::from_slice(hasher.finalize().as_bytes());
    if state_data.hash != hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Hash mismatch",
        ));
    }

    Ok(state_data)
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
        let val_manager = ValidationManager::new(&path);
        let res = val_manager.load_validate_info(1, dummy_block_hash());
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
        let val_manager = ValidationManager::new(&path);
        let file_name = val_manager.validate_file_name(block_number, block_hash);
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

        let loaded = val_manager
            .load_validate_info(block_number, block_hash)
            .unwrap();
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

        let val_manager = ValidationManager::new(&path);
        let block_number = 2u64;
        let block_hash = dummy_block_hash();
        let backup_file = val_manager.backup_file_path(block_number, block_hash, ".v");

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

        let val_manager = ValidationManager::new(&path);
        let loaded = val_manager
            .load_validate_info(block_number, block_hash)
            .unwrap();
        assert_eq!(loaded, info);
    }
}
