//! Validation manager for the stateless validator.
//! It manages the persistence of validation status, block data, and contract code.

// Table definitions for ValidationManager
const VALIDATE_TABLE: TableDefinition<(u64, [u8; 32]), Vec<u8>> = TableDefinition::new("validate");
const WITNESS_TABLE: TableDefinition<(u64, [u8; 32]), Vec<u8>> = TableDefinition::new("witness");
const CHAIN_STATUS_TABLE: TableDefinition<&str, Vec<u8>> = TableDefinition::new("chain_status");
use alloy_primitives::{B256, BlockHash, BlockNumber, hex};
use eyre::{Result, anyhow};
use jsonrpsee_types::error::{
    CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
    UNKNOWN_ERROR_CODE,
};
use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap as StdHashMap, time::SystemTime};

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

/// Manager for validation operations using redb embedded database
///
/// This is a redb-based version of ValidationManager that provides the same API
/// but uses an embedded database instead of the filesystem for improved performance,
/// ACID transactions, and concurrent access capabilities.
pub struct ValidationManager {
    /// redb database handle
    database: Database,
}

impl ValidationManager {
    /// Create a new ValidationManager with a redb database at the given path
    pub fn new(db_path: impl AsRef<std::path::Path>) -> Result<Self> {
        let database = Database::create(db_path)?;

        // Initialize all tables by opening them in a write transaction
        let write_txn = database.begin_write()?;
        {
            let _validate_table = write_txn.open_table(VALIDATE_TABLE)?;
            let _witness_table = write_txn.open_table(WITNESS_TABLE)?;
            let _chain_status_table = write_txn.open_table(CHAIN_STATUS_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self { database })
    }

    /// Loads the `ValidateInfo` for a specific block from the database.
    /// If the record does not exist, it returns a default `ValidateInfo` instance.
    pub fn load_validate_info(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> Result<ValidateInfo> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(VALIDATE_TABLE)?;

        match table.get((block_number, block_hash.0))? {
            Some(guard) => {
                let state_data = deserialized_state_data(guard.value().to_vec())
                    .map_err(|e| anyhow!("block({block_number}): {}", e))?;
                let (validate_info, _): (ValidateInfo, usize) =
                    bincode::serde::decode_from_slice(&state_data.data, bincode::config::legacy())
                        .map_err(|e| anyhow!("block({block_number}, {block_hash}): Failed to deserialize ValidateInfo: {}", e))?;
                Ok(validate_info)
            }
            None => Ok(ValidateInfo::default()),
        }
    }

    /// Sets and saves the validation status and other metadata for a block.
    ///
    /// This function loads the existing `ValidateInfo`, updates its fields with the provided
    /// values, and then saves it back to the database atomically.
    pub fn set_validate_status(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        status: ValidateStatus,
        state_root: Option<B256>,
        lock_time: Option<u64>,
        blob_ids: Option<Vec<[u8; 32]>>,
    ) -> Result<()> {
        let validate_info = ValidateInfo {
            status,
            block_hash,
            block_number,
            state_root: state_root.unwrap_or_default(),
            lock_time: lock_time.map_or(0, |t| curent_time_to_u64() + t),
            blob_ids: blob_ids.unwrap_or_default(),
        };

        let serialized = serialized_state_data(bincode::serde::encode_to_vec(
            &validate_info,
            bincode::config::legacy(),
        )?)?;

        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(VALIDATE_TABLE)?;
            table.insert((block_number, block_hash.0), serialized)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Loads the `WitnessStatus` for a specific block from the database.
    pub fn load_witness_status(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> Result<WitnessStatus> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(WITNESS_TABLE)?;

        match table.get((block_number, block_hash.0))? {
            Some(guard) => {
                let state_data = deserialized_state_data(guard.value().to_vec())
                    .map_err(|e| anyhow!("block({block_number}): {}", e))?;
                let (witness_status, _): (WitnessStatus, usize) =
                    bincode::serde::decode_from_slice(&state_data.data, bincode::config::legacy())
                        .map_err(|e| anyhow!("block({block_number}, {block_hash}): Failed to deserialize WitnessStatus: {}", e))?;
                Ok(witness_status)
            }
            None => Err(anyhow!(
                "No witness status found for block({block_number}, {block_hash})"
            )),
        }
    }

    /// Saves witness status for a specific block to the database.
    pub fn save_witness_status(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        witness_status: &WitnessStatus,
    ) -> Result<()> {
        let serialized = serialized_state_data(bincode::serde::encode_to_vec(
            witness_status,
            bincode::config::legacy(),
        )?)?;

        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(WITNESS_TABLE)?;
            table.insert((block_number, block_hash.0), serialized)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get block witness status by given block number and block hash
    ///
    /// Loads witness status from database or returns default idle status if record doesn't exist.
    pub fn get_witness_state(&self, block: &(BlockNumber, BlockHash)) -> Result<WitnessStatus> {
        self.load_witness_status(block.0, block.1).or_else(|_| {
            Ok(WitnessStatus {
                status: SaltWitnessState::Idle,
                block_hash: block.1,
                block_number: block.0,
                parent_hash: BlockHash::default(),
                pre_state_root: B256::default(),
                lock_time: curent_time_to_u64(),
                blob_ids: vec![],
                witness_data: vec![],
            })
        })
    }

    /// Reads the block hashes for a given block number from the witness table.
    ///
    /// Scans the witness table to find all records with the matching block number
    /// and returns their block hashes.
    pub fn find_block_hashes(&self, block_number: u64) -> Result<Vec<B256>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(WITNESS_TABLE)?;

        let mut hashes = Vec::new();
        let range_start = (block_number, [0u8; 32]);
        let range_end = (block_number + 1, [0u8; 32]);

        for result in table.range(range_start..range_end)? {
            let (key, _value) = result?;
            let (found_block_number, block_hash_bytes) = key.value();
            if found_block_number == block_number {
                hashes.push(B256::from(block_hash_bytes));
            }
        }

        if hashes.is_empty() {
            Err(anyhow!(
                "No witness records found for block {} in database",
                block_number
            ))
        } else {
            Ok(hashes)
        }
    }

    /// Get the chain status from the database
    ///
    /// Reads chain status from the chain status table.
    pub fn get_chain_status(&self) -> Result<ChainStatus> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(CHAIN_STATUS_TABLE)?;

        match table.get("current")? {
            Some(guard) => Ok(serde_json::from_slice(&guard.value())?),
            None => Ok(ChainStatus::default()),
        }
    }

    /// Set the chain status in the database
    ///
    /// Saves chain status to the chain status table.
    pub fn set_chain_status(&self, chain_status: &ChainStatus) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(CHAIN_STATUS_TABLE)?;
            table.insert("current", serde_json::to_vec(chain_status)?)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Add a new block to be validated with witness data
    ///
    /// This method accepts witness data directly (as would come from network)
    /// and stores it in the database for validation processing.
    pub fn add_new_block(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        parent_hash: BlockHash,
        pre_state_root: B256,
        witness_data: Vec<u8>,
        blob_ids: Vec<[u8; 32]>,
    ) -> Result<()> {
        self.save_witness_status(
            block_number,
            block_hash,
            &WitnessStatus {
                status: SaltWitnessState::Completed,
                block_hash,
                block_number,
                parent_hash,
                pre_state_root,
                lock_time: curent_time_to_u64(),
                blob_ids,
                witness_data,
            },
        )
    }

    /// Parse block number and hash from witness file name
    ///
    /// This is kept as a static method for compatibility with the original ValidationManager.
    pub fn parse_filename(filename: &str) -> (BlockNumber, BlockHash) {
        let parts: Vec<&str> = filename.split('.').collect();

        let block_number = parts
            .first()
            .and_then(|s| s.parse::<BlockNumber>().ok())
            .unwrap_or(0);

        let block_hash = parts
            .get(1)
            .and_then(|hash_str| {
                let hash_bytes = if let Some(stripped) = hash_str.strip_prefix("0x") {
                    hex::decode(stripped).ok()?
                } else {
                    hex::decode(hash_str).ok()?
                };
                (hash_bytes.len() == 32).then(|| BlockHash::from_slice(&hash_bytes))
            })
            .unwrap_or(BlockHash::ZERO);

        (block_number, block_hash)
    }

    /// Retrieve blob IDs for a set of validated blocks.
    ///
    /// This method processes a list of block identifiers (formatted as `"{number}.{hash}"`),
    /// checks their validation status from the database, and returns the associated
    /// blob IDs if validation was successful.
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
    /// finds the corresponding witness records, and returns the witness data as a hex-encoded string.
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

        // Get all witness records for this block number
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
    let state_data = StateData {
        hash: B256::from_slice(hasher.finalize().as_bytes()),
        data,
    };
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
    let (state_data, _): (StateData, usize) =
        bincode::serde::decode_from_slice(&data, bincode::config::legacy()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize state data: {}", e),
            )
        })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&state_data.data);
    if state_data.hash != B256::from_slice(hasher.finalize().as_bytes()) {
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
