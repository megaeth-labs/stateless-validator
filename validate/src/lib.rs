//! This module provides the specific stateless storage and validation implementation

pub mod produce;
pub use produce::*;
pub mod generate;
pub use generate::*;
pub mod validator;
pub use validator::*;
pub mod format;
pub use format::*;

use alloy_primitives::{B256, BlockHash, BlockNumber, hex};
use serde::{Deserialize, Serialize};

/// The number of blocks to shift for backup file naming
/// This is used to create a directory structure for backups, allowing for efficient storage
const BACKUP_SHIFT: BlockNumber = 10;

/// Record file storage content and related hash
#[derive(Debug, Deserialize, Serialize)]
pub struct StateData {
    /// validate data integrity
    pub hash: B256,
    /// store state data as u8 vector
    pub data: Vec<u8>,
}

/// Serialize state data to a byte vector
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

/// Deserialize state data from a byte vector
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

/// Get the block number from the file name
pub fn file_name_number(file_name: &str) -> BlockNumber {
    file_name
        .split('.')
        .next()
        .and_then(|s| s.parse::<BlockNumber>().ok())
        .unwrap_or_default()
}

/// Get the block hash from the file name
pub fn file_name_hash(file_name: &str) -> BlockHash {
    let hash_str = file_name.split('.').nth(1).unwrap_or("0x");
    BlockHash::from_slice(&hex::decode(hash_str.as_bytes()).unwrap_or_default())
}

/// Get backup file name from block number
pub fn backup_file(block_num: BlockNumber, block_hash: BlockHash, ext: &str) -> String {
    format!(
        "backup/{}/{}.{}{}",
        block_num >> BACKUP_SHIFT,
        block_num,
        block_hash,
        ext
    )
}

/// Get the backup directory path from the block number
pub fn backup_dir(block_num: BlockNumber) -> String {
    format!("backup/{}", block_num >> BACKUP_SHIFT)
}
