//! Stateless Validator Core Library
//!
//! This library provides the core functionality for stateless blockchain validation,
//! including witness data handling, file I/O operations, and validation logic.
//!
//! ## Key Components
//!
//! - **StateData**: Wrapper for serialized data with BLAKE3 hash verification
//! - **File Management**: Functions for witness file naming, backup storage, and I/O
//! - **Serialization**: Bincode-based serialization with integrity checking
//! - **Validation Logic**: Core validation algorithms for stateless operation
//!
//! ## Modules
//!
//! - [`chain`]: Chain status and finalization tracking
//! - [`witness`]: Witness data generation and state management  
//! - [`provider`]: Stateless database provider for REVM
//! - [`evm`]: EVM-specific validation logic and data types
//! - [`storage`]: File system storage and backup management
//! - [`client`]: External service communication
//! - [`evm`]: EVM-specific validation logic
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use validator_core::{StateData, serialized_state_data, deserialized_state_data};
//!
//! // Serialize data with hash verification
//! let data = vec![1, 2, 3, 4];
//! let serialized = serialized_state_data(data)?;
//!
//! // Deserialize and verify integrity
//! let state_data = deserialized_state_data(serialized)?;
//! # Ok::<(), std::io::Error>(())
//! ```

pub mod chain;
pub use chain::*;
pub mod witness;
pub use witness::*;
pub mod provider;
pub use provider::*;
pub mod storage;
pub use storage::*;
pub mod client;
pub use client::*;
pub mod evm;
pub use evm::*;

use alloy_primitives::{B256, BlockHash, BlockNumber, hex};
use serde::{Deserialize, Serialize};

/// The number of blocks to shift for backup file naming
/// This is used to create a directory structure for backups, allowing for efficient storage
const BACKUP_SHIFT: BlockNumber = 10;

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

/// Extract block number from witness file name
///
/// Parses the block number from a witness file name with format `{block_number}.{block_hash}.w`
///
/// # Arguments
/// * `file_name` - The witness file name to parse
///
/// # Returns
/// Block number extracted from the file name, or 0 if parsing fails
///
/// # Example
/// ```rust
/// use validator_core::file_name_number;
///
/// let number = file_name_number("280.0x03c5cb583df6c35f9dcca041f2aa609fce1ad92e170c96c694ce9a6bd3913df1.w");
/// assert_eq!(number, 280);
///
/// let invalid = file_name_number("invalid.w");
/// assert_eq!(invalid, 0);
/// ```
pub fn file_name_number(file_name: &str) -> BlockNumber {
    file_name
        .split('.')
        .next()
        .and_then(|s| s.parse::<BlockNumber>().ok())
        .unwrap_or(0)
}

/// Extract block hash from witness file name
///
/// Parses the block hash from a witness file name with format `{block_number}.{block_hash}.w`
///
/// # Arguments
/// * `file_name` - The witness file name to parse
///
/// # Returns
/// Block hash extracted from the file name, or zero hash if parsing fails
///
/// # Example
/// ```rust
/// use validator_core::file_name_hash;
/// use alloy_primitives::BlockHash;
///
/// let hash = file_name_hash("280.0x03c5cb583df6c35f9dcca041f2aa609fce1ad92e170c96c694ce9a6bd3913df1.w");
/// assert_ne!(hash, BlockHash::ZERO);
///
/// let invalid = file_name_hash("invalid.w");
/// assert_eq!(invalid, BlockHash::ZERO);
/// ```
pub fn file_name_hash(file_name: &str) -> BlockHash {
    let hash_str = file_name.split('.').nth(1).unwrap_or("");

    // Try to decode hex string, handling both with and without 0x prefix
    let hash_bytes = if let Some(stripped) = hash_str.strip_prefix("0x") {
        hex::decode(stripped).unwrap_or_default()
    } else {
        hex::decode(hash_str).unwrap_or_default()
    };

    // Return zero hash if decoding failed or wrong length
    if hash_bytes.len() != 32 {
        return BlockHash::ZERO;
    }

    BlockHash::from_slice(&hash_bytes)
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
/// Backup file path string in format `backup/{shifted_block}/{block_num}.{block_hash}{ext}`
///
/// # Example
/// ```rust
/// use validator_core::backup_file;
/// use alloy_primitives::{BlockHash, B256};
///
/// let hash = BlockHash::from([1u8; 32]);
/// let path = backup_file(1000, hash, ".w");
/// assert!(path.starts_with("backup/"));
/// ```
pub fn backup_file(block_num: BlockNumber, block_hash: BlockHash, ext: &str) -> String {
    format!(
        "backup/{}/{}.{:x}{}",
        block_num >> BACKUP_SHIFT,
        block_num,
        block_hash,
        ext
    )
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
/// Backup directory path string
///
/// # Example
/// ```rust
/// use validator_core::backup_dir;
///
/// let dir = backup_dir(1000);
/// assert!(dir.starts_with("backup/"));
/// ```
pub fn backup_dir(block_num: BlockNumber) -> String {
    format!("backup/{}", block_num >> BACKUP_SHIFT)
}
