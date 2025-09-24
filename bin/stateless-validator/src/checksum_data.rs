//! Checksum data handling with BLAKE3 hash verification
//!
//! This module provides functionality for handling serialized data with cryptographic
//! hash verification to ensure data integrity during storage and deserialization.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Container for file storage content with BLAKE3 hash verification
///
/// This structure wraps raw data with a cryptographic hash to ensure data integrity
/// during serialization, storage, and deserialization operations.
#[derive(Debug, Deserialize, Serialize)]
pub struct ChecksumData {
    /// BLAKE3 hash for data integrity verification
    pub hash: B256,
    /// Raw data stored as byte vector
    pub data: Vec<u8>,
}

/// Deserialize checksum data from a byte vector with hash verification
///
/// Deserializes a `ChecksumData` structure and verifies the embedded BLAKE3 hash
/// matches the actual data hash to ensure data integrity.
///
/// # Arguments
/// * `data` - Serialized ChecksumData bytes to deserialize and verify
///
/// # Returns
/// * `Ok(ChecksumData)` - Successfully deserialized and verified data
/// * `Err(std::io::Error)` - If deserialization fails or hash verification fails
///
/// # Errors
/// * `InvalidData` - If bincode deserialization fails
/// * `InvalidData` - If hash verification fails (data corruption detected)
///
/// # Example
/// ```rust,no_run
/// use crate::checksum_data::deserialized_checksum_data;
///
/// let serialized = vec![/* serialized data */];
/// let checksum_data = deserialized_checksum_data(serialized)?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn deserialized_checksum_data(data: Vec<u8>) -> std::io::Result<ChecksumData> {
    let (checksum_data, _): (ChecksumData, usize) =
        bincode::serde::decode_from_slice(&data, bincode::config::legacy()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize checksum data: {}", e),
            )
        })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&checksum_data.data);
    if checksum_data.hash != B256::from_slice(hasher.finalize().as_bytes()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Hash mismatch",
        ));
    }

    Ok(checksum_data)
}
