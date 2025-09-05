//! This module provides functionality to generate, store, and manage block witnesses in a file
//! system.
use crate::*;
use alloy_primitives::{BlockHash, BlockNumber};
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Read, path::Path, time::SystemTime};

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

/// get block witness status by given blocknum and blockhash
pub fn get_witness_state(
    path: &Path,
    block: &(BlockNumber, BlockHash),
) -> std::io::Result<WitnessStatus> {
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
    let state_data = deserialized_state_data(contents).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("block({:?}): {}", block, e),
        )
    })?;
    let deserialized =
        bincode::serde::decode_from_slice(&state_data.data, bincode::config::legacy()).map_err(
            |e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "block({:?}): Failed to deserialize  WitnessStatus: {}",
                        block, e
                    ),
                )
            },
        )?;
    Ok(deserialized.0)
}

/// Convert an Instant to a u64 timestamp
pub fn curent_time_to_u64() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH!")
        .as_secs()
}

/// change the witness file name to the given block number and block hash
pub fn witness_file_name(block_num: BlockNumber, block_hash: BlockHash) -> String {
    format!("{}.{}.w", block_num, block_hash)
}
