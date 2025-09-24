//! Witness status types for test and utility functionality
//!
//! This module contains types related to witness status tracking that are used
//! by tests and utilities but are not part of the core validator library.

use alloy_primitives::{BlockHash, BlockNumber, B256};
use serde::{Deserialize, Serialize};

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