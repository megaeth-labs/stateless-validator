//! this module provides the functionality to save and retrieve block state deltas
// and chain status for the Salt blockchain.

use alloy_primitives::{BlockHash, BlockNumber};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{Read, Result},
    path::Path,
};

/// the chain status, which contains the finalized block number, block hash
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    /// the block number of the finalized block
    pub block_number: BlockNumber,
    /// the block hash of the finalized block
    pub block_hash: BlockHash,
}

/// Get the chain status from file
pub fn get_chain_status(path: &Path) -> Result<ChainStatus> {
    let path = path.join("chain.status");
    let mut file = OpenOptions::new().read(true).open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let status: ChainStatus = serde_json::from_str(&contents)?;
    Ok(status)
}
