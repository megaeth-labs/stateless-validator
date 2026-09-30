//! JSONL protocol between the dispatcher and resident worker subprocesses: one request line in,
//! one response line out, strictly one block at a time per worker (LLVM counters are
//! process-global). Both ends share the data dir, so a block's files are named by its number.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::llvm::CoveredItem;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    /// Block number to replay.
    pub block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub block: u64,
    /// Block hash (zero when the spool entry could not be read).
    pub block_hash: B256,
    /// Why the block could not be replayed; `None` means it was.
    pub error: Option<String>,
    /// Sanity comparison against the block header (only meaningful without an `error`).
    pub gas_ok: bool,
    pub receipts_root_ok: bool,
    pub logs_bloom_ok: bool,
    /// Stable ids of all covered items in scope, sorted and deduped (see `llvm.rs`).
    pub counters: Vec<u64>,
    /// Covered items this worker process has not reported before. The judge needs provenance
    /// only for ids new to its store, and every earlier response of this worker reached it
    /// first (one ordered channel; any failed block stops the run).
    pub new_items: Vec<CoveredItem>,
    pub elapsed_ms: u64,
    pub tx_count: u64,
    pub gas_used: u64,
}
