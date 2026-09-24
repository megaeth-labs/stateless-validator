//! JSONL protocol between the dispatcher and resident worker subprocesses.
//!
//! One request line in, one response line out. Workers are long-lived and
//! process blocks strictly one at a time (the LLVM counters are process-global,
//! so per-block isolation comes from reset→execute→write within one worker).
//! Both ends share the data dir, so a block's files are named by its number
//! alone (`DataDir::spool_entry`, `DataDir::block_profdata`).

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
    /// Sanity comparison against the block header (only meaningful without
    /// an `error`).
    pub gas_ok: bool,
    pub receipts_root_ok: bool,
    pub logs_bloom_ok: bool,
    /// Stable 64-bit ids of all covered items (sorted, deduped) within the
    /// configured source scope — see `llvm.rs` for what an item is.
    pub counters: Vec<u64>,
    /// The covered items this worker process has not reported before — all
    /// of them on its first block, next to none after that. The judge needs
    /// their provenance only for ids its store has never seen, and every
    /// earlier response of this worker reached the judge first (one worker,
    /// one ordered channel; any failed block stops the run).
    pub new_items: Vec<CoveredItem>,
    pub elapsed_ms: u64,
    pub tx_count: u64,
    pub gas_used: u64,
}
