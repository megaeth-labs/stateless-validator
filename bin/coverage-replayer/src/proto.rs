//! JSONL protocol between the dispatcher and resident worker subprocesses.
//!
//! One request line in, one response line out. Workers are long-lived and
//! process blocks strictly one at a time (the LLVM counters are process-global,
//! so per-block isolation comes from reset→execute→write within one worker).

use std::path::PathBuf;

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    /// Block number to replay.
    pub block: u64,
    /// Path to the SpoolEntry file.
    pub spool: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub block: u64,
    /// Block hash (zero when the spool entry could not be read).
    pub block_hash: B256,
    /// Replay completed without an execution error.
    pub ok: bool,
    /// Execution error message when `ok == false`.
    pub error: Option<String>,
    /// Sanity comparison against the block header (only meaningful when `ok`).
    pub gas_ok: bool,
    pub receipts_root_ok: bool,
    pub logs_bloom_ok: bool,
    /// Stable 64-bit ids of all covered items (sorted, deduped) within the
    /// configured source scope — see `llvm.rs` for what an item is.
    pub counters: Vec<u64>,
    /// Path of the per-block sparse profdata written by the worker; the judge
    /// archives it when the block's pattern is new and not dominated.
    pub profile: PathBuf,
    /// Provenance of the covered items this worker process has not reported
    /// before — all of them on its first block, next to none after that. The
    /// judge needs it only for ids its store has never seen, and every earlier
    /// response of this worker reached the judge first (one worker, one
    /// ordered channel; any failed block stops the run).
    pub new_items: Vec<ItemDetail>,
    pub elapsed_ms: u64,
    pub tx_count: u64,
    pub gas_used: u64,
}

/// Where a covered item lives, recorded in the store the first time its id is
/// seen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemDetail {
    pub id: u64,
    pub line: u32,
    /// [`crate::llvm::ItemKind::as_str`].
    pub kind: String,
    /// `<source dir name>/<path inside it>:<line>:<col>`.
    pub location: String,
}
