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
    /// Stable 64-bit ids of all non-zero coverage counters (sorted, deduped),
    /// restricted to symbols matching the configured filter.
    pub counters: Vec<u64>,
    /// Path of the per-block profraw written by the worker.
    pub profraw: PathBuf,
    /// Path of the sidecar TSV (zstd) mapping counter ids to symbol details.
    pub symbols_tsv: PathBuf,
    pub elapsed_ms: u64,
    pub tx_count: u64,
    pub gas_used: u64,
}
