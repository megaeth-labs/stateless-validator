//! Resident coverage worker subprocess.
//!
//! Spawned by the dispatcher as `coverage-replayer internal-worker ...`. Reads
//! one JSONL [`WorkerRequest`] per line from stdin, replays the block with
//! per-block counter isolation (reset → execute → write profraw), extracts the
//! non-zero counter ids, and answers with one JSONL [`WorkerResponse`].
//!
//! The worker deliberately does NOT verify the witness or recompute state
//! roots — correctness is guaranteed by the production stateless validator.
//! It only keeps the free sanity comparison of `gas_used` / `receipts_root` /
//! `logs_bloom` against the block header, which catches chain-spec drift
//! before it can poison the coverage store.

use std::{
    io::{BufRead, Write as _},
    path::PathBuf,
    time::Instant,
};

use alloy_rpc_types_eth::Block;
use clap::Args;
use eyre::{Context, Result};
use op_alloy_rpc_types::Transaction as OpTransaction;
use stateless_core::{
    LightWitnessExecutor, WitnessDatabase, WitnessExternalEnv, chain_spec::ChainSpec, replay_block,
};

use crate::{
    llvm,
    proto::{WorkerRequest, WorkerResponse},
    spool::{self, SpoolEntry, write_atomic},
};

#[derive(Args, Debug, Clone)]
pub struct WorkerArgs {
    /// Genesis JSON path used to reconstruct the ChainSpec.
    #[clap(long)]
    pub genesis_file: String,
    /// Content-addressed contract bytecode directory.
    #[clap(long)]
    pub codes_dir: PathBuf,
    /// Directory for per-block profraw / symbol sidecar files.
    #[clap(long)]
    pub tmp_dir: PathBuf,
    /// Path to llvm-profdata.
    #[clap(long)]
    pub llvm_profdata: PathBuf,
    /// Substring filter on PGO symbol names (crate scope of the coverage universe).
    #[clap(long, default_value = "mega_evm")]
    pub symbol_filter: String,
}

/// Entry point of the worker subprocess. Loops until stdin closes.
pub fn run(args: WorkerArgs) -> Result<()> {
    let genesis = serde_json::from_str::<alloy_genesis::Genesis>(
        &std::fs::read_to_string(&args.genesis_file)
            .wrap_err_with(|| format!("read genesis {}", args.genesis_file))?,
    )?;
    let chain_spec = ChainSpec::from_genesis(genesis);

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: WorkerRequest = serde_json::from_str(&line)
            .map_err(|e| eyre::eyre!("bad worker request {line:?}: {e}"))?;
        let resp = process_block(&args, &chain_spec, &req)
            .unwrap_or_else(|e| error_response(req.block, format!("{e:#}")));
        serde_json::to_writer(&mut stdout, &resp)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

fn error_response(block: u64, error: String) -> WorkerResponse {
    WorkerResponse {
        block,
        block_hash: alloy_primitives::B256::ZERO,
        ok: false,
        error: Some(error),
        gas_ok: false,
        receipts_root_ok: false,
        logs_bloom_ok: false,
        counters: Vec::new(),
        profraw: PathBuf::new(),
        symbols_tsv: PathBuf::new(),
        elapsed_ms: 0,
        tx_count: 0,
        gas_used: 0,
    }
}

fn process_block(
    args: &WorkerArgs,
    chain_spec: &ChainSpec,
    req: &WorkerRequest,
) -> Result<WorkerResponse> {
    let start = Instant::now();

    let SpoolEntry { block_json, light_witness, code_hashes, .. } =
        SpoolEntry::read_from(&req.spool)?;
    let block: Block<OpTransaction> =
        serde_json::from_slice(&block_json).wrap_err("decode block json")?;
    let header = &block.header.inner;
    eyre::ensure!(header.number == req.block, "spool/request block number mismatch");

    let contracts = spool::load_contracts(&args.codes_dir, &code_hashes)?;
    let ext_env = WitnessExternalEnv::from_light_witness(&light_witness, header.number)
        .map_err(|e| eyre::eyre!("env oracle construction: {e}"))?;
    let executor = LightWitnessExecutor::from(light_witness);
    let db = WitnessDatabase { header, witness: &executor, contracts: &contracts };

    // Per-block counter isolation: this worker handles one block at a time.
    crate::profile_rt::reset_counters();
    let result = replay_block(chain_spec, &block, &db, ext_env, None);
    let profraw = args.tmp_dir.join(format!("block_{}.profraw", req.block));
    crate::profile_rt::write_profraw(&profraw)?;

    let output = match result {
        Ok((_accounts, output)) => output,
        Err(e) => {
            // Execution failed — the bitmap would be misleading, drop it.
            let _ = std::fs::remove_file(&profraw);
            let mut resp = error_response(req.block, format!("replay failed: {e}"));
            resp.block_hash = block.header.hash;
            return Ok(resp);
        }
    };

    let gas_ok = output.gas_used == header.gas_used;
    let receipts_root_ok = output.receipts_root == header.receipts_root;
    let logs_bloom_ok = output.logs_bloom == header.logs_bloom;

    let hits = llvm::extract_nonzero_counters(&args.llvm_profdata, &profraw, &args.symbol_filter)?;

    // Sidecar with full symbol details, read by the dispatcher only for ids it
    // has never seen before (rare after warm-up).
    let symbols_tsv = args.tmp_dir.join(format!("block_{}.symbols.tsv.zst", req.block));
    let mut tsv = String::with_capacity(hits.len() * 96);
    for h in &hits {
        use std::fmt::Write as _;
        let _ = writeln!(tsv, "{:016x}\t{}\t{}\t{}", h.id, h.index, h.func_hash, h.symbol);
    }
    write_atomic(&symbols_tsv, &zstd::encode_all(tsv.as_bytes(), 1)?)?;

    Ok(WorkerResponse {
        block: req.block,
        block_hash: block.header.hash,
        ok: true,
        error: None,
        gas_ok,
        receipts_root_ok,
        logs_bloom_ok,
        counters: hits.into_iter().map(|h| h.id).collect(),
        profraw,
        symbols_tsv,
        elapsed_ms: start.elapsed().as_millis() as u64,
        tx_count: block.transactions.len() as u64,
        gas_used: output.gas_used,
    })
}
