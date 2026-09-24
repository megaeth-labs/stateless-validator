//! Resident coverage worker subprocess.
//!
//! Spawned by the dispatcher as `coverage-replayer internal-worker ...`. Reads
//! one JSONL [`WorkerRequest`] per line from stdin, replays the block with
//! per-block counter isolation (reset → execute → write profraw), extracts the
//! covered items, and answers with one JSONL [`WorkerResponse`] on stdout —
//! which it holds exclusively (see [`protocol_channel`]).
//!
//! The worker deliberately does NOT verify the witness or recompute state
//! roots — correctness is guaranteed by the production stateless validator.
//! It only keeps the free sanity comparison of `gas_used` / `receipts_root` /
//! `logs_bloom` against the block header, which catches chain-spec drift
//! before it can poison the coverage store.

use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, Write as _},
    path::PathBuf,
    time::Instant,
};

use alloy_rpc_types_eth::Block;
use clap::Args;
use eyre::{Context, Result};
use mega_evm::{MegaPrecompiles, MegaSpecId};
use op_alloy_rpc_types::Transaction as OpTransaction;
use stateless_core::{
    LightWitnessExecutor, WitnessDatabase, WitnessExternalEnv, chain_spec::ChainSpec, replay_block,
};

use crate::{
    llvm,
    proto::{ItemDetail, WorkerRequest, WorkerResponse},
    spool::{self, SpoolEntry},
};

#[derive(Args, Debug, Clone)]
pub struct WorkerArgs {
    /// Genesis JSON path used to reconstruct the ChainSpec.
    #[clap(long)]
    pub genesis_file: String,
    /// Content-addressed contract bytecode directory.
    #[clap(long)]
    pub codes_dir: PathBuf,
    /// Directory for per-block profraw / profdata files.
    #[clap(long)]
    pub tmp_dir: PathBuf,
    /// Path to llvm-profdata.
    #[clap(long)]
    pub llvm_profdata: PathBuf,
    /// Path to llvm-cov.
    #[clap(long)]
    pub llvm_cov: PathBuf,
    /// Source directories scoping the coverage universe (resolved by the
    /// dispatcher, so every worker of a run agrees on them).
    #[clap(long = "source-dir", required = true)]
    pub source_dirs: Vec<PathBuf>,
}

/// Loads the chain spec a worker replays under. The dispatcher calls this
/// too, before launching any worker: a worker that cannot start looks, from
/// outside, exactly like one that crashed mid-block, and blocks are retried
/// forever by policy — so a mistyped `--genesis-file` has to fail the run up
/// front rather than wedge it in a respawn loop.
pub fn load_chain_spec(genesis_file: &str) -> Result<ChainSpec> {
    let genesis = serde_json::from_str::<alloy_genesis::Genesis>(
        &std::fs::read_to_string(genesis_file)
            .wrap_err_with(|| format!("read genesis {genesis_file}"))?,
    )
    .wrap_err_with(|| format!("parse genesis {genesis_file}"))?;
    Ok(ChainSpec::from_genesis(genesis))
}

/// Entry point of the worker subprocess. Loops until stdin closes.
pub fn run(args: WorkerArgs) -> Result<()> {
    let mut protocol = protocol_channel()?;
    let chain_spec = load_chain_spec(&args.genesis_file)?;
    // llvm-cov reads the coverage map out of the binary that wrote the
    // profile — this one, as it is running.
    let exe = crate::profile_rt::own_executable()?;
    warm_up();

    let mut reported = HashSet::new();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: WorkerRequest = serde_json::from_str(&line)
            .map_err(|e| eyre::eyre!("bad worker request {line:?}: {e}"))?;
        let resp = process_block(&args, &exe, &chain_spec, &req, &mut reported)
            .unwrap_or_else(|e| error_response(req.block, format!("{e:#}")));
        let mut frame = serde_json::to_vec(&resp)?;
        frame.push(b'\n');
        protocol.write_all(&frame)?;
    }
    Ok(())
}

/// Takes stdout for the protocol alone: returns a private duplicate of fd 1
/// and points fd 1 itself at stderr.
///
/// The replay stack underneath is not ours, and anything in it that prints —
/// a Rust `println!`, a C `printf` — writes to fd 1. On a shared channel such a
/// print can land inside a response frame and tear it, and a torn frame stalls
/// its block forever, since blocks are never killed. With the frames on a
/// descriptor nothing else knows about, every stray print ends up in the
/// worker's log instead. Runs before anything else in the worker, so nothing
/// is buffered for fd 1 yet.
fn protocol_channel() -> Result<File> {
    use std::os::fd::AsFd;
    let protocol = std::io::stdout().as_fd().try_clone_to_owned().wrap_err("duplicate stdout")?;
    // SAFETY: dup2 on two descriptors that are open for the life of the
    // process; it closes and replaces fd 1 atomically and touches no memory.
    let rc = unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) };
    eyre::ensure!(rc != -1, "redirect stdout to stderr: {}", std::io::Error::last_os_error());
    Ok(File::from(protocol))
}

/// Runs the process-lifetime initializers inside the measured code before any
/// block is captured.
///
/// mega-evm and op-revm build each hardfork's precompile table lazily, once
/// per process (`OnceBox::get_or_init`): mega-evm's `rex` and `mini_rex`,
/// op-revm's `isthmus`, `granite` and `fjord`. Left to the blocks, those
/// closures are covered by the first block a worker replays — and the first
/// block of each later table it meets — so the same block records different
/// coverage depending on where it fell in some worker's queue. Built here,
/// they are covered by no block, and `process_block`'s counter reset
/// discards the warm-up itself. The latest spec (`default()`) is included so
/// a table that only it uses is built as well.
fn warm_up() {
    for spec in
        [MegaSpecId::EQUIVALENCE, MegaSpecId::MINI_REX, MegaSpecId::REX, MegaSpecId::default()]
    {
        let _ = MegaPrecompiles::new_with_spec(spec);
    }
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
        profile: PathBuf::new(),
        new_items: Vec::new(),
        elapsed_ms: 0,
        tx_count: 0,
        gas_used: 0,
    }
}

fn process_block(
    args: &WorkerArgs,
    exe: &std::path::Path,
    chain_spec: &ChainSpec,
    req: &WorkerRequest,
    reported: &mut HashSet<u64>,
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
    let result = replay_block(chain_spec, &block, &db, ext_env);
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

    let extracted = llvm::extract_covered_items(
        &args.llvm_profdata,
        &args.llvm_cov,
        exe,
        &profraw,
        &args.source_dirs,
    );
    // The raw profile is large (the whole binary's counter array plus its
    // name table) and the sparse profdata supersedes it either way.
    let _ = std::fs::remove_file(&profraw);
    let (hits, profile) = extracted?;
    let new_items = hits
        .iter()
        .filter(|h| reported.insert(h.id))
        .map(|h| ItemDetail {
            id: h.id,
            line: h.line,
            kind: h.kind.as_str().to_string(),
            location: h.location.clone(),
        })
        .collect();

    Ok(WorkerResponse {
        block: req.block,
        block_hash: block.header.hash,
        ok: true,
        error: None,
        gas_ok,
        receipts_root_ok,
        logs_bloom_ok,
        counters: hits.into_iter().map(|h| h.id).collect(),
        profile,
        new_items,
        elapsed_ms: start.elapsed().as_millis() as u64,
        tx_count: block.transactions.len() as u64,
        gas_used: output.gas_used,
    })
}
