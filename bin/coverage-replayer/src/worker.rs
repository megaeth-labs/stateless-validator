//! Resident coverage worker subprocess (`internal-worker`): reads one JSONL [`WorkerRequest`] per
//! stdin line, replays the block with per-block counter isolation, and answers with one
//! [`WorkerResponse`] on stdout, which it holds exclusively (see [`protocol_channel`]).
//!
//! It does not verify the witness or state roots (the production validator does); it only
//! compares `gas_used` / `receipts_root` / `logs_bloom` with the header, which catches
//! chain-spec drift before it can poison the coverage store.

use std::{
    fs::File,
    io::{BufRead, Write as _},
    path::{Path, PathBuf},
    time::Instant,
};

use alloy_primitives::{B256, map::HashMap};
use alloy_rpc_types_eth::Block;
use clap::Args;
use eyre::{Context, Result};
use mega_evm::{MegaPrecompiles, MegaSpecId};
use op_alloy_rpc_types::Transaction as OpTransaction;
use revm::{context_interface::cfg::GasParams, primitives::hardfork::SpecId, state::Bytecode};
use stateless_core::{
    LightWitness, LightWitnessExecutor, ValidationError, WitnessDatabase, WitnessExternalEnv,
    chain_spec::ChainSpec, executor::BlockExecutionOutput, replay_block,
};

use crate::{
    llvm::{Llvm, LlvmArgs},
    proto::{WorkerRequest, WorkerResponse},
    spool::{DataDir, SpoolEntry},
};

#[derive(Args, Debug, Clone)]
pub struct WorkerArgs {
    /// Genesis JSON path used to reconstruct the ChainSpec.
    #[clap(long)]
    pub genesis_file: String,
    /// The run's data directory: contract codes in, per-block profiles out.
    #[clap(long)]
    pub data_dir: PathBuf,
    /// Resolved by the dispatcher (`Llvm::to_args`), so all workers share one scope and toolset.
    #[clap(flatten)]
    pub llvm: LlvmArgs,
}

/// Loads the chain spec a worker replays under. The dispatcher calls it up front too: a worker
/// that cannot start looks like one that crashed mid-block, and blocks are retried forever, so a
/// bad `--genesis-file` must fail the run rather than wedge it in a respawn loop.
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
    let dirs = DataDir::new(&args.data_dir);
    let llvm = args.llvm.resolve()?;
    // llvm-cov reads the coverage map from the binary that wrote the profile: this one.
    let exe = crate::profile_rt::own_executable()?;
    warm_up();

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: WorkerRequest = serde_json::from_str(&line)
            .map_err(|e| eyre::eyre!("bad worker request {line:?}: {e}"))?;
        let resp = process_block(&dirs, &llvm, &exe, &chain_spec, &req)
            .unwrap_or_else(|e| error_response(req.block, format!("{e:#}")));
        let mut frame = serde_json::to_vec(&resp)?;
        frame.push(b'\n');
        protocol.write_all(&frame)?;
    }
    Ok(())
}

/// Takes stdout for the protocol alone: returns a private duplicate of fd 1 and points fd 1 at
/// stderr. Any print in the replay stack (`println!`, C `printf`) could otherwise tear a response
/// frame and stall its block forever, since blocks are never killed. Runs first in the worker,
/// so nothing is buffered for fd 1 yet.
fn protocol_channel() -> Result<File> {
    use std::os::fd::AsFd;
    let protocol = std::io::stdout().as_fd().try_clone_to_owned().wrap_err("duplicate stdout")?;
    // SAFETY: dup2 on two descriptors that are open for the life of the
    // process; it closes and replaces fd 1 atomically and touches no memory.
    let rc = unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) };
    eyre::ensure!(rc != -1, "redirect stdout to stderr: {}", std::io::Error::last_os_error());
    Ok(File::from(protocol))
}

/// Builds the measured code's run-once tables before any block is captured: the per-hardfork
/// precompile tables mega-evm and op-revm build once per process (`OnceBox::get_or_init`), and
/// revm's per-hardfork gas tables (`GasParams::new_spec`, one `OnceLock` per spec group), which
/// every block's `CfgEnv` reaches. Left to the blocks, the first block to meet a table would be
/// credited with it, so a block's coverage would depend on its place in a worker's queue;
/// `process_block`'s counter reset discards the warm-up. Both spec sets are enumerated rather
/// than listed, so a spec added by a dependency bump is warmed too.
fn warm_up() {
    for &spec in MegaSpecId::ALL {
        let _ = MegaPrecompiles::new_with_spec(spec);
    }
    for spec in (0..=u8::MAX).filter_map(SpecId::try_from_u8) {
        let _ = GasParams::new_spec(spec);
    }
}

/// One captured replay: its outcome and its wall-clock.
struct Captured {
    output: std::result::Result<BlockExecutionOutput, ValidationError>,
    replay_ms: u64,
}

/// Replays `block` from its witness with per-block counter isolation — the counters reset just
/// before the replay and the profile written to `profraw` just after — so a profile holds that
/// one replay. The worker's one capture sequence, shared with the warm-up guard so that the
/// guard tests what a worker does.
fn replay_captured(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    light_witness: LightWitness,
    contracts: &HashMap<B256, Bytecode>,
    profraw: &Path,
) -> Result<Captured> {
    let header = &block.header.inner;
    let ext_env = WitnessExternalEnv::from_light_witness(&light_witness, header.number)
        .map_err(|e| eyre::eyre!("env oracle construction: {e}"))?;
    let executor = LightWitnessExecutor::from(light_witness);
    let db = WitnessDatabase { header, witness: &executor, contracts };
    crate::profile_rt::reset_counters();
    let start = Instant::now();
    let output = replay_block(chain_spec, block, &db, ext_env).map(|(_accounts, output)| output);
    let replay_ms = start.elapsed().as_millis() as u64;
    crate::profile_rt::write_profraw(profraw)?;
    Ok(Captured { output, replay_ms })
}

fn error_response(block: u64, error: String) -> WorkerResponse {
    WorkerResponse { block, error: Some(error), ..Default::default() }
}

fn process_block(
    dirs: &DataDir,
    llvm: &Llvm,
    exe: &std::path::Path,
    chain_spec: &ChainSpec,
    req: &WorkerRequest,
) -> Result<WorkerResponse> {
    let start = Instant::now();

    let (block, SpoolEntry { light_witness, code_hashes, .. }) =
        SpoolEntry::open(&dirs.spool_entry(req.block), req.block)?;
    let header = &block.header.inner;
    let contracts = dirs.load_contracts(&code_hashes)?;
    let profraw = dirs.block_profraw(req.block);
    let Captured { output, replay_ms } =
        replay_captured(chain_spec, &block, light_witness, &contracts, &profraw)?;

    let output = match output {
        Ok(output) => output,
        Err(e) => {
            // Execution failed — the bitmap would be misleading, drop it.
            let _ = std::fs::remove_file(&profraw);
            let mut resp = error_response(req.block, format!("replay failed: {e}"));
            resp.block_hash = block.header.hash;
            return Ok(resp);
        }
    };

    let mismatches: Vec<String> = [
        (output.gas_used != header.gas_used)
            .then(|| format!("gas_used {} != header {}", output.gas_used, header.gas_used)),
        (output.receipts_root != header.receipts_root).then(|| {
            format!(
                "receipts_root {:#x} != header {:#x}",
                output.receipts_root, header.receipts_root
            )
        }),
        (output.logs_bloom != header.logs_bloom).then(|| "logs_bloom != header".to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();
    let divergence = (!mismatches.is_empty()).then(|| mismatches.join(", "));

    let extracted = llvm.extract_covered_items(exe, &profraw, &dirs.block_profdata(req.block));
    // The raw profile is large, and the sparse profdata supersedes it either way.
    let _ = std::fs::remove_file(&profraw);
    let counters = extracted?;

    Ok(WorkerResponse {
        block: req.block,
        block_hash: block.header.hash,
        error: None,
        divergence,
        counters,
        replay_ms,
        elapsed_ms: start.elapsed().as_millis() as u64,
        tx_count: block.transactions.len() as u64,
        gas_used: output.gas_used,
    })
}

#[cfg(test)]
mod tests {
    /// Serializes the tests that run measured code: its counters are process-global.
    static MEASURED: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Every worker runs this before its first block: a panic here would crash-loop them all.
    #[test]
    fn warm_up_builds_every_table_without_panicking() {
        let _measured = MEASURED.lock().unwrap_or_else(|e| e.into_inner());
        super::warm_up();
    }

    /// The guard behind `warm_up`: after it, every fixture block's first replay covers exactly
    /// what its second does, so no run-once table that any of them reaches is left for a
    /// worker's first block to be credited with. A dependency bump that adds one fails here,
    /// naming the blocks and how many items each is credited with. It needs the instrumented
    /// build (normal builds compile it out):
    ///
    /// ```text
    /// RUSTC_WRAPPER="$PWD/bin/coverage-replayer/cov-rustc-wrapper.sh" cargo test \
    ///   --profile coverage -p coverage-replayer --bins \
    ///   --target "$(rustc -vV | sed -n 's/host: //p')" -- worker::tests
    /// ```
    #[cfg(coverage_replayer_instrumented)]
    #[test]
    fn every_fixture_block_replays_to_the_same_items_twice() {
        use stateless_test_utils::fixtures::TestFixtures;

        use super::*;

        let _measured = MEASURED.lock().unwrap_or_else(|e| e.into_inner());
        let fixtures = TestFixtures::mainnet_shared();
        let chain_spec = ChainSpec::from_genesis(fixtures.load_genesis().unwrap());
        let llvm = LlvmArgs { source_dirs: Vec::new(), llvm_profdata: None, llvm_cov: None }
            .resolve()
            .unwrap();
        let exe = crate::profile_rt::own_executable().unwrap();
        let dir = tempfile::tempdir().unwrap();

        warm_up();
        let covered = |hash: &B256, round: &str| -> Vec<u64> {
            let profraw = dir.path().join(format!("{round}.profraw"));
            let light = LightWitness::from(&fixtures.salt_witnesses[hash]);
            let block = &fixtures.blocks[hash];
            let captured =
                replay_captured(&chain_spec, block, light, &fixtures.contracts, &profraw).unwrap();
            captured.output.unwrap();
            let profdata = dir.path().join(format!("{round}.profdata"));
            llvm.extract_covered_items(&exe, &profraw, &profdata).unwrap()
        };
        let mut differing = Vec::new();
        for (number, hash) in fixtures.paired_blocks() {
            let (first, second) = (covered(&hash, "first"), covered(&hash, "second"));
            assert!(!first.is_empty(), "block {number} covered nothing in scope");
            let missing_from =
                |a: &[u64], b: &[u64]| a.iter().filter(|id| b.binary_search(id).is_err()).count();
            if first != second {
                differing.push((
                    number,
                    missing_from(&first, &second),
                    missing_from(&second, &first),
                ));
            }
        }
        assert!(
            differing.is_empty(),
            "(block, items only its first replay covers, items only its second does): {differing:?} \
             — a run-once table `warm_up` does not build"
        );
    }
}
