//! Backfill driver: fetch → spool → resident worker pool → judge, all running concurrently:
//!
//! ```text
//! fetch tasks (F) ──spool file──▶ dispatch queue ──▶ worker managers (N, one child each)
//!                                                        │ WorkerResponse
//!                                                        ▼
//!                                                  judge (single consumer, owns redb)
//! ```
//!
//! No block is ever skipped or killed: a scan covers only what it replayed, so a gap would
//! silently shrink the universe. Failed fetches and crashed workers are retried forever and
//! loudly; a slow block is only warned about. A replay error or a header divergence stops
//! the run (fail-stop) with the block recorded, so the next run retries it.

use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockId;
use clap::Args;
use eyre::{Context, Result, bail, ensure};
use rustc_hash::FxHashMap;
use stateless_common::{
    RpcClient, RpcClientConfig, atomic_write::write_scratch, block_list::read_block_list,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    process::Child,
    task::JoinSet,
};
use tracing::{info, warn};

use crate::{
    bitset::BitSet,
    llvm::{Llvm, LlvmArgs},
    proto::{WorkerRequest, WorkerResponse},
    spool::{DataDir, SpoolEntry},
    store::{
        BINARY_ID, BlockRecord, BlockStatus, ElapsedStats, PatternRecord, Store,
        resolve_pattern_slot,
    },
    witness::{R2Args, WitnessSource},
};

#[derive(Args, Debug, Clone)]
pub struct BackfillArgs {
    /// First block of the range (inclusive). Requires `--to`; exclusive with `--blocks-file`.
    #[clap(long)]
    pub from: Option<u64>,
    /// Last block of the range (inclusive). Requires `--from`.
    ///
    /// Scan only final blocks: a resumed run skips cleanly replayed blocks and reuses spool
    /// entries by NUMBER, so a height recorded before a reorg keeps its orphaned hash.
    #[clap(long)]
    pub to: Option<u64>,
    /// Replay an explicit block list instead of a range: one decimal block number per
    /// line, `#` comments and blank lines ignored (the `inspect --dump-pool` format).
    #[clap(long)]
    pub blocks_file: Option<PathBuf>,
    /// Data RPC endpoint(s) (blocks, bytecode).
    #[clap(
        long = "rpc-endpoint",
        env = "COVERAGE_REPLAYER_RPC_ENDPOINT",
        value_delimiter = ',',
        required = true
    )]
    pub rpc_endpoints: Vec<String>,
    /// Witness RPC endpoint(s) (`mega_getBlockWitness`): the only witness path, or the fallback
    /// behind the bucket when the `--r2-*` flags configure one.
    #[clap(
        long = "witness-endpoint",
        env = "COVERAGE_REPLAYER_WITNESS_ENDPOINT",
        value_delimiter = ',',
        required = true
    )]
    pub witness_endpoints: Vec<String>,
    #[clap(flatten)]
    pub r2: R2Args,
    /// Genesis JSON path (e.g. test_data/mainnet/genesis.json).
    #[clap(long, env = "COVERAGE_REPLAYER_GENESIS_FILE")]
    pub genesis_file: String,
    /// Root directory for spool/codes/archive/store.
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Number of resident worker subprocesses (default: cores - 2).
    #[clap(long, env = "COVERAGE_REPLAYER_WORKERS", value_parser = at_least_one())]
    pub workers: Option<usize>,
    /// Concurrent block fetches. Replay is fetch-bound, not compute-bound; raising this
    /// cannot flood the disk, since a full dispatch queue blocks the fetch loop.
    #[clap(long, default_value_t = 32, value_parser = at_least_one())]
    pub fetch_concurrency: usize,
    /// Concurrent requests to the data endpoints, blocks and bytecode alike, across all
    /// fetches. A block fetches every bytecode it lacks at once, so uncapped, one that
    /// references many new contracts can burst past an endpoint's rate limit and stall the
    /// scan in its retry loop. The default leaves room for a bytecode request beside every
    /// block fetch in flight.
    #[clap(
        long,
        env = "COVERAGE_REPLAYER_DATA_MAX_CONCURRENT_REQUESTS",
        default_value_t = 64,
        value_parser = at_least_one()
    )]
    pub data_max_concurrent_requests: usize,
    #[clap(flatten)]
    pub llvm: LlvmArgs,
    /// Interval (seconds) of the "block still executing" warning; blocks never time out.
    #[clap(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..))]
    pub slow_block_warn_secs: u64,
}

/// Parser for the count flags, none of which has a meaning at 0.
fn at_least_one() -> clap::builder::RangedU64ValueParser<usize> {
    clap::builder::RangedU64ValueParser::new().range(1..)
}

/// What this run was asked to replay. A range reads the store's records between its
/// ends; a list looks each member up, as its span may cover the whole history.
enum Selection {
    Range(std::ops::RangeInclusive<u64>),
    List(Vec<u64>),
}

impl Selection {
    /// Exactly one of `--from`/`--to` and `--blocks-file` selects the work.
    fn resolve(args: &BackfillArgs) -> Result<Self> {
        match (args.from, args.to, args.blocks_file.as_deref()) {
            (Some(from), Some(to), None) => {
                ensure!(from <= to, "--from must be <= --to");
                Ok(Self::Range(from..=to))
            }
            (None, None, Some(path)) => Ok(Self::List(read_block_list(path)?)),
            (None, None, None) => bail!("pass either --from with --to, or --blocks-file"),
            (_, _, Some(_)) => bail!("--blocks-file cannot be combined with --from/--to"),
            _ => bail!("--from and --to must be given together"),
        }
    }

    fn len(&self) -> u64 {
        match self {
            Self::Range(r) => r.end() - r.start() + 1,
            Self::List(v) => v.len() as u64,
        }
    }

    /// The highest block asked for — what the chain-tip guard checks.
    fn highest(&self) -> u64 {
        match self {
            Self::Range(r) => *r.end(),
            // `read_block_list` sorts the list and refuses an empty one.
            Self::List(v) => v.last().copied().unwrap_or(0),
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Range(r) => format!("{}..={}", r.start(), r.end()),
            Self::List(v) => {
                format!("{} listed blocks ({}..={})", v.len(), self.lowest(), self.highest())
            }
        }
    }

    fn lowest(&self) -> u64 {
        match self {
            Self::Range(r) => *r.start(),
            Self::List(v) => v.first().copied().unwrap_or(0),
        }
    }

    /// The selected blocks without a clean replay in the store, as ascending ranges (Error/
    /// Divergent records are retried), and how many of them have a record. A range is walked
    /// against the store's rows instead of loading them, and its unscanned stretches stay
    /// ranges: a full-history range has tens of millions of rows, or of blocks yet to scan.
    fn pending(&self, store: &Store) -> Result<(Vec<RangeInclusive<u64>>, Vec<u64>)> {
        let (mut todo, mut retrying) = (Vec::new(), Vec::new());
        match self {
            Self::Range(r) => {
                let mut next = *r.start();
                store.blocks(r.clone(), |n, record| {
                    if next < n {
                        todo.push(next..=n - 1);
                    }
                    if record.status != BlockStatus::Ok {
                        todo.push(n..=n);
                        retrying.push(n);
                    }
                    next = n + 1;
                })?;
                if next <= *r.end() {
                    todo.push(next..=*r.end());
                }
            }
            Self::List(v) => {
                let records = store.block_records(v)?;
                for &n in v {
                    match records.get(&n) {
                        Some(r) if r.status == BlockStatus::Ok => {}
                        Some(_) => {
                            todo.push(n..=n);
                            retrying.push(n);
                        }
                        None => todo.push(n..=n),
                    }
                }
            }
        }
        Ok((todo, retrying))
    }
}

pub async fn run(args: BackfillArgs) -> Result<()> {
    let selection = Selection::resolve(&args)?;
    let rpc_config = RpcClientConfig {
        data_max_concurrent_requests: Some(args.data_max_concurrent_requests),
        ..RpcClientConfig::default()
    };
    // Judged here, like the selection, so a bad `--r2-*` set fails before the data dir is touched.
    let r2 = args.r2.source(rpc_config.rpc_retry)?;
    ensure!(
        crate::profile_rt::is_instrumented_build(),
        "backfill requires the instrumented build (see [profile.coverage] in Cargo.toml)"
    );

    // Validate what every worker needs at startup before spawning any: see `load_chain_spec`.
    crate::worker::load_chain_spec(&args.genesis_file)?;

    let dirs = Arc::new(DataDir::new(&args.data_dir));
    crate::profile_rt::ensure_literal_profile_dir(&dirs.tmp())?;
    dirs.ensure_layout()?;
    info!(binary_id = BINARY_ID, "opening store");
    // Resolved once: all workers must agree on the scope, and a bad one stops the run early.
    let llvm = args.llvm.resolve()?;
    let universe = llvm.universe();
    info!(
        universe,
        llvm_profdata = %llvm.profdata.display(),
        llvm_cov = %llvm.cov.display(),
        "coverage universe"
    );
    let store = Store::open(&dirs.store_path(), BINARY_ID, &universe)?;
    // Only now: the store's exclusive lock means nothing left under the data dir is live.
    let cleared = dirs.clear_leftovers();
    if cleared > 0 {
        info!(cleared, "removed files a previous run left mid-flight");
    }
    let client = Arc::new(RpcClient::new_with_config(
        &args.rpc_endpoints.iter().map(String::as_str).collect::<Vec<_>>(),
        &args.witness_endpoints.iter().map(String::as_str).collect::<Vec<_>>(),
        rpc_config,
        None,
    )?);

    // Listening from here on: the tip check retries forever while RPC is down, and the store
    // is already open, so a signal must stop the run cleanly from this point.
    let mut stop = std::pin::pin!(stop_signal());
    let latest = tokio::select! {
        latest = client.get_latest_block_number() => latest,
        signal = &mut stop => bail!("stopped by {signal} before any block was judged"),
    };
    let highest = selection.highest();
    ensure!(
        highest <= latest,
        "block {highest} is beyond the chain tip {latest}; refusing to wait on unfetchable \
         blocks",
    );
    let witnesses = Arc::new(WitnessSource::new(client.clone(), r2, latest));

    let (todo, retrying) = selection.pending(&store)?;
    discard_spools(&dirs, &retrying);
    let total: u64 = todo.iter().map(|r| r.end() - r.start() + 1).sum();
    info!(
        selection = %selection.label(),
        todo = total,
        skipped = selection.len() - total,
        retrying_quarantined = retrying.len(),
        "backfill starting"
    );
    if todo.is_empty() {
        info!("nothing to do");
        return Ok(());
    }

    let workers = args.workers.unwrap_or_else(|| num_cpus::get().saturating_sub(2).max(1));
    let (dispatch_tx, dispatch_rx) = kanal::bounded_async::<u64>(workers * 2);
    let (judged_tx, mut judged_rx) = tokio::sync::mpsc::channel::<WorkerResponse>(workers * 2);

    let setup = Arc::new(WorkerSetup {
        exe: crate::profile_rt::own_executable()?,
        genesis_file: args.genesis_file.clone(),
        dirs: dirs.clone(),
        llvm,
        warn_after: Duration::from_secs(args.slow_block_warn_secs),
    });
    let mut manager_set = JoinSet::new();
    for id in 0..workers {
        let (rx, tx, setup) = (dispatch_rx.clone(), judged_tx.clone(), setup.clone());
        manager_set.spawn(async move { worker_manager(id, rx, tx, setup).await });
    }
    drop(dispatch_rx);
    drop(judged_tx);

    let verified_codes = Arc::new(VerifiedCodes::default());
    let fetcher = {
        let dirs = dirs.clone();
        let witnesses = witnesses.clone();
        let fetch_concurrency = args.fetch_concurrency;
        tokio::spawn(async move {
            let mut inflight: JoinSet<u64> = JoinSet::new();
            for n in todo.into_iter().flatten() {
                while inflight.len() >= fetch_concurrency {
                    if let Some(done) = inflight.join_next().await {
                        forward_fetched(done, &dispatch_tx).await;
                    }
                }
                let dirs = dirs.clone();
                let client = client.clone();
                let witnesses = witnesses.clone();
                let verified_codes = verified_codes.clone();
                inflight.spawn(async move {
                    let mut attempt = 0u64;
                    let mut block_cache = None;
                    loop {
                        match fetch_block(
                            &client,
                            &witnesses,
                            &dirs,
                            &verified_codes,
                            n,
                            &mut block_cache,
                        )
                        .await
                        {
                            Ok(()) => break n,
                            Err(e) => {
                                attempt += 1;
                                warn!(
                                    block = n,
                                    attempt,
                                    error = %format!("{e:#}"),
                                    "fetch failed; retrying in 5s (blocks are never skipped)"
                                );
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }
                    }
                });
            }
            while let Some(done) = inflight.join_next().await {
                forward_fetched(done, &dispatch_tx).await;
            }
        })
    };

    let mut judge =
        JudgeState::new(store.counters()?, store.patterns()?, &store, dirs.clone(), total);
    let judged: Result<()> = async {
        loop {
            tokio::select! {
                outcome = judged_rx.recv() => match outcome {
                    Some(outcome) => judge.ingest(outcome)?,
                    None => return Ok(()),
                },
                signal = &mut stop => bail!(
                    "stopped by {signal} after {} of {total} blocks; what was judged is \
                     flushed — re-run the same selection to resume",
                    judge.processed,
                ),
            }
        }
    }
    .await;
    // Whatever ended the loop, make what was judged durable before reporting it; a flush
    // failure must not hide why the loop ended.
    let flushed = store.flush();
    if judged.is_err() &&
        let Err(e) = &flushed
    {
        tracing::error!(error = %format!("{e:#}"), "flushing the store after the abort failed");
    }
    // Before any error returns: a stopped run's split is as worth knowing as a finished one's.
    witnesses.log_summary();
    judged?;
    flushed?;

    fetcher.await.ok();
    while manager_set.join_next().await.is_some() {}
    judge.final_summary();
    // The channel closing only means every task is gone: a panicked fetch task or a dead
    // manager drops its block with just a log line, so an incomplete run must not exit 0.
    ensure!(
        judge.processed == total,
        "backfill ended with {} of {total} blocks judged — a fetch or worker task died (see the \
         errors above). Nothing is lost: re-run the same selection to pick up the rest.",
        judge.processed,
    );
    Ok(())
}

/// Resolves on the first SIGINT or SIGTERM, naming it: the judge then stops, flushes and lets
/// the store close cleanly, instead of dying with unflushed commits and a store that read-only
/// openers refuse until a writer repairs it.
async fn stop_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut interrupt), Ok(mut terminate)) =
        (signal(SignalKind::interrupt()), signal(SignalKind::terminate()))
    else {
        warn!("cannot listen for SIGINT/SIGTERM; a signal will stop the run uncleanly");
        return std::future::pending().await;
    };
    tokio::select! {
        _ = interrupt.recv() => "SIGINT",
        _ = terminate.recv() => "SIGTERM",
    }
}

/// Deletes the spool entries of blocks being retried, so they are refetched: a block that
/// failed or diverged may have failed on its spooled bytes (a bad witness, a reorged hash),
/// and replaying the same entry would fail every re-run alike.
fn discard_spools(dirs: &DataDir, blocks: &[u64]) {
    for &n in blocks {
        let _ = std::fs::remove_file(dirs.spool_entry(n));
    }
}

async fn forward_fetched(
    done: std::result::Result<u64, tokio::task::JoinError>,
    dispatch_tx: &kanal::AsyncSender<u64>,
) {
    match done {
        Ok(n) => {
            // Queue closed (all managers dead) is fatal-ish; just log.
            if dispatch_tx.send(n).await.is_err() {
                warn!(block = n, "dispatch queue closed, dropping fetched block");
            }
        }
        // A code bug; the block stays absent from the store, so a re-run picks it up.
        Err(e) => tracing::error!(error = %e, "fetch task panicked — block will need a re-run"),
    }
}

/// Fetches one block + witness, resolves missing bytecodes, writes the spool entry, and
/// skips work already on disk (crash resume). `block_cache` keeps the block across the
/// caller's retries so a later failure does not re-download it.
async fn fetch_block(
    client: &RpcClient,
    witnesses: &WitnessSource,
    dirs: &DataDir,
    verified_codes: &Arc<VerifiedCodes>,
    n: u64,
    block_cache: &mut Option<alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction>>,
) -> Result<()> {
    let spool_path = dirs.spool_entry(n);
    if spool_path.exists() {
        // Opened exactly as the worker opens it, and refetched if unusable: a re-run skips
        // the fetch while the file exists, so a bad entry would fail-stop every restart.
        let existing = {
            let path = spool_path.clone();
            tokio::task::spawn_blocking(move || SpoolEntry::open(&path, n)).await?
        };
        match existing {
            Ok((_, entry)) => {
                // Its codes live in separate files: re-resolve any missing or corrupt ones.
                resolve_missing_codes(client, dirs, verified_codes, entry.code_hashes).await?;
                return Ok(());
            }
            Err(e) => {
                warn!(
                    block = n,
                    spool = %spool_path.display(),
                    error = %format!("{e:#}"),
                    "existing spool entry is corrupt — deleting and refetching"
                );
                std::fs::remove_file(&spool_path)
                    .wrap_err_with(|| format!("remove corrupt spool {}", spool_path.display()))?;
            }
        }
    }

    if block_cache.is_none() {
        // Unchecked on purpose: recovering every transaction's signer can dominate the fetch
        // stage in an instrumented binary. A wrong sender or transaction set cannot reproduce
        // the header's gas, receipts root and logs bloom, which the worker checks after replay.
        // The header hash is checked: it is cheap, and the manifest and witness lookup rely on it.
        let block = client.get_block_unchecked(BlockId::number(n), true).await;
        ensure!(
            block.header.hash_slow() == block.header.hash,
            "block {n}: the RPC header does not hash to the hash it claims ({:#x})",
            block.header.hash,
        );
        *block_cache = Some(block);
    }
    let block = block_cache.as_ref().expect("just filled");
    let hash = block.header.hash;
    // Light fetch: no elliptic-curve work is spent on a proof that is never verified.
    let (light_witness, _mpt_witness) = witnesses.get(n, hash).await;

    let code_hashes = stateless_core::collect_code_hashes(&light_witness.kvs);
    resolve_missing_codes(client, dirs, verified_codes, code_hashes.clone()).await?;

    // Serializing a large block is real CPU work, so it runs on the blocking pool with the write.
    // The block comes back either way, so a failed write keeps it for the caller's retry.
    let block = block_cache.take().expect("just filled");
    let (block, written) = tokio::task::spawn_blocking(move || {
        let written = serde_json::to_vec(&block).map_err(eyre::Report::from).and_then(|json| {
            SpoolEntry { block_json: json.into(), light_witness, code_hashes }.write_to(&spool_path)
        });
        (block, written)
    })
    .await?;
    if written.is_err() {
        *block_cache = Some(block);
    }
    written
}

/// Code files this run already found content-valid, shared by every fetch task so no
/// contract is re-hashed per block. A file verified once stays valid for the run: the
/// codes dir only gains files or has them replaced whole (renamed into place), never deleted.
#[derive(Default)]
struct VerifiedCodes(Mutex<HashSet<B256>>);

impl VerifiedCodes {
    /// The `code_hashes` with no content-valid file; only unverified ones are read from disk.
    fn missing(&self, dirs: &DataDir, code_hashes: &[B256]) -> Vec<B256> {
        let unverified: Vec<B256> = {
            let verified = self.0.lock().expect("verified-codes lock");
            code_hashes.iter().filter(|h| !verified.contains(*h)).copied().collect()
        };
        let (valid, missing): (Vec<B256>, Vec<B256>) =
            unverified.into_iter().partition(|h| code_file_is_valid(&dirs.code_file(h), h));
        self.remember(valid);
        missing
    }

    fn remember(&self, hashes: impl IntoIterator<Item = B256>) {
        self.0.lock().expect("verified-codes lock").extend(hashes);
    }
}

/// Fetches and persists any of `code_hashes` without a content-valid file. The files are
/// content-addressed, so one whose keccak mismatches its name is refetched; a corrupt file
/// would otherwise diverge every replay and fail-stop the run across restarts.
async fn resolve_missing_codes(
    client: &RpcClient,
    dirs: &DataDir,
    verified: &Arc<VerifiedCodes>,
    code_hashes: Vec<B256>,
) -> Result<()> {
    let missing = {
        let (dirs, verified) = (dirs.clone(), verified.clone());
        tokio::task::spawn_blocking(move || verified.missing(&dirs, &code_hashes)).await?
    };
    if missing.is_empty() {
        return Ok(());
    }
    // Verified against their hashes by the fetch itself.
    let codes = client
        .get_codes(&missing, true)
        .await
        .map_err(|e| eyre::eyre!("fetch {} bytecodes: {e}", missing.len()))?;
    let (dirs, verified) = (dirs.clone(), verified.clone());
    tokio::task::spawn_blocking(move || {
        for (code_hash, bytecode) in codes {
            write_scratch(&dirs.code_file(&code_hash), &bytecode.original_bytes())?;
            verified.remember([code_hash]);
        }
        Ok::<_, eyre::Report>(())
    })
    .await?
}

/// Whether `path` holds exactly the bytes hashing to `hash`. An invalid file is left for the
/// caller's refetch to replace by rename: deleting it here could race a concurrent fetch task
/// that read the same bad bytes and has already renamed a repaired file into place.
fn code_file_is_valid(path: &Path, hash: &B256) -> bool {
    match std::fs::read(path) {
        Ok(bytes) if alloy_primitives::keccak256(&bytes) == *hash => true,
        Ok(_) => {
            warn!(
                code = %format!("{hash:x}"),
                path = %path.display(),
                "content-addressed code file fails its hash — refetching"
            );
            false
        }
        Err(_) => false,
    }
}

/// What every worker of a run is launched with, resolved once so they cannot disagree.
struct WorkerSetup {
    /// The running image, so a worker respawned after a rebuild is still this build.
    exe: PathBuf,
    genesis_file: String,
    dirs: Arc<DataDir>,
    llvm: Llvm,
    /// Interval of the "block still executing" warning.
    warn_after: Duration,
}

/// Owns one resident worker child, respawned onto the same block whenever it dies.
async fn worker_manager(
    id: usize,
    rx: kanal::AsyncReceiver<u64>,
    tx: tokio::sync::mpsc::Sender<WorkerResponse>,
    setup: Arc<WorkerSetup>,
) {
    let mut worker: Option<WorkerHandle> = None;
    let (dirs, warn_after) = (&setup.dirs, setup.warn_after);

    while let Ok(n) = rx.recv().await {
        let req = WorkerRequest { block: n };
        let mut attempt = 0u64;
        let resp = loop {
            if worker.is_none() {
                match WorkerHandle::spawn(&setup) {
                    Ok(w) => worker = Some(w),
                    Err(e) => {
                        warn!(worker = id, error = %format!("{e:#}"), "spawn worker failed; retrying in 1s");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
            let w = worker.as_mut().expect("just spawned");
            match w.round_trip(&req, warn_after, id).await {
                Ok(resp) => break resp,
                Err(e) => {
                    attempt += 1;
                    warn!(
                        worker = id,
                        block = n,
                        attempt,
                        error = %format!("{e:#}"),
                        "worker died mid-block; respawning and retrying same block"
                    );
                    // Escalate so an operator can find a wedged block from the error log.
                    if attempt.is_multiple_of(10) {
                        tracing::error!(
                            worker = id,
                            block = n,
                            attempt,
                            spool = %dirs.spool_entry(n).display(),
                            "block has crashed the worker {attempt} times — wedged by policy \
                             (blocks are never skipped); this needs operator attention"
                        );
                    }
                    if let Some(mut dead) = worker.take() {
                        dead.kill().await;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        if tx.send(resp).await.is_err() {
            return; // judge gone (run aborting)
        }
    }
}

struct WorkerHandle {
    child: Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
}

impl WorkerHandle {
    fn spawn(setup: &WorkerSetup) -> Result<Self> {
        let mut child = tokio::process::Command::new(&setup.exe)
            .arg("internal-worker")
            .arg("--genesis-file")
            .arg(&setup.genesis_file)
            .arg("--data-dir")
            .arg(&setup.dirs.root)
            .args(setup.llvm.to_args())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            // Out of the terminal's process group: a Ctrl-C reaches only the dispatcher, which
            // stops the run in order, rather than killing every worker under it at once.
            .process_group(0)
            .spawn()
            .wrap_err("spawn internal-worker")?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Self { child, stdin, stdout: tokio::io::BufReader::new(stdout).lines() })
    }

    /// Sends one request and waits for the response with no deadline; an error means the
    /// child died (closed stdout, bad frame), never slowness.
    async fn round_trip(
        &mut self,
        req: &WorkerRequest,
        warn_after: Duration,
        worker_id: usize,
    ) -> Result<WorkerResponse> {
        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;

        let started = Instant::now();
        let frame = loop {
            match tokio::time::timeout(warn_after, self.stdout.next_line()).await {
                Err(_still_running) => warn!(
                    worker = worker_id,
                    block = req.block,
                    running_secs = started.elapsed().as_secs(),
                    "block still executing — waiting (blocks are never killed)"
                ),
                Ok(next) => {
                    break next?.ok_or_else(|| eyre::eyre!("worker closed stdout (crashed?)"))?;
                }
            }
        };
        // Only worker frames reach this pipe (`worker::protocol_channel`), so anything
        // else means a broken worker, handled like a crash.
        let resp: WorkerResponse = serde_json::from_str(&frame).wrap_err_with(|| {
            format!("malformed worker frame: {}", frame.chars().take(200).collect::<String>())
        })?;
        ensure!(resp.block == req.block, "response for wrong block");
        Ok(resp)
    }

    async fn kill(&mut self) {
        let _ = self.child.kill().await;
    }
}

/// Single-consumer ingest: pattern dedup, promotion, persistence, progress.
struct JudgeState<'a> {
    store: &'a Store,
    dirs: Arc<DataDir>,
    /// Counter id → dense index; its size is the universe's. Ids are already hashes, so
    /// the map need not hash them again.
    counters: FxHashMap<u64, u32>,
    patterns: HashMap<u64, PatternRecord>,
    /// Keys of the antichain: the patterns no other dominates. By transitivity, a new pattern
    /// dominated by anything is dominated by one of these, so the check scans only this set;
    /// a new member evicts the members it dominates, so the set never outgrows the antichain.
    undominated: Vec<u64>,
    processed: u64,
    total: u64,
    new_patterns: u64,
    started: Instant,
    /// Worker wall-clock per successfully replayed block.
    elapsed_ok_ms: ElapsedStats,
}

impl<'a> JudgeState<'a> {
    fn new(
        counters: FxHashMap<u64, u32>,
        patterns: HashMap<u64, PatternRecord>,
        store: &'a Store,
        dirs: Arc<DataDir>,
        total: u64,
    ) -> Self {
        let undominated = crate::setcover::antichain(&patterns);
        info!(universe = counters.len(), known_patterns = patterns.len(), "judge state restored");
        Self {
            store,
            dirs,
            counters,
            patterns,
            undominated,
            processed: 0,
            total,
            new_patterns: 0,
            started: Instant::now(),
            elapsed_ok_ms: ElapsedStats::default(),
        }
    }

    /// Fail-stop: a replay error or divergence is recorded (spool kept for forensics) and
    /// aborts the run; the next run refetches the non-Ok block and retries it.
    fn ingest(&mut self, resp: WorkerResponse) -> Result<()> {
        self.processed += 1;

        if let Some(error) = &resp.error {
            let record = block_record(&resp, BlockStatus::Error, None);
            self.store.commit_block(resp.block, &record, &[], None)?;
            eyre::bail!(
                "block {} failed to replay: {error} — ABORTING (no block may be skipped; \
                 spool kept at {} until a re-run refetches and retries this block)",
                resp.block,
                self.dirs.spool_entry(resp.block).display(),
            );
        }

        if let Some(divergence) = &resp.divergence {
            let record = block_record(&resp, BlockStatus::Divergent, None);
            self.store.commit_block(resp.block, &record, &[], None)?;
            eyre::bail!(
                "SANITY FAILURE at block {} ({divergence}) — execution diverged from the header; \
                 bitmap NOT ingested. ABORTING: this is chain-spec drift or an execution bug, and \
                 continuing would leave a silent coverage gap. Spool kept at {} until a \
                 re-run refetches and retries this block.",
                resp.block,
                self.dirs.spool_entry(resp.block).display(),
            );
        }

        self.ingest_ok(resp)?;
        if self.processed.is_multiple_of(25) || self.processed == self.total {
            self.progress_log();
        }
        Ok(())
    }

    fn ingest_ok(&mut self, resp: WorkerResponse) -> Result<()> {
        self.elapsed_ok_ms.record(resp.elapsed_ms);
        // Counter ids → dense indices; an id new to the store takes the next index.
        let mut new_counters: Vec<(u64, u32)> = Vec::new();
        let mut dense = Vec::with_capacity(resp.counters.len());
        for &id in &resp.counters {
            let next = self.counters.len() as u32;
            dense.push(*self.counters.entry(id).or_insert_with(|| {
                new_counters.push((id, next));
                next
            }));
        }

        let rec =
            PatternRecord::first_seen(BitSet::from_indices(dense), resp.block, resp.replay_ms);
        let profile = self.dirs.block_profdata(resp.block);
        // Worker counters arrive sorted and deduped, as the keying expects.
        let (key, occupied) = resolve_pattern_slot(&self.patterns, &resp.counters, &rec.bitmap);

        if occupied {
            // Known pattern: nothing on disk moves, as profiles are keyed by pattern.
            self.patterns.get_mut(&key).expect("occupied slot").absorb(&rec);
        } else {
            // A dominated pattern (strict subset of an existing one) is excluded from
            // set-cover candidates, so its bitmap is recorded but its profile not archived.
            let dominated = self.undominated.iter().any(|k| self.patterns[k].dominates(&rec));
            self.new_patterns += 1;
            info!(
                block = resp.block,
                pattern = %format!("{key:016x}"),
                bits = rec.bits,
                universe = self.counters.len(),
                "NEW coverage pattern"
            );
            // Durability invariant: the profile must be ON DISK before the pattern and Ok
            // record are committed. A crash in between leaves the block non-Ok, so a re-run
            // re-archives it; committing first could orphan an undominated pattern with no
            // profile for `report`. Archive failure aborts, keeping profile + spool.
            if !dominated {
                self.dirs.archive_profile(key, &profile).wrap_err_with(|| {
                    format!(
                        "failed to archive sparse profdata for NEW pattern of block {} (profile \
                         kept at {}) — ABORTING before the pattern is committed",
                        resp.block,
                        profile.display(),
                    )
                })?;
                let patterns = &self.patterns;
                self.undominated.retain(|k| !rec.dominates(&patterns[k]));
                self.undominated.push(key);
            }
            self.patterns.insert(key, rec);
        }

        // The spool entry is removed only after the commit; a crash leftover is harmless.
        let _ = std::fs::remove_file(&profile);
        let record = block_record(&resp, BlockStatus::Ok, Some(key));
        let pattern = Some((key, &self.patterns[&key]));
        self.store.commit_block(resp.block, &record, &new_counters, pattern)?;
        let _ = std::fs::remove_file(self.dirs.spool_entry(resp.block));
        Ok(())
    }

    fn progress_log(&self) {
        let elapsed = self.started.elapsed().as_secs_f64();
        let rate = self.processed as f64 / elapsed.max(0.001);
        let eta_secs = (self.total.saturating_sub(self.processed)) as f64 / rate.max(0.001);
        info!(
            processed = self.processed,
            total = self.total,
            patterns = self.patterns.len(),
            universe = self.counters.len(),
            rate = %format!("{rate:.1}/s"),
            eta = %format!("{:.0}s", eta_secs),
            "progress"
        );
    }

    fn final_summary(&self) {
        info!(
            processed = self.processed,
            new_patterns = self.new_patterns,
            total_patterns = self.patterns.len(),
            universe_counters = self.counters.len(),
            elapsed = %format!("{:.1}s", self.started.elapsed().as_secs_f64()),
            "backfill finished"
        );
        if let Some((avg, p50, p95, max)) = self.elapsed_ok_ms.summary() {
            info!(
                blocks = self.elapsed_ok_ms.blocks(),
                avg_ms = %format!("{avg:.0}"),
                p50_ms = p50,
                p95_ms = p95,
                max_ms = max,
                "per-block worker time (replay + profraw + bitmap)"
            );
        }
    }
}

/// The per-block store record for any judge outcome: error responses have `gas_used` 0
/// and ok ones no `error`, so only `status` and `pattern_key` differ.
fn block_record(
    resp: &WorkerResponse,
    status: BlockStatus,
    pattern_key: Option<u64>,
) -> BlockRecord {
    BlockRecord {
        hash: resp.block_hash,
        status,
        pattern_key,
        gas_used: resp.gas_used,
        tx_count: resp.tx_count,
        elapsed_ms: resp.elapsed_ms,
        error: resp.error.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{pattern_base_key, test_support::temp_store};

    /// A `Parser` wrapper, so tests exercise the real clap wiring of the flattened args.
    #[derive(clap::Parser)]
    struct TestCli {
        #[clap(flatten)]
        args: BackfillArgs,
    }

    fn parse(extra: &[&str]) -> Result<BackfillArgs> {
        let mut argv = vec![
            "backfill",
            "--rpc-endpoint",
            "http://rpc.invalid",
            "--witness-endpoint",
            "http://witness.invalid",
            "--genesis-file",
            "/genesis.json",
            "--data-dir",
            "/data",
        ];
        argv.extend_from_slice(extra);
        <TestCli as clap::Parser>::try_parse_from(argv)
            .map(|c| c.args)
            .map_err(|e| eyre::eyre!("{e}"))
    }

    /// Exactly one selection form must be given, or a run could sweep the wrong blocks.
    #[test]
    fn selection_requires_exactly_one_form() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.txt");
        std::fs::write(&path, "7\n").unwrap();
        let list = path.to_str().unwrap();

        let err = Selection::resolve(&parse(&[]).unwrap()).err().expect("no form");
        assert!(err.to_string().contains("either --from with --to"), "got: {err}");

        let err = Selection::resolve(&parse(&["--from", "1"]).unwrap()).err().expect("half range");
        assert!(err.to_string().contains("must be given together"), "got: {err}");

        let err = Selection::resolve(
            &parse(&["--from", "1", "--to", "9", "--blocks-file", list]).unwrap(),
        )
        .err()
        .expect("both forms");
        assert!(err.to_string().contains("cannot be combined"), "got: {err}");

        let err = Selection::resolve(&parse(&["--from", "9", "--to", "1"]).unwrap())
            .err()
            .expect("inverted range");
        assert!(err.to_string().contains("--from must be <= --to"), "got: {err}");
    }

    /// `highest` (tip guard) and `len` (skipped count) must mean the same for both forms.
    #[test]
    fn selection_reports_bounds_for_both_forms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.txt");
        std::fs::write(&path, "# hdr\n500\n7\n42\n").unwrap();
        let list = path.to_str().unwrap();

        let range = Selection::resolve(&parse(&["--from", "7", "--to", "500"]).unwrap()).unwrap();
        assert_eq!((range.lowest(), range.highest(), range.len()), (7, 500, 494));
        assert_eq!(range.label(), "7..=500");

        let listed = Selection::resolve(&parse(&["--blocks-file", list]).unwrap()).unwrap();
        assert_eq!((listed.lowest(), listed.highest(), listed.len()), (7, 500, 3));
        assert!(matches!(&listed, Selection::List(v) if v == &[7, 42, 500]));
        assert_eq!(listed.label(), "3 listed blocks (7..=500)");
    }

    /// Data requests are capped unless the operator raises the cap: uncapped, a block's
    /// bytecode fetches would all start at once (see `resolve_missing_codes`).
    #[test]
    fn data_requests_are_capped_by_default() {
        assert_eq!(parse(&[]).unwrap().data_max_concurrent_requests, 64);
        let raised = parse(&["--data-max-concurrent-requests", "256"]).unwrap();
        assert_eq!(raised.data_max_concurrent_requests, 256);
    }

    /// No count flag means anything at 0, so clap refuses it by name.
    #[test]
    fn count_flags_reject_zero() {
        for flag in [
            "--workers",
            "--fetch-concurrency",
            "--data-max-concurrent-requests",
            "--slow-block-warn-secs",
        ] {
            let err = parse(&[flag, "0"]).expect_err("0 must be refused");
            assert!(err.to_string().contains(flag), "error must name {flag}: {err}");
            parse(&[flag, "1"]).unwrap_or_else(|e| panic!("{flag} 1 must parse: {e}"));
        }
    }

    /// Blocks with no record and blocks that did not replay cleanly are pending, in order;
    /// clean ones are skipped, and rows outside the selection are ignored.
    #[test]
    fn pending_skips_only_clean_replays() {
        use crate::store::test_support::block;
        let (_tmp, _dirs, store) = temp_store();
        for (n, status) in [
            (11, BlockStatus::Ok),
            (12, BlockStatus::Error),
            (14, BlockStatus::Ok),
            (15, BlockStatus::Divergent),
            (99, BlockStatus::Ok),
        ] {
            store.commit_block(n, &block(status, None), &[], None).unwrap();
        }

        let pending = |selection: Selection| {
            let (todo, retrying) = selection.pending(&store).unwrap();
            (todo.into_iter().flatten().collect::<Vec<u64>>(), retrying)
        };
        assert_eq!(pending(Selection::Range(10..=16)), (vec![10, 12, 13, 15, 16], vec![12, 15]));
        assert_eq!(pending(Selection::Range(14..=14)), (vec![], vec![]));
        assert_eq!(pending(Selection::List(vec![11, 12, 13, 99])), (vec![12, 13], vec![12]));

        // An unscanned stretch stays one range, however long.
        let (todo, _) = Selection::Range(100..=u64::MAX - 1).pending(&store).unwrap();
        assert_eq!(todo, vec![100..=u64::MAX - 1]);
    }

    fn seeded_pattern(ids: &[u64], denses: &[u32], rep: u64, elapsed: u64) -> (u64, PatternRecord) {
        let bitmap = BitSet::from_indices(denses.iter().copied());
        let mut sorted = ids.to_vec();
        sorted.sort_unstable();
        let key = pattern_base_key(&sorted);
        (key, PatternRecord::first_seen(bitmap, rep, elapsed))
    }

    fn response(block: u64, counters: Vec<u64>, replay_ms: u64) -> WorkerResponse {
        WorkerResponse {
            block,
            block_hash: B256::repeat_byte(7),
            counters,
            replay_ms,
            elapsed_ms: replay_ms + 400,
            tx_count: 1,
            gas_used: 21000,
            ..Default::default()
        }
    }

    /// Judge on a temp store seeded with counters 1/2/3 (dense 0/1/2) and `patterns`; a
    /// test reaching the archive path writes the block's profdata first.
    fn judge_with<'a>(
        store: &'a Store,
        dirs: Arc<DataDir>,
        patterns: Vec<(u64, PatternRecord)>,
    ) -> JudgeState<'a> {
        let counters = [(1u64, 0u32), (2, 1), (3, 2)].into_iter().collect();
        JudgeState::new(counters, patterns.into_iter().collect(), store, dirs, 10)
    }

    #[test]
    fn known_pattern_dedups_and_rehomes_to_lightest() {
        let (_tmp, dirs, store) = temp_store();
        let (key, rec) = seeded_pattern(&[1, 2], &[0, 1], 100, 500);
        let mut judge = judge_with(&store, dirs, vec![(key, rec)]);

        // Same bitmap from a LIGHTER block → dedup + re-home.
        judge.ingest(response(200, vec![1, 2], 300)).unwrap();
        let rec = &judge.patterns[&key];
        assert_eq!(rec.hit_count, 2);
        assert_eq!(rec.representative, 200);
        assert_eq!(rec.representative_elapsed_ms, 300);
        assert_eq!(rec.last_block, 200);

        // Same bitmap from a HEAVIER block → count only, no re-home.
        judge.ingest(response(300, vec![1, 2], 900)).unwrap();
        let rec = &judge.patterns[&key];
        assert_eq!(rec.hit_count, 3);
        assert_eq!(rec.representative, 200);
        assert_eq!(judge.patterns.len(), 1, "no new pattern was created");

        // An earlier block finishing late must pull first_block down.
        assert_eq!(rec.first_block, 100);
        judge.ingest(response(50, vec![1, 2], 900)).unwrap();
        let rec = &judge.patterns[&key];
        assert_eq!(rec.first_block, 50);
        assert_eq!(rec.last_block, 300);
    }

    /// Ids new to the store take the next dense indices, in id order, and are persisted.
    #[test]
    fn new_ids_take_the_next_dense_indices() {
        let (_tmp, dirs, store) = temp_store();
        // Dominator over dense 0..=4 (ids 4 and 5 get 3 and 4), so {1, 4, 5} archives nothing.
        let (key, rec) = seeded_pattern(&[1, 2, 3, 4, 5], &[0, 1, 2, 3, 4], 100, 500);
        let mut judge = judge_with(&store, dirs, vec![(key, rec)]);

        judge.ingest(response(200, vec![1, 4, 5], 300)).unwrap();
        assert_eq!(judge.counters.len(), 5);
        let stored = judge.store.counters().unwrap();
        assert_eq!(stored, [(4, 3), (5, 4)].into_iter().collect(), "only the new ids are written");

        judge.ingest(response(201, vec![2, 5], 300)).unwrap();
        assert_eq!(judge.counters.len(), 5, "known ids keep their indices");
    }

    /// Codes this run verified are not re-read; unverified ones are checked on disk.
    #[test]
    fn verified_codes_are_checked_on_disk_once() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = DataDir::new(tmp.path());
        dirs.ensure_layout().unwrap();
        let bytes = b"\x60\x80\x60\x40".to_vec();
        let (good, absent) = (alloy_primitives::keccak256(&bytes), B256::repeat_byte(9));
        std::fs::write(dirs.code_file(&good), &bytes).unwrap();

        let verified = VerifiedCodes::default();
        assert_eq!(verified.missing(&dirs, &[good, absent]), vec![absent]);
        // Damage the verified file behind the cache's back: it is not re-read.
        std::fs::write(dirs.code_file(&good), b"torn").unwrap();
        assert_eq!(verified.missing(&dirs, &[good]), Vec::<B256>::new());
        // A fresh run has no such memory and catches the damage.
        assert_eq!(VerifiedCodes::default().missing(&dirs, &[good]), vec![good]);
    }

    /// A corrupt file reads as invalid but stays until the refetch's rename replaces it, so a
    /// check racing that repair can never delete the repaired file.
    #[test]
    fn corrupt_code_file_is_detected_and_left_for_the_refetch() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = b"\x60\x80\x60\x40".to_vec();
        let hash = alloy_primitives::keccak256(&bytes);

        let code = dir.path().join("code.bin");
        std::fs::write(&code, b"truncated").unwrap();
        assert!(!code_file_is_valid(&code, &hash));
        assert!(code.exists(), "the check must not delete what a concurrent fetch may repair");

        write_scratch(&code, &bytes).unwrap();
        assert!(code_file_is_valid(&code, &hash), "the refetch replaces it in place");
        assert!(code_file_is_valid(&code, &hash) && code.exists(), "checking never removes it");

        assert!(!code_file_is_valid(&dir.path().join("absent.bin"), &hash));
    }

    #[test]
    fn dominated_new_pattern_recorded_without_archive() {
        let (_tmp, dirs, store) = temp_store();
        let (dom_key, dom_rec) = seeded_pattern(&[1, 2, 3], &[0, 1, 2], 100, 500);
        let mut judge = judge_with(&store, dirs.clone(), vec![(dom_key, dom_rec)]);

        // {1,2} is a strict subset: a NEW, dominated pattern, so no profile is archived.
        judge.ingest(response(200, vec![1, 2], 300)).unwrap();
        assert_eq!(judge.patterns.len(), 2);
        let sub_key = pattern_base_key(&[1, 2]);
        assert!(judge.patterns.contains_key(&sub_key));
        assert!(
            !dirs.archived_profile(sub_key).exists(),
            "dominated pattern must not get an archived profile"
        );
        assert_eq!(judge.counters.len(), 3);

        // The store holds the committed pattern and record (the seed lived only in memory).
        let patterns = judge.store.patterns().unwrap();
        assert_eq!(patterns.len(), 1);
        assert!(patterns.contains_key(&sub_key));
        let record = &judge.store.block_records(&[200]).unwrap()[&200];
        assert_eq!(record.status, BlockStatus::Ok);
        assert_eq!(record.pattern_key, Some(sub_key));
    }

    /// A pattern arriving undominated must join the set domination is checked against, so
    /// a later subset of it archives nothing.
    #[test]
    fn a_new_undominated_pattern_dominates_later_subsets() {
        let (_tmp, dirs, store) = temp_store();
        let mut judge = judge_with(&store, dirs.clone(), vec![]);
        let with_profile = |block: u64, counters: Vec<u64>| {
            std::fs::write(dirs.block_profdata(block), b"sparse profdata").unwrap();
            response(block, counters, 100)
        };

        judge.ingest(with_profile(100, vec![1, 2, 3])).unwrap();
        assert!(dirs.archived_profile(pattern_base_key(&[1, 2, 3])).exists());
        judge.ingest(with_profile(200, vec![1, 2])).unwrap();
        assert!(
            !dirs.archived_profile(pattern_base_key(&[1, 2])).exists(),
            "{{1, 2}} is dominated by {{1, 2, 3}}, which arrived undominated"
        );
    }

    /// A new member of the antichain evicts the members it dominates: the domination check
    /// scans the antichain, not every pattern that was ever undominated on arrival.
    #[test]
    fn the_undominated_set_stays_an_antichain() {
        let (_tmp, dirs, store) = temp_store();
        let mut judge = judge_with(&store, dirs.clone(), vec![]);
        for (block, counters) in [(100, vec![1]), (200, vec![2]), (300, vec![1, 2, 3])] {
            std::fs::write(dirs.block_profdata(block), b"sparse profdata").unwrap();
            judge.ingest(response(block, counters, 100)).unwrap();
        }
        assert_eq!(judge.undominated, vec![pattern_base_key(&[1, 2, 3])]);
    }

    /// A retried block's spool is deleted, so the re-run refetches what failed; others stay.
    #[test]
    fn retried_blocks_are_refetched() {
        let (_tmp, dirs, _store) = temp_store();
        for n in [7, 8] {
            std::fs::write(dirs.spool_entry(n), b"entry").unwrap();
        }
        discard_spools(&dirs, &[7, 9]);
        assert!(!dirs.spool_entry(7).exists() && dirs.spool_entry(8).exists());
    }

    #[test]
    fn replay_error_and_divergence_fail_stop() {
        let (_tmp, dirs, store) = temp_store();
        let mut judge = judge_with(&store, dirs, vec![]);

        let mut bad = response(400, vec![1], 100);
        bad.error = Some("boom".into());
        let err = judge.ingest(bad).unwrap_err();
        assert!(err.to_string().contains("ABORTING"), "{err}");
        // The failure is recorded so a re-run retries the block.
        assert_eq!(judge.store.block_records(&[400]).unwrap()[&400].status, BlockStatus::Error);

        let mut divergent = response(401, vec![1], 100);
        divergent.divergence = Some("gas_used 21000 != header 42000".into());
        let err = judge.ingest(divergent).unwrap_err();
        assert!(err.to_string().contains("SANITY FAILURE"), "{err}");
        assert!(err.to_string().contains("gas_used 21000 != header 42000"), "{err}");
        assert_eq!(judge.store.block_records(&[401]).unwrap()[&401].status, BlockStatus::Divergent);
    }

    /// Keys hash the sorted ids: equal sets agree, distinct sets differ (barring collisions).
    #[test]
    fn pattern_key_contract() {
        assert_eq!(pattern_base_key(&[1, 2, 3]), pattern_base_key(&[1, 2, 3]));
        assert_ne!(pattern_base_key(&[1, 2]), pattern_base_key(&[1, 3]));
        assert_ne!(pattern_base_key(&[1]), pattern_base_key(&[1, 2]));
    }
}
