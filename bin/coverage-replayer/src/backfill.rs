//! Backfill driver: fetch a block range → spool → resident worker pool →
//! judge (pattern dedup, promotion, persistence).
//!
//! Data flow (all stages run concurrently, no barriers):
//!
//! ```text
//! fetch tasks (F) ──spool file──▶ dispatch queue ──▶ worker managers (N, one child each)
//!                                                        │ WorkerResponse
//!                                                        ▼
//!                                                  judge (single consumer, owns redb)
//! ```
//!
//! No block is ever skipped, and none is ever killed: a scan is only a cover
//! of what it replayed, so a gap would silently shrink the universe. A failed
//! fetch is retried every few seconds and a crashed worker is respawned onto
//! the same block, both indefinitely and loudly; a slow block is only warned
//! about. What cannot be retried into success — a replay error, or execution
//! that disagrees with the block's header — stops the run (fail-stop) with the
//! block recorded, so the next run retries it.

use std::{
    collections::{HashMap, HashSet},
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
    BackoffPolicy, R2WitnessTransport, RedactedSecret, RpcClient, decode_on_blocking_pool,
    decode_witness_payload_light,
};
use stateless_r2::fetch::{DEFAULT_CONNECT_TIMEOUT, FetchTimeouts};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    process::Child,
    task::JoinSet,
};
use tracing::{info, warn};

use crate::{
    bitset::BitSet,
    llvm::{Llvm, LlvmArgs},
    proto::{ItemDetail, WorkerRequest, WorkerResponse},
    spool::{DataDir, SpoolEntry, write_atomic, write_scratch},
    store::{
        BlockRecord, BlockStatus, CounterInfo, PatternRecord, Store, current_binary_id,
        elapsed_stats, resolve_pattern_slot,
    },
};

/// Where witnesses come from.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WitnessSource {
    /// `mega_getBlockWitness` RPC.
    #[default]
    Rpc,
    /// Straight from the R2 bucket over the S3 API. Requires the `--r2-*` flags.
    R2,
}

#[derive(Args, Debug, Clone)]
pub struct BackfillArgs {
    /// First block of the range (inclusive). Requires `--to`; mutually
    /// exclusive with `--blocks-file`.
    #[clap(long)]
    pub from: Option<u64>,
    /// Last block of the range (inclusive). Requires `--from`.
    ///
    /// Scan only blocks that are final. A resumed run skips cleanly replayed
    /// blocks — and reuses spool entries — by block NUMBER, so a height
    /// recorded just before a reorg keeps its orphaned hash and coverage.
    #[clap(long)]
    pub to: Option<u64>,
    /// Replay an explicit block list instead of a range: one decimal block
    /// number per line, `#` comments and blank lines ignored. This is the
    /// form that consumes `inspect --dump-pool` output (and any manifest
    /// converted to it), so a scattered candidate pool can be re-swept
    /// without walking the history between its members.
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
    /// Witness RPC endpoint(s) (`mega_getBlockWitness`). Required with
    /// `--witness-source rpc` (the default); ignored with `r2`.
    #[clap(
        long = "witness-endpoint",
        env = "COVERAGE_REPLAYER_WITNESS_ENDPOINT",
        value_delimiter = ','
    )]
    pub witness_endpoints: Vec<String>,
    /// Where to source witnesses from: `rpc` (default) or `r2` (straight from
    /// the R2 bucket over the S3 API; requires the `--r2-*` flags).
    #[clap(long, env = "COVERAGE_REPLAYER_WITNESS_SOURCE", value_enum, default_value_t = WitnessSource::Rpc)]
    pub witness_source: WitnessSource,
    /// R2 S3 endpoint origin, e.g. `https://<account>.r2.cloudflarestorage.com`
    /// (no bucket path). Required when `--witness-source r2`.
    #[clap(long, env = "COVERAGE_REPLAYER_R2_ENDPOINT")]
    pub r2_endpoint: Option<String>,
    /// R2 bucket holding the witnesses (e.g. `witness-mainnet`). Required when
    /// `--witness-source r2`.
    #[clap(long, env = "COVERAGE_REPLAYER_R2_BUCKET")]
    pub r2_bucket: Option<String>,
    /// R2 access key id (Object Read). Required when `--witness-source r2`.
    #[clap(long, env = "COVERAGE_REPLAYER_R2_ACCESS_KEY_ID")]
    pub r2_access_key_id: Option<String>,
    /// R2 secret access key. Required when `--witness-source r2`. Prefer the
    /// env var over the flag. Redacted in `Debug` output.
    #[clap(long, env = "COVERAGE_REPLAYER_R2_SECRET_ACCESS_KEY")]
    pub r2_secret_access_key: Option<RedactedSecret>,
    /// Genesis JSON path (e.g. test_data/mainnet/genesis.json).
    #[clap(long, env = "COVERAGE_REPLAYER_GENESIS_FILE")]
    pub genesis_file: String,
    /// Root directory for spool/codes/archive/store.
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Number of resident worker subprocesses (default: cores - 2).
    #[clap(long, env = "COVERAGE_REPLAYER_WORKERS")]
    pub workers: Option<usize>,
    /// Concurrent block fetches. Replay is fetch-bound, not compute-bound: a
    /// block costs far longer to download (block JSON, witness, bytecode) than
    /// to execute, most of all deep in history where blocks are large, so the
    /// worker pool idles behind a handful of fetches. Raising this cannot
    /// flood the disk — a full dispatch queue blocks the fetch loop, which
    /// bounds the spool backlog whatever the value.
    #[clap(long, default_value_t = 32)]
    pub fetch_concurrency: usize,
    #[clap(flatten)]
    pub llvm: LlvmArgs,
    /// Interval (seconds) for the "block still executing" progress warning.
    /// Blocks are never timed out — a stuck block stays visibly stuck in the
    /// log until it completes.
    #[clap(long, default_value_t = 600)]
    pub slow_block_warn_secs: u64,
}

/// What this run was asked to replay. The two forms differ in how the store
/// is consulted: a range reads the block records between its ends, a list
/// looks each member up — a pool drawn from the whole history spans every row
/// ever written.
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
            (None, None, Some(path)) => {
                let blocks = read_blocks_file(path)?;
                ensure!(!blocks.is_empty(), "block list {} holds no block numbers", path.display());
                Ok(Self::List(blocks))
            }
            (None, None, None) => bail!("pass either --from with --to, or --blocks-file"),
            (_, _, Some(_)) => bail!("--blocks-file cannot be combined with --from/--to"),
            _ => bail!("--from and --to must be given together"),
        }
    }

    fn iter(&self) -> Box<dyn Iterator<Item = u64> + '_> {
        match self {
            Self::Range(r) => Box::new(r.clone()),
            Self::List(v) => Box::new(v.iter().copied()),
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
            // `read_blocks_file` sorts, so the last entry is the maximum; an
            // empty list never reaches here (`resolve` rejects it).
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

    /// How the store last judged each selected block — all the todo filter
    /// needs, so a resumed full-range run holds a status per block rather
    /// than a whole record.
    fn statuses(&self, store: &Store) -> Result<HashMap<u64, BlockStatus>> {
        let mut found = HashMap::new();
        match self {
            Self::Range(r) => store.blocks(r.clone(), |n, record| {
                found.insert(n, record.status);
            })?,
            Self::List(v) => {
                found.extend(store.block_records(v)?.into_iter().map(|(n, r)| (n, r.status)));
            }
        }
        Ok(found)
    }
}

/// Parses a block list: one decimal block number per line, `#` comments and
/// blank lines ignored. Sorted and deduplicated, so concatenating several
/// shards' pools replays each block once, in history order.
fn read_blocks_file(path: &Path) -> Result<Vec<u64>> {
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("read block list {}", path.display()))?;
    let mut blocks = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        blocks.push(line.parse::<u64>().wrap_err_with(|| {
            format!("{}:{}: not a block number: {line:?}", path.display(), i + 1)
        })?);
    }
    blocks.sort_unstable();
    blocks.dedup();
    Ok(blocks)
}

pub async fn run(args: BackfillArgs) -> Result<()> {
    let selection = Selection::resolve(&args)?;
    ensure!(
        crate::profile_rt::is_instrumented_build(),
        "backfill requires the instrumented build (see [profile.coverage] in Cargo.toml)"
    );

    // Everything a worker needs at startup is validated here first (genesis
    // now, the source scope and the LLVM tools below): see `load_chain_spec`.
    crate::worker::load_chain_spec(&args.genesis_file)?;

    let dirs = Arc::new(DataDir::new(&args.data_dir));
    crate::profile_rt::ensure_literal_profile_dir(&dirs.tmp())?;
    dirs.ensure_layout()?;
    let binary_id = current_binary_id();
    info!(binary_id, "opening store");
    // Resolved once, here: every worker of the run must agree on the scope,
    // and a scope that cannot work (sources missing or ambiguous) has to stop
    // the run before any block is replayed.
    let llvm = args.llvm.resolve()?;
    let universe = llvm.universe();
    info!(
        universe,
        llvm_profdata = %llvm.profdata.display(),
        llvm_cov = %llvm.cov.display(),
        "coverage universe"
    );
    let store = Store::open(&dirs.store_path(), &binary_id, &universe)?;
    // Only now: the store's exclusive lock makes this the one process
    // writing under the data dir, so nothing left there is live.
    let cleared = dirs.clear_leftovers();
    if cleared > 0 {
        info!(cleared, "removed files a previous run left mid-flight");
    }
    let statuses = selection.statuses(&store)?;

    // R2 witness source: witnesses come from the bucket, so the RPC witness
    // endpoints are unused — feed the data endpoints in as placeholders (the
    // RpcClient requires a non-empty list).
    let r2 = match args.witness_source {
        WitnessSource::Rpc => {
            ensure!(
                !args.witness_endpoints.is_empty(),
                "--witness-endpoint is required with --witness-source rpc"
            );
            None
        }
        WitnessSource::R2 => {
            // The value itself is Debug-redacted, but a CLI-passed secret is
            // still visible in the process list for the whole (multi-week)
            // run. Detect "flag, not env" and nudge loudly.
            if args.r2_secret_access_key.is_some() &&
                std::env::var("COVERAGE_REPLAYER_R2_SECRET_ACCESS_KEY").is_err()
            {
                warn!(
                    "--r2-secret-access-key was passed on the command line — it is visible in \
                     `ps` for the lifetime of the process; prefer the \
                     COVERAGE_REPLAYER_R2_SECRET_ACCESS_KEY env var"
                );
            }
            let require = |v: Option<String>, flag: &str| {
                v.filter(|s| !s.is_empty()).ok_or_else(|| {
                    eyre::eyre!("{flag} is required (and non-empty) with --witness-source r2")
                })
            };
            let transport = R2WitnessTransport::new(
                &require(args.r2_endpoint.clone(), "--r2-endpoint")?,
                require(args.r2_bucket.clone(), "--r2-bucket")?,
                require(args.r2_access_key_id.clone(), "--r2-access-key-id")?,
                require(
                    args.r2_secret_access_key.as_ref().map(|s| s.as_ref().to_string()),
                    "--r2-secret-access-key",
                )?,
                FetchTimeouts {
                    per_attempt: Duration::from_secs(60),
                    connect: DEFAULT_CONNECT_TIMEOUT,
                },
                // Never used: `fetch_block` makes one attempt per round, and the
                // fetch loop's retry-forever is the pacing.
                BackoffPolicy::new(Duration::ZERO, Duration::ZERO),
                None,
            )?;
            info!(origin = %transport.origin(), "witness source: R2 (light decode)");
            Some(Arc::new(transport))
        }
    };

    let data_apis: Vec<String> = args.rpc_endpoints.clone();
    let witness_apis: Vec<String> =
        if r2.is_some() { data_apis.clone() } else { args.witness_endpoints.clone() };
    let client = Arc::new(RpcClient::new(
        &data_apis.iter().map(String::as_str).collect::<Vec<_>>(),
        &witness_apis.iter().map(String::as_str).collect::<Vec<_>>(),
    )?);

    let latest = client.get_latest_block_number().await;
    let highest = selection.highest();
    ensure!(
        highest <= latest,
        "block {highest} is beyond the chain tip {latest}; refusing to wait on unfetchable \
         blocks",
    );

    // Work list: skip only blocks that previously replayed CLEANLY. Error /
    // Divergent records are retried — no block is ever permanently excluded.
    let todo: Vec<u64> =
        selection.iter().filter(|n| statuses.get(n) != Some(&BlockStatus::Ok)).collect();
    let retrying = todo.iter().filter(|n| statuses.contains_key(n)).count();
    let total = todo.len() as u64;
    info!(
        selection = %selection.label(),
        todo = total,
        skipped = selection.len() - total,
        retrying_quarantined = retrying,
        "backfill starting"
    );
    if todo.is_empty() {
        info!("nothing to do");
        return Ok(());
    }

    let workers = args.workers.unwrap_or_else(|| num_cpus::get().saturating_sub(2).max(1));
    ensure!(workers >= 1, "--workers must be at least 1");
    let (dispatch_tx, dispatch_rx) = kanal::bounded_async::<u64>(workers * 2);
    let (judged_tx, mut judged_rx) = tokio::sync::mpsc::channel::<WorkerResponse>(workers * 2);

    // ---- worker managers ----
    let setup = Arc::new(WorkerSetup {
        exe: crate::profile_rt::own_executable()?,
        genesis_file: args.genesis_file.clone(),
        dirs: dirs.clone(),
        llvm,
        warn_after: Duration::from_secs(args.slow_block_warn_secs.max(1)),
    });
    let mut manager_set = JoinSet::new();
    for id in 0..workers {
        let (rx, tx, setup) = (dispatch_rx.clone(), judged_tx.clone(), setup.clone());
        manager_set.spawn(async move { worker_manager(id, rx, tx, setup).await });
    }
    drop(dispatch_rx);
    drop(judged_tx);

    // ---- fetch stage ----
    let verified_codes = Arc::new(VerifiedCodes::default());
    let fetcher = {
        let dirs = dirs.clone();
        let client = client.clone();
        let r2 = r2.clone();
        let dispatch_tx = dispatch_tx.clone();
        let fetch_concurrency = args.fetch_concurrency.max(1);
        tokio::spawn(async move {
            let mut inflight: JoinSet<u64> = JoinSet::new();
            for n in todo {
                while inflight.len() >= fetch_concurrency {
                    if let Some(done) = inflight.join_next().await {
                        forward_fetched(done, &dispatch_tx).await;
                    }
                }
                let dirs = dirs.clone();
                let client = client.clone();
                let r2 = r2.clone();
                let verified_codes = verified_codes.clone();
                inflight.spawn(async move {
                    let mut attempt = 0u64;
                    let mut block_cache = None;
                    loop {
                        match fetch_block(
                            &client,
                            r2.as_deref(),
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
    drop(dispatch_tx);

    // ---- judge (this task) ----
    let mut judge =
        JudgeState::new(store.counters()?, store.patterns()?, &store, dirs.clone(), total);
    let judged: Result<()> = async {
        while let Some(outcome) = judged_rx.recv().await {
            judge.ingest(outcome)?;
        }
        Ok(())
    }
    .await;
    // Whatever ended the loop, what was judged is made durable before the
    // run reports it.
    store.flush()?;
    judged?;

    fetcher.await.ok();
    while manager_set.join_next().await.is_some() {}
    judge.final_summary();
    // The judged channel closing only says every task is gone, not that every
    // block arrived: a fetch task that panicked, or a manager that died,
    // drops its block with nothing but a log line. Exiting 0 then would let
    // automation run set-cover over an incomplete universe.
    ensure!(
        judge.processed == total,
        "backfill ended with {} of {total} blocks judged — a fetch or worker task died (see the \
         errors above). Nothing is lost: re-run the same selection to pick up the rest.",
        judge.processed,
    );
    Ok(())
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
        // A panic in a fetch task is a code bug; the block stays absent from
        // the store, so a re-run picks it up. Loud, not silent.
        Err(e) => tracing::error!(error = %e, "fetch task panicked — block will need a re-run"),
    }
}

/// Fetches one block + witness, resolves missing bytecodes, writes the spool
/// entry. Skips work that already exists on disk (crash resume).
///
/// `block_cache` holds the fetched block across the caller's retry rounds so
/// a witness-side failure (e.g. R2 404 looping under retry-forever) does not
/// re-download the full block every 5 seconds.
async fn fetch_block(
    client: &RpcClient,
    r2: Option<&R2WitnessTransport>,
    dirs: &DataDir,
    verified_codes: &Arc<VerifiedCodes>,
    n: u64,
    block_cache: &mut Option<alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction>>,
) -> Result<()> {
    let spool_path = dirs.spool_entry(n);
    if spool_path.exists() {
        // An entry the worker cannot use (crash artifact, a layout change
        // between binary versions) would fail-stop the run on every restart,
        // since a re-run skips the fetch while the file exists. So it is
        // opened exactly as the worker opens it, and refetched on failure.
        let existing = {
            let path = spool_path.clone();
            tokio::task::spawn_blocking(move || SpoolEntry::open(&path, n)).await?
        };
        match existing {
            Ok(entry) => {
                // Its contract codes live in separate files — re-resolve any
                // missing or corrupt ones so the worker never wedges on a
                // half-cleaned codes dir.
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
        // Unchecked on purpose. The checked fetch recovers the signer of every
        // transaction — secp256k1 work, in a binary whose every basic block
        // bumps a shared coverage counter — and on blocks carrying tens of
        // thousands of transactions that, not the download, is what the fetch
        // stage spends its time on, with the concurrent fetches contending
        // for the same counters. Nothing is lost by skipping it: a wrong
        // sender or transaction set cannot reproduce the header's gas,
        // receipts root and logs bloom, which the worker compares after
        // replaying, and a divergence stops the run. The header hash is
        // checked here because it is cheap and it is what the manifest
        // publishes and the witness is addressed by.
        let block = client.get_block_unchecked(BlockId::number(n), true).await;
        ensure!(
            block.header.number == n,
            "asked for block {n}, the RPC returned {}",
            block.header.number
        );
        ensure!(
            block.header.hash_slow() == block.header.hash,
            "block {n}: the RPC header does not hash to the hash it claims ({:#x})",
            block.header.hash,
        );
        *block_cache = Some(block);
    }
    let block = block_cache.as_ref().expect("just filled");
    let hash = block.header.hash;
    // Zero-validation light fetch (from R2 or the witness RPC): no
    // elliptic-curve work is spent on the proof we never verify. Full
    // witnesses are NOT stored anywhere — when a selected block needs one, it
    // is re-fetched on demand. Either source serves the full history: the
    // bucket keeps every witness, and the witness RPC reads the same bucket.
    let (light_witness, _mpt_witness) = match r2 {
        Some(r2) => {
            let object = r2.fetcher().get_block_object(n, hash, 1, None, || {}).await?;
            decode_on_blocking_pool(object.bytes, n, hash, None, |bytes| {
                decode_witness_payload_light(bytes)
            })
            .await?
        }
        None => client.get_witness_light(n, hash).await,
    };

    let code_hashes = stateless_core::collect_code_hashes(&light_witness.kvs);
    resolve_missing_codes(client, dirs, verified_codes, code_hashes.clone()).await?;

    // Re-serializing a block of tens of thousands of transactions is real CPU
    // work, so it goes to the blocking pool with the write. The block leaves
    // the cache here, past everything a retry would want it for.
    let block = block_cache.take().expect("just filled");
    tokio::task::spawn_blocking(move || {
        let block_json = serde_json::to_vec(&block)?;
        SpoolEntry { block_json, light_witness, code_hashes }.write_to(&spool_path)
    })
    .await??;
    Ok(())
}

/// The codes-dir files this run has already found content-valid, shared by
/// every fetch task.
///
/// A deep-history block references thousands of contracts, nearly all of them
/// verified for an earlier block already; re-reading and re-hashing each one
/// for every block spends the fetch stage — the bottleneck — on settled work.
/// A file verified once stays valid for the run: the codes dir only ever gains
/// files (atomically renamed into place), and only an invalid file is deleted.
#[derive(Default)]
struct VerifiedCodes(Mutex<HashSet<B256>>);

impl VerifiedCodes {
    /// Of `code_hashes`, the ones with no content-valid file in `dirs` —
    /// checking on disk only those this run has not verified yet, and
    /// remembering the ones that pass.
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

/// Fetches and persists any of `code_hashes` not already in the codes dir —
/// where "in" means present AND content-valid: the files are content-
/// addressed, so anything whose keccak doesn't match its name (truncated by
/// a pre-fsync crash, damaged media) is deleted and refetched. Without this,
/// a corrupt code file wedges the run across restarts: the worker replays
/// wrong bytes, diverges, and the judge fail-stops — forever. The file work
/// runs on the blocking pool, off the fetch tasks' runtime threads.
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

/// Returns whether `path` holds exactly the bytes hashing to `hash`
/// (content-addressed check, same keccak the RPC fetch verifies). A present-
/// but-invalid file is deleted so the caller refetches it.
fn code_file_is_valid(path: &std::path::Path, hash: &B256) -> bool {
    match std::fs::read(path) {
        Ok(bytes) if alloy_primitives::keccak256(&bytes) == *hash => true,
        Ok(_) => {
            warn!(
                code = %format!("{hash:x}"),
                path = %path.display(),
                "content-addressed code file fails its hash — deleting and refetching"
            );
            let _ = std::fs::remove_file(path);
            false
        }
        Err(_) => false,
    }
}

/// What every worker of a run is launched with, resolved once by the
/// dispatcher so they cannot disagree.
struct WorkerSetup {
    /// The running image, not the file it came from: a worker respawned after
    /// a rebuild must still be this build (see `profile_rt::own_executable`).
    exe: PathBuf,
    genesis_file: String,
    dirs: Arc<DataDir>,
    llvm: Llvm,
    /// Interval of the "block still executing" warning.
    warn_after: Duration,
}

/// Owns one resident worker child, respawned onto the same block whenever it
/// dies.
async fn worker_manager(
    id: usize,
    rx: kanal::AsyncReceiver<u64>,
    tx: tokio::sync::mpsc::Sender<WorkerResponse>,
    setup: Arc<WorkerSetup>,
) {
    let mut worker: Option<WorkerHandle> = None;
    let (dirs, warn_after) = (&setup.dirs, setup.warn_after);

    while let Ok(n) = rx.recv().await {
        let req = WorkerRequest { block: n, spool: dirs.spool_entry(n) };
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
                    // Escalate a repeating crash on ONE block: by policy it is
                    // retried forever, but an operator must be able to find
                    // the wedge from the error log alone.
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
            .spawn()
            .wrap_err("spawn internal-worker")?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Self { child, stdin, stdout: tokio::io::BufReader::new(stdout).lines() })
    }

    /// Sends one request and waits for the response with no deadline (see the
    /// module doc). Errors here mean the child actually died (closed stdout /
    /// bad frame), not slowness.
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
        // Nothing but the worker's frames reaches this pipe
        // (`worker::protocol_channel`), so a line that is not one means the
        // worker is broken — handled like a crash: respawn, retry the block.
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

/// Judged blocks between two flushes of the store. A kill or crash rolls back
/// at most this many — they are replayed again — for one flush per batch
/// instead of one per block; every exit path of the judge flushes.
const COMMITS_PER_FLUSH: u64 = 64;

/// Single-consumer ingest: pattern dedup, promotion, persistence, progress.
struct JudgeState<'a> {
    store: &'a Store,
    dirs: Arc<DataDir>,
    /// Counter id → dense index. Every id enters with the pattern holding
    /// it, so its size is also the size of the universe. Ids are hashes
    /// already, so the map need not hash them again.
    counters: FxHashMap<u64, u32>,
    next_dense: u32,
    patterns: HashMap<u64, PatternRecord>,
    /// Keys of the patterns no pattern dominated when they arrived. A new
    /// pattern dominated by anything is dominated by one of these —
    /// domination is transitive — so the check scans this set instead of
    /// every pattern: all but a few percent of patterns arrive dominated.
    undominated: Vec<u64>,
    processed: u64,
    total: u64,
    new_patterns: u64,
    started: Instant,
    /// Worker wall-clock per successfully replayed block (spool load + replay
    /// + profraw + item extraction).
    elapsed_ok_ms: ElapsedSampler,
}

/// Bounded, deterministic reservoir for per-block timings: keeps every
/// `stride`-th sample and doubles the stride when full. A full-history run
/// would otherwise hold one u64 per block (hundreds of MB) just to print one
/// avg/p50/p95 line at the end.
struct ElapsedSampler {
    samples: Vec<u64>,
    stride: u64,
    seen: u64,
}

impl ElapsedSampler {
    /// ~8 MB worst case; large enough that percentiles are exact for any
    /// single-machine range and statistically indistinguishable beyond it.
    const CAP: usize = 1 << 20;

    fn new() -> Self {
        Self { samples: Vec::new(), stride: 1, seen: 0 }
    }

    fn record(&mut self, elapsed_ms: u64) {
        if self.seen.is_multiple_of(self.stride) {
            if self.samples.len() >= Self::CAP {
                // Decimate: keep every other retained sample, double the stride.
                let mut keep = false;
                self.samples.retain(|_| {
                    keep = !keep;
                    keep
                });
                self.stride *= 2;
            }
            self.samples.push(elapsed_ms);
        }
        self.seen += 1;
    }
}

impl<'a> JudgeState<'a> {
    fn new(
        counters: HashMap<u64, CounterInfo>,
        patterns: HashMap<u64, PatternRecord>,
        store: &'a Store,
        dirs: Arc<DataDir>,
        total: u64,
    ) -> Self {
        let next_dense = counters.values().map(|info| info.dense + 1).max().unwrap_or(0);
        let counters: FxHashMap<u64, u32> =
            counters.into_iter().map(|(id, info)| (id, info.dense)).collect();
        let undominated = crate::setcover::split_antichain(&patterns)
            .0
            .into_iter()
            .map(|(key, _)| *key)
            .collect();
        info!(universe = counters.len(), known_patterns = patterns.len(), "judge state restored");
        Self {
            store,
            dirs,
            counters,
            next_dense,
            patterns,
            undominated,
            processed: 0,
            total,
            new_patterns: 0,
            started: Instant::now(),
            elapsed_ok_ms: ElapsedSampler::new(),
        }
    }

    /// Fail-stop policy: replay errors and sanity divergences are recorded to
    /// the store (spool kept for forensics) and then ABORT the whole run.
    /// Rationale: every block has been independently verified to replay
    /// cleanly, so any failure here is an infrastructure/chain-spec bug — a
    /// gap must never be silently scanned past. The recorded non-Ok status is
    /// retried automatically on the next run (see the todo filter).
    fn ingest(&mut self, resp: WorkerResponse) -> Result<()> {
        self.processed += 1;

        if let Some(error) = &resp.error {
            let record = block_record(&resp, BlockStatus::Error, None);
            self.store.commit_block(resp.block, &record, &[], None, false)?;
            eyre::bail!(
                "block {} failed to replay: {error} — ABORTING (no block may be skipped; \
                 spool kept at {}; a re-run will retry this block)",
                resp.block,
                self.dirs.spool_entry(resp.block).display(),
            );
        }

        let sane = resp.gas_ok && resp.receipts_root_ok && resp.logs_bloom_ok;
        if !sane {
            let record = block_record(&resp, BlockStatus::Divergent, None);
            self.store.commit_block(resp.block, &record, &[], None, false)?;
            eyre::bail!(
                "SANITY FAILURE at block {} (gas_ok={} receipts_root_ok={} logs_bloom_ok={}) — \
                 execution diverged from the header; bitmap NOT ingested. ABORTING: this is \
                 chain-spec drift or an execution bug, and continuing would leave a silent \
                 coverage gap. Spool kept at {}.",
                resp.block,
                resp.gas_ok,
                resp.receipts_root_ok,
                resp.logs_bloom_ok,
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
        // Resolve counter ids → dense indices, registering unseen ids from the
        // details their worker sent along.
        let details: HashMap<u64, &ItemDetail> = resp.new_items.iter().map(|d| (d.id, d)).collect();
        let mut new_counters: Vec<(u64, CounterInfo)> = Vec::new();
        let mut dense = Vec::with_capacity(resp.counters.len());
        for id in &resp.counters {
            if let Some(&known) = self.counters.get(id) {
                dense.push(known);
                continue;
            }
            let d = details.get(id).ok_or_else(|| {
                eyre::eyre!(
                    "item {id:#x} of block {} is new to the store, but its worker never reported \
                     where it lives",
                    resp.block
                )
            })?;
            let index = self.next_dense;
            self.next_dense += 1;
            self.counters.insert(*id, index);
            dense.push(index);
            let info = CounterInfo {
                dense: index,
                location: d.location.clone(),
                kind: d.kind.clone(),
                line: d.line,
            };
            new_counters.push((*id, info));
        }

        let rec =
            PatternRecord::first_seen(BitSet::from_indices(dense), resp.block, resp.elapsed_ms);
        // Worker counters arrive sorted and deduped, as the keying expects.
        let (key, occupied) = resolve_pattern_slot(&self.patterns, &resp.counters, &rec.bitmap);

        if occupied {
            // Known pattern: nothing on disk moves — the profile is keyed by
            // pattern, whichever block now represents it.
            self.patterns.get_mut(&key).expect("occupied slot").absorb(&rec);
        } else {
            // Dominated patterns (strict subset of an existing one) can never
            // beat their dominator in set cover — record the bitmap for dedup
            // and stats, but skip the profile archive (93% of new patterns in
            // practice). set-cover excludes them from candidates, so a
            // selected block always has an archived profile.
            let dominated = self.undominated.iter().any(|k| self.patterns[k].dominates(&rec));
            self.new_patterns += 1;
            info!(
                block = resp.block,
                pattern = %format!("{key:016x}"),
                bits = rec.bits,
                universe = self.counters.len(),
                "NEW coverage pattern"
            );
            // Promote. Ordering is the durability invariant: the sparse
            // profdata must be ON DISK before the pattern + Ok record are
            // committed — a crash in between leaves the block non-Ok, so a
            // re-run re-executes it and re-archives. Committing first would
            // permanently orphan a non-dominated pattern (block never
            // retried, later same-bitmap profiles deleted, `report` fails on
            // the missing profile). Archive failure aborts (fail-stop),
            // keeping profile + spool for forensics.
            if !dominated {
                archive_sparse_profile(&resp.profile, &self.dirs.archived_profile(key))
                    .wrap_err_with(|| {
                        format!(
                            "failed to archive sparse profdata for NEW pattern of block {} \
                             (profile kept at {}) — ABORTING before the pattern is committed",
                            resp.block,
                            resp.profile.display(),
                        )
                    })?;
            }
            if !dominated {
                self.undominated.push(key);
            }
            self.patterns.insert(key, rec);
        }

        // Shared tail: commit, then clean up (the spool entry goes after the
        // commit — a leftover from a crash in between is harmless junk).
        let _ = std::fs::remove_file(&resp.profile);
        let record = block_record(&resp, BlockStatus::Ok, Some(key));
        let rec_ref = &self.patterns[&key];
        let durable = self.processed.is_multiple_of(COMMITS_PER_FLUSH);
        self.store.commit_block(
            resp.block,
            &record,
            &new_counters,
            Some((key, rec_ref)),
            durable,
        )?;
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

    fn final_summary(&mut self) {
        info!(
            processed = self.processed,
            new_patterns = self.new_patterns,
            total_patterns = self.patterns.len(),
            universe_counters = self.counters.len(),
            elapsed = %format!("{:.1}s", self.started.elapsed().as_secs_f64()),
            "backfill finished"
        );
        let blocks = self.elapsed_ok_ms.seen;
        let sampled = self.elapsed_ok_ms.stride > 1;
        let mut samples = std::mem::take(&mut self.elapsed_ok_ms.samples);
        if let Some((avg, p50, p95, max)) = elapsed_stats(&mut samples) {
            info!(
                blocks,
                sampled,
                avg_ms = %format!("{avg:.0}"),
                p50_ms = p50,
                p95_ms = p95,
                max_ms = max,
                "per-block worker time (replay + profraw + bitmap)"
            );
        }
    }
}

/// Builds the per-block store record from a worker response. The judge's
/// three commit paths (Ok / Divergent / Error) differ only in status and
/// pattern key: on error paths `resp.gas_used` is 0 and on ok paths
/// `resp.error` is `None`, so one constructor serves all.
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

/// Archives a promoted block's sparse profdata, zstd'd. The worker already
/// produced it — `llvm-cov` needs a profdata to evaluate the block's items —
/// so archiving is a compress-and-rename, with no LLVM tool on this side.
fn archive_sparse_profile(profile: &std::path::Path, dest: &std::path::Path) -> Result<()> {
    let bytes =
        std::fs::read(profile).wrap_err_with(|| format!("read profile {}", profile.display()))?;
    write_atomic(dest, &zstd::encode_all(&bytes[..], 3)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::pattern_base_key;

    /// `BackfillArgs` is a flattened `Args`, so parsing it in a test needs a
    /// `Parser` wrapper — which is also what exercises the real clap wiring
    /// rather than a hand-built struct.
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

    /// The list format is what carries a pool between builds, so its exact
    /// tolerances are load-bearing: `#` comments (the header `--dump-pool`
    /// writes), trailing comments, blank lines, and out-of-order duplicates
    /// from concatenating several shards' pools.
    #[test]
    fn block_list_skips_comments_sorts_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.txt");
        std::fs::write(
            &path,
            "# coverage-replayer candidate pool\n# blocks: 3\n\n  30 \n10\n20 # trailing\n10\n",
        )
        .unwrap();
        assert_eq!(read_blocks_file(&path).unwrap(), vec![10, 20, 30]);
    }

    #[test]
    fn block_list_rejects_a_non_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.txt");
        std::fs::write(&path, "10\n0x1f\n").unwrap();
        let err = read_blocks_file(&path).expect_err("must fail");
        assert!(err.to_string().contains("not a block number"), "got: {err}");
        // The line number points at the offending line, not the file start.
        assert!(err.to_string().contains(":2:"), "got: {err}");
    }

    /// The two selection forms must be exclusive and complete — a run that
    /// silently ignored one of them would sweep the wrong blocks.
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

    /// `highest` feeds the chain-tip guard and `len` the "skipped" count, so
    /// both forms must report them in the same units.
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
        assert_eq!(listed.iter().collect::<Vec<_>>(), vec![7, 42, 500]);
        assert_eq!(listed.label(), "3 listed blocks (7..=500)");
    }

    fn counter_info(dense: u32) -> CounterInfo {
        CounterInfo { dense, location: "s".into(), kind: "h".into(), line: dense }
    }

    fn seeded_pattern(ids: &[u64], denses: &[u32], rep: u64, elapsed: u64) -> (u64, PatternRecord) {
        let bitmap = BitSet::from_indices(denses.iter().copied());
        let mut sorted = ids.to_vec();
        sorted.sort_unstable();
        let key = pattern_base_key(&sorted);
        (key, PatternRecord::first_seen(bitmap, rep, elapsed))
    }

    fn response(block: u64, counters: Vec<u64>, elapsed_ms: u64) -> WorkerResponse {
        WorkerResponse {
            block,
            block_hash: B256::repeat_byte(7),
            error: None,
            gas_ok: true,
            receipts_root_ok: true,
            logs_bloom_ok: true,
            counters,
            profile: PathBuf::from("/nonexistent/test.profdata"),
            new_items: Vec::new(),
            elapsed_ms,
            tx_count: 1,
            gas_used: 21000,
        }
    }

    /// Judge harness on a real (temp) store, pre-seeded with counters for ids
    /// 1/2/3 (dense 0/1/2) and one pattern. Only paths that need no
    /// llvm-profdata are exercised (known-pattern dedup, dominated skip);
    /// the archive path is covered by the instrumented E2E runs.
    fn judge_with<'a>(
        store: &'a Store,
        dirs: Arc<DataDir>,
        patterns: Vec<(u64, PatternRecord)>,
    ) -> JudgeState<'a> {
        let counters = [(1u64, counter_info(0)), (2, counter_info(1)), (3, counter_info(2))];
        JudgeState::new(counters.into(), patterns.into_iter().collect(), store, dirs, 10)
    }

    #[test]
    fn known_pattern_dedups_and_rehomes_to_lightest() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(DataDir::new(tmp.path()));
        dirs.ensure_layout().unwrap();
        let store = Store::open(&dirs.store_path(), "test-id", "f").unwrap();
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

        // Completion order != block order: an EARLIER block finishing late
        // must pull first_block down (merge min-folds the same way — the two
        // must agree on provenance).
        assert_eq!(rec.first_block, 100);
        judge.ingest(response(50, vec![1, 2], 900)).unwrap();
        let rec = &judge.patterns[&key];
        assert_eq!(rec.first_block, 50);
        assert_eq!(rec.last_block, 300);
    }

    /// An id the store has never seen is registered from the details its
    /// worker sent along; one that arrives without them is a protocol breach
    /// and must stop the run rather than enter the store without provenance.
    #[test]
    fn new_items_are_registered_from_the_details_their_worker_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(DataDir::new(tmp.path()));
        dirs.ensure_layout().unwrap();
        let store = Store::open(&dirs.store_path(), "test-id", "f").unwrap();
        // A dominator over dense 0..=3, so the new pattern {1, 4} is dominated
        // and archives no profile (id 4 will get dense 3, the next free one).
        let (key, rec) = seeded_pattern(&[1, 2, 3, 4], &[0, 1, 2, 3], 100, 500);
        let mut judge = judge_with(&store, dirs, vec![(key, rec)]);

        let mut resp = response(200, vec![1, 4], 300);
        resp.new_items = vec![ItemDetail {
            id: 4,
            line: 12,
            kind: "branch-true".into(),
            location: "30ce038/src/a.rs:12:5".into(),
        }];
        judge.ingest(resp).unwrap();
        let stored = &judge.store.load().unwrap().counters[&4];
        assert_eq!((stored.dense, stored.line), (3, 12));
        assert_eq!(stored.location, "30ce038/src/a.rs:12:5");

        let err = judge.ingest(response(201, vec![1, 5], 300)).expect_err("no detail for id 5");
        assert!(err.to_string().contains("never reported where it lives"), "{err}");
    }

    /// Codes this run verified are not read again — the point of the cache —
    /// while unverified ones are checked on disk and missing ones reported.
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

    #[test]
    fn corrupt_code_file_is_detected_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = b"\x60\x80\x60\x40".to_vec();
        let hash = alloy_primitives::keccak256(&bytes);

        let good = dir.path().join("good.bin");
        std::fs::write(&good, &bytes).unwrap();
        assert!(code_file_is_valid(&good, &hash));
        assert!(good.exists());

        let bad = dir.path().join("bad.bin");
        std::fs::write(&bad, b"truncated").unwrap();
        assert!(!code_file_is_valid(&bad, &hash));
        assert!(!bad.exists(), "invalid content-addressed file must be deleted for refetch");

        assert!(!code_file_is_valid(&dir.path().join("absent.bin"), &hash));
    }

    #[test]
    fn elapsed_sampler_stays_bounded_and_representative() {
        let mut s = ElapsedSampler::new();
        let n = (ElapsedSampler::CAP * 3) as u64;
        for i in 0..n {
            s.record(i);
        }
        assert_eq!(s.seen, n);
        assert!(s.samples.len() <= ElapsedSampler::CAP, "bounded: {}", s.samples.len());
        assert!(s.stride > 1, "must have decimated");
        // Still spans the full range (deterministic stride, no bias to
        // either end): percentile estimates stay meaningful.
        let (min, max) = (s.samples.iter().min().unwrap(), s.samples.iter().max().unwrap());
        assert!(*min < n / 10, "min {} not near the start", min);
        assert!(*max > n - n / 10, "max {} not near the end", max);
    }

    #[test]
    fn dominated_new_pattern_recorded_without_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(DataDir::new(tmp.path()));
        dirs.ensure_layout().unwrap();
        let store = Store::open(&dirs.store_path(), "test-id", "f").unwrap();
        // Seed the dominator {1,2,3}.
        let (dom_key, dom_rec) = seeded_pattern(&[1, 2, 3], &[0, 1, 2], 100, 500);
        let mut judge = judge_with(&store, dirs.clone(), vec![(dom_key, dom_rec)]);

        // {1,2} is a strict subset → NEW pattern, dominated: bitmap recorded,
        // profile NOT archived.
        judge.ingest(response(200, vec![1, 2], 300)).unwrap();
        assert_eq!(judge.patterns.len(), 2);
        let sub_key = pattern_base_key(&[1, 2]);
        assert!(judge.patterns.contains_key(&sub_key));
        assert!(
            !dirs.archived_profile(sub_key).exists(),
            "dominated pattern must not get an archived profile"
        );
        // Universe unchanged: the subset contributed nothing new.
        assert_eq!(judge.counters.len(), 3);

        // The store round-trips the newly committed pattern and block record
        // (the seeded dominator lived only in the in-memory snapshot).
        let snap = judge.store.load().unwrap();
        assert_eq!(snap.patterns.len(), 1);
        assert!(snap.patterns.contains_key(&sub_key));
        assert_eq!(snap.blocks[&200].status, BlockStatus::Ok);
        assert_eq!(snap.blocks[&200].pattern_key, Some(sub_key));
    }

    /// The judge checks domination against the patterns that arrived
    /// undominated, so a pattern that arrives undominated has to join them:
    /// a later subset of it is dominated, and archives nothing.
    #[test]
    fn a_new_undominated_pattern_dominates_later_subsets() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(DataDir::new(tmp.path()));
        dirs.ensure_layout().unwrap();
        let store = Store::open(&dirs.store_path(), "test-id", "f").unwrap();
        let mut judge = judge_with(&store, dirs.clone(), vec![]);
        let with_profile = |block: u64, counters: Vec<u64>| {
            let mut resp = response(block, counters, 100);
            resp.profile = dirs.tmp().join(format!("block_{block}.profdata"));
            std::fs::write(&resp.profile, b"sparse profdata").unwrap();
            resp
        };

        judge.ingest(with_profile(100, vec![1, 2, 3])).unwrap();
        assert!(dirs.archived_profile(pattern_base_key(&[1, 2, 3])).exists());
        judge.ingest(with_profile(200, vec![1, 2])).unwrap();
        assert!(
            !dirs.archived_profile(pattern_base_key(&[1, 2])).exists(),
            "{{1, 2}} is dominated by {{1, 2, 3}}, which arrived undominated"
        );
    }

    #[test]
    fn replay_error_and_divergence_fail_stop() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(DataDir::new(tmp.path()));
        dirs.ensure_layout().unwrap();
        let store = Store::open(&dirs.store_path(), "test-id", "f").unwrap();
        let mut judge = judge_with(&store, dirs, vec![]);

        let mut bad = response(400, vec![1], 100);
        bad.error = Some("boom".into());
        let err = judge.ingest(bad).unwrap_err();
        assert!(err.to_string().contains("ABORTING"), "{err}");
        // The failure is recorded so a re-run retries the block.
        let snap = judge.store.load().unwrap();
        assert_eq!(snap.blocks[&400].status, BlockStatus::Error);

        let mut divergent = response(401, vec![1], 100);
        divergent.gas_ok = false;
        let err = judge.ingest(divergent).unwrap_err();
        assert!(err.to_string().contains("SANITY FAILURE"), "{err}");
        let snap = judge.store.load().unwrap();
        assert_eq!(snap.blocks[&401].status, BlockStatus::Divergent);
    }

    /// The keying contract shared with merge: sorted-id hashing, distinct sets
    /// → distinct keys (up to 64-bit collisions).
    #[test]
    fn pattern_key_contract() {
        assert_eq!(pattern_base_key(&[1, 2, 3]), pattern_base_key(&[1, 2, 3]));
        assert_ne!(pattern_base_key(&[1, 2]), pattern_base_key(&[1, 3]));
        assert_ne!(pattern_base_key(&[1]), pattern_base_key(&[1, 2]));
    }
}
