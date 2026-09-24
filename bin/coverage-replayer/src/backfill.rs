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
use stateless_common::RpcClient;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    process::Child,
    task::JoinSet,
};
use tracing::{info, warn};

use crate::{
    bitset::BitSet,
    llvm,
    proto::{ItemDetail, WorkerRequest, WorkerResponse},
    spool::{DataDir, SpoolEntry, write_atomic},
    store::{
        BlockRecord, BlockStatus, CounterInfo, PatternRecord, Store, StoreSnapshot,
        current_binary_id, elapsed_stats, resolve_pattern_slot,
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
    pub r2_secret_access_key: Option<crate::r2::RedactedSecret>,
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
    /// Source directories scoping the coverage universe — the same scope
    /// `report` measures. Default: the mega-evm checkout this binary was built
    /// against plus the crates in `measured-crates.txt` at their locked
    /// versions, found under the cargo home the build used. llvm-cov matches
    /// the absolute paths baked in at build time, so the sources must sit
    /// where they sat for the build.
    #[clap(long = "source-dir")]
    pub source_dirs: Vec<PathBuf>,
    /// Explicit llvm-profdata path (default: the `llvm-tools` of the toolchain
    /// that built this binary).
    #[clap(long)]
    pub llvm_profdata: Option<String>,
    /// Explicit llvm-cov path (default: the `llvm-tools` of the toolchain that
    /// built this binary).
    #[clap(long)]
    pub llvm_cov: Option<String>,
    /// Interval (seconds) for the "block still executing" progress warning.
    /// Blocks are NEVER timed out or skipped — a stuck block stays visibly
    /// stuck in the log until it completes.
    #[clap(long, default_value_t = 600)]
    pub slow_block_warn_secs: u64,
}

/// What this run was asked to replay. The two forms differ in how the store
/// is consulted: a range scans the BLOCKS table between its ends, a list does
/// one point lookup per member — which is what keeps resuming a pool drawn
/// from the whole history cheap, since its extremes span every row ever
/// written.
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

    fn load_snapshot(&self, store: &Store) -> Result<StoreSnapshot> {
        match self {
            Self::Range(r) => store.load_for_range(r.clone()),
            Self::List(v) => store.load_for_blocks(v),
        }
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
    let source_dirs = llvm::resolve_source_dirs(&args.source_dirs)?;
    let universe = llvm::universe_stamp(&source_dirs);
    info!(universe, "coverage universe");
    let store = Store::open(&dirs.store_path(), &binary_id, Some(&universe))?;
    // Writers killed mid-write_atomic leave uniquely-named *.tmp files that
    // would otherwise accumulate forever across crashes. Sweep only AFTER
    // Store::open: its exclusive redb lock guarantees no other backfill is
    // live on this data-dir (a doomed double-start must be refused before it
    // can delete a live writer's tmp files); the age threshold protects
    // non-locking processes like a concurrent `report`.
    let swept: usize = [dirs.spool(), dirs.codes(), dirs.tmp(), dirs.archive_profiles()]
        .iter()
        .map(|d| crate::spool::sweep_stale_tmp(d, Duration::from_secs(3600)))
        .sum();
    if swept > 0 {
        info!(swept, "removed stale tmp files from a previous crash");
    }
    let snapshot = selection.load_snapshot(&store)?;
    let tools = WorkerTools {
        llvm_profdata: llvm::find_tool("llvm-profdata", args.llvm_profdata.as_deref())?,
        llvm_cov: llvm::find_tool("llvm-cov", args.llvm_cov.as_deref())?,
        source_dirs,
    };
    info!(
        llvm_profdata = %tools.llvm_profdata.display(),
        llvm_cov = %tools.llvm_cov.display(),
        "llvm tools resolved"
    );

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
            let client = crate::r2::R2LightClient::new(
                &require(args.r2_endpoint.clone(), "--r2-endpoint")?,
                require(args.r2_bucket.clone(), "--r2-bucket")?,
                require(args.r2_access_key_id.clone(), "--r2-access-key-id")?,
                require(
                    args.r2_secret_access_key.as_ref().map(|s| s.as_ref().to_string()),
                    "--r2-secret-access-key",
                )?,
                Duration::from_secs(60),
            )?;
            info!("witness source: R2 (light decode)");
            Some(Arc::new(client))
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
    let todo: Vec<u64> = selection
        .iter()
        .filter(|n| !matches!(snapshot.blocks.get(n), Some(r) if r.status == BlockStatus::Ok))
        .collect();
    let retrying = todo.iter().filter(|n| snapshot.blocks.contains_key(n)).count();
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
    let mut manager_set = JoinSet::new();
    for id in 0..workers {
        let rx = dispatch_rx.clone();
        let tx = judged_tx.clone();
        let dirs = dirs.clone();
        let args = args.clone();
        let tools = tools.clone();
        manager_set.spawn(async move {
            worker_manager(id, rx, tx, dirs, args, tools).await;
        });
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
                // Retry until success — a block is never skipped. Transient
                // RPC/IO failures resolve on retry; a persistent failure loops
                // visibly in the log until the operator intervenes.
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
    let mut judge = JudgeState::new(snapshot, &store, dirs.clone(), total);
    while let Some(outcome) = judged_rx.recv().await {
        judge.ingest(outcome)?;
    }

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
    r2: Option<&crate::r2::R2LightClient>,
    dirs: &DataDir,
    verified_codes: &Arc<VerifiedCodes>,
    n: u64,
    block_cache: &mut Option<alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction>>,
) -> Result<()> {
    let spool_path = dirs.spool_entry(n);
    if spool_path.exists() {
        // Trust nothing left on disk: a spool the worker cannot use (crash
        // artifact, a SpoolEntry layout change between binary versions, a
        // corrupt inner block_json, or a wrong-numbered block) would
        // otherwise poison the worker on EVERY restart — the judge
        // fail-stops on it, the re-run skips the fetch because the file
        // exists, and the block can never complete. Validate exactly what
        // the worker will check and refetch on failure so every block
        // eventually executes.
        let existing = {
            let path = spool_path.clone();
            tokio::task::spawn_blocking(move || {
                let entry = SpoolEntry::read_from(&path)?;
                validate_spool_entry(&entry, n)?;
                Ok::<_, eyre::Report>(entry)
            })
            .await?
        };
        match existing {
            Ok(entry) => {
                // The spool is good, but its contract codes live in separate
                // files — re-resolve any missing or corrupt ones so the
                // worker never wedges on a half-cleaned codes dir.
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
        Some(r2) => r2.get_witness_light(n, hash).await?,
        None => client.get_witness_light(n, hash).await,
    };

    let code_hashes = stateless_core::collect_code_hashes(&light_witness.kvs);
    resolve_missing_codes(client, dirs, verified_codes, code_hashes.clone()).await?;

    let entry = SpoolEntry { block_json: serde_json::to_vec(block)?, light_witness, code_hashes };
    let path = spool_path.clone();
    tokio::task::spawn_blocking(move || entry.write_to(&path)).await??;
    Ok(())
}

/// Mirror of the worker's own requirements on a spool entry (see
/// `worker::process_block`): the inner block JSON must parse and carry the
/// expected block number. The bincode envelope decoding alone would pass a
/// spool whose opaque `block_json` bytes are damaged — and the worker would
/// then fail-stop the run on it, on every restart.
fn validate_spool_entry(entry: &SpoolEntry, block: u64) -> Result<()> {
    let parsed: alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction> =
        serde_json::from_slice(&entry.block_json).wrap_err("spool block_json does not parse")?;
    ensure!(
        parsed.header.inner.number == block,
        "spool holds block {}, expected {block}",
        parsed.header.inner.number
    );
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
            write_atomic(&dirs.code_file(&code_hash), &bytecode.original_bytes())?;
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

/// Owns one resident worker child. A block is NEVER skipped: worker crashes
/// respawn the child and retry the same block, indefinitely; long-running
/// blocks are only warned about (see `slow_block_warn_secs`), never killed.
/// What every worker of a run is launched with, resolved once by the
/// dispatcher so they cannot disagree.
#[derive(Clone)]
struct WorkerTools {
    llvm_profdata: PathBuf,
    llvm_cov: PathBuf,
    source_dirs: Vec<PathBuf>,
}

async fn worker_manager(
    id: usize,
    rx: kanal::AsyncReceiver<u64>,
    tx: tokio::sync::mpsc::Sender<WorkerResponse>,
    dirs: Arc<DataDir>,
    args: BackfillArgs,
    tools: WorkerTools,
) {
    let mut worker: Option<WorkerHandle> = None;
    let warn_after = Duration::from_secs(args.slow_block_warn_secs.max(1));

    while let Ok(n) = rx.recv().await {
        let req = WorkerRequest { block: n, spool: dirs.spool_entry(n) };
        let mut attempt = 0u64;
        let resp = loop {
            if worker.is_none() {
                match WorkerHandle::spawn(&args, &dirs, &tools) {
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
    fn spawn(args: &BackfillArgs, dirs: &DataDir, tools: &WorkerTools) -> Result<Self> {
        // The running image, not the file it came from: a worker respawned
        // after a rebuild must still be this build.
        let mut command = tokio::process::Command::new(crate::profile_rt::own_executable()?);
        command
            .arg("internal-worker")
            .arg("--genesis-file")
            .arg(&args.genesis_file)
            .arg("--codes-dir")
            .arg(dirs.codes())
            .arg("--tmp-dir")
            .arg(dirs.tmp())
            .arg("--llvm-profdata")
            .arg(&tools.llvm_profdata)
            .arg("--llvm-cov")
            .arg(&tools.llvm_cov);
        for dir in &tools.source_dirs {
            command.arg("--source-dir").arg(dir);
        }
        let mut child = command
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

    /// Sends one request and waits for the response with NO deadline: a slow
    /// block only produces a periodic warning, never a kill. Errors here mean
    /// the child actually died (closed stdout / bad frame), not slowness.
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

/// Single-consumer ingest: pattern dedup, promotion, persistence, progress.
struct JudgeState<'a> {
    store: &'a Store,
    dirs: Arc<DataDir>,
    counters: HashMap<u64, u32>,
    next_dense: u32,
    patterns: HashMap<u64, PatternRecord>,
    universe: BitSet,
    processed: u64,
    total: u64,
    new_patterns: u64,
    started: Instant,
    /// Worker wall-clock per successfully replayed block (spool load + replay
    /// + profraw + item extraction) — the E3 throughput measurement.
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
        snapshot: crate::store::StoreSnapshot,
        store: &'a Store,
        dirs: Arc<DataDir>,
        total: u64,
    ) -> Self {
        let mut counters = HashMap::with_capacity(snapshot.counters.len());
        let mut next_dense = 0u32;
        for (id, info) in &snapshot.counters {
            counters.insert(*id, info.dense);
            next_dense = next_dense.max(info.dense + 1);
        }
        let mut universe = BitSet::new();
        for rec in snapshot.patterns.values() {
            universe.union_with(&rec.bitmap);
        }
        info!(
            known_counters = counters.len(),
            known_patterns = snapshot.patterns.len(),
            universe = universe.count_ones(),
            "judge state restored"
        );
        Self {
            store,
            dirs,
            counters,
            next_dense,
            patterns: snapshot.patterns,
            universe,
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

        if !resp.ok {
            let record = block_record(&resp, BlockStatus::Error, None);
            self.store.commit_block(resp.block, &record, &[], None)?;
            self.cleanup_tmp(resp.block);
            eyre::bail!(
                "block {} failed to replay: {} — ABORTING (no block may be skipped; \
                 spool kept at {}; a re-run will retry this block)",
                resp.block,
                resp.error.as_deref().unwrap_or("unknown"),
                self.dirs.spool_entry(resp.block).display(),
            );
        }

        let sane = resp.gas_ok && resp.receipts_root_ok && resp.logs_bloom_ok;
        if !sane {
            let record = block_record(&resp, BlockStatus::Divergent, None);
            self.store.commit_block(resp.block, &record, &[], None)?;
            self.cleanup_tmp(resp.block);
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
        // Resolve counter ids → dense indices, registering unseen ids.
        let unknown: Vec<u64> =
            resp.counters.iter().filter(|id| !self.counters.contains_key(id)).copied().collect();
        let mut new_counters: Vec<(u64, CounterInfo)> = Vec::new();
        if !unknown.is_empty() {
            let details: HashMap<u64, &ItemDetail> =
                resp.new_items.iter().map(|d| (d.id, d)).collect();
            for id in &unknown {
                let d = details.get(id).ok_or_else(|| {
                    eyre::eyre!(
                        "item {id:#x} of block {} is new to the store, but its worker never \
                         reported where it lives",
                        resp.block
                    )
                })?;
                let dense = self.next_dense;
                self.next_dense += 1;
                self.counters.insert(*id, dense);
                let info = CounterInfo {
                    dense,
                    location: d.location.clone(),
                    kind: d.kind.clone(),
                    line: d.line,
                };
                new_counters.push((*id, info));
            }
        }

        let bitmap = BitSet::from_indices(resp.counters.iter().map(|id| self.counters[id]));

        // Shared probing walk (worker counters arrive sorted and deduped) —
        // the judge and merge MUST key identically; both go through
        // `resolve_pattern_slot`.
        let (key, occupied) = resolve_pattern_slot(&self.patterns, &resp.counters, &bitmap);

        if occupied {
            // Known pattern: merge stats; re-home the representative to the
            // lightest block seen (best fixture candidate; the profile is
            // keyed by pattern, so nothing on disk moves).
            let rec = self.patterns.get_mut(&key).expect("occupied slot");
            rec.hit_count += 1;
            // Completion order != block order under parallel workers, so both
            // bounds need clamping (merge does the same min/max fold —
            // sequential and merged stores must agree on provenance).
            rec.first_block = rec.first_block.min(resp.block);
            rec.last_block = rec.last_block.max(resp.block);
            if resp.elapsed_ms < rec.representative_elapsed_ms {
                rec.representative = resp.block;
                rec.representative_elapsed_ms = resp.elapsed_ms;
            }
        } else {
            let rec = PatternRecord {
                bits: bitmap.count_ones(),
                bitmap,
                first_block: resp.block,
                last_block: resp.block,
                hit_count: 1,
                representative: resp.block,
                representative_elapsed_ms: resp.elapsed_ms,
            };
            // Dominated patterns (strict subset of an existing one) can never
            // beat their dominator in set cover — record the bitmap for dedup
            // and stats, but skip the profile archive (93% of new patterns in
            // practice). set-cover excludes them from candidates, so a
            // selected block always has an archived profile.
            let dominated = self.patterns.values().any(|r| r.dominates(&rec));
            self.universe.union_with(&rec.bitmap);
            self.new_patterns += 1;
            info!(
                block = resp.block,
                pattern = %format!("{key:016x}"),
                bits = rec.bits,
                universe = self.universe.count_ones(),
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
            self.patterns.insert(key, rec);
        }

        // Shared tail: commit, then clean up (the spool entry goes after the
        // commit — a leftover from a crash in between is harmless junk).
        let _ = std::fs::remove_file(&resp.profile);
        let record = block_record(&resp, BlockStatus::Ok, Some(key));
        let rec_ref = &self.patterns[&key];
        self.store.commit_block(resp.block, &record, &new_counters, Some((key, rec_ref)))?;
        let _ = std::fs::remove_file(self.dirs.spool_entry(resp.block));
        Ok(())
    }

    fn cleanup_tmp(&self, block: u64) {
        let _ = std::fs::remove_file(self.dirs.tmp().join(format!("block_{block}.profraw")));
        let _ = std::fs::remove_file(self.dirs.tmp().join(format!("block_{block}.profdata")));
    }

    fn progress_log(&self) {
        let elapsed = self.started.elapsed().as_secs_f64();
        let rate = self.processed as f64 / elapsed.max(0.001);
        let eta_secs = (self.total.saturating_sub(self.processed)) as f64 / rate.max(0.001);
        info!(
            processed = self.processed,
            total = self.total,
            patterns = self.patterns.len(),
            universe = self.universe.count_ones(),
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
            universe_counters = self.universe.count_ones(),
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
    use crate::store::{StoreSnapshot, pattern_base_key};

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
        let rec = PatternRecord {
            bits: bitmap.count_ones(),
            bitmap,
            first_block: rep,
            last_block: rep,
            hit_count: 1,
            representative: rep,
            representative_elapsed_ms: elapsed,
        };
        (key, rec)
    }

    fn response(block: u64, counters: Vec<u64>, elapsed_ms: u64) -> WorkerResponse {
        WorkerResponse {
            block,
            block_hash: B256::repeat_byte(7),
            ok: true,
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
        let snapshot = StoreSnapshot {
            counters: [(1u64, counter_info(0)), (2, counter_info(1)), (3, counter_info(2))].into(),
            patterns: patterns.into_iter().collect(),
            blocks: HashMap::new(),
        };
        JudgeState::new(snapshot, store, dirs, 10)
    }

    #[test]
    fn known_pattern_dedups_and_rehomes_to_lightest() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(DataDir::new(tmp.path()));
        dirs.ensure_layout().unwrap();
        let store = Store::open(&dirs.store_path(), "test-id", Some("f")).unwrap();
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
        let store = Store::open(&dirs.store_path(), "test-id", Some("f")).unwrap();
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

    #[test]
    fn spool_validation_rejects_wrong_or_damaged_block_json() {
        let entry = |json: &[u8]| SpoolEntry {
            block_json: json.to_vec(),
            light_witness: stateless_core::LightWitness {
                kvs: Default::default(),
                levels: Default::default(),
            },
            code_hashes: vec![],
        };

        // Damaged inner JSON decodes fine as a bincode Vec<u8> but must fail
        // validation.
        assert!(validate_spool_entry(&entry(b"not json"), 7).is_err());

        // A real fixture block validates against its own number and is
        // rejected for any other.
        let fixture_path = std::fs::read_dir("../../test_data/mainnet/blocks")
            .expect("fixture dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "json"))
            .expect("at least one block fixture");
        let fixture = std::fs::read(&fixture_path).expect("fixture");
        let block: alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction> =
            serde_json::from_slice(&fixture).unwrap();
        let n = block.header.inner.number;
        assert!(validate_spool_entry(&entry(&fixture), n).is_ok());
        assert!(validate_spool_entry(&entry(&fixture), n + 1).is_err());
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
        let store = Store::open(&dirs.store_path(), "test-id", Some("f")).unwrap();
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
        assert_eq!(judge.universe.count_ones(), 3);

        // The store round-trips the newly committed pattern and block record
        // (the seeded dominator lived only in the in-memory snapshot).
        let snap = judge.store.load().unwrap();
        assert_eq!(snap.patterns.len(), 1);
        assert!(snap.patterns.contains_key(&sub_key));
        assert_eq!(snap.blocks[&200].status, BlockStatus::Ok);
        assert_eq!(snap.blocks[&200].pattern_key, Some(sub_key));
    }

    #[test]
    fn replay_error_and_divergence_fail_stop() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(DataDir::new(tmp.path()));
        dirs.ensure_layout().unwrap();
        let store = Store::open(&dirs.store_path(), "test-id", Some("f")).unwrap();
        let mut judge = judge_with(&store, dirs, vec![]);

        let mut bad = response(400, vec![1], 100);
        bad.ok = false;
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
