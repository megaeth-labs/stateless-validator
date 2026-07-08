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
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockId;
use clap::Args;
use eyre::{Context, Result, ensure};
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
    proto::{WorkerRequest, WorkerResponse},
    spool::{DataDir, SpoolEntry, write_atomic},
    store::{BlockRecord, BlockStatus, CounterInfo, PatternRecord, Store, current_binary_id},
};

/// Linear-probe step for pattern-key collisions (golden ratio).
const PROBE_STEP: u64 = 0x9E37_79B9_7F4A_7C15;
/// Abort the run after this many consecutive sanity failures — the chain spec
/// has almost certainly drifted and every further bitmap would be garbage.
const MAX_DIVERGENT_STREAK: u64 = 20;

#[derive(Args, Debug, Clone)]
pub struct BackfillArgs {
    /// First block of the range (inclusive).
    #[clap(long)]
    pub from: u64,
    /// Last block of the range (inclusive).
    #[clap(long)]
    pub to: u64,
    /// Data RPC endpoint(s) (blocks, bytecode).
    #[clap(
        long = "rpc-endpoint",
        env = "COVERAGE_REPLAYER_RPC_ENDPOINT",
        value_delimiter = ',',
        required = true
    )]
    pub rpc_endpoints: Vec<String>,
    /// Witness RPC endpoint(s) (`mega_getBlockWitness`).
    #[clap(
        long = "witness-endpoint",
        env = "COVERAGE_REPLAYER_WITNESS_ENDPOINT",
        value_delimiter = ',',
        required = true
    )]
    pub witness_endpoints: Vec<String>,
    /// Genesis JSON path (e.g. test_data/mainnet/genesis.json).
    #[clap(long, env = "COVERAGE_REPLAYER_GENESIS_FILE")]
    pub genesis_file: String,
    /// Root directory for spool/codes/archive/store.
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Number of resident worker subprocesses (default: cores - 2).
    #[clap(long, env = "COVERAGE_REPLAYER_WORKERS")]
    pub workers: Option<usize>,
    /// Concurrent block fetches.
    #[clap(long, default_value_t = 8)]
    pub fetch_concurrency: usize,
    /// Substring filter on PGO symbol names (coverage universe scope).
    #[clap(long, env = "COVERAGE_REPLAYER_SYMBOL_FILTER", default_value = "mega_evm")]
    pub symbol_filter: String,
    /// Explicit llvm-profdata path (default: auto-detect via rustc sysroot).
    #[clap(long)]
    pub llvm_profdata: Option<String>,
    /// Per-block worker timeout in seconds.
    #[clap(long, default_value_t = 600)]
    pub block_timeout_secs: u64,
}

enum Judged {
    Response(WorkerResponse),
    Failed { block: u64, error: String },
}

pub async fn run(args: BackfillArgs) -> Result<()> {
    ensure!(args.from <= args.to, "--from must be <= --to");
    ensure!(
        crate::profile_rt::is_instrumented_build(),
        "backfill requires the instrumented build (see [profile.coverage] in Cargo.toml)"
    );

    let dirs = Arc::new(DataDir::new(&args.data_dir)?);
    let binary_id = current_binary_id()?;
    info!(binary_id, "opening store");
    let store = Store::open(&dirs.store_path(), &binary_id)?;
    let snapshot = store.load()?;
    let llvm_profdata = llvm::find_tool("llvm-profdata", args.llvm_profdata.as_deref())?;
    info!(llvm_profdata = %llvm_profdata.display(), "llvm tools resolved");

    let endpoint_refs = |v: &[String]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let data_apis = endpoint_refs(&args.rpc_endpoints);
    let witness_apis = endpoint_refs(&args.witness_endpoints);
    let client = Arc::new(RpcClient::new(
        &data_apis.iter().map(String::as_str).collect::<Vec<_>>(),
        &witness_apis.iter().map(String::as_str).collect::<Vec<_>>(),
    )?);

    let latest = client.get_latest_block_number().await;
    ensure!(
        args.to <= latest,
        "--to {} is beyond the chain tip {latest}; refusing to wait on unfetchable blocks",
        args.to
    );

    // Work list: skip blocks already judged in a previous run.
    let todo: Vec<u64> =
        (args.from..=args.to).filter(|n| !snapshot.blocks.contains_key(n)).collect();
    let total = todo.len() as u64;
    info!(
        range = %format!("{}..={}", args.from, args.to),
        todo = total,
        skipped = (args.to - args.from + 1) - total,
        "backfill starting"
    );
    if todo.is_empty() {
        info!("nothing to do");
        return Ok(());
    }

    let workers = args.workers.unwrap_or_else(|| num_cpus::get().saturating_sub(2).max(1));
    let (dispatch_tx, dispatch_rx) = kanal::bounded_async::<u64>(workers * 2);
    let (judged_tx, mut judged_rx) = tokio::sync::mpsc::channel::<Judged>(workers * 2);

    // ---- worker managers ----
    let mut manager_set = JoinSet::new();
    for id in 0..workers {
        let rx = dispatch_rx.clone();
        let tx = judged_tx.clone();
        let dirs = dirs.clone();
        let args = args.clone();
        let llvm_profdata = llvm_profdata.clone();
        manager_set.spawn(async move {
            worker_manager(id, rx, tx, dirs, args, llvm_profdata).await;
        });
    }
    drop(dispatch_rx);
    drop(judged_tx);

    // ---- fetch stage ----
    let fetcher = {
        let dirs = dirs.clone();
        let client = client.clone();
        let dispatch_tx = dispatch_tx.clone();
        let fetch_concurrency = args.fetch_concurrency.max(1);
        tokio::spawn(async move {
            let mut inflight: JoinSet<(u64, Result<()>)> = JoinSet::new();
            for n in todo {
                while inflight.len() >= fetch_concurrency {
                    if let Some(done) = inflight.join_next().await {
                        forward_fetched(done, &dispatch_tx).await;
                    }
                }
                let dirs = dirs.clone();
                let client = client.clone();
                inflight.spawn(async move {
                    let res = fetch_block(&client, &dirs, n).await;
                    (n, res)
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
    Ok(())
}

async fn forward_fetched(
    done: std::result::Result<(u64, Result<()>), tokio::task::JoinError>,
    dispatch_tx: &kanal::AsyncSender<u64>,
) {
    match done {
        Ok((n, Ok(()))) => {
            // Queue closed (all managers dead) is fatal-ish; just log.
            if dispatch_tx.send(n).await.is_err() {
                warn!(block = n, "dispatch queue closed, dropping fetched block");
            }
        }
        Ok((n, Err(e))) => warn!(block = n, error = %format!("{e:#}"), "fetch failed, skipping"),
        Err(e) => warn!(error = %e, "fetch task panicked"),
    }
}

/// Fetches one block + witness, resolves missing bytecodes, writes the spool
/// entry. Skips work that already exists on disk (crash resume).
async fn fetch_block(client: &RpcClient, dirs: &DataDir, n: u64) -> Result<()> {
    let spool_path = dirs.spool_entry(n);
    if spool_path.exists() {
        return Ok(());
    }

    let block = client.get_block(BlockId::number(n), true).await;
    let hash = block.header.hash;
    // Zero-validation light fetch: no elliptic-curve work is spent on the
    // proof we never verify, and the raw compressed payload comes back
    // verbatim for archival — nothing to re-encode.
    let (light_witness, _mpt_witness, witness_payload) = client.get_witness_light(n, hash).await;

    let code_hashes = crate::spool::code_hashes_of(&light_witness);
    let missing: Vec<B256> =
        code_hashes.iter().filter(|h| !dirs.code_file(h).exists()).copied().collect();
    if !missing.is_empty() {
        let codes = client
            .get_codes(&missing, true)
            .await
            .map_err(|e| eyre::eyre!("fetch {} bytecodes: {e}", missing.len()))?;
        for (code_hash, bytecode) in codes {
            write_atomic(&dirs.code_file(&code_hash), &bytecode.original_bytes())?;
        }
    }

    let entry = SpoolEntry {
        block_hash: hash,
        block_json: serde_json::to_vec(&block)?,
        light_witness,
        witness_payload,
        code_hashes,
    };
    let path = spool_path.clone();
    tokio::task::spawn_blocking(move || entry.write_to(&path)).await??;
    Ok(())
}

/// Owns one resident worker child; respawns it on failure, retries a block
/// once in a fresh child before reporting it as failed.
async fn worker_manager(
    id: usize,
    rx: kanal::AsyncReceiver<u64>,
    tx: tokio::sync::mpsc::Sender<Judged>,
    dirs: Arc<DataDir>,
    args: BackfillArgs,
    llvm_profdata: PathBuf,
) {
    let mut worker: Option<WorkerHandle> = None;
    let timeout = Duration::from_secs(args.block_timeout_secs);

    while let Ok(n) = rx.recv().await {
        let req = WorkerRequest { block: n, spool: dirs.spool_entry(n) };
        let mut last_err = String::new();
        let mut delivered = false;

        for _attempt in 0..2 {
            if worker.is_none() {
                match WorkerHandle::spawn(&args, &dirs, &llvm_profdata) {
                    Ok(w) => worker = Some(w),
                    Err(e) => {
                        last_err = format!("spawn worker: {e:#}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
            let w = worker.as_mut().expect("just spawned");
            match w.round_trip(&req, timeout).await {
                Ok(resp) => {
                    let _ = tx.send(Judged::Response(resp)).await;
                    delivered = true;
                    break;
                }
                Err(e) => {
                    warn!(worker = id, block = n, error = %format!("{e:#}"), "worker round-trip failed, respawning");
                    last_err = format!("{e:#}");
                    if let Some(mut dead) = worker.take() {
                        dead.kill().await;
                    }
                }
            }
        }
        if !delivered {
            let _ = tx.send(Judged::Failed { block: n, error: last_err }).await;
        }
    }
}

struct WorkerHandle {
    child: Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
}

impl WorkerHandle {
    fn spawn(args: &BackfillArgs, dirs: &DataDir, llvm_profdata: &PathBuf) -> Result<Self> {
        let exe = std::env::current_exe()?;
        let mut child = tokio::process::Command::new(exe)
            .arg("internal-worker")
            .arg("--genesis-file")
            .arg(&args.genesis_file)
            .arg("--codes-dir")
            .arg(dirs.codes())
            .arg("--tmp-dir")
            .arg(dirs.tmp())
            .arg("--llvm-profdata")
            .arg(llvm_profdata)
            .arg("--symbol-filter")
            .arg(&args.symbol_filter)
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

    async fn round_trip(
        &mut self,
        req: &WorkerRequest,
        timeout: Duration,
    ) -> Result<WorkerResponse> {
        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;

        let next = tokio::time::timeout(timeout, self.stdout.next_line())
            .await
            .map_err(|_| eyre::eyre!("worker timed out after {timeout:?}"))??;
        let resp_line = next.ok_or_else(|| eyre::eyre!("worker closed stdout (crashed?)"))?;
        let resp: WorkerResponse = serde_json::from_str(&resp_line)
            .map_err(|e| eyre::eyre!("bad worker response {resp_line:?}: {e}"))?;
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
    divergent_streak: u64,
    started: Instant,
    /// Worker wall-clock per successfully replayed block (spool load + replay
    /// + profraw + bitmap extraction) — the E3 throughput measurement.
    elapsed_ok_ms: Vec<u64>,
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
            divergent_streak: 0,
            started: Instant::now(),
            elapsed_ok_ms: Vec::new(),
        }
    }

    fn ingest(&mut self, outcome: Judged) -> Result<()> {
        self.processed += 1;
        match outcome {
            Judged::Failed { block, error } => {
                warn!(block, error, "block failed permanently, quarantined");
                let record = BlockRecord {
                    hash: B256::ZERO,
                    status: BlockStatus::Error,
                    pattern_key: None,
                    gas_used: 0,
                    tx_count: 0,
                    elapsed_ms: 0,
                    error: Some(error),
                };
                self.store.commit_block(block, &record, &[], None)?;
                self.cleanup_tmp(block);
                // Spool entry is kept for debugging.
            }
            Judged::Response(resp) if !resp.ok => {
                warn!(block = resp.block, error = ?resp.error, "replay error, quarantined");
                let record = BlockRecord {
                    hash: resp.block_hash,
                    status: BlockStatus::Error,
                    pattern_key: None,
                    gas_used: 0,
                    tx_count: resp.tx_count,
                    elapsed_ms: resp.elapsed_ms,
                    error: resp.error.clone(),
                };
                self.store.commit_block(resp.block, &record, &[], None)?;
                self.cleanup_tmp(resp.block);
            }
            Judged::Response(resp) => {
                let sane = resp.gas_ok && resp.receipts_root_ok && resp.logs_bloom_ok;
                if !sane {
                    self.divergent_streak += 1;
                    warn!(
                        block = resp.block,
                        gas_ok = resp.gas_ok,
                        receipts_root_ok = resp.receipts_root_ok,
                        logs_bloom_ok = resp.logs_bloom_ok,
                        streak = self.divergent_streak,
                        "SANITY FAILURE — execution diverged from header, bitmap NOT ingested"
                    );
                    let record = BlockRecord {
                        hash: resp.block_hash,
                        status: BlockStatus::Divergent,
                        pattern_key: None,
                        gas_used: resp.gas_used,
                        tx_count: resp.tx_count,
                        elapsed_ms: resp.elapsed_ms,
                        error: None,
                    };
                    self.store.commit_block(resp.block, &record, &[], None)?;
                    self.cleanup_tmp(resp.block);
                    ensure!(
                        self.divergent_streak < MAX_DIVERGENT_STREAK,
                        "{} consecutive divergent blocks — chain spec drift, aborting",
                        self.divergent_streak
                    );
                } else {
                    self.divergent_streak = 0;
                    self.ingest_ok(resp)?;
                }
            }
        }
        if self.processed.is_multiple_of(25) || self.processed == self.total {
            self.progress_log();
        }
        Ok(())
    }

    fn ingest_ok(&mut self, resp: WorkerResponse) -> Result<()> {
        self.elapsed_ok_ms.push(resp.elapsed_ms);
        // Resolve counter ids → dense indices, registering unseen ids.
        let unknown: Vec<u64> =
            resp.counters.iter().filter(|id| !self.counters.contains_key(id)).copied().collect();
        let mut new_counters: Vec<(u64, CounterInfo)> = Vec::new();
        if !unknown.is_empty() {
            let details = read_symbols_tsv(&resp.symbols_tsv)?;
            for id in &unknown {
                let (index, func_hash, symbol) = details
                    .get(id)
                    .cloned()
                    .ok_or_else(|| eyre::eyre!("counter {id:#x} missing from symbols tsv"))?;
                let dense = self.next_dense;
                self.next_dense += 1;
                self.counters.insert(*id, dense);
                new_counters.push((*id, CounterInfo { dense, symbol, func_hash, index }));
            }
        }

        let bitmap = BitSet::from_indices(resp.counters.iter().map(|id| self.counters[id]));

        // Pattern lookup with collision probing (exact bitmap comparison).
        let mut key = {
            use std::hash::Hasher;
            let mut h = rustc_hash::FxHasher::default();
            for id in &resp.counters {
                h.write_u64(*id);
            }
            h.finish()
        };
        let is_new = loop {
            match self.patterns.get_mut(&key) {
                None => break true,
                Some(rec) if rec.bitmap == bitmap => {
                    rec.hit_count += 1;
                    rec.last_block = rec.last_block.max(resp.block);
                    break false;
                }
                Some(_) => key = key.wrapping_add(PROBE_STEP),
            }
        };

        if is_new {
            let rec = PatternRecord {
                bits: bitmap.count_ones(),
                bitmap,
                first_block: resp.block,
                last_block: resp.block,
                hit_count: 1,
                representative: resp.block,
            };
            self.universe.union_with(&rec.bitmap);
            self.new_patterns += 1;
            info!(
                block = resp.block,
                pattern = %format!("{key:016x}"),
                bits = rec.bits,
                universe = self.universe.count_ones(),
                "NEW coverage pattern — promoting block to archive"
            );
            // Promote: spool entry + profraw move to the permanent archive.
            std::fs::rename(
                self.dirs.spool_entry(resp.block),
                self.dirs.archived_entry(resp.block),
            )
            .wrap_err("promote spool entry")?;
            std::fs::rename(&resp.profraw, self.dirs.archived_profraw(resp.block))
                .wrap_err("promote profraw")?;
            let _ = std::fs::remove_file(&resp.symbols_tsv);

            let record = self.block_record_ok(&resp, key);
            self.patterns.insert(key, rec);
            let rec_ref = &self.patterns[&key];
            self.store.commit_block(resp.block, &record, &new_counters, Some((key, rec_ref)))?;
        } else {
            // Known pattern: delete everything, keep only the block record.
            let _ = std::fs::remove_file(self.dirs.spool_entry(resp.block));
            let _ = std::fs::remove_file(&resp.profraw);
            let _ = std::fs::remove_file(&resp.symbols_tsv);
            let record = self.block_record_ok(&resp, key);
            let rec_ref = &self.patterns[&key];
            self.store.commit_block(resp.block, &record, &new_counters, Some((key, rec_ref)))?;
        }
        Ok(())
    }

    fn block_record_ok(&self, resp: &WorkerResponse, pattern_key: u64) -> BlockRecord {
        BlockRecord {
            hash: resp.block_hash,
            status: BlockStatus::Ok,
            pattern_key: Some(pattern_key),
            gas_used: resp.gas_used,
            tx_count: resp.tx_count,
            elapsed_ms: resp.elapsed_ms,
            error: None,
        }
    }

    fn cleanup_tmp(&self, block: u64) {
        let _ = std::fs::remove_file(self.dirs.tmp().join(format!("block_{block}.profraw")));
        let _ =
            std::fs::remove_file(self.dirs.tmp().join(format!("block_{block}.symbols.tsv.zst")));
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

    fn final_summary(&self) {
        info!(
            processed = self.processed,
            new_patterns = self.new_patterns,
            total_patterns = self.patterns.len(),
            universe_counters = self.universe.count_ones(),
            elapsed = %format!("{:.1}s", self.started.elapsed().as_secs_f64()),
            "backfill finished"
        );
        if !self.elapsed_ok_ms.is_empty() {
            let mut v = self.elapsed_ok_ms.clone();
            v.sort_unstable();
            let avg = v.iter().sum::<u64>() as f64 / v.len() as f64;
            info!(
                blocks = v.len(),
                avg_ms = %format!("{avg:.0}"),
                p50_ms = v[v.len() / 2],
                p95_ms = v[(v.len() * 95 / 100).min(v.len() - 1)],
                max_ms = v[v.len() - 1],
                "per-block worker time (replay + profraw + bitmap)"
            );
        }
    }
}

/// Parses a worker symbols sidecar: `id_hex \t index \t func_hash \t symbol`.
fn read_symbols_tsv(path: &std::path::Path) -> Result<HashMap<u64, (u32, String, String)>> {
    let compressed = std::fs::read(path).wrap_err_with(|| format!("read {}", path.display()))?;
    let raw = zstd::decode_all(&compressed[..])?;
    let text = String::from_utf8(raw)?;
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut parts = line.splitn(4, '\t');
        let (Some(id), Some(index), Some(func_hash), Some(symbol)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let id = u64::from_str_radix(id, 16)?;
        map.insert(id, (index.parse()?, func_hash.to_string(), symbol.to_string()));
    }
    Ok(map)
}
