//! Debug/Trace RPC Server
//!
//! # Overview
//! A standalone RPC server for `debug_*` and `trace_*` methods using stateless execution.
//! Data can be fetched from upstream RPC endpoints or from a local database with chain sync.
//! With the `--r2-*` flags every request-serving witness fetch tries the R2 bucket first,
//! falling back to the RPC chain; the chain itself routes by block age — historical blocks
//! skip the internal generator endpoint (which only retains a small recent window) and go
//! straight to the fallback endpoints. Chain-sync prefetch always uses the full chain.
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        RPC Server                               │
//! │  Receives external requests, invokes executor, returns traces   │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │            HTTP Response Cache                           │   │
//! │  │  Caches pre-serialized JSON responses (quick_cache)      │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Stateless Executor                           │
//! │  Replays blocks using witness data to generate transaction traces│
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      DataProvider                               │
//! │  Multi-level lookup: Local DB → Remote RPC (with single-flight) │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported RPC Methods
//! - `debug_traceBlockByNumber` - Trace block execution by block number
//! - `debug_traceBlockByHash` - Trace block execution by block hash
//! - `debug_traceTransaction` - Trace a single transaction execution
//! - `trace_block` - Parity-style block tracing (flat call traces)
//! - `trace_transaction` - Parity-style transaction tracing
//! - `debug_getCacheStatus` - Query current response cache status
//!
//! # Operating Modes
//! - **Stateless mode**: Without `data_dir`, all data is fetched from remote RPC endpoints
//! - **Local cache mode**: With `data_dir`, enables chain sync to pre-fetch blocks into local DB

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_genesis::Genesis;
use alloy_primitives::BlockHash;
use alloy_rpc_types_eth::BlockId;
use clap::Parser;
use eyre::Result;
use jsonrpsee::server::{Server, ServerConfig, middleware::rpc::RpcServiceBuilder};
use stateless_common::{
    R2CountFlag, R2Flag, R2Flags, R2Target, R2TuningFlag, RedactedSecret, RpcClient,
    RpcClientConfig, logging::LogArgs, validate_r2_flags,
};
use stateless_core::{
    BisectResolver, ChainStore, ContractStore, DivergenceLookups, PipelineConfig,
    chain_spec::ChainSpec, db::BlockMeta, pipeline::run_pipeline,
};
use stateless_db::ContractCache;
use tokio::task;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, warn};

mod admin;
mod admission;
mod block_data_cache;
mod body_metrics;
mod chain_sync;
mod compression;
mod data_provider;
mod metrics;
mod middleware;
mod r2_witness;
mod raw_json;
mod response_cache;
mod response_size;
mod rpc_middleware;
mod rpc_service;
mod server_db;
mod timing;
mod tracing_executor;

use admission::AdmissionLimiter;
use block_data_cache::{
    BLOCK_DATA_CACHE_SHARDS, BlockDataCache, DEFAULT_BLOCK_DATA_CACHE_MAX_BYTES,
};
use data_provider::{DataProvider, NoopContractStore, WitnessFetchConfig};
use r2_witness::R2WitnessSource;
use response_cache::{DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS, ResponseCache, ResponseCacheConfig};
use rpc_service::RpcContext;
use server_db::{BlockStore, ServerDB};

use crate::chain_sync::{TraceFetcher, TraceHooks, TraceProcessor};

/// Command line arguments for the debug-trace-server.
#[derive(Parser, Debug)]
#[clap(name = "debug-trace-server", about = "Debug/Trace RPC Server")]
// Every `--r2-*` coherence rule is enforced after parsing, by
// `stateless_common::validate_r2_flags`, rather than through clap attributes: this workspace
// builds clap without its `error-context` feature (root `Cargo.toml`), so every clap rejection
// is generic and names no argument — useless to an operator debugging an env file. A blank env
// line also reads as *presence* to clap, so leaving exclusion to it would report a phantom
// conflict where the real fault is an empty value.
struct Args {
    /// RPC server listen address.
    #[clap(long, env = "DEBUG_TRACE_SERVER_ADDR", default_value = "0.0.0.0:8545")]
    addr: String,

    /// One or more upstream RPC endpoint URLs for fetching blockchain data (tried in order).
    /// Accepts repeated flags (`--rpc-endpoint a --rpc-endpoint b`) or a comma-separated
    /// list (`--rpc-endpoint a,b`, also via the env var).
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_RPC_ENDPOINT",
        required = true,
        value_delimiter = ',',
        action = clap::ArgAction::Append,
    )]
    rpc_endpoint: Vec<String>,

    /// One or more durable witness endpoint URLs for fetching witness data (tried in order).
    /// Accepts repeated flags (`--witness-endpoint a --witness-endpoint b`) or a comma-separated
    /// list (`--witness-endpoint a,b`, also via the env var). No endpoint here is ever special
    /// by position; declare the internal generator via `--witness-generator-endpoint`.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_WITNESS_ENDPOINT",
        required_unless_present = "witness_generator_endpoint",
        value_delimiter = ',',
        action = clap::ArgAction::Append,
    )]
    witness_endpoint: Vec<String>,

    /// The internal witness generator endpoint. It is probed first for recent blocks and
    /// skipped for historical ones (it only retains about `--witness-local-window` blocks),
    /// while `--witness-endpoint` lists the durable fallbacks (optional when this flag is
    /// set — generator-only works like any single-endpoint config, without routing). When
    /// absent, historical routing is disabled and every witness endpoint is plain failover.
    #[clap(long, env = "DEBUG_TRACE_SERVER_WITNESS_GENERATOR_ENDPOINT")]
    witness_generator_endpoint: Option<String>,

    /// Enable Prometheus metrics exporter.
    #[clap(long, env = "DEBUG_TRACE_SERVER_METRICS_ENABLED")]
    metrics_enabled: bool,

    /// Port for Prometheus metrics HTTP endpoint.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_METRICS_PORT",
        default_value_t = metrics::DEFAULT_METRICS_PORT
    )]
    metrics_port: u16,

    /// Path to genesis JSON file.
    #[clap(long, env = "DEBUG_TRACE_SERVER_GENESIS_FILE")]
    genesis_file: Option<String>,

    /// Data directory path for local database and chain sync.
    #[clap(long, env = "DEBUG_TRACE_SERVER_DATA_DIR")]
    data_dir: Option<String>,

    /// Trusted starting block hash for chain initialization.
    #[clap(long, env = "DEBUG_TRACE_SERVER_START_BLOCK")]
    start_block: Option<String>,

    /// Witness fetch timeout in seconds. No single witness-chain attempt may run longer
    /// than half of what the stage has left when the chain starts, so one stalled endpoint
    /// can never consume the whole stage and starve the retry rotation.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_WITNESS_TIMEOUT",
        default_value_t = data_provider::DEFAULT_WITNESS_TIMEOUT_SECS
    )]
    witness_timeout: u64,

    /// Total block-fetch timeout in seconds (header + witness + block + contracts).
    /// Bounds `RpcClient`'s unbounded retry loop so deterministic upstream errors
    /// (e.g. requesting a nonexistent block) surface instead of hanging the client.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_BLOCK_FETCH_TIMEOUT_SECS",
        default_value_t = data_provider::DEFAULT_BLOCK_FETCH_TIMEOUT_SECS
    )]
    block_fetch_timeout: u64,

    /// Maximum memory for response cache (e.g., "1GB", "512MB", "1024").
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_RESPONSE_CACHE_MAX_SIZE",
        default_value = "1GB",
        value_parser = parse_size,
    )]
    response_cache_max_size: u64,

    /// Disable the HTTP response cache entirely (every trace response is recomputed).
    #[clap(long, env = "DEBUG_TRACE_SERVER_RESPONSE_CACHE_DISABLED")]
    response_cache_disabled: bool,

    /// Disable gzip/zstd response compression (normally negotiated per request via the
    /// client's `Accept-Encoding` header; clients that do not opt in always get
    /// identity bodies either way).
    #[clap(long, env = "DEBUG_TRACE_SERVER_RESPONSE_COMPRESSION_DISABLED")]
    response_compression_disabled: bool,

    /// Maximum entries of one inbound JSON-RPC batch request executed concurrently.
    /// Each entry goes through the regular per-request pipeline either way; the bound
    /// only stops a single huge batch from monopolizing downstream resources. Set to 1
    /// for strictly sequential batch execution.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_BATCH_ITEM_CONCURRENCY",
        default_value_t = rpc_middleware::DEFAULT_BATCH_ITEM_CONCURRENCY,
        value_parser = clap::value_parser!(u32).range(1..),
    )]
    batch_item_concurrency: u32,

    /// Requests that may be fetching and replaying a block at once.
    ///
    /// This is the process's real work budget: every other concurrency knob here caps what
    /// we ask of someone else. Sizing is not a core count — only about 2% of a trace
    /// request is CPU, the rest is waiting on the upstream node and R2 — so derive it from
    /// measured service time instead: `throughput x mean_handler_seconds`. The default sits
    /// just above the highest occupancy this server has been measured serving cleanly, so it
    /// bounds a previously unbounded process without throttling a known-good workload.
    ///
    /// A response-cache hit never takes one of these.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_ADMISSION_MAX_CONCURRENT",
        default_value_t = DEFAULT_ADMISSION_MAX_CONCURRENT,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    admission_max_concurrent: u64,

    /// Requests that may wait for an execution permit on top of those holding one.
    ///
    /// A latency knob, not a memory one: queue depth divided by the service rate is how long
    /// a request waits, so `queue = rate x acceptable_wait`. At 1000 blocks/s a 1000-deep
    /// queue is one second of waiting. `0` means execute-or-shed with no waiting at all.
    /// Beyond `max_concurrent + max_queue` admitted requests, arrivals are refused
    /// immediately with `-32013` rather than queued indefinitely.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_ADMISSION_MAX_QUEUE",
        default_value_t = DEFAULT_ADMISSION_MAX_QUEUE,
    )]
    admission_max_queue: u64,

    /// Requests running a memory-hungry tracer that may execute at once, on top of needing
    /// an ordinary execution permit.
    ///
    /// `prestateTracer`, JS tracers, `muxTracer` and struct-logger requests with non-default
    /// flags can each produce hundreds of megabytes from one large block — a single such
    /// response has been measured at over 900 MB. This sub-cap, multiplied by
    /// `--max-response-size`, is what makes the process's worst-case resident set a number
    /// an operator can compute; size it from available memory, not from throughput.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_ADMISSION_HEAVY_MAX_CONCURRENT",
        default_value_t = DEFAULT_ADMISSION_HEAVY_MAX_CONCURRENT,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    admission_heavy_max_concurrent: u64,

    /// Disables inbound admission control entirely (kill switch).
    ///
    /// Restores the pre-gate behaviour: every request executes immediately and the process
    /// accepts unbounded concurrent work.
    #[clap(long, env = "DEBUG_TRACE_SERVER_ADMISSION_DISABLED")]
    admission_disabled: bool,

    /// Maximum serialized size of a single RPC response body.
    ///
    /// Checked where this server serializes the reply, so an over-limit body is discarded
    /// before it can be copied again into the JSON-RPC envelope and, for a batch, retained
    /// there until every entry finishes — that accumulation, not any single response, is what
    /// has previously exhausted memory on this server. Over-limit responses are answered with
    /// an error and counted on `debug_trace_response_oversized_total`.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_MAX_RESPONSE_SIZE",
        default_value = "256MB",
        value_parser = parse_size,
    )]
    max_response_size: u64,

    /// Maximum assembled size of one JSON-RPC batch response.
    ///
    /// A different bound from `--max-response-size`, because it bounds a different thing: the
    /// batch builder retains every completed entry's body until the whole batch finishes, so a
    /// batch's memory is the *sum* of its entries, not the largest of them. Left unbounded
    /// this is the dominant term — entries are capped individually while their accumulation is
    /// not, and a batch's entry count is limited only by the request body size. A batch that
    /// exceeds this is answered with a single oversized-response error.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_MAX_BATCH_RESPONSE_SIZE",
        default_value = "1GB",
        value_parser = parse_size,
    )]
    max_batch_response_size: u64,

    /// Address of the loopback-only admin RPC listener (e.g. `127.0.0.1:8546`).
    ///
    /// Serves `admin_getConcurrencyLimit` / `admin_setConcurrencyLimit`, which retune the
    /// admission gate without a restart. Omitted, no admin listener runs and the limits are
    /// fixed for the process's lifetime. This port has no authentication and its setters can
    /// throttle request serving, so a non-loopback bind is refused at startup; reach it
    /// through a port-forward or a sidecar.
    #[clap(long, env = "DEBUG_TRACE_SERVER_ADMIN_ADDR")]
    admin_addr: Option<String>,

    /// Estimated number of items in response cache (for initial capacity). Must be at
    /// least 1 — disable the cache with `--response-cache-disabled`, not with 0.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_RESPONSE_CACHE_ESTIMATED_ITEMS",
        default_value_t = DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS as u64,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    response_cache_estimated_items: u64,

    /// Maximum entries in the in-memory canonical-hash memo (number → hash for
    /// depth-final heights below the sync window). Roughly 80 bytes per entry when full;
    /// it fills lazily, so a generous cap costs nothing until a deep historical scan
    /// actually uses it.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_CANONICAL_HASH_MEMO_CAPACITY",
        default_value_t = data_provider::DEFAULT_CANONICAL_HASH_MEMO_CAPACITY,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    canonical_hash_memo_capacity: u64,

    /// Maximum memory for the in-memory block-data cache (e.g., "1GB", "512MB"; default 1GB).
    /// Set to "0" to disable. Blocks heavier than a cache shard's budget are never
    /// admitted, so very large blocks bypass the cache instead of thrashing it.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_BLOCK_DATA_CACHE_MAX_SIZE",
        default_value_t = DEFAULT_BLOCK_DATA_CACHE_MAX_BYTES,
        value_parser = parse_size,
    )]
    block_data_cache_max_size: u64,

    /// Number of recent blocks to retain in database (older blocks are pruned).
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_BLOCKS_TO_KEEP",
        default_value_t = DEFAULT_BLOCKS_TO_KEEP
    )]
    blocks_to_keep: u64,

    /// Maximum database file size before additional pruning triggers (e.g., "10GB", "512MB").
    /// Set to "0" to disable size-based pruning (only block-count pruning applies).
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_DB_MAX_SIZE",
        default_value = "0",
        value_parser = parse_size,
    )]
    db_max_size: u64,

    /// Interval between database pruning cycles in seconds.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_PRUNER_INTERVAL_SECS",
        default_value_t = DEFAULT_PRUNER_INTERVAL_SECS
    )]
    pruner_interval_secs: u64,

    /// Size-based pruning never removes block bodies above `tip - this`: a floor of recent
    /// bodies that stays resident even when the DB file remains over `--db-max-size`
    /// (redb files never shrink, so a permanently-over-limit file must not consume the
    /// whole body retention).
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_SIZE_PRUNE_MIN_RETAIN",
        default_value_t = DEFAULT_SIZE_PRUNE_MIN_RETAIN
    )]
    size_prune_min_retain: u64,

    /// Maximum concurrent in-flight data-endpoint requests (blocks, headers, code, tx).
    /// Omit for unlimited.
    #[clap(long, env = "DEBUG_TRACE_SERVER_DATA_MAX_CONCURRENT_REQUESTS")]
    data_max_concurrent_requests: Option<usize>,

    /// Maximum concurrent in-flight witness fetches, independent of the data cap.
    /// Omit for unlimited. One global cap: recent and historical witness routes share it.
    #[clap(long, env = "DEBUG_TRACE_SERVER_WITNESS_MAX_CONCURRENT_REQUESTS")]
    witness_max_concurrent_requests: Option<usize>,

    /// Blocks fewer than this many blocks below the local tip fetch witnesses through the
    /// full witness endpoint chain (internal generator first); blocks at least this far below
    /// skip the first witness endpoint — the generator only retains about this window (its
    /// `BACKUP` env, deployed at 4096), so probing it for historical blocks is a guaranteed
    /// miss. Requires a generator plus at least one fallback witness endpoint (see
    /// `--witness-generator-endpoint`) and a local DB (`--data-dir`), whose tip
    /// anchors block age; otherwise all blocks use the full chain. Applies to request
    /// serving; the chain-sync prefetch routes by freshness against the remote head
    /// instead (frontier-fresh blocks give the generator a short exclusive grace).
    /// Should match the generator's `BACKUP`.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_WITNESS_LOCAL_WINDOW",
        default_value_t = data_provider::DEFAULT_WITNESS_LOCAL_WINDOW
    )]
    witness_local_window: u64,

    /// Witness-stage budget in seconds for blocks at or below the local tip. Defaults to the
    /// full `--witness-timeout` budget (tracking it when raised); lower it to fail fast on
    /// blocks whose witness is likely pruned everywhere. Clamped to `--witness-timeout`.
    #[clap(long, env = "DEBUG_TRACE_SERVER_WITNESS_OLD_BLOCK_TIMEOUT")]
    witness_old_block_timeout: Option<u64>,

    /// R2 S3 endpoint origin, e.g. `https://<account>.r2.cloudflarestorage.com` (no bucket
    /// path). With `--r2-bucket` and the credential flags, every witness fetch tries the
    /// bucket first, with the RPC witness chain as fallback — frontier probes usually miss
    /// (one fast 404) while historical fetches are served here. Requires a local DB
    /// (`--data-dir`) to anchor block age. Alternative target: `--r2-custom-domain`.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_ENDPOINT")]
    r2_endpoint: Option<String>,

    /// Cloudflare custom domain fronting the witness bucket, e.g.
    /// `https://witness.example.com` (bare origin — objects are fetched as `/{key}`).
    /// Alternative to the `--r2-endpoint` credential quad: GETs go unsigned through the CDN
    /// edge, which multiplexes them over HTTP/2 and can serve the immutable witness objects
    /// from edge cache. Client-side routing, budgets, and fallback match the S3 target
    /// (including the `--data-dir` requirement); edge behavior is zone configuration —
    /// **any cache rule making these objects cacheable must set 404s to bypass cache**,
    /// or a pre-upload frontier miss gets pinned for the negative-cache TTL and a cached
    /// 404 can false-fire the below-band `missing` bucket-integrity alarm.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_CUSTOM_DOMAIN")]
    r2_custom_domain: Option<String>,

    /// Cloudflare Access service-token client id, sent as `CF-Access-Client-Id` on every
    /// custom-domain GET. Omit when the domain is locked by an IP allowlist instead.
    /// Redacted like the secret: the id alone is enough to look up the token.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_ACCESS_CLIENT_ID")]
    r2_access_client_id: Option<RedactedSecret>,

    /// Cloudflare Access service-token client secret, sent as `CF-Access-Client-Secret`.
    /// Prefer the env var over the flag so the secret stays out of shell history and
    /// process listings.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_ACCESS_CLIENT_SECRET")]
    r2_access_client_secret: Option<RedactedSecret>,

    /// R2 bucket holding the archived witness objects. Requires `--r2-endpoint`.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_BUCKET")]
    r2_bucket: Option<String>,

    /// R2 access key id (Object Read). Requires `--r2-endpoint`.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_ACCESS_KEY_ID")]
    r2_access_key_id: Option<String>,

    /// R2 secret access key. Requires `--r2-endpoint`. Prefer the env var over the flag so
    /// the secret stays out of shell history and process listings.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_SECRET_ACCESS_KEY")]
    r2_secret_access_key: Option<RedactedSecret>,

    /// R2 connection-establishment timeout (milliseconds). A healthy handshake to the local
    /// anycast edge is tens of ms. On the S3 endpoint, hangs past this are the per-IP
    /// connection-budget mitigation's signature and keep landing in the connect phase, since
    /// every in-flight GET holds its own connection; they surface as retryable `connect`-kind
    /// errors, falling back to the RPC chain fast. The custom domain pools a single h2
    /// connection, so this bounds its first handshake and any reconnect — a path that breaks
    /// after that surfaces as `transport` against the per-attempt budget instead, until the
    /// keep-alive ping reaps the connection.
    ///
    /// An `Option` rather than a clap default so "explicitly set" stays distinguishable:
    /// setting it with no R2 target configured is rejected by name instead of being silently
    /// ignored. [`DEFAULT_CONNECT_TIMEOUT`] applies when it is absent.
    ///
    /// [`DEFAULT_CONNECT_TIMEOUT`]: stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_R2_CONNECT_TIMEOUT_MS",
        value_parser = clap::value_parser!(u64).range(100..),
    )]
    r2_connect_timeout_ms: Option<u64>,

    /// Maximum concurrent in-flight R2 witness GETs. Omit for unlimited. Deliberately
    /// separate from
    /// `--witness-max-concurrent-requests`: that cap sizes the shared RPC gateway, while R2
    /// tolerates far higher parallelism.
    ///
    /// On the custom-domain target keep this at or below the edge's per-connection stream
    /// limit (Cloudflare's is 100, advertised in its `SETTINGS_MAX_CONCURRENT_STREAMS`):
    /// anything above it queues inside the HTTP/2 connection rather than on this semaphore,
    /// where the wait counts against the per-attempt timeout and never reaches
    /// `debug_trace_r2_witness_queue_wait_seconds`. The fetcher warns at startup when the
    /// configured value exceeds the limit.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_MAX_CONCURRENT_REQUESTS")]
    r2_max_concurrent_requests: Option<usize>,

    /// HTTP/2 connections the custom-domain target spreads its GETs over (default: 1).
    ///
    /// One `reqwest::Client` holds exactly one HTTP/2 connection and hyper opens no second one
    /// when the first saturates, so this is the only way past the edge's per-connection stream
    /// limit — and the only way a dropped connection stops taking every GET riding it down
    /// with it. `--r2-max-concurrent-requests` remains the cap across all of them, split evenly
    /// and rounded up, so raising this alone spreads the same concurrency thinner rather than
    /// lifting the ceiling; a count larger than that cap is rejected, since the surplus
    /// connections could never be filled.
    ///
    /// Taken as text and parsed after clap so a blank env line is rejected by name rather than
    /// through clap's unnamed value error.
    #[clap(long, env = "DEBUG_TRACE_SERVER_R2_CONNECTIONS")]
    r2_connections: Option<String>,

    /// Chain-sync pipeline tip buffer: stay this many blocks behind the upstream head so the
    /// fetcher does not race the witness generator — a fetch issued the moment a block appears
    /// typically arrives before its witness is written and burns a failed round plus a backoff
    /// sleep. 0 = fetch right at the head.
    #[clap(long, env = "DEBUG_TRACE_SERVER_TIP_BUFFER", default_value_t = 2)]
    tip_buffer: u64,

    /// Per-attempt RPC timeout (milliseconds). Must be ≥ 100ms.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_RPC_PER_ATTEMPT_TIMEOUT_MS",
        value_parser = clap::value_parser!(u64).range(100..),
    )]
    rpc_per_attempt_timeout_ms: Option<u64>,

    /// Logging configuration.
    #[command(flatten)]
    log: LogArgs,
}

/// Database filename for the trace server's local storage.
const TRACE_SERVER_DB_FILENAME: &str = "trace_server.redb";

/// Default number of blocks to keep in database.
const DEFAULT_BLOCKS_TO_KEEP: u64 = 1000;

/// Default pruner interval in seconds (5 minutes).
const DEFAULT_PRUNER_INTERVAL_SECS: u64 = 300;

/// Default floor of recent block bodies that size-based pruning never removes.
const DEFAULT_SIZE_PRUNE_MIN_RETAIN: u64 = 256;

/// Default execution-permit budget.
///
/// Just above the highest per-handler occupancy this server has been measured sustaining
/// with zero failures, computed by Little's law from that run's request-duration counters
/// rather than from its offered concurrency — the two differ by 3x, and the offered figure
/// would over-provision by the same factor. Deliberately above every clean measurement
/// rather than at a knee: no saturation point has been established for this workload, and a
/// default that throttles a known-good one is a worse failure than a loose bound.
const DEFAULT_ADMISSION_MAX_CONCURRENT: u64 = 640;

/// Default queue depth — roughly four seconds of backlog at the throughput measured on the
/// cold path, which keeps a full queue comfortably inside the block-fetch deadline.
const DEFAULT_ADMISSION_MAX_QUEUE: u64 = 8192;

/// Default budget for memory-hungry tracers. Derived from memory rather than throughput: a
/// single `prestateTracer` response over a large block has been measured near a gigabyte, so
/// this figure times `--max-response-size` is what to check against the host's memory limit.
const DEFAULT_ADMISSION_HEAVY_MAX_CONCURRENT: u64 = 8;

/// Parses a human-readable size string into bytes.
///
/// Accepts suffixes: `KB` (1024), `MB` (1024²), `GB` (1024³). Case-insensitive.
/// Plain numbers are treated as raw bytes.
///
/// # Examples
/// ```text
/// "1GB"   -> 1_073_741_824
/// "512MB" -> 536_870_912
/// "100KB" -> 102_400
/// "1024"  -> 1_024
/// ```
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let upper = s.to_uppercase();

    let (num_str, multiplier) = if let Some(n) = upper.strip_suffix("GB") {
        (n, 1024u64 * 1024 * 1024)
    } else if let Some(n) = upper.strip_suffix("MB") {
        (n, 1024u64 * 1024)
    } else if let Some(n) = upper.strip_suffix("KB") {
        (n, 1024u64)
    } else {
        (upper.as_str(), 1u64)
    };

    let value: u64 = num_str.trim().parse().map_err(|e| format!("invalid size '{}': {}", s, e))?;

    value.checked_mul(multiplier).ok_or_else(|| format!("size overflow: '{}'", s))
}

/// Effective old-block witness budget in seconds: the flag when set (clamped to
/// `--witness-timeout`), otherwise the full `--witness-timeout` budget — raising the witness
/// budget also raises the old-block cap.
fn old_block_witness_timeout_secs(args: &Args) -> u64 {
    args.witness_old_block_timeout.unwrap_or(args.witness_timeout).min(args.witness_timeout)
}

/// The combined witness endpoint chain: the declared internal generator
/// (`--witness-generator-endpoint`) first when configured, then the durable fallbacks in
/// their configured order. Without the flag no endpoint is special — the chain is plain
/// failover.
fn witness_endpoint_chain(args: &Args) -> Vec<&str> {
    args.witness_generator_endpoint
        .as_deref()
        .into_iter()
        .chain(args.witness_endpoint.iter().map(String::as_str))
        .collect()
}

/// This binary's `--r2-*` flags, in the spellings its operators use.
fn r2_flags<'a>(args: &'a Args, tuning: &'a [R2TuningFlag<'a>]) -> R2Flags<'a> {
    R2Flags {
        endpoint: R2Flag::new("--r2-endpoint", args.r2_endpoint.as_deref()),
        bucket: R2Flag::new("--r2-bucket", args.r2_bucket.as_deref()),
        access_key_id: R2Flag::new("--r2-access-key-id", args.r2_access_key_id.as_deref()),
        secret_access_key: R2Flag::new(
            "--r2-secret-access-key",
            args.r2_secret_access_key.as_ref().map(AsRef::as_ref),
        ),
        custom_domain: R2Flag::new("--r2-custom-domain", args.r2_custom_domain.as_deref()),
        access_client_id: R2Flag::new(
            "--r2-access-client-id",
            args.r2_access_client_id.as_ref().map(AsRef::as_ref),
        ),
        access_client_secret: R2Flag::new(
            "--r2-access-client-secret",
            args.r2_access_client_secret.as_ref().map(AsRef::as_ref),
        ),
        connections: R2Flag::new("--r2-connections", args.r2_connections.as_deref()),
        max_concurrent_requests: R2CountFlag::new(
            "--r2-max-concurrent-requests",
            args.r2_max_concurrent_requests,
        ),
        tuning,
    }
}

/// Validates cross-flag invariants that clap cannot express per-field, and reports which R2
/// target the flags select so the construction below does not have to decide it a second time.
fn validate_args(args: &Args) -> Result<R2Target> {
    // Early, flag-named mirror of `PipelineConfig::validate` (see its doc for the rationale);
    // only meaningful with chain sync, where `blocks_to_keep` becomes the stale-reset
    // threshold.
    if args.data_dir.is_some() && args.tip_buffer >= args.blocks_to_keep {
        eyre::bail!(
            "--tip-buffer ({}) must be smaller than --blocks-to-keep ({})",
            args.tip_buffer,
            args.blocks_to_keep
        );
    }
    // A generator listed again under --witness-endpoint would put the generator back into the
    // historical route's fallback rotation — every historical fetch would probe the pruned
    // endpoint the routing exists to skip, silently. The likely cause is migrating to
    // --witness-generator-endpoint without removing the generator from the fallback list.
    if let Some(generator) = &args.witness_generator_endpoint &&
        args.witness_endpoint.contains(generator)
    {
        eyre::bail!(
            "--witness-generator-endpoint ({generator}) must not also appear in \
             --witness-endpoint: list the generator once, via the dedicated flag"
        );
    }
    // Every R2 coherence rule — empty values, target exclusion, leftovers from the other
    // target, an incomplete credential quad, the Access pair, and tuning flags with nothing to
    // tune — comes from the shared validator, so the two binaries cannot drift apart on them
    // again. Unlike the validator, this one checks on every startup: the check predates the
    // custom-domain work here and operators already rely on a bad `--r2-*` value failing fast
    // rather than surfacing later as `kind="missing"`, the counter watched for bucket gaps.
    let tuning = [
        R2TuningFlag::new("--r2-connect-timeout-ms", args.r2_connect_timeout_ms.is_some()),
        R2TuningFlag::new(
            "--r2-max-concurrent-requests",
            args.r2_max_concurrent_requests.is_some(),
        ),
    ];
    let target = validate_r2_flags(&r2_flags(args, &tuning))?;
    // The R2 route anchors block age (frontier vs historical) to the local DB tip; without
    // --data-dir every block would classify as frontier and a genuine bucket hole would
    // never reach the `kind="missing"` alarm. An operator who configured R2 asked for the
    // real route — fail closed instead of running a blind approximation.
    if target != R2Target::None && args.data_dir.is_none() {
        eyre::bail!(
            "the R2 witness route requires --data-dir: it anchors block age \
             (frontier vs historical) to the local DB tip"
        );
    }
    // A batch's entries admit independently, so a gate narrower than one batch's concurrent
    // entries would shed part of every batch on a completely idle server.
    let admission_capacity = args.admission_max_concurrent.saturating_add(args.admission_max_queue);
    if !args.admission_disabled && admission_capacity < u64::from(args.batch_item_concurrency) {
        eyre::bail!(
            "--admission-max-concurrent ({}) + --admission-max-queue ({}) must be at least \
             --batch-item-concurrency ({}): one batch's entries admit independently, so a \
             smaller gate sheds part of every batch even on an idle server",
            args.admission_max_concurrent,
            args.admission_max_queue,
            args.batch_item_concurrency
        );
    }
    // The batch builder holds whole entry bodies, so a batch cap below one entry's cap could
    // never assemble even a single maximal response.
    if args.max_batch_response_size < args.max_response_size {
        eyre::bail!(
            "--max-batch-response-size ({}) must be at least --max-response-size ({}): a batch \
             holds whole entry bodies, so a smaller batch cap could not assemble even one \
             maximal entry",
            args.max_batch_response_size,
            args.max_response_size
        );
    }
    admin_bind_addr(args)?;
    Ok(target)
}

/// Parses `--admin-addr`, returning `None` when no admin listener was requested.
///
/// Pure, so `validate_args` can fail fast on a bad value at startup and `main` can ask again
/// for the parsed address without threading it through — the same shape
/// `old_block_witness_timeout_secs` already uses.
fn admin_bind_addr(args: &Args) -> Result<Option<SocketAddr>> {
    let Some(raw) = args.admin_addr.as_deref() else { return Ok(None) };
    let raw = raw.trim();
    // What a templated env file renders for a variable a role does not set.
    if raw.is_empty() {
        eyre::bail!(
            "--admin-addr was set to an empty value; omit it entirely to run without an \
             admin listener"
        );
    }
    // Deliberately an address literal, not a hostname: a name could resolve to a routable
    // address later, defeating the loopback check below.
    let addr: SocketAddr = raw.parse().map_err(|e| {
        eyre::eyre!("--admin-addr ({raw}) must be an address and port, e.g. 127.0.0.1:8546: {e}")
    })?;
    if !addr.ip().is_loopback() {
        eyre::bail!(
            "--admin-addr ({addr}) must bind loopback: this port has no authentication and \
             its setters can throttle request serving. Bind 127.0.0.1 or [::1] and reach it \
             through a port-forward or a sidecar"
        );
    }
    Ok(Some(addr))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let r2_target = validate_args(&args)?;
    let _log_guard = args.log.init_tracing()?;

    info!(
        listen_addr = %args.addr,
        "Debug-trace-server starting"
    );
    // The combined witness chain (generator first when configured) — the list actually fed to
    // the RPC client, not just the fallback flag values.
    let witness_apis = witness_endpoint_chain(&args);
    let witness_cfg = WitnessFetchConfig {
        witness_timeout: std::time::Duration::from_secs(args.witness_timeout),
        old_block_witness_timeout: std::time::Duration::from_secs(old_block_witness_timeout_secs(
            &args,
        )),
        local_window: args.witness_local_window,
        generator_first: args.witness_generator_endpoint.is_some(),
    };
    debug!(
        rpc_endpoints = ?args.rpc_endpoint,
        witness_endpoints = ?witness_apis,
        witness_generator_configured = witness_cfg.generator_first,
        witness_timeout_secs = args.witness_timeout,
        witness_old_block_timeout_secs = old_block_witness_timeout_secs(&args),
        witness_local_window = args.witness_local_window,
        r2_witness_configured = r2_target != R2Target::None,
        tip_buffer = args.tip_buffer,
        response_cache_disabled = args.response_cache_disabled,
        response_cache_max_size = args.response_cache_max_size,
        response_cache_estimated_items = args.response_cache_estimated_items,
        response_compression_disabled = args.response_compression_disabled,
        batch_item_concurrency = args.batch_item_concurrency,
        admission_disabled = args.admission_disabled,
        admission_max_concurrent = args.admission_max_concurrent,
        admission_max_queue = args.admission_max_queue,
        admission_heavy_max_concurrent = args.admission_heavy_max_concurrent,
        max_response_size = args.max_response_size,
        max_batch_response_size = args.max_batch_response_size,
        admin_addr = ?args.admin_addr,
        "Server configuration"
    );

    // Initialize metrics
    if args.metrics_enabled {
        let metrics_addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.metrics_port));
        match metrics::init_metrics(metrics_addr) {
            Ok(_) => info!(metrics_port = args.metrics_port, "Metrics enabled"),
            Err(e) => {
                error!(error = %e, metrics_port = args.metrics_port, "Failed to initialize metrics");
                return Err(e);
            }
        }
    } else {
        debug!("Metrics disabled");
    }

    // Initialize components
    let data_apis: Vec<&str> = args.rpc_endpoint.iter().map(String::as_str).collect();
    let rpc_defaults = RpcClientConfig::trace_server();
    let per_attempt_timeout = args
        .rpc_per_attempt_timeout_ms
        .map(std::time::Duration::from_millis)
        .unwrap_or(rpc_defaults.per_attempt_timeout);
    let rpc_retry = rpc_defaults.rpc_retry.clone();
    let rpc_config = RpcClientConfig {
        data_max_concurrent_requests: args.data_max_concurrent_requests,
        witness_max_concurrent_requests: args.witness_max_concurrent_requests,
        per_attempt_timeout,
        // Derived rather than flagged so it moves with --witness-timeout; a ceiling the
        // per-entry halving normally undercuts — the full contract lives on
        // `RpcClientConfig::witness_per_attempt_timeout`.
        witness_per_attempt_timeout: Some(std::time::Duration::from_secs(args.witness_timeout) / 2),
        ..rpc_defaults
    }
    .with_metrics(Arc::new(metrics::TraceRpcMetrics));
    let rpc_client =
        Arc::new(RpcClient::new_with_config(&data_apis, &witness_apis, rpc_config, None)?);

    // The same predicate `fetch_witness` evaluates per request: a declared generator plus at
    // least one fallback in the combined chain. Also handed to the chain-sync fetcher as its
    // frontier-routing switch.
    let routing_configured = witness_cfg.generator_first && witness_apis.len() >= 2;
    match (routing_configured, args.data_dir.is_some()) {
        (true, true) => info!(
            witness_local_window = args.witness_local_window,
            // The credential-stripped label, not the raw URL — configured endpoint URLs
            // may carry userinfo or token queries and this log line is info-level.
            skipped_endpoint = rpc_client.witness_provider_label(0).unwrap_or("<none>"),
            "Historical witnesses (at least the local window below the tip) skip the \
             internal generator endpoint"
        ),
        (true, false) => warn!(
            "Witness generator plus fallback endpoints but no --data-dir: historical witness \
             routing is inactive (block age is anchored to the local DB tip); all witness \
             fetches use the full endpoint chain"
        ),
        (false, _) => debug!(
            "No --witness-generator-endpoint (or no fallback endpoints); historical witness \
             routing disabled — witness endpoints are plain failover"
        ),
    }

    // Direct-from-R2 witness source — unsigned through a Cloudflare custom domain when
    // configured (h2-multiplexed, edge-cacheable), otherwise SigV4-signed against the bare
    // S3 endpoint. Which one is settled by `validate_args`, whose verdict is matched on below:
    // clap carries no constraint at all here, so parsing accepts both targets and the shared
    // validator rejects by name — along with empty values, S3 flags left over from the other
    // target, an incomplete S3 quad, and the data-dir-less combination. Shares the RPC path's
    // per-attempt timeout and retry pacing.
    let r2_timeouts = stateless_r2::fetch::FetchTimeouts {
        per_attempt: per_attempt_timeout,
        connect: args
            .r2_connect_timeout_ms
            .map_or(stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT, std::time::Duration::from_millis),
    };
    // Dispatch on the target the shared validator already selected. Re-deriving it from the
    // flags here would be a second copy of the precedence rule, which is the drift this PR
    // exists to end; the reads inside each arm rest on what that validator proved.
    let r2_source = match r2_target {
        R2Target::None => None,
        R2Target::CustomDomain { connections } => {
            let domain = args.r2_custom_domain.as_deref().expect("custom-domain target");
            let access =
                args.r2_access_client_id.as_ref().zip(args.r2_access_client_secret.as_ref()).map(
                    |(client_id, secret)| stateless_r2::fetch::CfAccessCredentials {
                        client_id: client_id.as_ref().to_string(),
                        client_secret: secret.as_ref().to_string(),
                    },
                );
            let cf_access = access.is_some();
            let source = R2WitnessSource::new_custom_domain(
                domain,
                access,
                r2_timeouts,
                rpc_retry,
                args.r2_max_concurrent_requests,
                connections,
            )?;
            metrics::record_r2_target(source.target_label());
            metrics::record_r2_connections(source.connections());
            info!(
                domain = %source.origin(),
                cf_access,
                connections = source.connections(),
                "Historical witness source: R2 (custom domain), RPC chain as fallback"
            );
            Some(source)
        }
        R2Target::S3 => {
            let take = |v: &Option<String>| v.clone().expect("S3 target");
            let source = R2WitnessSource::new(
                args.r2_endpoint.as_deref().expect("S3 target"),
                take(&args.r2_bucket),
                take(&args.r2_access_key_id),
                args.r2_secret_access_key.as_ref().expect("S3 target").as_ref().to_string(),
                r2_timeouts,
                rpc_retry,
                args.r2_max_concurrent_requests,
            )?;
            metrics::record_r2_target(source.target_label());
            info!(
                endpoint = %source.origin(),
                bucket = args.r2_bucket.as_deref().unwrap_or_default(),
                "Historical witness source: R2 (direct S3), RPC chain as fallback"
            );
            Some(source)
        }
    };
    let r2_witness_source = r2_source.map(Arc::new);

    let validator_db = init_validator_db(&args, &rpc_client).await?;

    // Keep concrete ServerDB for pipeline (needs Sized), and dyn BlockStore for data_provider
    let server_db: Option<Arc<ServerDB>> = validator_db;
    let block_store: Option<Arc<dyn BlockStore>> =
        server_db.as_ref().map(|db| Arc::clone(db) as Arc<dyn BlockStore>);

    // Contract cache: local-cache mode writes through to ServerDB, stateless mode is
    // memory-only via `NoopContractStore`. Either way every RPC-fetched contract is
    // cached for the lifetime of the process, so repeated trace requests skip RPC.
    let contract_store: Arc<dyn ContractStore> = match server_db.as_ref() {
        Some(db) => Arc::clone(db) as Arc<dyn ContractStore>,
        None => Arc::new(NoopContractStore),
    };
    let contract_cache = Arc::new(ContractCache::new(contract_store));

    let block_data_cache = if args.block_data_cache_max_size == 0 {
        warn!("Block-data cache disabled (max size = 0); every request re-resolves block data");
        None
    } else {
        debug!(
            max_bytes = args.block_data_cache_max_size,
            shards = BLOCK_DATA_CACHE_SHARDS,
            per_shard_budget = args.block_data_cache_max_size / BLOCK_DATA_CACHE_SHARDS as u64,
            "Block-data cache initialized; entries above the per-shard budget are never admitted"
        );
        Some(Arc::new(BlockDataCache::new(args.block_data_cache_max_size)))
    };

    let data_provider = Arc::new(
        DataProvider::new(
            rpc_client.clone(),
            block_store.clone(),
            block_data_cache,
            contract_cache,
            witness_cfg,
            std::time::Duration::from_secs(args.block_fetch_timeout),
            args.canonical_hash_memo_capacity as usize,
        )
        .with_r2_witness(r2_witness_source),
    );

    let chain_spec = load_chain_spec(&args)?;

    let response_cache = if args.response_cache_disabled {
        warn!(
            "Response cache disabled (--response-cache-disabled); every trace response will \
             be recomputed"
        );
        None
    } else {
        let cache = ResponseCache::new(ResponseCacheConfig::new(
            args.response_cache_max_size,
            args.response_cache_estimated_items as usize,
        ));
        debug!(
            max_bytes = args.response_cache_max_size,
            estimated_items = args.response_cache_estimated_items,
            "Response cache initialized"
        );
        Some(cache)
    };

    // Spawn background chain sync pipeline (if database is configured)
    if let Some(db) = &server_db {
        let shutdown = CancellationToken::new();
        debug!("Starting chain sync pipeline");

        // Spawn unified pipeline (fetch → process → advance with reorg restart).
        // `#[non_exhaustive]` on `PipelineConfig` rules out struct-update syntax across
        // the crate boundary; mutate a default instance instead.
        let mut pipeline_cfg = PipelineConfig::default();
        pipeline_cfg.concurrent_workers = 1;
        pipeline_cfg.tip_buffer = args.tip_buffer;
        pipeline_cfg.stale_reset_threshold = Some(args.blocks_to_keep);
        let config = Arc::new(pipeline_cfg);
        let processor = Arc::new(TraceProcessor);
        let hooks = Arc::new(TraceHooks::new(
            Arc::clone(db) as Arc<dyn BlockStore>,
            response_cache.clone(),
            data_provider.canonical_hash_memo(),
        ));
        let fetcher = Arc::new(TraceFetcher::new(Arc::clone(&rpc_client), routing_configured));
        task::spawn({
            let db = Arc::clone(db);
            let shutdown = shutdown.clone();
            async move {
                if let Err(e) =
                    run_pipeline(fetcher, db, processor, hooks, config, shutdown, BisectResolver)
                        .await
                {
                    error!(error = %e, "Chain sync pipeline exited with error");
                }
            }
        });

        // Spawn history pruner to prevent unbounded database growth
        let db_path =
            PathBuf::from(args.data_dir.as_deref().unwrap()).join(TRACE_SERVER_DB_FILENAME);
        let pruner_metrics = metrics::ChainSyncMetrics::create();
        task::spawn({
            let db = Arc::clone(db);
            let size_prune_min_retain = args.size_prune_min_retain;
            async move {
                if let Err(e) = history_pruner(
                    db,
                    args.blocks_to_keep,
                    args.pruner_interval_secs,
                    args.db_max_size,
                    size_prune_min_retain,
                    db_path,
                    pruner_metrics,
                )
                .await
                {
                    error!(error = %e, "History pruner exited with error");
                }
            }
        });
    }

    // Inbound admission gate. `None` disables it entirely: no layer is installed and every
    // request executes on arrival, as it did before this existed.
    let admission = (!args.admission_disabled).then(|| {
        AdmissionLimiter::new(
            args.admission_max_concurrent,
            args.admission_max_queue,
            args.admission_heavy_max_concurrent,
        )
    });
    match &admission {
        // Pairing a concurrency cap with a response-size cap is what makes the worst case a
        // number at all, and it is worth an operator seeing it at startup rather than
        // discovering it under load. Both products are logged, because they answer different
        // questions: the heavy one bounds the shapes that can actually reach the response cap,
        // while the overall one is the theoretical ceiling if every admitted request returned
        // a maximal body. Neither covers a tracer's intermediate allocations, which are not
        // bounded by anything here.
        Some(limiter) => info!(
            max_concurrent = limiter.max_concurrent(),
            max_queue = limiter.max_queue(),
            heavy_max_concurrent = limiter.heavy_max_concurrent(),
            max_permit_wait_ms = data_provider.max_permit_wait().as_millis() as u64,
            max_response_size = args.max_response_size,
            max_batch_response_size = args.max_batch_response_size,
            worst_case_heavy_response_bytes =
                limiter.heavy_max_concurrent().saturating_mul(args.max_response_size),
            worst_case_response_bytes =
                limiter.max_concurrent().saturating_mul(args.max_response_size),
            "Admission control enabled"
        ),
        None => warn!(
            "--admission-disabled: this process accepts unbounded concurrent work and has no \
             upper bound on the memory a burst of large traces can pin"
        ),
    }

    // Create RPC context and module
    let ctx = RpcContext::new(
        data_provider,
        chain_spec,
        response_cache,
        admission.clone(),
        args.max_response_size as usize,
    );

    // Spawn watch dog checker to monitor long-running requests
    let watch_dog = ctx.watch_dog().clone();
    task::spawn(async move {
        watch_dog
            .run_checker(
                std::time::Duration::from_secs(5),  // check interval
                std::time::Duration::from_secs(15), // warn threshold
            )
            .await;
    });

    let module = ctx.into_rpc_module()?;
    assert_admission_covers_module(&module);

    // Start server. One value feeds the framework's cap and the batch layer's assembly cap —
    // `rpc_middleware` requires those two to stay in step — while the per-response check at
    // our own serialization point is the separate, tighter bound that stops a single body
    // from ever being built up twice more.
    let max_response_body_size = u32::try_from(args.max_batch_response_size).unwrap_or_else(|_| {
        warn!(
            requested = args.max_batch_response_size,
            applied = u32::MAX,
            "--max-batch-response-size exceeds the JSON-RPC framework's cap; clamping"
        );
        u32::MAX
    });
    let config = ServerConfig::builder().max_response_body_size(max_response_body_size).build();
    // Order is load-bearing: the batch layer is outermost, so the admission layer below it
    // sees single calls *and* every batch entry. Reversed, an N-entry batch would pass the
    // gate as one unit — which is the traffic shape that has actually taken this server down.
    // `batch_entries_are_individually_gated` fails if these are swapped.
    let rpc_middleware = RpcServiceBuilder::new()
        .layer(rpc_middleware::ConcurrentBatchLayer::new(
            args.batch_item_concurrency as usize,
            max_response_body_size as usize,
        ))
        .option_layer(admission.clone().map(admission::AdmissionLayer::new));
    let server = Server::builder()
        .set_config(config)
        .set_rpc_middleware(rpc_middleware)
        .set_http_middleware(middleware::http_middleware(!args.response_compression_disabled))
        .build(&args.addr)
        .await?;
    let addr = server.local_addr()?;
    let handle = server.start(module);

    // The bound admin address, kept only for the record; the listener itself is owned by its
    // own thread for the process's lifetime (see `admin::spawn`).
    let _admin_addr = match (admin_bind_addr(&args)?, admission) {
        (Some(admin_addr), Some(limiter)) => {
            Some(admin::spawn(admin_addr, limiter, u64::from(args.batch_item_concurrency))?)
        }
        (Some(_), None) => {
            warn!("--admin-addr is set but --admission-disabled: no limits to serve, skipping");
            None
        }
        (None, _) => {
            warn!(
                "--admin-addr not set: admission limits are fixed for this process's lifetime \
                 and can only be changed by restarting"
            );
            None
        }
    };

    info!(listen_addr = %addr, "Server started");
    handle.stopped().await;

    Ok(())
}

/// Fails fast if a registered method escapes the admission gate's allowlist.
///
/// The allowlist is spelled by name, so a method added later would silently never be gated —
/// the failure mode of an omission here is an unprotected endpoint, discovered under load.
/// `debug_getCacheStatus` is the one deliberate exemption; see `metrics::GATED_METHODS`.
fn assert_admission_covers_module(module: &jsonrpsee::server::RpcModule<()>) {
    if let Some(name) = ungated_method(module.method_names()) {
        panic!(
            "method {name} is registered but neither gated by admission control nor \
             deliberately exempt; add it to metrics::GATED_METHODS or to the exemption list"
        );
    }
}

/// The first registered method that is neither gated nor deliberately exempt, if any.
fn ungated_method<'a>(names: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    // The one endpoint that does no I/O and reports what the server is doing; see
    // `metrics::GATED_METHODS` for why it is exempt.
    const EXEMPT: &[&str] =
        &[metrics::METHOD_DEBUG_GET_CACHE_STATUS, metrics::TIMED_METHOD_DEBUG_GET_CACHE_STATUS];
    names
        .filter(|name| !EXEMPT.contains(name))
        .find(|name| !metrics::is_gated(metrics::method_label(name)))
}

/// Initializes the validator database if data_dir is provided.
/// Returns the database if configured, None otherwise.
/// Note: Chain tracker is spawned separately in main() to allow passing the response cache
/// callback.
#[instrument(skip_all, name = "init_db")]
async fn init_validator_db(
    args: &Args,
    rpc_client: &Arc<RpcClient>,
) -> Result<Option<Arc<ServerDB>>> {
    let Some(data_dir) = &args.data_dir else {
        debug!("Running in stateless mode, no local database");
        return Ok(None);
    };

    debug!(data_dir = %data_dir, "Initializing local database");
    let work_dir = PathBuf::from(data_dir);
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| eyre::eyre!("Failed to create data dir {}: {e}", work_dir.display()))?;
    let db = Arc::new(ServerDB::new(work_dir.join(TRACE_SERVER_DB_FILENAME))?);

    // Check if we already have a local tip
    if db.get_local_tip()?.is_some() {
        debug!("Continuing from existing canonical chain");
        return Ok(Some(db));
    }

    // No local tip - need to initialize anchor block
    // Use explicit start_block if provided, otherwise fetch latest.
    //
    // `get_header` retries transient failures forever at the RPC layer; the binary stays
    // stuck here until the endpoint is reachable — a permanent misconfiguration surfaces via
    // the "no forward progress" signal rather than a bounded-retry error.
    let header = if let Some(start_block_str) = &args.start_block {
        debug!(start_block = %start_block_str, "Initializing from specified start block");
        let block_hash: BlockHash = start_block_str.parse()?;
        rpc_client.get_header(BlockId::Hash(block_hash.into()), false).await
    } else {
        info!("No local tip found, fetching latest block as anchor");
        rpc_client.get_header(BlockId::latest(), false).await
    };

    let anchor = BlockMeta {
        block_number: header.number,
        block_hash: header.hash,
        post_state_root: header.state_root,
        post_withdrawals_root: header
            .withdrawals_root
            .ok_or_else(|| eyre::eyre!("Block {} is missing withdrawals_root", header.hash))?,
    };
    ChainStore::reset_to_anchor(&*db, &anchor)
        .map_err(|e| eyre::eyre!("Failed to reset anchor: {}", e))?;

    info!(
        block_hash = %header.hash,
        block_number = header.number,
        "Anchor block initialized"
    );

    Ok(Some(db))
}

/// Loads the chain specification from genesis file or uses default.
#[instrument(skip_all, name = "load_chain_spec")]
fn load_chain_spec(args: &Args) -> Result<Arc<ChainSpec>> {
    if let Some(genesis_path) = &args.genesis_file {
        debug!(genesis_file = %genesis_path, "Loading genesis from file");
        let genesis_content = std::fs::read_to_string(genesis_path)?;
        let genesis: Genesis = serde_json::from_str(&genesis_content)?;
        Ok(Arc::new(ChainSpec::from_genesis(genesis)))
    } else {
        debug!("Using default chain spec");
        Ok(Arc::new(ChainSpec::default()))
    }
}

/// Background task that periodically prunes old block bodies to prevent unbounded database
/// growth. Runs [`run_prune_cycle`] every `interval_secs`.
#[instrument(skip_all, name = "history_pruner")]
async fn history_pruner(
    db: Arc<ServerDB>,
    blocks_to_keep: u64,
    interval_secs: u64,
    db_max_size: u64,
    size_prune_min_retain: u64,
    db_path: PathBuf,
    chain_sync_metrics: metrics::ChainSyncMetrics,
) -> Result<()> {
    let interval = std::time::Duration::from_secs(interval_secs);
    info!(
        blocks_to_keep = blocks_to_keep,
        interval_secs = interval_secs,
        db_max_size = db_max_size,
        size_prune_min_retain = size_prune_min_retain,
        "Starting history pruner"
    );

    loop {
        run_prune_cycle(
            &db,
            blocks_to_keep,
            db_max_size,
            size_prune_min_retain,
            &db_path,
            &chain_sync_metrics,
        );
        tokio::time::sleep(interval).await;
    }
}

/// One pruning pass: count-based pruning, then size-based pruning down to the
/// min-retain floor, then DB gauge updates.
fn run_prune_cycle(
    db: &ServerDB,
    blocks_to_keep: u64,
    db_max_size: u64,
    size_prune_min_retain: u64,
    db_path: &Path,
    chain_sync_metrics: &metrics::ChainSyncMetrics,
) {
    /// Number of extra blocks to prune per iteration when DB file is over size limit.
    const SIZE_PRUNE_BATCH: u64 = 100;

    let Ok(Some(tip)) = db.get_canonical_tip() else {
        return;
    };
    let current_tip = tip.block_number;
    let mut prune_before = current_tip.saturating_sub(blocks_to_keep);
    match db.prune_history(prune_before) {
        Ok(blocks_pruned) if blocks_pruned > 0 => {
            debug!(
                blocks_pruned = blocks_pruned,
                prune_before = prune_before,
                "Pruned old blocks from database"
            );
        }
        Err(e) => warn!(error = %e, "Failed to prune old block data"),
        _ => {}
    }

    // Size-based pruning: keep removing bodies until the DB file is under the limit or the
    // minimum-retention floor is reached. redb files never shrink on their own, so a file
    // that stays over the limit forever must not be allowed to eat every stored body.
    if db_max_size > 0 {
        let retain_floor = current_tip.saturating_sub(size_prune_min_retain);
        loop {
            let file_size = match std::fs::metadata(db_path) {
                Ok(m) => m.len(),
                Err(e) => {
                    warn!(error = %e, "Failed to read DB file size");
                    break;
                }
            };

            if file_size <= db_max_size {
                break;
            }

            prune_before = prune_before.saturating_add(SIZE_PRUNE_BATCH);
            if prune_before >= retain_floor {
                info!(
                    file_size = file_size,
                    db_max_size = db_max_size,
                    retain_floor = retain_floor,
                    "DB over size limit but at the minimum body-retention floor; not \
                     pruning further"
                );
                break;
            }

            info!(
                file_size = file_size,
                db_max_size = db_max_size,
                prune_before = prune_before,
                "DB over size limit, pruning additional blocks"
            );

            match db.prune_history(prune_before) {
                Ok(blocks_pruned) if blocks_pruned > 0 => {
                    debug!(
                        blocks_pruned = blocks_pruned,
                        prune_before = prune_before,
                        "Size-based prune completed"
                    );
                }
                Ok(_) => break, // No more blocks to prune
                Err(e) => {
                    warn!(error = %e, "Failed to prune during size-based pruning");
                    break;
                }
            }
        }
    }

    // DB gauges: `db_earliest_block` is the canonical window's start and
    // `db_body_earliest_block` the body-retention edge; pruning moves both together, but
    // they can diverge transiently (e.g. right after a stale reset, when the fresh
    // anchor row has no stored body and pre-reset bodies still await pruning).
    let earliest = db.get_earliest().ok().flatten().map(|(n, _)| n).unwrap_or(0);
    chain_sync_metrics.set_db_block_range(earliest, current_tip);
    if let Ok(Some(body_earliest)) = db.get_earliest_block_record() {
        chain_sync_metrics.set_db_body_earliest_block(body_earliest);
    }
    if let Ok(m) = std::fs::metadata(db_path) {
        chain_sync_metrics.set_db_size(m.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that an endpoint flag accepts repeated flags, CSV values, and env var —
    /// ensuring container deployments configured purely via env are not silently limited
    /// to one endpoint (clap's `value_delimiter` applies to env-var values too).
    fn assert_endpoint_accepts_multiple_forms(
        flag: &str,
        env: &str,
        base: &[&str],
        extract: impl Fn(Args) -> Vec<String>,
    ) {
        let guard = stateless_test_utils::env::env_lock();
        let parse =
            |extra: &[&str]| extract(Args::try_parse_from(base.iter().chain(extra)).unwrap());

        assert_eq!(parse(&[flag, "http://a,http://b"]), ["http://a", "http://b"]);
        assert_eq!(
            parse(&[flag, "http://a,http://b", flag, "http://c"]),
            ["http://a", "http://b", "http://c"],
        );

        let from_env = stateless_test_utils::env::with_env_var(
            &guard,
            env,
            "http://a,http://b",
            || parse(&[]),
        );
        assert_eq!(from_env, ["http://a", "http://b"]);
    }

    /// `--rpc-endpoint` accepts repeated flags and CSV values, both on the CLI and via env var,
    /// mirroring `--witness-endpoint` behavior for multi-endpoint data RPC support.
    #[test]
    fn witness_endpoint_accepts_multiple_forms() {
        assert_endpoint_accepts_multiple_forms(
            "--witness-endpoint",
            "DEBUG_TRACE_SERVER_WITNESS_ENDPOINT",
            &["debug-trace-server", "--rpc-endpoint", "http://rpc"],
            |a| a.witness_endpoint,
        );
    }

    #[test]
    fn rpc_endpoint_accepts_multiple_forms() {
        assert_endpoint_accepts_multiple_forms(
            "--rpc-endpoint",
            "DEBUG_TRACE_SERVER_RPC_ENDPOINT",
            &["debug-trace-server", "--witness-endpoint", "http://w"],
            |a| a.rpc_endpoint,
        );
    }

    /// Parses `Args` from the minimal required flags plus `extra`. Callers must hold
    /// `stateless_test_utils::env::env_lock()` — parsing reads `DEBUG_TRACE_SERVER_*` env
    /// vars, so it must be serialized with the tests that mutate them.
    fn parse_args(extra: &[&str]) -> Args {
        let base =
            ["debug-trace-server", "--rpc-endpoint", "http://r", "--witness-endpoint", "http://w"];
        Args::try_parse_from(base.iter().chain(extra)).unwrap()
    }

    /// Pins the tiered-witness-routing knob defaults (`--witness-local-window` must track the
    /// generator's `BACKUP`, the old-block budget defaults to the full witness budget) and the
    /// CLI + env parsing of all three knobs — a typo in an env attribute string would
    /// otherwise ship silently to env-only container deployments.
    #[test]
    fn tiered_routing_flag_defaults() {
        let guard = stateless_test_utils::env::env_lock();

        let defaults = parse_args(&[]);
        assert_eq!(defaults.witness_local_window, data_provider::DEFAULT_WITNESS_LOCAL_WINDOW);
        assert_eq!(defaults.witness_old_block_timeout, None);
        assert_eq!(
            old_block_witness_timeout_secs(&defaults),
            data_provider::DEFAULT_WITNESS_TIMEOUT_SECS,
            "old blocks default to the full witness budget",
        );
        assert_eq!(defaults.tip_buffer, 2);

        // The unset default tracks a raised --witness-timeout; an explicit flag wins.
        assert_eq!(old_block_witness_timeout_secs(&parse_args(&["--witness-timeout", "20"])), 20);
        assert_eq!(
            old_block_witness_timeout_secs(&parse_args(&[
                "--witness-timeout",
                "20",
                "--witness-old-block-timeout",
                "3"
            ])),
            3
        );

        assert_eq!(parse_args(&["--tip-buffer", "0"]).tip_buffer, 0);
        assert_eq!(parse_args(&["--witness-local-window", "128"]).witness_local_window, 128);
        assert_eq!(
            parse_args(&["--witness-old-block-timeout", "3"]).witness_old_block_timeout,
            Some(3)
        );

        let env = |name, value: &str| {
            stateless_test_utils::env::with_env_var(&guard, name, value, || parse_args(&[]))
        };
        assert_eq!(env("DEBUG_TRACE_SERVER_TIP_BUFFER", "5").tip_buffer, 5);
        assert_eq!(env("DEBUG_TRACE_SERVER_WITNESS_LOCAL_WINDOW", "256").witness_local_window, 256);
        assert_eq!(
            env("DEBUG_TRACE_SERVER_WITNESS_OLD_BLOCK_TIMEOUT", "4").witness_old_block_timeout,
            Some(4)
        );
    }

    /// Pins the block-data cache knob: 1 GB default, size-suffix parsing, "0" disables, and
    /// the env attribute string.
    #[test]
    fn block_data_cache_flag_default_env_and_disable() {
        let guard = stateless_test_utils::env::env_lock();

        assert_eq!(parse_args(&[]).block_data_cache_max_size, DEFAULT_BLOCK_DATA_CACHE_MAX_BYTES);
        assert_eq!(parse_args(&["--block-data-cache-max-size", "0"]).block_data_cache_max_size, 0);
        assert_eq!(
            parse_args(&["--block-data-cache-max-size", "512MB"]).block_data_cache_max_size,
            512 * 1024 * 1024
        );

        let from_env = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_BLOCK_DATA_CACHE_MAX_SIZE",
            "2GB",
            || parse_args(&[]),
        );
        assert_eq!(from_env.block_data_cache_max_size, 2 * 1024 * 1024 * 1024);
    }

    /// The witness chain puts the declared generator at index 0; without the flag no endpoint
    /// is special — even a multi-endpoint list is plain failover, keeping its pre-routing
    /// behavior.
    #[test]
    fn witness_generator_endpoint_chain() {
        let guard = stateless_test_utils::env::env_lock();

        // Typed flag: generator prepended ahead of the fallbacks.
        let typed = parse_args(&["--witness-generator-endpoint", "http://gen"]);
        assert_eq!(witness_endpoint_chain(&typed), vec!["http://gen", "http://w"]);

        // Multiple fallbacks keep their order after the generator.
        let multi = parse_args(&[
            "--witness-generator-endpoint",
            "http://gen",
            "--witness-endpoint",
            "http://w2",
        ]);
        assert_eq!(witness_endpoint_chain(&multi), vec!["http://gen", "http://w", "http://w2"]);

        // No flag: plain failover chains, regardless of endpoint count.
        assert_eq!(witness_endpoint_chain(&parse_args(&[])), vec!["http://w"]);
        let failover_pair = parse_args(&["--witness-endpoint", "http://w2"]);
        assert_eq!(witness_endpoint_chain(&failover_pair), vec!["http://w", "http://w2"]);

        // Generator-only: --witness-endpoint becomes optional, chain is the lone generator.
        let gen_only = Args::try_parse_from([
            "debug-trace-server",
            "--rpc-endpoint",
            "http://r",
            "--witness-generator-endpoint",
            "http://gen",
        ])
        .unwrap();
        assert_eq!(witness_endpoint_chain(&gen_only), vec!["http://gen"]);
        // Neither witness flag: still rejected.
        assert!(
            Args::try_parse_from(["debug-trace-server", "--rpc-endpoint", "http://r"]).is_err()
        );

        // The generator duplicated in the fallback list is a rejected misconfiguration —
        // it would put the generator back into the historical route's rotation.
        let dup = parse_args(&["--witness-generator-endpoint", "http://w"]);
        assert!(validate_args(&dup).is_err());
        assert!(validate_args(&typed).is_ok());

        // Env var parity with the CLI flag.
        let from_env = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_WITNESS_GENERATOR_ENDPOINT",
            "http://gen-env",
            || parse_args(&[]),
        );
        assert_eq!(from_env.witness_generator_endpoint.as_deref(), Some("http://gen-env"));
    }

    /// `--tip-buffer` must stay below `--blocks-to-keep` when chain sync is enabled: the
    /// pipeline's built-in lag would otherwise satisfy the stale-reset test on every
    /// transient restart. Inert in stateless mode, where neither flag is used.
    #[test]
    fn tip_buffer_must_stay_below_blocks_to_keep() {
        let _guard = stateless_test_utils::env::env_lock();

        // Stateless mode (no data dir): both flags are inert, any combination is accepted.
        assert!(validate_args(&parse_args(&["--tip-buffer", "2000"])).is_ok());

        let with_db = |extra: &[&str]| {
            let mut v = vec!["--data-dir", "/tmp/x"];
            v.extend_from_slice(extra);
            parse_args(&v)
        };
        assert!(validate_args(&with_db(&[])).is_ok());
        assert!(validate_args(&with_db(&["--tip-buffer", "999"])).is_ok());
        assert!(validate_args(&with_db(&["--tip-buffer", "1000"])).is_err());
        assert!(validate_args(&with_db(&["--tip-buffer", "5", "--blocks-to-keep", "5"])).is_err());
    }

    /// Verifies a concurrency cap flag parses via CLI and env var, and defaults to `None`.
    fn assert_concurrency_flag(
        flag: &str,
        env: &str,
        base: &[&str],
        extract: impl Fn(Args) -> Option<usize>,
    ) {
        let guard = stateless_test_utils::env::env_lock();
        let parse =
            |extra: &[&str]| extract(Args::try_parse_from(base.iter().chain(extra)).unwrap());

        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[flag, "7"]), Some(7));

        let from_env = stateless_test_utils::env::with_env_var(&guard, env, "12", || parse(&[]));
        assert_eq!(from_env, Some(12));
    }

    /// Response-cache flags: disabling is a dedicated flag (CLI + env), and 0 estimated
    /// items — the old disable convention — is rejected at parse time on both paths, so a
    /// deployment still exporting `..._ESTIMATED_ITEMS=0` fails loudly instead of silently
    /// running uncached.
    #[test]
    fn response_cache_flags() {
        let guard = stateless_test_utils::env::env_lock();

        let defaults = parse_args(&[]);
        assert!(!defaults.response_cache_disabled);
        assert_eq!(
            defaults.response_cache_estimated_items,
            DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS as u64
        );

        assert!(parse_args(&["--response-cache-disabled"]).response_cache_disabled);
        assert_eq!(
            parse_args(&["--response-cache-estimated-items", "50000"])
                .response_cache_estimated_items,
            50_000
        );

        let base =
            ["debug-trace-server", "--rpc-endpoint", "http://r", "--witness-endpoint", "http://w"];
        assert!(
            Args::try_parse_from(base.iter().chain(&["--response-cache-estimated-items", "0"]))
                .is_err(),
            "0 estimated items must be rejected at parse time"
        );
        let env_zero_rejected = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_RESPONSE_CACHE_ESTIMATED_ITEMS",
            "0",
            || Args::try_parse_from(base).is_err(),
        );
        assert!(env_zero_rejected, "0 estimated items via env must be rejected at parse time");

        let disabled_via_env = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_RESPONSE_CACHE_DISABLED",
            "true",
            || parse_args(&[]).response_cache_disabled,
        );
        assert!(disabled_via_env);
    }

    /// Compression kill switch: compression defaults on, disable via CLI or env.
    #[test]
    fn response_compression_flag() {
        let guard = stateless_test_utils::env::env_lock();

        assert!(!parse_args(&[]).response_compression_disabled);
        assert!(parse_args(&["--response-compression-disabled"]).response_compression_disabled);

        let disabled_via_env = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_RESPONSE_COMPRESSION_DISABLED",
            "true",
            || parse_args(&[]).response_compression_disabled,
        );
        assert!(disabled_via_env);
    }

    /// The admission allowlist is spelled by name, so a method added later would silently
    /// never be gated — an unprotected endpoint, discovered under load.
    #[test]
    fn every_registered_method_is_gated_or_deliberately_exempt() {
        let registered: Vec<&str> = metrics::ALL_METHOD_NAMES
            .iter()
            .copied()
            .chain(metrics::TIMED_METHOD_ALIASES.iter().map(|(alias, _)| *alias))
            .collect();
        assert_eq!(ungated_method(registered.iter().copied()), None);

        assert_eq!(
            ungated_method(["debug_traceBlockByNumber", "debug_newThing"].into_iter()),
            Some("debug_newThing"),
            "an unrecognized method must be reported, not folded into `unknown` and ignored"
        );
    }

    #[test]
    fn admission_flag_defaults_and_env() {
        let guard = stateless_test_utils::env::env_lock();

        let args = parse_args(&[]);
        assert_eq!(args.admission_max_concurrent, DEFAULT_ADMISSION_MAX_CONCURRENT);
        assert_eq!(args.admission_max_queue, DEFAULT_ADMISSION_MAX_QUEUE);
        assert_eq!(args.admission_heavy_max_concurrent, DEFAULT_ADMISSION_HEAVY_MAX_CONCURRENT);
        assert!(!args.admission_disabled);
        assert_eq!(args.max_response_size, 256 * 1024 * 1024);
        assert_eq!(args.max_batch_response_size, 1024 * 1024 * 1024);
        assert!(args.admin_addr.is_none());

        // Zero execution permits would park every request forever; zero queue is a legitimate
        // "execute or shed" configuration and must stay accepted.
        let base =
            ["debug-trace-server", "--rpc-endpoint", "http://r", "--witness-endpoint", "http://w"];
        for flag in ["--admission-max-concurrent", "--admission-heavy-max-concurrent"] {
            assert!(
                Args::try_parse_from(base.iter().chain(&[flag, "0"])).is_err(),
                "{flag} 0 must be rejected at parse time"
            );
        }
        assert_eq!(parse_args(&["--admission-max-queue", "0"]).admission_max_queue, 0);

        // Env attributes are what container deployments actually use, and a typo in one ships
        // silently — a default-looking value with nothing pointing at the cause.
        for (var, flag_value) in [
            ("DEBUG_TRACE_SERVER_ADMISSION_MAX_CONCURRENT", "77"),
            ("DEBUG_TRACE_SERVER_ADMISSION_MAX_QUEUE", "78"),
            ("DEBUG_TRACE_SERVER_ADMISSION_HEAVY_MAX_CONCURRENT", "79"),
        ] {
            let read = stateless_test_utils::env::with_env_var(&guard, var, flag_value, || {
                let args = parse_args(&[]);
                match var {
                    "DEBUG_TRACE_SERVER_ADMISSION_MAX_CONCURRENT" => args.admission_max_concurrent,
                    "DEBUG_TRACE_SERVER_ADMISSION_MAX_QUEUE" => args.admission_max_queue,
                    _ => args.admission_heavy_max_concurrent,
                }
            });
            assert_eq!(read.to_string(), flag_value, "{var} did not reach its field");
        }

        let sizes = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_MAX_RESPONSE_SIZE",
            "64MB",
            || parse_args(&[]).max_response_size,
        );
        assert_eq!(sizes, 64 * 1024 * 1024);
    }

    /// The admin port has no authentication and its setters can throttle request serving, so a
    /// non-loopback bind is refused by name rather than warned about.
    #[test]
    fn admin_addr_must_be_a_loopback_literal() {
        for accepted in ["127.0.0.1:8546", "127.0.0.5:1", "[::1]:8546"] {
            let args = parse_args(&["--admin-addr", accepted]);
            assert!(admin_bind_addr(&args).is_ok(), "{accepted} should be accepted");
        }

        // A hostname is refused even when it resolves to loopback today: it could resolve
        // elsewhere later, which would defeat the check silently.
        for rejected in ["0.0.0.0:8546", "10.1.2.3:8546", "[::]:8546", "localhost:8546", "8546"] {
            let args = parse_args(&["--admin-addr", rejected]);
            let err = admin_bind_addr(&args).unwrap_err().to_string();
            assert!(err.contains("--admin-addr"), "the error must name the flag: {err}");
        }

        // What a templated env file renders for a variable a role does not set.
        let args = parse_args(&["--admin-addr", "  "]);
        assert!(admin_bind_addr(&args).unwrap_err().to_string().contains("--admin-addr"));

        assert!(admin_bind_addr(&parse_args(&[])).unwrap().is_none(), "absent means disabled");
    }

    /// A gate with less total capacity than one batch's concurrent entries sheds part of every
    /// batch on a completely idle server — caught at startup, by name.
    #[test]
    fn admission_capacity_must_cover_one_batch() {
        let args = parse_args(&[
            "--batch-item-concurrency",
            "16",
            "--admission-max-concurrent",
            "4",
            "--admission-max-queue",
            "4",
        ]);
        let err = validate_args(&args).expect_err("8 of capacity cannot serve a 16-wide batch");
        let err = err.to_string();
        assert!(err.contains("--admission-max-concurrent"), "{err}");
        assert!(err.contains("--batch-item-concurrency"), "{err}");

        // The kill switch takes the rule out of play along with the gate.
        let args = parse_args(&[
            "--batch-item-concurrency",
            "16",
            "--admission-max-concurrent",
            "4",
            "--admission-max-queue",
            "4",
            "--admission-disabled",
        ]);
        assert!(validate_args(&args).is_ok());
    }

    /// A batch holds whole entry bodies, so a batch cap under one entry's cap could never
    /// assemble even a single maximal response.
    #[test]
    fn batch_response_cap_must_cover_one_response() {
        let args =
            parse_args(&["--max-response-size", "512MB", "--max-batch-response-size", "256MB"]);
        let err = validate_args(&args).expect_err("a batch cap below the entry cap").to_string();
        assert!(err.contains("--max-batch-response-size"), "{err}");
        assert!(validate_args(&parse_args(&["--max-response-size", "512MB"])).is_ok());
    }

    /// Batch concurrency knob: default, CLI/env override, and the zero rejection.
    #[test]
    fn batch_item_concurrency_flag() {
        let guard = stateless_test_utils::env::env_lock();

        assert_eq!(
            parse_args(&[]).batch_item_concurrency,
            rpc_middleware::DEFAULT_BATCH_ITEM_CONCURRENCY
        );
        assert_eq!(parse_args(&["--batch-item-concurrency", "1"]).batch_item_concurrency, 1);

        let base =
            ["debug-trace-server", "--rpc-endpoint", "http://r", "--witness-endpoint", "http://w"];
        assert!(
            Args::try_parse_from(base.iter().chain(&["--batch-item-concurrency", "0"])).is_err(),
            "0 batch concurrency must be rejected at parse time (1 = sequential)"
        );

        let via_env = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_BATCH_ITEM_CONCURRENCY",
            "32",
            || parse_args(&[]).batch_item_concurrency,
        );
        assert_eq!(via_env, 32);
    }

    /// Pruner-guard flag: default, CLI override, and env parity.
    #[test]
    fn size_prune_min_retain_flag() {
        let guard = stateless_test_utils::env::env_lock();

        assert_eq!(parse_args(&[]).size_prune_min_retain, 256);
        assert_eq!(parse_args(&["--size-prune-min-retain", "1024"]).size_prune_min_retain, 1024);

        let retain_via_env = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_SIZE_PRUNE_MIN_RETAIN",
            "512",
            || parse_args(&[]).size_prune_min_retain,
        );
        assert_eq!(retain_via_env, 512);
    }

    /// Canonical-hash memo capacity: default, CLI override, env parity, and 0 rejected at
    /// parse time.
    #[test]
    fn canonical_hash_memo_capacity_flag() {
        let guard = stateless_test_utils::env::env_lock();

        assert_eq!(
            parse_args(&[]).canonical_hash_memo_capacity,
            data_provider::DEFAULT_CANONICAL_HASH_MEMO_CAPACITY
        );
        assert_eq!(
            parse_args(&["--canonical-hash-memo-capacity", "1000000"]).canonical_hash_memo_capacity,
            1_000_000
        );

        let base =
            ["debug-trace-server", "--rpc-endpoint", "http://r", "--witness-endpoint", "http://w"];
        assert!(
            Args::try_parse_from(base.iter().chain(&["--canonical-hash-memo-capacity", "0"]))
                .is_err(),
            "0 memo capacity must be rejected at parse time"
        );
        let via_env = stateless_test_utils::env::with_env_var(
            &guard,
            "DEBUG_TRACE_SERVER_CANONICAL_HASH_MEMO_CAPACITY",
            "4096",
            || parse_args(&[]).canonical_hash_memo_capacity,
        );
        assert_eq!(via_env, 4096);
    }

    /// Size-based pruning stops at the min-retain floor: with a DB file permanently over
    /// `db_max_size` (redb files never shrink), bodies within `tip - size_prune_min_retain`
    /// survive every cycle instead of being pruned to nothing.
    #[test]
    fn run_prune_cycle_respects_min_retain_floor() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join(TRACE_SERVER_DB_FILENAME);
        let db = ServerDB::new(&db_path).unwrap();

        use crate::server_db::test_support::{empty_light_witness, make_test_block};

        let block_hash = |n: u64| BlockHash::from(alloy_primitives::U256::from(n).to_be_bytes());
        let blocks: Vec<_> = (1..=500u64)
            .map(|n| (make_test_block(n, block_hash(n)), empty_light_witness()))
            .collect();
        db.store_block_data(&blocks).unwrap();
        let metas: Vec<BlockMeta> = (1..=500u64)
            .map(|n| BlockMeta {
                block_number: n,
                block_hash: block_hash(n),
                post_state_root: Default::default(),
                post_withdrawals_root: Default::default(),
            })
            .collect();
        ChainStore::advance_chain(&db, &metas).unwrap();

        // db_max_size = 1 byte: permanently over the limit. blocks_to_keep exceeds the
        // chain length, so only size-based pruning can remove anything.
        let metrics = metrics::ChainSyncMetrics::create();
        run_prune_cycle(&db, 1_000, 1, 250, &db_path, &metrics);

        // The contract: bodies at or above tip - min_retain = 250 always survive.
        for n in [250u64, 300, 500] {
            assert!(db.get_block_and_witness(block_hash(n)).is_ok(), "body {n} must survive");
        }
        // Pruning did happen below the floor, chain rows included; the retained window
        // still answers.
        assert!(db.get_block_and_witness(block_hash(1)).is_err(), "body 1 must be pruned");
        for n in [1u64, 100] {
            assert_eq!(ChainStore::get_block_hash(&db, n).unwrap(), None, "chain row {n}");
        }
        for n in [250u64, 500] {
            assert!(ChainStore::get_block_hash(&db, n).unwrap().is_some(), "window row {n}");
        }
    }

    #[test]
    fn data_max_concurrent_requests_flag_and_env() {
        assert_concurrency_flag(
            "--data-max-concurrent-requests",
            "DEBUG_TRACE_SERVER_DATA_MAX_CONCURRENT_REQUESTS",
            &[
                "debug-trace-server",
                "--rpc-endpoint",
                "http://rpc",
                "--witness-endpoint",
                "http://w",
            ],
            |a| a.data_max_concurrent_requests,
        );
    }

    #[test]
    fn witness_max_concurrent_requests_flag_and_env() {
        assert_concurrency_flag(
            "--witness-max-concurrent-requests",
            "DEBUG_TRACE_SERVER_WITNESS_MAX_CONCURRENT_REQUESTS",
            &[
                "debug-trace-server",
                "--rpc-endpoint",
                "http://rpc",
                "--witness-endpoint",
                "http://w",
            ],
            |a| a.witness_max_concurrent_requests,
        );
    }

    /// The S3 `--r2-*` set is all-or-nothing: any subset missing a member is rejected by
    /// `validate_args` naming what is absent, the full quad passes, and none-of-them stays
    /// valid. Rejection is post-parse throughout — clap carries no constraint here.
    #[test]
    fn r2_s3_flag_set_is_all_or_nothing() {
        // Parsing reads every `#[clap(env = ...)]` variable, so serialize with the
        // env-mutating tests.
        let _guard = stateless_test_utils::env::env_lock();
        let full = [
            "--r2-endpoint",
            "https://acc.r2.cloudflarestorage.com",
            "--r2-bucket",
            "witness-mainnet",
            "--r2-access-key-id",
            "ak",
            "--r2-secret-access-key",
            "sk",
        ];

        assert_eq!(parse_args(&full).r2_bucket.as_deref(), Some("witness-mainnet"));
        assert_eq!(
            parse_args(&full).r2_connect_timeout_ms,
            None,
            "unset; the fetcher default applies"
        );
        let with_timeout: Vec<&str> =
            full.iter().copied().chain(["--r2-connect-timeout-ms", "2000"]).collect();
        assert_eq!(parse_args(&with_timeout).r2_connect_timeout_ms, Some(2000));
        // A tuning flag explicitly set with no target must be rejected rather than silently
        // ignored — by name, from `validate_args`, with defaults staying exempt.
        let err = validate_args(&parse_args(&["--r2-connect-timeout-ms", "2000"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--r2-connect-timeout-ms"), "{err}");
        let _ = parse_args(&[]); // no R2 flags stays valid

        // Dropping any one flag=value pair of the quad is rejected by `validate_args`, which
        // names the missing flag; clap's `requires` used to do it but could not (see `Args`).
        for skip in 0..4 {
            let partial: Vec<&str> = full
                .chunks(2)
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .flat_map(|(_, pair)| pair.iter().copied())
                .chain(["--data-dir", "/tmp/dts-test"])
                .collect();
            let dropped = full[skip * 2];
            let err = validate_args(&parse_args(&partial)).unwrap_err().to_string();
            assert!(err.contains(dropped), "missing {dropped} must be named: {err}");
        }
    }

    /// The custom-domain R2 target: stands alone (no credential quad), unlocks the shared
    /// tuning flags, is mutually exclusive with the S3 endpoint, and carries the Access
    /// token pair as an all-or-nothing add-on.
    #[test]
    fn r2_custom_domain_target_wiring() {
        let _guard = stateless_test_utils::env::env_lock();
        let base =
            ["debug-trace-server", "--rpc-endpoint", "http://r", "--witness-endpoint", "http://w"];
        let domain = ["--r2-custom-domain", "https://witness.example.com"];

        assert_eq!(
            parse_args(&domain).r2_custom_domain.as_deref(),
            Some("https://witness.example.com")
        );
        // The shared tuning flags belong to whichever target is configured, so each must be
        // accepted with the custom domain and still rejected by name with no target at all —
        // the direction a revert would break silently for every custom-domain deployment.
        let with_tuning: Vec<&str> = domain
            .iter()
            .copied()
            .chain([
                "--r2-connect-timeout-ms",
                "2000",
                "--r2-max-concurrent-requests",
                "48",
                "--r2-connections",
                "8",
            ])
            .collect();
        assert_eq!(parse_args(&with_tuning).r2_connect_timeout_ms, Some(2000));
        assert_eq!(parse_args(&with_tuning).r2_max_concurrent_requests, Some(48));
        assert_eq!(parse_args(&with_tuning).r2_connections.as_deref(), Some("8"));
        for orphan in [
            ["--r2-connect-timeout-ms", "2000"],
            ["--r2-max-concurrent-requests", "48"],
            ["--r2-connections", "8"],
        ] {
            let err = validate_args(&parse_args(&orphan)).unwrap_err().to_string();
            assert!(
                err.contains(orphan[0]),
                "{orphan:?} without either R2 target must be rejected by name: {err}",
            );
        }

        // The two read targets are mutually exclusive — rejected by `validate_args` with an
        // error naming both flags (clap's own rejection would name neither — see `Args`).
        let both = Args::try_parse_from(
            base.iter()
                .copied()
                .chain(domain)
                .chain([
                    "--r2-endpoint",
                    "https://acc.r2.cloudflarestorage.com",
                    "--r2-bucket",
                    "witness-mainnet",
                    "--r2-access-key-id",
                    "ak",
                    "--r2-secret-access-key",
                    "sk",
                    "--data-dir",
                    "/tmp/dts-test",
                ])
                .collect::<Vec<_>>(),
        )
        .expect("both targets must parse; rejection happens post-parse");
        let err = validate_args(&both).unwrap_err().to_string();
        assert!(err.contains("--r2-endpoint") && err.contains("--r2-custom-domain"), "{err}");

        // Access pair: each half requires the other, and both require the domain — rejected by
        // name, since a half-set pair would otherwise `zip` to `None` and build a working but
        // silently unauthenticated client.
        let half: Vec<&str> =
            domain.iter().copied().chain(["--r2-access-client-id", "tok"]).collect();
        let err = validate_args(&parse_args(&half)).unwrap_err().to_string();
        assert!(err.contains("--r2-access-client-secret"), "client id without secret: {err}");

        // The connection count is a multiplexing concept: zero of them builds a transport that
        // can carry nothing, and the HTTP/1.1 S3 target already opens a socket per in-flight
        // GET, so honouring a count there would promise a spread that never happens.
        let zero: Vec<&str> = domain.iter().copied().chain(["--r2-connections", "0"]).collect();
        let err = validate_args(&parse_args(&zero)).unwrap_err().to_string();
        assert!(err.contains("--r2-connections") && err.contains("at least 1"), "{err}");

        let on_s3 = Args::try_parse_from(
            base.iter()
                .copied()
                .chain([
                    "--r2-endpoint",
                    "https://acc.r2.cloudflarestorage.com",
                    "--r2-bucket",
                    "witness-mainnet",
                    "--r2-access-key-id",
                    "ak",
                    "--r2-secret-access-key",
                    "sk",
                    "--r2-connections",
                    "8",
                    "--data-dir",
                    "/tmp/dts-test",
                ])
                .collect::<Vec<_>>(),
        )
        .expect("rejection happens post-parse");
        let err = validate_args(&on_s3).unwrap_err().to_string();
        assert!(
            err.contains("--r2-connections") && err.contains("--r2-custom-domain"),
            "a connection count on the S3 target must be rejected by name: {err}"
        );

        let orphan_pair = ["--r2-access-client-id", "tok", "--r2-access-client-secret", "sk"];
        let err = validate_args(&parse_args(&orphan_pair)).unwrap_err().to_string();
        assert!(err.contains("--r2-custom-domain"), "token pair without the domain: {err}");
        let full: Vec<&str> = domain
            .iter()
            .copied()
            .chain(["--r2-access-client-id", "tok", "--r2-access-client-secret", "sk"])
            .collect();
        assert_eq!(parse_args(&full).r2_access_client_id.as_ref().map(|s| s.as_ref()), Some("tok"));
    }

    /// Custom-domain misconfigurations fail the same startup validation as the S3 flags:
    /// empty values and the data-dir-less combination.
    #[test]
    fn validate_args_rejects_custom_domain_misconfigurations() {
        let _guard = stateless_test_utils::env::env_lock();
        let dir = ["--data-dir", "/tmp/dts-test"];

        assert!(
            validate_args(&parse_args(&[
                "--r2-custom-domain",
                "https://w.example.com",
                dir[0],
                dir[1]
            ]))
            .is_ok()
        );
        assert!(
            validate_args(&parse_args(&["--r2-custom-domain", "https://w.example.com"])).is_err(),
            "custom domain without --data-dir must fail"
        );
        assert!(
            validate_args(&parse_args(&["--r2-custom-domain", "", dir[0], dir[1]])).is_err(),
            "empty custom domain must fail"
        );
        assert!(
            validate_args(&parse_args(&[
                "--r2-custom-domain",
                "https://w.example.com",
                "--r2-access-client-id",
                "tok",
                "--r2-access-client-secret",
                "",
                dir[0],
                dir[1],
            ]))
            .is_err(),
            "empty access secret must fail"
        );
        // A blank custom-domain env line over a working S3 config must get the named
        // empty-value error, not a phantom target conflict.
        let blank_over_s3 = parse_args(&[
            "--r2-endpoint",
            "https://acc.r2.cloudflarestorage.com",
            "--r2-bucket",
            "witness-mainnet",
            "--r2-access-key-id",
            "ak",
            "--r2-secret-access-key",
            "sk",
            "--r2-custom-domain",
            "",
            dir[0],
            dir[1],
        ]);
        let err = validate_args(&blank_over_s3).unwrap_err().to_string();
        assert!(err.contains("--r2-custom-domain") && err.contains("empty"), "{err}");
    }

    /// R2 misconfigurations fail startup validation: an empty value on any `--r2-*` flag
    /// (the shape of a failed env injection, which clap's presence-only `requires` cannot
    /// see) and the data-dir-less combination whose historical route can never fire.
    #[test]
    fn validate_args_rejects_r2_misconfigurations() {
        let _guard = stateless_test_utils::env::env_lock();
        let quad = [
            ("--r2-endpoint", "https://acc.r2.cloudflarestorage.com"),
            ("--r2-bucket", "witness-mainnet"),
            ("--r2-access-key-id", "ak"),
            ("--r2-secret-access-key", "sk"),
        ];
        let build = |empty: Option<&str>, data_dir: bool| {
            let mut v = vec![
                "debug-trace-server",
                "--rpc-endpoint",
                "http://r",
                "--witness-endpoint",
                "http://w",
            ];
            for (flag, value) in quad {
                v.push(flag);
                v.push(if empty == Some(flag) { "" } else { value });
            }
            if data_dir {
                v.extend(["--data-dir", "/tmp/dts-test"]);
            }
            Args::try_parse_from(v).unwrap()
        };

        assert!(validate_args(&build(None, true)).is_ok());
        // Explicitly configured R2 without a local DB is inert — fail closed, not warn.
        assert!(validate_args(&build(None, false)).is_err());
        // Any single empty value must fail instead of building a live source over it.
        for (flag, _) in quad {
            assert!(validate_args(&build(Some(flag), true)).is_err(), "{flag} empty must fail");
        }
    }
}
