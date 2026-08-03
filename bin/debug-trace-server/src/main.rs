//! Debug/Trace RPC Server
//!
//! # Overview
//! A standalone RPC server for `debug_*` and `trace_*` methods using stateless execution.
//! Data can be fetched from upstream RPC endpoints or from a local database with chain sync.
//! Request-serving witness fetches route by block age: historical blocks skip the internal
//! generator endpoint (which only retains a small recent window) and go straight to the
//! fallback endpoints. Chain-sync prefetch always uses the full chain.
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
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_genesis::Genesis;
use alloy_primitives::BlockHash;
use alloy_rpc_types_eth::BlockId;
use clap::Parser;
use eyre::Result;
use jsonrpsee::server::{Server, ServerConfig};
use stateless_common::{RpcClient, RpcClientConfig, logging::LogArgs};
use stateless_core::{
    BisectResolver, ChainStore, ContractStore, DivergenceLookups, PipelineConfig,
    chain_spec::ChainSpec, db::BlockMeta, pipeline::run_pipeline,
};
use stateless_db::ContractCache;
use tokio::task;
use tokio_util::sync::CancellationToken;
use tower::{
    ServiceBuilder,
    layer::util::{Identity, Stack},
};
use tracing::{debug, error, info, instrument, warn};

mod block_data_cache;
mod chain_sync;
mod compression;
mod data_provider;
mod metrics;
mod raw_json;
mod response_cache;
mod response_size;
mod rpc_service;
mod server_db;
mod timing;
mod tracing_executor;

use block_data_cache::{
    BLOCK_DATA_CACHE_SHARDS, BlockDataCache, DEFAULT_BLOCK_DATA_CACHE_MAX_BYTES,
};
use data_provider::{DataProvider, NoopContractStore, WitnessFetchConfig};
use response_cache::{DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS, ResponseCache, ResponseCacheConfig};
use rpc_service::RpcContext;
use server_db::{BlockStore, ServerDB};

use crate::chain_sync::{TraceFetcher, TraceHooks, TraceProcessor};

/// Command line arguments for the debug-trace-server.
#[derive(Parser, Debug)]
#[clap(name = "debug-trace-server", about = "Debug/Trace RPC Server")]
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

    /// Witness fetch timeout in seconds.
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

/// Validates cross-flag invariants that clap cannot express per-field.
fn validate_args(args: &Args) -> Result<()> {
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
    Ok(())
}

/// The middleware stack [`http_middleware`] composes, innermost layer first.
type HttpMiddleware = ServiceBuilder<
    Stack<
        timing::TimingHeaderLayer,
        Stack<
            response_size::ResponseSizeLayer,
            Stack<compression::ResponseCompressionLayer, Identity>,
        >,
    >,
>;

/// Composes the HTTP middleware stack — the one place its order is defined (the unit
/// tests in [`compression`] run requests through this exact stack).
///
/// Compression must stay outermost: `ResponseSizeLayer` reads the body's exact
/// `size_hint` (gone once the body is a compressed stream), and the timing layer's
/// future resolves before the body streams — so this order keeps `x-response-size` at
/// the uncompressed payload size and `x-execution-time-ns` free of compression CPU.
pub(crate) fn http_middleware(compression_enabled: bool) -> HttpMiddleware {
    ServiceBuilder::new()
        .layer(compression::layer(compression_enabled))
        .layer(response_size::ResponseSizeLayer)
        .layer(timing::TimingHeaderLayer)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    validate_args(&args)?;
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
        tip_buffer = args.tip_buffer,
        response_cache_disabled = args.response_cache_disabled,
        response_cache_max_size = args.response_cache_max_size,
        response_cache_estimated_items = args.response_cache_estimated_items,
        response_compression_disabled = args.response_compression_disabled,
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
    let rpc_config = RpcClientConfig {
        data_max_concurrent_requests: args.data_max_concurrent_requests,
        witness_max_concurrent_requests: args.witness_max_concurrent_requests,
        per_attempt_timeout,
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

    let data_provider = Arc::new(DataProvider::new(
        rpc_client.clone(),
        block_store.clone(),
        block_data_cache,
        contract_cache,
        witness_cfg,
        std::time::Duration::from_secs(args.block_fetch_timeout),
        args.canonical_hash_memo_capacity as usize,
    ));

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

    // Create RPC context and module
    let ctx = RpcContext::new(data_provider, chain_spec, response_cache);

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

    // Start server
    let config = ServerConfig::builder().max_response_body_size(u32::MAX).build();
    let server = Server::builder()
        .set_config(config)
        .set_http_middleware(http_middleware(!args.response_compression_disabled))
        .build(&args.addr)
        .await?;
    let addr = server.local_addr()?;
    let handle = server.start(module);

    info!(listen_addr = %addr, "Server started");
    handle.stopped().await;

    Ok(())
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
}
