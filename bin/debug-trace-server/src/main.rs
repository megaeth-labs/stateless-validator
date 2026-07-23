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
//! │  Witnesses: near-tip → full endpoint chain; historical skips    │
//! │  the internal generator (guaranteed miss) → fallback endpoints  │
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

use std::{path::PathBuf, sync::Arc};

use alloy_genesis::Genesis;
use alloy_primitives::BlockHash;
use alloy_rpc_types_eth::BlockId;
use clap::Parser;
use eyre::Result;
use jsonrpsee::server::{Server, ServerConfig};
use stateless_common::{RpcClient, RpcClientConfig, logging::LogArgs};
use stateless_core::{
    BisectResolver, ChainStore, ContractStore, PipelineConfig, chain_spec::ChainSpec,
    db::BlockMeta, pipeline::run_pipeline,
};
use stateless_db::ContractCache;
use tokio::task;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, warn};

mod chain_sync;
mod data_provider;
mod metrics;
mod response_cache;
mod response_size;
mod rpc_service;
mod server_db;
mod timing;
mod tracing_executor;

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

    /// One or more upstream witness endpoint URLs for fetching witness data (tried in order).
    /// Accepts repeated flags (`--witness-endpoint a --witness-endpoint b`) or a comma-separated
    /// list (`--witness-endpoint a,b`, also via the env var). The first endpoint is positionally
    /// special: it is treated as the internal witness generator and is skipped for historical
    /// blocks (see `--witness-local-window`).
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_WITNESS_ENDPOINT",
        required = true,
        value_delimiter = ',',
        action = clap::ArgAction::Append,
    )]
    witness_endpoint: Vec<String>,

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

    /// Estimated number of items in response cache (for initial capacity).
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_RESPONSE_CACHE_ESTIMATED_ITEMS",
        default_value_t = DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS
    )]
    response_cache_estimated_items: usize,

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
    /// miss. Requires at least two witness endpoints and a local DB (`--data-dir`), whose tip
    /// anchors block age; otherwise all blocks use the full chain. Applies to request
    /// serving; chain-sync prefetch always uses the full chain. Should match the generator's
    /// `BACKUP`.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_WITNESS_LOCAL_WINDOW",
        default_value_t = data_provider::DEFAULT_WITNESS_LOCAL_WINDOW
    )]
    witness_local_window: u64,

    /// Witness-stage budget in seconds for blocks at or below the local tip. Defaults to the
    /// full witness budget; lower it to fail fast on blocks whose witness is likely pruned
    /// everywhere. Clamped to `--witness-timeout`.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_WITNESS_OLD_BLOCK_TIMEOUT",
        default_value_t = data_provider::DEFAULT_OLD_BLOCK_WITNESS_TIMEOUT_SECS
    )]
    witness_old_block_timeout: u64,

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

/// Validates cross-flag invariants that clap cannot express per-field.
fn validate_args(args: &Args) -> Result<()> {
    // Only meaningful with chain sync: the fetcher holds the local tip `tip_buffer` blocks
    // behind the head, and `blocks_to_keep` doubles as the stale-reset threshold. A buffer at
    // or past the threshold makes the built-in lag itself look stale, so every transient
    // restart would reset the anchor and leave gaps in stored history.
    if args.data_dir.is_some() && args.tip_buffer >= args.blocks_to_keep {
        eyre::bail!(
            "--tip-buffer ({}) must be smaller than --blocks-to-keep ({})",
            args.tip_buffer,
            args.blocks_to_keep
        );
    }
    Ok(())
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
    let response_cache_disabled = args.response_cache_estimated_items == 0;
    debug!(
        rpc_endpoints = ?args.rpc_endpoint,
        witness_endpoints = ?args.witness_endpoint,
        witness_timeout_secs = args.witness_timeout,
        witness_old_block_timeout_secs = args.witness_old_block_timeout,
        witness_local_window = args.witness_local_window,
        tip_buffer = args.tip_buffer,
        response_cache_disabled,
        response_cache_max_size = args.response_cache_max_size,
        response_cache_estimated_items = args.response_cache_estimated_items,
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
    let witness_apis: Vec<&str> = args.witness_endpoint.iter().map(String::as_str).collect();
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

    match (witness_apis.len() >= 2, args.data_dir.is_some()) {
        (true, true) => info!(
            witness_local_window = args.witness_local_window,
            // The credential-stripped label, not the raw URL — configured endpoint URLs may
            // carry userinfo or token queries and this log line is info-level.
            skipped_endpoint = rpc_client.witness_provider_label(0).unwrap_or("<none>"),
            "Historical witnesses (at least the local window below the tip) skip the internal \
             generator endpoint"
        ),
        (true, false) => warn!(
            "Multiple witness endpoints but no --data-dir: historical witness routing is \
             inactive (block age is anchored to the local DB tip); all witness fetches use the \
             full endpoint chain"
        ),
        (false, _) => debug!("Single witness endpoint configured; no historical witness routing"),
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

    let witness_cfg = WitnessFetchConfig {
        witness_timeout: std::time::Duration::from_secs(args.witness_timeout),
        old_block_witness_timeout: std::time::Duration::from_secs(args.witness_old_block_timeout),
        local_window: args.witness_local_window,
    };
    let data_provider = Arc::new(DataProvider::new(
        rpc_client.clone(),
        block_store.clone(),
        contract_cache,
        witness_cfg,
        std::time::Duration::from_secs(args.block_fetch_timeout),
    ));

    let chain_spec = load_chain_spec(&args)?;

    let response_cache = if response_cache_disabled {
        info!("Response cache disabled (estimated_items = 0)");
        None
    } else {
        let cache = ResponseCache::new(ResponseCacheConfig::new(
            args.response_cache_max_size,
            args.response_cache_estimated_items,
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
        ));
        let fetcher = Arc::new(TraceFetcher { rpc_client: Arc::clone(&rpc_client) });
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
            async move {
                if let Err(e) = history_pruner(
                    db,
                    args.blocks_to_keep,
                    args.pruner_interval_secs,
                    args.db_max_size,
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
        .set_http_middleware(
            tower::ServiceBuilder::new()
                .layer(response_size::ResponseSizeLayer)
                .layer(timing::TimingHeaderLayer),
        )
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

/// Background task that periodically prunes old block data to prevent unbounded database growth.
///
/// Runs in an infinite loop, removing blocks older than `blocks_to_keep` from the current tip.
/// If `db_max_size > 0`, also prunes additional blocks when the DB file exceeds that size.
#[instrument(skip_all, name = "history_pruner")]
async fn history_pruner(
    validator_db: Arc<dyn BlockStore>,
    blocks_to_keep: u64,
    interval_secs: u64,
    db_max_size: u64,
    db_path: PathBuf,
    chain_sync_metrics: metrics::ChainSyncMetrics,
) -> Result<()> {
    let interval = std::time::Duration::from_secs(interval_secs);
    info!(
        blocks_to_keep = blocks_to_keep,
        interval_secs = interval_secs,
        db_max_size = db_max_size,
        "Starting history pruner"
    );

    /// Number of extra blocks to prune per iteration when DB file is over size limit.
    const SIZE_PRUNE_BATCH: u64 = 100;

    loop {
        if let Ok(Some(tip)) = validator_db.get_canonical_tip() {
            let current_tip = tip.block_number;
            let mut prune_before = current_tip.saturating_sub(blocks_to_keep);
            match validator_db.prune_chain(prune_before) {
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

            // Size-based pruning: keep removing blocks until DB is under the limit
            if db_max_size > 0 {
                loop {
                    let file_size = match std::fs::metadata(&db_path) {
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
                    // Don't prune beyond the current tip
                    if prune_before >= current_tip {
                        info!(
                            file_size = file_size,
                            db_max_size = db_max_size,
                            "DB still over size limit but no more blocks to prune"
                        );
                        break;
                    }

                    info!(
                        file_size = file_size,
                        db_max_size = db_max_size,
                        prune_before = prune_before,
                        "DB over size limit, pruning additional blocks"
                    );

                    match validator_db.prune_chain(prune_before) {
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

            // Update DB block range metrics
            let earliest = validator_db.get_earliest().ok().flatten().map(|(n, _)| n).unwrap_or(0);
            chain_sync_metrics.set_db_block_range(earliest, current_tip);

            // Update DB file size metric
            if let Ok(m) = std::fs::metadata(&db_path) {
                chain_sync_metrics.set_db_size(m.len());
            }
        }

        tokio::time::sleep(interval).await;
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

    /// Pins the tiered-witness-routing knob defaults (`--witness-local-window` must track the
    /// generator's `BACKUP`, the old-block budget defaults to the full witness budget) and the
    /// CLI + env parsing of all three knobs — a typo in an env attribute string would
    /// otherwise ship silently to env-only container deployments.
    /// Parses `Args` from the minimal required flags plus `extra`. Callers must hold
    /// `stateless_test_utils::env::env_lock()` — parsing reads `DEBUG_TRACE_SERVER_*` env
    /// vars, so it must be serialized with the tests that mutate them.
    fn parse_args(extra: &[&str]) -> Args {
        let base =
            ["debug-trace-server", "--rpc-endpoint", "http://r", "--witness-endpoint", "http://w"];
        Args::try_parse_from(base.iter().chain(extra)).unwrap()
    }

    #[test]
    fn tiered_routing_flag_defaults() {
        let guard = stateless_test_utils::env::env_lock();

        let defaults = parse_args(&[]);
        assert_eq!(defaults.witness_local_window, data_provider::DEFAULT_WITNESS_LOCAL_WINDOW);
        assert_eq!(
            defaults.witness_old_block_timeout,
            data_provider::DEFAULT_OLD_BLOCK_WITNESS_TIMEOUT_SECS
        );
        assert_eq!(
            data_provider::DEFAULT_OLD_BLOCK_WITNESS_TIMEOUT_SECS,
            data_provider::DEFAULT_WITNESS_TIMEOUT_SECS,
            "old blocks default to the full witness budget",
        );
        assert_eq!(defaults.tip_buffer, 2);

        assert_eq!(parse_args(&["--tip-buffer", "0"]).tip_buffer, 0);
        assert_eq!(parse_args(&["--witness-local-window", "128"]).witness_local_window, 128);
        assert_eq!(parse_args(&["--witness-old-block-timeout", "3"]).witness_old_block_timeout, 3);

        let env = |name, value: &str| {
            stateless_test_utils::env::with_env_var(&guard, name, value, || parse_args(&[]))
        };
        assert_eq!(env("DEBUG_TRACE_SERVER_TIP_BUFFER", "5").tip_buffer, 5);
        assert_eq!(env("DEBUG_TRACE_SERVER_WITNESS_LOCAL_WINDOW", "256").witness_local_window, 256);
        assert_eq!(
            env("DEBUG_TRACE_SERVER_WITNESS_OLD_BLOCK_TIMEOUT", "4").witness_old_block_timeout,
            4
        );
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
