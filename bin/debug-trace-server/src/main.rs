//! Debug/Trace RPC Server
//!
//! # Overview
//! A standalone RPC server for `debug_*` and `trace_*` methods using stateless execution.
//! Data can be fetched from upstream RPC endpoints or from a local database with chain sync.
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
//! - **Stateless mode**: Without `data_dir`, all data is fetched from remote RPC
//! - **Local cache mode**: With `data_dir`, enables chain sync to pre-fetch blocks into local DB

use std::{path::PathBuf, sync::Arc};

use alloy_genesis::Genesis;
use alloy_primitives::{hex, BlockHash, B256};
use alloy_rpc_types_eth::BlockId;
use clap::Parser;
use eyre::{anyhow, ensure, Result};
use jsonrpsee::server::Server;
use stateless_common::logging::LogArgs;
use tokio::task;
use tracing::{debug, error, info, instrument, warn};
use validator_core::{
    chain_spec::ChainSpec, remote_chain_tracker, ChainSyncConfig, RpcClient, RpcClientConfig,
    ValidatorDB,
};

mod data_provider;
mod metrics;
mod response_cache;
mod response_size;
mod rpc_service;
mod timing;

use data_provider::DataProvider;
use response_cache::{ResponseCache, ResponseCacheConfig, DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS};
use rpc_service::RpcContext;

/// Command line arguments for the debug-trace-server.
#[derive(Parser, Debug)]
#[clap(name = "debug-trace-server", about = "Debug/Trace RPC Server")]
struct Args {
    /// RPC server listen address.
    #[clap(long, env = "DEBUG_TRACE_SERVER_ADDR", default_value = "0.0.0.0:8545")]
    addr: String,

    /// Upstream RPC endpoint URL.
    #[clap(long, env = "DEBUG_TRACE_SERVER_RPC_ENDPOINT")]
    rpc_endpoint: String,

    /// Upstream witness endpoint URL.
    #[clap(long, env = "DEBUG_TRACE_SERVER_WITNESS_ENDPOINT")]
    witness_endpoint: String,

    /// Optional Cloudflare witness endpoint URL for pruned/archived blocks.
    #[clap(long, env = "DEBUG_TRACE_SERVER_CLOUDFLARE_WITNESS_ENDPOINT")]
    cloudflare_witness_endpoint: Option<String>,

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

    /// Logging configuration.
    #[command(flatten)]
    log: LogArgs,
}

/// Database filename for the validator's local storage.
const VALIDATOR_DB_FILENAME: &str = "validator.redb";

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

/// Parses a hex string into a BlockHash.
fn parse_block_hash(hex_str: &str) -> Result<BlockHash> {
    let hash_bytes = hex::decode(hex_str)?;
    ensure!(hash_bytes.len() == 32, "Block hash must be 32 bytes, got {}", hash_bytes.len());
    Ok(BlockHash::from_slice(&hash_bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _log_guard = args.log.init_tracing()?;

    info!(
        listen_addr = %args.addr,
        "Debug-trace-server starting"
    );
    let response_cache_disabled = args.response_cache_estimated_items == 0;
    debug!(
        rpc_endpoint = %args.rpc_endpoint,
        witness_endpoint = %args.witness_endpoint,
        witness_timeout_secs = args.witness_timeout,
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
    let rpc_client = Arc::new(RpcClient::new_with_config(
        &args.rpc_endpoint,
        &args.witness_endpoint,
        RpcClientConfig::trace_server(),
        args.cloudflare_witness_endpoint.as_deref(),
        None,
    )?);
    let validator_db = init_validator_db(&args, &rpc_client).await?;

    let data_provider =
        Arc::new(DataProvider::new(rpc_client.clone(), validator_db.clone(), args.witness_timeout));

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

    // Spawn background chain tracker with reorg callback (if database is configured)
    if let Some(db) = &validator_db {
        let config = Arc::new(ChainSyncConfig {
            // Auto-advance local tip since we don't run validation workers
            auto_advance_local_tip: true,
            ..ChainSyncConfig::default()
        });
        debug!(
            lookahead_blocks = config.tracker_lookahead_blocks,
            auto_advance = config.auto_advance_local_tip,
            "Starting chain sync tracker"
        );

        // Clone response_cache for the callback
        let cache_for_reorg = response_cache.clone();
        let chain_sync_metrics = metrics::ChainSyncMetrics::create();
        let fetch_metrics = metrics::ChainSyncMetrics::create();
        task::spawn(remote_chain_tracker(
            Arc::clone(&rpc_client),
            Arc::clone(db),
            config,
            Some(move |reverted_hashes: &[B256]| {
                if !reverted_hashes.is_empty() {
                    chain_sync_metrics.record_reorg(reverted_hashes.len() as u64);
                    if let Some(cache) = &cache_for_reorg {
                        tracing::info!(
                            count = reverted_hashes.len(),
                            "Invalidating response cache for reorged blocks"
                        );
                        cache.invalidate_blocks(reverted_hashes);
                    } else {
                        tracing::debug!(
                            count = reverted_hashes.len(),
                            "Reorg detected (response cache disabled)"
                        );
                    }
                }
            }),
            Some(move |result: &validator_core::FetchResult| {
                if let Some(height) = result.remote_chain_height {
                    fetch_metrics.set_remote_height(height);
                }
            }),
        ));

        // Spawn history pruner to prevent unbounded database growth
        let db_path = PathBuf::from(args.data_dir.as_deref().unwrap()).join(VALIDATOR_DB_FILENAME);
        let pruner_metrics = metrics::ChainSyncMetrics::create();
        task::spawn(history_pruner(
            Arc::clone(db),
            args.blocks_to_keep,
            args.pruner_interval_secs,
            args.db_max_size,
            db_path,
            pruner_metrics,
        ));
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
    let server = Server::builder()
        .max_response_body_size(u32::MAX)
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
) -> Result<Option<Arc<ValidatorDB>>> {
    let Some(data_dir) = &args.data_dir else {
        debug!("Running in stateless mode, no local database");
        return Ok(None);
    };

    debug!(data_dir = %data_dir, "Initializing local database");
    let work_dir = PathBuf::from(data_dir);
    let db = Arc::new(ValidatorDB::new(work_dir.join(VALIDATOR_DB_FILENAME))?);

    // Check if we already have a local tip
    if db.get_local_tip()?.is_some() {
        debug!("Continuing from existing canonical chain");
        return Ok(Some(db));
    }

    // No local tip - need to initialize anchor block
    // Use explicit start_block if provided, otherwise fetch latest
    let header = if let Some(start_block_str) = &args.start_block {
        debug!(start_block = %start_block_str, "Initializing from specified start block");
        let block_hash = parse_block_hash(start_block_str)?;
        loop {
            match rpc_client.get_header(BlockId::Hash(block_hash.into()), false).await {
                Ok(header) => break header,
                Err(e) => {
                    warn!(
                        block_hash = %block_hash,
                        error = %e,
                        "Failed to fetch start block, retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    } else {
        // Auto-initialize from latest block
        info!("No local tip found, fetching latest block as anchor");
        loop {
            match rpc_client.get_header(BlockId::latest(), false).await {
                Ok(header) => break header,
                Err(e) => {
                    warn!(error = %e, "Failed to fetch latest block, retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    };

    db.reset_anchor_block(
        header.number,
        header.hash,
        header.state_root,
        header
            .withdrawals_root
            .ok_or_else(|| anyhow!("Block {} is missing withdrawals_root", header.hash))?,
    )
    .map_err(|e| anyhow!("Failed to reset anchor: {}", e))?;

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
    validator_db: Arc<ValidatorDB>,
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
        if let Ok(Some((current_tip, _))) = validator_db.get_local_tip() {
            let mut prune_before = current_tip.saturating_sub(blocks_to_keep);
            match validator_db.prune_history(prune_before) {
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

                    match validator_db.prune_history(prune_before) {
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
            let earliest =
                validator_db.get_earliest_local_block().ok().flatten().map(|(n, _)| n).unwrap_or(0);
            chain_sync_metrics.set_db_block_range(earliest, current_tip);

            // Update DB file size metric
            if let Ok(m) = std::fs::metadata(&db_path) {
                chain_sync_metrics.set_db_size(m.len());
            }
        }

        tokio::time::sleep(interval).await;
    }
}
