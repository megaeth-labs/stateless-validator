//! Debug/Trace RPC Server
//!
//! A standalone RPC server for `debug_*` and `trace_*` methods using stateless execution.
//! Data can be fetched from upstream RPC endpoints or from a local database with chain sync.

use std::{path::PathBuf, sync::Arc, time::Instant};

use alloy_genesis::Genesis;
use alloy_primitives::{hex, BlockHash, B256};
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag};
use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use clap::Parser;
use eyre::{anyhow, ensure, Result};
use jsonrpsee::server::{RpcModule, Server};
use tokio::task;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use validator_core::{
    chain_spec::ChainSpec, remote_chain_tracker, ChainSyncConfig, RpcClient, ValidatorDB,
};

mod cache;
mod metrics;

use cache::DataProvider;

// ---------------------------------------------------------------------------
// RPC Method Names
// ---------------------------------------------------------------------------

/// debug_traceBlockByNumber method name.
const DEBUG_TRACE_BLOCK_BY_NUMBER: &str = "debug_traceBlockByNumber";
/// debug_traceBlockByHash method name.
const DEBUG_TRACE_BLOCK_BY_HASH: &str = "debug_traceBlockByHash";
/// debug_traceTransaction method name.
const DEBUG_TRACE_TRANSACTION: &str = "debug_traceTransaction";
/// trace_block method name.
const TRACE_BLOCK: &str = "trace_block";
/// trace_transaction method name.
const TRACE_TRANSACTION: &str = "trace_transaction";
/// debug_setCacheSize method name.
const DEBUG_SET_CACHE_SIZE: &str = "debug_setCacheSize";
/// debug_getCacheStatus method name.
const DEBUG_GET_CACHE_STATUS: &str = "debug_getCacheStatus";

/// Command line arguments for the debug-trace-server.
#[derive(Parser, Debug)]
#[clap(name = "debug-trace-server", about = "Debug/Trace RPC Server")]
struct Args {
    /// RPC server listen address.
    #[clap(long, env = "DEBUG_TRACE_SERVER_ADDR", default_value = "0.0.0.0:8545")]
    addr: String,

    /// Upstream RPC endpoint for fetching blocks and contract data.
    #[clap(long, env = "DEBUG_TRACE_SERVER_RPC_ENDPOINT")]
    rpc_endpoint: String,

    /// Upstream witness endpoint for fetching SALT witness data.
    #[clap(long, env = "DEBUG_TRACE_SERVER_WITNESS_ENDPOINT")]
    witness_endpoint: String,

    /// Enable Prometheus metrics endpoint.
    #[clap(long, env = "DEBUG_TRACE_SERVER_METRICS_ENABLED")]
    metrics_enabled: bool,

    /// Port for Prometheus metrics HTTP endpoint.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_METRICS_PORT",
        default_value_t = metrics::DEFAULT_METRICS_PORT
    )]
    metrics_port: u16,

    /// Path to genesis JSON file containing hardfork activation configuration.
    #[clap(long, env = "DEBUG_TRACE_SERVER_GENESIS_FILE")]
    genesis_file: Option<String>,

    /// Directory path where validator data and database files will be stored.
    /// When provided, enables chain sync to pre-fetch blocks into local database.
    #[clap(long, env = "DEBUG_TRACE_SERVER_DATA_DIR")]
    data_dir: Option<String>,

    /// Optional trusted block hash to start chain sync from.
    /// Required on first run when data_dir is provided.
    #[clap(long, env = "DEBUG_TRACE_SERVER_START_BLOCK")]
    start_block: Option<String>,

    /// Maximum number of blocks to cache in memory.
    /// Default is 128 blocks.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_CACHE_SIZE",
        default_value_t = cache::DEFAULT_CACHE_SIZE
    )]
    cache_size: u64,

    /// Timeout in seconds for witness fetch retry.
    /// Default is 8 seconds.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_WITNESS_TIMEOUT",
        default_value_t = cache::DEFAULT_WITNESS_TIMEOUT_SECS
    )]
    witness_timeout: u64,
}

/// Shared context for all RPC handlers.
#[derive(Clone)]
struct RpcContext {
    cache: Arc<DataProvider>,
    chain_spec: Arc<ChainSpec>,
}

/// Database filename for the validator.
const VALIDATOR_DB_FILENAME: &str = "validator.redb";

/// Convert hex string to BlockHash
fn parse_block_hash(hex_str: &str) -> Result<BlockHash> {
    let hash_bytes = hex::decode(hex_str)?;
    ensure!(
        hash_bytes.len() == 32,
        "Block hash must be 32 bytes, got {}",
        hash_bytes.len()
    );
    Ok(BlockHash::from_slice(&hash_bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug_trace_server=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    info!("Starting debug-trace-server");
    info!("RPC endpoint: {}", args.rpc_endpoint);
    info!("Witness endpoint: {}", args.witness_endpoint);
    info!("Listen address: {}", args.addr);
    info!("Cache size: {} blocks", args.cache_size);
    info!("Witness timeout: {} seconds", args.witness_timeout);

    // Initialize metrics
    if args.metrics_enabled {
        let metrics_addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.metrics_port));
        metrics::init_metrics(metrics_addr)?;
        info!("Metrics enabled on port {}", args.metrics_port);
    } else {
        info!("Metrics disabled");
    }

    // Initialize RPC client
    let rpc_client = Arc::new(RpcClient::new(&args.rpc_endpoint, &args.witness_endpoint)?);

    // Initialize ValidatorDB if data_dir is provided
    let validator_db = if let Some(data_dir) = &args.data_dir {
        info!("Data directory: {}", data_dir);
        let work_dir = PathBuf::from(data_dir);
        let db = Arc::new(ValidatorDB::new(work_dir.join(VALIDATOR_DB_FILENAME))?);

        // Handle optional start block initialization
        if let Some(start_block_str) = &args.start_block {
            info!("Initializing from start block: {}", start_block_str);

            let block_hash = parse_block_hash(start_block_str)?;
            let block = loop {
                match rpc_client
                    .get_block(BlockId::Hash(block_hash.into()), false)
                    .await
                {
                    Ok(block) => break block,
                    Err(e) => {
                        tracing::warn!("Failed to fetch block {block_hash}: {e}, retrying...");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            };

            db.reset_anchor_block(
                block.header.number,
                block.header.hash,
                block.header.state_root,
                block
                    .header
                    .withdrawals_root
                    .ok_or_else(|| anyhow!("Block {} is missing withdrawals_root", block_hash))?,
            )
            .map_err(|e| anyhow!("Failed to reset anchor: {}", e))?;

            info!(
                "Successfully initialized from block {} (number: {})",
                block.header.hash, block.header.number
            );
        } else {
            // If no start block was provided, ensure we have an existing canonical chain
            ensure!(
                db.get_local_tip()?.is_some(),
                "No trusted starting point found. Specify a trusted block with --start-block <blockhash>"
            );
            info!("Continuing from existing canonical chain");
        }

        // Spawn background chain tracker
        let config = Arc::new(ChainSyncConfig::default());
        info!(
            "Starting chain sync with {} block lookahead",
            config.tracker_lookahead_blocks
        );
        task::spawn(remote_chain_tracker(
            Arc::clone(&rpc_client),
            Arc::clone(&db),
            config,
            None::<fn(u64)>, // No reorg callback for debug-trace-server
        ));

        Some(db)
    } else {
        info!("No data directory specified, running in stateless mode (all data fetched from RPC)");
        None
    };

    let cache = Arc::new(DataProvider::new(
        &args.rpc_endpoint,
        &args.witness_endpoint,
        validator_db,
        args.cache_size,
        args.witness_timeout,
    )?);

    let chain_spec = if let Some(genesis_path) = &args.genesis_file {
        info!("Loading genesis from: {}", genesis_path);
        let genesis_content = std::fs::read_to_string(genesis_path)?;
        let genesis: Genesis = serde_json::from_str(&genesis_content)?;
        Arc::new(ChainSpec::from_genesis(genesis))
    } else {
        info!("Using default chain spec");
        Arc::new(ChainSpec::default())
    };

    let ctx = RpcContext { cache, chain_spec };

    let mut module = RpcModule::new(ctx);
    register_debug_methods(&mut module)?;
    register_trace_methods(&mut module)?;
    register_cache_methods(&mut module)?;

    let server = Server::builder().build(&args.addr).await?;
    let addr = server.local_addr()?;
    let handle = server.start(module);

    info!("debug-trace-server listening on {}", addr);
    handle.stopped().await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Shorthand for creating a JSON-RPC internal error.
fn rpc_err(msg: String) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(-32000, msg, None::<()>)
}

// ---------------------------------------------------------------------------
// debug_* methods
// ---------------------------------------------------------------------------

fn register_debug_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // debug_traceBlockByNumber
    module.register_async_method(DEBUG_TRACE_BLOCK_BY_NUMBER, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let block_tag: BlockNumberOrTag = seq.next()?;
        let opts: GethDebugTracingOptions = seq.optional_next()?.unwrap_or_default();

        let block_num = ctx
            .cache
            .resolve_block_number(block_tag)
            .await
            .map_err(|e| rpc_err(format!("Failed to resolve block number: {e}")))?;

        let data = ctx
            .cache
            .get_block_data(block_num)
            .await
            .map_err(|e| rpc_err(format!("Failed to fetch block data: {e}")))?;

        let results = validator_core::trace_block(
            &ctx.chain_spec,
            &data.block,
            &data.salt_witness,
            &data.contracts,
            opts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        metrics::record_rpc_request(DEBUG_TRACE_BLOCK_BY_NUMBER, start.elapsed().as_secs_f64());

        serde_json::to_value(results).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    })?;

    // debug_traceBlockByHash
    module.register_async_method(DEBUG_TRACE_BLOCK_BY_HASH, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let block_hash: B256 = seq.next()?;
        let opts: GethDebugTracingOptions = seq.optional_next()?.unwrap_or_default();

        let data = ctx
            .cache
            .get_block_data_by_hash(block_hash)
            .await
            .map_err(|e| rpc_err(format!("Failed to fetch block data: {e}")))?;

        let results = validator_core::trace_block(
            &ctx.chain_spec,
            &data.block,
            &data.salt_witness,
            &data.contracts,
            opts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        metrics::record_rpc_request(DEBUG_TRACE_BLOCK_BY_HASH, start.elapsed().as_secs_f64());

        serde_json::to_value(results).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    })?;

    // debug_traceTransaction
    module.register_async_method(DEBUG_TRACE_TRANSACTION, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let tx_hash: B256 = seq.next()?;
        let opts: GethDebugTracingOptions = seq.optional_next()?.unwrap_or_default();

        let (data, tx_index) = ctx
            .cache
            .get_block_data_for_tx(tx_hash)
            .await
            .map_err(|e| rpc_err(format!("Failed to get block data for tx {tx_hash:?}: {e}")))?;

        let result = validator_core::trace_transaction(
            &ctx.chain_spec,
            &data.block,
            tx_index,
            &data.salt_witness,
            &data.contracts,
            opts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        metrics::record_rpc_request(DEBUG_TRACE_TRANSACTION, start.elapsed().as_secs_f64());

        serde_json::to_value(result).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// trace_* methods (Parity-style, using FlatCallTracer)
// ---------------------------------------------------------------------------

fn register_trace_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // trace_block
    module.register_async_method(TRACE_BLOCK, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let block_tag: BlockNumberOrTag = seq.next()?;

        let block_num = ctx
            .cache
            .resolve_block_number(block_tag)
            .await
            .map_err(|e| rpc_err(format!("Failed to resolve block number: {e}")))?;

        let data = ctx
            .cache
            .get_block_data(block_num)
            .await
            .map_err(|e| rpc_err(format!("Failed to fetch block data: {e}")))?;

        // Use parity_trace_block for Parity-style flat trace output
        let results = validator_core::parity_trace_block(
            &ctx.chain_spec,
            &data.block,
            &data.salt_witness,
            &data.contracts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        metrics::record_rpc_request(TRACE_BLOCK, start.elapsed().as_secs_f64());

        serde_json::to_value(results).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    })?;

    // trace_transaction
    module.register_async_method(TRACE_TRANSACTION, |params, ctx, _| async move {
        let start = Instant::now();
        let mut seq = params.sequence();
        let tx_hash: B256 = seq.next()?;

        let (data, tx_index) = ctx
            .cache
            .get_block_data_for_tx(tx_hash)
            .await
            .map_err(|e| rpc_err(format!("Failed to get block data for tx {tx_hash:?}: {e}")))?;

        // Use parity_trace_transaction for Parity-style flat trace output
        let result = validator_core::parity_trace_transaction(
            &ctx.chain_spec,
            &data.block,
            tx_index,
            &data.salt_witness,
            &data.contracts,
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        metrics::record_rpc_request(TRACE_TRANSACTION, start.elapsed().as_secs_f64());

        serde_json::to_value(result).map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Cache management methods
// ---------------------------------------------------------------------------

fn register_cache_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // debug_setCacheSize - dynamically update cache size
    module.register_async_method(DEBUG_SET_CACHE_SIZE, |params, ctx, _| async move {
        let mut seq = params.sequence();
        let new_size: u64 = seq.next()?;

        ctx.cache.set_cache_size(new_size).await;

        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(serde_json::json!({
            "success": true,
            "newSize": new_size
        }))
    })?;

    // debug_getCacheStatus - get current cache status
    module.register_async_method(DEBUG_GET_CACHE_STATUS, |_params, ctx, _| async move {
        let size = ctx.cache.get_cache_size();
        let entry_count = ctx.cache.get_cache_entry_count().await;

        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(serde_json::json!({
            "maxSize": size,
            "entryCount": entry_count
        }))
    })?;

    Ok(())
}
