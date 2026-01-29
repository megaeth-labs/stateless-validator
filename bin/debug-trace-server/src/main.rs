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
//! │  Multi-level lookup: LRU cache → Local DB → Remote RPC          │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported RPC Methods
//! - `debug_traceBlockByNumber` - Trace block execution by block number
//! - `debug_traceBlockByHash` - Trace block execution by block hash
//! - `debug_traceTransaction` - Trace a single transaction execution
//! - `trace_block` - Parity-style block tracing (flat call traces)
//! - `trace_transaction` - Parity-style transaction tracing
//! - `debug_setCacheSize` - Dynamically adjust LRU cache size
//! - `debug_getCacheStatus` - Query current cache status
//!
//! # Operating Modes
//! - **Stateless mode**: Without `data_dir`, all data is fetched from remote RPC
//! - **Local cache mode**: With `data_dir`, enables chain sync to pre-fetch blocks into local DB

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
// RPC Method Name Constants
// ---------------------------------------------------------------------------

/// RPC method name for debug_traceBlockByNumber - traces block execution by number.
const DEBUG_TRACE_BLOCK_BY_NUMBER: &str = "debug_traceBlockByNumber";
/// RPC method name for debug_traceBlockByHash - traces block execution by hash.
const DEBUG_TRACE_BLOCK_BY_HASH: &str = "debug_traceBlockByHash";
/// RPC method name for debug_traceTransaction - traces a single transaction.
const DEBUG_TRACE_TRANSACTION: &str = "debug_traceTransaction";
/// RPC method name for trace_block - Parity-style block tracing (flat call traces).
const TRACE_BLOCK: &str = "trace_block";
/// RPC method name for trace_transaction - Parity-style transaction tracing.
const TRACE_TRANSACTION: &str = "trace_transaction";
/// RPC method name for debug_setCacheSize - dynamically adjusts LRU cache size.
const DEBUG_SET_CACHE_SIZE: &str = "debug_setCacheSize";
/// RPC method name for debug_getCacheStatus - queries current cache status.
const DEBUG_GET_CACHE_STATUS: &str = "debug_getCacheStatus";

/// Command line arguments for the debug-trace-server.
///
/// Configuration can be provided via command line arguments or environment variables.
/// Environment variables take precedence over defaults; CLI arguments take highest precedence.
#[derive(Parser, Debug)]
#[clap(name = "debug-trace-server", about = "Debug/Trace RPC Server")]
struct Args {
    /// RPC server listen address.
    /// Format: `host:port`, e.g., `0.0.0.0:8545`
    #[clap(long, env = "DEBUG_TRACE_SERVER_ADDR", default_value = "0.0.0.0:8545")]
    addr: String,

    /// Upstream RPC endpoint URL.
    /// Used for fetching block data and contract bytecode.
    #[clap(long, env = "DEBUG_TRACE_SERVER_RPC_ENDPOINT")]
    rpc_endpoint: String,

    /// Upstream witness endpoint URL.
    /// Used for fetching SALT witness data (state proofs).
    #[clap(long, env = "DEBUG_TRACE_SERVER_WITNESS_ENDPOINT")]
    witness_endpoint: String,

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
    /// Contains hardfork activation configuration for determining EVM rules at different heights.
    #[clap(long, env = "DEBUG_TRACE_SERVER_GENESIS_FILE")]
    genesis_file: Option<String>,

    /// Data directory path.
    /// When specified, enables local database storage and chain sync for pre-fetching blocks.
    /// Without this, the server runs in pure stateless mode (all data from remote RPC).
    #[clap(long, env = "DEBUG_TRACE_SERVER_DATA_DIR")]
    data_dir: Option<String>,

    /// Trusted starting block hash.
    /// Required on first run when data_dir is specified, used to initialize the local chain.
    #[clap(long, env = "DEBUG_TRACE_SERVER_START_BLOCK")]
    start_block: Option<String>,

    /// Maximum number of blocks in LRU cache.
    /// Caches recently accessed block data to reduce redundant RPC calls.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_CACHE_SIZE",
        default_value_t = cache::DEFAULT_CACHE_SIZE
    )]
    cache_size: u64,

    /// Witness fetch timeout in seconds.
    /// Returns error after timeout to avoid long waits.
    #[clap(
        long,
        env = "DEBUG_TRACE_SERVER_WITNESS_TIMEOUT",
        default_value_t = cache::DEFAULT_WITNESS_TIMEOUT_SECS
    )]
    witness_timeout: u64,
}

/// Shared context for all RPC handlers.
///
/// Contains the data provider (with caching) and chain specification,
/// shared across all RPC method handlers via Arc.
#[derive(Clone)]
struct RpcContext {
    /// Data provider with multi-level caching (LRU -> DB -> RPC).
    cache: Arc<DataProvider>,
    /// Chain specification containing hardfork activation rules.
    chain_spec: Arc<ChainSpec>,
}

/// Database filename for the validator's local storage.
const VALIDATOR_DB_FILENAME: &str = "validator.redb";

/// Parses a hex string into a BlockHash.
///
/// # Arguments
/// * `hex_str` - Hex-encoded block hash (with or without 0x prefix)
///
/// # Returns
/// * `Ok(BlockHash)` - Successfully parsed 32-byte block hash
/// * `Err` - If hex decoding fails or length is not 32 bytes
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

    let server = Server::builder()
        .max_response_body_size(u32::MAX)
        .build(&args.addr)
        .await?;
    let addr = server.local_addr()?;
    let handle = server.start(module);

    info!("debug-trace-server listening on {}", addr);
    handle.stopped().await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Creates a JSON-RPC internal error with the given message.
///
/// Uses error code -32000 which is the standard JSON-RPC server error code.
fn rpc_err(msg: String) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(-32000, msg, None::<()>)
}

// ---------------------------------------------------------------------------
// debug_* RPC Methods (Geth-style)
// ---------------------------------------------------------------------------

/// Registers all debug_* RPC methods.
///
/// These methods follow the Geth debug API specification and support various
/// tracer types including CallTracer, PreStateTracer, FourByteTracer, etc.
fn register_debug_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // debug_traceBlockByNumber - Traces all transactions in a block by block number.
    // Params: [blockNumber, tracingOptions?]
    // Returns: Array of TraceResult for each transaction
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

    // debug_traceBlockByHash - Traces all transactions in a block by block hash.
    // Params: [blockHash, tracingOptions?]
    // Returns: Array of TraceResult for each transaction
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

    // debug_traceTransaction - Traces a single transaction by its hash.
    // Replays all preceding transactions in the block to build correct state,
    // then traces the target transaction.
    // Params: [txHash, tracingOptions?]
    // Returns: GethTrace for the transaction
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
// trace_* RPC Methods (Parity/OpenEthereum-style)
// ---------------------------------------------------------------------------

/// Registers all trace_* RPC methods.
///
/// These methods follow the Parity/OpenEthereum trace API specification,
/// returning flat call traces (LocalizedTransactionTrace) instead of nested call frames.
fn register_trace_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // trace_block - Returns flat call traces for all transactions in a block.
    // Params: [blockNumber]
    // Returns: Array of LocalizedTransactionTrace
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

    // trace_transaction - Returns flat call traces for a single transaction.
    // Params: [txHash]
    // Returns: Array of LocalizedTransactionTrace
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
// Cache Management RPC Methods
// ---------------------------------------------------------------------------

/// Registers cache management RPC methods.
///
/// These methods allow runtime inspection and configuration of the LRU cache.
fn register_cache_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // debug_setCacheSize - Dynamically updates the LRU cache size.
    // Note: This clears all existing cache entries.
    // Params: [newSize]
    // Returns: { success: bool, newSize: u64 }
    module.register_async_method(DEBUG_SET_CACHE_SIZE, |params, ctx, _| async move {
        let mut seq = params.sequence();
        let new_size: u64 = seq.next()?;

        ctx.cache.set_cache_size(new_size).await;

        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(serde_json::json!({
            "success": true,
            "newSize": new_size
        }))
    })?;

    // debug_getCacheStatus - Returns current cache configuration and usage.
    // Params: none
    // Returns: { maxSize: u64, entryCount: u64 }
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
