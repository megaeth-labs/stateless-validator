//! Debug/Trace RPC Server
//!
//! A standalone RPC server for `debug_*` and `trace_*` methods using stateless execution.
//! Reuses the cache layer and tracing executor from `validator-core`.

use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockNumberOrTag;
use alloy_rpc_types_trace::geth::{
    GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
};
use clap::Parser;
use eyre::Result;
use jsonrpsee::server::{RpcModule, Server};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use validator_core::chain_spec::ChainSpec;

mod cache;
mod metrics;

use cache::{CacheConfig, CachedDataProvider};

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

/// Command line arguments for the debug-trace-server.
#[derive(Parser, Debug)]
#[clap(name = "debug-trace-server", about = "Debug/Trace RPC Server")]
struct Args {
    /// RPC server listen address.
    #[clap(long, env = "DEBUG_TRACE_SERVER_ADDR", default_value = "0.0.0.0:8545")]
    addr: String,

    /// Data directory for local storage.
    #[clap(long, env = "DEBUG_TRACE_SERVER_DATA_DIR", default_value = "./data")]
    data_dir: String,

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

    /// Maximum number of blocks to cache.
    #[clap(long, env = "DEBUG_TRACE_SERVER_CACHE_BLOCKS", default_value_t = 100)]
    cache_blocks: usize,

    /// Maximum number of witnesses to cache.
    #[clap(long, env = "DEBUG_TRACE_SERVER_CACHE_WITNESSES", default_value_t = 100)]
    cache_witnesses: usize,

    /// Maximum number of contracts to cache.
    #[clap(long, env = "DEBUG_TRACE_SERVER_CACHE_CONTRACTS", default_value_t = 10000)]
    cache_contracts: usize,
}

/// Shared context for all RPC handlers.
#[derive(Clone)]
struct RpcContext {
    cache: Arc<CachedDataProvider>,
    chain_spec: Arc<ChainSpec>,
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
    info!("Data directory: {}", args.data_dir);
    info!("RPC endpoint: {}", args.rpc_endpoint);
    info!("Witness endpoint: {}", args.witness_endpoint);
    info!("Listen address: {}", args.addr);
    info!(
        "Cache config: blocks={}, witnesses={}, contracts={}",
        args.cache_blocks, args.cache_witnesses, args.cache_contracts
    );

    // Ensure data directory exists
    std::fs::create_dir_all(&args.data_dir)?;

    // Initialize metrics
    if args.metrics_enabled {
        let metrics_addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.metrics_port));
        metrics::init_metrics(metrics_addr)?;
        info!("Metrics enabled on port {}", args.metrics_port);
    } else {
        info!("Metrics disabled");
    }

    // Create cached data provider (encapsulates RPC client internally)
    let cache_config = CacheConfig {
        max_blocks: args.cache_blocks,
        max_witnesses: args.cache_witnesses,
        max_contracts: args.cache_contracts,
    };
    let cache = Arc::new(CachedDataProvider::new(
        &args.rpc_endpoint,
        &args.witness_endpoint,
        cache_config,
    )?);

    let chain_spec = Arc::new(ChainSpec::default());
    let ctx = RpcContext {
        cache,
        chain_spec,
    };

    let mut module = RpcModule::new(ctx);
    register_debug_methods(&mut module)?;
    register_trace_methods(&mut module)?;

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

/// Creates tracing options for Parity-style flat call traces.
fn parity_trace_opts() -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        tracer: Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::FlatCallTracer,
        )),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// debug_* methods
// ---------------------------------------------------------------------------

fn register_debug_methods(module: &mut RpcModule<RpcContext>) -> Result<()> {
    // debug_traceBlockByNumber
    module.register_async_method(
        DEBUG_TRACE_BLOCK_BY_NUMBER,
        |params, ctx, _| async move {
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

            metrics::record_rpc_request(
                DEBUG_TRACE_BLOCK_BY_NUMBER,
                start.elapsed().as_secs_f64(),
            );

            serde_json::to_value(results)
                .map_err(|e| rpc_err(format!("Serialization failed: {e}")))
        },
    )?;

    // debug_traceBlockByHash
    module.register_async_method(
        DEBUG_TRACE_BLOCK_BY_HASH,
        |params, ctx, _| async move {
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

            metrics::record_rpc_request(
                DEBUG_TRACE_BLOCK_BY_HASH,
                start.elapsed().as_secs_f64(),
            );

            serde_json::to_value(results)
                .map_err(|e| rpc_err(format!("Serialization failed: {e}")))
        },
    )?;

    // debug_traceTransaction
    module.register_async_method(
        DEBUG_TRACE_TRANSACTION,
        |params, ctx, _| async move {
            let start = Instant::now();
            let mut seq = params.sequence();
            let tx_hash: B256 = seq.next()?;
            let opts: GethDebugTracingOptions = seq.optional_next()?.unwrap_or_default();

            // Use optimized method that caches tx -> block mapping
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

            metrics::record_rpc_request(
                DEBUG_TRACE_TRANSACTION,
                start.elapsed().as_secs_f64(),
            );

            serde_json::to_value(result)
                .map_err(|e| rpc_err(format!("Serialization failed: {e}")))
        },
    )?;

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

        let results = validator_core::trace_block(
            &ctx.chain_spec,
            &data.block,
            &data.salt_witness,
            &data.contracts,
            parity_trace_opts(),
        )
        .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

        metrics::record_rpc_request(TRACE_BLOCK, start.elapsed().as_secs_f64());

        serde_json::to_value(results)
            .map_err(|e| rpc_err(format!("Serialization failed: {e}")))
    })?;

    // trace_transaction
    module.register_async_method(
        TRACE_TRANSACTION,
        |params, ctx, _| async move {
            let start = Instant::now();
            let mut seq = params.sequence();
            let tx_hash: B256 = seq.next()?;

            // Use optimized method that caches tx -> block mapping
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
                parity_trace_opts(),
            )
            .map_err(|e| rpc_err(format!("Trace execution failed: {e}")))?;

            metrics::record_rpc_request(TRACE_TRANSACTION, start.elapsed().as_secs_f64());

            serde_json::to_value(result)
                .map_err(|e| rpc_err(format!("Serialization failed: {e}")))
        },
    )?;

    Ok(())
}
