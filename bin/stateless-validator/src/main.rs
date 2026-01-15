use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, BlockNumber, hex};
use alloy_rpc_types_eth::{Block, BlockId};
use clap::Parser;
use eyre::{Result, anyhow, ensure};
use futures::future;
use op_alloy_rpc_types::Transaction;
use revm::{primitives::KECCAK_EMPTY, state::Bytecode};
use salt::SaltWitness;
use tokio::{signal, task};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use validator_core::{
    BlockLimitsOverrides, ValidatorDB,
    chain_spec::ChainSpec,
    data_types::{PlainKey, PlainValue},
    executor::{ValidationResult, validate_block},
    withdrawals::MptWitness,
};

mod metrics;
mod rpc;
use rpc::RpcClient;

/// Database filename for the validator.
const VALIDATOR_DB_FILENAME: &str = "validator.redb";

/// Initialize logging system with environment variable configuration
///
/// Supports the following environment variables:
/// - STATELESS_VALIDATOR_LOG_FILE_DIRECTORY: Directory for log files (optional, file logging disabled if not set)
/// - STATELESS_VALIDATOR_LOG_FILE: Log level for file output (debug/info/warn/error), default: debug
/// - STATELESS_VALIDATOR_LOG_STDOUT: Log level for stdout (debug/info/warn/error), default: info
fn init_logging() -> Result<()> {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};

    // Load environment configuration with defaults
    let file_directory = std::env::var("STATELESS_VALIDATOR_LOG_FILE_DIRECTORY").ok();
    let file_filter =
        std::env::var("STATELESS_VALIDATOR_LOG_FILE").unwrap_or_else(|_| "debug".to_string());
    let stdout_filter =
        std::env::var("STATELESS_VALIDATOR_LOG_STDOUT").unwrap_or_else(|_| "info".to_string());

    // Configure stdout layer with external crate filtering
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(
            EnvFilter::new("warn")
                .add_directive(format!("validator_core={}", stdout_filter).parse()?)
                .add_directive(format!("stateless_validator={}", stdout_filter).parse()?),
        )
        .boxed();

    let subscriber = tracing_subscriber::registry().with(stdout_layer);

    // Optionally add file layer if directory is specified
    if let Some(log_dir) = &file_directory {
        let log_path = PathBuf::from(log_dir);
        std::fs::create_dir_all(&log_path)
            .map_err(|e| anyhow!("Failed to create log directory {log_dir}: {e}"))?;

        // Configure file layer with daily rotation and filter
        let file_layer = fmt::layer()
            .with_writer(RollingFileAppender::new(
                Rotation::DAILY,
                log_path,
                "stateless-validator.log",
            ))
            .with_filter(
                EnvFilter::new("warn")
                    .add_directive(format!("validator_core={}", file_filter).parse()?)
                    .add_directive(format!("stateless_validator={}", file_filter).parse()?),
            )
            .boxed();

        subscriber.with(file_layer).init();
        info!("[Logging] Initialized: stdout={stdout_filter}, file={file_filter} ({log_dir})");
    } else {
        subscriber.init();
        info!("[Logging] Initialized: stdout={stdout_filter}, file logging disabled");
    }

    Ok(())
}

/// Convert hex string to BlockHash
///
/// Accepts hex strings with or without "0x" prefix. Must be exactly 32 bytes when decoded.
fn parse_block_hash(hex_str: &str) -> Result<BlockHash> {
    let hash_bytes = hex::decode(hex_str)?;
    ensure!(
        hash_bytes.len() == 32,
        "Block hash must be 32 bytes, got {}",
        hash_bytes.len()
    );
    Ok(BlockHash::from_slice(&hash_bytes))
}

/// Loads or creates a ChainSpec from either the database or a genesis file.
///
/// This function implements the following logic:
/// 1. If `genesis_file` is provided: load from file, store in DB, return ChainSpec
/// 2. If `genesis_file` is None: load from DB
/// 3. If neither source available: return error
///
/// # Arguments
/// * `validator_db` - Database to load/store genesis configuration
/// * `genesis_file` - Optional path to genesis JSON file
///
/// # Returns
/// * `Ok(ChainSpec)` - Successfully loaded chain specification
/// * `Err(eyre::Error)` - Failed to load genesis from any source
fn load_or_create_chain_spec(
    validator_db: &ValidatorDB,
    genesis_file: Option<&str>,
) -> Result<ChainSpec> {
    let genesis = match genesis_file {
        Some(path) => {
            info!("[ChainSpec] Loading genesis from file: {path}");
            let genesis = serde_json::from_str::<Genesis>(&std::fs::read_to_string(path)?)?;
            validator_db.store_genesis(&genesis)?;
            genesis
        }
        None => {
            info!("[ChainSpec] Loading genesis from database");
            validator_db.load_genesis()?.ok_or_else(|| {
                anyhow!("No genesis config found. Please provide --genesis-file on first run.")
            })?
        }
    };

    Ok(ChainSpec::from_genesis(genesis))
}

/// Configuration for chain synchronization behavior
#[derive(Debug, Clone)]
pub struct ChainSyncConfig {
    /// Number of parallel validation workers to spawn
    pub concurrent_workers: usize,
    /// Time to wait between main sync cycles
    pub sync_poll_interval: Duration,
    /// Optional block height to sync to; None for infinite sync
    pub sync_target: Option<u64>,
    /// Number of blocks to maintain as lookahead buffer
    pub tracker_lookahead_blocks: u64,
    /// Time to wait between remote chain tracker cycles
    pub tracker_poll_interval: Duration,
    /// Time to wait between history pruning cycles
    pub pruner_interval: Duration,
    /// Number of recent blocks to retain from current tip
    pub pruner_blocks_to_keep: u64,
    /// Time to wait when validation workers have no tasks
    pub worker_idle_sleep: Duration,
    /// Time to wait when validation workers encounter errors
    pub worker_error_sleep: Duration,
    /// Time to wait when remote tracker encounters RPC/DB errors
    pub tracker_error_sleep: Duration,
    /// Enable reporting of validated blocks to upstream node
    pub report_validation_results: bool,
    /// Enable Prometheus metrics endpoint
    pub metrics_enabled: bool,
    /// Port for Prometheus metrics HTTP endpoint
    pub metrics_port: u16,
    /// Block limits overrides for testing purposes only
    pub block_limits_overrides: BlockLimitsOverrides,
}

impl Default for ChainSyncConfig {
    fn default() -> Self {
        Self {
            concurrent_workers: num_cpus::get(),
            sync_poll_interval: Duration::from_secs(1),
            sync_target: None,
            tracker_lookahead_blocks: 80,
            tracker_poll_interval: Duration::from_millis(100),
            pruner_interval: Duration::from_secs(300),
            pruner_blocks_to_keep: 1000,
            worker_idle_sleep: Duration::from_millis(500),
            worker_error_sleep: Duration::from_millis(1000),
            tracker_error_sleep: Duration::from_secs(1),
            report_validation_results: false,
            metrics_enabled: false,
            metrics_port: metrics::DEFAULT_METRICS_PORT,
            block_limits_overrides: BlockLimitsOverrides::default(),
        }
    }
}

/// Command line arguments for the stateless validator.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CommandLineArgs {
    /// Directory path where validator data and database files will be stored.
    #[clap(long, env = "STATELESS_VALIDATOR_DATA_DIR")]
    data_dir: String,

    /// The URL of the Ethereum JSON-RPC API endpoint for fetching blockchain data.
    #[clap(long, env = "STATELESS_VALIDATOR_RPC_ENDPOINT")]
    rpc_endpoint: String,

    /// The URL of the MegaETH JSON-RPC API endpoint for fetching witness data.
    #[clap(long, env = "STATELESS_VALIDATOR_WITNESS_ENDPOINT")]
    witness_endpoint: String,

    /// Optional trusted block hash to start validation from.
    #[clap(long, env = "STATELESS_VALIDATOR_START_BLOCK")]
    start_block: Option<String>,

    /// Path to the genesis JSON file for chain configuration.
    /// Required on first run, optional on subsequent runs (loads from database).
    #[clap(long, env = "STATELESS_VALIDATOR_GENESIS_FILE")]
    genesis_file: Option<String>,

    /// Enable reporting of validated blocks to the upstream node.
    /// When enabled, the validator will send validation results via mega_setValidatedBlock RPC.
    #[clap(long, env = "STATELESS_VALIDATOR_REPORT_VALIDATION_RESULTS")]
    report_validation_results: bool,

    /// Enable Prometheus metrics endpoint.
    /// When enabled, metrics are exposed at http://0.0.0.0:<metrics-port>/metrics
    #[clap(long, env = "STATELESS_VALIDATOR_METRICS_ENABLED")]
    metrics_enabled: bool,

    /// Port for Prometheus metrics HTTP endpoint.
    #[clap(long, env = "STATELESS_VALIDATOR_METRICS_PORT", default_value_t = metrics::DEFAULT_METRICS_PORT)]
    metrics_port: u16,
}

/// Reads block limits overrides from environment variables.
///
/// These overrides allow testing with different block limit parameters without
/// modifying the chain specification. DO NOT USE IN PRODUCTION.
///
/// If environment variables are not set, the following default values will be used:
/// - `block_txs_data_limit`: 101857600
/// - `block_kv_update_limit`: 1000000
/// - `block_state_growth_limit`: 1000000
///
/// Environment variables:
/// - `STATELESS_VALIDATOR_BLOCK_TXS_DATA_LIMIT_ONLY_TESTING`: Override block transaction data size limit
/// - `STATELESS_VALIDATOR_BLOCK_KV_UPDATE_LIMIT_ONLY_TESTING`: Override block KV update limit
/// - `STATELESS_VALIDATOR_BLOCK_STATE_GROWTH_LIMIT_ONLY_TESTING`: Override block state growth limit
fn read_block_limits_overrides_from_env() -> BlockLimitsOverrides {
    // Default values when environment variables are not set
    const DEFAULT_BLOCK_TXS_DATA_LIMIT: u64 = 101857600;
    const DEFAULT_BLOCK_KV_UPDATE_LIMIT: u64 = 1000000;
    const DEFAULT_BLOCK_STATE_GROWTH_LIMIT: u64 = 1000000;

    fn parse_env_u64(var_name: &str, default: u64) -> Option<u64> {
        Some(
            std::env::var(var_name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default),
        )
    }

    BlockLimitsOverrides {
        block_txs_data_limit: parse_env_u64(
            "STATELESS_VALIDATOR_BLOCK_TXS_DATA_LIMIT_ONLY_TESTING",
            DEFAULT_BLOCK_TXS_DATA_LIMIT,
        ),
        block_kv_update_limit: parse_env_u64(
            "STATELESS_VALIDATOR_BLOCK_KV_UPDATE_LIMIT_ONLY_TESTING",
            DEFAULT_BLOCK_KV_UPDATE_LIMIT,
        ),
        block_state_growth_limit: parse_env_u64(
            "STATELESS_VALIDATOR_BLOCK_STATE_GROWTH_LIMIT_ONLY_TESTING",
            DEFAULT_BLOCK_STATE_GROWTH_LIMIT,
        ),
    }
}

fn main() -> Result<()> {
    init_logging()?;
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow!("Failed to build Tokio runtime: {e}"))?;
    let timeout = Duration::from_secs(1);
    let result = runtime.block_on(run());
    let shutdown_start = Instant::now();
    runtime.shutdown_timeout(timeout);
    if shutdown_start.elapsed() >= timeout {
        warn!(
            "[Main] Tokio runtime shutdown reached the {:?} timeout.",
            timeout
        );
    }
    result
}

async fn run() -> Result<()> {
    let start = Instant::now();
    let args = CommandLineArgs::parse();

    info!("[Main] Data directory: {}", args.data_dir);
    info!("[Main] RPC endpoint: {}", args.rpc_endpoint);
    info!("[Main] Witness endpoint: {}", args.witness_endpoint);
    if let Some(ref genesis_file) = args.genesis_file {
        info!("[Main] Genesis file: {}", genesis_file);
    }

    // Initialize metrics if enabled
    if args.metrics_enabled {
        let metrics_addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.metrics_port));
        metrics::init_metrics(metrics_addr)?;
        info!("[Main] Metrics enabled on port {}", args.metrics_port);
    } else {
        info!("[Main] Metrics disabled");
    }

    let work_dir = PathBuf::from(args.data_dir);

    let client = Arc::new(RpcClient::new(&args.rpc_endpoint, &args.witness_endpoint)?);
    let validator_db = Arc::new(ValidatorDB::new(work_dir.join(VALIDATOR_DB_FILENAME))?);

    // Load chain spec from file (first run) or database (subsequent runs)
    let chain_spec = Arc::new(load_or_create_chain_spec(
        &validator_db,
        args.genesis_file.as_deref(),
    )?);
    info!("[Main] Chain spec loaded successfully");

    // Handle optional start block initialization
    if let Some(start_block_str) = &args.start_block {
        info!("[Main] Initializing from start block: {}", start_block_str);

        let block_hash = parse_block_hash(start_block_str)?;
        let block = loop {
            match client
                .get_block(BlockId::Hash(block_hash.into()), false)
                .await
            {
                Ok(block) => break block,
                Err(e) => {
                    warn!("[Main] Failed to fetch block {block_hash}: {e}, retrying...",);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };

        validator_db
            .reset_anchor_block(
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
            "[Main] Successfully initialized from block {} (number: {})",
            block.header.hash, block.header.number
        );
    } else {
        // If no start block was provided, ensure we have an existing canonical chain
        ensure!(
            validator_db.get_local_tip()?.is_some(),
            "No trusted starting point found. Specify a trusted block with --start-block <blockhash>"
        );
        info!("[Main] Continuing from existing canonical chain");
    }

    // Create chain sync configuration
    let config = Arc::new(ChainSyncConfig {
        concurrent_workers: num_cpus::get(),
        report_validation_results: args.report_validation_results,
        metrics_enabled: args.metrics_enabled,
        metrics_port: args.metrics_port,
        block_limits_overrides: read_block_limits_overrides_from_env(),
        ..ChainSyncConfig::default()
    });
    info!(
        "[Main] Number of concurrent tasks: {}",
        config.concurrent_workers
    );
    info!(
        "[Main] Validation result reporting: {}",
        if config.report_validation_results {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        "[Main] Block limits overrides: {:?}",
        config.block_limits_overrides
    );

    let validator_logic = chain_sync(client.clone(), validator_db.clone(), config, chain_spec);

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow!("Failed to register SIGTERM handler: {e}"))?;

    tokio::select! {
        res = validator_logic => res?,
        _ = signal::ctrl_c() => {
            info!("[Main] SIGINT received, shutting down.");
        }
        _ = sigterm.recv() => {
            info!("[Main] SIGTERM received, shutting down.");
        }
    }

    info!("[Main] Total execution time: {:?}", start.elapsed());
    Ok(())
}

/// Chain synchronizer entry point - orchestrates the complete chain synchronization pipeline
///
/// Implements a multi-phase startup process for stateless block validation:
/// 1. **Task Recovery** - Recovers interrupted validation tasks from previous crashes
/// 2. **Remote Chain Tracking** - Spawns background tracker to maintain block lookahead
/// 3. **Validation Reporter** - Optionally spawns background task to report validation results to upstream node (when enabled)
/// 4. **History Pruning** - Spawns background pruner to manage storage overhead
/// 5. **Validation Workers** - Spawns configured number of parallel validation workers
/// 6. **Main Sync Loop** - Continuously advances canonical chain as blocks are validated
///
/// Runs indefinitely unless a sync target is configured. Background components operate
/// independently while the main thread advances the canonical chain.
///
/// # Arguments
/// * `client` - RPC client for communicating with remote blockchain node
/// * `validator_db` - Database interface for task coordination and chain state management
/// * `config` - Configuration including worker count, polling intervals, optional sync target, and validation reporting
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
///
/// # Returns
/// * `Ok(())` - When sync target is reached (if configured)
/// * `Err(eyre::Error)` - On critical failures during task recovery
async fn chain_sync(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
    chain_spec: Arc<ChainSpec>,
) -> Result<()> {
    info!(
        "[Chain Sync] Starting with {} validation workers",
        config.concurrent_workers
    );

    // Step 1: Recover any interrupted tasks from previous crashes
    info!("[Chain Sync] Recovering interrupted validation tasks from previous runs...");
    validator_db
        .recover_interrupted_tasks()
        .map_err(|e| anyhow!("Failed to recover interrupted tasks: {}", e))?;
    info!("[Chain Sync] Task recovery completed");

    // Step 2: Spawn remote chain tracker
    info!("[Chain Sync] Starting remote chain tracker...");
    task::spawn(remote_chain_tracker(
        Arc::clone(&client),
        Arc::clone(&validator_db),
        Arc::clone(&config),
    ));

    // Step 3: Spawn validation reporter (optional, based on config)
    if config.report_validation_results {
        info!("[Chain Sync] Starting validation reporter...");
        task::spawn(validation_reporter(
            Arc::clone(&client),
            Arc::clone(&validator_db),
            Arc::clone(&config),
        ));
    } else {
        info!("[Chain Sync] Validation reporter disabled (validation reporting not enabled)");
    }

    // Step 4: Spawn history pruner
    task::spawn(history_pruner(
        Arc::clone(&validator_db),
        Arc::clone(&config),
    ));

    // Step 5: Spawn validation workers as tokio tasks
    info!(
        "[Chain Sync] Spawning {} validation workers...",
        config.concurrent_workers
    );
    for worker_id in 0..config.concurrent_workers {
        task::spawn(validation_worker(
            worker_id,
            Arc::clone(&client),
            Arc::clone(&validator_db),
            Arc::clone(&config),
            Arc::clone(&chain_spec),
        ));
    }
    info!("[Chain Sync] All validation workers started");

    // Step 6: Main chain synchronizer loop
    info!("[Chain Sync] Starting main synchronizer loop...");

    loop {
        if let Some(target) = config.sync_target
            && let Ok(Some((local_block_number, _))) = validator_db.get_local_tip()
            && local_block_number >= target
        {
            debug!("[Chain Sync] Reached sync target height {target}, terminating");
            return Ok(());
        }

        if let Err(e) = async {
            // Advance the canonical chain with newly validated blocks
            let mut blocks_advanced = 0;
            while validator_db.grow_local_chain()? {
                blocks_advanced += 1;
            }

            if blocks_advanced > 0 {
                debug!("[Chain Sync] Advanced canonical chain by {blocks_advanced} blocks");
            } else {
                // No work to do, wait a bit before polling again
                tokio::time::sleep(config.sync_poll_interval).await;
            }

            // Update chain height metrics
            if let (Ok(Some((local_tip, _))), Ok(remote_tip)) =
                (validator_db.get_local_tip(), validator_db.get_remote_tip())
            {
                let remote_height = remote_tip.map(|(n, _)| n).unwrap_or(local_tip);
                metrics::set_chain_heights(local_tip, remote_height);
            }

            Ok::<(), eyre::Error>(())
        }
        .await
        {
            // NOTE: We do NOT retry on errors here. All errors from grow_local_chain()
            // represent non-retriable conditions:
            //
            // 1. ValidationDbError::FailedValidation
            //    - Block validation failed, or state/withdrawals root mismatch
            //    - These are deterministic failures; the block will never become valid on retry
            //
            // 2. ValidationDbError::Database
            //    - Database I/O errors, corruption, disk full, permission denied
            //    - These are persistent infrastructure issues requiring operator intervention
            //    - Retrying won't help; the underlying issue must be fixed
            //
            // 3. ValidationDbError::MissingData
            //    - Block data, witness, or validation result not found in database
            //    - This should NEVER occur in normal operation because block data and witnesses
            //      are written atomically during validation
            //    - If this occurs, it indicates either a bug in the validation pipeline or
            //      database corruption
            //
            // The chain sync process terminates immediately and returns the error to the caller.
            // Operators should investigate the root cause.

            error!("[Chain Sync] Failed to advance canonical chain: {}", e);
            return Err(e);
        }
    }
}

/// Remote chain tracker that maintains a lookahead of unvalidated blocks
///
/// Runs in an infinite loop, monitoring the gap between local canonical tip and remote
/// tip to maintain a sufficient buffer of unvalidated blocks for validation workers.
/// Infrastructure errors (RPC failures, network issues) are logged and contained.
///
/// # Arguments
/// * `client` - RPC client for fetching blocks from remote blockchain
/// * `validator_db` - Database interface for chain management
/// * `config` - Configuration for tracker behavior
///
/// # Returns
/// * Never returns under normal operation - runs indefinitely until externally terminated
async fn remote_chain_tracker(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
) -> Result<()> {
    info!(
        "[Tracker] Starting with {} block lookahead",
        config.tracker_lookahead_blocks
    );

    // Track error counts for each block
    let mut block_error_counts: HashMap<u64, usize> = HashMap::new();

    loop {
        if let Err(e) = async {
            // Calculate how far behind our local chain is from remote
            let local_tip = validator_db
                .get_local_tip()?
                .ok_or_else(|| anyhow!("Local chain is empty"))?;
            let remote_tip = validator_db.get_remote_tip()?.unwrap_or(local_tip);
            let gap = remote_tip.0.saturating_sub(local_tip.0);

            debug!(
                "[Tracker] local={}, remote={}, gap={}",
                local_tip.0, remote_tip.0, gap
            );

            // Detect and resolve chain reorgs
            match client
                .get_block(BlockId::Number(remote_tip.0.into()), false)
                .await
            {
                Ok(block) if block.header.hash != remote_tip.1 => {
                    warn!(
                        "[Tracker] Hash mismatch! Expected {}, got {}. Resolving chain divergence.",
                        remote_tip.1, block.header.hash
                    );
                    match find_divergence_point(&client, &validator_db, remote_tip.0).await {
                        Ok(rollback_to) => {
                            warn!("[Tracker] Rolling back to block {rollback_to}");
                            metrics::on_chain_reorg(remote_tip.0.saturating_sub(rollback_to));
                            validator_db.rollback_chain(rollback_to)?;
                            return Ok(());
                        }
                        Err(e) => {
                            error!("[Tracker] Failed to find divergence point: {e}");
                            return Err(e);
                        }
                    }
                }
                Err(e) => warn!(
                    "[Tracker] Network error validating tip {}: {}",
                    remote_tip.1, e
                ),
                _ => {}
            }

            // Stop if we already have sufficient lookahead
            if gap >= config.tracker_lookahead_blocks {
                return Ok(());
            }

            // Calculate how many blocks to fetch (bounded by latest available)
            let blocks_to_fetch = (config.tracker_lookahead_blocks - gap).min(
                client
                    .get_latest_block_number()
                    .await?
                    .saturating_sub(remote_tip.0),
            );

            if blocks_to_fetch == 0 {
                return Ok(());
            }

            debug!(
                "[Tracker] Fetching {} blocks starting from {}",
                blocks_to_fetch,
                remote_tip.0 + 1
            );

            // Fetch blocks in parallel
            let tasks = future::join_all(
                (remote_tip.0 + 1..remote_tip.0 + 1 + blocks_to_fetch).map(|block_number| {
                    let client = client.clone();
                    tokio::spawn(async move {
                        let block = client
                            .get_block(BlockId::Number(block_number.into()), false)
                            .await?;
                        let (salt_witness, mpt_witness) = client
                            .get_witness(block.header.number, block.header.hash)
                            .await?;
                        let block = client
                            .get_block(BlockId::Number(block_number.into()), true)
                            .await?;

                        Ok::<(Block<Transaction>, SaltWitness, MptWitness), eyre::Error>((
                            block,
                            salt_witness,
                            mpt_witness,
                        ))
                    })
                }),
            )
            .await
            .into_iter()
            .enumerate()
            // Stop on first error to maintain block sequence contiguity
            .take_while(|(i, result)| match result {
                Ok(Ok(_)) => {
                    block_error_counts.remove(&(remote_tip.0 + 1 + *i as u64));
                    true
                }
                Ok(Err(e)) => {
                    let block_number = remote_tip.0 + 1 + *i as u64;
                    let count = block_error_counts.entry(block_number).or_insert(0);
                    *count += 1;

                    if *count > 5 {
                        error!("[Tracker] DB or RPC error at block {block_number} (attempt {count}): {e}");
                    } else {
                        debug!("[Tracker] DB or RPC error at block {block_number} (attempt {count}): {e}");
                    }
                    false
                }
                Err(e) => {
                    error!(
                        "[Tracker] Task join error at block {}: {e}",
                        remote_tip.0 + 1 + *i as u64
                    );
                    false
                }
            })
            .filter_map(|(_, result)| result.ok().and_then(|r| r.ok()))
            .collect::<Vec<_>>();

            // Add successfully fetched headers to remote chain
            validator_db.add_validation_tasks(&tasks)?;
            validator_db.grow_remote_chain(tasks.iter().map(|(block, _, _)| &block.header))?;

            // Encountered an DB/RPC error, wait a bit before polling again
            if tasks.len() < blocks_to_fetch as usize {
                tokio::time::sleep(config.tracker_error_sleep).await;
            }

            Ok(())
        }
        .await
        {
            warn!("[Tracker] Iteration failed: {}", e);
        }

        tokio::time::sleep(config.tracker_poll_interval).await;
    }
}

/// Validation worker that continuously processes blocks from the task queue
///
/// Runs in an infinite loop, claiming validation tasks from ValidatorDB and processing
/// them via `validate_one()`. Infrastructure errors (database, RPC failures) are logged
/// and contained.
///
/// # Arguments
/// * `worker_id` - Worker identifier for logging
/// * `client` - RPC client for fetching data on demand
/// * `validator_db` - Database interface for task coordination
/// * `config` - Configuration for worker behavior
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
///
/// # Returns
/// * Never returns under normal operation - runs indefinitely until externally terminated
async fn validation_worker(
    worker_id: usize,
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
    chain_spec: Arc<ChainSpec>,
) -> Result<()> {
    info!("[Worker {}] Started", worker_id);
    loop {
        match validate_one(
            worker_id,
            &client,
            &validator_db,
            chain_spec.clone(),
            &config.block_limits_overrides,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                // No tasks available, wait before checking again
                tokio::time::sleep(config.worker_idle_sleep).await;
            }
            Err(e) => {
                // RPC/DB failures may get resolved over time, introduce a small
                // delay to prevent tight error loops
                error!("[Worker {worker_id}] Error during task processing: {e}");
                tokio::time::sleep(config.worker_error_sleep).await;
            }
        }
    }
}

/// Processes a single validation task
///
/// This function encapsulates the workflow for processing one validation task,
/// including task acquisition, contract code fetching, block validation, and
/// result storage. All errors are propagated to the caller for centralized error
/// handling.
///
/// # Arguments
/// * `worker_id` - Worker identifier for logging
/// * `client` - RPC client for fetching contract bytecode from remote nodes
/// * `validator_db` - Database for tasks and data
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
/// * `block_limits_overrides` - Block limits overrides for testing purposes only
///
/// # Returns
/// * `Ok(true)` - Task was processed (validation success/failure stored in DB)
/// * `Ok(false)` - No tasks available, no work performed
/// * `Err(eyre::Error)` - Infrastructure error (DB/RPC failures)
async fn validate_one(
    worker_id: usize,
    client: &RpcClient,
    validator_db: &ValidatorDB,
    chain_spec: Arc<ChainSpec>,
    block_limits_overrides: &BlockLimitsOverrides,
) -> Result<bool> {
    match validator_db.get_next_task()? {
        Some((block, witness, mpt_witness)) => {
            let block_number = block.header.number;
            let tx_count = block.transactions.len() as u64;
            let gas_used = block.header.gas_used;
            debug!("[Worker {}] Validating block {}", worker_id, block_number);

            let start = Instant::now();

            // Prepare the contract map to be used by validation
            let codehashes = extract_contract_codes(&witness);

            let (mut contracts, missing_contracts) = validator_db.get_contract_codes(codehashes)?;

            metrics::on_contract_cache_read(contracts.len() as u64, missing_contracts.len() as u64);

            // Fetch missing contract codes via RPC concurrently and update the local DB
            let codes =
                future::try_join_all(missing_contracts.iter().map(|&hash| client.get_code(hash)))
                    .await?;

            // Validate all fetched bytecodes match expected hashes
            let new_bytecodes: Vec<_> = missing_contracts
                .into_iter()
                .zip(codes.iter())
                .map(|(code_hash, bytes)| {
                    let bytecode = Bytecode::new_raw(bytes.clone());
                    let computed_hash = bytecode.hash_slow();

                    ensure!(
                        computed_hash == code_hash,
                        "RPC provider returned bytecode with unexpected codehash: expected {code_hash:?}, got {computed_hash:?}",
                    );

                    Ok((computed_hash, bytecode))
                })
                .collect::<Result<_>>()?;

            validator_db.add_contract_codes(new_bytecodes.iter().map(|(_, bytecode)| bytecode))?;
            contracts.extend(new_bytecodes);

            let pre_state_root = B256::from(witness.state_root()?);
            let post_state_root = block.header.state_root;
            let pre_withdrawals_root = mpt_witness.storage_root;
            let block_hash = block.header.hash;
            let post_withdrawals_root = block.header.withdrawals_root.ok_or(eyre::eyre!(
                "Withdrawals root not found in block {block_hash}"
            ))?;

            // Convert to core BlockLimitsOverrides for validate_block call
            let core_overrides = BlockLimitsOverrides {
                block_txs_data_limit: block_limits_overrides.block_txs_data_limit,
                block_kv_update_limit: block_limits_overrides.block_kv_update_limit,
                block_state_growth_limit: block_limits_overrides.block_state_growth_limit,
            };

            // Validate in a blocking thread so async tasks (reporter, tracker, etc.) stay responsive.
            let validation_result = task::spawn_blocking(move || {
                validate_block(
                    &chain_spec,
                    &block,
                    witness,
                    mpt_witness,
                    &contracts,
                    None,
                    &core_overrides,
                )
            })
            .await
            .map_err(|e| eyre::eyre!("Validation task panicked: {e}"))?;

            let (success, error_message) = match &validation_result {
                Ok(stats) => {
                    info!("[Worker {worker_id}] Successfully validated block {block_number}");
                    metrics::on_validation_success(
                        start.elapsed().as_secs_f64(),
                        stats.witness_verification_time,
                        stats.block_replay_time,
                        stats.salt_update_time,
                        tx_count,
                        gas_used,
                        stats.state_reads,
                        stats.state_writes,
                    );
                    (true, None)
                }
                Err(e) => {
                    error!("[Worker {worker_id}] Failed to validate block {block_number}: {e}");
                    (false, Some(e.to_string()))
                }
            };
            metrics::on_worker_task_done(worker_id, success);

            validator_db.complete_validation(ValidationResult {
                pre_state_root,
                post_state_root,
                pre_withdrawals_root,
                post_withdrawals_root,
                block_number,
                block_hash,
                success,
                error_message,
                completed_at: SystemTime::now(),
            })?;

            Ok(true)
        }
        None => Ok(false),
    }
}

/// Reports validated blocks to the upstream node
///
/// Periodically monitors the canonical chain and reports the complete validated range
/// (first to last block) to the upstream node via `mega_setValidatedBlocks` RPC.
/// Only reports when new blocks have been validated.
///
/// # Arguments
/// * `client` - RPC client for communicating with upstream node
/// * `validator_db` - Database interface for reading canonical chain
/// * `config` - Configuration containing sync_poll_interval
///
/// # Returns
/// * `Ok(())` - Never returns under normal operation
/// * `Err(eyre::Error)` - Terminates if validation gap detected (upstream's last validated
///   block < local chain start)
async fn validation_reporter(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
) -> Result<()> {
    info!("[Reporter] Starting validation reporter");
    let mut last_reported_block = (0u64, BlockHash::ZERO);

    loop {
        tokio::time::sleep(config.sync_poll_interval).await;

        // Get canonical chain bounds
        let (first_block, last_block) = match (
            validator_db.get_anchor_block(),
            validator_db.get_local_tip(),
        ) {
            (Ok(Some(first)), Ok(Some(last))) => (first, last),
            _ => continue,
        };

        // Skip if no new blocks
        if last_block == last_reported_block {
            continue;
        }

        // Report validated range to upstream
        match client
            .set_validated_blocks(
                (first_block.0, B256::from(first_block.1.0)),
                (last_block.0, B256::from(last_block.1.0)),
            )
            .await
        {
            Ok(response) if response.accepted => {
                debug!("[Reporter] Reported blocks successfully: {first_block:?} - {last_block:?}");
                last_reported_block = last_block;
            }
            Ok(response) => {
                // Check for validation gap
                if response.last_validated_block.0 < first_block.0 {
                    return Err(anyhow!(
                        "Validation gap detected: upstream at block {}, but local chain starts at {}. Cannot advance validation.",
                        response.last_validated_block.0,
                        first_block.0
                    ));
                }
                error!(
                    "[Reporter] Report rejected for blocks {first_block:?}-{last_block:?}, upstream at {:?}",
                    response.last_validated_block
                );
            }
            Err(e) => {
                error!("[Reporter] Failed to report blocks: {e}");
            }
        }
    }
}

/// Periodically prunes old block data to maintain constant storage overhead
///
/// Runs in an infinite loop, removing blocks older than `blocks_to_keep` from the
/// local chain tip at regular intervals. Pruning errors are logged but don't stop
/// the pruner from continuing.
///
/// # Arguments
/// * `validator_db` - Database interface for pruning operations
/// * `config` - Configuration for pruning behavior
///
/// # Returns
/// * Never returns under normal operation - runs indefinitely until externally terminated
async fn history_pruner(
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
) -> Result<()> {
    info!(
        "[Pruner] Starting with interval {:?}",
        config.pruner_interval
    );

    loop {
        if let Ok(Some((current_tip, _))) = validator_db.get_local_tip() {
            let prune_before = current_tip.saturating_sub(config.pruner_blocks_to_keep);
            match validator_db.prune_history(prune_before) {
                Ok(blocks_pruned) if blocks_pruned > 0 => {
                    debug!("[Pruner] Pruned {blocks_pruned} blocks before block {prune_before}");
                    metrics::on_blocks_pruned(blocks_pruned);
                }
                Err(e) => warn!("[Pruner] Failed to prune old block data: {e}"),
                _ => {}
            }
        }

        tokio::time::sleep(config.pruner_interval).await;
    }
}

/// Returns all contract addresses and their code hashes from the witness.
///
/// Filters witness data to find accounts with non-empty bytecode, which are
/// needed for contract code fetching during block execution.
fn extract_contract_codes(salt_witness: &SaltWitness) -> HashSet<B256> {
    salt_witness
        .kvs
        .values()
        .filter_map(|salt_val| salt_val.as_ref())
        .filter_map(
            |val| match (PlainKey::decode(val.key()), PlainValue::decode(val.value())) {
                (PlainKey::Account(_), PlainValue::Account(acc)) => {
                    acc.codehash.filter(|&codehash| codehash != KECCAK_EMPTY)
                }
                _ => None,
            },
        )
        .collect()
}

/// Finds where the local chain diverges from the remote RPC node using binary search
///
/// # Algorithm
/// Uses binary search to efficiently locate where the local canonical chain diverges
/// from the remote chain. The algorithm is guaranteed to terminate in O(log N) time
/// and return a block number between the earliest local block and `mismatch_block`.
///
/// If the remote RPC node reorgs again during the binary search, the returned block
/// number may not be the accurate divergence point; however, this is acceptable
/// because `remote_chain_tracker` will retry and detect the reorg again anyway.
///
/// # Parameters
/// * `client` - RPC client to fetch remote block hashes
/// * `validator_db` - Database to query local blocks
/// * `mismatch_block` - Block number where hash mismatch was detected
///
/// # Returns
/// * `Ok(block_number)` - Block number to rollback to (last common block)
/// * `Err(_)` - Network or database error during resolution
///
/// # Panics
/// Panics if a catastrophic reorg is detected (earliest local block hash differs
/// from remote chain), indicating the local chain has diverged beyond recovery.
async fn find_divergence_point(
    client: &RpcClient,
    validator_db: &ValidatorDB,
    mismatch_block: BlockNumber,
) -> Result<BlockNumber> {
    let earliest_local = validator_db
        .get_earliest_local_block()?
        .expect("Local chain cannot be empty");

    // Safety check: verify earliest block matches remote chain
    let earliest_remote = client
        .get_block(BlockId::Number(earliest_local.0.into()), false)
        .await?;
    if earliest_remote.header.hash != earliest_local.1 {
        panic!(
            "Catastrophic reorg: earliest local block {} hash mismatch (local: {:?}, remote: {:?})",
            earliest_local.0, earliest_local.1, earliest_remote.header.hash
        );
    }

    // Binary search for divergence point
    let (mut left, mut right, mut last_matching) =
        (earliest_local.0, mismatch_block, earliest_local.0);
    while left <= right {
        let mid = left + (right - left) / 2;
        let local_hash = validator_db.get_block_hash(mid)?.unwrap();
        let remote_hash = client
            .get_block(BlockId::Number(mid.into()), false)
            .await?
            .header
            .hash;
        if remote_hash == local_hash {
            last_matching = mid;
            left = mid + 1;
        } else {
            right = mid.saturating_sub(1);
        }
    }
    Ok(last_matching)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

    use alloy_primitives::{BlockHash, BlockNumber};
    use alloy_rpc_types_eth::Block;
    use eyre::Context;
    use jsonrpsee::{
        RpcModule,
        server::{ServerBuilder, ServerConfigBuilder},
    };
    use jsonrpsee_types::error::{
        CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
    };
    use op_alloy_rpc_types::Transaction;
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use validator_core::withdrawals::MptWitness;

    use super::*;

    /// Serialized witness data for a blockchain block.
    ///
    /// Contains all necessary information to verify the state transition
    /// and execution of a block without requiring the full state.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub(crate) struct WitnessFileContent {
        /// Hash of operation attributes for execution verification
        pub op_attributes_hash: B256,
        /// Parent block hash for chain continuity verification
        pub parent_hash: BlockHash,
        /// Cryptographic witness proving state transitions
        pub salt_witness: SaltWitness,
    }

    /// Maximum response body size for the RPC server.
    /// This is set to 100 MB to accommodate large block data and witness information.
    const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

    /// Helper function to create RPC errors with consistent format
    fn make_rpc_error(code: i32, msg: String) -> ErrorObject<'static> {
        ErrorObject::owned(code, msg, None::<()>)
    }

    /// Directory containing test block data files for mock RPC server.
    ///
    /// Files in this directory should be named with block numbers and hashes,
    /// e.g., "280.0xabc123.json" for block 280 with hash 0xabc123.
    const TEST_BLOCK_DIR: &str = "../../test_data/blocks";

    /// Path to the test contracts data file.
    ///
    /// This file contains contract bytecode data with one JSON array per line
    /// in the format `[hash, bytecode]` for use in integration tests.
    const CONTRACTS_FILE: &str = "../../test_data/contracts.txt";

    /// Directory containing test witness data files for integration testing.
    ///
    /// Files in this directory should have `.w` extension and contain serialized
    /// SaltWitness data.
    const TEST_WITNESS_DIR: &str = "../../test_data/stateless/witness";

    /// Path to the genesis configuration file for integration testing.
    const TEST_GENESIS_FILE: &str = "../../genesis/genesis.json";

    /// Context object containing pre-loaded test data for efficient RPC serving
    ///
    /// This struct holds all test data (blocks, witnesses, contracts) loaded once during
    /// setup to eliminate file system access during RPC calls.
    #[derive(Debug, Clone)]
    struct RpcModuleContext {
        /// Block data indexed by block hash (single storage)
        blocks_by_hash: HashMap<BlockHash, Block<Transaction>>,

        /// Ordered block number to hash mapping for number-based lookups
        block_hashes: BTreeMap<u64, BlockHash>,

        /// Salt Witness data indexed by block hash
        witness_data: HashMap<BlockHash, SaltWitness>,

        /// Mpt Witness data indexed by block hash
        mpt_witness_data: HashMap<BlockHash, MptWitness>,

        /// Contract bytecode indexed by code hash for eth_getCodeByHash RPC
        bytecodes: HashMap<B256, Bytecode>,

        /// Minimum block in the test data set (block number and hash)
        min_block: (u64, BlockHash),

        /// Maximum block in the test data set (block number and hash)
        max_block: (u64, BlockHash),
    }

    /// Parse block number and hash from string
    ///
    /// Parses strings in the format "{block_number}.{block_hash}" where
    /// the block hash can optionally have a "0x" prefix.
    ///
    /// # Arguments
    /// * `input` - String in format "280.0xabc123def456"
    ///
    /// # Returns
    /// * `Ok((BlockNumber, BlockHash))` - Successfully parsed block identifiers
    /// * `Err(eyre::Error)` - Invalid format or malformed hash
    fn parse_block_num_and_hash(input: &str) -> Result<(BlockNumber, BlockHash)> {
        let (block_str, hash_str) = input
            .split_once('.')
            .ok_or_else(|| anyhow!("Invalid format: {input}"))?;

        Ok((block_str.parse()?, parse_block_hash(hash_str)?))
    }

    /// Creates a ValidatorDB instance for integration testing with pre-populated test data.
    ///
    /// Sets up a temporary database and initializes it with the necessary test data for
    /// integration testing. The function performs the following setup steps:
    /// 1. Creates a temporary directory and ValidatorDB instance
    /// 2. Initializes the canonical chain tip using the minimum block from test data
    /// 3. Populates the CONTRACTS table with test contract bytecode from `CONTRACTS_FILE`
    ///
    /// The temporary directory will be cleaned up automatically after the test ends.
    ///
    /// # Returns
    ///
    /// `Arc<ValidatorDB>` - Database instance with initialized chain tip and contract cache
    ///
    /// # Errors
    ///
    /// Returns error if temporary directory creation, database initialization,
    /// test data loading, or contract population fails.
    fn setup_test_db(context: &RpcModuleContext) -> Result<Arc<ValidatorDB>> {
        // Create a temporary directory and then keep it alive by leaking it.
        // OS will clean it when test process ends.
        let temp_dir = tempfile::tempdir()
            .map_err(|e| anyhow!("Failed to create temporary directory: {e}"))?;
        let validator_db = ValidatorDB::new(temp_dir.path().join(VALIDATOR_DB_FILENAME))?;
        std::mem::forget(temp_dir);

        // Set the local chain tip to the first block in test data.
        let (block_num, block_hash) = context.min_block;
        let block = context
            .blocks_by_hash
            .get(&block_hash)
            .ok_or_else(|| anyhow!("Local tip {block_hash} not found"))?;
        let state_root = block.header.state_root;
        let withdrawals_root = block
            .header
            .withdrawals_root
            .ok_or_else(|| anyhow!("Block {} is missing withdrawals_root", block_hash))?;
        validator_db.reset_anchor_block(block_num, block_hash, state_root, withdrawals_root)?;

        Ok(Arc::new(validator_db))
    }

    /// Set up mock RPC server with pre-loaded context and return the handle and URL.
    async fn setup_mock_rpc_server(
        context: RpcModuleContext,
    ) -> (jsonrpsee::server::ServerHandle, String) {
        let mut module = RpcModule::new(context);

        module
            .register_method("eth_getBlockByNumber", |params, context, _| {
                let (hex_number, full_block): (String, bool) = params.parse().unwrap();

                let block_number = u64::from_str_radix(&hex_number[2..], 16).unwrap_or(0);

                // Look up block by number
                let block = context
                    .block_hashes
                    .get(&block_number)
                    .and_then(|hash| context.blocks_by_hash.get(hash))
                    .ok_or_else(|| {
                        make_rpc_error(
                            CALL_EXECUTION_FAILED_CODE,
                            format!("Block {block_number} not found"),
                        )
                    })?;

                let result_block = if full_block {
                    block.clone()
                } else {
                    Block {
                        transactions: block.transactions.clone().into_hashes(),
                        ..block.clone()
                    }
                };
                Ok::<_, ErrorObject<'static>>(result_block)
            })
            .unwrap();

        module
            .register_method("eth_blockNumber", |_params, context, _| {
                // Return the largest block number available in test data
                Ok::<String, ErrorObjectOwned>(format!("0x{:x}", context.max_block.0))
            })
            .unwrap();

        module
            .register_method("eth_getCodeByHash", |params, context, _| {
                let (hash,): (B256,) = params.parse().map_err(|e| {
                    make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}"))
                })?;

                let code = context.bytecodes.get(&hash).cloned().unwrap_or_default();

                Ok::<_, ErrorObject<'static>>(code.original_bytes())
            })
            .unwrap();

        module
            .register_method("mega_getBlockWitness", |params, context, _| {
                let (_number_str, hash_str): (String, String) = params.parse().unwrap();

                // Parse hash string to BlockHash
                let block_hash = parse_block_hash(&hash_str).map_err(|e| {
                    make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid block hash: {e}"))
                })?;

                // Look up witness data by block hash
                let salt_witness =
                    context
                        .witness_data
                        .get(&block_hash)
                        .cloned()
                        .ok_or_else(|| {
                            make_rpc_error(
                                CALL_EXECUTION_FAILED_CODE,
                                format!("Witness for block {hash_str} not found"),
                            )
                        })?;

                let mpt_witness = context
                    .mpt_witness_data
                    .get(&block_hash)
                    .cloned()
                    .ok_or_else(|| {
                        make_rpc_error(
                            CALL_EXECUTION_FAILED_CODE,
                            format!("Witness for block {hash_str} not found"),
                        )
                    })?;

                Ok::<_, ErrorObject<'static>>((salt_witness, mpt_witness))
            })
            .unwrap();

        module
            .register_method("mega_setValidatedBlocks", |params, _context, _| {
                let (_first_block, last_block): ((u64, String), (u64, String)) =
                    params.parse().unwrap();
                let last_hash = parse_block_hash(&last_block.1).unwrap();

                // Return response with accepted=true and the last validated block
                let response = serde_json::json!({
                    "accepted": true,
                    "lastValidatedBlock": [last_block.0, last_hash]
                });
                Ok::<serde_json::Value, ErrorObjectOwned>(response)
            })
            .unwrap();

        let cfg = ServerConfigBuilder::default()
            .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
            .build();
        let server = ServerBuilder::default()
            .set_config(cfg)
            .build("0.0.0.0:0")
            .await
            .unwrap();

        let url = format!("http://{}", server.local_addr().unwrap());
        (server.start(module), url)
    }

    /// Loads and deserializes JSON data from a file.
    ///
    /// This generic function reads a JSON file and deserializes it into any type
    /// that implements `serde::de::DeserializeOwned`.
    ///
    /// # Arguments
    ///
    /// * `file_path`: The path to the JSON file to load.
    ///
    /// # Returns
    ///
    /// Returns `Ok(T)` containing the deserialized data if successful.
    /// Returns an `Err` if any step (file opening, reading, or deserialization) fails.
    fn load_json<T: DeserializeOwned>(file_path: impl AsRef<Path>) -> Result<T> {
        let path = file_path.as_ref();
        let contents = std::fs::read(path)
            .with_context(|| format!("Failed to read file {path}", path = path.display()))?;
        serde_json::from_slice(&contents)
            .with_context(|| format!("Failed to parse JSON from {path}", path = path.display()))
    }

    /// Loads contract bytecode from a test data file.
    ///
    /// Reads a file where each line contains a JSON array with contract hash and bytecode:
    /// `[hash, bytecode]`. Empty lines are ignored.
    ///
    /// # Arguments
    /// * `path` - Path to the contracts file
    ///
    /// # Returns
    /// A HashMap mapping contract hashes (B256) to bytecode (Bytecode)
    fn load_contracts(path: impl AsRef<Path>) -> HashMap<B256, Bytecode> {
        let file = File::open(path).expect("Failed to open contracts file");
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(&line).expect("Failed to parse contract"))
            .collect()
    }

    /// Creates RPC module context by pre-loading all test data
    ///
    /// This function scans the test directories and loads all block data, witness data,
    /// and contracts into memory for efficient RPC serving. It eliminates file system
    /// access during RPC calls by pre-loading everything into HashMap/BTreeMap structures.
    ///
    /// # Returns
    /// * `Ok(RpcModuleContext)` - Context with all test data loaded
    /// * `Err(eyre::Error)` - If directories cannot be read or data is malformed
    fn create_rpc_module_context() -> Result<RpcModuleContext> {
        let mut blocks_by_hash = HashMap::new();
        let mut block_hashes = BTreeMap::new();
        let mut witness_data = HashMap::new();
        let mut mpt_witness_data = HashMap::new();

        // Load block data from TEST_BLOCK_DIR
        debug!("Loading block data from {}", TEST_BLOCK_DIR);
        let test_block_dir = PathBuf::from(TEST_BLOCK_DIR);
        let block_entries = std::fs::read_dir(&test_block_dir)
            .map_err(|e| anyhow!("Failed to read test block directory {TEST_BLOCK_DIR}: {e}"))?;

        let mut block_numbers = Vec::new();

        for entry in block_entries {
            let file = entry.map_err(|e| anyhow!("Failed to read directory entry: {e}"))?;
            let file_name = file.file_name();
            let file_str = file_name.to_string_lossy();

            // Skip non-JSON files
            if !file_str.ends_with(".json") {
                continue;
            }

            // Parse filename in format "{block_number}.{block_hash}.json"
            if let Some(dot_pos) = file_str.find('.') {
                let block_number_str = &file_str[..dot_pos];
                if let Ok(block_number) = block_number_str.parse::<u64>() {
                    // Load the block data
                    let block: Block<Transaction> = load_json(file.path())
                        .map_err(|e| anyhow!("Failed to load block file {file_str}: {e}"))?;

                    let block_hash = BlockHash::from(block.header.hash);

                    // Store block by hash and create number->hash mapping
                    blocks_by_hash.insert(block_hash, block);
                    block_hashes.insert(block_number, block_hash);
                    block_numbers.push(block_number);
                }
            }
        }

        if block_numbers.is_empty() {
            return Err(anyhow!("No valid block files found in {TEST_BLOCK_DIR}"));
        }

        block_numbers.sort_unstable();
        let min_block_num = *block_numbers.first().unwrap();
        let max_block_num = *block_numbers.last().unwrap();

        // Get the hashes for the minimum and maximum block numbers
        let min_block_hash = *block_hashes.get(&min_block_num).unwrap();
        let max_block_hash = *block_hashes.get(&max_block_num).unwrap();
        let min_block = (min_block_num, min_block_hash);
        let max_block = (max_block_num, max_block_hash);

        debug!(
            "Loaded {} blocks (range: {} - {})",
            block_numbers.len(),
            min_block.0,
            max_block.0
        );

        // Load witness data from TEST_WITNESS_DIR
        debug!("Loading witness data from {}", TEST_WITNESS_DIR);
        let test_witness_dir = PathBuf::from(TEST_WITNESS_DIR);
        if test_witness_dir.exists() {
            let witness_entries = std::fs::read_dir(&test_witness_dir)
                .map_err(|e| anyhow!("Failed to read test witness directory: {e}"))?;

            for entry in witness_entries {
                let entry = entry?;
                let file_path = entry.path();
                let Some(ext) = file_path.extension().and_then(|s| s.to_str()) else {
                    continue;
                };

                let block_num_and_hash = file_path.file_stem().unwrap().to_str().unwrap();
                let (_, block_hash) = parse_block_num_and_hash(block_num_and_hash)?;
                let file_data = std::fs::read(&file_path)?;

                match ext {
                    "salt" => {
                        let salt_witness: WitnessFileContent = bincode::serde::decode_from_slice(&file_data, bincode::config::legacy())
                            .map_err(|e| anyhow!("Failed to deserialize SaltWitness from file_data {block_num_and_hash}: {e}"))?.0;
                        witness_data.insert(block_hash, salt_witness.salt_witness);
                    }
                    "mpt" => {
                        let (mpt_witness, _): (MptWitness, usize) = bincode::serde::decode_from_slice(&file_data, bincode::config::legacy())
                            .map_err(|e| anyhow!("Failed to deserialize MptWitness from file_data {block_num_and_hash}: {e}"))?;
                        mpt_witness_data.insert(block_hash, mpt_witness);
                    }
                    _ => {}
                }
            }
            debug!("Loaded {} salt witness files", witness_data.len());
            debug!("Loaded {} mpt witness files", mpt_witness_data.len());
        } else {
            debug!(
                "Witness directory {} does not exist, skipping witness data",
                TEST_WITNESS_DIR
            );
        }

        // Load contract data and build address-to-bytecode mapping from witness data
        let bytecodes = load_contracts(CONTRACTS_FILE);
        debug!("Loaded {} contracts from {CONTRACTS_FILE}", bytecodes.len());

        Ok(RpcModuleContext {
            blocks_by_hash,
            block_hashes,
            witness_data,
            mpt_witness_data,
            bytecodes,
            min_block,
            max_block,
        })
    }

    #[tokio::test]
    async fn integration_test() {
        // Initialize logging for tests with debug level
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::new("warn").add_directive("stateless_validator=debug".parse().unwrap()),
            )
            .try_init();

        // Create RPC module context with pre-loaded test data
        debug!("=== Creating RPC Module Context ===");
        let context = create_rpc_module_context().unwrap();
        debug!(
            "Context created with {} blocks, {} witnesses, {} contracts",
            context.blocks_by_hash.len(),
            context.witness_data.len(),
            context.bytecodes.len()
        );
        debug!(
            "Block range: {} - {}",
            context.min_block.0, context.max_block.0
        );

        let sync_target = Some(context.max_block.0);
        let validator_db = setup_test_db(&context).unwrap();
        let (handle, url) = setup_mock_rpc_server(context).await;
        let client = Arc::new(RpcClient::new(&url, &url).unwrap());

        // Load chain spec using helper function
        let chain_spec =
            Arc::new(load_or_create_chain_spec(&validator_db, Some(TEST_GENESIS_FILE)).unwrap());

        // Create test configuration with faster intervals for testing
        let config = Arc::new(ChainSyncConfig {
            concurrent_workers: 1,
            sync_target,
            ..ChainSyncConfig::default()
        });

        chain_sync(client.clone(), validator_db, config, chain_spec)
            .await
            .unwrap();

        handle.stop().unwrap();
        info!("Mock RPC server has been shut down.");
    }
}
