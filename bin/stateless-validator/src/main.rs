use std::{
    collections::HashSet,
    future::Future,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_genesis::Genesis;
use alloy_primitives::{B256, BlockHash, hex};
use alloy_rpc_types_eth::BlockId;
use clap::Parser;
use eyre::{Result, anyhow, ensure};
use futures::future;
use revm::{primitives::KECCAK_EMPTY, state::Bytecode};
use salt::SaltWitness;
use stateless_common::logging::{LogArgs, migrate_legacy_env_vars};
use stateless_core::{
    ChainStore, ChainSyncConfig, ContractCache, ContractStore, ReorgEvent, RpcClient,
    RpcClientConfig, ValidatorDB,
    chain_spec::ChainSpec,
    data_types::{PlainKey, PlainValue},
    db::{BlockMeta, ValidatedBlock, ValidationFailure, ValidationTask},
    executor::validate_block,
};
use tokio::{signal, task, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

mod metrics;

/// Handles to all spawned background tasks, awaited during shutdown.
type BackgroundTasks = Vec<JoinHandle<Result<()>>>;

enum RunLoopAction {
    Restart(ReorgEvent),
    Shutdown,
}

/// Database filename for the validator.
const VALIDATOR_DB_FILENAME: &str = "validator.redb";

/// Convert hex string to BlockHash
///
/// Accepts hex strings with or without "0x" prefix. Must be exactly 32 bytes when decoded.
fn parse_block_hash(hex_str: &str) -> Result<BlockHash> {
    let hash_bytes = hex::decode(hex_str)?;
    ensure!(hash_bytes.len() == 32, "Block hash must be 32 bytes, got {}", hash_bytes.len());
    Ok(BlockHash::from_slice(&hash_bytes))
}

/// Loads or creates a ChainSpec from the database or a genesis file.
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

    /// Endpoint for reporting validated blocks via mega_setValidatedBlocks RPC.
    /// If not provided, validation reporting is disabled.
    #[clap(long, env = "STATELESS_VALIDATOR_REPORT_VALIDATION_ENDPOINT")]
    report_validation_endpoint: Option<String>,

    /// Enable Prometheus metrics endpoint.
    /// When enabled, metrics are exposed at http://0.0.0.0:<metrics-port>/metrics
    #[clap(long, env = "STATELESS_VALIDATOR_METRICS_ENABLED")]
    metrics_enabled: bool,

    /// Port for Prometheus metrics HTTP endpoint.
    #[clap(long, env = "STATELESS_VALIDATOR_METRICS_PORT", default_value_t = metrics::DEFAULT_METRICS_PORT)]
    metrics_port: u16,

    /// Logging configuration.
    #[command(flatten)]
    log: LogArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    migrate_legacy_env_vars();
    let args = CommandLineArgs::parse();
    let _log_guard = args.log.init_tracing()?;
    let start = Instant::now();

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

    let rpc_config = RpcClientConfig::validator().with_metrics(Arc::new(metrics::ValidatorMetrics));
    let client = Arc::new(RpcClient::new_with_config(
        &args.rpc_endpoint,
        &args.witness_endpoint,
        rpc_config,
        None, // No Cloudflare fallback for validator
        args.report_validation_endpoint.as_deref(),
    )?);
    let validator_db = Arc::new(ValidatorDB::new(work_dir.join(VALIDATOR_DB_FILENAME))?);
    let contract_cache =
        Arc::new(ContractCache::new(Arc::clone(&validator_db) as Arc<dyn ContractStore>));

    // Load chain spec from file (first run) or database (subsequent runs)
    let chain_spec =
        Arc::new(load_or_create_chain_spec(&validator_db, args.genesis_file.as_deref())?);
    info!("[Main] Chain spec loaded successfully");

    // Handle optional start block initialization
    if let Some(start_block_str) = &args.start_block {
        info!("[Main] Initializing from start block: {}", start_block_str);

        let block_hash = parse_block_hash(start_block_str)?;
        let header = loop {
            match client.get_header(BlockId::Hash(block_hash.into()), true).await {
                Ok(header) => break header,
                Err(e) => {
                    warn!(block_hash = %block_hash, error = %e, "[Main] Failed to fetch block, retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };

        let anchor = BlockMeta {
            block_number: header.number,
            block_hash: header.hash,
            post_state_root: header.state_root,
            post_withdrawals_root: header
                .withdrawals_root
                .ok_or_else(|| anyhow!("Block {} is missing withdrawals_root", block_hash))?,
        };
        validator_db.reset_to_anchor(&anchor)?;

        info!(
            "[Main] Successfully initialized from block {} (number: {})",
            header.hash, header.number
        );
    } else {
        // If no start block was provided, ensure we have an existing canonical tip
        let tip = validator_db.get_canonical_tip()?.ok_or_else(|| {
            anyhow!("No trusted starting point found. Specify a trusted block with --start-block <blockhash>")
        })?;
        info!(
            block_number = tip.block_number,
            block_hash = %tip.block_hash,
            "[Main] Continuing from existing canonical chain"
        );
    }

    // Create chain sync configuration
    let config = Arc::new(ChainSyncConfig {
        concurrent_workers: num_cpus::get(),
        report_validation_results: args.report_validation_endpoint.is_some(),
        metrics_enabled: args.metrics_enabled,
        metrics_port: args.metrics_port,
        ..ChainSyncConfig::default()
    });
    info!(concurrent_workers = config.concurrent_workers, "[Main] Starting pipeline");
    info!(
        "[Main] Validation result reporting: {}",
        if config.report_validation_results { "enabled" } else { "disabled" }
    );

    let result =
        run_with_reorg_restart(client, validator_db, contract_cache, config, chain_spec).await;

    info!(elapsed = ?start.elapsed(), "[Main] Shutdown complete");
    result
}

/// Runs the validation pipeline in a loop, restarting on reorg detection.
///
/// Returns when the pipeline completes normally, encounters a fatal error,
/// or receives a shutdown signal (SIGINT/SIGTERM).
async fn run_with_reorg_restart(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    contract_cache: Arc<ContractCache>,
    config: Arc<ChainSyncConfig>,
    chain_spec: Arc<ChainSpec>,
) -> Result<()> {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow!("Failed to register SIGTERM handler: {e}"))?;

    loop {
        let shutdown = CancellationToken::new();
        let (validator_logic, bg_tasks) = chain_sync(
            client.clone(),
            Arc::clone(&validator_db),
            Arc::clone(&contract_cache),
            Arc::clone(&config),
            Arc::clone(&chain_spec),
            shutdown.clone(),
        )?;

        let reorg_monitor = stateless_core::validator_reorg_monitor(
            Arc::clone(&client),
            Arc::clone(&validator_db) as Arc<dyn ChainStore>,
            config.tracker_poll_interval,
            shutdown.clone(),
        );

        let action = tokio::select! {
            res = validator_logic => {
                if let Err(ref e) = res {
                    error!(error = %e, "[Main] Validator exited with error");
                }
                shutdown.cancel();
                await_bg_tasks(bg_tasks).await;
                return res;
            }
            res = reorg_monitor => {
                match res {
                    Ok(reorg) => RunLoopAction::Restart(reorg),
                    Err(e) => {
                        error!(error = %e, "[Main] Reorg monitor exited with error");
                        shutdown.cancel();
                        await_bg_tasks(bg_tasks).await;
                        return Err(e);
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("[Main] SIGINT received, shutting down.");
                RunLoopAction::Shutdown
            }
            _ = sigterm.recv() => {
                info!("[Main] SIGTERM received, shutting down.");
                RunLoopAction::Shutdown
            }
        };

        shutdown.cancel();
        await_bg_tasks(bg_tasks).await;

        match action {
            RunLoopAction::Restart(reorg) => {
                warn!(
                    rollback_to = reorg.rollback_to,
                    depth = reorg.depth,
                    "[Main] Reorg detected, restarting pipeline"
                );
                metrics::on_reorg(reorg.depth);
            }
            RunLoopAction::Shutdown => return Ok(()),
        }

        info!("[Main] Restarting pipeline...");
    }
}

/// Waits for background tasks to finish with a timeout.
async fn await_bg_tasks(bg_tasks: BackgroundTasks) {
    let timeout = Duration::from_secs(3);
    match tokio::time::timeout(timeout, future::join_all(bg_tasks)).await {
        Ok(results) => {
            for (i, result) in results.into_iter().enumerate() {
                match result {
                    Ok(Err(e)) => warn!(task_idx = i, error = %e, "[Main] Background task error"),
                    Err(e) if e.is_cancelled() => {}
                    Err(e) => error!(task_idx = i, error = %e, "[Main] Background task panic"),
                    Ok(Ok(())) => {}
                }
            }
        }
        Err(_) => warn!(timeout = ?timeout, "[Main] Background tasks did not finish in time"),
    }
}

// ---------------------------------------------------------------------------
// Pipeline orchestration
// ---------------------------------------------------------------------------

/// Sets up the streaming validation pipeline:
/// 1. Fetcher task: fetches blocks from RPC, sends to channel
/// 2. N worker tasks: validate blocks, send results to channel
/// 3. Advancer task (main loop): collects results in order, advances canonical chain
/// 4. Optional reporter task: reports validated blocks upstream
/// 5. History pruner: periodically removes old CANONICAL_CHAIN entries
fn chain_sync(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    contract_cache: Arc<ContractCache>,
    config: Arc<ChainSyncConfig>,
    chain_spec: Arc<ChainSpec>,
    shutdown: CancellationToken,
) -> Result<(impl Future<Output = Result<()>>, BackgroundTasks)> {
    let initial_tip = validator_db
        .get_canonical_tip()?
        .ok_or_else(|| anyhow!("No canonical tip found — run with --start-block first"))?;

    let start_block = initial_tip.block_number + 1;
    info!(
        start_block,
        workers = config.concurrent_workers,
        "[Pipeline] Starting validation pipeline"
    );

    // Create kanal channels
    let (fetch_tx, fetch_rx) = kanal::bounded(config.fetch_channel_capacity);
    let (result_tx, result_rx) = kanal::bounded(config.result_channel_capacity);

    let mut bg_tasks: BackgroundTasks = Vec::new();

    // Task 1: Block fetcher
    bg_tasks.push(task::spawn({
        let client = Arc::clone(&client);
        let config = Arc::clone(&config);
        let shutdown = shutdown.clone();
        async move {
            stateless_core::block_fetcher(
                client,
                fetch_tx,
                start_block,
                config,
                shutdown,
                |block, salt_witness, mpt_witness| ValidationTask {
                    block,
                    salt_witness,
                    mpt_witness,
                },
                Some(metrics::set_remote_chain_height),
            )
            .await
        }
    }));

    // Task 2: N validation workers
    for worker_id in 0..config.concurrent_workers {
        let fetch_rx = fetch_rx.clone();
        let result_tx = result_tx.clone();
        let client = Arc::clone(&client);
        let contract_cache = Arc::clone(&contract_cache);
        let chain_spec = Arc::clone(&chain_spec);
        let shutdown = shutdown.clone();

        bg_tasks.push(task::spawn(validation_worker(
            worker_id,
            client,
            contract_cache,
            chain_spec,
            fetch_rx,
            result_tx,
            shutdown,
        )));
    }
    // Drop the original sender/receiver so channel closes when all workers finish
    drop(fetch_rx);
    drop(result_tx);

    // Task 3: Optional validation reporter
    if config.report_validation_results {
        info!("[Pipeline] Starting validation reporter...");
        bg_tasks.push(task::spawn(validation_reporter(
            Arc::clone(&client),
            Arc::clone(&validator_db),
            Arc::clone(&config),
            shutdown.clone(),
        )));
    } else {
        info!("[Pipeline] Validation reporter disabled");
    }

    // Main loop = chain advancer
    let main_loop = stateless_core::chain_advancer(
        result_rx,
        validator_db as Arc<dyn ChainStore>,
        initial_tip,
        shutdown,
        Some(metrics::set_chain_height),
    );

    Ok((main_loop, bg_tasks))
}

// ---------------------------------------------------------------------------
// Validation worker
// ---------------------------------------------------------------------------

/// Validation worker that receives blocks from the fetch channel, validates them,
/// and sends results to the advancer channel.
async fn validation_worker(
    worker_id: usize,
    client: Arc<RpcClient>,
    contract_cache: Arc<ContractCache>,
    chain_spec: Arc<ChainSpec>,
    fetch_rx: kanal::Receiver<stateless_core::ValidationTask>,
    result_tx: kanal::Sender<std::result::Result<ValidatedBlock, ValidationFailure>>,
    shutdown: CancellationToken,
) -> Result<()> {
    info!(worker_id, "[Worker] Started");
    let fetch_rx = fetch_rx.to_async();
    let result_tx = result_tx.to_async();

    loop {
        // Receive next task from shared fetch channel
        let task = tokio::select! {
            r = fetch_rx.recv() => match r {
                Ok(task) => task,
                Err(_) => {
                    info!(worker_id, "[Worker] Fetch channel closed, stopping");
                    break;
                }
            },
            _ = shutdown.cancelled() => {
                info!(worker_id, "[Worker] Shutting down gracefully");
                break;
            }
        };

        let block_number = task.block.header.number;
        let block_hash = task.block.header.hash;
        let tx_count = task.block.transactions.len() as u64;
        let gas_used = task.block.header.gas_used;
        debug!(worker_id, block_number, "[Worker] Validating block");
        let start = Instant::now();

        // Resolve contract codes
        let codehashes = extract_contract_codes(&task.salt_witness);
        let (mut contracts, missing_contracts) =
            contract_cache.get(&codehashes.iter().copied().collect::<Vec<_>>())?;

        metrics::on_contract_cache_read(contracts.len() as u64, missing_contracts.len() as u64);

        if !missing_contracts.is_empty() {
            let codes = future::try_join_all(missing_contracts.iter().map(|&hash| {
                let client = Arc::clone(&client);
                async move { client.get_code(hash).await }
            }))
            .await?;

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

            contract_cache.insert(&new_bytecodes)?;
            contracts.extend(new_bytecodes);
        }

        // Extract state roots before moving data into spawn_blocking
        let pre_state_root = B256::from(task.salt_witness.state_root()?);
        let post_state_root = task.block.header.state_root;
        let pre_withdrawals_root = task.mpt_witness.storage_root;
        let post_withdrawals_root = task
            .block
            .header
            .withdrawals_root
            .ok_or(eyre::eyre!("Withdrawals root not found in block {block_hash}"))?;

        // Validate in a blocking thread
        let chain_spec_clone = Arc::clone(&chain_spec);
        let validation_result = task::spawn_blocking(move || {
            validate_block(
                &chain_spec_clone,
                &task.block,
                task.salt_witness,
                task.mpt_witness,
                &contracts,
                None,
            )
        })
        .await
        .map_err(|e| eyre::eyre!("Validation task panicked: {e}"))?;

        let result = match &validation_result {
            Ok(stats) => {
                info!(worker_id, block_number, "[Worker] Successfully validated block");
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
                metrics::on_worker_task_done(worker_id, true);
                Ok(ValidatedBlock {
                    block_number,
                    block_hash,
                    post_state_root,
                    post_withdrawals_root,
                    pre_state_root,
                    pre_withdrawals_root,
                })
            }
            Err(e) => {
                error!(worker_id, block_number, error = %e, "[Worker] Failed to validate block");
                metrics::on_worker_task_done(worker_id, false);
                Err(ValidationFailure { block_number, block_hash, error: e.to_string() })
            }
        };

        if result_tx.send(result).await.is_err() {
            info!(worker_id, "[Worker] Result channel closed, stopping");
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation reporter (reads from ValidatorDB)
// ---------------------------------------------------------------------------

/// Reports validated blocks to the dedicated report endpoint.
///
/// Periodically reads the canonical tip from ValidatorDB and reports the
/// validated range to the upstream node.
async fn validation_reporter(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
    shutdown: CancellationToken,
) -> Result<()> {
    info!("[Reporter] Starting validation reporter");
    let mut last_reported_block = 0u64;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(config.sync_poll_interval) => {}
            _ = shutdown.cancelled() => {
                info!("[Reporter] Shutting down gracefully");
                return Ok(());
            }
        }

        // Get anchor and canonical tip
        let (anchor, tip) =
            match (validator_db.get_anchor_block(), validator_db.get_canonical_tip()) {
                (Ok(Some(a)), Ok(Some(t))) => (a, t),
                _ => continue,
            };

        // Skip if no new blocks
        if tip.block_number == last_reported_block {
            continue;
        }

        // Report validated range to upstream
        let result = client
            .set_validated_blocks(
                (anchor.block_number, B256::from(anchor.block_hash.0)),
                (tip.block_number, B256::from(tip.block_hash.0)),
            )
            .await;

        match result {
            Ok(response) if response.accepted => {
                debug!(
                    "[Reporter] Reported blocks: anchor={} tip={}",
                    anchor.block_number, tip.block_number
                );
                last_reported_block = tip.block_number;
            }
            Ok(response) => {
                if response.last_validated_block.0 < anchor.block_number {
                    return Err(anyhow!(
                        "Validation gap detected: upstream at block {}, but local chain starts at {}",
                        response.last_validated_block.0,
                        anchor.block_number
                    ));
                }
                error!(
                    "[Reporter] Report rejected, upstream at {:?}",
                    response.last_validated_block
                );
            }
            Err(e) => {
                error!(error = %e, "[Reporter] Failed to report blocks");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns all contract code hashes from the witness.
///
/// Filters witness data to find accounts with non-empty bytecode, which are
/// needed for contract code fetching during block execution.
fn extract_contract_codes(salt_witness: &SaltWitness) -> HashSet<B256> {
    salt_witness
        .kvs
        .values()
        .filter_map(|salt_val| salt_val.as_ref())
        .filter_map(|val| match (PlainKey::decode(val.key()), PlainValue::decode(val.value())) {
            (PlainKey::Account(_), PlainValue::Account(acc)) => {
                acc.codehash.filter(|&codehash| codehash != KECCAK_EMPTY)
            }
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

    use alloy_primitives::{BlockHash, BlockNumber};
    use alloy_rpc_types_eth::Block;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
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
    use stateless_core::{rpc_client::WitnessRequestKeys, withdrawals::MptWitness};
    use tracing_subscriber::EnvFilter;

    use super::*;

    const SYNTHETIC_DATA_DIR: &str = "../../test_data/synthetic";
    const MAINNET_DATA_DIR: &str = "../../test_data/mainnet";
    const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

    /// Witness file envelope containing the SALT witness and metadata.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub(crate) struct WitnessFileContent {
        /// Hash of operation attributes for execution verification
        pub op_attributes_hash: B256,
        /// Parent block hash for chain continuity verification
        pub parent_hash: BlockHash,
        /// Cryptographic witness proving state transitions
        pub salt_witness: SaltWitness,
    }

    /// Pre-loaded test data: blocks, witnesses, and contract bytecodes.
    #[derive(Debug, Clone)]
    struct TestData {
        blocks_by_hash: HashMap<BlockHash, Block<Transaction>>,
        block_hashes: BTreeMap<u64, BlockHash>,
        salt_witnesses: HashMap<BlockHash, SaltWitness>,
        mpt_witnesses: HashMap<BlockHash, MptWitness>,
        bytecodes: HashMap<B256, Bytecode>,
    }

    impl TestData {
        /// Load all test data (blocks, witnesses, contracts) from `data_dir`.
        fn load(data_dir: &str) -> Self {
            let block_dir = format!("{data_dir}/blocks");
            let witness_dir = format!("{data_dir}/stateless/witness");
            let contracts_file = format!("{data_dir}/contracts.txt");

            // Load blocks
            debug!("Loading block data from {block_dir}");
            let mut blocks_by_hash = HashMap::new();
            let mut block_hashes = BTreeMap::new();

            for entry in std::fs::read_dir(&block_dir)
                .unwrap_or_else(|e| panic!("Failed to read block directory {block_dir}: {e}"))
            {
                let file = entry.unwrap();
                let file_name = file.file_name();
                let file_str = file_name.to_string_lossy();
                if !file_str.ends_with(".json") {
                    continue;
                }
                if let Some(dot_pos) = file_str.find('.') &&
                    let Ok(block_number) = file_str[..dot_pos].parse::<u64>()
                {
                    let block: Block<Transaction> = load_json(file.path()).unwrap();
                    let block_hash = BlockHash::from(block.header.hash);
                    blocks_by_hash.insert(block_hash, block);
                    block_hashes.insert(block_number, block_hash);
                }
            }

            let (&min, &max) = (
                block_hashes.keys().next().expect("No blocks found"),
                block_hashes.keys().next_back().unwrap(),
            );
            debug!("Loaded {} blocks (range: {} - {})", blocks_by_hash.len(), min, max);

            // Load witnesses
            debug!("Loading witness data from {witness_dir}");
            let mut salt_witnesses = HashMap::new();
            let mut mpt_witnesses = HashMap::new();

            for entry in std::fs::read_dir(&witness_dir)
                .unwrap_or_else(|e| panic!("Failed to read witness directory {witness_dir}: {e}"))
            {
                let entry = entry.unwrap();
                let file_path = entry.path();
                let Some(ext) = file_path.extension().and_then(|s| s.to_str()) else {
                    continue;
                };

                let stem = file_path.file_stem().unwrap().to_str().unwrap();
                let (_, block_hash) = parse_block_num_and_hash(stem).unwrap();
                let file_data = std::fs::read(&file_path).unwrap();

                match ext {
                    "salt" => {
                        let (content, _): (WitnessFileContent, usize) =
                            bincode::serde::decode_from_slice(
                                &file_data,
                                bincode::config::legacy(),
                            )
                            .unwrap_or_else(|e| {
                                panic!("Failed to deserialize SaltWitness {stem}: {e}")
                            });
                        salt_witnesses.insert(block_hash, content.salt_witness);
                    }
                    "mpt" => {
                        let (mpt_witness, _): (MptWitness, usize) =
                            bincode::serde::decode_from_slice(
                                &file_data,
                                bincode::config::legacy(),
                            )
                            .unwrap_or_else(|e| {
                                panic!("Failed to deserialize MptWitness {stem}: {e}")
                            });
                        mpt_witnesses.insert(block_hash, mpt_witness);
                    }
                    _ => {}
                }
            }

            debug!("Loaded {} salt witness files", salt_witnesses.len());
            debug!("Loaded {} mpt witness files", mpt_witnesses.len());

            // Load contracts
            let bytecodes = load_contracts(&contracts_file);
            debug!("Loaded {} contracts from {contracts_file}", bytecodes.len());

            Self { blocks_by_hash, block_hashes, salt_witnesses, mpt_witnesses, bytecodes }
        }

        fn min_block(&self) -> (u64, BlockHash) {
            let (&num, &hash) = self.block_hashes.first_key_value().unwrap();
            (num, hash)
        }

        fn max_block(&self) -> (u64, BlockHash) {
            let (&num, &hash) = self.block_hashes.last_key_value().unwrap();
            (num, hash)
        }
    }

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::new("warn").add_directive("stateless_validator=debug".parse().unwrap()),
            )
            .try_init();
    }

    fn make_rpc_error(code: i32, msg: String) -> ErrorObject<'static> {
        ErrorObject::owned(code, msg, None::<()>)
    }

    /// Parse "{block_number}.{block_hash}" from a filename stem.
    fn parse_block_num_and_hash(input: &str) -> Result<(BlockNumber, BlockHash)> {
        let (block_str, hash_str) =
            input.split_once('.').ok_or_else(|| anyhow!("Invalid format: {input}"))?;
        Ok((block_str.parse()?, parse_block_hash(hash_str)?))
    }

    fn load_json<T: DeserializeOwned>(file_path: impl AsRef<Path>) -> Result<T> {
        let path = file_path.as_ref();
        let contents = std::fs::read(path)
            .with_context(|| format!("Failed to read file {}", path.display()))?;
        serde_json::from_slice(&contents)
            .with_context(|| format!("Failed to parse JSON from {}", path.display()))
    }

    /// Load contract bytecodes from a file (one `[hash, bytecode]` JSON per line).
    fn load_contracts(path: impl AsRef<Path>) -> HashMap<B256, Bytecode> {
        let file = File::open(path).expect("Failed to open contracts file");
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(&line).expect("Failed to parse contract"))
            .collect()
    }

    /// Create a temporary ValidatorDB with the anchor set to the first block in test data.
    fn setup_test_db(data: &TestData) -> Result<Arc<ValidatorDB>> {
        let temp_dir = tempfile::tempdir()?;
        let db = ValidatorDB::new(temp_dir.path().join(VALIDATOR_DB_FILENAME))?;
        // Intentionally leak the temp dir — ValidatorDB holds a path into it.
        // The OS will clean it up when the test process exits.
        std::mem::forget(temp_dir);

        let (block_num, block_hash) = data.min_block();
        let block = &data.blocks_by_hash[&block_hash];
        let withdrawals_root = block
            .header
            .withdrawals_root
            .ok_or_else(|| anyhow!("Block {block_hash} missing withdrawals_root"))?;

        let anchor = BlockMeta {
            block_number: block_num,
            block_hash,
            post_state_root: block.header.state_root,
            post_withdrawals_root: withdrawals_root,
        };
        db.reset_to_anchor(&anchor)?;

        Ok(Arc::new(db))
    }

    /// Start a mock RPC server backed by pre-loaded test data.
    async fn setup_mock_rpc_server(data: TestData) -> (jsonrpsee::server::ServerHandle, String) {
        let mut module = RpcModule::new(data);

        module
            .register_method("eth_getBlockByNumber", |params, ctx, _| {
                let (hex_number, full_block): (String, bool) = params.parse().unwrap();
                let block_number = u64::from_str_radix(&hex_number[2..], 16).unwrap_or(0);

                let block = ctx
                    .block_hashes
                    .get(&block_number)
                    .and_then(|hash| ctx.blocks_by_hash.get(hash))
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
            .register_method("eth_blockNumber", |_params, ctx, _| {
                let (&max_num, _) = ctx.block_hashes.last_key_value().unwrap();
                Ok::<String, ErrorObjectOwned>(format!("0x{max_num:x}"))
            })
            .unwrap();

        module
            .register_method("eth_getHeaderByNumber", |params, ctx, _| {
                let (hex_number,): (String,) = params.parse().unwrap();
                let block_number = u64::from_str_radix(&hex_number[2..], 16).unwrap_or(0);

                let block = ctx
                    .block_hashes
                    .get(&block_number)
                    .and_then(|hash| ctx.blocks_by_hash.get(hash))
                    .ok_or_else(|| {
                        make_rpc_error(
                            CALL_EXECUTION_FAILED_CODE,
                            format!("Block {block_number} not found"),
                        )
                    })?;

                Ok::<_, ErrorObject<'static>>(block.header.clone())
            })
            .unwrap();

        module
            .register_method("eth_getHeaderByHash", |params, ctx, _| {
                let (hash,): (B256,) = params.parse().map_err(|e| {
                    make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}"))
                })?;

                let block_hash = BlockHash::from(hash.0);
                let block = ctx.blocks_by_hash.get(&block_hash).ok_or_else(|| {
                    make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Block {hash} not found"))
                })?;

                Ok::<_, ErrorObject<'static>>(block.header.clone())
            })
            .unwrap();

        module
            .register_method("eth_getCodeByHash", |params, ctx, _| {
                let (hash,): (B256,) = params.parse().map_err(|e| {
                    make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}"))
                })?;

                let code = ctx.bytecodes.get(&hash).cloned().unwrap_or_default();
                Ok::<_, ErrorObject<'static>>(code.original_bytes())
            })
            .unwrap();

        module
            .register_method("mega_getBlockWitness", |params, ctx, _| {
                let (keys,): (WitnessRequestKeys,) = params.parse().map_err(|e| {
                    make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}"))
                })?;
                let block_hash = BlockHash::from(keys.block_hash.0);

                let salt_witness =
                    ctx.salt_witnesses.get(&block_hash).cloned().ok_or_else(|| {
                        make_rpc_error(
                            CALL_EXECUTION_FAILED_CODE,
                            format!("Witness for block {block_hash} not found"),
                        )
                    })?;

                let mpt_witness = ctx.mpt_witnesses.get(&block_hash).cloned().ok_or_else(|| {
                    make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Witness for block {block_hash} not found"),
                    )
                })?;

                let encoded = bincode::serde::encode_to_vec(
                    &(salt_witness, mpt_witness),
                    bincode::config::legacy(),
                )
                .map_err(|e| {
                    make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Failed to serialize witness: {e}"),
                    )
                })
                .and_then(|raw| {
                    zstd::encode_all(raw.as_slice(), 9).map_err(|e| {
                        make_rpc_error(
                            CALL_EXECUTION_FAILED_CODE,
                            format!("Failed to compress witness: {e}"),
                        )
                    })
                })
                .map(|compressed| format!("v0:{}", BASE64.encode(compressed)))?;

                Ok::<_, ErrorObject<'static>>(encoded)
            })
            .unwrap();

        module
            .register_method("mega_setValidatedBlocks", |params, _ctx, _| {
                let (_first_block, last_block): ((u64, String), (u64, String)) =
                    params.parse().unwrap();
                let last_hash = parse_block_hash(&last_block.1).unwrap();
                Ok::<serde_json::Value, ErrorObjectOwned>(serde_json::json!({
                    "accepted": true,
                    "lastValidatedBlock": [last_block.0, last_hash]
                }))
            })
            .unwrap();

        let cfg =
            ServerConfigBuilder::default().max_response_body_size(MAX_RESPONSE_BODY_SIZE).build();
        let server = ServerBuilder::default().set_config(cfg).build("0.0.0.0:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (server.start(module), url)
    }

    /// Synthetic data integration test: validates consecutive blocks via the streaming pipeline.
    #[tokio::test]
    async fn integration_test() {
        init_test_logging();
        debug!("=== Loading Synthetic Test Data ===");
        let data = TestData::load(SYNTHETIC_DATA_DIR);

        let genesis_file = format!("{SYNTHETIC_DATA_DIR}/genesis.json");
        let sync_target = Some(data.max_block().0);
        let validator_db = setup_test_db(&data).unwrap();
        let contract_cache =
            Arc::new(ContractCache::new(Arc::clone(&validator_db) as Arc<dyn ContractStore>));
        let (handle, url) = setup_mock_rpc_server(data).await;
        let client = Arc::new(RpcClient::new(&url, &url).unwrap());

        let chain_spec =
            Arc::new(load_or_create_chain_spec(&validator_db, Some(&genesis_file)).unwrap());

        let config = Arc::new(ChainSyncConfig {
            concurrent_workers: 1,
            sync_target,
            ..ChainSyncConfig::default()
        });

        let shutdown = CancellationToken::new();
        let (main_loop, bg_tasks) = chain_sync(
            client.clone(),
            validator_db,
            contract_cache,
            config,
            chain_spec,
            shutdown.clone(),
        )
        .unwrap();
        main_loop.await.unwrap();

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), future::join_all(bg_tasks)).await;

        handle.stop().unwrap();
        info!("Mock RPC server has been shut down.");
    }

    /// Mainnet integration test: validates non-contiguous blocks individually.
    #[test]
    fn mainnet_integration_test() {
        init_test_logging();
        debug!("=== Loading Mainnet Test Data ===");
        let mut data = TestData::load(MAINNET_DATA_DIR);

        let genesis_file = format!("{MAINNET_DATA_DIR}/genesis.json");
        let genesis: Genesis = load_json(&genesis_file).unwrap();
        let chain_spec = ChainSpec::from_genesis(genesis);

        // Target blocks are those with witness data
        let target_blocks: Vec<u64> = data
            .block_hashes
            .keys()
            .filter(|num| {
                let hash = data.block_hashes[num];
                data.salt_witnesses.contains_key(&hash)
            })
            .copied()
            .collect();

        info!("Validating {} mainnet blocks: {:?}", target_blocks.len(), target_blocks);

        for block_number in &target_blocks {
            let block_hash = data.block_hashes[block_number];
            let block = &data.blocks_by_hash[&block_hash];
            let salt_witness = data.salt_witnesses.remove(&block_hash).unwrap();
            let mpt_witness = data.mpt_witnesses.remove(&block_hash).unwrap();

            debug!("Validating mainnet block {block_number}");

            match validate_block(
                &chain_spec,
                block,
                salt_witness,
                mpt_witness,
                &data.bytecodes,
                None,
            ) {
                Ok(_) => info!("Successfully validated mainnet block {block_number}"),
                Err(e) => panic!("Block {block_number} validation failed: {e}"),
            }
        }

        info!("All {} mainnet blocks validated successfully", target_blocks.len());
    }
}
