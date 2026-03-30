use std::{
    collections::HashSet,
    future::Future,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
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
    ChainSyncConfig, FetchResult, RpcClient, RpcClientConfig, ValidatorDB,
    chain_spec::ChainSpec,
    data_types::{PlainKey, PlainValue},
    executor::{ValidationResult, validate_block},
    remote_chain_tracker,
};
use tokio::{signal, task, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

mod metrics;

/// Handles to all spawned background tasks, awaited during shutdown.
type BackgroundTasks = Vec<JoinHandle<Result<()>>>;

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
                    warn!("[Main] Failed to fetch block {block_hash}: {e}, retrying...",);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };

        validator_db
            .reset_anchor_block(
                header.number,
                header.hash,
                header.state_root,
                header
                    .withdrawals_root
                    .ok_or_else(|| anyhow!("Block {} is missing withdrawals_root", block_hash))?,
            )
            .map_err(|e| anyhow!("Failed to reset anchor: {}", e))?;

        info!(
            "[Main] Successfully initialized from block {} (number: {})",
            header.hash, header.number
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
        report_validation_results: args.report_validation_endpoint.is_some(),
        metrics_enabled: args.metrics_enabled,
        metrics_port: args.metrics_port,
        ..ChainSyncConfig::default()
    });
    info!("[Main] Number of concurrent tasks: {}", config.concurrent_workers);
    info!(
        "[Main] Validation result reporting: {}",
        if config.report_validation_results { "enabled" } else { "disabled" }
    );

    let shutdown_token = CancellationToken::new();
    let (validator_logic, bg_tasks) =
        chain_sync(client.clone(), &validator_db, config, chain_spec, shutdown_token.clone())?;

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow!("Failed to register SIGTERM handler: {e}"))?;

    let validator_result = tokio::select! {
        res = validator_logic => {
            if let Err(ref e) = res {
                error!(error = %e, "[Main] Validator exited with error");
            }
            Some(res)
        }
        _ = signal::ctrl_c() => {
            info!("[Main] SIGINT received, shutting down.");
            None
        }
        _ = sigterm.recv() => {
            info!("[Main] SIGTERM received, shutting down.");
            None
        }
    };

    // Signal all workers to stop cooperatively
    shutdown_token.cancel();

    // Wait for background tasks to acknowledge cancellation and finish cleanly
    let timeout = Duration::from_secs(3);
    let bg_tasks_len = bg_tasks.len();
    match tokio::time::timeout(timeout, future::join_all(bg_tasks)).await {
        Ok(results) => {
            for (i, result) in results.into_iter().enumerate() {
                match result {
                    Ok(Err(e)) => {
                        warn!(task_idx = i, error = %e, "[Main] Background task finished with error")
                    }
                    Err(e) if e.is_cancelled() => {
                        debug!(task_idx = i, "[Main] Background task cancelled")
                    }
                    Err(e) => {
                        error!(task_idx = i, error = %e, "[Main] Background task terminated unexpectedly")
                    }
                    Ok(Ok(())) => {}
                }
            }
        }
        Err(_) => {
            warn!(timeout = ?timeout, task_count = bg_tasks_len, "[Main] Background tasks did not finish within timeout")
        }
    }

    info!("[Main] Shutdown complete.");

    info!("[Main] Total execution time: {:?}", start.elapsed());

    // Propagate the validator error (if any) after shutdown completes,
    // so background tasks are always cleaned up before exiting.
    if let Some(res) = validator_result { res } else { Ok(()) }
}

/// Chain synchronizer entry point - orchestrates the complete chain synchronization pipeline
///
/// Implements a multi-phase startup process for stateless block validation:
/// 1. **Task Recovery** - Recovers interrupted validation tasks from previous crashes
/// 2. **Remote Chain Tracking** - Spawns background tracker to maintain block lookahead
/// 3. **Validation Reporter** - Optionally spawns background task to report validated blocks to a
///    dedicated report endpoint (when `report_validation_endpoint` is provided)
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
/// * `config` - Configuration including worker count, polling intervals, optional sync target, and
///   validation reporting
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
///
/// # Returns
/// * `Ok((main_loop, bg_tasks))` - Main sync loop future and handles to all background tasks
/// * `Err(eyre::Error)` - On critical failures during task recovery
fn chain_sync(
    client: Arc<RpcClient>,
    validator_db: &Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
    chain_spec: Arc<ChainSpec>,
    shutdown: CancellationToken,
) -> Result<(impl Future<Output = Result<()>>, BackgroundTasks)> {
    info!("[Chain Sync] Starting with {} validation workers", config.concurrent_workers);

    // Step 1: Recover any interrupted tasks from previous crashes
    info!("[Chain Sync] Recovering interrupted validation tasks from previous runs...");
    validator_db
        .recover_interrupted_tasks()
        .map_err(|e| anyhow!("Failed to recover interrupted tasks: {}", e))?;
    info!("[Chain Sync] Task recovery completed");

    let mut bg_tasks: BackgroundTasks = Vec::new();

    // Step 2: Spawn remote chain tracker
    // Safe to cancel externally: all DB writes in remote_chain_tracker are
    // atomic transactions, and in-flight RPC data can be re-fetched on restart.
    info!("[Chain Sync] Starting remote chain tracker...");
    bg_tasks.push(task::spawn({
        let (client, db, config, shutdown) = (
            Arc::clone(&client),
            Arc::clone(validator_db),
            Arc::clone(&config),
            shutdown.clone(),
        );
        async move {
            tokio::select! {
                res = remote_chain_tracker(client, db, config, Some(metrics::on_chain_reorg), None::<fn(&FetchResult)>) => res,
                _ = shutdown.cancelled() => { info!("[Tracker] Shutting down gracefully"); Ok(()) }
            }
        }
    }));

    // Step 3: Spawn validation reporter (optional, based on config)
    if config.report_validation_results {
        info!("[Chain Sync] Starting validation reporter...");
        bg_tasks.push(task::spawn(validation_reporter(
            Arc::clone(&client),
            Arc::clone(validator_db),
            Arc::clone(&config),
            shutdown.clone(),
        )));
    } else {
        info!("[Chain Sync] Validation reporter disabled (validation reporting not enabled)");
    }

    // Step 4: Spawn history pruner
    bg_tasks.push(task::spawn(history_pruner(
        Arc::clone(validator_db),
        Arc::clone(&config),
        shutdown.clone(),
    )));

    // Step 5: Spawn validation workers as tokio tasks
    info!("[Chain Sync] Spawning {} validation workers...", config.concurrent_workers);
    for worker_id in 0..config.concurrent_workers {
        bg_tasks.push(task::spawn(validation_worker(
            worker_id,
            Arc::clone(&client),
            Arc::clone(validator_db),
            Arc::clone(&config),
            Arc::clone(&chain_spec),
            shutdown.clone(),
        )));
    }
    info!("[Chain Sync] All validation workers started");

    // Step 6: Return main chain synchronizer loop as a future
    info!("[Chain Sync] Starting main synchronizer loop...");

    let validator_db = Arc::clone(validator_db);
    let main_loop = async move {
        loop {
            if shutdown.is_cancelled() {
                info!("[Chain Sync] Shutting down gracefully");
                return Ok(());
            }

            if let Some(target) = config.sync_target &&
                let Ok(Some((local_block_number, _))) = validator_db.get_local_tip() &&
                local_block_number >= target
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
                    tokio::select! {
                        _ = tokio::time::sleep(config.sync_poll_interval) => {}
                        _ = shutdown.cancelled() => {}
                    }
                }

                // Update chain height metrics
                if let (Ok(Some((local_tip, _))), Ok(remote_tip)) =
                    (validator_db.get_local_tip(), validator_db.get_remote_tip())
                {
                    let remote_height = remote_tip.map(|(n, _)| n).unwrap_or(local_tip);
                    metrics::set_chain_heights(local_tip, remote_height);

                    let earliest = validator_db
                        .get_earliest_local_block()
                        .ok()
                        .flatten()
                        .map(|(n, _)| n)
                        .unwrap_or(0);
                    metrics::set_db_block_range(earliest, local_tip);
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
                // 4. ValidationDbError::ValidationResultMismatch
                //    - Validation result does not match the first remote chain entry
                //    - Indicates database inconsistency or logic error in the pipeline
                //
                // The chain sync process terminates immediately and returns the error to the
                // caller. Operators should investigate the root cause.

                error!("[Chain Sync] Failed to advance canonical chain: {}", e);
                return Err(e);
            }
        }
    };

    Ok((main_loop, bg_tasks))
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
    shutdown: CancellationToken,
) -> Result<()> {
    info!("[Worker {}] Started", worker_id);
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        // NOTE: shutdown is not preemptive during `validate_one`. If a cancellation arrives
        // while a block is being validated (which runs on a blocking thread via spawn_blocking),
        // the worker will finish the current block before checking the token again at the top
        // of this loop or in the idle/error select! branches below.
        match validate_one(worker_id, &client, &validator_db, chain_spec.clone()).await {
            Ok(true) => {}
            Ok(false) => tokio::select! {
                _ = tokio::time::sleep(config.worker_idle_sleep) => {}
                _ = shutdown.cancelled() => break,
            },
            Err(e) => {
                if shutdown.is_cancelled() {
                    warn!(worker_id, error = %e, "[Worker] Error during shutdown, stopping");
                    break;
                }
                error!("[Worker {worker_id}] Error during task processing: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(config.worker_error_sleep) => {}
                    _ = shutdown.cancelled() => break,
                }
            }
        }
    }
    info!("[Worker {worker_id}] Shutting down gracefully");
    Ok(())
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
            let codes = future::try_join_all(
                missing_contracts.iter().map(|&hash| async move { client.get_code(hash).await }),
            )
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

            validator_db.add_contract_codes(&new_bytecodes)?;
            contracts.extend(new_bytecodes);

            let pre_state_root = B256::from(witness.state_root()?);
            let post_state_root = block.header.state_root;
            let pre_withdrawals_root = mpt_witness.storage_root;
            let block_hash = block.header.hash;
            let post_withdrawals_root = block
                .header
                .withdrawals_root
                .ok_or(eyre::eyre!("Withdrawals root not found in block {block_hash}"))?;

            // Validate in a blocking thread so async tasks (reporter, tracker, etc.) stay
            // responsive.
            let validation_result = task::spawn_blocking(move || {
                validate_block(&chain_spec, &block, witness, mpt_witness, &contracts, None)
            })
            .await
            .map_err(|e| eyre::eyre!("Validation task failed: {e}"))?;

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

/// Reports validated blocks to the dedicated report endpoint
///
/// Periodically monitors the canonical chain and reports the complete validated range
/// (first to last block) to the report endpoint via `mega_setValidatedBlocks` RPC.
/// Only reports when new blocks have been validated.
///
/// # Arguments
/// * `client` - RPC client with a configured report provider
/// * `validator_db` - Database interface for reading canonical chain
/// * `config` - Configuration containing sync_poll_interval
///
/// # Returns
/// * `Ok(())` - Never returns under normal operation
/// * `Err(eyre::Error)` - Terminates if validation gap detected (upstream's last validated block <
///   local chain start)
async fn validation_reporter(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
    shutdown: CancellationToken,
) -> Result<()> {
    info!("[Reporter] Starting validation reporter");
    let mut last_reported_block = (0u64, BlockHash::ZERO);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(config.sync_poll_interval) => {}
            _ = shutdown.cancelled() => {
                info!("[Reporter] Shutting down gracefully");
                return Ok(());
            }
        }

        // Get canonical chain bounds
        let (first_block, last_block) =
            match (validator_db.get_anchor_block(), validator_db.get_local_tip()) {
                (Ok(Some(first)), Ok(Some(last))) => (first, last),
                _ => continue,
            };

        // Skip if no new blocks
        if last_block == last_reported_block {
            continue;
        }

        // Report validated range to upstream
        let result = client
            .set_validated_blocks(
                (first_block.0, B256::from(first_block.1.0)),
                (last_block.0, B256::from(last_block.1.0)),
            )
            .await;

        match result {
            Ok(response) if response.accepted => {
                debug!("[Reporter] Reported blocks successfully: {first_block:?} - {last_block:?}");
                last_reported_block = last_block;
            }
            Ok(response) => {
                // Check for validation gap
                if response.last_validated_block.0 < first_block.0 {
                    debug!(
                        "[Reporter] Validation gap detected: upstream at block {}, but local chain starts at {}. Cannot advance validation.",
                        response.last_validated_block.0, first_block.0
                    );
                    return Err(anyhow!(
                        "Validation gap detected: upstream at block {}, but local chain starts at {}. Cannot advance validation.",
                        response.last_validated_block.0,
                        first_block.0
                    ));
                }
                debug!(
                    "[Reporter] Report rejected for blocks {first_block:?}-{last_block:?}, upstream at {:?}",
                    response.last_validated_block
                );
                error!(
                    "[Reporter] Report rejected for blocks {first_block:?}-{last_block:?}, upstream at {:?}",
                    response.last_validated_block
                );
            }
            Err(e) => {
                debug!("[Reporter] Failed to report blocks: {e}");
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
    shutdown: CancellationToken,
) -> Result<()> {
    info!("[Pruner] Starting with interval {:?}", config.pruner_interval);

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

            // Update DB block range metrics
            let earliest =
                validator_db.get_earliest_local_block().ok().flatten().map(|(n, _)| n).unwrap_or(0);
            metrics::set_db_block_range(earliest, current_tip);
        }

        tokio::select! {
            _ = tokio::time::sleep(config.pruner_interval) => {}
            _ = shutdown.cancelled() => {
                info!("[Pruner] Shutting down gracefully");
                return Ok(());
            }
        }
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
        .filter_map(|val| match (PlainKey::decode(val.key()), PlainValue::decode(val.value())) {
            (PlainKey::Account(_), PlainValue::Account(acc)) => {
                acc.codehash.filter(|&codehash| codehash != KECCAK_EMPTY)
            }
            _ => None,
        })
        .collect()
}

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
        let validator_db = ValidatorDB::new(temp_dir.path().join(VALIDATOR_DB_FILENAME))?;
        // Intentionally leak the temp dir — ValidatorDB holds a path into it.
        // The OS will clean it up when the test process exits.
        std::mem::forget(temp_dir);

        let (block_num, block_hash) = data.min_block();
        let block = &data.blocks_by_hash[&block_hash];
        let withdrawals_root = block
            .header
            .withdrawals_root
            .ok_or_else(|| anyhow!("Block {block_hash} missing withdrawals_root"))?;
        validator_db.reset_anchor_block(
            block_num,
            block_hash,
            block.header.state_root,
            withdrawals_root,
        )?;

        Ok(Arc::new(validator_db))
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

    /// Synthetic data integration test: validates consecutive blocks via chain_sync.
    #[tokio::test]
    async fn integration_test() {
        init_test_logging();
        debug!("=== Loading Synthetic Test Data ===");
        let data = TestData::load(SYNTHETIC_DATA_DIR);

        let genesis_file = format!("{SYNTHETIC_DATA_DIR}/genesis.json");
        let sync_target = Some(data.max_block().0);
        let validator_db = setup_test_db(&data).unwrap();
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
        let (main_loop, bg_tasks) =
            chain_sync(client.clone(), &validator_db, config, chain_spec, shutdown.clone())
                .unwrap();
        main_loop.await.unwrap();

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), future::join_all(bg_tasks)).await;
        drop(validator_db);

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
