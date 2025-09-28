use alloy_primitives::{Address, BlockHash, hex};
use alloy_rpc_types_eth::Header;
use clap::Parser;
use eyre::{Result, anyhow};
use futures::future;
use jsonrpsee::{
    RpcModule,
    server::{ServerBuilder, ServerConfigBuilder},
};
use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, ErrorObject, INVALID_PARAMS_CODE};
use revm::{
    primitives::{B256, KECCAK_EMPTY},
    state::Bytecode,
};
use salt::SaltWitness;
use std::collections::HashMap;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::{signal, task};
use tracing::{error, info, warn};
use validator_core::{
    ValidatorDB,
    data_types::{PlainKey, PlainValue},
    executor::{ValidationResult, validate_block},
};

mod rpc;
use rpc::RpcClient;

mod checksum_data;
mod witness_types;
use checksum_data::deserialized_checksum_data;

/// Maximum response body size for the RPC server.
/// This is set to 100 MB to accommodate large block data and witness information.
const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

/// Database filename for the validator.
const VALIDATOR_DB_FILENAME: &str = "validator.redb";

/// Helper function to create RPC errors with consistent format
fn make_rpc_error(code: i32, msg: String) -> ErrorObject<'static> {
    ErrorObject::owned(code, msg, None::<()>)
}

// FIXME: not `rerun_block`!
/// Command line arguments for the `rerun_block` executable.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // FIXME: How is `datadir` the starting block number?
    /// The starting block number from which to begin replaying.
    #[clap(short, long)]
    datadir: String,

    // FIXME: how is `lock_time` related to # consecutive blocks? what is the latter anyway?
    /// The total number of consecutive blocks to replay.
    #[clap(short, long, default_value_t = 5)]
    lock_time: u64,

    // FIXME: why do we need to fetch block data? what else needs to be fetched from rpc endpoint?
    /// The URL of the Ethereum JSON-RPC API endpoint to use for fetching block data.
    #[clap(short, long)]
    api: String,

    // FIXME: what is "stateless validator server"? is there a client?
    /// The port of the stateless validator server.
    #[clap(short, long)]
    port: Option<u16>,
}

/// The main entry point for the stateless validator.
///
/// This executable is responsible for scanning for new block witnesses, validating them by
/// replaying the block, and verifying the resulting state root. It can run in a standalone mode or
/// expose an RPC server for querying validation status.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let start = Instant::now();
    let args = Args::parse();

    info!("[Main] Data directory: {}", args.datadir);
    info!("[Main] Lock time: {} seconds", args.lock_time);
    info!("[Main] API endpoint: {}", args.api);
    info!("[Main] Server port: {:?}", args.port);

    // Reserve 2 CPUs for the server if it's running, otherwise use all available CPUs.
    let concurrent_num = if args.port.is_some() {
        (num_cpus::get() - 2).max(1)
    } else {
        num_cpus::get()
    };
    info!("[Main] Number of concurrent tasks: {}", concurrent_num);

    let work_dir = PathBuf::from(args.datadir);

    let client = Arc::new(RpcClient::new(&args.api)?);
    let validator_db = Arc::new(ValidatorDB::new(work_dir.join(VALIDATOR_DB_FILENAME))?);

    let validator_logic = chain_sync(
        client.clone(),
        validator_db.clone(),
        concurrent_num,
        Duration::from_secs(5), // poll_interval
        None,                   // sync_target (infinite sync)
    );

    if let Some(port) = args.port {
        let mut module = RpcModule::new(validator_db.clone());

        module.register_method("stateless_getValidation", |params, validator_db, _| {
            let (_block_number, block_hash): (u64, String) = params.parse()?;
            let block_hash = parse_block_hash(&block_hash).map_err(|e| {
                make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid block hash: {e}"))
            })?;

            match validator_db.get_validation_result(block_hash) {
                Ok(Some(result)) => Ok(result.success),
                Ok(None) => Err(make_rpc_error(
                    INVALID_PARAMS_CODE,
                    "Validation result not found".to_string(),
                )),
                Err(e) => Err(make_rpc_error(CALL_EXECUTION_FAILED_CODE, e.to_string())),
            }
        })?;

        let cfg = ServerConfigBuilder::default()
            .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
            .build();
        let server = ServerBuilder::default()
            .set_config(cfg)
            .build(format!("0.0.0.0:{port}"))
            .await?;

        let addr = server.local_addr()?.to_string();
        info!("[RPC Server] Listening on {}", addr);

        let handle = server.start(module);

        tokio::select! {
            res = validator_logic => res?,
            _ = handle.stopped() => {
                info!("[RPC Server] Stopped");
            },
            _ = signal::ctrl_c() => {
                info!("[Main] Ctrl-C received, shutting down.");
            }
        }
    } else {
        info!("[Main] Server not configured to start. Running validation logic only.");
        tokio::select! {
            res = validator_logic => res?,
            _ = signal::ctrl_c() => {
                info!("[Main] Ctrl-C received, shutting down.");
            }
        }
    }

    info!("[Main] Total execution time: {:?}", start.elapsed());
    Ok(())
}

/// Convert hex string to BlockHash
///
/// Accepts hex strings with or without "0x" prefix. Must be exactly 32 bytes when decoded.
fn parse_block_hash(hex_str: &str) -> Result<BlockHash> {
    let hash_bytes = hex::decode(hex_str)?;
    if hash_bytes.len() != 32 {
        return Err(anyhow!(
            "Block hash must be 32 bytes, got {}",
            hash_bytes.len()
        ));
    }
    Ok(BlockHash::from_slice(&hash_bytes))
}

/// Returns all contract addresses and their code hashes from the witness.
///
/// Filters witness data to find accounts with non-empty bytecode, which are
/// needed for contract code fetching during block execution.
fn extract_contract_codes(salt_witness: &SaltWitness) -> HashMap<Address, B256> {
    salt_witness
        .kvs
        .values()
        .filter_map(|salt_val| salt_val.as_ref())
        .filter_map(
            |val| match (PlainKey::decode(val.key()), PlainValue::decode(val.value())) {
                (PlainKey::Account(addr), PlainValue::Account(acc)) => acc
                    .codehash
                    .filter(|&codehash| codehash != KECCAK_EMPTY)
                    .map(|codehash| (addr, codehash)),
                _ => None,
            },
        )
        .collect()
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
///
/// # Returns
/// * Never returns under normal operation - runs indefinitely until externally terminated
async fn validation_worker(
    worker_id: usize,
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
) -> Result<()> {
    info!("[Worker {}] Started", worker_id);
    loop {
        match validate_one(worker_id, &client, &validator_db).await {
            Ok(true) => {}
            Ok(false) => {
                // No tasks available, wait before checking again
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                // RPC/DB failures may get resolved over time, introduce a small
                // delay to prevent tight error loops
                error!("[Worker {worker_id}] Error during task processing: {e}");
                tokio::time::sleep(Duration::from_millis(1000)).await;
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
///
/// # Returns
/// * `Ok(true)` - Task was processed (validation success/failure stored in DB)
/// * `Ok(false)` - No tasks available, no work performed
/// * `Err(eyre::Error)` - Infrastructure error (DB/RPC failures)
async fn validate_one(
    worker_id: usize,
    client: &RpcClient,
    validator_db: &ValidatorDB,
) -> Result<bool> {
    match validator_db.get_next_task()? {
        Some((block, witness)) => {
            let block_number = block.header.number;
            info!("[Worker {}] Validating block {}", worker_id, block_number);

            // Prepare the contract map to be used by validation
            let codehashes = extract_contract_codes(&witness);
            let mut missing_contracts = Vec::new();
            let mut contracts = HashMap::new();

            for (address, code_hash) in &codehashes {
                match validator_db.get_contract_code(*code_hash) {
                    Ok(Some(bytecode)) => {
                        contracts.insert(*code_hash, bytecode);
                    }
                    _ => missing_contracts.push(*address),
                }
            }

            // Fetch missing contract codes via RPC and update the local DB
            let codes = client
                .codes_at(&missing_contracts, (block_number - 1).into())
                .await?;

            for (address, bytes) in missing_contracts.iter().zip(codes.iter()) {
                let bytecode = Bytecode::new_raw(bytes.clone());
                validator_db.add_contract_code(&bytecode)?;
                contracts.insert(codehashes[address], bytecode);
            }

            // Validate the given block
            let pre_state_root = B256::from(witness.state_root()?);
            let (success, error_message) = match validate_block(&block, witness, &contracts) {
                Ok(()) => {
                    info!("[Worker {worker_id}] Successfully validated block {block_number}");
                    (true, None)
                }
                Err(e) => {
                    error!("[Worker {worker_id}] Failed to validate block {block_number}: {e}");
                    (false, Some(e.to_string()))
                }
            };

            validator_db.complete_validation(ValidationResult {
                pre_state_root,
                post_state_root: block.header.state_root,
                block_number,
                block_hash: block.header.hash,
                success,
                error_message,
                completed_at: SystemTime::now(),
            })?;

            Ok(true)
        }
        None => Ok(false),
    }
}

/// Chain synchronizer entry point - implements the Chain Synchronizer component from the design document
///
/// This function serves as the main orchestrator that:
/// - Monitors chain head progression via remote RPC endpoint
/// - Tracks block finality status via remote RPC endpoint
/// - Manages reorganization detection and recovery
/// - Fetches block and witness data via remote RPC endpoint
/// - Creates validation tasks and stores them in ValidatorDB for validation workers
/// - Processes validation results to drive local chain tip progression
/// - Prunes old block and witness data to maintain constant storage overhead
/// - Coordinates with parallel validation workers via ValidatorDB
///
/// # Arguments
/// * `client` - RPC client for communicating with remote blockchain node
/// * `validator_db` - Database interface for coordinating with validation workers
/// * `concurrent_num` - Number of parallel validation workers to spawn
/// * `poll_interval` - Time to wait between sync cycles
/// * `sync_target` - Optional block height to sync to; None for infinite sync
async fn chain_sync(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    concurrent_num: usize,
    poll_interval: Duration,
    sync_target: Option<u64>,
) -> Result<()> {
    info!(
        "[Chain Sync] Starting with {} validation workers",
        concurrent_num
    );

    // Step 1: Recover any interrupted tasks from previous crashes
    info!("[Chain Sync] Recovering interrupted validation tasks from previous runs...");
    validator_db
        .recover_interrupted_tasks()
        .map_err(|e| anyhow!("Failed to recover interrupted tasks: {}", e))?;
    info!("[Chain Sync] Task recovery completed");

    // Step 2: Spawn remote chain tracker
    info!("[Chain Sync] Starting remote chain tracker...");
    let _tracker_handle = {
        let client_clone = Arc::clone(&client);
        let validator_db_clone = Arc::clone(&validator_db);

        task::spawn(async move { remote_chain_tracker(client_clone, validator_db_clone).await })
    };
    info!("[Chain Sync] Remote chain tracker started");

    // Step 3: Spawn history pruner
    task::spawn({
        let validator_db = Arc::clone(&validator_db);
        async move { history_pruner(validator_db, Duration::from_secs(300), 1000).await }
    });

    // Step 4: Spawn validation workers as tokio tasks
    info!(
        "[Chain Sync] Spawning {} validation workers...",
        concurrent_num
    );
    let mut worker_handles = Vec::new();

    for worker_id in 0..concurrent_num {
        let client_clone = Arc::clone(&client);
        let validator_db_clone = Arc::clone(&validator_db);

        let handle = task::spawn(async move {
            validation_worker(worker_id, client_clone, validator_db_clone).await
        });

        worker_handles.push(handle);
    }
    info!("[Chain Sync] All validation workers started");

    // Step 5: Main chain synchronizer loop
    info!("[Chain Sync] Starting main synchronizer loop...");

    loop {
        // Check if we've reached the sync target
        if let Some(target) = sync_target
            && let Ok(Some((local_block_number, _))) = validator_db.get_local_tip()
            && local_block_number >= target
        {
            info!("[Chain Sync] Reached sync target height {target}, terminating");
            return Ok(());
        }

        // Chain sync iteration - advance canonical chain
        if let Err(e) = async {
            // Advance the canonical chain with newly validated blocks
            let mut blocks_advanced = 0;
            while validator_db.grow_local_chain()? {
                blocks_advanced += 1;
            }

            if blocks_advanced > 0 {
                info!("[Chain Sync] Advanced canonical chain by {blocks_advanced} blocks");
            }

            Ok::<(), eyre::Error>(())
        }
        .await
        {
            error!("[Chain Sync] Iteration failed: {}", e);
        }

        // Wait before next sync cycle
        tokio::time::sleep(poll_interval).await;
    }
}

/// Remote chain tracker that maintains a lookahead of unvalidated blocks
///
/// This function runs an infinite loop that:
/// 1. Monitors the gap between local canonical tip and local remote tip
/// 2. Fetches new blocks from the remote RPC when the gap is too small
/// 3. Validates that the remote tip is still valid (detects reorgs)
/// 4. Maintains a sufficient number of unvalidated blocks for validation workers
///
/// # Arguments
/// * `client` - RPC client for fetching blocks from remote blockchain
/// * `validator_db` - Database interface for chain management
async fn remote_chain_tracker(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
) -> Result<()> {
    const LOOKAHEAD_BLOCKS: u64 = 10;
    const POLLING_INTERVAL_SECS: u64 = 2;

    info!("[Tracker] Starting with {LOOKAHEAD_BLOCKS} block lookahead");

    loop {
        // Perform one iteration of remote chain tracking
        if let Err(e) = async {
            // Get current chain tips and analyze gap
            let local_tip = validator_db
                .get_local_tip()?
                .ok_or_else(|| anyhow!("Local chain is empty - cannot track remote chain"))?;
            let remote_tip = validator_db.get_remote_tip()?.unwrap_or(local_tip);
            let gap = remote_tip.0.saturating_sub(local_tip.0);
            info!("[Tracker] Chain status: local_tip={}, remote_tip={}, gap={}", local_tip.0, remote_tip.0, gap);

            // Check if we are still on the right chain (detect reorgs)
            match client.block_by_number(remote_tip.0, false).await {
                Ok(block) if block.header.hash != remote_tip.1 => {
                    error!("[Tracker] Remote tip hash mismatch! Expected: {}, got: {}. Triggering rollback.", remote_tip.1, block.header.hash);
                    // FIXME: Find proper common ancestor between local and remote chains
                    validator_db.rollback_chain(local_tip.0)?;
                    return Ok(());
                }
                Err(e) => warn!("[Tracker] Failed to validate remote tip {} (network issue): {}. Continuing without rollback.", remote_tip.1, e),
                _ => {} // Valid remote tip, continue
            }

            if gap >= LOOKAHEAD_BLOCKS {
                info!("[Tracker] Sufficient lookahead maintained (gap: {})", gap);
                return Ok(());
            }

            // Query latest block and calculate fetch range
            let latest_remote_block = client.block_number().await?;
            let blocks_to_fetch = (LOOKAHEAD_BLOCKS - gap)
                .min(latest_remote_block.saturating_sub(remote_tip.0));

            if blocks_to_fetch == 0 {
                info!("[Tracker] No new blocks available on remote chain (latest: {})", latest_remote_block);
                return Ok(());
            }

            let start_block = remote_tip.0 + 1;
            info!("[Tracker] Fetching {} blocks (range: {} to {}) to maintain lookahead",
                  blocks_to_fetch, start_block, start_block + blocks_to_fetch - 1);

            // Fetch blocks and witnesses, queue for validation, return headers
            let fetch_tasks: Vec<_> = (start_block..start_block + blocks_to_fetch)
                .map(|block_number| {
                    let client = client.clone();
                    let db = validator_db.clone();
                    tokio::spawn(async move {
                        let block = client.block_by_number(block_number, true).await?;
                        let witness = client.witness_by_block_hash(block.header.hash).await?;
                        db.add_validation_task(&block, &witness)?;
                        Ok::<Header, eyre::Error>(block.header)
                    })
                })
                .collect();

            // Wait for all fetches and process results, ensuring contiguity
            let fetch_results = future::join_all(fetch_tasks).await;
            let mut fetched_headers = Vec::new();

            for (i, task_result) in fetch_results.into_iter().enumerate() {
                let block_number = start_block + i as u64;
                match task_result {
                    Ok(Ok(header)) => fetched_headers.push(header),
                    Ok(Err(e)) => {
                        error!("[Tracker] RPC error fetching block {}: {}. Stopping to maintain contiguity.", block_number, e);
                        break;
                    }
                    Err(e) => {
                        error!("[Tracker] Task join error for block {}: {}. Stopping to maintain contiguity.", block_number, e);
                        break;
                    }
                }
            }

            if fetched_headers.len() < blocks_to_fetch as usize {
                info!("[Tracker] Fetched {} out of {} requested blocks due to failures. Will retry missing blocks in next iteration.",
                      fetched_headers.len(), blocks_to_fetch);
            }

            // Add headers to remote chain
            for header in fetched_headers {
                if let Err(e) = validator_db.grow_remote_chain(&header) {
                    error!("[Tracker] Failed to add block {} to remote chain: {}. Stopping to avoid gaps.", header.number, e);
                    break;
                }
            }

            Ok::<(), eyre::Error>(())
        }.await {
            error!("[Tracker] Iteration failed: {}", e);
            // Continue running despite errors - individual iterations can fail
        }

        // Wait before next iteration
        tokio::time::sleep(Duration::from_secs(POLLING_INTERVAL_SECS)).await;
    }
}

/// Periodically prunes old block data to manage storage
async fn history_pruner(
    validator_db: Arc<ValidatorDB>,
    pruning_interval: Duration,
    blocks_to_keep: u64,
) -> Result<()> {
    info!("[Pruner] Starting with interval {pruning_interval:?}");

    loop {
        if let Ok(Some((current_tip, _))) = validator_db.get_local_tip() {
            let prune_before = current_tip.saturating_sub(blocks_to_keep);
            match validator_db.prune_history(prune_before) {
                Ok(blocks_pruned) if blocks_pruned > 0 => {
                    info!("[Pruner] Pruned {blocks_pruned} blocks before block {prune_before}");
                }
                Err(e) => warn!("[Pruner] Failed to prune old block data: {e}"),
                _ => {}
            }
        }

        tokio::time::sleep(pruning_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness_types::WitnessStatus;
    use alloy_primitives::BlockNumber;
    use alloy_rpc_types_eth::Block;
    use eyre::Context;
    use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, ErrorObjectOwned};
    use op_alloy_rpc_types::Transaction;
    use serde::de::DeserializeOwned;
    use std::{
        collections::BTreeMap,
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

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
    /// WitnessStatus data with BLAKE3 hash verification.
    const TEST_WITNESS_DIR: &str = "../../test_data/stateless/witness";

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

        /// Witness data indexed by block hash
        witness_data: HashMap<BlockHash, SaltWitness>,

        /// Contract bytecode cache
        contracts: HashMap<B256, Bytecode>,

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
        let validator_db = ValidatorDB::new(&temp_dir.path().join(VALIDATOR_DB_FILENAME))?;
        std::mem::forget(temp_dir);

        // Set the local chain tip to the first block in test data.
        let (block_num, block_hash) = context.min_block;
        let state_root = context
            .blocks_by_hash
            .get(&block_hash)
            .ok_or_else(|| anyhow!("Local tip {block_hash} not found"))?
            .header
            .state_root;
        validator_db.set_local_tip(block_num, block_hash, state_root)?;

        // Populate CONTRACTS table with test contract bytecode
        let contracts = load_contracts(CONTRACTS_FILE);
        contracts.into_iter().for_each(|(code_hash, bytecode)| {
            validator_db
                .add_contract_code(&bytecode)
                .unwrap_or_else(|e| {
                    error!("Failed to add contract {code_hash} to database: {e}");
                    Err(e).unwrap()
                })
        });

        Ok(Arc::new(validator_db))
    }

    /// Set up mock RPC server with pre-loaded context and return the handle.
    async fn setup_mock_rpc_server(context: RpcModuleContext) -> jsonrpsee::server::ServerHandle {
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
            .register_method("eth_getWitness", |params, context, _| {
                let (hash_str,): (String,) = params.parse().unwrap();

                // Parse hash string to BlockHash
                let block_hash = parse_block_hash(&hash_str).map_err(|e| {
                    make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid block hash: {e}"))
                })?;

                // Look up witness data by block hash
                match context.witness_data.get(&block_hash) {
                    Some(salt_witness) => {
                        // Serialize SaltWitness back to Vec<u8> for RPC response
                        match bincode::serde::encode_to_vec(salt_witness, bincode::config::legacy())
                        {
                            Ok(witness_bytes) => Ok(witness_bytes),
                            Err(e) => Err(make_rpc_error(
                                CALL_EXECUTION_FAILED_CODE,
                                format!("Failed to serialize SaltWitness: {e}"),
                            )),
                        }
                    }
                    None => Err(make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Witness for block {hash_str} not found"),
                    )),
                }
            })
            .unwrap();

        let cfg = ServerConfigBuilder::default()
            .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
            .build();
        let server = ServerBuilder::default()
            .set_config(cfg)
            .build("0.0.0.0:59545")
            .await
            .unwrap();

        let handle = server.start(module);
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle
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
            .filter_map(|line| line.ok())
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

        // Load block data from TEST_BLOCK_DIR
        info!("Loading block data from {}", TEST_BLOCK_DIR);
        let test_block_dir = PathBuf::from(TEST_BLOCK_DIR);
        let block_entries = std::fs::read_dir(&test_block_dir).map_err(|e| {
            anyhow!(
                "Failed to read test block directory {}: {}",
                TEST_BLOCK_DIR,
                e
            )
        })?;

        let mut block_numbers = Vec::new();

        for entry in block_entries {
            let file = entry.map_err(|e| anyhow!("Failed to read directory entry: {}", e))?;
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
                        .map_err(|e| anyhow!("Failed to load block file {}: {}", file_str, e))?;

                    let block_hash = BlockHash::from(block.header.hash);

                    // Store block by hash and create number->hash mapping
                    blocks_by_hash.insert(block_hash, block);
                    block_hashes.insert(block_number, block_hash);
                    block_numbers.push(block_number);
                }
            }
        }

        if block_numbers.is_empty() {
            return Err(anyhow!("No valid block files found in {}", TEST_BLOCK_DIR));
        }

        block_numbers.sort_unstable();
        let min_block_num = *block_numbers.first().unwrap();
        let max_block_num = *block_numbers.last().unwrap();

        // Get the hashes for the minimum and maximum block numbers
        let min_block_hash = *block_hashes.get(&min_block_num).unwrap();
        let max_block_hash = *block_hashes.get(&max_block_num).unwrap();
        let min_block = (min_block_num, min_block_hash);
        let max_block = (max_block_num, max_block_hash);

        info!(
            "Loaded {} blocks (range: {} - {})",
            block_numbers.len(),
            min_block.0,
            max_block.0
        );

        // Load witness data from TEST_WITNESS_DIR
        info!("Loading witness data from {}", TEST_WITNESS_DIR);
        let test_witness_dir = PathBuf::from(TEST_WITNESS_DIR);
        if test_witness_dir.exists() {
            let witness_entries = std::fs::read_dir(&test_witness_dir)
                .map_err(|e| anyhow!("Failed to read test witness directory: {}", e))?;

            let mut witness_count = 0;
            for entry in witness_entries {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension().and_then(|s| s.to_str()) == Some("w") {
                    // Parse filename for block info
                    let block_num_and_hash = file_path.file_stem().unwrap().to_str().unwrap();
                    let (_, block_hash) = parse_block_num_and_hash(block_num_and_hash)?;

                    // Read and deserialize witness file
                    let file_data = std::fs::read(&file_path)?;
                    let state_data = deserialized_checksum_data(file_data).map_err(|e| {
                        anyhow!(
                            "Failed to deserialize state data from {}: {}",
                            block_num_and_hash,
                            e
                        )
                    })?;

                    let (witness_status, _): (WitnessStatus, usize) =
                        bincode::serde::decode_from_slice(
                            &state_data.data,
                            bincode::config::legacy(),
                        )
                        .map_err(|e| {
                            anyhow!(
                                "Failed to deserialize WitnessStatus from {}: {}",
                                block_num_and_hash,
                                e
                            )
                        })?;

                    // Extract and deserialize SaltWitness from WitnessStatus
                    let (salt_witness, _): (SaltWitness, usize) =
                        bincode::serde::decode_from_slice(
                            &witness_status.witness_data,
                            bincode::config::legacy(),
                        )
                        .map_err(|e| {
                            anyhow!(
                                "Failed to deserialize SaltWitness from WitnessStatus {}: {}",
                                block_num_and_hash,
                                e
                            )
                        })?;

                    witness_data.insert(block_hash, salt_witness);
                    witness_count += 1;
                }
            }
            info!("Loaded {} witness files", witness_count);
        } else {
            info!(
                "Witness directory {} does not exist, skipping witness data",
                TEST_WITNESS_DIR
            );
        }

        // Load contract data
        info!("Loading contract data from {}", CONTRACTS_FILE);
        let contracts = load_contracts(CONTRACTS_FILE);
        info!("Loaded {} contracts", contracts.len());

        Ok(RpcModuleContext {
            blocks_by_hash,
            block_hashes,
            witness_data,
            contracts,
            min_block,
            max_block,
        })
    }

    #[tokio::test]
    async fn integration_test() {
        tracing_subscriber::fmt::init();

        // Create RPC module context with pre-loaded test data
        info!("=== Creating RPC Module Context ===");
        let context = create_rpc_module_context().unwrap();
        info!(
            "Context created with {} blocks, {} witnesses, {} contracts",
            context.blocks_by_hash.len(),
            context.witness_data.len(),
            context.contracts.len()
        );
        info!(
            "Block range: {} - {}",
            context.min_block.0, context.max_block.0
        );

        let sync_target = Some(context.max_block.0);
        let validator_db = setup_test_db(&context).unwrap();
        let handle = setup_mock_rpc_server(context).await;
        let client = Arc::new(RpcClient::new("http://127.0.0.1:59545").unwrap());

        chain_sync(
            client.clone(),
            validator_db,
            1,
            Duration::from_millis(100),
            sync_target,
        )
        .await
        .unwrap();

        handle.stop().unwrap();
        info!("Mock RPC server has been shut down.");
    }
}
