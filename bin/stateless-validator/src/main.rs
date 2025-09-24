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
    executor::validate_block,
    validator_db::ValidationResult,
};

mod rpc;
use rpc::RpcClient;

mod witness_types;

/// Maximum response body size for the RPC server.
/// This is set to 100 MB to accommodate large block data and witness information.
const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

/// Database filename for the validator.
const VALIDATOR_DB_FILENAME: &str = "validator.redb";

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

    info!("Data directory: {}", args.datadir);
    info!("Lock time: {} seconds", args.lock_time);
    info!("API endpoint: {}", args.api);
    info!("Server port: {:?}", args.port);

    // Reserve 2 CPUs for the server if it's running, otherwise use all available CPUs.
    let concurrent_num = if args.port.is_some() {
        (num_cpus::get() - 2).max(1)
    } else {
        num_cpus::get()
    };
    info!("Number of concurrent tasks: {}", concurrent_num);

    let work_dir = PathBuf::from(args.datadir);

    let client = Arc::new(RpcClient::new(&args.api)?);
    let validator_db = setup_validator_db(work_dir.join(VALIDATOR_DB_FILENAME)).await?;

    let validator_logic = chain_sync(
        client.clone(),
        validator_db.clone(),
        concurrent_num,
        5,    // sync_interval_secs
        None, // sync_target (infinite sync)
    );

    if let Some(port) = args.port {
        let mut module = RpcModule::new(validator_db.clone());

        module.register_method("stateless_getValidation", |params, validator_db, _| {
            // Helper function to create RPC errors
            let make_rpc_error = |code, msg: String| ErrorObject::owned(code, msg, None::<()>);

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
        info!("Server listening on {}", addr);

        let handle = server.start(module);

        tokio::select! {
            res = validator_logic => res?,
            _ = handle.stopped() => {
                info!("Server has stopped.");
            },
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down.");
            }
        }
    } else {
        info!("Server not configured to start. Running validation logic only.");
        tokio::select! {
            res = validator_logic => res?,
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down.");
            }
        }
    }

    info!("Total execution time: {:?}", start.elapsed());
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

/// Setup ValidatorDB instance for production use
///
/// Creates a new ValidatorDB instance at the specified path, initializing all required tables.
/// This function is simpler than setup_test_db as it doesn't pre-populate test data.
async fn setup_validator_db(db_path: impl AsRef<std::path::Path>) -> Result<Arc<ValidatorDB>> {
    let validator_db = ValidatorDB::new(db_path)?;
    Ok(Arc::new(validator_db))
}

/// Returns all contract addresses and their code hashes from the witness.
///
/// Filters witness data to find accounts with non-empty bytecode, which are
/// needed for contract code fetching during block execution.
fn extract_contract_codes(salt_witness: &SaltWitness) -> Vec<(Address, B256)> {
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

/// Individual validation worker that processes blocks from the task queue
///
/// This worker operates in a continuous loop with robust error handling to ensure
/// operational resilience. Unlike the previous implementation, errors from infrastructure
/// components (database, RPC) are contained and logged rather than terminating the worker.
///
/// Each worker continuously:
/// 1. Claims the next validation task from ValidatorDB
/// 2. Performs block validation using the existing validate_block function
/// 3. Handles contract code caching as needed
/// 4. Records validation results back to ValidatorDB
///
/// # Error Handling Strategy
/// - **Infrastructure errors** (database, RPC failures): Logged and contained, worker continues
/// - **Validation errors** (state root mismatches): Recorded as failed ValidationResults
/// - **Task processing errors**: Individual task failures don't affect subsequent tasks
///
/// # Arguments
/// * `worker_id` - Unique identifier for this worker (for logging)
/// * `client` - RPC client for fetching contract bytecode as needed
/// * `validator_db` - Database interface for task coordination
///
/// # Returns
/// * `Result<()>` - Only returns on fatal errors that require worker restart
async fn validation_worker(
    worker_id: usize,
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
) -> Result<()> {
    info!("Validation worker {} started", worker_id);

    loop {
        // Process individual task with error containment
        if let Err(e) = process_single_task(worker_id, &client, &validator_db).await {
            error!(
                "Worker {} encountered error during task processing: {}",
                worker_id, e
            );
            // Continue to next iteration instead of terminating worker
        }

        // Small delay to prevent tight error loops
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Processes a single validation task with comprehensive error handling
///
/// This function encapsulates the complete workflow for processing one validation task,
/// including task acquisition, contract code fetching, block validation, and result storage.
/// All errors are propagated to the caller for centralized error handling.
///
/// # Workflow
/// 1. **Task Acquisition**: Get next pending validation task from database
/// 2. **Contract Fetching**: Retrieve required contract bytecode from cache or RPC
/// 3. **Block Validation**: Execute block using validate_block with witness data
/// 4. **Result Storage**: Record validation outcome in database
///
/// # Arguments
/// * `worker_id` - Unique identifier for this worker (for logging)
/// * `client` - RPC client for fetching contract bytecode from remote nodes
/// * `validator_db` - Database interface for task coordination and result storage
///
/// # Returns
/// * `Ok(())` - Task processed successfully (validation may have succeeded or failed)
/// * `Err(eyre::Error)` - Infrastructure error occurred (database, RPC, serialization)
///
/// # Error Categories
/// - **No tasks available**: Returns Ok() after brief sleep
/// - **Database errors**: Propagated to caller for retry logic
/// - **RPC errors**: Propagated to caller for retry logic
/// - **Validation errors**: Captured and stored as failed ValidationResult
async fn process_single_task(
    worker_id: usize,
    client: &RpcClient,
    validator_db: &ValidatorDB,
) -> Result<()> {
    // Step 1: Get next validation task atomically
    match validator_db.get_next_task()? {
        Some((block, witness)) => {
            let block_number = block.header.number;
            let block_hash = block.header.hash;

            info!("Worker {} validating block {}", worker_id, block_number);

            // Step 2: Handle contract code fetching using database cache only
            let contract_codes = extract_contract_codes(&witness);

            // Find contracts that need to be fetched from RPC
            let mut contracts_to_fetch = Vec::new();
            for (address, code_hash) in &contract_codes {
                // Check if we have it in the database cache
                match validator_db.get_contract_code(*code_hash) {
                    Ok(Some(_)) => {
                        // Already cached, no need to fetch
                    }
                    _ => {
                        // Not cached or error accessing cache, need to fetch from RPC
                        contracts_to_fetch.push(*address);
                    }
                }
            }

            // Fetch any missing contract codes from RPC
            if !contracts_to_fetch.is_empty() {
                let codes = client
                    .codes_at(&contracts_to_fetch, (block_number - 1).into())
                    .await?;

                for bytes in &codes {
                    let bytecode = Bytecode::new_raw(bytes.clone());
                    // Cache the bytecode in the database for other workers
                    // Ignore caching errors - validation can proceed without caching
                    let _ = validator_db.add_contract_code(&bytecode);
                }
            }

            // Step 3: Build contracts HashMap from database for validation
            let contracts: HashMap<B256, Bytecode> = contract_codes
                .iter()
                .filter_map(|(_, code_hash)| {
                    validator_db
                        .get_contract_code(*code_hash)
                        .ok()
                        .flatten()
                        .map(|bytecode| (*code_hash, bytecode))
                })
                .collect();

            // Extract pre-state root from witness before validation
            let pre_state_root = B256::from(witness.state_root()?);
            let validation_result = match validate_block(&block, witness, &contracts) {
                Ok(()) => {
                    info!(
                        "Worker {} successfully validated block {}",
                        worker_id, block_number
                    );
                    ValidationResult {
                        pre_state_root,
                        post_state_root: block.header.state_root,
                        block_number,
                        block_hash,
                        success: true,
                        error_message: None,
                        completed_at: SystemTime::now(),
                    }
                }
                Err(e) => {
                    error!(
                        "Worker {} failed to validate block {}: {}",
                        worker_id, block_number, e
                    );
                    ValidationResult {
                        pre_state_root,
                        post_state_root: block.header.state_root,
                        block_number,
                        block_hash,
                        success: false,
                        error_message: Some(e.to_string()),
                        completed_at: SystemTime::now(),
                    }
                }
            };

            // Step 4: Record validation result
            validator_db.complete_validation(validation_result)?;
        }
        None => {
            // No tasks available, wait a bit before checking again
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    Ok(())
}

/// Single iteration of the chain synchronizer logic
///
/// Processes completed validation results and advances the canonical chain by moving
/// successfully validated blocks from the remote chain to the canonical chain.
/// Also performs basic data pruning to maintain storage efficiency.
async fn chain_sync_iteration(_client: &RpcClient, validator_db: &ValidatorDB) -> Result<()> {
    let mut blocks_advanced = 0;

    // Continuously try to advance the canonical chain with newly validated blocks
    loop {
        match validator_db.grow_local_chain() {
            Ok(()) => {
                blocks_advanced += 1;
                // Continue to try advancing the next block
            }
            Err(e) => {
                // Cannot advance further - this could be due to:
                // - Remote chain is empty
                // - Next block is not validated yet
                // - Next block validation failed
                // - Chain continuity issues
                if blocks_advanced == 0 {
                    // Only log if we haven't advanced any blocks in this iteration
                    match e.to_string().as_str() {
                        msg if msg.contains("Remote chain is empty") => {
                            // This is normal when no blocks are queued
                        }
                        msg if msg.contains("not validated") => {
                            // This is normal when validation is still in progress
                        }
                        msg if msg.contains("failed validation") => {
                            warn!("Cannot advance chain due to failed validation: {}", e);
                        }
                        _ => {
                            warn!("Cannot advance chain: {}", e);
                        }
                    }
                }
                break; // Stop trying to advance
            }
        }
    }

    // Log current chain status
    match (
        validator_db.get_local_tip()?,
        validator_db.get_remote_tip()?,
    ) {
        (Some((local_number, local_hash)), Some((remote_number, remote_hash))) => {
            info!(
                "Chain status: local_tip=block {} ({}), remote_tip=block {} ({}), gap={}",
                local_number,
                local_hash,
                remote_number,
                remote_hash,
                remote_number.saturating_sub(local_number)
            );
        }
        (Some((local_number, local_hash)), None) => {
            info!(
                "Chain status: local_tip=block {} ({}), no remote chain",
                local_number, local_hash
            );
        }
        (None, Some((remote_number, remote_hash))) => {
            info!(
                "Chain status: no local chain, remote_tip=block {} ({})",
                remote_number, remote_hash
            );
        }
        (None, None) => {
            info!("Chain status: no local or remote chain established");
        }
    }

    // Report advancement progress
    if blocks_advanced > 0 {
        info!("Advanced canonical chain by {} blocks", blocks_advanced);
    }

    // Perform basic data pruning - keep last 1000 blocks
    if let Some((current_tip, _)) = validator_db.get_local_tip()? {
        const BLOCKS_TO_KEEP: u64 = 1000;
        if current_tip > BLOCKS_TO_KEEP {
            let prune_before = current_tip - BLOCKS_TO_KEEP;
            match validator_db.prune_history(prune_before) {
                Ok(()) => {
                    info!("Pruned block data before block {}", prune_before);
                }
                Err(e) => {
                    warn!("Failed to prune old block data: {}", e);
                }
            }
        }
    }

    Ok(())
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
/// * `sync_interval_secs` - Time to wait between sync cycles in seconds
/// * `sync_target` - Optional block height to sync to; None for infinite sync
async fn chain_sync(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    concurrent_num: usize,
    sync_interval_secs: u64,
    sync_target: Option<u64>,
) -> Result<()> {
    info!(
        "Starting chain synchronizer with {} validation workers",
        concurrent_num
    );

    // Step 1: Recover any interrupted tasks from previous crashes
    info!("Recovering interrupted validation tasks from previous runs...");
    validator_db
        .recover_interrupted_tasks()
        .map_err(|e| anyhow!("Failed to recover interrupted tasks: {}", e))?;
    info!("Task recovery completed");

    // Step 2: Spawn remote chain tracker
    info!("Starting remote chain tracker...");
    let _tracker_handle = {
        let client_clone = Arc::clone(&client);
        let validator_db_clone = Arc::clone(&validator_db);

        task::spawn(async move { remote_chain_tracker(client_clone, validator_db_clone).await })
    };
    info!("Remote chain tracker started");

    // Step 3: Spawn validation workers as tokio tasks
    info!("Spawning {} validation workers...", concurrent_num);
    let mut worker_handles = Vec::new();

    for worker_id in 0..concurrent_num {
        let client_clone = Arc::clone(&client);
        let validator_db_clone = Arc::clone(&validator_db);

        let handle = task::spawn(async move {
            validation_worker(worker_id, client_clone, validator_db_clone).await
        });

        worker_handles.push(handle);
    }
    info!("All validation workers started");

    // Step 4: Main chain synchronizer loop
    info!("Starting main chain synchronizer loop...");

    loop {
        // Check if we've reached the sync target
        if let Some(target) = sync_target {
            match validator_db.get_local_tip() {
                Ok(Some((local_block_number, _))) => {
                    if local_block_number >= target {
                        info!(
                            "Reached sync target height {}, terminating chain sync",
                            target
                        );
                        return Ok(());
                    }
                }
                Ok(None) => {
                    // No local tip yet, continue syncing
                }
                Err(e) => {
                    warn!("Failed to check local tip for sync target: {}", e);
                    // Continue running despite error
                }
            }
        }

        if let Err(e) = chain_sync_iteration(&client, &validator_db).await {
            error!("Chain sync iteration failed: {}", e);
            // Continue running despite errors - individual iterations can fail
        }

        // Wait before next sync cycle
        tokio::time::sleep(Duration::from_secs(sync_interval_secs)).await;
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
    const POLLING_INTERVAL_SECS: u64 = 5;

    info!(
        "Starting remote chain tracker with {} block lookahead",
        LOOKAHEAD_BLOCKS
    );

    loop {
        // Perform one iteration of remote chain tracking
        if let Err(e) = async {
            // Step 1: Get current chain tips
            let local_tip = validator_db
                .get_local_tip()?
                .ok_or_else(|| anyhow!("Local chain is empty - cannot track remote chain"))?;

            let remote_tip = validator_db.get_remote_tip()?.unwrap_or(local_tip); // If no remote chain, start from local tip

            // Step 2: Analyze gap between local and remote tips
            let gap = remote_tip.0.saturating_sub(local_tip.0);
            info!(
                "Chain status: local_tip={}, remote_tip={}, gap={}",
                local_tip.0, remote_tip.0, gap
            );

            // Step 3: Check if we are still on the right chain (detect reorgs)
            match client.block_by_number(remote_tip.0, false).await {
                Ok(block) => {
                    if block.header.hash != remote_tip.1 {
                        error!(
                            "Remote tip hash mismatch! Expected: {}, got: {}. Triggering rollback.",
                            remote_tip.1, block.header.hash
                        );
                        // FIXME: Find proper common ancestor between local and remote chains
                        // For now, rollback to local tip as a simple approximation
                        validator_db.rollback_chain(local_tip.0)?;
                        return Ok(());
                    }
                }
                Err(e) => {
                    // Network error - don't rollback eagerly, it may be just a network glitch
                    warn!(
                        "Failed to validate remote tip {} (network issue): {}. Continuing without rollback.",
                        remote_tip.1, e
                    );
                }
            }

            if gap >= LOOKAHEAD_BLOCKS {
                info!("Sufficient lookahead maintained (gap: {})", gap);
                return Ok(());
            }

            // Step 4: Fetch more blocks to maintain lookahead
            let blocks_to_fetch = (LOOKAHEAD_BLOCKS - gap).min(20); // Limit to 20 blocks per iteration
            let start_block = remote_tip.0 + 1;
            let end_block = start_block + blocks_to_fetch - 1;

            info!(
                "Fetching {} blocks (range: {} to {}) to maintain lookahead",
                blocks_to_fetch, start_block, end_block
            );

            // Step 4.1: Fetch blocks and witnesses, queue for validation, return headers
            let fetch_tasks: Vec<_> = (start_block..=end_block)
                .map(|block_number| {
                    let client_clone = client.clone();
                    let validator_db_clone = validator_db.clone();
                    tokio::spawn(async move {
                        // Fetch block first
                        let block = client_clone.block_by_number(block_number, true).await?;
                        // Then fetch witness using block hash
                        let witness = client_clone.witness_by_block_hash(block.header.hash).await?;

                        // Immediately queue for validation while we have both
                        validator_db_clone.add_validation_task(&block, &witness)?;
                        info!("Queued block {} for validation", block.header.number);

                        // Return only the header (has block number + hash for grow_remote_chain)
                        Ok::<Header, eyre::Error>(block.header)
                    })
                })
                .collect();

            // Step 4.2: Wait for all fetches to complete, handling individual failures
            let fetch_results = future::join_all(fetch_tasks).await;

            // Step 4.3: Process results and ensure contiguous headers
            let mut header_results = Vec::new();
            for (i, task_result) in fetch_results.into_iter().enumerate() {
                let expected_block_number = start_block + i as u64;
                match task_result {
                    Ok(Ok(header)) => {
                        header_results.push(Ok(header));
                    }
                    Ok(Err(rpc_error)) => {
                        error!("RPC error fetching block/witness {}: {}", expected_block_number, rpc_error);
                        header_results.push(Err(rpc_error));
                    }
                    Err(join_error) => {
                        error!("Task join error for block {}: {}", expected_block_number, join_error);
                        header_results.push(Err(join_error.into()));
                    }
                }
            }

            // Step 4.4: Ensure contiguity - stop at first failure
            let mut fetched_headers = Vec::new();
            for result in header_results {
                match result {
                    Ok(header) => {
                        fetched_headers.push(header);
                    }
                    Err(e) => {
                        // Can't get block number from failed header, use index instead
                        let failed_block_number = start_block + fetched_headers.len() as u64;
                        error!(
                            "Failed to fetch block {}: {}. Stopping to maintain contiguity.",
                            failed_block_number, e
                        );
                        // Stop at first gap to maintain contiguity
                        break;
                    }
                }
            }

            if fetched_headers.len() < blocks_to_fetch as usize {
                info!(
                    "Fetched {} out of {} requested blocks due to failures. Will retry missing blocks in next iteration.",
                    fetched_headers.len(),
                    blocks_to_fetch
                );
            }

            // Step 4.5: Add headers to remote chain
            for header in fetched_headers {
                match validator_db.grow_remote_chain(&header) {
                    Ok(()) => {
                        info!("Added block {} to remote chain", header.number);
                    }
                    Err(e) => {
                        error!(
                            "Failed to add block {} to remote chain: {}",
                            header.number, e
                        );
                        // Stop processing to avoid gaps in the chain
                        break;
                    }
                }
            }

            Ok::<(), eyre::Error>(())
        }.await {
            error!("Remote chain tracker iteration failed: {}", e);
            // Continue running despite errors - individual iterations can fail
        }

        // Wait before next iteration
        tokio::time::sleep(Duration::from_secs(POLLING_INTERVAL_SECS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness_types::WitnessStatus;
    use alloy_primitives::BlockNumber;
    use alloy_rpc_types_eth::Block;
    use eyre::Context;
    use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned};
    use op_alloy_rpc_types::Transaction;
    use serde::de::DeserializeOwned;
    use std::{
        collections::BTreeMap,
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };
    use validator_core::deserialized_state_data;

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
    fn setup_test_db() -> Result<Arc<ValidatorDB>> {
        let temp_dir = tempfile::tempdir()
            .map_err(|e| anyhow!("Failed to create temporary directory: {e}"))?;
        let work_dir = temp_dir.path().to_path_buf();

        // Create ValidatorDB with database
        let db_path = work_dir.join(VALIDATOR_DB_FILENAME);
        let validator_db = ValidatorDB::new(&db_path)?;

        // Initialize canonical chain tip using RpcModuleContext
        let context = create_rpc_module_context()?;
        let local_tip = context.min_block;

        // Set the canonical chain tip to the starting block (parent of minimum test block)
        // For test setup, we need to get the state root from the block header
        let local_tip_block = context.blocks_by_hash.get(&local_tip.1).ok_or_else(|| {
            anyhow!(
                "Local tip block hash {} not found in test context",
                local_tip.1
            )
        })?;
        validator_db.set_local_tip(local_tip.0, local_tip.1, local_tip_block.header.state_root)?;

        // Populate CONTRACTS table with test contract bytecode
        info!("Populating CONTRACTS table from test data...");
        let contracts = load_contracts(CONTRACTS_FILE);
        let mut contracts_added = 0;

        for (code_hash, bytecode) in contracts {
            match validator_db.add_contract_code(&bytecode) {
                Ok(()) => {
                    contracts_added += 1;
                }
                Err(e) => {
                    error!("Failed to add contract {code_hash} to database: {e}");
                    return Err(e);
                }
            }
        }

        info!("Successfully populated CONTRACTS table with {contracts_added} contracts");

        // Keep the temp dir alive by leaking it. OS will clean it when test process ends.
        std::mem::forget(temp_dir);

        Ok(Arc::new(validator_db))
    }

    /// Set up mock RPC server with pre-loaded context and return the handle.
    async fn setup_mock_rpc_server(context: RpcModuleContext) -> jsonrpsee::server::ServerHandle {
        let mut module = RpcModule::new(context);

        module
            .register_method("eth_getBlockByHash", |params, context, _| {
                let (hash_str, full_block): (String, bool) = params.parse().unwrap();

                // Parse hash string to BlockHash
                let block_hash = match parse_block_hash(&hash_str) {
                    Ok(hash) => hash,
                    Err(e) => {
                        return Err(ErrorObject::owned(
                            INVALID_PARAMS_CODE,
                            format!("Invalid block hash: {}", e),
                            None::<()>,
                        ));
                    }
                };

                // Look up block in context
                match context.blocks_by_hash.get(&block_hash) {
                    Some(block) => {
                        let result_block = if full_block {
                            block.clone()
                        } else {
                            Block {
                                transactions: block.transactions.clone().into_hashes(),
                                ..block.clone()
                            }
                        };
                        Ok(result_block)
                    }
                    None => Err(ErrorObject::owned(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Block {} not found", hash_str),
                        None::<()>,
                    )),
                }
            })
            .unwrap();

        module
            .register_method("eth_getBlockByNumber", |params, context, _| {
                let (hex_number, full_block): (String, bool) = params.parse().unwrap();

                let block_number = if hex_number == "finalized" {
                    // Return the smallest block number for "finalized" tag
                    context.min_block.0
                } else {
                    // Parse hex number as before
                    u64::from_str_radix(&hex_number[2..], 16).unwrap_or(0)
                };

                // Look up block hash by number, then get block by hash
                match context.block_hashes.get(&block_number) {
                    Some(block_hash) => match context.blocks_by_hash.get(block_hash) {
                        Some(block) => {
                            let result_block = if full_block {
                                block.clone()
                            } else {
                                Block {
                                    transactions: block.transactions.clone().into_hashes(),
                                    ..block.clone()
                                }
                            };
                            Ok(result_block)
                        }
                        None => Err(ErrorObject::owned(
                            CALL_EXECUTION_FAILED_CODE,
                            format!("Block data not found for number {}", block_number),
                            None::<()>,
                        )),
                    },
                    None => Err(ErrorObject::owned(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Block {} not found", block_number),
                        None::<()>,
                    )),
                }
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
                let block_hash = match parse_block_hash(&hash_str) {
                    Ok(hash) => hash,
                    Err(e) => {
                        return Err(ErrorObject::owned(
                            INVALID_PARAMS_CODE,
                            format!("Invalid block hash: {}", e),
                            None::<()>,
                        ));
                    }
                };

                // Look up witness data by block hash
                match context.witness_data.get(&block_hash) {
                    Some(salt_witness) => {
                        // Serialize SaltWitness back to Vec<u8> for RPC response
                        match bincode::serde::encode_to_vec(salt_witness, bincode::config::legacy())
                        {
                            Ok(witness_bytes) => Ok(witness_bytes),
                            Err(e) => Err(ErrorObject::owned(
                                CALL_EXECUTION_FAILED_CODE,
                                format!("Failed to serialize SaltWitness: {}", e),
                                None::<()>,
                            )),
                        }
                    }
                    None => Err(ErrorObject::owned(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Witness for block {} not found", hash_str),
                        None::<()>,
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
                    let state_data = deserialized_state_data(file_data).map_err(|e| {
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

        let max_block_number = context.max_block.0;
        let handle = setup_mock_rpc_server(context).await;
        let client = Arc::new(RpcClient::new("http://127.0.0.1:59545").unwrap());

        // Verify new RPC methods work correctly
        info!("=== Testing Enhanced RPC Methods ===");

        // Test eth_blockNumber method
        let latest_block = client.block_number().await.unwrap();
        info!("Latest block number from RPC: {}", latest_block);

        // Test eth_getBlockByNumber with "finalized" tag
        let finalized_block = client
            .block_by_number_tag("finalized", false)
            .await
            .unwrap();
        info!(
            "Finalized block: number={}, hash={}",
            finalized_block.header.number, finalized_block.header.hash
        );

        // Test regular block number query for comparison
        let regular_block = client.block_by_number(latest_block, false).await.unwrap();
        info!(
            "Latest block: number={}, hash={}",
            regular_block.header.number, regular_block.header.hash
        );

        info!("=== RPC Method Verification Complete ===");

        let validator_db = setup_test_db().unwrap();

        // Test the new chain_sync architecture instead of manual validation
        let worker_count = 4; // Number of parallel validation workers
        let sync_interval = 1; // Sync interval in seconds for testing

        chain_sync(
            client.clone(),
            validator_db,
            worker_count,
            sync_interval,
            Some(max_block_number),
        )
        .await
        .unwrap();

        handle.stop().unwrap();
        info!("Mock RPC server has been shut down.");
    }
}
