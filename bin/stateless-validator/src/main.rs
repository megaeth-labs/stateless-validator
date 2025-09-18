use alloy_primitives::{Address, BlockHash, hex};
use clap::Parser;
use eyre::{Result, anyhow};
use futures::stream::{self, StreamExt};
use jsonrpsee::{
    RpcModule,
    server::{ServerBuilder, ServerConfigBuilder},
};
use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, ErrorObject, INVALID_PARAMS_CODE};
use revm::{
    primitives::{B256, HashMap, KECCAK_EMPTY},
    state::Bytecode,
};
use salt::SaltWitness;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{signal, sync::Mutex, task};
use tracing::{error, info};
use validator_core::{
    SaltWitnessState, ValidateStatus, ValidatorDB, ValidatorDB2, curent_time_to_u64,
    data_types::{PlainKey, PlainValue},
    executor::validate_block,
    validator_db2::ValidationResult,
};

mod rpc;
use rpc::RpcClient;

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
    let validator_db = Arc::new(ValidatorDB::new(work_dir.join(VALIDATOR_DB_FILENAME))?);

    // fetch the latest finalized block number.
    let chain_status = validator_db.get_chain_status()?;
    let finalized_num = chain_status.block_number;

    // Start validating from the block after the last finalized one.
    let block_counter = finalized_num + 1;
    let validator_logic = scan_and_validate(
        client,
        validator_db.clone(),
        block_counter,
        args.lock_time,
        concurrent_num,
    );

    if let Some(port) = args.port {
        let mut module = RpcModule::new(validator_db.clone());

        module.register_method("stateless_getValidation", |params, validator_db, _| {
            // Helper function to create RPC errors
            let make_rpc_error = |code, msg: String| ErrorObject::owned(code, msg, None::<()>);

            let (block_number, block_hash): (u64, String) = params.parse()?;
            let block_hash = parse_block_hash(&block_hash).map_err(|e| {
                make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid block hash: {e}"))
            })?;

            validator_db
                .get_validation_result(block_number, block_hash)
                .map_err(|e| make_rpc_error(CALL_EXECUTION_FAILED_CODE, e.to_string()))
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

/// Scans for and validates block witnesses concurrently.
///
/// This function creates a stream of block numbers starting from `block_counter` and processes them
/// concurrently.
async fn scan_and_validate(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    block_counter: u64,
    lock_time: u64,
    concurrent_num: usize,
) -> Result<()> {
    // TODO: populate the initial contract cache from an external db instance
    // Start with an empty contract cache.
    let contracts = Arc::new(Mutex::new(HashMap::default()));

    // Create an infinite stream of block numbers to process.
    stream::iter(block_counter..)
        .for_each_concurrent(Some(concurrent_num), |block_counter| {
            let client = Arc::clone(&client);
            let validator_db = Arc::clone(&validator_db);
            let contracts = Arc::clone(&contracts);

            async move {
                // Continuously validate blocks, retrying on failure until the block becomes stale.
                // The loop breaks if validation succeeds or if the block is older than the
                // latest finalized block.
                while let Err(e) = wait_and_validate(
                    client.clone(),
                    validator_db.clone(),
                    block_counter,
                    lock_time,
                    contracts.clone(),
                )
                .await
                {
                    error!(
                        "Failed to validate block {}: {:?}, try block({}) again",
                        block_counter, e, block_counter
                    );
                    let chain_status = validator_db.get_chain_status().unwrap_or_default();
                    if block_counter <= chain_status.block_number {
                        info!(
                            "block({}) is less than finalized block({}), skipping",
                            block_counter, chain_status.block_number
                        );
                        break;
                    }
                }
            }
        })
        .await;

    Ok(())
}

// FIXME: any code that can be reused by other stateless validator deployments?
// if yes, they should be moved into the library.
/// Performs the validation for a single block.
///
/// This function handles the entire lifecycle of validating a block:
/// 1. Waits for the block's witness to become available.
/// 2. Checks if the block needs validation and locks it.
/// 3. Fetches block data and decodes the witness.
/// 4. Verifies the witness proof.
/// 5. Fetches any new contract bytecodes.
/// 6. Replays the block transactions using an in-memory DB with the witness provider.
/// 7. Computes the new state root and compares it with the one in the block header.
/// 8. Updates the validation status of the block.
async fn wait_and_validate(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    block_counter: u64,
    lock_time: u64,
    contracts: Arc<Mutex<HashMap<B256, Bytecode>>>,
) -> Result<()> {
    info!("Processing block: {}", block_counter);

    // This loop waits for the witness for the block to be generated and available.
    loop {
        let block_hashes = match validator_db.find_block_hashes(block_counter) {
            Ok(hashes) => hashes,
            Err(_e) => {
                // Witness for block_counter not found, waiting...
                info!("Witness for block {} not found, waiting...", block_counter);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        for block_hash in block_hashes {
            let witness_status = validator_db.get_witness_state(&(block_counter, block_hash))?;
            if matches!(
                witness_status.status,
                SaltWitnessState::Idle | SaltWitnessState::Processing
            ) {
                // Wait for the witness to be completed.
                tokio::time::sleep(Duration::from_secs(5)).await;
                // start with while loop to handle this block hash again
                break;
            }

            let validate_info = validator_db.load_validate_info(block_counter, block_hash)?;
            // Check if the block has already been validated or is being processed by another validator.
            match validate_info.status {
                ValidateStatus::Success => {
                    info!(
                        "Block {} has already been validated with result: {:?}",
                        block_counter, validate_info.status
                    );
                    return Ok(());
                }
                ValidateStatus::Processing if validate_info.lock_time >= curent_time_to_u64() => {
                    info!(
                        "Block {} is currently being processed by another validator.",
                        block_counter
                    );
                    return Ok(());
                }
                ValidateStatus::Failed => {
                    info!("Block {} validation failed, replay again...", block_counter);
                    // Continue to retry this block hash
                    break;
                }
                _ => {} // Continue with processing
            }
            // Lock the block for processing to prevent other validators from working on it.
            validator_db.set_validate_status(
                block_counter,
                block_hash,
                ValidateStatus::Processing,
                None,
                Some(lock_time),
            )?;

            // Fetch the full block details and decode the witness concurrently.
            let witness_bytes = witness_status.witness_data;
            let (blocks_result, witness_decode_result) = {
                let witness_bytes_clone = witness_bytes.clone();
                tokio::join!(
                    client.block_by_hash(block_hash, true),
                    tokio::task::spawn_blocking(move || {
                        bincode::serde::decode_from_slice(
                            &witness_bytes_clone,
                            bincode::config::legacy(),
                        )
                        .map_err(|e| anyhow!("Failed to parse witness: {e}"))
                    })
                )
            };

            let block = blocks_result?;
            let (salt_witness, _size): (SaltWitness, usize) = witness_decode_result??;

            let old_state_root = get_root(
                client.as_ref(),
                &validator_db,
                block_counter - 1,
                block.header.parent_hash,
            )
            .await?;

            let contract_codes = extract_contract_codes(&salt_witness);

            let mut contracts_guard = contracts.lock().await;

            let new_contracts_address = contract_codes
                .iter()
                .filter_map(|(address, code_hash)| {
                    if !contracts_guard.contains_key(code_hash) {
                        Some(*address)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            let codes = client
                .codes_at(&new_contracts_address, (block_counter - 1).into())
                .await?;

            let mut new_contracts = HashMap::new();
            for bytes in &codes {
                let bytecode = Bytecode::new_raw(bytes.clone());
                new_contracts.insert(bytecode.hash_slow(), bytecode.clone());
            }

            contracts_guard.extend(new_contracts.clone());

            // Perform the actual block validation
            match validate_block(&block, salt_witness, old_state_root, &contracts_guard) {
                Ok(()) => {
                    info!(
                        "Validation SUCCESS for block {}. State root: 0x{}",
                        block_counter,
                        hex::encode(block.header.state_root)
                    );
                    validator_db.set_validate_status(
                        block_counter,
                        block_hash,
                        ValidateStatus::Success,
                        Some(block.header.state_root),
                        None,
                    )?;
                    return Ok(());
                }
                Err(validation_error) => {
                    error!(
                        "Validation FAILED for block {}: {}",
                        block_counter, validation_error
                    );
                    validator_db.set_validate_status(
                        block_counter,
                        block_hash,
                        ValidateStatus::Failed,
                        Some(block.header.state_root),
                        None,
                    )?;
                }
            }
            drop(contracts_guard);
        }
    }
}

/// Retrieves the state root for a given block number.
///
/// It first attempts to find the state root from the local validation files. If not found, it
/// falls back to fetching the block from the RPC endpoint.
async fn get_root(
    client: &RpcClient,
    validator_db: &ValidatorDB,
    block_number: u64,
    block_hash: B256,
) -> Result<B256> {
    let validate_info = validator_db.load_validate_info(block_number, block_hash)?;
    if validate_info.state_root.is_zero() {
        // If state root is not in our validation records, fetch from RPC.
        let block = client.block_by_number(block_number, false).await?;
        return Ok(block.header.state_root);
    }

    Ok(validate_info.state_root)
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
/// Each worker continuously:
/// 1. Claims the next validation task from ValidatorDB2
/// 2. Performs block validation using the existing validate_block function
/// 3. Handles contract code caching as needed
/// 4. Records validation results back to ValidatorDB2
///
/// # Arguments
/// * `worker_id` - Unique identifier for this worker (for logging)
/// * `client` - RPC client for fetching contract bytecode as needed
/// * `validator_db2` - Database interface for task coordination
async fn validation_worker(
    worker_id: usize,
    client: Arc<RpcClient>,
    validator_db2: Arc<ValidatorDB2>,
) -> Result<()> {
    info!("Validation worker {} started", worker_id);

    // Contract cache shared by this worker (following current architecture)
    let contracts = Arc::new(Mutex::new(HashMap::default()));

    loop {
        // Step 1: Get next validation task atomically
        match validator_db2.get_next_task()? {
            Some((block, witness)) => {
                let block_number = block.header.number;
                let block_hash = block.header.hash;

                info!("Worker {} validating block {}", worker_id, block_number);

                // Step 2: Get the previous state root for validation
                // TODO: This logic should be improved to handle the parent block properly
                let old_state_root = if block_number > 0 {
                    // For now, use a placeholder - this needs proper implementation
                    block.header.parent_hash
                } else {
                    B256::ZERO
                };

                // Step 3: Handle contract code fetching (following existing pattern)
                let contract_codes = extract_contract_codes(&witness);
                let mut contracts_guard = contracts.lock().await;

                let new_contracts_address = contract_codes
                    .iter()
                    .filter_map(|(address, code_hash)| {
                        if !contracts_guard.contains_key(code_hash) {
                            // Check if we have it in the database cache first
                            match validator_db2.get_contract_code(*code_hash) {
                                Ok(Some(bytecode)) => {
                                    contracts_guard.insert(*code_hash, bytecode);
                                    None
                                }
                                _ => Some(*address),
                            }
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                // Fetch any missing contract codes from RPC
                if !new_contracts_address.is_empty() {
                    let codes = client
                        .codes_at(&new_contracts_address, (block_number - 1).into())
                        .await?;

                    for bytes in &codes {
                        let bytecode = Bytecode::new_raw(bytes.clone());
                        let code_hash = bytecode.hash_slow();
                        contracts_guard.insert(code_hash, bytecode.clone());

                        // Cache the bytecode in the database for other workers
                        validator_db2.add_contract_code(&bytecode)?;
                    }
                }

                // Step 4: Perform validation using existing validate_block function
                let validation_result =
                    match validate_block(&block, witness, old_state_root, &contracts_guard) {
                        Ok(()) => {
                            info!(
                                "Worker {} successfully validated block {}",
                                worker_id, block_number
                            );
                            ValidationResult {
                                block_number,
                                block_hash,
                                success: true,
                                error_message: None,
                                completed_at: curent_time_to_u64(),
                            }
                        }
                        Err(e) => {
                            error!(
                                "Worker {} failed to validate block {}: {}",
                                worker_id, block_number, e
                            );
                            ValidationResult {
                                block_number,
                                block_hash,
                                success: false,
                                error_message: Some(e.to_string()),
                                completed_at: curent_time_to_u64(),
                            }
                        }
                    };

                // Step 5: Record validation result
                validator_db2.complete_validation(validation_result)?;

                drop(contracts_guard);
            }
            None => {
                // No tasks available, wait a bit before checking again
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Single iteration of the chain synchronizer logic
///
/// Performs one cycle of chain synchronization:
/// 1. Monitor chain head progression
/// 2. Track block finality status
/// 3. Detect and handle reorganizations
/// 4. Fetch new blocks and witnesses
/// 5. Create validation tasks
/// 6. Process validation results and advance canonical chain
/// 7. Prune old data
async fn chain_sync_iteration(_client: &RpcClient, validator_db2: &ValidatorDB2) -> Result<()> {
    // TODO: Implement chain head monitoring
    // Need to add RPC methods to get latest block number and finalized block number

    // TODO: Implement block fetching and witness handling
    // Need to determine source of witness data (not specified in current RPC client)

    // TODO: Implement result processing and chain growth
    // Process completed validation results and advance canonical chain

    // TODO: Implement reorganization detection
    // Compare local canonical tip with remote chain head

    // TODO: Implement data pruning
    // Remove old block data beyond retention policy

    // Placeholder implementation - just log that we're running
    if let Some((tip_number, tip_hash)) = validator_db2.get_canonical_tip()? {
        info!(
            "Current canonical tip: block {} hash {}",
            tip_number, tip_hash
        );
    } else {
        info!("No canonical chain established yet");
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
/// - Creates validation tasks and stores them in ValidatorDB2 for validation workers
/// - Processes validation results to drive local chain tip progression
/// - Prunes old block and witness data to maintain constant storage overhead
/// - Coordinates with parallel validation workers via ValidatorDB2
///
/// # Arguments
/// * `client` - RPC client for communicating with remote blockchain node
/// * `validator_db2` - Database interface for coordinating with validation workers
/// * `concurrent_num` - Number of parallel validation workers to spawn
/// * `sync_interval_secs` - Time to wait between sync cycles in seconds
async fn chain_sync(
    client: Arc<RpcClient>,
    validator_db2: Arc<ValidatorDB2>,
    concurrent_num: usize,
    sync_interval_secs: u64,
) -> Result<()> {
    info!(
        "Starting chain synchronizer with {} validation workers",
        concurrent_num
    );

    // Step 1: Recover any interrupted tasks from previous crashes
    info!("Recovering interrupted validation tasks from previous runs...");
    validator_db2
        .recover_interrupted_tasks()
        .map_err(|e| anyhow!("Failed to recover interrupted tasks: {}", e))?;
    info!("Task recovery completed");

    // Step 2: Spawn validation workers as tokio tasks
    info!("Spawning {} validation workers...", concurrent_num);
    let mut worker_handles = Vec::new();

    for worker_id in 0..concurrent_num {
        let client_clone = Arc::clone(&client);
        let validator_db2_clone = Arc::clone(&validator_db2);

        let handle = task::spawn(async move {
            validation_worker(worker_id, client_clone, validator_db2_clone).await
        });

        worker_handles.push(handle);
    }
    info!("All validation workers started");

    // Step 3: Main chain synchronizer loop
    info!("Starting main chain synchronizer loop...");

    loop {
        if let Err(e) = chain_sync_iteration(&client, &validator_db2).await {
            error!("Chain sync iteration failed: {}", e);
            // Continue running despite errors - individual iterations can fail
        }

        // Wait before next sync cycle
        tokio::time::sleep(Duration::from_secs(sync_interval_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::BlockNumber;
    use alloy_rpc_types_eth::Block;
    use eyre::Context;
    use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned};
    use op_alloy_rpc_types::Transaction;
    use serde::de::DeserializeOwned;
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };
    use validator_core::{WitnessStatus, deserialized_state_data};

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

    /// Block identifier used to locate test block data files.
    ///
    /// This enum represents the two ways to identify a blockchain block:
    /// by its unique hash or by its sequential number in the chain.
    #[derive(Debug)]
    enum BlockId {
        /// Block identified by its hash (e.g., "0xabc123...")
        Hash(String),
        /// Block identified by its number (e.g., 280)
        Number(u64),
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

    /// Creates a ValidatorDB populated with test witness data for integration testing.
    ///
    /// Sets up a temporary database and loads witness files from `TEST_WITNESS_DIR`
    /// (files with `.w` extension). The temporary directory will be cleaned up
    /// automatically after the test ends.
    ///
    /// # Returns
    ///
    /// `Arc<ValidatorDB>` - Database instance with loaded test data
    ///
    /// # Errors
    ///
    /// Returns error if directory creation, file I/O, or witness deserialization fails.
    fn setup_test_db() -> Result<Arc<ValidatorDB>> {
        let temp_dir = tempfile::tempdir()
            .map_err(|e| anyhow!("Failed to create temporary directory: {e}"))?;
        let work_dir = temp_dir.path().to_path_buf();

        // Create ValidatorDB with database
        let db_path = work_dir.join(VALIDATOR_DB_FILENAME);
        let validator_db = ValidatorDB::new(&db_path)?;

        // Load witness files and populate database
        let test_witness_dir = PathBuf::from(TEST_WITNESS_DIR);
        if test_witness_dir.exists() {
            for entry in std::fs::read_dir(&test_witness_dir)
                .map_err(|e| anyhow!("Failed to read test witness directory: {e}"))?
            {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension().and_then(|s| s.to_str()) == Some("w") {
                    // Parse filename for block info
                    let block_num_and_hash = file_path.file_stem().unwrap().to_str().unwrap();
                    let (block_number, block_hash) = parse_block_num_and_hash(block_num_and_hash)?;

                    // Read and deserialize witness file
                    let file_data = std::fs::read(&file_path)?;
                    let state_data = deserialized_state_data(file_data).map_err(|e| {
                        anyhow!("Failed to deserialize state data from {block_num_and_hash}: {e}")
                    })?;

                    let (witness_status, _): (WitnessStatus, usize) =
                        bincode::serde::decode_from_slice(
                            &state_data.data,
                            bincode::config::legacy(),
                        )
                        .map_err(|e| {
                            anyhow!(
                                "Failed to deserialize WitnessStatus from {block_num_and_hash}: {e}"
                            )
                        })?;

                    // Add to database using network-style interface
                    validator_db.add_new_block(
                        block_number,
                        block_hash,
                        witness_status.parent_hash,
                        witness_status.pre_state_root,
                        witness_status.witness_data,
                        witness_status.blob_ids,
                    )?;
                }
            }
        }

        // Keep the temp dir alive by leaking it. OS will clean it when test process ends.
        std::mem::forget(temp_dir);

        Ok(Arc::new(validator_db))
    }

    /// Set up mock RPC server and return the handle.
    async fn setup_mock_rpc_server() -> jsonrpsee::server::ServerHandle {
        let mut module = RpcModule::new(());

        module
            .register_method("eth_getBlockByHash", |params, _, _| {
                let (hash, full_block): (String, bool) = params.parse().unwrap();
                load_test_block(BlockId::Hash(hash), full_block)
            })
            .unwrap();

        module
            .register_method("eth_getBlockByNumber", |params, _, _| {
                let (hex_number, full_block): (String, bool) = params.parse().unwrap();

                let number = if hex_number == "finalized" {
                    // Return the smallest block number for "finalized" tag
                    match load_test_block_range() {
                        Ok((min_block, _)) => min_block,
                        Err(_) => {
                            return Err(ErrorObject::owned(
                                CALL_EXECUTION_FAILED_CODE,
                                "Failed to determine block range".to_string(),
                                None::<()>,
                            ));
                        }
                    }
                } else {
                    // Parse hex number as before
                    u64::from_str_radix(&hex_number[2..], 16).unwrap_or(0)
                };

                load_test_block(BlockId::Number(number), full_block)
            })
            .unwrap();

        module
            .register_method("eth_blockNumber", |_params, _, _| {
                // Return the largest block number available in test data
                match load_test_block_range() {
                    Ok((_, max_block)) => Ok(format!("0x{:x}", max_block)),
                    Err(e) => Err(ErrorObject::owned(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Failed to determine block range: {}", e),
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

    /// Loads a block from test data files for mock RPC server responses.
    ///
    /// This function searches the test block directory for files matching the given
    /// block identifier and returns the block data in the format expected by
    /// JSON-RPC clients.
    ///
    /// # Arguments
    ///
    /// * `block_id` - The block identifier (hash or number) to search for
    /// * `transaction_details` - If true, returns full transaction objects;
    ///                          if false, returns only transaction hashes
    ///
    /// # Returns
    ///
    /// Returns `Ok(Block<Transaction>)` if the block is found and successfully loaded.
    /// Returns an `ErrorObjectOwned` compatible with jsonrpsee RPC error handling if:
    /// - Block file is not found
    /// - Directory cannot be read
    /// - JSON parsing fails
    fn load_test_block(
        block_id: BlockId,
        full_block: bool,
    ) -> Result<Block<Transaction>, ErrorObjectOwned> {
        // Helper function to check if a given file contains the desired block
        let find_block_data = |filename: &str| match block_id {
            BlockId::Hash(ref hash) => filename.contains(hash),
            BlockId::Number(number) => filename.starts_with(&format!("{number}.")),
        };

        // Convert errors to ErrorObjectOwned
        let to_rpc_error =
            |msg: String| ErrorObject::owned(CALL_EXECUTION_FAILED_CODE, msg, None::<()>);

        // Find and load the matching file
        std::fs::read_dir(TEST_BLOCK_DIR)
            .map_err(|e| to_rpc_error(format!("Failed to read directory: {e}")))?
            .find_map(|entry| {
                let file = entry.ok()?;
                let file_name = file.file_name();
                if find_block_data(&file_name.to_string_lossy()) {
                    let block: Block<Transaction> = load_json(file.path()).ok()?;
                    Some(if full_block {
                        block
                    } else {
                        Block {
                            transactions: block.transactions.clone().into_hashes(),
                            ..block.clone()
                        }
                    })
                } else {
                    None
                }
            })
            .ok_or_else(|| to_rpc_error(format!("Block {block_id:?} not found")))
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

    /// Scans test block directory and returns the range of available block numbers
    ///
    /// This function reads all files in TEST_BLOCK_DIR and extracts block numbers
    /// from filenames in the format "{block_number}.{block_hash}.json".
    ///
    /// # Returns
    /// * `Ok((min_block, max_block))` - Range of available block numbers
    /// * `Err(eyre::Error)` - If directory cannot be read or no valid blocks found
    fn load_test_block_range() -> Result<(u64, u64)> {
        let test_block_dir = PathBuf::from(TEST_BLOCK_DIR);

        let entries = std::fs::read_dir(&test_block_dir).map_err(|e| {
            anyhow!(
                "Failed to read test block directory {}: {}",
                TEST_BLOCK_DIR,
                e
            )
        })?;

        let mut block_numbers = Vec::new();

        for entry in entries {
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
                    block_numbers.push(block_number);
                }
            }
        }

        if block_numbers.is_empty() {
            return Err(anyhow!("No valid block files found in {}", TEST_BLOCK_DIR));
        }

        block_numbers.sort_unstable();
        let min_block = *block_numbers.first().unwrap();
        let max_block = *block_numbers.last().unwrap();

        Ok((min_block, max_block))
    }

    #[tokio::test]
    async fn integration_test() {
        tracing_subscriber::fmt::init();

        let handle = setup_mock_rpc_server().await;
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
        let contracts = Arc::new(Mutex::new(load_contracts(&CONTRACTS_FILE)));

        for block_num in 3780..3801 {
            wait_and_validate(
                client.clone(),
                validator_db.clone(),
                block_num,
                5,
                contracts.clone(),
            )
            .await
            .unwrap();
        }

        handle.stop().unwrap();
        info!("Mock RPC server has been shut down.");
    }
}
