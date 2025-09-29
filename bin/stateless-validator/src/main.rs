use alloy_primitives::{Address, B256, BlockHash, BlockNumber, hex};
use alloy_rpc_types_eth::{BlockId, Header};
use clap::Parser;
use eyre::{Result, anyhow};
use futures::future;
use revm::{primitives::KECCAK_EMPTY, state::Bytecode};
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
    chain_spec::CHAIN_SPEC,
    data_types::{PlainKey, PlainValue},
    executor::{ValidationResult, validate_block},
};

mod rpc;
use rpc::RpcClient;

/// Database filename for the validator.
const VALIDATOR_DB_FILENAME: &str = "validator.redb";

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
}

impl Default for ChainSyncConfig {
    fn default() -> Self {
        Self {
            concurrent_workers: num_cpus::get(),
            sync_poll_interval: Duration::from_secs(1),
            sync_target: None,
            tracker_lookahead_blocks: 10,
            tracker_poll_interval: Duration::from_secs(2),
            pruner_interval: Duration::from_secs(300),
            pruner_blocks_to_keep: 1000,
            worker_idle_sleep: Duration::from_millis(500),
            worker_error_sleep: Duration::from_millis(1000),
        }
    }
}

/// Command line arguments for the stateless validator.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CommandLineArgs {
    /// Directory path where validator data and database files will be stored.
    #[clap(short = 'd', long)]
    data_dir: String,

    /// The URL of the Ethereum JSON-RPC API endpoint for fetching blockchain data.
    #[clap(short = 'r', long)]
    rpc_endpoint: String,

    /// Optional trusted block hash to start validation from.
    #[clap(long)]
    start_block: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let start = Instant::now();
    let args = CommandLineArgs::parse();

    info!("[Main] Data directory: {}", args.data_dir);
    info!("[Main] RPC endpoint: {}", args.rpc_endpoint);

    let work_dir = PathBuf::from(args.data_dir);

    let client = Arc::new(RpcClient::new(&args.rpc_endpoint)?);
    let validator_db = Arc::new(ValidatorDB::new(work_dir.join(VALIDATOR_DB_FILENAME))?);

    // Handle optional start block initialization
    if let Some(start_block_str) = &args.start_block {
        info!("[Main] Initializing from start block: {}", start_block_str);

        let block_hash = parse_block_hash(start_block_str)?;
        let block = client
            .get_block(BlockId::Hash(block_hash.into()), false)
            .await
            .map_err(|e| anyhow!("Failed to fetch block {}: {}", block_hash, e))?;

        validator_db
            .reset_anchor_block(
                block.header.number,
                block.header.hash,
                block.header.state_root,
            )
            .map_err(|e| anyhow!("Failed to reset anchor: {}", e))?;

        info!(
            "[Main] Successfully initialized from block {} (number: {})",
            block.header.hash, block.header.number
        );
    } else {
        // If no start block was provided, ensure we have an existing canonical chain
        if validator_db.get_local_tip()?.is_none() {
            return Err(anyhow!(
                "No trusted starting point found. Specify a trusted block with --start-block <blockhash>"
            ));
        }
        info!("[Main] Continuing from existing canonical chain");
    }

    // Create chain sync configuration
    let config = Arc::new(ChainSyncConfig {
        concurrent_workers: num_cpus::get(),
        ..ChainSyncConfig::default()
    });
    info!(
        "[Main] Number of concurrent tasks: {}",
        config.concurrent_workers
    );

    let validator_logic = chain_sync(client.clone(), validator_db.clone(), config);

    tokio::select! {
        res = validator_logic => res?,
        _ = signal::ctrl_c() => {
            info!("[Main] Ctrl-C received, shutting down.");
        }
    }

    info!("[Main] Total execution time: {:?}", start.elapsed());
    Ok(())
}

/// Chain synchronizer entry point - orchestrates the complete chain synchronization pipeline
///
/// Implements a five-phase startup process for stateless block validation:
/// 1. **Task Recovery** - Recovers interrupted validation tasks from previous crashes
/// 2. **Remote Chain Tracking** - Spawns background tracker to maintain block lookahead
/// 3. **History Pruning** - Spawns background pruner to manage storage overhead
/// 4. **Validation Workers** - Spawns configured number of parallel validation workers
/// 5. **Main Sync Loop** - Continuously advances canonical chain as blocks are validated
///
/// Runs indefinitely unless a sync target is configured. Background components operate
/// independently while the main thread advances the canonical chain.
///
/// # Arguments
/// * `client` - RPC client for communicating with remote blockchain node
/// * `validator_db` - Database interface for task coordination and chain state management
/// * `config` - Configuration including worker count, polling intervals, and optional sync target
///
/// # Returns
/// * `Ok(())` - When sync target is reached (if configured)
/// * `Err(eyre::Error)` - On critical failures during task recovery
async fn chain_sync(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
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

    // Step 3: Spawn history pruner
    task::spawn(history_pruner(
        Arc::clone(&validator_db),
        Arc::clone(&config),
    ));

    // Step 4: Spawn validation workers as tokio tasks
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
        ));
    }
    info!("[Chain Sync] All validation workers started");

    // Step 5: Main chain synchronizer loop
    info!("[Chain Sync] Starting main synchronizer loop...");

    loop {
        if let Some(target) = config.sync_target
            && let Ok(Some((local_block_number, _))) = validator_db.get_local_tip()
            && local_block_number >= target
        {
            info!("[Chain Sync] Reached sync target height {target}, terminating");
            return Ok(());
        }

        if let Err(e) = async {
            // Advance the canonical chain with newly validated blocks
            let mut blocks_advanced = 0;
            while validator_db.grow_local_chain()? {
                blocks_advanced += 1;
            }

            if blocks_advanced > 0 {
                info!("[Chain Sync] Advanced canonical chain by {blocks_advanced} blocks");
            } else {
                // No work to do, wait a bit before polling again
                tokio::time::sleep(config.sync_poll_interval).await;
            }

            Ok::<(), eyre::Error>(())
        }
        .await
        {
            error!("[Chain Sync] Iteration failed: {}", e);
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

    loop {
        if let Err(e) = async {
            // Calculate how far behind our local chain is from remote
            let local_tip = validator_db
                .get_local_tip()?
                .ok_or_else(|| anyhow!("Local chain is empty"))?;
            let remote_tip = validator_db.get_remote_tip()?.unwrap_or(local_tip);
            let gap = remote_tip.0.saturating_sub(local_tip.0);

            info!(
                "[Tracker] local={}, remote={}, gap={}",
                local_tip.0, remote_tip.0, gap
            );

            // Detect and resolve chain reorgs
            match client
                .get_block(BlockId::Number(remote_tip.0.into()), false)
                .await
            {
                Ok(block) if block.header.hash != remote_tip.1 => {
                    error!(
                        "[Tracker] Hash mismatch! Expected {}, got {}. Resolving chain divergence.",
                        remote_tip.1, block.header.hash
                    );
                    match find_divergence_point(&client, &validator_db, remote_tip.0).await {
                        Ok(rollback_to) => {
                            info!("[Tracker] Rolling back to block {rollback_to}");
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

            info!(
                "[Tracker] Fetching {} blocks starting from {}",
                blocks_to_fetch,
                remote_tip.0 + 1
            );

            // Fetch blocks in parallel and queue validation tasks
            let headers = future::join_all(
                (remote_tip.0 + 1..remote_tip.0 + 1 + blocks_to_fetch).map(|block_number| {
                    let client = client.clone();
                    let db = validator_db.clone();
                    tokio::spawn(async move {
                        let block = client
                            .get_block(BlockId::Number(block_number.into()), true)
                            .await?;
                        let witness = client.get_witness(block.header.hash).await?;
                        db.add_validation_task(&block, &witness)?;
                        Ok::<Header, eyre::Error>(block.header)
                    })
                }),
            )
            .await
            .into_iter()
            .enumerate()
            // Stop on first error to maintain block sequence contiguity
            .take_while(|(i, result)| match result {
                Ok(Ok(_)) => true,
                Ok(Err(e)) => {
                    error!(
                        "[Tracker] DB or RPC error at block {}: {e}",
                        remote_tip.0 + 1 + *i as u64
                    );
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
            for header in headers {
                validator_db.grow_remote_chain(&header)?;
            }

            Ok::<(), eyre::Error>(())
        }
        .await
        {
            error!("[Tracker] Iteration failed: {}", e);
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
///
/// # Returns
/// * Never returns under normal operation - runs indefinitely until externally terminated
async fn validation_worker(
    worker_id: usize,
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    config: Arc<ChainSyncConfig>,
) -> Result<()> {
    info!("[Worker {}] Started", worker_id);
    loop {
        match validate_one(worker_id, &client, &validator_db).await {
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
                .get_code(&missing_contracts, (block_number - 1).into())
                .await?;

            for (address, bytes) in missing_contracts.iter().zip(codes.iter()) {
                let bytecode = Bytecode::new_raw(bytes.clone());
                validator_db.add_contract_code(&bytecode)?;
                contracts.insert(codehashes[address], bytecode);
            }

            // Validate the given block
            let pre_state_root = B256::from(witness.state_root()?);
            let (success, error_message) =
                match validate_block(CHAIN_SPEC.clone(), &block, witness, &contracts) {
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
                    info!("[Pruner] Pruned {blocks_pruned} blocks before block {prune_before}");
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
    use super::*;
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
    use serde::de::DeserializeOwned;
    use std::{
        collections::BTreeMap,
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

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
        validator_db.reset_anchor_block(block_num, block_hash, state_root)?;

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
                .map_err(|e| anyhow!("Failed to read test witness directory: {e}"))?;

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

                    // Extract and deserialize SaltWitness from file_data
                    let (salt_witness, _): (SaltWitness, usize) =
                        bincode::serde::decode_from_slice(&file_data, bincode::config::legacy())
                            .map_err(|e| {
                                anyhow!(
                                    "Failed to deserialize SaltWitness from file_data {block_num_and_hash}: {e}"
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
        let (handle, url) = setup_mock_rpc_server(context).await;
        let client = Arc::new(RpcClient::new(&url).unwrap());

        // Create test configuration with faster intervals for testing
        let config = Arc::new(ChainSyncConfig {
            concurrent_workers: 1,
            sync_target,
            ..ChainSyncConfig::default()
        });

        chain_sync(client.clone(), validator_db, config)
            .await
            .unwrap();

        handle.stop().unwrap();
        info!("Mock RPC server has been shut down.");
    }
}
