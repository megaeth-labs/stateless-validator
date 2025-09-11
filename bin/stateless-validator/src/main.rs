use alloy_primitives::{Address, hex};
use clap::Parser;
use eyre::{Result, anyhow};
use futures::stream::{self, StreamExt};
use jsonrpsee::{
    RpcModule,
    server::{ServerBuilder, ServerConfigBuilder},
};
use revm::{
    primitives::{B256, HashMap, KECCAK_EMPTY},
    state::Bytecode,
};
use salt::{EphemeralSaltState, SaltWitness, StateRoot, Witness};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, signal, sync::Mutex};
use tracing::{error, info};
use validator_core::{
    SaltWitnessState, ValidateStatus, ValidationManager, curent_time_to_u64,
    database::WitnessDatabase,
    evm::replay_block,
    evm::{PlainKey, PlainValue},
};

mod rpc;
use rpc::RpcClient;

/// Maximum response body size for the RPC server.
/// This is set to 100 MB to accommodate large block data and witness information.
const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

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

    let stateless_dir = PathBuf::from(args.datadir);

    let client = Arc::new(RpcClient::new(&args.api)?);
    let val_manager = ValidationManager::new(&stateless_dir);

    // fetch the latest finalized block number.
    let chain_status = val_manager.get_chain_status()?;
    let finalized_num = chain_status.block_number;

    // Start validating from the block after the last finalized one.
    let block_counter = finalized_num + 1;
    let validator_logic = scan_and_validate_block_witnesses(
        client,
        &stateless_dir,
        block_counter,
        args.lock_time,
        concurrent_num,
    );

    if let Some(port) = args.port {
        let mut module = RpcModule::new(stateless_dir.clone());

        module.register_method("stateless_getValidation", |params, path, _| {
            let blocks: Vec<String> = params.parse()?;
            let val_manager = ValidationManager::new(path);
            val_manager.get_blob_ids(blocks)
        })?;

        module.register_method("stateless_getWitness", |params, path, _| {
            let block_info: String = params.parse()?;
            let val_manager = ValidationManager::new(path);
            val_manager.get_witness(block_info)
        })?;

        //let server = Server::builder().build(format!("0.0.0.0:{}", port)).await?;
        let cfg = ServerConfigBuilder::default()
            .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
            .build();
        let server = ServerBuilder::default()
            .set_config(cfg)
            .build(format!("0.0.0.0:{}", port))
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

/// Scans for and validates block witnesses concurrently.
///
/// This function creates a stream of block numbers starting from `block_counter` and processes them
/// concurrently.
async fn scan_and_validate_block_witnesses(
    client: Arc<RpcClient>,
    stateless_dir: &Path,
    block_counter: u64,
    lock_time: u64,
    concurrent_num: usize,
) -> Result<()> {
    // Load already known contracts from a file to avoid re-fetching them.
    let val_manager = ValidationManager::new(stateless_dir);
    let contracts = Arc::new(Mutex::new(
        val_manager.load_contracts_file().unwrap_or_default(),
    ));

    let stateless_dir = stateless_dir.to_path_buf();

    // Create an infinite stream of block numbers to process.
    stream::iter(block_counter..)
        .for_each_concurrent(Some(concurrent_num), |block_counter| {
            let client = Arc::clone(&client);
            let stateless_dir = stateless_dir.clone();
            let contracts = Arc::clone(&contracts);

            async move {
                // Continuously validate blocks, retrying on failure until the block becomes stale.
                // The loop breaks if validation succeeds or if the block is older than the
                // latest finalized block.
                while let Err(e) = validate_block(
                    client.clone(),
                    &stateless_dir,
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
                    let val_manager = ValidationManager::new(&stateless_dir);
                    let chain_status = val_manager.get_chain_status().unwrap_or_default();
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
async fn validate_block(
    client: Arc<RpcClient>,
    stateless_dir: &Path,
    block_counter: u64,
    lock_time: u64,
    contracts: Arc<Mutex<HashMap<B256, Bytecode>>>,
) -> Result<()> {
    // Create ValidationManager for handling block-related file operations
    let val_manager = ValidationManager::new(stateless_dir);

    info!("Processing block: {}", block_counter);

    let mut loops = true;

    // This loop waits for the witness for the block to be generated and available.
    while loops {
        let block_hashes = match val_manager.find_block_hashes(block_counter) {
            Ok(hashes) => hashes,
            Err(_e) => {
                // Witness for block_counter not found, waiting...
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        for block_hash in block_hashes {
            let witness_status = val_manager.get_witness_state(&(block_counter, block_hash))?;
            if witness_status.status == SaltWitnessState::Idle
                || witness_status.status == SaltWitnessState::Processing
            {
                // Wait for the witness to be completed.
                tokio::time::sleep(Duration::from_secs(5)).await;
                // start with while loop to handle this block hash again
                break;
            }

            let witness_bytes = witness_status.witness_data;

            let validate_info = val_manager.load_validate_info(block_counter, block_hash)?;
            // Check if the block has already been validated or is being processed by another
            // validator.
            if validate_info.status == ValidateStatus::Success {
                info!(
                    "Block {} has already been validated with result: {:?}",
                    block_counter, validate_info.status
                );
                return Ok(());
            } else if validate_info.status == ValidateStatus::Processing
                && validate_info.lock_time >= curent_time_to_u64()
            {
                info!(
                    "Block {} is currently being processed by another validator.",
                    block_counter
                );
                return Ok(());
            } else if validate_info.status == ValidateStatus::Failed {
                info!("Block {} validation failed, replay again...", block_counter);
                // start with while loop to handle this block hash again
                break;
            }
            // Lock the block for processing to prevent other validators from working on it.
            val_manager.set_validate_status(
                block_counter,
                block_hash,
                ValidateStatus::Processing,
                None,
                Some(lock_time),
                Some(witness_status.blob_ids.clone()),
            )?;

            // Fetch the full block details and decode the witness concurrently.
            let (blocks_result, witness_decode_result) = {
                let witness_bytes_clone = witness_bytes.clone();
                tokio::join!(
                    client.block_by_hash(block_hash, true),
                    tokio::task::spawn_blocking(move || {
                        bincode::serde::decode_from_slice(
                            &witness_bytes_clone,
                            bincode::config::legacy(),
                        )
                        .map_err(|e| anyhow!("Failed to parse witness: {}", e))
                    })
                )
            };

            let block = blocks_result?;
            let (block_witness, _size): (SaltWitness, usize) = witness_decode_result??;

            let old_state_root = get_root(
                client.as_ref(),
                stateless_dir,
                block_counter - 1,
                block.header.parent_hash,
            )
            .await?;
            let new_state_root = block.header.state_root;

            let addresses_with_code = get_addresses_with_code(&block_witness);

            let block_witness = Witness::from(block_witness);
            block_witness.verify(*old_state_root)?;

            let mut contracts_guard = contracts.lock().await;

            let new_contracts_address = addresses_with_code
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
            let contracts_for_provider = contracts_guard.clone();
            drop(contracts_guard);

            // Persist new contracts to the file.
            for (hash, bytecode) in new_contracts {
                val_manager.append_contract(hash, &bytecode)?;
            }

            let witness_provider = WitnessDatabase {
                witness: block_witness.clone(),
                contracts: contracts_for_provider,
                client: client.provider.clone(),
                runtime: Handle::current(),
            };

            let kv_updates = replay_block(block.clone(), &witness_provider)?;

            let state_updates = EphemeralSaltState::new(&block_witness)
                .update(&kv_updates)
                .map_err(|e| anyhow!("Failed to update state: {}", e))?;

            let mut trie = StateRoot::new(&block_witness);
            let (new_trie_root, _trie_updates) = trie
                .update_fin(state_updates)
                .map_err(|e| anyhow!("Failed to update trie: {}", e))?;

            if new_trie_root != new_state_root {
                error!(
                    "Validation FAILED for block {}. Calculated state root: 0x{}, Expected state root: 0x{}",
                    block_counter,
                    hex::encode(new_trie_root),
                    hex::encode(new_state_root)
                );
                val_manager.set_validate_status(
                    block_counter,
                    block_hash,
                    ValidateStatus::Failed,
                    Some(new_state_root),
                    None,
                    None,
                )?;
            } else {
                info!(
                    "Validation SUCCESS for block {}. State root: 0x{}",
                    block_counter,
                    hex::encode(new_trie_root)
                );
                val_manager.set_validate_status(
                    block_counter,
                    block_hash,
                    ValidateStatus::Success,
                    Some(new_state_root),
                    None,
                    None,
                )?;
                loops = false;
            }
        }
    }

    Ok(())
}

/// Retrieves the state root for a given block number.
///
/// It first attempts to find the state root from the local validation files. If not found, it
/// falls back to fetching the block from the RPC endpoint.
async fn get_root(
    client: &RpcClient,
    stateless_dir: &Path,
    block_number: u64,
    block_hash: B256,
) -> Result<B256> {
    let val_manager = ValidationManager::new(stateless_dir);
    let validate_info = val_manager.load_validate_info(block_number, block_hash)?;
    if validate_info.state_root.is_zero() {
        // If state root is not in our validation records, fetch from RPC.
        let block = client.block_by_number(block_number, false).await?;
        return Ok(block.header.state_root);
    }

    Ok(validate_info.state_root)
}

/// Extracts all addresses that have a non-empty bytecode hash from the witness.
/// This is useful for fetching contract code required for block execution.
fn get_addresses_with_code(block_witness: &SaltWitness) -> Vec<(Address, B256)> {
    block_witness
        .kvs
        .iter()
        .filter_map(|(k, v)| {
            let val = v.as_ref()?;

            // Skip bucket meta slots as they do not contain account information.
            let key = val.key();
            if k.is_in_meta_bucket() || key.len() != Address::len_bytes() {
                return None;
            }

            let plain_key = PlainKey::decode(key);
            let plain_value = PlainValue::decode(val.value());

            match (plain_key, plain_value) {
                (PlainKey::Account(address), PlainValue::Account(account)) => account
                    .bytecode_hash
                    .filter(|&code_hash| code_hash != KECCAK_EMPTY)
                    .map(|code_hash| (address, code_hash)),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rpc_types_eth::Block;
    use fs_extra::dir;
    use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned};
    use op_alloy_rpc_types::Transaction;
    use validator_core::ValidationManager;

    /// Set up a temporary work directory and copy test data into it.
    /// Return the path to the work directory.
    fn setup_work_dir() -> Result<PathBuf> {
        let temp_dir = tempfile::tempdir()
            .map_err(|e| anyhow!("Failed to create temporary directory: {}", e))?;

        let data_dir = PathBuf::from("../../test_data/stateless");
        let work_dir = temp_dir.path().to_path_buf();

        let mut options = dir::CopyOptions::new();
        options.content_only = true;
        dir::copy(&data_dir, &work_dir, &options)
            .map_err(|e| anyhow!("Failed to copy test data: {}", e))?;

        // Keep the temp dir alive by leaking it. OS will clean it when test process ends.
        std::mem::forget(temp_dir);

        Ok(work_dir)
    }

    #[derive(Debug)]
    enum Input {
        Hash(String),
        Number(u64),
    }

    fn full_block_to_without_tx(block: &Block<Transaction>) -> Block<Transaction> {
        let transactions = block.transactions.clone();
        let hashes = transactions.into_hashes();
        let mut block = block.clone();
        block.transactions = hashes;
        block
    }

    fn load_block(
        path: &PathBuf,
        input: Input,
        is_full: bool,
    ) -> Result<Block<Transaction>, ErrorObjectOwned> {
        let val_manager = ValidationManager::new(path);
        let files = std::fs::read_dir(path).unwrap();

        for file in files {
            let file = file.unwrap();
            let file_name = file.file_name();
            let file_name_str = file_name.to_string_lossy();

            match input {
                Input::Hash(ref hash) => {
                    if file_name_str.contains(hash) {
                        let block = val_manager.load_block_data(&file_name_str).unwrap();
                        return Ok(if is_full {
                            block
                        } else {
                            full_block_to_without_tx(&block)
                        });
                    }
                }
                Input::Number(number) => {
                    if file_name_str.starts_with(&format!("{number}.")) {
                        let block = val_manager.load_block_data(&file_name_str).unwrap();
                        return Ok(if is_full {
                            block
                        } else {
                            full_block_to_without_tx(&block)
                        });
                    }
                }
            }
        }

        Err(ErrorObject::owned(
            CALL_EXECUTION_FAILED_CODE,
            format!("This block {input:?} not found"),
            None::<()>,
        ))
    }

    #[tokio::test]
    async fn test_validate_blocks() {
        tracing_subscriber::fmt::init();

        // Set up test data in temporary directory
        let work_dir = setup_work_dir().unwrap();

        // 1. start the mock RPC server using original blocks path (read-only)
        let blocks_path = PathBuf::from("../../test_data/blocks");
        let mut module = RpcModule::new(blocks_path);

        module
            .register_method("eth_getBlockByHash", |params, path, _| {
                let (hash, is_full): (String, bool) = params.parse().unwrap();
                let block = load_block(path, Input::Hash(hash), is_full);
                block
            })
            .unwrap();

        module
            .register_method("eth_getBlockByNumber", |params, path, _| {
                let (number_str, is_full): (String, bool) = params.parse().unwrap();
                // Convert hex string starting with 0x to u64
                let number = if number_str.starts_with("0x") {
                    u64::from_str_radix(&number_str[2..], 16).unwrap_or(0)
                } else {
                    number_str.parse::<u64>().unwrap_or(0)
                };
                let block = load_block(path, Input::Number(number), is_full);
                block
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

        // Give the server a moment to start up
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 2. create the client that will connect to our mock server
        let client = Arc::new(RpcClient::new("http://127.0.0.1:59545").unwrap());

        // Load already known contracts from a file to avoid re-fetching them.
        let val_manager = ValidationManager::new(&work_dir);
        let contracts = Arc::new(Mutex::new(
            val_manager.load_contracts_file().unwrap_or_default(),
        ));

        let finalized_num = 279;
        let block_counter = finalized_num + 1;

        for block_counter in block_counter..block_counter + 21 {
            let res = validate_block(
                client.clone(),
                &work_dir,
                block_counter,
                5,
                contracts.clone(),
            )
            .await;
            assert!(res.is_ok());
        }
        // Finally, shut down the mock server
        handle.stop().unwrap();
        info!("Mock RPC server has been shut down.");
    }
}
