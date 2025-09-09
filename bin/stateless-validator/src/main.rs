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
    SaltWitnessState,
    chain::get_chain_status,
    client::{RpcClient, get_blob_ids, get_witness},
    database::{PlainKeyUpdate, WitnessDatabase},
    evm::replay_block,
    evm::{PlainKey, PlainValue},
    storage::{
        ValidateStatus, append_json_line_to_file, load_contracts_file, load_validate_info,
        read_block_hash_by_number_from_file, set_validate_status,
    },
    witness::{curent_time_to_u64, get_witness_state},
};

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

    // fetch the latest finalized block number.
    let chain_status = get_chain_status(&stateless_dir)?;
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
            get_blob_ids(path, blocks)
        })?;

        module.register_method("stateless_getWitness", |params, path, _| {
            let block_info: String = params.parse()?;
            get_witness(path, block_info)
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
    let validate_path = stateless_dir.join("validate");
    let contracts_file = "contracts.txt";

    // Load already known contracts from a file to avoid re-fetching them.
    let contracts = Arc::new(Mutex::new(
        load_contracts_file(&validate_path, contracts_file).unwrap_or_default(),
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
                    let chain_status = get_chain_status(&stateless_dir).unwrap_or_default();
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
    let validate_path = stateless_dir.join("validate");
    let witness_dir = stateless_dir.join("witness");
    let contracts_file = "contracts.txt";

    info!("Processing block: {}", block_counter);

    let mut loops = true;

    // This loop waits for the witness for the block to be generated and available.
    while loops {
        let block_hashes = match read_block_hash_by_number_from_file(block_counter, &witness_dir) {
            Ok(hashes) => hashes,
            Err(_e) => {
                // Witness for block_counter not found, waiting...
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        for block_hash in block_hashes {
            let witness_status = get_witness_state(stateless_dir, &(block_counter, block_hash))?;
            if witness_status.status == SaltWitnessState::Idle
                || witness_status.status == SaltWitnessState::Processing
            {
                // Wait for the witness to be completed.
                tokio::time::sleep(Duration::from_secs(5)).await;
                // start with while loop to handle this block hash again
                break;
            }

            let witness_bytes = witness_status.witness_data;

            let validate_info = load_validate_info(stateless_dir, block_counter, block_hash)?;
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
            set_validate_status(
                stateless_dir,
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
                append_json_line_to_file(&(hash, bytecode), &validate_path, contracts_file)?;
            }

            let rt = Handle::current();
            let witness_provider = WitnessDatabase {
                witness: block_witness.clone(),
                contracts: contracts_for_provider,
                provider: client.provider.clone(),
                rt,
            };

            let accounts = replay_block(block.clone(), &witness_provider)?;

            let plain_state = PlainKeyUpdate::from(accounts);

            let state_updates = EphemeralSaltState::new(&block_witness)
                .update(&plain_state.data)
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
                set_validate_status(
                    stateless_dir,
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
                set_validate_status(
                    stateless_dir,
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
    let validate_info = load_validate_info(stateless_dir, block_number, block_hash)?;
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
    use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned};
    use op_alloy_rpc_types::Transaction;
    use std::fs;
    use validator_core::storage::load_json_file;

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
        let files = std::fs::read_dir(path).unwrap();

        for file in files {
            let file = file.unwrap();
            let file_name = file.file_name();
            let file_name_str = file_name.to_string_lossy();

            match input {
                Input::Hash(ref hash) => {
                    if file_name_str.contains(hash) {
                        let block =
                            load_json_file::<Block<Transaction>>(path, &file_name_str).unwrap();
                        return Ok(if is_full {
                            block
                        } else {
                            full_block_to_without_tx(&block)
                        });
                    }
                }
                Input::Number(number) => {
                    if file_name_str.starts_with(&format!("{number}.")) {
                        let block =
                            load_json_file::<Block<Transaction>>(path, &file_name_str).unwrap();
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

    fn delete_validate_files() {
        // ===============================
        // delete the test_data/stateless/validate/*.v files to re-validate the blocks
        // ===============================
        let validate_dir = PathBuf::from("../../test_data/stateless/validate");

        // Delete all .v files in the validate directory
        if let Ok(entries) = fs::read_dir(&validate_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(extension) = path.extension() {
                    if extension == "v" {
                        if let Err(e) = fs::remove_file(&path) {
                            error!("Failed to delete file {:?}: {}", path, e);
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_validate_blocks() {
        tracing_subscriber::fmt::init();
        delete_validate_files();
        // 1. start the mock RPC server
        let block_path = PathBuf::from("../../test_data/blocks");
        let mut module = RpcModule::new(block_path);

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

        let stateless_dir = PathBuf::from("../../test_data/stateless");

        let validate_path = stateless_dir.join("validate");
        let contracts_file = "contracts.txt";

        // Load already known contracts from a file to avoid re-fetching them.
        let contracts = Arc::new(Mutex::new(
            load_contracts_file(&validate_path, contracts_file).unwrap_or_default(),
        ));

        let finalized_num = 279;
        let block_counter = finalized_num + 1;

        for block_counter in block_counter..block_counter + 21 {
            let res = validate_block(
                client.clone(),
                &stateless_dir,
                block_counter,
                5,
                contracts.clone(),
            )
            .await;
            assert!(res.is_ok());
        }

        delete_validate_files();
        // Finally, shut down the mock server
        handle.stop().unwrap();
        info!("Mock RPC server has been shut down.");
    }
}
