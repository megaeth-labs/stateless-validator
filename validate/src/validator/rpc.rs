//! This module provides an RPC client and handler for the stateless validator.
//!
//! The `RpcClient` is used to communicate with a full Ethereum node to fetch data
//! required for validation that is not present in the `BlockWitness` (e.g., contract code,
//! historical block).
//!
//! The `get_blob_ids` function acts as an RPC endpoint handler, allowing clients to query
//! the validation status and retrieve blob information for a given block.
use crate::file::{
    ValidateStatus, load_from_file_or_backup, load_validate_info,
    read_block_hash_by_number_from_file,
};
use alloy_primitives::hex;
use alloy_primitives::{Address, B256, Bytes};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::{Result, eyre};
use futures::future::try_join_all;
use jsonrpsee_types::error::{
    CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
    UNKNOWN_ERROR_CODE,
};
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;
//use reth_primitives::{Address, BlockNumberOrTag, Bytes, B256};
use std::{collections::HashMap, path::Path, str::FromStr};

/// An RPC client for fetching data from a full Ethereum node.
#[derive(Debug, Clone)]
pub struct RpcClient {
    /// The HTTP-based RPC provider.
    pub provider: RootProvider<Optimism>,
}

impl RpcClient {
    /// Creates a new `RpcClient` connected to the given API endpoint.
    pub fn new(api: &str) -> Result<Self> {
        let provider = ProviderBuilder::<_, _, Optimism>::default()
            .connect_http(api.parse().map_err(|e| eyre!("parse api failed: {}", e))?);

        Ok(Self { provider })
    }

    /// Fetches the bytecode for multiple addresses at a specific block.
    ///
    /// The requests are executed concurrently for efficiency.
    pub async fn codes_at(
        &self,
        addresses: &[Address],
        block_number: BlockNumberOrTag,
    ) -> Result<Vec<Bytes>> {
        let futures = addresses.iter().map(|&single_address| {
            let provider_clone = self.provider.clone();

            async move {
                provider_clone
                    .get_code_at(single_address)
                    .block_id(block_number.into())
                    .await
                    .map_err(|e| {
                        eyre!(
                            "get_code_at for address {single_address:?} at block {block_number:?} failed: {e}"
                        )
                    })
            }
        });

        try_join_all(futures).await
    }

    /// Fetches the block hashes for multiple block numbers.
    ///
    /// The requests are executed concurrently for efficiency.
    pub async fn block_hashs(&self, block_nums: &[u64]) -> Result<Vec<B256>> {
        let futures = block_nums.iter().map(|&block_number| {
            let provider_clone = self.provider.clone();

            async move {
                provider_clone
                    .get_block(block_number.into())
                    .await
                    .map_err(|e| eyre!("get_block_by_number at {block_number} failed: {e}"))
            }
        });

        let results = try_join_all(futures)
            .await
            .map_err(|e| {
                eyre!(
                    "Failed to gather block data from provider(s) concurrently: {}",
                    e
                )
            })
            .and_then(|block_options_vec| {
                block_options_vec
                    .into_iter()
                    .map(|opt_block| {
                        opt_block.map(|block| block.header.hash).ok_or_else(|| {
                            eyre!(
                                "A requested block was not found by the provider or its header is missing"
                            )
                        })
                    })
                    .collect::<Result<Vec<B256>, _>>()
            })?;

        Ok(results)
    }

    /// Fetches a full block by its hash.
    pub async fn block_by_hash(&self, hash: B256, full_txs: bool) -> Result<Block<Transaction>> {
        self.fetch_block(BlockId::Hash(hash.into()), full_txs)
            .await
            .map_err(|e| eyre!("get_block_by_hash at {hash} failed: {e}"))
    }

    /// Fetches a full block by its number.
    pub async fn block_by_number(&self, number: u64, full_txs: bool) -> Result<Block<Transaction>> {
        self.fetch_block(BlockId::Number(number.into()), full_txs)
            .await
            .map_err(|e| eyre!("get_block_by_number at {number} failed: {e}"))
    }

    /// Generic helper to fetch a block by its ID (hash or number).
    async fn fetch_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let block_request = self.provider.get_block(block_id);

        let block = if full_txs {
            block_request.full().await?
        } else {
            block_request.await?
        };

        block.ok_or_else(|| eyre!("Block {:?} not found", block_id))
    }
}

/// An RPC handler that retrieves blob IDs for a set of validated blocks.
///
/// This function processes a list of block identifiers (formatted as `"{number}.{hash}"`),
/// checks their validation status from the local file system, and returns the associated
/// blob IDs if validation was successful.
///
/// # Arguments
///
/// * `stateless_dir` - The directory where validation status files are stored.
/// * `blocks` - A `Vec` of strings, each identifying a block.
///
/// # Returns
///
/// Returns a `HashMap` from the block identifier string to a `Vec` of `B256` blob IDs.
/// Returns a `jsonrpsee` `ErrorObjectOwned` if any block is invalid, not found, or has
/// not yet been successfully validated.
pub fn get_blob_ids(
    stateless_dir: &Path,
    blocks: Vec<String>,
) -> Result<HashMap<String, Vec<B256>>, ErrorObjectOwned> {
    let mut results = HashMap::new();

    for block in blocks {
        let (block_number, block_hash) = parse_num_hash(&block)?;

        let validation =
            load_validate_info(stateless_dir, block_number, block_hash).map_err(|e| {
                ErrorObject::owned(CALL_EXECUTION_FAILED_CODE, e.to_string(), None::<()>)
            })?;

        match validation.status {
            ValidateStatus::Failed => {
                return Err(ErrorObject::owned(
                    UNKNOWN_ERROR_CODE,
                    format!("This block {block_number} validation failed"),
                    None::<()>,
                ));
            }
            ValidateStatus::Idle => {
                return Err(ErrorObject::owned(
                    CALL_EXECUTION_FAILED_CODE,
                    format!("This block {block_number} is too old or not validated yet"),
                    None::<()>,
                ));
            }
            ValidateStatus::Processing => {
                return Err(ErrorObject::owned(
                    CALL_EXECUTION_FAILED_CODE,
                    format!("This block {block_number} in processing"),
                    None::<()>,
                ));
            }
            ValidateStatus::Success => {
                results.insert(
                    block,
                    validation.blob_ids.into_iter().map(B256::from).collect(),
                );
            }
        }
    }

    Ok(results)
}

/// Get the witness for a block.
pub fn get_witness(stateless_dir: &Path, block_info: String) -> Result<String, ErrorObjectOwned> {
    let (block_number, parent_hash) = parse_num_hash(&block_info)?;

    // get the witness from witness directory
    let witness_dir = stateless_dir.join("witness");
    let block_hashes =
        if let Ok(hashes) = read_block_hash_by_number_from_file(block_number, &witness_dir) {
            hashes
        } else {
            let backup_dir = stateless_dir.join(crate::backup_dir(block_number));
            read_block_hash_by_number_from_file(block_number, &backup_dir).map_err(|_| {
                ErrorObject::owned(
                    INVALID_PARAMS_CODE,
                    format!("not found block number: {}", block_number),
                    None::<()>,
                )
            })?
        };

    for block_hash in block_hashes {
        let witness =
            load_from_file_or_backup(stateless_dir, block_number, block_hash).map_err(|e| {
                ErrorObject::owned(
                    INVALID_PARAMS_CODE,
                    format!("block {block_number} err:{e}"),
                    None::<()>,
                )
            })?;
        if witness.parent_hash == parent_hash {
            // Return the witness data as a hex-encoded string
            return Ok(hex::encode(&witness.witness_data));
        }
    }

    Err(ErrorObject::owned(
        INVALID_PARAMS_CODE,
        format!("not found witness for block {block_info}"),
        None::<()>,
    ))
}

fn parse_num_hash(block: &str) -> Result<(u64, B256), ErrorObjectOwned> {
    let parts: Vec<&str> = block.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ErrorObject::owned(
            INVALID_PARAMS_CODE,
            format!("invalid params format: {}", block),
            None::<()>,
        ));
    }

    let block_number = parts[0].parse::<u64>().map_err(|_| {
        ErrorObject::owned(
            INVALID_PARAMS_CODE,
            format!("invalid block number: {}", parts[0]),
            None::<()>,
        )
    })?;
    let block_hash = B256::from_str(parts[1]).map_err(|_| {
        ErrorObject::owned(
            INVALID_PARAMS_CODE,
            format!("invalid block hash: {}", parts[1]),
            None::<()>,
        )
    })?;

    Ok((block_number, block_hash))
}
