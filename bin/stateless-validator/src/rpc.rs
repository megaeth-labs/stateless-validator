//! RPC client for fetching missing data during stateless validation.
use std::time::Instant;

use alloy_primitives::{B256, Bytes};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::{Context, Result, ensure, eyre};
use futures::future::try_join_all;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use serde::{Deserialize, Serialize};
use validator_core::{executor::verify_block_integrity, withdrawals::MptWitness};

use crate::metrics;

/// Response from mega_setValidatedBlocks RPC call
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetValidatedBlocksResponse {
    pub accepted: bool,
    pub last_validated_block: (u64, B256),
}

/// RPC client for MegaETH blockchain data.
///
/// Fetches contract bytecode, blocks, and witness data during stateless validation.
#[derive(Debug, Clone)]
pub struct RpcClient {
    /// Upstream MegaETH node providing blocks and contract bytecode.
    pub data_provider: RootProvider<Optimism>,
    /// Witness provider for fetching SALT witness data.
    pub witness_provider: RootProvider,
}

impl RpcClient {
    /// Creates a new RPC client connected to MegaETH blockchain nodes.
    ///
    /// # Arguments
    /// * `data_api` - HTTP URL of the standard JSON-RPC endpoint for blocks and contract data
    /// * `witness_api` - HTTP URL of the witness RPC endpoint for SALT witness data
    ///
    /// # Returns
    /// Configured RPC client ready to make requests to the MegaETH blockchain.
    ///
    /// # Errors
    /// Returns error if either API URL is malformed or invalid.
    pub fn new(data_api: &str, witness_api: &str) -> Result<Self> {
        Ok(Self {
            data_provider: ProviderBuilder::<_, _, Optimism>::default()
                .connect_http(data_api.parse().context("Failed to parse API URL")?),
            witness_provider: ProviderBuilder::default()
                .connect_http(witness_api.parse().context("Failed to parse API URL")?),
        })
    }

    /// Gets contract bytecode for multiple code hashes.
    ///
    /// # Arguments
    /// * `hashes` - Contract code hashes to fetch bytecode for
    ///
    /// # Returns
    /// Vector of bytecode in the same order as input hashes. Empty bytecode
    /// is returned for hashes without corresponding contract code.
    ///
    /// # Performance
    /// Executes all requests concurrently for optimal performance.
    pub async fn get_code(&self, hashes: &[B256]) -> Result<Vec<Bytes>> {
        let start = Instant::now();
        let result = try_join_all(hashes.iter().map(|&hash| async move {
            let result = self
                .data_provider
                .client()
                .request("eth_getCodeByHash", (hash,))
                .await
                .map_err(|e| eyre!("eth_getCodeByHash for hash {hash:?} failed: {e}"));

            metrics::record_rpc_request("eth_getCodeByHash", result.is_ok());
            result
        }))
        .await;

        metrics::record_code_fetch(start.elapsed().as_secs_f64(), hashes.len());
        result
    }

    /// Gets a block by its identifier with optional transaction details.
    ///
    /// Performs data integrity checks on the returned block:
    /// - Verifies block_id matches the returned block
    /// - Verifies block hash matches the computed hash from header
    /// - If full transactions: verifies transaction hashes and roots, and signers
    ///
    /// # Arguments
    /// * `block_id` - Block identifier (number, hash, latest, etc.)
    /// * `full_txs` - If true, includes full transaction objects; if false, only transaction hashes
    ///
    /// # Returns
    /// Complete block data including header, transactions, and metadata.
    ///
    /// # Errors
    /// Returns error if block doesn't exist, RPC call fails, or integrity checks fail.
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let start = Instant::now();

        let block = if full_txs {
            self.data_provider.get_block(block_id).full().await?
        } else {
            self.data_provider.get_block(block_id).await?
        };

        let duration = start.elapsed().as_secs_f64();
        let success = block.is_some();
        metrics::record_rpc_request("eth_getBlockByNumber", success);
        metrics::record_block_fetch(duration);

        let block = block.ok_or_else(|| eyre!("Block {:?} not found", block_id))?;

        // Verify block_id matches the returned block
        match block_id {
            BlockId::Number(BlockNumberOrTag::Number(num)) => {
                ensure!(
                    block.header.number == num,
                    "Block number mismatch: requested {}, got {}",
                    num,
                    block.header.number
                );
            }
            BlockId::Hash(hash) => {
                ensure!(
                    block.header.hash == hash.block_hash,
                    "Block hash mismatch: requested {:?}, got {:?}",
                    hash.block_hash,
                    block.header.hash
                );
            }
            _ => {} // Skip for latest, earliest, pending, etc.
        }

        verify_block_integrity(&block)?;

        Ok(block)
    }

    /// Gets the current latest block number from the blockchain.
    ///
    /// # Returns
    /// The highest block number that has been mined.
    ///
    /// # Errors
    /// Returns error if unable to connect to the blockchain or RPC fails.
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        let result = self
            .data_provider
            .get_block_number()
            .await
            .context("Failed to get block number");

        metrics::record_rpc_request("eth_blockNumber", result.is_ok());
        result
    }

    /// Gets execution witness data for a specific block.
    ///
    /// # Arguments
    /// * `number` - Block number to fetch witness data for
    /// * `hash` - Block hash to fetch witness data for
    ///
    /// # Returns
    /// [`SaltWitness`] containing state access patterns and execution traces
    /// required for stateless validation.
    ///
    /// # Errors
    /// Returns error if block hash doesn't exist, witness unavailable
    pub async fn get_witness(&self, number: u64, hash: B256) -> Result<(SaltWitness, MptWitness)> {
        let start = Instant::now();
        let result = self
            .witness_provider
            .client()
            .request("mega_getBlockWitness", (number.to_string(), hash))
            .await
            .map_err(|e| eyre!("Failed to get witness for block {hash}: {e}"));

        let duration = start.elapsed().as_secs_f64();
        metrics::record_rpc_request("mega_getBlockWitness", result.is_ok());
        metrics::record_witness_fetch(duration);
        result
    }

    /// Reports a range of validated blocks to the upstream node.
    ///
    /// Notifies the upstream node that the validator has successfully validated
    /// a contiguous range of blocks in its canonical chain.
    ///
    /// # Arguments
    /// * `first_block` - Tuple of (block number, block hash) for the earliest validated block
    /// * `last_block` - Tuple of (block number, block hash) for the latest validated block
    ///
    /// # Returns
    /// [`SetValidatedBlocksResponse`] containing:
    /// - `accepted`: Whether the upstream node accepted the report
    /// - `last_validated_block`: The upstream's current last validated block (number, hash)
    ///
    /// # Errors
    /// Returns error if the RPC call fails or connection is lost.
    pub async fn set_validated_blocks(
        &self,
        first_block: (u64, B256),
        last_block: (u64, B256),
    ) -> Result<SetValidatedBlocksResponse> {
        let result = self
            .data_provider
            .client()
            .request("mega_setValidatedBlocks", (first_block, last_block))
            .await
            .map_err(|e| eyre!("Failed to set validated blocks: {e}"));

        metrics::record_rpc_request("mega_setValidatedBlocks", result.is_ok());
        result
    }
}
