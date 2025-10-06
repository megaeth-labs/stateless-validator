//! RPC client for fetching missing data during stateless validation.
//!
//! Fetches contract bytecode, blocks, and SALT witness data from OP Stack nodes
//! when not present in witness files.
use alloy_primitives::{Address, B256, Bytes, hex};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::{Context, Result, eyre};
use futures::future::try_join_all;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use validator_core::withdrawals::MptWitness;

/// RPC client for OP Stack nodes.
///
/// Fetches missing contract bytecode, blocks, and witness data during stateless validation.
/// Executes requests concurrently for performance.
#[derive(Debug, Clone)]
pub struct RpcClient {
    /// OP Stack RPC provider.
    pub provider: RootProvider<Optimism>,
}

impl RpcClient {
    /// Creates a new RPC client connected to an Ethereum node.
    ///
    /// # Arguments
    /// * `api` - HTTP URL of the Ethereum RPC endpoint (e.g., "http://localhost:8545")
    ///
    /// # Returns
    /// Configured RPC client ready to make requests to the Optimism network.
    ///
    /// # Errors
    /// Returns error if the API URL is malformed or invalid.
    pub fn new(api: &str) -> Result<Self> {
        Ok(Self {
            provider: ProviderBuilder::<_, _, Optimism>::default()
                .connect_http(api.parse().context("Failed to parse API URL")?),
        })
    }

    /// Gets contract bytecode for multiple addresses at a specific block height.
    ///
    /// # Arguments
    /// * `addresses` - Contract addresses to fetch bytecode for
    /// * `block_number` - Block height to query (supports latest, earliest, pending)
    ///
    /// # Returns
    /// Vector of bytecode in the same order as input addresses. Empty bytecode
    /// is returned for addresses without deployed contracts.
    ///
    /// # Performance
    /// Executes all requests concurrently for optimal performance.
    pub async fn get_code(
        &self,
        addresses: &[Address],
        block_number: BlockNumberOrTag,
    ) -> Result<Vec<Bytes>> {
        try_join_all(addresses.iter().map(|&addr| async move {
            self.provider
                .get_code_at(addr)
                .block_id(block_number.into())
                .await
                .context(format!(
                    "get_code_at for address {addr:?} at block {block_number:?}"
                ))
        }))
        .await
    }

    /// Gets a block by its identifier with optional transaction details.
    ///
    /// # Arguments
    /// * `block_id` - Block identifier (number, hash, latest, etc.)
    /// * `full_txs` - If true, includes full transaction objects; if false, only transaction hashes
    ///
    /// # Returns
    /// Complete block data including header, transactions, and metadata.
    ///
    /// # Errors
    /// Returns error if block doesn't exist or RPC call fails.
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let block = if full_txs {
            self.provider.get_block(block_id).full().await?
        } else {
            self.provider.get_block(block_id).await?
        };
        block.ok_or_else(|| eyre!("Block {:?} not found", block_id))
    }

    /// Gets the current latest block number from the blockchain.
    ///
    /// # Returns
    /// The highest block number that has been mined.
    ///
    /// # Errors
    /// Returns error if unable to connect to the blockchain or RPC fails.
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        self.provider
            .get_block_number()
            .await
            .context("Failed to get block number")
    }

    /// Gets execution witness data for a specific block.
    ///
    /// # Arguments
    /// * `hash` - Block hash to fetch witness data for
    ///
    /// # Returns
    /// Decoded witness containing state access patterns and execution traces
    /// required for stateless validation.
    ///
    /// # Errors
    /// Returns error if block hash doesn't exist, witness unavailable, or
    /// witness data is corrupted and cannot be decoded.
    pub async fn get_witness(&self, hash: B256) -> Result<(SaltWitness, MptWitness)> {
        self.provider
            .client()
            .request("eth_getWitness", (format!("0x{}", hex::encode(hash)),))
            .await
            .context(format!("get_witness for block {hash}"))
            .and_then(|data: Vec<u8>| {
                bincode::serde::decode_from_slice(&data, bincode::config::legacy())
                    .map(
                        |((salt_witness, mpt_witness), _): ((SaltWitness, MptWitness), usize)| {
                            (salt_witness, mpt_witness)
                        },
                    )
                    .context(format!("Failed to decode witness for block {hash}"))
            })
    }
}
