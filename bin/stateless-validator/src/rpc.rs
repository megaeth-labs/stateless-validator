//! RPC client for the stateless validator.
//!
//! The `RpcClient` is used to communicate with a full Ethereum node to fetch data
//! required for validation that is not present in the `BlockWitness` (e.g., contract code,
//! historical block).
use alloy_primitives::{Address, B256, Bytes, hex};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::{Result, eyre};
use futures::future::try_join_all;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;

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
        let futures = addresses.iter().map(|&addr| {
            let provider = self.provider.clone();

            async move {
                provider
                    .get_code_at(addr)
                    .block_id(block_number.into())
                    .await
                    .map_err(|e| {
                        eyre!(
                            "get_code_at for address {addr:?} at block {block_number:?} failed: {e}"
                        )
                    })
            }
        });

        try_join_all(futures).await
    }

    /// Fetches a full block by its number.
    pub async fn block_by_number(&self, number: u64, full_txs: bool) -> Result<Block<Transaction>> {
        self.fetch_block(BlockId::Number(number.into()), full_txs)
            .await
            .map_err(|e| eyre!("get_block_by_number at {number} failed: {e}"))
    }

    /// Fetches the latest block number from the blockchain.
    pub async fn block_number(&self) -> Result<u64> {
        self.provider
            .get_block_number()
            .await
            .map_err(|e| eyre!("get_block_number failed: {e}"))
    }

    /// Fetches a witness by its block hash.
    pub async fn witness_by_block_hash(&self, hash: B256) -> Result<SaltWitness> {
        let witness_data: Vec<u8> = self
            .provider
            .client()
            .request("eth_getWitness", (format!("0x{}", hex::encode(hash)),))
            .await
            .map_err(|e| eyre!("get_witness for block {hash} failed: {e}"))?;

        let (witness, _): (SaltWitness, usize) =
            bincode::serde::decode_from_slice(&witness_data, bincode::config::legacy())
                .map_err(|e| eyre!("Failed to decode witness for block {hash}: {e}"))?;

        Ok(witness)
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
