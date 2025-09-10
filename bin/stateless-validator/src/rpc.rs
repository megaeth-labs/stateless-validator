//! RPC client for the stateless validator.
//!
//! The `RpcClient` is used to communicate with a full Ethereum node to fetch data
//! required for validation that is not present in the `BlockWitness` (e.g., contract code,
//! historical block).
use alloy_primitives::{Address, B256, Bytes};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::{Result, eyre};
use futures::future::try_join_all;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;

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
