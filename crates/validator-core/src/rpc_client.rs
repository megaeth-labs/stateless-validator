//! RPC client for fetching blockchain data.
//!
//! Provides methods to fetch blocks, witnesses, and contract bytecode from MegaETH nodes.

use std::collections::HashMap;

use alloy_primitives::{B256, Bytes, U64};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::{Context, Result, ensure, eyre};
use futures::future;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;
use serde::{Deserialize, Serialize};

use crate::{executor::verify_block_integrity, withdrawals::MptWitness};

/// Configuration for RPC client behavior.
#[derive(Debug, Clone, Default)]
pub struct RpcClientConfig {
    /// Skip ECDSA signature verification and block hash verification.
    /// Enable for trusted data sources (e.g., debug-trace-server fetching from upstream RPC)
    /// where integrity checks are unnecessary overhead.
    pub skip_block_verification: bool,
}

impl RpcClientConfig {
    /// Creates a config for validation mode (full verification).
    pub fn validator() -> Self {
        Self { skip_block_verification: false }
    }

    /// Creates a config for trace/debug mode (skip verification).
    pub fn trace_server() -> Self {
        Self { skip_block_verification: true }
    }
}

/// Response from mega_setValidatedBlocks RPC call
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetValidatedBlocksResponse {
    pub accepted: bool,
    pub last_validated_block: (U64, B256),
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
    /// Configuration controlling verification behavior
    config: RpcClientConfig,
}

impl RpcClient {
    /// Creates a new RPC client connected to MegaETH blockchain nodes.
    ///
    /// # Arguments
    /// * `data_api` - HTTP URL of the standard JSON-RPC endpoint for blocks and contract data
    /// * `witness_api` - HTTP URL of the witness RPC endpoint for SALT witness data
    pub fn new(data_api: &str, witness_api: &str) -> Result<Self> {
        Self::new_with_config(data_api, witness_api, RpcClientConfig::default())
    }

    /// Creates a new RPC client with custom configuration.
    ///
    /// # Arguments
    /// * `data_api` - HTTP URL of the standard JSON-RPC endpoint for blocks and contract data
    /// * `witness_api` - HTTP URL of the witness RPC endpoint for SALT witness data
    /// * `config` - Configuration controlling verification and transport behavior
    pub fn new_with_config(
        data_api: &str,
        witness_api: &str,
        config: RpcClientConfig,
    ) -> Result<Self> {
        Ok(Self {
            data_provider: ProviderBuilder::<_, _, Optimism>::default()
                .connect_http(data_api.parse().context("Failed to parse API URL")?),
            witness_provider: ProviderBuilder::default()
                .connect_http(witness_api.parse().context("Failed to parse API URL")?),
            config,
        })
    }

    /// Returns whether block verification is skipped.
    pub fn skip_block_verification(&self) -> bool {
        self.config.skip_block_verification
    }

    /// Gets contract bytecode for a code hash.
    pub async fn get_code(&self, hash: B256) -> Result<Bytes> {
        self.data_provider
            .client()
            .request("eth_getCodeByHash", (hash,))
            .await
            .map_err(|e| eyre!("eth_getCodeByHash for hash {hash:?} failed: {e}"))
    }

    /// Gets a block by its identifier with optional transaction details.
    ///
    /// If `skip_block_verification` is enabled in config, skips integrity checks.
    /// Otherwise performs ECDSA signature and block hash verification.
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let block = self.get_block_unchecked(block_id, full_txs).await?;
        if !self.config.skip_block_verification {
            verify_block_integrity(&block)?;
        }
        Ok(block)
    }

    /// Gets a block by its identifier without integrity checks.
    ///
    /// Use this for trusted data sources (e.g., debug-trace-server fetching from upstream RPC)
    /// where integrity checks are unnecessary overhead.
    pub async fn get_block_unchecked(
        &self,
        block_id: BlockId,
        full_txs: bool,
    ) -> Result<Block<Transaction>> {
        let block = if full_txs {
            self.data_provider.get_block(block_id).full().await?
        } else {
            self.data_provider.get_block(block_id).await?
        };

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

        Ok(block)
    }

    /// Gets the current latest block number from the blockchain.
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        self.data_provider.get_block_number().await.context("Failed to get block number")
    }

    /// Gets just the block hash for a block number.
    ///
    /// More efficient than get_block when only the hash is needed (e.g., for divergence checking).
    pub async fn get_block_hash(&self, block_number: u64) -> Result<B256> {
        let block = self
            .data_provider
            .get_block(BlockId::Number(block_number.into()))
            .await?
            .ok_or_else(|| eyre!("Block {} not found", block_number))?;
        Ok(block.header.hash)
    }

    /// Gets execution witness data for a specific block.
    pub async fn get_witness(&self, number: u64, hash: B256) -> Result<(SaltWitness, MptWitness)> {
        let (witness, mpt_witness): (SaltWitness, MptWitness) = self
            .witness_provider
            .client()
            .request("mega_getBlockWitness", (number.to_string(), hash))
            .await
            .map_err(|e| eyre!("Failed to get witness for block {hash}: {e}"))?;

        Ok((witness, mpt_witness))
    }

    /// Reports a range of validated blocks to the upstream node.
    pub async fn set_validated_blocks(
        &self,
        first_block: (u64, B256),
        last_block: (u64, B256),
    ) -> Result<SetValidatedBlocksResponse> {
        self.data_provider
            .client()
            .request("mega_setValidatedBlocks", (first_block, last_block))
            .await
            .map_err(|e| eyre!("Failed to set validated blocks: {e}"))
    }

    /// Gets contract bytecode for multiple code hashes concurrently.
    ///
    /// Fetches bytecode for all the given hashes in parallel, filtering out any that fail to fetch.
    pub async fn get_codes(&self, hashes: &[B256]) -> Result<HashMap<B256, Bytecode>> {
        let results = future::join_all(hashes.iter().map(|&hash| async move {
            match self.get_code(hash).await {
                Ok(bytes) => Some((hash, Bytecode::new_raw(bytes))),
                Err(e) => {
                    tracing::warn!("Failed to fetch code for hash {:?}: {}", hash, e);
                    None
                }
            }
        }))
        .await;

        Ok(results.into_iter().flatten().collect())
    }

    /// Gets the transaction by hash and returns its containing block hash.
    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: B256,
    ) -> Result<Option<(Transaction, B256)>> {
        let tx = self
            .data_provider
            .get_transaction_by_hash(tx_hash)
            .await
            .context("Failed to get transaction by hash")?;

        match tx {
            Some(tx) => {
                let block_hash = tx.block_hash.ok_or_else(|| {
                    eyre!("Transaction {} is pending and has no block hash", tx_hash)
                })?;
                Ok(Some((tx, block_hash)))
            }
            None => Ok(None),
        }
    }
}
