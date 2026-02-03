//! RPC client for fetching blockchain data.
//!
//! Provides methods to fetch blocks, witnesses, and contract bytecode from MegaETH nodes.

use std::{collections::HashMap, sync::Arc, time::Instant};

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

/// RPC method identifiers for metrics tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethod {
    /// eth_getCodeByHash
    EthGetCodeByHash,
    /// eth_getBlockByNumber / eth_getBlockByHash
    EthGetBlockByNumber,
    /// eth_blockNumber
    EthBlockNumber,
    /// mega_getBlockWitness
    MegaGetBlockWitness,
    /// mega_setValidatedBlocks
    MegaSetValidatedBlocks,
}

impl RpcMethod {
    /// Returns the method name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            RpcMethod::EthGetCodeByHash => "eth_getCodeByHash",
            RpcMethod::EthGetBlockByNumber => "eth_getBlockByNumber",
            RpcMethod::EthBlockNumber => "eth_blockNumber",
            RpcMethod::MegaGetBlockWitness => "mega_getBlockWitness",
            RpcMethod::MegaSetValidatedBlocks => "mega_setValidatedBlocks",
        }
    }
}

/// Trait for RPC metrics callbacks.
///
/// Implement this trait to receive metrics events from the RPC client.
pub trait RpcMetrics: Send + Sync {
    /// Called when an RPC request completes.
    ///
    /// # Arguments
    /// * `method` - The RPC method that was called
    /// * `success` - Whether the call succeeded
    /// * `duration_secs` - Optional duration of the call in seconds
    fn on_rpc_complete(&self, method: RpcMethod, success: bool, duration_secs: Option<f64>);

    /// Called when witness data is successfully fetched.
    ///
    /// # Arguments
    /// * `salt_size` - Estimated size of the salt witness in bytes
    /// * `kvs_count` - Number of key-value pairs in the witness
    /// * `salt_kvs_size` - Size of the key-value data in bytes
    /// * `mpt_size` - Size of the MPT witness in bytes
    fn on_witness_fetch(
        &self,
        salt_size: usize,
        kvs_count: usize,
        salt_kvs_size: usize,
        mpt_size: usize,
    );
}

/// Configuration for RPC client behavior.
#[derive(Clone, Default)]
pub struct RpcClientConfig {
    /// Skip ECDSA signature verification and block hash verification.
    /// Enable for trusted data sources (e.g., debug-trace-server fetching from upstream RPC)
    /// where integrity checks are unnecessary overhead.
    pub skip_block_verification: bool,
    /// Optional metrics callbacks for tracking RPC performance.
    pub metrics: Option<Arc<dyn RpcMetrics>>,
}

impl std::fmt::Debug for RpcClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClientConfig")
            .field("skip_block_verification", &self.skip_block_verification)
            .field("metrics", &self.metrics.is_some())
            .finish()
    }
}

impl RpcClientConfig {
    /// Creates a config for validation mode (full verification).
    pub fn validator() -> Self {
        Self { skip_block_verification: false, metrics: None }
    }

    /// Creates a config for trace/debug mode (skip verification).
    pub fn trace_server() -> Self {
        Self { skip_block_verification: true, metrics: None }
    }

    /// Sets the metrics callbacks.
    pub fn with_metrics(mut self, metrics: Arc<dyn RpcMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
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

    /// Records an RPC metrics event if metrics are configured.
    fn record_rpc(&self, method: RpcMethod, success: bool, duration_secs: Option<f64>) {
        if let Some(ref metrics) = self.config.metrics {
            metrics.on_rpc_complete(method, success, duration_secs);
        }
    }

    /// Gets contract bytecode for a code hash.
    pub async fn get_code(&self, hash: B256) -> Result<Bytes> {
        let start = Instant::now();
        let result = self
            .data_provider
            .client()
            .request("eth_getCodeByHash", (hash,))
            .await
            .map_err(|e| eyre!("eth_getCodeByHash for hash {hash:?} failed: {e}"));
        self.record_rpc(
            RpcMethod::EthGetCodeByHash,
            result.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );
        result
    }

    /// Gets a block by its identifier with optional transaction details.
    ///
    /// If `skip_block_verification` is enabled in config, skips integrity checks.
    /// Otherwise performs ECDSA signature and block hash verification.
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let start = Instant::now();
        let block = self.get_block_unchecked(block_id, full_txs).await;
        self.record_rpc(
            RpcMethod::EthGetBlockByNumber,
            block.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );
        let block = block?;
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
        let result =
            self.data_provider.get_block_number().await.context("Failed to get block number");
        self.record_rpc(RpcMethod::EthBlockNumber, result.is_ok(), None);
        result
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
        let start = Instant::now();
        let result: Result<(SaltWitness, MptWitness)> = self
            .witness_provider
            .client()
            .request("mega_getBlockWitness", (number.to_string(), hash))
            .await
            .map_err(|e| eyre!("Failed to get witness for block {hash}: {e}"));

        self.record_rpc(
            RpcMethod::MegaGetBlockWitness,
            result.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );

        if let Ok((ref witness, ref mpt_witness)) = result &&
            let Some(ref metrics) = self.config.metrics
        {
            // Estimate sizes without full serialization (approximate but efficient)
            // SaltKey (8 bytes) + Option<SaltValue> (1 + 94 bytes) ≈ 103 bytes per entry
            let kvs_count = witness.kvs.len();
            let salt_kvs_size = kvs_count * 103;

            // Proof: commitments (64 bytes each) + IPA proof (~576 bytes) + levels (5 bytes
            // each)
            let proof_size =
                witness.proof.parents_commitments.len() * 64 + 576 + witness.proof.levels.len() * 5;
            let salt_size = salt_kvs_size + proof_size;

            // MptWitness: storage_root (32 bytes) + sum of state bytes
            let mpt_size = 32 + mpt_witness.state.iter().map(|b| b.len()).sum::<usize>();

            metrics.on_witness_fetch(salt_size, kvs_count, salt_kvs_size, mpt_size);
        }

        result
    }

    /// Reports a range of validated blocks to the upstream node.
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
        self.record_rpc(RpcMethod::MegaSetValidatedBlocks, result.is_ok(), None);
        result
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
