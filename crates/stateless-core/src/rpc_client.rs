//! RPC client for fetching blockchain data.
//!
//! Provides methods to fetch blocks, witnesses, and contract bytecode from MegaETH nodes.

use std::{collections::HashMap, sync::Arc, time::Instant};

use alloy_primitives::{B256, Bytes, U64};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag, Header};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use eyre::{Context, Result, ensure, eyre};
use futures::future;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{executor::verify_block_integrity, withdrawals::MptWitness};

/// Request keys for fetching block witness data.
/// Format compatible with both upstream witness endpoint and worker-kv-demo Cloudflare RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessRequestKeys {
    /// Block number as U64.
    pub block_number: U64,
    /// Block hash.
    pub block_hash: B256,
}

/// RPC method identifiers for metrics tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethod {
    /// eth_getCodeByHash
    EthGetCodeByHash,
    /// eth_getBlockByNumber / eth_getBlockByHash
    EthGetBlockByNumber,
    /// eth_blockNumber
    EthBlockNumber,
    /// eth_getHeaderByNumber / eth_getHeaderByHash
    EthGetHeader,
    /// mega_getBlockWitness (primary witness generator)
    MegaGetBlockWitness,
    /// mega_getBlockWitness (Cloudflare fallback)
    MegaGetBlockWitnessCloudflare,
    /// mega_setValidatedBlocks
    MegaSetValidatedBlocks,
}

impl RpcMethod {
    /// Returns the method name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            RpcMethod::EthGetCodeByHash => "eth_getCodeByHash",
            RpcMethod::EthGetBlockByNumber => "eth_getBlockByNumber",
            RpcMethod::EthGetHeader => "eth_getHeader",
            RpcMethod::EthBlockNumber => "eth_blockNumber",
            RpcMethod::MegaGetBlockWitness => "mega_getBlockWitness",
            RpcMethod::MegaGetBlockWitnessCloudflare => "mega_getBlockWitness_cloudflare",
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
    /// Optional Cloudflare witness provider for pruned/archived blocks.
    cloudflare_witness_provider: Option<RootProvider>,
    /// Optional dedicated provider for reporting validated blocks.
    report_provider: Option<RootProvider<Optimism>>,
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
        Self::new_with_config(data_api, witness_api, RpcClientConfig::default(), None, None)
    }

    /// Creates a new RPC client with custom configuration.
    ///
    /// # Arguments
    /// * `data_api` - HTTP URL of the standard JSON-RPC endpoint for blocks and contract data
    /// * `witness_api` - HTTP URL of the witness RPC endpoint for SALT witness data
    /// * `config` - Configuration controlling verification and transport behavior
    /// * `cloudflare_witness_api` - Optional HTTP URL of the Cloudflare witness endpoint
    /// * `report_api` - Optional HTTP URL of the endpoint for reporting validated blocks
    pub fn new_with_config(
        data_api: &str,
        witness_api: &str,
        config: RpcClientConfig,
        cloudflare_witness_api: Option<&str>,
        report_api: Option<&str>,
    ) -> Result<Self> {
        let cloudflare_witness_provider = cloudflare_witness_api
            .map(|url| -> Result<RootProvider> {
                Ok(ProviderBuilder::default().connect_http(
                    url.parse().context("Failed to parse Cloudflare witness API URL")?,
                ))
            })
            .transpose()?;

        let report_provider = report_api
            .map(|url| -> Result<RootProvider<Optimism>> {
                Ok(ProviderBuilder::<_, _, Optimism>::default()
                    .connect_http(url.parse().context("Failed to parse report API URL")?))
            })
            .transpose()?;

        Ok(Self {
            data_provider: ProviderBuilder::<_, _, Optimism>::default()
                .connect_http(data_api.parse().context("Failed to parse API URL")?),
            witness_provider: ProviderBuilder::default()
                .connect_http(witness_api.parse().context("Failed to parse API URL")?),
            cloudflare_witness_provider,
            report_provider,
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
        if let Err(ref e) = result {
            trace!(%hash, error = %e, "eth_getCodeByHash failed");
        }
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
        if let Err(ref e) = block {
            trace!(?block_id, error = %e, "get_block failed");
        }
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
        if let Err(ref e) = result {
            trace!(error = %e, "eth_blockNumber failed");
        }
        result
    }

    /// Gets the block header by block ID.
    ///
    /// Uses `eth_getHeaderByNumber` / `eth_getHeaderByHash` instead of `eth_getBlockByNumber`
    /// to avoid transferring the transaction hash list. Even without full transaction objects,
    /// `eth_getBlockByNumber` still returns all transaction hashes, which is significant
    /// at high TPS.
    ///
    /// When `verify_hash` is true, computes `hash_slow()` to verify the header hash matches
    /// the RPC-provided hash. This is important when initializing from a trusted start block
    /// hash, but can be skipped when the header will be verified downstream (e.g., via
    /// `verify_block_integrity`) or when running in a trusted context like the trace server.
    pub async fn get_header(&self, block_id: BlockId, verify_hash: bool) -> Result<Header> {
        let start = Instant::now();
        let result = match block_id {
            BlockId::Hash(hash) => self
                .data_provider
                .client()
                .request::<_, Header>("eth_getHeaderByHash", (hash.block_hash,))
                .await
                .map_err(|e| eyre!("eth_getHeaderByHash for {} failed: {e}", hash.block_hash)),
            BlockId::Number(tag) => self
                .data_provider
                .client()
                .request::<_, Header>("eth_getHeaderByNumber", (tag,))
                .await
                .map_err(|e| eyre!("eth_getHeaderByNumber for {:?} failed: {e}", tag)),
        };
        self.record_rpc(
            RpcMethod::EthGetHeader,
            result.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );
        let header = result?;

        // Verify block_id matches the returned header
        match block_id {
            BlockId::Number(BlockNumberOrTag::Number(num)) => {
                ensure!(
                    header.number == num,
                    "Header number mismatch: requested {}, got {}",
                    num,
                    header.number
                );
            }
            BlockId::Hash(hash) => {
                ensure!(
                    header.hash == hash.block_hash,
                    "Header hash mismatch: requested {:?}, got {:?}",
                    hash.block_hash,
                    header.hash
                );
            }
            _ => {}
        }

        if verify_hash {
            // Verify header hash matches the computed hash
            ensure!(
                header.hash_slow() == header.hash,
                "Header hash mismatch: expected {:?}, computed {:?}",
                header.hash,
                header.hash_slow()
            );
        }

        Ok(header)
    }

    /// Gets just the block hash for a block number.
    ///
    /// Uses `eth_getHeaderByNumber` to avoid transferring the large transaction hash list
    /// that `eth_getBlockByNumber` would include (e.g., for divergence checking).
    pub async fn get_block_hash(&self, block_number: u64) -> Result<B256> {
        self.get_header(BlockId::Number(BlockNumberOrTag::Number(block_number)), false)
            .await
            .map_err(|e| {
                let err = eyre!("eth_getHeaderByNumber for block {} failed: {e}", block_number);
                trace!(block_number, error = %e, "eth_getHeaderByNumber failed");
                err
            })
            .map(|h| h.hash)
    }

    /// Gets execution witness data for a specific block.
    pub async fn get_witness(&self, number: u64, hash: B256) -> Result<(SaltWitness, MptWitness)> {
        self.fetch_witness_from_provider(
            &self.witness_provider,
            number,
            hash,
            "witness_generator",
            RpcMethod::MegaGetBlockWitness,
        )
        .await
    }

    /// Returns whether a Cloudflare witness provider is configured.
    pub fn has_cloudflare_provider(&self) -> bool {
        self.cloudflare_witness_provider.is_some()
    }

    /// Gets execution witness data from the Cloudflare fallback endpoint.
    ///
    /// Single attempt, no retry (it's a KV lookup, either it exists or it doesn't).
    /// Returns error if Cloudflare provider is not configured.
    pub async fn get_witness_from_cloudflare(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness)> {
        let provider = self
            .cloudflare_witness_provider
            .as_ref()
            .ok_or_else(|| eyre!("Cloudflare witness provider not configured"))?;

        self.fetch_witness_from_provider(
            provider,
            number,
            hash,
            "cloudflare_worker",
            RpcMethod::MegaGetBlockWitnessCloudflare,
        )
        .await
    }

    /// Fetches and decodes witness data from a given provider.
    ///
    /// Both the upstream witness endpoint and the Cloudflare KV endpoint use the same
    /// unified RPC interface: `mega_getBlockWitness` with a `WitnessRequestKeys` parameter,
    /// returning a `"v0:<base64_encoded_data>"` string (zstd-compressed, bincode-serialized).
    async fn fetch_witness_from_provider(
        &self,
        provider: &RootProvider,
        number: u64,
        hash: B256,
        source: &str,
        rpc_method: RpcMethod,
    ) -> Result<(SaltWitness, MptWitness)> {
        let start = Instant::now();
        let keys = WitnessRequestKeys { block_number: U64::from(number), block_hash: hash };
        let result: Result<String> = provider
            .client()
            .request("mega_getBlockWitness", (keys,))
            .await
            .map_err(|e| eyre!("{} witness fetch failed for block {}: {}", source, number, e));

        self.record_rpc(rpc_method, result.is_ok(), Some(start.elapsed().as_secs_f64()));

        if let Err(ref e) = result {
            trace!(block_number = number, %hash, error = %e, "{source} mega_getBlockWitness failed");
        }

        let encoded = result?;

        let decode_start = Instant::now();
        let (salt_witness, mpt_witness) =
            tokio::task::spawn_blocking(move || -> Result<(SaltWitness, MptWitness)> {
                let b64_data = encoded
                    .strip_prefix("v0:")
                    .ok_or_else(|| eyre!("Witness response missing 'v0:' prefix"))?;
                let compressed = BASE64.decode(b64_data).context("base64 decode failed")?;
                let decompressed =
                    zstd::decode_all(compressed.as_slice()).context("zstd decompress failed")?;
                let (witness, _): ((SaltWitness, MptWitness), _) =
                    bincode::serde::decode_from_slice(&decompressed, bincode::config::legacy())
                        .context("bincode deserialize failed")?;
                Ok(witness)
            })
            .await
            .context("decode task failed")??;
        trace!(block_number = number, %hash, decode_ms = decode_start.elapsed().as_millis(), "{source} witness decoded");

        if let Some(ref metrics) = self.config.metrics {
            // Estimate sizes without full serialization (approximate but efficient)
            // SaltKey (8 bytes) + Option<SaltValue> (1 + 94 bytes) ≈ 103 bytes per entry
            let kvs_count = salt_witness.kvs.len();
            let salt_kvs_size = kvs_count * 103;

            // Proof: commitments (64 bytes each) + IPA proof (~576 bytes) + levels (5 bytes
            // each)
            let proof_size = salt_witness.proof.parents_commitments.len() * 64 +
                576 +
                salt_witness.proof.levels.len() * 5;
            let salt_size = salt_kvs_size + proof_size;

            // MptWitness: storage_root (32 bytes) + sum of state bytes
            let mpt_size = 32 + mpt_witness.state.iter().map(|b| b.len()).sum::<usize>();

            metrics.on_witness_fetch(salt_size, kvs_count, salt_kvs_size, mpt_size);
        }

        Ok((salt_witness, mpt_witness))
    }

    /// Reports a range of validated blocks via the dedicated report endpoint.
    pub async fn set_validated_blocks(
        &self,
        first_block: (u64, B256),
        last_block: (u64, B256),
    ) -> Result<SetValidatedBlocksResponse> {
        let provider =
            self.report_provider.as_ref().ok_or_else(|| eyre!("Report provider not configured"))?;
        let result = provider
            .client()
            .request("mega_setValidatedBlocks", (first_block, last_block))
            .await
            .map_err(|e| eyre!("Failed to set validated blocks: {e}"));
        self.record_rpc(RpcMethod::MegaSetValidatedBlocks, result.is_ok(), None);
        if let Err(ref e) = result {
            trace!(error = %e, "mega_setValidatedBlocks failed");
        }
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
                    tracing::trace!("Failed to fetch code for hash {:?}: {}", hash, e);
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
            .map_err(|e| {
                trace!(%tx_hash, error = %e, "get_transaction_by_hash failed");
                e
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_request_keys_serialization() {
        let keys = WitnessRequestKeys { block_number: U64::from(12345), block_hash: B256::ZERO };

        let json = serde_json::to_string(&keys).unwrap();
        // Should use camelCase
        assert!(json.contains("blockNumber"));
        assert!(json.contains("blockHash"));
        assert!(!json.contains("block_number"));
        assert!(!json.contains("block_hash"));
    }

    #[test]
    fn test_rpc_client_config_default() {
        let config = RpcClientConfig::default();
        assert!(!config.skip_block_verification);
        assert!(config.metrics.is_none());
    }

    #[test]
    fn test_rpc_client_config_validator() {
        let config = RpcClientConfig::validator();
        assert!(!config.skip_block_verification);
        assert!(config.metrics.is_none());
    }

    #[test]
    fn test_rpc_client_config_trace_server() {
        let config = RpcClientConfig::trace_server();
        assert!(config.skip_block_verification);
        assert!(config.metrics.is_none());
    }

    #[test]
    fn test_rpc_method_as_str() {
        assert_eq!(RpcMethod::EthGetCodeByHash.as_str(), "eth_getCodeByHash");
        assert_eq!(RpcMethod::EthGetBlockByNumber.as_str(), "eth_getBlockByNumber");
        assert_eq!(RpcMethod::EthBlockNumber.as_str(), "eth_blockNumber");
        assert_eq!(RpcMethod::MegaGetBlockWitness.as_str(), "mega_getBlockWitness");
        assert_eq!(
            RpcMethod::MegaGetBlockWitnessCloudflare.as_str(),
            "mega_getBlockWitness_cloudflare"
        );
        assert_eq!(RpcMethod::MegaSetValidatedBlocks.as_str(), "mega_setValidatedBlocks");
    }

    #[test]
    fn test_new_with_invalid_url() {
        let result = RpcClient::new("not a url", "http://localhost:8545");
        assert!(result.is_err());
    }

    #[test]
    fn test_new_with_valid_url() {
        let result = RpcClient::new("http://localhost:8545", "http://localhost:8546");
        assert!(result.is_ok());
        let client = result.unwrap();
        assert!(!client.has_cloudflare_provider());
    }

    #[test]
    fn test_new_with_cloudflare_provider() {
        let result = RpcClient::new_with_config(
            "http://localhost:8545",
            "http://localhost:8546",
            RpcClientConfig::default(),
            Some("http://localhost:9546"),
            None,
        );
        assert!(result.is_ok());
        let client = result.unwrap();
        assert!(client.has_cloudflare_provider());
    }

    #[test]
    fn test_new_with_invalid_cloudflare_url() {
        let result = RpcClient::new_with_config(
            "http://localhost:8545",
            "http://localhost:8546",
            RpcClientConfig::default(),
            Some("not a url"),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_block_verification() {
        let client = RpcClient::new_with_config(
            "http://localhost:8545",
            "http://localhost:8546",
            RpcClientConfig::validator(),
            None,
            None,
        )
        .unwrap();
        assert!(!client.skip_block_verification());

        let client = RpcClient::new_with_config(
            "http://localhost:8545",
            "http://localhost:8546",
            RpcClientConfig::trace_server(),
            None,
            None,
        )
        .unwrap();
        assert!(client.skip_block_verification());
    }
}
