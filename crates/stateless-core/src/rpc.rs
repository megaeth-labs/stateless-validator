//! RPC abstraction layer for stateless validation.
//!
//! Defines the public API contract for fetching blockchain data:
//! - [`ChainDataProvider`]: Async trait for block/witness fetching (used by `chain_sync`)
//! - [`RpcMethod`]: RPC method identifiers for metrics tracking
//! - [`RpcMetrics`]: Callback trait for RPC performance metrics
//! - [`RpcClientConfig`]: Configuration for concrete RPC client behavior
//!
//! Concrete implementations live in the `stateless-common` crate.

use std::{future::Future, sync::Arc};

use alloy_primitives::{B256, U64};
use alloy_rpc_types_eth::{Block, BlockId};
use eyre::Result;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use serde::{Deserialize, Serialize};

use crate::withdrawals::MptWitness;

// ===========================================================================
// ChainDataProvider trait
// ===========================================================================

/// Async trait for fetching blockchain data from a remote source.
///
/// This is the abstraction that allows `chain_sync` to work without
/// depending on any concrete HTTP client. The concrete `RpcClient`
/// in `stateless-common` implements this trait.
pub trait ChainDataProvider: Send + Sync {
    /// Gets the current latest block number from the blockchain.
    fn get_latest_block_number(&self) -> impl Future<Output = Result<u64>> + Send;

    /// Gets just the block hash for a block number.
    fn get_block_hash(&self, block_number: u64) -> impl Future<Output = Result<B256>> + Send;

    /// Gets execution witness data for a specific block.
    fn get_witness(
        &self,
        number: u64,
        hash: B256,
    ) -> impl Future<Output = Result<(SaltWitness, MptWitness)>> + Send;

    /// Gets a block by its identifier with optional transaction details.
    fn get_block(
        &self,
        block_id: BlockId,
        full_txs: bool,
    ) -> impl Future<Output = Result<Block<Transaction>>> + Send;
}

/// Blanket implementation so `Arc<C>` also implements `ChainDataProvider`.
impl<C: ChainDataProvider> ChainDataProvider for Arc<C> {
    fn get_latest_block_number(&self) -> impl Future<Output = Result<u64>> + Send {
        (**self).get_latest_block_number()
    }

    fn get_block_hash(&self, block_number: u64) -> impl Future<Output = Result<B256>> + Send {
        (**self).get_block_hash(block_number)
    }

    fn get_witness(
        &self,
        number: u64,
        hash: B256,
    ) -> impl Future<Output = Result<(SaltWitness, MptWitness)>> + Send {
        (**self).get_witness(number, hash)
    }

    fn get_block(
        &self,
        block_id: BlockId,
        full_txs: bool,
    ) -> impl Future<Output = Result<Block<Transaction>>> + Send {
        (**self).get_block(block_id, full_txs)
    }
}

// ===========================================================================
// RPC data types and traits
// ===========================================================================

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
}
