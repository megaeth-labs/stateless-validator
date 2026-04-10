//! RPC metrics types shared by both binaries.
//!
//! Provides [`RpcMethod`] for identifying RPC calls and [`RpcMetrics`] as a
//! callback trait for tracking RPC performance.

use std::sync::Arc;

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
    fn on_rpc_complete(&self, method: RpcMethod, success: bool, duration_secs: Option<f64>);

    /// Called when witness data is successfully fetched.
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

#[cfg(test)]
mod tests {
    use super::*;

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
