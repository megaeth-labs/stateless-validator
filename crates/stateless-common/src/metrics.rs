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
    /// mega_getBlockWitness (any witness provider)
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
            RpcMethod::EthGetHeader => "eth_getHeader",
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
    /// Called when an RPC request completes (final outcome — success or permanent failure).
    fn on_rpc_complete(&self, method: RpcMethod, success: bool, duration_secs: Option<f64>);

    /// Called on each transient failure that will be retried (not on the final outcome).
    ///
    /// Default: no-op. Implement to track retry volume separately from logical errors.
    fn on_rpc_retry(&self, _method: RpcMethod) {}

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
#[derive(Clone)]
pub struct RpcClientConfig {
    /// Skip ECDSA signature verification and block hash verification.
    /// Enable for trusted data sources (e.g., debug-trace-server fetching from upstream RPC)
    /// where integrity checks are unnecessary overhead.
    pub skip_block_verification: bool,
    /// Optional metrics callbacks for tracking RPC performance.
    pub metrics: Option<Arc<dyn RpcMetrics>>,
    /// Maximum number of concurrent in-flight RPC requests across all methods.
    /// Implemented as a semaphore to prevent thundering herd under many parallel workers.
    /// `None` means unlimited concurrency.
    pub max_concurrent_requests: Option<usize>,
    /// Maximum number of per-call retry attempts before propagating the error.
    /// Does not apply to `get_witness` (which falls back across providers instead).
    pub max_retries: u32,
    /// Initial backoff duration before the first retry (milliseconds).
    pub initial_backoff_ms: u64,
    /// Upper cap on per-call backoff (milliseconds; backoff doubles each retry).
    pub max_backoff_ms: u64,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            skip_block_verification: false,
            metrics: None,
            max_concurrent_requests: None,
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 10_000,
        }
    }
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
        Self { skip_block_verification: false, ..Default::default() }
    }

    /// Creates a config for trace/debug mode (skip verification).
    pub fn trace_server() -> Self {
        Self { skip_block_verification: true, ..Default::default() }
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
        assert_eq!(RpcMethod::MegaSetValidatedBlocks.as_str(), "mega_setValidatedBlocks");
    }
}
