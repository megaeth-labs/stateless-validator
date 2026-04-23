//! RPC metrics types shared by both binaries.
//!
//! Provides [`RpcMethod`] for identifying RPC calls and [`RpcMetrics`] as a
//! callback trait for tracking RPC performance.

use crate::witness_size::WitnessSizeBreakdown;

/// Byte-size histogram buckets: 1 KB, 10 KB, 50 KB, 200 KB, 1 MB, 5 MB, 20 MB.
pub const BYTE_BUCKETS: &[f64] =
    &[1_024.0, 10_240.0, 51_200.0, 204_800.0, 1_048_576.0, 5_242_880.0, 20_971_520.0];

/// Reorg depth (~ 1–50 blocks).
pub const REORG_DEPTH_BUCKETS: &[f64] = &[1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 50.0];

/// RPC method identifiers for metrics tracking.
///
/// `EthGetBlock` and `EthGetHeader` each cover both the by-number and by-hash call
/// flavors; [`as_str`] returns the by-number label (validator default) and binaries
/// whose hot path is by-hash remap via their own [`RpcMetrics`] adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethod {
    /// eth_getCodeByHash
    EthGetCodeByHash,
    /// eth_getBlockByNumber / eth_getBlockByHash
    EthGetBlock,
    /// eth_blockNumber
    EthBlockNumber,
    /// eth_getHeaderByNumber / eth_getHeaderByHash
    EthGetHeader,
    /// eth_getTransactionByHash
    EthGetTransactionByHash,
    /// mega_getBlockWitness (any witness provider)
    MegaGetBlockWitness,
    /// mega_setValidatedBlocks
    MegaSetValidatedBlocks,
}

impl RpcMethod {
    /// Returns the default dashboard label for this method.
    pub fn as_str(&self) -> &'static str {
        match self {
            RpcMethod::EthGetCodeByHash => "eth_getCodeByHash",
            RpcMethod::EthGetBlock => "eth_getBlockByNumber",
            RpcMethod::EthGetHeader => "eth_getHeader",
            RpcMethod::EthBlockNumber => "eth_blockNumber",
            RpcMethod::EthGetTransactionByHash => "eth_getTransactionByHash",
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
    fn on_witness_fetch(&self, breakdown: WitnessSizeBreakdown);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_method_as_str() {
        assert_eq!(RpcMethod::EthGetCodeByHash.as_str(), "eth_getCodeByHash");
        assert_eq!(RpcMethod::EthGetBlock.as_str(), "eth_getBlockByNumber");
        assert_eq!(RpcMethod::EthBlockNumber.as_str(), "eth_blockNumber");
        assert_eq!(RpcMethod::MegaGetBlockWitness.as_str(), "mega_getBlockWitness");
        assert_eq!(RpcMethod::MegaSetValidatedBlocks.as_str(), "mega_setValidatedBlocks");
    }
}
