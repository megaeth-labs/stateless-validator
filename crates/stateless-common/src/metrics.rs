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

/// Outcome of a single provider attempt inside the retry loop.
///
/// The retry loop reports one of these per provider round trip, so metrics can
/// attribute latency and failure *reason* per endpoint instead of collapsing
/// every non-success into one opaque error count. `Error` and `Timeout` are
/// both retriable failures; the split lets operators tell a provider that
/// answered with an error from one that stalled and had to be timed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcAttemptOutcome {
    /// The provider returned a usable response.
    Success,
    /// The provider returned an error, or its response failed to decode.
    Error,
    /// The attempt hit the per-attempt timeout: the provider accepted the
    /// request but did not answer within the budget (a stall).
    Timeout,
    /// The attempt was abandoned because the *logical call's* deadline elapsed while it
    /// was still running. Separate from [`Self::Timeout`]: the attempt window was clamped
    /// to the remaining budget, so the provider never got a fair round trip — but the
    /// attempt did consume that budget, and dropping it would make a provider that
    /// swallows the entire remaining budget indistinguishable from one never called.
    DeadlineClamped,
}

impl RpcAttemptOutcome {
    /// Stable metric-label string for this outcome.
    pub fn as_str(&self) -> &'static str {
        match self {
            RpcAttemptOutcome::Success => "success",
            RpcAttemptOutcome::DeadlineClamped => "deadline_clamped",
            RpcAttemptOutcome::Error => "error",
            RpcAttemptOutcome::Timeout => "timeout",
        }
    }

    /// Whether this attempt succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, RpcAttemptOutcome::Success)
    }
}

/// Trait for RPC metrics callbacks.
///
/// Implement this trait to receive metrics events from the RPC client. All
/// callbacks fire from inside the retry loop, so `on_rpc_attempt` is called
/// once per provider round trip (not once per logical call).
pub trait RpcMetrics: Send + Sync {
    /// Called once per provider attempt, tagged with the endpoint `provider`
    /// label and the attempt [`RpcAttemptOutcome`].
    ///
    /// Every round trip the retry loop makes fires exactly one of these, so
    /// both per-endpoint latency (via `duration_secs`) and per-reason failure
    /// counts (via `outcome`) are derivable. `provider` is a bounded,
    /// credential-free endpoint label (see the RPC client's `endpoint_label`).
    fn on_rpc_attempt(
        &self,
        method: RpcMethod,
        provider: &str,
        outcome: RpcAttemptOutcome,
        duration_secs: f64,
    );

    /// Called on each transient failure that will be retried (not on the final outcome).
    ///
    /// Default: no-op. Implement to track retry volume separately from logical errors.
    fn on_rpc_retry(&self, _method: RpcMethod) {}

    /// Called once per permit-queue wait: before each attempt starts, and for a wait the
    /// caller's deadline cut short (which therefore yielded no attempt).
    ///
    /// Separates "the endpoint was slow" from "we were queued behind our own concurrency
    /// cap" — two causes with opposite fixes that are otherwise indistinguishable, because
    /// the permit wait sits inside the caller's deadline and emits no signal of its own.
    /// Default: no-op.
    fn on_rpc_permit_wait(&self, _method: RpcMethod, _wait_secs: f64) {}

    /// Called when a logical call gives up because its overall deadline elapsed.
    ///
    /// Distinct from a per-attempt [`RpcAttemptOutcome::Timeout`]: this counts
    /// the *logical call* exhausting its whole budget (e.g. a witness fetch's
    /// 3s deadline), which is the operator-facing "request timed out" signal.
    /// Fires at most once per logical call. Default: no-op.
    fn on_rpc_deadline_exceeded(&self, _method: RpcMethod, _elapsed_secs: f64) {}

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

    #[test]
    fn test_rpc_attempt_outcome() {
        assert_eq!(RpcAttemptOutcome::Success.as_str(), "success");
        assert_eq!(RpcAttemptOutcome::Error.as_str(), "error");
        assert_eq!(RpcAttemptOutcome::Timeout.as_str(), "timeout");
        assert_eq!(RpcAttemptOutcome::DeadlineClamped.as_str(), "deadline_clamped");
        assert!(RpcAttemptOutcome::Success.is_success());
        assert!(!RpcAttemptOutcome::Error.is_success());
        assert!(!RpcAttemptOutcome::Timeout.is_success());
        assert!(!RpcAttemptOutcome::DeadlineClamped.is_success());
    }
}
