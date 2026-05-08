//! Concrete RPC client for fetching blockchain data.
//!
//! Provides [`RpcClient`] — the HTTP-based client for fetching blocks, witnesses, and
//! contract bytecode from MegaETH nodes.
//!
//! ## Network resilience
//!
//! - **Multi-endpoint data support**: accepts an ordered list of data endpoints.
//! - **Multi-endpoint witness support**: accepts an ordered list of witness endpoints.
//! - **Concurrency limiting**: two independent [`tokio::sync::Semaphore`]s cap in-flight requests —
//!   one for data-endpoint calls (blocks/headers/code/tx), one for witness fetches — so a burst on
//!   one path cannot starve the other. `set_validated_blocks` is unthrottled.
//! - **Retry model**: within a single logical call, each provider is attempted once per round. If
//!   all providers in a round fail, the client sleeps for round-level exponential backoff (capped
//!   at [`BackoffPolicy::max`](crate::BackoffPolicy)) and starts a new round. Load distribution
//!   differs by method type:
//!   - **Data** (blocks/headers/code/tx): round-robin starting provider rotates per call, so
//!     healthy endpoints share load evenly.
//!   - **Witness**: round always starts from provider 0 — the first witness endpoint is the
//!     primary, others are failover-only.
//! - **Deadlines**: every public method has a `_with_deadline` variant that takes an
//!   `Option<Instant>`. With `Some(deadline)` the retry loop returns [`RpcDeadlineExceeded`] once
//!   the wall-clock deadline passes (and clamps each inter-round sleep so it doesn't overshoot).
//!   With `None` the loop retries forever — this is the validator's background-sync contract. The
//!   non-`_with_deadline` methods delegate to the deadline version with `None`.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

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
use stateless_core::withdrawals::MptWitness;
use tokio::sync::Semaphore;
use tracing::{trace, warn};

use crate::{
    metrics::{RpcMethod, RpcMetrics},
    witness_size::WitnessSizeBreakdown,
};

/// Exponential-backoff policy used by [`RpcClient`]'s round-level retry loop.
///
/// `initial` is the first sleep duration; each round doubles it up to `max`.
/// The loop itself lives in [`round_robin_with_backoff`]; this type only describes
/// the sleep schedule.
#[derive(Debug, Clone)]
pub struct BackoffPolicy {
    /// First retry sleep. Each subsequent retry doubles up to `max`.
    pub initial: Duration,
    /// Upper bound on any single retry sleep.
    pub max: Duration,
}

impl BackoffPolicy {
    /// Creates a new policy with the given `initial` and `max` sleep durations.
    pub const fn new(initial: Duration, max: Duration) -> Self {
        Self { initial, max }
    }
}

/// Error returned by the `_with_deadline` RPC methods when a caller-supplied
/// deadline elapses before any provider succeeds.
///
/// The retry loop checks the deadline before each round and clamps inter-round
/// sleeps to not overshoot it, so the observed wall-clock of this error stays
/// within a small jitter of the requested deadline.
#[derive(Debug, thiserror::Error)]
pub struct RpcDeadlineExceeded {
    /// The RPC method whose retry loop was aborted.
    pub method: RpcMethod,
    /// Wall-clock time from the first attempt to the deadline firing.
    pub elapsed: Duration,
}

impl std::fmt::Display for RpcDeadlineExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RPC call for {} exceeded deadline after {:?}",
            self.method.as_str(),
            self.elapsed
        )
    }
}

/// Configuration for [`RpcClient`] behavior.
#[derive(Clone)]
pub struct RpcClientConfig {
    /// Skip ECDSA signature verification and block hash verification.
    /// Enable for trusted data sources (e.g., debug-trace-server fetching from upstream RPC)
    /// where integrity checks are unnecessary overhead.
    pub skip_block_verification: bool,
    /// Optional metrics callbacks for tracking RPC performance.
    pub metrics: Option<Arc<dyn RpcMetrics>>,
    /// Maximum number of concurrent in-flight data-endpoint requests
    /// (blocks, headers, contract bytecode, transactions). `None` means unlimited.
    pub data_max_concurrent_requests: Option<usize>,
    /// Maximum number of concurrent in-flight witness fetches. Independent from the data cap so
    /// a burst of block fetches cannot starve witness retrieval (and vice versa). `None` means
    /// unlimited.
    pub witness_max_concurrent_requests: Option<usize>,
    /// Round-level exponential backoff policy for retrying RPC calls. When a call fails on
    /// every configured provider in a single round, the client sleeps for `initial` (with
    /// jitter) before the next round and doubles the sleep each round up to `max`. Retry is
    /// unbounded — caller-visible failures don't occur.
    pub rpc_retry: BackoffPolicy,
    /// Hard cap on a single provider attempt. Applied even when no overall deadline is set,
    /// so a provider that accepts TCP but never replies cannot wedge the retry loop —
    /// timing out the attempt rotates `round_robin_with_backoff` to the next provider.
    /// With `deadline = Some(d)`, each attempt uses `min(per_attempt_timeout, d - now)`.
    pub per_attempt_timeout: Duration,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            skip_block_verification: false,
            metrics: None,
            data_max_concurrent_requests: None,
            witness_max_concurrent_requests: None,
            // Round-level backoff: first cross-provider retry sleeps ~500ms, doubling up to
            // 30s. That's gentle enough to ride out near-tip witness generation latency (a
            // few seconds) without hammering upstream when something is genuinely broken.
            rpc_retry: BackoffPolicy::new(Duration::from_millis(500), Duration::from_secs(30)),
            // 20s is well above any healthy single-attempt latency (witness near-tip can take
            // several seconds; everything else is sub-second), but bounded enough that a
            // stalled (TCP-accept-no-reply) provider is detected within reasonable time.
            per_attempt_timeout: Duration::from_secs(20),
        }
    }
}

impl std::fmt::Debug for RpcClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClientConfig")
            .field("skip_block_verification", &self.skip_block_verification)
            .field("metrics", &self.metrics.is_some())
            .field("data_max_concurrent_requests", &self.data_max_concurrent_requests)
            .field("witness_max_concurrent_requests", &self.witness_max_concurrent_requests)
            .field("rpc_retry", &self.rpc_retry)
            .field("per_attempt_timeout", &self.per_attempt_timeout)
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

/// Boxed, `'static` future returned by `call()` closures.
type BoxFuture<T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'static>>;

/// Request parameters for `mega_getBlockWitness`, sent to every provider in
/// [`RpcClient::witness_providers`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessRequestKeys {
    /// Block number as U64.
    pub block_number: U64,
    /// Block hash.
    pub block_hash: B256,
}

/// Response from mega_setValidatedBlocks RPC call
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetValidatedBlocksResponse {
    pub accepted: bool,
    pub last_validated_block: (U64, B256),
}

/// Errors returned by [`RpcClient::get_codes`] / [`RpcClient::get_codes_with_deadline`].
///
/// - `VerificationFailure` is deterministic (upstream returned bytecode whose keccak does not match
///   the requested hash): validators should halt rather than retry.
/// - `Deadline` only surfaces from [`RpcClient::get_codes_with_deadline`] when the caller- supplied
///   deadline elapsed before every per-hash fetch completed. The unbounded [`RpcClient::get_codes`]
///   never produces this variant.
#[derive(Debug, thiserror::Error)]
pub enum CodeFetchError {
    #[error(
        "RPC provider returned bytecode with unexpected codehash: expected {requested:?}, got {actual:?}"
    )]
    VerificationFailure { requested: B256, actual: B256 },
    #[error(transparent)]
    Deadline(#[from] RpcDeadlineExceeded),
}

/// RPC client for MegaETH blockchain data.
///
/// Fetches contract bytecode, blocks, and witness data during stateless validation.
///
/// Cloning is cheap — all providers are `Arc`-backed internally.
#[derive(Debug, Clone)]
pub struct RpcClient {
    /// Ordered list of data providers. Data methods use round-robin load balancing: each call
    /// picks a starting provider via an atomic counter and cycles forward on failure.
    data_providers: Vec<RootProvider<Optimism>>,
    /// Round-robin counter for selecting the starting data provider on each call.
    /// Shared across clones so load balancing is global per logical client.
    data_rr_counter: Arc<AtomicUsize>,
    /// Ordered list of witness providers. `get_witness` always starts from index 0 (primary);
    /// later entries are failover-only.
    witness_providers: Vec<RootProvider>,
    /// Optional dedicated provider for reporting validated blocks.
    report_provider: Option<RootProvider>,
    /// Configuration controlling verification, retry, and concurrency behavior.
    config: RpcClientConfig,
    /// Semaphore capping concurrent in-flight data-endpoint requests
    /// (blocks, headers, contract bytecode, transactions).
    data_concurrency: Arc<Semaphore>,
    /// Semaphore capping concurrent in-flight witness fetches, independent of the data cap.
    witness_concurrency: Arc<Semaphore>,
}

impl RpcClient {
    /// Creates a new RPC client connected to MegaETH blockchain nodes.
    ///
    /// # Arguments
    /// * `data_apis` - HTTP URLs of the standard JSON-RPC endpoints for blocks and contract data
    ///   (tried in order)
    /// * `witness_apis` - HTTP URLs of the witness RPC endpoints (tried in order)
    pub fn new(data_apis: &[&str], witness_apis: &[&str]) -> Result<Self> {
        Self::new_with_config(data_apis, witness_apis, RpcClientConfig::default(), None)
    }

    /// Creates a new RPC client with custom configuration.
    ///
    /// # Arguments
    /// * `data_apis` - HTTP URLs of the standard JSON-RPC endpoints for blocks and contract data
    ///   (tried in order, non-empty)
    /// * `witness_apis` - HTTP URLs of the witness RPC endpoints (tried in order, non-empty)
    /// * `config` - Configuration controlling verification, retry, and concurrency behavior
    /// * `report_api` - Optional HTTP URL of the endpoint for reporting validated blocks
    pub fn new_with_config(
        data_apis: &[&str],
        witness_apis: &[&str],
        config: RpcClientConfig,
        report_api: Option<&str>,
    ) -> Result<Self> {
        if data_apis.is_empty() {
            return Err(eyre!("At least one data API URL must be provided"));
        }
        if witness_apis.is_empty() {
            return Err(eyre!("At least one witness API URL must be provided"));
        }

        let data_providers = data_apis
            .iter()
            .map(|url| -> Result<RootProvider<Optimism>> {
                Ok(ProviderBuilder::<_, _, Optimism>::default()
                    .connect_http(url.parse().context("Failed to parse data API URL")?))
            })
            .collect::<Result<Vec<_>>>()?;

        let witness_providers = witness_apis
            .iter()
            .map(|url| -> Result<RootProvider> {
                Ok(ProviderBuilder::default()
                    .connect_http(url.parse().context("Failed to parse witness API URL")?))
            })
            .collect::<Result<Vec<_>>>()?;

        let report_provider = report_api
            .map(|url| -> Result<RootProvider> {
                Ok(ProviderBuilder::default()
                    .connect_http(url.parse().context("Failed to parse report API URL")?))
            })
            .transpose()?;

        // `.max(1)` guards against `--data-max-concurrent-requests 0` (or the witness
        // equivalent) silently wedging every RPC call — `Semaphore::new(0)` blocks
        // `.acquire()` forever.
        let data_concurrency = Arc::new(Semaphore::new(
            config.data_max_concurrent_requests.unwrap_or(Semaphore::MAX_PERMITS).max(1),
        ));
        let witness_concurrency = Arc::new(Semaphore::new(
            config.witness_max_concurrent_requests.unwrap_or(Semaphore::MAX_PERMITS).max(1),
        ));

        Ok(Self {
            data_providers,
            data_rr_counter: Arc::new(AtomicUsize::new(0)),
            witness_providers,
            report_provider,
            config,
            data_concurrency,
            witness_concurrency,
        })
    }

    /// Returns whether block verification is skipped.
    pub fn skip_block_verification(&self) -> bool {
        self.config.skip_block_verification
    }

    /// Returns the number of configured data endpoints.
    pub fn data_provider_count(&self) -> usize {
        self.data_providers.len()
    }

    /// Returns the number of configured witness endpoints.
    pub fn witness_provider_count(&self) -> usize {
        self.witness_providers.len()
    }

    /// Wraps a data-method RPC call with round-robin load balancing and round-level backoff.
    ///
    /// Retries forever — transient failures never surface to callers. Use
    /// [`Self::call_with_deadline`] when the caller needs a bounded wait.
    async fn call<T: Send + 'static>(
        &self,
        method: RpcMethod,
        f: impl Fn(RootProvider<Optimism>) -> BoxFuture<Result<T>>,
    ) -> T {
        self.call_with_deadline(method, None, f).await.unwrap_or_else(|e| {
            // `None` deadline ⇒ retry loop is truly unbounded and this branch is unreachable.
            unreachable!("call() with None deadline cannot return RpcDeadlineExceeded: {e}")
        })
    }

    /// Deadline-aware counterpart of [`Self::call`].
    ///
    /// With `deadline = Some(..)` the retry loop returns [`RpcDeadlineExceeded`] once the
    /// deadline passes, clamping each inter-round sleep so it doesn't overshoot. With
    /// `None` this is equivalent to [`Self::call`] and never returns `Err`.
    ///
    /// Each call performs rounds of "try every data provider once in round-robin order".
    /// The starting provider rotates per call via an atomic counter so healthy endpoints
    /// share load evenly; within a round the order is fixed (start → start+1 → …).
    async fn call_with_deadline<T: Send + 'static>(
        &self,
        method: RpcMethod,
        deadline: Option<Instant>,
        f: impl Fn(RootProvider<Optimism>) -> BoxFuture<Result<T>>,
    ) -> std::result::Result<T, RpcDeadlineExceeded> {
        // Safety: constructor guarantees at least one data provider.
        let n = self.data_providers.len();
        // Skip the atomic op when there's a single provider — avoids pointless contention.
        let rr_start =
            if n > 1 { self.data_rr_counter.fetch_add(1, Ordering::Relaxed) % n } else { 0 };
        round_robin_with_backoff(
            &self.data_providers,
            &self.data_concurrency,
            &self.config.rpc_retry,
            self.config.per_attempt_timeout,
            rr_start,
            method,
            self.config.metrics.as_ref(),
            deadline,
            |provider| f(provider.clone()),
        )
        .await
    }

    /// Gets contract bytecode for a code hash. Retries forever.
    pub async fn get_code(&self, hash: B256) -> Bytes {
        self.get_code_with_deadline(hash, None).await.expect("None deadline cannot time out")
    }

    /// Deadline-aware counterpart of [`Self::get_code`].
    ///
    /// An empty response (`"0x"`) for a non-empty codehash is treated as a transient error and
    /// rotates round-robin to the next provider. MegaETH RPC nodes return `"0x"` for codes they
    /// have not yet synced (rather than a JSON-RPC error); without this guard, an unsynced
    /// upstream would silently return zero bytes that then fail keccak verification, halting the
    /// validator. Retrying lets a sync-ready provider serve the request.
    pub async fn get_code_with_deadline(
        &self,
        hash: B256,
        deadline: Option<Instant>,
    ) -> std::result::Result<Bytes, RpcDeadlineExceeded> {
        self.call_with_deadline(RpcMethod::EthGetCodeByHash, deadline, move |provider| {
            Box::pin(async move {
                let bytes: Bytes =
                    provider.client().request("eth_getCodeByHash", (hash,)).await.map_err(|e| {
                        trace!(%hash, error = %e, "eth_getCodeByHash failed");
                        eyre!("eth_getCodeByHash for hash {hash:?} failed: {e}")
                    })?;
                // Guard against the legitimate case where the requested hash *is* the
                // empty-code hash — then `"0x"` is the correct answer and retrying would loop
                // forever. Every other empty response is treated as upstream-not-sync-ready.
                if bytes.is_empty() && hash != revm::primitives::KECCAK_EMPTY {
                    trace!(%hash, "eth_getCodeByHash returned empty bytecode (provider not sync-ready?)");
                    return Err(eyre!(
                        "eth_getCodeByHash for hash {hash:?} returned empty bytecode (provider may not be sync-ready)"
                    ));
                }
                Ok(bytes)
            })
        })
        .await
    }

    /// Gets a block by its identifier with optional transaction details. Retries forever.
    ///
    /// If `skip_block_verification` is enabled in config, skips integrity checks.
    /// Otherwise performs ECDSA signature and block hash verification — an integrity failure
    /// is treated as a retriable error (round-robin rotates to the next provider).
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Block<Transaction> {
        self.get_block_with_deadline(block_id, full_txs, None)
            .await
            .expect("None deadline cannot time out")
    }

    /// Deadline-aware counterpart of [`Self::get_block`].
    pub async fn get_block_with_deadline(
        &self,
        block_id: BlockId,
        full_txs: bool,
        deadline: Option<Instant>,
    ) -> std::result::Result<Block<Transaction>, RpcDeadlineExceeded> {
        let verify = !self.config.skip_block_verification;
        self.call_with_deadline(RpcMethod::EthGetBlock, deadline, move |provider| {
            Box::pin(async move {
                let block = do_get_block_unchecked(&provider, block_id, full_txs).await?;
                if verify {
                    verify_block_integrity(&block)?;
                }
                Ok(block)
            })
        })
        .await
    }

    /// Gets a block by its identifier without integrity checks. Retries forever.
    ///
    /// Use this for trusted data sources (e.g., debug-trace-server fetching from upstream RPC)
    /// where integrity checks are unnecessary overhead.
    pub async fn get_block_unchecked(
        &self,
        block_id: BlockId,
        full_txs: bool,
    ) -> Block<Transaction> {
        self.call(RpcMethod::EthGetBlock, move |provider| {
            Box::pin(async move { do_get_block_unchecked(&provider, block_id, full_txs).await })
        })
        .await
    }

    /// Gets the current latest block number from the blockchain. Retries forever.
    pub async fn get_latest_block_number(&self) -> u64 {
        self.get_latest_block_number_with_deadline(None)
            .await
            .expect("None deadline cannot time out")
    }

    /// Deadline-aware counterpart of [`Self::get_latest_block_number`].
    pub async fn get_latest_block_number_with_deadline(
        &self,
        deadline: Option<Instant>,
    ) -> std::result::Result<u64, RpcDeadlineExceeded> {
        self.call_with_deadline(RpcMethod::EthBlockNumber, deadline, move |provider| {
            Box::pin(async move {
                provider.get_block_number().await.context("Failed to get block number").map_err(
                    |e| {
                        trace!(error = %e, "eth_blockNumber failed");
                        e
                    },
                )
            })
        })
        .await
    }

    /// Gets the block header by block ID. Retries forever.
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
    pub async fn get_header(&self, block_id: BlockId, verify_hash: bool) -> Header {
        self.get_header_with_deadline(block_id, verify_hash, None)
            .await
            .expect("None deadline cannot time out")
    }

    /// Deadline-aware counterpart of [`Self::get_header`].
    pub async fn get_header_with_deadline(
        &self,
        block_id: BlockId,
        verify_hash: bool,
        deadline: Option<Instant>,
    ) -> std::result::Result<Header, RpcDeadlineExceeded> {
        self.call_with_deadline(RpcMethod::EthGetHeader, deadline, move |provider| {
            Box::pin(async move {
                do_get_header(&provider, block_id, verify_hash).await.map_err(|e| {
                    trace!(?block_id, error = %e, "get_header failed");
                    e
                })
            })
        })
        .await
    }

    /// Gets just the block hash for a block number. Retries forever.
    pub async fn get_block_hash(&self, block_number: u64) -> B256 {
        self.get_header(BlockId::Number(BlockNumberOrTag::Number(block_number)), false).await.hash
    }

    /// Deadline-aware counterpart of [`Self::get_block_hash`].
    pub async fn get_block_hash_with_deadline(
        &self,
        block_number: u64,
        deadline: Option<Instant>,
    ) -> std::result::Result<B256, RpcDeadlineExceeded> {
        self.get_header_with_deadline(
            BlockId::Number(BlockNumberOrTag::Number(block_number)),
            false,
            deadline,
        )
        .await
        .map(|h| h.hash)
    }

    /// Gets execution witness data for a specific block. Retries forever.
    ///
    /// Uses primary-failover rather than round-robin: each round starts from provider 0
    /// (the primary), falling through to later providers only on failure. If every provider
    /// fails in a round, sleeps for round-level exponential backoff and starts another round.
    /// This keeps the primary endpoint as the hot path (cache-friendly) while still
    /// tolerating its temporary outages.
    pub async fn get_witness(&self, number: u64, hash: B256) -> (SaltWitness, MptWitness) {
        self.get_witness_with_deadline(number, hash, None)
            .await
            .expect("None deadline cannot time out")
    }

    /// Deadline-aware counterpart of [`Self::get_witness`].
    pub async fn get_witness_with_deadline(
        &self,
        number: u64,
        hash: B256,
        deadline: Option<Instant>,
    ) -> std::result::Result<(SaltWitness, MptWitness), RpcDeadlineExceeded> {
        let witness = round_robin_with_backoff(
            &self.witness_providers,
            &self.witness_concurrency,
            &self.config.rpc_retry,
            self.config.per_attempt_timeout,
            // Primary-failover: always start from provider 0 so the primary takes all traffic
            // while healthy. Backup endpoints are touched only while the primary is failing.
            0,
            RpcMethod::MegaGetBlockWitness,
            self.config.metrics.as_ref(),
            deadline,
            |provider| Box::pin(async move { fetch_witness_raw(&provider, number, hash).await }),
        )
        .await?;

        if let Some(ref metrics) = self.config.metrics {
            metrics.on_witness_fetch(WitnessSizeBreakdown::new(&witness.0, &witness.1));
        }
        Ok(witness)
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
            .map_err(|e| {
                trace!(error = %e, "mega_setValidatedBlocks failed");
                eyre!("Failed to set validated blocks: {e}")
            });
        if let Some(ref metrics) = self.config.metrics {
            metrics.on_rpc_complete(RpcMethod::MegaSetValidatedBlocks, result.is_ok(), None);
        }
        result
    }

    /// Gets contract bytecode for multiple code hashes concurrently.
    ///
    /// When `verify` is `true`, each returned bytecode's keccak hash is checked against its
    /// requested code hash inside the same per-hash future, so hashing runs concurrently
    /// with the remaining fetches.
    ///
    /// # Fail-fast on mismatch
    ///
    /// A single hash mismatch aborts the whole batch with an `Err`, and the bytecodes for the
    /// other (concurrently-fetched and verified) hashes in the same batch are **discarded** —
    /// they are not returned and not cached. This is an intentional security tradeoff: a
    /// misbehaving or malicious upstream in the batch taints the entire fetch, and we would
    /// rather re-do the round-trip than risk priming the cache with any byte from a provider
    /// that has demonstrated bad data in this batch. A persistently-misbehaving upstream will
    /// cause repeated failures for any block touching the offending contract until the
    /// operator intervenes — failure is the intended signal, not silent skipping.
    ///
    /// # Return type
    ///
    /// Returns `Arc<Bytecode>` so the value shares one allocation with the
    /// [`crate::ContractCache`] end-to-end. Callers that feed into the verified
    /// `ContractCache` tiers should pass `verify = true`; the cache itself trusts memory/disk
    /// hits and does not re-verify.
    pub async fn get_codes(
        &self,
        hashes: &[B256],
        verify: bool,
    ) -> std::result::Result<HashMap<B256, Arc<Bytecode>>, CodeFetchError> {
        self.get_codes_with_deadline(hashes, verify, None).await
    }

    /// Deadline-aware counterpart of [`Self::get_codes`].
    ///
    /// The same deadline is applied to every per-hash fetch; if it fires during any fetch
    /// the whole batch aborts with `Err(CodeFetchError::Deadline(..))`. With `deadline = None`
    /// the per-hash retries are unbounded and this function can only fail with
    /// `VerificationFailure`.
    pub async fn get_codes_with_deadline(
        &self,
        hashes: &[B256],
        verify: bool,
        deadline: Option<Instant>,
    ) -> std::result::Result<HashMap<B256, Arc<Bytecode>>, CodeFetchError> {
        // `try_join_all` cancels the remaining per-hash futures on the first error — a
        // `VerificationFailure` or `Deadline` on one hash stops the rest of the batch
        // immediately and releases their concurrency permits, so a slow straggler can't
        // hold permits until its own per-attempt timeout fires.
        future::try_join_all(hashes.iter().map(|&hash| async move {
            let bytes = self.get_code_with_deadline(hash, deadline).await?;
            let code = Bytecode::new_raw(bytes);
            if verify {
                let actual = code.hash_slow();
                if actual != hash {
                    return Err(CodeFetchError::VerificationFailure { requested: hash, actual });
                }
            }
            Ok::<_, CodeFetchError>((hash, Arc::new(code)))
        }))
        .await
        .map(|pairs| pairs.into_iter().collect())
    }

    /// Gets the transaction by hash and returns its containing block hash. Retries forever.
    ///
    /// Returns `Ok(None)` when the tx is not found, `Err` when the tx is pending (no
    /// block hash yet — a semantic error the caller must handle). Transient RPC failures
    /// are retried inside `call()`.
    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: B256,
    ) -> Result<Option<(Transaction, B256)>> {
        match self.get_transaction_by_hash_with_deadline(tx_hash, None).await {
            Ok(ok) => ok,
            // `None` deadline ⇒ retry loop is truly unbounded and this branch is unreachable.
            Err(e) => unreachable!("None deadline cannot time out: {e}"),
        }
    }

    /// Deadline-aware counterpart of [`Self::get_transaction_by_hash`].
    ///
    /// On deadline: returns `Err(RpcDeadlineExceeded)`. On a pending tx (no block hash):
    /// returns `Ok(Err(..))`. On tx-not-found: returns `Ok(Ok(None))`.
    pub async fn get_transaction_by_hash_with_deadline(
        &self,
        tx_hash: B256,
        deadline: Option<Instant>,
    ) -> std::result::Result<Result<Option<(Transaction, B256)>>, RpcDeadlineExceeded> {
        let tx = self
            .call_with_deadline(RpcMethod::EthGetTransactionByHash, deadline, move |provider| {
                Box::pin(async move {
                    provider.get_transaction_by_hash(tx_hash).await.map_err(|e| {
                        trace!(%tx_hash, error = %e, "get_transaction_by_hash failed");
                        eyre::Error::from(e)
                    })
                })
            })
            .await?;

        Ok(match tx {
            Some(tx) => match tx.block_hash {
                Some(h) => Ok(Some((tx, h))),
                None => Err(eyre!("Transaction {} is pending and has no block hash", tx_hash)),
            },
            None => Ok(None),
        })
    }
}

/// Emits a tracing event at `warn!` or `debug!` depending on a runtime flag.
///
/// Used by the retry loop to escalate DEBUG → WARN after `WARN_AT_ROUND` without
/// duplicating every log call. The level ends up baked into a static `Metadata`
/// inside the expanded `tracing::warn!` / `tracing::debug!` calls, so the filter
/// short-circuit still works per-branch.
macro_rules! log_at {
    ($warn_level:expr, $($args:tt)*) => {
        if $warn_level {
            ::tracing::warn!($($args)*);
        } else {
            ::tracing::debug!($($args)*);
        }
    };
}

/// Runs a round-robin RPC call with round-level exponential backoff and an optional deadline.
///
/// Each round attempts every provider once in round-robin starting at `rr_start`. If any
/// provider succeeds, returns the result. If every provider in a round fails, sleeps for
/// round-level exponential backoff (capped at `policy.max`, with jitter up to 50%) and starts
/// a new round with the backoff doubled.
///
/// When `deadline` is `Some`, the loop returns [`RpcDeadlineExceeded`] once the deadline
/// elapses, and clamps each inter-round sleep so it does not overshoot. When `deadline` is
/// `None`, retry is unbounded — the function never returns an error.
///
/// Used by both the data-method `call()` (rotates `rr_start` per call for load balancing) and
/// `get_witness()` (pins `rr_start=0` for primary-failover).
// 9-argument retry primitive. Each field plays a distinct role (providers, concurrency,
// backoff policy, per-attempt timeout, starting provider, method label, metrics sink, deadline,
// per-attempt closure) and bundling them into a struct would be ceremony without encapsulation —
// there are exactly two call sites in this crate. Prefer clarity at the definition over fewer
// commas at the call.
#[allow(clippy::too_many_arguments)]
async fn round_robin_with_backoff<N, T>(
    providers: &[RootProvider<N>],
    semaphore: &Semaphore,
    policy: &BackoffPolicy,
    per_attempt_timeout: Duration,
    rr_start: usize,
    method: RpcMethod,
    metrics: Option<&Arc<dyn RpcMetrics>>,
    deadline: Option<Instant>,
    f: impl Fn(RootProvider<N>) -> BoxFuture<Result<T>>,
) -> std::result::Result<T, RpcDeadlineExceeded>
where
    N: alloy_provider::Network,
    T: Send + 'static,
{
    /// Round index from which retry logs escalate DEBUG → WARN. Short blips typically resolve
    /// within the first few rounds (with `initial=500ms, max=30s` defaults that's rounds 0/1/2
    /// sleeping 500/1000/2000 ms + jitter, so cumulative 3.5–5.25 s before a round-3 WARN).
    /// Only sustained failures past that reach operator-visible WARN.
    const WARN_AT_ROUND: u32 = 3;

    let n = providers.len();
    let max_backoff_ms = policy.max.as_millis() as u64;
    let initial_backoff_ms = policy.initial.as_millis() as u64;
    let mut round_backoff_ms = initial_backoff_ms;
    let mut round = 0u32;
    let call_start = Instant::now();

    loop {
        // Last error observed in this round. Used for the round-summary log at the bottom so
        // the per-provider error detail is not lost when we skip the "trying next" log for the
        // final provider (see below).
        let mut last_err: Option<eyre::Error> = None;
        // First few rounds are DEBUG — a transient blip shouldn't page anyone. After the
        // threshold the same logs escalate to WARN so sustained failures surface to ops.
        let warn_level = round >= WARN_AT_ROUND;

        for offset in 0..n {
            // Bail before eating the next permit if the deadline already fired — avoids
            // queueing behind the semaphore just to immediately bail.
            if let Some(d) = deadline &&
                Instant::now() >= d
            {
                return Err(RpcDeadlineExceeded { method, elapsed: call_start.elapsed() });
            }
            let provider_idx = (rr_start + offset) % n;
            let permit = semaphore.acquire().await.expect("semaphore closed unexpectedly");
            // Per-attempt timing: record each provider call individually so histograms
            // and success/error counters reflect what actually happened in the retry loop
            // rather than always showing "success" with the cumulative logical-call time.
            let attempt_start = Instant::now();
            // Bound every attempt by `per_attempt_timeout` — applied even with `deadline =
            // None` so a provider that accepts the TCP connection but never replies cannot
            // wedge the retry loop. With `deadline = Some(d)` the attempt is further capped
            // by `d - now` so we never sleep past the caller's budget.
            let attempt_timeout = match deadline {
                Some(d) => d.saturating_duration_since(Instant::now()).min(per_attempt_timeout),
                None => per_attempt_timeout,
            };
            let result = match tokio::time::timeout(
                attempt_timeout,
                f(providers[provider_idx].clone()),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    // Attempt-level timeout fired. Distinguish two cases:
                    //   - deadline set and now past it ⇒ overall call budget exhausted; bail with
                    //     the typed error so the caller sees one consistent failure mode.
                    //   - otherwise ⇒ the provider stalled but the call still has budget;
                    //     synthesize a normal error and rotate to the next provider in this round,
                    //     mirroring the path a returned `Err` from the closure takes.
                    if let Some(d) = deadline &&
                        Instant::now() >= d
                    {
                        drop(permit);
                        if let Some(m) = metrics {
                            // Only record `on_rpc_complete(false)` here — NOT `on_rpc_retry`.
                            // The non-timeout failure arm fires `on_rpc_retry` because
                            // it's about to loop and try another provider; this arm
                            // gives up, so counting it as a retry would inflate the
                            // retry metric above the actual number of attempts made.
                            m.on_rpc_complete(
                                method,
                                false,
                                Some(attempt_start.elapsed().as_secs_f64()),
                            );
                        }
                        return Err(RpcDeadlineExceeded { method, elapsed: call_start.elapsed() });
                    }
                    // Always WARN, regardless of round — a stalled provider (TCP-accept-
                    // no-reply) is the failure mode this guard exists to catch, and ops
                    // need to see it on round 0 instead of waiting for the round-3
                    // escalation that the returned-Err path goes through.
                    warn!(
                        method = method.as_str(),
                        provider_idx,
                        round,
                        attempt_timeout_ms = attempt_timeout.as_millis() as u64,
                        "RPC provider stalled past per-attempt timeout, rotating",
                    );
                    Err(eyre!(
                        "{} attempt against provider {} timed out after {:?} (per_attempt_timeout)",
                        method.as_str(),
                        provider_idx,
                        attempt_timeout,
                    ))
                }
            };
            let attempt_duration = attempt_start.elapsed().as_secs_f64();
            drop(permit);

            match result {
                Ok(v) => {
                    if let Some(m) = metrics {
                        m.on_rpc_complete(method, true, Some(attempt_duration));
                    }
                    return Ok(v);
                }
                Err(e) => {
                    if let Some(m) = metrics {
                        m.on_rpc_complete(method, false, Some(attempt_duration));
                        m.on_rpc_retry(method);
                    }
                    // Log "trying next" only when there really is a next provider in this
                    // round. Suppresses two kinds of noise:
                    //   - Single-provider config (n=1): no per-provider log at all; the
                    //     round-summary log below is the whole story.
                    //   - Multi-provider, last provider in a round: no "trying next" lie; the error
                    //     is carried into the round-summary log instead.
                    let has_next = offset + 1 < n;
                    if has_next {
                        log_at!(
                            warn_level,
                            method = method.as_str(),
                            provider_idx,
                            round,
                            error = %e,
                            "RPC provider failed, trying next",
                        );
                    }
                    last_err = Some(e);
                }
            }
        }

        // Every provider in this round failed — summarize with the last error + sleep.
        // `last_err` is always `Some` here: `n >= 1` is enforced by the `RpcClient`
        // constructor and we only reach this point after `n` iterations that each set it.
        let last_err = last_err.expect("last_err set when every provider failed this round");
        let jitter_ms = fastrand::u64(0..=round_backoff_ms / 2);
        // `.max(1)` prevents a hot-spin loop if a caller constructs a zero-backoff policy
        // (`BackoffPolicy::new(Duration::ZERO, Duration::ZERO)`): the computed sleep would
        // otherwise be `0` and the retry loop would busy-wait on every round.
        let mut sleep_ms = (round_backoff_ms + jitter_ms).min(max_backoff_ms).max(1);
        // Clamp the sleep so it doesn't overshoot the caller's deadline — if no time is
        // left we bail immediately rather than sleeping past the deadline and then bailing.
        if let Some(d) = deadline {
            let remaining_ms = d.saturating_duration_since(Instant::now()).as_millis() as u64;
            if remaining_ms == 0 {
                return Err(RpcDeadlineExceeded { method, elapsed: call_start.elapsed() });
            }
            sleep_ms = sleep_ms.min(remaining_ms);
        }
        log_at!(
            warn_level,
            method = method.as_str(),
            round,
            providers = n,
            sleep_ms,
            error = %last_err,
            "All providers failed this round, backing off",
        );
        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
        round_backoff_ms = (round_backoff_ms * 2).min(max_backoff_ms);
        round += 1;
    }
}

/// Fetches a block by ID without integrity verification.
async fn do_get_block_unchecked(
    provider: &RootProvider<Optimism>,
    block_id: BlockId,
    full_txs: bool,
) -> Result<Block<Transaction>> {
    let block = if full_txs {
        provider.get_block(block_id).full().await?
    } else {
        provider.get_block(block_id).await?
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

/// Fetches a block header by block ID with optional hash verification.
async fn do_get_header(
    provider: &RootProvider<Optimism>,
    block_id: BlockId,
    verify_hash: bool,
) -> Result<Header> {
    let result = match block_id {
        BlockId::Hash(hash) => provider
            .client()
            .request::<_, Header>("eth_getHeaderByHash", (hash.block_hash,))
            .await
            .map_err(|e| eyre!("eth_getHeaderByHash for {} failed: {e}", hash.block_hash)),
        BlockId::Number(tag) => provider
            .client()
            .request::<_, Header>("eth_getHeaderByNumber", (tag,))
            .await
            .map_err(|e| eyre!("eth_getHeaderByNumber for {:?} failed: {e}", tag)),
    };

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
        ensure!(
            header.hash_slow() == header.hash,
            "Header hash mismatch: expected {:?}, computed {:?}",
            header.hash,
            header.hash_slow()
        );
    }

    Ok(header)
}

/// Fetches and decodes witness data from a single RPC provider (one attempt, no retry).
///
/// Format: `"v0:<base64>"` string → base64-decode → zstd-decompress → bincode-legacy-decode
/// into `(SaltWitness, MptWitness)`.
async fn fetch_witness_raw(
    provider: &RootProvider,
    number: u64,
    hash: B256,
) -> Result<(SaltWitness, MptWitness)> {
    let keys = WitnessRequestKeys { block_number: U64::from(number), block_hash: hash };
    let encoded: String = provider
        .client()
        .request("mega_getBlockWitness", (keys,))
        .await
        .map_err(|e| eyre!("mega_getBlockWitness failed for block {number}: {e}"))?;

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
        .context("decode task panicked")??;

    trace!(
        block_number = number,
        %hash,
        decode_ms = decode_start.elapsed().as_millis(),
        "Witness decoded",
    );

    Ok((salt_witness, mpt_witness))
}

/// Verifies structural integrity of a block fetched from RPC.
///
/// Checks:
/// 1. **Block Hash**: Verifies the block hash matches the computed hash from the header
/// 2. **Transaction Hashes**: For each transaction, verifies that the transaction hash matches its
///    computed hash
/// 3. **Transaction Signers**: Recovers and verifies the signer for each transaction matches the
///    claimed `from` address
/// 4. **Transactions Root**: Computes the Merkle root of all transactions and verifies it matches
///    the `transactions_root` in the block header
fn verify_block_integrity(block: &Block<Transaction>) -> Result<()> {
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_rpc_types_eth::BlockTransactions;
    use alloy_trie::root::ordered_trie_root_with_encoder;
    use op_alloy_network::{TransactionResponse, eip2718::Encodable2718};

    // Verify block hash matches the computed hash from header
    ensure!(
        block.header.hash_slow() == block.header.hash,
        "Block hash mismatch: expected {:?}, computed {:?}",
        block.header.hash,
        block.header.hash_slow()
    );

    // Verify transaction hashes and transactions root
    if let BlockTransactions::Full(ref transactions) = block.transactions {
        for tx in transactions {
            let tx_envelope = tx.inner.clone().into_inner();
            ensure!(
                tx_envelope.trie_hash() == *tx_envelope.hash(),
                "Transaction hash mismatch: expected {:?}, computed {:?}",
                tx_envelope.hash(),
                tx_envelope.trie_hash()
            );

            let recovered = tx_envelope
                .recover_signer()
                .map_err(|err| eyre!("Failed to recover signer: {}", err))?;

            ensure!(
                recovered == tx.from(),
                "Transaction signer mismatch: expected {:?}, got {:?}",
                tx.from(),
                recovered
            );
        }

        let computed_tx_root = ordered_trie_root_with_encoder(transactions, |tx, buf| {
            tx.inner.clone().into_inner().encode_2718(buf)
        });
        ensure!(
            computed_tx_root == block.header.transactions_root,
            "Transactions root mismatch: expected {:?}, computed {:?}",
            block.header.transactions_root,
            computed_tx_root
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use alloy_primitives::BlockHash;
    use jsonrpsee::{
        RpcModule,
        server::{ServerBuilder, ServerHandle},
        types::ErrorObjectOwned,
    };
    use stateless_core::{
        PipelineConfig, block_fetcher,
        db::{BlockMeta, StoreResult},
        find_divergence_point,
        pipeline::{BlockFetcher, DivergenceLookups},
    };
    use tokio_util::sync::CancellationToken;

    use super::*;

    const LOCALHOST_A: &str = "http://localhost:8545";
    const LOCALHOST_B: &str = "http://localhost:8546";

    /// Test wrapper that implements BlockFetcher by delegating to RpcClient.
    struct TestFetcher(RpcClient);

    impl BlockFetcher for TestFetcher {
        type Output = ();
        async fn fetch(&self, _: u64) -> eyre::Result<()> {
            unimplemented!("not used")
        }
        async fn latest_block_number(&self) -> eyre::Result<u64> {
            Ok(self.0.get_latest_block_number().await)
        }
        async fn block_hash(&self, n: u64) -> eyre::Result<BlockHash> {
            Ok(self.0.get_block_hash(n).await)
        }
        async fn latest_block_meta(&self) -> eyre::Result<BlockMeta> {
            unimplemented!("not used")
        }
    }

    fn client_at(url: &str) -> RpcClient {
        RpcClient::new(&[url], &[url]).unwrap()
    }

    fn fetcher_at(url: &str) -> Arc<TestFetcher> {
        Arc::new(TestFetcher(client_at(url)))
    }

    fn err_obj(msg: &'static str) -> ErrorObjectOwned {
        ErrorObjectOwned::owned::<()>(-32000, msg, None)
    }

    fn parse_hex_u64(s: &str) -> u64 {
        u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).unwrap()
    }

    /// Minimal valid [`Header`] with `hash`/`number` populated; all other fields default.
    fn header_stub(number: u64, hash: BlockHash) -> Header {
        Header {
            hash,
            inner: alloy_consensus::Header { number, ..Default::default() },
            ..Default::default()
        }
    }

    /// Starts a jsonrpsee server bound to a random port and registers methods via `register`.
    async fn serve<Ctx: Send + Sync + 'static>(
        ctx: Ctx,
        register: impl FnOnce(&mut RpcModule<Ctx>),
    ) -> (ServerHandle, String) {
        let mut module = RpcModule::new(ctx);
        register(&mut module);
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (server.start(module), url)
    }

    /// Serves `eth_getHeaderByNumber` with headers derived from `hashes`.
    async fn start_mock_rpc(hashes: HashMap<u64, BlockHash>) -> (ServerHandle, String) {
        serve(hashes, |m| {
            m.register_method("eth_getHeaderByNumber", |params, ctx, _| {
                let (hex,): (String,) = params.parse().unwrap();
                let n = parse_hex_u64(&hex);
                Ok::<_, ErrorObjectOwned>(header_stub(n, ctx.get(&n).copied().unwrap_or_default()))
            })
            .unwrap();
        })
        .await
    }

    /// Serves `eth_blockNumber` returning `latest`; fails the first `fail_first` calls.
    /// Returns the hit counter so tests can inspect per-endpoint call counts.
    async fn start_counting_block_number_rpc(
        latest: u64,
        fail_first: usize,
    ) -> (ServerHandle, String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let (handle, url) = serve((latest, fail_first, hits.clone()), |m| {
            m.register_method("eth_blockNumber", |_p, (latest, fail_first, hits), _| {
                if hits.fetch_add(1, Ordering::Relaxed) < *fail_first {
                    Err::<String, _>(err_obj("synthetic failure"))
                } else {
                    Ok(format!("0x{:x}", *latest))
                }
            })
            .unwrap();
        })
        .await;
        (handle, url, hits)
    }

    /// Shortcut for tests that don't care about per-endpoint hit counts.
    async fn start_block_number_rpc(latest: u64) -> (ServerHandle, String) {
        let (h, u, _) = start_counting_block_number_rpc(latest, 0).await;
        (h, u)
    }

    /// Builds paired local/remote hash maps that agree on `earliest..=diverge_at` and diverge
    /// on `(diverge_at+1)..=tip`.
    fn make_divergence_chains(
        earliest: u64,
        tip: u64,
        diverge_at: u64,
    ) -> (HashMap<u64, BlockHash>, HashMap<u64, BlockHash>) {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        for n in earliest..=tip {
            local.insert(n, BlockHash::from([n as u8; 32]));
            let remote_hash = if n <= diverge_at { [n as u8; 32] } else { [(n + 128) as u8; 32] };
            remote.insert(n, BlockHash::from(remote_hash));
        }
        (local, remote)
    }

    /// Minimal `DivergenceLookups` impl for these tests (replaces the two-closure pattern).
    struct MapLookups {
        hashes: HashMap<u64, BlockHash>,
        earliest: u64,
    }

    impl DivergenceLookups for MapLookups {
        fn get_hash(&self, n: u64) -> StoreResult<Option<BlockHash>> {
            Ok(self.hashes.get(&n).copied())
        }
        fn get_earliest(&self) -> StoreResult<Option<(u64, BlockHash)>> {
            Ok(self.hashes.get(&self.earliest).map(|&h| (self.earliest, h)))
        }
    }

    /// Runs `find_divergence_point` against a mock server and asserts the expected split.
    async fn assert_divergence(earliest: u64, tip: u64, diverge_at: u64, expected: u64) {
        let (local, remote) = make_divergence_chains(earliest, tip, diverge_at);
        let (handle, url) = start_mock_rpc(remote).await;
        let fetcher = TestFetcher(client_at(&url));
        let lookups = MapLookups { hashes: local, earliest };
        let result = find_divergence_point(&fetcher, &lookups, tip).await.unwrap();
        assert_eq!(result, expected);
        handle.stop().unwrap();
    }

    #[test]
    fn test_new_validates_urls_and_counts_providers() {
        assert!(RpcClient::new(&["not a url"], &[LOCALHOST_A]).is_err());
        assert!(RpcClient::new(&[LOCALHOST_A], &["not a url"]).is_err());
        assert!(
            RpcClient::new(&[], &[LOCALHOST_A])
                .unwrap_err()
                .to_string()
                .contains("At least one data API")
        );
        assert!(
            RpcClient::new(&[LOCALHOST_A], &[])
                .unwrap_err()
                .to_string()
                .contains("At least one witness API")
        );

        for endpoints in [&[LOCALHOST_B][..], &[LOCALHOST_B, "http://localhost:8547"]] {
            assert_eq!(
                RpcClient::new(&[LOCALHOST_A], endpoints).unwrap().witness_provider_count(),
                endpoints.len()
            );
            assert_eq!(
                RpcClient::new(endpoints, &[LOCALHOST_A]).unwrap().data_provider_count(),
                endpoints.len()
            );
        }
    }

    #[test]
    fn test_config_propagates_to_client() {
        let make = |config| {
            RpcClient::new_with_config(&[LOCALHOST_A], &[LOCALHOST_B], config, None).unwrap()
        };
        assert!(!make(RpcClientConfig::validator()).skip_block_verification());
        assert!(make(RpcClientConfig::trace_server()).skip_block_verification());
        // `Some(0)` must not produce a permanently-blocked semaphore.
        let zero = make(RpcClientConfig {
            data_max_concurrent_requests: Some(0),
            witness_max_concurrent_requests: Some(0),
            ..Default::default()
        });
        assert_eq!(zero.data_concurrency.available_permits(), 1);
        assert_eq!(zero.witness_concurrency.available_permits(), 1);
        let client = make(RpcClientConfig {
            data_max_concurrent_requests: Some(10),
            witness_max_concurrent_requests: Some(2),
            ..Default::default()
        });
        assert_eq!(client.data_concurrency.available_permits(), 10);
        assert_eq!(client.witness_concurrency.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_find_divergence_single_block_reorg() {
        assert_divergence(1, 10, 9, 9).await;
    }

    #[tokio::test]
    async fn test_find_divergence_multi_block_reorg() {
        assert_divergence(1, 10, 5, 5).await;
    }

    #[tokio::test]
    async fn test_find_divergence_to_earliest() {
        assert_divergence(5, 10, 5, 5).await;
    }

    #[tokio::test]
    async fn test_find_divergence_catastrophic_reorg() {
        let (local, remote) = make_divergence_chains(1, 5, 0); // no agreement at all
        let (handle, url) = start_mock_rpc(remote).await;
        let fetcher = TestFetcher(client_at(&url));
        let lookups = MapLookups { hashes: local, earliest: 1 };

        let result = find_divergence_point(&fetcher, &lookups, 5).await;

        assert!(result.unwrap_err().to_string().contains("Catastrophic reorg"));
        handle.stop().unwrap();
    }

    /// Holds references that must outlive the fetcher under test (server handle, rx).
    struct FetcherHarness {
        handle: ServerHandle,
        fetcher: Arc<TestFetcher>,
        tx: kanal::Sender<()>,
        _rx: kanal::Receiver<()>,
        config: Arc<PipelineConfig>,
        shutdown: CancellationToken,
    }

    /// Common setup for block_fetcher tests. `config_fn` mutates the default `PipelineConfig`.
    async fn fetcher_harness(
        latest: u64,
        config_fn: impl FnOnce(&mut PipelineConfig),
    ) -> FetcherHarness {
        let (handle, url) = start_block_number_rpc(latest).await;
        let (tx, _rx) = kanal::bounded::<()>(16);
        let mut config = PipelineConfig::default();
        config_fn(&mut config);
        FetcherHarness {
            handle,
            fetcher: fetcher_at(&url),
            tx,
            _rx,
            config: Arc::new(config),
            shutdown: CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn test_block_fetcher_sync_target_already_reached() {
        let h = fetcher_harness(100, |c| c.sync_target = Some(5)).await;
        assert!(block_fetcher(h.fetcher, h.tx, 6, h.config, h.shutdown).await.is_ok());
        h.handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_block_fetcher_shutdown_immediate() {
        let h = fetcher_harness(100, |_| {}).await;
        h.shutdown.cancel();
        assert!(block_fetcher(h.fetcher, h.tx, 1, h.config, h.shutdown).await.is_ok());
        h.handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_block_fetcher_invokes_latest_block_number() {
        let h = fetcher_harness(42, |c| c.poll_interval = Duration::from_secs(60)).await;
        let canceller = h.shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            canceller.cancel();
        });
        assert!(block_fetcher(h.fetcher, h.tx, 100, h.config, h.shutdown).await.is_ok());
        h.handle.stop().unwrap();
    }

    /// Asserts that `call()` spreads load across data providers via round-robin.
    ///
    /// Two healthy mocks, 10 calls, both must receive ≥ 3 hits (perfect distribution = 5/5).
    /// Proves the counter cycles the starting provider instead of always hitting `[0]`.
    #[tokio::test]
    async fn test_call_round_robins_across_healthy_providers() {
        let (h1, url1, hits1) = start_counting_block_number_rpc(10, 0).await;
        let (h2, url2, hits2) = start_counting_block_number_rpc(10, 0).await;

        let client = RpcClient::new(&[url1.as_str(), url2.as_str()], &[url1.as_str()]).unwrap();
        for _ in 0..10 {
            client.get_latest_block_number().await;
        }

        let (a, b) = (hits1.load(Ordering::Relaxed), hits2.load(Ordering::Relaxed));
        assert_eq!(a + b, 10, "all calls should have succeeded");
        assert!(a >= 3 && b >= 3, "round-robin should distribute load: got {a}/{b}");

        h1.stop().unwrap();
        h2.stop().unwrap();
    }

    /// Asserts the round-level retry model: one failing provider + one healthy provider in
    /// the same pool means the first round has 1 failure + 1 success (no sleep, no second
    /// round). Total hits = 2.
    #[tokio::test]
    async fn test_call_falls_back_to_next_provider_same_round() {
        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2)),
            ..Default::default()
        };
        // Provider A fails its single attempt (`fail_first = 1`), B serves success.
        let (ha, url_a, hits_a) = start_counting_block_number_rpc(42, 1).await;
        let (hb, url_b, hits_b) = start_counting_block_number_rpc(42, 0).await;

        let client = RpcClient::new_with_config(
            &[url_a.as_str(), url_b.as_str()],
            &[url_a.as_str()],
            config,
            None,
        )
        .unwrap();

        assert_eq!(client.get_latest_block_number().await, 42);

        let (a, b) = (hits_a.load(Ordering::Relaxed), hits_b.load(Ordering::Relaxed));
        assert_eq!(a + b, 2, "1 failed attempt on A + 1 successful attempt on B, got {a}/{b}");
        assert!(a >= 1 && b >= 1, "both providers should have been tried: got {a}/{b}");

        ha.stop().unwrap();
        hb.stop().unwrap();
    }

    /// After every provider in a round fails, the helper sleeps and starts a new round.
    /// Observable via two providers that each fail one request then recover: the call must
    /// succeed after at least one full round of failures.
    #[tokio::test]
    async fn test_call_starts_new_round_after_all_providers_fail() {
        // Both providers fail their first request, then serve success.
        let (ha, url_a, hits_a) = start_counting_block_number_rpc(99, 1).await;
        let (hb, url_b, hits_b) = start_counting_block_number_rpc(99, 1).await;

        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2)),
            ..Default::default()
        };
        let client = RpcClient::new_with_config(
            &[url_a.as_str(), url_b.as_str()],
            &[url_a.as_str()],
            config,
            None,
        )
        .unwrap();

        assert_eq!(client.get_latest_block_number().await, 99);

        // Round 1: both fail → total 2 hits, helper sleeps.
        // Round 2: first provider tried now succeeds → 1 more hit, total = 3.
        let total = hits_a.load(Ordering::Relaxed) + hits_b.load(Ordering::Relaxed);
        assert_eq!(total, 3, "round 1 fails both (2 hits), round 2 succeeds on first try (1 more)");

        ha.stop().unwrap();
        hb.stop().unwrap();
    }

    /// `get_witness` pins `rr_start = 0`, so every round visits the primary first and only
    /// falls through to the backup on failure. We can't easily make the primary succeed in
    /// a unit test (a valid witness payload needs real cryptographic proof material), but
    /// we can still verify the ordering invariant — primary is always tried *before* the
    /// backup in every round.
    #[tokio::test]
    async fn test_get_witness_always_starts_from_primary() {
        // Shared log records which provider was hit, in order. Both providers return a stub
        // that fails decode downstream, so every round runs to completion and all providers
        // in the pool get hit — the order is what we assert on.
        let order = Arc::new(std::sync::Mutex::new(Vec::<char>::new()));
        let (ha, url_a) = start_ordered_witness_rpc('A', order.clone()).await;
        let (hb, url_b) = start_ordered_witness_rpc('B', order.clone()).await;

        let client = RpcClient::new(&[url_a.as_str()], &[url_a.as_str(), url_b.as_str()]).unwrap();

        // Short-timeout each call so backoff doesn't stretch them into multiple rounds.
        const CALLS: usize = 5;
        for _ in 0..CALLS {
            let _ = tokio::time::timeout(
                Duration::from_millis(100),
                client.get_witness(1, BlockHash::ZERO),
            )
            .await;
        }

        let log = order.lock().unwrap();
        assert_eq!(log.len(), 2 * CALLS, "each call runs one full round hitting both: {log:?}");
        // A at every even index, B at every odd index — primary strictly precedes backup.
        for chunk in log.chunks_exact(2) {
            assert_eq!(chunk, &['A', 'B'], "primary must be hit before backup each round");
        }

        ha.stop().unwrap();
        hb.stop().unwrap();
    }

    /// Serves `mega_getBlockWitness` returning a stub that decodes-fails, while recording
    /// the provider's label to a shared `order` log on each hit. Used to verify call routing.
    async fn start_ordered_witness_rpc(
        label: char,
        order: Arc<std::sync::Mutex<Vec<char>>>,
    ) -> (ServerHandle, String) {
        let (handle, url) = serve((label, order), |m| {
            m.register_method("mega_getBlockWitness", |_p, (label, order), _| {
                order.lock().unwrap().push(*label);
                // Stub that fails base64/zstd decode, so the round continues to the next
                // provider and we see the full routing order.
                Ok::<_, ErrorObjectOwned>("v0:AAAA".to_string())
            })
            .unwrap();
        })
        .await;
        (handle, url)
    }

    /// Serves `eth_getCodeByHash` returning `codes[hash]` verbatim (so the server can return
    /// bytes whose keccak256 does NOT match the requested hash, exercising the verify path).
    async fn start_code_rpc(codes: HashMap<B256, Bytes>) -> (ServerHandle, String) {
        serve(codes, |m| {
            m.register_method("eth_getCodeByHash", |params, ctx, _| {
                let (hash,): (B256,) = params.parse().unwrap();
                Ok::<_, ErrorObjectOwned>(
                    ctx.get(&hash).cloned().unwrap_or_else(|| Bytes::from_static(&[])),
                )
            })
            .unwrap();
        })
        .await
    }

    /// `get_codes(verify=true)` must abort the batch with an `Err` when the returned bytecode's
    /// keccak256 doesn't match the requested hash. Documents the security contract: unverified
    /// bytes never reach the cache.
    #[tokio::test]
    async fn test_get_codes_verify_rejects_hash_mismatch() {
        // Good entry: the "requested" hash equals keccak256 of [0x60, 0x00].
        let good_code = Bytes::from_static(&[0x60, 0x00]);
        let good_hash = Bytecode::new_raw(good_code.clone()).hash_slow();
        // Bad entry: request a hash whose keccak the server won't produce (it returns different
        // bytes). `[0xAA; 32]` is arbitrary — the server returns `[0xDE, 0xAD]` instead.
        let bad_hash = B256::from([0xAA; 32]);
        let bad_code = Bytes::from_static(&[0xDE, 0xAD]);

        let codes = HashMap::from([(good_hash, good_code.clone()), (bad_hash, bad_code)]);
        let (handle, url) = start_code_rpc(codes).await;
        let client = client_at(&url);

        // `verify=true` on just the bad hash → typed `VerificationFailure` naming that hash.
        let err = client.get_codes(&[bad_hash], true).await.expect_err("mismatch must fail");
        match err {
            CodeFetchError::VerificationFailure { requested, actual } => {
                assert_eq!(requested, bad_hash);
                assert_ne!(actual, bad_hash, "actual must reflect what the server returned");
            }
            other => panic!("expected VerificationFailure, got {other:?}"),
        }

        // Mixed batch with one bad hash → whole batch fails (security contract: discard all).
        let err = client
            .get_codes(&[good_hash, bad_hash], true)
            .await
            .expect_err("any mismatch must abort the batch");
        assert!(
            matches!(err, CodeFetchError::VerificationFailure { requested, .. } if requested == bad_hash),
            "expected VerificationFailure for bad_hash",
        );

        // `verify=false` → both entries returned (caller opted out of verification).
        let ok = client.get_codes(&[good_hash, bad_hash], false).await.unwrap();
        assert_eq!(ok.len(), 2, "verify=false must return every requested entry");
        // Compare against the canonical analyzed form (revm appends a trailing 0 byte).
        assert_eq!(ok[&good_hash].bytes_slice(), Bytecode::new_raw(good_code).bytes_slice(),);

        handle.stop().unwrap();
    }

    /// All-good batch: verified entries are returned wrapped in `Arc<Bytecode>` (the type
    /// change that lets `ContractCache::insert` avoid a second allocation at each call site).
    #[tokio::test]
    async fn test_get_codes_verify_ok_returns_arc_bytecode() {
        let good_code = Bytes::from_static(&[0x60, 0x00, 0x60, 0x01]);
        let good_hash = Bytecode::new_raw(good_code.clone()).hash_slow();

        let (handle, url) = start_code_rpc(HashMap::from([(good_hash, good_code.clone())])).await;
        let client = client_at(&url);

        let ok = client.get_codes(&[good_hash], true).await.unwrap();
        assert_eq!(ok.len(), 1);
        let arc = ok.get(&good_hash).expect("good hash present");
        assert_eq!(arc.bytes_slice(), Bytecode::new_raw(good_code).bytes_slice());
        // Compile-time check that the return type is `Arc<Bytecode>` (refcount share with cache).
        let _arc_clone: Arc<Bytecode> = Arc::clone(arc);

        handle.stop().unwrap();
    }

    /// `eth_getCodeByHash` returning `"0x"` for a non-empty codehash (the symptom of an
    /// upstream that isn't sync-ready) must be retried, not propagated as success. Without
    /// the retry guard this would land in `get_codes(verify=true)` as a bytecode whose
    /// keccak doesn't match the requested hash → fatal `VerificationFailure` → halt.
    #[tokio::test]
    async fn test_get_code_retries_empty_response_until_deadline() {
        let arbitrary_hash = B256::from([0xCC; 32]);
        // Server always returns "0x" for any hash and bumps `hits` so the test can prove
        // the call was actually retried (not accepted on first try).
        let hits = Arc::new(AtomicUsize::new(0));
        let (handle, url) = serve(hits.clone(), |m| {
            m.register_method("eth_getCodeByHash", |_p, hits, _| {
                hits.fetch_add(1, Ordering::Relaxed);
                Ok::<Bytes, ErrorObjectOwned>(Bytes::from_static(&[]))
            })
            .unwrap();
        })
        .await;

        // Tight retry config so the test wraps in well under a second.
        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20)),
            per_attempt_timeout: Duration::from_millis(500),
            ..Default::default()
        };
        let client = RpcClient::new_with_config(&[&url], &[&url], config, None).unwrap();

        let deadline = Instant::now() + Duration::from_millis(300);
        let err = client
            .get_code_with_deadline(arbitrary_hash, Some(deadline))
            .await
            .expect_err("empty response with non-empty-code hash must surface as deadline");
        assert_eq!(err.method, RpcMethod::EthGetCodeByHash);
        assert!(
            hits.load(Ordering::Relaxed) > 1,
            "expected > 1 attempt before deadline (was {})",
            hits.load(Ordering::Relaxed)
        );

        handle.stop().unwrap();
    }

    /// The `KECCAK_EMPTY` codehash is the legitimate "empty bytecode" case: `"0x"` is the
    /// correct answer and must be returned, not retried (otherwise the call would loop forever).
    ///
    /// `client.get_code` uses `deadline = None` (unbounded retry); the outer
    /// `tokio::time::timeout` is a regression guard — if the `!= KECCAK_EMPTY` check is ever
    /// flipped or removed, the call would hang instead of returning, and CI would hang with
    /// it. The timeout converts that failure mode into an explicit test failure.
    #[tokio::test]
    async fn test_get_code_accepts_empty_response_for_keccak_empty() {
        let (handle, url) = start_code_rpc(HashMap::new()).await; // server returns "0x" for everything
        let client = client_at(&url);

        let bytes = tokio::time::timeout(
            Duration::from_millis(500),
            client.get_code(revm::primitives::KECCAK_EMPTY),
        )
        .await
        .expect("KECCAK_EMPTY guard must short-circuit without retrying");
        assert!(bytes.is_empty(), "KECCAK_EMPTY hash must accept empty bytecode");

        handle.stop().unwrap();
    }

    /// A provider that accepts the TCP connection but never replies must be detected by the
    /// per-attempt timeout — even when the call has no deadline (the chain-sync contract).
    /// Without per-attempt timing, the retry loop wedges on the stalled provider forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_per_attempt_timeout_rotates_past_stalled_provider() {
        // Stalled "provider": bind a TCP listener that accepts connections but never reads
        // or writes. A client request to it will hang on the response.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stalled_addr = listener.local_addr().unwrap();
        let stalled_url = format!("http://{stalled_addr}/");
        // Keep the listener alive (in scope) so the OS doesn't refuse the connection — we
        // want accept + never-reply, not refused. Drops cleanly at end of test.
        let _listener = listener;

        // Healthy provider as the second endpoint. Round-robin starts at index 0 so the
        // call hits the stalled provider first, has to time out the attempt, then rotates.
        let healthy_latest = 4242u64;
        let (handle, healthy_url) = start_block_number_rpc(healthy_latest).await;

        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20)),
            // Short per-attempt so a stalled provider rotates quickly.
            per_attempt_timeout: Duration::from_millis(150),
            ..Default::default()
        };
        let client = RpcClient::new_with_config(
            &[&stalled_url, &healthy_url],
            &[&healthy_url],
            config,
            None,
        )
        .unwrap();

        // Bound the test wall clock with `tokio::time::timeout` (NOT a deadline parameter):
        // this tests the `deadline = None` path. If the bug regressed, the call would hang
        // and this outer timeout would fire instead of the call returning Ok.
        let result = tokio::time::timeout(Duration::from_secs(3), client.get_latest_block_number())
            .await
            .expect("call must return — per-attempt timeout should rotate past stalled provider");
        assert_eq!(result, healthy_latest);

        handle.stop().unwrap();
    }
}
