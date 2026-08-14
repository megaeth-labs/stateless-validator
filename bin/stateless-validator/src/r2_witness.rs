//! Direct-from-R2 witness source.
//!
//! Fetches the primary witness object straight from the R2 bucket over the S3 API and returns
//! the same `(SaltWitness, MptWitness)` tuple the RPC path yields. The transport core is
//! [`R2ObjectFetcher`] from `stateless-r2`, shared with the debug-trace-server's historical
//! witness source; this adapter owns what is validator-specific: the **full** payload decode
//! (proof verification needs the elliptic-curve points the light decode skips), the validator
//! metrics, and the surfaced-failure pacing the pipeline fetcher relies on. The object body is
//! `zstd(bincode-legacy((SaltWitness, MptWitness)))`, which
//! [`stateless_common::decode_witness_payload`] inverts exactly.
//!
//! Operator note on missing objects: the pipeline retries a `Missing` witness indefinitely
//! (each attempt throttled by [`DETERMINISTIC_FAILURE_THROTTLE`]). Near the tip that is
//! exactly right — the object appears once the uploader wins the race. But on a fixed
//! `--end-block` slice over history, a permanently absent object means the run never
//! completes and never fails: alert on `r2_witness_errors_total{kind="missing"}` staying hot
//! for the same block, and use the object key from the error's log line to check/backfill
//! the bucket.

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use salt::SaltWitness;
use stateless_common::{
    BackoffPolicy, WitnessDecodingError, WitnessSizeBreakdown, decode_witness_payload,
};
use stateless_core::withdrawals::MptWitness;
use stateless_r2::{
    fetch::{CfAccessCredentials, FetchTimeouts, R2GetError, R2ObjectFetcher, RetryPacing},
    keys,
};
use tokio::task::JoinError;
use tracing::trace;

use crate::metrics;

/// Throttle applied before surfacing any deterministic (non-retryable) failure: the pipeline
/// fetcher (`stateless-core/src/pipeline/fetcher.rs`) re-enqueues failed fetches with no delay,
/// so returning instantly would hot-loop signed GETs against R2. Delete this once the fetcher
/// grows per-block re-enqueue backoff. Test builds shrink it so the failure-path tests run in
/// milliseconds.
const DETERMINISTIC_FAILURE_THROTTLE: Duration =
    if cfg!(test) { Duration::from_millis(5) } else { Duration::from_secs(2) };

/// Total GET attempts (first try + retries) per fetch for retryable (transport/429/5xx)
/// failures before the error surfaces. Stays a local constant: the RPC witness path retries
/// unboundedly, so there is no operator flag to mirror.
const MAX_ATTEMPTS: usize = 9;

/// Failure outcome of an R2 witness fetch.
#[derive(Debug, thiserror::Error)]
pub enum R2WitnessError {
    /// The signed GET failed (absent object, transport, throttle, or unexpected status —
    /// see [`R2GetError`], and the module docs for the `Missing` operator note).
    #[error(transparent)]
    Get(#[from] R2GetError),
    /// The object was fetched but its bytes did not decode to a `(SaltWitness, MptWitness)` tuple
    /// — a corrupt witness in R2. Deterministic; not retried.
    #[error("R2 witness for block {number} (key {key}) failed to decode: {source}")]
    Decode { number: u64, key: String, source: WitnessDecodingError },
    /// The decode task panicked. This is a bug in our own decoder, not a problem with the data in
    /// R2, so it is kept out of [`Self::Decode`].
    #[error("R2 witness decode task for block {number} (key {key}) panicked: {source}")]
    DecodePanicked { number: u64, key: String, source: JoinError },
}

impl R2WitnessError {
    /// Every label [`Self::kind`] can produce, for metrics pre-registration
    /// (`crate::metrics::init_metrics` zero-inits the error counter per kind).
    pub const KINDS: &'static [&'static str] = &[
        "missing",
        "transport",
        "throttled",
        "status",
        "connect",
        "deadline",
        "decode",
        "decode_panicked",
    ];

    /// Stable lowercase label for this variant — the `kind` label on the R2 witness error
    /// counter. Every value returned here must appear in [`Self::KINDS`].
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Get(e) => e.kind(),
            Self::Decode { .. } => "decode",
            Self::DecodePanicked { .. } => "decode_panicked",
        }
    }

    /// Whether an immediate retry against the same endpoint could plausibly succeed (transport
    /// blips, 429, 5xx). Every other variant is deterministic and is surfaced without retrying.
    const fn is_retryable(&self) -> bool {
        matches!(self, Self::Get(e) if e.is_retryable())
    }
}

/// Fetches witness objects straight from an R2 bucket over the S3 API with SigV4-signed GETs.
/// The fetcher's `Debug` redacts the credentials.
#[derive(Debug)]
pub struct R2WitnessClient {
    fetcher: R2ObjectFetcher,
}

impl R2WitnessClient {
    /// Builds a client from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `timeouts` bounds each individual GET (end-to-end and connect). `retry_backoff` paces the
    /// retries of retryable failures — first sleep `initial`, doubling up to `max`, each with
    /// up to 50% jitter — and is the same policy the RPC path builds from
    /// `--rpc-initial-backoff-ms` / `--rpc-max-backoff-ms`, so one pair of flags tunes both
    /// paths. `max_concurrent_requests` caps the number of GETs in flight at once (`None` =
    /// unlimited, `Some(0)` clamps to 1 — same semantics as the RPC witness semaphore; in R2
    /// mode this client is the only enforcement of `--witness-max-concurrent-requests`). Fails
    /// if the endpoint is not a bare `scheme://host[:port]` origin or the HTTP client cannot be
    /// built.
    pub fn new(
        endpoint: &str,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        timeouts: FetchTimeouts,
        retry_backoff: BackoffPolicy,
        max_concurrent_requests: Option<usize>,
    ) -> eyre::Result<Self> {
        let fetcher = R2ObjectFetcher::new(
            endpoint,
            bucket,
            access_key_id,
            secret_access_key,
            timeouts,
            RetryPacing { initial: retry_backoff.initial, max: retry_backoff.max },
            max_concurrent_requests,
        )
        .map_err(|e| eyre::eyre!(e))?;
        Ok(Self { fetcher })
    }

    /// Builds a client that fetches unsigned through a Cloudflare custom domain fronting the
    /// bucket (h2-multiplexed, edge-cacheable), with optional Cloudflare Access service-token
    /// headers. The remaining parameters mean what they mean on [`Self::new`].
    pub fn new_custom_domain(
        domain: &str,
        access: Option<CfAccessCredentials>,
        timeouts: FetchTimeouts,
        retry_backoff: BackoffPolicy,
        max_concurrent_requests: Option<usize>,
    ) -> eyre::Result<Self> {
        let fetcher = R2ObjectFetcher::new_custom_domain(
            domain,
            access,
            timeouts,
            RetryPacing { initial: retry_backoff.initial, max: retry_backoff.max },
            max_concurrent_requests,
        )
        .map_err(|e| eyre::eyre!(e))?;
        Ok(Self { fetcher })
    }

    /// Fetches and decodes the witness for `(number, hash)` from R2.
    ///
    /// Transport/429/5xx failures are retried internally, paced by the `retry_backoff` policy
    /// given at construction. Every surfaced failure pauses before returning (the pipeline
    /// fetcher re-enqueues failed fetches with zero delay, so returning instantly would
    /// hot-loop GETs against R2): deterministic failures wait the fixed
    /// [`DETERMINISTIC_FAILURE_THROTTLE`], and exhausted retryable failures wait the policy's
    /// `max` backoff — without that, the next fetch cycle would restart its ramp at `initial`,
    /// re-bursting GETs into the same brownout the exhausted ramp just backed away from.
    pub async fn get_witness(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let result = self.get_witness_inner(number, hash).await;
        if let Err(e) = &result {
            metrics::on_r2_witness_error(e.kind());
            // Exhausted retryable failures pause the pacing's `max`: without it, the next
            // fetch cycle would restart its ramp at `initial`, re-bursting GETs into the
            // same brownout the exhausted ramp just backed away from.
            let pause = if e.is_retryable() {
                self.fetcher.pacing().max
            } else {
                DETERMINISTIC_FAILURE_THROTTLE
            };
            tokio::time::sleep(pause).await;
        }
        result
    }

    /// [`Self::get_witness`] without the surfaced-failure pause.
    async fn get_witness_inner(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let started = Instant::now();
        let fetched = self
            .fetcher
            .get_block_object(number, hash, MAX_ATTEMPTS, None, metrics::on_r2_witness_retry)
            .await?;
        let bytes = fetched.bytes;

        // zstd + bincode over a multi-MB witness is CPU-bound; keep it off the runtime.
        let key = || keys::block_object_key(number, hash);
        match tokio::task::spawn_blocking(move || decode_witness_payload(&bytes)).await {
            Ok(Ok(witness)) => {
                trace!(number, "R2 witness fetched and decoded");
                // Queue wait on the self-imposed concurrency cap is subtracted: folded in, it
                // would masquerade as R2 slowness.
                metrics::on_r2_witness_fetch_success(
                    started.elapsed().saturating_sub(fetched.queue_wait).as_secs_f64(),
                    WitnessSizeBreakdown::new(&witness.0, &witness.1),
                );
                Ok(witness)
            }
            Ok(Err(source)) => Err(R2WitnessError::Decode { number, key: key(), source }),
            Err(source) => Err(R2WitnessError::DecodePanicked { number, key: key(), source }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::atomic::Ordering};

    use stateless_test_utils::{fixtures::TestFixtures, mock_r2::mock_r2};

    use super::*;

    /// Guards the one layer `stateless-r2` cannot pin itself: that [`B256`]'s `Display` renders
    /// full lowercase `0x` hex. If that changed, every GET would 404.
    #[test]
    fn block_object_key_renders_b256_as_lowercase_hex() {
        let hash =
            B256::from_str("0x05dd41e545b25db0ce04f628e6e1705232240c70a0435c8233ac4479176fe6b0")
                .unwrap();
        assert_eq!(
            keys::block_object_key(6_632_136, hash),
            "block/6632000_6632999/6632136.\
             0x05dd41e545b25db0ce04f628e6e1705232240c70a0435c8233ac4479176fe6b0",
        );
    }

    /// Millisecond-scale retry pacing so the retry-path tests run fast (production runs pass
    /// the seconds-scale policy built from the `--rpc-*-backoff-ms` flags).
    fn test_backoff() -> BackoffPolicy {
        BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20))
    }

    fn test_timeouts() -> FetchTimeouts {
        FetchTimeouts {
            per_attempt: Duration::from_secs(5),
            connect: stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT,
        }
    }

    fn client_with_backoff(endpoint: &str, retry_backoff: BackoffPolicy) -> R2WitnessClient {
        R2WitnessClient::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            test_timeouts(),
            retry_backoff,
            None,
        )
        .unwrap()
    }

    async fn fetch(endpoint: &str) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        client_with_backoff(endpoint, test_backoff()).get_witness(1, B256::ZERO).await
    }

    /// Construction errors from the shared fetcher must surface through the eyre conversion.
    #[test]
    fn rejects_endpoint_with_path() {
        let err = R2WitnessClient::new(
            "https://acc.r2.cloudflarestorage.com/witness-mainnet",
            "witness-mainnet".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            test_timeouts(),
            test_backoff(),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid R2 endpoint"));
    }

    /// Every fetch-level kind must appear in this adapter's pre-registered [`KINDS`] — a new
    /// `R2GetError` kind escaping metric pre-registration would drift silently otherwise.
    #[test]
    fn kinds_cover_all_fetch_kinds() {
        assert!(R2GetError::KINDS.iter().all(|k| R2WitnessError::KINDS.contains(k)));
    }

    /// The only test of the success path (fetch → `spawn_blocking` decode): a fixture witness
    /// encoded with the uploader's `encode_witness_payload` must round-trip to the original
    /// tuple.
    #[tokio::test]
    async fn valid_object_decodes_end_to_end() {
        let (salt_witness, mpt_witness): (_, MptWitness) =
            TestFixtures::mainnet_shared().first_paired_witness();
        let (_, payload) = stateless_common::encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("fixture witness must encode");

        let (endpoint, hits) = mock_r2(vec![(200, payload)]).await;
        let (decoded_salt, decoded_mpt) =
            fetch(&endpoint).await.expect("valid object must fetch and decode");
        assert_eq!(decoded_salt, salt_witness);
        assert_eq!(decoded_mpt, mpt_witness);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a successful fetch must take exactly one GET");
    }

    #[tokio::test]
    async fn undecodable_body_surfaces_decode_without_retry() {
        let (endpoint, hits) = mock_r2(vec![(200, "not a zstd witness")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Decode { .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a corrupt object must not be re-downloaded");
    }

    /// Every deterministic failure must be throttled before surfacing (see
    /// [`DETERMINISTIC_FAILURE_THROTTLE`] for why).
    #[tokio::test]
    async fn deterministic_failures_are_throttled_before_surfacing() {
        for (status, body) in [(403, ""), (404, ""), (200, "garbage")] {
            let (endpoint, _) = mock_r2(vec![(status, body)]).await;
            let started = std::time::Instant::now();
            fetch(&endpoint).await.unwrap_err();
            assert!(
                started.elapsed() >= DETERMINISTIC_FAILURE_THROTTLE,
                "status {status} surfaced without the deterministic-failure throttle",
            );
        }
    }

    /// Exhausted retryable failures must pause the policy's `max` backoff before surfacing:
    /// the pipeline fetcher re-enqueues with zero delay, so without the pause the next fetch
    /// cycle would re-burst a fresh ramp (starting at `initial`) into the same brownout.
    #[tokio::test]
    async fn exhausted_retries_pause_max_backoff_before_surfacing() {
        let (endpoint, hits) = mock_r2(vec![(503, "overloaded")]).await;
        // The ramp's 8 in-loop sleeps double from 1ms and never reach the 400ms cap
        // (1+2+…+128 = 255ms before jitter, ≤382ms with the ≤50% jitter), so of the asserted
        // lower bound, ≥400ms is attributable to the exhaustion pause alone.
        let (initial, max) = (Duration::from_millis(1), Duration::from_millis(400));
        let client = client_with_backoff(&endpoint, BackoffPolicy::new(initial, max));
        let started = std::time::Instant::now();
        let err = client.get_witness(1, B256::ZERO).await.unwrap_err();
        assert!(
            matches!(err, R2WitnessError::Get(R2GetError::Throttled { status: 503, .. })),
            "{err}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS);
        assert!(
            started.elapsed() >= Duration::from_millis(255) + max,
            "exhausted retries surfaced without the max-backoff pause ({:?})",
            started.elapsed(),
        );
    }
}
