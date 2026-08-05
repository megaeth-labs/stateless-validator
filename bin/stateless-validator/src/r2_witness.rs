//! Direct-from-R2 witness source.
//!
//! Fetches the primary witness object straight from the R2 bucket over the S3 API (a SigV4-signed
//! `GET`), decompresses it, and returns the same `(SaltWitness, MptWitness)` tuple the RPC path
//! yields.
//!
//! The transport core — signed GET, response classification, retry/backoff, concurrency cap —
//! is [`R2ObjectFetcher`] from `stateless-r2`, shared with the debug-trace-server's historical
//! witness source so the readers cannot drift. This adapter owns what is validator-specific:
//! the **full** payload decode (proof verification needs the elliptic-curve points light decode
//! skips), the validator metrics, and the surfaced-failure pacing the pipeline fetcher relies
//! on. The primary object body is `zstd(bincode-legacy((SaltWitness, MptWitness)))` (the
//! uploader's `encode_witness_payload`), which [`stateless_common::decode_witness_payload`]
//! inverts exactly.

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use salt::SaltWitness;
use stateless_common::{
    BackoffPolicy, WitnessDecodingError, WitnessSizeBreakdown, decode_witness_payload,
};
use stateless_core::withdrawals::MptWitness;
use stateless_r2::{
    fetch::{DEFAULT_MAX_ATTEMPTS, R2GetError, R2ObjectFetcher, RetryPacing},
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

/// Failure outcome of an R2 witness fetch.
#[derive(Debug, thiserror::Error)]
pub enum R2WitnessError {
    /// The primary object is absent from the bucket (HTTP 404 `NoSuchKey`): a transient miss
    /// near the tip / right after a reorg (the uploader has not PUT the object yet), or a
    /// permanent completeness gap in R2.
    ///
    /// Operator note: the pipeline retries a missing witness indefinitely (each attempt
    /// throttled by [`DETERMINISTIC_FAILURE_THROTTLE`]). Near the tip that is exactly right —
    /// the object appears once the uploader wins the race. But on a fixed `--end-block` slice
    /// over history, a permanently absent object means the run never completes and never
    /// fails: alert on `r2_witness_errors_total{kind="missing"}` staying hot for the same
    /// block, and use the object key from this error's log line to check/backfill the bucket.
    #[error("R2 witness MISSING for block {number} (key {key}): object not found (404)")]
    Missing { number: u64, key: String },
    /// Transport-level failure (connection reset/timeout) — the endpoint is effectively
    /// unreachable. Retried internally with backoff before surfacing.
    #[error("R2 transport failure for block {number} (key {key}): {source}")]
    Transport { number: u64, key: String, source: reqwest::Error },
    /// R2 asked us to slow down (429) or returned a server-side error (5xx, including R2's 503
    /// overload / SlowDown). Retried internally with backoff before surfacing.
    #[error("R2 throttled/server error {status} for block {number} (key {key}): {body}")]
    Throttled { number: u64, key: String, status: u16, body: String },
    /// A non-success status unlikely to clear on retry: a 4xx other than 429 (e.g. 403 bad
    /// credentials, 404 NoSuchBucket) or a 3xx (redirects are never followed — see
    /// [`R2ObjectFetcher::new`]).
    #[error("R2 unexpected status {status} for block {number} (key {key}): {body}")]
    Status { number: u64, key: String, status: u16, body: String },
    /// The object was fetched but its bytes did not decode to a `(SaltWitness, MptWitness)` tuple
    /// — a corrupt witness in R2. Deterministic; not retried.
    #[error("R2 witness for block {number} (key {key}) failed to decode: {source}")]
    Decode { number: u64, key: String, source: WitnessDecodingError },
    /// The decode task panicked. This is a bug in our own decoder, not a problem with the data in
    /// R2, so it is kept out of [`Self::Decode`].
    #[error("R2 witness decode task for block {number} (key {key}) panicked: {source}")]
    DecodePanicked { number: u64, key: String, source: JoinError },
}

impl From<R2GetError> for R2WitnessError {
    fn from(e: R2GetError) -> Self {
        match e {
            R2GetError::Missing { number, key } => Self::Missing { number, key },
            R2GetError::Transport { number, key, source } => {
                Self::Transport { number, key, source }
            }
            R2GetError::Throttled { number, key, status, body } => {
                Self::Throttled { number, key, status, body }
            }
            R2GetError::Status { number, key, status, body } => {
                Self::Status { number, key, status, body }
            }
        }
    }
}

impl R2WitnessError {
    /// Every label [`Self::kind`] can produce, for metrics pre-registration
    /// (`crate::metrics::init_metrics` zero-inits the error counter per kind).
    pub const KINDS: &'static [&'static str] =
        &["missing", "transport", "throttled", "status", "decode", "decode_panicked"];

    /// Stable lowercase label for this variant — the `kind` label on the R2 witness error
    /// counter. Every value returned here must appear in [`Self::KINDS`].
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Missing { .. } => "missing",
            Self::Transport { .. } => "transport",
            Self::Throttled { .. } => "throttled",
            Self::Status { .. } => "status",
            Self::Decode { .. } => "decode",
            Self::DecodePanicked { .. } => "decode_panicked",
        }
    }

    /// Whether an immediate retry against the same endpoint could plausibly succeed (transport
    /// blips, 429, 5xx). Every other variant is deterministic and is surfaced without retrying.
    const fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport { .. } | Self::Throttled { .. })
    }
}

/// Fetches witness objects straight from an R2 bucket over the S3 API with SigV4-signed GETs.
///
/// Cloning is cheap — the fetcher's `reqwest::Client` and signer are internally
/// reference-counted / small, and its `Debug` redacts the credentials.
#[derive(Clone, Debug)]
pub struct R2WitnessClient {
    fetcher: R2ObjectFetcher,
    /// Pause applied before surfacing an exhausted retryable failure (the pacing's `max`):
    /// without it, the next fetch cycle would restart its ramp at `initial`, re-bursting GETs
    /// into the same brownout the exhausted ramp just backed away from.
    exhausted_pause: Duration,
}

impl R2WitnessClient {
    /// Builds a client from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `per_attempt_timeout` bounds each individual GET. `retry_backoff` paces the retries of
    /// retryable failures — first sleep `initial`, doubling up to `max`, each with up to 50%
    /// jitter — and is the same policy the RPC path builds from `--rpc-initial-backoff-ms` /
    /// `--rpc-max-backoff-ms`, so one pair of flags tunes both paths. `max_concurrent_requests`
    /// caps the number of GETs in flight at once (`None` = unlimited, `Some(0)` clamps to 1 —
    /// same semantics as the RPC witness semaphore; in R2 mode this client is the only
    /// enforcement of `--witness-max-concurrent-requests`). Fails if the endpoint is not a bare
    /// `scheme://host[:port]` origin or the HTTP client cannot be built.
    pub fn new(
        endpoint: &str,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        per_attempt_timeout: Duration,
        retry_backoff: BackoffPolicy,
        max_concurrent_requests: Option<usize>,
    ) -> eyre::Result<Self> {
        let fetcher = R2ObjectFetcher::new(
            endpoint,
            bucket,
            access_key_id,
            secret_access_key,
            per_attempt_timeout,
            RetryPacing { initial: retry_backoff.initial, max: retry_backoff.max },
            max_concurrent_requests,
        )
        .map_err(|e| eyre::eyre!(e))?;
        Ok(Self { fetcher, exhausted_pause: retry_backoff.max })
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
            let pause = if e.is_retryable() {
                self.exhausted_pause
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
            .get_block_object(number, hash, DEFAULT_MAX_ATTEMPTS, None, metrics::on_r2_witness_retry)
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

    use stateless_test_utils::mock_r2::mock_r2;

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

    fn client(endpoint: &str) -> R2WitnessClient {
        client_with_backoff(endpoint, test_backoff())
    }

    fn client_with_backoff(endpoint: &str, retry_backoff: BackoffPolicy) -> R2WitnessClient {
        R2WitnessClient::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(5),
            retry_backoff,
            None,
        )
        .unwrap()
    }

    async fn fetch(endpoint: &str) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        client(endpoint).get_witness(1, B256::ZERO).await
    }

    #[test]
    fn rejects_endpoint_with_path() {
        // A bucket-in-path URL is the classic misconfiguration; construction must fail fast.
        let err = R2WitnessClient::new(
            "https://acc.r2.cloudflarestorage.com/witness-mainnet",
            "witness-mainnet".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(20),
            test_backoff(),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid R2 endpoint"));
    }

    /// Every fetch-level classification must map onto the matching validator variant (and
    /// therefore the matching metrics kind).
    #[test]
    fn fetch_errors_map_onto_matching_kinds() {
        let cases: Vec<(R2GetError, &str)> = vec![
            (R2GetError::Missing { number: 1, key: "k".into() }, "missing"),
            (
                R2GetError::Throttled { number: 1, key: "k".into(), status: 503, body: "".into() },
                "throttled",
            ),
            (
                R2GetError::Status { number: 1, key: "k".into(), status: 403, body: "".into() },
                "status",
            ),
        ];
        for (fetch_error, kind) in cases {
            assert_eq!(R2WitnessError::from(fetch_error).kind(), kind);
        }
    }

    /// The only test of the success path (fetch → `spawn_blocking` decode): a fixture witness
    /// encoded with the uploader's `encode_witness_payload` must round-trip to the original
    /// tuple.
    #[tokio::test]
    async fn valid_object_decodes_end_to_end() {
        use stateless_test_utils::fixtures::TestFixtures;

        let fixtures = TestFixtures::mainnet_shared();
        let (_, hash) =
            fixtures.paired_blocks().into_iter().next().expect("mainnet fixtures have a witness");
        let salt_witness = fixtures.salt_witnesses[&hash].clone();
        let mpt_witness: MptWitness = fixtures.mpt_witness(&hash);
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
        assert!(matches!(err, R2WitnessError::Throttled { status: 503, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), DEFAULT_MAX_ATTEMPTS);
        assert!(
            started.elapsed() >= Duration::from_millis(255) + max,
            "exhausted retries surfaced without the max-backoff pause ({:?})",
            started.elapsed(),
        );
    }
}
