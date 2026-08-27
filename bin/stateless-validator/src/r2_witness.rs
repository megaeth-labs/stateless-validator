//! Direct-from-R2 witness source.
//!
//! Fetches the primary witness object straight from the R2 bucket — via SigV4-signed S3 GETs
//! or unsigned GETs through a Cloudflare custom domain, per construction — and returns
//! the same `(SaltWitness, MptWitness)` tuple the RPC path yields. The failure taxonomy and
//! the transport wrapper are [`stateless_common::r2_witness`], shared with the
//! debug-trace-server's adapter; the transport core below that is `stateless-r2`'s
//! [`R2ObjectFetcher`]. This adapter owns what is validator-specific: the **full** payload
//! decode (proof verification needs the elliptic-curve points the light decode skips), the
//! validator metrics, and the surfaced-failure pacing the pipeline fetcher relies on. The
//! object body is `zstd(bincode-legacy((SaltWitness, MptWitness)))`, which
//! [`stateless_common::decode_witness_payload`] inverts exactly.
//!
//! Operator note on missing objects: the pipeline retries a `Missing` witness indefinitely
//! (each attempt throttled by [`DETERMINISTIC_FAILURE_THROTTLE`]). Near the tip that is
//! exactly right — the object appears once the uploader wins the race. But on a fixed
//! `--end-block` slice over history, a permanently absent object means the run never
//! completes and never fails: alert on `r2_witness_errors_total{kind="missing"}` staying hot
//! for the same block, and use the object key from the error's log line to check/backfill
//! the bucket. On the custom-domain target, "appears once the uploader wins" additionally
//! assumes the edge does not cache 404s — see the `--r2-custom-domain` flag docs.
//!
//! [`R2ObjectFetcher`]: stateless_r2::fetch::R2ObjectFetcher

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use salt::SaltWitness;
pub use stateless_common::R2WitnessError;
use stateless_common::{
    BackoffPolicy, R2WitnessTransport, WitnessSizeBreakdown, decode_witness_payload,
};
use stateless_core::withdrawals::MptWitness;
use stateless_r2::{
    fetch::{CfAccessCredentials, FetchTimeouts},
    keys,
};
use tracing::trace;

use crate::metrics;

/// Throttle applied before surfacing any deterministic (non-retryable) failure: the pipeline
/// fetcher (`stateless-core/src/pipeline/fetcher.rs`) re-enqueues failed fetches with no delay,
/// so returning instantly would hot-loop GETs against R2. Delete this once the fetcher
/// grows per-block re-enqueue backoff. Test builds shrink it so the failure-path tests run in
/// milliseconds.
const DETERMINISTIC_FAILURE_THROTTLE: Duration =
    if cfg!(test) { Duration::from_millis(5) } else { Duration::from_secs(2) };

/// Total GET attempts (first try + retries) per fetch for retryable (transport/429/5xx)
/// failures before the error surfaces. Stays a local constant: the RPC witness path retries
/// unboundedly, so there is no operator flag to mirror.
const MAX_ATTEMPTS: usize = 9;

/// Fetches witness objects straight from an R2 bucket — SigV4-signed over the S3 API, or
/// unsigned through a Cloudflare custom domain, per construction.
/// The transport's `Debug` redacts the credentials.
#[derive(Debug)]
pub struct R2WitnessClient {
    transport: R2WitnessTransport,
}

impl R2WitnessClient {
    /// The configured target's origin, for startup logging.
    pub fn origin(&self) -> &str {
        self.transport.origin()
    }

    /// The configured target's metric label.
    pub const fn target_label(&self) -> &'static str {
        self.transport.target_label()
    }

    /// How many HTTP/2 connections the transport spreads its GETs over, for startup logging.
    pub fn connections(&self) -> usize {
        self.transport.connections()
    }

    /// The configured cap on in-flight GETs (`None` = unlimited; see [`Self::new`] for the
    /// exact semantics), for startup logging.
    pub fn max_concurrent_requests(&self) -> Option<usize> {
        self.transport.max_concurrent_requests()
    }

    /// Builds a client from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `timeouts` bounds each individual GET (end-to-end and connect). `retry_backoff` paces the
    /// retries of retryable failures — first sleep `initial`, doubling up to `max`, each with
    /// up to 50% jitter — and is the same policy the RPC path builds from
    /// `--rpc-initial-backoff-ms` / `--rpc-max-backoff-ms`, so one pair of flags tunes both
    /// paths. `max_concurrent_requests` caps the number of GETs in flight at once (`None` =
    /// unlimited, `Some(0)` clamps to 1 — same semantics as the RPC witness semaphore; in R2
    /// mode this client is the only enforcement of `--r2-max-concurrent-requests`). Fails
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
        R2WitnessTransport::new(
            endpoint,
            bucket,
            access_key_id,
            secret_access_key,
            timeouts,
            retry_backoff,
            max_concurrent_requests,
        )
        .map(|transport| Self { transport })
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
        connections: usize,
    ) -> eyre::Result<Self> {
        R2WitnessTransport::new_custom_domain(
            domain,
            access,
            timeouts,
            retry_backoff,
            max_concurrent_requests,
            connections,
            metrics::record_r2_negotiated_version,
        )
        .map(|transport| Self { transport })
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
                self.transport.fetcher().pacing().max
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
            .transport
            .fetcher()
            .get_block_object(number, hash, MAX_ATTEMPTS, None, metrics::on_r2_witness_retry)
            .await?;
        let (bytes, queue_wait) = (fetched.bytes, fetched.queue_wait);

        // zstd + bincode over a multi-MB witness is CPU-bound; keep it off the runtime.
        let key = || keys::block_object_key(number, hash);
        match tokio::task::spawn_blocking(move || decode_witness_payload(&bytes)).await {
            Ok(Ok(witness)) => {
                trace!(number, "R2 witness fetched and decoded");
                // Queue wait on the self-imposed concurrency cap is subtracted: folded in, it
                // would masquerade as R2 slowness.
                metrics::on_r2_witness_fetch_success(
                    started.elapsed().saturating_sub(queue_wait).as_secs_f64(),
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

    use stateless_r2::fetch::R2GetError;
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

    /// Construction errors from the shared transport must surface through the eyre conversion.
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

    /// The custom-domain client serves the same full-decode path end-to-end, requesting the
    /// bare `/{key}` layout (no bucket segment, no SigV4 authorization).
    #[tokio::test]
    async fn custom_domain_client_decodes_and_requests_bare_key() {
        let (salt_witness, mpt_witness): (_, MptWitness) =
            TestFixtures::mainnet_shared().first_paired_witness();
        let (_, payload) = stateless_common::encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("fixture witness must encode");

        let (domain, _, heads) =
            stateless_test_utils::mock_r2::mock_r2_capturing(vec![(200, payload)]).await;
        let client = R2WitnessClient::new_custom_domain(
            &domain,
            None,
            test_timeouts(),
            test_backoff(),
            None,
            1,
        )
        .unwrap();
        let (decoded_salt, _) =
            client.get_witness(1, B256::ZERO).await.expect("valid object must fetch and decode");
        assert_eq!(decoded_salt, salt_witness);
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(head.starts_with("get /block/0_999/1."), "bucketless key layout: {head}");
        assert!(!head.contains("authorization:"), "custom-domain GET must be unsigned: {head}");
    }

    /// Construction errors from the shared transport's custom-domain arm surface through the
    /// same eyre conversion as the S3 arm.
    #[test]
    fn custom_domain_rejects_origin_with_path() {
        let err = R2WitnessClient::new_custom_domain(
            "https://witness.example.com/witness-mainnet",
            None,
            test_timeouts(),
            test_backoff(),
            None,
            1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid R2 custom domain"));
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
