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
//! What happens after a fetch fails is the [`R2FailurePolicy`] chosen at the wiring site.
//! Under `--witness-source r2` R2 is the sole source: the pipeline retries a `Missing`
//! witness indefinitely (each attempt throttled by [`DETERMINISTIC_FAILURE_THROTTLE`]),
//! which near the tip is exactly right — the object appears once the uploader wins the
//! race. Under `--witness-source r2-then-rpc` the RPC witness path waits behind R2, so a
//! failure surfaces at once, with a short retry budget and no pause, and the pipeline
//! fetcher takes the block over RPC — the trace server's R2-first shape.
//!
//! Operator note on missing objects: a `missing` inside the [`R2_FRONTIER_WINDOW`] below
//! the last polled remote head is the uploader still catching up and lands on
//! `r2_witness_errors_total{kind="missing_frontier"}`; a `missing` deeper than that is a
//! bucket hole and feeds `kind="missing"`. On a fixed `--end-block` slice over history under
//! `--witness-source r2`, a permanently absent object means the run never completes and
//! never fails: alert on `kind="missing"`, and use the object key from the error's log line
//! to check/backfill the bucket. On the custom-domain target, "appears once the uploader
//! wins" additionally assumes the edge does not cache 404s — see the `--r2-custom-domain`
//! flag docs.
//!
//! [`R2ObjectFetcher`]: stateless_r2::fetch::R2ObjectFetcher

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use salt::SaltWitness;
pub use stateless_common::R2WitnessError;
use stateless_common::{
    R2_FRONTIER_WINDOW, R2WitnessTransport, WitnessSizeBreakdown, decode_on_blocking_pool,
    decode_witness_payload,
};
use stateless_core::withdrawals::MptWitness;
use tracing::{debug, trace, warn};

use crate::metrics;

/// Throttle applied before surfacing any deterministic (non-retryable) failure under
/// [`R2FailurePolicy::Surface`]: the pipeline fetcher
/// (`stateless-core/src/pipeline/fetcher.rs`) re-enqueues failed fetches with no delay, so
/// returning instantly would hot-loop GETs against R2. Delete this once the fetcher grows
/// per-block re-enqueue backoff. Test builds shrink it so the failure-path tests run in
/// milliseconds.
const DETERMINISTIC_FAILURE_THROTTLE: Duration =
    if cfg!(test) { Duration::from_millis(5) } else { Duration::from_secs(2) };

/// Synthetic `kind` label for a `missing` inside the frontier band — the uploader has not
/// reached the block yet, the expected near-tip outcome. Kept off [`R2WitnessError::KINDS`]
/// (no error variant produces it); [`error_kind`] derives it so the `kind="missing"`
/// bucket-integrity alarm only ever counts objects that must exist.
pub(crate) const KIND_MISSING_FRONTIER: &str = "missing_frontier";

/// What the pipeline does with an R2 failure, and therefore how hard the client tries before
/// surfacing one. Chosen by `--witness-source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum R2FailurePolicy {
    /// R2 is the sole witness source (`--witness-source r2`): the pipeline fetcher
    /// re-enqueues a failed block with no delay, so the client retries retryable failures
    /// through a long budget and pauses before surfacing anything.
    Surface,
    /// The RPC witness path waits behind R2 (`--witness-source r2-then-rpc`): a failure hands
    /// the block to RPC at once, so the retry budget is short and nothing pauses — a throttled
    /// R2 should hand over quickly instead of holding the block on backoff sleeps.
    FallBackToRpc,
}

impl R2FailurePolicy {
    /// Total GET attempts (first try + retries) per fetch for retryable (transport/429/5xx)
    /// failures before the error surfaces. Local constants rather than flags: the RPC witness
    /// path retries unboundedly, so there is no operator setting to mirror.
    const fn max_attempts(self) -> usize {
        match self {
            Self::Surface => 9,
            Self::FallBackToRpc => 3,
        }
    }
}

/// The `kind` label an R2 witness failure is recorded under: [`R2WitnessError::kind`], except
/// that a `missing` inside the [`R2_FRONTIER_WINDOW`] below `remote_head` — or with no head
/// polled yet, when nothing is known to be uploaded — is [`KIND_MISSING_FRONTIER`].
///
/// The validator only fetches at or below the head it last polled, so unlike the trace
/// server there is no above-tip band: a block is either near enough to the head for the
/// uploader to plausibly still be behind it, or deep enough that the object must exist.
pub(crate) fn error_kind(
    e: &R2WitnessError,
    number: u64,
    remote_head: Option<u64>,
) -> &'static str {
    let frontier = remote_head.is_none_or(|head| number.saturating_add(R2_FRONTIER_WINDOW) >= head);
    if e.is_missing() && frontier { KIND_MISSING_FRONTIER } else { e.kind() }
}

/// Fetches witness objects straight from an R2 bucket — SigV4-signed over the S3 API, or
/// unsigned through a Cloudflare custom domain, per construction.
/// The transport's `Debug` redacts the credentials.
#[derive(Debug)]
pub struct R2WitnessClient {
    transport: R2WitnessTransport,
    policy: R2FailurePolicy,
}

impl R2WitnessClient {
    /// Wraps an already-built transport. Construction (and the startup logging that reads
    /// the configured target off it) lives at the wiring site, which owns the flags.
    pub const fn new(transport: R2WitnessTransport, policy: R2FailurePolicy) -> Self {
        Self { transport, policy }
    }

    /// What the pipeline does with a failure this client surfaces.
    pub const fn policy(&self) -> R2FailurePolicy {
        self.policy
    }

    /// Fetches and decodes the witness for `(number, hash)` from R2. `remote_head` is the
    /// chain head the caller last polled, which classifies a miss (see [`error_kind`]).
    ///
    /// Transport/429/5xx failures are retried internally, paced by the `retry_backoff` policy
    /// given at construction, up to the [`R2FailurePolicy`]'s attempt budget. Under
    /// [`R2FailurePolicy::Surface`] every surfaced failure pauses before returning (the
    /// pipeline fetcher re-enqueues failed fetches with zero delay, so returning instantly
    /// would hot-loop GETs against R2): deterministic failures wait the fixed
    /// [`DETERMINISTIC_FAILURE_THROTTLE`], and exhausted retryable failures wait the policy's
    /// `max` backoff — without that, the next fetch cycle would restart its ramp at `initial`,
    /// re-bursting GETs into the same brownout the exhausted ramp just backed away from.
    /// Under [`R2FailurePolicy::FallBackToRpc`] failures return at once: the caller's next
    /// move is the RPC witness path, and it should not wait for it.
    pub async fn get_witness(
        &self,
        number: u64,
        hash: B256,
        remote_head: Option<u64>,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let result = self.get_witness_inner(number, hash).await;
        if let Err(e) = &result {
            let kind = error_kind(e, number, remote_head);
            metrics::on_r2_witness_error(kind);
            match self.policy {
                R2FailurePolicy::Surface => {
                    // The pipeline fetcher logs the surfaced error when it re-enqueues.
                    let pause = if e.is_retryable() {
                        self.transport.fetcher().pacing().max
                    } else {
                        DETERMINISTIC_FAILURE_THROTTLE
                    };
                    tokio::time::sleep(pause).await;
                }
                R2FailurePolicy::FallBackToRpc if kind == KIND_MISSING_FRONTIER => {
                    debug!(number, %hash, "Frontier witness not in R2 yet; fetching over RPC");
                }
                R2FailurePolicy::FallBackToRpc => {
                    warn!(
                        number,
                        %hash,
                        kind,
                        error = %e,
                        "R2 witness fetch failed, falling back to the RPC witness path",
                    );
                }
            }
        }
        result
    }

    /// [`Self::get_witness`] without the failure bookkeeping.
    async fn get_witness_inner(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let started = Instant::now();
        let fetched = self
            .transport
            .fetcher()
            .get_block_object(
                number,
                hash,
                self.policy.max_attempts(),
                None,
                metrics::on_r2_witness_retry,
            )
            .await?;
        let (bytes, queue_wait) = (fetched.bytes, fetched.queue_wait);

        // No deadline: the pipeline fetcher has no per-block budget to protect, so a slow
        // decode must finish rather than be abandoned and re-fetched.
        let witness = decode_on_blocking_pool(bytes, number, hash, None, |bytes| {
            decode_witness_payload(bytes)
        })
        .await?;
        trace!(number, "R2 witness fetched and decoded");
        // Queue wait on the self-imposed concurrency cap is subtracted: folded in, it would
        // masquerade as R2 slowness.
        metrics::on_r2_witness_fetch_success(
            started.elapsed().saturating_sub(queue_wait).as_secs_f64(),
            WitnessSizeBreakdown::new(&witness.0, &witness.1),
        );
        Ok(witness)
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::atomic::Ordering};

    use stateless_common::BackoffPolicy;
    use stateless_r2::{
        fetch::{FetchTimeouts, R2GetError},
        keys,
    };
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

    fn client_with(
        endpoint: &str,
        retry_backoff: BackoffPolicy,
        policy: R2FailurePolicy,
    ) -> R2WitnessClient {
        let transport = R2WitnessTransport::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            FetchTimeouts {
                per_attempt: Duration::from_secs(5),
                connect: stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT,
            },
            retry_backoff,
            None,
        )
        .unwrap();
        R2WitnessClient::new(transport, policy)
    }

    /// One fetch under the given policy, with no remote head polled.
    async fn fetch_with(
        endpoint: &str,
        policy: R2FailurePolicy,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        client_with(endpoint, test_backoff(), policy).get_witness(1, B256::ZERO, None).await
    }

    /// One fetch under the sole-source policy — the shape most tests exercise.
    async fn fetch(endpoint: &str) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        fetch_with(endpoint, R2FailurePolicy::Surface).await
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
        let transport = R2WitnessTransport::new_custom_domain(
            &domain,
            None,
            FetchTimeouts {
                per_attempt: Duration::from_secs(5),
                connect: stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT,
            },
            test_backoff(),
            None,
            1,
            metrics::record_r2_negotiated_version,
        )
        .unwrap();
        let client = R2WitnessClient::new(transport, R2FailurePolicy::Surface);
        let (decoded_salt, _) = client
            .get_witness(1, B256::ZERO, None)
            .await
            .expect("valid object must fetch and decode");
        assert_eq!(decoded_salt, salt_witness);
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(head.starts_with("get /block/0_999/1."), "bucketless key layout: {head}");
        assert!(!head.contains("authorization:"), "custom-domain GET must be unsigned: {head}");
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
        let client =
            client_with(&endpoint, BackoffPolicy::new(initial, max), R2FailurePolicy::Surface);
        let started = std::time::Instant::now();
        let err = client.get_witness(1, B256::ZERO, None).await.unwrap_err();
        assert!(
            matches!(err, R2WitnessError::Get(R2GetError::Throttled { status: 503, .. })),
            "{err}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), R2FailurePolicy::Surface.max_attempts());
        assert!(
            started.elapsed() >= Duration::from_millis(255) + max,
            "exhausted retries surfaced without the max-backoff pause ({:?})",
            started.elapsed(),
        );
    }

    /// Under the fallback policy a failure is the RPC path's cue, so it must surface at once:
    /// a short retry budget for retryable failures and no pause of any kind — neither the
    /// deterministic-failure throttle nor the exhausted-retry pause, both of which exist only
    /// to pace the sole-source pipeline's blind re-enqueue.
    #[tokio::test]
    async fn fallback_policy_hands_over_after_a_short_budget_without_pausing() {
        let (endpoint, hits) = mock_r2(vec![(503, "overloaded")]).await;
        let started = std::time::Instant::now();
        let err = fetch_with(&endpoint, R2FailurePolicy::FallBackToRpc).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Get(R2GetError::Throttled { .. })), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), R2FailurePolicy::FallBackToRpc.max_attempts());
        // The two in-loop backoff sleeps of `test_backoff` total well under 100ms; the
        // sole-source policy would have added its `max` pause on top.
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "an exhausted retryable failure paused before surfacing ({:?})",
            started.elapsed(),
        );

        for (status, body) in [(403, ""), (404, ""), (200, "garbage")] {
            let (endpoint, hits) = mock_r2(vec![(status, body)]).await;
            let started = std::time::Instant::now();
            fetch_with(&endpoint, R2FailurePolicy::FallBackToRpc).await.unwrap_err();
            assert_eq!(hits.load(Ordering::SeqCst), 1, "status {status} must not be retried");
            assert!(
                started.elapsed() < DETERMINISTIC_FAILURE_THROTTLE,
                "status {status} paused before surfacing ({:?})",
                started.elapsed(),
            );
        }
    }

    /// A `missing` within the frontier band below the polled head — or with no head polled
    /// yet — is the uploader still catching up and must stay off the `kind="missing"`
    /// bucket-integrity alarm; deeper than the band the object must exist. Every other kind
    /// is its own, wherever the block sits.
    #[test]
    fn error_kind_splits_frontier_misses_from_bucket_holes() {
        let missing = R2WitnessError::Get(R2GetError::Missing { number: 1, key: "k".into() });
        let head = 5000;
        assert_eq!(error_kind(&missing, 100, None), KIND_MISSING_FRONTIER, "no head polled yet");
        assert_eq!(error_kind(&missing, head, Some(head)), KIND_MISSING_FRONTIER, "the head");
        assert_eq!(
            error_kind(&missing, head - R2_FRONTIER_WINDOW, Some(head)),
            KIND_MISSING_FRONTIER,
            "the band's deep edge is still inside it",
        );
        assert_eq!(
            error_kind(&missing, head - R2_FRONTIER_WINDOW - 1, Some(head)),
            "missing",
            "one past the band is a hole",
        );
        assert_eq!(error_kind(&missing, 100, Some(head)), "missing", "deep history is a hole");

        let throttled = R2WitnessError::Get(R2GetError::Throttled {
            number: 1,
            key: "k".into(),
            status: 503,
            body: String::new(),
        });
        assert_eq!(error_kind(&throttled, head, Some(head)), "throttled", "only misses split");
    }
}
