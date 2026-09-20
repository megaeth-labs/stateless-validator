//! Direct-from-R2 witness source.
//!
//! Fetches the primary witness object straight from the R2 bucket — via SigV4-signed S3 GETs
//! or unsigned GETs through a Cloudflare custom domain, per construction — and returns
//! the same `(SaltWitness, MptWitness)` tuple the RPC path yields. The failure taxonomy and
//! the transport wrapper are [`stateless_common::r2_witness`], shared with the
//! debug-trace-server's adapter; the transport core below that is `stateless-r2`'s
//! [`R2ObjectFetcher`]. This adapter owns what is validator-specific: the **full** payload
//! decode (proof verification needs the elliptic-curve points the light decode skips), the
//! validator metrics, the per-block stage budget, and how a miss is classified against the
//! polled head. The object body is `zstd(bincode-legacy((SaltWitness, MptWitness)))`, which
//! [`stateless_common::decode_witness_payload`] inverts exactly.
//!
//! Every failure surfaces at once, on a short retry budget within a bounded total and with no
//! pause before returning: the block's next stop is the `--witness-endpoint` RPC chain, and
//! it should not wait for it any longer than the fast path is worth. That fallback is a
//! second *path* to the same bytes rather than a second copy of them — the witness gateway
//! reads this same bucket — so what it covers is our own path failing (the CDN edge, an
//! Access token, HTTP/2, the credentials, this fetcher), not the bucket failing.
//!
//! Operator note on missing objects, and on which counter is worth watching in which mode.
//! A `missing` inside the [`R2_FRONTIER_WINDOW`][w] below the last polled remote head is the
//! uploader still catching up and lands on `r2_witness_frontier_misses_total`, its own series
//! so that `r2_witness_errors_total` stays an error rate; deeper than that the object must
//! exist, so it feeds `r2_witness_errors_total{kind="missing"}`.
//!
//! While following the tip those bands do not both apply: the fetcher works at
//! `head - tip_buffer`, and every deployed buffer is far inside a 32-block window, so every
//! miss is a frontier miss and `kind="missing"` stays at zero by construction. Frontier
//! misses are routine and numerous there, which is exactly why they are kept off the error
//! counter, and what to watch instead is their own rate. `kind="missing"` earns its name
//! during catch-up and fixed `--end-block` backfills, where blocks sit far below the head.
//!
//! A hole that first appears near the tip is therefore not detected here: the block is
//! fetched once, falls back, and is never probed again. That is deliberate rather than an
//! oversight — the fallback already served the block, so this process has nothing to act on,
//! and re-probing to keep a counter honest belongs with whatever watches the uploader. A
//! true hole does not resolve by falling back either, it moves the retry onto the shared
//! gateway. On the custom-domain target all of this additionally assumes the edge does not
//! cache 404s — see the `--r2-custom-domain` docs.
//!
//! [`R2ObjectFetcher`]: stateless_r2::fetch::R2ObjectFetcher
//! [w]: stateless_common::R2_FRONTIER_WINDOW

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use salt::SaltWitness;
pub use stateless_common::R2WitnessError;
use stateless_common::{
    R2Band, R2WitnessTransport, WitnessSizeBreakdown, decode_on_blocking_pool,
    decode_witness_payload, r2_band,
};
use stateless_core::withdrawals::MptWitness;
use tracing::{debug, trace, warn};

use crate::metrics;

/// Total GET attempts (first try + retries) per fetch, for retryable (transport/429/5xx)
/// failures. Small on purpose: the RPC witness chain waits behind this one, so a throttled R2
/// should hand the block over after a couple of retries rather than work through a long
/// ramp. The retries are spaced by the `--rpc-*-backoff-ms` ramp — up to about two seconds in
/// total at its defaults — and everything, sleeps included, stays inside the stage budget
/// given to [`R2WitnessClient::new`]. Not an operator flag — the RPC witness path retries
/// unboundedly, so there is nothing to mirror.
const MAX_ATTEMPTS: usize = 3;

/// Whether a failure is the routine near-tip outcome: the object is absent and the block sits
/// within [`R2_FRONTIER_WINDOW`](stateless_common::R2_FRONTIER_WINDOW) of the head the
/// fetcher last polled, so the uploader may
/// simply not have reached it yet. Those are counted on their own series; everything else is
/// an error, which is what keeps `r2_witness_errors_total` an error rate.
///
/// `remote_head` is `0` before the first poll, which the shared classifier reads as "no tip
/// learned" and puts every block in the frontier — which is right: nothing is known to be
/// uploaded yet.
fn is_frontier_miss(e: &R2WitnessError, number: u64, remote_head: u64) -> bool {
    e.is_missing() && r2_band(remote_head, number) == R2Band::Frontier
}

/// Fetches witness objects straight from an R2 bucket — SigV4-signed over the S3 API, or
/// unsigned through a Cloudflare custom domain, per construction.
/// The transport's `Debug` redacts the credentials.
#[derive(Debug)]
pub struct R2WitnessClient {
    transport: R2WitnessTransport,
    stage_timeout: Duration,
}

impl R2WitnessClient {
    /// Wraps an already-built transport. Construction (and the startup logging that reads
    /// the configured target off it) lives at the wiring site, which owns the flags.
    ///
    /// `stage_timeout` bounds the whole fast path per block: the wait for a concurrency
    /// permit plus every GET attempt. Without it, [`MAX_ATTEMPTS`] against an endpoint that
    /// accepts connections and then stalls costs that many full per-attempt timeouts before
    /// the block reaches RPC, and blocks queued behind the concurrency cap wait through
    /// several such holders — which is the brownout the fallback exists to absorb, absorbed
    /// far too slowly to keep the pipeline moving.
    pub const fn new(transport: R2WitnessTransport, stage_timeout: Duration) -> Self {
        Self { transport, stage_timeout }
    }

    /// Fetches and decodes the witness for `(number, hash)` from R2. `remote_head` is the
    /// chain head the caller last polled (`0` before the first poll), which classifies a miss
    /// (see [`is_frontier_miss`]).
    ///
    /// Transport/429/5xx failures are retried internally up to [`MAX_ATTEMPTS`], paced by the
    /// backoff policy given at construction and bounded in total by the `stage_timeout` given
    /// there. Everything else surfaces on the first attempt, and nothing pauses before
    /// returning: the caller's next move is the RPC witness path, which should not wait behind
    /// a failure that has already been recorded here.
    pub async fn get_witness(
        &self,
        number: u64,
        hash: B256,
        remote_head: u64,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let result = self.get_witness_inner(number, hash).await;
        if let Err(e) = &result {
            if is_frontier_miss(e, number, remote_head) {
                metrics::on_r2_witness_frontier_miss();
                debug!(number, %hash, "Frontier witness not in R2 yet; fetching over RPC");
            } else {
                metrics::on_r2_witness_error(e.kind());
                warn!(
                    number,
                    %hash,
                    kind = e.kind(),
                    error = %e,
                    "R2 witness fetch failed, falling back to the RPC witness path",
                );
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
        let deadline = started + self.stage_timeout;
        let fetched = self
            .transport
            .fetcher()
            .get_block_object(
                number,
                hash,
                MAX_ATTEMPTS,
                Some(deadline),
                metrics::on_r2_witness_retry,
            )
            .await?;
        let (bytes, queue_wait) = (fetched.bytes, fetched.queue_wait);

        // The decode deliberately runs outside that deadline. It is our own CPU on bytes
        // already in hand, so it finishes; abandoning it would only re-fetch the same witness
        // over RPC and decode it again. What the deadline is there to bound is waiting on a
        // remote that may never answer.
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
    use std::{str::FromStr, sync::atomic::Ordering, time::Duration};

    use stateless_common::{BackoffPolicy, R2_FRONTIER_WINDOW};
    use stateless_r2::{
        fetch::{FetchTimeouts, R2GetError},
        keys,
    };
    use stateless_test_utils::{
        fixtures::TestFixtures,
        mock_r2::{mock_r2, mock_r2_held},
    };

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

    /// A stage budget far above anything these tests spend, so each one exercises the
    /// behaviour it names rather than the deadline. The deadline has its own test.
    const TEST_STAGE_TIMEOUT: Duration = Duration::from_secs(5);

    fn transport(endpoint: &str) -> R2WitnessTransport {
        R2WitnessTransport::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            test_timeouts(),
            test_backoff(),
            None,
        )
        .unwrap()
    }

    fn client(endpoint: &str) -> R2WitnessClient {
        R2WitnessClient::new(transport(endpoint), TEST_STAGE_TIMEOUT)
    }

    /// One fetch with no remote head polled yet.
    async fn fetch(endpoint: &str) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        client(endpoint).get_witness(1, B256::ZERO, 0).await
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
            test_timeouts(),
            test_backoff(),
            None,
            1,
            |_| {},
        )
        .unwrap();
        let (decoded_salt, _) = R2WitnessClient::new(transport, TEST_STAGE_TIMEOUT)
            .get_witness(1, B256::ZERO, 0)
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

    /// Every failure hands the block to the RPC witness chain, so none of them may pause on
    /// the way out and the retryable ones stop at a small budget. A pause here would be spent
    /// before the fallback even starts, on every block R2 cannot serve.
    #[tokio::test]
    async fn failures_surface_immediately_for_the_rpc_fallback() {
        let (endpoint, hits) = mock_r2(vec![(503, "overloaded")]).await;
        let started = std::time::Instant::now();
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Get(R2GetError::Throttled { .. })), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS, "retryable failures use the budget");
        // The two in-loop backoff sleeps of `test_backoff` total well under this; anything
        // larger is a pacing pause that no longer belongs here.
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "an exhausted retryable failure paused before surfacing ({:?})",
            started.elapsed(),
        );

        for (status, body) in [(403, ""), (404, ""), (200, "garbage")] {
            let (endpoint, hits) = mock_r2(vec![(status, body)]).await;
            let started = std::time::Instant::now();
            fetch(&endpoint).await.unwrap_err();
            assert_eq!(hits.load(Ordering::SeqCst), 1, "status {status} must not be retried");
            assert!(
                started.elapsed() < Duration::from_millis(100),
                "status {status} paused before surfacing ({:?})",
                started.elapsed(),
            );
        }
    }

    /// An endpoint that accepts the connection and then stalls must not hold the block for
    /// [`MAX_ATTEMPTS`] full per-attempt timeouts before the RPC chain gets it. The stage
    /// budget covers the permit wait and every attempt together, so the block leaves for RPC
    /// on that budget rather than on a multiple of it.
    ///
    /// Driven with a per-attempt timeout an order of magnitude above the stage budget, which
    /// is the shape that goes wrong: without the aggregate bound the first attempt alone
    /// would outlast the assertion.
    #[tokio::test]
    async fn a_stalling_endpoint_is_abandoned_on_the_stage_budget() {
        let stage = Duration::from_millis(200);
        // The shape that goes wrong needs a per-attempt timeout well above the stage budget;
        // anything closer and a single attempt would end the stage on its own.
        assert!(test_timeouts().per_attempt >= 10 * stage);
        let (endpoint, _peak) = mock_r2_held(200, Duration::from_secs(30)).await;

        let started = std::time::Instant::now();
        let err = R2WitnessClient::new(transport(&endpoint), stage)
            .get_witness(1, B256::ZERO, 0)
            .await
            .expect_err("a stalling endpoint must not serve");
        let elapsed = started.elapsed();
        assert!(elapsed >= stage, "gave up before spending the budget ({elapsed:?}): {err}");
        assert!(
            elapsed < Duration::from_secs(2),
            "the stage outlived its budget ({elapsed:?}), so the block waited on a multiple \
             of it before reaching RPC: {err}",
        );
    }

    /// A `missing` within the frontier band below the polled head — or with no head polled
    /// yet — is the uploader still catching up, so it must stay off the error counter; the
    /// band's deep edge and everything under it is a hole that belongs on it. Every other
    /// kind is an error wherever the block sits. The edges themselves are pinned once, in
    /// `stateless-common` beside the classifier.
    #[test]
    fn only_a_near_tip_miss_is_a_frontier_miss() {
        let missing = R2WitnessError::Get(R2GetError::Missing { number: 1, key: "k".into() });
        let head = 5000;
        assert!(is_frontier_miss(&missing, 100, 0), "no head polled yet");
        assert!(is_frontier_miss(&missing, head, head), "the head itself");
        assert!(
            is_frontier_miss(&missing, head - R2_FRONTIER_WINDOW + 1, head),
            "just inside the band",
        );
        assert!(
            !is_frontier_miss(&missing, head - R2_FRONTIER_WINDOW, head),
            "the band's deep edge is already a hole",
        );
        assert!(!is_frontier_miss(&missing, 100, head), "deep history is a hole");

        let throttled = R2WitnessError::Get(R2GetError::Throttled {
            number: 1,
            key: "k".into(),
            status: 503,
            body: String::new(),
        });
        assert!(!is_frontier_miss(&throttled, head, head), "only an absent object can split");
    }
}
