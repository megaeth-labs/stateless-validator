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
//! Every failure surfaces at once, with no pause: the block's next stop is the
//! `--witness-endpoint` RPC chain. That chain is a second *path* to the same bytes, not a
//! second copy — the witness gateway reads this same bucket — so it covers our path failing
//! (edge, Access token, HTTP/2, credentials, this fetcher), not the bucket.
//!
//! Operator note: a miss is banded against the last polled head — in-band it is uploader lag
//! on `r2_witness_frontier_misses_total`, below the band a bucket hole on
//! `r2_witness_errors_total{kind="missing"}`. A tip-following run fetches at
//! `head - tip_buffer`, well inside the [`R2_FRONTIER_WINDOW`][w], so it produces frontier
//! misses only; `kind="missing"` earns its name during catch-up and `--end-block` backfills.
//! A hole first appearing near the tip is not re-probed — the fallback already served the
//! block, so watching the uploader belongs with whatever watches the uploader. On the
//! custom-domain target this assumes the edge does not cache 404s.
//!
//! [`R2ObjectFetcher`]: stateless_r2::fetch::R2ObjectFetcher
//! [w]: stateless_common::R2_FRONTIER_WINDOW

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use salt::SaltWitness;
pub use stateless_common::R2WitnessError;
use stateless_common::{
    R2WitnessTransport, WitnessSizeBreakdown, decode_on_blocking_pool, decode_witness_payload,
    r2_band,
};
use stateless_core::withdrawals::MptWitness;
use tracing::{debug, trace, warn};

use crate::metrics;

/// Total GET attempts (first try + retries) per fetch, for retryable (transport/429/5xx)
/// failures. Small on purpose: the RPC witness chain waits behind this one. Retries are paced
/// by the `--rpc-*-backoff-ms` ramp, and everything, sleeps included, stays inside the stage
/// budget given to [`R2WitnessClient::new`]. Not an operator flag — the RPC witness path
/// retries unboundedly, so there is nothing to mirror.
const MAX_ATTEMPTS: usize = 3;

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
    /// chain head the caller last polled (`0` before the first poll), which bands a miss into
    /// routine uploader lag or a bucket hole.
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
            if e.is_frontier_miss(r2_band(remote_head, number)) {
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

        // Outside the deadline on purpose: our own CPU on bytes already in hand, and
        // abandoning it would only re-fetch and re-decode the same witness over RPC.
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

    use stateless_common::BackoffPolicy;
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

        // A decode failure is the deterministic case that is ours rather than the transport's
        // (`stateless-r2` pins 4xx classification); it must not pause on the way out either.
        let (endpoint, _) = mock_r2(vec![(200, "garbage")]).await;
        let started = std::time::Instant::now();
        fetch(&endpoint).await.unwrap_err();
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "a decode failure paused before surfacing ({:?})",
            started.elapsed(),
        );
    }

    /// An endpoint that accepts the connection and then stalls must leave for RPC on the stage
    /// budget, not on [`MAX_ATTEMPTS`] full per-attempt timeouts. The assert below pins the
    /// shape that goes wrong: without the aggregate bound one attempt alone would outlast it.
    #[tokio::test]
    async fn a_stalling_endpoint_is_abandoned_on_the_stage_budget() {
        let stage = Duration::from_millis(200);
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
}
