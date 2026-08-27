//! Direct-from-R2 witness source.
//!
//! Fetches the primary witness object straight from the R2 bucket — via SigV4-signed S3
//! GETs or unsigned GETs through a Cloudflare custom domain, per construction — and decodes
//! it with the **light** decoder — the trace server never verifies the witness proof, so the
//! full decode's per-point elliptic-curve work would buy nothing (see
//! `stateless_core::light_witness`). The failure taxonomy and the transport wrapper are
//! [`stateless_common::r2_witness`], shared with the validator's adapter; the transport
//! core below that is `stateless-r2`'s [`R2ObjectFetcher`].
//!
//! This adapter is request-serving, which shapes it differently from the validator's:
//! every fetch runs under the caller's witness-stage deadline, failures surface immediately
//! with **no pacing pause** (the caller's next move is the RPC fallback chain, not a blind
//! re-enqueue), and the retry budget is small — a throttled R2 should hand over to the RPC
//! chain quickly instead of burning the witness budget on backoff sleeps.
//!
//! [`R2ObjectFetcher`]: stateless_r2::fetch::R2ObjectFetcher

use std::time::Instant;

use alloy_primitives::B256;
pub use stateless_common::R2WitnessError;
use stateless_common::{BackoffPolicy, R2WitnessTransport, decode_witness_payload_light};
use stateless_core::{LightWitness, withdrawals::MptWitness};
use stateless_r2::{
    fetch::{CfAccessCredentials, FetchTimeouts},
    keys,
};
use tracing::trace;

use crate::metrics;

/// Total GET attempts per fetch: small because the RPC chain waits as fallback, and the
/// caller's deadline clamps the loop harder anyway.
const MAX_ATTEMPTS: usize = 3;

/// Synthetic `kind` label for a `missing` above the frontier band — a catch-up-gap probe
/// whose bucket state is unknowable from the stale local tip. Kept off
/// [`R2WitnessError::KINDS`] (no error variant produces it); the band classifier in
/// `data_provider` records it so catch-up bursts stay visible without flooding the
/// below-band `kind="missing"` bucket-integrity alarm.
pub(crate) const KIND_MISSING_ABOVE_TIP: &str = "missing_above_tip";

/// Fetches and light-decodes witnesses straight from an R2 bucket.
/// The transport's `Debug` redacts the credentials.
#[derive(Debug)]
pub struct R2WitnessSource {
    transport: R2WitnessTransport,
}

impl R2WitnessSource {
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

    /// Builds a source from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `timeouts` bounds each individual GET end-to-end and in its connect phase (further
    /// clamped by the caller's deadline), `retry_backoff` paces the retries, and
    /// `max_concurrent_requests` caps in-flight GETs (`None` = unlimited; see the
    /// `--r2-max-concurrent-requests` flag for why it is separate from the RPC cap).
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

    /// Builds a source that fetches unsigned through a Cloudflare custom domain fronting
    /// the bucket (h2-multiplexed, edge-cacheable), with optional Cloudflare Access
    /// service-token headers. The remaining parameters mean what they mean on [`Self::new`].
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

    /// Fetches and light-decodes the witness for `(number, hash)` under `deadline`.
    pub async fn get_witness_light(
        &self,
        number: u64,
        hash: B256,
        deadline: Instant,
    ) -> Result<(LightWitness, MptWitness), R2WitnessError> {
        let fetched = self
            .transport
            .fetcher()
            .get_block_object(
                number,
                hash,
                MAX_ATTEMPTS,
                Some(deadline),
                metrics::record_r2_witness_retry,
            )
            .await?;
        // The caller's end-to-end duration metric deliberately keeps this queue wait in —
        // on the request path the user really did wait through it — so the queued share is
        // reported on its own series instead of being subtracted the way the validator's
        // throughput pipeline does.
        metrics::record_r2_witness_queue_wait(fetched.queue_wait.as_secs_f64());
        decode_light_with_deadline(fetched.bytes, number, hash, deadline).await
    }
}

/// Light-decodes `bytes` on the blocking pool, bounded by the same `deadline` as the GET —
/// an oversized or pathological object must not eat the RPC fallback's share of the stage.
/// On timeout the blocking task is abandoned (it cannot be cancelled) and finishes in the
/// background.
async fn decode_light_with_deadline(
    bytes: bytes::Bytes,
    number: u64,
    hash: B256,
    deadline: Instant,
) -> Result<(LightWitness, MptWitness), R2WitnessError> {
    let key = || keys::block_object_key(number, hash);
    // A GET that lands right at the deadline gets no decode at all — nothing would wait
    // for it.
    if Instant::now() >= deadline {
        return Err(R2WitnessError::DecodeTimeout { number, key: key() });
    }
    // zstd + bincode over a multi-MB witness is CPU-bound; keep it off the runtime.
    let decode = tokio::task::spawn_blocking(move || decode_witness_payload_light(&bytes));
    match tokio::time::timeout_at(deadline.into(), decode).await {
        Ok(Ok(Ok(witness))) => {
            trace!(number, "R2 witness fetched and light-decoded");
            Ok(witness)
        }
        Ok(Ok(Err(source))) => Err(R2WitnessError::Decode { number, key: key(), source }),
        Ok(Err(source)) => Err(R2WitnessError::DecodePanicked { number, key: key(), source }),
        Err(_) => Err(R2WitnessError::DecodeTimeout { number, key: key() }),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::time::Duration;

    use super::*;

    /// Test source pointed at a mock endpoint, with millisecond retry pacing.
    pub(crate) fn source(endpoint: &str) -> R2WitnessSource {
        R2WitnessSource::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            FetchTimeouts {
                per_attempt: Duration::from_secs(5),
                connect: stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT,
            },
            BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20)),
            None,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::Ordering, time::Duration};

    use stateless_r2::fetch::R2GetError;
    use stateless_test_utils::{fixtures::TestFixtures, mock_r2::mock_r2};

    use super::{test_support::source, *};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// The custom-domain source serves the same decode path end-to-end, requesting the bare
    /// `/{key}` layout (no bucket segment, no SigV4 authorization).
    #[tokio::test]
    async fn custom_domain_source_decodes_and_requests_bare_key() {
        let (salt_witness, mpt_witness): (_, MptWitness) =
            TestFixtures::mainnet_shared().first_paired_witness();
        let (_, payload) = stateless_common::encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("fixture witness must encode");

        let (domain, _, heads) =
            stateless_test_utils::mock_r2::mock_r2_capturing(vec![(200, payload)]).await;
        let source = R2WitnessSource::new_custom_domain(
            &domain,
            None,
            FetchTimeouts {
                per_attempt: Duration::from_secs(5),
                connect: stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT,
            },
            BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20)),
            None,
            1,
        )
        .unwrap();
        source
            .get_witness_light(1, B256::ZERO, deadline())
            .await
            .expect("valid object must fetch and decode");
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(head.starts_with("get /block/0_999/1."), "bucketless key layout: {head}");
        assert!(!head.contains("authorization:"), "custom-domain GET must be unsigned: {head}");
    }

    /// A fixture witness encoded with the uploader's `encode_witness_payload` must
    /// light-decode to the same kvs the RPC light path yields.
    #[tokio::test]
    async fn valid_object_light_decodes_end_to_end() {
        let (salt_witness, mpt_witness): (_, MptWitness) =
            TestFixtures::mainnet_shared().first_paired_witness();
        let (_, payload) = stateless_common::encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("fixture witness must encode");
        let (expected_light, _) =
            decode_witness_payload_light(&payload).expect("payload must light-decode");

        let (endpoint, hits) = mock_r2(vec![(200, payload)]).await;
        let (light, decoded_mpt) = source(&endpoint)
            .get_witness_light(1, B256::ZERO, deadline())
            .await
            .expect("valid object must fetch and decode");
        assert_eq!(light.kvs, expected_light.kvs);
        assert_eq!(decoded_mpt, mpt_witness);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a successful fetch must take exactly one GET");
    }

    /// Failures surface immediately: no deterministic-failure pause, no exhausted-retry
    /// pause — the caller's RPC fallback needs the remaining budget.
    #[tokio::test]
    async fn failures_surface_without_pacing_pauses() {
        let (endpoint, hits) = mock_r2(vec![(404, "<Code>NoSuchKey</Code>")]).await;
        let started = Instant::now();
        let err = source(&endpoint).get_witness_light(1, B256::ZERO, deadline()).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Get(R2GetError::Missing { .. })), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "404 must not be retried");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a deterministic failure paused before surfacing ({:?})",
            started.elapsed(),
        );
    }

    /// Retryable failures stop at [`MAX_ATTEMPTS`] — the request path hands over to the RPC
    /// fallback instead of burning the witness budget like the pipeline reader's 9 attempts.
    #[tokio::test]
    async fn retryable_failures_stop_at_the_request_attempt_budget() {
        let (endpoint, hits) = mock_r2(vec![(503, "overloaded")]).await;
        let err = source(&endpoint).get_witness_light(1, B256::ZERO, deadline()).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Get(R2GetError::Throttled { .. })), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn undecodable_body_surfaces_decode_error() {
        let (endpoint, _) = mock_r2(vec![(200, "not a zstd witness")]).await;
        let err = source(&endpoint).get_witness_light(1, B256::ZERO, deadline()).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Decode { .. }), "{err}");
        assert_eq!(err.kind(), "decode");
    }

    /// A decode that outruns the deadline is abandoned so the caller falls back on its
    /// reserved budget share, instead of the object holding the witness stage hostage.
    /// Driven through the extracted decode step with the deadline already gone — the
    /// GET-succeeds-then-decode-overruns timing cannot be scripted deterministically.
    #[tokio::test]
    async fn decode_past_the_deadline_surfaces_decode_timeout() {
        let (salt_witness, mpt_witness): (_, MptWitness) =
            TestFixtures::mainnet_shared().first_paired_witness();
        let (_, payload) = stateless_common::encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("fixture witness must encode");

        let err = decode_light_with_deadline(payload.into(), 1, B256::ZERO, Instant::now())
            .await
            .expect_err("an already-elapsed deadline must abandon the decode");
        assert!(matches!(err, R2WitnessError::DecodeTimeout { .. }), "{err}");
        assert_eq!(err.kind(), "decode_timeout");
    }
}
