//! Direct-from-R2 historical witness source.
//!
//! Fetches the primary witness object straight from the R2 bucket over the S3 API and decodes
//! it with the **light** decoder — the trace server never verifies the witness proof, so the
//! full decode's per-point elliptic-curve work would buy nothing (see
//! `stateless_core::light_witness`). The transport core is `stateless-r2`'s
//! [`R2ObjectFetcher`], shared with the validator's pipeline reader.
//!
//! This adapter is request-serving, which shapes it differently from the validator's:
//! every fetch runs under the caller's witness-stage deadline, failures surface immediately
//! with **no pacing pause** (the caller's next move is the RPC fallback chain, not a blind
//! re-enqueue), and the retry budget is small — a throttled R2 should hand over to the RPC
//! chain quickly instead of burning the witness budget on backoff sleeps.

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use stateless_common::{BackoffPolicy, WitnessDecodingError, decode_witness_payload_light};
use stateless_core::{LightWitness, withdrawals::MptWitness};
use stateless_r2::{
    fetch::{R2GetError, R2ObjectFetcher, RetryPacing},
    keys,
};
use tokio::task::JoinError;
use tracing::trace;

use crate::metrics;

/// Total GET attempts per fetch: small because the RPC chain waits as fallback, and the
/// caller's deadline clamps the loop harder anyway.
const MAX_ATTEMPTS: usize = 3;

/// Failure outcome of an R2 historical witness fetch.
#[derive(Debug, thiserror::Error)]
pub enum R2WitnessError {
    /// The signed GET failed (absent object, transport, throttle, or unexpected status).
    #[error(transparent)]
    Get(#[from] R2GetError),
    /// The object was fetched but its bytes did not decode to a witness tuple — a corrupt
    /// witness in R2. Deterministic; not retried.
    #[error("R2 witness for block {number} (key {key}) failed to decode: {source}")]
    Decode { number: u64, key: String, source: WitnessDecodingError },
    /// The decode task panicked. This is a bug in our own decoder, not a problem with the
    /// data in R2, so it is kept out of [`Self::Decode`].
    #[error("R2 witness decode task for block {number} (key {key}) panicked: {source}")]
    DecodePanicked { number: u64, key: String, source: JoinError },
}

impl R2WitnessError {
    /// Every label [`Self::kind`] can produce, for metrics pre-registration.
    pub const KINDS: &'static [&'static str] =
        &["missing", "transport", "throttled", "status", "decode", "decode_panicked"];

    /// Stable lowercase label for this variant — the `kind` label on the R2 witness error
    /// counter. Every value returned here must appear in [`Self::KINDS`].
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Get(e) => e.kind(),
            Self::Decode { .. } => "decode",
            Self::DecodePanicked { .. } => "decode_panicked",
        }
    }
}

/// Fetches and light-decodes historical witnesses straight from an R2 bucket.
///
/// Cloning is cheap — the fetcher's `reqwest::Client` and signer are internally
/// reference-counted / small, and its `Debug` redacts the credentials.
#[derive(Clone, Debug)]
pub struct R2WitnessSource {
    fetcher: R2ObjectFetcher,
}

impl R2WitnessSource {
    /// Builds a source from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `per_attempt_timeout` bounds each individual GET (further clamped by the caller's
    /// deadline), `retry_backoff` paces the retries, and `max_concurrent_requests` caps
    /// in-flight GETs (`None` = unlimited; see the `--r2-max-concurrent-requests` flag
    /// for why it is separate from the RPC cap).
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
        Ok(Self { fetcher })
    }

    /// Fetches and light-decodes the witness for `(number, hash)` under `deadline`.
    pub async fn get_witness_light(
        &self,
        number: u64,
        hash: B256,
        deadline: Instant,
    ) -> Result<(LightWitness, MptWitness), R2WitnessError> {
        let fetched = self
            .fetcher
            .get_block_object(
                number,
                hash,
                MAX_ATTEMPTS,
                Some(deadline),
                metrics::record_r2_witness_retry,
            )
            .await?;
        let bytes = fetched.bytes;

        // zstd + bincode over a multi-MB witness is CPU-bound; keep it off the runtime.
        let key = || keys::block_object_key(number, hash);
        match tokio::task::spawn_blocking(move || decode_witness_payload_light(&bytes)).await {
            Ok(Ok(witness)) => {
                trace!(number, "R2 witness fetched and light-decoded");
                Ok(witness)
            }
            Ok(Err(source)) => Err(R2WitnessError::Decode { number, key: key(), source }),
            Err(source) => Err(R2WitnessError::DecodePanicked { number, key: key(), source }),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Test source pointed at a mock endpoint, with millisecond retry pacing.
    pub(crate) fn source(endpoint: &str) -> R2WitnessSource {
        R2WitnessSource::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(5),
            BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20)),
            None,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use stateless_test_utils::{fixtures::TestFixtures, mock_r2::mock_r2};

    use super::{test_support::source, *};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
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

    /// Every fetch-level kind must appear in this adapter's pre-registered [`KINDS`] — a new
    /// `R2GetError` kind escaping metric pre-registration would drift silently otherwise.
    #[test]
    fn kinds_cover_all_fetch_kinds() {
        assert!(R2GetError::KINDS.iter().all(|k| R2WitnessError::KINDS.contains(k)));
    }

    #[tokio::test]
    async fn undecodable_body_surfaces_decode_error() {
        let (endpoint, _) = mock_r2(vec![(200, "not a zstd witness")]).await;
        let err = source(&endpoint).get_witness_light(1, B256::ZERO, deadline()).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Decode { .. }), "{err}");
        assert_eq!(err.kind(), "decode");
    }
}
