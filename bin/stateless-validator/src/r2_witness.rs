//! Direct-from-R2 witness source.
//!
//! Fetches the primary witness object straight from the R2 bucket over the S3 API (a SigV4-signed
//! `GET`), decompresses it, and returns the same `(SaltWitness, MptWitness)` tuple the RPC path
//! yields.
//!
//! The object-key layout, SigV4 signer, and endpoint parsing come from `stateless-r2` — the same
//! crate the witness uploaders write with — so the read path here cannot drift from the write
//! path. The primary object body is `zstd(bincode-legacy((SaltWitness, MptWitness)))` (the
//! uploader's `encode_witness_payload`), which [`stateless_common::decode_witness_payload`]
//! inverts exactly.

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use bytes::Bytes;
use chrono::Utc;
use reqwest::Client;
use salt::SaltWitness;
use stateless_common::{WitnessDecodingError, WitnessSizeBreakdown, decode_witness_payload};
use stateless_core::withdrawals::MptWitness;
use stateless_r2::{
    client::is_throttle_status,
    endpoint::parse_endpoint,
    keys,
    sigv4::{SigV4Signer, encode_uri_path},
};
use tokio::task::JoinError;
use tracing::{trace, warn};

use crate::metrics;

/// Max retry rounds for retryable (transport/429/5xx) failures before surfacing an error.
const MAX_RETRIES: usize = 8;
/// First retry sleep; doubles each round up to [`MAX_BACKOFF`]. Test builds shrink all three
/// durations so the retry-path tests run in milliseconds; the loop logic is identical.
const INITIAL_BACKOFF: Duration =
    if cfg!(test) { Duration::from_millis(5) } else { Duration::from_millis(500) };
/// Upper bound on any single retry sleep.
const MAX_BACKOFF: Duration =
    if cfg!(test) { Duration::from_millis(20) } else { Duration::from_secs(30) };
/// Throttle applied before surfacing any deterministic failure (`Missing`, `Status`, `Decode`,
/// `DecodePanicked`): the pipeline fetcher re-enqueues a failed fetch immediately with no delay
/// (`stateless-core/src/pipeline/fetcher.rs`), so returning instantly would hot-loop signed GETs
/// (and full block re-downloads) against R2 on a wrong credential, a corrupt object, or a genuine
/// gap. If the fetcher ever grows per-block re-enqueue backoff, this throttle is the piece to
/// delete.
const DETERMINISTIC_FAILURE_THROTTLE: Duration =
    if cfg!(test) { Duration::from_millis(5) } else { Duration::from_secs(2) };
/// Cap on the response body carried inside `Throttled`/`Status` errors.
const MAX_ERROR_BODY_BYTES: usize = 1024;

/// Failure outcome of an R2 witness fetch.
#[derive(Debug, thiserror::Error)]
pub enum R2WitnessError {
    /// The primary object is absent from the bucket (HTTP 404). For a block known to have a
    /// witness this is a completeness gap in R2, but near the tip (or right after a reorg) it can
    /// also fire transiently before the uploader has PUT the object — the retry that follows the
    /// pipeline's re-enqueue resolves those.
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
    /// A non-success status unlikely to clear on retry: 4xx other than 429 (e.g. 403
    /// SignatureDoesNotMatch from bad credentials, 404 NoSuchBucket from a wrong bucket name) or a
    /// 3xx (redirects are never followed — a signed GET cannot survive one).
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
/// Cloning is cheap — the `reqwest::Client` and signer are internally reference-counted / small.
/// `Debug` is safe to derive: [`SigV4Signer`]'s own `Debug` redacts the credentials.
#[derive(Clone, Debug)]
pub struct R2WitnessClient {
    http: Client,
    signer: SigV4Signer,
    /// Endpoint origin (`scheme://host`, no trailing slash).
    endpoint: String,
    /// SigV4 canonical host (`host[:port]`).
    host: String,
    bucket: String,
}

impl R2WitnessClient {
    /// Builds a client from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `per_attempt_timeout` bounds each individual GET. Fails if the endpoint is not a bare
    /// `scheme://host[:port]` origin (see [`parse_endpoint`]) or the HTTP client cannot be built.
    pub fn new(
        endpoint: &str,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        per_attempt_timeout: Duration,
    ) -> eyre::Result<Self> {
        let (origin, host) = parse_endpoint(endpoint);
        if host.is_empty() {
            return Err(eyre::eyre!(
                "Invalid R2 endpoint {endpoint:?}: expected a bare scheme://host origin \
                 (no path/query), e.g. https://<account>.r2.cloudflarestorage.com"
            ));
        }
        let http = Client::builder()
            .timeout(per_attempt_timeout)
            // A SigV4-signed GET can never survive a redirect (reqwest strips `authorization` on
            // cross-host hops, and a same-host hop invalidates the signed URI), so following one
            // just turns the real cause into a baffling 403. Surface the 3xx as a `Status` error.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| eyre::eyre!("Failed to build R2 HTTP client: {e}"))?;
        Ok(Self {
            http,
            signer: SigV4Signer::new(access_key_id, secret_access_key),
            endpoint: origin,
            host,
            bucket,
        })
    }

    /// Fetches and decodes the witness for `(number, hash)` from R2.
    ///
    /// Transport/429/5xx failures are retried with backoff up to `MAX_RETRIES` times. Every
    /// other failure is deterministic and surfaces after a short
    /// `DETERMINISTIC_FAILURE_THROTTLE` sleep (see its docs for why).
    pub async fn get_witness(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let result = self.get_witness_inner(number, hash).await;
        if let Err(e) = &result {
            metrics::on_r2_witness_error(e.kind());
            if !e.is_retryable() {
                tokio::time::sleep(DETERMINISTIC_FAILURE_THROTTLE).await;
            }
        }
        result
    }

    /// [`Self::get_witness`] without the deterministic-failure throttle.
    async fn get_witness_inner(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let started = Instant::now();
        let key = keys::block_object_key(number, hash);
        let mut backoff = INITIAL_BACKOFF;
        let mut attempt = 0usize;

        let bytes = loop {
            attempt += 1;
            match self.get_object(number, &key).await {
                Ok(bytes) => break bytes,
                Err(e) => {
                    if !e.is_retryable() || attempt > MAX_RETRIES {
                        return Err(e);
                    }
                    metrics::on_r2_witness_retry();
                    warn!(number, %key, attempt, error = %e, "R2 witness GET failed, backing off");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        };

        // zstd + bincode over a multi-MB witness is CPU-bound; keep it off the runtime.
        match tokio::task::spawn_blocking(move || decode_witness_payload(&bytes)).await {
            Ok(Ok(witness)) => {
                trace!(number, "R2 witness fetched and decoded");
                metrics::on_r2_witness_fetch_success(
                    started.elapsed().as_secs_f64(),
                    WitnessSizeBreakdown::new(&witness.0, &witness.1),
                );
                Ok(witness)
            }
            Ok(Err(source)) => Err(R2WitnessError::Decode { number, key, source }),
            Err(source) => Err(R2WitnessError::DecodePanicked { number, key, source }),
        }
    }

    /// Performs one SigV4-signed GET and classifies the response. No retry. The body comes back
    /// as [`Bytes`] (refcounted), so the multi-MB witness is never copied between the HTTP
    /// response and the decoder.
    async fn get_object(&self, number: u64, key: &str) -> Result<Bytes, R2WitnessError> {
        let canonical_uri = encode_uri_path(&self.bucket, key);
        let url = format!("{}{}", self.endpoint, canonical_uri);
        // Signed-payload mode with an empty body: x-amz-content-sha256 = sha256("").
        let signed = self.signer.sign("GET", &self.host, &canonical_uri, "", &[], b"", Utc::now());

        let mut request = self.http.get(&url);
        for (name, value) in signed {
            request = request.header(name, value);
        }
        let transport = |source| R2WitnessError::Transport { number, key: key.to_string(), source };
        let response = request.send().await.map_err(transport)?;

        let status = response.status();
        if status.is_success() {
            return response.bytes().await.map_err(transport);
        }
        let code = status.as_u16();
        let mut body = response.text().await.unwrap_or_default();
        // Cap the body carried in the error (and re-printed by the retry `warn!`): real R2 error
        // bodies are a few hundred bytes of XML, but a misconfigured endpoint fronted by a
        // verbose proxy can return arbitrarily large HTML.
        if body.len() > MAX_ERROR_BODY_BYTES {
            let mut end = MAX_ERROR_BODY_BYTES;
            while !body.is_char_boundary(end) {
                end -= 1;
            }
            body.truncate(end);
        }
        // A 404 usually means the object is absent (`NoSuchKey`) — but S3 also 404s a missing
        // *bucket*, which is operator misconfiguration, not a data gap; keep those apart.
        if code == 404 && !body.contains("NoSuchBucket") {
            return Err(R2WitnessError::Missing { number, key: key.to_string() });
        }
        let key = key.to_string();
        if is_throttle_status(code) {
            Err(R2WitnessError::Throttled { number, key, status: code, body })
        } else {
            Err(R2WitnessError::Status { number, key, status: code, body })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[test]
    fn rejects_endpoint_with_path() {
        // A bucket-in-path URL is the classic misconfiguration; construction must fail fast.
        let err = R2WitnessClient::new(
            "https://acc.r2.cloudflarestorage.com/witness-mainnet",
            "witness-mainnet".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(20),
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid R2 endpoint"));
    }

    /// Serves one scripted HTTP/1.1 response per connection on a local port and counts requests.
    /// The last response repeats if more connections arrive than were scripted. Bodies are
    /// anything `Into<Vec<u8>>` so failure tests pass `&str` and the happy-path test raw bytes.
    async fn mock_r2(responses: Vec<(u16, impl Into<Vec<u8>>)>) -> (String, Arc<AtomicUsize>) {
        let responses: Vec<(u16, Vec<u8>)> =
            responses.into_iter().map(|(status, body)| (status, body.into())).collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let (status, body) = &responses[n.min(responses.len() - 1)];
                // Drain the request head before replying.
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                // The reason phrase is never interpreted, and `location` is load-bearing only for
                // the 3xx (redirects-not-followed) test — harmless noise on other statuses.
                let head = format!(
                    "HTTP/1.1 {status} X\r\nconnection: close\r\n\
                     location: http://example.invalid/elsewhere\r\n\
                     content-length: {}\r\n\r\n",
                    body.len(),
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
            }
        });
        (endpoint, hits)
    }

    fn client(endpoint: &str) -> R2WitnessClient {
        R2WitnessClient::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    async fn fetch(endpoint: &str) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        client(endpoint).get_witness(1, B256::ZERO).await
    }

    #[tokio::test]
    async fn status_4xx_surfaces_without_retry() {
        let (endpoint, hits) = mock_r2(vec![(403, "SignatureDoesNotMatch")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Status { status: 403, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "4xx must not be retried");
    }

    #[tokio::test]
    async fn missing_404_surfaces_without_retry() {
        let (endpoint, hits) = mock_r2(vec![(404, "<Code>NoSuchKey</Code>")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Missing { number: 1, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "404 must not be retried");
    }

    #[tokio::test]
    async fn missing_bucket_404_is_a_config_error_not_a_gap() {
        let (endpoint, _) = mock_r2(vec![(404, "<Code>NoSuchBucket</Code>")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Status { status: 404, .. }), "{err}");
    }

    #[tokio::test]
    async fn throttled_5xx_retries_until_a_deterministic_answer() {
        let (endpoint, hits) = mock_r2(vec![(503, "SlowDown"), (503, "SlowDown"), (403, "")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Status { status: 403, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 3, "5xx must be retried, 4xx must stop the loop");
    }

    #[tokio::test]
    async fn persistent_5xx_exhausts_retries_and_surfaces_throttled() {
        let (endpoint, hits) = mock_r2(vec![(503, "overloaded")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Throttled { status: 503, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), MAX_RETRIES + 1, "initial attempt + MAX_RETRIES");
    }

    /// End-to-end happy path: a real fixture witness encoded exactly as the uploader writes it
    /// (`encode_witness_payload`) and served with a 200 must decode back to the original tuple in
    /// a single GET. This is the only test that exercises the success path of
    /// `get_object` → `spawn_blocking` decode; the failure tests can't prove it.
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

    #[tokio::test]
    async fn redirects_are_not_followed() {
        // A signed GET cannot survive a redirect; the 3xx must surface instead of a spurious 403
        // from the redirect target (which would also leak the request outside the endpoint).
        let (endpoint, hits) = mock_r2(vec![(301, "moved")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Status { status: 301, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// Every deterministic failure must be throttled before surfacing — the pipeline re-enqueues
    /// failed fetches immediately, so an unthrottled return hot-loops GETs against R2.
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
}
