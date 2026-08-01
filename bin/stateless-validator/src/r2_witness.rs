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

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use bytes::Bytes;
use chrono::Utc;
use reqwest::Client;
use salt::SaltWitness;
use stateless_common::{
    BackoffPolicy, WitnessDecodingError, WitnessSizeBreakdown, decode_witness_payload,
};
use stateless_core::withdrawals::MptWitness;
use stateless_r2::{
    client::is_throttle_status,
    endpoint::parse_endpoint,
    keys,
    sigv4::{SigV4Signer, encode_uri_path},
};
use tokio::{sync::Semaphore, task::JoinError};
use tracing::{trace, warn};

use crate::metrics;

/// Total GET attempts (first try + retries) per fetch for retryable (transport/429/5xx)
/// failures before the error surfaces. Stays a local constant while the backoff pacing is
/// injected (see [`R2WitnessClient::new`]): the RPC path retries unboundedly, so there is no
/// operator flag to mirror.
const MAX_ATTEMPTS: usize = 9;
/// Throttle applied before surfacing any deterministic (non-retryable) failure: the pipeline
/// fetcher (`stateless-core/src/pipeline/fetcher.rs`) re-enqueues failed fetches with no delay,
/// so returning instantly would hot-loop signed GETs against R2. Delete this once the fetcher
/// grows per-block re-enqueue backoff. Test builds shrink it so the failure-path tests run in
/// milliseconds.
const DETERMINISTIC_FAILURE_THROTTLE: Duration =
    if cfg!(test) { Duration::from_millis(5) } else { Duration::from_secs(2) };
/// Cap on the response body carried inside `Throttled`/`Status` errors.
const MAX_ERROR_BODY_BYTES: usize = 1024;

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
    /// [`R2WitnessClient::new`]).
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
    /// Paces retries of retryable GET failures: doubling with jitter, mirroring the RPC retry
    /// loop. Injected so the `--rpc-initial-backoff-ms` / `--rpc-max-backoff-ms` flags govern
    /// R2 pacing too.
    retry_backoff: BackoffPolicy,
    /// Caps concurrent GETs, honoring `--witness-max-concurrent-requests` (the RPC witness path
    /// enforces it inside `RpcClient`, which R2 mode bypasses).
    concurrency: Arc<Semaphore>,
}

impl R2WitnessClient {
    /// Builds a client from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `per_attempt_timeout` bounds each individual GET. `retry_backoff` paces the retries of
    /// retryable failures — first sleep `initial`, doubling up to `max`, each with up to 50%
    /// jitter — and is the same policy the RPC path builds from `--rpc-initial-backoff-ms` /
    /// `--rpc-max-backoff-ms`, so one pair of flags tunes both paths. `max_concurrent_requests`
    /// caps the number of GETs in flight at once (`None` = unlimited, `Some(0)` clamps to 1 —
    /// same semantics as the RPC witness semaphore). Fails if the endpoint is not a bare
    /// `scheme://host[:port]` origin (see [`parse_endpoint`]) or the HTTP client cannot be built.
    pub fn new(
        endpoint: &str,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        per_attempt_timeout: Duration,
        retry_backoff: BackoffPolicy,
        max_concurrent_requests: Option<usize>,
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
            retry_backoff,
            concurrency: Arc::new(Semaphore::new(
                max_concurrent_requests.unwrap_or(Semaphore::MAX_PERMITS).max(1),
            )),
        })
    }

    /// Fetches and decodes the witness for `(number, hash)` from R2.
    ///
    /// Transport/429/5xx failures are retried up to [`MAX_ATTEMPTS`] total attempts, paced by
    /// the `retry_backoff` policy given at construction. Every surfaced failure pauses before
    /// returning (the pipeline fetcher re-enqueues failed fetches with zero delay, so returning
    /// instantly would hot-loop GETs against R2): deterministic failures wait the fixed
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
                self.retry_backoff.max
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
        // Subtracted from the fetch-duration metric below: queue wait on the concurrency cap is
        // self-imposed, and folded in it would masquerade as R2 slowness.
        let mut queue_wait = Duration::ZERO;
        let key = keys::block_object_key(number, hash);
        let mut backoff = self.retry_backoff.schedule();
        let mut attempt = 0usize;

        let bytes = loop {
            attempt += 1;
            // Permit scoped to the GET itself — holding it across the backoff sleep or the
            // decode below would waste capacity other fetches could use.
            let outcome = {
                let queued = Instant::now();
                let _permit = self.concurrency.acquire().await.expect("semaphore is never closed");
                queue_wait += queued.elapsed();
                self.get_object(number, &key).await
            };
            match outcome {
                Ok(bytes) => break bytes,
                Err(e) => {
                    if !e.is_retryable() || attempt >= MAX_ATTEMPTS {
                        return Err(e);
                    }
                    metrics::on_r2_witness_retry();
                    // The shared jittered-doubling schedule (`BackoffPolicy::schedule`): jitter
                    // keeps parallel validators (several typically slice a block range) from
                    // retrying in lockstep through a shared R2 brownout.
                    let sleep_ms = backoff.next_sleep_ms();
                    warn!(
                        number, %key, attempt, sleep_ms, error = %e,
                        "R2 witness GET failed, backing off",
                    );
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                }
            }
        };

        // zstd + bincode over a multi-MB witness is CPU-bound; keep it off the runtime.
        match tokio::task::spawn_blocking(move || decode_witness_payload(&bytes)).await {
            Ok(Ok(witness)) => {
                trace!(number, "R2 witness fetched and decoded");
                metrics::on_r2_witness_fetch_success(
                    started.elapsed().saturating_sub(queue_wait).as_secs_f64(),
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
        // *bucket*, which is operator misconfiguration, not a data gap; keep those apart by
        // parsing the S3 XML error code. A 404 with no parseable code (a proxy's bare 404, a
        // truncated body) still counts as Missing: for a correctly configured endpoint that is
        // by far the likeliest cause, and misreading a config error as Missing only changes
        // the metric kind, not the retry behavior.
        if code == 404 && s3_error_code(&body).is_none_or(|c| c == "NoSuchKey") {
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

/// Extracts the value of the first `<Code>…</Code>` element from an S3 XML error body, e.g.
/// `NoSuchKey` / `NoSuchBucket`. `None` when the body carries no such element (non-XML proxy
/// response, truncation that ate the element).
fn s3_error_code(body: &str) -> Option<&str> {
    let start = body.find("<Code>")? + "<Code>".len();
    let len = body[start..].find("</Code>")?;
    Some(&body[start..start + len])
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
            test_backoff(),
            None,
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
                // The reason phrase is never interpreted; `location` matters only to the
                // redirects-not-followed test.
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

    /// Millisecond-scale retry pacing so the retry-path tests run fast (production runs pass
    /// the seconds-scale policy built from the `--rpc-*-backoff-ms` flags).
    fn test_backoff() -> BackoffPolicy {
        BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20))
    }

    fn client(endpoint: &str) -> R2WitnessClient {
        client_with_limit(endpoint, None)
    }

    fn client_with_limit(endpoint: &str, limit: Option<usize>) -> R2WitnessClient {
        client_with_backoff(endpoint, limit, test_backoff())
    }

    fn client_with_backoff(
        endpoint: &str,
        limit: Option<usize>,
        retry_backoff: BackoffPolicy,
    ) -> R2WitnessClient {
        R2WitnessClient::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(5),
            retry_backoff,
            limit,
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

    /// Any parseable S3 code other than `NoSuchKey` on a 404 is not a data gap; a 404 with no
    /// parseable code (bare proxy 404, truncated body) still counts as Missing.
    #[tokio::test]
    async fn only_no_such_key_and_bare_404s_are_missing() {
        let (endpoint, _) = mock_r2(vec![(404, "<Code>AccessDenied</Code>")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Status { status: 404, .. }), "{err}");

        let (endpoint, _) = mock_r2(vec![(404, "<html>not found</html>")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Missing { .. }), "{err}");
    }

    #[test]
    fn s3_error_code_parses_real_and_degenerate_bodies() {
        let real = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>"#;
        assert_eq!(s3_error_code(real), Some("NoSuchKey"));
        assert_eq!(s3_error_code("<Code>NoSuchBucket</Code>"), Some("NoSuchBucket"));
        assert_eq!(s3_error_code(""), None);
        assert_eq!(s3_error_code("<html>gateway error</html>"), None);
        // Truncation that ate the closing tag must not panic or misparse.
        assert_eq!(s3_error_code("<Error><Code>NoSuchBu"), None);
    }

    #[tokio::test]
    async fn throttled_5xx_retries_until_a_deterministic_answer() {
        let (endpoint, hits) = mock_r2(vec![(503, "SlowDown"), (503, "SlowDown"), (403, "")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Status { status: 403, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 3, "5xx must be retried, 4xx must stop the loop");
    }

    /// The injected policy actually paces retries: with `initial = 50ms`, the sleep between
    /// the throttled first attempt and the second must be at least 50ms (jitter only adds).
    #[tokio::test]
    async fn retries_are_paced_by_the_injected_backoff_policy() {
        let (endpoint, hits) = mock_r2(vec![(503, "SlowDown"), (404, "")]).await;
        let client = client_with_backoff(
            &endpoint,
            None,
            BackoffPolicy::new(Duration::from_millis(50), Duration::from_millis(200)),
        );
        let started = std::time::Instant::now();
        let err = client.get_witness(1, B256::ZERO).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Missing { .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "retry surfaced before the policy's initial backoff elapsed",
        );
    }

    #[tokio::test]
    async fn persistent_5xx_exhausts_retries_and_surfaces_throttled() {
        let (endpoint, hits) = mock_r2(vec![(503, "overloaded")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Throttled { status: 503, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS, "exactly MAX_ATTEMPTS GETs");
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
        let client = client_with_backoff(&endpoint, None, BackoffPolicy::new(initial, max));
        let started = std::time::Instant::now();
        let err = client.get_witness(1, B256::ZERO).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Throttled { status: 503, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS);
        assert!(
            started.elapsed() >= Duration::from_millis(255) + max,
            "exhausted retries surfaced without the max-backoff pause ({:?})",
            started.elapsed(),
        );
    }

    /// The only test of the success path (`get_object` → `spawn_blocking` decode): a fixture
    /// witness encoded with the uploader's `encode_witness_payload` must round-trip to the
    /// original tuple.
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
        let (endpoint, hits) = mock_r2(vec![(301, "moved")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2WitnessError::Status { status: 301, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// In R2 mode this client is the only enforcement of `--witness-max-concurrent-requests`:
    /// six concurrent fetches against a limit of 2 must never exceed two in-flight GETs.
    #[tokio::test]
    async fn concurrency_limit_bounds_in_flight_gets() {
        const LIMIT: usize = 2;
        const FETCHES: u64 = 6;

        // Per-connection tasks (unlike `mock_r2`, which serves serially) track the in-flight
        // high-water mark; each response is held 50ms so fetches pile up behind the semaphore,
        // then answered 404 (deterministic → exactly one GET per fetch).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        {
            let (in_flight, peak) = (in_flight.clone(), peak.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else { return };
                    let (in_flight, peak) = (in_flight.clone(), peak.clone());
                    tokio::spawn(async move {
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        let mut buf = [0u8; 4096];
                        let _ = sock.read(&mut buf).await;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let response =
                            "HTTP/1.1 404 X\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
                        let _ = sock.write_all(response.as_bytes()).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
        }

        let client = client_with_limit(&endpoint, Some(LIMIT));
        let mut fetches = tokio::task::JoinSet::new();
        for number in 0..FETCHES {
            let client = client.clone();
            fetches.spawn(async move { client.get_witness(number, B256::ZERO).await });
        }
        while let Some(result) = fetches.join_next().await {
            let err = result.unwrap().unwrap_err();
            assert!(matches!(err, R2WitnessError::Missing { .. }), "{err}");
        }

        let peak = peak.load(Ordering::SeqCst);
        assert!(peak <= LIMIT, "peak in-flight GETs {peak} exceeded the limit {LIMIT}");
        // Liveness guard: with six fetches, a 2-permit semaphore, and 50ms-held responses,
        // the limit must actually be reached — otherwise this test can't have observed it.
        assert_eq!(peak, LIMIT, "expected the fetches to saturate the concurrency limit");
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
}
