//! Signed `GET` of witness objects with retry, backoff, and concurrency capping.
//!
//! [`R2ObjectFetcher`] is the transport core shared by every R2 witness *reader* — the
//! validator's pipeline source and the debug-trace-server's historical witness source.
//! It owns exactly the parts whose behavior must not drift between readers: the SigV4-signed
//! `GET`, the response classification ([`R2GetError`]), the retry loop with jittered
//! exponential backoff, and the in-flight concurrency cap. Everything reader-specific stays
//! with the caller: payload decoding (full vs light), metrics, and failure pacing policies.
//!
//! The loop is optionally deadline-aware (see [`R2ObjectFetcher::get_block_object`]).

use std::{
    fmt::Display,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use chrono::Utc;
use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::{
    client::is_throttle_status,
    endpoint::parse_endpoint,
    keys,
    sigv4::{SigV4Signer, encode_uri_path},
};

/// Default total GET attempts (first try + retries) per fetch for retryable
/// (transport/429/5xx) failures before the error surfaces. Sized for deadline-less
/// pipeline readers; request-serving callers with a fallback waiting pass fewer.
pub const DEFAULT_MAX_ATTEMPTS: usize = 9;

/// Cap on the response body carried inside `Throttled`/`Status` errors.
const MAX_ERROR_BODY_BYTES: usize = 1024;

/// Failure outcome of a signed witness-object `GET`, after the fetcher's own retries.
///
/// Decode failures are deliberately absent: the fetcher stops at bytes, and each reader
/// classifies its own decode errors.
#[derive(Debug)]
pub enum R2GetError {
    /// The object is absent from the bucket (HTTP 404 `NoSuchKey`): a transient miss near
    /// the tip / right after a reorg (the uploader has not PUT the object yet), or a
    /// permanent completeness gap in R2.
    Missing { number: u64, key: String },
    /// Transport-level failure (connection reset/timeout) — the endpoint is effectively
    /// unreachable. Retried internally with backoff before surfacing.
    Transport { number: u64, key: String, source: reqwest::Error },
    /// R2 asked us to slow down (429) or returned a server-side error (5xx, including R2's
    /// 503 overload / SlowDown). Retried internally with backoff before surfacing.
    Throttled { number: u64, key: String, status: u16, body: String },
    /// A non-success status unlikely to clear on retry: a 4xx other than 429 (e.g. 403 bad
    /// credentials, 404 NoSuchBucket) or a 3xx (redirects are never followed — see
    /// [`R2ObjectFetcher::new`]). Bodies are best-effort and capped.
    Status { number: u64, key: String, status: u16, body: String },
}

impl R2GetError {
    /// Every label [`Self::kind`] can produce, for callers pre-registering per-kind metrics.
    pub const KINDS: &'static [&'static str] = &["missing", "transport", "throttled", "status"];

    /// Stable lowercase label for this variant, for callers' per-kind error metrics. Every
    /// value returned here appears in [`Self::KINDS`].
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Missing { .. } => "missing",
            Self::Transport { .. } => "transport",
            Self::Throttled { .. } => "throttled",
            Self::Status { .. } => "status",
        }
    }

    /// Whether an immediate retry against the same endpoint could plausibly succeed
    /// (transport blips, 429, 5xx). The other variants are deterministic and are surfaced
    /// without retrying.
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport { .. } | Self::Throttled { .. })
    }
}

impl Display for R2GetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { number, key } => {
                write!(
                    f,
                    "R2 witness MISSING for block {number} (key {key}): object not found (404)"
                )
            }
            Self::Transport { number, key, source } => {
                write!(f, "R2 transport failure for block {number} (key {key}): {source}")
            }
            Self::Throttled { number, key, status, body } => {
                write!(
                    f,
                    "R2 throttled/server error {status} for block {number} (key {key}): {body}"
                )
            }
            Self::Status { number, key, status, body } => {
                write!(f, "R2 unexpected status {status} for block {number} (key {key}): {body}")
            }
        }
    }
}

impl std::error::Error for R2GetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Retry pacing for retryable GET failures: first sleep `initial` (with up to 50% jitter),
/// doubling up to `max`.
///
/// A plain pair rather than a reference to any binary's backoff-policy type, so this crate
/// stays free of upward dependencies; callers build it from whatever flags govern their
/// retry pacing.
#[derive(Clone, Copy, Debug)]
pub struct RetryPacing {
    /// First inter-attempt sleep.
    pub initial: Duration,
    /// Cap on the doubled sleeps.
    pub max: Duration,
}

/// A successfully fetched object body plus the time the fetch spent queued on the
/// concurrency cap.
///
/// `queue_wait` is reported separately so duration metrics can subtract it: queue wait on
/// the self-imposed cap folded into a fetch-duration metric would masquerade as R2 slowness.
#[derive(Debug)]
pub struct FetchedObject {
    /// The object body. [`Bytes`] is refcounted, so the multi-MB witness is never copied
    /// between the HTTP response and the caller's decoder.
    pub bytes: Bytes,
    /// Total time spent waiting for a concurrency permit, across all attempts.
    pub queue_wait: Duration,
}

/// Fetches witness objects from an R2 bucket over the S3 API with SigV4-signed GETs.
///
/// Cloning is cheap — the `reqwest::Client` and signer are internally reference-counted /
/// small. `Debug` is safe to derive: [`SigV4Signer`]'s own `Debug` redacts the credentials.
#[derive(Clone, Debug)]
pub struct R2ObjectFetcher {
    http: Client,
    signer: SigV4Signer,
    /// Endpoint origin (`scheme://host`, no trailing slash).
    endpoint: String,
    /// SigV4 canonical host (`host[:port]`).
    host: String,
    bucket: String,
    /// Hard cap on a single GET attempt; with a deadline, each attempt uses
    /// `min(per_attempt_timeout, remaining)`.
    per_attempt_timeout: Duration,
    pacing: RetryPacing,
    /// Caps concurrent GETs across all fetches sharing this fetcher.
    concurrency: Arc<Semaphore>,
}

impl R2ObjectFetcher {
    /// Builds a fetcher from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `per_attempt_timeout` bounds each individual GET. `pacing` governs the retry sleeps of
    /// retryable failures. `max_concurrent_requests` caps the number of GETs in flight at once
    /// (`None` = unlimited, `Some(0)` clamps to 1). Fails if the endpoint is not a bare
    /// `scheme://host[:port]` origin (see [`parse_endpoint`]) or the HTTP client cannot be
    /// built; the error is a plain message so this crate needs no error-handling dependency.
    pub fn new(
        endpoint: &str,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        per_attempt_timeout: Duration,
        pacing: RetryPacing,
        max_concurrent_requests: Option<usize>,
    ) -> Result<Self, String> {
        let (origin, host) = parse_endpoint(endpoint);
        if host.is_empty() {
            return Err(format!(
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
            .map_err(|e| format!("Failed to build R2 HTTP client: {e}"))?;
        Ok(Self {
            http,
            signer: SigV4Signer::new(access_key_id, secret_access_key),
            endpoint: origin,
            host,
            bucket,
            per_attempt_timeout,
            pacing,
            concurrency: Arc::new(Semaphore::new(
                max_concurrent_requests.unwrap_or(Semaphore::MAX_PERMITS).max(1),
            )),
        })
    }

    /// Fetches the primary witness object for `(number, hash)`, retrying retryable failures.
    ///
    /// Transport/429/5xx failures are retried up to `max_attempts` total attempts, paced by
    /// the constructed [`RetryPacing`] with jittered doubling — jitter keeps parallel readers
    /// (several typically slice a block range) from retrying in lockstep through a shared R2
    /// brownout. `on_retry` fires once per retry, for the caller's metrics.
    ///
    /// With `deadline = Some(d)`, each attempt's HTTP timeout is clamped to the remaining
    /// budget and the loop surfaces the current error instead of starting a backoff sleep
    /// that would overrun `d`. The fetcher never sleeps after the *final* failure — surfaced
    /// failure pacing is reader policy, not transport policy.
    pub async fn get_block_object(
        &self,
        number: u64,
        hash: impl Display,
        max_attempts: usize,
        deadline: Option<Instant>,
        on_retry: impl Fn(),
    ) -> Result<FetchedObject, R2GetError> {
        let key = keys::block_object_key(number, hash);
        let max_backoff_ms = self.pacing.max.as_millis() as u64;
        let mut backoff_ms = self.pacing.initial.as_millis() as u64;
        let mut attempt = 0usize;
        let mut queue_wait = Duration::ZERO;

        loop {
            attempt += 1;
            // Permit scoped to the GET itself — holding it across the backoff sleep would
            // waste capacity other fetches could use.
            let outcome = {
                let queued = Instant::now();
                let _permit = self.concurrency.acquire().await.expect("semaphore is never closed");
                queue_wait += queued.elapsed();
                self.get_object(number, &key, deadline).await
            };
            match outcome {
                Ok(bytes) => return Ok(FetchedObject { bytes, queue_wait }),
                Err(e) => {
                    // Jittered doubling; `.max(1)` keeps a zero-duration policy from
                    // busy-looping.
                    let jitter_ms = fastrand::u64(0..=backoff_ms / 2);
                    let sleep_ms = (backoff_ms + jitter_ms).min(max_backoff_ms).max(1);
                    let out_of_time = deadline
                        .is_some_and(|d| Instant::now() + Duration::from_millis(sleep_ms) >= d);
                    if !e.is_retryable() || attempt >= max_attempts || out_of_time {
                        return Err(e);
                    }
                    on_retry();
                    warn!(
                        number, %key, attempt, sleep_ms, error = %e,
                        "R2 witness GET failed, backing off",
                    );
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(max_backoff_ms);
                }
            }
        }
    }

    /// Performs one SigV4-signed GET and classifies the response. No retry.
    async fn get_object(
        &self,
        number: u64,
        key: &str,
        deadline: Option<Instant>,
    ) -> Result<Bytes, R2GetError> {
        let canonical_uri = encode_uri_path(&self.bucket, key);
        let url = format!("{}{}", self.endpoint, canonical_uri);
        // Signed-payload mode with an empty body: x-amz-content-sha256 = sha256("").
        let signed = self.signer.sign("GET", &self.host, &canonical_uri, "", &[], b"", Utc::now());

        let mut request = self.http.get(&url);
        // Clamp the attempt to the remaining budget; an already-expired deadline degrades to
        // a floor timeout whose transport error the retry loop then surfaces as out-of-time.
        if let Some(deadline) = deadline {
            let remaining =
                deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            request = request.timeout(self.per_attempt_timeout.min(remaining));
        }
        for (name, value) in signed {
            request = request.header(name, value);
        }
        let transport = |source| R2GetError::Transport { number, key: key.to_string(), source };
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
        // the caller's metric kind, not the retry behavior.
        if code == 404 && s3_error_code(&body).is_none_or(|c| c == "NoSuchKey") {
            return Err(R2GetError::Missing { number, key: key.to_string() });
        }
        let key = key.to_string();
        if is_throttle_status(code) {
            Err(R2GetError::Throttled { number, key, status: code, body })
        } else {
            Err(R2GetError::Status { number, key, status: code, body })
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use stateless_test_utils::mock_r2::{mock_r2, mock_r2_held};

    use super::*;

    /// Millisecond-scale retry pacing so the retry-path tests run fast.
    fn test_pacing() -> RetryPacing {
        RetryPacing { initial: Duration::from_millis(5), max: Duration::from_millis(20) }
    }

    fn fetcher(endpoint: &str) -> R2ObjectFetcher {
        fetcher_with(endpoint, None, test_pacing())
    }

    fn fetcher_with(endpoint: &str, limit: Option<usize>, pacing: RetryPacing) -> R2ObjectFetcher {
        R2ObjectFetcher::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(5),
            pacing,
            limit,
        )
        .unwrap()
    }

    async fn fetch(endpoint: &str) -> Result<FetchedObject, R2GetError> {
        fetcher(endpoint).get_block_object(1, "0xhash", DEFAULT_MAX_ATTEMPTS, None, || ()).await
    }

    #[test]
    fn rejects_endpoint_with_path() {
        // A bucket-in-path URL is the classic misconfiguration; construction must fail fast.
        let err = R2ObjectFetcher::new(
            "https://acc.r2.cloudflarestorage.com/witness-mainnet",
            "witness-mainnet".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(20),
            test_pacing(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("Invalid R2 endpoint"));
    }

    #[tokio::test]
    async fn success_returns_body_bytes() {
        let (endpoint, hits) = mock_r2(vec![(200, "witness bytes")]).await;
        let fetched = fetch(&endpoint).await.expect("200 must succeed");
        assert_eq!(fetched.bytes.as_ref(), b"witness bytes");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a successful fetch must take exactly one GET");
    }

    #[tokio::test]
    async fn status_4xx_surfaces_without_retry() {
        let (endpoint, hits) = mock_r2(vec![(403, "SignatureDoesNotMatch")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2GetError::Status { status: 403, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "4xx must not be retried");
    }

    #[tokio::test]
    async fn missing_404_surfaces_without_retry() {
        let (endpoint, hits) = mock_r2(vec![(404, "<Code>NoSuchKey</Code>")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2GetError::Missing { number: 1, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "404 must not be retried");
    }

    #[tokio::test]
    async fn missing_bucket_404_is_a_config_error_not_a_gap() {
        let (endpoint, _) = mock_r2(vec![(404, "<Code>NoSuchBucket</Code>")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2GetError::Status { status: 404, .. }), "{err}");
    }

    /// Any parseable S3 code other than `NoSuchKey` on a 404 is not a data gap; a 404 with no
    /// parseable code (bare proxy 404, truncated body) still counts as Missing.
    #[tokio::test]
    async fn only_no_such_key_and_bare_404s_are_missing() {
        let (endpoint, _) = mock_r2(vec![(404, "<Code>AccessDenied</Code>")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2GetError::Status { status: 404, .. }), "{err}");

        let (endpoint, _) = mock_r2(vec![(404, "<html>not found</html>")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2GetError::Missing { .. }), "{err}");
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
        assert!(matches!(err, R2GetError::Status { status: 403, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 3, "5xx must be retried, 4xx must stop the loop");
    }

    /// The injected pacing actually paces retries: with `initial = 50ms`, the sleep between
    /// the throttled first attempt and the second must be at least 50ms (jitter only adds).
    #[tokio::test]
    async fn retries_are_paced_by_the_injected_pacing() {
        let (endpoint, hits) = mock_r2(vec![(503, "SlowDown"), (404, "")]).await;
        let fetcher = fetcher_with(
            &endpoint,
            None,
            RetryPacing { initial: Duration::from_millis(50), max: Duration::from_millis(200) },
        );
        let started = Instant::now();
        let err = fetcher
            .get_block_object(1, "0xhash", DEFAULT_MAX_ATTEMPTS, None, || ())
            .await
            .unwrap_err();
        assert!(matches!(err, R2GetError::Missing { .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "retry surfaced before the pacing's initial backoff elapsed",
        );
    }

    #[tokio::test]
    async fn persistent_5xx_exhausts_attempts_and_surfaces_throttled() {
        let (endpoint, hits) = mock_r2(vec![(503, "overloaded")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2GetError::Throttled { status: 503, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), DEFAULT_MAX_ATTEMPTS, "exactly max_attempts GETs");
    }

    /// `on_retry` fires once per retry — attempts minus one.
    #[tokio::test]
    async fn on_retry_fires_once_per_retry() {
        let (endpoint, _) = mock_r2(vec![(503, "overloaded")]).await;
        let retries = AtomicUsize::new(0);
        let err = fetcher(&endpoint)
            .get_block_object(1, "0xhash", 4, None, || {
                retries.fetch_add(1, Ordering::SeqCst);
            })
            .await
            .unwrap_err();
        assert!(matches!(err, R2GetError::Throttled { .. }), "{err}");
        assert_eq!(retries.load(Ordering::SeqCst), 3, "4 attempts = 3 retries");
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let (endpoint, hits) = mock_r2(vec![(301, "moved")]).await;
        let err = fetch(&endpoint).await.unwrap_err();
        assert!(matches!(err, R2GetError::Status { status: 301, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// A deadline too tight for another backoff sleep surfaces the current retryable error
    /// instead of sleeping through it: with pacing `initial = 1s` and a ~50ms budget, the
    /// first 503 must surface immediately after one GET.
    #[tokio::test]
    async fn deadline_stops_retries_before_the_backoff_sleep() {
        let (endpoint, hits) = mock_r2(vec![(503, "overloaded")]).await;
        let fetcher = fetcher_with(
            &endpoint,
            None,
            RetryPacing { initial: Duration::from_secs(1), max: Duration::from_secs(1) },
        );
        let started = Instant::now();
        let deadline = Instant::now() + Duration::from_millis(50);
        let err = fetcher
            .get_block_object(1, "0xhash", DEFAULT_MAX_ATTEMPTS, Some(deadline), || ())
            .await
            .unwrap_err();
        assert!(matches!(err, R2GetError::Throttled { status: 503, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no retry fits inside the deadline");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the loop slept through the deadline ({:?})",
            started.elapsed(),
        );
    }

    /// An already-expired deadline degrades to a floor per-attempt timeout: the GET fails as
    /// a transport timeout and surfaces without any backoff sleep.
    #[tokio::test]
    async fn expired_deadline_surfaces_a_transport_error_fast() {
        // Holds every response far past the floor timeout.
        let (endpoint, _, _) = mock_r2_held(404, Duration::from_secs(5)).await;
        let started = Instant::now();
        let deadline = Instant::now() - Duration::from_secs(1);
        let err = fetcher(&endpoint)
            .get_block_object(1, "0xhash", DEFAULT_MAX_ATTEMPTS, Some(deadline), || ())
            .await
            .unwrap_err();
        assert!(matches!(err, R2GetError::Transport { .. }), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "expired deadline must fail fast ({:?})",
            started.elapsed(),
        );
    }

    /// Six concurrent fetches against a limit of 2 must never exceed two in-flight GETs.
    #[tokio::test]
    async fn concurrency_limit_bounds_in_flight_gets() {
        const LIMIT: usize = 2;
        const FETCHES: u64 = 6;

        // Responses held 50ms so fetches pile up behind the semaphore, then answered 404
        // (deterministic -> exactly one GET per fetch).
        let (endpoint, _, peak) = mock_r2_held(404, Duration::from_millis(50)).await;

        let fetcher = fetcher_with(&endpoint, Some(LIMIT), test_pacing());
        let mut fetches = tokio::task::JoinSet::new();
        for number in 0..FETCHES {
            let fetcher = fetcher.clone();
            fetches.spawn(async move {
                fetcher.get_block_object(number, "0xhash", DEFAULT_MAX_ATTEMPTS, None, || ()).await
            });
        }
        while let Some(result) = fetches.join_next().await {
            let err = result.unwrap().unwrap_err();
            assert!(matches!(err, R2GetError::Missing { .. }), "{err}");
        }

        let peak = peak.load(Ordering::SeqCst);
        assert!(peak <= LIMIT, "peak in-flight GETs {peak} exceeded the limit {LIMIT}");
        // Liveness guard: with six fetches, a 2-permit semaphore, and 50ms-held responses,
        // the limit must actually be reached — otherwise this test can't have observed it.
        assert_eq!(peak, LIMIT, "expected the fetches to saturate the concurrency limit");
    }
}
