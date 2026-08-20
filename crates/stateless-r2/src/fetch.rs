//! `GET` of witness objects with retry, backoff, and concurrency capping.
//!
//! [`R2ObjectFetcher`] is the transport core shared by every R2 witness *reader* — the
//! validator's pipeline source and the debug-trace-server's historical witness source.
//! It owns exactly the parts whose behavior must not drift between readers: the `GET`
//! itself, the response classification ([`R2GetError`]), the retry loop with jittered
//! exponential backoff, and the in-flight concurrency cap. Everything reader-specific stays
//! with the caller: payload decoding (full vs light), metrics, and failure pacing policies.
//!
//! The fetcher reaches the bucket through one of two targets:
//! - the bare **S3 API endpoint** ([`R2ObjectFetcher::new`]) — SigV4-signed GETs of
//!   `/{bucket}/{key}`; the endpoint negotiates HTTP/1.1 only, so every in-flight GET holds its own
//!   connection;
//! - a **Cloudflare custom domain** fronting the bucket ([`R2ObjectFetcher::new_custom_domain`]) —
//!   unsigned GETs of `/{key}` through the CDN edge, which negotiates h2 (many in-flight GETs
//!   multiplex over a few connections) and can serve the immutable witness objects from edge cache.
//!   Access control is the domain's business: an IP allowlist needs nothing from this client, and
//!   Cloudflare Access service tokens ride along as headers via [`CfAccessCredentials`].
//!
//! The loop is optionally deadline-aware (see [`R2ObjectFetcher::get_block_object`]).

use std::{
    fmt::Display,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use chrono::Utc;
use reqwest::{
    Client,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use tokio::sync::Semaphore;
use tracing::warn;

use crate::{
    client::is_throttle_status,
    endpoint::parse_endpoint,
    keys,
    sigv4::{SigV4Signer, encode_key_path, encode_uri_path},
};

/// Cap on the response body carried inside `Throttled`/`Status` errors.
const MAX_ERROR_BODY_BYTES: usize = 1024;

/// Default bound on connection establishment (DNS + TCP + TLS). A healthy handshake to the
/// local anycast edge is ~10-50ms. On the S3 target — where HTTP/1.1 means one connection
/// per in-flight GET — Cloudflare's per-IP connection mitigation manifests as handshakes
/// that hang without erroring, so anything past this is that signature (the one legitimate
/// slow case — a lost SYN retried at the kernel's 1s RTO — is cheaper to abort and retry on
/// a fresh attempt than to wait out); on the custom-domain target, which holds only a few
/// multiplexed connections, a slow handshake is ordinary DNS/TCP/TLS trouble. Either way
/// the bound keeps a wedged endpoint from eating the caller's whole budget before its
/// fallback gets a turn. Operators tune it via the binaries' `--r2-connect-timeout-ms`.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// The two HTTP-level bounds a fetcher applies to every GET attempt, threaded together so
/// constructor signatures stay flat.
#[derive(Clone, Copy, Debug)]
pub struct FetchTimeouts {
    /// Hard cap on a single GET attempt end-to-end; with a deadline, each attempt uses
    /// `min(per_attempt, remaining)`.
    pub per_attempt: Duration,
    /// Cap on connection establishment (see [`DEFAULT_CONNECT_TIMEOUT`]).
    pub connect: Duration,
}

/// Failure outcome of a witness-object `GET`, after the fetcher's own retries. Shared by both
/// targets: the classification happens on the response, below the signed/unsigned split.
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
    /// Connection establishment failed or exceeded the connect timeout — distinct from
    /// [`Self::Transport`] because on the S3 target a hung handshake to the local anycast
    /// edge is the signature of the per-IP connection-budget mitigation, and operators
    /// alert on this kind to detect it. On the custom-domain target (a few multiplexed h2
    /// connections) this kind is ordinary DNS/TCP/TLS/edge trouble.
    Connect { number: u64, key: String, source: reqwest::Error },
    /// The caller's deadline expired while the fetch was still queued for a concurrency
    /// permit — under saturation the queue wait must not eat the budget the caller reserved
    /// for its fallback. Only produced when a deadline is passed.
    Deadline { number: u64, key: String },
}

impl R2GetError {
    /// Every label [`Self::kind`] can produce, for callers pre-registering per-kind metrics.
    pub const KINDS: &'static [&'static str] =
        &["missing", "transport", "throttled", "status", "connect", "deadline"];

    /// Stable lowercase label for this variant, for callers' per-kind error metrics. Every
    /// value returned here appears in [`Self::KINDS`].
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Missing { .. } => "missing",
            Self::Transport { .. } => "transport",
            Self::Throttled { .. } => "throttled",
            Self::Status { .. } => "status",
            Self::Connect { .. } => "connect",
            Self::Deadline { .. } => "deadline",
        }
    }

    /// Whether an immediate retry against the same endpoint could plausibly succeed
    /// (transport blips, 429, 5xx). The other variants are deterministic and are surfaced
    /// without retrying.
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport { .. } | Self::Throttled { .. } | Self::Connect { .. })
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
            Self::Connect { number, key, source } => {
                write!(
                    f,
                    "R2 connect/TLS handshake failed or timed out for block {number} \
                     (key {key}): {source}"
                )
            }
            Self::Deadline { number, key } => {
                write!(
                    f,
                    "R2 witness fetch for block {number} (key {key}) ran out of deadline \
                     queued for a concurrency permit"
                )
            }
        }
    }
}

impl std::error::Error for R2GetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport { source, .. } | Self::Connect { source, .. } => Some(source),
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

/// Cloudflare Access service-token credentials, sent as the `CF-Access-Client-Id` /
/// `CF-Access-Client-Secret` headers on every custom-domain GET.
///
/// `Debug` redacts both halves: the id alone is enough to look up the token, so it gets the
/// same treatment as the secret.
#[derive(Clone)]
pub struct CfAccessCredentials {
    /// The service token's client id.
    pub client_id: String,
    /// The service token's client secret.
    pub client_secret: String,
}

impl CfAccessCredentials {
    /// Builds the two Access headers, marked sensitive so they are never HPACK-indexed and
    /// stay redacted in header debug output.
    ///
    /// Fails when a value cannot be an HTTP header value — a trailing newline picked up from a
    /// secret file or an unquoted env line is the usual cause. The offending value is never
    /// echoed: it is the credential. Validating here turns what would otherwise be a builder
    /// error raised per GET — classified retryable and so retried forever, with no startup
    /// failure — into one named error at construction.
    fn into_header_map(self) -> Result<HeaderMap, String> {
        let mut headers = HeaderMap::new();
        for (name, value, flag) in [
            ("cf-access-client-id", self.client_id, "--r2-access-client-id"),
            ("cf-access-client-secret", self.client_secret, "--r2-access-client-secret"),
        ] {
            let mut value = HeaderValue::from_str(&value).map_err(|_| {
                format!(
                    "{flag} is not a valid HTTP header value (control characters — a trailing \
                     newline from the secret store is the usual cause)"
                )
            })?;
            value.set_sensitive(true);
            headers.insert(HeaderName::from_static(name), value);
        }
        Ok(headers)
    }
}

impl std::fmt::Debug for CfAccessCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CfAccessCredentials")
            .field("client_id", &"[redacted]")
            .field("client_secret", &"[redacted]")
            .finish()
    }
}

/// How a [`R2ObjectFetcher`] reaches the bucket. `Debug` is safe to derive: the only credential
/// holder left ([`SigV4Signer`]) redacts itself, and Access tokens live on the client's default
/// headers rather than here.
#[derive(Clone, Debug)]
enum Target {
    /// SigV4-signed GETs of `/{bucket}/{key}` against the bare S3 API endpoint.
    S3 {
        signer: SigV4Signer,
        /// Endpoint origin (`scheme://host`, no trailing slash).
        endpoint: String,
        /// SigV4 canonical host (`host[:port]`).
        host: String,
        bucket: String,
    },
    /// Unsigned GETs of `/{key}` against a Cloudflare custom domain fronting the bucket.
    ///
    /// Any Cloudflare Access service token is attached by the client's default headers, so it
    /// cannot be bypassed by a request path that does not go through `request_parts`.
    CustomDomain {
        /// Domain origin (`scheme://host`, no trailing slash).
        origin: String,
    },
}

/// Parses a target's bare origin, rejecting anything that is not `scheme://host[:port]`.
///
/// `label` and `example` name the flag the caller owns, so each target keeps its own error.
/// The raw input is never echoed back: a rejected shape may carry inline credentials
/// (userinfo), and this message ends up in startup logs.
fn parse_target_origin(
    input: &str,
    label: &str,
    example: &str,
) -> Result<(String, String), String> {
    let (origin, host) = parse_endpoint(input);
    if host.is_empty() {
        return Err(format!(
            "Invalid R2 {label}: expected a bare scheme://host origin (no path/query/userinfo), \
             e.g. {example}"
        ));
    }
    // A scheme reqwest cannot drive would pass startup and then fail inside `send()` as a
    // builder error — classified retryable, so a permanently broken URL would be retried
    // forever instead of failing once here.
    if !origin.starts_with("https://") && !origin.starts_with("http://") {
        return Err(format!(
            "Invalid R2 {label}: only http and https are supported, e.g. {example}"
        ));
    }
    Ok((origin, host))
}

/// Idle connections the pool may keep per host when `--r2-max-concurrent-requests` is unset.
///
/// Only binds on the degraded HTTP/1.1 path: an h2 pool holds a single connection whatever this
/// says. There it is what stops `pool_idle_timeout(None)` — set so the multiplexed connection
/// survives the gaps between request waves — from letting idle sockets accumulate without
/// bound, which reqwest's `pool_max_idle_per_host` default of `usize::MAX` otherwise allows.
const MAX_IDLE_CONNECTIONS_PER_HOST: usize = 64;

/// Streams a Cloudflare edge accepts on one HTTP/2 connection: its advertised
/// `SETTINGS_MAX_CONCURRENT_STREAMS`, which is Cloudflare's default since HTTP/2 Rapid Reset
/// and was read off the wire on the zone this target was built for.
pub const CLOUDFLARE_MAX_CONCURRENT_STREAMS: usize = 100;

/// `negotiated_version` before any response has been seen.
const VERSION_UNOBSERVED: u8 = 0;
/// Protocol labels, indexed by the code stored in `negotiated_version`.
const VERSION_LABELS: [&str; 7] = ["", "http/0.9", "http/1.0", "http/1.1", "h2", "h3", "other"];

fn version_code(version: reqwest::Version) -> u8 {
    match version {
        v if v == reqwest::Version::HTTP_09 => 1,
        v if v == reqwest::Version::HTTP_10 => 2,
        v if v == reqwest::Version::HTTP_11 => 3,
        v if v == reqwest::Version::HTTP_2 => 4,
        v if v == reqwest::Version::HTTP_3 => 5,
        _ => 6,
    }
}

/// Whether `host[:port]` names the loopback interface, where plaintext `http` is the mock and
/// port-forward shape rather than a credential exposure.
fn is_loopback_host(host: &str) -> bool {
    let bare = match host.strip_prefix('[') {
        // IPv6 literal, `[::1]` or `[::1]:8080`.
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => host.split(':').next().unwrap_or(host),
    };
    bare.eq_ignore_ascii_case("localhost") ||
        bare.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The HTTP client settings both targets share; each constructor adds its own wire posture.
///
/// Neither target may follow a redirect. A SigV4-signed GET cannot survive one — reqwest strips
/// `authorization` on cross-host hops and a same-host hop invalidates the signed URI, so
/// following just turns the real cause into a baffling 403. A 3xx from a custom domain is
/// itself the signal (Cloudflare Access bouncing an unauthenticated client to its login page),
/// which following would bury under an HTML body. Both surface the 3xx as a `Status` error.
fn base_client(timeouts: FetchTimeouts) -> reqwest::ClientBuilder {
    Client::builder()
        .timeout(timeouts.per_attempt)
        .connect_timeout(timeouts.connect)
        .redirect(reqwest::redirect::Policy::none())
}

/// Permits for the in-flight GET cap: `None` = unlimited, `Some(0)` clamps to 1 — a
/// zero-permit semaphore would wedge every fetch on `acquire()` forever.
fn concurrency_permits(max_concurrent_requests: Option<usize>) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(max_concurrent_requests.unwrap_or(Semaphore::MAX_PERMITS).max(1)))
}

/// Fetches witness objects from an R2 bucket — SigV4-signed over the S3 API, or unsigned
/// through a Cloudflare custom domain (see the module docs for the two targets).
///
/// Cloning is cheap — the `reqwest::Client` and the target's credential holders are
/// internally reference-counted / small. `Debug` is safe to derive: the target redacts.
#[derive(Clone, Debug)]
pub struct R2ObjectFetcher {
    http: Client,
    target: Target,
    /// Hard cap on a single GET attempt; with a deadline, each attempt uses
    /// `min(timeouts.per_attempt, remaining)`.
    per_attempt_timeout: Duration,
    pacing: RetryPacing,
    /// Caps concurrent GETs across all fetches sharing this fetcher.
    concurrency: Arc<Semaphore>,
    /// Protocol the first response actually used, [`VERSION_UNOBSERVED`] until one arrives.
    /// Shared across clones so the degradation warning fires once per fetcher, not per clone.
    negotiated_version: Arc<AtomicU8>,
}

impl R2ObjectFetcher {
    /// The retry pacing this fetcher was built with, for callers whose surfaced-failure
    /// policies must stay in sync with the retry ramp (e.g. pausing the ramp's `max`).
    pub const fn pacing(&self) -> RetryPacing {
        self.pacing
    }

    /// This fetcher's target origin (`scheme://host[:port]`).
    ///
    /// Callers log this instead of the flag they were given: the raw operator string can carry
    /// inline credentials (userinfo), and these lines are info-level.
    pub fn origin(&self) -> &str {
        match &self.target {
            Target::S3 { endpoint, .. } => endpoint,
            Target::CustomDomain { origin, .. } => origin,
        }
    }

    /// Stable lowercase label for the configured target, for callers' metric labels.
    ///
    /// Lives here for the same reason [`R2GetError::kind`] does: the vocabulary belongs to the
    /// enum it names, so a renamed or added target cannot leave a binary publishing a stale
    /// string that nothing would flag.
    pub const fn target_label(&self) -> &'static str {
        match &self.target {
            Target::S3 { .. } => "s3",
            Target::CustomDomain { .. } => "custom_domain",
        }
    }

    /// The protocol the first response on this fetcher actually used, once one has arrived.
    ///
    /// Answers "did the custom domain really give us h2", which the configured target alone
    /// cannot: version selection is pure ALPN, so a degraded origin looks identical from the
    /// configuration side.
    pub fn negotiated_http_version(&self) -> Option<&'static str> {
        match self.negotiated_version.load(Ordering::Relaxed) {
            VERSION_UNOBSERVED => None,
            code => Some(VERSION_LABELS[code as usize]),
        }
    }

    /// Records the protocol of the first response, warning once if a custom domain did not
    /// negotiate HTTP/2.
    ///
    /// There is deliberately no `http2_prior_knowledge` — it would break the plaintext loopback
    /// path the mocks and port-forwards rely on — so an h1-only peer simply answers normally and
    /// nothing else notices. That is the trap worth naming: the three h2 knobs go inert, while
    /// `pool_idle_timeout(None)` stays in force over an HTTP/1.1 pool, and the target gauge goes
    /// on asserting the target that was *configured*. Warned once rather than per GET, which at
    /// this call rate would be thousands of lines a minute.
    fn observe_version(&self, version: reqwest::Version) {
        let code = version_code(version);
        if self
            .negotiated_version
            .compare_exchange(VERSION_UNOBSERVED, code, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        if version != reqwest::Version::HTTP_2 {
            warn!(
                negotiated = VERSION_LABELS[code as usize],
                origin = self.origin(),
                "R2 custom domain did not negotiate HTTP/2: the multiplexing this target exists \
                 for is unavailable, its h2 tuning is inert, and connection reuse now follows \
                 HTTP/1.1 pooling. Check that the domain is proxied by Cloudflare and that the \
                 zone has HTTP/2 enabled."
            );
        }
    }

    /// The configured concurrency, when it over-subscribes the edge's per-connection stream
    /// limit — that is, when the limit rather than this fetcher's semaphore is what bounds the
    /// GETs actually in flight.
    ///
    /// One client holds exactly one HTTP/2 connection, and hyper never opens a second one to
    /// relieve a saturated one: `is_open` on a pooled h2 connection reports liveness, not
    /// stream capacity, and the dispatch channel behind it is unbounded. So a request past the
    /// limit does not fail and does not get its own connection — it waits inside the
    /// connection, where the wait is invisible to the caller's queue-wait metric and still
    /// counts against the per-attempt timeout.
    ///
    /// Exactly *at* the limit is the intended sizing, not a misconfiguration: every permit maps
    /// to a stream slot and nothing queues. Unlimited is not flagged either — it is the
    /// unconfigured default, and a warning that fires on a default is one operators learn to
    /// skip.
    fn concurrency_over_edge_stream_limit(max_concurrent_requests: Option<usize>) -> Option<usize> {
        max_concurrent_requests.filter(|n| *n > CLOUDFLARE_MAX_CONCURRENT_STREAMS)
    }

    /// Builds a fetcher from an R2 endpoint origin, bucket, and bucket-scoped S3 credentials.
    ///
    /// `timeouts` bounds each individual GET (end-to-end and connect phase). `pacing`
    /// governs the retry sleeps of retryable failures. `max_concurrent_requests` caps the
    /// number of GETs in flight at once (`None` = unlimited, `Some(0)` clamps to 1). Fails
    /// if the endpoint is not a bare `scheme://host[:port]` origin (see [`parse_endpoint`])
    /// or the HTTP client cannot be built; the error is a plain message so this crate needs
    /// no error-handling dependency.
    pub fn new(
        endpoint: &str,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        timeouts: FetchTimeouts,
        pacing: RetryPacing,
        max_concurrent_requests: Option<usize>,
    ) -> Result<Self, String> {
        let (origin, host) = parse_target_origin(
            endpoint,
            "endpoint",
            "https://<account>.r2.cloudflarestorage.com",
        )?;
        let http = base_client(timeouts)
            // Pin the S3 target to HTTP/1.1 in the client rather than relying on the server's
            // ALPN choice: the endpoint only speaks h1.1 today, and this keeps the signed
            // path's wire behavior fixed even if that ever changes upstream.
            .http1_only()
            .build()
            .map_err(|e| format!("Failed to build R2 HTTP client: {e}"))?;
        Ok(Self {
            http,
            target: Target::S3 {
                signer: SigV4Signer::new(access_key_id, secret_access_key),
                endpoint: origin,
                host,
                bucket,
            },
            per_attempt_timeout: timeouts.per_attempt,
            pacing,
            concurrency: concurrency_permits(max_concurrent_requests),
            negotiated_version: Arc::new(AtomicU8::new(VERSION_UNOBSERVED)),
        })
    }

    /// Builds a fetcher that GETs objects unsigned through a Cloudflare custom domain
    /// fronting the bucket (`https://<domain>/{key}` — no bucket path segment, the domain is
    /// bucket-scoped).
    ///
    /// `access` attaches Cloudflare Access service-token headers to every GET; leave it
    /// `None` when the domain is locked by an IP allowlist instead. The remaining parameters
    /// mean exactly what they mean on [`Self::new`]. Fails if the domain is not a bare
    /// `scheme://host[:port]` origin — the object path is appended by this fetcher, and a
    /// path-bearing domain would silently double it.
    ///
    /// The domain rides Cloudflare's h2-capable edge, so this client differs from the S3 one
    /// in its HTTP/2 posture (all three knobs are inert on an endpoint that only offers
    /// http/1.1 via ALPN, which also keeps this constructor honest against a non-h2 origin):
    /// - adaptive flow-control windows — the defaults are sized well under the bandwidth-delay
    ///   product of an intercontinental path, and would cap a multi-MB tail object far below the
    ///   link's actual capacity;
    /// - keep-alive pings, including while idle — the single multiplexed connection must survive
    ///   the gaps between request waves, or every wave re-pays the TLS handshake and
    ///   congestion-window ramp that connection reuse exists to avoid.
    pub fn new_custom_domain(
        domain: &str,
        access: Option<CfAccessCredentials>,
        timeouts: FetchTimeouts,
        pacing: RetryPacing,
        max_concurrent_requests: Option<usize>,
    ) -> Result<Self, String> {
        let (origin, host) =
            parse_target_origin(domain, "custom domain", "https://witness.example.com")?;
        // An Access service token is a bearer credential; plaintext would put it on the wire in
        // the clear on every GET. Loopback stays allowed — that is the mock and port-forward
        // shape, not an exposure.
        if access.is_some() && origin.starts_with("http://") && !is_loopback_host(&host) {
            return Err("Refusing to send Cloudflare Access credentials over plaintext http:// \
                 to a non-loopback host: give --r2-custom-domain an https:// origin"
                .to_string());
        }
        let mut builder = base_client(timeouts)
            // Cloudflare's Browser Integrity Check, on by default on many zones, challenges
            // requests that carry no user agent — which would arrive here as a non-retryable
            // 403 on every GET. It also makes this traffic attributable in zone analytics.
            .user_agent(concat!("stateless-r2/", env!("CARGO_PKG_VERSION")))
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_while_idle(true)
            // Keep-alive pings hold the connection open at the protocol level, but the pool
            // reaps idle connections on a 90s default of its own — shorter than the gaps
            // between request waves that this single multiplexed connection exists to survive.
            .pool_idle_timeout(None)
            // Paired with the line above: without an idle timeout, an unbounded idle pool would
            // never release a socket. Inert on h2 (one connection); the bound that matters is
            // on the h1.1 path this client silently falls back to against a non-h2 origin.
            .pool_max_idle_per_host(
                max_concurrent_requests.unwrap_or(MAX_IDLE_CONNECTIONS_PER_HOST),
            )
            // Stated rather than inherited: with keep-alive pings on, this is what bounds how
            // long a blackholed connection keeps accepting doomed streams.
            .http2_keep_alive_timeout(Duration::from_secs(20));
        if let Some(access) = access {
            // On the client, not per attempt: authentication is then a property of every
            // request this fetcher makes, and an unusable credential fails here by name
            // instead of once per GET as a retryable transport error.
            builder = builder.default_headers(access.into_header_map()?);
        }
        if let Some(configured) = Self::concurrency_over_edge_stream_limit(max_concurrent_requests)
        {
            warn!(
                configured,
                edge_stream_limit = CLOUDFLARE_MAX_CONCURRENT_STREAMS,
                "R2 custom-domain concurrency over-subscribes the edge's per-connection HTTP/2 \
                 stream limit: the surplus queues inside the connection rather than on the \
                 semaphore, where the wait escapes the queue-wait metric and still counts \
                 against the per-attempt timeout."
            );
        }
        let http = builder.build().map_err(|e| format!("Failed to build R2 HTTP client: {e}"))?;
        Ok(Self {
            http,
            target: Target::CustomDomain { origin },
            per_attempt_timeout: timeouts.per_attempt,
            pacing,
            concurrency: concurrency_permits(max_concurrent_requests),
            negotiated_version: Arc::new(AtomicU8::new(VERSION_UNOBSERVED)),
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
                // A deadline bounds the queue wait too: under saturation the caller's budget
                // must stay available for its fallback, not drain waiting for a permit.
                let permit = match deadline {
                    None => self.concurrency.acquire().await,
                    Some(d) => {
                        match tokio::time::timeout_at(d.into(), self.concurrency.acquire()).await {
                            Ok(acquired) => acquired,
                            Err(_) => return Err(R2GetError::Deadline { number, key }),
                        }
                    }
                }
                .expect("semaphore is never closed");
                queue_wait += queued.elapsed();
                let _permit = permit;
                self.get_object(number, &key, deadline).await
            };
            match outcome {
                Ok(bytes) => return Ok(FetchedObject { bytes, queue_wait }),
                Err(e) => {
                    if !e.is_retryable() || attempt >= max_attempts {
                        return Err(e);
                    }
                    // Jittered doubling; `.max(1)` keeps a zero-duration policy from
                    // busy-looping.
                    let jitter_ms = fastrand::u64(0..=backoff_ms / 2);
                    let sleep_ms = (backoff_ms + jitter_ms).min(max_backoff_ms).max(1);
                    if deadline
                        .is_some_and(|d| Instant::now() + Duration::from_millis(sleep_ms) >= d)
                    {
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

    /// Builds one attempt's request for this fetcher's target: the signed S3 layout
    /// (`/{bucket}/{key}` plus freshly-signed SigV4 headers) or the unsigned custom-domain
    /// layout (`/{key}`, whose only credentials are the client's default headers).
    ///
    /// Called per attempt because a SigV4 signature is timestamped and cannot be reused.
    fn request(&self, key: &str) -> reqwest::RequestBuilder {
        match &self.target {
            Target::S3 { signer, endpoint, host, bucket } => {
                let canonical_uri = encode_uri_path(bucket, key);
                // Signed-payload mode with an empty body: x-amz-content-sha256 = sha256("").
                let signed = signer.sign("GET", host, &canonical_uri, "", &[], b"", Utc::now());
                signed.into_iter().fold(
                    self.http.get(format!("{endpoint}{canonical_uri}")),
                    |request, (name, value)| request.header(name, value),
                )
            }
            Target::CustomDomain { origin } => {
                self.http.get(format!("{origin}{}", encode_key_path(key)))
            }
        }
    }

    /// Performs one GET against this fetcher's target and classifies the response. No retry.
    async fn get_object(
        &self,
        number: u64,
        key: &str,
        deadline: Option<Instant>,
    ) -> Result<Bytes, R2GetError> {
        let mut request = self.request(key);
        // Clamp the attempt to the remaining budget; an already-expired deadline degrades to
        // a floor timeout whose transport error the retry loop then surfaces as out-of-time.
        if let Some(deadline) = deadline {
            let remaining =
                deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            request = request.timeout(self.per_attempt_timeout.min(remaining));
        }
        let transport = |source: reqwest::Error| {
            let key = key.to_string();
            if source.is_connect() {
                R2GetError::Connect { number, key, source }
            } else {
                R2GetError::Transport { number, key, source }
            }
        };
        let response = request.send().await.map_err(transport)?;
        if matches!(self.target, Target::CustomDomain { .. }) {
            self.observe_version(response.version());
        }

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
        // the caller's metric kind, not the retry behavior. Custom-domain 404s carry no S3
        // XML at all, so they classify as Missing through that same arm — also the right
        // default there, where an absent object is the only routine 404.
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

    use stateless_test_utils::mock_r2::{mock_r2, mock_r2_capturing, mock_r2_held};

    use super::*;

    /// Attempt budget used by the exhaust-path tests (the pipeline reader's sizing).
    const MAX_ATTEMPTS: usize = 9;

    /// Millisecond-scale retry pacing so the retry-path tests run fast.
    fn test_pacing() -> RetryPacing {
        RetryPacing { initial: Duration::from_millis(5), max: Duration::from_millis(20) }
    }

    fn fetcher(endpoint: &str) -> R2ObjectFetcher {
        fetcher_with(endpoint, None, test_pacing())
    }

    fn test_timeouts() -> FetchTimeouts {
        FetchTimeouts { per_attempt: Duration::from_secs(5), connect: DEFAULT_CONNECT_TIMEOUT }
    }

    fn fetcher_with(endpoint: &str, limit: Option<usize>, pacing: RetryPacing) -> R2ObjectFetcher {
        R2ObjectFetcher::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            test_timeouts(),
            pacing,
            limit,
        )
        .unwrap()
    }

    async fn fetch(endpoint: &str) -> Result<FetchedObject, R2GetError> {
        fetcher(endpoint).get_block_object(1, "0xhash", MAX_ATTEMPTS, None, || ()).await
    }

    #[test]
    fn rejects_endpoint_with_path() {
        // A bucket-in-path URL is the classic misconfiguration; construction must fail fast.
        let err = R2ObjectFetcher::new(
            "https://acc.r2.cloudflarestorage.com/witness-mainnet",
            "witness-mainnet".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            test_timeouts(),
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
        let err =
            fetcher.get_block_object(1, "0xhash", MAX_ATTEMPTS, None, || ()).await.unwrap_err();
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
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS, "exactly max_attempts GETs");
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
            .get_block_object(1, "0xhash", MAX_ATTEMPTS, Some(deadline), || ())
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
        let (endpoint, _) = mock_r2_held(404, Duration::from_secs(5)).await;
        let started = Instant::now();
        let deadline = Instant::now() - Duration::from_secs(1);
        let err = fetcher(&endpoint)
            .get_block_object(1, "0xhash", MAX_ATTEMPTS, Some(deadline), || ())
            .await
            .unwrap_err();
        assert!(matches!(err, R2GetError::Transport { .. }), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "expired deadline must fail fast ({:?})",
            started.elapsed(),
        );
    }

    /// Connection-establishment failures surface as `Connect` (the mitigation-detection
    /// kind) and are bounded by [`CONNECT_TIMEOUT`] rather than the full attempt timeout.
    /// 192.0.2.1 (TEST-NET-1) is unroutable: the connect either errors immediately or
    /// blackholes until the connect timeout — both must classify as `Connect`, fast.
    #[tokio::test]
    async fn unreachable_endpoint_surfaces_connect_kind_fast() {
        let fetcher = fetcher_with("http://192.0.2.1:81", None, test_pacing());
        let started = Instant::now();
        let err = fetcher.get_block_object(1, "0xhash", 1, None, || ()).await.unwrap_err();
        assert!(matches!(err, R2GetError::Connect { .. }), "{err}");
        assert_eq!(err.kind(), "connect");
        assert!(
            started.elapsed() < DEFAULT_CONNECT_TIMEOUT + Duration::from_millis(500),
            "connect failure must be bounded by the connect timeout ({:?})",
            started.elapsed(),
        );
    }

    /// A fetch whose deadline expires while queued for a permit surfaces `Deadline`
    /// promptly instead of waiting out the holder — the queue wait must not consume the
    /// budget the caller reserved for its fallback.
    #[tokio::test]
    async fn queued_fetch_surfaces_deadline_before_permit_frees() {
        let (endpoint, _) = mock_r2_held(404, Duration::from_secs(3)).await;
        let fetcher = fetcher_with(&endpoint, Some(1), test_pacing());

        // Occupy the single permit with a long-held GET.
        let holder = {
            let fetcher = fetcher.clone();
            tokio::spawn(async move { fetcher.get_block_object(1, "0xhold", 1, None, || ()).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = Instant::now();
        let deadline = Instant::now() + Duration::from_millis(150);
        let err =
            fetcher.get_block_object(2, "0xqueued", 1, Some(deadline), || ()).await.unwrap_err();
        assert!(matches!(err, R2GetError::Deadline { number: 2, .. }), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "queued fetch must surface at its deadline, not the holder's ({:?})",
            started.elapsed(),
        );
        let _ = holder.await;
    }

    fn custom_fetcher(domain: &str, access: Option<CfAccessCredentials>) -> R2ObjectFetcher {
        R2ObjectFetcher::new_custom_domain(domain, access, test_timeouts(), test_pacing(), None)
            .unwrap()
    }

    /// A credential that cannot be a header value fails at construction, by flag name and
    /// without echoing the value. Left to `send()` it becomes a reqwest builder error, which
    /// classifies as retryable `Transport` — so every GET would burn the full retry ramp
    /// forever and no startup failure would ever name the real cause.
    #[test]
    fn access_credential_with_a_control_byte_fails_construction_without_echoing_it() {
        let err = R2ObjectFetcher::new_custom_domain(
            "https://witness.example.com",
            Some(CfAccessCredentials {
                client_id: "tok-3f1.access".to_string(),
                // The shape of `$(cat secret.txt)` or an unquoted env-file line.
                client_secret: "sec-9a2\n".to_string(),
            }),
            test_timeouts(),
            test_pacing(),
            None,
        )
        .expect_err("a trailing newline cannot be a header value");
        assert!(err.contains("--r2-access-client-secret"), "{err}");
        assert!(!err.contains("sec-9a2"), "the secret must never reach a log line: {err}");
    }

    /// Access tokens are bearer credentials, so a plaintext non-loopback origin is refused
    /// rather than putting them on the wire in the clear on every GET.
    #[test]
    fn access_credentials_are_refused_over_plaintext_to_a_remote_host() {
        let access = || {
            Some(CfAccessCredentials {
                client_id: "tok-3f1.access".to_string(),
                client_secret: "sec-9a2".to_string(),
            })
        };
        let err = R2ObjectFetcher::new_custom_domain(
            "http://witness.example.com",
            access(),
            test_timeouts(),
            test_pacing(),
            None,
        )
        .expect_err("plaintext + credentials to a remote host must be refused");
        assert!(err.contains("plaintext"), "{err}");

        // Loopback stays usable: that is the mock and port-forward shape, and every
        // custom-domain test here depends on it.
        for loopback in ["http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"] {
            R2ObjectFetcher::new_custom_domain(
                loopback,
                access(),
                test_timeouts(),
                test_pacing(),
                None,
            )
            .unwrap_or_else(|e| panic!("{loopback} must be allowed: {e}"));
        }
        // Plaintext without credentials has nothing to leak.
        custom_fetcher("http://witness.example.com", None);
    }

    /// A scheme reqwest cannot drive is rejected at construction on both targets; left alone it
    /// surfaces per GET as a retryable transport error, retrying a permanently broken URL.
    #[test]
    fn non_http_schemes_are_rejected_on_both_targets() {
        let custom = R2ObjectFetcher::new_custom_domain(
            "ftp://witness.example.com",
            None,
            test_timeouts(),
            test_pacing(),
            None,
        )
        .expect_err("ftp is not drivable");
        assert!(custom.contains("only http and https"), "{custom}");

        let s3 = R2ObjectFetcher::new(
            "ftp://acc.r2.cloudflarestorage.com",
            "witness-mainnet".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            test_timeouts(),
            test_pacing(),
            None,
        )
        .expect_err("ftp is not drivable");
        assert!(s3.contains("only http and https"), "{s3}");
    }

    /// The custom-domain target degrades to HTTP/1.1 in silence against any origin that does
    /// not offer h2 over ALPN — and every mock in this suite is exactly such an origin, so the
    /// green tests here *are* the degraded path. Pinning that keeps it visible: the protocol
    /// actually negotiated is observable, rather than inferred from the configured target.
    #[tokio::test]
    async fn custom_domain_reports_the_protocol_it_actually_negotiated() {
        let (domain, _hits) = mock_r2(vec![(200, "witness bytes")]).await;
        let fetcher = custom_fetcher(&domain, None);
        assert_eq!(fetcher.negotiated_http_version(), None, "nothing observed before a request");

        fetcher
            .get_block_object(2500, "0xblock", MAX_ATTEMPTS, None, || ())
            .await
            .expect("200 must succeed");
        assert_eq!(
            fetcher.negotiated_http_version(),
            Some("http/1.1"),
            "the plaintext mock cannot offer h2, and that must be visible rather than assumed"
        );
    }

    /// The advisory covers over-subscription only. Exactly at the limit every permit maps to
    /// a stream slot, which is the sizing the flag documentation asks for — warning there would
    /// fire on a correct configuration, and warning on unlimited would fire on the default.
    #[test]
    fn edge_stream_limit_advisory_covers_over_subscription_only() {
        let over = R2ObjectFetcher::concurrency_over_edge_stream_limit;
        assert_eq!(over(None), None, "unlimited is the default, not a misconfiguration");
        assert_eq!(over(Some(CLOUDFLARE_MAX_CONCURRENT_STREAMS)), None, "at the limit is exact");
        assert_eq!(
            over(Some(CLOUDFLARE_MAX_CONCURRENT_STREAMS + 1)),
            Some(CLOUDFLARE_MAX_CONCURRENT_STREAMS + 1),
            "one past the limit is one GET queued where the queue cannot be seen"
        );
        assert_eq!(over(Some(4096)), Some(4096));
    }

    /// Cloudflare's Browser Integrity Check challenges user-agent-less requests, which would
    /// arrive as a non-retryable 403 on every GET — and the validator's R2 mode has no fallback.
    #[tokio::test]
    async fn custom_domain_sends_a_user_agent() {
        let (domain, _hits, heads) = mock_r2_capturing(vec![(200, "witness bytes")]).await;
        custom_fetcher(&domain, None)
            .get_block_object(2500, "0xblock", MAX_ATTEMPTS, None, || ())
            .await
            .expect("200 must succeed");
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(head.contains("user-agent: stateless-r2/"), "{head}");
    }

    #[test]
    fn custom_domain_rejects_origin_with_path() {
        // The fetcher appends the object path itself; a path-bearing domain would silently
        // double it, so construction must fail fast (same policy as the S3 endpoint).
        let err = R2ObjectFetcher::new_custom_domain(
            "https://witness.example.com/witness-mainnet",
            None,
            test_timeouts(),
            test_pacing(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("Invalid R2 custom domain"), "{err}");
    }

    /// The custom-domain wire shape: `GET /{key}` with no bucket segment, no SigV4
    /// `authorization`, and no Access headers unless configured.
    #[tokio::test]
    async fn custom_domain_gets_bare_key_path_unsigned() {
        let (domain, hits, heads) = mock_r2_capturing(vec![(200, "witness bytes")]).await;
        let fetched = custom_fetcher(&domain, None)
            .get_block_object(2500, "0xblock", MAX_ATTEMPTS, None, || ())
            .await
            .expect("200 must succeed");
        assert_eq!(fetched.bytes.as_ref(), b"witness bytes");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(head.starts_with("get /block/2000_2999/2500.0xblock http/1.1\r\n"), "{head}");
        assert!(!head.contains("authorization:"), "custom-domain GET must be unsigned: {head}");
        assert!(!head.contains("cf-access-client-id:"), "no Access headers configured: {head}");
    }

    /// The S3 wire shape stays what it was: `GET /{bucket}/{key}` carrying a SigV4
    /// `authorization` header — pinned so the custom-domain arm can never bleed into it.
    #[tokio::test]
    async fn s3_get_prefixes_the_bucket_and_signs() {
        let (endpoint, _, heads) = mock_r2_capturing(vec![(200, "witness bytes")]).await;
        fetcher(&endpoint)
            .get_block_object(2500, "0xblock", MAX_ATTEMPTS, None, || ())
            .await
            .expect("200 must succeed");
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(
            head.starts_with("get /witness-test/block/2000_2999/2500.0xblock http/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("authorization: aws4-hmac-sha256"), "{head}");
    }

    #[tokio::test]
    async fn custom_domain_sends_access_headers_when_configured() {
        let (domain, _, heads) = mock_r2_capturing(vec![(200, "ok")]).await;
        let access = CfAccessCredentials {
            client_id: "tok-3f1.access".to_string(),
            client_secret: "sec-9a2".to_string(),
        };
        custom_fetcher(&domain, Some(access))
            .get_block_object(1, "0xhash", 1, None, || ())
            .await
            .expect("200 must succeed");
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(head.contains("cf-access-client-id: tok-3f1.access"), "{head}");
        assert!(head.contains("cf-access-client-secret: sec-9a2"), "{head}");
        assert!(!head.contains("authorization:"), "{head}");
    }

    /// The custom-domain client shares the no-redirect policy: a 3xx (the shape of a
    /// Cloudflare Access login bounce) must surface as `Status`, not be followed into an
    /// HTML page.
    #[tokio::test]
    async fn custom_domain_redirects_are_not_followed() {
        let (domain, hits) = mock_r2(vec![(302, "login bounce")]).await;
        let err = custom_fetcher(&domain, None)
            .get_block_object(1, "0xhash", MAX_ATTEMPTS, None, || ())
            .await
            .unwrap_err();
        assert!(matches!(err, R2GetError::Status { status: 302, .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// Credentials are rebuilt per attempt: the retry after a throttle must still carry the
    /// Access pair (custom domain) / a fresh SigV4 authorization (S3) — pinned so a future
    /// hoist of header construction out of the attempt loop cannot silently strip retries.
    #[tokio::test]
    async fn retries_resend_credentials() {
        let (domain, hits, heads) = mock_r2_capturing(vec![(503, "slow"), (200, "ok")]).await;
        let access = CfAccessCredentials {
            client_id: "tok-3f1.access".to_string(),
            client_secret: "sec-9a2".to_string(),
        };
        custom_fetcher(&domain, Some(access))
            .get_block_object(1, "0xhash", MAX_ATTEMPTS, None, || ())
            .await
            .expect("retry must succeed");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        let retry_head = heads.lock().unwrap()[1].to_lowercase();
        assert!(retry_head.contains("cf-access-client-id: tok-3f1.access"), "{retry_head}");
        assert!(retry_head.contains("cf-access-client-secret: sec-9a2"), "{retry_head}");

        let (endpoint, hits, heads) = mock_r2_capturing(vec![(503, "slow"), (200, "ok")]).await;
        fetcher(&endpoint)
            .get_block_object(1, "0xhash", MAX_ATTEMPTS, None, || ())
            .await
            .expect("retry must succeed");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        let retry_head = heads.lock().unwrap()[1].to_lowercase();
        assert!(retry_head.contains("authorization: aws4-hmac-sha256"), "{retry_head}");
    }

    /// A custom-domain 404 carries no S3 XML; the bare body must classify as `Missing`.
    #[tokio::test]
    async fn custom_domain_bare_404_is_missing() {
        let (domain, hits) = mock_r2(vec![(404, "<html>not found</html>")]).await;
        let err = custom_fetcher(&domain, None)
            .get_block_object(1, "0xhash", MAX_ATTEMPTS, None, || ())
            .await
            .unwrap_err();
        assert!(matches!(err, R2GetError::Missing { .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "404 must not be retried");
    }

    /// Neither Access half may leak through `Debug` — the fetcher (and its target) end up in
    /// startup logs via `Debug` formatting.
    #[test]
    fn access_credentials_never_leak_through_debug() {
        let access = CfAccessCredentials {
            client_id: "tok-3f1.access".to_string(),
            client_secret: "sec-9a2".to_string(),
        };
        let direct = format!("{access:?}");
        let via_fetcher = format!("{:?}", custom_fetcher("https://w.example.com", Some(access)));
        for rendered in [direct, via_fetcher] {
            assert!(!rendered.contains("tok-3f1"), "{rendered}");
            assert!(!rendered.contains("sec-9a2"), "{rendered}");
        }
    }

    /// Six concurrent fetches against a limit of 2 must never exceed two in-flight GETs.
    #[tokio::test]
    async fn concurrency_limit_bounds_in_flight_gets() {
        const LIMIT: usize = 2;
        const FETCHES: u64 = 6;

        // Responses held 50ms so fetches pile up behind the semaphore, then answered 404
        // (deterministic -> exactly one GET per fetch).
        let (endpoint, peak) = mock_r2_held(404, Duration::from_millis(50)).await;

        let fetcher = fetcher_with(&endpoint, Some(LIMIT), test_pacing());
        let mut fetches = tokio::task::JoinSet::new();
        for number in 0..FETCHES {
            let fetcher = fetcher.clone();
            fetches.spawn(async move {
                fetcher.get_block_object(number, "0xhash", MAX_ATTEMPTS, None, || ()).await
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
