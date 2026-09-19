//! Shared core of the two binaries' direct-from-R2 witness adapters.
//!
//! Both binaries read witness objects straight from the R2 bucket through
//! [`R2ObjectFetcher`], try it before their RPC witness chain, and hand any failure to that
//! chain on a small retry budget with no pause before surfacing. What still differs is how
//! each reads a fetched object and how long it may take: the trace server light-decodes
//! under the caller's request deadline, decode included, while the validator full-decodes
//! (proof verification needs the curve points the light decode skips) on a fixed per-block
//! stage budget that stops at the GET. What lives here is the part that is identical by
//! construction — the failure taxonomy with its metric labels, and the transport wrapper
//! (construction from a validated verdict, target accessors) — so the two adapters cannot
//! drift apart on it.

use std::{sync::Arc, time::Instant};

use alloy_primitives::B256;
use stateless_r2::{
    fetch::{CfAccessCredentials, FetchTimeouts, R2GetError, R2ObjectFetcher},
    keys,
};
use tokio::task::JoinError;

use crate::{BackoffPolicy, R2Config, WitnessDecodingError};

/// Near-tip band (in blocks) inside which an R2 witness `missing` is the expected
/// probe-ahead outcome — the uploader may plausibly not have PUT the object yet — rather
/// than a bucket hole. Sized to comfortably cover the uploader's PUT latency plus the lag of
/// whatever tip the reader measures against (the trace server's local DB tip, the
/// validator's last polled remote head), a few seconds each.
///
/// Both readers gate their `kind="missing"` bucket-integrity alarm on it: a miss inside the
/// band is recorded apart from the alarm, a miss below it means the object must exist and
/// does not.
pub const R2_FRONTIER_WINDOW: u64 = 32;

/// Failure outcome of an R2 witness fetch, shared by both binaries' adapters.
///
/// A binary whose decode runs without a deadline never produces [`Self::DecodeTimeout`]; its
/// pre-registered series for that kind stays at zero.
#[derive(Debug, thiserror::Error)]
pub enum R2WitnessError {
    /// The GET failed (absent object, transport, throttle, unexpected status, or out of
    /// deadline while queued) — see [`R2GetError`].
    #[error(transparent)]
    Get(#[from] R2GetError),
    /// The object was fetched but its bytes did not decode to a witness tuple — a corrupt
    /// witness in R2. Deterministic; not retried.
    #[error("R2 witness for block {number} (key {key}) failed to decode: {source}")]
    Decode { number: u64, key: String, source: WitnessDecodingError },
    /// The decode outran what was left of the caller's deadline — an oversized or
    /// pathological object. The blocking decode itself cannot be cancelled and finishes in
    /// the background.
    #[error("R2 witness decode for block {number} (key {key}) outran the deadline")]
    DecodeTimeout { number: u64, key: String },
    /// The decode task panicked. This is a bug in our own decoder, not a problem with the
    /// data in R2, so it is kept out of [`Self::Decode`].
    #[error("R2 witness decode task for block {number} (key {key}) panicked: {source}")]
    DecodePanicked { number: u64, key: String, source: JoinError },
}

impl R2WitnessError {
    /// Every label [`Self::kind`] can produce, for metrics pre-registration.
    pub const KINDS: &'static [&'static str] = &[
        "missing",
        "transport",
        "throttled",
        "status",
        "connect",
        "deadline",
        "decode",
        "decode_timeout",
        "decode_panicked",
    ];

    /// Stable lowercase label for this variant — the `kind` label on the R2 witness error
    /// counter. Every value returned here must appear in [`Self::KINDS`].
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Get(e) => e.kind(),
            Self::Decode { .. } => "decode",
            Self::DecodeTimeout { .. } => "decode_timeout",
            Self::DecodePanicked { .. } => "decode_panicked",
        }
    }

    /// Whether the object was absent from the bucket — the one failure a caller probing
    /// ahead of the uploader treats as expected rather than alarming.
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Get(R2GetError::Missing { .. }))
    }
}

/// Decodes a fetched witness object with `decode` on the blocking pool — zstd + bincode over
/// a multi-MB witness is CPU-bound and must stay off the runtime — mapping both failure modes
/// onto [`R2WitnessError`].
///
/// `deadline` is the caller's budget for the decode: `Some` bounds it (an oversized or
/// pathological object must not eat what the caller reserved for its fallback, and an already
/// elapsed deadline skips the decode entirely — nothing would wait for it), while `None` lets
/// it run to completion. A decode abandoned on the deadline cannot be cancelled and finishes
/// in the background.
pub async fn decode_on_blocking_pool<T: Send + 'static>(
    bytes: impl AsRef<[u8]> + Send + 'static,
    number: u64,
    hash: B256,
    deadline: Option<Instant>,
    decode: impl FnOnce(&[u8]) -> Result<T, WitnessDecodingError> + Send + 'static,
) -> Result<T, R2WitnessError> {
    let key = || keys::block_object_key(number, hash);
    if deadline.is_some_and(|d| Instant::now() >= d) {
        return Err(R2WitnessError::DecodeTimeout { number, key: key() });
    }
    let task = tokio::task::spawn_blocking(move || decode(bytes.as_ref()));
    let joined = match deadline {
        Some(d) => match tokio::time::timeout_at(d.into(), task).await {
            Ok(joined) => joined,
            Err(_) => return Err(R2WitnessError::DecodeTimeout { number, key: key() }),
        },
        None => task.await,
    };
    match joined {
        Ok(Ok(decoded)) => Ok(decoded),
        Ok(Err(source)) => Err(R2WitnessError::Decode { number, key: key(), source }),
        Err(source) => Err(R2WitnessError::DecodePanicked { number, key: key(), source }),
    }
}

/// What the shared transport constructor publishes about the target it built, implemented by
/// each binary so the constructor never needs to know a metric-name prefix.
///
/// Mirrors [`RpcMetrics`](crate::RpcMetrics), which does the same for the RPC client: the
/// binaries own their metric names, this crate owns when the values are known.
pub trait R2Metrics: Send + Sync {
    /// The configured target's label, known at startup.
    fn on_target(&self, target: &'static str);

    /// How many HTTP/2 connections the custom-domain target spreads its GETs over. Not called
    /// for the S3 target, where one client already opens a socket per in-flight GET and the
    /// count is not a property of the transport.
    fn on_connections(&self, connections: usize);

    /// The protocol the custom domain actually negotiated. Only knowable once a response has
    /// been seen, so this fires from the fetcher rather than at startup.
    fn on_negotiated_version(&self, version: &'static str);
}

/// The shared transport of the two R2 witness adapters: an [`R2ObjectFetcher`] plus the
/// construction and target accessors both binaries would otherwise duplicate verbatim.
/// The fetcher's `Debug` redacts the credentials.
#[derive(Debug)]
pub struct R2WitnessTransport {
    fetcher: R2ObjectFetcher,
    /// The configured in-flight GET cap, retained here because the fetcher decomposes it
    /// into per-connection permits and cannot report the configured value back.
    max_concurrent_requests: Option<usize>,
}

impl R2WitnessTransport {
    /// Builds a transport from an R2 endpoint origin, bucket, and bucket-scoped S3
    /// credentials.
    ///
    /// `timeouts` bounds each individual GET (end-to-end and connect), `retry_backoff`
    /// paces the fetcher's internal retries, and `max_concurrent_requests` caps in-flight
    /// GETs (`None` = unlimited, `Some(0)` clamps to 1). Fails if the endpoint is not a
    /// bare `scheme://host[:port]` origin or the HTTP client cannot be built.
    pub fn new(
        endpoint: &str,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        timeouts: FetchTimeouts,
        retry_backoff: BackoffPolicy,
        max_concurrent_requests: Option<usize>,
    ) -> eyre::Result<Self> {
        let fetcher = R2ObjectFetcher::new(
            endpoint,
            bucket,
            access_key_id,
            secret_access_key,
            timeouts,
            retry_backoff,
            max_concurrent_requests,
        )
        .map_err(|e| eyre::eyre!(e))?;
        Ok(Self { fetcher, max_concurrent_requests })
    }

    /// Builds a transport that fetches unsigned through a Cloudflare custom domain
    /// fronting the bucket (h2-multiplexed, edge-cacheable), with optional Cloudflare
    /// Access service-token headers. `on_version_observed` receives the negotiated HTTP
    /// version's metric label once known (each binary passes its own recorder); the
    /// remaining parameters mean what they mean on [`Self::new`].
    pub fn new_custom_domain(
        domain: &str,
        access: Option<CfAccessCredentials>,
        timeouts: FetchTimeouts,
        retry_backoff: BackoffPolicy,
        max_concurrent_requests: Option<usize>,
        connections: usize,
        on_version_observed: impl Fn(&'static str) + Send + Sync + 'static,
    ) -> eyre::Result<Self> {
        let fetcher = R2ObjectFetcher::new_custom_domain(
            domain,
            access,
            timeouts,
            retry_backoff,
            max_concurrent_requests,
            connections,
        )
        .map(|fetcher| fetcher.on_version_observed(on_version_observed))
        .map_err(|e| eyre::eyre!(e))?;
        Ok(Self { fetcher, max_concurrent_requests })
    }

    /// Builds the transport a validated [`R2Config`] selects, or `None` when no R2 target is
    /// configured, publishing what it built through `metrics`.
    ///
    /// This is the one place either binary turns a verdict into a transport, taking every
    /// target-dependent value — the in-flight cap included — from the verdict rather than
    /// from the caller's flags. The caller logs what it built from the accessors below, in its
    /// own words.
    pub fn from_config(
        config: R2Config,
        timeouts: FetchTimeouts,
        retry_backoff: BackoffPolicy,
        metrics: Arc<dyn R2Metrics>,
    ) -> eyre::Result<Option<Self>> {
        let transport = match config {
            R2Config::None => return Ok(None),
            R2Config::CustomDomain { domain, access, connections, max_concurrent_requests } => {
                let observer = Arc::clone(&metrics);
                let transport = Self::new_custom_domain(
                    &domain,
                    access,
                    timeouts,
                    retry_backoff,
                    max_concurrent_requests,
                    connections,
                    move |version| observer.on_negotiated_version(version),
                )?;
                // Read back off the transport rather than echoing the configured count: the
                // gauge must report the connections that exist.
                metrics.on_connections(transport.connections());
                transport
            }
            R2Config::S3 {
                endpoint,
                bucket,
                access_key_id,
                secret_access_key,
                max_concurrent_requests,
            } => Self::new(
                &endpoint,
                bucket,
                access_key_id,
                secret_access_key.as_ref().to_owned(),
                timeouts,
                retry_backoff,
                max_concurrent_requests,
            )?,
        };
        metrics.on_target(transport.target_label());
        Ok(Some(transport))
    }

    /// The underlying fetcher, for the adapter's own GETs.
    pub fn fetcher(&self) -> &R2ObjectFetcher {
        &self.fetcher
    }

    /// The configured target's origin, for startup logging (see
    /// [`R2ObjectFetcher::origin`]).
    pub fn origin(&self) -> &str {
        self.fetcher.origin()
    }

    /// The configured target's metric label (see [`R2ObjectFetcher::target_label`]).
    pub const fn target_label(&self) -> &'static str {
        self.fetcher.target_label()
    }

    /// How many HTTP/2 connections the transport spreads its GETs over, for startup
    /// logging (see [`R2ObjectFetcher::connections`]).
    pub fn connections(&self) -> usize {
        self.fetcher.connections()
    }

    /// The configured cap on in-flight GETs (`None` = unlimited; see [`Self::new`]), for
    /// startup logging.
    pub fn max_concurrent_requests(&self) -> Option<usize> {
        self.max_concurrent_requests
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn test_timeouts() -> FetchTimeouts {
        FetchTimeouts {
            per_attempt: Duration::from_secs(5),
            connect: stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT,
        }
    }

    fn test_backoff() -> BackoffPolicy {
        BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20))
    }

    /// Every fetch-level kind must appear in the pre-registered [`R2WitnessError::KINDS`]
    /// — a new [`R2GetError`] kind escaping metric pre-registration would drift silently
    /// otherwise. One copy here guards both binaries' pre-registration loops.
    #[test]
    fn kinds_cover_all_fetch_kinds() {
        assert!(R2GetError::KINDS.iter().all(|k| R2WitnessError::KINDS.contains(k)));
    }

    /// Construction errors from the underlying fetcher must surface through the eyre
    /// conversion, on both targets — one copy here covers both binaries' adapters.
    #[test]
    fn construction_rejects_a_target_carrying_a_path() {
        let s3 = R2WitnessTransport::new(
            "https://acc.r2.cloudflarestorage.com/witness-mainnet",
            "witness-mainnet".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            test_timeouts(),
            test_backoff(),
            None,
        )
        .unwrap_err();
        assert!(s3.to_string().contains("Invalid R2 endpoint"), "{s3}");

        let custom_domain = R2WitnessTransport::new_custom_domain(
            "https://witness.example.com/witness-mainnet",
            None,
            test_timeouts(),
            test_backoff(),
            None,
            1,
            |_| {},
        )
        .unwrap_err();
        assert!(custom_domain.to_string().contains("Invalid R2 custom domain"), "{custom_domain}");
    }

    /// A decode whose deadline is already gone is abandoned before it starts — nothing
    /// would wait for it — while a deadline-less decode runs to completion.
    #[tokio::test]
    async fn decode_respects_an_elapsed_deadline_and_runs_without_one() {
        let elapsed = |_: &[u8]| -> Result<usize, WitnessDecodingError> {
            panic!("an elapsed deadline must not start the decode")
        };
        let err =
            decode_on_blocking_pool(vec![0_u8; 8], 1, B256::ZERO, Some(Instant::now()), elapsed)
                .await
                .expect_err("an already-elapsed deadline must abandon the decode");
        assert!(matches!(err, R2WitnessError::DecodeTimeout { .. }), "{err}");
        assert_eq!(err.kind(), "decode_timeout");

        let decoded = decode_on_blocking_pool(vec![7_u8; 4], 1, B256::ZERO, None, |bytes| {
            Ok::<usize, WitnessDecodingError>(bytes.len())
        })
        .await
        .expect("a deadline-less decode must run");
        assert_eq!(decoded, 4);
    }
}
