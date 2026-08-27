//! Shared core of the two binaries' direct-from-R2 witness adapters.
//!
//! Each binary reads witness objects straight from the R2 bucket through
//! [`R2ObjectFetcher`], but decodes and paces them differently: the trace server
//! light-decodes under a request deadline with no failure pauses, the validator
//! full-decodes with surfaced-failure pacing for its pipeline fetcher. What lives here is
//! the part that is identical by construction — the failure taxonomy with its metric
//! labels, and the transport wrapper (construction, target accessors) — so the two
//! adapters cannot drift apart on it.

use stateless_r2::fetch::{
    CfAccessCredentials, FetchTimeouts, R2GetError, R2ObjectFetcher, RetryPacing,
};
use tokio::task::JoinError;

use crate::{BackoffPolicy, WitnessDecodingError};

/// Failure outcome of an R2 witness fetch, shared by both binaries' adapters.
///
/// A binary whose fetches pass no deadline never produces [`Self::DecodeTimeout`] (or the
/// fetch-level `deadline` kind); its pre-registered series for those kinds stay at zero.
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

    /// Whether the object was absent from the bucket — the one failure the trace server's
    /// frontier probe treats as expected rather than alarming.
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Get(R2GetError::Missing { .. }))
    }

    /// Whether an immediate retry against the same endpoint could plausibly succeed
    /// (transport blips, 429, 5xx). Every other variant is deterministic and is surfaced
    /// without retrying.
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Get(e) if e.is_retryable())
    }
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

/// The fetcher's pacing view of a [`BackoffPolicy`] — the adapter-layer conversion that
/// keeps `stateless-r2` free of a dependency on this workspace's backoff type.
fn pacing(backoff: &BackoffPolicy) -> RetryPacing {
    RetryPacing { initial: backoff.initial, max: backoff.max }
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
            pacing(&retry_backoff),
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
            pacing(&retry_backoff),
            max_concurrent_requests,
            connections,
        )
        .map(|fetcher| fetcher.on_version_observed(on_version_observed))
        .map_err(|e| eyre::eyre!(e))?;
        Ok(Self { fetcher, max_concurrent_requests })
    }

    /// The underlying fetcher, for the adapter's own GETs and pacing reads.
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
    use super::*;

    /// Every fetch-level kind must appear in the pre-registered [`R2WitnessError::KINDS`]
    /// — a new [`R2GetError`] kind escaping metric pre-registration would drift silently
    /// otherwise. One copy here guards both binaries' pre-registration loops.
    #[test]
    fn kinds_cover_all_fetch_kinds() {
        assert!(R2GetError::KINDS.iter().all(|k| R2WitnessError::KINDS.contains(k)));
    }
}
