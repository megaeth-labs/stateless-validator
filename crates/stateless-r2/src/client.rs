//! Signed `PUT` helper and response classification for R2 uploads.
//!
//! [`put_object`] signs a single object `PUT` with `SigV4` (signed-payload mode) and sends it,
//! mapping the outcome to [`R2Error`]. Both uploaders share this so the set of statuses that should
//! trigger a backoff stays identical between the two binaries.

use bytes::Bytes;
use chrono::Utc;
use reqwest::Client;

use crate::sigv4::{Header, SigV4Signer, encode_uri_path};

/// Failure outcome of a signed R2 `PUT`.
#[derive(Debug)]
pub enum R2Error {
    /// The endpoint host was empty (endpoint not configured or not a valid URL); nothing was sent.
    InvalidEndpoint,
    /// The request never produced an HTTP response — a transport-level failure such as a
    /// connection timeout or reset. The endpoint is effectively unreachable, so the caller
    /// should back off before retrying.
    Transport(String),
    /// The endpoint asked us to slow down (`429`) or returned a server-side error (`5xx`,
    /// including R2's `503` overload / `SlowDown`). Retrying without a backoff would keep
    /// hammering a struggling endpoint, so the caller should back off.
    Throttled {
        /// HTTP status code returned by R2.
        status: u16,
        /// Response body (best-effort), included for diagnostics.
        body: String,
    },
    /// A non-success status that is unlikely to clear on an immediate retry (typically a `4xx`
    /// other than `429`). The caller may requeue but a pool-wide backoff is not warranted.
    Status {
        /// HTTP status code returned by R2.
        status: u16,
        /// Response body (best-effort), included for diagnostics.
        body: String,
    },
}

impl R2Error {
    /// Whether this failure means the endpoint itself is unhealthy/overloaded and the caller
    /// should apply a backoff (transport failures, `429`, and any `5xx`) rather than retry
    /// immediately.
    pub const fn is_backoff_worthy(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Throttled { .. })
    }
}

impl std::fmt::Display for R2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEndpoint => write!(f, "R2 endpoint is not a valid URL"),
            Self::Transport(err) => write!(f, "R2 request transport failure: {err}"),
            Self::Throttled { status, body } => {
                write!(f, "R2 throttled or server error: {status} - {body}")
            }
            Self::Status { status, body } => write!(f, "R2 request failed: {status} - {body}"),
        }
    }
}

impl std::error::Error for R2Error {}

/// Uploads a single object to R2 with a SigV4-signed `PUT` request.
///
/// `endpoint` is the origin (`scheme://host`, no trailing slash), `host` the `SigV4` canonical host
/// (`host[:port]`), `bucket`/`key` the destination object, `body` the object bytes, and `meta` the
/// `x-amz-meta-*` headers to store alongside the object (empty for pointer objects).
///
/// `body` is a [`Bytes`], so the caller can hand off a cheap clone of an already-buffered payload;
/// `reqwest` consumes it without an extra copy.
// The connection parameters (client/signer/endpoint/host/bucket) live on the caller's uploader
// struct; passing them through keeps this helper stateless and avoids a second copy of that state.
#[allow(clippy::too_many_arguments)]
pub async fn put_object(
    client: &Client,
    signer: &SigV4Signer,
    endpoint: &str,
    host: &str,
    bucket: &str,
    key: &str,
    body: Bytes,
    meta: &[Header],
) -> Result<(), R2Error> {
    if host.is_empty() {
        return Err(R2Error::InvalidEndpoint);
    }
    let canonical_uri = encode_uri_path(bucket, key);
    let url = format!("{endpoint}{canonical_uri}");
    let signed = signer.sign("PUT", host, &canonical_uri, "", meta, &body, Utc::now());

    let mut request = client.put(&url).body(body);
    for (name, value) in signed {
        request = request.header(name, value);
    }
    let response = request.send().await.map_err(|err| R2Error::Transport(err.to_string()))?;
    classify_response(response).await
}

/// Whether a non-success status (`429` or any `5xx`) is backoff-worthy throttling, as opposed to
/// one that will not clear on retry. The single definition of the throttle set — the write path
/// (`classify_response`) and the validator's R2 reader both classify with it.
pub const fn is_throttle_status(status: u16) -> bool {
    status == 429 || status >= 500
}

/// Classifies an R2 (S3 API) response into [`R2Error`], treating [`is_throttle_status`] statuses
/// as backoff-worthy throttling and every other non-success status as a plain failure.
async fn classify_response(response: reqwest::Response) -> Result<(), R2Error> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let code = status.as_u16();
    let body = response.text().await.unwrap_or_default();
    if is_throttle_status(code) {
        Err(R2Error::Throttled { status: code, body })
    } else {
        Err(R2Error::Status { status: code, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_worthy_covers_transport_and_throttled_only() {
        assert!(R2Error::Transport("timeout".to_string()).is_backoff_worthy());
        assert!(R2Error::Throttled { status: 429, body: String::new() }.is_backoff_worthy());
        assert!(R2Error::Throttled { status: 503, body: String::new() }.is_backoff_worthy());
        assert!(R2Error::Throttled { status: 500, body: String::new() }.is_backoff_worthy());
        assert!(!R2Error::Status { status: 403, body: String::new() }.is_backoff_worthy());
        assert!(!R2Error::InvalidEndpoint.is_backoff_worthy());
    }
}
