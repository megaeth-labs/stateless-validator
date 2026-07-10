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

use std::time::Duration;

use alloy_primitives::B256;
use bytes::Bytes;
use chrono::Utc;
use reqwest::Client;
use salt::SaltWitness;
use stateless_common::{decode_witness_payload, witness_encoding::WitnessDecodingError};
use stateless_core::withdrawals::MptWitness;
use stateless_r2::{
    endpoint::parse_endpoint,
    keys,
    sigv4::{SigV4Signer, encode_uri_path},
};
use tokio::task::JoinError;
use tracing::{trace, warn};

/// Max retry rounds for retryable (transport/429/5xx) failures before surfacing an error.
const MAX_RETRIES: usize = 8;
/// First retry sleep; doubles each round up to [`MAX_BACKOFF`].
const INITIAL_BACKOFF: Duration = Duration::from_millis(500);
/// Upper bound on any single retry sleep.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Throttle applied before surfacing a `Missing` (404), so the pipeline's immediate re-enqueue of
/// a failed fetch does not hot-spin GETs against R2 on a genuine gap.
const MISSING_THROTTLE: Duration = Duration::from_secs(2);

/// Failure outcome of an R2 witness fetch.
#[derive(Debug, thiserror::Error)]
pub enum R2WitnessError {
    /// The primary object is absent from the bucket (HTTP 404) — a completeness gap in R2 for
    /// blocks known to have a witness.
    #[error(
        "R2 witness MISSING for block {number} (key {key}): object not found (404) — R2 completeness gap"
    )]
    Missing { number: u64, key: String },
    /// Transport-level failure (connection reset/timeout) — the endpoint is effectively
    /// unreachable. Retried internally with backoff before surfacing.
    #[error("R2 transport failure for block {number} (key {key}): {source}")]
    Transport { number: u64, key: String, source: reqwest::Error },
    /// R2 asked us to slow down (429) or returned a server-side error (5xx, including R2's 503
    /// overload / SlowDown). Retried internally with backoff before surfacing.
    #[error("R2 throttled/server error {status} for block {number} (key {key}): {body}")]
    Throttled { number: u64, key: String, status: u16, body: String },
    /// A non-success status unlikely to clear on retry (typically 4xx other than 429 — e.g. 403
    /// SignatureDoesNotMatch from bad credentials or a malformed endpoint).
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
    /// Whether an immediate retry against the same endpoint could plausibly succeed (transport
    /// blips, 429, 5xx). Every other variant is deterministic and is surfaced without retrying.
    const fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport { .. } | Self::Throttled { .. })
    }
}

/// Outcome of a single (non-retrying) GET attempt.
enum Attempt {
    /// 2xx with the object body. Held as [`Bytes`] (refcounted) so the multi-MB witness is never
    /// copied between the HTTP response and the decoder.
    Found(Bytes),
    /// 404 — object absent.
    Missing,
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
    /// Transport/429/5xx failures are retried with backoff up to [`MAX_RETRIES`] times;
    /// `Missing` (404) and `Decode` failures are deterministic and surface immediately.
    pub async fn get_witness(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let key = keys::block_object_key(number, hash);
        let mut backoff = INITIAL_BACKOFF;
        let mut attempt = 0usize;

        let bytes = loop {
            attempt += 1;
            match self.get_object(number, &key).await {
                Ok(Attempt::Found(bytes)) => break bytes,
                Ok(Attempt::Missing) => {
                    // Deterministic gap. Sleep briefly first: the fetcher re-enqueues a failed
                    // fetch immediately, so returning instantly would hot-loop 404s against R2.
                    tokio::time::sleep(MISSING_THROTTLE).await;
                    return Err(R2WitnessError::Missing { number, key });
                }
                Err(e) => {
                    if !e.is_retryable() || attempt > MAX_RETRIES {
                        return Err(e);
                    }
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
                Ok(witness)
            }
            Ok(Err(source)) => Err(R2WitnessError::Decode { number, key, source }),
            Err(source) => Err(R2WitnessError::DecodePanicked { number, key, source }),
        }
    }

    /// Performs one SigV4-signed GET and classifies the response. No retry.
    async fn get_object(&self, number: u64, key: &str) -> Result<Attempt, R2WitnessError> {
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
            let bytes = response.bytes().await.map_err(transport)?;
            return Ok(Attempt::Found(bytes));
        }
        let code = status.as_u16();
        if code == 404 {
            return Ok(Attempt::Missing);
        }
        let body = response.text().await.unwrap_or_default();
        let key = key.to_string();
        if code == 429 || code >= 500 {
            Err(R2WitnessError::Throttled { number, key, status: code, body })
        } else {
            Err(R2WitnessError::Status { number, key, status: code, body })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

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
}
