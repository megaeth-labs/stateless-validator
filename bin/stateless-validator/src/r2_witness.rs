//! Direct-from-R2 witness source for end-to-end validation of the migrated archive.
//!
//! The production validator fetches witnesses over `mega_getBlockWitness`, which transparently
//! falls back to KV — so a block validating successfully does **not** prove its witness actually
//! came from R2. This client bypasses the RPC entirely: it fetches the primary witness object
//! straight from the R2 bucket over the S3 API (a SigV4-signed `GET`), decompresses it, and
//! returns the same `(SaltWitness, MptWitness)` tuple the RPC path yields. Pointing the validator
//! at this source and replaying a block range therefore proves every witness is present and
//! correct in R2 alone.
//!
//! The object-key layout, SigV4 signer, and endpoint parsing are reused from `megaeth-witness-r2`
//! — the very crate the witness generator and the replayer uploader write with — so the read path
//! here cannot drift from the write path. The primary object body is
//! `zstd(bincode-legacy((SaltWitness, MptWitness)))` (see the uploader's `encode_witness_payload`),
//! which [`stateless_common::decode_witness_payload`] inverts exactly.

use std::time::Duration;

use alloy_primitives::B256;
use bytes::Bytes;
use chrono::Utc;
use megaeth_witness_r2::{
    endpoint::parse_endpoint,
    keys,
    sigv4::{SigV4Signer, encode_uri_path},
};
use reqwest::Client;
use salt::SaltWitness;
use stateless_common::{decode_witness_payload, witness_encoding::WitnessDecodingError};
use stateless_core::withdrawals::MptWitness;
use tokio::task::JoinError;
use tracing::{Level, debug, enabled, trace, warn};

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
    /// The primary object is absent from the bucket (HTTP 404). For blocks known to have a
    /// witness this is a genuine completeness gap in R2 — the whole point of the validation run
    /// is to prove this never happens.
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
    /// — a corrupt witness in R2. Deterministic; a finding, not retried.
    #[error("R2 witness for block {number} (key {key}) failed to decode: {source}")]
    Decode { number: u64, key: String, source: WitnessDecodingError },
    /// The decode task panicked. This is a bug in our own decoder, not evidence about the archive,
    /// so it is kept out of [`Self::Decode`] — a panic must never masquerade as an R2 finding.
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

    /// The primary witness object key for `(number, hash)`: `block/{range}/{number}.{hash}`.
    ///
    /// Built from the same `megaeth-witness-r2` bucketing constants the uploader uses, so it is
    /// byte-identical to the key that was written. `hash` renders via `B256`'s `Display`
    /// (lowercase `0x` + 64 hex); the pinned test below guards that against drift.
    fn block_key(number: u64, hash: B256) -> String {
        let range_start = keys::block_range_prefix(number);
        let range_end = range_start + keys::BLOCK_RANGE_SIZE - 1;
        format!("{}/{range_start}_{range_end}/{number}.{hash}", keys::BLOCK_PREFIX)
    }

    /// Fetches and decodes the witness for `(number, hash)` from R2.
    ///
    /// Retryable failures (transport/429/5xx) are retried with exponential backoff up to
    /// [`MAX_RETRIES`] times. `Missing` (404) and `Decode` failures are deterministic and surface
    /// immediately as findings.
    pub async fn get_witness(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness), R2WitnessError> {
        let key = Self::block_key(number, hash);
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
            // Snapshot the response headers before `bytes()` consumes `response` — but only when
            // the log will actually emit, since this sits on the per-block hot path. These prove
            // the witness came from R2: `cf-ray` / `x-amz-request-id` are Cloudflare/S3 request
            // ids, and the `x-amz-meta-*` set is the custom metadata the migration/uploader wrote
            // onto the object — the RPC/KV witness path carries none of it.
            let headers = enabled!(Level::DEBUG).then(|| response.headers().clone());
            let bytes = response.bytes().await.map_err(transport)?;
            if let Some(headers) = headers {
                let hdr =
                    |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
                debug!(
                    block_number = number,
                    bucket = %self.bucket,
                    key,
                    http_status = status.as_u16(),
                    bytes = bytes.len(),
                    content_type = hdr("content-type"),
                    etag = hdr("etag"),
                    last_modified = hdr("last-modified"),
                    cf_ray = hdr("cf-ray"),
                    x_amz_request_id = hdr("x-amz-request-id"),
                    x_amz_meta_compression = hdr("x-amz-meta-compression"),
                    x_amz_meta_original_size = hdr("x-amz-meta-original-size"),
                    x_amz_meta_compressed_size = hdr("x-amz-meta-compressed-size"),
                    x_amz_meta_sha256 = hdr("x-amz-meta-sha256"),
                    x_amz_meta_parent_hash = hdr("x-amz-meta-parent-hash"),
                    x_amz_meta_attr_hash = hdr("x-amz-meta-attr-hash"),
                    "witness fetched from R2 (S3 GET)",
                );
            }
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

    /// Pins the object-key format to a real migrated mainnet key. If `B256`'s `Display` ever
    /// stopped rendering full lowercase `0x` hex, every GET would 404 — this catches that at
    /// build time rather than as a silent wall of "missing" in production.
    #[test]
    fn block_key_matches_migrated_layout() {
        let hash =
            B256::from_str("0x05dd41e545b25db0ce04f628e6e1705232240c70a0435c8233ac4479176fe6b0")
                .unwrap();
        assert_eq!(
            R2WitnessClient::block_key(6_632_136, hash),
            "block/6632000_6632999/6632136.\
             0x05dd41e545b25db0ce04f628e6e1705232240c70a0435c8233ac4479176fe6b0",
        );
    }

    #[test]
    fn block_key_buckets_on_thousands() {
        let h = B256::ZERO;
        assert!(R2WitnessClient::block_key(0, h).starts_with("block/0_999/0."));
        assert!(R2WitnessClient::block_key(999, h).starts_with("block/0_999/999."));
        assert!(R2WitnessClient::block_key(1000, h).starts_with("block/1000_1999/1000."));
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
