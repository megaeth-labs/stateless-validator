//! Minimal AWS Signature Version 4 signer for S3-compatible object storage.
//!
//! The witness uploaders write to Cloudflare R2 through R2's S3 API. R2 authenticates requests with
//! AWS `SigV4` (`service = "s3"`, `region = "auto"`), so this module implements just the slice of
//! `SigV4` the uploaders need: signing a single `PUT` / `GET` / `DELETE` request whose payload is
//! fully buffered in memory.
//!
//! Only the "signed payload" mode is implemented (`x-amz-content-sha256 = hex(sha256(body))`),
//! which is appropriate because compressed witnesses are at most tens of MiB and are already held
//! as buffered bytes on the upload path. Streaming / `UNSIGNED-PAYLOAD` is intentionally omitted.
//!
//! Reference: <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// `SigV4` signing algorithm identifier.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The `aws4_request` terminator used by both the credential scope and the signing key.
const REQUEST_TYPE: &str = "aws4_request";

/// Characters that do **not** need percent-encoding in a `SigV4` canonical URI path segment.
///
/// AWS leaves the RFC 3986 *unreserved* set (`A-Z a-z 0-9 - _ . ~`) untouched and percent-encodes
/// everything else. `NON_ALPHANUMERIC` encodes every non-alphanumeric byte, so we remove the four
/// unreserved punctuation characters from it. The path separator `/` is handled by the caller,
/// which encodes each segment independently and rejoins them with `/`.
const URI_SEGMENT: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// A single HTTP header (lowercase name, value) that participates in signing and is sent on the
/// request.
pub type Header = (String, String);

/// Region placed in the credential scope. R2 ignores the value but requires a non-empty scope;
/// Cloudflare's documented convention is the literal string `"auto"`. Never varies by deployment,
/// so hardcoded.
const REGION: &str = "auto";

/// Holds the long-lived credentials and scope used to sign R2 requests.
#[derive(Clone)]
pub struct SigV4Signer {
    access_key_id: String,
    secret_access_key: String,
    /// Always [`REGION`].
    region: String,
    /// Always `"s3"` for R2.
    service: String,
}

impl std::fmt::Debug for SigV4Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the credentials.
        f.debug_struct("SigV4Signer")
            .field("access_key_id", &"[redacted]")
            .field("secret_access_key", &"[redacted]")
            .field("region", &self.region)
            .field("service", &self.service)
            .finish()
    }
}

impl SigV4Signer {
    /// Builds a signer from bucket-scoped R2 credentials.
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            region: REGION.to_string(),
            service: "s3".to_string(),
        }
    }

    /// Signs a request and returns the complete set of headers to attach to it.
    ///
    /// `host` is the request host with no scheme or trailing slash (e.g.
    /// `<account>.r2.cloudflarestorage.com`). `canonical_uri` is the absolute, already
    /// percent-encoded request path (see [`encode_uri_path`]). `extra_headers` are additional
    /// lowercase headers that must be covered by the signature — typically the `x-amz-meta-*`
    /// custom-metadata headers; their names must be lowercase and they must also be sent on the
    /// wire exactly as signed.
    ///
    /// The returned vector contains `extra_headers` plus the three computed headers
    /// (`x-amz-date`, `x-amz-content-sha256`, `authorization`); the caller attaches every entry to
    /// the outgoing request.
    // The parameters mirror the inputs to the SigV4 canonical request; bundling them into a struct
    // would only add indirection at the single call site in `client::put_object`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        method: &str,
        host: &str,
        canonical_uri: &str,
        canonical_query: &str,
        extra_headers: &[Header],
        payload: &[u8],
        now: DateTime<Utc>,
    ) -> Vec<Header> {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(payload));

        // Assemble the full signed-header set: host + the two amz headers + caller extras.
        let mut headers: Vec<Header> = Vec::with_capacity(extra_headers.len() + 3);
        headers.push(("host".to_string(), host.to_string()));
        headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
        headers.push(("x-amz-date".to_string(), amz_date.clone()));
        headers.extend(extra_headers.iter().cloned());
        // Canonical headers are sorted by lowercase name; values are trimmed.
        headers.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers: String =
            headers.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
        let signed_headers: String =
            headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");

        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        let credential_scope =
            format!("{date_stamp}/{}/{}/{REQUEST_TYPE}", self.region, self.service);
        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{credential_scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let signing_key = self.signing_key(&date_stamp);
        let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "{ALGORITHM} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id
        );

        // Return exactly the signed set minus `host` (the HTTP client sets it from the URL) plus
        // the computed authorization — reusing the signed list makes sent == signed by
        // construction.
        let mut out: Vec<Header> = headers.into_iter().filter(|(name, _)| name != "host").collect();
        out.push(("authorization".to_string(), authorization));
        out
    }

    /// Derives the `SigV4` signing key for the given date via the four-step HMAC chain.
    fn signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date =
            hmac(format!("AWS4{}", self.secret_access_key).as_bytes(), date_stamp.as_bytes());
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, self.service.as_bytes());
        hmac(&k_service, REQUEST_TYPE.as_bytes())
    }
}

/// Computes `HMAC-SHA256(key, data)`.
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Percent-encodes an object key into a `SigV4` canonical URI path.
///
/// Each `/`-delimited segment is encoded with the RFC 3986 unreserved set preserved, then the
/// segments are rejoined with `/`. A leading `/` is always present. R2 object keys produced by the
/// uploaders (`block/<range>/<n>.<hash>`, `attr/...`, `num/...`) are already within the unreserved
/// set, but this keeps the signer correct for any key.
pub fn encode_uri_path(bucket: &str, key: &str) -> String {
    let mut path = String::from("/");
    path.push_str(&encode_segment(bucket));
    for segment in key.split('/') {
        path.push('/');
        path.push_str(&encode_segment(segment));
    }
    path
}

/// Percent-encodes a single path segment with the `SigV4` unreserved set.
fn encode_segment(segment: &str) -> String {
    percent_encoding::utf8_percent_encode(segment, URI_SEGMENT).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS-published test vector for the `SigV4` signing-key derivation.
    ///
    /// From <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>:
    /// secret `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, date `20150830`, region `us-east-1`,
    /// service `iam` yields the documented signing key.
    #[test]
    fn signing_key_matches_aws_reference_vector() {
        let signer = SigV4Signer {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(), /* pragma: allowlist secret */
            region: "us-east-1".to_string(),
            service: "iam".to_string(),
        };
        let key = signer.signing_key("20150830");
        assert_eq!(
            hex::encode(key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn encode_uri_path_preserves_unreserved_and_separators() {
        // Witness keys only contain unreserved characters plus `/`, so they pass through unchanged.
        let path = encode_uri_path("witness-testnet", "block/2000_2999/2045.0x23758c4d28eed6");
        assert_eq!(path, "/witness-testnet/block/2000_2999/2045.0x23758c4d28eed6");
    }

    #[test]
    fn encode_uri_path_escapes_reserved_characters() {
        // Defensive: a space and a colon must be percent-encoded, the `/` separators must not.
        let path = encode_uri_path("b", "a b/c:d");
        assert_eq!(path, "/b/a%20b/c%3Ad");
    }

    #[test]
    fn sign_produces_authorization_and_amz_headers() {
        let signer = SigV4Signer::new("access".to_string(), "secret".to_string());
        let now = DateTime::parse_from_rfc3339("2026-06-13T12:00:00Z").unwrap().with_timezone(&Utc);
        let headers = signer.sign(
            "PUT",
            "acc.r2.cloudflarestorage.com",
            "/witness-testnet/block/2000_2999/2045.0xabc",
            "",
            &[("x-amz-meta-compression".to_string(), "zstd".to_string())],
            b"payload",
            now,
        );

        let content_sha = headers
            .iter()
            .find(|(k, _)| k == "x-amz-content-sha256")
            .map(|(_, v)| v.clone())
            .expect("content sha header present");
        assert_eq!(content_sha, hex::encode(Sha256::digest(b"payload")));

        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone())
            .expect("authorization header present");
        // Credential scope, the signed-header list (sorted, includes the meta header), and a
        // signature must all be present.
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=access/20260613/auto/s3/aws4_request")
        );
        assert!(
            auth.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-compression"
            )
        );
        assert!(auth.contains("Signature="));
        // The custom-metadata header is echoed back for the caller to send.
        assert!(headers.iter().any(|(k, v)| k == "x-amz-meta-compression" && v == "zstd"));
        // `host` is not returned (the HTTP client sets it from the URL).
        assert!(!headers.iter().any(|(k, _)| k == "host"));
    }

    /// Golden wire vector: the byte-exact header set for a complete signed request, computed with
    /// an independent SigV4 implementation (Python `hashlib`/`hmac` over the AWS-documented
    /// algorithm) — not with this code — so the signer is certified against the algorithm rather
    /// than against itself. Any change to canonicalization, header ordering, credential scope, or
    /// the HMAC chain flips the pinned signature.
    #[test]
    fn sign_matches_independent_golden_vector() {
        let signer = SigV4Signer::new("access".to_string(), "secret".to_string());
        let now = DateTime::parse_from_rfc3339("2026-06-13T12:00:00Z").unwrap().with_timezone(&Utc);
        let headers = signer.sign(
            "PUT",
            "acc.r2.cloudflarestorage.com",
            "/witness-testnet/block/2000_2999/2045.0xabc",
            "",
            &[("x-amz-meta-compression".to_string(), "zstd".to_string())],
            b"payload",
            now,
        );

        let expected = [
            (
                "x-amz-content-sha256",
                "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
            ),
            ("x-amz-date", "20260613T120000Z"),
            ("x-amz-meta-compression", "zstd"),
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=access/20260613/auto/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-compression, \
                 Signature=dbbe53136588499c6798a928641af52e8dedf930a8cdd20cf138d4f8281fb167",
            ),
        ];
        assert_eq!(headers.len(), expected.len());
        for (name, value) in expected {
            assert_eq!(
                headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()),
                Some(value),
                "header {name} mismatch",
            );
        }
    }
}
