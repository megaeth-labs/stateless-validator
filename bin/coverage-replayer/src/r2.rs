//! Direct-from-R2 witness source for the replayer, on the zero-validation
//! light-decode path.
//!
//! Same wire objects as the validator's `--witness-source r2`: the primary
//! object body is `zstd(bincode-legacy((SaltWitness, MptWitness)))`, keyed by
//! `stateless-r2`'s layout so the read path cannot drift from the uploaders.
//! Unlike the validator, the body is decoded with
//! [`decode_witness_payload_light`] — the replayer never verifies proofs, so
//! no elliptic-curve work is spent.
//!
//! Error handling is deliberately minimal: every failure surfaces as an
//! `eyre` error with full context, and the backfill fetcher's retry-forever
//! loop (WARN + 5s backoff, blocks are never skipped) is the retry policy.
//! That flat 5s cadence is already gentler than a backoff ladder's early
//! rounds, so no internal retry loop is needed here.

use std::time::Duration;

use alloy_primitives::B256;
use chrono::Utc;
use eyre::{Context, Result, ensure};
use reqwest::Client;
use stateless_common::decode_witness_payload_light;
use stateless_core::{LightWitness, withdrawals::MptWitness};
use stateless_r2::{
    endpoint::parse_endpoint,
    keys,
    sigv4::{SigV4Signer, encode_uri_path},
};

/// Cap on the response body carried inside error messages (real R2 error
/// bodies are a few hundred bytes of XML; a proxy can return arbitrary HTML).
const MAX_ERROR_BODY_BYTES: usize = 1024;

/// Fetches witness objects from an R2 bucket with SigV4-signed GETs and
/// decodes them on the light path. Cloning is cheap (`reqwest::Client` is
/// refcounted; the signer redacts credentials in `Debug`).
#[derive(Clone, Debug)]
pub struct R2LightClient {
    http: Client,
    signer: SigV4Signer,
    /// Endpoint origin (`scheme://host`, no trailing slash).
    endpoint: String,
    /// SigV4 canonical host (`host[:port]`).
    host: String,
    bucket: String,
}

impl R2LightClient {
    /// Builds a client from an R2 endpoint origin, bucket, and bucket-scoped
    /// S3 credentials. `per_attempt_timeout` bounds each individual GET.
    pub fn new(
        endpoint: &str,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        per_attempt_timeout: Duration,
    ) -> Result<Self> {
        let (origin, host) = parse_endpoint(endpoint);
        ensure!(
            !host.is_empty(),
            "invalid R2 endpoint {endpoint:?}: expected a bare scheme://host origin \
             (no path/query), e.g. https://<account>.r2.cloudflarestorage.com"
        );
        let http = Client::builder()
            .timeout(per_attempt_timeout)
            // A SigV4-signed GET can never survive a redirect; surface the 3xx.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .wrap_err("build R2 HTTP client")?;
        Ok(Self {
            http,
            signer: SigV4Signer::new(access_key_id, secret_access_key),
            endpoint: origin,
            host,
            bucket,
        })
    }

    /// Fetches and light-decodes the witness for `(number, hash)`.
    pub async fn get_witness_light(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(LightWitness, MptWitness)> {
        let key = keys::block_object_key(number, hash);
        let canonical_uri = encode_uri_path(&self.bucket, &key);
        let url = format!("{}{}", self.endpoint, canonical_uri);
        // Signed-payload mode with an empty body: x-amz-content-sha256 = sha256("").
        let signed = self.signer.sign("GET", &self.host, &canonical_uri, "", &[], b"", Utc::now());

        let mut request = self.http.get(&url);
        for (name, value) in signed {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .await
            .wrap_err_with(|| format!("R2 GET transport failure for block {number} (key {key})"))?;

        let status = response.status();
        if !status.is_success() {
            let mut body = response.text().await.unwrap_or_default();
            if body.len() > MAX_ERROR_BODY_BYTES {
                let mut end = MAX_ERROR_BODY_BYTES;
                while !body.is_char_boundary(end) {
                    end -= 1;
                }
                body.truncate(end);
            }
            eyre::bail!("R2 GET for block {number} (key {key}) returned {status}: {body}");
        }
        let bytes = response
            .bytes()
            .await
            .wrap_err_with(|| format!("R2 GET body read failed for block {number} (key {key})"))?;

        // zstd + bincode over a multi-MB witness is CPU-bound; keep it off the runtime.
        tokio::task::spawn_blocking(move || decode_witness_payload_light(&bytes))
            .await
            .wrap_err("R2 witness light-decode task panicked")?
            .wrap_err_with(|| format!("R2 witness for block {number} (key {key}) failed to decode"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Serves one scripted HTTP/1.1 response per connection on a local port
    /// and counts requests (same shape as the validator's r2_witness tests).
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
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 {status} X\r\nconnection: close\r\ncontent-length: {}\r\n\r\n",
                    body.len(),
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
            }
        });
        (endpoint, hits)
    }

    fn client(endpoint: &str) -> R2LightClient {
        R2LightClient::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    /// Happy path end to end: a fixture witness encoded exactly as the
    /// uploader writes it must light-decode from a single GET to the same
    /// light parts the full decode yields.
    #[tokio::test]
    async fn valid_object_light_decodes_end_to_end() {
        use stateless_test_utils::fixtures::TestFixtures;

        let fixtures = TestFixtures::mainnet_shared();
        let (_, hash) =
            fixtures.paired_blocks().into_iter().next().expect("mainnet fixtures have a witness");
        let salt_witness = fixtures.salt_witnesses[&hash].clone();
        let mpt_witness: MptWitness = fixtures.mpt_witness(&hash);
        let (_, payload) = stateless_common::encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("fixture witness must encode");

        let (endpoint, hits) = mock_r2(vec![(200, payload)]).await;
        let (light, mpt) = client(&endpoint)
            .get_witness_light(1, B256::ZERO)
            .await
            .expect("valid object must fetch and light-decode");
        assert_eq!(light, LightWitness::from(&salt_witness));
        assert_eq!(mpt, mpt_witness);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "one GET for a successful fetch");
    }

    /// Failures surface as errors with the status and key in the message —
    /// the backfill retry-forever loop is the retry policy, not this client.
    #[tokio::test]
    async fn non_success_status_surfaces_with_context() {
        let (endpoint, hits) = mock_r2(vec![(404, "<Code>NoSuchKey</Code>")]).await;
        let err = client(&endpoint).get_witness_light(7, B256::ZERO).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("404") && msg.contains("block 7"), "{msg}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no internal retry");
    }

    #[tokio::test]
    async fn corrupt_body_surfaces_decode_error() {
        let (endpoint, _) = mock_r2(vec![(200, "not a zstd witness")]).await;
        let err = client(&endpoint).get_witness_light(9, B256::ZERO).await.unwrap_err();
        assert!(format!("{err:#}").contains("failed to decode"), "{err:#}");
    }
}
