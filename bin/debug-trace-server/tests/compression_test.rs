//! Integration test for negotiated gzip/zstd response compression.
//!
//! Verifies that the debug-trace-server compresses responses only when the client
//! opts in via `Accept-Encoding` and the body clears the minimum-size threshold, and
//! that compressed bodies decode back to the identity response.
//!
//! # Configuration
//!
//! Uses the same environment variables as timing_header_test.rs:
//! - `DEBUG_TRACE_SERVER_URL`: debug-trace-server RPC endpoint (default: http://localhost:18545)
//! - `REQUEST_TIMEOUT_SECS`: Request timeout in seconds (default: 120)
//!
//! # Running
//!
//! ```bash
//! cargo test --package debug-trace-server --test compression_test -- --ignored --nocapture
//! ```
//!
//! Note: Cargo feature unification turns on reqwest's `gzip`/`brotli` features here
//! (stateless-common enables them), which would make the client silently send
//! `Accept-Encoding` and transparently decompress — so every client below opts out via
//! `no_gzip()`/`no_brotli()` to keep the raw-byte assertions valid.

use std::{env, io::Read, time::Duration};

use reqwest::{
    blocking::Client,
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap},
};
use serde_json::{Value, json};

/// Compression only engages above this body size (`MIN_COMPRESS_SIZE` server-side).
const MIN_COMPRESS_SIZE: usize = 4096;

fn server_url() -> String {
    let _ = dotenvy::dotenv();
    env::var("DEBUG_TRACE_SERVER_URL").unwrap_or_else(|_| "http://localhost:18545".to_string())
}

fn client() -> Client {
    let _ = dotenvy::dotenv();
    let timeout = Duration::from_secs(
        env::var("REQUEST_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(120),
    );
    Client::builder().timeout(timeout).no_gzip().no_brotli().build().unwrap()
}

/// Sends one JSON-RPC request with an optional `Accept-Encoding` header and returns
/// the response headers plus the raw (undecoded) body bytes.
fn rpc_raw(
    client: &Client,
    method: &str,
    params: Value,
    accept_encoding: Option<&str>,
) -> (HeaderMap, Vec<u8>) {
    let payload = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut req = client.post(server_url()).json(&payload);
    if let Some(enc) = accept_encoding {
        req = req.header(ACCEPT_ENCODING, enc);
    }
    let resp = req.send().expect("Failed to send request");
    assert!(resp.status().is_success(), "HTTP {}", resp.status());
    let headers = resp.headers().clone();
    (headers, resp.bytes().expect("Failed to read body").to_vec())
}

/// Fetches a large trace (latest block, callTracer) with the given `Accept-Encoding`.
/// Returns None — skipping the caller's assertions — when the latest block's trace is
/// too small to clear the compression threshold (e.g. an idle dev chain).
fn large_trace(client: &Client, accept_encoding: &str) -> Option<(HeaderMap, Vec<u8>)> {
    let (headers, body) = rpc_raw(
        client,
        "debug_traceBlockByNumber",
        json!(["latest", {"tracer": "callTracer"}]),
        Some(accept_encoding),
    );
    let size: usize = headers
        .get("x-response-size")
        .expect("server always sets x-response-size")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    if size < MIN_COMPRESS_SIZE {
        // still assert the threshold behavior before skipping the compression checks
        assert!(
            headers.get(CONTENT_ENCODING).is_none(),
            "sub-threshold response must stay identity"
        );
        println!(
            "    ⚠ latest-block trace is only {size} bytes (< {MIN_COMPRESS_SIZE}) — skipping"
        );
        return None;
    }
    Some((headers, body))
}

/// Without Accept-Encoding the body must be plain JSON (legacy clients unaffected).
#[test]
#[ignore]
fn test_no_accept_encoding_stays_identity() {
    let (headers, body) = rpc_raw(&client(), "debug_getCacheStatus", json!([]), None);
    assert!(
        headers.get(CONTENT_ENCODING).is_none(),
        "unexpected content-encoding: {:?}",
        headers.get(CONTENT_ENCODING)
    );
    serde_json::from_slice::<Value>(&body).expect("identity body should be plain JSON");
    println!("    ✓ identity response without Accept-Encoding ({} bytes)", body.len());
}

/// Small responses stay identity even when the client opts in (min-size threshold).
#[test]
#[ignore]
fn test_small_response_stays_identity() {
    let (headers, body) = rpc_raw(&client(), "debug_getCacheStatus", json!([]), Some("gzip, zstd"));
    assert!(body.len() < MIN_COMPRESS_SIZE, "cache status unexpectedly large: {}", body.len());
    assert!(headers.get(CONTENT_ENCODING).is_none());
    serde_json::from_slice::<Value>(&body).expect("identity body should be plain JSON");
    println!("    ✓ small response stays identity with Accept-Encoding set ({} bytes)", body.len());
}

/// With `Accept-Encoding: gzip` a large trace must arrive gzip-encoded and decode to JSON.
#[test]
#[ignore]
fn test_gzip_negotiated() {
    let Some((headers, body)) = large_trace(&client(), "gzip") else { return };
    assert_eq!(headers.get(CONTENT_ENCODING).map(|v| v.to_str().unwrap()), Some("gzip"));
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(&body[..])
        .read_to_end(&mut decoded)
        .expect("body should be valid gzip");
    serde_json::from_slice::<Value>(&decoded).expect("decoded body should be JSON");
    println!("    ✓ gzip: {} bytes on the wire, {} decoded", body.len(), decoded.len());
}

/// With `Accept-Encoding: zstd` a large trace must arrive zstd-encoded and decode to JSON.
#[test]
#[ignore]
fn test_zstd_negotiated() {
    let Some((headers, body)) = large_trace(&client(), "zstd") else { return };
    assert_eq!(headers.get(CONTENT_ENCODING).map(|v| v.to_str().unwrap()), Some("zstd"));
    let decoded = zstd::decode_all(&body[..]).expect("body should be valid zstd");
    serde_json::from_slice::<Value>(&decoded).expect("decoded body should be JSON");
    println!("    ✓ zstd: {} bytes on the wire, {} decoded", body.len(), decoded.len());
}
