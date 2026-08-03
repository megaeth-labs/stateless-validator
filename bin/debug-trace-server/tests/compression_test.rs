//! Integration test for negotiated gzip/zstd response compression.
//!
//! Verifies that the debug-trace-server compresses responses only when the client
//! opts in via `Accept-Encoding`, and that compressed bodies decode back to the
//! identity response.
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
//! Note: the workspace `reqwest` has no compression features enabled, so the client
//! neither sends `Accept-Encoding` on its own nor transparently decompresses —
//! exactly what these assertions need.

use std::{env, io::Read, time::Duration};

use reqwest::blocking::Client;
use serde_json::{Value, json};

fn server_url() -> String {
    let _ = dotenvy::dotenv();
    env::var("DEBUG_TRACE_SERVER_URL").unwrap_or_else(|_| "http://localhost:18545".to_string())
}

fn request_timeout() -> Duration {
    let _ = dotenvy::dotenv();
    Duration::from_secs(
        env::var("REQUEST_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(120),
    )
}

/// Sends debug_getCacheStatus with an optional `Accept-Encoding` header and returns
/// (content-encoding, raw body bytes).
fn cache_status_raw(client: &Client, accept_encoding: Option<&str>) -> (Option<String>, Vec<u8>) {
    let payload =
        json!({"jsonrpc": "2.0", "id": 1, "method": "debug_getCacheStatus", "params": []});
    let mut req = client.post(server_url()).json(&payload);
    if let Some(enc) = accept_encoding {
        req = req.header("accept-encoding", enc);
    }
    let resp = req.send().expect("Failed to send request");
    assert!(resp.status().is_success(), "HTTP {}", resp.status());
    let encoding = resp.headers().get("content-encoding").map(|v| v.to_str().unwrap().to_string());
    (encoding, resp.bytes().expect("Failed to read body").to_vec())
}

/// Without Accept-Encoding the body must be plain JSON (legacy clients unaffected).
#[test]
#[ignore]
fn test_no_accept_encoding_stays_identity() {
    let client = Client::builder().timeout(request_timeout()).build().unwrap();
    let (encoding, body) = cache_status_raw(&client, None);
    assert!(encoding.is_none(), "unexpected content-encoding: {encoding:?}");
    serde_json::from_slice::<Value>(&body).expect("identity body should be plain JSON");
    println!("    ✓ identity response without Accept-Encoding ({} bytes)", body.len());
}

/// With `Accept-Encoding: gzip` the body must arrive gzip-encoded and decode to JSON.
#[test]
#[ignore]
fn test_gzip_negotiated() {
    let client = Client::builder().timeout(request_timeout()).build().unwrap();
    let (encoding, body) = cache_status_raw(&client, Some("gzip"));
    assert_eq!(encoding.as_deref(), Some("gzip"));
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(&body[..])
        .read_to_end(&mut decoded)
        .expect("body should be valid gzip");
    serde_json::from_slice::<Value>(&decoded).expect("decoded body should be JSON");
    println!("    ✓ gzip: {} bytes on the wire, {} decoded", body.len(), decoded.len());
}

/// With `Accept-Encoding: zstd` the body must arrive zstd-encoded and decode to JSON.
#[test]
#[ignore]
fn test_zstd_negotiated() {
    let client = Client::builder().timeout(request_timeout()).build().unwrap();
    let (encoding, body) = cache_status_raw(&client, Some("zstd"));
    assert_eq!(encoding.as_deref(), Some("zstd"));
    let decoded = zstd::stream::decode_all(&body[..]).expect("body should be valid zstd");
    serde_json::from_slice::<Value>(&decoded).expect("decoded body should be JSON");
    println!("    ✓ zstd: {} bytes on the wire, {} decoded", body.len(), decoded.len());
}
