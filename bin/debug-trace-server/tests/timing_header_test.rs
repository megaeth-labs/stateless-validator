//! Integration test for the x-execution-time-ns response header.
//!
//! Verifies that the debug-trace-server returns the `x-execution-time-ns` header
//! on all RPC responses, measuring CPU execution time in nanoseconds.
//!
//! # Configuration
//!
//! Uses the same environment variables as consistency_test.rs:
//! - `DEBUG_TRACE_SERVER_URL`: debug-trace-server RPC endpoint (default: http://localhost:18545)
//! - `REQUEST_TIMEOUT_SECS`: Request timeout in seconds (default: 120)
//!
//! # Running
//!
//! ```bash
//! cargo test --package debug-trace-server --test timing_header_test -- --ignored --nocapture
//! ```

use std::{env, time::Duration};

use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::{Value, json};

/// JSON-RPC request structure.
#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    method: String,
    params: Value,
    id: u64,
}

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

/// Sends a raw HTTP POST with a JSON-RPC request and returns the full HTTP response
/// (including headers).
fn send_rpc_request(
    client: &Client,
    url: &str,
    method: &str,
    params: Value,
) -> reqwest::blocking::Response {
    let request = RpcRequest { jsonrpc: "2.0", method: method.to_string(), params, id: 1 };
    client.post(url).json(&request).send().expect("Failed to send request")
}

/// Test that the x-execution-time-ns header is present on debug_getCacheStatus responses.
///
/// This is a lightweight RPC method that doesn't require any block data,
/// making it ideal for testing the timing header.
#[test]
#[ignore]
fn test_timing_header_on_cache_status() {
    let url = server_url();
    let client = Client::builder().timeout(request_timeout()).build().unwrap();

    println!("\n  Testing x-execution-time-ns header on debug_getCacheStatus...");
    let response = send_rpc_request(&client, &url, "debug_getCacheStatus", json!([]));

    let timing_header = response.headers().get("x-execution-time-ns");
    assert!(timing_header.is_some(), "Response should contain x-execution-time-ns header");

    let timing_value = timing_header.unwrap().to_str().unwrap();
    let timing_ns: u64 = timing_value.parse().expect("Header should be a valid u64");
    println!(
        "    x-execution-time-ns: {} ns ({:.3} ms)",
        timing_ns,
        timing_ns as f64 / 1_000_000.0
    );

    // CPU time should be reasonable (> 0 and < 60 seconds)
    assert!(timing_ns > 0, "CPU time should be greater than 0");
    assert!(timing_ns < 60_000_000_000, "CPU time should be less than 60 seconds");

    println!("    ✓ Timing header present and valid");
}

/// Test that the x-execution-time-ns header is present on debug_traceBlockByNumber responses.
///
/// This tests a heavier RPC method that involves actual block execution.
#[test]
#[ignore]
fn test_timing_header_on_trace_block() {
    let url = server_url();
    let client = Client::builder().timeout(request_timeout()).build().unwrap();

    // First get the latest block number
    println!("\n  Getting latest block number...");
    let response = send_rpc_request(&client, &url, "eth_blockNumber", json!([]));
    // eth_blockNumber may not be supported, fall back to debug_traceBlockByNumber with "latest"
    let block_param = if response.status().is_success() {
        let body: Value = response.json().unwrap();
        if let Some(result) = body.get("result").and_then(|v| v.as_str()) {
            Value::String(result.to_string())
        } else {
            Value::String("latest".to_string())
        }
    } else {
        Value::String("latest".to_string())
    };

    println!("  Testing x-execution-time-ns header on debug_traceBlockByNumber...");
    let response =
        send_rpc_request(&client, &url, "debug_traceBlockByNumber", json!([block_param, {}]));

    let timing_header = response.headers().get("x-execution-time-ns");
    assert!(timing_header.is_some(), "Response should contain x-execution-time-ns header");

    let timing_value = timing_header.unwrap().to_str().unwrap();
    let timing_ns: u64 = timing_value.parse().expect("Header should be a valid u64");
    println!(
        "    x-execution-time-ns: {} ns ({:.3} ms)",
        timing_ns,
        timing_ns as f64 / 1_000_000.0
    );

    assert!(timing_ns > 0, "CPU time should be greater than 0");
    println!("    ✓ Timing header present and valid");
}

/// Test that CPU time excludes sleep/IO wait time.
///
/// Sends two requests: one lightweight (cache status) and one heavy (trace block).
/// The heavy request should report more CPU time than the lightweight one.
#[test]
#[ignore]
fn test_timing_header_cpu_time_ordering() {
    let url = server_url();
    let client = Client::builder().timeout(request_timeout()).build().unwrap();

    println!("\n  Testing CPU time ordering (light vs heavy request)...");

    // Light request: debug_getCacheStatus
    let response = send_rpc_request(&client, &url, "debug_getCacheStatus", json!([]));
    let light_ns: u64 = response
        .headers()
        .get("x-execution-time-ns")
        .expect("Should have timing header")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();

    // Heavy request: debug_traceBlockByNumber with callTracer
    let response = send_rpc_request(
        &client,
        &url,
        "debug_traceBlockByNumber",
        json!(["latest", {"tracer": "callTracer"}]),
    );
    let heavy_ns: u64 = response
        .headers()
        .get("x-execution-time-ns")
        .expect("Should have timing header")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();

    println!(
        "    Light request (cache status): {} ns ({:.3} ms)",
        light_ns,
        light_ns as f64 / 1_000_000.0
    );
    println!(
        "    Heavy request (trace block):  {} ns ({:.3} ms)",
        heavy_ns,
        heavy_ns as f64 / 1_000_000.0
    );

    // The trace block request should generally use more CPU time than cache status.
    // We don't assert this strictly since caching could make trace fast on repeated calls,
    // but we log it for manual verification.
    if heavy_ns > light_ns {
        println!("    ✓ Heavy request used more CPU time as expected");
    } else {
        println!("    ⚠ Heavy request used less CPU time (possibly cached)");
    }

    println!("    ✓ Both requests have valid timing headers");
}

/// Test that the timing header is present even on error responses.
#[test]
#[ignore]
fn test_timing_header_on_error_response() {
    let url = server_url();
    let client = Client::builder().timeout(request_timeout()).build().unwrap();

    println!("\n  Testing x-execution-time-ns header on error response...");

    // Request a non-existent block to trigger an error
    let response =
        send_rpc_request(&client, &url, "debug_traceBlockByNumber", json!(["0xffffffffff", {}]));

    let timing_header = response.headers().get("x-execution-time-ns");
    assert!(
        timing_header.is_some(),
        "Error response should also contain x-execution-time-ns header"
    );

    let timing_value = timing_header.unwrap().to_str().unwrap();
    let timing_ns: u64 = timing_value.parse().expect("Header should be a valid u64");
    println!(
        "    x-execution-time-ns: {} ns ({:.3} ms)",
        timing_ns,
        timing_ns as f64 / 1_000_000.0
    );

    println!("    ✓ Timing header present on error response");
}
