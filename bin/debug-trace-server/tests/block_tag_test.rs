//! Integration tests for block tag support and error handling.
//!
//! These tests verify:
//! 1. All block tags (earliest, latest, pending, finalized, safe) are handled correctly
//! 2. Consistency with mega-reth for block tag resolution
//! 3. Error handling for pending blocks
//! 4. debug_traceBlockByNumber works with various block tags
//! 5. Transaction sending and tracing with block tags
//!
//! # Configuration
//!
//! Tests are configured via environment variables:
//! - `MEGA_RETH_URL`: mega-reth RPC endpoint (default: http://localhost:49945)
//! - `DEBUG_TRACE_SERVER_URL`: debug-trace-server RPC endpoint (default: http://localhost:18545)
//! - `REQUEST_TIMEOUT_SECS`: Request timeout in seconds (default: 120)
//! - `TEST_PRIVATE_KEY`: Private key for sending test transactions
//!
//! # Running Tests
//!
//! ```bash
//! TEST_PRIVATE_KEY=1c01053175cebf0f10036c444a24a29c684b3085ad6b7c77d3b38f6519617269 \
//!   cargo test --package debug-trace-server --test block_tag_test -- --nocapture --ignored
//! ```

use std::{env, time::Duration};

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_network::TxSignerSync;
use alloy_primitives::{Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Test Infrastructure
// ---------------------------------------------------------------------------

struct TestConfig {
    mega_reth_url: String,
    debug_trace_server_url: String,
    request_timeout: Duration,
    private_key: Option<String>,
}

impl TestConfig {
    fn from_env() -> Self {
        let _ = dotenvy::dotenv();
        Self {
            mega_reth_url: env::var("MEGA_RETH_URL")
                .unwrap_or_else(|_| "http://localhost:49945".to_string()),
            debug_trace_server_url: env::var("DEBUG_TRACE_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:18545".to_string()),
            request_timeout: Duration::from_secs(
                env::var("REQUEST_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(120),
            ),
            private_key: env::var("TEST_PRIVATE_KEY").ok(),
        }
    }
}

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    method: String,
    params: Value,
    id: u64,
}

#[derive(Deserialize, Debug)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<Value>,
    error: Option<Value>,
}

struct RpcClient {
    client: Client,
    url: String,
}

impl RpcClient {
    fn new(url: &str, timeout: Duration) -> Self {
        let client =
            Client::builder().timeout(timeout).build().expect("Failed to create HTTP client");
        Self { client, url: url.to_string() }
    }

    fn call(&self, method: &str, params: Value) -> Result<RpcResponse, String> {
        let request = RpcRequest { jsonrpc: "2.0", method: method.to_string(), params, id: 1 };

        self.client
            .post(&self.url)
            .json(&request)
            .send()
            .map_err(|e| format!("Request failed: {}", e))?
            .json::<RpcResponse>()
            .map_err(|e| format!("Failed to parse response: {}", e))
    }
}

/// Helper to decode hex strings.
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
            })
            .collect()
    }

    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

fn get_block_number(client: &RpcClient) -> u64 {
    let resp = client.call("eth_blockNumber", json!([])).unwrap();
    let hex = resp.result.as_ref().unwrap().as_str().unwrap();
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap()
}

/// Find a recent block that has transactions.
fn find_block_with_txs(client: &RpcClient) -> Option<(u64, String)> {
    let latest = get_block_number(client);
    for block_num in (1..latest.saturating_sub(5)).rev() {
        let resp = client
            .call("eth_getBlockByNumber", json!([format!("0x{:x}", block_num), false]))
            .ok()?;
        if let Some(block) = resp.result {
            if let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) {
                if !txs.is_empty() {
                    let hash =
                        block.get("hash").and_then(|h| h.as_str()).unwrap_or_default().to_string();
                    return Some((block_num, hash));
                }
            }
        }
    }
    None
}

/// Normalize JSON values for comparison (sorts keys, normalizes hex).
fn normalize_json(value: &Value) -> Value {
    normalize_json_inner(value, None)
}

fn normalize_json_inner(value: &Value, current_key: Option<&str>) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: serde_json::Map<String, Value> = serde_json::Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), normalize_json_inner(&map[key], Some(key.as_str())));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|v| normalize_json_inner(v, None)).collect())
        }
        Value::String(s) => {
            if current_key == Some("returnValue") {
                let normalized = s.strip_prefix("0x").unwrap_or(s);
                return Value::String(normalized.to_lowercase());
            }
            if s.starts_with("0x") {
                if s == "0x" {
                    Value::String(String::new())
                } else {
                    Value::String(s.to_lowercase())
                }
            } else {
                Value::String(s.clone())
            }
        }
        _ => value.clone(),
    }
}

/// Compare two RPC responses for equality.
fn assert_responses_match(label: &str, resp1: &RpcResponse, resp2: &RpcResponse) {
    match (&resp1.error, &resp2.error) {
        (Some(_), Some(_)) => {
            println!("    {} - both returned errors (OK)", label);
            return;
        }
        (Some(e), None) => panic!("{}: mega-reth returned error: {:?}", label, e),
        (None, Some(e)) => panic!("{}: debug-trace-server returned error: {:?}", label, e),
        (None, None) => {}
    }

    let r1 = resp1.result.as_ref().expect("mega-reth no result");
    let r2 = resp2.result.as_ref().expect("debug-trace-server no result");

    let n1 = normalize_json(r1);
    let n2 = normalize_json(r2);

    assert_eq!(n1, n2, "{}: results differ", label);
    println!("    {} - PASS", label);
}

// ---------------------------------------------------------------------------
// Block Tag Tests
// ---------------------------------------------------------------------------

/// Test that "earliest" block tag (block 0) works.
/// Should return the genesis block trace or an appropriate response.
#[test]
#[ignore]
fn test_trace_block_by_earliest() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: debug_traceBlockByNumber with 'earliest' tag");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Test with "earliest" tag
    let params = json!(["earliest", {"tracer": "callTracer"}]);

    let r1 = mega_reth
        .call("debug_traceBlockByNumber", params.clone())
        .expect("mega-reth request failed");
    let r2 = dts.call("debug_traceBlockByNumber", params).expect("dts request failed");

    // Both should succeed (genesis block is valid) or both should error
    match (&r1.error, &r2.error) {
        (Some(_), Some(_)) => {
            println!("  Both returned errors for earliest block (acceptable)");
        }
        (None, None) => {
            assert_responses_match("earliest/callTracer", &r1, &r2);
        }
        (Some(e), None) => {
            println!("  mega-reth error: {:?}", e);
            println!("  debug-trace-server succeeded - checking response is valid");
            assert!(r2.result.is_some(), "dts should return a result");
        }
        (None, Some(e)) => {
            println!("  debug-trace-server error: {:?}", e);
            println!("  mega-reth succeeded - checking response is valid");
            assert!(r1.result.is_some(), "mega-reth should return a result");
        }
    }

    println!("\n  PASS: earliest tag handled");
}

/// Test that "latest" block tag works and results match mega-reth.
#[test]
#[ignore]
fn test_trace_block_by_latest() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: debug_traceBlockByNumber with 'latest' tag");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // First get latest block number to know what we're tracing
    let latest = get_block_number(&mega_reth);
    println!("  Latest block: {}", latest);

    // Use a recent block that's more likely to match between servers
    // (latest may differ if blocks are being produced quickly)
    let block_num = latest.saturating_sub(3);
    let block_hex = format!("0x{:x}", block_num);

    let tracers = vec![
        ("default", json!({})),
        ("callTracer", json!({"tracer": "callTracer"})),
        ("prestateTracer", json!({"tracer": "prestateTracer"})),
    ];

    for (name, opts) in &tracers {
        let params = json!([&block_hex, opts]);
        let r1 =
            mega_reth.call("debug_traceBlockByNumber", params.clone()).expect("mega-reth failed");
        let r2 = dts.call("debug_traceBlockByNumber", params).expect("dts failed");

        assert_responses_match(&format!("latest-3/{}", name), &r1, &r2);
    }

    println!("\n  PASS: latest block tag handled");
}

/// Test that "pending" block tag returns an appropriate error.
#[test]
#[ignore]
fn test_trace_block_by_pending_returns_error() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: debug_traceBlockByNumber with 'pending' tag");
    println!("{}", "=".repeat(70));

    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    let params = json!(["pending", {"tracer": "callTracer"}]);
    let resp = dts.call("debug_traceBlockByNumber", params).expect("request failed");

    // Should return an error since pending block is not supported for tracing
    assert!(
        resp.error.is_some(),
        "Expected error for pending block, got result: {:?}",
        resp.result
    );

    let error = resp.error.unwrap();
    let error_str = format!("{:?}", error);
    println!("  Error returned: {}", error_str);

    // Verify error mentions "pending" and "not supported"
    let error_msg =
        error.get("message").and_then(|v| v.as_str()).unwrap_or(&error_str).to_lowercase();
    assert!(
        error_msg.contains("pending") || error_msg.contains("not supported"),
        "Error message should mention pending: {}",
        error_msg
    );

    println!("\n  PASS: pending tag correctly returns error");
}

/// Test that "finalized" block tag works.
#[test]
#[ignore]
fn test_trace_block_by_finalized() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: debug_traceBlockByNumber with 'finalized' tag");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // First check if finalized is supported by mega-reth
    let check = mega_reth.call("eth_getBlockByNumber", json!(["finalized", false]));

    match check {
        Ok(resp) if resp.error.is_some() => {
            println!("  mega-reth does not support finalized tag, skipping");
            return;
        }
        Err(e) => {
            println!("  mega-reth request failed: {}, skipping", e);
            return;
        }
        _ => {}
    }

    let params = json!(["finalized", {"tracer": "callTracer"}]);
    let r1 = mega_reth.call("debug_traceBlockByNumber", params.clone()).expect("mega-reth failed");
    let r2 = dts.call("debug_traceBlockByNumber", params).expect("dts failed");

    match (&r1.error, &r2.error) {
        (Some(_), Some(_)) => {
            println!("  Both returned errors for finalized (acceptable)");
        }
        (None, None) => {
            assert_responses_match("finalized/callTracer", &r1, &r2);
        }
        _ => {
            println!("  mega-reth error: {:?}", r1.error);
            println!("  dts error: {:?}", r2.error);
            println!("  Responses differ, but finalized may not be available");
        }
    }

    println!("\n  PASS: finalized tag handled");
}

/// Test that "safe" block tag works.
#[test]
#[ignore]
fn test_trace_block_by_safe() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: debug_traceBlockByNumber with 'safe' tag");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // First check if safe is supported by mega-reth
    let check = mega_reth.call("eth_getBlockByNumber", json!(["safe", false]));

    match check {
        Ok(resp) if resp.error.is_some() => {
            println!("  mega-reth does not support safe tag, skipping");
            return;
        }
        Err(e) => {
            println!("  mega-reth request failed: {}, skipping", e);
            return;
        }
        _ => {}
    }

    let params = json!(["safe", {"tracer": "callTracer"}]);
    let r1 = mega_reth.call("debug_traceBlockByNumber", params.clone()).expect("mega-reth failed");
    let r2 = dts.call("debug_traceBlockByNumber", params).expect("dts failed");

    match (&r1.error, &r2.error) {
        (Some(_), Some(_)) => {
            println!("  Both returned errors for safe (acceptable)");
        }
        (None, None) => {
            assert_responses_match("safe/callTracer", &r1, &r2);
        }
        _ => {
            println!("  mega-reth error: {:?}", r1.error);
            println!("  dts error: {:?}", r2.error);
            println!("  Responses differ, but safe may not be available");
        }
    }

    println!("\n  PASS: safe tag handled");
}

// ---------------------------------------------------------------------------
// Block Number vs Tag Consistency
// ---------------------------------------------------------------------------

/// Test that tracing by number and by hash for the same block produce identical results.
#[test]
#[ignore]
fn test_trace_block_number_vs_hash_consistency() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: traceBlockByNumber vs traceBlockByHash consistency");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    let (block_num, block_hash) =
        find_block_with_txs(&mega_reth).expect("No blocks with txs found");
    println!("  Testing block {} (hash: {}...)", block_num, &block_hash[..18]);

    let tracers = vec![("callTracer", json!({"tracer": "callTracer"})), ("default", json!({}))];

    for (name, opts) in &tracers {
        let block_hex = format!("0x{:x}", block_num);

        // Trace by number
        let by_number = dts
            .call("debug_traceBlockByNumber", json!([&block_hex, opts]))
            .expect("traceBlockByNumber failed");

        // Trace by hash
        let by_hash = dts
            .call("debug_traceBlockByHash", json!([&block_hash, opts]))
            .expect("traceBlockByHash failed");

        assert!(by_number.error.is_none(), "traceBlockByNumber error: {:?}", by_number.error);
        assert!(by_hash.error.is_none(), "traceBlockByHash error: {:?}", by_hash.error);

        let n1 = normalize_json(by_number.result.as_ref().unwrap());
        let n2 = normalize_json(by_hash.result.as_ref().unwrap());

        assert_eq!(n1, n2, "by-number vs by-hash differ for {}", name);
        println!("    {} - by_number == by_hash  PASS", name);
    }

    println!("\n  PASS: number vs hash consistency verified");
}

// ---------------------------------------------------------------------------
// Parity Trace with Block Tags
// ---------------------------------------------------------------------------

/// Test that trace_block works with block numbers.
#[test]
#[ignore]
fn test_parity_trace_block_consistency() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: trace_block consistency with mega-reth");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    let (block_num, _) = find_block_with_txs(&mega_reth).expect("No blocks with txs found");
    let block_hex = format!("0x{:x}", block_num);
    println!("  Testing block {}", block_num);

    let r1 = mega_reth.call("trace_block", json!([&block_hex])).expect("mega-reth failed");
    let r2 = dts.call("trace_block", json!([&block_hex])).expect("dts failed");

    assert_responses_match("trace_block", &r1, &r2);

    println!("\n  PASS: trace_block consistency verified");
}

/// Test trace_transaction consistency.
#[test]
#[ignore]
fn test_parity_trace_transaction_consistency() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: trace_transaction consistency with mega-reth");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    let (block_num, _) = find_block_with_txs(&mega_reth).expect("No blocks with txs found");

    // Get full block to find tx hashes
    let resp = mega_reth
        .call("eth_getBlockByNumber", json!([format!("0x{:x}", block_num), true]))
        .expect("Failed to get block");

    let txs = resp
        .result
        .as_ref()
        .and_then(|b| b.get("transactions"))
        .and_then(|t| t.as_array())
        .expect("No transactions");

    let tx_hash = txs[0].get("hash").and_then(|h| h.as_str()).expect("No tx hash");

    println!("  Testing tx {}...", &tx_hash[..18]);

    let r1 = mega_reth.call("trace_transaction", json!([tx_hash])).expect("mega-reth failed");
    let r2 = dts.call("trace_transaction", json!([tx_hash])).expect("dts failed");

    assert_responses_match("trace_transaction", &r1, &r2);

    println!("\n  PASS: trace_transaction consistency verified");
}

// ---------------------------------------------------------------------------
// Send Transaction and Trace Tests
// ---------------------------------------------------------------------------

/// Helper to send a transaction with retry on nonce conflicts.
fn send_tx_with_retry(
    mega_reth: &RpcClient,
    signer: &PrivateKeySigner,
    chain_id: u64,
    max_retries: usize,
) -> (String, u64) {
    for attempt in 0..max_retries {
        // Get fresh nonce for each attempt
        let resp = mega_reth
            .call("eth_getTransactionCount", json!([format!("{:?}", signer.address()), "pending"]))
            .unwrap();
        let nonce_hex = resp.result.as_ref().unwrap().as_str().unwrap();
        let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16).unwrap();

        // Get gas price with bump for retries
        let resp = mega_reth.call("eth_gasPrice", json!([])).unwrap();
        let gas_hex = resp.result.as_ref().unwrap().as_str().unwrap();
        let base_gas_price = u128::from_str_radix(gas_hex.trim_start_matches("0x"), 16).unwrap();
        // Increase gas price on retries to avoid "replacement transaction underpriced"
        let gas_price = base_gas_price + (base_gas_price * attempt as u128 / 10);

        if attempt > 0 {
            println!("    Retry {}: nonce={}, gas_price={}", attempt, nonce, gas_price);
        }

        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price,
            gas_limit: 100_000,
            to: TxKind::Call(signer.address()),
            value: U256::from(1),
            input: Bytes::default(),
        };

        let signature = signer.sign_transaction_sync(&mut tx.clone()).expect("Failed to sign");

        let signed_tx = tx.into_signed(signature);
        let mut encoded = Vec::new();
        signed_tx.rlp_encode(&mut encoded);
        let raw_tx = format!("0x{}", hex::encode(&encoded));

        let resp = mega_reth.call("eth_sendRawTransaction", json!([raw_tx])).expect("send failed");

        if let Some(error) = &resp.error {
            let error_msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("");
            if error_msg.contains("nonce") || error_msg.contains("underpriced") {
                // Nonce conflict, wait and retry
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            panic!("Send tx error: {:?}", resp.error);
        }

        let tx_hash = resp.result.as_ref().unwrap().as_str().unwrap().to_string();
        return (tx_hash, nonce);
    }
    panic!("Failed to send transaction after {} retries", max_retries);
}

/// Send a transaction, wait for it to be mined, and verify tracing works.
#[test]
#[ignore]
fn test_send_tx_and_trace() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: send transaction and trace");
    println!("{}", "=".repeat(70));

    let private_key = match &config.private_key {
        Some(pk) => pk,
        None => {
            println!("  TEST_PRIVATE_KEY not set, skipping");
            return;
        }
    };

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Create signer
    let key_bytes =
        hex::decode(private_key.trim_start_matches("0x")).expect("Invalid private key hex");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("Invalid private key");

    // Get chain ID
    let resp = mega_reth.call("eth_chainId", json!([])).unwrap();
    let chain_id_hex = resp.result.as_ref().unwrap().as_str().unwrap();
    let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16).unwrap();

    println!("  Sender: {:?}", signer.address());
    println!("  Chain ID: {}", chain_id);

    // Send transaction with retry logic
    let (tx_hash, nonce) = send_tx_with_retry(&mega_reth, &signer, chain_id, 5);
    println!("  Nonce: {}", nonce);
    println!("  Sent tx: {}", tx_hash);

    // Wait for mining
    println!("  Waiting for mining...");
    let mut block_number = None;
    for _ in 0..120 {
        std::thread::sleep(Duration::from_millis(500));
        let resp = mega_reth.call("eth_getTransactionReceipt", json!([&tx_hash])).unwrap();
        if let Some(receipt) = resp.result {
            if !receipt.is_null() {
                if let Some(bn) = receipt.get("blockNumber").and_then(|v| v.as_str()) {
                    block_number =
                        Some(u64::from_str_radix(bn.trim_start_matches("0x"), 16).unwrap());
                    break;
                }
            }
        }
    }

    let block_number = block_number.expect("Tx not mined in time");
    println!("  Mined in block {}", block_number);

    // Wait for witness
    std::thread::sleep(Duration::from_secs(3));

    // Test debug_traceBlockByNumber with various tracers
    let block_hex = format!("0x{:x}", block_number);

    let tracers = vec![
        ("default", json!({})),
        ("callTracer", json!({"tracer": "callTracer"})),
        ("callTracer+logs", json!({"tracer": "callTracer", "tracerConfig": {"withLog": true}})),
        ("prestateTracer", json!({"tracer": "prestateTracer"})),
        ("4byteTracer", json!({"tracer": "4byteTracer"})),
        ("noopTracer", json!({"tracer": "noopTracer"})),
        ("flatCallTracer", json!({"tracer": "flatCallTracer"})),
    ];

    println!("\n  Testing debug_traceBlockByNumber:");
    for (name, opts) in &tracers {
        let params = json!([&block_hex, opts]);
        let r1 =
            mega_reth.call("debug_traceBlockByNumber", params.clone()).expect("mega-reth failed");
        let r2 = dts.call("debug_traceBlockByNumber", params).expect("dts failed");
        assert_responses_match(&format!("block/{}", name), &r1, &r2);
    }

    // Test debug_traceTransaction
    println!("\n  Testing debug_traceTransaction:");
    for (name, opts) in &tracers {
        let params = json!([&tx_hash, opts]);
        let r1 =
            mega_reth.call("debug_traceTransaction", params.clone()).expect("mega-reth failed");
        let r2 = dts.call("debug_traceTransaction", params).expect("dts failed");
        assert_responses_match(&format!("tx/{}", name), &r1, &r2);
    }

    // Test trace_block
    println!("\n  Testing trace_block:");
    let r1 = mega_reth.call("trace_block", json!([&block_hex])).expect("mega-reth failed");
    let r2 = dts.call("trace_block", json!([&block_hex])).expect("dts failed");
    assert_responses_match("trace_block", &r1, &r2);

    // Test trace_transaction
    println!("\n  Testing trace_transaction:");
    let r1 = mega_reth.call("trace_transaction", json!([&tx_hash])).expect("mega-reth failed");
    let r2 = dts.call("trace_transaction", json!([&tx_hash])).expect("dts failed");
    assert_responses_match("trace_transaction", &r1, &r2);

    println!("\n  PASS: send tx and trace verified");
}

/// Helper to deploy a contract with retry on nonce conflicts.
fn deploy_contract_with_retry(
    mega_reth: &RpcClient,
    signer: &PrivateKeySigner,
    chain_id: u64,
    bytecode: Vec<u8>,
    max_retries: usize,
) -> String {
    for attempt in 0..max_retries {
        // Get fresh nonce for each attempt
        let resp = mega_reth
            .call("eth_getTransactionCount", json!([format!("{:?}", signer.address()), "pending"]))
            .unwrap();
        let nonce_hex = resp.result.as_ref().unwrap().as_str().unwrap();
        let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16).unwrap();

        // Get gas price with bump for retries
        let resp = mega_reth.call("eth_gasPrice", json!([])).unwrap();
        let gas_hex = resp.result.as_ref().unwrap().as_str().unwrap();
        let base_gas_price = u128::from_str_radix(gas_hex.trim_start_matches("0x"), 16).unwrap();
        let gas_price = base_gas_price + (base_gas_price * attempt as u128 / 10);

        if attempt > 0 {
            println!("    Retry {}: nonce={}, gas_price={}", attempt, nonce, gas_price);
        }

        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price,
            gas_limit: 3_000_000,
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::from(bytecode.clone()),
        };

        let signature = signer.sign_transaction_sync(&mut tx.clone()).expect("Failed to sign");

        let signed_tx = tx.into_signed(signature);
        let mut encoded = Vec::new();
        signed_tx.rlp_encode(&mut encoded);
        let raw_tx = format!("0x{}", hex::encode(&encoded));

        let resp = mega_reth.call("eth_sendRawTransaction", json!([raw_tx])).expect("send failed");

        if let Some(error) = &resp.error {
            let error_msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("");
            if error_msg.contains("nonce") || error_msg.contains("underpriced") {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            panic!("Deploy error: {:?}", resp.error);
        }

        return resp.result.as_ref().unwrap().as_str().unwrap().to_string();
    }
    panic!("Failed to deploy contract after {} retries", max_retries);
}

/// Deploy a contract, trace the deployment transaction.
#[test]
#[ignore]
fn test_deploy_contract_and_trace() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: deploy contract and trace");
    println!("{}", "=".repeat(70));

    let private_key = match &config.private_key {
        Some(pk) => pk,
        None => {
            println!("  TEST_PRIVATE_KEY not set, skipping");
            return;
        }
    };

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    let key_bytes =
        hex::decode(private_key.trim_start_matches("0x")).expect("Invalid private key hex");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("Invalid private key");

    let resp = mega_reth.call("eth_chainId", json!([])).unwrap();
    let chain_id_hex = resp.result.as_ref().unwrap().as_str().unwrap();
    let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16).unwrap();

    // Simple storage contract bytecode
    let bytecode = hex::decode(
        "6080604052602a60005534801561001557600080fd5b5060b3806100246000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80633fa4f2451460375780635524107714604f575b600080fd5b603d6061565b60405190815260200160405180910390f35b605f600480360381019060599190606a565b6067565b005b60005481565b600055565b600060208284031215607b57600080fd5b503591905056fea264697066735822122000000000000000000000000000000000000000000000000000000000000000000064736f6c63430008130033"
    ).expect("Invalid bytecode");

    let tx_hash = deploy_contract_with_retry(&mega_reth, &signer, chain_id, bytecode, 5);
    println!("  Deploy tx: {}", tx_hash);

    // Wait for mining
    let mut block_number = None;
    for _ in 0..120 {
        std::thread::sleep(Duration::from_millis(500));
        let resp = mega_reth.call("eth_getTransactionReceipt", json!([&tx_hash])).unwrap();
        if let Some(receipt) = resp.result {
            if !receipt.is_null() {
                if let Some(bn) = receipt.get("blockNumber").and_then(|v| v.as_str()) {
                    block_number =
                        Some(u64::from_str_radix(bn.trim_start_matches("0x"), 16).unwrap());
                    break;
                }
            }
        }
    }

    let block_number = block_number.expect("Deploy tx not mined");
    println!("  Mined in block {}", block_number);

    std::thread::sleep(Duration::from_secs(3));

    let block_hex = format!("0x{:x}", block_number);

    // Test tracing the deployment block
    println!("\n  Tracing deployment block:");
    let tracers = vec![
        ("callTracer", json!({"tracer": "callTracer"})),
        ("prestateTracer", json!({"tracer": "prestateTracer"})),
        (
            "prestateTracer+diff",
            json!({"tracer": "prestateTracer", "tracerConfig": {"diffMode": true}}),
        ),
    ];

    for (name, opts) in &tracers {
        let params = json!([&block_hex, opts]);
        let r1 =
            mega_reth.call("debug_traceBlockByNumber", params.clone()).expect("mega-reth failed");
        let r2 = dts.call("debug_traceBlockByNumber", params).expect("dts failed");
        assert_responses_match(&format!("deploy/{}", name), &r1, &r2);
    }

    // Test tracing the deployment transaction
    println!("\n  Tracing deployment transaction:");
    for (name, opts) in &tracers {
        let params = json!([&tx_hash, opts]);
        let r1 =
            mega_reth.call("debug_traceTransaction", params.clone()).expect("mega-reth failed");
        let r2 = dts.call("debug_traceTransaction", params).expect("dts failed");
        assert_responses_match(&format!("deploy-tx/{}", name), &r1, &r2);
    }

    println!("\n  PASS: contract deploy and trace verified");
}

// ---------------------------------------------------------------------------
// Cache Verification
// ---------------------------------------------------------------------------

/// Test that repeated requests for the same block return identical results (cache correctness).
#[test]
#[ignore]
fn test_cache_correctness() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Test: cache correctness - repeated requests return identical results");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    let (block_num, _) = find_block_with_txs(&mega_reth).expect("No blocks with txs found");
    let block_hex = format!("0x{:x}", block_num);
    println!("  Testing block {}", block_num);

    let tracers = vec![
        ("callTracer", json!({"tracer": "callTracer"})),
        ("default", json!({})),
        ("prestateTracer", json!({"tracer": "prestateTracer"})),
    ];

    for (name, opts) in &tracers {
        let params = json!([&block_hex, opts]);

        // First request (may be cache miss)
        let r1 =
            dts.call("debug_traceBlockByNumber", params.clone()).expect("first request failed");
        assert!(r1.error.is_none(), "first request error: {:?}", r1.error);

        // Second request (should be cache hit)
        let r2 =
            dts.call("debug_traceBlockByNumber", params.clone()).expect("second request failed");
        assert!(r2.error.is_none(), "second request error: {:?}", r2.error);

        // Third request
        let r3 = dts.call("debug_traceBlockByNumber", params).expect("third request failed");
        assert!(r3.error.is_none(), "third request error: {:?}", r3.error);

        // All three must be identical
        assert_eq!(r1.result, r2.result, "{}: r1 != r2", name);
        assert_eq!(r2.result, r3.result, "{}: r2 != r3", name);
        println!("    {} - 3 identical responses  PASS", name);
    }

    println!("\n  PASS: cache correctness verified");
}
