//! Performance tests for debug-trace-server tracers.
//!
//! Tests the performance of different tracers under various scenarios:
//! 1. Cache hit - repeated requests for the same block
//! 2. Fresh block - newly mined block (may be in local DB if chain sync is enabled)
//! 3. Cold request - block not in cache or local DB
//!
//! # Running Tests
//!
//! ```bash
//! TEST_PRIVATE_KEY=<your_private_key> \
//!   MEGA_RETH_URL=http://localhost:49945 \
//!   DEBUG_TRACE_SERVER_URL=http://localhost:18545 \
//!   cargo test --package debug-trace-server --test performance_test -- --nocapture --ignored
//! ```

use std::{
    env,
    time::{Duration, Instant},
};

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_network::TxSignerSync;
use alloy_primitives::{Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

    /// Call with timing, returns (response, duration_ms)
    fn call_timed(&self, method: &str, params: Value) -> Result<(RpcResponse, f64), String> {
        let start = Instant::now();
        let response = self.call(method, params)?;
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        Ok((response, duration_ms))
    }
}

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

/// Performance measurement result
#[derive(Debug, Clone)]
struct PerfResult {
    tracer: String,
    scenario: String,
    block_num: u64,
    duration_ms: f64,
    success: bool,
}

impl PerfResult {
    fn print_header() {
        println!(
            "{:<20} {:<15} {:>10} {:>12} {:>8}",
            "Tracer", "Scenario", "Block", "Time (ms)", "Status"
        );
        println!("{}", "-".repeat(70));
    }

    fn print(&self) {
        println!(
            "{:<20} {:<15} {:>10} {:>12.2} {:>8}",
            self.tracer,
            self.scenario,
            self.block_num,
            self.duration_ms,
            if self.success { "OK" } else { "FAIL" }
        );
    }
}

// ---------------------------------------------------------------------------
// Tracer Configurations
// ---------------------------------------------------------------------------

fn get_tracers() -> Vec<(&'static str, Value)> {
    vec![
        ("default", json!({})),
        ("callTracer", json!({"tracer": "callTracer"})),
        ("callTracer+logs", json!({"tracer": "callTracer", "tracerConfig": {"withLog": true}})),
        ("prestateTracer", json!({"tracer": "prestateTracer"})),
        (
            "prestateTracer+diff",
            json!({"tracer": "prestateTracer", "tracerConfig": {"diffMode": true}}),
        ),
        ("4byteTracer", json!({"tracer": "4byteTracer"})),
        ("noopTracer", json!({"tracer": "noopTracer"})),
        ("flatCallTracer", json!({"tracer": "flatCallTracer"})),
    ]
}

// ---------------------------------------------------------------------------
// Performance Tests
// ---------------------------------------------------------------------------

/// Test tracer performance with cache hits (repeated requests for same block)
#[test]
#[ignore]
fn test_tracer_performance_cache_hit() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Performance Test: Cache Hit Scenario");
    println!("(Repeated requests for the same block - should hit cache)");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Find a block with transactions
    let latest = get_block_number(&mega_reth);
    let mut test_block = latest.saturating_sub(10);

    for bn in (1..latest.saturating_sub(5)).rev() {
        let resp =
            mega_reth.call("eth_getBlockByNumber", json!([format!("0x{:x}", bn), false])).ok();
        if let Some(resp) = resp &&
            let Some(block) = resp.result &&
            let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) &&
            !txs.is_empty()
        {
            test_block = bn;
            break;
        }
    }

    println!("\nTest block: {}", test_block);
    let block_hex = format!("0x{:x}", test_block);
    let tracers = get_tracers();

    // Warm up cache with first request
    println!("\n--- Warming up cache ---");
    for (name, opts) in &tracers {
        let _ = dts.call("debug_traceBlockByNumber", json!([&block_hex, opts]));
        println!("  Warmed: {}", name);
    }

    // Now test cache hits (3 iterations each)
    println!("\n--- Cache Hit Performance (3 iterations each) ---\n");
    PerfResult::print_header();

    let mut results: Vec<PerfResult> = Vec::new();

    for (name, opts) in &tracers {
        let mut times = Vec::new();

        for i in 0..3 {
            let (resp, duration_ms) = dts
                .call_timed("debug_traceBlockByNumber", json!([&block_hex, opts]))
                .expect("Request failed");

            let success = resp.error.is_none();
            times.push(duration_ms);

            let result = PerfResult {
                tracer: name.to_string(),
                scenario: format!("cache_hit_{}", i + 1),
                block_num: test_block,
                duration_ms,
                success,
            };
            result.print();
            results.push(result);
        }

        // Print average
        let avg = times.iter().sum::<f64>() / times.len() as f64;
        println!("{:<20} {:<15} {:>10} {:>12.2} {:>8}", name, "AVERAGE", "", avg, "");
        println!();
    }

    // Summary
    println!("\n{}", "=".repeat(70));
    println!("Cache Hit Summary");
    println!("{}", "=".repeat(70));

    for (name, _) in &tracers {
        let tracer_results: Vec<_> = results.iter().filter(|r| r.tracer == *name).collect();
        let avg =
            tracer_results.iter().map(|r| r.duration_ms).sum::<f64>() / tracer_results.len() as f64;
        let min = tracer_results.iter().map(|r| r.duration_ms).fold(f64::MAX, f64::min);
        let max = tracer_results.iter().map(|r| r.duration_ms).fold(f64::MIN, f64::max);
        println!("{:<20}: avg={:>8.2}ms, min={:>8.2}ms, max={:>8.2}ms", name, avg, min, max);
    }
}

/// Test tracer performance with fresh blocks (newly mined, may be in local DB)
#[test]
#[ignore]
fn test_tracer_performance_fresh_block() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Performance Test: Fresh Block Scenario");
    println!("(Newly mined blocks - first request, may hit local DB)");
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
    let key_bytes = hex::decode(private_key.trim_start_matches("0x")).expect("Invalid key");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("Invalid signer");

    let resp = mega_reth.call("eth_chainId", json!([])).unwrap();
    let chain_id_hex = resp.result.as_ref().unwrap().as_str().unwrap();
    let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16).unwrap();

    let tracers = get_tracers();
    let mut results: Vec<PerfResult> = Vec::new();

    println!("\n--- Fresh Block Performance (1 tx per block, trace immediately) ---\n");
    PerfResult::print_header();

    for (name, opts) in &tracers {
        // Get current nonce
        let resp = mega_reth
            .call("eth_getTransactionCount", json!([format!("{:?}", signer.address()), "pending"]))
            .unwrap();
        let nonce_hex = resp.result.as_ref().unwrap().as_str().unwrap();
        let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16).unwrap();

        // Get gas price
        let resp = mega_reth.call("eth_gasPrice", json!([])).unwrap();
        let gas_hex = resp.result.as_ref().unwrap().as_str().unwrap();
        let gas_price = u128::from_str_radix(gas_hex.trim_start_matches("0x"), 16).unwrap();

        // Send a transaction
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price,
            gas_limit: 100_000,
            to: TxKind::Call(signer.address()),
            value: U256::from(1),
            input: Bytes::default(),
        };

        let signature = signer.sign_transaction_sync(&mut tx.clone()).expect("Sign failed");
        let signed_tx = tx.into_signed(signature);
        let mut encoded = Vec::new();
        signed_tx.rlp_encode(&mut encoded);
        let raw_tx = format!("0x{}", hex::encode(&encoded));

        let resp = mega_reth.call("eth_sendRawTransaction", json!([raw_tx])).expect("Send failed");
        if resp.error.is_some() {
            println!("  Failed to send tx for {}: {:?}", name, resp.error);
            continue;
        }

        let tx_hash = resp.result.as_ref().unwrap().as_str().unwrap().to_string();

        // Wait for mining
        let mut block_number = None;
        for _ in 0..60 {
            std::thread::sleep(Duration::from_millis(500));
            let resp = mega_reth.call("eth_getTransactionReceipt", json!([&tx_hash])).unwrap();
            if let Some(receipt) = resp.result &&
                !receipt.is_null() &&
                let Some(bn) = receipt.get("blockNumber").and_then(|v| v.as_str())
            {
                block_number = Some(u64::from_str_radix(bn.trim_start_matches("0x"), 16).unwrap());
                break;
            }
        }

        let block_number = match block_number {
            Some(bn) => bn,
            None => {
                println!("  Tx not mined for {}", name);
                continue;
            }
        };

        // Wait briefly for witness availability
        std::thread::sleep(Duration::from_secs(1));

        // Trace the fresh block
        let block_hex = format!("0x{:x}", block_number);
        let (resp, duration_ms) = dts
            .call_timed("debug_traceBlockByNumber", json!([&block_hex, opts]))
            .expect("Trace failed");

        let success = resp.error.is_none();
        let result = PerfResult {
            tracer: name.to_string(),
            scenario: "fresh_block".to_string(),
            block_num: block_number,
            duration_ms,
            success,
        };
        result.print();
        results.push(result);
    }

    // Summary
    println!("\n{}", "=".repeat(70));
    println!("Fresh Block Summary");
    println!("{}", "=".repeat(70));

    for result in &results {
        println!(
            "{:<20}: {:>8.2}ms (block {})",
            result.tracer, result.duration_ms, result.block_num
        );
    }
}

/// Test tracer performance with cold requests (blocks not in cache, older blocks)
#[test]
#[ignore]
fn test_tracer_performance_cold_request() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Performance Test: Cold Request Scenario");
    println!("(Older blocks not in cache - pure RPC fetch)");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Find older blocks with transactions (go back further to avoid cache)
    let latest = get_block_number(&mega_reth);
    let mut test_blocks: Vec<u64> = Vec::new();

    for bn in (1..latest.saturating_sub(100)).rev() {
        if test_blocks.len() >= 8 {
            break;
        }
        let resp =
            mega_reth.call("eth_getBlockByNumber", json!([format!("0x{:x}", bn), false])).ok();
        if let Some(resp) = resp &&
            let Some(block) = resp.result &&
            let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) &&
            !txs.is_empty()
        {
            test_blocks.push(bn);
        }
    }

    if test_blocks.is_empty() {
        println!("  No suitable blocks found for cold request test");
        return;
    }

    println!("\nTest blocks: {:?}", test_blocks);
    let tracers = get_tracers();
    let mut results: Vec<PerfResult> = Vec::new();

    println!("\n--- Cold Request Performance (different block per tracer) ---\n");
    PerfResult::print_header();

    for (i, (name, opts)) in tracers.iter().enumerate() {
        let block_num = test_blocks[i % test_blocks.len()];
        let block_hex = format!("0x{:x}", block_num);

        let (resp, duration_ms) = dts
            .call_timed("debug_traceBlockByNumber", json!([&block_hex, opts]))
            .expect("Request failed");

        let success = resp.error.is_none();
        let result = PerfResult {
            tracer: name.to_string(),
            scenario: "cold_request".to_string(),
            block_num,
            duration_ms,
            success,
        };
        result.print();
        results.push(result);
    }

    // Summary
    println!("\n{}", "=".repeat(70));
    println!("Cold Request Summary");
    println!("{}", "=".repeat(70));

    for result in &results {
        println!(
            "{:<20}: {:>8.2}ms (block {})",
            result.tracer, result.duration_ms, result.block_num
        );
    }
}

/// Comprehensive performance comparison across all scenarios
#[test]
#[ignore]
fn test_tracer_performance_comparison() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(80));
    println!("Comprehensive Tracer Performance Comparison");
    println!("{}", "=".repeat(80));

    let private_key = match &config.private_key {
        Some(pk) => pk,
        None => {
            println!("  TEST_PRIVATE_KEY not set, skipping");
            return;
        }
    };

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let dts = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    let key_bytes = hex::decode(private_key.trim_start_matches("0x")).expect("Invalid key");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("Invalid signer");

    let resp = mega_reth.call("eth_chainId", json!([])).unwrap();
    let chain_id_hex = resp.result.as_ref().unwrap().as_str().unwrap();
    let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16).unwrap();

    // Get gas price once
    let resp = mega_reth.call("eth_gasPrice", json!([])).unwrap();
    let gas_hex = resp.result.as_ref().unwrap().as_str().unwrap();
    let gas_price = u128::from_str_radix(gas_hex.trim_start_matches("0x"), 16).unwrap();

    let tracers = get_tracers();

    println!(
        "\n{:<20} {:>12} {:>12} {:>12} {:>12}",
        "Tracer", "Fresh (ms)", "Cache1 (ms)", "Cache2 (ms)", "Cache3 (ms)"
    );
    println!("{}", "-".repeat(80));

    for (name, opts) in &tracers {
        // Get nonce
        let resp = mega_reth
            .call("eth_getTransactionCount", json!([format!("{:?}", signer.address()), "pending"]))
            .unwrap();
        let nonce_hex = resp.result.as_ref().unwrap().as_str().unwrap();
        let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16).unwrap();

        // Send a transaction
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price,
            gas_limit: 100_000,
            to: TxKind::Call(signer.address()),
            value: U256::from(1),
            input: Bytes::default(),
        };

        let signature = signer.sign_transaction_sync(&mut tx.clone()).expect("Sign failed");
        let signed_tx = tx.into_signed(signature);
        let mut encoded = Vec::new();
        signed_tx.rlp_encode(&mut encoded);
        let raw_tx = format!("0x{}", hex::encode(&encoded));

        let resp = mega_reth.call("eth_sendRawTransaction", json!([raw_tx])).expect("Send failed");
        if resp.error.is_some() {
            println!("{:<20} {:>12} {:>12} {:>12} {:>12}", name, "SEND_ERR", "-", "-", "-");
            continue;
        }

        let tx_hash = resp.result.as_ref().unwrap().as_str().unwrap().to_string();

        // Wait for mining
        let mut block_number = None;
        for _ in 0..60 {
            std::thread::sleep(Duration::from_millis(500));
            let resp = mega_reth.call("eth_getTransactionReceipt", json!([&tx_hash])).unwrap();
            if let Some(receipt) = resp.result &&
                !receipt.is_null() &&
                let Some(bn) = receipt.get("blockNumber").and_then(|v| v.as_str())
            {
                block_number = Some(u64::from_str_radix(bn.trim_start_matches("0x"), 16).unwrap());
                break;
            }
        }

        let block_number = match block_number {
            Some(bn) => bn,
            None => {
                println!("{:<20} {:>12} {:>12} {:>12} {:>12}", name, "NOT_MINED", "-", "-", "-");
                continue;
            }
        };

        // Wait for witness
        std::thread::sleep(Duration::from_secs(1));

        let block_hex = format!("0x{:x}", block_number);

        // Fresh request (no cache)
        let (resp, fresh_ms) = dts
            .call_timed("debug_traceBlockByNumber", json!([&block_hex, opts]))
            .unwrap_or_else(|_| {
                (
                    RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: 1,
                        result: None,
                        error: Some(json!({})),
                    },
                    0.0,
                )
            });

        if resp.error.is_some() {
            println!("{:<20} {:>12} {:>12} {:>12} {:>12}", name, "ERROR", "-", "-", "-");
            continue;
        }

        // Cache hit 1
        let (_, cache1_ms) =
            dts.call_timed("debug_traceBlockByNumber", json!([&block_hex, opts])).unwrap();

        // Cache hit 2
        let (_, cache2_ms) =
            dts.call_timed("debug_traceBlockByNumber", json!([&block_hex, opts])).unwrap();

        // Cache hit 3
        let (_, cache3_ms) =
            dts.call_timed("debug_traceBlockByNumber", json!([&block_hex, opts])).unwrap();

        println!(
            "{:<20} {:>12.2} {:>12.2} {:>12.2} {:>12.2}",
            name, fresh_ms, cache1_ms, cache2_ms, cache3_ms
        );
    }

    // Get cache stats
    println!("\n{}", "=".repeat(80));
    println!("Cache Statistics");
    println!("{}", "=".repeat(80));

    let resp = dts.call("debug_getCacheStatus", json!([])).unwrap();
    if let Some(result) = resp.result &&
        let Some(cache) = result.get("responseCache")
    {
        println!("  Entries: {}", cache.get("entryCount").unwrap_or(&json!("?")));
        println!(
            "  Total Bytes: {} ({} MB)",
            cache.get("totalBytes").unwrap_or(&json!("?")),
            cache.get("totalBytesMB").unwrap_or(&json!("?"))
        );
        println!("  Hits: {}", cache.get("hits").unwrap_or(&json!("?")));
        println!("  Misses: {}", cache.get("misses").unwrap_or(&json!("?")));
        println!("  Hit Rate: {}", cache.get("hitRate").unwrap_or(&json!("?")));
    }

    println!("\n{}", "=".repeat(80));
    println!("Performance comparison complete!");
    println!("{}", "=".repeat(80));
}

/// Test debug_traceTransaction performance
#[test]
#[ignore]
fn test_trace_transaction_performance() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Performance Test: debug_traceTransaction");
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

    let key_bytes = hex::decode(private_key.trim_start_matches("0x")).expect("Invalid key");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("Invalid signer");

    let resp = mega_reth.call("eth_chainId", json!([])).unwrap();
    let chain_id_hex = resp.result.as_ref().unwrap().as_str().unwrap();
    let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16).unwrap();

    let resp = mega_reth.call("eth_gasPrice", json!([])).unwrap();
    let gas_hex = resp.result.as_ref().unwrap().as_str().unwrap();
    let gas_price = u128::from_str_radix(gas_hex.trim_start_matches("0x"), 16).unwrap();

    // Send a transaction
    let resp = mega_reth
        .call("eth_getTransactionCount", json!([format!("{:?}", signer.address()), "pending"]))
        .unwrap();
    let nonce_hex = resp.result.as_ref().unwrap().as_str().unwrap();
    let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16).unwrap();

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price,
        gas_limit: 100_000,
        to: TxKind::Call(signer.address()),
        value: U256::from(1),
        input: Bytes::default(),
    };

    let signature = signer.sign_transaction_sync(&mut tx.clone()).expect("Sign failed");
    let signed_tx = tx.into_signed(signature);
    let mut encoded = Vec::new();
    signed_tx.rlp_encode(&mut encoded);
    let raw_tx = format!("0x{}", hex::encode(&encoded));

    let resp = mega_reth.call("eth_sendRawTransaction", json!([raw_tx])).expect("Send failed");
    let tx_hash = resp.result.as_ref().unwrap().as_str().unwrap().to_string();
    println!("\nSent tx: {}", tx_hash);

    // Wait for mining
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(500));
        let resp = mega_reth.call("eth_getTransactionReceipt", json!([&tx_hash])).unwrap();
        if let Some(receipt) = resp.result &&
            !receipt.is_null()
        {
            break;
        }
    }

    std::thread::sleep(Duration::from_secs(2));

    let tracers = get_tracers();

    println!("\n{:<20} {:>12} {:>12} {:>12}", "Tracer", "1st (ms)", "2nd (ms)", "3rd (ms)");
    println!("{}", "-".repeat(60));

    for (name, opts) in &tracers {
        let (resp, t1) = dts.call_timed("debug_traceTransaction", json!([&tx_hash, opts])).unwrap();
        if resp.error.is_some() {
            println!("{:<20} {:>12}", name, "ERROR");
            continue;
        }
        let (_, t2) = dts.call_timed("debug_traceTransaction", json!([&tx_hash, opts])).unwrap();
        let (_, t3) = dts.call_timed("debug_traceTransaction", json!([&tx_hash, opts])).unwrap();

        println!("{:<20} {:>12.2} {:>12.2} {:>12.2}", name, t1, t2, t3);
    }

    println!("\nNote: debug_traceTransaction is NOT cached (depends on tx index in block)");
}
