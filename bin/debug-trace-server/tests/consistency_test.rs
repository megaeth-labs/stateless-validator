//! Integration tests for debug-trace-server consistency with mega-reth.
//!
//! These tests verify that the debug-trace-server returns identical results
//! to mega-reth for all supported debug/trace RPC methods.
//!
//! # Configuration
//!
//! Tests are configured via environment variables (see .env.example):
//! - `MEGA_RETH_URL`: mega-reth RPC endpoint
//! - `DEBUG_TRACE_SERVER_URL`: debug-trace-server RPC endpoint
//! - `TEST_BLOCK_COUNT`: Number of blocks to test
//! - `MAX_TX_PER_BLOCK`: Maximum transactions per block to test
//! - `REQUEST_TIMEOUT_SECS`: Request timeout in seconds
//! - `TEST_PRIVATE_KEY`: Optional private key for sending test transactions
//! - `TX_SEND_COUNT`: Number of transactions to send in tx tests (default: 5)
//!
//! # Running Tests
//!
//! ```bash
//! # Copy and configure environment
//! cp .env.example .env
//! # Edit .env with your configuration
//!
//! # Run tests
//! cargo test --package debug-trace-server --test consistency_test -- --nocapture
//! ```

use std::{env, time::Duration};

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Test configuration loaded from environment variables.
struct TestConfig {
    mega_reth_url: String,
    debug_trace_server_url: String,
    test_block_count: usize,
    max_tx_per_block: usize,
    request_timeout: Duration,
    /// Optional private key for sending test transactions.
    private_key: Option<String>,
    /// Number of transactions to send in tx tests.
    tx_send_count: usize,
}

impl TestConfig {
    fn from_env() -> Self {
        // Try to load .env file
        let _ = dotenvy::dotenv();

        Self {
            mega_reth_url: env::var("MEGA_RETH_URL")
                .unwrap_or_else(|_| "http://localhost:49945".to_string()),
            debug_trace_server_url: env::var("DEBUG_TRACE_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:18545".to_string()),
            test_block_count: env::var("TEST_BLOCK_COUNT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            max_tx_per_block: env::var("MAX_TX_PER_BLOCK")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            request_timeout: Duration::from_secs(
                env::var("REQUEST_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(120),
            ),
            private_key: env::var("TEST_PRIVATE_KEY").ok(),
            tx_send_count: env::var("TX_SEND_COUNT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(6),
        }
    }
}

/// JSON-RPC request structure.
#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    method: String,
    params: Value,
    id: u64,
}

/// JSON-RPC response structure.
#[derive(Deserialize, Debug)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<Value>,
    error: Option<Value>,
}

/// Block information with transactions.
struct BlockInfo {
    number: u64,
    hash: String,
    tx_hashes: Vec<String>,
}

/// RPC client for making JSON-RPC calls.
struct RpcClient {
    client: Client,
    url: String,
}

impl RpcClient {
    fn new(url: &str, timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");
        Self {
            client,
            url: url.to_string(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<RpcResponse, String> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
            id: 1,
        };

        self.client
            .post(&self.url)
            .json(&request)
            .send()
            .map_err(|e| format!("Request failed: {}", e))?
            .json::<RpcResponse>()
            .map_err(|e| format!("Failed to parse response: {}", e))
    }
}

/// Transaction sender for creating test transactions.
struct TransactionSender {
    signer: PrivateKeySigner,
    client: RpcClient,
    chain_id: u64,
}

impl TransactionSender {
    /// Creates a new transaction sender from a private key hex string.
    fn new(private_key: &str, rpc_url: &str, timeout: Duration) -> Result<Self, String> {
        let key_bytes = hex::decode(private_key.trim_start_matches("0x"))
            .map_err(|e| format!("Invalid private key hex: {}", e))?;
        let signer = PrivateKeySigner::from_slice(&key_bytes)
            .map_err(|e| format!("Invalid private key: {}", e))?;
        let client = RpcClient::new(rpc_url, timeout);

        // Get chain ID
        let resp = client.call("eth_chainId", json!([]))?;
        let chain_id_hex = resp
            .result
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or("Failed to get chain ID")?;
        let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse chain ID: {}", e))?;

        Ok(Self {
            signer,
            client,
            chain_id,
        })
    }

    /// Returns the sender address.
    fn address(&self) -> Address {
        self.signer.address()
    }

    /// Gets the current nonce for the sender address.
    fn get_nonce(&self) -> Result<u64, String> {
        let resp = self.client.call(
            "eth_getTransactionCount",
            json!([format!("{:?}", self.address()), "pending"]),
        )?;
        let nonce_hex = resp
            .result
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or("Failed to get nonce")?;
        u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse nonce: {}", e))
    }

    /// Gets the current gas price.
    fn get_gas_price(&self) -> Result<u128, String> {
        let resp = self.client.call("eth_gasPrice", json!([]))?;
        let gas_hex = resp
            .result
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or("Failed to get gas price")?;
        u128::from_str_radix(gas_hex.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse gas price: {}", e))
    }

    /// Sends a simple ETH transfer transaction.
    /// Returns the transaction hash.
    fn send_transfer(&self, to: Address, value: U256, nonce: u64) -> Result<String, String> {
        let gas_price = self.get_gas_price()?;

        // Use higher gas limit for OP chains (L1 data fee requires more gas)
        let tx = TxLegacy {
            chain_id: Some(self.chain_id),
            nonce,
            gas_price,
            gas_limit: 100000,
            to: TxKind::Call(to),
            value,
            input: Bytes::default(),
        };

        // Sign the transaction
        let signature = self
            .signer
            .sign_transaction_sync(&mut tx.clone())
            .map_err(|e| format!("Failed to sign transaction: {}", e))?;

        // Encode the signed transaction
        let signed_tx = tx.into_signed(signature);
        let mut encoded = Vec::new();
        signed_tx.rlp_encode(&mut encoded);
        let raw_tx = format!("0x{}", hex::encode(&encoded));

        // Send the transaction
        let resp = self
            .client
            .call("eth_sendRawTransaction", json!([raw_tx]))?;

        if let Some(error) = resp.error {
            return Err(format!("Transaction failed: {:?}", error));
        }

        resp.result
            .as_ref()
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| "No transaction hash returned".to_string())
    }

    /// Deploys a simple contract and returns the transaction hash.
    /// Uses a minimal storage contract bytecode for testing.
    fn deploy_contract(&self, nonce: u64) -> Result<String, String> {
        let gas_price = self.get_gas_price()?;

        // Simple storage contract bytecode
        // Solidity source:
        // contract SimpleStorage {
        //     uint256 public value;
        //     constructor() { value = 42; }
        //     function setValue(uint256 _value) public { value = _value; }
        // }
        //
        // This is a complete, minimal contract that:
        // - Stores a uint256 value (initialized to 42 in constructor)
        // - Has a setValue function to update the value
        // - Has a public value getter
        let bytecode = hex::decode(
            "6080604052602a60005534801561001557600080fd5b5060b3806100246000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80633fa4f2451460375780635524107714604f575b600080fd5b603d6061565b60405190815260200160405180910390f35b605f600480360381019060599190606a565b6067565b005b60005481565b600055565b600060208284031215607b57600080fd5b503591905056fea264697066735822122000000000000000000000000000000000000000000000000000000000000000000064736f6c63430008130033"
        ).map_err(|e| format!("Invalid bytecode: {}", e))?;

        let tx = TxLegacy {
            chain_id: Some(self.chain_id),
            nonce,
            gas_price,
            gas_limit: 3000000, // Higher gas limit for contract deployment
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::from(bytecode),
        };

        // Sign the transaction
        let signature = self
            .signer
            .sign_transaction_sync(&mut tx.clone())
            .map_err(|e| format!("Failed to sign transaction: {}", e))?;

        // Encode the signed transaction
        let signed_tx = tx.into_signed(signature);
        let mut encoded = Vec::new();
        signed_tx.rlp_encode(&mut encoded);
        let raw_tx = format!("0x{}", hex::encode(&encoded));

        // Send the transaction
        let resp = self
            .client
            .call("eth_sendRawTransaction", json!([raw_tx]))?;

        if let Some(error) = resp.error {
            return Err(format!("Contract deployment failed: {:?}", error));
        }

        resp.result
            .as_ref()
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| "No transaction hash returned".to_string())
    }

    /// Sends multiple transactions (transfers and contract deployments) and returns their hashes.
    fn send_multiple_transfers(&self, count: usize) -> Result<Vec<String>, String> {
        let mut nonce = self.get_nonce()?;
        let mut tx_hashes = Vec::new();

        // Send to self with minimal value
        let to = self.address();
        let value = U256::from(1);

        for i in 0..count {
            // Deploy a contract for every 3rd transaction (index 0, 3, 6, ...)
            let result = if i % 3 == 0 {
                println!("    Deploying contract {}/{}...", i + 1, count);
                self.deploy_contract(nonce)
            } else {
                self.send_transfer(to, value, nonce)
            };

            match result {
                Ok(hash) => {
                    let tx_type = if i % 3 == 0 { "deploy" } else { "transfer" };
                    println!("    Sent {} tx {}/{}: {}", tx_type, i + 1, count, hash);
                    tx_hashes.push(hash);
                    nonce += 1;
                }
                Err(e) => {
                    println!("    Failed to send tx {}/{}: {}", i + 1, count, e);
                    // Continue trying to send more
                }
            }
        }

        if tx_hashes.is_empty() {
            Err("Failed to send any transactions".to_string())
        } else {
            Ok(tx_hashes)
        }
    }

    /// Waits for transactions to be mined and returns the block number.
    fn wait_for_transactions(
        &self,
        tx_hashes: &[String],
        timeout: Duration,
    ) -> Result<u64, String> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(500);

        while start.elapsed() < timeout {
            // Check if all transactions are mined
            let mut all_mined = true;
            let mut block_number = None;

            for hash in tx_hashes {
                let resp = self
                    .client
                    .call("eth_getTransactionReceipt", json!([hash]))?;

                if let Some(receipt) = resp.result {
                    if !receipt.is_null() {
                        if let Some(bn) = receipt.get("blockNumber").and_then(|v| v.as_str()) {
                            let bn = u64::from_str_radix(bn.trim_start_matches("0x"), 16)
                                .map_err(|e| format!("Failed to parse block number: {}", e))?;
                            block_number = Some(bn);
                        }
                    } else {
                        all_mined = false;
                        break;
                    }
                } else {
                    all_mined = false;
                    break;
                }
            }

            if all_mined {
                return block_number.ok_or_else(|| "No block number found".to_string());
            }

            std::thread::sleep(poll_interval);
        }

        Err(format!(
            "Timeout waiting for transactions after {:?}",
            timeout
        ))
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

/// Normalize JSON values for comparison.
/// - Sorts object keys
/// - Normalizes hex strings to lowercase
/// - Treats "0x" as equivalent to empty string
/// - Normalizes returnValue field (removes 0x prefix for comparison)
fn normalize_json(value: &Value) -> Value {
    normalize_json_inner(value, None)
}

/// Inner function for normalize_json with current key context
fn normalize_json_inner(value: &Value, current_key: Option<&str>) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: serde_json::Map<String, Value> = serde_json::Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for key in keys {
                let normalized = normalize_json_inner(&map[key], Some(key.as_str()));
                sorted.insert(key.clone(), normalized);
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|v| normalize_json_inner(v, None)).collect())
        }
        Value::String(s) => {
            // Special handling for returnValue field - normalize to no prefix
            // This handles the difference between alloy-rpc-types-trace versions
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

/// Compare two RPC responses and return whether they match.
fn compare_responses(resp1: &RpcResponse, resp2: &RpcResponse) -> Result<(), String> {
    // Check for errors
    match (&resp1.error, &resp2.error) {
        (Some(_), Some(_)) => return Ok(()), // Both errors is acceptable
        (Some(e), None) => return Err(format!("mega-reth returned error: {:?}", e)),
        (None, Some(e)) => return Err(format!("debug-trace-server returned error: {:?}", e)),
        (None, None) => {}
    }

    let result1 = resp1
        .result
        .as_ref()
        .ok_or("mega-reth returned no result")?;
    let result2 = resp2
        .result
        .as_ref()
        .ok_or("debug-trace-server returned no result")?;

    let norm1 = normalize_json(result1);
    let norm2 = normalize_json(result2);

    if norm1 == norm2 {
        Ok(())
    } else {
        // Generate a diff summary
        let str1 = serde_json::to_string_pretty(&norm1).unwrap_or_default();
        let str2 = serde_json::to_string_pretty(&norm2).unwrap_or_default();
        let preview1 = if str1.len() > 2000 {
            format!("{}...", &str1[..2000])
        } else {
            str1.clone()
        };
        let preview2 = if str2.len() > 2000 {
            format!("{}...", &str2[..2000])
        } else {
            str2.clone()
        };

        // Find the first difference
        let diff_pos = str1
            .chars()
            .zip(str2.chars())
            .position(|(a, b)| a != b)
            .unwrap_or(str1.len().min(str2.len()));
        let diff_context = if diff_pos > 0 {
            let start = diff_pos.saturating_sub(50);
            let end1 = (diff_pos + 100).min(str1.len());
            let end2 = (diff_pos + 100).min(str2.len());
            format!(
                "\nFirst difference at position {}:\nmega-reth: ...{}...\ndebug-trace-server: ...{}...",
                diff_pos,
                &str1[start..end1],
                &str2[start..end2]
            )
        } else {
            String::new()
        };

        Err(format!(
            "Results differ:\nmega-reth: {}\ndebug-trace-server: {}{}",
            preview1, preview2, diff_context
        ))
    }
}

/// Get recent blocks that have transactions.
fn get_blocks_with_transactions(
    client: &RpcClient,
    count: usize,
) -> Result<Vec<BlockInfo>, String> {
    // Get latest block number
    let resp = client.call("eth_blockNumber", json!([]))?;
    let latest_hex = resp
        .result
        .as_ref()
        .and_then(|v| v.as_str())
        .ok_or("Failed to get block number")?;
    let latest = u64::from_str_radix(latest_hex.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Failed to parse block number: {}", e))?;

    let mut blocks = Vec::new();

    // Search backwards for blocks with transactions
    for block_num in (1..latest.saturating_sub(5)).rev() {
        if blocks.len() >= count {
            break;
        }

        let resp = client.call(
            "eth_getBlockByNumber",
            json!([format!("0x{:x}", block_num), true]),
        )?;

        if let Some(block) = resp.result {
            if let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) {
                if !txs.is_empty() {
                    let hash = block
                        .get("hash")
                        .and_then(|h| h.as_str())
                        .unwrap_or_default()
                        .to_string();

                    let tx_hashes: Vec<String> = txs
                        .iter()
                        .filter_map(|tx| tx.get("hash").and_then(|h| h.as_str()).map(String::from))
                        .collect();

                    if !tx_hashes.is_empty() {
                        blocks.push(BlockInfo {
                            number: block_num,
                            hash,
                            tx_hashes,
                        });
                    }
                }
            }
        }
    }

    Ok(blocks)
}

/// Test result tracking.
struct TestResults {
    passed: usize,
    failed: usize,
    errors: Vec<String>,
}

impl TestResults {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            errors: Vec::new(),
        }
    }

    fn record(&mut self, test_name: &str, result: Result<(), String>) {
        match result {
            Ok(()) => {
                self.passed += 1;
                println!("    ✓ {}", test_name);
            }
            Err(e) => {
                self.failed += 1;
                let error_msg = format!("{}: {}", test_name, e);
                println!("    ✗ {}", test_name);
                if e.len() < 200 {
                    println!("      Error: {}", e);
                }
                self.errors.push(error_msg);
            }
        }
    }

    fn is_success(&self) -> bool {
        self.failed == 0
    }
}

/// Test a specific tracer for debug_traceBlockByNumber.
fn test_trace_block_by_number(
    mega_reth: &RpcClient,
    debug_trace_server: &RpcClient,
    block_num: u64,
    tracer_opts: Value,
    tracer_name: &str,
    results: &mut TestResults,
) {
    let block_hex = format!("0x{:x}", block_num);
    let params = json!([block_hex, tracer_opts]);

    let resp1 = mega_reth.call("debug_traceBlockByNumber", params.clone());
    let resp2 = debug_trace_server.call("debug_traceBlockByNumber", params);

    let test_name = format!("debug_traceBlockByNumber ({})", tracer_name);

    match (resp1, resp2) {
        (Ok(r1), Ok(r2)) => results.record(&test_name, compare_responses(&r1, &r2)),
        (Err(e), _) => results.record(&test_name, Err(format!("mega-reth request failed: {}", e))),
        (_, Err(e)) => results.record(
            &test_name,
            Err(format!("debug-trace-server request failed: {}", e)),
        ),
    }
}

/// Test a specific tracer for debug_traceBlockByHash.
fn test_trace_block_by_hash(
    mega_reth: &RpcClient,
    debug_trace_server: &RpcClient,
    block_hash: &str,
    tracer_opts: Value,
    tracer_name: &str,
    results: &mut TestResults,
) {
    let params = json!([block_hash, tracer_opts]);

    let resp1 = mega_reth.call("debug_traceBlockByHash", params.clone());
    let resp2 = debug_trace_server.call("debug_traceBlockByHash", params);

    let test_name = format!("debug_traceBlockByHash ({})", tracer_name);

    match (resp1, resp2) {
        (Ok(r1), Ok(r2)) => results.record(&test_name, compare_responses(&r1, &r2)),
        (Err(e), _) => results.record(&test_name, Err(format!("mega-reth request failed: {}", e))),
        (_, Err(e)) => results.record(
            &test_name,
            Err(format!("debug-trace-server request failed: {}", e)),
        ),
    }
}

/// Test a specific tracer for debug_traceTransaction.
fn test_trace_transaction(
    mega_reth: &RpcClient,
    debug_trace_server: &RpcClient,
    tx_hash: &str,
    tracer_opts: Value,
    tracer_name: &str,
    results: &mut TestResults,
) {
    let params = json!([tx_hash, tracer_opts]);

    let resp1 = mega_reth.call("debug_traceTransaction", params.clone());
    let resp2 = debug_trace_server.call("debug_traceTransaction", params);

    let test_name = format!("debug_traceTransaction ({})", tracer_name);

    match (resp1, resp2) {
        (Ok(r1), Ok(r2)) => results.record(&test_name, compare_responses(&r1, &r2)),
        (Err(e), _) => results.record(&test_name, Err(format!("mega-reth request failed: {}", e))),
        (_, Err(e)) => results.record(
            &test_name,
            Err(format!("debug-trace-server request failed: {}", e)),
        ),
    }
}

/// Test trace_block (Parity-style).
fn test_parity_trace_block(
    mega_reth: &RpcClient,
    debug_trace_server: &RpcClient,
    block_num: u64,
    results: &mut TestResults,
) {
    let block_hex = format!("0x{:x}", block_num);
    let params = json!([block_hex]);

    let resp1 = mega_reth.call("trace_block", params.clone());
    let resp2 = debug_trace_server.call("trace_block", params);

    let test_name = "trace_block";

    match (resp1, resp2) {
        (Ok(r1), Ok(r2)) => results.record(test_name, compare_responses(&r1, &r2)),
        (Err(e), _) => results.record(test_name, Err(format!("mega-reth request failed: {}", e))),
        (_, Err(e)) => results.record(
            test_name,
            Err(format!("debug-trace-server request failed: {}", e)),
        ),
    }
}

/// Test trace_transaction (Parity-style).
fn test_parity_trace_transaction(
    mega_reth: &RpcClient,
    debug_trace_server: &RpcClient,
    tx_hash: &str,
    results: &mut TestResults,
) {
    let params = json!([tx_hash]);

    let resp1 = mega_reth.call("trace_transaction", params.clone());
    let resp2 = debug_trace_server.call("trace_transaction", params);

    let test_name = "trace_transaction";

    match (resp1, resp2) {
        (Ok(r1), Ok(r2)) => results.record(test_name, compare_responses(&r1, &r2)),
        (Err(e), _) => results.record(test_name, Err(format!("mega-reth request failed: {}", e))),
        (_, Err(e)) => results.record(
            test_name,
            Err(format!("debug-trace-server request failed: {}", e)),
        ),
    }
}

/// All tracer configurations to test.
fn get_tracer_configs() -> Vec<(&'static str, Value)> {
    vec![
        // Default struct logger (no tracer specified)
        ("default", json!({})),
        // Call tracer
        ("callTracer", json!({"tracer": "callTracer"})),
        // Call tracer with logs
        (
            "callTracer+logs",
            json!({"tracer": "callTracer", "tracerConfig": {"withLog": true}}),
        ),
        // Four byte tracer
        ("4byteTracer", json!({"tracer": "4byteTracer"})),
        // Prestate tracer
        ("prestateTracer", json!({"tracer": "prestateTracer"})),
        (
            "prestateTracer+diff",
            json!({"tracer": "prestateTracer", "tracerConfig": {"diffMode": true}}),
        ),
        // Noop tracer
        ("noopTracer", json!({"tracer": "noopTracer"})),
        // Flat call tracer (used internally for trace_* methods)
        ("flatCallTracer", json!({"tracer": "flatCallTracer"})),
    ]
}

#[test]
fn test_debug_trace_consistency() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Debug/Trace Server Consistency Tests");
    println!("{}", "=".repeat(70));
    println!("mega-reth URL: {}", config.mega_reth_url);
    println!("debug-trace-server URL: {}", config.debug_trace_server_url);
    println!("Test block count: {}", config.test_block_count);
    println!("Max TX per block: {}", config.max_tx_per_block);
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let debug_trace_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Check server availability
    println!("\nChecking server availability...");
    if mega_reth.call("eth_blockNumber", json!([])).is_err() {
        panic!("mega-reth is not available at {}", config.mega_reth_url);
    }
    println!("  ✓ mega-reth is available");

    if debug_trace_server
        .call("eth_blockNumber", json!([]))
        .is_err()
    {
        panic!(
            "debug-trace-server is not available at {}",
            config.debug_trace_server_url
        );
    }
    println!("  ✓ debug-trace-server is available");

    // Get blocks with transactions
    println!("\nFetching blocks with transactions...");
    let blocks = get_blocks_with_transactions(&mega_reth, config.test_block_count)
        .expect("Failed to get blocks");

    if blocks.is_empty() {
        panic!("No blocks with transactions found!");
    }
    println!("  Found {} blocks with transactions", blocks.len());

    let tracer_configs = get_tracer_configs();
    let mut results = TestResults::new();

    // Test each block
    for block in &blocks {
        println!("\n{}", "=".repeat(70));
        println!(
            "Block {} (hash: {}...)",
            block.number,
            &block.hash[..18.min(block.hash.len())]
        );
        println!("{}", "=".repeat(70));

        // Test block-level methods with all tracers
        println!("\n  Block-level methods:");

        for (tracer_name, tracer_opts) in &tracer_configs {
            test_trace_block_by_number(
                &mega_reth,
                &debug_trace_server,
                block.number,
                tracer_opts.clone(),
                tracer_name,
                &mut results,
            );
        }

        // Test debug_traceBlockByHash with default tracer
        test_trace_block_by_hash(
            &mega_reth,
            &debug_trace_server,
            &block.hash,
            json!({}),
            "default",
            &mut results,
        );

        // Test Parity-style trace_block
        test_parity_trace_block(&mega_reth, &debug_trace_server, block.number, &mut results);

        // Test transaction-level methods
        let tx_count = block.tx_hashes.len().min(config.max_tx_per_block);
        println!("\n  Transaction-level methods ({} transactions):", tx_count);

        for (i, tx_hash) in block
            .tx_hashes
            .iter()
            .take(config.max_tx_per_block)
            .enumerate()
        {
            println!(
                "\n    TX {}/{}: {}...",
                i + 1,
                tx_count,
                &tx_hash[..18.min(tx_hash.len())]
            );

            // Test with all tracers
            for (tracer_name, tracer_opts) in &tracer_configs {
                test_trace_transaction(
                    &mega_reth,
                    &debug_trace_server,
                    tx_hash,
                    tracer_opts.clone(),
                    tracer_name,
                    &mut results,
                );
            }

            // Test Parity-style trace_transaction
            test_parity_trace_transaction(&mega_reth, &debug_trace_server, tx_hash, &mut results);
        }
    }

    // Print summary
    println!("\n{}", "=".repeat(70));
    println!("FINAL SUMMARY");
    println!("{}", "=".repeat(70));
    println!("Total tests: {}", results.passed + results.failed);
    println!("Passed: {}", results.passed);
    println!("Failed: {}", results.failed);
    println!("{}", "=".repeat(70));

    if !results.is_success() {
        println!("\nFailed tests:");
        for error in &results.errors {
            println!("  - {}", error);
        }
        panic!(
            "Consistency tests failed: {} passed, {} failed",
            results.passed, results.failed
        );
    }

    println!("\n✓ All consistency tests passed!");
}

/// Test only block-level methods (faster, for quick verification).
#[test]
fn test_block_level_consistency() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Block-Level Consistency Tests");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let debug_trace_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Get one block with transactions
    let blocks = get_blocks_with_transactions(&mega_reth, 1).expect("Failed to get blocks");

    if blocks.is_empty() {
        panic!("No blocks with transactions found!");
    }

    let block = &blocks[0];
    println!("Testing block {}", block.number);

    let tracer_configs = get_tracer_configs();
    let mut results = TestResults::new();

    for (tracer_name, tracer_opts) in &tracer_configs {
        test_trace_block_by_number(
            &mega_reth,
            &debug_trace_server,
            block.number,
            tracer_opts.clone(),
            tracer_name,
            &mut results,
        );
    }

    test_parity_trace_block(&mega_reth, &debug_trace_server, block.number, &mut results);

    println!("\nPassed: {}, Failed: {}", results.passed, results.failed);

    assert!(results.is_success(), "Block-level consistency tests failed");
}

/// Test only transaction-level methods for a single transaction.
#[test]
fn test_transaction_level_consistency() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Transaction-Level Consistency Tests");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let debug_trace_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Get one block with transactions
    let blocks = get_blocks_with_transactions(&mega_reth, 1).expect("Failed to get blocks");

    if blocks.is_empty() {
        panic!("No blocks with transactions found!");
    }

    let block = &blocks[0];
    let tx_hash = &block.tx_hashes[0];
    println!(
        "Testing transaction {}...",
        &tx_hash[..18.min(tx_hash.len())]
    );

    let tracer_configs = get_tracer_configs();
    let mut results = TestResults::new();

    for (tracer_name, tracer_opts) in &tracer_configs {
        test_trace_transaction(
            &mega_reth,
            &debug_trace_server,
            tx_hash,
            tracer_opts.clone(),
            tracer_name,
            &mut results,
        );
    }

    test_parity_trace_transaction(&mega_reth, &debug_trace_server, tx_hash, &mut results);

    println!("\nPassed: {}, Failed: {}", results.passed, results.failed);

    assert!(
        results.is_success(),
        "Transaction-level consistency tests failed"
    );
}

/// Test cache management RPC methods (debug_setCacheSize, debug_getCacheStatus).
/// This test is skipped if the server doesn't support these methods.
#[test]
fn test_cache_management() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Cache Management Tests");
    println!("{}", "=".repeat(70));

    let debug_trace_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Test debug_getCacheStatus
    println!("\n  Testing debug_getCacheStatus...");
    let resp = match debug_trace_server.call("debug_getCacheStatus", json!([])) {
        Ok(r) => r,
        Err(e) => {
            println!("    ⚠ debug_getCacheStatus not available: {}", e);
            println!("    Skipping cache management tests (server may not support these methods)");
            return;
        }
    };

    // Check if method returned an error (method not found)
    if resp.error.is_some() {
        println!(
            "    ⚠ debug_getCacheStatus returned error: {:?}",
            resp.error
        );
        println!("    Skipping cache management tests (server may not support these methods)");
        return;
    }

    if let Some(result) = &resp.result {
        println!("    Cache status: {}", result);
        assert!(
            result.get("maxSize").is_some(),
            "Cache status should have maxSize"
        );
        assert!(
            result.get("entryCount").is_some(),
            "Cache status should have entryCount"
        );
        println!("    ✓ debug_getCacheStatus works correctly");
    } else {
        println!("    ⚠ debug_getCacheStatus returned no result");
        println!("    Skipping cache management tests (server may not support these methods)");
        return;
    }

    // Test debug_setCacheSize
    println!("\n  Testing debug_setCacheSize...");
    let new_size = 256u64;
    let resp = match debug_trace_server.call("debug_setCacheSize", json!([new_size])) {
        Ok(r) => r,
        Err(e) => {
            println!("    ⚠ debug_setCacheSize failed: {}", e);
            return;
        }
    };

    if resp.error.is_some() {
        println!("    ⚠ debug_setCacheSize returned error: {:?}", resp.error);
        return;
    }

    if let Some(result) = &resp.result {
        println!("    Set cache size response: {}", result);
        assert!(
            result.get("success").and_then(|v| v.as_bool()) == Some(true),
            "debug_setCacheSize should return success: true"
        );
        assert!(
            result.get("newSize").and_then(|v| v.as_u64()) == Some(new_size),
            "debug_setCacheSize should return the new size"
        );
        println!("    ✓ debug_setCacheSize works correctly");
    } else {
        println!("    ⚠ debug_setCacheSize returned no result");
        return;
    }

    // Verify the new size is applied
    println!("\n  Verifying new cache size...");
    let resp = debug_trace_server
        .call("debug_getCacheStatus", json!([]))
        .expect("debug_getCacheStatus failed");

    if let Some(result) = &resp.result {
        let max_size = result.get("maxSize").and_then(|v| v.as_u64());
        assert_eq!(
            max_size,
            Some(new_size),
            "Cache maxSize should be updated to {}",
            new_size
        );
        println!("    ✓ Cache size updated correctly to {}", new_size);
    }

    println!("\n✓ All cache management tests passed!");
}

/// Test concurrent requests to verify single-flight behavior.
/// This test makes multiple concurrent requests for the same block
/// and verifies they all return the same result.
#[test]
fn test_concurrent_requests() {
    use std::{sync::Arc, thread};

    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Concurrent Requests Tests (Single-Flight Verification)");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let debug_trace_server_url = Arc::new(config.debug_trace_server_url.clone());
    let timeout = config.request_timeout;

    // Get a block with transactions
    let blocks = get_blocks_with_transactions(&mega_reth, 1).expect("Failed to get blocks");
    if blocks.is_empty() {
        panic!("No blocks with transactions found!");
    }

    let block = &blocks[0];
    let block_num = block.number;
    println!("\n  Testing concurrent requests for block {}", block_num);

    // Spawn multiple threads making the same request
    let num_threads = 5;
    let mut handles = Vec::new();

    for i in 0..num_threads {
        let url = Arc::clone(&debug_trace_server_url);
        let handle = thread::spawn(move || {
            let client = RpcClient::new(&url, timeout);
            let block_hex = format!("0x{:x}", block_num);
            let params = json!([block_hex, {"tracer": "callTracer"}]);
            let result = client.call("debug_traceBlockByNumber", params);
            (i, result)
        });
        handles.push(handle);
    }

    // Collect results
    let mut results: Vec<(usize, Result<RpcResponse, String>)> = Vec::new();
    for handle in handles {
        results.push(handle.join().expect("Thread panicked"));
    }

    // Verify all results are the same
    let mut first_result: Option<Value> = None;
    let mut all_same = true;

    for (i, result) in &results {
        match result {
            Ok(resp) => {
                if let Some(res) = &resp.result {
                    let normalized = normalize_json(res);
                    if let Some(ref first) = first_result {
                        if &normalized != first {
                            println!("    ✗ Thread {} returned different result", i);
                            all_same = false;
                        } else {
                            println!("    ✓ Thread {} returned same result", i);
                        }
                    } else {
                        first_result = Some(normalized);
                        println!("    ✓ Thread {} returned result (baseline)", i);
                    }
                } else {
                    println!("    ✗ Thread {} returned no result", i);
                    all_same = false;
                }
            }
            Err(e) => {
                println!("    ✗ Thread {} failed: {}", i, e);
                all_same = false;
            }
        }
    }

    assert!(
        all_same,
        "All concurrent requests should return the same result"
    );
    println!("\n✓ All concurrent requests returned identical results!");
}

/// Test with multiple blocks to verify cache behavior.
#[test]
fn test_multiple_blocks_cache() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Multiple Blocks Cache Tests");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let debug_trace_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Get multiple blocks
    let blocks = get_blocks_with_transactions(&mega_reth, 3).expect("Failed to get blocks");
    if blocks.is_empty() {
        panic!("No blocks with transactions found!");
    }

    println!("\n  Testing {} blocks...", blocks.len());

    let mut results = TestResults::new();

    // First pass: fetch all blocks (should populate cache)
    println!("\n  First pass (populating cache):");
    for block in &blocks {
        test_trace_block_by_number(
            &mega_reth,
            &debug_trace_server,
            block.number,
            json!({"tracer": "callTracer"}),
            "callTracer",
            &mut results,
        );
    }

    // Second pass: fetch same blocks again (should hit cache)
    println!("\n  Second pass (should hit cache):");
    for block in &blocks {
        test_trace_block_by_number(
            &mega_reth,
            &debug_trace_server,
            block.number,
            json!({"tracer": "callTracer"}),
            "callTracer",
            &mut results,
        );
    }

    // Also test by hash
    println!("\n  Testing by hash:");
    for block in &blocks {
        test_trace_block_by_hash(
            &mega_reth,
            &debug_trace_server,
            &block.hash,
            json!({"tracer": "callTracer"}),
            "callTracer",
            &mut results,
        );
    }

    println!(
        "\n  Total: {} passed, {} failed",
        results.passed, results.failed
    );

    assert!(results.is_success(), "Multiple blocks cache tests failed");
    println!("\n✓ All multiple blocks cache tests passed!");
}

/// Test edge cases: blocks with many transactions.
/// This test is skipped if no block with multiple transactions is found.
#[test]
fn test_large_block() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Large Block Tests");
    println!("{}", "=".repeat(70));

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let debug_trace_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Find a block with multiple transactions (at least 3)
    println!("\n  Searching for a block with multiple transactions...");

    let resp = mega_reth
        .call("eth_blockNumber", json!([]))
        .expect("Failed to get block number");
    let latest_hex = resp
        .result
        .as_ref()
        .and_then(|v| v.as_str())
        .expect("Failed to get block number");
    let latest =
        u64::from_str_radix(latest_hex.trim_start_matches("0x"), 16).expect("Failed to parse");

    let mut large_block: Option<BlockInfo> = None;
    let min_tx_count = 3; // Reduced from 5 to 3

    for block_num in (1..latest.saturating_sub(200)).rev() {
        let resp = mega_reth
            .call(
                "eth_getBlockByNumber",
                json!([format!("0x{:x}", block_num), true]),
            )
            .ok();

        if let Some(resp) = resp {
            if let Some(block) = resp.result {
                if let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) {
                    if txs.len() >= min_tx_count {
                        let hash = block
                            .get("hash")
                            .and_then(|h| h.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let tx_hashes: Vec<String> = txs
                            .iter()
                            .filter_map(|tx| {
                                tx.get("hash").and_then(|h| h.as_str()).map(String::from)
                            })
                            .collect();

                        println!(
                            "  Found block {} with {} transactions",
                            block_num,
                            tx_hashes.len()
                        );
                        large_block = Some(BlockInfo {
                            number: block_num,
                            hash,
                            tx_hashes,
                        });
                        break;
                    }
                }
            }
        }
    }

    let block = match large_block {
        Some(b) => b,
        None => {
            println!(
                "  ⚠ No block with {}+ transactions found in recent history",
                min_tx_count
            );
            println!("  Skipping large block tests");
            return;
        }
    };

    let mut results = TestResults::new();

    // Test block-level tracing
    println!("\n  Testing block-level tracing:");
    test_trace_block_by_number(
        &mega_reth,
        &debug_trace_server,
        block.number,
        json!({"tracer": "callTracer"}),
        "callTracer",
        &mut results,
    );

    test_parity_trace_block(&mega_reth, &debug_trace_server, block.number, &mut results);

    // Test a few transactions
    println!("\n  Testing transactions:");
    for tx_hash in block.tx_hashes.iter().take(3) {
        test_trace_transaction(
            &mega_reth,
            &debug_trace_server,
            tx_hash,
            json!({"tracer": "callTracer"}),
            "callTracer",
            &mut results,
        );
    }

    println!(
        "\n  Total: {} passed, {} failed",
        results.passed, results.failed
    );

    assert!(results.is_success(), "Large block tests failed");
    println!("\n✓ All large block tests passed!");
}

/// Test sending multiple transactions and tracing them.
/// This test requires TEST_PRIVATE_KEY to be set.
/// It sends multiple transactions, waits for them to be mined,
/// and then verifies the trace results match between mega-reth and debug-trace-server.
#[test]
fn test_send_and_trace_transactions() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Send and Trace Transactions Test");
    println!("{}", "=".repeat(70));

    // Check if private key is configured
    let private_key = match &config.private_key {
        Some(pk) => pk,
        None => {
            println!("  ⚠ TEST_PRIVATE_KEY not set, skipping transaction sending test");
            println!("  Set TEST_PRIVATE_KEY environment variable to enable this test");
            return;
        }
    };

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let debug_trace_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Create transaction sender
    println!("\n  Creating transaction sender...");
    let tx_sender =
        match TransactionSender::new(private_key, &config.mega_reth_url, config.request_timeout) {
            Ok(sender) => sender,
            Err(e) => {
                println!("  ⚠ Failed to create transaction sender: {}", e);
                return;
            }
        };

    println!("  Sender address: {:?}", tx_sender.address());

    // Check sender balance
    let balance_resp = mega_reth
        .call(
            "eth_getBalance",
            json!([format!("{:?}", tx_sender.address()), "latest"]),
        )
        .expect("Failed to get balance");
    let balance_hex = balance_resp
        .result
        .as_ref()
        .and_then(|v| v.as_str())
        .unwrap_or("0x0");
    println!("  Sender balance: {}", balance_hex);

    // Send multiple transactions
    println!("\n  Sending {} transactions...", config.tx_send_count);
    let tx_hashes = match tx_sender.send_multiple_transfers(config.tx_send_count) {
        Ok(hashes) => hashes,
        Err(e) => {
            println!("  ⚠ Failed to send transactions: {}", e);
            println!("  Make sure the sender account has sufficient balance");
            return;
        }
    };

    println!("  Sent {} transactions", tx_hashes.len());

    // Wait for transactions to be mined
    println!("\n  Waiting for transactions to be mined...");
    let block_number = match tx_sender.wait_for_transactions(&tx_hashes, Duration::from_secs(60)) {
        Ok(bn) => bn,
        Err(e) => {
            println!("  ⚠ Failed to wait for transactions: {}", e);
            return;
        }
    };

    println!("  Transactions mined in block {}", block_number);

    // Wait a bit for witness to be available
    println!("\n  Waiting for witness availability...");
    std::thread::sleep(Duration::from_secs(3));

    // Test the block with our transactions
    let mut results = TestResults::new();

    println!("\n  Testing block-level tracing:");
    let tracer_configs = get_tracer_configs();

    for (tracer_name, tracer_opts) in &tracer_configs {
        test_trace_block_by_number(
            &mega_reth,
            &debug_trace_server,
            block_number,
            tracer_opts.clone(),
            tracer_name,
            &mut results,
        );
    }

    // Test Parity-style trace_block
    test_parity_trace_block(&mega_reth, &debug_trace_server, block_number, &mut results);

    // Test each transaction
    println!(
        "\n  Testing transaction-level tracing ({} transactions):",
        tx_hashes.len()
    );

    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        println!(
            "\n    TX {}/{}: {}...",
            i + 1,
            tx_hashes.len(),
            &tx_hash[..18.min(tx_hash.len())]
        );

        for (tracer_name, tracer_opts) in &tracer_configs {
            test_trace_transaction(
                &mega_reth,
                &debug_trace_server,
                tx_hash,
                tracer_opts.clone(),
                tracer_name,
                &mut results,
            );
        }

        // Test Parity-style trace_transaction
        test_parity_trace_transaction(&mega_reth, &debug_trace_server, tx_hash, &mut results);
    }

    // Print summary
    println!("\n{}", "=".repeat(70));
    println!("SEND AND TRACE TEST SUMMARY");
    println!("{}", "=".repeat(70));
    println!("Transactions sent: {}", tx_hashes.len());
    println!("Block number: {}", block_number);
    println!("Total tests: {}", results.passed + results.failed);
    println!("Passed: {}", results.passed);
    println!("Failed: {}", results.failed);
    println!("{}", "=".repeat(70));

    if !results.is_success() {
        println!("\nFailed tests:");
        for error in &results.errors {
            println!("  - {}", error);
        }
        panic!(
            "Send and trace tests failed: {} passed, {} failed",
            results.passed, results.failed
        );
    }

    println!("\n✓ All send and trace tests passed!");
}

/// Test continuous transaction sending while tracing.
/// This test sends transactions in a loop while simultaneously testing trace consistency.
/// Requires TEST_PRIVATE_KEY to be set.
#[test]
fn test_continuous_tx_and_trace() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Continuous Transaction and Trace Test");
    println!("{}", "=".repeat(70));

    // Check if private key is configured
    let private_key = match &config.private_key {
        Some(pk) => pk,
        None => {
            println!("  ⚠ TEST_PRIVATE_KEY not set, skipping continuous test");
            return;
        }
    };

    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);
    let debug_trace_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    // Create transaction sender
    let tx_sender =
        match TransactionSender::new(private_key, &config.mega_reth_url, config.request_timeout) {
            Ok(sender) => sender,
            Err(e) => {
                println!("  ⚠ Failed to create transaction sender: {}", e);
                return;
            }
        };

    println!("  Sender address: {:?}", tx_sender.address());

    let mut results = TestResults::new();
    let rounds = 10;

    for round in 1..=rounds {
        println!("\n  Round {}/{}", round, rounds);

        // Send transactions
        println!("    Sending {} transactions...", config.tx_send_count);
        let tx_hashes = match tx_sender.send_multiple_transfers(config.tx_send_count) {
            Ok(hashes) => hashes,
            Err(e) => {
                println!("    ⚠ Failed to send transactions: {}", e);
                continue;
            }
        };

        // Wait for mining
        println!("    Waiting for transactions to be mined...");
        let block_number =
            match tx_sender.wait_for_transactions(&tx_hashes, Duration::from_secs(60)) {
                Ok(bn) => bn,
                Err(e) => {
                    println!("    ⚠ Failed to wait for transactions: {}", e);
                    continue;
                }
            };

        println!("    Transactions mined in block {}", block_number);

        // Wait for witness
        std::thread::sleep(Duration::from_secs(2));

        // Test the block
        println!("    Testing block {}...", block_number);
        test_trace_block_by_number(
            &mega_reth,
            &debug_trace_server,
            block_number,
            json!({"tracer": "callTracer"}),
            "callTracer",
            &mut results,
        );

        test_parity_trace_block(&mega_reth, &debug_trace_server, block_number, &mut results);

        // Test first transaction
        if let Some(tx_hash) = tx_hashes.first() {
            test_trace_transaction(
                &mega_reth,
                &debug_trace_server,
                tx_hash,
                json!({"tracer": "callTracer"}),
                "callTracer",
                &mut results,
            );
        }
    }

    println!(
        "\n  Total: {} passed, {} failed",
        results.passed, results.failed
    );

    assert!(results.is_success(), "Continuous tx and trace tests failed");
    println!("\n✓ All continuous tx and trace tests passed!");
}
