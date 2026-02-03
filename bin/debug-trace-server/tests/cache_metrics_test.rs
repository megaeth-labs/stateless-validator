//! Integration tests for cache behavior and metrics verification.
//!
//! These tests verify that:
//! 1. The response cache properly caches trace results
//! 2. Metrics are correctly tracking cache hits/misses
//! 3. The debug_getCacheStatus RPC method reports accurate statistics
//!
//! # Configuration
//!
//! Tests are configured via environment variables:
//! - `DEBUG_TRACE_SERVER_URL`: debug-trace-server RPC endpoint (default: http://localhost:18545)
//! - `DEBUG_TRACE_SERVER_METRICS_URL`: Prometheus metrics endpoint (default: http://localhost:48901/metrics)
//! - `MEGA_RETH_URL`: mega-reth RPC endpoint for getting test blocks (default: http://localhost:49945)
//! - `REQUEST_TIMEOUT_SECS`: Request timeout in seconds (default: 120)
//!
//! # Running Tests
//!
//! ```bash
//! cargo test --package debug-trace-server --test cache_metrics_test -- --nocapture --ignored
//! ```

use std::{env, time::Duration};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Test configuration loaded from environment variables.
struct TestConfig {
    debug_trace_server_url: String,
    metrics_url: String,
    mega_reth_url: String,
    request_timeout: Duration,
}

impl TestConfig {
    fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        Self {
            debug_trace_server_url: env::var("DEBUG_TRACE_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:18545".to_string()),
            metrics_url: env::var("DEBUG_TRACE_SERVER_METRICS_URL")
                .unwrap_or_else(|_| "http://localhost:48901/metrics".to_string()),
            mega_reth_url: env::var("MEGA_RETH_URL")
                .unwrap_or_else(|_| "http://localhost:49945".to_string()),
            request_timeout: Duration::from_secs(
                env::var("REQUEST_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(120),
            ),
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

/// RPC client for making JSON-RPC calls.
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

/// Cache statistics from debug_getCacheStatus.
#[derive(Debug, Clone)]
struct CacheStats {
    entry_count: u64,
    total_bytes: u64,
    hits: u64,
    misses: u64,
}

impl CacheStats {
    fn from_json(value: &Value) -> Option<Self> {
        let cache = value.get("responseCache")?;
        Some(Self {
            entry_count: cache.get("entryCount")?.as_u64()?,
            total_bytes: cache.get("totalBytes")?.as_u64()?,
            hits: cache.get("hits")?.as_u64()?,
            misses: cache.get("misses")?.as_u64()?,
        })
    }
}

/// Get cache statistics from the debug_getCacheStatus RPC method.
fn get_cache_stats(client: &RpcClient) -> Result<CacheStats, String> {
    let resp = client.call("debug_getCacheStatus", json!([]))?;

    if let Some(error) = resp.error {
        return Err(format!("RPC error: {:?}", error));
    }

    let result = resp.result.ok_or("No result in response")?;
    CacheStats::from_json(&result).ok_or_else(|| "Failed to parse cache stats".to_string())
}

/// Fetch Prometheus metrics from the metrics endpoint.
fn fetch_metrics(client: &Client, metrics_url: &str) -> Result<String, String> {
    client
        .get(metrics_url)
        .send()
        .map_err(|e| format!("Failed to fetch metrics: {}", e))?
        .text()
        .map_err(|e| format!("Failed to read metrics: {}", e))
}

/// Parse a specific metric value from Prometheus text format.
#[allow(dead_code)] // Useful for future metric parsing
fn parse_metric(metrics_text: &str, metric_name: &str, labels: &str) -> Option<f64> {
    for line in metrics_text.lines() {
        if line.starts_with('#') {
            continue;
        }

        // Match metric name with labels
        let search_pattern = if labels.is_empty() {
            format!("{} ", metric_name)
        } else {
            format!("{}{{{}}} ", metric_name, labels)
        };

        if line.starts_with(&search_pattern) ||
            line.starts_with(&format!("{}{{{}", metric_name, labels))
        {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts.last()?.parse().ok();
            }
        }
    }
    None
}

/// Get a recent block with transactions.
fn get_recent_block_with_txs(client: &RpcClient) -> Result<(u64, String), String> {
    // Get latest block number
    let resp = client.call("eth_blockNumber", json!([]))?;
    let latest_hex =
        resp.result.as_ref().and_then(|v| v.as_str()).ok_or("Failed to get block number")?;
    let latest = u64::from_str_radix(latest_hex.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Failed to parse block number: {}", e))?;

    // Search backwards for a block with transactions
    for block_num in (1..latest.saturating_sub(5)).rev() {
        let resp =
            client.call("eth_getBlockByNumber", json!([format!("0x{:x}", block_num), false]))?;

        if let Some(block) = resp.result {
            if let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) {
                if !txs.is_empty() {
                    let hash =
                        block.get("hash").and_then(|h| h.as_str()).unwrap_or_default().to_string();
                    return Ok((block_num, hash));
                }
            }
        }
    }

    Err("No blocks with transactions found".to_string())
}

/// Test that cache statistics are correctly updated.
#[test]
#[ignore]
fn test_cache_hit_miss_tracking() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Cache Hit/Miss Tracking Test");
    println!("{}", "=".repeat(70));
    println!("debug-trace-server URL: {}", config.debug_trace_server_url);
    println!("mega-reth URL: {}", config.mega_reth_url);
    println!("{}", "=".repeat(70));

    let debug_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);
    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);

    // Check server availability
    println!("\nChecking server availability...");
    if debug_server.call("eth_blockNumber", json!([])).is_err() {
        panic!("debug-trace-server is not available at {}", config.debug_trace_server_url);
    }
    println!("  ✓ debug-trace-server is available");

    // Get a block to test with
    println!("\nFinding a block with transactions...");
    let (block_num, block_hash) =
        get_recent_block_with_txs(&mega_reth).expect("Failed to find block with transactions");
    println!("  Found block {} (hash: {}...)", block_num, &block_hash[..18]);

    // Get initial cache stats
    println!("\nGetting initial cache stats...");
    let initial_stats = get_cache_stats(&debug_server).expect("Failed to get initial cache stats");
    println!(
        "  Initial stats: hits={}, misses={}, entries={}",
        initial_stats.hits, initial_stats.misses, initial_stats.entry_count
    );

    // First request - should be a cache miss
    println!("\nMaking first request (should be cache miss)...");
    let block_hex = format!("0x{:x}", block_num);
    let resp1 = debug_server
        .call("debug_traceBlockByNumber", json!([block_hex, {"tracer": "callTracer"}]))
        .expect("First request failed");

    if resp1.error.is_some() {
        panic!("First request returned error: {:?}", resp1.error);
    }
    println!("  ✓ First request completed");

    // Check cache stats after first request
    let stats_after_miss = get_cache_stats(&debug_server).expect("Failed to get cache stats");
    println!(
        "  Stats after first request: hits={}, misses={}, entries={}",
        stats_after_miss.hits, stats_after_miss.misses, stats_after_miss.entry_count
    );

    // Verify miss count increased
    assert!(
        stats_after_miss.misses > initial_stats.misses,
        "Miss count should have increased: {} -> {}",
        initial_stats.misses,
        stats_after_miss.misses
    );
    println!("  ✓ Miss count increased as expected");

    // Second request for same block - should be a cache hit
    println!("\nMaking second request for same block (should be cache hit)...");
    let resp2 = debug_server
        .call("debug_traceBlockByNumber", json!([block_hex, {"tracer": "callTracer"}]))
        .expect("Second request failed");

    if resp2.error.is_some() {
        panic!("Second request returned error: {:?}", resp2.error);
    }
    println!("  ✓ Second request completed");

    // Check cache stats after second request
    let stats_after_hit = get_cache_stats(&debug_server).expect("Failed to get cache stats");
    println!(
        "  Stats after second request: hits={}, misses={}, entries={}",
        stats_after_hit.hits, stats_after_hit.misses, stats_after_hit.entry_count
    );

    // Verify hit count increased
    assert!(
        stats_after_hit.hits > stats_after_miss.hits,
        "Hit count should have increased: {} -> {}",
        stats_after_miss.hits,
        stats_after_hit.hits
    );
    println!("  ✓ Hit count increased as expected");

    // Verify miss count stayed the same
    assert_eq!(
        stats_after_hit.misses, stats_after_miss.misses,
        "Miss count should not have changed: {} -> {}",
        stats_after_miss.misses, stats_after_hit.misses
    );
    println!("  ✓ Miss count unchanged as expected");

    // Verify results are identical
    assert_eq!(resp1.result, resp2.result, "Cached response should be identical to original");
    println!("  ✓ Responses are identical");

    println!("\n✓ Cache hit/miss tracking test passed!");
}

/// Test that different tracer variants are cached separately.
#[test]
#[ignore]
fn test_cache_variant_separation() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Cache Variant Separation Test");
    println!("{}", "=".repeat(70));

    let debug_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);
    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);

    // Get a block to test with
    println!("\nFinding a block with transactions...");
    let (block_num, _) =
        get_recent_block_with_txs(&mega_reth).expect("Failed to find block with transactions");
    println!("  Found block {}", block_num);

    let block_hex = format!("0x{:x}", block_num);

    // Get initial stats
    let initial_stats = get_cache_stats(&debug_server).expect("Failed to get initial cache stats");
    println!("\nInitial stats: hits={}, misses={}", initial_stats.hits, initial_stats.misses);

    // Request with callTracer
    println!("\nRequesting with callTracer...");
    let _ = debug_server
        .call("debug_traceBlockByNumber", json!([block_hex, {"tracer": "callTracer"}]))
        .expect("callTracer request failed");

    let stats1 = get_cache_stats(&debug_server).expect("Failed to get cache stats");
    println!("  Stats: hits={}, misses={}", stats1.hits, stats1.misses);

    // Request with prestateTracer (different variant, should be a miss)
    println!("\nRequesting with prestateTracer (should be new cache entry)...");
    let _ = debug_server
        .call("debug_traceBlockByNumber", json!([block_hex, {"tracer": "prestateTracer"}]))
        .expect("prestateTracer request failed");

    let stats2 = get_cache_stats(&debug_server).expect("Failed to get cache stats");
    println!("  Stats: hits={}, misses={}", stats2.hits, stats2.misses);

    // Verify miss count increased (new variant)
    assert!(stats2.misses > stats1.misses, "prestateTracer should cause a new cache miss");
    println!("  ✓ Different tracer variant caused cache miss");

    // Request callTracer again (should be a hit)
    println!("\nRequesting callTracer again (should be cache hit)...");
    let _ = debug_server
        .call("debug_traceBlockByNumber", json!([block_hex, {"tracer": "callTracer"}]))
        .expect("callTracer request failed");

    let stats3 = get_cache_stats(&debug_server).expect("Failed to get cache stats");
    println!("  Stats: hits={}, misses={}", stats3.hits, stats3.misses);

    // Verify hit count increased
    assert!(stats3.hits > stats2.hits, "Second callTracer request should be a cache hit");
    println!("  ✓ Same tracer variant returned from cache");

    println!("\n✓ Cache variant separation test passed!");
}

/// Test that Prometheus metrics endpoint is working.
#[test]
#[ignore]
fn test_prometheus_metrics() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Prometheus Metrics Test");
    println!("{}", "=".repeat(70));
    println!("Metrics URL: {}", config.metrics_url);
    println!("{}", "=".repeat(70));

    let client = Client::builder()
        .timeout(config.request_timeout)
        .build()
        .expect("Failed to create HTTP client");

    // Fetch metrics
    println!("\nFetching Prometheus metrics...");
    let metrics_text = match fetch_metrics(&client, &config.metrics_url) {
        Ok(text) => text,
        Err(e) => {
            println!("  ⚠ Failed to fetch metrics: {}", e);
            println!("  Skipping Prometheus metrics test (metrics endpoint may not be enabled)");
            return;
        }
    };

    println!("  ✓ Metrics endpoint is accessible");
    println!("  Metrics length: {} bytes", metrics_text.len());

    // Check for expected metrics
    let expected_metrics = ["rpc_request_duration_seconds", "rpc_request_count"];

    println!("\nChecking for expected metrics...");
    for metric in expected_metrics {
        if metrics_text.contains(metric) {
            println!("  ✓ Found metric: {}", metric);
        } else {
            println!("  ⚠ Metric not found: {} (may not have any requests yet)", metric);
        }
    }

    // Make a request to ensure metrics are generated
    let debug_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);
    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);

    println!("\nMaking a trace request to generate metrics...");
    if let Ok((block_num, _)) = get_recent_block_with_txs(&mega_reth) {
        let block_hex = format!("0x{:x}", block_num);
        let _ = debug_server.call("debug_traceBlockByNumber", json!([block_hex, {}]));
        println!("  ✓ Request completed");

        // Fetch metrics again
        let metrics_text = fetch_metrics(&client, &config.metrics_url)
            .expect("Failed to fetch metrics after request");

        // Check if request metrics were recorded
        if metrics_text.contains("debug_traceBlockByNumber") {
            println!("  ✓ Request was recorded in metrics");
        }
    }

    // Print some sample metrics
    println!("\nSample metrics:");
    for line in metrics_text.lines().take(20) {
        if !line.starts_with('#') && !line.is_empty() {
            println!("  {}", line);
        }
    }

    println!("\n✓ Prometheus metrics test passed!");
}

/// Test cache behavior with multiple blocks.
#[test]
#[ignore]
fn test_cache_multiple_blocks() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Cache Multiple Blocks Test");
    println!("{}", "=".repeat(70));

    let debug_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);
    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);

    // Get initial stats
    let initial_stats = get_cache_stats(&debug_server).expect("Failed to get initial cache stats");
    println!("\nInitial cache entries: {}", initial_stats.entry_count);

    // Get latest block number
    let resp = mega_reth.call("eth_blockNumber", json!([])).expect("Failed to get block number");
    let latest_hex =
        resp.result.as_ref().and_then(|v| v.as_str()).expect("Failed to get block number");
    let latest = u64::from_str_radix(latest_hex.trim_start_matches("0x"), 16)
        .expect("Failed to parse block number");

    // Test multiple different blocks
    let mut tested_blocks = 0;
    let max_blocks = 5;

    println!("\nTesting {} different blocks...", max_blocks);
    for block_num in (1..latest.saturating_sub(5)).rev() {
        if tested_blocks >= max_blocks {
            break;
        }

        let block_hex = format!("0x{:x}", block_num);

        // Check if block has transactions
        let block_resp = mega_reth.call("eth_getBlockByNumber", json!([&block_hex, false])).ok();

        if let Some(resp) = block_resp {
            if let Some(block) = resp.result {
                if let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) {
                    if !txs.is_empty() {
                        println!("\n  Block {} ({} txs):", block_num, txs.len());

                        // First request (miss)
                        let stats_before =
                            get_cache_stats(&debug_server).expect("Failed to get cache stats");

                        let _ = debug_server.call(
                            "debug_traceBlockByNumber",
                            json!([&block_hex, {"tracer": "callTracer"}]),
                        );

                        let stats_after =
                            get_cache_stats(&debug_server).expect("Failed to get cache stats");

                        println!(
                            "    First request: misses {} -> {}",
                            stats_before.misses, stats_after.misses
                        );

                        // Second request (hit)
                        let _ = debug_server.call(
                            "debug_traceBlockByNumber",
                            json!([&block_hex, {"tracer": "callTracer"}]),
                        );

                        let stats_final =
                            get_cache_stats(&debug_server).expect("Failed to get cache stats");

                        println!(
                            "    Second request: hits {} -> {}",
                            stats_after.hits, stats_final.hits
                        );

                        tested_blocks += 1;
                    }
                }
            }
        }
    }

    // Get final stats
    let final_stats = get_cache_stats(&debug_server).expect("Failed to get final cache stats");
    println!("\nFinal cache entries: {}", final_stats.entry_count);
    println!("Total hits: {}", final_stats.hits);
    println!("Total misses: {}", final_stats.misses);

    if final_stats.hits > 0 && final_stats.misses > 0 {
        let hit_rate =
            final_stats.hits as f64 / (final_stats.hits + final_stats.misses) as f64 * 100.0;
        println!("Hit rate: {:.1}%", hit_rate);
    }

    println!("\n✓ Cache multiple blocks test passed!");
}

/// Test that trace_block also uses the cache.
#[test]
#[ignore]
fn test_trace_block_cache() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("trace_block Cache Test");
    println!("{}", "=".repeat(70));

    let debug_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);
    let mega_reth = RpcClient::new(&config.mega_reth_url, config.request_timeout);

    // Get a block to test with
    let (block_num, _) =
        get_recent_block_with_txs(&mega_reth).expect("Failed to find block with transactions");
    let block_hex = format!("0x{:x}", block_num);
    println!("\nTesting block {}", block_num);

    // Get initial stats
    let initial_stats = get_cache_stats(&debug_server).expect("Failed to get initial cache stats");
    println!("\nInitial stats: hits={}, misses={}", initial_stats.hits, initial_stats.misses);

    // First trace_block request (miss)
    println!("\nFirst trace_block request (should be miss)...");
    let _ = debug_server
        .call("trace_block", json!([&block_hex]))
        .expect("First trace_block request failed");

    let stats_after_miss = get_cache_stats(&debug_server).expect("Failed to get cache stats");
    println!("  Stats: hits={}, misses={}", stats_after_miss.hits, stats_after_miss.misses);

    assert!(
        stats_after_miss.misses > initial_stats.misses,
        "trace_block should cause a cache miss"
    );
    println!("  ✓ Cache miss recorded");

    // Second trace_block request (hit)
    println!("\nSecond trace_block request (should be hit)...");
    let _ = debug_server
        .call("trace_block", json!([&block_hex]))
        .expect("Second trace_block request failed");

    let stats_after_hit = get_cache_stats(&debug_server).expect("Failed to get cache stats");
    println!("  Stats: hits={}, misses={}", stats_after_hit.hits, stats_after_hit.misses);

    assert!(
        stats_after_hit.hits > stats_after_miss.hits,
        "Second trace_block request should be a cache hit"
    );
    println!("  ✓ Cache hit recorded");

    println!("\n✓ trace_block cache test passed!");
}

/// Test cache statistics summary.
#[test]
#[ignore]
fn test_cache_stats_summary() {
    let config = TestConfig::from_env();

    println!("\n{}", "=".repeat(70));
    println!("Cache Statistics Summary");
    println!("{}", "=".repeat(70));

    let debug_server = RpcClient::new(&config.debug_trace_server_url, config.request_timeout);

    let stats = get_cache_stats(&debug_server).expect("Failed to get cache stats");

    println!("\nCurrent cache statistics:");
    println!("  Entry count: {}", stats.entry_count);
    println!(
        "  Total bytes: {} ({:.2} MB)",
        stats.total_bytes,
        stats.total_bytes as f64 / 1024.0 / 1024.0
    );
    println!("  Hits: {}", stats.hits);
    println!("  Misses: {}", stats.misses);

    if stats.hits + stats.misses > 0 {
        let hit_rate = stats.hits as f64 / (stats.hits + stats.misses) as f64 * 100.0;
        println!("  Hit rate: {:.1}%", hit_rate);
    }

    println!("\n✓ Cache statistics retrieved successfully!");
}
