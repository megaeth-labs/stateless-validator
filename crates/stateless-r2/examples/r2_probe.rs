//! Live probe for the R2 witness read path (read-only against a real bucket).
//!
//! Prints the ALPN-negotiated HTTP version, then drives the production [`R2ObjectFetcher`]
//! through a concurrency ladder of real witness GETs, reporting wall time / latency
//! percentiles / failures per level. Useful for validating credentials and bucket wiring
//! at deploy time, and for measuring a host's realistic per-GET latency and safe
//! concurrency before setting `--r2-max-concurrent-requests`.
//!
//! Finding this probe documents (2026-08): **R2's S3 endpoint negotiates HTTP/1.1 only** —
//! the client offers h2 via ALPN, the server picks `http/1.1` (the CDN-fronted gateway by
//! contrast picks h2). Every in-flight GET therefore holds its own connection, which is why
//! the fetcher's concurrency cap must respect the egress IP's connection budget.
//!
//! Block hashes are resolved through the gateway so the probe needs no local node.
//!
//! ```text
//! export DEBUG_TRACE_SERVER_R2_ENDPOINT=...     # https://<account>.r2.cloudflarestorage.com
//! export DEBUG_TRACE_SERVER_R2_BUCKET=...
//! export DEBUG_TRACE_SERVER_R2_ACCESS_KEY_ID=...
//! export DEBUG_TRACE_SERVER_R2_SECRET_ACCESS_KEY=...
//! export DEBUG_TRACE_SERVER_WITNESS_ENDPOINT=...  # gateway URL for hash resolution
//! cargo run -p stateless-r2 --example r2_probe -- [start_block] [count] [ladder]
//! cargo run -p stateless-r2 --example r2_probe -- 22962000 128 16,48
//! ```

use std::{
    env,
    error::Error,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use stateless_r2::fetch::{R2ObjectFetcher, RetryPacing};

fn envv(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing env {name}"))
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

/// Resolves `count` block hashes starting at `start` through the gateway (batches of 100).
async fn resolve_hashes(
    gateway: &str,
    start: u64,
    count: u64,
) -> Result<Vec<(u64, String)>, Box<dyn Error>> {
    let client = reqwest::Client::new();
    let mut out = Vec::new();
    let mut n = start;
    while (out.len() as u64) < count {
        let chunk: Vec<u64> = (n..(n + 100).min(start + count)).collect();
        n = chunk[chunk.len() - 1] + 1;
        let body: Vec<serde_json::Value> = chunk
            .iter()
            .enumerate()
            .map(|(i, b)| {
                serde_json::json!({
                    "jsonrpc": "2.0", "id": i, "method": "eth_getBlockByNumber",
                    "params": [format!("{:#x}", b), false],
                })
            })
            .collect();
        let raw = client
            .post(gateway)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body)?)
            .send()
            .await?
            .bytes()
            .await?;
        let resp: Vec<serde_json::Value> = serde_json::from_slice(&raw)?;
        for item in resp {
            let id = item["id"].as_u64().ok_or("batch item without id")? as usize;
            let hash = item["result"]["hash"]
                .as_str()
                .ok_or_else(|| format!("no hash for block {}", chunk[id]))?;
            out.push((chunk[id], hash.to_string()));
        }
    }
    out.sort();
    Ok(out)
}

async fn run_level(
    fetcher: &R2ObjectFetcher,
    blocks: &[(u64, String)],
) -> (f64, Vec<f64>, usize, u64) {
    let lat = Arc::new(Mutex::new(Vec::new()));
    let mut fails = 0usize;
    let mut bytes = 0u64;
    let t0 = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for (number, hash) in blocks.iter().cloned() {
        let fetcher = fetcher.clone();
        let lat = Arc::clone(&lat);
        tasks.spawn(async move {
            let t = Instant::now();
            let r = fetcher.get_block_object(number, hash, 1, None, || ()).await;
            r.map(|f| {
                lat.lock().unwrap().push(t.elapsed().as_secs_f64() * 1000.0);
                f.bytes.len() as u64
            })
        });
    }
    while let Some(res) = tasks.join_next().await {
        match res.unwrap() {
            Ok(b) => bytes += b,
            Err(_) => fails += 1,
        }
    }
    let wall = t0.elapsed().as_secs_f64();
    let mut lat = Arc::try_unwrap(lat).unwrap().into_inner().unwrap();
    lat.sort_by(f64::total_cmp);
    (wall, lat, fails, bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let start: u64 = args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(22_962_000);
    let count: u64 = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(128);
    let ladder: Vec<usize> = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("16,48")
        .split(',')
        .map(|x| x.parse())
        .collect::<Result<_, _>>()?;

    let endpoint = envv("DEBUG_TRACE_SERVER_R2_ENDPOINT")?;
    let bucket = envv("DEBUG_TRACE_SERVER_R2_BUCKET")?;
    let ak = envv("DEBUG_TRACE_SERVER_R2_ACCESS_KEY_ID")?;
    let sk = envv("DEBUG_TRACE_SERVER_R2_SECRET_ACCESS_KEY")?;
    let gateway = envv("DEBUG_TRACE_SERVER_WITNESS_ENDPOINT")?;

    // An unauthenticated GET is enough to learn the ALPN outcome — the error response
    // still carries the negotiated version.
    let probe_client = reqwest::Client::builder().build()?;
    match probe_client.get(&endpoint).send().await {
        Ok(resp) => println!("[alpn] negotiated {:?}, status {}", resp.version(), resp.status()),
        Err(e) => println!("[alpn] probe request failed: {e}"),
    }

    println!("[prep] resolving {count} hashes from block {start} via gateway ...");
    let blocks = resolve_hashes(&gateway, start, count).await?;
    println!("[prep] resolved {}", blocks.len());

    for &conc in &ladder {
        let fetcher = R2ObjectFetcher::new(
            &endpoint,
            bucket.clone(),
            ak.clone(),
            sk.clone(),
            Duration::from_secs(30),
            RetryPacing { initial: Duration::from_millis(1), max: Duration::from_millis(2) },
            Some(conc),
        )
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
        let (wall, lat, fails, bytes) = run_level(&fetcher, &blocks).await;
        println!(
            "[conc={conc:3}] wall={:6.0}ms  ok={:3} fail={fails:3}  {:5.1} wit/s  {:6.2}MB  \
             p50/p90/p99/max={:.0}/{:.0}/{:.0}/{:.0}ms",
            wall * 1000.0,
            blocks.len() - fails,
            (blocks.len() - fails) as f64 / wall,
            bytes as f64 / 1e6,
            pct(&lat, 0.5),
            pct(&lat, 0.9),
            pct(&lat, 0.99),
            lat.last().copied().unwrap_or(f64::NAN),
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(())
}
