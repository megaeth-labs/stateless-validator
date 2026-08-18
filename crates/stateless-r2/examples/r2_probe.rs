//! Live probe for the R2 witness read path (read-only against a real bucket).
//!
//! Prints the ALPN-negotiated HTTP version, then drives the production [`R2ObjectFetcher`]
//! through a concurrency ladder of real witness GETs, reporting wall time / latency
//! percentiles / failures per level. Useful for validating credentials and bucket wiring
//! at deploy time, and for measuring a host's realistic per-GET latency and safe
//! concurrency before setting `--r2-max-concurrent-requests`.
//!
//! Finding this probe documents (2026-08): **R2's bare S3 endpoint negotiates HTTP/1.1
//! only** — the client offers h2 via ALPN, the server picks `http/1.1` — so on that
//! endpoint every in-flight GET holds its own connection and the fetcher's concurrency cap
//! must respect the egress IP's connection budget. R2 **custom domains** ride the regular
//! CDN stack and do negotiate h2: set `R2_PROBE_CUSTOM_DOMAIN=https://<domain>` to probe
//! one instead, through the production fetcher's custom-domain mode (unsigned GETs of
//! `/{key}` — expect the ALPN line to say HTTP/2 and high concurrency to hold few
//! connections).
//!
//! Block hashes are resolved through the gateway so the probe needs no local node.
//!
//! Because the probe drives the production fetcher, its requests carry the production header
//! set — notably **no `User-Agent`**. That makes it the right acceptance tool for a
//! Cloudflare-fronted domain: a `curl` check can pass where production fails, since curl
//! sends a UA and Cloudflare's Browser Integrity Check challenges requests without one.
//!
//! ```text
//! export DEBUG_TRACE_SERVER_WITNESS_ENDPOINT=...  # gateway URL for hash resolution
//! # S3 mode:
//! export DEBUG_TRACE_SERVER_R2_ENDPOINT=...     # https://<account>.r2.cloudflarestorage.com
//! export DEBUG_TRACE_SERVER_R2_BUCKET=...
//! export DEBUG_TRACE_SERVER_R2_ACCESS_KEY_ID=...
//! export DEBUG_TRACE_SERVER_R2_SECRET_ACCESS_KEY=...
//! # or custom-domain mode (Access token pair optional — omit on an IP-allowlisted domain):
//! export R2_PROBE_CUSTOM_DOMAIN=https://witness.example.com
//! export R2_PROBE_ACCESS_CLIENT_ID=... R2_PROBE_ACCESS_CLIENT_SECRET=...
//! cargo run -p stateless-r2 --example r2_probe -- [start_block] [count] [ladder]
//! cargo run -p stateless-r2 --example r2_probe -- 22962000 128 16,48
//! ```

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use stateless_r2::fetch::{
    CfAccessCredentials, DEFAULT_CONNECT_TIMEOUT, FetchTimeouts, R2ObjectFetcher, RetryPacing,
};

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
    let end = start + count;
    let mut n = start;
    // Driven by the block range rather than by `out.len()`: a gateway that answers a batch
    // with fewer items than requested must still terminate the loop instead of walking `n`
    // forward into an empty range and indexing off the end of it.
    while n < end {
        let chunk: Vec<u64> = (n..(n + 100).min(end)).collect();
        // Non-empty while `n < end`, so the last-element index cannot underflow.
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
            // The id is echoed by the gateway, so it is untrusted input into this index.
            let number = *chunk
                .get(id)
                .ok_or_else(|| format!("gateway echoed out-of-range batch id {id}"))?;
            let hash = item["result"]["hash"]
                .as_str()
                .ok_or_else(|| format!("no hash for block {number}"))?;
            out.push((number, hash.to_string()));
        }
    }
    out.sort();
    // A gateway that repeats an id would otherwise inflate the per-rung GET count.
    out.dedup();
    Ok(out)
}

/// One concurrency rung's measurements.
struct LevelStats {
    wall: f64,
    /// Per-GET latency in ms with the fetcher's own queue wait subtracted, sorted. Folding
    /// queue wait in would report the probe's self-imposed cap as R2 slowness, and would make
    /// a tighter rung look slower than a looser one on an identical link.
    lat: Vec<f64>,
    /// Per-GET time in ms spent waiting on the concurrency cap, sorted.
    queue: Vec<f64>,
    fails: usize,
    bytes: u64,
    /// Failure count and one sample message per `R2GetError` kind, so a wall of failures says
    /// *why* rather than only how many.
    errors: BTreeMap<&'static str, (usize, String)>,
}

async fn run_level(fetcher: &R2ObjectFetcher, blocks: &[(u64, String)]) -> LevelStats {
    let samples = Arc::new(Mutex::new((Vec::new(), Vec::new())));
    let mut fails = 0usize;
    let mut bytes = 0u64;
    let mut errors: BTreeMap<&'static str, (usize, String)> = BTreeMap::new();
    let t0 = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for (number, hash) in blocks.iter().cloned() {
        let fetcher = fetcher.clone();
        let samples = Arc::clone(&samples);
        tasks.spawn(async move {
            let t = Instant::now();
            let r = fetcher.get_block_object(number, hash, 1, None, || ()).await;
            r.map(|f| {
                let net = t.elapsed().saturating_sub(f.queue_wait);
                let mut s = samples.lock().unwrap();
                s.0.push(net.as_secs_f64() * 1000.0);
                s.1.push(f.queue_wait.as_secs_f64() * 1000.0);
                f.bytes.len() as u64
            })
        });
    }
    while let Some(res) = tasks.join_next().await {
        match res.unwrap() {
            Ok(b) => bytes += b,
            Err(e) => {
                fails += 1;
                errors.entry(e.kind()).or_insert_with(|| (0, e.to_string())).0 += 1;
            }
        }
    }
    let wall = t0.elapsed().as_secs_f64();
    let (mut lat, mut queue) = Arc::try_unwrap(samples).unwrap().into_inner().unwrap();
    lat.sort_by(f64::total_cmp);
    queue.sort_by(f64::total_cmp);
    LevelStats { wall, lat, queue, fails, bytes, errors }
}

fn report(tag: &str, conc: usize, s: &LevelStats, n: usize) {
    println!(
        "[{tag} conc={conc:3}] wall={:6.0}ms  ok={:3} fail={:3}  {:5.1} wit/s           {:6.2}MB  p50/p90/p99/max={:.0}/{:.0}/{:.0}/{:.0}ms  queue p50/max={:.0}/{:.0}ms",
        s.wall * 1000.0,
        n - s.fails,
        s.fails,
        (n - s.fails) as f64 / s.wall,
        s.bytes as f64 / 1e6,
        pct(&s.lat, 0.5),
        pct(&s.lat, 0.9),
        pct(&s.lat, 0.99),
        s.lat.last().copied().unwrap_or(f64::NAN),
        pct(&s.queue, 0.5),
        s.queue.last().copied().unwrap_or(f64::NAN),
    );
    // Without this a failed rung prints only a count, leaving a rejected token, an unattached
    // domain, a wrong bucket and an unreachable host indistinguishable from each other.
    for (kind, (count, sample)) in &s.errors {
        println!("           fail kind={kind:9} n={count:3}  e.g. {sample}");
    }
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

    let gateway = envv("DEBUG_TRACE_SERVER_WITNESS_ENDPOINT")?;
    let custom_domain = env::var("R2_PROBE_CUSTOM_DOMAIN").ok();
    let alpn_target = match &custom_domain {
        Some(domain) => domain.clone(),
        None => envv("DEBUG_TRACE_SERVER_R2_ENDPOINT")?,
    };

    // An unauthenticated GET is enough to learn the ALPN outcome — the error response
    // still carries the negotiated version.
    // Redirects disabled to match the production fetcher: an Access-protected domain answers
    // an unauthenticated GET with a 302 to the login page, and following it would report the
    // login host's negotiated version instead of the domain under test.
    let probe_client =
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
    match probe_client.get(&alpn_target).send().await {
        Ok(resp) => println!("[alpn] negotiated {:?}, status {}", resp.version(), resp.status()),
        Err(e) => println!("[alpn] probe request failed: {e}"),
    }

    println!("[prep] resolving {count} hashes from block {start} via gateway ...");
    let blocks = resolve_hashes(&gateway, start, count).await?;
    println!("[prep] resolved {}", blocks.len());
    if blocks.is_empty() {
        return Err(
            "gateway resolved no block hashes: check the endpoint and the block range".into()
        );
    }
    if (blocks.len() as u64) < count {
        println!(
            "[prep] WARNING: gateway returned {} of {count} requested blocks; every rung runs \
             that many GETs",
            blocks.len()
        );
    }

    let timeouts =
        FetchTimeouts { per_attempt: Duration::from_secs(30), connect: DEFAULT_CONNECT_TIMEOUT };
    let pacing = RetryPacing { initial: Duration::from_millis(1), max: Duration::from_millis(2) };
    // A half-set pair silently probing unauthenticated would defeat the probe's purpose of
    // validating credentials, so it is a hard error (the binaries get this check from clap).
    let access = match (
        env::var("R2_PROBE_ACCESS_CLIENT_ID").ok(),
        env::var("R2_PROBE_ACCESS_CLIENT_SECRET").ok(),
    ) {
        (Some(client_id), Some(client_secret)) => {
            println!("[access] sending CF Access service-token headers");
            Some(CfAccessCredentials { client_id, client_secret })
        }
        (None, None) => None,
        _ => {
            return Err(
                "set both R2_PROBE_ACCESS_CLIENT_ID and R2_PROBE_ACCESS_CLIENT_SECRET, or neither"
                    .into(),
            );
        }
    };
    for &conc in &ladder {
        // A fresh fetcher per rung so each level starts on a cold connection pool —
        // production behavior through the production client, custom-domain mode included.
        let (tag, fetcher) = match &custom_domain {
            Some(domain) => (
                "custom",
                R2ObjectFetcher::new_custom_domain(
                    domain,
                    access.clone(),
                    timeouts,
                    pacing,
                    Some(conc),
                ),
            ),
            None => (
                "s3",
                R2ObjectFetcher::new(
                    &envv("DEBUG_TRACE_SERVER_R2_ENDPOINT")?,
                    envv("DEBUG_TRACE_SERVER_R2_BUCKET")?,
                    envv("DEBUG_TRACE_SERVER_R2_ACCESS_KEY_ID")?,
                    envv("DEBUG_TRACE_SERVER_R2_SECRET_ACCESS_KEY")?,
                    timeouts,
                    pacing,
                    Some(conc),
                ),
            ),
        };
        let fetcher = fetcher.map_err(|e| -> Box<dyn Error> { e.into() })?;
        let stats = run_level(&fetcher, &blocks).await;
        report(tag, conc, &stats, blocks.len());
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(())
}
