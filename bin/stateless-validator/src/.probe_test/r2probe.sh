#!/usr/bin/env bash
# r2probe — 单文件版 R2 自定义域名探针（自解压 + 自构建 + 运行）
#
# 把这一个文件放进 stateless-validator 仓库树里的任何位置,然后直接跑:
#     ./r2probe.sh preflight
#     ./r2probe.sh ladder 0 500 1x96,4x96,1x200,4x200
#
# 它会自己向上找到仓库根(靠 crates/stateless-r2 认路),把 Rust 源码解到
# <仓库根>/target/r2probe-build/ 下,用 release 构建一次,之后直接复用二进制。
#
# 为什么必须待在仓库里:探针以 path 依赖引入 stateless-r2,跑的是**生产 fetcher**。
# 我们的客户端不发 User-Agent,而 Cloudflare 的 Browser Integrity Check 会质询无 UA
# 的请求——curl 会发 UA,所以 curl 测通不代表生产测通;httpx/aiohttp 同理测的是那个
# 客户端的 h2 实现。把 fetcher 换掉,这个工具就失去意义了。
#
# --readme 打印完整操作说明。
set -euo pipefail

if [ "${1:-}" = "--readme" ]; then
  cat <<'MD_EOF'
# r2probe — R2 自定义域名探针

验证 `witness.megaeth.com` 这条 witness 读取路径：Access 是否生效、凭据对不对、有没有真的走 HTTP/2、404 会不会被边缘缓存，以及在不同**连接数 × 并发**组合下的吞吐与延迟。

**它为什么不是 curl 或 Python 脚本。** 探针用 `path` 依赖引入 `stateless-r2`，跑的是**生产 fetcher 本身**。这不是洁癖：我们的客户端**不发 `User-Agent`**，而 Cloudflare 的 Browser Integrity Check 会质询无 UA 的请求——curl 会发 UA，所以 curl 测通不代表生产测通。同样，httpx/aiohttp 测到的是那个客户端的 h2 实现，不是线上跑的 hyper（`witness-path-bench.py` 建在 aiohttp 上，只有 HTTP/1.1，做不了这件事）。

不在仓库里（`validator-data/` 被 `.gitignore` 覆盖），是运维工具，不进 CI。

---

## 1. 准备凭据

两个文件，**必须用 `printf '%s'`**——尾随换行不能作为 HTTP header 值，fetcher 会在启动时按名报错：

```bash
cd validator-data/debug_trace_server
umask 077
printf '%s' '<32位十六进制>.access' > .r2_access_id
printf '%s' '<64位十六进制>'        > .r2_access_secret
wc -c .r2_access_id .r2_access_secret     # 期望 39 和 64
```

⚠ **Client ID 必须带 `.access` 后缀**。运维交付的是 32 位十六进制，少了后缀会被 Access 以 403 拒绝——而 403 在我们代码里不可重试，validator 的 R2 模式又没有 RPC 回退，等于直接停摆。preflight 会明确抓出这一条。

## 2. 构建

```bash
cd validator-data/debug_trace_server/r2probe
cargo build --release
```

依赖同仓库的 `crates/stateless-r2`（相对路径 `../../../crates/stateless-r2`），所以要在仓库树里构建。

## 3. 环境变量

```bash
cd validator-data/debug_trace_server/r2probe
export R2_PROBE_DOMAIN=https://witness.megaeth.com
export R2_PROBE_GATEWAY=https://mainnet.megaeth.com/rpc   # 仅用于把块号解析成哈希
export R2_PROBE_ID_FILE=$PWD/../.r2_access_id
export R2_PROBE_SECRET_FILE=$PWD/../.r2_access_secret
```

在 tko 上把 `R2_PROBE_GATEWAY` 换成本机节点（`http://127.0.0.1:9547`）更快，且不占公共网关配额。

## 4. preflight —— 先跑这个

```bash
./target/release/r2probe preflight
```

全绿长这样：

```
  ok   Access rejects unauthenticated     status=403 Forbidden
  ok   credentials accepted               status=404 Not Found (want 404 = past Access, object absent)
  ok   404 not served from cache          cf-cache-status: MISS -> EXPIRED
  ok   authenticated witness GET          block 24351809, 20694 bytes, key block/...
  ok   negotiated protocol                h2
  => PREFLIGHT PASSED
```

五条各自的含义：

| 检查 | 失败意味着 |
| --- | --- |
| Access rejects unauthenticated | 域名没被 Access 保护，桶对公网可读 |
| credentials accepted | 凭据被拒。403 基本就是 client id 少了 `.access` |
| 404 not served from cache | 边缘缓存了 404。读取方会先于上传探测对象，被缓存的 404 会把 tip-following 卡住整个负缓存 TTL |
| authenticated witness GET | 取不到真实对象——桶、key 布局或权限有问题 |
| **negotiated protocol** | **不是 `h2` 就地停下。** 多路复用没了、h2 调参全部失效，这次改造的收益归零。查 DNS 是不是橙云代理、zone 的 HTTP/2 开关 |

preflight 不过就不要往下跑——压测只会把同一个错误重复几十万次。

## 5. ladder —— 连接数 × 并发

```bash
./target/release/r2probe ladder 0 500 1x96,2x96,4x96,8x96,1x200,4x200,8x400
```

参数：`ladder [起始块] [每档对象数] [档位]`。起始块传 `0` = `tip - 2000`（远低于上传前沿，miss 就是真的有洞）。

档位写作 `<分片数>x<总并发>`。**分片数就是连接数**——每个分片是一个独立的 `R2ObjectFetcher`，各自持有一个 `reqwest::Client`，而 hyper-util 对每个 host 只保一条 h2 连接。

### 为什么要测分片

Cloudflare 边缘每连接 `SETTINGS_MAX_CONCURRENT_STREAMS=100`（对本域名 `nghttp -nv` 实测确认）。当前实现只有一个 `Client`，所以**真正在途的请求永远不可能超过 100**——把并发设成 200 只会让另外 100 个在 hyper 内部排队。多连接是突破 100 的唯一办法，另外还带来各自独立的拥塞窗口和 TCP 队头阻塞域。

代价是要改代码（`R2ObjectFetcher` 持有 N 个 `Client` 并轮询）。**先测，值不值得做由数据说了算。**

### 怎么读

- 比较**相同总并发**下不同分片数的行，这样"连接数"这个变量才被隔离出来。
- 某一档 `lat p50` 暴涨而 `queue p50` 反而趋近 0 = 已经越过每连接 stream 上限。那段等待跑进了 h2 连接内部，既算 per-attempt 超时，又不出现在 queue-wait 指标里。
- `wit/s` 随分片数上升到某处走平，走平点就是这台机器的真实上限。

### 一条参考数据（以及它的局限）

Mac 上跑三遍，每档 200 个对象：

| 配置 | 吞吐 | lat p50（三次） | queue |
| --- | ---: | ---: | ---: |
| 1x96 | 0.63 MB/s | 3063 / 3982 / 3900 | 2135ms |
| 4x96 | 0.73 MB/s | 2173 / 2794 / 2976 | 1443ms |
| 1x200 | 0.57 MB/s | 9692 / 7462 / 7606 | **0ms** |
| 4x200 | 0.65 MB/s | 5082 / 6179 / 5648 | **0ms** |

**吞吐那列作废**——0.57–0.73 MB/s 是家用宽带打满，四个配置分不出来。**tko 本机直连才测得到吞吐。**

**延迟那列可信**，两个排序三次全部一致，是协议层现象、与带宽无关：`4x96` 每次都优于 `1x96`（96 < 100 一条连接装得下，所以这是多连接本身的收益，不是 stream 上限）；`1x200` 每次都远差于 `4x200` 且 queue 恒为 0（stream 上限被越过的确证）。

## 6. 验证边缘上限（可选，一条命令）

```bash
nghttp -nv https://witness.megaeth.com/ 2>&1 | grep -A3 "recv SETTINGS"
#   [SETTINGS_MAX_CONCURRENT_STREAMS(0x03):100]
```

换域名或 Cloudflare 改计划后值得重跑——整个并发策略都挂在这个数上。

## 7. 跑完发回什么

preflight 与 ladder 的**完整控制台输出**（`| tee r2probe_tko.log`）。两者都只打到 stdout，不写文件。
MD_EOF
  exit 0
fi

# 向上找仓库根
root=$(pwd)
while [ "$root" != "/" ] && [ ! -d "$root/crates/stateless-r2" ]; do
  root=$(dirname "$root")
done
if [ ! -d "$root/crates/stateless-r2" ]; then
  echo "错误:没找到 stateless-validator 仓库根(靠 crates/stateless-r2 认路)。" >&2
  echo "      请把 r2probe.sh 放进仓库树里再跑——它需要 path 依赖引入生产 fetcher。" >&2
  exit 1
fi

build="$root/target/r2probe-build"
mkdir -p "$build/src"

cat > "$build/Cargo.toml" <<TOML_EOF
[package]
name = "r2probe"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
stateless-r2 = { path = "$root/crates/stateless-r2" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "http2", "json"] }
serde_json = "1"
TOML_EOF

cat > "$build/src/main.rs" <<'RS_EOF'
//! R2 witness custom-domain probe — functional acceptance and a connection/concurrency ladder.
//!
//! Standalone on purpose (not part of the workspace build), but it depends on `stateless-r2` by
//! path so the GETs it makes are byte-for-byte the ones the validator and the trace server make.
//! That matters more than it sounds: our client sends **no `User-Agent`**, and Cloudflare's
//! Browser Integrity Check challenges requests without one — so a `curl` check can pass on a
//! zone where production would be 403'd on every GET. Likewise an httpx/aiohttp probe would
//! characterise *that* client's HTTP/2, not the hyper stack we actually ship.
//!
//! Two subcommands:
//!
//!   preflight  Functional checks — Access enforcement, an authenticated fetch, the protocol
//!              actually negotiated, and the 404 negative-cache gate. Run this first; if it
//!              fails, a load run only repeats the same error a few hundred thousand times.
//!
//!   ladder     Throughput/latency across `<shards>x<total concurrency>` rungs. `shards` is the
//!              number of independent `R2ObjectFetcher`s, and since hyper-util keeps exactly one
//!              h2 connection per host per client, shard count *is* connection count. Comparing
//!              rungs at equal total concurrency isolates the effect of spreading load over more
//!              connections — which is the only way past the edge's 100-streams-per-connection
//!              limit, and also gives each connection its own congestion window and its own TCP
//!              head-of-line domain.
//!
//! Credentials come from files, never the environment, so they cannot show up in a process
//! listing or a shell history. Write them with `printf '%s'` — a trailing newline cannot be an
//! HTTP header value and the fetcher refuses it at construction.

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use stateless_r2::{
    fetch::{
        CfAccessCredentials, DEFAULT_CONNECT_TIMEOUT, FetchTimeouts, R2ObjectFetcher, RetryPacing,
    },
    keys,
};

type Res<T> = Result<T, Box<dyn Error>>;

const USAGE: &str = "\
usage:
  r2probe preflight
  r2probe ladder [start_block] [count] [rungs]

  start_block  0 (default) = tip - 2000, safely below the uploader frontier
  count        objects per rung (default 200)
  rungs        comma-separated <shards>x<total concurrency>
               default 1x48,1x96,2x96,4x96,1x200,4x200

environment:
  R2_PROBE_DOMAIN        https://witness.megaeth.com
  R2_PROBE_GATEWAY       JSON-RPC URL used only to resolve block hashes
  R2_PROBE_ID_FILE       file holding the CF Access client id   (needs the .access suffix)
  R2_PROBE_SECRET_FILE   file holding the CF Access client secret
";

fn env_var(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing env {name}"))
}

fn read_secret_file(name: &str) -> Res<String> {
    let path = env_var(name)?;
    let raw = std::fs::read_to_string(&path)?;
    if raw.trim_end_matches(['\n', '\r']).len() != raw.len() {
        return Err(format!("{path} ends with a newline; write it with `printf '%s'`").into());
    }
    if raw.is_empty() {
        return Err(format!("{path} is empty").into());
    }
    Ok(raw)
}

struct Config {
    domain: String,
    gateway: String,
    access: CfAccessCredentials,
}

impl Config {
    fn from_env() -> Res<Self> {
        Ok(Self {
            domain: env_var("R2_PROBE_DOMAIN")?,
            gateway: env_var("R2_PROBE_GATEWAY")?,
            access: CfAccessCredentials {
                client_id: read_secret_file("R2_PROBE_ID_FILE")?,
                client_secret: read_secret_file("R2_PROBE_SECRET_FILE")?,
            },
        })
    }

    fn fetcher(&self, concurrency: usize) -> Res<R2ObjectFetcher> {
        R2ObjectFetcher::new_custom_domain(
            &self.domain,
            Some(self.access.clone()),
            FetchTimeouts {
                per_attempt: Duration::from_secs(30),
                connect: DEFAULT_CONNECT_TIMEOUT,
            },
            RetryPacing { initial: Duration::from_millis(1), max: Duration::from_millis(2) },
            Some(concurrency),
        )
        .map_err(Into::into)
    }
}

/// A bare client matching production's header fingerprint — notably no `User-Agent`, so the
/// edge sees what our fetcher would send. Used only where response *headers* are the subject
/// (Access enforcement, `cf-cache-status`), which the fetcher does not surface.
fn raw_client() -> Res<reqwest::Client> {
    Ok(reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?)
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

// ------------------------------------------------------------------ block hashes

/// Resolves `count` block hashes from `start` through the gateway, in batches of 100.
async fn resolve_hashes(gateway: &str, start: u64, count: u64) -> Res<Vec<(u64, String)>> {
    let client = reqwest::Client::new();
    let (mut out, end, mut n) = (Vec::new(), start + count, start);
    // Driven by the block range, not by how many hashes came back: a gateway answering a batch
    // short must still terminate the loop rather than walk into an empty range.
    while n < end {
        let chunk: Vec<u64> = (n..(n + 100).min(end)).collect();
        n = chunk[chunk.len() - 1] + 1;
        let body: Vec<serde_json::Value> = chunk
            .iter()
            .enumerate()
            .map(|(i, b)| {
                serde_json::json!({
                    "jsonrpc": "2.0", "id": i, "method": "eth_getBlockByNumber",
                    "params": [format!("{b:#x}"), false],
                })
            })
            .collect();
        let resp: Vec<serde_json::Value> = client
            .post(gateway)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body)?)
            .send()
            .await?
            .json()
            .await?;
        for item in resp {
            let id = item["id"].as_u64().ok_or("batch item without id")? as usize;
            // The id is echoed by the gateway, so it is untrusted input into this index.
            let number = *chunk.get(id).ok_or_else(|| format!("gateway echoed batch id {id}"))?;
            let Some(hash) = item["result"]["hash"].as_str() else { continue };
            out.push((number, hash.to_string()));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

async fn chain_tip(gateway: &str) -> Res<u64> {
    let v: serde_json::Value = reqwest::Client::new()
        .post(gateway)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#)
        .send()
        .await?
        .json()
        .await?;
    let hex = v["result"].as_str().ok_or("no eth_blockNumber result")?;
    Ok(u64::from_str_radix(hex.trim_start_matches("0x"), 16)?)
}

// ------------------------------------------------------------------ preflight

fn verdict(ok: bool, name: &str, detail: impl std::fmt::Display) -> bool {
    println!("  {} {name:<34} {detail}", if ok { "ok  " } else { "FAIL" });
    ok
}

async fn preflight(cfg: &Config) -> Res<()> {
    println!("preflight against {}\n", cfg.domain);
    let raw = raw_client()?;
    let mut all = true;

    // 1. Access must actually be enforcing. A key that cannot exist is enough: Access is
    //    evaluated at the edge, before the request ever reaches the bucket.
    let probe_key = format!("__probe__/nonexistent-{}", std::process::id());
    let url = format!("{}/{}", cfg.domain.trim_end_matches('/'), probe_key);
    let r = raw.get(&url).send().await?;
    all &= verdict(
        r.status() == 403 || r.status().is_redirection(),
        "Access rejects unauthenticated",
        format!("status={} (want 403 or a redirect to the login page)", r.status()),
    );

    // 2. The same request with credentials must get past Access. A 404 is the success signal:
    //    it means the edge let us through and the bucket simply has no such object.
    let authed = raw
        .get(&url)
        .header("CF-Access-Client-Id", &cfg.access.client_id)
        .header("CF-Access-Client-Secret", &cfg.access.client_secret)
        .send()
        .await?;
    let status = authed.status();
    let cache_1 = header(&authed, "cf-cache-status");
    all &= verdict(
        status == 404,
        "credentials accepted",
        format!(
            "status={status} (want 404 = past Access, object absent){}",
            if status == 403 {
                "  <- 403 means the credentials were refused; is the client id missing its \
                 `.access` suffix?"
            } else {
                ""
            }
        ),
    );

    // 3. The 404 negative-cache gate. R2 mode has no RPC fallback and the reader probes ahead of
    //    the uploader, so a cached pre-upload 404 would pin a miss for the negative-cache TTL and
    //    stall tip-following. Never HIT is the requirement.
    let second = raw
        .get(&url)
        .header("CF-Access-Client-Id", &cfg.access.client_id)
        .header("CF-Access-Client-Secret", &cfg.access.client_secret)
        .send()
        .await?;
    let cache_2 = header(&second, "cf-cache-status");
    let hit = cache_2.eq_ignore_ascii_case("HIT");
    all &= verdict(
        !hit,
        "404 not served from cache",
        format!("cf-cache-status: {cache_1} -> {cache_2} (HIT would stall tip-following)"),
    );

    // 4. The protocol the production fetcher actually negotiated, on a real object.
    let tip = chain_tip(&cfg.gateway).await?;
    let blocks = resolve_hashes(&cfg.gateway, tip - 2_000, 1).await?;
    let (number, hash) = blocks.first().ok_or("gateway resolved no hash")?;
    let fetcher = cfg.fetcher(1)?;
    let fetched = fetcher.get_block_object(*number, hash, 3, None, || ()).await;
    match &fetched {
        Ok(o) => {
            all &= verdict(
                true,
                "authenticated witness GET",
                format!("block {number}, {} bytes, key {}", o.bytes.len(),
                        keys::block_object_key(*number, hash)),
            );
        }
        Err(e) => all &= verdict(false, "authenticated witness GET", e),
    }
    let proto = fetcher.negotiated_http_version().unwrap_or("unknown");
    all &= verdict(
        proto == "h2",
        "negotiated protocol",
        format!(
            "{proto}{}",
            if proto == "h2" {
                ""
            } else {
                "  <- degraded; multiplexing is gone and the h2 tuning is inert"
            }
        ),
    );

    println!("\n  => {}", if all { "PREFLIGHT PASSED" } else { "PREFLIGHT FAILED — fix before load testing" });
    if !all {
        return Err("preflight failed".into());
    }
    Ok(())
}

fn header(r: &reqwest::Response, name: &str) -> String {
    r.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("(absent)").to_string()
}

// ------------------------------------------------------------------ ladder

struct Level {
    wall: f64,
    /// Per-GET latency in ms with the fetcher's own queue wait subtracted. Folding it in would
    /// report the probe's self-imposed cap as R2 slowness.
    lat: Vec<f64>,
    queue: Vec<f64>,
    bytes: u64,
    errors: BTreeMap<&'static str, (usize, String)>,
}

async fn run_level(shards: &[R2ObjectFetcher], blocks: &[(u64, String)]) -> Level {
    let samples = Arc::new(Mutex::new((Vec::new(), Vec::new())));
    let (mut bytes, mut errors) = (0u64, BTreeMap::new());
    let t0 = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for (i, (number, hash)) in blocks.iter().cloned().enumerate() {
        let fetcher = shards[i % shards.len()].clone();
        let samples = Arc::clone(&samples);
        tasks.spawn(async move {
            let t = Instant::now();
            fetcher.get_block_object(number, hash, 1, None, || ()).await.map(|f| {
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
                errors.entry(e.kind()).or_insert_with(|| (0, e.to_string())).0 += 1;
            }
        }
    }
    let wall = t0.elapsed().as_secs_f64();
    let (mut lat, mut queue) = Arc::try_unwrap(samples).unwrap().into_inner().unwrap();
    lat.sort_by(f64::total_cmp);
    queue.sort_by(f64::total_cmp);
    Level { wall, lat, queue, bytes, errors }
}

async fn ladder(cfg: &Config, args: &[String]) -> Res<()> {
    let start: u64 = args.first().map(|s| s.parse()).transpose()?.unwrap_or(0);
    let count: u64 = args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(200);
    let rungs: Vec<(usize, usize)> = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("1x48,1x96,2x96,4x96,1x200,4x200")
        .split(',')
        .map(|spec| {
            let (k, c) = spec.split_once('x').ok_or_else(|| format!("bad rung {spec:?}"))?;
            let num = |t: &str| {
                t.trim().parse::<usize>().map(|v| v.max(1)).map_err(|e| format!("{spec:?}: {e}"))
            };
            Ok::<_, String>((num(k)?, num(c)?))
        })
        .collect::<Result<_, _>>()?;

    // Well below the tip so every object is certainly uploaded: a miss here would be a real gap,
    // not the uploader lagging.
    let start = if start == 0 { chain_tip(&cfg.gateway).await? - 2_000 } else { start };
    println!("[prep] resolving {count} hashes from block {start} ...");
    let blocks = resolve_hashes(&cfg.gateway, start, count).await?;
    if blocks.is_empty() {
        return Err("gateway resolved no block hashes".into());
    }
    if (blocks.len() as u64) < count {
        println!("[prep] WARNING: got {} of {count}; every rung runs that many", blocks.len());
    }
    println!(
        "[prep] {} objects/rung. shards = independent clients = h2 connections\n",
        blocks.len()
    );
    println!(
        "{:>10}  {:>5}  {:>4}  {:>8}  {:>7}  {:>22}  {:>8}  {:>7}",
        "shards x C", "proto", "fail", "wall_ms", "wit/s", "lat p50/p90/p99 ms", "queue p50", "MB/s"
    );
    for (k, total) in rungs {
        let per_shard = total.div_ceil(k);
        // Fresh clients per rung, so each starts on a cold pool as a restarted process would.
        let shards: Vec<R2ObjectFetcher> =
            (0..k).map(|_| cfg.fetcher(per_shard)).collect::<Res<_>>()?;
        let l = run_level(&shards, &blocks).await;
        let ok = l.lat.len();
        println!(
            "{:>10}  {:>5}  {:>4}  {:>8.0}  {:>7.1}  {:>7.0}/{:>6.0}/{:>6.0}  {:>6.0}ms  {:>7.2}",
            format!("{k}x{total}"),
            shards[0].negotiated_http_version().unwrap_or("?"),
            blocks.len() - ok,
            l.wall * 1000.0,
            ok as f64 / l.wall,
            pct(&l.lat, 0.5),
            pct(&l.lat, 0.9),
            pct(&l.lat, 0.99),
            pct(&l.queue, 0.5),
            l.bytes as f64 / 1e6 / l.wall,
        );
        for (kind, (n, sample)) in &l.errors {
            println!("            fail kind={kind:9} n={n:3}  e.g. {sample}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    println!(
        "\nreading it: compare rungs at EQUAL total concurrency to isolate connection count.\n\
         A rung whose lat p50 balloons while queue p50 falls to ~0 has exceeded the edge's\n\
         per-connection stream limit — that wait moved inside the h2 connection, where it\n\
         counts against the per-attempt timeout and never reaches the queue-wait metric."
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Res<()> {
    let argv: Vec<String> = env::args().collect();
    let cmd = argv.get(1).map(String::as_str).unwrap_or("");
    if matches!(cmd, "" | "-h" | "--help" | "help") {
        print!("{USAGE}");
        return Ok(());
    }
    let cfg = Config::from_env()?;
    match cmd {
        "preflight" => preflight(&cfg).await,
        "ladder" => ladder(&cfg, &argv[2..]).await,
        other => {
            print!("{USAGE}");
            Err(format!("unknown subcommand {other:?}").into())
        }
    }
}
RS_EOF

bin="$build/target/release/r2probe"
# 源码有变化才重新构建
if [ ! -x "$bin" ] || [ "$build/src/main.rs" -nt "$bin" ] || [ "$build/Cargo.toml" -nt "$bin" ]; then
  echo "[build] 编译探针（首次约需 1-2 分钟）..." >&2
  ( cd "$build" && cargo build --release ) >&2
fi

exec "$bin" "$@"
