//! RPC middleware that executes JSON-RPC batch entries concurrently.
//!
//! jsonrpsee's built-in batch handling awaits entries strictly one after another, so a
//! batch answers in the sum of its items' latencies even when the server is otherwise
//! idle — for batch clients the throughput floor is `batch size × per-item latency`,
//! independent of server capacity. JSON-RPC 2.0 explicitly allows processing batch
//! entries concurrently and responding in any order (responses are matched by `id`),
//! so this layer replaces just the batch path: entries still go through the inner
//! service's `call` — every per-request mechanism (single-flight, caches, semaphores,
//! metrics) applies unchanged — but up to `concurrency` of them run **as independent
//! runtime tasks**, and the batch completes near its slowest entry. Spawning, rather
//! than interleaving entry futures on the one connection task, is what makes that hold
//! for CPU-bound entries too: EVM tracing runs synchronously inline, so a merely
//! interleaved batch would serialize behind whichever entry is mid-trace, while spawned
//! entries proceed on other worker threads. The bound exists so a single oversized
//! batch cannot monopolize what its entries contend on — the witness-fetch semaphores
//! and the runtime's workers — against concurrently served requests; `1` restores
//! strictly sequential execution. CPU burned inside spawned entries is invisible to the
//! timing layer's thread-clock sampling of the connection task, so it is summed per
//! batch and folded back into `x-execution-time-ns` and the request CPU metric through
//! a response extension.

use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use jsonrpsee::{
    core::server::BatchResponseBuilder,
    server::middleware::rpc::{
        Batch, BatchEntry, MethodResponse, Notification, Request, RpcServiceT,
    },
};
use tokio::task::JoinSet;
use tower::Layer;

use crate::{
    metrics::BatchMetrics,
    timing::{CpuSampled, SpawnedCpuNanos},
};

/// Default bound on concurrently executing entries of one batch request.
pub(crate) const DEFAULT_BATCH_ITEM_CONCURRENCY: u32 = 16;

/// Tower layer installing [`ConcurrentBatch`] around the RPC service.
#[derive(Clone)]
pub(crate) struct ConcurrentBatchLayer {
    concurrency: usize,
    max_response_body_size: usize,
    metrics: BatchMetrics,
}

impl ConcurrentBatchLayer {
    /// `concurrency` is clamped to at least 1: the CLI parser already enforces it, but a
    /// zero bound would silently answer every batch as empty, so the floor is structural
    /// rather than an assertion that compiles out. `max_response_body_size` must match
    /// the server's configured limit so batch responses are capped identically to
    /// jsonrpsee's own batch path.
    pub(crate) fn new(concurrency: usize, max_response_body_size: usize) -> Self {
        Self {
            concurrency: concurrency.max(1),
            max_response_body_size,
            metrics: BatchMetrics::create(),
        }
    }
}

impl<S> Layer<S> for ConcurrentBatchLayer {
    type Service = ConcurrentBatch<S>;

    fn layer(&self, service: S) -> Self::Service {
        ConcurrentBatch {
            service,
            concurrency: self.concurrency,
            max_response_body_size: self.max_response_body_size,
            metrics: self.metrics.clone(),
        }
    }
}

/// Rebuilds a borrowed request as `'static` (owned id/method/params) so its execution
/// can be spawned as an independent runtime task. Exhaustive destructuring makes an
/// upstream field added to `Request` a compile error here instead of a silently dropped
/// piece of context.
fn owned_request(req: Request<'_>) -> Request<'static> {
    let Request { jsonrpc: _, id, method, params, extensions } = req;
    let mut owned =
        Request::owned(method.into_owned(), params.map(Cow::into_owned), id.into_owned());
    owned.extensions = extensions;
    owned
}

/// [`owned_request`]'s counterpart for notification entries.
fn owned_notification(n: Notification<'_>) -> Notification<'static> {
    let Notification { jsonrpc: _, method, params, extensions } = n;
    let mut owned = Notification::new(
        Cow::Owned(method.into_owned()),
        params.map(|p| Cow::Owned(p.into_owned())),
    );
    owned.extensions = extensions;
    owned
}

/// Attaches the entries' summed off-task CPU to a batch response so the timing layer
/// can fold it into `x-execution-time-ns` and the request CPU metric — spawned entries
/// burn their CPU on other worker threads, invisible to that layer's thread-clock
/// sampling of the connection task.
fn stamp_entry_cpu(mut rp: MethodResponse, entry_cpu: &AtomicU64) -> MethodResponse {
    rp.extensions_mut().insert(SpawnedCpuNanos(entry_cpu.load(Ordering::Relaxed)));
    rp
}

/// Counts a request whose future was dropped before it produced a response.
///
/// The drop is the only observable trace of a client hanging up: jsonrpsee cancels the
/// handler by dropping its future, and every completion-time metric (`rpc_requests_total`,
/// `rpc_errors_total`, `request_duration_seconds`) is by definition never reached. Placing
/// the guard here rather than in the handlers is what makes it cover batch entries too —
/// this layer is the only one that sees every entry.
struct CancelGuard {
    /// `None` once the request produced a response, which disarms the drop.
    method: Option<&'static str>,
}

impl CancelGuard {
    fn new(method: &str) -> Self {
        Self {
            method: Some(crate::metrics::resolve_method(crate::metrics::strip_timed_prefix(
                method,
            ))),
        }
    }

    /// Marks the request as answered, so dropping the guard records nothing.
    fn settle(mut self) {
        self.method = None;
    }

    /// Whether dropping now would count a cancellation.
    #[cfg(test)]
    fn armed(&self) -> bool {
        self.method.is_some()
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(method) = self.method {
            crate::metrics::record_request_cancelled(method);
        }
    }
}

/// Passes single calls and notifications through untouched; overrides only `batch`.
#[derive(Clone)]
pub(crate) struct ConcurrentBatch<S> {
    service: S,
    concurrency: usize,
    max_response_body_size: usize,
    metrics: BatchMetrics,
}

impl<S> RpcServiceT for ConcurrentBatch<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse, NotificationResponse = MethodResponse>
        + Clone
        + Send
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(
        &self,
        request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let service = self.service.clone();
        let guard = CancelGuard::new(request.method_name());
        async move {
            let rp = service.call(request).await;
            guard.settle();
            rp
        }
    }

    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        self.service.notification(n)
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        let service = self.service.clone();
        let concurrency = self.concurrency;
        let mut batch_rp = BatchResponseBuilder::new_with_limit(self.max_response_body_size);
        self.metrics.record(batch.len());
        async move {
            let mut got_notification = false;
            let mut entries = batch.into_iter();
            let entry_cpu = Arc::new(AtomicU64::new(0));

            // Refill-and-drain: at most `concurrency` entries are alive as spawned
            // tasks, converted to owned form lazily at spawn time — an oversized batch
            // cannot balloon memory ahead of execution. Parse-failed entries answer
            // inline without consuming a slot. Responses append in completion order —
            // valid per spec (matched by `id`), and what keeps a slow entry from holding
            // back an open slot. Dropping the set (early return, client disconnect)
            // aborts every outstanding entry.
            let mut tasks = JoinSet::new();
            loop {
                while tasks.len() < concurrency {
                    let Some(entry) = entries.next() else { break };
                    match entry {
                        Ok(BatchEntry::Call(req)) => {
                            let service = service.clone();
                            let guard = CancelGuard::new(req.method_name());
                            let req = owned_request(req);
                            tasks.spawn(CpuSampled::new(
                                async move {
                                    let rp = service.call(req).await;
                                    guard.settle();
                                    Some(rp)
                                },
                                entry_cpu.clone(),
                            ));
                        }
                        Ok(BatchEntry::Notification(n)) => {
                            let service = service.clone();
                            let n = owned_notification(n);
                            tasks.spawn(CpuSampled::new(
                                async move {
                                    service.notification(n).await;
                                    None
                                },
                                entry_cpu.clone(),
                            ));
                        }
                        Err(err) => {
                            let (err, id) = err.into_parts();
                            if let Err(err) = batch_rp.append(MethodResponse::error(id, err)) {
                                return stamp_entry_cpu(err, &entry_cpu);
                            }
                        }
                    }
                }
                match tasks.join_next().await {
                    Some(Ok(Some(rp))) => {
                        if let Err(err) = batch_rp.append(rp) {
                            return stamp_entry_cpu(err, &entry_cpu);
                        }
                    }
                    Some(Ok(None)) => got_notification = true,
                    Some(Err(e)) => {
                        // A panicking method unwinds this (connection) task, matching
                        // the sequential batch path; cancellation is unobservable here
                        // (entries are only aborted when the set itself is dropped).
                        if e.is_panic() {
                            std::panic::resume_unwind(e.into_panic());
                        }
                    }
                    None => break,
                }
            }

            // Mirrors jsonrpsee's sequential batch tail: only-notifications batches get
            // an empty reply, empty batches an invalid-request error.
            let rp = if batch_rp.is_empty() && got_notification {
                MethodResponse::notification()
            } else {
                MethodResponse::from_batch(batch_rp.finish())
            };
            stamp_entry_cpu(rp, &entry_cpu)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        time::{Duration, Instant},
    };

    use jsonrpsee::{
        RpcModule,
        server::{Server, ServerHandle, middleware::rpc::RpcServiceBuilder},
    };
    use serde_json::{Value, json};

    use super::*;

    const SLOW_MS: u64 = 200;
    const SPIN_MS: u64 = 40;

    fn test_module() -> RpcModule<()> {
        let mut module = RpcModule::new(());
        module
            .register_async_method("slow", |_, _, _| async {
                tokio::time::sleep(Duration::from_millis(SLOW_MS)).await;
                "done"
            })
            .unwrap();
        module
            .register_async_method("echo", |params, _, _| async move {
                params.one::<String>().unwrap_or_default()
            })
            .unwrap();
        // Synchronous-CPU stand-in: blocks its worker thread for the whole duration,
        // like the inline EVM trace does.
        module
            .register_async_method("busy", |_, _, _| async {
                std::thread::sleep(Duration::from_millis(SLOW_MS));
                "done"
            })
            .unwrap();
        // Burns ~SPIN_MS of real thread CPU (measured by the CPU clock, so the amount
        // is scheduling-independent) — for CPU-accounting tests.
        module
            .register_async_method("spin", |_, _, _| async {
                let start = crate::timing::thread_cpu_time();
                while crate::timing::thread_cpu_time().saturating_sub(start) <
                    Duration::from_millis(SPIN_MS)
                {
                    std::hint::black_box(0u64);
                }
                "done"
            })
            .unwrap();
        module
    }

    /// Server running [`test_module`]'s methods behind [`ConcurrentBatchLayer`] at the
    /// given bound and response cap, with the timing layer sealing
    /// `x-execution-time-ns` like production.
    async fn spawn(
        concurrency: usize,
        max_response_body_size: usize,
    ) -> (SocketAddr, ServerHandle) {
        let rpc_middleware = RpcServiceBuilder::new()
            .layer(ConcurrentBatchLayer::new(concurrency, max_response_body_size));
        let http_middleware = tower::ServiceBuilder::new().layer(crate::timing::TimingHeaderLayer);
        let server = Server::builder()
            .set_rpc_middleware(rpc_middleware)
            .set_http_middleware(http_middleware)
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        (addr, server.start(test_module()))
    }

    /// The same server without the layer — jsonrpsee's stock sequential batch path.
    async fn spawn_bare() -> (SocketAddr, ServerHandle) {
        let server = Server::builder().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        (addr, server.start(test_module()))
    }

    async fn post_text(addr: SocketAddr, body: String) -> String {
        reqwest::Client::new()
            .post(format!("http://{addr}"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    }

    async fn post_raw(addr: SocketAddr, body: String) -> Value {
        serde_json::from_str(&post_text(addr, body).await).unwrap()
    }

    /// The cancel guard is armed on creation and disarmed by `settle`, so only a request
    /// that never produced a response can be counted as cancelled. Unknown methods collapse
    /// to the bounded `"unknown"` label rather than letting client input drive cardinality.
    #[test]
    fn cancel_guard_arms_until_settled() {
        let g = CancelGuard::new("debug_traceBlockByNumber");
        assert!(g.armed(), "a fresh guard must count a drop as a cancellation");
        assert_eq!(g.method, Some("debug_traceBlockByNumber"));
        g.settle();

        // `timed_` aliases share the underlying method's label.
        assert_eq!(
            CancelGuard::new("timed_debug_traceTransaction").method,
            Some("debug_traceTransaction")
        );
        // Arbitrary client input must not widen label cardinality.
        assert_eq!(CancelGuard::new("not_a_method").method, Some("unknown"));
    }

    fn batch_of(method: &str, n: u64) -> String {
        let entries: Vec<Value> = (1..=n)
            .map(|id| json!({"jsonrpc": "2.0", "id": id, "method": method, "params": []}))
            .collect();
        serde_json::to_string(&entries).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_entries_execute_concurrently() {
        let (addr, _handle) = spawn(16, u32::MAX as usize).await;

        let started = Instant::now();
        let rp = post_raw(addr, batch_of("slow", 8)).await;
        let elapsed = started.elapsed();

        let items = rp.as_array().expect("batch response is an array");
        assert_eq!(items.len(), 8);
        let mut ids: Vec<u64> =
            items.iter().map(|i| i["id"].as_u64().expect("numeric id")).collect();
        ids.sort_unstable();
        assert_eq!(ids, (1..=8).collect::<Vec<_>>());
        assert!(items.iter().all(|i| i["result"] == "done"), "all entries succeed: {rp}");

        // Sequential execution would need 8 × SLOW_MS; concurrent completes near 1 ×.
        assert!(
            elapsed < Duration::from_millis(4 * SLOW_MS),
            "batch took {elapsed:?}, expected near {SLOW_MS}ms"
        );
    }

    /// Entries whose cost is synchronous CPU (stand-in: a worker-blocking sleep, like
    /// the inline EVM trace) must still overlap: spawned as independent tasks they
    /// occupy separate worker threads. The regression mode is interleaving all entry
    /// futures on the one connection task, where the batch degrades to the sum of its
    /// entries' CPU time. A blocking sleep rather than a spin pins the same property —
    /// worker-thread occupancy — while staying independent of the CI host's core count
    /// (four sleeps overlap on four worker threads even on one core; four spins do not).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cpu_bound_entries_parallelize() {
        let (addr, _handle) = spawn(16, u32::MAX as usize).await;

        let started = Instant::now();
        let rp = post_raw(addr, batch_of("busy", 6)).await;
        let elapsed = started.elapsed();

        let items = rp.as_array().expect("batch response is an array");
        assert_eq!(items.len(), 6);
        assert!(items.iter().all(|i| i["result"] == "done"), "all entries succeed: {rp}");
        // 6 × SLOW_MS of blocking work over 4 workers ≈ 2 × SLOW_MS; single-task
        // interleaving would need the full 6 ×.
        assert!(
            elapsed < Duration::from_millis(5 * SLOW_MS),
            "cpu-bound batch took {elapsed:?}, expected near {}ms",
            2 * SLOW_MS
        );
    }

    /// Spawned entries burn their CPU on other worker threads, invisible to the timing
    /// layer's thread-clock sampling of the connection task — the summed entry CPU must
    /// ride back on the response so `x-execution-time-ns` still accounts for it. The
    /// regression mode is a batch header reporting only JoinSet orchestration.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_header_accounts_for_spawned_entry_cpu() {
        let (addr, _handle) = spawn(16, u32::MAX as usize).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}"))
            .header("content-type", "application/json")
            .body(batch_of("spin", 3))
            .send()
            .await
            .unwrap();
        let cpu_ns: u64 = resp
            .headers()
            .get(crate::timing::TIMING_HEADER_NAME)
            .expect("timing header present")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let rp: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(rp.as_array().unwrap().len(), 3);

        // Each spin burns >= SPIN_MS of thread CPU by the CPU clock, however the
        // entries are scheduled; a small allowance covers sampling granularity.
        let expected_ns = (3 * SPIN_MS - 5) * 1_000_000;
        assert!(
            cpu_ns >= expected_ns,
            "header reports {cpu_ns}ns, expected at least {expected_ns}ns of entry CPU"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrency_one_is_sequential_and_ordered() {
        let (addr, _handle) = spawn(1, u32::MAX as usize).await;

        let started = Instant::now();
        let rp = post_raw(addr, batch_of("slow", 3)).await;
        let elapsed = started.elapsed();

        // One entry at a time both sums the latencies and preserves request order.
        let ids: Vec<u64> =
            rp.as_array().unwrap().iter().map(|i| i["id"].as_u64().unwrap()).collect();
        assert_eq!(ids, vec![1, 2, 3]);
        assert!(
            elapsed >= Duration::from_millis(3 * SLOW_MS),
            "sequential batch took {elapsed:?}, expected at least {}ms",
            3 * SLOW_MS
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mixed_batch_answers_calls_errors_and_skips_notifications() {
        let (addr, _handle) = spawn(16, u32::MAX as usize).await;

        let body = r#"[
            {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": ["hi"]},
            {"jsonrpc": "2.0", "id": 2, "method": "no_such_method", "params": []},
            42,
            {"jsonrpc": "2.0", "method": "slow", "params": []}
        ]"#;
        let rp = post_raw(addr, body.to_string()).await;

        // Three responses: the call, the unknown method, the malformed entry; the
        // notification (no id) contributes nothing.
        let items = rp.as_array().unwrap();
        assert_eq!(items.len(), 3, "unexpected response set: {rp}");
        let by_id = |id: Value| items.iter().find(|i| i["id"] == id).unwrap();
        assert_eq!(by_id(json!(1))["result"], "hi");
        assert_eq!(by_id(json!(2))["error"]["code"], -32601);
        assert_eq!(by_id(Value::Null)["error"]["code"], -32600);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_batch_response_returns_single_error() {
        let (addr, _handle) = spawn(16, 128).await;

        let long = "x".repeat(200);
        let body = json!([{"jsonrpc": "2.0", "id": 1, "method": "echo", "params": [long]}]);
        let rp = post_raw(addr, body.to_string()).await;

        assert!(rp.is_object(), "over-limit batch collapses to one error: {rp}");
        assert!(rp["error"]["code"].is_i64());
    }

    /// The tail branches mirrored from jsonrpsee's sequential batch implementation
    /// (empty batch, notifications-only batch) stay pinned to its semantics by
    /// construction: this layer's wire output must equal a bare jsonrpsee server's for
    /// those shapes. Breaks loudly if an upstream upgrade changes the tail while the
    /// mirror silently keeps the old shape.
    #[tokio::test(flavor = "multi_thread")]
    async fn tail_semantics_match_jsonrpsee() {
        let (ours, _h1) = spawn(16, u32::MAX as usize).await;
        let (bare, _h2) = spawn_bare().await;

        for body in ["[]", r#"[{"jsonrpc":"2.0","method":"echo","params":["x"]}]"#] {
            let a = post_text(ours, body.to_string()).await;
            let b = post_text(bare, body.to_string()).await;
            assert_eq!(a, b, "tail output diverged from jsonrpsee for {body}");
        }
    }
}
