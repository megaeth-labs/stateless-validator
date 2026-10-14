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
        atomic::{AtomicBool, AtomicU64, Ordering},
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
///
/// Constructed *inside* the request future, so it arms on the first poll — the same poll
/// that runs the handler's synchronous prefix and records the arrival. A future dropped
/// before ever being polled therefore records neither side of the accounting identity.
struct CancelGuard {
    /// `None` once the request produced a response, which disarms the drop.
    method: Option<&'static str>,
    /// Batch-wide "the server aborted this batch itself" flag; a drop with it set is not
    /// a client hangup and records nothing. `None` for single calls.
    server_abort: Option<Arc<AtomicBool>>,
}

impl CancelGuard {
    fn new(method: &'static str) -> Self {
        Self { method: Some(method), server_abort: None }
    }

    /// Guard for one batch entry, sharing the batch's server-abort flag. Spelled out
    /// rather than `..Self::new(method)`: `CancelGuard` implements `Drop` and its fields
    /// are `Copy`, so a functional-record-update source would be dropped *armed* right
    /// here, phantom-counting every batch entry as cancelled at creation.
    fn for_entry(method: &'static str, server_abort: Arc<AtomicBool>) -> Self {
        Self { method: Some(method), server_abort: Some(server_abort) }
    }

    /// Marks the request as answered, so dropping the guard records nothing.
    fn settle(mut self) {
        self.method = None;
    }

    /// The method a drop right now would count as cancelled, if any.
    fn drop_outcome(&self) -> Option<&'static str> {
        self.method
            .filter(|_| !self.server_abort.as_ref().is_some_and(|f| f.load(Ordering::Relaxed)))
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(method) = self.drop_outcome() {
            crate::metrics::record_request_cancelled(method);
        }
    }
}

/// Settles `guard` for a produced response, accounting any error response no handler
/// recorded — split by who produced it, which the response code reveals:
///
/// - A framework code (parse / invalid-request / method-not-found / invalid-params) means the
///   framework answered before any handler (and its counters) could run, so no arrival exists:
///   recorded as the balanced `rejected` arrival/outcome pair. An unrecorded `-32602` is always the
///   framework's — a handler rejecting a `tracerConfig` with the same code records it through the
///   funnel first (the task-local exists for exactly that ambiguity).
/// - Any other code means a handler ran (and recorded its arrival at entry) but bypassed the error
///   funnel: recorded error-side only as `reason="unattributed"`, so the drift stays visible on its
///   own series instead of absorbed into `rejected` — and the identity stays closed instead of
///   gaining a phantom arrival.
fn settle_response(rp: &MethodResponse, handler_reported: bool, guard: CancelGuard) {
    use jsonrpsee::types::error::{
        INVALID_PARAMS_CODE, INVALID_REQUEST_CODE, METHOD_NOT_FOUND_CODE, OVERSIZED_RESPONSE_CODE,
        PARSE_ERROR_CODE,
    };
    if rp.is_error() &&
        !handler_reported &&
        let Some(method) = guard.drop_outcome()
    {
        match rp.as_error_code() {
            Some(
                PARSE_ERROR_CODE |
                INVALID_REQUEST_CODE |
                METHOD_NOT_FOUND_CODE |
                INVALID_PARAMS_CODE,
            ) |
            None => crate::metrics::record_framework_rejection(method),
            // The framework swapped a handler's *Ok* for the oversized-response error
            // after the handler already recorded arrival + served: the books are balanced,
            // and recording again here would both over-count the identity and false-fire
            // the drift alarm. Reachable since `--max-batch-response-size` became a real
            // bound: an entry body that passes the per-response check can still push the
            // assembled batch past the framework's cap. The client-saw-error /
            // books-say-served mismatch is accepted like the other documented
            // approximations — but the oversized counter is not part of the identity, so it
            // is recorded here too rather than leaving these invisible to the one series an
            // operator would alert on.
            Some(OVERSIZED_RESPONSE_CODE) => crate::metrics::record_response_oversized(method),
            Some(_) => {
                crate::metrics::record_rpc_error(method, crate::metrics::ErrorReason::Unattributed)
            }
        }
    }
    guard.settle();
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
        let method = crate::metrics::method_label(request.method_name());
        // Created eagerly so the wrapper owns no service clone — only the batch path,
        // which spawns entries, needs one.
        let fut = self.service.call(request);
        async move {
            let guard = CancelGuard::new(method);
            let (rp, reported) = crate::metrics::track_handler_errors(fut).await;
            settle_response(&rp, reported, guard);
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
            // Set before a server-side early return (response over the size cap) so the
            // aborted entries' guards do not read as client hangups. Such a batch's books
            // are deliberately approximate: killed entries keep an arrival with no
            // outcome; never-started entries are on neither side.
            let server_abort = Arc::new(AtomicBool::new(false));

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
                            let method = crate::metrics::method_label(req.method_name());
                            let server_abort = server_abort.clone();
                            let req = owned_request(req);
                            tasks.spawn(CpuSampled::new(
                                async move {
                                    let guard = CancelGuard::for_entry(method, server_abort);
                                    let (rp, reported) =
                                        crate::metrics::track_handler_errors(service.call(req))
                                            .await;
                                    settle_response(&rp, reported, guard);
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
                            // A client-visible error entry no handler will ever see —
                            // account for it like the other framework rejections.
                            crate::metrics::record_framework_rejection("unknown");
                            let (err, id) = err.into_parts();
                            if let Err(err) = batch_rp.append(MethodResponse::error(id, err)) {
                                server_abort.store(true, Ordering::Relaxed);
                                return stamp_entry_cpu(err, &entry_cpu);
                            }
                        }
                    }
                }
                match tasks.join_next().await {
                    Some(Ok(Some(rp))) => {
                        if let Err(err) = batch_rp.append(rp) {
                            server_abort.store(true, Ordering::Relaxed);
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

/// JSON-RPC POST helpers shared by every in-crate test that drives a real server.
#[cfg(test)]
pub(crate) mod test_support {
    use std::net::SocketAddr;

    use serde_json::Value;

    pub(crate) async fn post_text(addr: SocketAddr, body: String) -> String {
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

    pub(crate) async fn post_raw(addr: SocketAddr, body: String) -> Value {
        serde_json::from_str(&post_text(addr, body).await).unwrap()
    }

    /// A permit cutoff far enough away that a test never trips the deadline clamp by
    /// accident.
    pub(crate) fn far() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(30)
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

    use super::{test_support::*, *};

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

    /// Server running `module`'s methods behind [`ConcurrentBatchLayer`] at the given
    /// bound and response cap, with the timing layer sealing `x-execution-time-ns` like
    /// production.
    async fn spawn_with(
        module: RpcModule<()>,
        concurrency: usize,
        max_response_body_size: usize,
    ) -> (SocketAddr, ServerHandle) {
        spawn_with_limits(module, concurrency, max_response_body_size, None).await
    }

    /// [`spawn_with`] plus an optional admission gate, installed *below* the batch layer
    /// exactly as production does — so these tests exercise the real layer order rather than
    /// a replica of it.
    async fn spawn_with_limits(
        module: RpcModule<()>,
        concurrency: usize,
        max_response_body_size: usize,
        limiter: Option<Arc<crate::admission::AdmissionLimiter>>,
    ) -> (SocketAddr, ServerHandle) {
        let rpc_middleware = RpcServiceBuilder::new()
            .layer(ConcurrentBatchLayer::new(concurrency, max_response_body_size))
            .option_layer(limiter.map(crate::admission::AdmissionLayer::new));
        let http_middleware = tower::ServiceBuilder::new().layer(crate::timing::TimingHeaderLayer);
        let server = Server::builder()
            .set_rpc_middleware(rpc_middleware)
            .set_http_middleware(http_middleware)
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        (addr, server.start(module))
    }

    /// [`spawn_with`] running [`test_module`].
    async fn spawn(
        concurrency: usize,
        max_response_body_size: usize,
    ) -> (SocketAddr, ServerHandle) {
        spawn_with(test_module(), concurrency, max_response_body_size).await
    }

    /// The same server without the layer — jsonrpsee's stock sequential batch path.
    async fn spawn_bare() -> (SocketAddr, ServerHandle) {
        let server = Server::builder().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        (addr, server.start(test_module()))
    }

    /// The cancel guard counts a drop as a cancellation only while armed — not after
    /// `settle`, and not once the batch flagged a server-side abort.
    #[test]
    fn cancel_guard_counts_only_client_abandonment() {
        let g = CancelGuard::new("debug_traceBlockByNumber");
        assert_eq!(g.drop_outcome(), Some("debug_traceBlockByNumber"));
        g.settle();

        let abort = Arc::new(AtomicBool::new(false));
        let g = CancelGuard::for_entry("trace_block", abort.clone());
        assert_eq!(g.drop_outcome(), Some("trace_block"), "client teardown must count");
        abort.store(true, Ordering::Relaxed);
        assert_eq!(g.drop_outcome(), None, "a server-side abort must not count");
        g.settle();
    }

    /// `track_handler_errors` reports whether the handler recorded its own error, which
    /// is what keeps the middleware fallback from double-counting handler errors while
    /// still catching responses the framework produced on its own.
    #[tokio::test]
    async fn handler_error_tracking_separates_self_reported_errors() {
        let ((), reported) = crate::metrics::track_handler_errors(async {}).await;
        assert!(!reported, "nothing recorded => the fallback owns the outcome");

        let ((), reported) = crate::metrics::track_handler_errors(async {
            crate::metrics::record_rpc_error("trace_block", crate::metrics::ErrorReason::Internal);
        })
        .await;
        assert!(reported, "a handler-recorded error must disarm the fallback");
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

    // Accounting-series names, shared by every test that reads the identity.
    const SHAPE: &str = "debug_trace_request_shape_total";
    // The derive-based served counter keeps its raw dotted scope name here — the
    // dot-to-underscore rename happens in the Prometheus exporter, not the recorder.
    const SERVED: &str = "debug_trace.rpc_requests_total";
    const ERRORS: &str = "debug_trace_rpc_errors_total";
    const CANCELLED: &str = "debug_trace_requests_cancelled_total";

    type Acc = std::collections::HashMap<(String, Vec<(String, String)>), u64>;

    /// Folds one drain of `snapshotter` into `acc`.
    ///
    /// `Snapshotter::snapshot` *drains* the recorder (each counter swaps to zero), so every
    /// observation has to funnel through one accumulator that survives repeated polls.
    fn drain(snapshotter: &metrics_util::debugging::Snapshotter, acc: &mut Acc) {
        use metrics_util::debugging::DebugValue;
        for (ck, _, _, value) in snapshotter.snapshot().into_vec() {
            if let DebugValue::Counter(v) = value {
                let key = ck.key();
                let labels: Vec<(String, String)> =
                    key.labels().map(|l| (l.key().to_string(), l.value().to_string())).collect();
                *acc.entry((key.name().to_string(), labels)).or_default() += v;
            }
        }
    }

    /// Sums every accumulated counter matching `metric` and all of `labels` (a subset match,
    /// so a method-only query sums across shapes and reasons).
    fn read(acc: &Acc, metric: &str, labels: &[(&str, &str)]) -> u64 {
        acc.iter()
            .filter(|((name, ls), _)| {
                name.as_str() == metric &&
                    labels.iter().all(|(lk, lv)| {
                        ls.iter().any(|(k, v)| k.as_str() == *lk && v.as_str() == *lv)
                    })
            })
            .map(|(_, v)| *v)
            .sum()
    }

    /// Handlers following the real handlers' accounting contract — arrival recorded at
    /// entry, then exactly one outcome — plus one that deliberately bypasses the error
    /// funnel, mimicking the drift `reason="unattributed"` exists to catch. Registered
    /// under real method names so `method_label` resolves them like production traffic.
    fn contract_module() -> RpcModule<()> {
        use jsonrpsee::types::ErrorObjectOwned;

        use crate::metrics::{self, ErrorReason};
        let mut module = RpcModule::new(());
        // Served.
        module
            .register_async_method(metrics::METHOD_TRACE_BLOCK, |_, _, _| async {
                metrics::record_request_shape(metrics::METHOD_TRACE_BLOCK, "default");
                metrics::record_rpc_request(metrics::METHOD_TRACE_BLOCK, 0.001);
                "ok"
            })
            .unwrap();
        // Failed, recorded through the error funnel.
        module
            .register_async_method(metrics::METHOD_TRACE_TRANSACTION, |_, _, _| async {
                metrics::record_request_shape(metrics::METHOD_TRACE_TRANSACTION, "default");
                metrics::record_rpc_error(metrics::METHOD_TRACE_TRANSACTION, ErrorReason::NotFound);
                Err::<&str, _>(ErrorObjectOwned::owned(-32001, "not found", None::<()>))
            })
            .unwrap();
        // Funnel bypass: an arrival, then an error the handler never records.
        module
            .register_async_method(metrics::METHOD_DEBUG_TRACE_TRANSACTION, |_, _, _| async {
                metrics::record_request_shape(metrics::METHOD_DEBUG_TRACE_TRANSACTION, "default");
                Err::<&str, _>(ErrorObjectOwned::owned(-32000, "boom", None::<()>))
            })
            .unwrap();
        // Cancellation target: an arrival, then outlives any client patience.
        module
            .register_async_method(metrics::METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, |_, _, _| async {
                metrics::record_request_shape(
                    metrics::METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
                    "default",
                );
                tokio::time::sleep(Duration::from_secs(30)).await;
                "never"
            })
            .unwrap();
        module
    }

    /// A gated method slow enough to hold its capacity while siblings arrive, and the one
    /// exempt method. Both follow the real handlers' accounting contract: arrival recorded at
    /// entry, then exactly one outcome.
    fn admission_module() -> RpcModule<()> {
        use crate::metrics;
        let mut module = RpcModule::new(());
        module
            .register_async_method(metrics::METHOD_TRACE_BLOCK, |_, _, _| async {
                metrics::record_request_shape(metrics::METHOD_TRACE_BLOCK, "default");
                tokio::time::sleep(Duration::from_millis(SLOW_MS)).await;
                metrics::record_rpc_request(metrics::METHOD_TRACE_BLOCK, 0.001);
                "ok"
            })
            .unwrap();
        module
            .register_async_method(metrics::METHOD_DEBUG_GET_CACHE_STATUS, |_, _, _| async {
                metrics::record_request_shape(metrics::METHOD_DEBUG_GET_CACHE_STATUS, "default");
                metrics::record_rpc_request(metrics::METHOD_DEBUG_GET_CACHE_STATUS, 0.001);
                "status"
            })
            .unwrap();
        module
            .register_alias(
                metrics::TIMED_METHOD_DEBUG_GET_CACHE_STATUS,
                metrics::METHOD_DEBUG_GET_CACHE_STATUS,
            )
            .unwrap();
        module
    }

    /// A notification never reaches a handler, so it must not consume admission capacity.
    ///
    /// Pinned because the opposite is an inviting misreading: a JSON-RPC message with no `id`
    /// looks like it should be gated like any other call. jsonrpsee answers it in
    /// `RpcService::notification` without dispatching the method at all, so gating one would
    /// spend a slot on work that never happens — and, since a notification cannot carry an
    /// error response, shedding one could only be silent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_notification_never_reaches_a_handler_or_takes_capacity() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let handler_ran = Arc::new(AtomicBool::new(false));

        let mut module = RpcModule::new(());
        let flag = Arc::clone(&handler_ran);
        module
            .register_async_method(crate::metrics::METHOD_TRACE_BLOCK, move |_, _, _| {
                let flag = Arc::clone(&flag);
                async move {
                    flag.store(true, Ordering::SeqCst);
                    "ok"
                }
            })
            .unwrap();

        // A gate with no capacity at all: anything that were gated would be shed.
        let limiter = crate::admission::AdmissionLimiter::new(1, 0, 1);
        let _held = limiter
            .acquire_execution(
                crate::metrics::METHOD_TRACE_BLOCK,
                crate::response_cache::TraceWeight::Normal,
                far(),
            )
            .await
            .expect("the test holds the only execution permit");
        let (addr, _handle) =
            spawn_with_limits(module, 4, u32::MAX as usize, Some(Arc::clone(&limiter))).await;

        let body = post_text(
            addr,
            json!({"jsonrpc": "2.0", "method": "trace_block", "params": []}).to_string(),
        )
        .await;

        // jsonrpsee answers a notification-only request with a bare `null` — no result, no
        // error, nothing that could carry a shed.
        assert!(
            body.is_empty() || body == "null",
            "a notification gets no real response: {body:?}"
        );
        assert!(!handler_ran.load(Ordering::SeqCst), "the framework never dispatched the method");
        assert_eq!(limiter.in_flight(), 0, "and it never took a unit of admitted capacity");
    }

    /// Every entry of a batch admits on its own account.
    ///
    /// This is the layer-order pin. `ConcurrentBatch` must sit *outside* the admission layer,
    /// because it decomposes batches into per-entry `call`s rather than delegating to an inner
    /// `batch`. Swap the two `.layer()` calls in `main` and an N-entry batch passes the gate as
    /// a single unit — no compile error, no other test failing, and the one traffic shape that
    /// has actually exhausted this server sails straight through. Here that shows up as all
    /// four entries succeeding against a gate with room for one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_entries_are_individually_gated() {
        let limiter = crate::admission::AdmissionLimiter::new(1, 0, 1);
        let (addr, _handle) =
            spawn_with_limits(admission_module(), 4, u32::MAX as usize, Some(limiter)).await;

        let batch = r#"[
            {"jsonrpc": "2.0", "id": 1, "method": "trace_block", "params": []},
            {"jsonrpc": "2.0", "id": 2, "method": "trace_block", "params": []},
            {"jsonrpc": "2.0", "id": 3, "method": "trace_block", "params": []},
            {"jsonrpc": "2.0", "id": 4, "method": "trace_block", "params": []}
        ]"#;
        let response = post_raw(addr, batch.to_string()).await;
        let entries = response.as_array().expect("a batch answers with an array");
        assert_eq!(entries.len(), 4);

        let shed = entries
            .iter()
            .filter(|e| e["error"]["code"] == json!(crate::admission::QUEUE_FULL_CODE))
            .count();
        let served = entries.iter().filter(|e| e["result"].is_string()).count();
        assert!(served >= 1, "the gate's one unit of capacity must serve someone: {response}");
        assert!(
            shed >= 1,
            "entries admit individually, so a gate with room for one must shed the rest: \
             {response}"
        );
        assert_eq!(shed + served, 4, "every entry landed on exactly one outcome: {response}");
    }

    /// The shed response carries mega-reth's `ConcurrencyLimiter` contract byte for byte, so
    /// whatever already backs off for the node backs off for us.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shed_response_matches_the_queue_full_contract() {
        let limiter = crate::admission::AdmissionLimiter::new(1, 0, 1);
        let (addr, _handle) =
            spawn_with_limits(admission_module(), 4, u32::MAX as usize, Some(limiter)).await;

        let call =
            json!({"jsonrpc": "2.0", "id": 1, "method": "trace_block", "params": []}).to_string();
        let held = tokio::spawn(post_raw(addr, call.clone()));
        tokio::time::sleep(Duration::from_millis(SLOW_MS / 4)).await;
        let shed = post_raw(addr, call).await;

        assert_eq!(shed["error"]["code"], json!(crate::admission::QUEUE_FULL_CODE));
        assert_eq!(shed["error"]["message"], json!(crate::admission::QUEUE_FULL_MESSAGE));
        assert_eq!(shed["id"], json!(1), "a shed response still answers the request it refused");
        held.await.unwrap();
    }

    /// The one exempt method keeps answering while the gate is shedding everything else.
    ///
    /// Also pins that the exemption is matched on the `timed_`-stripped name: the gateway adds
    /// that prefix by default, so an exemption written against the bare wire name would never
    /// match in production and the operator's only introspection endpoint would be shed
    /// exactly when it is needed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exempt_method_answers_while_shedding() {
        let limiter = crate::admission::AdmissionLimiter::new(1, 0, 1);
        let (addr, _handle) =
            spawn_with_limits(admission_module(), 4, u32::MAX as usize, Some(limiter)).await;

        let held = tokio::spawn(post_raw(
            addr,
            json!({"jsonrpc": "2.0", "id": 1, "method": "trace_block", "params": []}).to_string(),
        ));
        tokio::time::sleep(Duration::from_millis(SLOW_MS / 4)).await;

        for method in ["debug_getCacheStatus", "timed_debug_getCacheStatus"] {
            let response = post_raw(
                addr,
                json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": []}).to_string(),
            )
            .await;
            assert_eq!(response["result"], json!("status"), "{method} must stay reachable");
        }
        held.await.unwrap();
    }

    /// Shedding keeps the books balanced, and does not read as drift.
    ///
    /// Two things are pinned. The balanced pair: a shed records one arrival
    /// (`shape="shed"`) and one outcome (`reason="overloaded"`), so the identity closes for a
    /// request no handler ever saw. And `reason="unattributed"` staying at zero: `-32013` is
    /// not a framework code, so if the shed were recorded outside `track_handler_errors`'
    /// task-local scope, `settle_response` would charge every one of them to the drift alarm
    /// as well — silently doubling the error side and paging on a healthy server.
    #[test]
    fn admission_shed_keeps_the_identity_closed() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let mut acc = Acc::new();

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let limiter = crate::admission::AdmissionLimiter::new(1, 0, 1);
                let (addr, _handle) =
                    spawn_with_limits(admission_module(), 4, u32::MAX as usize, Some(limiter))
                        .await;
                let call =
                    json!({"jsonrpc": "2.0", "id": 1, "method": "trace_block", "params": []})
                        .to_string();
                // One holds the single unit of capacity; the rest arrive while it does.
                let calls: Vec<_> =
                    (0..4).map(|_| tokio::spawn(post_raw(addr, call.clone()))).collect();
                for call in calls {
                    call.await.unwrap();
                }
            })
        });
        drain(&snapshotter, &mut acc);

        let method = [("method", "trace_block")];
        let shed = read(&acc, SHAPE, &[("method", "trace_block"), ("shape", "shed")]);
        assert!(shed >= 1, "a gate with room for one must have shed something");
        assert_eq!(
            shed,
            read(&acc, ERRORS, &[("method", "trace_block"), ("reason", "overloaded")]),
            "every shed arrival has exactly one matching outcome"
        );
        assert_eq!(
            read(&acc, ERRORS, &[("reason", "unattributed")]),
            0,
            "a shed must never also land on the drift alarm"
        );
        assert_eq!(
            read(&acc, SHAPE, &method),
            read(&acc, SERVED, &method) +
                read(&acc, ERRORS, &method) +
                read(&acc, CANCELLED, &method),
            "shape = served + errors + cancelled"
        );
    }

    /// End-to-end pin of the accounting identity `shape = requests + errors + cancelled`
    /// per method — the contract that otherwise lives only in AGENTS.md prose. One pass
    /// drives every terminal path through a real server: served (single call and batch
    /// entry; a batch notification rides along to pin that notifications contribute to
    /// neither side — jsonrpsee never dispatches a handler for them), a funnel-recorded
    /// error, a funnel *bypass* (must land error-side on `unattributed`, never in
    /// `rejected`), framework rejections (unknown method, malformed batch entry), and a
    /// client hangup. The whole server runs on a
    /// current-thread runtime inside `metrics::with_local_recorder`, so every sample —
    /// handlers, middleware, guards — lands in this test's recorder and concurrently
    /// running tests stay invisible to it.
    #[test]
    fn accounting_identity_holds_end_to_end() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let mut acc = Acc::new();

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let (addr, _handle) = spawn_with(contract_module(), 16, u32::MAX as usize).await;
                let single = |method: &str| {
                    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).to_string()
                };

                // Served; funnel-recorded error; funnel bypass; unknown method.
                for method in ["trace_block", "trace_transaction", "debug_traceTransaction", "nope"]
                {
                    post_text(addr, single(method)).await;
                }
                // Batch: served entry, unknown method, malformed entry, notification.
                let batch = r#"[
                    {"jsonrpc": "2.0", "id": 1, "method": "trace_block", "params": []},
                    {"jsonrpc": "2.0", "id": 2, "method": "nope", "params": []},
                    42,
                    {"jsonrpc": "2.0", "method": "trace_block", "params": []}
                ]"#;
                post_text(addr, batch.to_string()).await;
                // Client hangup: the handler sleeps far past the client's timeout, so the
                // dropped call future is the request's only trace.
                let _ = reqwest::Client::new()
                    .post(format!("http://{addr}"))
                    .timeout(Duration::from_millis(100))
                    .header("content-type", "application/json")
                    .body(single("debug_traceBlockByNumber"))
                    .send()
                    .await;
                // The drop lands only once the connection teardown reaches the server.
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    drain(&snapshotter, &mut acc);
                    if read(&acc, CANCELLED, &[("method", "debug_traceBlockByNumber")]) > 0 {
                        break;
                    }
                    assert!(Instant::now() < deadline, "cancellation was never recorded");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
        });
        drain(&snapshotter, &mut acc);

        // Terminal-path pins: each scenario landed on exactly the series it must.
        assert_eq!(
            read(&acc, ERRORS, &[("method", "trace_transaction"), ("reason", "not_found")]),
            1
        );
        assert_eq!(
            read(&acc, ERRORS, &[("method", "debug_traceTransaction"), ("reason", "unattributed")]),
            1,
            "a funnel bypass must land on its own drift series, error-side only",
        );
        assert_eq!(
            read(&acc, ERRORS, &[("method", "debug_traceTransaction"), ("reason", "rejected")]),
            0,
            "a funnel bypass must not be absorbed into the framework's `rejected`",
        );
        // Three framework rejections: the unknown single call, the unknown batch entry,
        // and the malformed batch entry — each a balanced arrival/outcome pair.
        assert_eq!(read(&acc, SHAPE, &[("method", "unknown"), ("shape", "rejected")]), 3);
        assert_eq!(read(&acc, ERRORS, &[("method", "unknown"), ("reason", "rejected")]), 3);
        assert_eq!(read(&acc, CANCELLED, &[("method", "debug_traceBlockByNumber")]), 1);

        // The identity itself, per method touched by the pass.
        for method in [
            "trace_block",
            "trace_transaction",
            "debug_traceTransaction",
            "debug_traceBlockByNumber",
            "unknown",
        ] {
            let m = [("method", method)];
            let shape = read(&acc, SHAPE, &m);
            let served = read(&acc, SERVED, &m);
            let errors = read(&acc, ERRORS, &m);
            let cancelled = read(&acc, CANCELLED, &m);
            assert!(shape > 0, "the pass never touched {method}");
            assert_eq!(
                shape,
                served + errors + cancelled,
                "identity broken for {method}: shape={shape} served={served} \
                 errors={errors} cancelled={cancelled}",
            );
        }
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
