//! RPC middleware that executes JSON-RPC batch entries concurrently.
//!
//! jsonrpsee's built-in batch handling awaits entries strictly one after another, so a
//! batch answers in the sum of its items' latencies even when the server is otherwise
//! idle — for batch clients the throughput floor is `batch size × per-item latency`,
//! independent of server capacity. JSON-RPC 2.0 explicitly allows processing batch
//! entries concurrently and responding in any order (responses are matched by `id`),
//! so this layer replaces just the batch path: entries still go through the inner
//! service's `call` one by one — every per-request mechanism (single-flight, caches,
//! semaphores, metrics) applies unchanged — but up to `concurrency` of them run at
//! once, and the batch completes near its slowest item. The bound exists so a single
//! oversized batch cannot monopolize what its entries actually contend on — the
//! witness-fetch semaphores and the runtime's worker threads (traces execute inline on
//! the async runtime) — against concurrently served requests; `1` restores strictly
//! sequential execution.

use futures::stream::{self, StreamExt};
use jsonrpsee::{
    core::server::BatchResponseBuilder,
    server::middleware::rpc::{
        Batch, BatchEntry, BatchEntryErr, MethodResponse, Notification, Request, RpcServiceT,
    },
};
use tower::Layer;

use crate::metrics::BatchMetrics;

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
    /// `concurrency` must be at least 1 (the CLI parser enforces it);
    /// `max_response_body_size` must match the server's configured limit so batch
    /// responses are capped identically to jsonrpsee's own batch path.
    pub(crate) fn new(concurrency: usize, max_response_body_size: usize) -> Self {
        debug_assert!(concurrency >= 1, "a zero bound would stall every batch stream");
        Self { concurrency, max_response_body_size, metrics: BatchMetrics::create() }
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

/// Executes one batch entry: parse-failed entries answer directly, calls and
/// notifications go through the inner service. `None` marks a notification (which gets
/// no response entry). A named `async fn` rather than a closure-held `async` block —
/// the closure form trips rustc's higher-ranked lifetime inference inside
/// `buffer_unordered`.
async fn run_entry<'a, S>(
    service: &S,
    entry: Result<BatchEntry<'a>, BatchEntryErr<'a>>,
) -> Option<MethodResponse>
where
    S: RpcServiceT<MethodResponse = MethodResponse, NotificationResponse = MethodResponse>
        + Send
        + Sync,
{
    match entry {
        Ok(BatchEntry::Call(req)) => Some(service.call(req).await),
        Ok(BatchEntry::Notification(n)) => {
            service.notification(n).await;
            None
        }
        Err(err) => {
            let (err, id) = err.into_parts();
            Some(MethodResponse::error(id, err))
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
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            NotificationResponse = MethodResponse,
            BatchResponse = MethodResponse,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(
        &self,
        request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        self.service.call(request)
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

            // One lazy pass: every entry becomes one future — parse-failed entries as
            // ready error responses, calls and notifications through the (borrowed)
            // inner service. `buffer_unordered` pulls futures from the iterator only as
            // slots free up, so it both bounds the parallelism and keeps at most
            // `concurrency` futures alive — an oversized batch cannot balloon memory
            // ahead of execution. Responses append in completion order — valid per spec
            // (matched by `id`), and what keeps a slow entry from holding back an open
            // concurrency slot.
            let service = &service;
            // `from_fn` instead of `Iterator::map`: a closure taking the
            // lifetime-carrying entries as input trips rustc's higher-ranked lifetime
            // inference once it appears in the stream's type; this closure takes no
            // input, so the stream stays lazy without the false obligation.
            let mut entries = batch.into_iter();
            let futs = std::iter::from_fn(move || Some(run_entry(service, entries.next()?)));
            let mut responses = stream::iter(futs).buffer_unordered(concurrency);

            while let Some(rp) = responses.next().await {
                match rp {
                    Some(rp) => {
                        if let Err(err) = batch_rp.append(rp) {
                            return err;
                        }
                    }
                    None => got_notification = true,
                }
            }

            // Mirrors jsonrpsee's sequential batch tail: only-notifications batches get
            // an empty reply, empty batches an invalid-request error.
            if batch_rp.is_empty() && got_notification {
                MethodResponse::notification()
            } else {
                MethodResponse::from_batch(batch_rp.finish())
            }
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
        module
    }

    /// Server with a `slow` method (sleeps [`SLOW_MS`]) and an `echo` method, batches
    /// executed through [`ConcurrentBatchLayer`] at the given bound and response cap.
    async fn spawn(
        concurrency: usize,
        max_response_body_size: usize,
    ) -> (SocketAddr, ServerHandle) {
        let rpc_middleware = RpcServiceBuilder::new()
            .layer(ConcurrentBatchLayer::new(concurrency, max_response_body_size));
        let server = Server::builder()
            .set_rpc_middleware(rpc_middleware)
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

    fn slow_batch(n: u64) -> String {
        let entries: Vec<Value> = (1..=n)
            .map(|id| json!({"jsonrpc": "2.0", "id": id, "method": "slow", "params": []}))
            .collect();
        serde_json::to_string(&entries).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_entries_execute_concurrently() {
        let (addr, _handle) = spawn(16, u32::MAX as usize).await;

        let started = Instant::now();
        let rp = post_raw(addr, slow_batch(8)).await;
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

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrency_one_is_sequential_and_ordered() {
        let (addr, _handle) = spawn(1, u32::MAX as usize).await;

        let started = Instant::now();
        let rp = post_raw(addr, slow_batch(3)).await;
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
