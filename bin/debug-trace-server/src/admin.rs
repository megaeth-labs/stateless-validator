//! Loopback-only admin RPC for retuning the admission gate without a restart.
//!
//! # Why a separate listener
//!
//! These setters can throttle request serving to a trickle, and there is no authentication
//! anywhere in this server. Registering them on the customer-facing port would hand every
//! client that can reach us a switch for the gate that is supposed to protect us from them,
//! so the listener is separate, loopback-only (enforced at startup), and off unless asked
//! for. It also carries no RPC middleware: routed through the batch layer, admin traffic
//! would land in the accounting identity's series as `unknown`, and routed through the
//! admission layer, a saturated public port could shed the very call that relieves it.
//!
//! # Why a dedicated runtime
//!
//! EVM tracing runs synchronously inline on the main runtime's worker threads, and tokio
//! cannot preempt a synchronous loop. Enough concurrent traces and no other task on that
//! runtime gets polled — which is precisely the moment an operator reaches for this port. So
//! the admin server gets its own OS thread and its own single-threaded runtime, where
//! nothing traces. This is a workaround for the inline execution, not a fix for it; the fix
//! is a bounded blocking pool for tracing.
//!
//! The method names, parameters and response fields mirror mega-reth's `admin_*`
//! concurrency-limit RPCs, so an operator runbook written for the node works here unchanged.

use std::{net::SocketAddr, sync::Arc, thread};

use eyre::{Result, eyre};
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    server::{Server, ServerConfig, ServerHandle},
};
use serde::Serialize;
use tracing::{info, warn};

use crate::{
    admission::{AdmissionLimiter, Limit, check_capacity_covers_batch},
    rpc_service::invalid_params_err,
};

/// A snapshot of the gate: what it is enforcing, and what it currently holds.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConcurrencyLimitInfo {
    /// Requests admitted but not yet holding an execution permit.
    pub queued_requests: u64,
    /// Requests holding an execution permit.
    pub executing_requests: u64,
    /// Requests allowed to wait on top of those executing.
    pub max_queue_size: u64,
    /// Execution permits.
    pub max_concurrent: u64,
    /// Requests holding a permit from the memory-hungry-tracer sub-cap.
    pub heavy_executing_requests: u64,
    /// Execution permits reserved for memory-hungry tracers.
    pub heavy_max_concurrent: u64,
}

#[rpc(server, namespace = "admin")]
pub trait AdminRpc {
    /// Returns the admission gate's current limits and occupancy.
    #[method(name = "getConcurrencyLimit")]
    async fn get_concurrency_limit(&self) -> RpcResult<ConcurrencyLimitInfo>;

    /// Updates any subset of the admission limits, returning the resulting state.
    ///
    /// Lowering a limit below current occupancy aborts nothing — it stops admitting until
    /// the excess drains, which is what keeps a retune from being a client-visible incident.
    #[method(name = "setConcurrencyLimit")]
    async fn set_concurrency_limit(
        &self,
        max_concurrent: Option<u64>,
        max_queue_size: Option<u64>,
        heavy_max_concurrent: Option<u64>,
    ) -> RpcResult<ConcurrencyLimitInfo>;
}

/// Serves the admin methods against one limiter.
pub struct AdminApi {
    limiter: Arc<AdmissionLimiter>,
    /// Mirrors the startup rule: a gate narrower than one batch's concurrent entries sheds
    /// part of every batch on an idle server, so the setter refuses to create that state.
    batch_item_concurrency: u64,
}

impl AdminApi {
    fn snapshot(&self) -> ConcurrencyLimitInfo {
        ConcurrencyLimitInfo {
            queued_requests: self.limiter.queued() as u64,
            executing_requests: self.limiter.executing() as u64,
            max_queue_size: self.limiter.max_queue(),
            max_concurrent: self.limiter.max_concurrent(),
            heavy_executing_requests: self.limiter.heavy_executing() as u64,
            heavy_max_concurrent: self.limiter.heavy_max_concurrent(),
        }
    }
}

#[jsonrpsee::core::async_trait]
impl AdminRpcServer for AdminApi {
    async fn get_concurrency_limit(&self) -> RpcResult<ConcurrencyLimitInfo> {
        Ok(self.snapshot())
    }

    async fn set_concurrency_limit(
        &self,
        max_concurrent: Option<u64>,
        max_queue_size: Option<u64>,
        heavy_max_concurrent: Option<u64>,
    ) -> RpcResult<ConcurrencyLimitInfo> {
        // Zero execution permits would park every subsequent request forever with nothing
        // left running to release one. Refused rather than clamped: silently substituting a
        // different limit than the one asked for is worse than saying no.
        if max_concurrent == Some(0) {
            return Err(invalid_params_err(
                "maxConcurrent must be at least 1: zero would park every request with nothing \
                 running to release a permit",
            ));
        }
        if heavy_max_concurrent == Some(0) {
            return Err(invalid_params_err(
                "heavyMaxConcurrent must be at least 1: zero would park every heavy-tracer \
                 request with nothing running to release a permit",
            ));
        }
        // The same rule startup enforces, in this caller's vocabulary — see
        // `admission::check_capacity_covers_batch`. This validate-then-apply section must
        // stay await-free: the admin server runs on a current-thread runtime, so staying
        // synchronous is what makes read-check-apply atomic across concurrent admin calls —
        // an await point would let two writes each pass this check against limits the other
        // is about to change.
        check_capacity_covers_batch(
            Limit::new(
                "maxConcurrent",
                max_concurrent.unwrap_or_else(|| self.limiter.max_concurrent()),
            ),
            Limit::new("maxQueueSize", max_queue_size.unwrap_or_else(|| self.limiter.max_queue())),
            Limit::new("the batch item concurrency", self.batch_item_concurrency),
        )
        .map_err(invalid_params_err)?;

        let before = self.snapshot();
        if let Some(permits) = max_concurrent {
            self.limiter.set_max_concurrent(permits);
        }
        if let Some(permits) = max_queue_size {
            self.limiter.set_max_queue(permits);
        }
        if let Some(permits) = heavy_max_concurrent {
            self.limiter.set_heavy_max_concurrent(permits);
        }
        let after = self.snapshot();
        // A production mutation reached over the wire belongs in the log record, with both
        // sides of it, so a later shed spike can be attributed to the change that caused it.
        info!(
            max_concurrent_before = before.max_concurrent,
            max_concurrent_after = after.max_concurrent,
            max_queue_before = before.max_queue_size,
            max_queue_after = after.max_queue_size,
            heavy_before = before.heavy_max_concurrent,
            heavy_after = after.heavy_max_concurrent,
            "Admission limits changed over admin RPC"
        );
        Ok(after)
    }
}

/// Starts the admin listener on its own thread and runtime, returning once it is bound.
///
/// The server is owned by that thread for the process's lifetime, so there is no handle to
/// drop early — dropping a jsonrpsee `ServerHandle` stops its server, and a listener that
/// shuts down the moment it is started is a failure mode worth designing out rather than
/// remembering.
pub(crate) fn spawn(
    addr: SocketAddr,
    limiter: Arc<AdmissionLimiter>,
    batch_item_concurrency: u64,
) -> Result<SocketAddr> {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::Builder::new()
        .name("dts-admin".to_owned())
        .spawn(move || match bind(addr, limiter, batch_item_concurrency) {
            Ok((runtime, bound, handle)) => {
                if tx.send(Ok(bound)).is_err() {
                    warn!("admin listener started but its caller is gone; shutting it down");
                    return;
                }
                runtime.block_on(handle.stopped());
            }
            Err(e) => {
                let _ = tx.send(Err(e));
            }
        })
        .map_err(|e| eyre!("failed to spawn the admin listener thread: {e}"))?;

    let bound =
        rx.recv().map_err(|_| eyre!("the admin listener thread exited before binding"))??;
    info!(admin_addr = %bound, "Admin RPC listening");
    Ok(bound)
}

/// Builds the admin runtime and starts the listener on it, returning both so the caller's
/// thread can own them for the process's lifetime.
///
/// Split out so every failure funnels through one `?` chain instead of three hand-written
/// send-and-return arms, each of which had to remember to do both.
fn bind(
    addr: SocketAddr,
    limiter: Arc<AdmissionLimiter>,
    batch_item_concurrency: u64,
) -> Result<(tokio::runtime::Runtime, SocketAddr, ServerHandle)> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| eyre!("failed to build the admin runtime: {e}"))?;
    let (bound, handle) = runtime.block_on(async {
        // A handful of connections is all an operator or a probe needs, and this port is
        // unauthenticated.
        let config = ServerConfig::builder().max_connections(8).build();
        let server = Server::builder()
            .set_config(config)
            .build(addr)
            .await
            .map_err(|e| eyre!("failed to bind --admin-addr ({addr}): {e}"))?;
        let bound =
            server.local_addr().map_err(|e| eyre!("admin listener has no local address: {e}"))?;
        let api = AdminApi { limiter, batch_item_concurrency };
        Ok::<_, eyre::Report>((bound, server.start(api.into_rpc())))
    })?;
    Ok((runtime, bound, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        response_cache::TraceWeight,
        rpc_middleware::test_support::{far, post_raw},
    };

    const BATCH_ITEM_CONCURRENCY: u64 = 16;

    fn api(max_concurrent: u64, max_queue: u64, heavy: u64) -> AdminApi {
        AdminApi {
            limiter: AdmissionLimiter::new(max_concurrent, max_queue, heavy),
            batch_item_concurrency: BATCH_ITEM_CONCURRENCY,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_reports_limits_and_occupancy() {
        let api = api(4, 32, 2);
        let info = api.get_concurrency_limit().await.expect("get");
        assert_eq!(info.max_concurrent, 4);
        assert_eq!(info.max_queue_size, 32);
        assert_eq!(info.heavy_max_concurrent, 2);
        assert_eq!(info.queued_requests, 0);
        assert_eq!(info.executing_requests, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_applies_only_the_fields_given() {
        let api = api(4, 32, 2);
        let info = api.set_concurrency_limit(Some(9), None, None).await.expect("set");
        assert_eq!(info.max_concurrent, 9);
        assert_eq!(info.max_queue_size, 32, "an omitted field is left alone");
        assert_eq!(info.heavy_max_concurrent, 2);
        assert_eq!(api.limiter.max_concurrent(), 9, "the limiter itself changed");
    }

    /// Zero execution permits would park every subsequent request with nothing left running
    /// to release one — a state only a restart recovers from. Refused rather than clamped:
    /// quietly enforcing a different limit than the one asked for is its own failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_rejects_zero_permits() {
        let api = api(4, 32, 2);
        for (concurrent, heavy) in [(Some(0), None), (None, Some(0))] {
            let err = api
                .set_concurrency_limit(concurrent, None, heavy)
                .await
                .expect_err("zero permits must be refused");
            assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        }
        assert_eq!(api.limiter.max_concurrent(), 4, "a refused write changes nothing");
        assert_eq!(api.limiter.heavy_max_concurrent(), 2);
    }

    /// The same rule startup enforces: a gate narrower than one batch's concurrent entries
    /// sheds part of every batch even on an idle server, so the setter refuses to create it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_rejects_a_gate_narrower_than_one_batch() {
        let api = api(4, 32, 2);
        let err = api
            .set_concurrency_limit(Some(1), Some(1), None)
            .await
            .expect_err("2 total is below the batch item concurrency");
        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert_eq!(api.limiter.max_concurrent(), 4);
        assert_eq!(api.limiter.max_queue(), 32);

        api.set_concurrency_limit(Some(1), Some(BATCH_ITEM_CONCURRENCY - 1), None)
            .await
            .expect("exactly at the floor is allowed");
    }

    /// Lowering a limit below current occupancy must not abort anything — it stops admitting
    /// until the excess drains. The opposite would make a routine retune a client-visible
    /// incident.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lowering_a_limit_does_not_abort_in_flight_work() {
        let api = api(4, 32, 2);
        let held = api
            .limiter
            .acquire_execution(crate::metrics::METHOD_TRACE_BLOCK, TraceWeight::Normal, far())
            .await
            .expect("permit");
        api.set_concurrency_limit(Some(1), None, None).await.expect("set");
        assert_eq!(api.limiter.executing(), 1, "the in-flight request kept its permit");
        drop(held);
    }

    /// The listener binds, serves the namespace, and a write over the wire reaches the
    /// limiter the request path reads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_listener_binds_and_serves() {
        let limiter = AdmissionLimiter::new(4, 32, 2);
        let addr = spawn("127.0.0.1:0".parse().unwrap(), Arc::clone(&limiter), 16)
            .expect("the admin listener binds");

        let got = post_raw(
            addr,
            r#"{"jsonrpc":"2.0","id":1,"method":"admin_getConcurrencyLimit","params":[]}"#.into(),
        )
        .await;
        assert_eq!(got["result"]["maxConcurrent"], serde_json::json!(4));
        assert_eq!(got["result"]["maxQueueSize"], serde_json::json!(32));

        let set = post_raw(
            addr,
            r#"{"jsonrpc":"2.0","id":2,"method":"admin_setConcurrencyLimit","params":[64,128,3]}"#
                .into(),
        )
        .await;
        assert_eq!(set["result"]["maxConcurrent"], serde_json::json!(64));
        assert_eq!(limiter.max_concurrent(), 64, "the wire write reached the live limiter");
        assert_eq!(limiter.max_queue(), 128);
        assert_eq!(limiter.heavy_max_concurrent(), 3);
    }
}
