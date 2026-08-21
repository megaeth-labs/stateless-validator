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
    server::{Server, ServerConfig},
    types::{ErrorObjectOwned, error::INVALID_PARAMS_CODE},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::admission::AdmissionLimiter;

/// A snapshot of the gate: what it is enforcing, and what it currently holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn invalid_params(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, message.into(), None::<()>)
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
            return Err(invalid_params(
                "maxConcurrent must be at least 1: zero would park every request with nothing \
                 running to release a permit",
            ));
        }
        if heavy_max_concurrent == Some(0) {
            return Err(invalid_params(
                "heavyMaxConcurrent must be at least 1: zero would park every heavy-tracer \
                 request with nothing running to release a permit",
            ));
        }
        let resulting_concurrent = max_concurrent.unwrap_or_else(|| self.limiter.max_concurrent());
        let resulting_queue = max_queue_size.unwrap_or_else(|| self.limiter.max_queue());
        let resulting_capacity = resulting_concurrent.saturating_add(resulting_queue);
        if resulting_capacity < self.batch_item_concurrency {
            return Err(invalid_params(format!(
                "maxConcurrent ({resulting_concurrent}) + maxQueueSize ({resulting_queue}) must \
                 be at least the batch item concurrency ({}): one batch's entries admit \
                 independently, so a smaller gate sheds part of every batch even on an idle \
                 server",
                self.batch_item_concurrency
            )));
        }

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
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = tx.send(Err(eyre!("failed to build the admin runtime: {e}")));
                    return;
                }
            };
            runtime.block_on(async move {
                // A handful of connections is all an operator or a probe needs, and this port
                // is unauthenticated.
                let config = ServerConfig::builder().max_connections(8).build();
                let server = match Server::builder().set_config(config).build(addr).await {
                    Ok(server) => server,
                    Err(e) => {
                        let _ = tx.send(Err(eyre!("failed to bind --admin-addr ({addr}): {e}")));
                        return;
                    }
                };
                let bound = match server.local_addr() {
                    Ok(bound) => bound,
                    Err(e) => {
                        let _ = tx.send(Err(eyre!("admin listener has no local address: {e}")));
                        return;
                    }
                };
                let api = AdminApi { limiter, batch_item_concurrency };
                let handle = server.start(api.into_rpc());
                if tx.send(Ok(bound)).is_err() {
                    warn!("admin listener started but its caller is gone; shutting it down");
                    return;
                }
                handle.stopped().await;
            });
        })
        .map_err(|e| eyre!("failed to spawn the admin listener thread: {e}"))?;

    let bound =
        rx.recv().map_err(|_| eyre!("the admin listener thread exited before binding"))??;
    info!(admin_addr = %bound, "Admin RPC listening");
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BATCH_ITEM_CONCURRENCY: u64 = 16;

    fn api(max_concurrent: u64, max_queue: u64, heavy: u64) -> AdminApi {
        AdminApi {
            limiter: AdmissionLimiter::new(max_concurrent, max_queue, heavy),
            batch_item_concurrency: BATCH_ITEM_CONCURRENCY,
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    #[test]
    fn get_reports_limits_and_occupancy() {
        let api = api(4, 32, 2);
        let info = block_on(api.get_concurrency_limit()).expect("get");
        assert_eq!(info.max_concurrent, 4);
        assert_eq!(info.max_queue_size, 32);
        assert_eq!(info.heavy_max_concurrent, 2);
        assert_eq!(info.queued_requests, 0);
        assert_eq!(info.executing_requests, 0);
    }

    #[test]
    fn set_applies_only_the_fields_given() {
        let api = api(4, 32, 2);
        let info = block_on(api.set_concurrency_limit(Some(9), None, None)).expect("set");
        assert_eq!(info.max_concurrent, 9);
        assert_eq!(info.max_queue_size, 32, "an omitted field is left alone");
        assert_eq!(info.heavy_max_concurrent, 2);
        assert_eq!(api.limiter.max_concurrent(), 9, "the limiter itself changed");
    }

    /// Zero execution permits would park every subsequent request with nothing left running
    /// to release one — a state only a restart recovers from. Refused rather than clamped:
    /// quietly enforcing a different limit than the one asked for is its own failure.
    #[test]
    fn set_rejects_zero_permits() {
        let api = api(4, 32, 2);
        for (concurrent, heavy) in [(Some(0), None), (None, Some(0))] {
            let err = block_on(api.set_concurrency_limit(concurrent, None, heavy))
                .expect_err("zero permits must be refused");
            assert_eq!(err.code(), INVALID_PARAMS_CODE);
        }
        assert_eq!(api.limiter.max_concurrent(), 4, "a refused write changes nothing");
        assert_eq!(api.limiter.heavy_max_concurrent(), 2);
    }

    /// The same rule startup enforces: a gate narrower than one batch's concurrent entries
    /// sheds part of every batch even on an idle server, so the setter refuses to create it.
    #[test]
    fn set_rejects_a_gate_narrower_than_one_batch() {
        let api = api(4, 32, 2);
        let err = block_on(api.set_concurrency_limit(Some(1), Some(1), None))
            .expect_err("2 total is below the batch item concurrency");
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert_eq!(api.limiter.max_concurrent(), 4);
        assert_eq!(api.limiter.max_queue(), 32);

        block_on(api.set_concurrency_limit(Some(1), Some(BATCH_ITEM_CONCURRENCY - 1), None))
            .expect("exactly at the floor is allowed");
    }

    /// Lowering a limit below current occupancy must not abort anything — it stops admitting
    /// until the excess drains. The opposite would make a routine retune a client-visible
    /// incident.
    #[test]
    fn lowering_a_limit_does_not_abort_in_flight_work() {
        let api = api(4, 32, 2);
        block_on(async {
            let cutoff = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let held = api
                .limiter
                .acquire_execution(crate::metrics::METHOD_TRACE_BLOCK, false, cutoff)
                .await
                .expect("permit");
            api.set_concurrency_limit(Some(1), None, None).await.expect("set");
            assert_eq!(api.limiter.executing(), 1, "the in-flight request kept its permit");
            drop(held);
        });
    }

    /// The listener binds, serves the namespace, and a write over the wire reaches the
    /// limiter the request path reads.
    #[test]
    fn admin_listener_binds_and_serves() {
        let limiter = AdmissionLimiter::new(4, 32, 2);
        let addr = spawn("127.0.0.1:0".parse().unwrap(), Arc::clone(&limiter), 16)
            .expect("the admin listener binds");

        let post = |body: &str| {
            reqwest::blocking::Client::new()
                .post(format!("http://{addr}"))
                .header("content-type", "application/json")
                .body(body.to_owned())
                .send()
                .unwrap()
                .json::<serde_json::Value>()
                .unwrap()
        };

        let got =
            post(r#"{"jsonrpc":"2.0","id":1,"method":"admin_getConcurrencyLimit","params":[]}"#);
        assert_eq!(got["result"]["maxConcurrent"], serde_json::json!(4));
        assert_eq!(got["result"]["maxQueueSize"], serde_json::json!(32));

        let set = post(
            r#"{"jsonrpc":"2.0","id":2,"method":"admin_setConcurrencyLimit","params":[64,128,3]}"#,
        );
        assert_eq!(set["result"]["maxConcurrent"], serde_json::json!(64));
        assert_eq!(limiter.max_concurrent(), 64, "the wire write reached the live limiter");
        assert_eq!(limiter.max_queue(), 128);
        assert_eq!(limiter.heavy_max_concurrent(), 3);
    }
}
