//! Inbound admission control: the gate that decides, before any work happens, whether a
//! request can be served at all.
//!
//! Every other concurrency bound in this binary is *outbound* — the witness, data and R2
//! semaphores cap what we ask of someone else, and they are unbounded waits, so overflow
//! can only ever surface as a timeout. Nothing caps what clients ask of us: EVM tracing
//! runs inline on the runtime's worker threads, so enough concurrent requests starve chain
//! sync, the accept loop and the metrics exporter along with each other. This module is the
//! missing half — it turns "too much work offered" into an immediate, typed refusal instead
//! of a slow collapse, which is what makes "may be slow, may reject, must not time out"
//! true rather than aspirational.
//!
//! # Two phases, deliberately in two different places
//!
//! [`AdmissionLayer`] does only the cheap half: a non-blocking compare-and-swap against
//! `max_queue + max_concurrent`, answering [`QUEUE_FULL_CODE`] on the spot when the process
//! is already holding all the work it agreed to hold. The expensive half — waiting for an
//! execution permit — happens in the handler, in [`AdmissionLimiter::acquire_execution`],
//! after the response cache has been consulted.
//!
//! Splitting them is not an aesthetic choice; a single gate in the middleware would break
//! the metrics accounting identity. `CancelGuard` in [`crate::rpc_middleware`] arms on a
//! request's first poll, and today the handler records that request's *arrival*
//! synchronously in that very same poll, before its first `.await`. Arming and arrival are
//! therefore atomic. A middleware gate that parked before the handler would sever that: a
//! client hanging up while queued would record a cancellation with no matching arrival, and
//! `shape = served + errors + cancelled` would drift negative — permanently, and worst
//! under exactly the overload the gate exists for. Because this layer only ever CAS-es, it
//! either sheds inline or falls straight through to the handler in the same poll, and the
//! invariant holds by construction. The permit wait then sits *after* the arrival is
//! already on the books, so a hangup there is a balanced arrival + cancellation for free.
//!
//! Putting the wait in the handler pays three more ways: a response-cache hit returns before
//! a permit is ever requested, so cheap hits are not queued behind cold traces; the tracer
//! identity is already parsed there, so the heavy-shape sub-cap costs nothing rather than
//! requiring a second parse of attacker-controlled JSON at the gate; and what the permits
//! count is blocks actually being fetched and replayed.
//!
//! # Layer order
//!
//! This layer must be installed *inside* `ConcurrentBatchLayer`. That layer never delegates
//! to an inner `batch()` — it decomposes the batch itself and dispatches each entry through
//! `service.call`, so an inner layer sees single calls and every batch entry through one
//! path. Installed outside instead, an N-entry batch would pass the gate as a single unit,
//! which is the same as not gating batches at all — and batches are the traffic shape that
//! has actually taken this server down. It is also what puts the shed inside
//! `track_handler_errors`' task-local scope, which is what keeps `settle_response`
//! unchanged. `batch_entries_are_individually_gated` pins the order.

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};

use futures::future::Either;
use jsonrpsee::server::middleware::rpc::{
    Batch, MethodResponse, Notification, Request, RpcServiceT,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Layer;

use crate::{
    metrics::{self, AdmissionMetrics},
    response_cache::TraceWeight,
};

/// JSON-RPC error code for a request turned away by the gate.
///
/// Deliberately mega-reth's `ConcurrencyLimiter` code and message verbatim rather than
/// jsonrpsee's `-32009 SERVER_IS_BUSY`: the same gateway fronts both, so a single backpressure
/// code across the fleet means whatever already backs off for the node backs off for us.
pub(crate) const QUEUE_FULL_CODE: i32 = -32013;

/// The message paired with [`QUEUE_FULL_CODE`], byte-identical to mega-reth's.
pub(crate) const QUEUE_FULL_MESSAGE: &str = "Request queue is full";

/// Builds the shed error response body — the single construction site for the shed contract.
///
/// `borrowed` rather than `owned`: the message is a `&'static str`, so this allocates nothing
/// on the one path that by definition runs while the process is already under strain.
pub(crate) fn queue_full_error() -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::borrowed(QUEUE_FULL_CODE, QUEUE_FULL_MESSAGE, None)
}

/// A permit count that can be raised and lowered while requests are in flight, without
/// giving up FIFO fairness.
///
/// The obvious alternative — a hand-rolled counter plus [`tokio::sync::Notify`], which is
/// what the mega-reth limiter this design otherwise mirrors uses — has two failure modes
/// worth not inheriting. `Notify::notify_waiters` wakes every waiter to race for one slot,
/// which is O(waiters²) wakeups to drain a queue and offers no ordering, so a request can
/// lose every race indefinitely; and a `Notified` only receives broadcasts issued after it
/// is *created*, so checking capacity before creating one parks a request until some
/// unrelated request happens to finish. A semaphore has neither problem.
///
/// What a semaphore lacks is shrinking: `forget_permits` can only remove permits that are
/// currently available, and reports how many it managed. The shortfall is recorded as
/// `debt` and settled lazily — a permit released while a debt is outstanding is forgotten
/// instead of returned. So a shrink takes effect as soon as it can and never blocks, and
/// the limit is honoured from the next release onward.
struct ResizableSemaphore {
    sem: Arc<Semaphore>,
    /// The configured limit — authoritative for reporting, and reached by the semaphore
    /// itself once any outstanding `debt` is settled.
    limit: AtomicU64,
    /// Permits a shrink could not remove because they were checked out at the time.
    debt: AtomicU64,
    /// Permits currently handed out.
    ///
    /// Tracked rather than derived as `limit - available`: once a shrink leaves debt behind
    /// that difference stops being the number of holders and becomes the *new* limit, which is
    /// exactly backwards — the reason the shrink left debt is that the old holders are all
    /// still running. Reporting the new limit as occupancy would tell an operator their retune
    /// had already taken effect while every one of those requests was still resident.
    checked_out: AtomicUsize,
    /// Serializes resizes against each other. Never taken on the acquire/release path.
    resize: Mutex<()>,
    /// Test-only seam: fires between a shrink's debt publish and its permit removal, so the
    /// nanoseconds-wide window a concurrent release can land in is drivable deterministically
    /// instead of raced against.
    #[cfg(test)]
    shrink_window_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl std::fmt::Debug for ResizableSemaphore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResizableSemaphore")
            .field("limit", &self.limit)
            .field("debt", &self.debt)
            .field("checked_out", &self.checked_out)
            .finish()
    }
}

impl ResizableSemaphore {
    fn new(permits: u64) -> Self {
        let permits = clamp_permits(permits);
        Self {
            sem: Arc::new(Semaphore::new(permits as usize)),
            limit: AtomicU64::new(permits),
            debt: AtomicU64::new(0),
            checked_out: AtomicUsize::new(0),
            resize: Mutex::new(()),
            #[cfg(test)]
            shrink_window_hook: Mutex::new(None),
        }
    }

    fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Applies a new limit, growing immediately and shrinking as far as free permits allow.
    fn set_limit(&self, permits: u64) {
        let permits = clamp_permits(permits);
        let _resize = self.resize.lock().unwrap_or_else(|e| e.into_inner());
        let previous = self.limit.swap(permits, Ordering::SeqCst);
        if permits > previous {
            // Cancel outstanding debt first: those permits were already removed from the
            // budget on paper but not yet from the semaphore, so re-adding them here as
            // well would double-count the growth.
            let growth = permits - previous;
            let cancelled = self.cancel_debt(growth);
            if growth > cancelled {
                self.sem.add_permits((growth - cancelled) as usize);
            }
        } else if permits < previous {
            let wanted = previous - permits;
            // The debt is published *before* any permit is removed: published after instead,
            // a release landing in between would observe zero debt, hand its permit back,
            // and let a queued request through above the limit the shrink just set. The
            // price of that ordering is the settlement below — a release inside the window
            // sees a debt that is at worst too large and forgets a permit `forget_permits`
            // was about to remove anyway, so the cancel is compared against what the removal
            // actually took and the overlap is returned. Without that, every such release
            // would leak one permit permanently, sliding real capacity below the configured
            // limit with nothing but a restart to recover it.
            self.debt.fetch_add(wanted, Ordering::SeqCst);
            #[cfg(test)]
            if let Some(hook) =
                self.shrink_window_hook.lock().unwrap_or_else(|e| e.into_inner()).take()
            {
                hook();
            }
            let removed = self.sem.forget_permits(wanted as usize) as u64;
            let cancelled = self.cancel_debt(removed);
            if removed > cancelled {
                self.sem.add_permits((removed - cancelled) as usize);
            }
        }
    }

    /// Cancels up to `max` of the outstanding debt, returning how much was cancelled.
    fn cancel_debt(&self, max: u64) -> u64 {
        let mut current = self.debt.load(Ordering::SeqCst);
        loop {
            if current == 0 || max == 0 {
                return 0;
            }
            let take = current.min(max);
            match self.debt.compare_exchange_weak(
                current,
                current - take,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return take,
                Err(actual) => current = actual,
            }
        }
    }

    /// Whether a permit being released should be forgotten rather than returned.
    fn settle_on_release(&self) -> bool {
        self.cancel_debt(1) == 1
    }

    /// Permits currently handed out.
    fn checked_out(&self) -> usize {
        self.checked_out.load(Ordering::Relaxed)
    }

    /// Acquires one permit, giving up at `cutoff`.
    async fn acquire(self: &Arc<Self>, cutoff: Instant) -> Result<DebtAwarePermit, AdmissionError> {
        let sem = Arc::clone(&self.sem);
        let permit = tokio::time::timeout_at(cutoff.into(), sem.acquire_owned())
            .await
            .map_err(|_| AdmissionError::Overloaded)?
            // The semaphore is never closed for the process's lifetime.
            .map_err(|_| AdmissionError::Overloaded)?;
        self.checked_out.fetch_add(1, Ordering::Acquire);
        Ok(DebtAwarePermit { permit: Some(permit), owner: Arc::clone(self) })
    }
}

/// How a caller spells a limit, so a shared rule can name it in the caller's own vocabulary —
/// CLI flags at startup, JSON fields over the admin RPC. The same shape as
/// `stateless_common::R2Flag`, and for the same reason: the rule and its rationale exist once
/// while each entry point still produces an error its own audience recognizes.
pub(crate) struct Limit<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: u64,
}

impl<'a> Limit<'a> {
    pub(crate) fn new(name: &'a str, value: u64) -> Self {
        Self { name, value }
    }
}

/// Rejects a gate too narrow to admit one batch's worth of concurrent entries.
///
/// A batch's entries admit independently, so a total below `--batch-item-concurrency` sheds
/// part of every batch on a completely idle server. Enforced identically at startup and on the
/// admin RPC, because a rule written twice is a rule that drifts.
pub(crate) fn check_capacity_covers_batch(
    concurrent: Limit<'_>,
    queue: Limit<'_>,
    batch: Limit<'_>,
) -> Result<(), String> {
    if concurrent.value.saturating_add(queue.value) >= batch.value {
        return Ok(());
    }
    Err(format!(
        "{} ({}) + {} ({}) must be at least {} ({}): one batch's entries admit independently, \
         so a smaller gate sheds part of every batch even on an idle server",
        concurrent.name, concurrent.value, queue.name, queue.value, batch.name, batch.value
    ))
}

/// Claims one unit of a bounded counter, or reports that the bound is already reached.
///
/// The lock-free half of admission, shared by the process-wide gate and the heavy-class gate:
/// the subtle part is the pair of orderings (`Acquire` on the claim, `Release` in the guard
/// that releases it), and a second copy would let those drift with nothing to catch it.
fn try_claim(counter: &AtomicUsize, capacity: u64) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current as u64 >= capacity {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// Tokio panics past this, and the admin RPC takes operator input.
fn clamp_permits(permits: u64) -> u64 {
    permits.clamp(1, Semaphore::MAX_PERMITS as u64)
}

/// A checked-out permit that honours any pending shrink when it is released.
#[derive(Debug)]
struct DebtAwarePermit {
    permit: Option<OwnedSemaphorePermit>,
    owner: Arc<ResizableSemaphore>,
}

impl Drop for DebtAwarePermit {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.owner.checked_out.fetch_sub(1, Ordering::Release);
            if self.owner.settle_on_release() {
                permit.forget();
            }
        }
    }
}

/// Why a request could not obtain an execution permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    /// The wait would have left too little of the request's budget for the work itself.
    Overloaded,
}

/// The process-wide inbound gate.
pub(crate) struct AdmissionLimiter {
    /// Admitted and unfinished: queued plus executing.
    in_flight: AtomicUsize,
    /// How many admitted requests may be waiting on top of the executing ones.
    max_queue: AtomicU64,
    /// Execution permits — one per block being fetched and replayed.
    execution: Arc<ResizableSemaphore>,
    /// A smaller budget the memory-hungry tracer shapes must pass first.
    heavy: Arc<ResizableSemaphore>,
    /// Heavy requests that have reached the permit stage and not yet finished.
    ///
    /// Bounded separately from `in_flight` because the two have different bottlenecks. The
    /// admitted budget is class-blind by design — the gate runs before anything parses the
    /// tracer — so without this a flood of heavy requests fills it while blocking on a sub-cap
    /// a fraction of its size, and ordinary traffic is shed with most execution permits idle.
    heavy_in_flight: AtomicUsize,
}

impl AdmissionLimiter {
    /// Builds a limiter. Every value is clamped to at least 1 permit; `max_queue` may be 0,
    /// which means "execute or shed, never wait".
    pub(crate) fn new(max_concurrent: u64, max_queue: u64, heavy_max_concurrent: u64) -> Arc<Self> {
        let limiter = Arc::new(Self {
            in_flight: AtomicUsize::new(0),
            max_queue: AtomicU64::new(max_queue),
            execution: Arc::new(ResizableSemaphore::new(max_concurrent)),
            heavy: Arc::new(ResizableSemaphore::new(heavy_max_concurrent)),
            heavy_in_flight: AtomicUsize::new(0),
        });
        limiter.publish_limits();
        limiter
    }

    /// Total requests that may be admitted at once.
    ///
    /// `saturating_add` because both terms are operator input: a `u64::MAX` "unlimited"
    /// sentinel that wrapped here would make the gate shed *everything*.
    fn capacity(&self) -> u64 {
        self.max_queue.load(Ordering::Relaxed).saturating_add(self.execution.limit())
    }

    /// How many heavy requests may be at the permit stage at once.
    ///
    /// The heavy class is allowed to queue in the same proportion to its execution budget as
    /// the process as a whole — `max_queue / max_concurrent` waiters per slot — so it can
    /// absorb a burst without being able to crowd ordinary traffic out of admission. It also
    /// makes `--admission-max-queue 0` mean execute-or-shed for heavy requests too, which a
    /// share of the shared budget did not.
    fn heavy_capacity(&self) -> u64 {
        let queue_per_slot = self.max_queue() / self.execution.limit().max(1);
        self.heavy.limit().saturating_mul(queue_per_slot.saturating_add(1))
    }

    pub(crate) fn max_concurrent(&self) -> u64 {
        self.execution.limit()
    }

    pub(crate) fn max_queue(&self) -> u64 {
        self.max_queue.load(Ordering::Relaxed)
    }

    pub(crate) fn heavy_max_concurrent(&self) -> u64 {
        self.heavy.limit()
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Requests holding an execution permit.
    pub(crate) fn executing(&self) -> usize {
        self.execution.checked_out()
    }

    /// Requests holding a permit from the heavy-tracer sub-cap.
    pub(crate) fn heavy_executing(&self) -> usize {
        self.heavy.checked_out()
    }

    /// Requests admitted but not yet executing.
    pub(crate) fn queued(&self) -> usize {
        self.in_flight().saturating_sub(self.executing())
    }

    pub(crate) fn set_max_concurrent(&self, permits: u64) {
        self.execution.set_limit(permits);
        self.publish_limits();
    }

    pub(crate) fn set_max_queue(&self, permits: u64) {
        self.max_queue.store(permits, Ordering::Relaxed);
        self.publish_limits();
    }

    pub(crate) fn set_heavy_max_concurrent(&self, permits: u64) {
        self.heavy.set_limit(permits);
        self.publish_limits();
    }

    fn publish_limits(&self) {
        metrics::record_admission_limits(
            self.max_concurrent(),
            self.max_queue(),
            self.heavy_max_concurrent(),
        );
    }

    /// The whole admission decision, made without blocking and without touching the handler.
    ///
    /// `None` means shed. This is the "can this request be served at all" question answered
    /// before any parsing, fetching or tracing happens.
    fn try_admit(self: &Arc<Self>, method: &'static str) -> Option<InFlightGuard> {
        try_claim(&self.in_flight, self.capacity()).then(|| {
            let gauges = AdmissionMetrics::new_for_method(method);
            gauges.in_flight_delta(1.0);
            InFlightGuard { limiter: Arc::clone(self), gauges }
        })
    }

    /// Waits for the permits this request needs to fetch and replay a block.
    ///
    /// `cutoff` is the instant past which starting the work would be pointless — the caller
    /// derives it from its own deadline, so a request that has queued away the budget its
    /// witness fetch still needs is refused now rather than started and timed out later.
    /// That refusal is the difference between "may reject" and "times out".
    ///
    /// A heavy shape takes the sub-cap permit *first*. Acquiring it second would let heavy
    /// requests occupy execution permits while waiting for each other, starving ordinary
    /// traffic behind work that is not running. It is also refused outright once the heavy
    /// class already holds its share of the budget, rather than joining a queue that only its
    /// own sub-cap drains — see [`Self::heavy_capacity`].
    pub(crate) async fn acquire_execution(
        self: &Arc<Self>,
        method: &'static str,
        weight: TraceWeight,
        cutoff: Instant,
    ) -> Result<ExecutionPermit, AdmissionError> {
        let started = Instant::now();
        let heavy_permit = if weight == TraceWeight::Heavy {
            let _slot = self.enter_heavy()?;
            let permit = HeavyPermit::new(self.heavy.acquire(cutoff).await?);
            Some((permit, _slot))
        } else {
            None
        };
        let permit = self.execution.acquire(cutoff).await?;
        metrics::record_admission_permit_wait(started.elapsed().as_secs_f64());

        let gauges = AdmissionMetrics::new_for_method(method);
        gauges.executing_delta(1.0);
        Ok(ExecutionPermit { _permit: permit, heavy: heavy_permit, gauges })
    }

    /// Claims one of the heavy class's slots, or refuses when it already holds its share.
    fn enter_heavy(self: &Arc<Self>) -> Result<HeavySlot, AdmissionError> {
        try_claim(&self.heavy_in_flight, self.heavy_capacity())
            .then(|| HeavySlot { limiter: Arc::clone(self) })
            .ok_or(AdmissionError::Overloaded)
    }
}

/// Holds one of the heavy class's share of the admitted budget.
pub(crate) struct HeavySlot {
    limiter: Arc<AdmissionLimiter>,
}

impl Drop for HeavySlot {
    fn drop(&mut self) {
        self.limiter.heavy_in_flight.fetch_sub(1, Ordering::Release);
    }
}

/// A heavy sub-cap permit, counted on the occupancy gauge for as long as it is held.
///
/// The gauge is raised here rather than once *both* permits are in hand, so it cannot read
/// zero while every heavy permit is reserved and further heavy requests are blocked on them —
/// the state an operator is most likely to be staring at. Raised at the same moment the
/// limiter's own counter is, so the Prometheus view and the admin RPC cannot disagree.
struct HeavyPermit {
    /// Held for its `Drop`, which returns the sub-cap permit.
    _permit: DebtAwarePermit,
}

impl HeavyPermit {
    fn new(permit: DebtAwarePermit) -> Self {
        metrics::record_admission_heavy_delta(1.0);
        Self { _permit: permit }
    }
}

impl Drop for HeavyPermit {
    fn drop(&mut self) {
        metrics::record_admission_heavy_delta(-1.0);
    }
}

/// Holds one unit of admitted capacity for the whole request.
pub(crate) struct InFlightGuard {
    limiter: Arc<AdmissionLimiter>,
    gauges: AdmissionMetrics,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::Release);
        self.gauges.in_flight_delta(-1.0);
    }
}

/// Holds the right to fetch and replay one block.
pub(crate) struct ExecutionPermit {
    _permit: DebtAwarePermit,
    /// The sub-cap permit and the budget slot, both released with this one.
    heavy: Option<(HeavyPermit, HeavySlot)>,
    gauges: AdmissionMetrics,
}

impl std::fmt::Debug for ExecutionPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionPermit").field("heavy", &self.heavy.is_some()).finish()
    }
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        self.gauges.executing_delta(-1.0);
    }
}

/// Tower layer installing [`AdmissionService`] around the RPC service.
#[derive(Clone)]
pub(crate) struct AdmissionLayer {
    limiter: Arc<AdmissionLimiter>,
}

impl AdmissionLayer {
    pub(crate) fn new(limiter: Arc<AdmissionLimiter>) -> Self {
        Self { limiter }
    }
}

impl<S> Layer<S> for AdmissionLayer {
    type Service = AdmissionService<S>;

    fn layer(&self, service: S) -> Self::Service {
        AdmissionService { service, limiter: Arc::clone(&self.limiter) }
    }
}

/// Sheds calls the process has no capacity for; passes everything else through untouched.
#[derive(Clone)]
pub(crate) struct AdmissionService<S> {
    service: S,
    limiter: Arc<AdmissionLimiter>,
}

impl<S> RpcServiceT for AdmissionService<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse> + Clone + Send + Sync + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = S::NotificationResponse;
    type BatchResponse = S::BatchResponse;

    fn call<'a>(
        &self,
        request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let method = metrics::method_label(request.method_name());
        // An ungated call hands back the inner future untouched — no service clone, no
        // wrapper — so the exempt cache-status polls and unknown methods pay nothing here.
        if !metrics::is_gated(method) {
            return Either::Left(self.service.call(request));
        }
        let service = self.service.clone();
        let limiter = Arc::clone(&self.limiter);
        // The shed decision and its recording run inside this block, never in the prefix
        // above: `record_admission_shed` reaches for the `ERROR_SELF_REPORTED` task-local
        // that tells the batch layer's fallback this `-32013` is already accounted for, and
        // that scope only exists once the future is being polled. Recorded from the prefix,
        // every shed would double-count its error and false-fire the `unattributed` alarm.
        Either::Right(async move {
            let Some(guard) = limiter.try_admit(method) else {
                metrics::record_admission_shed(method);
                return MethodResponse::error(request.id, queue_full_error())
                    .with_extensions(request.extensions);
            };
            let response = service.call(request).await;
            drop(guard);
            response
        })
    }

    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        // jsonrpsee answers notifications without ever dispatching a handler, so there is
        // no work here to protect and nothing to shed.
        self.service.notification(n)
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        // Unreachable in this server: `ConcurrentBatch` sits outside and decomposes batches
        // into per-entry `call`s rather than delegating here. Kept as a pass-through so the
        // layer stays correct if it is ever installed on its own.
        self.service.batch(batch)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{metrics::METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, rpc_middleware::test_support::far};

    const METHOD: &str = METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER;

    /// Takes `n` ordinary execution permits and hands them back for the caller to hold.
    async fn hold(limiter: &Arc<AdmissionLimiter>, n: usize) -> Vec<ExecutionPermit> {
        let mut held = Vec::with_capacity(n);
        for _ in 0..n {
            held.push(
                limiter
                    .acquire_execution(METHOD, TraceWeight::Normal, far())
                    .await
                    .expect("permit"),
            );
        }
        held
    }

    #[test]
    fn admits_exactly_queue_plus_concurrent() {
        let limiter = AdmissionLimiter::new(2, 3, 1);
        let admitted: Vec<_> = (0..5).map(|_| limiter.try_admit(METHOD)).collect();
        assert!(admitted.iter().all(|guard| guard.is_some()), "the first five must be admitted");
        assert!(limiter.try_admit(METHOD).is_none(), "the sixth is past capacity");
        assert_eq!(limiter.in_flight(), 5);

        drop(admitted);
        assert_eq!(limiter.in_flight(), 0, "every guard returns its unit");
        assert!(limiter.try_admit(METHOD).is_some(), "capacity is available again");
    }

    /// `u64::MAX` is the shape of an "unlimited" sentinel an operator might reach for. If the
    /// capacity sum wrapped, the gate would shed *everything* — the exact inverse of intent.
    #[test]
    fn capacity_saturates_instead_of_wrapping() {
        let limiter = AdmissionLimiter::new(u64::MAX, u64::MAX, 1);
        assert_eq!(limiter.capacity(), u64::MAX);
        assert!(limiter.try_admit(METHOD).is_some());
    }

    #[test]
    fn queue_is_zero_means_execute_or_shed() {
        let limiter = AdmissionLimiter::new(1, 0, 1);
        let _first = limiter.try_admit(METHOD).expect("the one execution slot is admissible");
        assert!(limiter.try_admit(METHOD).is_none(), "with no queue there is nowhere to wait");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn heavy_requests_pass_both_budgets() {
        let limiter = AdmissionLimiter::new(8, 8, 1);
        let heavy = limiter
            .acquire_execution(METHOD, TraceWeight::Heavy, far())
            .await
            .expect("first heavy");
        assert_eq!(limiter.executing(), 1);

        // The sub-cap is full, so a second heavy request waits even though seven ordinary
        // execution permits are free.
        let blocked = limiter.acquire_execution(METHOD, TraceWeight::Heavy, Instant::now()).await;
        assert_eq!(blocked.unwrap_err(), AdmissionError::Overloaded);

        // An ordinary request is unaffected by the heavy sub-cap.
        let _normal =
            limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await.expect("normal");
        drop(heavy);
        limiter.acquire_execution(METHOD, TraceWeight::Heavy, far()).await.expect("sub-cap freed");
    }

    /// A request that queued past the point where its remaining budget could still cover the
    /// work is refused rather than started — the difference between "may reject" and "times
    /// out", which is the whole reason the cutoff is threaded in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn permit_wait_gives_up_at_the_cutoff() {
        let limiter = AdmissionLimiter::new(1, 8, 1);
        let _held =
            limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await.expect("first");

        let started = Instant::now();
        let refused = limiter
            .acquire_execution(
                METHOD,
                TraceWeight::Normal,
                Instant::now() + Duration::from_millis(50),
            )
            .await;
        assert_eq!(refused.unwrap_err(), AdmissionError::Overloaded);
        assert!(started.elapsed() < Duration::from_secs(5), "it gave up, it did not hang");
    }

    /// Regression for the reference implementation's lost wakeup: it created its wait future
    /// *after* checking capacity, so a permit released in that window was never observed and
    /// the request parked until some unrelated request happened to finish. The failure mode is
    /// a hang, not an assertion, so the whole loop runs under a timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_permit_freed_while_waiting_is_never_lost() {
        let limiter = AdmissionLimiter::new(1, 64, 1);
        let churn = async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let limiter = Arc::clone(&limiter);
                tasks.spawn(async move {
                    for _ in 0..250 {
                        let permit = limiter
                            .acquire_execution(METHOD, TraceWeight::Normal, far())
                            .await
                            .expect("permit");
                        drop(permit);
                        tokio::task::yield_now().await;
                    }
                });
            }
            while let Some(joined) = tasks.join_next().await {
                joined.expect("no task panicked");
            }
        };
        tokio::time::timeout(Duration::from_secs(30), churn)
            .await
            .expect("a freed permit was lost and the waiters parked forever");
    }

    /// Regression for the reference implementation's other bug: raising a limit there only
    /// stored the new value, so parked waiters learned about the extra capacity at the next
    /// completion — and never, if nothing was running. Note the holder is deliberately *not*
    /// released; the raise alone must be enough.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn raising_the_limit_wakes_parked_waiters() {
        let limiter = AdmissionLimiter::new(1, 64, 1);
        let _held =
            limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await.expect("first");

        let mut waiters = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let limiter = Arc::clone(&limiter);
            waiters.spawn(async move {
                limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await
            });
        }
        // Let them all reach the wait before the capacity appears.
        tokio::time::sleep(Duration::from_millis(50)).await;
        limiter.set_max_concurrent(8);

        let woken = async {
            let mut permits = Vec::new();
            while let Some(joined) = waiters.join_next().await {
                permits.push(joined.expect("no panic").expect("permit"));
            }
            permits
        };
        let permits = tokio::time::timeout(Duration::from_secs(10), woken)
            .await
            .expect("raising the limit did not wake the parked waiters");
        assert_eq!(permits.len(), 4);
    }

    /// Shrinking cannot revoke a permit that is already checked out, so the shortfall is
    /// carried as debt and settled by the next releases. Verified through behaviour: after the
    /// shrink the limiter must never hand out more than the new limit at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shrinking_below_checked_out_permits_settles_on_release() {
        let limiter = AdmissionLimiter::new(4, 64, 1);
        let held = hold(&limiter, 4).await;
        assert_eq!(limiter.executing(), 4);

        limiter.set_max_concurrent(1);
        assert_eq!(limiter.max_concurrent(), 1, "the configured limit applies immediately");

        // Releasing three must not make three permits available again: they pay off the debt.
        drop(held);
        let _one = limiter
            .acquire_execution(METHOD, TraceWeight::Normal, far())
            .await
            .expect("the one permit");
        let second = limiter
            .acquire_execution(
                METHOD,
                TraceWeight::Normal,
                Instant::now() + Duration::from_millis(50),
            )
            .await;
        assert_eq!(
            second.unwrap_err(),
            AdmissionError::Overloaded,
            "the shrink was honoured once the permits came back"
        );
    }

    /// A release landing inside the shrink window must not leak a permit.
    ///
    /// The regression this pins: between the debt publish and the permit removal, a release
    /// pays one unit of debt by forgetting a permit that `forget_permits` was about to
    /// remove anyway. Settled without comparing the cancel against the removal, that
    /// overlap removed one permit too many — permanently, since growth only re-adds the
    /// difference between limits, so repeated retunes under load slid real capacity below
    /// the configured value with no error surface. The window is nanoseconds wide, so the
    /// test drives it through a deterministic hook rather than racing tasks at it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_inside_the_shrink_window_leaks_no_permit() {
        let limiter = AdmissionLimiter::new(10, 64, 1);
        let mut held = hold(&limiter, 10).await;
        // Leave the shrink free permits to remove: five stay checked out, five come back.
        held.truncate(5);
        assert_eq!(limiter.executing(), 5);

        // One holder releases exactly inside the window.
        let released = held.pop().expect("a permit to release in the window");
        *limiter.execution.shrink_window_hook.lock().unwrap() =
            Some(Box::new(move || drop(released)));

        limiter.set_max_concurrent(5);
        held.clear();

        assert_eq!(limiter.executing(), 0, "every permit was returned");
        assert_eq!(limiter.execution.debt.load(Ordering::SeqCst), 0, "no debt outstanding");
        assert_eq!(
            limiter.execution.sem.available_permits(),
            5,
            "the in-window release must not shrink the budget below the configured limit"
        );
    }

    /// A flood of heavy requests cannot crowd ordinary traffic out of admission.
    ///
    /// The regression this pins: the admitted budget is class-blind, so heavy requests used to
    /// fill it while blocking on a sub-cap a fraction of its size. Twelve of them would take
    /// all twelve admitted slots, one would execute, and an ordinary request was then shed with
    /// three execution permits sitting idle — a priority inversion handed to whoever sends the
    /// most expensive shape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_heavy_flood_cannot_shed_ordinary_traffic() {
        // 4 + 8 = 12 admitted; 4 execution permits; 1 heavy at a time, so heavy gets
        // 1 * (1 + 8/4) = 3 of the budget.
        let limiter = AdmissionLimiter::new(4, 8, 1);
        assert_eq!(limiter.heavy_capacity(), 3);

        let mut admitted = Vec::new();
        let mut waiters = tokio::task::JoinSet::new();
        for _ in 0..12 {
            admitted.push(limiter.try_admit(METHOD).expect("admitted by the class-blind gate"));
            let limiter = Arc::clone(&limiter);
            waiters.spawn(async move {
                limiter.acquire_execution(METHOD, TraceWeight::Heavy, far()).await
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        // One heavy request runs and two wait; the other nine were refused at the class gate
        // instead of parking on a sub-cap only they can drain.
        assert_eq!(limiter.heavy_executing(), 1);
        assert!(limiter.heavy_in_flight.load(Ordering::Relaxed) <= 3);

        // Which is the point: an ordinary request still gets a permit, because the execution
        // permits the heavy flood was not using are still reachable.
        let ordinary = limiter
            .acquire_execution(METHOD, TraceWeight::Normal, far())
            .await
            .expect("ordinary traffic is not starved by a heavy flood");
        drop(ordinary);
        waiters.abort_all();
    }

    /// `--admission-max-queue 0` means execute-or-shed for heavy requests too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_zero_queue_leaves_heavy_requests_nowhere_to_wait() {
        let limiter = AdmissionLimiter::new(8, 0, 2);
        assert_eq!(limiter.heavy_capacity(), 2, "no queue means no heavy waiters either");

        let _first = limiter
            .acquire_execution(METHOD, TraceWeight::Heavy, far())
            .await
            .expect("first heavy");
        let _second = limiter
            .acquire_execution(METHOD, TraceWeight::Heavy, far())
            .await
            .expect("second heavy");
        let started = Instant::now();
        let refused = limiter.acquire_execution(METHOD, TraceWeight::Heavy, far()).await;
        assert_eq!(refused.unwrap_err(), AdmissionError::Overloaded);
        // Promptness is the assertion that discriminates: sharing the class-blind budget also
        // ends in `Overloaded`, but only after parking on the sub-cap until the cutoff — which
        // is the queueing this configuration says it does not want.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "refused outright, not parked on a full sub-cap until the deadline"
        );
    }

    /// The heavy occupancy gauge is raised the moment the sub-cap permit is taken, not once
    /// both permits are in hand — otherwise it reads zero while every heavy permit is reserved
    /// and further heavy requests are blocked on them, disagreeing with the admin RPC.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn heavy_occupancy_is_visible_while_waiting_for_an_execution_permit() {
        let limiter = AdmissionLimiter::new(1, 8, 1);
        let _blocker =
            limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await.expect("blocker");

        let waiting = {
            let limiter = Arc::clone(&limiter);
            tokio::spawn(async move {
                limiter.acquire_execution(METHOD, TraceWeight::Heavy, far()).await
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            limiter.heavy_executing(),
            1,
            "the sub-cap permit is held and must be visible as such, not only once the \
             execution permit follows"
        );
        waiting.abort();
    }

    /// Resizing concurrently with acquire/release must not leak or duplicate permits.
    ///
    /// The debt protocol has two writers on the hot path (a release settling debt) and one on
    /// the admin path (a resize), so its failure mode is drift rather than a crash: a permit
    /// forgotten twice shrinks the budget permanently, one returned when it should have been
    /// forgotten inflates it. Neither shows up until much later, so this asserts the books
    /// balance exactly once everything quiesces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_resizes_and_releases_keep_the_budget_exact() {
        let limiter = AdmissionLimiter::new(8, 64, 8);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let limiter = Arc::clone(&limiter);
            tasks.spawn(async move {
                for _ in 0..200 {
                    if let Ok(permit) =
                        limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await
                    {
                        tokio::task::yield_now().await;
                        drop(permit);
                    }
                }
            });
        }
        {
            let limiter = Arc::clone(&limiter);
            tasks.spawn(async move {
                for round in 0..200u64 {
                    limiter.set_max_concurrent(1 + round % 8);
                    tokio::task::yield_now().await;
                }
            });
        }
        // Bounded: a protocol that loses permits starves every acquirer, and the failure would
        // otherwise be a hung job rather than a red test.
        let drain = async {
            while let Some(joined) = tasks.join_next().await {
                joined.expect("no task panicked");
            }
        };
        tokio::time::timeout(Duration::from_secs(20), drain)
            .await
            .expect("permits stopped circulating — the debt protocol lost some");

        // Quiesced: everything handed out came back, and the semaphore holds exactly the
        // configured limit — no permit lost to a double-forget, none conjured by a release
        // that should have forgotten one.
        limiter.set_max_concurrent(8);
        assert_eq!(limiter.executing(), 0, "every permit was returned");
        assert_eq!(limiter.execution.debt.load(Ordering::SeqCst), 0, "no debt outstanding");
        assert_eq!(
            limiter.execution.sem.available_permits(),
            8,
            "the budget is exactly the configured limit"
        );
    }

    /// Occupancy stays truthful while a shrink's debt is outstanding.
    ///
    /// The regression this pins: deriving `executing()` as `limit - available_permits` reports
    /// the *new* limit once a shrink cannot remove permits that are checked out — so an
    /// operator shrinking 4 to 1 under load would be told 1 request was executing and 3 were
    /// queued, when in truth 4 were still executing and nothing was queued. That is the
    /// read-back of the very write they just made, wrong in both directions, during exactly
    /// the incident it exists to inform.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn occupancy_stays_truthful_while_a_shrink_is_outstanding() {
        let limiter = AdmissionLimiter::new(4, 64, 4);
        let _admitted: Vec<_> = (0..4).map(|_| limiter.try_admit(METHOD).expect("admit")).collect();
        let mut held = hold(&limiter, 4).await;
        assert_eq!(limiter.executing(), 4);

        limiter.set_max_concurrent(1);
        assert_eq!(limiter.max_concurrent(), 1, "the configured limit applies at once");
        assert_eq!(limiter.executing(), 4, "but all four holders are still running");
        assert_eq!(limiter.queued(), 0, "and none of them is waiting for anything");

        held.pop();
        assert_eq!(limiter.executing(), 3, "occupancy tracks releases through the debt");
        held.clear();
        assert_eq!(limiter.executing(), 0);
    }

    /// The heavy sub-cap reports its own occupancy, so the admin snapshot can distinguish
    /// "saturated on memory-hungry tracers" from "saturated overall".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn heavy_occupancy_is_reported_separately() {
        let limiter = AdmissionLimiter::new(8, 8, 2);
        let _heavy =
            limiter.acquire_execution(METHOD, TraceWeight::Heavy, far()).await.expect("heavy");
        let _normal =
            limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await.expect("normal");
        assert_eq!(limiter.executing(), 2, "both hold an ordinary execution permit");
        assert_eq!(limiter.heavy_executing(), 1, "only one holds a heavy permit");
    }

    /// A heavy request that wins the sub-cap but loses the ordinary permit must not keep the
    /// scarcer of the two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_heavy_request_that_times_out_releases_its_sub_cap_permit() {
        let limiter = AdmissionLimiter::new(1, 8, 1);
        let _blocker =
            limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await.expect("blocker");

        let refused = limiter
            .acquire_execution(
                METHOD,
                TraceWeight::Heavy,
                Instant::now() + Duration::from_millis(50),
            )
            .await;
        assert_eq!(refused.unwrap_err(), AdmissionError::Overloaded);
        assert_eq!(
            limiter.heavy_executing(),
            0,
            "the sub-cap permit was released when the ordinary one could not be had"
        );
    }

    /// Growing again after a shrink that left debt must not double-count: the growth first
    /// cancels the outstanding debt, and only the remainder becomes new permits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn growing_cancels_outstanding_debt_first() {
        let limiter = AdmissionLimiter::new(4, 64, 1);
        let held = hold(&limiter, 4).await;
        limiter.set_max_concurrent(1); // 4 checked out, 3 of debt
        limiter.set_max_concurrent(4); // back where we started; debt must simply vanish
        drop(held);

        let _regained = hold(&limiter, 4).await;
        assert_eq!(limiter.executing(), 4, "all four permits came back, none forgotten twice");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_is_in_flight_minus_executing() {
        let limiter = AdmissionLimiter::new(1, 4, 1);
        let _admitted: Vec<_> = (0..3).map(|_| limiter.try_admit(METHOD).expect("admit")).collect();
        assert_eq!(limiter.queued(), 3, "admitted, none executing yet");

        let _permit =
            limiter.acquire_execution(METHOD, TraceWeight::Normal, far()).await.expect("permit");
        assert_eq!(limiter.executing(), 1);
        assert_eq!(limiter.queued(), 2);
    }
}
