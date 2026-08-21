//! Prometheus Metrics for Debug-Trace-Server
//!
//! This module provides metrics collection and export for monitoring the debug-trace-server.
//! Metrics are exposed via HTTP endpoint for Prometheus scraping.
//!
//! Uses `metrics-derive` for declarative metric definitions following mega-reth patterns.

use std::net::SocketAddr;

use eyre::Result;
use metrics::{Counter, Gauge, Histogram, counter, gauge, histogram};
use metrics_derive::Metrics;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
pub use stateless_common::{
    DEFAULT_METRICS_PORT,
    metrics::{BYTE_BUCKETS, REORG_DEPTH_BUCKETS},
};

/// Prefix for timed RPC method aliases.
pub const TIMED_PREFIX: &str = "timed_";

/// RPC method name for debug_traceBlockByNumber.
pub const METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER: &str = "debug_traceBlockByNumber";
/// RPC method name for debug_traceBlockByHash.
pub const METHOD_DEBUG_TRACE_BLOCK_BY_HASH: &str = "debug_traceBlockByHash";
/// RPC method name for debug_traceTransaction.
pub const METHOD_DEBUG_TRACE_TRANSACTION: &str = "debug_traceTransaction";
/// RPC method name for debug_getCacheStatus.
pub const METHOD_DEBUG_GET_CACHE_STATUS: &str = "debug_getCacheStatus";
/// RPC method name for trace_block.
pub const METHOD_TRACE_BLOCK: &str = "trace_block";
/// RPC method name for trace_transaction.
pub const METHOD_TRACE_TRANSACTION: &str = "trace_transaction";

/// Timed alias for debug_traceBlockByNumber.
pub const TIMED_METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER: &str = "timed_debug_traceBlockByNumber";
/// Timed alias for debug_traceBlockByHash.
pub const TIMED_METHOD_DEBUG_TRACE_BLOCK_BY_HASH: &str = "timed_debug_traceBlockByHash";
/// Timed alias for debug_traceTransaction.
pub const TIMED_METHOD_DEBUG_TRACE_TRANSACTION: &str = "timed_debug_traceTransaction";
/// Timed alias for debug_getCacheStatus.
pub const TIMED_METHOD_DEBUG_GET_CACHE_STATUS: &str = "timed_debug_getCacheStatus";
/// Timed alias for trace_block.
pub const TIMED_METHOD_TRACE_BLOCK: &str = "timed_trace_block";
/// Timed alias for trace_transaction.
pub const TIMED_METHOD_TRACE_TRANSACTION: &str = "timed_trace_transaction";

/// All (timed_alias, original_method) pairs for registering aliases.
pub const TIMED_METHOD_ALIASES: &[(&str, &str)] = &[
    (TIMED_METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER, METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER),
    (TIMED_METHOD_DEBUG_TRACE_BLOCK_BY_HASH, METHOD_DEBUG_TRACE_BLOCK_BY_HASH),
    (TIMED_METHOD_DEBUG_TRACE_TRANSACTION, METHOD_DEBUG_TRACE_TRANSACTION),
    (TIMED_METHOD_DEBUG_GET_CACHE_STATUS, METHOD_DEBUG_GET_CACHE_STATUS),
    (TIMED_METHOD_TRACE_BLOCK, METHOD_TRACE_BLOCK),
    (TIMED_METHOD_TRACE_TRANSACTION, METHOD_TRACE_TRANSACTION),
];

/// Cache type for debug trace block responses.
pub const CACHE_TYPE_DEBUG_TRACE: &str = "debug_trace_block";
/// Cache type for parity trace block responses.
pub const CACHE_TYPE_TRACE: &str = "trace_block";
/// Cache type for the in-memory block-data cache.
pub const CACHE_TYPE_BLOCK_DATA: &str = "block_data";

// All known RPC methods (for resolving &str → &'static str)
/// [`ALL_METHODS`] exposed for the admission-coverage test in `main`.
#[cfg(test)]
pub const ALL_METHOD_NAMES: &[&str] = ALL_METHODS;

const ALL_METHODS: &[&str] = &[
    METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
    METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
    METHOD_DEBUG_TRACE_TRANSACTION,
    METHOD_DEBUG_GET_CACHE_STATUS,
    METHOD_TRACE_BLOCK,
    METHOD_TRACE_TRANSACTION,
];

/// The methods the inbound admission gate applies to: everything that fetches a block and
/// runs a tracer, i.e. everything whose cost is a block-unit.
///
/// `debug_getCacheStatus` is deliberately absent — it is pure atomic reads, touches neither
/// upstream nor EVM, and shedding the one endpoint an operator uses to ask what the server
/// is doing, precisely while it is shedding, would be self-defeating. Unknown methods are
/// absent too: the framework answers them `-32601` in microseconds, so gating buys nothing
/// and would replace that with a misleading `-32013`.
///
/// This is the single source of truth for the allowlist: the admission layer gates exactly
/// these, and [`pre_register_all_metrics`] registers the `shed` arrival series for exactly
/// these. Callers must resolve the wire name through [`method_label`] first, so `timed_`
/// aliases are covered.
pub const GATED_METHODS: &[&str] = &[
    METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
    METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
    METHOD_DEBUG_TRACE_TRANSACTION,
    METHOD_TRACE_BLOCK,
    METHOD_TRACE_TRANSACTION,
];

/// Whether the admission gate applies to an already-resolved method label.
pub fn is_gated(method: &'static str) -> bool {
    GATED_METHODS.contains(&method)
}

/// Maps an arbitrary method string onto one of the known `&'static str` labels, so a
/// caller that only has a borrowed name can still label a metric without allocating.
/// Unknown methods collapse to `"unknown"`, keeping label cardinality bounded against
/// arbitrary client input.
pub fn resolve_method(method: &str) -> &'static str {
    ALL_METHODS.iter().find(|&&m| m == method).copied().unwrap_or("unknown")
}

/// RPC method metrics with method label.
///
/// `rpc_errors_total` deliberately does *not* live here: it needs a second `reason` label
/// (see [`ErrorReason`]) and is emitted through [`record_rpc_error`] instead, so the two
/// label sets never collide on one metric name.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct RpcMethodMetrics {
    /// Total number of RPC requests
    rpc_requests_total: Counter,
    /// Duration of RPC method calls in seconds
    request_duration_seconds: Histogram,
}

impl RpcMethodMetrics {
    /// Creates metrics for a specific RPC method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Records a successful request.
    pub fn record_request(&self, duration_secs: f64) {
        self.rpc_requests_total.increment(1);
        self.request_duration_seconds.record(duration_secs);
    }
}

/// Client-visible error outcomes, labeled `(method, reason)`.
const RPC_ERRORS_TOTAL: &str = "debug_trace_rpc_errors_total";
/// Requests abandoned by the client before the handler produced a response, labeled `(method)`.
const RPC_REQUESTS_CANCELLED_TOTAL: &str = "debug_trace_requests_cancelled_total";
/// Requests answered with a JSON `null` result because an underlying failure was
/// deliberately degraded rather than surfaced, labeled `(method, reason)`.
const RPC_NULL_RESULTS_TOTAL: &str = "debug_trace_null_results_total";

/// Why a request failed, as seen by the client.
///
/// Exists because a single unlabeled error counter cannot answer the one question that
/// matters operationally — "did anyone get a timeout?" — since a malformed `tracerConfig`
/// (`-32602`), a missing transaction (`-32001`), a blown deadline (`-32001`) and a trace
/// execution failure (`-32000`) otherwise collapse into the same series.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorReason {
    /// The witness sub-deadline elapsed — the frontier-witness case operators must alert on.
    DeadlineWitness,
    /// The block-pipeline deadline elapsed (header, full block, contracts, tag resolution).
    DeadlineBlock,
    /// Deterministically absent: unknown transaction, or a transaction still pending.
    NotFound,
    /// Rejected at the boundary before any fetch — currently a type-malformed `tracerConfig`.
    InvalidParams,
    /// The tracer ran and failed, or its output could not be serialized.
    TraceFailed,
    /// Transport decode, DB, or another internal fault.
    Internal,
    /// Answered by the framework before the handler ran (unknown method, malformed
    /// top-level params, unparsable batch entry) — recorded by the RPC middleware's
    /// fallback, never by a handler.
    Rejected,
    /// Shed by the inbound admission gate: the request arrived while queue + execution
    /// capacity was already full, or waited for an execution permit until so little of its
    /// budget remained that the witness stage could no longer fit. Answered `-32013`
    /// without the tracer ever running.
    Overloaded,
    /// An error response with a non-framework code left the server without a
    /// handler-recorded reason — a handler ran but bypassed the error funnel. This series
    /// sitting at nonzero is a code-drift alarm, not an operating state: it keeps a future
    /// funnel bypass visible instead of silently absorbed into [`Self::Rejected`].
    Unattributed,
}

impl ErrorReason {
    /// The `reason` label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeadlineWitness => "deadline_witness",
            Self::DeadlineBlock => "deadline_block",
            Self::NotFound => "not_found",
            Self::InvalidParams => "invalid_params",
            Self::TraceFailed => "trace_failed",
            Self::Internal => "internal",
            Self::Rejected => "rejected",
            Self::Overloaded => "overloaded",
            Self::Unattributed => "unattributed",
        }
    }

    /// Every variant, for pre-registration and tests.
    pub const ALL: &'static [Self] = &[
        Self::DeadlineWitness,
        Self::DeadlineBlock,
        Self::NotFound,
        Self::InvalidParams,
        Self::TraceFailed,
        Self::Internal,
        Self::Rejected,
        Self::Overloaded,
        Self::Unattributed,
    ];
}

/// Global RPC metrics (singleton).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct RpcGlobalMetrics {
    /// Number of currently in-flight RPC requests
    inflight_requests: Gauge,
}

impl RpcGlobalMetrics {
    /// Creates global RPC metrics.
    pub fn create() -> Self {
        Self::new_with_labels(&[("scope", "global")])
    }

    /// Increments the in-flight request count.
    pub fn inc_inflight(&self) {
        self.inflight_requests.increment(1.0);
    }

    /// Decrements the in-flight request count.
    pub fn dec_inflight(&self) {
        self.inflight_requests.decrement(1.0);
    }
}

/// Response size metrics with method label.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct ResponseSizeMetrics {
    /// Response size in bytes
    response_size_bytes: Histogram,
}

impl ResponseSizeMetrics {
    /// Creates metrics for a specific method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Records a response size.
    pub fn record(&self, size: usize) {
        self.response_size_bytes.record(size as f64);
    }
}

/// CPU execution time per request (global, no method label).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct CpuTimeMetrics {
    /// CPU execution time per request in seconds
    cpu_time_seconds: Histogram,
}

impl CpuTimeMetrics {
    /// Creates global CPU time metrics.
    pub fn create() -> Self {
        Self::new_with_labels(&[] as &[(&str, &str)])
    }

    /// Records a CPU time measurement.
    pub fn record(&self, seconds: f64) {
        self.cpu_time_seconds.record(seconds);
    }
}

/// Body-streaming telemetry, labeled by negotiated content encoding.
///
/// Covers the phase [`CpuTimeMetrics`] cannot see: the request-scoped CPU measurement
/// is finalized before the first body frame is polled, while compression runs inside
/// body polling — so its CPU and the actual wire bytes are only observable there.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct BodyMetrics {
    /// Thread CPU seconds spent streaming one response body (compression + frame copies)
    body_cpu_time_seconds: Histogram,
    /// Bytes put on the wire (post-compression)
    wire_bytes_total: Counter,
}

impl BodyMetrics {
    /// Creates body metrics for one negotiated encoding (`"identity"` when none).
    pub fn create(encoding: &'static str) -> Self {
        Self::new_with_labels(&[("encoding", encoding)])
    }

    /// Records one finished (or aborted) response body.
    pub fn record(&self, cpu_seconds: f64, wire_bytes: u64) {
        self.body_cpu_time_seconds.record(cpu_seconds);
        self.wire_bytes_total.increment(wire_bytes);
    }
}

/// Inbound JSON-RPC batch shape, recorded by the concurrent-batch RPC middleware.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct BatchMetrics {
    /// Entries per inbound JSON-RPC batch request
    batch_size: Histogram,
}

impl BatchMetrics {
    /// Creates the global batch-shape metrics.
    pub fn create() -> Self {
        Self::new_with_labels(&[] as &[(&str, &str)])
    }

    /// Records one inbound batch's entry count.
    pub fn record(&self, entries: usize) {
        self.batch_size.record(entries as f64);
    }
}

/// Cache hit/miss/size metrics with cache type label, shared by every cache tier.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct CacheMetrics {
    /// Total cache hits
    cache_hits_total: Counter,
    /// Total cache misses
    cache_misses_total: Counter,
    /// Current number of entries in cache
    cache_entries: Gauge,
    /// Current cache data size in bytes
    cache_bytes: Gauge,
    /// Inserts that were not retained by the cache (rejected at admission or immediately
    /// evicted), so silent non-admission is distinguishable from ordinary misses; may
    /// include rare false positives from a concurrent eviction racing the retention check
    cache_admission_rejects_total: Counter,
}

impl CacheMetrics {
    /// Creates metrics for a specific cache type.
    pub fn new_for_cache(cache_type: &'static str) -> Self {
        Self::new_with_labels(&[("type", cache_type)])
    }

    /// Records a cache hit.
    pub fn record_hit(&self) {
        self.cache_hits_total.increment(1);
    }

    /// Records a cache miss.
    pub fn record_miss(&self) {
        self.cache_misses_total.increment(1);
    }

    /// Records an insert the cache did not retain.
    pub fn record_admission_reject(&self) {
        self.cache_admission_rejects_total.increment(1);
    }

    /// Sets the current cache size.
    pub fn set_size(&self, entry_count: usize, data_bytes: usize) {
        self.cache_entries.set(entry_count as f64);
        self.cache_bytes.set(data_bytes as f64);
    }
}

/// Counts block-data cache entries dropped after a data-attributable trace failure,
/// labelled by the RPC method that observed the failure. A sustained rate points at an
/// upstream serving bad witnesses (or at eviction misclassification).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct BlockDataEvictionMetrics {
    /// Total block-data cache evictions triggered by trace failures
    block_data_evictions_total: Counter,
}

impl BlockDataEvictionMetrics {
    /// Creates metrics for a specific RPC method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Records one eviction.
    pub fn record(&self) {
        self.block_data_evictions_total.increment(1);
    }
}

/// Point-in-time counter snapshot of a cache, the query-side counterpart of
/// [`CacheMetrics`]; shared by the response cache and the block-data cache.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries in cache.
    pub entry_count: u64,
    /// Total bytes cached.
    pub total_bytes: u64,
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
}

impl CacheStats {
    /// Returns the cache hit rate as a percentage.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { (self.hits as f64 / total as f64) * 100.0 }
    }
}

/// Tracks which source provided block data. Sources: `cache` (HTTP response cache),
/// `memory` (in-memory block-data cache), `db`, and the two RPC witness routes —
/// `witness_generator` (full endpoint chain, generator first) and `witness_historical`
/// (skip-generator chain for blocks at least the local window below the tip). The RPC path
/// as a whole is the sum of the two witness labels.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct DataSourceMetrics {
    /// Total block data fetches by source
    block_data_fetches_total: Counter,
}

impl DataSourceMetrics {
    /// Creates metrics for a specific data source.
    pub fn new_for_source(source: &'static str) -> Self {
        Self::new_with_labels(&[("source", source)])
    }

    /// Records a block data fetch from this source.
    pub fn record(&self) {
        self.block_data_fetches_total.increment(1);
    }
}

/// Single-flight coalescing metrics (new/coalesced/bypassed).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct SingleFlightMetrics {
    /// Total single-flight events by type
    single_flight_total: Counter,
}

impl SingleFlightMetrics {
    /// Creates metrics for a specific single-flight event type.
    pub fn new_for_type(event_type: &'static str) -> Self {
        Self::new_with_labels(&[("type", event_type)])
    }

    /// Records a single-flight event.
    pub fn record(&self) {
        self.single_flight_total.increment(1);
    }
}

/// Total upstream RPC attempts, labeled `(method, provider, outcome)`.
const UPSTREAM_REQUESTS_TOTAL: &str = "debug_trace_upstream_requests_total";
/// Per-attempt upstream RPC duration in seconds, labeled `(method, provider, outcome)`.
const UPSTREAM_DURATION_SECONDS: &str = "debug_trace_upstream_duration_seconds";
/// Logical-call deadline-exceeded ("request timed out") count, labeled `(method)`.
const UPSTREAM_DEADLINE_EXCEEDED_TOTAL: &str = "debug_trace_upstream_deadline_exceeded_total";

/// Records one upstream RPC attempt against `provider` with its `outcome` and duration.
///
/// The `(method, provider, outcome)` labeling is what lets operators attribute latency and
/// separate a returned error from a stall-timeout, per endpoint — the collapsed method-only
/// `success` boolean could do neither. `provider` is a bounded, credential-free endpoint host.
fn record_upstream_attempt(
    method: &'static str,
    provider: &str,
    outcome: &'static str,
    duration_secs: f64,
) {
    counter!(UPSTREAM_REQUESTS_TOTAL, "method" => method, "provider" => provider.to_owned(), "outcome" => outcome)
        .increment(1);
    histogram!(UPSTREAM_DURATION_SECONDS, "method" => method, "provider" => provider.to_owned(), "outcome" => outcome)
        .record(duration_secs);
}

/// Time an upstream call spent queued behind our own concurrency cap, labeled `(method)`.
const UPSTREAM_PERMIT_WAIT_SECONDS: &str = "debug_trace_upstream_permit_wait_seconds";

/// Records one permit-queue wait sample; semantics on `RpcMetrics::on_rpc_permit_wait`.
fn record_upstream_permit_wait(method: &'static str, wait_secs: f64) {
    histogram!(UPSTREAM_PERMIT_WAIT_SECONDS, "method" => method).record(wait_secs);
}

/// Records one logical upstream call giving up because its overall deadline elapsed.
fn record_upstream_deadline_exceeded(method: &'static str) {
    counter!(UPSTREAM_DEADLINE_EXCEEDED_TOTAL, "method" => method).increment(1);
}

/// Request parameter-shape counter, labeled `(method, shape)` — the first-hand answer to
/// "which tracer shapes does production actually send", and how often the non-cacheable
/// shapes bypass the response cache.
const REQUEST_SHAPE_TOTAL: &str = "debug_trace_request_shape_total";

/// Every label emitted by `RequestShape::label`, for pre-registration and tests — plus the
/// two the request never reached a tracer for: `rejected`, recorded by the RPC middleware
/// for requests the framework answered before the handler ran (see
/// [`record_framework_rejection`]), and `shed`, recorded by the admission layer for
/// requests turned away before the handler ran (see [`record_admission_shed`]).
pub const REQUEST_SHAPES: &[&str] = &[
    "default",
    "call_tracer",
    "prestate_tracer",
    "four_byte_tracer",
    "noop_tracer",
    "flat_call_tracer",
    "struct_logger_config",
    "js_tracer",
    "mux_tracer",
    "rejected",
    "shed",
];

/// Records one request of the given parameter shape for `method`.
pub fn record_request_shape(method: &'static str, shape: &'static str) {
    counter!(REQUEST_SHAPE_TOTAL, "method" => method, "shape" => shape).increment(1);
}

/// R2 witness GET retries (one increment per retried attempt).
const R2_WITNESS_RETRIES_TOTAL: &str = "debug_trace_r2_witness_retries_total";

/// R2 witness fetch failures, labeled by `kind`
/// (see `crate::r2_witness::R2WitnessError::KINDS`). Failures here are not user-visible
/// errors — the witness stage falls back to the RPC chain — so this counter is the signal
/// that the R2 fast path is degrading. `kind="missing"` stays the bucket-integrity alarm:
/// a frontier probe's miss is the expected ran-ahead-of-the-uploader outcome and is
/// deliberately not counted here (it still lands on
/// `witness_errors_total{source="witness_r2_frontier"}`); frontier = the near-tip
/// `data_provider::R2_FRONTIER_WINDOW` band, deliberately narrower than the routing
/// window (see its doc).
const R2_WITNESS_ERRORS_TOTAL: &str = "debug_trace_r2_witness_errors_total";

/// Records one retried R2 witness GET attempt.
pub fn record_r2_witness_retry() {
    counter!(R2_WITNESS_RETRIES_TOTAL).increment(1);
}

/// Records one failed R2 witness fetch of the given error `kind`.
pub fn record_r2_witness_error(kind: &'static str) {
    counter!(R2_WITNESS_ERRORS_TOTAL, "kind" => kind).increment(1);
}

/// Time an R2 witness GET spent queued on the self-imposed concurrency cap
/// (`--r2-max-concurrent-requests`) before its first attempt. Deliberately separate from
/// the `witness_r2` duration histogram: on the request path the caller really did wait
/// through this queue, so that histogram reports honest end-to-end time — and this one
/// makes cap-induced queueing distinguishable from actual R2 slowness.
const R2_WITNESS_QUEUE_WAIT_SECONDS: &str = "debug_trace_r2_witness_queue_wait_seconds";

/// Records the queued share of one R2 witness fetch.
pub fn record_r2_witness_queue_wait(seconds: f64) {
    histogram!(R2_WITNESS_QUEUE_WAIT_SECONDS).record(seconds);
}

/// Which R2 target this process was configured with, as a constant-1 info gauge labeled
/// `target`. The R2 series above carry no target dimension, so during a fleet rollout — some
/// hosts on the custom domain, some still on the S3 endpoint — a spike in
/// `debug_trace_r2_witness_errors_total` cannot be attributed to one or the other. Joining on
/// this gauge supplies that dimension without changing the established metric contract.
const R2_TARGET_INFO: &str = "debug_trace_r2_target_info";

/// Publishes the configured R2 target once at startup.
pub fn record_r2_target(target: &'static str) {
    gauge!(R2_TARGET_INFO, "target" => target).set(1.0);
}

/// How many HTTP/2 connections the custom-domain target spreads its GETs over.
///
/// A plain value rather than an info label: it is the divisor for the per-connection stream
/// budget, so a dashboard wants to read it against `--r2-max-concurrent-requests` and against
/// the edge's limit, not group by it. Published only for the custom-domain target, where one
/// client is one connection and the count is therefore a real property of the transport.
const R2_CONNECTIONS: &str = "debug_trace_r2_connections";

/// Publishes the custom-domain connection count once at startup.
pub fn record_r2_connections(connections: usize) {
    gauge!(R2_CONNECTIONS).set(connections as f64);
}

/// The protocol the R2 custom-domain target actually negotiated, as a constant-1 info gauge
/// labeled `version`, published once the first response has been seen.
///
/// Separate from the target gauge on purpose: that one answers "what was configured" and can be
/// published at startup, while this one is only knowable after a request. Folding both into one
/// gauge would mean publishing it twice with different label sets, leaving the startup series
/// stuck at 1 forever alongside the corrected one.
const R2_NEGOTIATED_VERSION_INFO: &str = "debug_trace_r2_negotiated_http_version_info";

/// Publishes the protocol the custom-domain target negotiated.
pub fn record_r2_negotiated_version(version: &'static str) {
    gauge!(R2_NEGOTIATED_VERSION_INFO, "version" => version).set(1.0);
}

/// Canonical number → hash resolution counter, labeled `(source, outcome)` — how often
/// by-number requests resolve their canonical hash from the local DB index vs upstream,
/// and how often resolution misses or fails.
const CANONICAL_HASH_RESOLUTION_TOTAL: &str = "debug_trace_canonical_hash_resolution_total";

/// Records one canonical-hash resolution attempt against `source` (`"db"` | `"memo"` |
/// `"upstream"`) with `outcome` (`"ok"` | `"miss"` | `"error"`; the in-memory memo cannot
/// error, and upstream has no miss — a missing block is an error from the retry loop).
/// `source = "tip_seed"` (`"ok"` | `"error"`) counts the throttled `eth_blockNumber`
/// fetches that teach the memo's depth gate the tip when no other tip source exists.
/// `source = "tag"` (`"ok"` | `"error"`) counts `latest`/`finalized`/`safe` resolutions,
/// which bind number → hash in their single header fetch instead of resolving through
/// the tiers above.
pub fn record_canonical_hash_resolution(source: &'static str, outcome: &'static str) {
    counter!(CANONICAL_HASH_RESOLUTION_TOTAL, "source" => source, "outcome" => outcome)
        .increment(1);
}

/// Witness fetch metrics by source.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct WitnessSourceMetrics {
    /// Total witness fetch requests
    witness_requests_total: Counter,
    /// Total witness fetch errors
    witness_errors_total: Counter,
    /// Duration of witness fetch in seconds
    witness_duration_seconds: Histogram,
    /// Witness response size in bytes
    witness_bytes: Histogram,
}

impl WitnessSourceMetrics {
    /// Creates metrics for a specific witness source.
    pub fn new_for_source(source: &'static str) -> Self {
        Self::new_with_labels(&[("source", source)])
    }

    /// Records a witness fetch request.
    pub fn record_request(&self, success: bool, duration_secs: f64) {
        self.witness_requests_total.increment(1);
        if !success {
            self.witness_errors_total.increment(1);
        }
        self.witness_duration_seconds.record(duration_secs);
    }

    /// Records witness response size.
    pub fn record_size(&self, bytes: usize) {
        self.witness_bytes.record(bytes as f64);
    }
}

/// EVM execution metrics with method label.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct EvmExecutionMetrics {
    /// EVM execution duration in seconds
    evm_execution_seconds: Histogram,
    /// Number of transactions per traced block
    evm_block_tx_count: Histogram,
}

impl EvmExecutionMetrics {
    /// Creates metrics for a specific method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Records an EVM execution.
    pub fn record(&self, duration_secs: f64, tx_count: usize) {
        self.evm_execution_seconds.record(duration_secs);
        self.evm_block_tx_count.record(tx_count as f64);
    }
}

/// Chain sync metrics (singleton).
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct ChainSyncMetrics {
    /// Depth of chain reorgs
    reorg_depth: Histogram,
    /// Duration of DB read operations in seconds
    db_read_duration_seconds: Histogram,
    /// Distance of requested block from chain tip
    block_distance_from_tip: Histogram,
    /// Earliest block number in validator DB
    db_earliest_block: Gauge,
    /// Earliest block number with a stored body + witness. Tracks `db_earliest_block`
    /// (pruning removes bodies and chain rows together) but can differ transiently, e.g.
    /// chain rows advanced whose bodies were never stored
    db_body_earliest_block: Gauge,
    /// Latest block number in validator DB
    db_latest_block: Gauge,
    /// Database file size in bytes
    db_size_bytes: Gauge,
    /// Local chain tip block number (updated on every advance)
    local_chain_height: Gauge,
}

impl ChainSyncMetrics {
    /// Creates chain sync metrics.
    pub fn create() -> Self {
        Self::new_with_labels(&[("scope", "chain_sync")])
    }

    /// Records a reorg event.
    pub fn record_reorg(&self, depth: u64) {
        self.reorg_depth.record(depth as f64);
    }

    /// Records a DB read duration.
    pub fn record_db_read(&self, duration_secs: f64) {
        self.db_read_duration_seconds.record(duration_secs);
    }

    /// Records block distance from tip.
    pub fn record_block_distance(&self, distance: u64) {
        self.block_distance_from_tip.record(distance as f64);
    }

    /// Sets the earliest and latest block numbers in the validator DB.
    pub fn set_db_block_range(&self, earliest: u64, latest: u64) {
        self.db_earliest_block.set(earliest as f64);
        self.db_latest_block.set(latest as f64);
    }

    /// Sets the earliest block that still has a stored body (the body-retention edge).
    pub fn set_db_body_earliest_block(&self, earliest: u64) {
        self.db_body_earliest_block.set(earliest as f64);
    }

    /// Sets the database file size in bytes.
    pub fn set_db_size(&self, bytes: u64) {
        self.db_size_bytes.set(bytes as f64);
    }

    /// Updates the local chain height gauge.
    pub fn set_chain_height(&self, height: u64) {
        self.local_chain_height.set(height as f64);
    }
}

/// Inbound admission-gate occupancy, labeled `(method)`.
///
/// Two independent gauges rather than a queued/executing pair, because the two phases are
/// raised in different places: `in_flight` by the RPC middleware for the whole request,
/// `executing` by the handler for the span it holds an execution permit. Queue depth is
/// `in_flight - executing`, derived at query time.
///
/// Both are lowered by RAII guards: a request cancelled while queued, or midway through
/// execution, must not leave a gauge stuck high forever.
#[derive(Clone, Metrics)]
#[metrics(scope = "debug_trace")]
pub struct AdmissionMetrics {
    /// Requests admitted by the gate and not yet finished.
    admission_in_flight: Gauge,
    /// Requests holding an execution permit.
    admission_executing: Gauge,
}

impl AdmissionMetrics {
    /// Creates admission metrics for a specific RPC method.
    pub fn new_for_method(method: &'static str) -> Self {
        Self::new_with_labels(&[("method", method)])
    }

    /// Adjusts the admitted-and-unfinished gauge.
    pub fn in_flight_delta(&self, delta: f64) {
        self.admission_in_flight.increment(delta);
    }

    /// Adjusts the holding-an-execution-permit gauge.
    pub fn executing_delta(&self, delta: f64) {
        self.admission_executing.increment(delta);
    }
}

/// Requests holding a permit from the heavy-shape sub-cap. Unlabeled: the sub-cap is a
/// single process-wide budget, and which method asked for it is already on
/// `admission_executing`.
const ADMISSION_HEAVY_EXECUTING: &str = "debug_trace_admission_heavy_executing";

/// Time a request spent waiting for an execution permit. Unlabeled, following the
/// `debug_trace_r2_witness_queue_wait_seconds` precedent: under a single global limiter the
/// wait is method-independent, and the method dimension is already on the gauges.
///
/// Biased by construction: only waits that ended in a permit are sampled. A wait that ended
/// in a client hangup lands on `requests_cancelled_total`, and one clamped by the deadline
/// lands on `rpc_errors_total{reason="overloaded"}`.
const ADMISSION_PERMIT_WAIT_SECONDS: &str = "debug_trace_admission_permit_wait_seconds";

/// The limits currently in effect. Published at startup and on every admin write — these are
/// runtime-mutable, so without them a dashboard cannot tell what the gate is actually
/// enforcing, and a shed spike is unattributable to the change that caused it.
const ADMISSION_MAX_CONCURRENT: &str = "debug_trace_admission_max_concurrent";
/// See [`ADMISSION_MAX_CONCURRENT`].
const ADMISSION_MAX_QUEUE: &str = "debug_trace_admission_max_queue";
/// See [`ADMISSION_MAX_CONCURRENT`].
const ADMISSION_HEAVY_MAX_CONCURRENT: &str = "debug_trace_admission_heavy_max_concurrent";

/// Responses discarded for exceeding `--max-response-size`, labeled `(method)`.
const RESPONSE_OVERSIZED_TOTAL: &str = "debug_trace_response_oversized_total";

/// Records the wait one request spent queued for an execution permit.
pub fn record_admission_permit_wait(seconds: f64) {
    histogram!(ADMISSION_PERMIT_WAIT_SECONDS).record(seconds);
}

/// Publishes the limits currently in effect.
pub fn record_admission_limits(max_concurrent: u64, max_queue: u64, heavy_max_concurrent: u64) {
    gauge!(ADMISSION_MAX_CONCURRENT).set(max_concurrent as f64);
    gauge!(ADMISSION_MAX_QUEUE).set(max_queue as f64);
    gauge!(ADMISSION_HEAVY_MAX_CONCURRENT).set(heavy_max_concurrent as f64);
}

/// Adjusts the heavy sub-cap occupancy gauge.
pub fn record_admission_heavy_delta(delta: f64) {
    gauge!(ADMISSION_HEAVY_EXECUTING).increment(delta);
}

/// Records one response discarded for exceeding the configured size cap.
pub fn record_response_oversized(method: &'static str) {
    counter!(RESPONSE_OVERSIZED_TOTAL, "method" => method).increment(1);
}

/// Pre-registers all metrics so they appear in Prometheus from startup (with zero values).
fn pre_register_all_metrics() {
    // Request Layer: RPC method metrics — every method that can record a served request,
    // including the cache-status endpoint outside the trace pipeline.
    let _ = RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
    let _ = RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
    let _ = RpcMethodMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION);
    let _ = RpcMethodMetrics::new_for_method(METHOD_TRACE_BLOCK);
    let _ = RpcMethodMetrics::new_for_method(METHOD_TRACE_TRANSACTION);
    let _ = RpcMethodMetrics::new_for_method(METHOD_DEBUG_GET_CACHE_STATUS);

    // Request Layer: the accounting identity's error/cancellation terms. Pre-registering the
    // full (method x reason) grid means a dashboard can subtract zeros instead of missing
    // series, and `rate(...{reason="deadline_witness"})` alerts on absence from boot. Every
    // known method participates — the middleware's cancelled/rejected terms cover them all —
    // plus the `unknown` fold target `resolve_method` maps arbitrary client method names
    // onto, which those same middleware terms label.
    for method in ALL_METHODS.iter().copied().chain(["unknown"]) {
        counter!(RPC_REQUESTS_CANCELLED_TOTAL, "method" => method).increment(0);
        for reason in ErrorReason::ALL {
            counter!(RPC_ERRORS_TOTAL, "method" => method, "reason" => reason.as_str())
                .increment(0);
        }
    }
    // Only Parity `trace_transaction` degrades a failure to a null result.
    for reason in [ErrorReason::DeadlineWitness, ErrorReason::DeadlineBlock, ErrorReason::NotFound]
    {
        counter!(RPC_NULL_RESULTS_TOTAL, "method" => METHOD_TRACE_TRANSACTION, "reason" => reason.as_str())
            .increment(0);
    }

    // Request Layer: global
    let _ = RpcGlobalMetrics::create();

    // Request Layer: response size (per method)
    let _ = ResponseSizeMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
    let _ = ResponseSizeMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
    let _ = ResponseSizeMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION);
    let _ = ResponseSizeMetrics::new_for_method(METHOD_TRACE_BLOCK);
    let _ = ResponseSizeMetrics::new_for_method(METHOD_TRACE_TRANSACTION);

    // Request Layer: CPU time (global)
    let _ = CpuTimeMetrics::create();

    // Request Layer: inbound batch shape (global)
    let _ = BatchMetrics::create();

    // Request Layer: body streaming (per negotiated encoding); br/deflate are
    // deliberately not offered, so only these three series can ever be written
    for encoding in ["identity", "gzip", "zstd"] {
        let _ = BodyMetrics::create(encoding);
    }

    // Cache Layer
    let _ = CacheMetrics::new_for_cache(CACHE_TYPE_DEBUG_TRACE);
    let _ = CacheMetrics::new_for_cache(CACHE_TYPE_TRACE);
    let _ = CacheMetrics::new_for_cache(CACHE_TYPE_BLOCK_DATA);
    let _ = BlockDataEvictionMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
    let _ = BlockDataEvictionMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
    let _ = BlockDataEvictionMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION);
    let _ = BlockDataEvictionMetrics::new_for_method(METHOD_TRACE_BLOCK);
    let _ = BlockDataEvictionMetrics::new_for_method(METHOD_TRACE_TRANSACTION);

    // Data Fetch Layer: data source
    let _ = DataSourceMetrics::new_for_source("cache");
    let _ = DataSourceMetrics::new_for_source("memory");
    let _ = DataSourceMetrics::new_for_source("db");
    let _ = DataSourceMetrics::new_for_source("witness_generator");
    let _ = DataSourceMetrics::new_for_source("witness_historical");
    let _ = DataSourceMetrics::new_for_source("witness_r2");
    let _ = DataSourceMetrics::new_for_source("witness_r2_frontier");

    // Data Fetch Layer: R2 witness source
    counter!(R2_WITNESS_RETRIES_TOTAL).increment(0);
    for kind in crate::r2_witness::R2WitnessError::KINDS {
        counter!(R2_WITNESS_ERRORS_TOTAL, "kind" => *kind).increment(0);
    }
    counter!(R2_WITNESS_ERRORS_TOTAL, "kind" => crate::r2_witness::KIND_MISSING_ABOVE_TIP)
        .increment(0);
    let _ = histogram!(R2_WITNESS_QUEUE_WAIT_SECONDS);

    // Data Fetch Layer: single-flight
    let _ = SingleFlightMetrics::new_for_type("new");
    let _ = SingleFlightMetrics::new_for_type("coalesced");
    let _ = SingleFlightMetrics::new_for_type("bypassed");

    // Data Fetch Layer: upstream RPC. The attempt series (`upstream_requests_total` /
    // `upstream_duration_seconds`) carry a dynamic per-endpoint `provider` label, so they first
    // appear on the initial attempt; only the method-keyed series are pre-registrable here.
    for method in
        ["eth_getHeaderByHash", "eth_getBlockByHash", "mega_getWitness", "eth_getCodeByHash"]
    {
        counter!(UPSTREAM_DEADLINE_EXCEEDED_TOTAL, "method" => method).increment(0);
        let _ = histogram!(UPSTREAM_PERMIT_WAIT_SECONDS, "method" => method);
    }

    // Request Layer: parameter shapes (per opts-taking method)
    for method in [
        METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER,
        METHOD_DEBUG_TRACE_BLOCK_BY_HASH,
        METHOD_DEBUG_TRACE_TRANSACTION,
    ] {
        for shape in REQUEST_SHAPES {
            counter!(REQUEST_SHAPE_TOTAL, "method" => method, "shape" => *shape).increment(0);
        }
    }
    // Arrival series for the opts-less methods: "default" at handler entry, "rejected" via
    // the middleware fallback, plus "shed" for the two the admission gate applies to. The
    // three opts-taking methods get "shed" from `REQUEST_SHAPES` above; `debug_getCacheStatus`
    // is exempt from the gate (see `GATED_METHODS`) so it has no `shed` series at all.
    for method in [METHOD_TRACE_BLOCK, METHOD_TRACE_TRANSACTION] {
        for shape in ["default", "rejected", "shed"] {
            counter!(REQUEST_SHAPE_TOTAL, "method" => method, "shape" => shape).increment(0);
        }
    }
    for shape in ["default", "rejected"] {
        counter!(REQUEST_SHAPE_TOTAL, "method" => METHOD_DEBUG_GET_CACHE_STATUS, "shape" => shape)
            .increment(0);
    }
    // The `unknown` fold target only ever arrives through the middleware's rejected pair.
    counter!(REQUEST_SHAPE_TOTAL, "method" => "unknown", "shape" => "rejected").increment(0);

    // Request Layer: admission gate. Occupancy is per gated method; the limit gauges are
    // global and are re-published on every admin write.
    for method in GATED_METHODS.iter().copied() {
        let _ = AdmissionMetrics::new_for_method(method);
    }
    let _ = histogram!(ADMISSION_PERMIT_WAIT_SECONDS);
    gauge!(ADMISSION_HEAVY_EXECUTING).set(0.0);

    // Request Layer: responses discarded for exceeding `--max-response-size`. Every method
    // that can produce a trace body participates; a nonzero value here is the signal that
    // clients are asking for more than the process is willing to materialize.
    for method in GATED_METHODS.iter().copied() {
        counter!(RESPONSE_OVERSIZED_TOTAL, "method" => method).increment(0);
    }

    // Data Fetch Layer: canonical number → hash resolution
    for (source, outcome) in [
        ("db", "ok"),
        ("db", "miss"),
        ("db", "error"),
        ("memo", "ok"),
        ("memo", "miss"),
        ("upstream", "ok"),
        ("upstream", "error"),
        ("tip_seed", "ok"),
        ("tip_seed", "error"),
        ("tag", "ok"),
        ("tag", "error"),
    ] {
        counter!(CANONICAL_HASH_RESOLUTION_TOTAL, "source" => source, "outcome" => outcome)
            .increment(0);
    }

    // Witness Layer
    let _ = WitnessSourceMetrics::new_for_source("witness_generator");
    let _ = WitnessSourceMetrics::new_for_source("witness_historical");
    let _ = WitnessSourceMetrics::new_for_source("witness_r2");
    let _ = WitnessSourceMetrics::new_for_source("witness_r2_frontier");

    // Execution Layer (per method)
    let _ = EvmExecutionMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_NUMBER);
    let _ = EvmExecutionMetrics::new_for_method(METHOD_DEBUG_TRACE_BLOCK_BY_HASH);
    let _ = EvmExecutionMetrics::new_for_method(METHOD_DEBUG_TRACE_TRANSACTION);
    let _ = EvmExecutionMetrics::new_for_method(METHOD_TRACE_BLOCK);
    let _ = EvmExecutionMetrics::new_for_method(METHOD_TRACE_TRANSACTION);

    // Infrastructure
    let _ = ChainSyncMetrics::create();
}

/// Transaction count per traced block (~ 1–500).
const TX_COUNT_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0];

/// Block distance from chain tip (~ 0–1000 blocks).
const BLOCK_DISTANCE_BUCKETS: &[f64] = &[0.0, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0];

/// Body-streaming CPU per response, seconds (~ sub-ms identity frames to hundreds of ms
/// compressing a multi-MB trace). Explicit buckets keep this an aggregatable histogram —
/// without them the exporter renders per-instance summary quantiles, which cannot be
/// combined across replicas or alerted on cleanly.
const BODY_CPU_TIME_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5];

/// Wait for an inbound execution permit, seconds. Spans "uncontended" (microseconds) to the
/// deadline clamp (seconds). Explicit buckets for the same reason as
/// [`BODY_CPU_TIME_BUCKETS`]: without them the exporter renders per-instance summary
/// quantiles that cannot be aggregated across replicas.
const ADMISSION_WAIT_BUCKETS: &[f64] =
    &[0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// (metric_name, buckets) pairs applied via `set_buckets_for_metric` at startup.
const BUCKET_SPECS: &[(&str, &[f64])] = &[
    ("debug_trace_evm_block_tx_count", TX_COUNT_BUCKETS),
    ("debug_trace_batch_size", TX_COUNT_BUCKETS),
    ("debug_trace_block_distance_from_tip", BLOCK_DISTANCE_BUCKETS),
    ("debug_trace_reorg_depth", REORG_DEPTH_BUCKETS),
    ("debug_trace_witness_bytes", BYTE_BUCKETS),
    ("debug_trace_body_cpu_time_seconds", BODY_CPU_TIME_BUCKETS),
    ("debug_trace_admission_permit_wait_seconds", ADMISSION_WAIT_BUCKETS),
];

/// Initializes the Prometheus metrics exporter.
pub fn init_metrics(addr: SocketAddr) -> Result<()> {
    let builder = BUCKET_SPECS.iter().fold(PrometheusBuilder::new(), |b, &(name, buckets)| {
        b.set_buckets_for_metric(Matcher::Full(name.to_owned()), buckets)
            .expect("valid bucket config")
    });

    builder
        .with_http_listener(addr)
        .install()
        .map_err(|e| eyre::eyre!("Failed to install metrics exporter: {}", e))?;

    // Pre-register all metrics
    pre_register_all_metrics();

    Ok(())
}

/// Strips the `timed_` prefix from a method name if present.
pub fn strip_timed_prefix(method: &str) -> &str {
    method.strip_prefix(TIMED_PREFIX).unwrap_or(method)
}

/// Resolves a wire method name (possibly `timed_`-prefixed, possibly arbitrary client
/// input) to its bounded `&'static str` metric label.
pub fn method_label(method: &str) -> &'static str {
    resolve_method(strip_timed_prefix(method))
}

/// Records a successful RPC request.
pub fn record_rpc_request(method: &str, duration_secs: f64) {
    let method = resolve_method(strip_timed_prefix(method));
    RpcMethodMetrics::new_for_method(method).record_request(duration_secs);
}

/// Records a client-visible RPC error, attributed to `reason`.
///
/// Together with [`record_rpc_request`], [`record_request_cancelled`] and
/// [`record_request_shape`] this closes the per-method accounting identity
/// `request_shape_total = rpc_requests_total + rpc_errors_total + requests_cancelled_total`.
pub fn record_rpc_error(method: &str, reason: ErrorReason) {
    // Tell the RPC middleware's fallback this error response is already accounted for.
    let _ = ERROR_SELF_REPORTED.try_with(|reported| reported.set(true));
    let method = resolve_method(strip_timed_prefix(method));
    counter!(RPC_ERRORS_TOTAL, "method" => method, "reason" => reason.as_str()).increment(1);
}

tokio::task_local! {
    /// Whether the current request's handler already recorded its error outcome.
    /// Scoped per request by [`track_handler_errors`]; [`record_rpc_error`] sets it.
    static ERROR_SELF_REPORTED: std::cell::Cell<bool>;
}

/// Runs one request future with error-outcome tracking, returning its response and
/// whether the handler self-reported an error via [`record_rpc_error`].
///
/// This is what lets the RPC middleware close the last accounting gap: an error response
/// produced without a handler record (unknown method, malformed top-level params — the
/// framework answers before the handler runs) is otherwise invisible to every counter.
/// The task-local is load-bearing only for the `-32602` ambiguity — the framework's
/// param-parse rejection and a handler's `tracerConfig` rejection share the code, so no
/// response-code inspection could tell them apart.
pub async fn track_handler_errors<F: Future>(fut: F) -> (F::Output, bool) {
    ERROR_SELF_REPORTED
        .scope(std::cell::Cell::new(false), async move {
            let out = fut.await;
            let reported = ERROR_SELF_REPORTED.with(|reported| reported.get());
            (out, reported)
        })
        .await
}

/// Records a request the framework rejected before its handler ran, as the balanced pair
/// `request_shape_total{shape="rejected"}` + `rpc_errors_total{reason="rejected"}` — an
/// arrival and an outcome, so the accounting identity holds for requests no handler saw.
/// Takes the already-resolved label, like [`record_request_cancelled`].
pub fn record_framework_rejection(method: &'static str) {
    record_request_shape(method, "rejected");
    record_rpc_error(method, ErrorReason::Rejected);
}

/// Records a request the admission gate turned away before its handler ran, as the balanced
/// pair `request_shape_total{shape="shed"}` + `rpc_errors_total{reason="overloaded"}` — an
/// arrival and an outcome, so the accounting identity holds for requests no handler saw.
/// Takes the already-resolved label, like [`record_framework_rejection`].
///
/// Must be called from inside the request future, never from a layer's synchronous prefix:
/// [`record_rpc_error`] sets the `ERROR_SELF_REPORTED` task-local that tells the middleware
/// fallback this `-32013` is already accounted for, and that task-local only exists inside
/// [`track_handler_errors`]' scope. Recorded outside it, every shed would both double-count
/// the error side and false-fire the `unattributed` drift alarm.
pub fn record_admission_shed(method: &'static str) {
    record_request_shape(method, "shed");
    record_rpc_error(method, ErrorReason::Overloaded);
}

/// Records a request whose handler future was dropped before producing a response —
/// in practice a client that hung up or timed out on its own side.
///
/// Recorded from the RPC middleware rather than the handlers: it is the only layer that
/// observes every entry (single calls *and* batch entries) and still sees the drop.
/// Takes the already-resolved label — the middleware's guard is the one resolution point.
pub fn record_request_cancelled(method: &'static str) {
    counter!(RPC_REQUESTS_CANCELLED_TOTAL, "method" => method).increment(1);
}

/// Records a request answered with a JSON `null` result after an underlying failure was
/// deliberately degraded (the Parity `trace_*` compatibility behaviour).
///
/// The request still counts as served by [`record_rpc_request`], so the accounting identity
/// holds; this counter is what keeps the swallowed failure visible instead of silent.
pub fn record_null_result(method: &str, reason: ErrorReason) {
    let method = resolve_method(strip_timed_prefix(method));
    counter!(RPC_NULL_RESULTS_TOTAL, "method" => method, "reason" => reason.as_str()).increment(1);
}

/// Maps an [`RpcMethod`] to the `method` label used by the upstream attempt metrics.
///
/// The existing dashboard labels (`eth_getHeaderByHash`, `eth_getBlockByHash`, etc.)
/// encode the trace-server-specific call flavor. Since [`RpcMethod`] is coarser
/// (no ByHash/ByNumber split), we keep the existing labels for the hot-path
/// methods and fall back to [`RpcMethod::as_str`] for the others.
fn upstream_label_for(method: stateless_common::metrics::RpcMethod) -> &'static str {
    use stateless_common::metrics::RpcMethod;
    match method {
        RpcMethod::EthGetHeader => "eth_getHeaderByHash",
        RpcMethod::EthGetBlock => "eth_getBlockByHash",
        RpcMethod::MegaGetBlockWitness => "mega_getWitness",
        RpcMethod::EthGetCodeByHash => "eth_getCodeByHash",
        other => other.as_str(),
    }
}

/// [`stateless_common::RpcMetrics`] adapter that forwards every per-attempt RPC
/// event to the upstream metrics, keyed by `(method, provider, outcome)`.
///
/// Wired via [`stateless_common::RpcClientConfig::with_metrics`] so that the
/// per-attempt duration and per-endpoint outcome counters recorded inside
/// `round_robin_with_backoff` reach Prometheus — including the primary-vs-failover
/// split for `mega_getWitness` and the reason (error vs timeout) for each failure.
#[derive(Default)]
pub struct TraceRpcMetrics;

impl stateless_common::RpcMetrics for TraceRpcMetrics {
    fn on_rpc_attempt(
        &self,
        method: stateless_common::metrics::RpcMethod,
        provider: &str,
        outcome: stateless_common::metrics::RpcAttemptOutcome,
        duration_secs: f64,
    ) {
        record_upstream_attempt(
            upstream_label_for(method),
            provider,
            outcome.as_str(),
            duration_secs,
        );
    }

    fn on_rpc_permit_wait(&self, method: stateless_common::metrics::RpcMethod, wait_secs: f64) {
        record_upstream_permit_wait(upstream_label_for(method), wait_secs);
    }

    fn on_rpc_deadline_exceeded(
        &self,
        method: stateless_common::metrics::RpcMethod,
        _elapsed_secs: f64,
    ) {
        record_upstream_deadline_exceeded(upstream_label_for(method));
    }

    fn on_witness_fetch(&self, _breakdown: stateless_common::witness_size::WitnessSizeBreakdown) {
        // Witness size/source metrics are recorded by `fetch_witness` at the outer
        // boundary (distinct semantics from per-attempt).
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_timed_prefix_with_prefix() {
        assert_eq!(
            strip_timed_prefix("timed_debug_traceBlockByNumber"),
            "debug_traceBlockByNumber"
        );
        assert_eq!(strip_timed_prefix("timed_trace_block"), "trace_block");
    }

    #[test]
    fn test_strip_timed_prefix_without_prefix() {
        assert_eq!(strip_timed_prefix("debug_traceBlockByNumber"), "debug_traceBlockByNumber");
        assert_eq!(strip_timed_prefix("unknown_method"), "unknown_method");
    }

    #[test]
    fn test_resolve_method_known() {
        assert_eq!(resolve_method("debug_traceBlockByNumber"), "debug_traceBlockByNumber");
        assert_eq!(resolve_method("trace_block"), "trace_block");
    }

    #[test]
    fn test_resolve_method_unknown() {
        assert_eq!(resolve_method("nonexistent"), "unknown");
    }

    #[test]
    fn test_timed_aliases_consistency() {
        for &(alias, _original) in TIMED_METHOD_ALIASES {
            assert!(alias.starts_with(TIMED_PREFIX));
        }
    }

    #[test]
    fn test_timed_aliases_match_originals() {
        for &(alias, original) in TIMED_METHOD_ALIASES {
            assert_eq!(strip_timed_prefix(alias), original);
        }
    }
}
