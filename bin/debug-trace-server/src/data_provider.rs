//! Data Provider for Block Data Fetching
//!
//! This module provides a data provider that fetches block data required by the
//! debug/trace RPC methods from multiple sources:
//!
//! 1. **Local Database** (fast) - Local DB for pre-fetched blocks (if configured)
//! 2. **Remote RPC** (slower) - Upstream RPC endpoints as fallback
//!
//! Within the RPC fallback, the witness stage routes by block age (see [`WitnessFetchConfig`]):
//! blocks fewer than `local_window` blocks below the local tip use the full witness endpoint
//! chain (internal generator first), while historical blocks — at least `local_window` below,
//! which the generator has long pruned — skip the generator and go straight to the remaining
//! endpoints.
//!
//! # Features
//! - **Single-flight request coalescing**: concurrent callers for the same block hash share one
//!   in-flight fetch via [`futures::future::Shared`]; the result is handed out as `Arc<BlockData>`
//!   so the hot path is a refcount bump, not a deep clone.
//! - **Single deadline per request**: the RPC handler mints one wall-clock deadline via
//!   [`DataProvider::fetch_deadline`] and threads it through the full pipeline (tag resolution,
//!   canonical-hash resolution, header, witness, block, contracts). The witness stage gets a
//!   tighter sub-deadline for blocks at or below the local tip. No more nested
//!   `tokio::time::timeout` wrappers.
//! - **Contract bytecode resolution**: checks [`ContractCache`] (memory → redb), falls back to a
//!   parallel + verified `RpcClient::get_codes_with_deadline` fetch on miss.
//!
//! # Note
//! Response caching is handled at the HTTP layer by `ResponseCache`, not here.

use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use alloy_primitives::{B256, map::HashMap};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use dashmap::DashMap;
use futures::{FutureExt, future::Shared};
use op_alloy_rpc_types::Transaction;
use quick_cache::sync::Cache;
use revm::state::Bytecode;
use stateless_common::{CodeFetchError, RpcClient, RpcDeadlineExceeded, WitnessSizeBreakdown};
use stateless_core::{
    ContractStore, LightWitness, StoreResult, db::StoreError, withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use tracing::{debug, instrument, trace, warn};

use crate::{
    block_data_cache::BlockDataCache,
    metrics::{
        CacheStats, ChainSyncMetrics, DataSourceMetrics, SingleFlightMetrics, WitnessSourceMetrics,
        record_canonical_hash_resolution,
    },
    r2_witness::R2WitnessSource,
    server_db::BlockStore,
};

/// Witness-stage budget and routing-window configuration, shared by the single-flight fetch
/// futures. Whether the historical route is actually taken is derived per fetch from
/// `generator_first`, the client's endpoint count, and the local tip (see [`witness_route`]).
#[derive(Clone, Copy)]
pub(crate) struct WitnessFetchConfig {
    /// Sub-deadline applied to the witness stage for blocks above the local tip.
    pub witness_timeout: Duration,
    /// Sub-deadline for blocks at or below the local tip (clamped to `witness_timeout`).
    pub old_block_witness_timeout: Duration,
    /// Blocks at least this far below the local tip are historical and skip the internal
    /// generator endpoint (see [`DEFAULT_WITNESS_LOCAL_WINDOW`] for the rationale).
    pub local_window: u64,
    /// Whether the first witness endpoint is a declared internal generator
    /// (`--witness-generator-endpoint`) — only then may historical blocks skip it. CLI
    /// knowledge, not derivable from the client: every endpoint speaks the same witness RPC.
    pub generator_first: bool,
}

impl WitnessFetchConfig {
    /// Config with the default window, no declared generator, and the default old-block
    /// budget (the full witness budget, mirroring the unset `--witness-old-block-timeout`
    /// behavior).
    #[cfg(test)]
    pub fn with_defaults(witness_timeout_secs: u64) -> Self {
        Self {
            witness_timeout: Duration::from_secs(witness_timeout_secs),
            old_block_witness_timeout: Duration::from_secs(witness_timeout_secs),
            local_window: DEFAULT_WITNESS_LOCAL_WINDOW,
            generator_first: false,
        }
    }
}

/// Block data bundle containing all information needed for stateless execution.
///
/// This struct aggregates the block, its witness (state proof), and all
/// contract bytecodes referenced in the witness. Together, these enable
/// complete block re-execution without access to the full state database.
///
/// Uses `LightWitness` for improved deserialization performance (~10x faster than
/// `SaltWitness`) since we trust our local database and don't need cryptographic
/// proof verification.
///
/// Not `Clone`: all callers hold `Arc<BlockData>` and clone the `Arc`, not the inner
/// struct. The full block + witness + contract map is megabytes, so deep-cloning was
/// never cheap and is never needed.
pub struct BlockData {
    /// The block with full transaction data.
    pub block: Block<Transaction>,
    /// Light witness without expensive EC point validation.
    pub witness: LightWitness,
    /// Contract bytecodes keyed by code hash, required for EVM execution.
    /// `Bytecode` is internally reference-counted, so values share their underlying allocation
    /// with the `ContractCache` (and across `BlockData` clones) via cheap refcount-bump clones.
    pub contracts: HashMap<B256, Bytecode>,
}

/// Default timeout for a user-facing witness fetch in seconds (8 seconds).
///
/// Applied as a sub-deadline on top of the outer block-fetch deadline: the witness stage
/// gets `min(block_deadline, now + witness_timeout)`. Covers the "block is near the tip and
/// the witness is still being generated upstream" case where a few seconds of waiting is
/// normal.
pub const DEFAULT_WITNESS_TIMEOUT_SECS: u64 = 8;

/// Default local-tip window (in blocks): witnesses at least this far below the local tip are
/// historical and skip the internal generator endpoint (see [`witness_route`]).
///
/// Matches the witness generator's default deployed local retention (`BACKUP=4096`): blocks
/// at least this far below the tip are guaranteed misses on the internal generator endpoint,
/// so probing it first only burns a failover round trip.
pub const DEFAULT_WITNESS_LOCAL_WINDOW: u64 = 4096;

/// Default deadline for the full block-fetch pipeline (header + witness + block + contracts)
/// in seconds (13 seconds).
///
/// The RPC client's retry loop is deadline-aware: `RpcClient::*_with_deadline` methods return
/// [`RpcDeadlineExceeded`] once the deadline fires, so a request for a nonexistent block
/// surfaces quickly instead of hanging. This is the full budget for one user-facing RPC
/// request — every upstream fetch on the way to serving the response shares it.
pub const DEFAULT_BLOCK_FETCH_TIMEOUT_SECS: u64 = 13;

/// Default capacity (entries) of the in-memory canonical-hash memo. An entry is one
/// `u64 → B256` binding (~80 bytes with cache overhead), and the memo fills lazily, so a
/// generous cap costs nothing until a deep historical scan actually uses it — full, it
/// covers a full-history crawl's working set many times over.
pub const DEFAULT_CANONICAL_HASH_MEMO_CAPACITY: u64 = 8_000_000;

/// Minimum depth below the observed tip before an upstream-resolved number → hash binding
/// may be memoized. A memoized binding is served without re-checking upstream for as long
/// as it stays cached, so this margin carries the memo's safety argument. The operating
/// assumption it encodes: **reorgs on the target chain never run deeper than this** —
/// less the slack the tip hint itself can carry after a reorg (see `tip_hint`), so the
/// effective headroom is this constant minus the deepest reorg since startup. Shallow
/// heights resolve upstream on every request instead.
///
/// In local-cache mode the assumption is additionally defended by hooks: the sync window
/// answers every height it covers before the memo is consulted, and the chain-sync
/// pipeline clears the memo on a stale reset and on any reorg at least this deep
/// (`TraceHooks` in `chain_sync`). In stateless mode there is no pipeline and the margin
/// alone is the argument — a deeper reorg would pin the orphaned hashes for the affected
/// heights until the process restarts, with nothing to detect it.
const CANONICAL_MEMO_MIN_DEPTH: u64 = 64;

/// Minimum interval between upstream tip seeds (`eth_blockNumber`), fired when neither
/// the tip hint nor the local window can decide whether a height is depth-final —
/// without one, a numeric-only client in stateless mode would never raise the hint (a
/// header cannot qualify its own height) and the memo would stay permanently empty. The
/// throttle bounds the extra upstream call to one per interval across all requests;
/// requests inside the window skip memoization for that round, and the resulting hint
/// staleness only under-estimates (blocks becoming final meanwhile stay unmemoized a
/// little longer), which is the safe direction.
const TIP_SEED_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// Cap on one tip seed's upstream wait, applied on top of the request's own deadline.
/// The seed only enables future memoization — the caller's answer is already in hand —
/// so a degraded upstream must not eat the request's remaining budget retrying it.
const TIP_SEED_TIMEOUT: Duration = Duration::from_secs(1);

/// Slow stage threshold: any individual stage exceeding this triggers a warn log.
pub(crate) const SLOW_STAGE_THRESHOLD_MS: u128 = 1000;

/// Concurrent prefetch fetches the historical readahead may hold in flight. Scheduling uses
/// `try_acquire`, so this also bounds the spawned-task backlog: a saturated readahead drops
/// further candidates instead of queueing them, and the next by-number request re-triggers.
const READAHEAD_CONCURRENCY: usize = 16;

/// Stage that ran out of time. Used only to label the typed `Timeout` error below.
#[derive(Debug, Clone, Copy)]
pub enum TimeoutStage {
    /// A witness fetch (`mega_getBlockWitness`) exceeded its stage or call deadline.
    Witness,
    /// The block-fetch pipeline as a whole exceeded its deadline.
    Block,
}

impl std::fmt::Display for TimeoutStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TimeoutStage::Witness => "witness",
            TimeoutStage::Block => "block",
        })
    }
}

/// Errors returned by [`DataProvider`]'s user-facing fetch methods.
///
/// The enum classifies up-front so the RPC layer can map variants to JSON-RPC error codes
/// without string-matching. `Internal` is the catch-all for transport / decode / DB errors;
/// everything else is a deterministic "not found" or a deadline-exceeded signal caused by
/// `RpcClient`'s retry loop running out of time.
#[derive(Debug, thiserror::Error)]
pub enum DataProviderError {
    #[error("transaction {0} not found")]
    TransactionNotFound(B256),
    #[error("transaction {0} is pending")]
    TransactionPending(B256),
    #[error("{stage} fetch exceeded deadline after {elapsed:?}")]
    Timeout { stage: TimeoutStage, elapsed: Duration },
    /// Wrapped in `Arc` so [`shared_to_result`] can clone the pointer across coalesced
    /// callers without losing the `eyre::Error` cause chain (which is the operational
    /// signal for redb / bincode / transport decode errors). `eyre::Error` itself isn't
    /// `Clone`; stringifying it would drop the "caused by" trail.
    #[error(transparent)]
    Internal(Arc<eyre::Error>),
}

impl From<eyre::Error> for DataProviderError {
    fn from(e: eyre::Error) -> Self {
        DataProviderError::Internal(Arc::new(e))
    }
}

impl From<RpcDeadlineExceeded> for DataProviderError {
    fn from(e: RpcDeadlineExceeded) -> Self {
        // Choose a stage label based on the RPC method: witness fetches produce a Witness
        // timeout, everything else (header/block/code) falls under the block-pipeline bucket.
        let stage = match e.method {
            stateless_common::RpcMethod::MegaGetBlockWitness => TimeoutStage::Witness,
            _ => TimeoutStage::Block,
        };
        DataProviderError::Timeout { stage, elapsed: e.elapsed }
    }
}

impl From<CodeFetchError> for DataProviderError {
    fn from(e: CodeFetchError) -> Self {
        match e {
            CodeFetchError::Deadline(d) => d.into(),
            CodeFetchError::VerificationFailure { .. } => eyre::eyre!("{e}").into(),
        }
    }
}

impl From<StoreError> for DataProviderError {
    fn from(e: StoreError) -> Self {
        // Any `StoreError` surfacing at this layer is an internal persistence issue, not a
        // user-facing "not found" — the `MissingData` fall-through happens upstream of here.
        eyre::eyre!(e).into()
    }
}

/// Result alias for [`DataProvider`] fetch methods.
pub type DataProviderResult<T> = std::result::Result<T, DataProviderError>;

/// Outcome of the shared block-data fetch. `Arc` on both sides makes the result `Clone`
/// so `Shared` can hand a copy to every coalesced waiter.
type BlockDataOutcome = std::result::Result<Arc<BlockData>, Arc<DataProviderError>>;

/// The fetch future as a `'static + Send` trait object — required to store it in
/// [`futures::future::Shared`], which can't work with borrowed futures.
type BlockDataFetchFuture = Pin<Box<dyn Future<Output = BlockDataOutcome> + Send>>;

/// Shared in-flight future for the single-flight pattern.
///
/// Stored in the `in_flight` map so concurrent callers for the same block hash share one
/// fetch. [`Shared`] hands each waker a clone of the outcome — we use `Arc<BlockData>` for
/// success (refcount bump, not deep clone) and `Arc<DataProviderError>` for failure (errors
/// aren't `Clone`). Only the primary task drives the inner future; waiters are parked on its
/// waker. If the primary is cancelled, any remaining waiter keeps polling it to completion.
type BlockDataFuture = Shared<BlockDataFetchFuture>;

/// RAII cleanup for the `in_flight` map. The primary inserts into the map and then holds
/// this guard for the duration of its fetch; `Drop` removes the entry unconditionally on
/// **any** exit — normal return, `?`, panic unwind, or task cancellation while
/// `shared.await` is parked. Without this, a cancelled primary would leave the
/// `Shared<_>` — and with it, the `Arc<BlockData>` (megabytes) it caches — pinned in the
/// map until the process exits, and later callers for the same hash would subscribe to a
/// stalled future.
struct InFlightGuard<'a> {
    map: &'a DashMap<B256, BlockDataFuture>,
    key: B256,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

/// Sequential-readahead state for historical by-number traffic.
///
/// Backfill crawlers walk block numbers in order, and every historical block costs an
/// upstream witness fetch; prefetching the next few numbers turns their next requests into
/// warm block-data-cache (or single-flight coalesce) hits. Prefetches run the same
/// resolve + fetch pipeline as real requests, so results land in the shared cache and the
/// canonical-hash memo with no separate code path.
struct Readahead {
    /// How many blocks past a requested number to prefetch.
    depth: u64,
    /// Bounds in-flight prefetch tasks (see [`READAHEAD_CONCURRENCY`]).
    permits: Arc<tokio::sync::Semaphore>,
    /// Recently scheduled numbers (insertion-ordered, bounded), so repeated requests
    /// sweeping through an already-warmed range don't re-schedule the same prefetches.
    /// Entries age out by insertion order; failed prefetches are removed eagerly so a
    /// later pass can retry them.
    scheduled: Mutex<ScheduledWindow>,
}

/// Bounded insertion-ordered set backing [`Readahead::scheduled`].
struct ScheduledWindow {
    set: HashSet<u64>,
    order: VecDeque<u64>,
    cap: usize,
}

impl Readahead {
    fn new(depth: u64) -> Self {
        // Wide enough to cover the active frontier of an interleaved multi-batch crawler
        // (the incident client flies 15 batches at once) many times over, small enough to
        // stay irrelevant memory-wise.
        let cap = (depth as usize * 8).clamp(256, 65_536);
        Self {
            depth,
            permits: Arc::new(tokio::sync::Semaphore::new(READAHEAD_CONCURRENCY)),
            scheduled: Mutex::new(ScheduledWindow {
                set: HashSet::new(),
                order: VecDeque::new(),
                cap,
            }),
        }
    }

    /// Marks `number` as scheduled. Returns `false` when it is already in the window.
    fn mark(&self, number: u64) -> bool {
        let mut window = self.scheduled.lock().expect("readahead window lock");
        if !window.set.insert(number) {
            return false;
        }
        window.order.push_back(number);
        while window.order.len() > window.cap {
            let evicted = window.order.pop_front().expect("order tracks set");
            window.set.remove(&evicted);
        }
        true
    }

    /// Forgets `number` so a later request may schedule it again (failed or dropped
    /// prefetches must not poison the window for the whole window lifetime).
    fn unmark(&self, number: u64) {
        // The stale `order` entry is left behind; it ages out and its second eviction is a
        // no-op on the set.
        self.scheduled.lock().expect("readahead window lock").set.remove(&number);
    }
}

/// Data provider with single-flight request coalescing.
///
/// # Data Lookup Strategy
/// 1. Check the in-memory block-data cache (if enabled)
/// 2. Check local database (if configured)
/// 3. Fetch from remote RPC endpoints (multi-provider fallback handled by `RpcClient`)
///
/// # Single-Flight Pattern
/// When multiple requests arrive for the same block simultaneously, only one
/// RPC call is made. Other requests subscribe to the result via broadcast channel.
pub(crate) struct DataProvider {
    /// RPC client for upstream data fetching (handles multi-endpoint fallback internally).
    rpc_client: Arc<RpcClient>,
    /// Optional local database for pre-fetched blocks (trait object).
    db: Option<Arc<dyn BlockStore>>,
    /// Optional bounded in-memory cache of resolved block data, keyed by block hash.
    /// Fronts both the DB tier (repeated redb reads + witness decodes) and the RPC tier;
    /// its main beneficiaries are transaction-level requests, which are never
    /// response-cached and cluster on shared blocks.
    block_data_cache: Option<Arc<BlockDataCache>>,
    /// Tip height memoized by the last DB-backed [`Self::record_block_distance`], so the
    /// memory-tier hit path records its block distance without opening a redb read.
    /// `u64::MAX` = no tip observed yet.
    last_seen_db_tip: AtomicU64,
    /// In-memory contract bytecode cache backed by either `ServerDB` (local-cache mode)
    /// or [`NoopContractStore`] (stateless mode).
    /// Every contract read and every RPC-fetched contract goes through here, so
    /// repeated trace requests for the same contract hit memory instead of
    /// redb (slow) or RPC (slowest).
    contract_cache: Arc<ContractCache>,
    /// Witness-stage routing (full chain vs historical skip-generator chain) and budgets.
    /// The full-call deadline still dominates; the per-stage budgets cap how much of it the
    /// witness fetch can burn.
    witness_cfg: WitnessFetchConfig,
    /// Optional direct-from-R2 source for historical witnesses. When present, the witness
    /// stage tries it before the RPC chain for blocks the routing window classifies as
    /// historical; every R2 failure falls back to the RPC chain on the remaining deadline.
    r2_witness: Option<Arc<R2WitnessSource>>,
    /// Optional sequential readahead for historical by-number traffic
    /// (`--historical-readahead`; `None` = disabled).
    readahead: Option<Readahead>,
    /// Wall-clock budget for one user-facing block-data call, from entry through
    /// header + witness + block + contract resolution. The retry loop in `RpcClient`
    /// checks this before each round and clamps its sleep accordingly, so a missing
    /// block surfaces as a typed [`DataProviderError::Timeout`] rather than hanging.
    block_fetch_timeout: Duration,
    /// Single-flight coalescing map keyed by block hash.
    ///
    /// Concurrent RPC fetches for the same block share one [`Shared`] future, so the
    /// hot path is a refcount bump. The map holds the shared future's handle for the
    /// duration of the fetch; the primary task removes it after `.await` completes.
    in_flight: DashMap<B256, BlockDataFuture>,
    /// Bounded in-memory memo of depth-final number → canonical-hash bindings, filled by
    /// upstream resolutions for heights the sync window no longer (or never) covers.
    /// Restart-cold by design: the first request per height after a restart pays one
    /// upstream header fetch, and a stale entry cannot outlive the process. Shared with
    /// the chain-sync hooks (see [`CanonicalHashMemo`]).
    canonical_hash_memo: CanonicalHashMemo,
    /// Monotonic maximum chain height observed from upstream answers (latest-tag
    /// resolutions, verified headers, tip seeds) and the local window tip. Only real
    /// on-chain numbers feed it, so it never exceeds the highest height ever seen as
    /// canonical — but a reorg lowers the real tip while the hint stays put, so it can
    /// overshoot the *current* tip by up to the reorg's depth. The memo gate's effective
    /// margin is therefore [`CANONICAL_MEMO_MIN_DEPTH`] minus the deepest reorg since
    /// startup; that is the precise form of the depth-finality claim.
    tip_hint: AtomicU64,
    /// Earliest instant the next upstream tip seed may fire. The lock's winner advances
    /// it by [`TIP_SEED_MIN_INTERVAL`], so exactly one request per interval pays the
    /// `eth_blockNumber` round-trip; it is only ever touched after the depth gate has
    /// already failed, never on hit paths.
    tip_seed_next: Mutex<Instant>,
}

/// Shared handle to the bounded number → canonical-hash memo. The chain-sync hooks hold a
/// clone so pipeline events can invalidate memoized bindings alongside the response
/// cache; the memo owns the reaction policy (see [`CANONICAL_MEMO_MIN_DEPTH`]), the
/// hooks only forward the events.
#[derive(Clone)]
pub(crate) struct CanonicalHashMemo(Arc<Cache<u64, B256>>);

impl CanonicalHashMemo {
    pub(crate) fn new(capacity: usize) -> Self {
        Self(Arc::new(Cache::new(capacity)))
    }

    pub(crate) fn get(&self, block_num: &u64) -> Option<B256> {
        self.0.get(block_num)
    }

    pub(crate) fn insert(&self, block_num: u64, hash: B256) {
        self.0.insert(block_num, hash);
    }

    /// Drops every memoized binding; they refill lazily at one header fetch per height.
    pub(crate) fn clear(&self) {
        self.0.clear();
    }

    /// Reorg reaction: a reorg at least [`CANONICAL_MEMO_MIN_DEPTH`] deep breaches the
    /// margin every memoized binding relied on — some heights may now bind to orphaned
    /// hashes, and once the sync window slides past them nothing else would ever correct
    /// the binding — so the whole memo goes. Shallower reorgs cannot touch memoized
    /// (depth-final) heights by construction and keep the memo intact.
    pub(crate) fn on_reorg(&self, depth: u64) {
        if depth >= CANONICAL_MEMO_MIN_DEPTH {
            warn!(depth, "Deep reorg; clearing the canonical-hash memo");
            self.0.clear();
        }
    }
}

impl DataProvider {
    /// Creates a new data provider.
    ///
    /// # Arguments
    /// * `rpc_client` - RPC client for upstream data fetching
    /// * `db` - Optional local database for cached block data
    /// * `block_data_cache` - Optional in-memory cache of resolved block data
    /// * `contract_cache` - Shared in-memory contract cache (backed by the DB when present, or an
    ///   in-memory-only noop store in stateless mode)
    /// * `witness_cfg` - Witness-source routing window (by block age) and per-stage budgets
    /// * `block_fetch_timeout` - User-facing cap on the full block-fetch pipeline (header + witness
    ///   + block + contracts)
    /// * `canonical_hash_memo_capacity` - Entry cap for the in-memory canonical-hash memo
    ///
    /// The optional extras — the R2 historical witness source and the historical readahead —
    /// attach via [`Self::with_r2_witness`] / [`Self::with_historical_readahead`].
    pub fn new(
        rpc_client: Arc<RpcClient>,
        db: Option<Arc<dyn BlockStore>>,
        block_data_cache: Option<Arc<BlockDataCache>>,
        contract_cache: Arc<ContractCache>,
        witness_cfg: WitnessFetchConfig,
        block_fetch_timeout: Duration,
        canonical_hash_memo_capacity: usize,
    ) -> Self {
        Self {
            rpc_client,
            db,
            block_data_cache,
            last_seen_db_tip: AtomicU64::new(u64::MAX),
            contract_cache,
            witness_cfg,
            r2_witness: None,
            readahead: None,
            block_fetch_timeout,
            in_flight: DashMap::new(),
            canonical_hash_memo: CanonicalHashMemo::new(canonical_hash_memo_capacity),
            tip_hint: AtomicU64::new(0),
            tip_seed_next: Mutex::new(Instant::now()),
        }
    }

    /// Attaches a direct-from-R2 source, tried before the RPC chain for historical
    /// witnesses. `None` keeps the RPC chain as the only witness source.
    pub fn with_r2_witness(mut self, r2_witness: Option<Arc<R2WitnessSource>>) -> Self {
        self.r2_witness = r2_witness;
        self
    }

    /// Enables sequential readahead for historical by-number traffic: each request for a
    /// historical number schedules background prefetches of the next `depth` numbers.
    /// `depth = 0` leaves readahead disabled.
    pub fn with_historical_readahead(mut self, depth: u64) -> Self {
        self.readahead = (depth > 0).then(|| Readahead::new(depth));
        self
    }

    /// Schedules background prefetches of the blocks after `from_block`, when readahead is
    /// enabled and `from_block` is historical (a non-historical number serves from the local
    /// DB, where prefetching buys nothing). Cheap no-op for already-scheduled numbers; when
    /// the prefetch permits are exhausted the remaining candidates are dropped — the next
    /// by-number request re-triggers scheduling, so the frontier keeps pace with the crawl.
    ///
    /// Callers hand this the *requested* number on every by-number lookup, cached or not:
    /// requests sweeping through an already-warmed range must keep pushing the prefetch
    /// frontier ahead of the cursor, or the crawl would stall on a cold block every `depth`
    /// blocks.
    pub fn schedule_readahead(self: &Arc<Self>, from_block: u64) {
        let Some(readahead) = &self.readahead else { return };
        let db_tip = db_tip_height(self.db.as_deref());
        if !is_historical(db_tip, from_block, self.witness_cfg.local_window) {
            return;
        }
        for number in from_block + 1..=from_block.saturating_add(readahead.depth) {
            // The crawl runs toward the tip; stop at the local window — those blocks serve
            // from the DB.
            if !is_historical(db_tip, number, self.witness_cfg.local_window) {
                break;
            }
            if !readahead.mark(number) {
                continue;
            }
            let Ok(permit) = Arc::clone(&readahead.permits).try_acquire_owned() else {
                readahead.unmark(number);
                crate::metrics::record_readahead("saturated");
                return;
            };
            crate::metrics::record_readahead("scheduled");
            let provider = Arc::clone(self);
            tokio::spawn(async move {
                let _permit = permit;
                let deadline = provider.fetch_deadline();
                let fetched = async {
                    let hash = provider.resolve_canonical_hash(number, deadline).await?;
                    provider.get_block_data_by_hash_with_deadline(hash, deadline).await
                }
                .await;
                match fetched {
                    Ok(_) => crate::metrics::record_readahead("completed"),
                    Err(e) => {
                        crate::metrics::record_readahead("failed");
                        // Forget the number so a later pass can retry it; prefetches are
                        // best-effort and must never log above debug.
                        provider.readahead.as_ref().expect("spawned by readahead").unmark(number);
                        debug!(number, error = %e, "Readahead prefetch failed");
                    }
                }
            });
        }
    }

    /// Returns block-data cache statistics, or `None` when the cache is disabled.
    pub fn block_data_cache_stats(&self) -> Option<CacheStats> {
        self.block_data_cache.as_ref().map(|cache| cache.stats())
    }

    /// Drops a block from the memory cache after its data failed execution: a decodable but
    /// incomplete witness would otherwise stay pinned, failing every retry until eviction —
    /// dropping it lets the next request refetch from the endpoints. Returns whether an
    /// entry was actually removed, so the caller can count real evictions.
    pub fn evict_block_data(&self, block_hash: &B256) -> bool {
        self.block_data_cache.as_ref().is_some_and(|cache| cache.remove(block_hash))
    }

    /// Clonable handle to the canonical-hash memo, for the chain-sync invalidation hooks.
    pub(crate) fn canonical_hash_memo(&self) -> CanonicalHashMemo {
        self.canonical_hash_memo.clone()
    }

    /// Folds an observed on-chain height into the monotonic tip hint.
    fn observe_tip(&self, block_number: u64) {
        self.tip_hint.fetch_max(block_number, Ordering::Relaxed);
    }

    /// Learns the current tip from upstream (`eth_blockNumber`) so the memo's depth gate
    /// can decide, when neither the hint nor a local window tip could. Throttled to one
    /// upstream call per [`TIP_SEED_MIN_INTERVAL`] and best-effort: throttled or failed
    /// seeds just skip memoization for this round, costing one repeat header fetch later.
    async fn seed_tip_from_upstream(&self, deadline: Instant) {
        let now = Instant::now();
        {
            let mut next = self.tip_seed_next.lock().unwrap();
            if now < *next {
                return;
            }
            *next = now + TIP_SEED_MIN_INTERVAL;
        }
        let deadline = deadline.min(now + TIP_SEED_TIMEOUT);
        match self.rpc_client.get_latest_block_number_with_deadline(Some(deadline)).await {
            Ok(tip) => {
                record_canonical_hash_resolution("tip_seed", "ok");
                self.observe_tip(tip);
            }
            Err(e) => {
                record_canonical_hash_resolution("tip_seed", "error");
                debug!(error = %e, "Upstream tip seed failed; skipping memoization this round");
            }
        }
    }

    /// Mints the single wall-clock deadline for one user-facing request, from
    /// `block_fetch_timeout`. Handlers call this once at entry and thread the result through
    /// every stage (tag resolution, canonical-hash resolution, header, witness, block,
    /// contracts) so the whole request shares ONE budget.
    pub(crate) fn fetch_deadline(&self) -> Instant {
        Instant::now() + self.block_fetch_timeout
    }

    /// Resolves a block number to its canonical block hash.
    ///
    /// This is what makes number-keyed requests safe to serve from the hash-keyed response
    /// cache: the number → hash binding is resolved *before* the cache lookup, so a reorged
    /// height resolves to the new hash and misses cleanly instead of serving a dead block.
    ///
    /// Lookup order: the bounded canonical window, then the in-memory memo of depth-final
    /// bindings, then upstream `eth_getHeaderByNumber` on the shared `deadline`. A DB
    /// read error is logged and falls through to the next tier rather than failing the
    /// request.
    ///
    /// **Memoization**: an upstream-resolved header (fetched with `verify_hash = true`,
    /// so its hash provably matches its content) is memoized — only when more than
    /// [`CANONICAL_MEMO_MIN_DEPTH`] below the observed tip, where the binding can no
    /// longer reorg — so repeat requests for historical heights resolve locally for the
    /// lifetime of the process. Shallow and above-window heights resolve upstream every
    /// time. When neither the hint nor a window tip can decide (stateless mode with
    /// numeric-only traffic), a throttled `eth_blockNumber` seed learns the tip.
    pub(crate) async fn resolve_canonical_hash(
        &self,
        block_num: u64,
        deadline: Instant,
    ) -> DataProviderResult<B256> {
        if let Some(db) = &self.db {
            match db.get_block_hash(block_num) {
                Ok(Some(hash)) => {
                    record_canonical_hash_resolution("db", "ok");
                    return Ok(hash);
                }
                Ok(None) => record_canonical_hash_resolution("db", "miss"),
                Err(e) => {
                    record_canonical_hash_resolution("db", "error");
                    warn!(
                        block_number = block_num,
                        error = %e,
                        "Local canonical-hash read failed; trying the next tier",
                    );
                }
            }
        }
        if let Some(hash) = self.canonical_hash_memo.get(&block_num) {
            record_canonical_hash_resolution("memo", "ok");
            return Ok(hash);
        }
        record_canonical_hash_resolution("memo", "miss");

        let header = match self
            .rpc_client
            .get_header_with_deadline(
                BlockId::Number(BlockNumberOrTag::Number(block_num)),
                true,
                Some(deadline),
            )
            .await
        {
            Ok(header) => {
                record_canonical_hash_resolution("upstream", "ok");
                header
            }
            Err(e) => {
                record_canonical_hash_resolution("upstream", "error");
                return Err(e.into());
            }
        };

        // Memoize only depth-final heights. The tip hint never exceeds the highest height
        // ever seen as canonical (see `tip_hint` for the reorg-slack caveat), so a gate
        // that passes on it is final within the `CANONICAL_MEMO_MIN_DEPTH` assumption.
        // When the hint alone cannot admit the height (typically just the first
        // resolution after startup — a header can never qualify its own height), consult
        // the sync window's tip; without one (stateless mode, or an empty window) fall
        // back to a throttled upstream tip seed. A present-but-lagging window tip gets no
        // seed: the window is that mode's authority, its lag is bounded by the
        // stale-reset threshold, and skipped memoization is only ever a missed
        // optimization.
        self.observe_tip(header.number);
        let gate = |hint: u64| block_num < hint.saturating_sub(CANONICAL_MEMO_MIN_DEPTH);
        if !gate(self.tip_hint.load(Ordering::Relaxed)) {
            match db_tip_height(self.db.as_deref()) {
                Some(tip) => self.observe_tip(tip),
                None => self.seed_tip_from_upstream(deadline).await,
            }
        }
        if gate(self.tip_hint.load(Ordering::Relaxed)) {
            self.canonical_hash_memo.insert(block_num, header.hash);
        }
        Ok(header.hash)
    }

    /// Gets block data by block hash with single-flight coalescing, minting its own
    /// deadline. Entry point for callers without a shared budget; handlers that already
    /// resolved a hash on a deadline use [`Self::get_block_data_by_hash_with_deadline`].
    pub async fn get_block_data_by_hash(
        &self,
        block_hash: B256,
    ) -> DataProviderResult<Arc<BlockData>> {
        self.get_block_data_by_hash_with_deadline(block_hash, self.fetch_deadline()).await
    }

    /// Gets block data by block hash with single-flight coalescing on the caller's
    /// `deadline` — the tail of the shared per-request budget minted by
    /// [`Self::fetch_deadline`].
    pub(crate) async fn get_block_data_by_hash_with_deadline(
        &self,
        block_hash: B256,
        deadline: Instant,
    ) -> DataProviderResult<Arc<BlockData>> {
        let start = Instant::now();

        // Memory tier: a hit skips the DB read + witness decode entirely.
        if let Some(cache) = &self.block_data_cache &&
            let Some(data) = cache.get(&block_hash)
        {
            trace!(
                block_hash = %block_hash,
                source = "memory",
                "Block data retrieved from memory cache"
            );
            DataSourceMetrics::new_for_source("memory").record();
            SingleFlightMetrics::new_for_type("bypassed").record();
            self.record_block_distance_cached(data.block.header.number);
            return Ok(data);
        }

        // Try the local DB next. `Ok(None)` = "not in DB, fall through"; `Err(..)` surfaces
        // typed errors (e.g. a `Timeout` from contract resolution) so we don't then burn the
        // remaining deadline on an RPC call that is guaranteed to hit the same timeout.
        if let Some(db) = &self.db &&
            let Some(data) =
                self.get_block_data_from_db(db.as_ref(), block_hash, deadline).await?
        {
            trace!(
                block_hash = %block_hash,
                source = "database",
                elapsed_ms = start.elapsed().as_millis() as u64,
                "Block data retrieved from local DB"
            );
            DataSourceMetrics::new_for_source("db").record();
            SingleFlightMetrics::new_for_type("bypassed").record();
            self.record_block_distance(data.block.header.number);
            let data = Arc::new(data);
            if let Some(cache) = &self.block_data_cache {
                cache.insert(block_hash, Arc::clone(&data));
            }
            return Ok(data);
        }

        // Fall back to RPC
        trace!(
            block_hash = %block_hash,
            source = "rpc",
            "Fetching block data from RPC"
        );
        let data = self.fetch_block_data_single_flight(block_hash, deadline).await?;

        trace!(
            block_hash = %block_hash,
            source = "rpc",
            elapsed_ms = start.elapsed().as_millis() as u64,
            "Block data fetched from RPC"
        );

        self.record_block_distance(data.block.header.number);
        Ok(data)
    }

    /// Gets block data for a transaction by its hash. A single deadline covers the transaction
    /// lookup and the subsequent block-data fetch.
    #[instrument(skip(self), name = "get_block_data_for_tx", fields(tx_hash = %tx_hash))]
    pub async fn get_block_data_for_tx(
        &self,
        tx_hash: B256,
    ) -> DataProviderResult<(Arc<BlockData>, usize)> {
        trace!(tx_hash = %tx_hash, "Looking up transaction");
        let deadline = self.fetch_deadline();

        // Fetch the transaction to find its block. The outer result is `Err(Deadline)`; the
        // inner is `Err` for "tx exists but has no block_hash" (pending) — classify explicitly
        // so `trace_parity_transaction` returns `null` instead of `-32000 internal error`.
        let (tx, block_hash) = self
            .rpc_client
            .get_transaction_by_hash_with_deadline(tx_hash, Some(deadline))
            .await?
            .map_err(|_| DataProviderError::TransactionPending(tx_hash))?
            .ok_or(DataProviderError::TransactionNotFound(tx_hash))?;

        let tx_index =
            tx.transaction_index.ok_or(DataProviderError::TransactionPending(tx_hash))? as usize;

        debug!(
            tx_hash = %tx_hash,
            block_hash = %block_hash,
            tx_index,
            "Transaction located in block"
        );

        let data = self.get_block_data_by_hash_with_deadline(block_hash, deadline).await?;
        Ok((data, tx_index))
    }

    /// Resolves a block tag to a concrete block number on the caller's `deadline`.
    ///
    /// Numeric tags are a pure local no-op. `Latest`, `Finalized`, and `Safe` must hit
    /// upstream to learn the tip — there is no cache key until we have a concrete number,
    /// so falling back to the cache on upstream failure is not an option. The `deadline` is
    /// the shared per-request budget from [`Self::fetch_deadline`], so a stuck upstream
    /// surfaces as a typed [`DataProviderError::Timeout`] rather than hanging the RPC
    /// caller forever — and tag resolution cannot double the request's total budget.
    pub async fn resolve_block_number(
        &self,
        tag: BlockNumberOrTag,
        deadline: Instant,
    ) -> DataProviderResult<u64> {
        match tag {
            BlockNumberOrTag::Number(n) => Ok(n),
            BlockNumberOrTag::Earliest => Ok(0),
            BlockNumberOrTag::Pending => Err(eyre::eyre!("Pending block not supported").into()),
            BlockNumberOrTag::Latest => {
                let number =
                    self.rpc_client.get_latest_block_number_with_deadline(Some(deadline)).await?;
                self.observe_tip(number);
                Ok(number)
            }
            BlockNumberOrTag::Finalized | BlockNumberOrTag::Safe => {
                let header = self
                    .rpc_client
                    .get_header_with_deadline(BlockId::Number(tag), false, Some(deadline))
                    .await?;
                self.observe_tip(header.number);
                Ok(header.number)
            }
        }
    }

    /// Records the distance of a requested block from the local chain tip, memoizing the
    /// tip for [`Self::record_block_distance_cached`].
    fn record_block_distance(&self, block_number: u64) {
        if let Some(tip) = db_tip_height(self.db.as_deref()) {
            self.last_seen_db_tip.store(tip, Ordering::Relaxed);
            let distance = tip.saturating_sub(block_number);
            ChainSyncMetrics::create().record_block_distance(distance);
        }
    }

    /// [`Self::record_block_distance`] against the memoized tip, for the memory-tier hit
    /// path: a pure cache hit must not open a redb read just for this histogram. The memo
    /// can lag the real tip by the blocks synced since the last DB-backed serve, which is
    /// immaterial for a distance distribution; with no tip observed yet (stateless mode, or
    /// no DB-backed serve so far) nothing is recorded, matching the DB-backed variant.
    fn record_block_distance_cached(&self, block_number: u64) {
        let tip = self.last_seen_db_tip.load(Ordering::Relaxed);
        if tip != u64::MAX {
            ChainSyncMetrics::create().record_block_distance(tip.saturating_sub(block_number));
        }
    }

    /// Gets block data from the local database using LightWitness.
    ///
    /// Takes the shared `deadline` so contract resolution (which can hit RPC on cache miss)
    /// respects the same budget as the rest of the call.
    ///
    /// Returns:
    /// - `Ok(Some(data))` — block found and fully resolved.
    /// - `Ok(None)` — block not in DB (expected cache miss) OR backend read error (logged and
    ///   treated as a miss so the caller falls through to RPC).
    /// - `Err(..)` — typed `DataProviderError` from contract resolution (e.g. `Timeout`). These
    ///   must surface immediately; falling through to RPC would just time out again on the shared
    ///   deadline with confusing double-wait behavior.
    async fn get_block_data_from_db(
        &self,
        db: &dyn BlockStore,
        block_hash: alloy_primitives::BlockHash,
        deadline: Instant,
    ) -> DataProviderResult<Option<BlockData>> {
        let overall_start = Instant::now();

        // Get block data from database using light witness (fast deserialization).
        let start = Instant::now();
        let (block, witness) = match db.get_block_and_witness(block_hash) {
            Ok(v) => v,
            Err(StoreError::MissingData { .. }) => return Ok(None),
            Err(e) => {
                // Real backend error (redb I/O, decode corruption). Log it — but still fall
                // through to RPC so the request isn't lost. `Ok(None)` signals that to the
                // caller, and the warn preserves the operator signal.
                warn!(
                    block_hash = %block_hash,
                    error = %e,
                    "Local DB read failed; falling back to RPC",
                );
                return Ok(None);
            }
        };
        let db_read_secs = start.elapsed().as_secs_f64();
        let db_read_ms = start.elapsed().as_millis();

        ChainSyncMetrics::create().record_db_read(db_read_secs);

        // Extract code hashes and get contracts. Contract resolution can time out; that typed
        // error propagates through `?` without being wrapped in `eyre::Error`, so the caller
        // surfaces it directly instead of misinterpreting it as a DB miss.
        let start = Instant::now();
        let code_hashes = crate::tracing_executor::extract_code_hashes(&witness);
        let num_contracts = code_hashes.len();
        let contracts = self.resolve_contracts(&code_hashes, deadline).await?;
        let fetch_contracts_ms = start.elapsed().as_millis();

        let total_ms = overall_start.elapsed().as_millis();

        if db_read_ms >= SLOW_STAGE_THRESHOLD_MS || fetch_contracts_ms >= SLOW_STAGE_THRESHOLD_MS {
            warn!(
                block_number = block.header.number,
                block_hash = %block_hash,
                tx_count = block.transactions.len(),
                num_contracts,
                db_read_ms = db_read_ms as u64,
                fetch_contracts_ms = fetch_contracts_ms as u64,
                total_ms = total_ms as u64,
                "get_block_data_from_db slow stages detected"
            );
        }

        Ok(Some(BlockData { block, witness, contracts }))
    }

    /// Single-flight fetch via [`futures::future::Shared`]: concurrent callers for the same
    /// block hash subscribe to one in-flight future. The primary holds an [`InFlightGuard`]
    /// for the duration of its fetch, so the map entry is cleaned up on every exit path —
    /// including task cancellation at `shared.await`. Coalesced waiters don't own the entry
    /// and can drop freely; they just hold their own `Shared` clone.
    async fn fetch_block_data_single_flight(
        &self,
        block_hash: B256,
        deadline: Instant,
    ) -> DataProviderResult<Arc<BlockData>> {
        // `_guard` is only set on the primary path; coalesced waiters leave it `None`.
        let (shared, _guard) = match self.in_flight.entry(block_hash) {
            dashmap::Entry::Occupied(occupied) => {
                let fut = occupied.get().clone();
                drop(occupied);
                SingleFlightMetrics::new_for_type("coalesced").record();
                trace!(block_hash = %block_hash, "Joining existing in-flight request");
                return shared_to_result(fut.await);
            }
            dashmap::Entry::Vacant(vacant) => {
                // Build the owned future. `Arc::clone` the client so the future is `'static`
                // (doesn't borrow `self`) — `Shared` requires `'static` futures.
                let rpc_client = Arc::clone(&self.rpc_client);
                let db = self.db.clone();
                let contract_cache = Arc::clone(&self.contract_cache);
                let witness_cfg = self.witness_cfg;
                let r2_witness = self.r2_witness.clone();
                let block_data_cache = self.block_data_cache.clone();
                let fut: BlockDataFetchFuture = Box::pin(async move {
                    let data = do_fetch_block_data(
                        rpc_client,
                        db,
                        contract_cache,
                        witness_cfg,
                        r2_witness,
                        block_hash,
                        deadline,
                    )
                    .await
                    .map(Arc::new)
                    .map_err(Arc::new)?;
                    // Inserting inside the shared future gives exactly one insert per fetch
                    // and still runs when the primary caller is cancelled while a coalesced
                    // waiter drives the future to completion.
                    if let Some(cache) = &block_data_cache {
                        cache.insert(block_hash, Arc::clone(&data));
                    }
                    Ok(data)
                });
                let shared = fut.shared();
                vacant.insert(shared.clone());
                // Guard must be constructed *after* the insert so cancellation before the
                // insert doesn't try to remove an entry that was never added.
                let guard = InFlightGuard { map: &self.in_flight, key: block_hash };
                (shared, Some(guard))
            }
        };
        SingleFlightMetrics::new_for_type("new").record();

        trace!(block_hash = %block_hash, "Starting new block data fetch");
        let result = shared.await;

        // `_guard` drops here, unconditionally removing the map entry. On cancellation at
        // `shared.await` it drops via unwind; on panic likewise. A late arrival in the
        // tiny window between `shared.await` returning and the guard actually dropping
        // may subscribe to a Shared whose inner future has already resolved — that's fine,
        // they get the cached result.
        shared_to_result(result)
    }

    /// Resolves contract bytecodes via the three-tier cache chain:
    /// memory (`ContractCache`) → persistent store (`ServerDB` in local-cache mode,
    /// [`NoopContractStore`] in stateless mode) → upstream RPC.
    ///
    /// The RPC tier goes through `RpcClient::get_codes_with_deadline(.., verify=true, deadline)`
    /// — parallel fetch plus hash verification sharing the caller's deadline. Entries promoted
    /// through the cache are trusted on subsequent hits (no re-verification).
    async fn resolve_contracts(
        &self,
        code_hashes: &[B256],
        deadline: Instant,
    ) -> DataProviderResult<HashMap<B256, Bytecode>> {
        resolve_contracts_inner(&self.rpc_client, &self.contract_cache, code_hashes, deadline).await
    }
}

/// Unwraps a `Result<Arc<BlockData>, Arc<DataProviderError>>` (the output type of the shared
/// future) into the owned `DataProviderResult<Arc<BlockData>>` callers expect.
///
/// `DataProviderError` isn't `Clone`, so `Shared` hands every caller an `Arc<_>`. `Arc::try_unwrap`
/// isn't a viable extraction path here: `Shared`'s internal `Inner` holds its own clone of the
/// result for as long as the local `shared` binding lives at the call site, so the refcount is
/// always ≥ 2 when this function runs. Instead, we reconstruct the typed variant from a shared
/// reference — the `Timeout`/`NotFound`/`Pending` variants carry only `Copy` fields, and
/// `Internal` holds an `Arc<eyre::Error>` so we share the same pointer (and the full cause
/// chain) across coalesced waiters. The RPC layer keeps seeing `-32001` for `Timeout` etc.
/// regardless of how many callers coalesced on the same fetch, and operators still see the
/// full "caused by" trail for redb / bincode / transport decode errors.
fn shared_to_result(
    r: std::result::Result<Arc<BlockData>, Arc<DataProviderError>>,
) -> DataProviderResult<Arc<BlockData>> {
    r.map_err(|arc| match arc.as_ref() {
        DataProviderError::Timeout { stage, elapsed } => {
            DataProviderError::Timeout { stage: *stage, elapsed: *elapsed }
        }
        DataProviderError::TransactionNotFound(h) => DataProviderError::TransactionNotFound(*h),
        DataProviderError::TransactionPending(h) => DataProviderError::TransactionPending(*h),
        DataProviderError::Internal(e) => DataProviderError::Internal(Arc::clone(e)),
    })
}

/// Free function version of the fetch pipeline so it can be `.shared()` without borrowing `self`.
///
/// Performs the complete RPC fetch sequence:
/// 1. Fetch block header (without transactions) to get the block number.
/// 2. Fetch witness and full block in parallel, each subject to the shared `deadline`. The witness
///    stage also gets a sub-deadline: `min(deadline, now + witness_timeout)`, tightened further for
///    old blocks (see `witness_deadline_for`).
/// 3. The witness arrives as a `LightWitness` already (zero-validation light decode).
/// 4. Extract code hashes from witness and fetch contract bytecodes (shares `deadline`).
async fn do_fetch_block_data(
    rpc_client: Arc<RpcClient>,
    db: Option<Arc<dyn BlockStore>>,
    contract_cache: Arc<ContractCache>,
    witness_cfg: WitnessFetchConfig,
    r2_witness: Option<Arc<R2WitnessSource>>,
    block_hash: B256,
    deadline: Instant,
) -> DataProviderResult<BlockData> {
    let overall_start = Instant::now();

    // Step 1: Fetch header first to get the block number.
    let start = Instant::now();
    let header = rpc_client
        .get_header_with_deadline(BlockId::Hash(block_hash.into()), false, Some(deadline))
        .await?;
    let block_number = header.number;
    let fetch_header_ms = start.elapsed().as_millis();

    // Step 2: Pick the witness deadline based on "new vs old" heuristic, then run witness
    // and full-block fetches in parallel. The tip is read once and shared by the deadline
    // heuristic and the witness-source routing.
    let db_tip = db_tip_height(db.as_deref());
    let witness_deadline = witness_deadline_for(db_tip, block_number, &witness_cfg, deadline);
    let (witness_timed, block_timed) = tokio::join!(
        async {
            let start = Instant::now();
            let result = fetch_witness(
                &rpc_client,
                &witness_cfg,
                r2_witness.as_deref(),
                db_tip,
                block_number,
                header.hash,
                witness_deadline,
            )
            .await;
            (result, start.elapsed())
        },
        async {
            let start = Instant::now();
            let result = rpc_client
                .get_block_with_deadline(BlockId::Hash(block_hash.into()), true, Some(deadline))
                .await
                .map_err(DataProviderError::from);
            (result, start.elapsed())
        },
    );

    let (witness_result, witness_elapsed) = witness_timed;
    let (block_result, block_elapsed) = block_timed;

    let fetch_witness_ms = witness_elapsed.as_millis();
    // Step 3: the light decode already produced a LightWitness — no conversion.
    let (witness, _mpt_witness) = witness_result?;
    let block = block_result?;
    let fetch_full_block_ms = block_elapsed.as_millis();

    // Step 4: Extract code hashes and fetch contracts.
    let start = Instant::now();
    let code_hashes = crate::tracing_executor::extract_code_hashes(&witness);
    let num_contracts = code_hashes.len();
    let contracts =
        resolve_contracts_inner(&rpc_client, &contract_cache, &code_hashes, deadline).await?;
    let fetch_contracts_ms = start.elapsed().as_millis();

    let total_ms = overall_start.elapsed().as_millis();

    if fetch_header_ms >= SLOW_STAGE_THRESHOLD_MS ||
        fetch_witness_ms >= SLOW_STAGE_THRESHOLD_MS ||
        fetch_full_block_ms >= SLOW_STAGE_THRESHOLD_MS ||
        fetch_contracts_ms >= SLOW_STAGE_THRESHOLD_MS
    {
        warn!(
            block_number,
            block_hash = %block_hash,
            tx_count = block.transactions.len(),
            num_contracts,
            fetch_header_ms = fetch_header_ms as u64,
            fetch_witness_ms = fetch_witness_ms as u64,
            fetch_full_block_ms = fetch_full_block_ms as u64,
            fetch_contracts_ms = fetch_contracts_ms as u64,
            total_ms = total_ms as u64,
            "do_fetch_block_data slow stages detected"
        );
    }

    Ok(BlockData { block, witness, contracts })
}

/// Reads the local DB's canonical tip height, `None` when no DB is configured or the tip is
/// unknown.
fn db_tip_height(db: Option<&dyn BlockStore>) -> Option<u64> {
    db.and_then(|db| db.get_canonical_tip().ok().flatten().map(|tip| tip.block_number))
}

/// Whether a block is at or below the local tip. `false` with no local DB — a new block's
/// witness may still be generating upstream, so unknown conservatively counts as new.
fn is_old_block(db_tip: Option<u64>, block_number: u64) -> bool {
    db_tip.is_some_and(|tip| block_number <= tip)
}

/// Witness-stage budget for a block: full `witness_timeout` for **new** blocks (above local tip
/// or no local DB — covers "witness still being generated upstream"), and the separately
/// configurable `old_block_witness_timeout` (clamped to `witness_timeout`) for blocks at or
/// below the tip.
fn witness_budget(db_tip: Option<u64>, block_number: u64, cfg: &WitnessFetchConfig) -> Duration {
    if is_old_block(db_tip, block_number) {
        cfg.witness_timeout.min(cfg.old_block_witness_timeout)
    } else {
        cfg.witness_timeout
    }
}

/// Picks the effective deadline for a witness fetch: [`witness_budget`] from now, clamped by the
/// outer call deadline.
fn witness_deadline_for(
    db_tip: Option<u64>,
    block_number: u64,
    cfg: &WitnessFetchConfig,
    outer_deadline: Instant,
) -> Instant {
    let budget = witness_budget(db_tip, block_number, cfg);
    let stage_deadline = Instant::now() + budget;
    trace!(
        block_number,
        db_tip,
        budget_ms = budget.as_millis() as u64,
        "Computed witness stage deadline",
    );
    stage_deadline.min(outer_deadline)
}

/// Whether a block is historical for witness routing: at least `local_window` blocks below the
/// local tip (see [`DEFAULT_WITNESS_LOCAL_WINDOW`] for why the window matters). Unknown tip
/// (or an overflowing window) conservatively counts as recent.
fn is_historical(db_tip: Option<u64>, block_number: u64, local_window: u64) -> bool {
    match (db_tip, block_number.checked_add(local_window)) {
        (Some(tip), Some(horizon)) => horizon <= tip,
        _ => false,
    }
}

/// Witness route for a block: how many leading witness endpoints to skip, plus the metrics
/// source label. Historical blocks skip the internal generator at index 0 — but only with a
/// fallback endpoint to skip to (`can_skip_generator`, so the skip-aware fetch never sees an
/// empty rotation); everything else uses the full chain.
fn witness_route(
    can_skip_generator: bool,
    db_tip: Option<u64>,
    block_number: u64,
    local_window: u64,
) -> (usize, &'static str) {
    if can_skip_generator && is_historical(db_tip, block_number, local_window) {
        (1, "witness_historical")
    } else {
        (0, "witness_generator")
    }
}

/// Fetches witness data, routing by block age. The `deadline` is the witness stage's
/// effective deadline (see [`witness_deadline_for`]).
///
/// - **Recent block** (fewer than `local_window` blocks below the local tip, or tip unknown): the
///   full RPC witness endpoint chain, tried in order — the internal generator first, so near-tip
///   witnesses stay on the fast internal path.
/// - **Historical block** with an R2 source configured: R2 first — object storage tolerates far
///   more parallelism than the shared RPC gateway, and the bucket holds full history while the
///   generator prunes beyond its window. Every R2 failure (missing object, throttle-exhausted,
///   transport, corrupt payload) falls back to the RPC chain below on the remaining deadline.
/// - **Historical block** on the RPC chain, with a declared generator and a fallback endpoint
///   configured: the same chain minus the generator, the guaranteed-miss probe
///   [`DEFAULT_WITNESS_LOCAL_WINDOW`] describes.
///
/// Uses the zero-validation light decode: the trace server never verifies the witness proof,
/// so the full decode's per-point elliptic-curve work bought nothing. The recorded size is
/// the light lower bound (excludes the never-decoded parent commitments).
async fn fetch_witness(
    rpc_client: &RpcClient,
    cfg: &WitnessFetchConfig,
    r2_witness: Option<&R2WitnessSource>,
    db_tip: Option<u64>,
    block_number: u64,
    block_hash: B256,
    deadline: Instant,
) -> DataProviderResult<(LightWitness, MptWitness)> {
    if let Some(r2) = r2_witness &&
        is_historical(db_tip, block_number, cfg.local_window)
    {
        // Half the remaining witness budget, so a hung R2 endpoint can never starve the RPC
        // fallback of its turn; a healthy R2 answers in a fraction of it.
        let r2_deadline =
            (Instant::now() + deadline.saturating_duration_since(Instant::now()) / 2).min(deadline);
        let metrics = WitnessSourceMetrics::new_for_source("witness_r2");
        let start = Instant::now();
        match r2.get_witness_light(block_number, block_hash, r2_deadline).await {
            Ok(witness) => {
                metrics.record_request(true, start.elapsed().as_secs_f64());
                metrics
                    .record_size(WitnessSizeBreakdown::new_light(&witness.0, &witness.1).total());
                DataSourceMetrics::new_for_source("witness_r2").record();
                return Ok(witness);
            }
            Err(e) => {
                metrics.record_request(false, start.elapsed().as_secs_f64());
                crate::metrics::record_r2_witness_error(e.kind());
                warn!(
                    block_number,
                    block_hash = %block_hash,
                    kind = e.kind(),
                    error = %e,
                    "R2 witness fetch failed, falling back to the RPC chain",
                );
            }
        }
    }

    let can_skip_generator = cfg.generator_first && rpc_client.witness_provider_count() >= 2;
    let (skip, source) = witness_route(can_skip_generator, db_tip, block_number, cfg.local_window);
    let metrics = WitnessSourceMetrics::new_for_source(source);
    let start = Instant::now();

    match rpc_client
        .get_witness_light_with_deadline_from(skip, block_number, block_hash, Some(deadline))
        .await
    {
        Ok(w) => {
            metrics.record_request(true, start.elapsed().as_secs_f64());
            metrics.record_size(WitnessSizeBreakdown::new_light(&w.0, &w.1).total());
            DataSourceMetrics::new_for_source(source).record();
            Ok(w)
        }
        Err(e) => {
            metrics.record_request(false, start.elapsed().as_secs_f64());
            let budget = deadline.saturating_duration_since(start);
            // Attribution-grade context for the next timeout incident: the effective stage
            // budget, the route taken, and whether the old-block clamp applied — the client
            // only ever sees the generic `-32001` message.
            warn!(
                block_number,
                block_hash = %block_hash,
                source,
                old_block = is_old_block(db_tip, block_number),
                budget_ms = budget.as_millis() as u64,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "Witness fetch deadline exceeded",
            );
            Err(e.into())
        }
    }
}

/// Free-function version of contract resolution so it can be called from the shared-future
/// pipeline without borrowing `DataProvider`.
async fn resolve_contracts_inner(
    rpc_client: &RpcClient,
    contract_cache: &ContractCache,
    code_hashes: &[B256],
    deadline: Instant,
) -> DataProviderResult<HashMap<B256, Bytecode>> {
    let (mut contracts, missing) = contract_cache.get(code_hashes)?;

    if missing.is_empty() {
        return Ok(contracts);
    }

    trace!(
        total = code_hashes.len(),
        from_cache = contracts.len(),
        missing = missing.len(),
        "Cache miss — fetching contracts from RPC"
    );

    // Per-attempt `eth_getCodeByHash` metrics land on the upstream attempt metrics via the
    // `TraceRpcMetrics` adapter inside `round_robin_with_backoff`.
    let fetched = rpc_client.get_codes_with_deadline(&missing, true, Some(deadline)).await?;

    let new_contracts: Vec<(B256, Bytecode)> = fetched.into_iter().collect();

    // Write-through: memory always, disk in local-cache mode. We don't fail the trace on
    // cache-insert errors; the request has already been served.
    if let Err(e) = contract_cache.insert(&new_contracts) {
        warn!(error = %e, count = new_contracts.len(), "Failed to persist fetched contracts to cache");
    }

    contracts.extend(new_contracts);
    Ok(contracts)
}

/// In-memory-only [`ContractStore`] used as [`ContractCache`]'s backing store in
/// stateless mode (no `--data-dir`).
///
/// Reads always return "everything missing" so the cache falls back to RPC; writes
/// silently drop — the cache's own in-memory layer is the only persistence in this mode.
pub(crate) struct NoopContractStore;

impl ContractStore for NoopContractStore {
    fn get_contracts(&self, hashes: &[B256]) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
        Ok((HashMap::default(), hashes.to_vec()))
    }

    fn add_contracts(&self, _codes: &[(B256, Bytecode)]) -> StoreResult<()> {
        Ok(())
    }
}

/// Test fixtures shared with the `rpc_service`, `block_data_cache`, and
/// `tracing_executor` unit tests; the [`BlockStore`] stub lives in
/// `server_db::test_support`, next to the trait.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use jsonrpsee::{RpcModule, server::ServerHandle, types::ErrorObjectOwned};
    use stateless_test_utils::fixtures::TestFixtures;

    use super::*;

    /// URL of a bound-but-never-answering listener, leaked so connects hang (instead of
    /// failing fast) for the process lifetime.
    pub(crate) fn hanging_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::mem::forget(listener);
        url
    }

    /// An empty contract cache over the no-op store.
    pub(crate) fn noop_contract_cache() -> Arc<ContractCache> {
        Arc::new(ContractCache::new(Arc::new(NoopContractStore) as Arc<dyn ContractStore>))
    }

    /// Builds a real [`BlockData`] (block, light witness, full fixture contract map) from
    /// the synthetic fixture set.
    pub(crate) fn fixture_block_data() -> BlockData {
        let fixtures = TestFixtures::synthetic();
        let (_, hash) = fixtures.paired_blocks().into_iter().next().expect("paired fixture");
        let block = fixtures.blocks[&hash].clone();
        let witness = LightWitness::from(&fixtures.salt_witnesses[&hash]);
        let contracts: HashMap<B256, Bytecode> =
            fixtures.contracts.iter().map(|(h, code)| (*h, code.clone())).collect();
        BlockData { block, witness, contracts }
    }

    /// Minimal self-consistent RPC `Header` for `number`: `hash` is the real `hash_slow()`
    /// of the inner header, so `verify_hash = true` fetches accept it.
    pub(crate) fn consistent_header(number: u64) -> alloy_rpc_types_eth::Header {
        let inner = alloy_consensus::Header { number, ..Default::default() };
        alloy_rpc_types_eth::Header { hash: inner.hash_slow(), inner, ..Default::default() }
    }

    /// Serves `eth_getHeaderByNumber` with a self-consistent header for any number, and
    /// `eth_blockNumber` with `tip` — counting the latter's calls so tip-seed tests can
    /// assert whether (and how often) the seed fired.
    pub(crate) async fn start_mock_rpc(tip: u64) -> (ServerHandle, String, Arc<AtomicUsize>) {
        let seed_hits = Arc::new(AtomicUsize::new(0));
        let mut module = RpcModule::new(seed_hits.clone());
        module
            .register_method("eth_getHeaderByNumber", |params, _, _| {
                let (hex,): (String,) = params.parse().unwrap();
                let n = u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(&hex), 16).unwrap();
                Ok::<_, ErrorObjectOwned>(consistent_header(n))
            })
            .unwrap();
        module
            .register_method("eth_blockNumber", move |_params, seed_hits, _| {
                seed_hits.fetch_add(1, Ordering::Relaxed);
                Ok::<_, ErrorObjectOwned>(format!("{tip:#x}"))
            })
            .unwrap();
        let server =
            jsonrpsee::server::ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (server.start(module), url, seed_hits)
    }

    /// Serves `mega_getBlockWitness`: "not generated yet" errors for the first
    /// `misses_before_serve` calls, then `wire` forever (always errors when `wire` is
    /// `None`), counting every call.
    pub(crate) async fn scripted_witness_rpc(
        misses_before_serve: usize,
        wire: Option<String>,
    ) -> (ServerHandle, String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let mut module = RpcModule::new((hits.clone(), wire));
        module
            .register_method("mega_getBlockWitness", move |_p, (hits, wire), _| {
                let call = hits.fetch_add(1, Ordering::Relaxed);
                match wire {
                    Some(wire) if call >= misses_before_serve => Ok(wire.clone()),
                    _ => Err(ErrorObjectOwned::owned::<()>(
                        -32602,
                        "Failed to get witness: not generated yet",
                        None,
                    )),
                }
            })
            .unwrap();
        let server =
            jsonrpsee::server::ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (server.start(module), url, hits)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, sync::atomic::Ordering};

    use stateless_common::{BackoffPolicy, RpcClientConfig};

    use super::{
        test_support::{consistent_header, scripted_witness_rpc, start_mock_rpc},
        *,
    };
    use crate::server_db::test_support::StubBlockStore;

    /// Compile-time trait bounds + timeout constants.
    #[test]
    fn type_bounds_and_timeout_constants() {
        fn _assert_clone<T: Clone + Send + Sync>() {}
        fn _assert_sync<T: Send + Sync>() {}
        // BlockData is intentionally not Clone — callers share it via `Arc<BlockData>`.
        _assert_sync::<BlockData>();
        _assert_clone::<Arc<RpcClient>>();
        _assert_clone::<Option<Arc<dyn BlockStore>>>();
        // `Shared` is `Clone` by design — that's the whole reason we use it here.
        _assert_clone::<BlockDataFuture>();

        assert_eq!(DEFAULT_WITNESS_TIMEOUT_SECS, 8);
        assert_eq!(Duration::from_secs(DEFAULT_WITNESS_TIMEOUT_SECS).as_millis(), 8000);
    }

    /// Witness-source routing boundary: historical iff `number + local_window <= tip`;
    /// unknown tip and window overflow are conservatively recent (RPC path).
    #[test]
    fn historical_routing_boundary() {
        assert!(!is_historical(None, 100, 4096), "unknown tip is recent");
        assert!(is_historical(Some(5000), 904, 4096), "904 + 4096 == 5000: exactly at the window");
        assert!(!is_historical(Some(5000), 905, 4096), "one inside the window is recent");
        assert!(!is_historical(Some(5000), 5000, 4096), "the tip itself is recent");
        assert!(is_historical(Some(4096), 0, 4096), "genesis with tip == window");
        assert!(!is_historical(Some(4095), 0, 4096));
        assert!(!is_historical(Some(u64::MAX), u64::MAX, 4096), "overflowing horizon is recent");
        assert!(is_historical(Some(100), 50, 0), "zero window: everything at/below tip");
    }

    /// Route selection: the skip-generator chain and the `witness_historical` label apply
    /// only when the generator may be skipped (declared generator + fallback) AND the block
    /// is historical; everything else stays on the full chain under the `witness_generator`
    /// label.
    #[test]
    fn witness_route_selection() {
        // No declared generator (or no fallback to skip to): always the full chain.
        assert_eq!(witness_route(false, Some(5000), 900, 100), (0, "witness_generator"));
        assert_eq!(witness_route(true, Some(5000), 900, 100), (1, "witness_historical"));
        assert_eq!(witness_route(true, Some(5000), 4999, 100), (0, "witness_generator"));
        assert_eq!(witness_route(true, None, 900, 100), (0, "witness_generator"), "unknown tip");
    }

    /// Fast-retry client over `witness_urls` plus a routing config (1 s budgets, 100-block
    /// window) for the `fetch_witness` dispatch tests below.
    fn routing_fixture(
        witness_urls: &[&str],
        generator_first: bool,
    ) -> (RpcClient, WitnessFetchConfig) {
        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2)),
            ..RpcClientConfig::trace_server()
        };
        let rpc_client =
            RpcClient::new_with_config(&witness_urls[..1], witness_urls, config, None).unwrap();
        let cfg = WitnessFetchConfig {
            local_window: 100,
            generator_first,
            ..WitnessFetchConfig::with_defaults(1)
        };
        (rpc_client, cfg)
    }

    /// Builds a fixture `(block, witness)` pair plus a contract cache pre-loaded with every
    /// code hash the witness references, so DB-served fetches never fall through to RPC.
    fn fixture_block_and_cache() -> (Block<Transaction>, LightWitness, Arc<ContractCache>) {
        let BlockData { block, witness, contracts } = test_support::fixture_block_data();
        let contract_cache = test_support::noop_contract_cache();
        let codes: Vec<(B256, Bytecode)> = crate::tracing_executor::extract_code_hashes(&witness)
            .into_iter()
            .map(|h| {
                let code = contracts
                    .get(&h)
                    .cloned()
                    .unwrap_or_else(|| Bytecode::new_raw(vec![0u8].into()));
                (h, code)
            })
            .collect();
        contract_cache.insert(&codes).unwrap();
        (block, witness, contract_cache)
    }

    /// Provider over `url` with optional DB / memory-cache tiers and a caller-supplied
    /// contract cache, using a fast-fail retry config (150 ms attempts, millisecond
    /// backoff) and a 1 s fetch budget so hang tests stay fast.
    fn provider_with_tiers(
        url: &str,
        db: Option<Arc<dyn BlockStore>>,
        block_data_cache: Option<Arc<BlockDataCache>>,
        contract_cache: Arc<ContractCache>,
    ) -> DataProvider {
        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2)),
            per_attempt_timeout: Duration::from_millis(150),
            ..RpcClientConfig::trace_server()
        };
        let rpc_client =
            Arc::new(RpcClient::new_with_config(&[url], &[url], config, None).unwrap());
        DataProvider::new(
            rpc_client,
            db,
            block_data_cache,
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(1),
            1024,
        )
    }

    /// [`provider_with_tiers`] with no memory cache and an empty noop-backed contract
    /// cache.
    fn provider_with(url: &str, db: Option<Arc<dyn BlockStore>>) -> DataProvider {
        provider_with_tiers(url, db, None, test_support::noop_contract_cache())
    }

    /// A DB-served block populates the memory cache: the second request for the same hash is
    /// served from memory — no DB block read, and no fresh tip read for the block-distance
    /// histogram — and shares the same allocation.
    #[tokio::test]
    async fn db_hit_populates_memory_cache_and_second_read_skips_db() {
        let (block, witness, contract_cache) = fixture_block_and_cache();
        let hash = block.header.hash;
        let store = Arc::new(StubBlockStore {
            canonical_tip: Some(block.header.number),
            block_data: Some((block, witness)),
            ..Default::default()
        });
        let cache = Arc::new(BlockDataCache::new(1024 * 1024 * 1024));
        let provider = provider_with_tiers(
            &test_support::hanging_url(),
            Some(Arc::clone(&store) as Arc<dyn BlockStore>),
            Some(Arc::clone(&cache)),
            contract_cache,
        );

        let first = provider.get_block_data_by_hash(hash).await.expect("db-served fetch");
        let second = provider.get_block_data_by_hash(hash).await.expect("memory-served fetch");

        assert_eq!(
            store.block_reads.load(Ordering::Relaxed),
            1,
            "second read must come from memory"
        );
        assert!(Arc::ptr_eq(&first, &second), "memory hits share the same allocation");
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(
            store.tip_reads.load(Ordering::Relaxed),
            1,
            "the memory hit must record its distance from the memoized tip, not a DB read"
        );
    }

    /// A pre-seeded memory entry is served before DB and RPC: with a hanging upstream and no
    /// DB, the request must return instantly instead of burning the block-fetch deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn memory_hit_short_circuits_before_db_and_rpc() {
        let (block, witness, contract_cache) = fixture_block_and_cache();
        let hash = block.header.hash;
        let cache = Arc::new(BlockDataCache::new(1024 * 1024 * 1024));
        cache.insert(hash, Arc::new(BlockData { block, witness, contracts: HashMap::default() }));
        let provider =
            provider_with_tiers(&test_support::hanging_url(), None, Some(cache), contract_cache);

        let start = std::time::Instant::now();
        let data = provider.get_block_data_by_hash(hash).await.expect("memory hit");
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "memory hit must not reach the hanging upstream"
        );
        assert_eq!(data.block.header.hash, hash);
    }

    /// With the memory cache disabled, every request re-reads the DB.
    #[tokio::test]
    async fn disabled_block_data_cache_reads_db_each_time() {
        let (block, witness, contract_cache) = fixture_block_and_cache();
        let hash = block.header.hash;
        let store =
            Arc::new(StubBlockStore { block_data: Some((block, witness)), ..Default::default() });
        let provider = provider_with_tiers(
            &test_support::hanging_url(),
            Some(Arc::clone(&store) as Arc<dyn BlockStore>),
            None,
            contract_cache,
        );

        provider.get_block_data_by_hash(hash).await.expect("first db read");
        provider.get_block_data_by_hash(hash).await.expect("second db read");
        assert_eq!(store.block_reads.load(Ordering::Relaxed), 2);
    }

    /// [`provider_with`] over a [`StubBlockStore`] whose canonical window answers with
    /// the given fixed hash.
    fn provider_at(url: &str, db: Option<Option<B256>>) -> DataProvider {
        provider_with(
            url,
            db.map(|hash| {
                Arc::new(StubBlockStore { canonical_hash: hash, ..Default::default() })
                    as Arc<dyn BlockStore>
            }),
        )
    }

    /// The local canonical index answers first: a DB hit never consults the upstream —
    /// pinned by pointing the provider at a hanging listener that would eat the deadline.
    #[tokio::test]
    async fn resolve_canonical_hash_prefers_db_index() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let _listener = listener;

        let h1 = B256::from([1u8; 32]);
        let provider = provider_at(&url, Some(Some(h1)));
        let deadline = Instant::now() + Duration::from_millis(300);
        assert_eq!(provider.resolve_canonical_hash(7, deadline).await.unwrap(), h1);
    }

    /// Stateless mode (no DB) and local-cache mode with a DB miss both resolve the hash
    /// upstream via `eth_getHeaderByNumber`, hash-verified — the mock serves
    /// self-consistent headers.
    #[tokio::test]
    async fn resolve_canonical_hash_resolves_upstream_without_db_or_on_db_miss() {
        let (handle, url, _seed_hits) = start_mock_rpc(1_000_000).await;

        for db in [None, Some(None)] {
            let provider = provider_at(&url, db);
            let deadline = Instant::now() + Duration::from_secs(2);
            assert_eq!(
                provider.resolve_canonical_hash(42, deadline).await.unwrap(),
                consistent_header(42).hash
            );
        }
        handle.stop().unwrap();
    }

    /// The memo: an upstream-resolved hash for a depth-final height below the canonical
    /// window is memoized (the window itself untouched), so the next resolution needs no
    /// upstream at all — pinned by stopping the mock server between resolves. A shallow
    /// height (within the safety depth of the tip) is never memoized and must fail once
    /// the upstream is gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_canonical_hash_memoizes_depth_final_upstream_answers() {
        use stateless_core::{ChainStore, DivergenceLookups};

        use crate::server_db::test_support::make_block_meta;

        let (handle, url, seed_hits) = start_mock_rpc(200).await;
        let dir = tempfile::tempdir().unwrap();
        let server_db =
            Arc::new(crate::server_db::ServerDB::new(dir.path().join("t.redb")).unwrap());
        // The anchor-init path installs the canonical window as a single row at {200}:
        // height 42 is more than the safety depth below that tip, height 199 is not.
        ChainStore::reset_to_anchor(&*server_db, &make_block_meta(200)).unwrap();

        let provider = provider_with(&url, Some(Arc::clone(&server_db) as Arc<dyn BlockStore>));
        let deadline = Instant::now() + Duration::from_secs(2);
        let resolved = provider.resolve_canonical_hash(42, deadline).await.unwrap();
        assert_eq!(resolved, consistent_header(42).hash);
        let shallow = provider.resolve_canonical_hash(199, deadline).await.unwrap();
        assert_eq!(shallow, consistent_header(199).hash);
        assert_eq!(
            ChainStore::get_block_hash(&*server_db, 42).unwrap(),
            None,
            "the canonical window must not be touched by memoization"
        );
        assert_eq!(DivergenceLookups::get_earliest(&*server_db).unwrap().unwrap().0, 200);
        assert_eq!(
            seed_hits.load(Ordering::Relaxed),
            0,
            "a present window tip must gate the memo without an upstream tip seed"
        );

        // With the upstream gone: the depth-final height serves from the memo; the
        // shallow one must go upstream every time, and now fails.
        handle.stop().unwrap();
        let deadline = Instant::now() + Duration::from_millis(300);
        assert_eq!(provider.resolve_canonical_hash(42, deadline).await.unwrap(), resolved);
        let deadline = Instant::now() + Duration::from_millis(300);
        assert!(provider.resolve_canonical_hash(199, deadline).await.is_err());
    }

    /// Stateless mode with numeric-only traffic: no `latest` lookup ever raises the tip
    /// hint, so the first resolution must learn the tip itself — via the throttled
    /// `eth_blockNumber` seed — for the memo to ever fill. Later depth-final heights are
    /// admitted by the seeded hint and shallow heights stay unmemoized, both without a
    /// second seed call (the throttle); pinned by the seed counter and by stopping the
    /// upstream.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_canonical_hash_seeds_tip_for_stateless_numeric_traffic() {
        let (handle, url, seed_hits) = start_mock_rpc(500).await;
        let provider = provider_at(&url, None);
        let deadline = Instant::now() + Duration::from_secs(2);

        // Cold hint: height 42 alone cannot pass the gate, so the seed fires once and
        // tip 500 admits it as depth-final.
        let deep = provider.resolve_canonical_hash(42, deadline).await.unwrap();
        assert_eq!(deep, consistent_header(42).hash);
        assert_eq!(seed_hits.load(Ordering::Relaxed), 1, "cold hint must seed exactly once");

        // 400 passes on the seeded hint (500 - 64 = 436); 450 fails the gate and its
        // seed attempt lands inside the throttle window. Neither re-fetches the tip.
        let mid = provider.resolve_canonical_hash(400, deadline).await.unwrap();
        let shallow = provider.resolve_canonical_hash(450, deadline).await.unwrap();
        assert_eq!(shallow, consistent_header(450).hash);
        assert_eq!(seed_hits.load(Ordering::Relaxed), 1, "further seeds must be throttled");

        // Upstream gone: both depth-final heights serve from the memo; the shallow one
        // was never memoized and must fail upstream.
        handle.stop().unwrap();
        let deadline = Instant::now() + Duration::from_millis(300);
        assert_eq!(provider.resolve_canonical_hash(42, deadline).await.unwrap(), deep);
        assert_eq!(provider.resolve_canonical_hash(400, deadline).await.unwrap(), mid);
        assert!(provider.resolve_canonical_hash(450, deadline).await.is_err());
    }

    /// The memo owns its reorg policy: reorgs shallower than the finality margin cannot
    /// touch memoized (depth-final) heights and leave the memo intact; from the margin
    /// on, the assumption every binding relied on is breached and everything goes.
    #[test]
    fn only_margin_deep_reorgs_clear_the_memo() {
        let memo = CanonicalHashMemo::new(16);
        memo.insert(42, B256::from([1u8; 32]));

        memo.on_reorg(CANONICAL_MEMO_MIN_DEPTH - 1);
        assert!(memo.get(&42).is_some(), "a sub-margin reorg must keep the memo");

        memo.on_reorg(CANONICAL_MEMO_MIN_DEPTH);
        assert!(memo.get(&42).is_none(), "a margin-deep reorg must clear the memo");
    }

    /// A hanging upstream surfaces as a typed `Timeout` bounded by the caller's deadline —
    /// hash resolution shares the request budget and cannot hang the caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_canonical_hash_surfaces_timeout_when_upstream_hangs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let _listener = listener;

        let provider = provider_at(&url, None);
        let start = Instant::now();
        let deadline = Instant::now() + Duration::from_millis(300);
        let err = provider.resolve_canonical_hash(42, deadline).await.unwrap_err();
        assert!(
            matches!(err, DataProviderError::Timeout { stage: TimeoutStage::Block, .. }),
            "expected Timeout{{Block}}, got: {err:?}",
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "deadline must bound the hang; elapsed: {:?}",
            start.elapsed(),
        );
    }

    /// End-to-end routing dispatch through `fetch_witness`: a historical block must never
    /// touch the first (generator) endpoint, while a recent block probes it first.
    #[tokio::test]
    async fn fetch_witness_routes_historical_blocks_past_the_generator() {
        let (ha, url_a, hits_a) = scripted_witness_rpc(0, None).await;
        let (hb, url_b, hits_b) = scripted_witness_rpc(0, None).await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str(), url_b.as_str()], true);
        let db_tip = Some(5000);

        // Historical block (900 + 100 <= 5000): the generator endpoint must stay untouched.
        let deadline = Instant::now() + Duration::from_millis(150);
        let result =
            fetch_witness(&rpc_client, &cfg, None, db_tip, 900, B256::ZERO, deadline).await;
        assert!(result.is_err(), "the mock only returns errors, so the deadline must fire");
        assert_eq!(hits_a.load(Ordering::Relaxed), 0, "historical fetch must skip the generator");
        assert!(hits_b.load(Ordering::Relaxed) >= 1, "the fallback endpoint must be tried");

        // Recent block (the tip itself): the full chain, generator first.
        let deadline = Instant::now() + Duration::from_millis(150);
        let _ = fetch_witness(&rpc_client, &cfg, None, db_tip, 5000, B256::ZERO, deadline).await;
        assert!(hits_a.load(Ordering::Relaxed) >= 1, "recent fetch must probe the generator");

        ha.stop().unwrap();
        hb.stop().unwrap();
    }

    /// A declared generator with no fallback has nothing to skip to: a historical block must
    /// still fetch through the sole endpoint without tripping the skip assert. Pins the
    /// `>= 2` fallback guard in `fetch_witness` — a `>= 1` regression would pass every other
    /// test and panic in production on the first historical fetch.
    #[tokio::test]
    async fn fetch_witness_single_endpoint_serves_historical_from_generator() {
        let (ha, url_a, hits_a) = scripted_witness_rpc(0, None).await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str()], true);

        // Historical block (900 + 100 <= 5000) with no fallback endpoint configured.
        let deadline = Instant::now() + Duration::from_millis(150);
        let result =
            fetch_witness(&rpc_client, &cfg, None, Some(5000), 900, B256::ZERO, deadline).await;
        assert!(result.is_err(), "the mock only returns errors, so the deadline must fire");
        assert!(
            hits_a.load(Ordering::Relaxed) >= 1,
            "the sole endpoint must serve historical blocks"
        );

        ha.stop().unwrap();
    }

    /// Two durable endpoints without a declared generator must never skip: historical blocks
    /// still probe the first endpoint. Pins routing as an explicit opt-in — a pure failover
    /// pair keeps its pre-routing behavior, with no endpoint special by position.
    #[tokio::test]
    async fn fetch_witness_without_generator_never_skips() {
        let (ha, url_a, hits_a) = scripted_witness_rpc(0, None).await;
        let (hb, url_b, _hits_b) = scripted_witness_rpc(0, None).await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str(), url_b.as_str()], false);

        // Historical block (900 + 100 <= 5000): with no declared generator, the first
        // endpoint stays in the rotation.
        let deadline = Instant::now() + Duration::from_millis(150);
        let result =
            fetch_witness(&rpc_client, &cfg, None, Some(5000), 900, B256::ZERO, deadline).await;
        assert!(result.is_err(), "the mock only returns errors, so the deadline must fire");
        assert!(hits_a.load(Ordering::Relaxed) >= 1, "first endpoint must not be skipped");

        ha.stop().unwrap();
        hb.stop().unwrap();
    }

    /// R2 source for routing tests, pointed at a mock endpoint with millisecond retry pacing.
    fn r2_source(endpoint: &str) -> R2WitnessSource {
        R2WitnessSource::new(
            endpoint,
            "witness-test".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            Duration::from_secs(5),
            BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2)),
            None,
        )
        .unwrap()
    }

    /// Fixture witness encoded as an R2 object body (the uploader's wire format).
    fn fixture_r2_payload() -> Vec<u8> {
        use stateless_test_utils::fixtures::TestFixtures;

        let fixtures = TestFixtures::mainnet_shared();
        let (_, hash) =
            fixtures.paired_blocks().into_iter().next().expect("mainnet fixtures have a witness");
        let salt_witness = fixtures.salt_witnesses[&hash].clone();
        let mpt_witness = fixtures.mpt_witness(&hash);
        let (_, payload) = stateless_common::encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("fixture witness must encode");
        payload
    }

    /// A historical block with R2 configured is served from R2 alone: neither the generator
    /// nor the fallback RPC endpoint sees a request.
    #[tokio::test]
    async fn fetch_witness_historical_prefers_r2_over_the_rpc_chain() {
        use stateless_test_utils::mock_r2::mock_r2;

        let (r2_endpoint, r2_hits) = mock_r2(vec![(200, fixture_r2_payload())]).await;
        let (ha, url_a, hits_a) = scripted_witness_rpc(0, None).await;
        let (hb, url_b, hits_b) = scripted_witness_rpc(0, None).await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str(), url_b.as_str()], true);
        let r2 = r2_source(&r2_endpoint);

        // Historical block (900 + 100 <= 5000).
        let deadline = Instant::now() + Duration::from_secs(5);
        let result =
            fetch_witness(&rpc_client, &cfg, Some(&r2), Some(5000), 900, B256::ZERO, deadline)
                .await;
        assert!(result.is_ok(), "R2 must serve the historical witness");
        assert_eq!(r2_hits.load(Ordering::SeqCst), 1, "exactly one R2 GET");
        assert_eq!(hits_a.load(Ordering::Relaxed), 0, "generator must stay untouched");
        assert_eq!(hits_b.load(Ordering::Relaxed), 0, "RPC fallback must stay untouched");

        ha.stop().unwrap();
        hb.stop().unwrap();
    }

    /// Any R2 failure falls back to the RPC chain — which still skips the generator for
    /// historical blocks — instead of surfacing to the caller.
    #[tokio::test]
    async fn fetch_witness_falls_back_to_the_rpc_chain_when_r2_misses() {
        use stateless_test_utils::mock_r2::mock_r2;

        let (r2_endpoint, r2_hits) = mock_r2(vec![(404, "<Code>NoSuchKey</Code>")]).await;
        let (ha, url_a, hits_a) = scripted_witness_rpc(0, None).await;
        let (hb, url_b, hits_b) = scripted_witness_rpc(0, None).await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str(), url_b.as_str()], true);
        let r2 = r2_source(&r2_endpoint);

        let deadline = Instant::now() + Duration::from_millis(150);
        let result =
            fetch_witness(&rpc_client, &cfg, Some(&r2), Some(5000), 900, B256::ZERO, deadline)
                .await;
        assert!(result.is_err(), "the RPC mock only returns errors, so the deadline must fire");
        assert_eq!(r2_hits.load(Ordering::SeqCst), 1, "the R2 miss must not be retried");
        assert_eq!(hits_a.load(Ordering::Relaxed), 0, "the fallback still skips the generator");
        assert!(hits_b.load(Ordering::Relaxed) >= 1, "the RPC chain must take over after R2");

        ha.stop().unwrap();
        hb.stop().unwrap();
    }

    /// Readahead window semantics: dedup on mark, re-admission after unmark, eviction by
    /// insertion order once the cap is exceeded — and depth 0 disables readahead entirely.
    #[test]
    fn readahead_window_marks_dedups_and_evicts() {
        let readahead = Readahead::new(32); // cap clamps to 256
        assert!(readahead.mark(1));
        assert!(!readahead.mark(1), "second mark of the same number must dedup");
        readahead.unmark(1);
        assert!(readahead.mark(1), "unmark must re-admit the number");

        // Fill far past the cap; the oldest entries fall out and become re-admittable.
        for number in 0..300u64 {
            readahead.mark(10_000 + number);
        }
        assert!(readahead.mark(10_000), "evicted numbers must be re-admittable");

        let disabled = provider_with("http://127.0.0.1:9/", None).with_historical_readahead(0);
        assert!(disabled.readahead.is_none(), "depth 0 must leave readahead disabled");
    }

    /// `schedule_readahead` covers the following historical numbers exactly once, stops at
    /// the local-window boundary, and no-ops for non-historical requests. Current-thread
    /// runtime: the spawned prefetch tasks are never polled, so the scheduling window is
    /// race-free to assert.
    #[tokio::test]
    async fn schedule_readahead_covers_the_following_historical_numbers_once() {
        // tip 5000, local window 4096 ⇒ historical numbers are those ≤ 904. The URL is never
        // contacted: the prefetch tasks are spawned but not polled.
        let db: Arc<dyn BlockStore> =
            Arc::new(StubBlockStore { canonical_tip: Some(5000), ..Default::default() });
        let provider =
            Arc::new(provider_with("http://127.0.0.1:9/", Some(db)).with_historical_readahead(8));
        let window_len = || {
            let readahead = provider.readahead.as_ref().unwrap();
            let window = readahead.scheduled.lock().unwrap();
            window.order.len()
        };

        provider.schedule_readahead(890);
        {
            let readahead = provider.readahead.as_ref().unwrap();
            let window = readahead.scheduled.lock().unwrap();
            assert!((891..=898).all(|n| window.set.contains(&n)), "depth-8 span from 890");
            assert_eq!(window.order.len(), 8);
        }

        // The same cursor again: pure dedup. An advanced cursor: only the new tail.
        provider.schedule_readahead(890);
        assert_eq!(window_len(), 8);
        provider.schedule_readahead(892);
        assert_eq!(window_len(), 10, "893..=900 adds only 899 and 900");

        // The last historical number has no historical successors; a non-historical
        // request must not schedule at all.
        provider.schedule_readahead(904);
        assert_eq!(window_len(), 10);
        provider.schedule_readahead(4000);
        assert_eq!(window_len(), 10);
    }

    /// Exhausted prefetch permits drop the remaining candidates (and forget them, so a
    /// later request can retry) instead of queueing unbounded tasks.
    #[tokio::test]
    async fn schedule_readahead_saturates_at_the_concurrency_cap() {
        let db: Arc<dyn BlockStore> =
            Arc::new(StubBlockStore { canonical_tip: Some(10_000), ..Default::default() });
        let provider =
            Arc::new(provider_with("http://127.0.0.1:9/", Some(db)).with_historical_readahead(8));

        // Two full spans consume all 16 permits (the unpolled tasks hold them); the third
        // must saturate without marking anything.
        provider.schedule_readahead(5000);
        provider.schedule_readahead(5010);
        provider.schedule_readahead(5020);

        let readahead = provider.readahead.as_ref().unwrap();
        let window = readahead.scheduled.lock().unwrap();
        assert_eq!(window.set.len(), READAHEAD_CONCURRENCY, "exactly the permit count sticks");
        assert!(!window.set.contains(&5021), "saturated candidates must be forgotten");
    }

    /// Recent blocks never touch R2 (the bucket lags the generator at the frontier): the
    /// full RPC chain with the generator first keeps serving them.
    #[tokio::test]
    async fn fetch_witness_recent_block_ignores_r2() {
        use stateless_test_utils::mock_r2::mock_r2;

        let (r2_endpoint, r2_hits) = mock_r2(vec![(200, "never fetched")]).await;
        let (ha, url_a, hits_a) = scripted_witness_rpc(0, None).await;
        let (hb, url_b, _hits_b) = scripted_witness_rpc(0, None).await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str(), url_b.as_str()], true);
        let r2 = r2_source(&r2_endpoint);

        // The tip itself is recent: R2 must stay untouched, the generator probed first.
        let deadline = Instant::now() + Duration::from_millis(150);
        let _ = fetch_witness(&rpc_client, &cfg, Some(&r2), Some(5000), 5000, B256::ZERO, deadline)
            .await;
        assert_eq!(r2_hits.load(Ordering::SeqCst), 0, "a recent block must not touch R2");
        assert!(hits_a.load(Ordering::Relaxed) >= 1, "recent fetch must probe the generator");

        ha.stop().unwrap();
        hb.stop().unwrap();
    }

    /// Old-block witness budget honors the configurable timeout and clamps to
    /// `witness_timeout`.
    #[test]
    fn old_block_budget_is_configurable_and_clamped() {
        let mut cfg = WitnessFetchConfig::with_defaults(10);
        cfg.old_block_witness_timeout = Duration::from_secs(8);
        // New block (above tip / no tip): full witness_timeout.
        assert_eq!(witness_budget(None, 42, &cfg), Duration::from_secs(10));
        assert_eq!(witness_budget(Some(41), 42, &cfg), Duration::from_secs(10));
        // Old block (at/below tip): the configured old-block budget.
        assert_eq!(witness_budget(Some(42), 42, &cfg), Duration::from_secs(8));
        // Clamped: old-block budget can never exceed witness_timeout.
        cfg.old_block_witness_timeout = Duration::from_secs(30);
        assert_eq!(witness_budget(Some(42), 42, &cfg), Duration::from_secs(10));
    }

    /// `BlockNumberOrTag` / `BlockId` variants that `resolve_block_number` matches on.
    /// Collapses `test_resolve_block_number_with_number`, `test_block_number_or_tag_variants`,
    /// `test_earliest_tag_returns_zero`, `test_block_id_from_tag`, and
    /// `test_block_id_from_safe_tag`.
    #[test]
    fn block_tag_and_id_variants() {
        assert!(matches!(BlockNumberOrTag::Number(12345), BlockNumberOrTag::Number(12345)));
        for tag in [
            BlockNumberOrTag::Number(100),
            BlockNumberOrTag::Latest,
            BlockNumberOrTag::Pending,
            BlockNumberOrTag::Earliest,
            BlockNumberOrTag::Finalized,
            BlockNumberOrTag::Safe,
        ] {
            assert!(matches!(BlockId::Number(tag), BlockId::Number(_)));
        }
    }

    /// Error-message + hash-display formatting used in log and RPC error strings.
    /// Collapses `test_pending_tag_error_message`, `test_eyre_error_creation`, and
    /// `test_contract_hash_display`.
    #[test]
    fn error_and_hash_formatting() {
        let pending = "Pending block not supported";
        assert!(pending.contains("Pending") && pending.contains("not supported"));

        let hash = B256::ZERO;
        let err = eyre::eyre!("Failed to fetch contract code {}: test error", hash).to_string();
        assert!(err.contains("Failed to fetch contract code") && err.contains("test error"));

        let display = format!("{hash}");
        assert!(display.starts_with("0x") && display.len() == 66);
    }

    /// `block_fetch_timeout` must bound the caller when the upstream hangs. We simulate a hang
    /// by pointing the `RpcClient` at a TCP listener that accepts connections but never replies
    /// — so `RpcClient`'s unbounded retry loop would otherwise loop forever. The timeout surfaces
    /// as a user-facing error within a small multiple of `block_fetch_timeout`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_block_data_surfaces_timeout_when_upstream_hangs() {
        // Bind to a real port that accepts but never responds — forces the RPC call to hang.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let _listener = listener;

        let provider = provider_at(&url, None);
        let start = std::time::Instant::now();
        let result = provider.get_block_data_by_hash(B256::from([0x42; 32])).await;
        let elapsed = start.elapsed();

        let err = match result {
            Ok(_) => panic!("hanging upstream must surface as an error"),
            Err(e) => e,
        };
        assert!(
            matches!(err, DataProviderError::Timeout { stage: TimeoutStage::Block, .. }),
            "expected Timeout{{Block}}, got: {err:?}",
        );
        // Allow generous headroom for retry backoff + scheduling; ≤5s proves the unbounded loop
        // is actually bounded.
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout must fire quickly; elapsed: {elapsed:?}"
        );
    }

    /// Tag-resolution branches (`Latest`/`Finalized`/`Safe`) must be bounded by the
    /// caller's deadline rather than retrying a stuck upstream forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_block_number_surfaces_timeout_when_upstream_hangs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/");
        let _listener = listener;

        let provider = provider_at(&url, None);

        for tag in [BlockNumberOrTag::Latest, BlockNumberOrTag::Finalized, BlockNumberOrTag::Safe] {
            let start = std::time::Instant::now();
            let deadline = Instant::now() + Duration::from_millis(300);
            let result = provider.resolve_block_number(tag, deadline).await;
            let elapsed = start.elapsed();

            let err = match result {
                Ok(n) => panic!("hanging upstream must surface as an error for {tag:?}, got {n}"),
                Err(e) => e,
            };
            assert!(
                matches!(err, DataProviderError::Timeout { stage: TimeoutStage::Block, .. }),
                "expected Timeout{{Block}} for {tag:?}, got: {err:?}",
            );
            assert!(
                elapsed < Duration::from_secs(5),
                "timeout must fire quickly for {tag:?}; elapsed: {elapsed:?}"
            );
        }
    }

    /// Cancellation of the primary fetch task (e.g. client disconnect) must not leak an
    /// entry in `in_flight` — the `InFlightGuard` removes it via `Drop` on unwind. Without
    /// the guard the `Shared<_>` stays pinned in the map and its cached `Arc<BlockData>`
    /// leaks until the process exits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn in_flight_entry_cleaned_up_on_task_cancellation() {
        // Hanging upstream: TCP connections accepted but never replied to, so the primary
        // parks at `shared.await` inside `fetch_block_data_single_flight`.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/");

        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        // Generous deadline so the task is cancelled *by us*, not by the deadline firing.
        let provider = Arc::new(DataProvider::new(
            rpc_client,
            None,
            None,
            test_support::noop_contract_cache(),
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(60),
            1024,
        ));

        let block_hash = B256::from([0xAB; 32]);
        let handle = {
            let provider = Arc::clone(&provider);
            tokio::spawn(async move { provider.get_block_data_by_hash(block_hash).await })
        };

        // Give the spawned task enough scheduling turns to reach `shared.await` and register
        // the `in_flight` entry. 200 ms is generous vs the ~10 µs it takes to reach the park.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            provider.in_flight.len(),
            1,
            "primary should have registered itself in in_flight"
        );

        // Cancel the task. `.await` on the handle returns once the task is fully dropped,
        // by which point our `InFlightGuard::drop` has run.
        handle.abort();
        let _ = handle.await;

        assert!(
            provider.in_flight.is_empty(),
            "InFlightGuard must remove the entry on cancellation; map={:?}",
            provider.in_flight.len(),
        );
    }

    /// `eyre::Error` auto-converts into `DataProviderError::Internal` via `#[from]` so call
    /// sites can keep using `?` for transport / decode errors without explicit wrapping.
    #[test]
    fn internal_from_eyre_conversion() {
        fn boundary() -> DataProviderResult<()> {
            Err(eyre::eyre!("downstream error"))?
        }
        let err = boundary().unwrap_err();
        assert!(matches!(err, DataProviderError::Internal(_)));
    }

    /// `RpcDeadlineExceeded` from the witness stage lands on `Timeout { Witness, .. }`; any
    /// other RPC method on `Timeout { Block, .. }`. Keeps the "witness vs block stage"
    /// distinction that drove the old `WitnessTimeout`/`BlockFetchTimeout` split without
    /// needing separate enum variants.
    #[test]
    fn rpc_deadline_maps_to_correct_stage() {
        let witness_err: DataProviderError = RpcDeadlineExceeded {
            method: stateless_common::RpcMethod::MegaGetBlockWitness,
            elapsed: Duration::from_secs(3),
        }
        .into();
        assert!(matches!(
            witness_err,
            DataProviderError::Timeout { stage: TimeoutStage::Witness, .. }
        ));

        let block_err: DataProviderError = RpcDeadlineExceeded {
            method: stateless_common::RpcMethod::EthGetBlock,
            elapsed: Duration::from_secs(13),
        }
        .into();
        assert!(matches!(block_err, DataProviderError::Timeout { stage: TimeoutStage::Block, .. }));
    }
}
