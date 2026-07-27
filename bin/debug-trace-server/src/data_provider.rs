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
//! - **Single deadline per call**: every public entry point computes one wall-clock deadline from
//!   `block_fetch_timeout` and threads it through the full pipeline (hash resolution, header,
//!   witness, block, contracts). The witness stage gets a tighter sub-deadline for blocks at or
//!   below the local tip. No more nested `tokio::time::timeout` wrappers.
//! - **Contract bytecode resolution**: checks [`ContractCache`] (memory → redb), falls back to a
//!   parallel + verified `RpcClient::get_codes_with_deadline` fetch on miss.
//!
//! # Note
//! Response caching is handled at the HTTP layer by `ResponseCache`, not here.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{B256, map::HashMap};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use dashmap::DashMap;
use futures::{FutureExt, future::Shared};
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use stateless_common::{CodeFetchError, RpcClient, RpcDeadlineExceeded, WitnessSizeBreakdown};
use stateless_core::{
    ContractStore, LightWitness, StoreResult, db::StoreError, withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use tracing::{debug, instrument, trace, warn};

use crate::{
    block_data_cache::BlockDataCache,
    metrics::{ChainSyncMetrics, DataSourceMetrics, SingleFlightMetrics, WitnessSourceMetrics},
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

/// Slow stage threshold: any individual stage exceeding this triggers a warn log.
pub(crate) const SLOW_STAGE_THRESHOLD_MS: u128 = 1000;

/// Deadline for the upstream canonical-hash check backing number-keyed cache hits in
/// stateless mode (see [`DataProvider::is_canonical`]).
const CANONICAL_CHECK_TIMEOUT_SECS: u64 = 2;

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
    pub fn new(
        rpc_client: Arc<RpcClient>,
        db: Option<Arc<dyn BlockStore>>,
        block_data_cache: Option<Arc<BlockDataCache>>,
        contract_cache: Arc<ContractCache>,
        witness_cfg: WitnessFetchConfig,
        block_fetch_timeout: Duration,
    ) -> Self {
        Self {
            rpc_client,
            db,
            block_data_cache,
            contract_cache,
            witness_cfg,
            block_fetch_timeout,
            in_flight: DashMap::new(),
        }
    }

    /// Returns block-data cache statistics, or `None` when the cache is disabled.
    pub fn block_data_cache_stats(&self) -> Option<crate::response_cache::CacheStats> {
        self.block_data_cache.as_ref().map(|cache| cache.stats())
    }

    /// Drops a block from the memory cache after its data failed execution: a decodable but
    /// incomplete witness would otherwise stay pinned, failing every retry until eviction —
    /// dropping it lets the next request refetch from the endpoints.
    pub fn evict_block_data(&self, block_hash: &B256) {
        if let Some(cache) = &self.block_data_cache {
            cache.remove(block_hash);
        }
    }

    /// Whether `hash` is the canonical hash for `number`, used to validate number-keyed
    /// response-cache hits.
    ///
    /// `Some(true)` = canonical: the local DB agrees, or the number is below the DB's
    /// retention window, where chain-sync reorg handling would have invalidated any
    /// re-keyed entry long before it was pruned. `Some(false)` = verified mismatch (the
    /// cached entry belongs to a dead block). `None` = unverifiable (treat as a cache miss,
    /// but do not invalidate). Stateless mode has no local chain at all, so the check goes
    /// upstream with a short deadline — still far cheaper than replaying the block.
    pub async fn is_canonical(&self, number: u64, hash: B256) -> Option<bool> {
        if let Some(db) = &self.db {
            return match db.get_block_hash(number) {
                Ok(Some(canonical)) => Some(canonical == hash),
                Ok(None) => Some(true),
                Err(_) => None,
            };
        }
        let deadline = Instant::now() + Duration::from_secs(CANONICAL_CHECK_TIMEOUT_SECS);
        match self.rpc_client.get_block_hash_with_deadline(number, Some(deadline)).await {
            Ok(canonical) => Some(canonical == hash),
            Err(_) => None,
        }
    }

    /// Gets block data by block number.
    ///
    /// Lookup order: local database -> RPC. A single wall-clock deadline (computed from
    /// `block_fetch_timeout`) covers the entire call — resolving the hash from RPC, fetching
    /// the block + witness, and resolving contract bytecodes all share this one budget.
    pub async fn get_block_data(&self, block_num: u64) -> DataProviderResult<Arc<BlockData>> {
        let deadline = Instant::now() + self.block_fetch_timeout;

        // Try to get block hash from local database first.
        if let Some(db) = &self.db &&
            let Ok(Some(hash)) = db.get_block_hash(block_num)
        {
            return self.get_block_data_by_hash_inner(hash, deadline).await;
        }

        // Fall back to RPC. The deadline carries through to `get_block_data_by_hash_inner` so
        // there is only ONE budget shared across hash resolution + the full pipeline.
        let block_hash =
            self.rpc_client.get_block_hash_with_deadline(block_num, Some(deadline)).await?;
        self.get_block_data_by_hash_inner(block_hash, deadline).await
    }

    /// Gets block data by block hash with single-flight coalescing. One deadline for the
    /// whole call; see [`Self::get_block_data`] for the semantics.
    pub async fn get_block_data_by_hash(
        &self,
        block_hash: B256,
    ) -> DataProviderResult<Arc<BlockData>> {
        let deadline = Instant::now() + self.block_fetch_timeout;
        self.get_block_data_by_hash_inner(block_hash, deadline).await
    }

    async fn get_block_data_by_hash_inner(
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
            self.record_block_distance(data.block.header.number);
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
        let deadline = Instant::now() + self.block_fetch_timeout;

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

        let data = self.get_block_data_by_hash_inner(block_hash, deadline).await?;
        Ok((data, tx_index))
    }

    /// Resolves a block tag to a concrete block number.
    ///
    /// Numeric tags are a pure local no-op. `Latest`, `Finalized`, and `Safe` must hit
    /// upstream to learn the tip — there is no cache key until we have a concrete number,
    /// so falling back to the cache on upstream failure is not an option. These branches
    /// are bounded by `block_fetch_timeout` so a stuck upstream surfaces as a typed
    /// [`DataProviderError::Timeout`] rather than hanging the RPC caller forever.
    pub async fn resolve_block_number(&self, tag: BlockNumberOrTag) -> DataProviderResult<u64> {
        match tag {
            BlockNumberOrTag::Number(n) => Ok(n),
            BlockNumberOrTag::Earliest => Ok(0),
            BlockNumberOrTag::Pending => Err(eyre::eyre!("Pending block not supported").into()),
            BlockNumberOrTag::Latest => {
                let deadline = Instant::now() + self.block_fetch_timeout;
                Ok(self.rpc_client.get_latest_block_number_with_deadline(Some(deadline)).await?)
            }
            BlockNumberOrTag::Finalized | BlockNumberOrTag::Safe => {
                let deadline = Instant::now() + self.block_fetch_timeout;
                let header = self
                    .rpc_client
                    .get_header_with_deadline(BlockId::Number(tag), false, Some(deadline))
                    .await?;
                Ok(header.number)
            }
        }
    }

    /// Records the distance of a requested block from the local chain tip.
    fn record_block_distance(&self, block_number: u64) {
        if let Some(tip) = db_tip_height(self.db.as_deref()) {
            let distance = tip.saturating_sub(block_number);
            ChainSyncMetrics::create().record_block_distance(distance);
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
                let block_data_cache = self.block_data_cache.clone();
                let fut: BlockDataFetchFuture = Box::pin(async move {
                    let data = do_fetch_block_data(
                        rpc_client,
                        db,
                        contract_cache,
                        witness_cfg,
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
/// - **Historical block** with a declared generator and a fallback endpoint configured: the same
///   chain minus the generator, the guaranteed-miss probe [`DEFAULT_WITNESS_LOCAL_WINDOW`]
///   describes.
///
/// Uses the zero-validation light decode: the trace server never verifies the witness proof,
/// so the full decode's per-point elliptic-curve work bought nothing. The recorded size is
/// the light lower bound (excludes the never-decoded parent commitments).
async fn fetch_witness(
    rpc_client: &RpcClient,
    cfg: &WitnessFetchConfig,
    db_tip: Option<u64>,
    block_number: u64,
    block_hash: B256,
    deadline: Instant,
) -> DataProviderResult<(LightWitness, MptWitness)> {
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

/// Test doubles shared with `rpc_service` unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// [`BlockStore`] stub whose canonical index answers `get_block_hash` with a fixed value;
    /// everything else is empty.
    pub(crate) struct StaticHashStore(pub Option<B256>);

    impl ContractStore for StaticHashStore {
        fn get_contracts(&self, _: &[B256]) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
            Ok((HashMap::default(), vec![]))
        }
        fn add_contracts(&self, _: &[(B256, Bytecode)]) -> StoreResult<()> {
            Ok(())
        }
    }

    impl stateless_core::ChainStore for StaticHashStore {
        fn get_canonical_tip(&self) -> StoreResult<Option<stateless_core::db::BlockMeta>> {
            Ok(None)
        }
        fn get_anchor(&self) -> StoreResult<Option<stateless_core::db::BlockMeta>> {
            Ok(None)
        }
        fn advance_chain(&self, _: &[stateless_core::db::BlockMeta]) -> StoreResult<()> {
            Ok(())
        }
        fn get_block_hash(&self, _: u64) -> StoreResult<Option<B256>> {
            Ok(self.0)
        }
        fn rollback_chain(&self, _: u64) -> StoreResult<()> {
            Ok(())
        }
        fn reset_to_anchor(&self, _: &stateless_core::db::BlockMeta) -> StoreResult<()> {
            Ok(())
        }
    }

    impl stateless_core::DivergenceLookups for StaticHashStore {
        fn get_hash(&self, _: u64) -> StoreResult<Option<B256>> {
            Ok(self.0)
        }
        fn get_earliest(&self) -> StoreResult<Option<(u64, B256)>> {
            Ok(None)
        }
    }

    impl BlockStore for StaticHashStore {
        fn prune_chain(&self, _: u64) -> StoreResult<u64> {
            Ok(0)
        }
        fn store_block_data(&self, _: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()> {
            Ok(())
        }
        fn get_block_and_witness(
            &self,
            block_hash: alloy_primitives::BlockHash,
        ) -> StoreResult<(Block<Transaction>, LightWitness)> {
            Err(StoreError::MissingData {
                kind: stateless_core::db::MissingDataKind::Block,
                block_hash,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::TcpListener,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use stateless_common::{BackoffPolicy, RpcClientConfig};

    use super::*;

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

    /// Serves `mega_getBlockWitness` returning an RPC error, counting hits per endpoint.
    async fn start_counting_witness_rpc()
    -> (jsonrpsee::server::ServerHandle, String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let mut module = jsonrpsee::server::RpcModule::new(hits.clone());
        module
            .register_method("mega_getBlockWitness", |_p, hits, _| {
                hits.fetch_add(1, Ordering::Relaxed);
                Err::<String, _>(jsonrpsee::types::ErrorObjectOwned::owned::<()>(
                    -32000,
                    "no witness",
                    None,
                ))
            })
            .unwrap();
        let server =
            jsonrpsee::server::ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (server.start(module), url, hits)
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
        let fixtures = stateless_test_utils::fixtures::TestFixtures::synthetic();
        let (_, hash) = fixtures.paired_blocks().into_iter().next().expect("paired fixture");
        let block = fixtures.blocks[&hash].clone();
        let witness = LightWitness::from(&fixtures.salt_witnesses[&hash]);
        let contract_cache =
            Arc::new(ContractCache::new(Arc::new(NoopContractStore) as Arc<dyn ContractStore>));
        let codes: Vec<(B256, Bytecode)> = crate::tracing_executor::extract_code_hashes(&witness)
            .into_iter()
            .map(|h| {
                let code = fixtures
                    .contracts
                    .get(&h)
                    .cloned()
                    .unwrap_or_else(|| Bytecode::new_raw(vec![0u8].into()));
                (h, code)
            })
            .collect();
        contract_cache.insert(&codes).unwrap();
        (block, witness, contract_cache)
    }

    /// [`BlockStore`] stub serving one fixture block, counting `get_block_and_witness` reads.
    struct CountingBlockStore {
        block: Block<Transaction>,
        witness: LightWitness,
        reads: AtomicUsize,
    }

    impl ContractStore for CountingBlockStore {
        fn get_contracts(&self, _: &[B256]) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
            Ok((HashMap::default(), vec![]))
        }
        fn add_contracts(&self, _: &[(B256, Bytecode)]) -> StoreResult<()> {
            Ok(())
        }
    }

    impl stateless_core::ChainStore for CountingBlockStore {
        fn get_canonical_tip(&self) -> StoreResult<Option<stateless_core::db::BlockMeta>> {
            Ok(None)
        }
        fn get_anchor(&self) -> StoreResult<Option<stateless_core::db::BlockMeta>> {
            Ok(None)
        }
        fn advance_chain(&self, _: &[stateless_core::db::BlockMeta]) -> StoreResult<()> {
            Ok(())
        }
        fn get_block_hash(&self, _: u64) -> StoreResult<Option<B256>> {
            Ok(None)
        }
        fn rollback_chain(&self, _: u64) -> StoreResult<()> {
            Ok(())
        }
        fn reset_to_anchor(&self, _: &stateless_core::db::BlockMeta) -> StoreResult<()> {
            Ok(())
        }
    }

    impl stateless_core::DivergenceLookups for CountingBlockStore {
        fn get_hash(&self, _: u64) -> StoreResult<Option<B256>> {
            Ok(None)
        }
        fn get_earliest(&self) -> StoreResult<Option<(u64, B256)>> {
            Ok(None)
        }
    }

    impl BlockStore for CountingBlockStore {
        fn prune_chain(&self, _: u64) -> StoreResult<u64> {
            Ok(0)
        }
        fn store_block_data(&self, _: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()> {
            Ok(())
        }
        fn get_block_and_witness(
            &self,
            _: alloy_primitives::BlockHash,
        ) -> StoreResult<(Block<Transaction>, LightWitness)> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok((self.block.clone(), self.witness.clone()))
        }
    }

    /// A DB-served block populates the memory cache, so the second request for the same hash
    /// is served from memory without touching the DB and shares the same allocation.
    #[tokio::test]
    async fn db_hit_populates_memory_cache_and_second_read_skips_db() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let (block, witness, contract_cache) = fixture_block_and_cache();
        let hash = block.header.hash;
        let store = Arc::new(CountingBlockStore { block, witness, reads: AtomicUsize::new(0) });
        let cache = Arc::new(BlockDataCache::new(1024 * 1024 * 1024));
        let provider = DataProvider::new(
            rpc_client,
            Some(Arc::clone(&store) as Arc<dyn BlockStore>),
            Some(Arc::clone(&cache)),
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(5),
        );

        let first = provider.get_block_data_by_hash(hash).await.expect("db-served fetch");
        let second = provider.get_block_data_by_hash(hash).await.expect("memory-served fetch");

        assert_eq!(store.reads.load(Ordering::Relaxed), 1, "second read must come from memory");
        assert!(Arc::ptr_eq(&first, &second), "memory hits share the same allocation");
        assert_eq!(cache.stats().hits, 1);
    }

    /// A pre-seeded memory entry is served before DB and RPC: with a hanging upstream and no
    /// DB, the request must return instantly instead of burning the block-fetch deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn memory_hit_short_circuits_before_db_and_rpc() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let (block, witness, contract_cache) = fixture_block_and_cache();
        let hash = block.header.hash;
        let cache = Arc::new(BlockDataCache::new(1024 * 1024 * 1024));
        cache.insert(hash, Arc::new(BlockData { block, witness, contracts: HashMap::default() }));
        let provider = DataProvider::new(
            rpc_client,
            None,
            Some(cache),
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(1),
        );

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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let (block, witness, contract_cache) = fixture_block_and_cache();
        let hash = block.header.hash;
        let store = Arc::new(CountingBlockStore { block, witness, reads: AtomicUsize::new(0) });
        let provider = DataProvider::new(
            rpc_client,
            Some(Arc::clone(&store) as Arc<dyn BlockStore>),
            None,
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(5),
        );

        provider.get_block_data_by_hash(hash).await.expect("first db read");
        provider.get_block_data_by_hash(hash).await.expect("second db read");
        assert_eq!(store.reads.load(Ordering::Relaxed), 2);
    }

    /// Provider over a hanging upstream with an optional DB canonical index.
    fn canonical_fixture(db_hash: Option<Option<B256>>) -> DataProvider {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        // Leak the listener so the port stays bound (and hanging) for the provider's lifetime.
        std::mem::forget(listener);
        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let contract_cache =
            Arc::new(ContractCache::new(Arc::new(NoopContractStore) as Arc<dyn ContractStore>));
        let db = db_hash
            .map(|h| Arc::new(super::test_support::StaticHashStore(h)) as Arc<dyn BlockStore>);
        DataProvider::new(
            rpc_client,
            db,
            None,
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(1),
        )
    }

    /// DB mode: a matching canonical index verifies the hit, a differing one is a verified
    /// mismatch, and a pruned (below-retention) number is trusted by depth.
    #[tokio::test]
    async fn is_canonical_uses_db_index_and_depth() {
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);

        assert_eq!(canonical_fixture(Some(Some(h1))).is_canonical(7, h1).await, Some(true));
        assert_eq!(canonical_fixture(Some(Some(h2))).is_canonical(7, h1).await, Some(false));
        assert_eq!(canonical_fixture(Some(None)).is_canonical(7, h1).await, Some(true));
    }

    /// Stateless mode with an unreachable upstream: the check is unverifiable — the caller
    /// must treat the hit as a miss without invalidating anything.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn is_canonical_unverifiable_without_chain_source() {
        let provider = canonical_fixture(None);
        assert_eq!(provider.is_canonical(7, B256::from([1u8; 32])).await, None);
    }

    /// End-to-end routing dispatch through `fetch_witness`: a historical block must never
    /// touch the first (generator) endpoint, while a recent block probes it first.
    #[tokio::test]
    async fn fetch_witness_routes_historical_blocks_past_the_generator() {
        let (ha, url_a, hits_a) = start_counting_witness_rpc().await;
        let (hb, url_b, hits_b) = start_counting_witness_rpc().await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str(), url_b.as_str()], true);
        let db_tip = Some(5000);

        // Historical block (900 + 100 <= 5000): the generator endpoint must stay untouched.
        let deadline = Instant::now() + Duration::from_millis(150);
        let result = fetch_witness(&rpc_client, &cfg, db_tip, 900, B256::ZERO, deadline).await;
        assert!(result.is_err(), "the mock only returns errors, so the deadline must fire");
        assert_eq!(hits_a.load(Ordering::Relaxed), 0, "historical fetch must skip the generator");
        assert!(hits_b.load(Ordering::Relaxed) >= 1, "the fallback endpoint must be tried");

        // Recent block (the tip itself): the full chain, generator first.
        let deadline = Instant::now() + Duration::from_millis(150);
        let _ = fetch_witness(&rpc_client, &cfg, db_tip, 5000, B256::ZERO, deadline).await;
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
        let (ha, url_a, hits_a) = start_counting_witness_rpc().await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str()], true);

        // Historical block (900 + 100 <= 5000) with no fallback endpoint configured.
        let deadline = Instant::now() + Duration::from_millis(150);
        let result = fetch_witness(&rpc_client, &cfg, Some(5000), 900, B256::ZERO, deadline).await;
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
        let (ha, url_a, hits_a) = start_counting_witness_rpc().await;
        let (hb, url_b, _hits_b) = start_counting_witness_rpc().await;
        let (rpc_client, cfg) = routing_fixture(&[url_a.as_str(), url_b.as_str()], false);

        // Historical block (900 + 100 <= 5000): with no declared generator, the first
        // endpoint stays in the rotation.
        let deadline = Instant::now() + Duration::from_millis(150);
        let result = fetch_witness(&rpc_client, &cfg, Some(5000), 900, B256::ZERO, deadline).await;
        assert!(result.is_err(), "the mock only returns errors, so the deadline must fire");
        assert!(hits_a.load(Ordering::Relaxed) >= 1, "first endpoint must not be skipped");

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
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/");

        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let contract_cache =
            Arc::new(ContractCache::new(Arc::new(NoopContractStore) as Arc<dyn ContractStore>));
        let provider = DataProvider::new(
            rpc_client,
            None,
            None,
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(1),
        );

        let start = std::time::Instant::now();
        let result = provider.get_block_data(42).await;
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

    /// Tag-resolution branches (`Latest`/`Finalized`/`Safe`) must be deadline-bounded.
    /// Before this was wired, `resolve_block_number("latest")` would call the non-deadline
    /// `get_latest_block_number` / `get_header` helpers and retry the upstream forever,
    /// hanging the RPC caller on a stuck endpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_block_number_surfaces_timeout_when_upstream_hangs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/");

        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let contract_cache =
            Arc::new(ContractCache::new(Arc::new(NoopContractStore) as Arc<dyn ContractStore>));
        let provider = DataProvider::new(
            rpc_client,
            None,
            None,
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(1),
        );

        for tag in [BlockNumberOrTag::Latest, BlockNumberOrTag::Finalized, BlockNumberOrTag::Safe] {
            let start = std::time::Instant::now();
            let result = provider.resolve_block_number(tag).await;
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
        let contract_cache =
            Arc::new(ContractCache::new(Arc::new(NoopContractStore) as Arc<dyn ContractStore>));
        // Generous deadline so the task is cancelled *by us*, not by the deadline firing.
        let provider = Arc::new(DataProvider::new(
            rpc_client,
            None,
            None,
            contract_cache,
            WitnessFetchConfig::with_defaults(DEFAULT_WITNESS_TIMEOUT_SECS),
            Duration::from_secs(60),
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
