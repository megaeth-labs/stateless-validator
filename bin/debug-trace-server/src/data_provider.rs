//! Data Provider for Block Data Fetching
//!
//! This module provides a data provider that fetches block data required by the
//! debug/trace RPC methods from multiple sources:
//!
//! 1. **Local Database** (fast) - Local DB for pre-fetched blocks (if configured)
//! 2. **Remote RPC** (slower) - Upstream RPC endpoints as fallback
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
use salt::SaltWitness;
use stateless_common::{CodeFetchError, RpcClient, RpcDeadlineExceeded, estimate_witness_size};
use stateless_core::{
    BlockStore, ContractStore, LightWitness, StoreResult, db::StoreError, withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use tracing::{debug, instrument, trace, warn};

use crate::metrics::{
    ChainSyncMetrics, DataSourceMetrics, SingleFlightMetrics, WitnessSourceMetrics,
};

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
    /// Values share allocations with the `ContractCache`.
    pub contracts: HashMap<B256, Arc<Bytecode>>,
}

/// Default timeout for a user-facing witness fetch in seconds (8 seconds).
///
/// Applied as a sub-deadline on top of the outer block-fetch deadline: the witness stage
/// gets `min(block_deadline, now + witness_timeout)`. Covers the "block is near the tip and
/// the witness is still being generated upstream" case where a few seconds of waiting is
/// normal.
pub const DEFAULT_WITNESS_TIMEOUT_SECS: u64 = 8;

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
/// 1. Check local database (if configured)
/// 2. Fetch from remote RPC endpoints (multi-provider fallback handled by `RpcClient`)
///
/// # Single-Flight Pattern
/// When multiple requests arrive for the same block simultaneously, only one
/// RPC call is made. Other requests subscribe to the result via broadcast channel.
pub(crate) struct DataProvider {
    /// RPC client for upstream data fetching (handles multi-endpoint fallback internally).
    rpc_client: Arc<RpcClient>,
    /// Optional local database for pre-fetched blocks (trait object).
    db: Option<Arc<dyn BlockStore>>,
    /// In-memory contract bytecode cache backed by either `ServerDB` (local-cache mode)
    /// or [`NoopContractStore`] (stateless mode).
    /// Every contract read and every RPC-fetched contract goes through here, so
    /// repeated trace requests for the same contract hit memory instead of
    /// redb (slow) or RPC (slowest).
    contract_cache: Arc<ContractCache>,
    /// Sub-deadline applied to the witness stage only. The full-call deadline still
    /// dominates; this caps how long the witness fetch can burn out of that budget.
    witness_timeout: Duration,
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
    /// * `contract_cache` - Shared in-memory contract cache (backed by the DB when present, or an
    ///   in-memory-only noop store in stateless mode)
    /// * `witness_timeout_secs` - User-facing cap on a single witness fetch, in seconds
    /// * `block_fetch_timeout_secs` - User-facing cap on the full block-fetch pipeline (header +
    ///   witness + block + contracts), in seconds
    pub fn new(
        rpc_client: Arc<RpcClient>,
        db: Option<Arc<dyn BlockStore>>,
        contract_cache: Arc<ContractCache>,
        witness_timeout_secs: u64,
        block_fetch_timeout_secs: u64,
    ) -> Self {
        Self {
            rpc_client,
            db,
            contract_cache,
            witness_timeout: Duration::from_secs(witness_timeout_secs),
            block_fetch_timeout: Duration::from_secs(block_fetch_timeout_secs),
            in_flight: DashMap::new(),
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

        // Try the local DB first. `Ok(None)` = "not in DB, fall through"; `Err(..)` surfaces
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
            return Ok(Arc::new(data));
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
        if let Some(db) = &self.db &&
            let Ok(Some(tip)) = db.get_canonical_tip()
        {
            let distance = tip.block_number.saturating_sub(block_number);
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
                let witness_timeout = self.witness_timeout;
                let fut: BlockDataFetchFuture = Box::pin(async move {
                    do_fetch_block_data(
                        rpc_client,
                        db,
                        contract_cache,
                        witness_timeout,
                        block_hash,
                        deadline,
                    )
                    .await
                    .map(Arc::new)
                    .map_err(Arc::new)
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
    ) -> DataProviderResult<HashMap<B256, Arc<Bytecode>>> {
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
/// 3. Convert SaltWitness to LightWitness.
/// 4. Extract code hashes from witness and fetch contract bytecodes (shares `deadline`).
async fn do_fetch_block_data(
    rpc_client: Arc<RpcClient>,
    db: Option<Arc<dyn BlockStore>>,
    contract_cache: Arc<ContractCache>,
    witness_timeout: Duration,
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
    // and full-block fetches in parallel.
    let witness_deadline =
        witness_deadline_for(db.as_deref(), block_number, witness_timeout, deadline);
    let (witness_timed, block_timed) = tokio::join!(
        async {
            let start = Instant::now();
            let result =
                fetch_witness(&rpc_client, block_number, header.hash, witness_deadline).await;
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
    let (salt_witness, _mpt_witness) = witness_result?;
    let block = block_result?;
    let fetch_full_block_ms = block_elapsed.as_millis();

    // Step 3: Convert SaltWitness to LightWitness.
    let start = Instant::now();
    let witness = LightWitness::from(&salt_witness);
    let convert_witness_ms = start.elapsed().as_millis();

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
        convert_witness_ms >= SLOW_STAGE_THRESHOLD_MS ||
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
            convert_witness_ms = convert_witness_ms as u64,
            fetch_full_block_ms = fetch_full_block_ms as u64,
            fetch_contracts_ms = fetch_contracts_ms as u64,
            total_ms = total_ms as u64,
            "do_fetch_block_data slow stages detected"
        );
    }

    Ok(BlockData { block, witness, contracts })
}

/// Picks the effective deadline for a witness fetch.
///
/// - **New block** (above local tip or no local DB): full `witness_timeout` sub-deadline, clamped
///   by the outer call deadline. Covers "witness still being generated upstream".
/// - **Old / pruned block** (at or below local tip): tightened to `OLD_BLOCK_WITNESS_TIMEOUT` (≤
///   witness_timeout) because witness data for such blocks is either available immediately or not
///   at all; burning the full witness_timeout on a pruned block is a bad tradeoff.
fn witness_deadline_for(
    db: Option<&dyn BlockStore>,
    block_number: u64,
    witness_timeout: Duration,
    outer_deadline: Instant,
) -> Instant {
    /// Cap on witness fetches for blocks at or below the local tip.
    ///
    /// Sized against the default [`BackoffPolicy`](stateless_common::BackoffPolicy)
    /// (`initial = 500 ms`, 2× doubling): 500 ms + 1 s + 2 s ≈ 3.5 s, so 3 s lets
    /// every provider be probed across ~2–3 rounds before we fail.
    const OLD_BLOCK_WITNESS_TIMEOUT: Duration = Duration::from_secs(3);

    let db_max_height =
        db.and_then(|db| db.get_canonical_tip().ok().flatten().map(|tip| tip.block_number));
    let is_new_block = db_max_height.is_none_or(|max| block_number > max);
    let budget =
        if is_new_block { witness_timeout } else { witness_timeout.min(OLD_BLOCK_WITNESS_TIMEOUT) };
    let stage_deadline = Instant::now() + budget;
    trace!(
        block_number,
        db_max_height,
        is_new_block,
        budget_ms = budget.as_millis() as u64,
        "Computed witness stage deadline",
    );
    stage_deadline.min(outer_deadline)
}

/// Fetches witness data via the deadline-aware `RpcClient` API. The `deadline` is the
/// witness stage's effective deadline (see [`witness_deadline_for`]).
async fn fetch_witness(
    rpc_client: &RpcClient,
    block_number: u64,
    block_hash: B256,
    deadline: Instant,
) -> DataProviderResult<(SaltWitness, MptWitness)> {
    let wg_metrics = WitnessSourceMetrics::new_for_source("witness_generator");
    let start = Instant::now();

    match rpc_client.get_witness_with_deadline(block_number, block_hash, Some(deadline)).await {
        Ok(w) => {
            wg_metrics.record_request(true, start.elapsed().as_secs_f64());
            wg_metrics.record_size(estimate_witness_size(&w.0, &w.1));
            DataSourceMetrics::new_for_source("witness_generator").record();
            Ok(w)
        }
        Err(e) => {
            wg_metrics.record_request(false, start.elapsed().as_secs_f64());
            warn!(
                block_number,
                block_hash = %block_hash,
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
) -> DataProviderResult<HashMap<B256, Arc<Bytecode>>> {
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

    // Per-attempt `eth_getCodeByHash` metrics land on `UpstreamMetrics` via the
    // `TraceRpcMetrics` adapter inside `round_robin_with_backoff`.
    let fetched = rpc_client.get_codes_with_deadline(&missing, true, Some(deadline)).await?;

    let new_contracts: Vec<(B256, Arc<Bytecode>)> = fetched.into_iter().collect();

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
    fn get_contracts(
        &self,
        hashes: &[B256],
    ) -> StoreResult<(HashMap<B256, Arc<Bytecode>>, Vec<B256>)> {
        Ok((HashMap::default(), hashes.to_vec()))
    }

    fn add_contracts(&self, _codes: &[(B256, Arc<Bytecode>)]) -> StoreResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use stateless_common::RpcClientConfig;

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
            contract_cache,
            DEFAULT_WITNESS_TIMEOUT_SECS,
            1, // 1-second block fetch timeout
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
            contract_cache,
            DEFAULT_WITNESS_TIMEOUT_SECS,
            1, // 1-second block fetch timeout
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
            contract_cache,
            DEFAULT_WITNESS_TIMEOUT_SECS,
            60,
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
