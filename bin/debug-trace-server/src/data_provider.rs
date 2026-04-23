//! Data Provider for Block Data Fetching
//!
//! This module provides a data provider that fetches block data required by the
//! debug/trace RPC methods from multiple sources:
//!
//! 1. **Local Database** (fast) - Local DB for pre-fetched blocks (if configured)
//! 2. **Remote RPC** (slower) - Upstream RPC endpoints as fallback
//!
//! # Features
//! - **Single-flight request coalescing**: Multiple callers for the same block hash share one
//!   fetch; the result is handed out as `Arc<BlockData>` so the hot path is a refcount bump, not a
//!   deep clone.
//! - **Witness fetch timeout**: caps the user-facing wait on the RPC client's internal retry loop
//!   so an RPC request never hangs indefinitely.
//! - **Contract bytecode resolution**: checks [`ContractCache`] (memory → redb), falls back to a
//!   parallel + verified `RpcClient::get_codes` fetch on miss.
//!
//! # Note
//! Response caching is handled at the HTTP layer by `ResponseCache`, not here.

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy_primitives::B256;
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use dashmap::DashMap;
use eyre::Result;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;
use stateless_common::{RpcClient, estimate_witness_size};
use stateless_core::{
    BlockStore, ContractStore, LightWitness, StoreResult, db::StoreError, withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use tokio::sync::broadcast;
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
/// Caps how long `fetch_witness_with_fallback` will wait for the RPC client's internal
/// round-level retry loop to produce a witness. A user's trace/debug RPC request times out
/// with an error if this elapses.
pub const DEFAULT_WITNESS_TIMEOUT_SECS: u64 = 8;

/// Default timeout for the full block-fetch pipeline (header + witness + block + contracts)
/// in seconds (13 seconds).
///
/// Caps how long a user-facing trace/debug request waits on `RpcClient`'s unbounded
/// round-robin + exponential backoff retry loop. Without this, a request for a block that
/// doesn't exist upstream (e.g. a future block number, or a mistyped hash) would hang
/// indefinitely, holding a concurrency permit. Sits between the 4th retry's max-jitter
/// sleep completion (~11.25 s — cumulative 500 ms → 1 s → 2 s → 4 s with jitter) and the
/// 5th retry's min-jitter sleep completion (~15.5 s), so ~4 backoff rounds run before the
/// timeout fires. Stays above `DEFAULT_WITNESS_TIMEOUT_SECS` so the inner witness timeout
/// still fires first for legitimate near-tip witness-generation waits.
///
/// **Note on the number-lookup path.** [`DataProvider::get_block_data`] (by number) applies
/// this timeout twice on the RPC path: once around `get_block_hash(num)` to resolve the
/// hash, then again around the full pipeline inside `get_block_data_by_hash`. Worst-case
/// wall-clock budget there is `2 × block_fetch_timeout`. The hash-keyed entry point
/// [`DataProvider::get_block_data_by_hash`] applies it once.
pub const DEFAULT_BLOCK_FETCH_TIMEOUT_SECS: u64 = 13;

/// Slow stage threshold: any individual stage exceeding this triggers a warn log.
pub(crate) const SLOW_STAGE_THRESHOLD_MS: u128 = 1000;

/// Errors returned by [`DataProvider`]'s user-facing fetch methods.
///
/// The enum classifies up-front so the RPC layer can map variants to JSON-RPC error codes
/// without string-matching. `Internal` is the catch-all for transport / decode / DB errors;
/// everything else is a deterministic "not found" or a timeout caused by `RpcClient`'s
/// unbounded retry loop.
#[derive(Debug, thiserror::Error)]
pub enum DataProviderError {
    #[error("transaction {0} not found")]
    TransactionNotFound(B256),
    #[error("transaction {0} is pending")]
    TransactionPending(B256),
    #[error("witness fetch timed out after {0:?}")]
    WitnessTimeout(Duration),
    #[error("block fetch timed out after {0:?}")]
    BlockFetchTimeout(Duration),
    #[error(transparent)]
    Internal(#[from] eyre::Error),
}

impl DataProviderError {
    /// Converts into a JSON-RPC error. Everything that could plausibly be a client mistake
    /// (tx / pending / timeouts while `RpcClient`'s unbounded retry loop can't satisfy the
    /// request) maps to `-32001 resource not found` so operators see a consistent response
    /// for the hot-path "block doesn't exist upstream" and "upstream is slow" cases.
    /// Genuine internal failures fall through to `-32000`.
    pub fn to_rpc_error(&self) -> jsonrpsee::types::ErrorObjectOwned {
        use jsonrpsee::types::ErrorObjectOwned;
        const NOT_FOUND: i32 = -32001;
        const INTERNAL: i32 = -32000;
        match self {
            DataProviderError::TransactionNotFound(_) |
            DataProviderError::TransactionPending(_) |
            DataProviderError::WitnessTimeout(_) |
            DataProviderError::BlockFetchTimeout(_) => {
                ErrorObjectOwned::owned(NOT_FOUND, self.to_string(), None::<()>)
            }
            DataProviderError::Internal(_) => {
                ErrorObjectOwned::owned(INTERNAL, "internal error".to_string(), None::<()>)
            }
        }
    }
}

/// Result alias for [`DataProvider`] fetch methods.
pub type DataProviderResult<T> = std::result::Result<T, DataProviderError>;

/// Broadcast sender type for single-flight request pattern.
/// Used to notify all waiters when a block fetch completes.
///
/// `Arc<BlockData>` rather than `BlockData` so coalesced waiters share one allocation
/// — the value carries a full block, witness, and contract map.
type InFlightSender = broadcast::Sender<Result<Arc<BlockData>, String>>;

/// RAII cleanup guard for the single-flight `in_flight` map.
///
/// On a normal path, [`fetch_block_data_single_flight`] does an explicit
/// `remove-before-send` (see the block comment there for why order matters) and
/// calls [`Self::disarm`] so this guard becomes a no-op. On any early exit —
/// panic in the fetch future, `.await` cancellation, etc. — the guard fires and
/// removes the stale entry so future callers for the same block hash don't
/// subscribe to a dead broadcast sender.
///
/// [`fetch_block_data_single_flight`]: DataProvider::fetch_block_data_single_flight
struct InFlightGuard<'a> {
    map: &'a DashMap<B256, InFlightSender>,
    key: B256,
    armed: bool,
}

impl<'a> InFlightGuard<'a> {
    fn new(map: &'a DashMap<B256, InFlightSender>, key: B256) -> Self {
        Self { map, key, armed: true }
    }

    /// Consumes the guard without removing the entry. Call after an explicit
    /// `map.remove(&key)` on the happy path.
    fn disarm(mut self) {
        self.armed = false;
        // `self` drops here; `Drop::drop` sees `armed = false` and is a no-op.
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.map.remove(&self.key);
        }
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
    /// User-facing cap on witness fetches (the RPC client retries internally).
    witness_timeout: Duration,
    /// User-facing cap on the full block-fetch pipeline (including witness, block, contracts).
    /// Bounds `RpcClient`'s unbounded retry loop so deterministic "not found" errors surface
    /// instead of hanging the caller and holding a concurrency permit.
    block_fetch_timeout: Duration,
    /// In-flight requests map for single-flight pattern (keyed by block hash).
    in_flight: DashMap<B256, InFlightSender>,
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
    /// Lookup order: local database -> RPC.
    ///
    /// # Arguments
    /// * `block_num` - The block number to fetch
    ///
    /// # Returns
    /// * `Ok(Arc<BlockData>)` - Block data including witness and contracts
    /// * `Err(DataProviderError)` - Typed error variant describing the failure mode
    pub async fn get_block_data(&self, block_num: u64) -> DataProviderResult<Arc<BlockData>> {
        // Try to get block hash from local database first
        if let Some(db) = &self.db &&
            let Ok(Some(hash)) = db.get_block_hash(block_num)
        {
            return self.get_block_data_by_hash(hash).await;
        }

        // Fall back to RPC. The underlying `get_block_hash` retries unbounded; bound it with
        // `block_fetch_timeout` so a future/invalid block number surfaces as a typed timeout
        // rather than hanging the caller.
        let block_hash = tokio::time::timeout(
            self.block_fetch_timeout,
            self.rpc_client.get_block_hash(block_num),
        )
        .await
        .map_err(|_| DataProviderError::BlockFetchTimeout(self.block_fetch_timeout))?;

        self.get_block_data_by_hash(block_hash).await
    }

    /// Gets block data by block hash with single-flight coalescing.
    ///
    /// Lookup order: local database -> RPC.
    ///
    /// # Arguments
    /// * `block_hash` - The 32-byte block hash to fetch
    ///
    /// # Returns
    /// * `Ok(Arc<BlockData>)` - Block data including witness and contracts
    /// * `Err` - If the block cannot be fetched from any source
    pub async fn get_block_data_by_hash(
        &self,
        block_hash: B256,
    ) -> DataProviderResult<Arc<BlockData>> {
        let start = std::time::Instant::now();

        // Try the local DB first. Only `MissingData` falls through to RPC silently —
        // real backend errors (redb I/O, decode corruption) must surface in the log,
        // even though we still fall through so the request isn't lost.
        if let Some(db) = &self.db {
            match self.get_block_data_from_db(db.as_ref(), block_hash).await {
                Ok(data) => {
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
                Err(e) => match e.downcast_ref::<StoreError>() {
                    Some(StoreError::MissingData { .. }) => {
                        // expected cache miss; fall through to RPC
                    }
                    _ => {
                        warn!(
                            block_hash = %block_hash,
                            error = %e,
                            "Local DB read failed; falling back to RPC",
                        );
                    }
                },
            }
        }

        // Fall back to RPC
        trace!(
            block_hash = %block_hash,
            source = "rpc",
            "Fetching block data from RPC"
        );
        let data = self.fetch_block_data_by_hash_from_rpc(block_hash).await?;

        trace!(
            block_hash = %block_hash,
            source = "rpc",
            elapsed_ms = start.elapsed().as_millis() as u64,
            "Block data fetched from RPC"
        );

        self.record_block_distance(data.block.header.number);
        Ok(data)
    }

    /// Gets block data for a transaction by its hash.
    ///
    /// First fetches the transaction to find its containing block, then retrieves
    /// the full block data. Returns both the block data and the transaction's index
    /// within the block (needed for replaying preceding transactions).
    ///
    /// # Arguments
    /// * `tx_hash` - The transaction hash to look up
    ///
    /// # Returns
    /// * `Ok((Arc<BlockData>, usize))` - Block data and transaction index
    /// * `Err` - If transaction not found or is still pending
    #[instrument(skip(self), name = "get_block_data_for_tx", fields(tx_hash = %tx_hash))]
    pub async fn get_block_data_for_tx(
        &self,
        tx_hash: B256,
    ) -> DataProviderResult<(Arc<BlockData>, usize)> {
        trace!(tx_hash = %tx_hash, "Looking up transaction");

        // Fetch the transaction to find its block
        let (tx, block_hash) = self
            .rpc_client
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or(DataProviderError::TransactionNotFound(tx_hash))?;

        let tx_index =
            tx.transaction_index.ok_or(DataProviderError::TransactionPending(tx_hash))? as usize;

        debug!(
            tx_hash = %tx_hash,
            block_hash = %block_hash,
            tx_index,
            "Transaction located in block"
        );

        // Get block data
        let data = self.get_block_data_by_hash(block_hash).await?;

        Ok((data, tx_index))
    }

    /// Resolves a block tag to a concrete block number.
    ///
    /// Supports all standard block tags:
    /// - `Number(n)` - Returns the number directly
    /// - `Latest` - Returns the latest block number
    /// - `Earliest` - Returns 0 (genesis block)
    /// - `Pending` - Returns error "Pending block not supported" (consistent with mega-reth)
    /// - `Finalized` / `Safe` - Fetches the block from upstream RPC and extracts the number
    ///
    /// # Arguments
    /// * `tag` - Block number or tag (e.g., "latest", specific number)
    ///
    /// # Returns
    /// * `Ok(u64)` - The resolved block number
    /// * `Err` - If the tag is unsupported or RPC call fails
    pub async fn resolve_block_number(&self, tag: BlockNumberOrTag) -> Result<u64> {
        match tag {
            BlockNumberOrTag::Number(n) => Ok(n),
            BlockNumberOrTag::Latest => Ok(self.rpc_client.get_latest_block_number().await),
            BlockNumberOrTag::Earliest => Ok(0),
            BlockNumberOrTag::Pending => Err(eyre::eyre!("Pending block not supported")),
            BlockNumberOrTag::Finalized | BlockNumberOrTag::Safe => {
                // Fetch the header from upstream RPC to resolve the tag
                let header = self.rpc_client.get_header(BlockId::Number(tag), false).await;
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
    async fn get_block_data_from_db(
        &self,
        db: &dyn BlockStore,
        block_hash: alloy_primitives::BlockHash,
    ) -> Result<BlockData> {
        let overall_start = std::time::Instant::now();

        // Get block data from database using light witness (fast deserialization)
        let start = std::time::Instant::now();
        let (block, witness) = db.get_block_and_witness(block_hash)?;
        let db_read_secs = start.elapsed().as_secs_f64();
        let db_read_ms = start.elapsed().as_millis();

        // Record DB read duration metric
        ChainSyncMetrics::create().record_db_read(db_read_secs);

        // Extract code hashes and get contracts
        let start = std::time::Instant::now();
        let code_hashes = crate::tracing_executor::extract_code_hashes(&witness);
        let num_contracts = code_hashes.len();
        let contracts = self.resolve_contracts(&code_hashes).await?;
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

        Ok(BlockData { block, witness, contracts })
    }

    /// Fetches block data from RPC by block hash with single-flight coalescing.
    async fn fetch_block_data_by_hash_from_rpc(
        &self,
        block_hash: B256,
    ) -> DataProviderResult<Arc<BlockData>> {
        self.fetch_block_data_single_flight(block_hash).await
    }

    /// Single-flight fetch: ensures only one RPC call per block hash.
    ///
    /// When multiple requests arrive for the same block simultaneously:
    /// 1. First request creates a broadcast channel and starts the fetch
    /// 2. Subsequent requests subscribe to the channel and wait
    /// 3. When fetch completes, result is broadcast to all waiters
    ///
    /// This prevents redundant RPC calls and reduces upstream load.
    async fn fetch_block_data_single_flight(
        &self,
        block_hash: B256,
    ) -> DataProviderResult<Arc<BlockData>> {
        // Atomic check-and-insert via `entry()` — a plain `get` + `insert` sequence would
        // let two callers both observe "vacant" and each kick off their own RPC fetch.
        // Coalesced waiters receive the outcome as a `String` (errors aren't Clone) and
        // are mapped back to `DataProviderError::Internal` — the primary fetcher's
        // variant-level classification still lands on its direct caller.
        let tx = match self.in_flight.entry(block_hash) {
            dashmap::Entry::Occupied(occupied) => {
                let mut receiver = occupied.get().subscribe();
                drop(occupied);
                SingleFlightMetrics::new_for_type("coalesced").record();
                trace!(block_hash = %block_hash, "Joining existing in-flight request");
                return receiver
                    .recv()
                    .await
                    .map_err(|e| {
                        DataProviderError::Internal(eyre::eyre!(
                            "Failed to receive from in-flight request: {}",
                            e
                        ))
                    })?
                    .map_err(|e| DataProviderError::Internal(eyre::eyre!("{}", e)));
            }
            dashmap::Entry::Vacant(vacant) => {
                let (tx, _) = broadcast::channel(1);
                vacant.insert(tx.clone());
                tx
            }
        };
        SingleFlightMetrics::new_for_type("new").record();

        // RAII cleanup: if the fetch panics or is cancelled mid-flight, the guard
        // removes the stale entry so future callers don't subscribe to a dead
        // sender forever. On the normal path we disarm the guard after the
        // explicit `remove-before-send` below.
        let cleanup = InFlightGuard::new(&self.in_flight, block_hash);

        trace!(
            block_hash = %block_hash,
            "Starting new block data fetch"
        );

        // Perform the actual fetch. Cap the whole pipeline (header + witness + block + contracts)
        // with `block_fetch_timeout` so a deterministic upstream "not found" can't hang forever in
        // `RpcClient`'s unbounded round-robin retry loop. The inner `witness_timeout` still
        // applies to the witness stage specifically; this outer bound covers the header/block/
        // contract stages which have no inner timeout of their own.
        let result: DataProviderResult<Arc<BlockData>> = match tokio::time::timeout(
            self.block_fetch_timeout,
            self.do_fetch_block_data(block_hash),
        )
        .await
        {
            Ok(r) => r.map(Arc::new),
            Err(_) => Err(DataProviderError::BlockFetchTimeout(self.block_fetch_timeout)),
        };

        // Clone is an Arc refcount bump; `DataProviderError` is not Clone so errors
        // are stringified for coalesced waiters (they'll see `Internal(eyre::Error)`).
        let broadcast_result = result.as_ref().map(Arc::clone).map_err(|e| e.to_string());

        // Remove BEFORE send. `broadcast::Receiver` cursors set in `subscribe()` are
        // positioned at the channel's current tail — a subscriber that calls `subscribe()`
        // after `send()` misses the value and receives `RecvError::Closed` when the last
        // sender drops. Removing first means any late arrival in the tiny `[remove, send]`
        // window sees `Vacant` and starts its own fetch (acceptable duplicate; window is
        // a few instructions). Prior subscribers (captured before `remove`) still receive
        // the value because their cursors were established before the send.
        self.in_flight.remove(&block_hash);
        cleanup.disarm();
        let _ = tx.send(broadcast_result);

        result
    }

    /// Actually fetches block data from RPC (called by single-flight).
    ///
    /// Performs the complete fetch sequence:
    /// 1. Fetch block header (without transactions) to get block number
    /// 2. Fetch witness and full block in parallel
    /// 3. Convert SaltWitness to LightWitness
    /// 4. Extract code hashes from witness and fetch contract bytecodes
    async fn do_fetch_block_data(&self, block_hash: B256) -> DataProviderResult<BlockData> {
        let overall_start = std::time::Instant::now();
        // Per-attempt upstream RPC metrics (requests_total / errors_total / duration) are
        // now recorded inside `RpcClient::round_robin_with_backoff` via the
        // `TraceRpcMetrics` adapter wired at startup. The outer callers here used to record
        // one-shot "(true, cumulative_time)" entries which were always success under the
        // unbounded-retry design — see data_provider.rs history prior to the RpcMetrics
        // wiring for context.

        // Step 1: Fetch header first to get the block number
        let start = std::time::Instant::now();
        let header = self.rpc_client.get_header(BlockId::Hash(block_hash.into()), false).await;
        let block_number = header.number;
        let fetch_header_ms = start.elapsed().as_millis();

        // Step 2: Fetch witness and full block in parallel, timing each independently
        let (witness_timed, block_timed) = tokio::join!(
            async {
                let start = std::time::Instant::now();
                let result = self.fetch_witness_with_timeout(block_number, header.hash).await;
                (result, start.elapsed())
            },
            async {
                let start = std::time::Instant::now();
                let result =
                    self.rpc_client.get_block(BlockId::Hash(block_hash.into()), true).await;
                (result, start.elapsed())
            },
        );

        let (witness_result, witness_elapsed) = witness_timed;
        let (block, block_elapsed) = block_timed;

        let fetch_witness_ms = witness_elapsed.as_millis();
        let (salt_witness, _mpt_witness) = witness_result?;

        let fetch_full_block_ms = block_elapsed.as_millis();

        // Step 3: Convert SaltWitness to LightWitness
        let start = std::time::Instant::now();
        let witness = LightWitness::from(&salt_witness);
        let convert_witness_ms = start.elapsed().as_millis();

        // Step 4: Extract code hashes and fetch contracts
        let start = std::time::Instant::now();
        let code_hashes = crate::tracing_executor::extract_code_hashes(&witness);
        let num_contracts = code_hashes.len();
        let contracts = self.resolve_contracts(&code_hashes).await?;
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

    /// Fetches witness data with a user-facing timeout.
    ///
    /// The underlying `RpcClient::get_witness` retries transient failures forever internally;
    /// this wrapper imposes a time bound so a user-facing RPC request never hangs. On timeout
    /// the caller receives a typed [`DataProviderError::WitnessTimeout`].
    ///
    /// The timeout is selected based on whether the block is ahead of the local tip:
    ///
    /// - **New block** (above local tip or no local DB): full [`Self::witness_timeout`] applies.
    ///   This covers the "block is fresh and the witness is still being generated upstream" case
    ///   where a few seconds of waiting is normal.
    /// - **Old / pruned block** (at or below local tip): the shorter `OLD_BLOCK_WITNESS_TIMEOUT`
    ///   caps the wait. Witness data for such blocks is either available immediately or not at all;
    ///   because `get_witness` retries transient errors forever, the tight cap ensures a
    ///   pruned-block `debug_traceBlock*` returns quickly instead of burning the full
    ///   `witness_timeout`.
    async fn fetch_witness_with_timeout(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> DataProviderResult<(SaltWitness, MptWitness)> {
        /// Cap on witness fetches for blocks at or below the local tip (pruned / old
        /// upstream blocks). Tighter than [`Self::witness_timeout`] because the upstream
        /// retry loop never terminates on errors — without this bound a pruned-block
        /// trace request would wait the full `witness_timeout` before returning.
        ///
        /// Sized against the default [`BackoffPolicy`](stateless_common::BackoffPolicy)
        /// (`initial = 500 ms`, 2× doubling): 500 ms + 1 s + 2 s ≈ 3.5 s, so 3 s lets
        /// every provider be probed across ~2–3 rounds before we fail. If the policy
        /// defaults change, revisit this value so the cap still allows at least one
        /// full round of probes.
        const OLD_BLOCK_WITNESS_TIMEOUT: Duration = Duration::from_secs(3);

        let db_max_height = self
            .db
            .as_ref()
            .and_then(|db| db.get_canonical_tip().ok().flatten().map(|tip| tip.block_number));
        let is_new_block = db_max_height.is_none_or(|max| block_number > max);
        let effective_timeout = if is_new_block {
            self.witness_timeout
        } else {
            self.witness_timeout.min(OLD_BLOCK_WITNESS_TIMEOUT)
        };
        trace!(
            block_number,
            db_max_height,
            is_new_block,
            timeout_ms = effective_timeout.as_millis() as u64,
            "Fetching witness",
        );

        let wg_metrics = WitnessSourceMetrics::new_for_source("witness_generator");
        let start = std::time::Instant::now();

        let result = tokio::time::timeout(
            effective_timeout,
            self.rpc_client.get_witness(block_number, block_hash),
        )
        .await;

        match result {
            Ok(w) => {
                wg_metrics.record_request(true, start.elapsed().as_secs_f64());
                wg_metrics.record_size(estimate_witness_size(&w.0, &w.1));
                DataSourceMetrics::new_for_source("witness_generator").record();
                Ok(w)
            }
            Err(_) => {
                wg_metrics.record_request(false, start.elapsed().as_secs_f64());
                warn!(
                    block_number,
                    block_hash = %block_hash,
                    timeout_ms = effective_timeout.as_millis() as u64,
                    is_new_block,
                    "Witness fetch timeout",
                );
                Err(DataProviderError::WitnessTimeout(effective_timeout))
            }
        }
    }

    /// Resolves contract bytecodes via the three-tier cache chain:
    /// memory (`ContractCache`) → persistent store (`ServerDB` in local-cache mode,
    /// [`NoopContractStore`] in stateless mode) → upstream RPC.
    ///
    /// The RPC tier goes through `RpcClient::get_codes(..., verify=true)` — parallel
    /// fetch plus hash verification in one place. Entries promoted through the cache
    /// are trusted on subsequent hits (no re-verification).
    async fn resolve_contracts(
        &self,
        code_hashes: &[B256],
    ) -> Result<HashMap<B256, Arc<Bytecode>>> {
        let (mut contracts, missing) = self.contract_cache.get(code_hashes)?;

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
        // `TraceRpcMetrics` adapter inside `round_robin_with_backoff`. Recording
        // another `(result.is_ok(), ...)` here on the same label would double-count the
        // per-hash attempts. A batch-level `CodeFetchError::VerificationFailure` is
        // rare (signals a bad upstream / bad witness); if we need a dedicated metric
        // for it, add a new counter rather than reusing the per-attempt histogram.
        let fetched = self.rpc_client.get_codes(&missing, true).await?;

        let new_contracts: Vec<(B256, Arc<Bytecode>)> = fetched.into_iter().collect();

        // Write-through: memory always, disk in local-cache mode.
        // We don't fail the trace on cache-insert errors; the request has already been served.
        if let Err(e) = self.contract_cache.insert(&new_contracts) {
            warn!(error = %e, count = new_contracts.len(), "Failed to persist fetched contracts to cache");
        }

        contracts.extend(new_contracts);
        Ok(contracts)
    }
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
        Ok((HashMap::new(), hashes.to_vec()))
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

    /// Compile-time trait bounds + timeout constants. Collapses the former
    /// `test_block_data_clone`, `test_in_flight_sender_type`, `test_data_provider_struct_fields`,
    /// `test_default_witness_timeout`, and `test_duration_from_secs` into one test.
    #[test]
    fn type_bounds_and_timeout_constants() {
        fn _assert_clone<T: Clone + Send + Sync>() {}
        fn _assert_sync<T: Send + Sync>() {}
        // BlockData is intentionally not Clone — callers share it via `Arc<BlockData>`.
        _assert_sync::<BlockData>();
        _assert_clone::<InFlightSender>();
        _assert_clone::<Arc<RpcClient>>();
        _assert_clone::<Option<Arc<dyn BlockStore>>>();
        _assert_clone::<DashMap<B256, InFlightSender>>();

        assert_eq!(DEFAULT_WITNESS_TIMEOUT_SECS, 8);
        assert_eq!(Duration::from_secs(DEFAULT_WITNESS_TIMEOUT_SECS).as_millis(), 8000);
    }

    /// Dropping an armed `InFlightGuard` removes the entry — the panic/cancellation path.
    #[test]
    fn inflight_guard_removes_entry_on_drop() {
        let map: DashMap<B256, InFlightSender> = DashMap::new();
        let key = B256::from([0x42; 32]);
        let (tx, _) = broadcast::channel::<Result<Arc<BlockData>, String>>(1);
        map.insert(key, tx);

        {
            let _guard = InFlightGuard::new(&map, key);
            assert!(map.contains_key(&key), "entry present while guard is armed");
        }
        assert!(!map.contains_key(&key), "Drop must clear the entry on armed guard");
    }

    /// Disarming leaves the entry intact — the happy-path `remove-before-send` leaves the
    /// caller responsible for the removal, and the guard becomes a no-op.
    #[test]
    fn inflight_guard_disarm_leaves_entry() {
        let map: DashMap<B256, InFlightSender> = DashMap::new();
        let key = B256::from([0x99; 32]);
        let (tx, _) = broadcast::channel::<Result<Arc<BlockData>, String>>(1);
        map.insert(key, tx);

        let guard = InFlightGuard::new(&map, key);
        guard.disarm();
        assert!(map.contains_key(&key), "disarmed guard must not touch the map");
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
            matches!(err, DataProviderError::BlockFetchTimeout(_)),
            "expected BlockFetchTimeout, got: {err:?}",
        );
        // Allow generous headroom for retry backoff + scheduling; ≤5s proves the unbounded loop
        // is actually bounded.
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout must fire quickly; elapsed: {elapsed:?}"
        );
    }

    /// Each `DataProviderError` variant maps to a specific JSON-RPC error code. Missing /
    /// timeout cases must surface as `-32001` (resource not found); `Internal` falls through
    /// to `-32000`. Replaces the ad-hoc string-matching classifiers in `rpc_service.rs`.
    #[test]
    fn data_provider_error_to_rpc_error_code_mapping() {
        let tx_hash = B256::from([0x11; 32]);

        let not_found_variants: [DataProviderError; 4] = [
            DataProviderError::TransactionNotFound(tx_hash),
            DataProviderError::TransactionPending(tx_hash),
            DataProviderError::WitnessTimeout(Duration::from_secs(8)),
            DataProviderError::BlockFetchTimeout(Duration::from_secs(13)),
        ];

        for variant in not_found_variants {
            let err = variant.to_rpc_error();
            assert_eq!(err.code(), -32001, "variant {variant:?} must map to resource-not-found");
            // Display text surfaces in the RPC message — confirm it's non-empty and matches the
            // variant's `#[error(..)]` string so operators see the same wording in both places.
            assert_eq!(err.message(), variant.to_string().as_str());
        }

        let internal = DataProviderError::Internal(eyre::eyre!("boom"));
        let err = internal.to_rpc_error();
        assert_eq!(err.code(), -32000);
        assert_eq!(err.message(), "internal error");
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
}
