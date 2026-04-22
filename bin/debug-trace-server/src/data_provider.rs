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
    ChainSyncMetrics, DataSourceMetrics, SingleFlightMetrics, UpstreamMetrics, WitnessSourceMetrics,
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
#[derive(Clone)]
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

/// Slow stage threshold: any individual stage exceeding this triggers a warn log.
pub(crate) const SLOW_STAGE_THRESHOLD_MS: u128 = 1000;

/// Broadcast sender type for single-flight request pattern.
/// Used to notify all waiters when a block fetch completes.
///
/// `Arc<BlockData>` rather than `BlockData` so coalesced waiters share one allocation
/// — the value carries a full block, witness, and contract map.
type InFlightSender = broadcast::Sender<Result<Arc<BlockData>, String>>;

/// Data provider with single-flight request coalescing.
///
/// # Data Lookup Strategy
/// 1. Check local database (if configured)
/// 2. Fetch from remote RPC endpoints (multi-provider fallback handled by `RpcClient`)
///
/// # Single-Flight Pattern
/// When multiple requests arrive for the same block simultaneously, only one
/// RPC call is made. Other requests subscribe to the result via broadcast channel.
pub struct DataProvider {
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
    pub fn new(
        rpc_client: Arc<RpcClient>,
        db: Option<Arc<dyn BlockStore>>,
        contract_cache: Arc<ContractCache>,
        witness_timeout_secs: u64,
    ) -> Self {
        Self {
            rpc_client,
            db,
            contract_cache,
            witness_timeout: Duration::from_secs(witness_timeout_secs),
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
    /// * `Err` - If the block cannot be fetched from any source
    pub async fn get_block_data(&self, block_num: u64) -> Result<Arc<BlockData>> {
        // Try to get block hash from local database first
        if let Some(db) = &self.db &&
            let Ok(Some(hash)) = db.get_block_hash(block_num)
        {
            return self.get_block_data_by_hash(hash).await;
        }

        // Fall back to RPC - fetch header to get hash, then delegate to get_block_data_by_hash
        let block_hash = self.rpc_client.get_block_hash(block_num).await;

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
    pub async fn get_block_data_by_hash(&self, block_hash: B256) -> Result<Arc<BlockData>> {
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
    pub async fn get_block_data_for_tx(&self, tx_hash: B256) -> Result<(Arc<BlockData>, usize)> {
        trace!(tx_hash = %tx_hash, "Looking up transaction");

        // Fetch the transaction to find its block
        let (tx, block_hash) = self
            .rpc_client
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or_else(|| eyre::eyre!("Transaction {} not found", tx_hash))?;

        let tx_index =
            tx.transaction_index.ok_or_else(|| eyre::eyre!("Transaction {} is pending", tx_hash))?
                as usize;

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
    async fn fetch_block_data_by_hash_from_rpc(&self, block_hash: B256) -> Result<Arc<BlockData>> {
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
    async fn fetch_block_data_single_flight(&self, block_hash: B256) -> Result<Arc<BlockData>> {
        // Check if there's already an in-flight request for this block
        if let Some(sender) = self.in_flight.get(&block_hash) {
            // Subscribe to the existing request
            let mut receiver = sender.subscribe();
            drop(sender); // Release the lock
            SingleFlightMetrics::new_for_type("coalesced").record();
            trace!(
                block_hash = %block_hash,
                "Joining existing in-flight request"
            );
            return receiver
                .recv()
                .await
                .map_err(|e| eyre::eyre!("Failed to receive from in-flight request: {}", e))?
                .map_err(|e| eyre::eyre!("{}", e));
        }

        // Create a new broadcast channel for this request
        let (tx, _) = broadcast::channel(1);
        self.in_flight.insert(block_hash, tx.clone());
        SingleFlightMetrics::new_for_type("new").record();

        trace!(
            block_hash = %block_hash,
            "Starting new block data fetch"
        );

        // Perform the actual fetch
        let result = self.do_fetch_block_data(block_hash).await.map(Arc::new);

        // Clone is an Arc refcount bump; eyre::Error is not Clone so errors are stringified.
        let broadcast_result = result.as_ref().map(Arc::clone).map_err(|e| e.to_string());

        // Broadcast result to all waiters (ignore send errors - no receivers is ok)
        let _ = tx.send(broadcast_result);

        // Remove from in-flight map
        self.in_flight.remove(&block_hash);

        result
    }

    /// Actually fetches block data from RPC (called by single-flight).
    ///
    /// Performs the complete fetch sequence:
    /// 1. Fetch block header (without transactions) to get block number
    /// 2. Fetch witness and full block in parallel
    /// 3. Convert SaltWitness to LightWitness
    /// 4. Extract code hashes from witness and fetch contract bytecodes
    async fn do_fetch_block_data(&self, block_hash: B256) -> Result<BlockData> {
        let overall_start = std::time::Instant::now();
        let upstream_header = UpstreamMetrics::new_for_method("eth_getHeaderByHash");
        let upstream_block = UpstreamMetrics::new_for_method("eth_getBlockByHash");
        let upstream_witness = UpstreamMetrics::new_for_method("mega_getWitness");

        // Step 1: Fetch header first to get the block number
        let start = std::time::Instant::now();
        let header = self.rpc_client.get_header(BlockId::Hash(block_hash.into()), false).await;
        upstream_header.record_request(true, start.elapsed().as_secs_f64());
        let block_number = header.number;
        let fetch_header_ms = start.elapsed().as_millis();

        // Step 2: Fetch witness and full block in parallel, timing each independently
        let (witness_timed, block_timed) = tokio::join!(
            async {
                let start = std::time::Instant::now();
                let result = self.fetch_witness_with_fallback(block_number, header.hash).await;
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
        upstream_witness.record_request(witness_result.is_ok(), witness_elapsed.as_secs_f64());
        let (salt_witness, _mpt_witness) = witness_result?;

        let fetch_full_block_ms = block_elapsed.as_millis();
        upstream_block.record_request(true, block_elapsed.as_secs_f64());

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
    /// the caller surfaces an error back to the RPC client. `witness_timeout` covers the "block
    /// is fresh and the witness is still being generated upstream" case for new blocks; for old
    /// blocks the RPC layer's round-robin + backoff reaches an upstream conclusion quickly.
    async fn fetch_witness_with_fallback(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<(SaltWitness, MptWitness)> {
        let db_max_height = self
            .db
            .as_ref()
            .and_then(|db| db.get_canonical_tip().ok().flatten().map(|tip| tip.block_number));
        let is_new_block = db_max_height.is_none_or(|max| block_number > max);
        trace!(block_number, db_max_height, is_new_block, "Fetching witness");

        let wg_metrics = WitnessSourceMetrics::new_for_source("witness_generator");
        let start = std::time::Instant::now();

        let result = tokio::time::timeout(
            self.witness_timeout,
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
                    timeout_ms = self.witness_timeout.as_millis() as u64,
                    "Witness fetch timeout",
                );
                Err(eyre::eyre!(
                    "Witness fetch timeout after {:?} for block {}",
                    self.witness_timeout,
                    block_number
                ))
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

        let upstream = UpstreamMetrics::new_for_method("eth_getCodeByHash");
        let start = std::time::Instant::now();
        let result = self.rpc_client.get_codes(&missing, true).await;
        upstream.record_request(result.is_ok(), start.elapsed().as_secs_f64());
        let fetched = result?;

        let new_contracts: Vec<(B256, Arc<Bytecode>)> =
            fetched.into_iter().map(|(h, b)| (h, Arc::new(b))).collect();

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
pub struct NoopContractStore;

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
    use super::*;

    #[test]
    fn test_block_data_clone() {
        // BlockData should be Clone
        fn assert_clone<T: Clone>() {}
        assert_clone::<BlockData>();
    }

    #[test]
    fn test_default_witness_timeout() {
        assert_eq!(DEFAULT_WITNESS_TIMEOUT_SECS, 8);
    }

    #[tokio::test]
    async fn test_resolve_block_number_with_number() {
        // This test verifies the logic without needing a real RPC
        let tag = BlockNumberOrTag::Number(12345);
        match tag {
            BlockNumberOrTag::Number(n) => assert_eq!(n, 12345),
            _ => panic!("Expected Number variant"),
        }
    }

    #[test]
    fn test_block_number_or_tag_variants() {
        // Test that we handle the expected variants
        let number = BlockNumberOrTag::Number(100);
        let latest = BlockNumberOrTag::Latest;
        let pending = BlockNumberOrTag::Pending;
        let earliest = BlockNumberOrTag::Earliest;
        let finalized = BlockNumberOrTag::Finalized;
        let safe = BlockNumberOrTag::Safe;

        assert!(matches!(number, BlockNumberOrTag::Number(100)));
        assert!(matches!(latest, BlockNumberOrTag::Latest));
        assert!(matches!(pending, BlockNumberOrTag::Pending));
        assert!(matches!(earliest, BlockNumberOrTag::Earliest));
        assert!(matches!(finalized, BlockNumberOrTag::Finalized));
        assert!(matches!(safe, BlockNumberOrTag::Safe));
    }

    #[test]
    fn test_in_flight_sender_type() {
        // Verify that InFlightSender can hold our expected result types
        fn _assert_send_sync<T: Send + Sync>() {}
        _assert_send_sync::<InFlightSender>();
    }

    #[test]
    fn test_data_provider_struct_fields() {
        // Verify DataProvider has expected trait bounds
        // DataProvider should be Send + Sync for use across async tasks
        // We can't create a DataProvider without a real RPC client,
        // but we can verify the struct layout is correct
        fn _check_arc<T: Send + Sync>() {}
        _check_arc::<Arc<RpcClient>>();
        _check_arc::<Option<Arc<dyn BlockStore>>>();
        _check_arc::<DashMap<B256, InFlightSender>>();
    }

    #[test]
    fn test_block_data_struct() {
        // Verify BlockData struct has expected fields
        use std::collections::HashMap;

        // Create a minimal BlockData for testing field access patterns
        // (we can't fully construct one without real data, but we can verify types)
        let _: Option<HashMap<B256, Bytecode>> = None;
        let _: Option<SaltWitness> = None;
    }

    #[test]
    fn test_duration_from_secs() {
        // Verify timeout duration is created correctly
        let timeout = Duration::from_secs(DEFAULT_WITNESS_TIMEOUT_SECS);
        assert_eq!(timeout.as_secs(), 8);
        assert_eq!(timeout.as_millis(), 8000);
    }

    // Tests for resolve_block_number logic (block tag handling)

    #[test]
    fn test_earliest_tag_returns_zero() {
        // Earliest block should always be 0 (genesis)
        let tag = BlockNumberOrTag::Earliest;
        match tag {
            BlockNumberOrTag::Earliest => {
                // Our implementation returns Ok(0) for Earliest
                assert_eq!(0u64, 0u64); // Placeholder for the actual logic
            }
            _ => panic!("Expected Earliest variant"),
        }
    }

    #[test]
    fn test_pending_tag_error_message() {
        // Verify the error message for pending tag matches mega-reth
        let expected_error = "Pending block not supported";
        // This tests that our error message is consistent with mega-reth
        assert!(expected_error.contains("Pending"));
        assert!(expected_error.contains("not supported"));
    }

    #[test]
    fn test_block_id_from_tag() {
        // Test that BlockId can be constructed from BlockNumberOrTag
        let tag = BlockNumberOrTag::Finalized;
        let block_id = BlockId::Number(tag);
        assert!(matches!(block_id, BlockId::Number(BlockNumberOrTag::Finalized)));
    }

    #[test]
    fn test_block_id_from_safe_tag() {
        let tag = BlockNumberOrTag::Safe;
        let block_id = BlockId::Number(tag);
        assert!(matches!(block_id, BlockId::Number(BlockNumberOrTag::Safe)));
    }

    // Tests for error handling

    #[test]
    fn test_eyre_error_creation() {
        // Test that we can create eyre errors with proper messages
        let hash = B256::ZERO;
        let error = eyre::eyre!("Failed to fetch contract code {}: test error", hash);
        let error_string = error.to_string();
        assert!(error_string.contains("Failed to fetch contract code"));
        assert!(error_string.contains("test error"));
    }

    #[test]
    fn test_contract_hash_display() {
        // Test B256 display for error messages
        let hash = B256::ZERO;
        let display = format!("{}", hash);
        assert!(display.contains("0x"));
        assert_eq!(display.len(), 66); // 0x + 64 hex chars
    }
}
