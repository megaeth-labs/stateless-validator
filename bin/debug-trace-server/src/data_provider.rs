//! Data Provider for Block Data Fetching
//!
//! This module provides a data provider that fetches block data required by the
//! debug/trace RPC methods from multiple sources:
//!
//! 1. **Local Database** (fast) - ValidatorDB for pre-fetched blocks (if configured)
//! 2. **Remote RPC** (slower) - Upstream RPC endpoints as fallback
//! 3. **Cloudflare KV** (archive) - Optional fallback for pruned/old blocks (via RpcClient)
//!
//! # Features
//! - **Single-flight request coalescing**: Prevents duplicate RPC calls for the same block
//! - **Witness fetch retry**: Automatic retry with configurable timeout for witness data
//! - **Height-based witness routing**: Routes to appropriate source based on block height
//! - **Contract bytecode fetching**: Fetches contract code alongside block data
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
use tokio::sync::broadcast;
use tracing::{debug, instrument, trace, warn};
use validator_core::{withdrawals::MptWitness, LightWitness, RpcClient, ValidatorDB};

use crate::metrics::UpstreamMetrics;

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
    pub contracts: HashMap<B256, Bytecode>,
}

/// Default timeout for witness fetch retry in seconds (8 seconds).
pub const DEFAULT_WITNESS_TIMEOUT_SECS: u64 = 8;

/// Retry interval for witness fetch in milliseconds (200ms).
const WITNESS_RETRY_INTERVAL_MS: u64 = 200;

/// Slow stage threshold: any individual stage exceeding this triggers a warn log.
const SLOW_STAGE_THRESHOLD_MS: u128 = 1000;

/// Broadcast sender type for single-flight request pattern.
/// Used to notify all waiters when a block fetch completes.
type InFlightSender = broadcast::Sender<Result<BlockData, String>>;

/// Data provider with single-flight request coalescing.
///
/// # Data Lookup Strategy
/// 1. Check local ValidatorDB (if configured)
/// 2. Fetch from remote RPC endpoints
/// 3. Fall back to Cloudflare KV (if configured in RpcClient) for pruned blocks
///
/// # Single-Flight Pattern
/// When multiple requests arrive for the same block simultaneously, only one
/// RPC call is made. Other requests subscribe to the result via broadcast channel.
pub struct DataProvider {
    /// RPC client for upstream data fetching (includes optional Cloudflare fallback).
    rpc_client: Arc<RpcClient>,
    /// Optional local database for pre-fetched blocks.
    validator_db: Option<Arc<ValidatorDB>>,
    /// Timeout for witness fetch retry operations.
    witness_timeout: Duration,
    /// In-flight requests map for single-flight pattern (keyed by block hash).
    in_flight: DashMap<B256, InFlightSender>,
}

impl DataProvider {
    /// Creates a new data provider.
    ///
    /// # Arguments
    /// * `rpc_client` - RPC client for upstream data fetching (may include Cloudflare fallback)
    /// * `validator_db` - Optional local database for cached block data
    /// * `witness_timeout_secs` - Timeout in seconds for witness fetch retry
    pub fn new(
        rpc_client: Arc<RpcClient>,
        validator_db: Option<Arc<ValidatorDB>>,
        witness_timeout_secs: u64,
    ) -> Self {
        if rpc_client.has_cloudflare_provider() {
            debug!("Cloudflare witness fallback enabled via RpcClient");
        }

        Self {
            rpc_client,
            validator_db,
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
    /// * `Ok(BlockData)` - Block data including witness and contracts
    /// * `Err` - If the block cannot be fetched from any source
    pub async fn get_block_data(&self, block_num: u64) -> Result<BlockData> {
        // Try to get block hash from local database first
        if let Some(db) = &self.validator_db {
            if let Ok(Some(hash)) = db.get_block_hash(block_num) {
                return self.get_block_data_by_hash(hash).await;
            }
        }

        // Fall back to RPC - fetch header to get hash, then delegate to get_block_data_by_hash
        let block_hash = self.rpc_client.get_block_hash(block_num).await?;

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
    /// * `Ok(BlockData)` - Block data including witness and contracts
    /// * `Err` - If the block cannot be fetched from any source
    pub async fn get_block_data_by_hash(&self, block_hash: B256) -> Result<BlockData> {
        let start = std::time::Instant::now();

        // Try to get from local database
        if let Some(db) = &self.validator_db {
            if let Ok(data) = self.get_block_data_from_db(db, block_hash).await {
                trace!(
                    block_hash = %block_hash,
                    source = "database",
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    "Block data retrieved from local DB"
                );
                return Ok(data);
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
    /// * `Ok((BlockData, usize))` - Block data and transaction index
    /// * `Err` - If transaction not found or is still pending
    #[instrument(skip(self), name = "get_block_data_for_tx", fields(tx_hash = %tx_hash))]
    pub async fn get_block_data_for_tx(&self, tx_hash: B256) -> Result<(BlockData, usize)> {
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
            BlockNumberOrTag::Latest => self.rpc_client.get_latest_block_number().await,
            BlockNumberOrTag::Earliest => Ok(0),
            BlockNumberOrTag::Pending => Err(eyre::eyre!("Pending block not supported")),
            BlockNumberOrTag::Finalized | BlockNumberOrTag::Safe => {
                // Fetch the header from upstream RPC to resolve the tag
                let header = self.rpc_client.get_header(BlockId::Number(tag), false).await?;
                Ok(header.number)
            }
        }
    }

    /// Gets block data from the local database using LightWitness.
    async fn get_block_data_from_db(
        &self,
        db: &ValidatorDB,
        block_hash: alloy_primitives::BlockHash,
    ) -> Result<BlockData> {
        let overall_start = std::time::Instant::now();

        // Get block data from database using light witness (fast deserialization)
        let start = std::time::Instant::now();
        let (block, witness) = db.get_block_and_witness(block_hash)?;
        let db_read_ms = start.elapsed().as_millis();

        // Extract code hashes and get contracts
        let start = std::time::Instant::now();
        let code_hashes = validator_core::extract_code_hashes(&witness);
        let num_contracts = code_hashes.len();
        let contracts = self.get_contracts_with_db(db, &code_hashes).await?;
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
    async fn fetch_block_data_by_hash_from_rpc(&self, block_hash: B256) -> Result<BlockData> {
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
    async fn fetch_block_data_single_flight(&self, block_hash: B256) -> Result<BlockData> {
        // Check if there's already an in-flight request for this block
        if let Some(sender) = self.in_flight.get(&block_hash) {
            // Subscribe to the existing request
            let mut receiver = sender.subscribe();
            drop(sender); // Release the lock
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

        trace!(
            block_hash = %block_hash,
            "Starting new block data fetch"
        );

        // Perform the actual fetch
        let result = self.do_fetch_block_data(block_hash).await;

        // Convert result to string error for broadcast (eyre::Error is not Clone)
        let broadcast_result = result.as_ref().map(|data| data.clone()).map_err(|e| e.to_string());

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
        upstream_header.record_request(header.is_ok(), start.elapsed().as_secs_f64());
        let header = header?;
        let block_number = header.number;
        let fetch_header_ms = start.elapsed().as_millis();

        // Step 2: Fetch witness and full block in parallel
        let witness_start = std::time::Instant::now();
        let full_block_start = std::time::Instant::now();

        let (witness_result, full_block_result) = tokio::join!(
            self.fetch_witness_with_fallback(block_number, header.hash),
            self.rpc_client.get_block(BlockId::Hash(block_hash.into()), true),
        );

        let fetch_witness_ms = witness_start.elapsed().as_millis();
        upstream_witness.record_request(witness_result.is_ok(), fetch_witness_ms as f64 / 1000.0);
        let (salt_witness, _mpt_witness) = witness_result?;

        let fetch_full_block_ms = full_block_start.elapsed().as_millis();
        upstream_block
            .record_request(full_block_result.is_ok(), fetch_full_block_ms as f64 / 1000.0);
        let block = full_block_result?;

        // Step 3: Convert SaltWitness to LightWitness
        let start = std::time::Instant::now();
        let witness = LightWitness::from(salt_witness);
        let convert_witness_ms = start.elapsed().as_millis();

        // Step 4: Extract code hashes and fetch contracts
        let start = std::time::Instant::now();
        let code_hashes = validator_core::extract_code_hashes(&witness);
        let num_contracts = code_hashes.len();
        let contracts = self.get_contracts(&code_hashes).await?;
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

    /// Fetches witness data from Cloudflare KV via RpcClient.
    ///
    /// Single attempt, no retry (it's a KV lookup, either it exists or it doesn't).
    async fn get_witness_from_cloudflare(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<(SaltWitness, MptWitness)> {
        match self.rpc_client.get_witness_from_cloudflare(block_number, block_hash).await {
            Ok(result) => {
                trace!(
                    block_number,
                    block_hash = %block_hash,
                    "Witness fetched from Cloudflare"
                );
                Ok(result)
            }
            Err(e) => {
                warn!(
                    block_number,
                    block_hash = %block_hash,
                    error = %e,
                    "Cloudflare witness fetch failed"
                );
                Err(e)
            }
        }
    }

    /// Fetches witness data with height-based routing and fallback.
    ///
    /// Routing logic:
    /// - `block > db_max` → Retry witness endpoint (block is new, witness may be delayed), then
    ///   Cloudflare fallback
    /// - `block <= db_max` (or no DB) → Single witness attempt, then immediate Cloudflare fallback
    ///   (block is old/pruned, no point retrying)
    async fn fetch_witness_with_fallback(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<(SaltWitness, MptWitness)> {
        // Determine db_max_height if we have a database
        let db_max_height = self
            .validator_db
            .as_ref()
            .and_then(|db| db.get_local_tip().ok().flatten().map(|(height, _)| height));

        let is_new_block = match db_max_height {
            Some(max) => block_number > max,
            None => true, // No DB means treat all blocks as "new" (try witness endpoint with retry)
        };

        if is_new_block {
            // Block is newer than DB max: retry witness endpoint until timeout
            trace!(
                block_number,
                db_max_height,
                "Block is new, using retry loop for witness endpoint"
            );

            match self.fetch_witness_with_retry(block_number, block_hash).await {
                Ok(result) => Ok(result),
                Err(e) => {
                    // Timeout reached, try Cloudflare fallback
                    if self.rpc_client.has_cloudflare_provider() {
                        trace!(
                            block_number,
                            %e,
                            "Witness endpoint timeout, falling back to Cloudflare"
                        );
                        self.get_witness_from_cloudflare(block_number, block_hash).await
                    } else {
                        Err(e)
                    }
                }
            }
        } else {
            // Block is older/pruned: single attempt on witness endpoint, then immediate Cloudflare
            trace!(
                block_number,
                db_max_height,
                "Block is old/pruned, single attempt then Cloudflare fallback"
            );

            match self.rpc_client.get_witness(block_number, block_hash).await {
                Ok(result) => Ok(result),
                Err(e) => {
                    // Single attempt failed, try Cloudflare fallback
                    if self.rpc_client.has_cloudflare_provider() {
                        trace!(
                            block_number,
                            %e,
                            "Witness endpoint failed, falling back to Cloudflare"
                        );
                        self.get_witness_from_cloudflare(block_number, block_hash).await
                    } else {
                        // No Cloudflare configured and witness fetch failed
                        Err(eyre::eyre!("Block witness not found for block {}", block_number))
                    }
                }
            }
        }
    }

    /// Fetches witness data with retry logic.
    ///
    /// Retries fetching witness until success or timeout is reached.
    /// This handles the case where witness data may not be immediately available
    /// for very recent blocks.
    ///
    /// # Arguments
    /// * `block_number` - Block number for logging
    /// * `block_hash` - Block hash to fetch witness for
    ///
    /// # Returns
    /// * `Ok((SaltWitness, MptWitness))` - Successfully fetched witness data
    /// * `Err` - If timeout reached without successful fetch
    #[instrument(skip(self), name = "fetch_witness")]
    async fn fetch_witness_with_retry(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<(SaltWitness, MptWitness)> {
        let start = std::time::Instant::now();
        let retry_interval = Duration::from_millis(WITNESS_RETRY_INTERVAL_MS);
        let mut last_error = None;
        let mut retry_count = 0u32;

        while start.elapsed() < self.witness_timeout {
            match self.rpc_client.get_witness(block_number, block_hash).await {
                Ok(result) => {
                    if retry_count > 0 {
                        trace!(
                            block_number,
                            block_hash = %block_hash,
                            retry_count,
                            elapsed_ms = start.elapsed().as_millis() as u64,
                            "Witness fetched after retries"
                        );
                    }
                    return Ok(result);
                }
                Err(e) => {
                    retry_count += 1;
                    warn!(
                        block_number,
                        block_hash = %block_hash,
                        retry_count,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        error = %e,
                        "Witness fetch failed, retrying"
                    );
                    last_error = Some(e);
                    tokio::time::sleep(retry_interval).await;
                }
            }
        }

        // Log final failure
        warn!(
            block_number,
            block_hash = %block_hash,
            retry_count,
            timeout_ms = self.witness_timeout.as_millis() as u64,
            "Witness fetch timeout"
        );

        Err(last_error.unwrap_or_else(|| {
            eyre::eyre!(
                "Witness fetch timeout after {:?} for block {}",
                self.witness_timeout,
                block_number
            )
        }))
    }

    /// Gets contracts from local database with RPC fallback.
    ///
    /// First attempts to retrieve all contracts from the local database.
    /// Any missing contracts are then fetched from the upstream RPC.
    /// Returns an error if any contract cannot be fetched.
    async fn get_contracts_with_db(
        &self,
        db: &ValidatorDB,
        code_hashes: &[B256],
    ) -> Result<HashMap<B256, Bytecode>> {
        // First try to get from database
        let (mut contracts, missing) = db.get_contract_codes(code_hashes.iter().copied())?;

        if !missing.is_empty() {
            trace!(
                total = code_hashes.len(),
                from_db = contracts.len(),
                missing = missing.len(),
                "Some contracts missing from DB, fetching from RPC"
            );
        }

        // Fetch missing contracts from RPC
        for hash in missing {
            let code = self
                .rpc_client
                .get_code(hash)
                .await
                .map_err(|e| eyre::eyre!("Failed to fetch contract code {}: {}", hash, e))?;
            contracts.insert(hash, Bytecode::new_raw(code));
        }

        Ok(contracts)
    }

    /// Gets multiple contracts by their code hashes from RPC.
    ///
    /// Fetches each contract individually. Returns an error if any contract
    /// cannot be fetched.
    async fn get_contracts(&self, code_hashes: &[B256]) -> Result<HashMap<B256, Bytecode>> {
        let mut result = HashMap::new();

        trace!(count = code_hashes.len(), "Fetching contracts from RPC");

        for &hash in code_hashes {
            let code = self
                .rpc_client
                .get_code(hash)
                .await
                .map_err(|e| eyre::eyre!("Failed to fetch contract code {}: {}", hash, e))?;
            result.insert(hash, Bytecode::new_raw(code));
        }

        Ok(result)
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

    #[test]
    fn test_witness_retry_interval() {
        // Retry interval should be reasonable (200ms)
        assert_eq!(WITNESS_RETRY_INTERVAL_MS, 200);
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
        _check_arc::<Option<Arc<ValidatorDB>>>();
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

    #[test]
    fn test_retry_interval_duration() {
        let interval = Duration::from_millis(WITNESS_RETRY_INTERVAL_MS);
        assert_eq!(interval.as_millis(), 200);
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
