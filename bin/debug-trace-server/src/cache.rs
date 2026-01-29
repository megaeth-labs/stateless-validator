//! Data Provider with Multi-Level Caching
//!
//! This module provides a data provider that implements a three-level lookup strategy
//! for fetching block data required by the debug/trace RPC methods:
//!
//! 1. **LRU Cache** (fastest) - In-memory cache for recently accessed blocks
//! 2. **Local Database** (medium) - ValidatorDB for pre-fetched blocks (if configured)
//! 3. **Remote RPC** (slowest) - Upstream RPC endpoints as fallback
//!
//! # Features
//! - **Single-flight request coalescing**: Prevents duplicate RPC calls for the same block
//! - **Configurable cache size**: Runtime-adjustable LRU cache capacity
//! - **Witness fetch retry**: Automatic retry with configurable timeout for witness data
//! - **Contract bytecode caching**: Fetches and caches contract code alongside block data

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy_primitives::B256;
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use dashmap::DashMap;
use eyre::Result;
use mini_moka::sync::Cache;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;
use tokio::sync::broadcast;
use tracing::{debug, warn};
use validator_core::{withdrawals::MptWitness, RpcClient, ValidatorDB};

/// Block data bundle containing all information needed for stateless execution.
///
/// This struct aggregates the block, its SALT witness (state proof), and all
/// contract bytecodes referenced in the witness. Together, these enable
/// complete block re-execution without access to the full state database.
#[derive(Clone)]
pub struct BlockData {
    /// The block with full transaction data.
    pub block: Block<Transaction>,
    /// SALT witness containing state proofs for all accessed accounts and storage.
    pub salt_witness: SaltWitness,
    /// Contract bytecodes keyed by code hash, required for EVM execution.
    pub contracts: HashMap<B256, Bytecode>,
}

/// Default maximum number of blocks to cache in memory (128 blocks).
pub const DEFAULT_CACHE_SIZE: u64 = 128;

/// Default timeout for witness fetch retry in seconds (8 seconds).
pub const DEFAULT_WITNESS_TIMEOUT_SECS: u64 = 8;

/// Retry interval for witness fetch in milliseconds (200ms).
const WITNESS_RETRY_INTERVAL_MS: u64 = 200;

/// Broadcast sender type for single-flight request pattern.
/// Used to notify all waiters when a block fetch completes.
type InFlightSender = broadcast::Sender<Result<BlockData, String>>;

/// Data provider with multi-level caching and single-flight request coalescing.
///
/// # Data Lookup Strategy
/// 1. Check LRU cache (keyed by block hash)
/// 2. Check local ValidatorDB (if configured)
/// 3. Fetch from remote RPC endpoints
///
/// # Single-Flight Pattern
/// When multiple requests arrive for the same block simultaneously, only one
/// RPC call is made. Other requests subscribe to the result via broadcast channel.
pub struct DataProvider {
    /// RPC client for upstream data fetching.
    rpc_client: Arc<RpcClient>,
    /// Optional local database for pre-fetched blocks.
    validator_db: Option<Arc<ValidatorDB>>,
    /// LRU cache keyed by block hash for fast repeated access.
    block_cache: tokio::sync::RwLock<Cache<B256, BlockData>>,
    /// Current cache size limit (can be changed at runtime).
    cache_size: std::sync::atomic::AtomicU64,
    /// Timeout for witness fetch retry operations.
    witness_timeout: Duration,
    /// In-flight requests map for single-flight pattern (keyed by block hash).
    in_flight: DashMap<B256, InFlightSender>,
}

impl DataProvider {
    /// Creates a new data provider.
    ///
    /// # Arguments
    /// * `rpc_endpoint` - Upstream RPC endpoint for fetching blocks and contracts
    /// * `witness_endpoint` - Upstream witness endpoint for fetching SALT witness data
    /// * `validator_db` - Optional local database for cached block data
    /// * `cache_size` - Maximum number of blocks to cache in memory
    /// * `witness_timeout_secs` - Timeout in seconds for witness fetch retry
    pub fn new(
        rpc_endpoint: &str,
        witness_endpoint: &str,
        validator_db: Option<Arc<ValidatorDB>>,
        cache_size: u64,
        witness_timeout_secs: u64,
    ) -> eyre::Result<Self> {
        let rpc_client = Arc::new(RpcClient::new(rpc_endpoint, witness_endpoint)?);
        let block_cache = tokio::sync::RwLock::new(Cache::new(cache_size));
        Ok(Self {
            rpc_client,
            validator_db,
            block_cache,
            cache_size: std::sync::atomic::AtomicU64::new(cache_size),
            witness_timeout: Duration::from_secs(witness_timeout_secs),
            in_flight: DashMap::new(),
        })
    }

    /// Sets a new cache size limit.
    ///
    /// **Warning**: This recreates the cache with the new size, clearing all existing entries.
    /// Use with caution in production as it may cause temporary performance degradation.
    pub async fn set_cache_size(&self, new_size: u64) {
        self.cache_size
            .store(new_size, std::sync::atomic::Ordering::Relaxed);
        let mut cache = self.block_cache.write().await;
        *cache = Cache::new(new_size);
        debug!("Cache size updated to {} blocks", new_size);
    }

    /// Returns the current cache size limit.
    pub fn get_cache_size(&self) -> u64 {
        self.cache_size.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns the current number of entries in the cache.
    pub async fn get_cache_entry_count(&self) -> u64 {
        self.block_cache.read().await.entry_count()
    }

    /// Gets block data by block number.
    ///
    /// Lookup order: LRU cache -> local database -> RPC.
    /// Results are cached in the LRU cache for subsequent requests.
    ///
    /// # Arguments
    /// * `block_num` - The block number to fetch
    ///
    /// # Returns
    /// * `Ok(BlockData)` - Block data including witness and contracts
    /// * `Err` - If the block cannot be fetched from any source
    pub async fn get_block_data(&self, block_num: u64) -> Result<BlockData> {
        // First resolve block number to hash for cache lookup
        let block_hash = if let Some(db) = &self.validator_db {
            db.get_block_hash(block_num)?
        } else {
            None
        };

        // Check LRU cache if we have the hash
        if let Some(hash) = block_hash {
            if let Some(data) = self.block_cache.read().await.get(&hash) {
                debug!("Block {} fetched from LRU cache", block_num);
                return Ok(data);
            }
        }

        // Try to get from local database
        if let Some(db) = &self.validator_db {
            if let Some(hash) = block_hash {
                if let Ok(data) = self.get_block_data_from_db(db, hash).await {
                    debug!("Block {} fetched from database", block_num);
                    self.block_cache.read().await.insert(hash, data.clone());
                    return Ok(data);
                }
            }
        }

        // Fall back to RPC
        debug!("Block {} fetched from RPC", block_num);
        let data = self.fetch_block_data_from_rpc(block_num).await?;
        self.block_cache
            .read()
            .await
            .insert(data.block.header.hash, data.clone());
        Ok(data)
    }

    /// Gets block data by block hash.
    ///
    /// Lookup order: LRU cache -> local database -> RPC.
    /// Results are cached in the LRU cache for subsequent requests.
    ///
    /// # Arguments
    /// * `block_hash` - The 32-byte block hash to fetch
    ///
    /// # Returns
    /// * `Ok(BlockData)` - Block data including witness and contracts
    /// * `Err` - If the block cannot be fetched from any source
    pub async fn get_block_data_by_hash(&self, block_hash: B256) -> Result<BlockData> {
        // Check LRU cache first
        if let Some(data) = self.block_cache.read().await.get(&block_hash) {
            debug!("Block {} fetched from LRU cache", block_hash);
            return Ok(data);
        }

        // Try to get from local database
        if let Some(db) = &self.validator_db {
            if let Ok(data) = self.get_block_data_from_db(db, block_hash).await {
                debug!("Block {} fetched from database", block_hash);
                self.block_cache
                    .read()
                    .await
                    .insert(block_hash, data.clone());
                return Ok(data);
            }
        }

        // Fall back to RPC
        debug!("Block {} fetched from RPC", block_hash);
        let data = self.fetch_block_data_by_hash_from_rpc(block_hash).await?;
        self.block_cache
            .read()
            .await
            .insert(block_hash, data.clone());
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
    pub async fn get_block_data_for_tx(&self, tx_hash: B256) -> Result<(BlockData, usize)> {
        debug!("Fetching block data for tx {}", tx_hash);

        // Fetch the transaction to find its block
        let (tx, block_hash) = self
            .rpc_client
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or_else(|| eyre::eyre!("Transaction {} not found", tx_hash))?;

        let tx_index = tx
            .transaction_index
            .ok_or_else(|| eyre::eyre!("Transaction {} is pending", tx_hash))?
            as usize;

        // Get block data
        let data = self.get_block_data_by_hash(block_hash).await?;

        Ok((data, tx_index))
    }

    /// Resolves a block tag to a concrete block number.
    ///
    /// Supports `Number(n)` and `Latest` tags. Other tags (Pending, Safe, Finalized)
    /// are not supported and will return an error.
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
            other => Err(eyre::eyre!("Unsupported block tag: {:?}", other)),
        }
    }

    /// Gets block data from the local database.
    ///
    /// Retrieves block and witness from ValidatorDB, then fetches any missing
    /// contract bytecodes (checking DB first, then falling back to RPC).
    async fn get_block_data_from_db(
        &self,
        db: &ValidatorDB,
        block_hash: alloy_primitives::BlockHash,
    ) -> Result<BlockData> {
        // Get block data from database
        let (block, salt_witness) = db.get_block_and_witness(block_hash)?;

        // Extract code hashes and get contracts
        let code_hashes = validator_core::extract_code_hashes(&salt_witness);
        let contracts = self.get_contracts_with_db(db, &code_hashes).await?;

        Ok(BlockData {
            block,
            salt_witness,
            contracts,
        })
    }

    /// Fetches block data from RPC by block number with single-flight coalescing.
    ///
    /// First fetches the block header to get the hash, then delegates to
    /// single-flight fetch to avoid duplicate requests.
    async fn fetch_block_data_from_rpc(&self, block_num: u64) -> Result<BlockData> {
        // First fetch block without transactions to get the hash
        let block = self
            .rpc_client
            .get_block(BlockId::Number(BlockNumberOrTag::Number(block_num)), false)
            .await?;

        // Use single-flight for the actual data fetch
        self.fetch_block_data_single_flight(block.header.hash).await
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
            debug!(
                "Joining existing in-flight request for block {}",
                block_hash
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

        // Perform the actual fetch
        let result = self.do_fetch_block_data(block_hash).await;

        // Convert result to string error for broadcast (eyre::Error is not Clone)
        let broadcast_result = result
            .as_ref()
            .map(|data| data.clone())
            .map_err(|e| e.to_string());

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
    /// 2. Fetch witness data with retry logic
    /// 3. Fetch block with full transactions
    /// 4. Extract code hashes from witness and fetch contract bytecodes
    async fn do_fetch_block_data(&self, block_hash: B256) -> Result<BlockData> {
        // Fetch block without transactions first to get the number
        let block = self
            .rpc_client
            .get_block(BlockId::Hash(block_hash.into()), false)
            .await?;

        // Fetch witness with retry
        let (salt_witness, _mpt_witness) = self
            .fetch_witness_with_retry(block.header.number, block.header.hash)
            .await?;

        // Fetch block with full transactions
        let block = self
            .rpc_client
            .get_block(BlockId::Hash(block_hash.into()), true)
            .await?;

        // Extract code hashes and fetch contracts
        let code_hashes = validator_core::extract_code_hashes(&salt_witness);
        let contracts = self.get_contracts(&code_hashes).await?;

        Ok(BlockData {
            block,
            salt_witness,
            contracts,
        })
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
    async fn fetch_witness_with_retry(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<(SaltWitness, MptWitness)> {
        let start = std::time::Instant::now();
        let retry_interval = Duration::from_millis(WITNESS_RETRY_INTERVAL_MS);
        let mut last_error = None;

        while start.elapsed() < self.witness_timeout {
            match self.rpc_client.get_witness(block_number, block_hash).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!(
                        "Failed to fetch witness for block {}, retrying: {}",
                        block_number, e
                    );
                    last_error = Some(e);
                    tokio::time::sleep(retry_interval).await;
                }
            }
        }

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
    async fn get_contracts_with_db(
        &self,
        db: &ValidatorDB,
        code_hashes: &[B256],
    ) -> Result<HashMap<B256, Bytecode>> {
        // First try to get from database
        let (mut contracts, missing) = db.get_contract_codes(code_hashes.iter().copied())?;

        // Fetch missing contracts from RPC
        for hash in missing {
            match self.rpc_client.get_code(hash).await {
                Ok(code) => {
                    contracts.insert(hash, Bytecode::new_raw(code));
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch contract {}: {}", hash, e);
                }
            }
        }

        Ok(contracts)
    }

    /// Gets multiple contracts by their code hashes from RPC.
    ///
    /// Fetches each contract individually. Failed fetches are logged but don't
    /// cause the entire operation to fail (contracts may be missing for various reasons).
    async fn get_contracts(&self, code_hashes: &[B256]) -> Result<HashMap<B256, Bytecode>> {
        let mut result = HashMap::new();

        for &hash in code_hashes {
            match self.rpc_client.get_code(hash).await {
                Ok(code) => {
                    result.insert(hash, Bytecode::new_raw(code));
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch contract {}: {}", hash, e);
                }
            }
        }

        Ok(result)
    }
}
