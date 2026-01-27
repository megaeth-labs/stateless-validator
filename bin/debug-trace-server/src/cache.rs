//! Data cache with single-flight pattern for deduplicating concurrent requests.
//!
//! This module provides a caching layer over the RPC client that:
//! - Caches blocks, witnesses, and contracts with configurable limits
//! - Uses single-flight pattern to avoid duplicate concurrent requests
//! - Tracks cache hit/miss metrics

use std::collections::HashMap;
use std::sync::Arc;

use alloy_primitives::B256;
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::Result;
use lru::LruCache;
use op_alloy_rpc_types::Transaction;
use parking_lot::Mutex;
use revm::state::Bytecode;
use salt::SaltWitness;
use tokio::sync::broadcast;
use tracing::{debug, warn};
use validator_core::RpcClient;

use crate::metrics;

/// Configuration for the data cache.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of blocks to cache.
    pub max_blocks: usize,
    /// Maximum number of witnesses to cache (used together with blocks).
    pub max_witnesses: usize,
    /// Maximum number of contracts to cache.
    pub max_contracts: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_blocks: 100,
            max_witnesses: 100,
            max_contracts: 1000,
        }
    }
}

/// Cached block data including the block, witness, and contracts.
#[derive(Clone)]
pub struct CachedBlockData {
    pub block: Block<Transaction>,
    pub salt_witness: SaltWitness,
    pub contracts: HashMap<B256, Bytecode>,
}

impl CachedBlockData {
    /// Returns an estimate of the memory size of this cached data in bytes.
    #[allow(dead_code)]
    pub fn estimated_size(&self) -> usize {
        // Rough estimate: block header + transactions + witness + contracts
        std::mem::size_of::<Block<Transaction>>()
            + self.block.transactions.len() * 500 // ~500 bytes per transaction
            + self.salt_witness.kvs.len() * 100 // ~100 bytes per witness entry
            + self.contracts.values().map(|c| c.bytes().len()).sum::<usize>()
    }
}

/// In-flight request state for single-flight pattern.
type InFlightSender<T> = broadcast::Sender<Result<T, String>>;

/// Data provider with caching and single-flight deduplication.
pub struct CachedDataProvider {
    /// Underlying RPC client.
    rpc_client: Arc<RpcClient>,

    /// Block cache (by block number) - includes block, witness, and contracts.
    block_cache: Mutex<LruCache<u64, CachedBlockData>>,

    /// Block hash to block number mapping cache.
    hash_to_number: Mutex<LruCache<B256, u64>>,

    /// Transaction hash to (block_number, tx_index) mapping cache.
    /// This allows us to skip the get_transaction_by_hash RPC call when we've
    /// already seen this transaction in a block trace.
    tx_to_location: Mutex<LruCache<B256, (u64, usize)>>,

    /// Contract bytecode cache (by code hash).
    contract_cache: Mutex<LruCache<B256, Bytecode>>,

    /// In-flight block requests for single-flight pattern.
    inflight_blocks: Mutex<HashMap<u64, InFlightSender<CachedBlockData>>>,

    /// In-flight contract requests for single-flight pattern.
    inflight_contracts: Mutex<HashMap<B256, InFlightSender<Bytecode>>>,

    /// Maximum cache size configuration.
    _config: CacheConfig,
}

impl CachedDataProvider {
    /// Creates a new cached data provider.
    ///
    /// Internally creates an `RpcClient` from the given endpoint URLs. All RPC
    /// interaction is encapsulated here – callers only need to work with the
    /// cache layer.
    pub fn new(rpc_endpoint: &str, witness_endpoint: &str, config: CacheConfig) -> eyre::Result<Self> {
        let rpc_client = Arc::new(RpcClient::new(rpc_endpoint, witness_endpoint)?);

        // Use min of max_blocks and max_witnesses for the block cache
        let block_cache_size = config.max_blocks.min(config.max_witnesses);
        // Assume ~100 transactions per block for tx mapping cache
        let tx_cache_size = block_cache_size * 100;

        Ok(Self {
            rpc_client,
            block_cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(block_cache_size).unwrap(),
            )),
            hash_to_number: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(block_cache_size).unwrap(),
            )),
            tx_to_location: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(tx_cache_size).unwrap(),
            )),
            contract_cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(config.max_contracts).unwrap(),
            )),
            inflight_blocks: Mutex::new(HashMap::new()),
            inflight_contracts: Mutex::new(HashMap::new()),
            _config: config,
        })
    }

    /// Gets block data (block + witness + contracts) with caching.
    ///
    /// Uses single-flight pattern: if multiple requests come in for the same block,
    /// only one RPC call is made and all waiters receive the result.
    pub async fn get_block_data(&self, block_num: u64) -> Result<CachedBlockData> {
        // Check cache first
        {
            let mut cache = self.block_cache.lock();
            if let Some(data) = cache.get(&block_num) {
                metrics::record_cache_hit("block");
                debug!("Cache hit for block {}", block_num);
                return Ok(data.clone());
            }
        }
        metrics::record_cache_miss("block");

        // Check if there's an in-flight request
        let receiver = {
            let mut inflight = self.inflight_blocks.lock();
            if let Some(sender) = inflight.get(&block_num) {
                // Join existing request
                debug!("Joining in-flight request for block {}", block_num);
                Some(sender.subscribe())
            } else {
                // Start new request
                let (tx, _) = broadcast::channel(1);
                inflight.insert(block_num, tx);
                None
            }
        };

        if let Some(mut rx) = receiver {
            // Wait for in-flight request
            match rx.recv().await {
                Ok(Ok(data)) => return Ok(data),
                Ok(Err(e)) => return Err(eyre::eyre!("{}", e)),
                Err(_) => return Err(eyre::eyre!("In-flight request dropped")),
            }
        }

        // We're the leader - fetch the data
        let result = self.fetch_block_data_internal(block_num).await;

        // Notify waiters and cleanup
        let notify_result = match &result {
            Ok(data) => Ok(data.clone()),
            Err(e) => Err(e.to_string()),
        };
        {
            let mut inflight = self.inflight_blocks.lock();
            if let Some(sender) = inflight.remove(&block_num) {
                let _ = sender.send(notify_result);
            }
        }

        // Cache the result on success
        if let Ok(ref data) = result {
            let mut cache = self.block_cache.lock();
            cache.put(block_num, data.clone());
            // Also update hash_to_number mapping
            let mut h2n = self.hash_to_number.lock();
            h2n.put(data.block.header.hash, block_num);
            drop(h2n);
            drop(cache);
            // Index transaction locations
            self.index_block_transactions(data);
        }

        result
    }

    /// Internal method to fetch block data from RPC.
    async fn fetch_block_data_internal(&self, block_num: u64) -> Result<CachedBlockData> {
        debug!("Fetching block {} from RPC", block_num);

        // Fetch block
        let block = self
            .rpc_client
            .get_block(BlockId::Number(BlockNumberOrTag::Number(block_num)), true)
            .await?;

        // Fetch witness
        let (salt_witness, _mpt_witness) = self
            .rpc_client
            .get_witness(block.header.number, block.header.hash)
            .await?;

        // Extract code hashes and fetch contracts (with caching)
        let code_hashes = validator_core::extract_code_hashes(&salt_witness);
        let contracts = self.get_contracts(&code_hashes).await?;

        Ok(CachedBlockData {
            block,
            salt_witness,
            contracts,
        })
    }

    /// Gets block data by hash.
    ///
    /// First checks the hash_to_number cache, then reuses get_block_data for the actual fetch.
    /// This avoids fetching the block twice when we already have the mapping.
    pub async fn get_block_data_by_hash(&self, block_hash: B256) -> Result<CachedBlockData> {
        // Check if we have a cached hash -> number mapping
        let cached_num = {
            let mut h2n = self.hash_to_number.lock();
            h2n.get(&block_hash).copied()
        };

        if let Some(block_num) = cached_num {
            debug!("Hash to number cache hit: {} -> {}", block_hash, block_num);
            // Use get_block_data which handles caching and single-flight
            return self.get_block_data(block_num).await;
        }

        // No cached mapping, need to fetch the block to get its number
        debug!("Hash to number cache miss for {}", block_hash);
        let block = self
            .rpc_client
            .get_block(BlockId::Hash(block_hash.into()), true)
            .await?;

        let block_num = block.header.number;

        // Update hash_to_number mapping
        {
            let mut h2n = self.hash_to_number.lock();
            h2n.put(block_hash, block_num);
        }

        // Check if we already have this block cached by number
        {
            let mut cache = self.block_cache.lock();
            if let Some(data) = cache.get(&block_num) {
                if data.block.header.hash == block_hash {
                    metrics::record_cache_hit("block");
                    return Ok(data.clone());
                }
            }
        }
        metrics::record_cache_miss("block");

        // Fetch witness and contracts
        let (salt_witness, _mpt_witness) = self
            .rpc_client
            .get_witness(block.header.number, block.header.hash)
            .await?;

        let code_hashes = validator_core::extract_code_hashes(&salt_witness);
        let contracts = self.get_contracts(&code_hashes).await?;

        let data = CachedBlockData {
            block,
            salt_witness,
            contracts,
        };

        // Cache it and index transactions
        {
            let mut cache = self.block_cache.lock();
            cache.put(block_num, data.clone());
        }
        self.index_block_transactions(&data);

        Ok(data)
    }

    /// Gets multiple contracts with caching and single-flight.
    async fn get_contracts(&self, code_hashes: &[B256]) -> Result<HashMap<B256, Bytecode>> {
        let mut result = HashMap::new();
        let mut missing = Vec::new();

        // Check cache for each contract
        {
            let mut cache = self.contract_cache.lock();
            for &hash in code_hashes {
                if let Some(bytecode) = cache.get(&hash) {
                    metrics::record_cache_hit("contract");
                    result.insert(hash, bytecode.clone());
                } else {
                    metrics::record_cache_miss("contract");
                    missing.push(hash);
                }
            }
        }

        // Fetch missing contracts
        for hash in missing {
            match self.get_contract(hash).await {
                Ok(bytecode) => {
                    result.insert(hash, bytecode);
                }
                Err(e) => {
                    warn!("Failed to fetch contract {}: {}", hash, e);
                }
            }
        }

        Ok(result)
    }

    /// Gets a single contract with caching and single-flight.
    async fn get_contract(&self, hash: B256) -> Result<Bytecode> {
        // Check cache
        {
            let mut cache = self.contract_cache.lock();
            if let Some(bytecode) = cache.get(&hash) {
                return Ok(bytecode.clone());
            }
        }

        // Check for in-flight request
        let receiver = {
            let mut inflight = self.inflight_contracts.lock();
            if let Some(sender) = inflight.get(&hash) {
                Some(sender.subscribe())
            } else {
                let (tx, _) = broadcast::channel(1);
                inflight.insert(hash, tx);
                None
            }
        };

        if let Some(mut rx) = receiver {
            match rx.recv().await {
                Ok(Ok(bytecode)) => return Ok(bytecode),
                Ok(Err(e)) => return Err(eyre::eyre!("{}", e)),
                Err(_) => return Err(eyre::eyre!("In-flight request dropped")),
            }
        }

        // Fetch from RPC
        let result = self.rpc_client.get_code(hash).await.map(Bytecode::new_raw);

        // Notify waiters
        let notify_result = match &result {
            Ok(bytecode) => Ok(bytecode.clone()),
            Err(e) => Err(e.to_string()),
        };
        {
            let mut inflight = self.inflight_contracts.lock();
            if let Some(sender) = inflight.remove(&hash) {
                let _ = sender.send(notify_result);
            }
        }

        // Cache on success
        if let Ok(ref bytecode) = result {
            let mut cache = self.contract_cache.lock();
            cache.put(hash, bytecode.clone());
        }

        result
    }

    /// Resolves a block tag to a concrete block number.
    pub async fn resolve_block_number(&self, tag: BlockNumberOrTag) -> Result<u64> {
        match tag {
            BlockNumberOrTag::Number(n) => Ok(n),
            BlockNumberOrTag::Latest => self.rpc_client.get_latest_block_number().await,
            other => Err(eyre::eyre!("Unsupported block tag: {:?}", other)),
        }
    }

    /// Indexes transaction locations from a block into the tx_to_location cache.
    fn index_block_transactions(&self, data: &CachedBlockData) {
        use alloy_rpc_types_eth::BlockTransactions;

        if let BlockTransactions::Full(txs) = &data.block.transactions {
            let mut tx_cache = self.tx_to_location.lock();
            for (idx, tx) in txs.iter().enumerate() {
                // Access tx_hash through the inner envelope
                let tx_hash = tx.inner.inner.tx_hash();
                tx_cache.put(tx_hash, (data.block.header.number, idx));
            }
        }
    }

    /// Gets block data and transaction index for a transaction hash.
    ///
    /// This method is optimized to avoid extra RPC calls:
    /// 1. First checks the tx_to_location cache for a known mapping
    /// 2. If found, reuses get_block_data with the cached block number
    /// 3. If not found, fetches the transaction to find its block, then gets block data
    /// 4. Updates the tx_to_location cache from the block's transactions
    ///
    /// Returns (block_data, tx_index) tuple.
    pub async fn get_block_data_for_tx(&self, tx_hash: B256) -> Result<(CachedBlockData, usize)> {
        // Check if we have a cached tx -> (block_number, tx_index) mapping
        let cached_location = {
            let mut tx_cache = self.tx_to_location.lock();
            tx_cache.get(&tx_hash).copied()
        };

        if let Some((block_num, tx_idx)) = cached_location {
            debug!("Tx location cache hit: {} -> block {} idx {}", tx_hash, block_num, tx_idx);
            let data = self.get_block_data(block_num).await?;
            return Ok((data, tx_idx));
        }

        debug!("Tx location cache miss for {}", tx_hash);

        // No cached mapping, need to fetch the transaction to find its block
        let (tx, block_hash) = self
            .rpc_client
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or_else(|| eyre::eyre!("Transaction {} not found", tx_hash))?;

        let tx_index = tx
            .transaction_index
            .ok_or_else(|| eyre::eyre!("Transaction {} is pending", tx_hash))?
            as usize;

        // Get block data (this will cache the block)
        let data = self.get_block_data_by_hash(block_hash).await?;

        // Index all transactions from this block into the cache
        self.index_block_transactions(&data);

        Ok((data, tx_index))
    }
}
