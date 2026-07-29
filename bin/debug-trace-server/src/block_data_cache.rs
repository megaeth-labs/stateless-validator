//! Bounded in-memory cache of fully-resolved [`BlockData`], keyed by block hash.
//!
//! Sits between the HTTP response cache and the DB / RPC tiers so that requests which miss
//! the response cache — different tracer variants of one block, and especially
//! `debug_traceTransaction` calls for different transactions of the same block, which are
//! never response-cached — reuse one witness fetch + contract resolution instead of
//! repeating it per request.
//!
//! Keying by hash makes entries immutable facts about that hash: block-number lookups
//! resolve number → hash against the local DB or upstream before touching this cache, so
//! canonicality is never cached and no reorg invalidation hook is needed. Entries for
//! orphaned hashes linger until evicted, bounded by the byte budget.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use alloy_consensus::Transaction;
use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockTransactions;
use quick_cache::{Weighter, sync::Cache};
use stateless_common::witness_size::light_witness_memory_bytes;
use stateless_db::bytecode_weight;

use crate::{
    data_provider::BlockData,
    metrics::{CACHE_TYPE_BLOCK_DATA, CacheMetrics, CacheStats},
};

/// Default maximum memory for the block-data cache (1 GB).
pub const DEFAULT_BLOCK_DATA_CACHE_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Initial capacity hint; not a cap.
const BLOCK_DATA_CACHE_ESTIMATED_ITEMS: usize = 1024;

/// Fixed per-entry bookkeeping overhead.
const ENTRY_OVERHEAD: u64 = 128;
/// Approximate fixed size of a block header + envelope.
const BLOCK_FIXED_OVERHEAD: u64 = 2048;
/// Approximate per-transaction size excluding variable-length fields (envelope, signature,
/// hashes).
const TX_OVERHEAD: u64 = 512;
/// Approximate per-item size of an EIP-2930 access-list entry excluding its storage keys
/// (address + vec header).
const ACCESS_LIST_ITEM_BYTES: u64 = 64;
/// Size of one access-list storage key.
const STORAGE_KEY_BYTES: u64 = 32;
/// Approximate size of one EIP-7702 signed authorization (chain id + address + nonce +
/// signature).
const AUTHORIZATION_BYTES: u64 = 192;

/// Approximates the in-memory footprint of a [`BlockData`].
///
/// Charges the witness KV/level payload, each contract's bytecode (same accounting as the
/// contract cache, via [`bytecode_weight`]), and a per-transaction envelope overhead plus
/// calldata — the only unbounded variable-size block component. Allocator and map-node
/// overhead is not counted, so true RSS can exceed the budget by tens of percent for
/// kv-heavy witnesses; the contracts term over-counts in the other direction (bytecode
/// allocations are refcounted and shared with the contract cache).
///
/// Computed once per entry at insert time; the cache stores the result so the weigher —
/// which quick_cache re-invokes on admission, promotion, and eviction, under a shard
/// lock — never re-walks the payload.
pub fn block_data_weight(data: &BlockData) -> u64 {
    let witness = light_witness_memory_bytes(&data.witness) as u64;
    let contracts: u64 = data.contracts.values().map(bytecode_weight).sum();
    let block = BLOCK_FIXED_OVERHEAD +
        match &data.block.transactions {
            BlockTransactions::Full(txs) => txs
                .iter()
                .map(|tx| {
                    let calldata = tx.inner.input().len() as u64;
                    let access_list = tx.inner.access_list().map_or(0, |al| {
                        al.iter()
                            .map(|item| {
                                ACCESS_LIST_ITEM_BYTES +
                                    item.storage_keys.len() as u64 * STORAGE_KEY_BYTES
                            })
                            .sum()
                    });
                    let authorizations = tx
                        .inner
                        .authorization_list()
                        .map_or(0, |auths| auths.len() as u64 * AUTHORIZATION_BYTES);
                    TX_OVERHEAD + calldata + access_list + authorizations
                })
                .sum::<u64>(),
            other => other.len() as u64 * TX_OVERHEAD,
        };
    ENTRY_OVERHEAD + witness + contracts + block
}

/// Weighter reading the [`block_data_weight`] precomputed at insert.
#[derive(Debug, Clone, Default)]
pub struct BlockDataWeighter;

impl Weighter<B256, (u64, Arc<BlockData>)> for BlockDataWeighter {
    fn weight(&self, _key: &B256, val: &(u64, Arc<BlockData>)) -> u64 {
        val.0
    }
}

type MemoryCache = Cache<B256, (u64, Arc<BlockData>), BlockDataWeighter>;

/// Thread-safe bounded cache of resolved block data.
///
/// Entries heavier than a cache shard's budget are never admitted by `quick_cache`, so with
/// a small byte budget the largest blocks simply bypass the cache instead of thrashing it.
pub struct BlockDataCache {
    cache: MemoryCache,
    hits: AtomicU64,
    misses: AtomicU64,
    metrics: CacheMetrics,
}

impl BlockDataCache {
    /// Creates a new cache bounded to `max_bytes` of estimated memory.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            cache: Cache::with_weighter(
                BLOCK_DATA_CACHE_ESTIMATED_ITEMS,
                max_bytes,
                BlockDataWeighter,
            ),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            metrics: CacheMetrics::new_for_cache(CACHE_TYPE_BLOCK_DATA),
        }
    }

    /// Returns the cached block data for `hash`, recording hit/miss counters.
    pub fn get(&self, hash: &B256) -> Option<Arc<BlockData>> {
        let result = self.cache.get(hash).map(|(_, data)| data);
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_hit();
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_miss();
        }
        result
    }

    /// Inserts resolved block data, weighing it once, and refreshes the size gauges.
    pub fn insert(&self, hash: B256, data: Arc<BlockData>) {
        self.cache.insert(hash, (block_data_weight(&data), data));
        self.refresh_size_gauges();
    }

    /// Removes an entry, e.g. when its witness turned out to be unusable at execution time —
    /// a decodable but wrong upstream response must not stay pinned until eviction.
    pub fn remove(&self, hash: &B256) {
        self.cache.remove(hash);
        self.refresh_size_gauges();
    }

    /// Returns cache statistics and refreshes the size gauges.
    pub fn stats(&self) -> CacheStats {
        self.refresh_size_gauges();
        CacheStats {
            entry_count: self.cache.len() as u64,
            total_bytes: self.cache.weight(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }

    /// Pushes the current entry count and byte weight to the Prometheus gauges.
    fn refresh_size_gauges(&self) {
        self.metrics.set_size(self.cache.len(), self.cache.weight() as usize);
    }
}

#[cfg(test)]
mod tests {
    use revm::state::Bytecode;

    use super::*;
    use crate::data_provider::test_support::fixture_block_data;

    #[test]
    fn weigher_charges_witness_contracts_and_transactions() {
        let data = fixture_block_data();
        let witness_bytes = light_witness_memory_bytes(&data.witness) as u64;
        let contract_bytes: u64 = data.contracts.values().map(bytecode_weight).sum();

        let weight = block_data_weight(&data);
        assert!(weight >= witness_bytes + contract_bytes + BLOCK_FIXED_OVERHEAD);

        let mut heavier = fixture_block_data();
        heavier.contracts.insert(B256::from([9u8; 32]), Bytecode::new_raw([0u8; 64].into()));
        assert!(block_data_weight(&heavier) > weight, "adding a contract must increase the weight");
    }

    #[test]
    fn hit_miss_counters_and_stats() {
        let cache = BlockDataCache::new(DEFAULT_BLOCK_DATA_CACHE_MAX_BYTES);
        let hash = B256::from([1u8; 32]);
        let data = Arc::new(fixture_block_data());

        assert!(cache.get(&hash).is_none());
        cache.insert(hash, Arc::clone(&data));
        let got = cache.get(&hash).expect("cached entry");
        assert!(Arc::ptr_eq(&got, &data), "hits must share the same allocation");

        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert!(stats.total_bytes > 0);

        // Execution-failure eviction path: a removed entry misses on the next request.
        cache.remove(&hash);
        assert!(cache.get(&hash).is_none());
        assert_eq!(cache.stats().entry_count, 0);
    }

    #[test]
    fn eviction_respects_byte_budget() {
        let data = Arc::new(fixture_block_data());
        let one = block_data_weight(&data);
        let cache = BlockDataCache::new(one * 3 / 2);

        for i in 1..=3u8 {
            cache.insert(B256::from([i; 32]), Arc::clone(&data));
        }
        // quick_cache admits entries only within the byte budget (over-budget entries are
        // rejected or evict older ones), so the cache never exceeds it.
        let stats = cache.stats();
        assert!(stats.total_bytes <= one * 3 / 2);
        assert!(stats.entry_count <= 2);
    }
}
