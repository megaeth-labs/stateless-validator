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

use std::{
    hash::RandomState,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use alloy_consensus::Transaction;
use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockTransactions;
use quick_cache::{
    OptionsBuilder, Weighter,
    sync::{Cache, DefaultLifecycle},
};
use stateless_common::witness_size::light_witness_memory_bytes;
use stateless_db::bytecode_weight;
use tracing::debug;

use crate::{
    data_provider::BlockData,
    metrics::{CACHE_TYPE_BLOCK_DATA, CacheMetrics, CacheStats},
};

/// Default maximum memory for the block-data cache (1 GB).
pub const DEFAULT_BLOCK_DATA_CACHE_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Shard count, pinned so the per-shard byte budget — the admission ceiling for a single
/// entry — is `max_bytes / 4` on every host. quick_cache's default shard count scales
/// with the core count, which would shrink the largest admissible block as machines get
/// bigger; four shards keep contention negligible at trace-server request rates while
/// leaving the ceiling far above any realistic block.
pub(crate) const BLOCK_DATA_CACHE_SHARDS: usize = 4;

/// Assumed typical in-memory size of one resolved block, used only to derive the
/// estimated-items capacity hint (initial sizing + ghost-queue length, not correctness)
/// from the byte budget. Measured with `block_data_weight` over the mainnet fixture
/// blocks: quiet blocks (~25 txs) weigh ~70–360 KB and the load-test-era ones (~600 txs)
/// ~0.5–1.0 MB, so 256 KiB sits near the sample median.
const EXPECTED_BLOCK_DATA_BYTES: u64 = 256 * 1024;

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
            // Defensive: tracing requires full transactions, so cached blocks always carry
            // `Full` and this arm is not reached in practice.
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
/// Entries heavier than a single shard's byte budget (`max_bytes` divided by the pinned
/// [`BLOCK_DATA_CACHE_SHARDS`]) are never admitted by `quick_cache`, so with a small byte
/// budget the largest blocks simply bypass the cache instead of thrashing it. Non-retained
/// inserts are counted, so a budget too small for real blocks is visible instead of
/// masquerading as an ordinary low hit rate.
pub struct BlockDataCache {
    cache: MemoryCache,
    hits: AtomicU64,
    misses: AtomicU64,
    admission_rejects: AtomicU64,
    metrics: CacheMetrics,
}

impl BlockDataCache {
    /// Creates a new cache bounded to `max_bytes` of estimated memory.
    pub fn new(max_bytes: u64) -> Self {
        Self::with_shards(max_bytes, BLOCK_DATA_CACHE_SHARDS)
    }

    /// [`Self::new`] with an explicit shard count; tests pin a single shard so the
    /// admission arithmetic is deterministic.
    fn with_shards(max_bytes: u64, shards: usize) -> Self {
        let estimated_items = (max_bytes / EXPECTED_BLOCK_DATA_BYTES).clamp(64, 4096) as usize;
        let options = OptionsBuilder::new()
            .estimated_items_capacity(estimated_items)
            .weight_capacity(max_bytes)
            .shards(shards)
            .build()
            .expect("block-data cache options are statically valid");
        Self {
            cache: Cache::with_options(
                options,
                BlockDataWeighter,
                RandomState::default(),
                DefaultLifecycle::default(),
            ),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            admission_rejects: AtomicU64::new(0),
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
    /// An insert the cache did not retain — the entry outweighs a shard's budget, or was
    /// evicted on arrival — is counted and logged, since it is otherwise indistinguishable
    /// from an ordinary miss on the next request. The check races concurrent inserts, so
    /// an entry legitimately evicted under pressure between the insert and the check also
    /// counts — the counter is a pressure signal, not an exact tally of oversized entries.
    pub fn insert(&self, hash: B256, data: Arc<BlockData>) {
        let weight = block_data_weight(&data);
        self.cache.insert(hash, (weight, data));
        if self.cache.peek(&hash).is_none() {
            self.admission_rejects.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_admission_reject();
            debug!(block_hash = %hash, weight, "Block-data cache did not retain insert");
        }
        self.refresh_size_gauges();
    }

    /// Removes an entry, e.g. when its witness turned out to be unusable at execution time —
    /// a decodable but wrong upstream response must not stay pinned until eviction. Returns
    /// whether an entry was present.
    pub fn remove(&self, hash: &B256) -> bool {
        let removed = self.cache.remove(hash).is_some();
        self.refresh_size_gauges();
        removed
    }

    /// Returns cache statistics and refreshes the size gauges.
    pub fn stats(&self) -> CacheStats {
        let (entry_count, total_bytes) = self.refresh_size_gauges();
        CacheStats {
            entry_count: entry_count as u64,
            total_bytes,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }

    /// Pushes the current entry count and byte weight to the Prometheus gauges and returns
    /// the pair, so callers don't re-sweep the shards for values just read.
    fn refresh_size_gauges(&self) -> (usize, u64) {
        let (entry_count, total_bytes) = (self.cache.len(), self.cache.weight());
        self.metrics.set_size(entry_count, total_bytes as usize);
        (entry_count, total_bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{Signed, TxEip7702, transaction::Recovered};
    use alloy_primitives::{Address, Bytes, Signature, U256};
    use mega_evm::{
        alloy_eips::{
            eip2930::{AccessList, AccessListItem},
            eip7702::{Authorization, SignedAuthorization},
        },
        op_alloy_consensus::OpTxEnvelope,
    };
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

    /// Builds an EIP-7702 transaction carrying `calldata_len` input bytes, one access-list
    /// item with `storage_keys` keys, and `auths` signed authorizations.
    fn synthetic_list_tx(
        calldata_len: usize,
        storage_keys: usize,
        auths: usize,
    ) -> op_alloy_rpc_types::Transaction {
        let tx = TxEip7702 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: Address::ZERO,
            value: U256::ZERO,
            access_list: AccessList(vec![AccessListItem {
                address: Address::ZERO,
                storage_keys: vec![B256::ZERO; storage_keys],
            }]),
            authorization_list: (0..auths)
                .map(|_| {
                    SignedAuthorization::new_unchecked(
                        Authorization { chain_id: U256::ONE, address: Address::ZERO, nonce: 0 },
                        0,
                        U256::ONE,
                        U256::ONE,
                    )
                })
                .collect(),
            input: Bytes::from(vec![0u8; calldata_len]),
        };
        let signed = Signed::new_unchecked(tx, Signature::test_signature(), B256::ZERO);
        op_alloy_rpc_types::Transaction {
            inner: alloy_rpc_types_eth::Transaction {
                inner: Recovered::new_unchecked(OpTxEnvelope::Eip7702(signed), Address::ZERO),
                block_hash: None,
                block_number: None,
                transaction_index: None,
                effective_gas_price: None,
            },
            deposit_nonce: None,
            deposit_receipt_version: None,
        }
    }

    /// The variable transaction terms must be charged exactly: appending a transaction
    /// with known calldata, access-list, and authorization-list sizes increases the weight
    /// by precisely the documented arithmetic — dropping any term fails this test.
    #[test]
    fn weigher_charges_access_and_authorization_lists() {
        let mut data = fixture_block_data();
        let base = block_data_weight(&data);

        let (calldata, keys, auths) = (100usize, 3usize, 2usize);
        let BlockTransactions::Full(txs) = &mut data.block.transactions else {
            panic!("fixture block must carry full transactions");
        };
        txs.push(synthetic_list_tx(calldata, keys, auths));

        let expected = TX_OVERHEAD +
            calldata as u64 +
            ACCESS_LIST_ITEM_BYTES +
            keys as u64 * STORAGE_KEY_BYTES +
            auths as u64 * AUTHORIZATION_BYTES;
        assert_eq!(block_data_weight(&data) - base, expected);
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

    /// With one shard the admission arithmetic is deterministic: three same-weight inserts
    /// into a budget with room for two must retain exactly two entries — this fails both
    /// if the budget is not enforced and if the cache silently admits nothing.
    #[test]
    fn eviction_respects_byte_budget() {
        let data = Arc::new(fixture_block_data());
        let one = block_data_weight(&data);
        let cache = BlockDataCache::with_shards(one * 5 / 2, 1);

        for i in 1..=3u8 {
            cache.insert(B256::from([i; 32]), Arc::clone(&data));
        }
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 2, "budget with room for two must retain exactly two");
        assert_eq!(stats.total_bytes, one * 2);
    }

    /// An entry heavier than a shard's budget is never admitted, and the rejected insert
    /// is counted instead of masquerading as an ordinary miss.
    #[test]
    fn oversized_entry_is_rejected_and_counted() {
        let data = Arc::new(fixture_block_data());
        let one = block_data_weight(&data);
        let cache = BlockDataCache::with_shards(one / 2, 1);

        let hash = B256::from([1u8; 32]);
        cache.insert(hash, data);
        assert!(cache.get(&hash).is_none());
        assert_eq!(cache.stats().entry_count, 0);
        assert_eq!(cache.admission_rejects.load(Ordering::Relaxed), 1);
    }
}
