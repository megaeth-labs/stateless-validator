//! In-memory write-through cache for contract bytecodes.

use std::{
    collections::HashMap,
    hash::RandomState,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use alloy_primitives::B256;
use quick_cache::{
    Weighter,
    sync::{Cache, DefaultLifecycle},
};
use revm::state::Bytecode;
use stateless_core::db::{ContractLookup, ContractStore, StoreResult};

/// Default memory budget for the contract cache (512 MiB).
pub const DEFAULT_CONTRACT_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Default estimated entry count for initial sizing.
pub const DEFAULT_CONTRACT_CACHE_ESTIMATED_ITEMS: usize = 8192;

/// Configuration for the contract cache.
#[derive(Debug, Clone, Copy)]
pub struct ContractCacheConfig {
    /// Maximum memory-tier bytes before eviction (S3-FIFO).
    pub max_bytes: u64,
    /// Initial capacity hint; not a cap.
    pub estimated_items: usize,
}

impl Default for ContractCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_CONTRACT_CACHE_MAX_BYTES,
            estimated_items: DEFAULT_CONTRACT_CACHE_ESTIMATED_ITEMS,
        }
    }
}

/// Weighter that charges a fixed entry overhead plus the bytecode length.
#[derive(Debug, Clone, Default)]
pub(crate) struct BytecodeWeighter;

impl Weighter<B256, Arc<Bytecode>> for BytecodeWeighter {
    fn weight(&self, _key: &B256, val: &Arc<Bytecode>) -> u64 {
        const ENTRY_OVERHEAD: u64 = 128;
        ENTRY_OVERHEAD + val.bytes_slice().len() as u64
    }
}

type MemoryCache = Cache<
    B256,
    Arc<Bytecode>,
    BytecodeWeighter,
    RandomState,
    DefaultLifecycle<B256, Arc<Bytecode>>,
>;

/// Snapshot of cache counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContractCacheStats {
    /// Memory-tier hits.
    pub hits: u64,
    /// Memory-tier misses (fell through to persistent store).
    pub misses: u64,
    /// Successful `insert` calls (batches, not individual entries).
    pub inserts: u64,
    /// Current entry count in memory.
    pub len: usize,
    /// Current weight (bytes) in memory.
    pub weight: u64,
}

/// In-memory contract bytecode cache backed by persistent storage.
///
/// Reads check the in-memory cache first, falling back to the persistent store.
/// Writes go to both disk and memory (write-through; disk first so a failed store
/// write never leaves memory hotter than disk).
///
/// Values are stored as `Arc<Bytecode>` so that hits — the hot path — return by
/// reference-count bump instead of deep-copying the bytecode.
pub struct ContractCache {
    memory: MemoryCache,
    store: Arc<dyn ContractStore>,
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
}

impl ContractCache {
    /// Creates a new contract cache with default configuration.
    pub fn new(store: Arc<dyn ContractStore>) -> Self {
        Self::with_config(store, ContractCacheConfig::default())
    }

    /// Creates a new contract cache with the given configuration.
    pub fn with_config(store: Arc<dyn ContractStore>, config: ContractCacheConfig) -> Self {
        let memory = Cache::with(
            config.estimated_items,
            config.max_bytes,
            BytecodeWeighter,
            RandomState::default(),
            DefaultLifecycle::default(),
        );
        Self {
            memory,
            store,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
        }
    }

    /// Retrieves contract bytecodes, checking memory first then persistent store.
    ///
    /// Returns `(found, missing)`. Memory hits are trusted and not re-verified; the
    /// caller should use a verified RPC fetch (`RpcClient::get_codes(.., verify=true)`)
    /// to populate the cache so all entries arrive pre-verified.
    pub fn get(&self, hashes: &[B256]) -> StoreResult<ContractLookup> {
        let mut found = HashMap::with_capacity(hashes.len());
        let mut not_in_memory = Vec::with_capacity(hashes.len());

        for &hash in hashes {
            if let Some(arc) = self.memory.get(&hash) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                found.insert(hash, arc);
            } else {
                self.misses.fetch_add(1, Ordering::Relaxed);
                not_in_memory.push(hash);
            }
        }

        if not_in_memory.is_empty() {
            return Ok((found, Vec::new()));
        }

        let (from_disk, missing) = self.store.get_contracts(&not_in_memory)?;

        for (hash, arc) in &from_disk {
            self.memory.insert(*hash, arc.clone());
        }
        found.extend(from_disk);

        Ok((found, missing))
    }

    /// Adds contract bytecodes to both disk and memory (write-through).
    pub fn insert(&self, codes: &[(B256, Arc<Bytecode>)]) -> StoreResult<()> {
        if codes.is_empty() {
            return Ok(());
        }

        self.store.add_contracts(codes)?;

        for (hash, arc) in codes {
            self.memory.insert(*hash, arc.clone());
        }
        self.inserts.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Returns a snapshot of the cache counters.
    pub fn stats(&self) -> ContractCacheStats {
        ContractCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
            len: self.memory.len(),
            weight: self.memory.weight(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use alloy_primitives::Bytes;
    use stateless_core::db::StoreError;

    use super::*;

    fn bc(b: u8) -> Arc<Bytecode> {
        Arc::new(Bytecode::new_raw(Bytes::from(vec![b])))
    }

    fn bc_sized(len: usize, fill: u8) -> Arc<Bytecode> {
        Arc::new(Bytecode::new_raw(Bytes::from(vec![fill; len])))
    }

    fn h(n: u8) -> B256 {
        B256::from([n; 32])
    }

    /// In-memory `ContractStore` that tracks hit counts and can be toggled to fail on writes.
    #[derive(Default)]
    struct FakeStore {
        data: dashmap::DashMap<B256, Arc<Bytecode>>,
        get_calls: AtomicUsize,
        add_calls: AtomicUsize,
        fail_add: std::sync::atomic::AtomicBool,
    }

    impl FakeStore {
        fn get_calls(&self) -> usize {
            self.get_calls.load(Ordering::Relaxed)
        }
        fn add_calls(&self) -> usize {
            self.add_calls.load(Ordering::Relaxed)
        }
    }

    impl ContractStore for FakeStore {
        fn get_contracts(
            &self,
            hashes: &[B256],
        ) -> StoreResult<(HashMap<B256, Arc<Bytecode>>, Vec<B256>)> {
            self.get_calls.fetch_add(1, Ordering::Relaxed);
            let mut found = HashMap::new();
            let mut missing = Vec::new();
            for &h in hashes {
                match self.data.get(&h) {
                    Some(v) => {
                        found.insert(h, v.value().clone());
                    }
                    None => missing.push(h),
                }
            }
            Ok((found, missing))
        }

        fn add_contracts(&self, codes: &[(B256, Arc<Bytecode>)]) -> StoreResult<()> {
            self.add_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_add.load(Ordering::Relaxed) {
                return Err(StoreError::Corrupt("fake add failure".into()));
            }
            for (hash, bc) in codes {
                self.data.insert(*hash, bc.clone());
            }
            Ok(())
        }
    }

    #[test]
    fn get_returns_from_memory_without_hitting_store() {
        let store = Arc::new(FakeStore::default());
        let cache = ContractCache::new(store.clone());
        let original = bc(0xAA);
        cache.memory.insert(h(1), original.clone());

        let (found, missing) = cache.get(&[h(1)]).unwrap();
        let returned = found.get(&h(1)).unwrap();
        assert!(Arc::ptr_eq(returned, &original), "memory hit must share the same Arc allocation");
        assert!(missing.is_empty());
        assert_eq!(store.get_calls(), 0, "memory hit must not hit store");
    }

    #[test]
    fn get_populates_memory_on_store_hit() {
        let store = Arc::new(FakeStore::default());
        let original = bc(0xBB);
        store.data.insert(h(2), original.clone());
        let cache = ContractCache::new(store.clone());

        let (found, missing) = cache.get(&[h(2)]).unwrap();
        assert_eq!(found[&h(2)].bytes_slice(), original.bytes_slice());
        assert!(missing.is_empty());
        assert_eq!(store.get_calls(), 1);

        // Second call hits memory: store is not touched again.
        let _ = cache.get(&[h(2)]).unwrap();
        assert_eq!(store.get_calls(), 1, "second get must hit memory");
    }

    #[test]
    fn get_reports_missing_when_store_also_misses() {
        let store = Arc::new(FakeStore::default());
        let cache = ContractCache::new(store);
        let (found, missing) = cache.get(&[h(9)]).unwrap();
        assert!(found.is_empty());
        assert_eq!(missing, vec![h(9)]);
    }

    #[test]
    fn insert_writes_through_to_store_and_memory() {
        let store = Arc::new(FakeStore::default());
        let cache = ContractCache::new(store.clone());
        let original = bc(0xCC);
        cache.insert(&[(h(3), original.clone())]).unwrap();

        assert_eq!(store.add_calls(), 1, "insert must write through to store");
        assert_eq!(store.data.get(&h(3)).unwrap().value().bytes_slice(), original.bytes_slice());
        assert_eq!(cache.memory.get(&h(3)).unwrap().bytes_slice(), original.bytes_slice());
    }

    #[test]
    fn insert_store_error_propagates_and_leaves_memory_unchanged() {
        let store = Arc::new(FakeStore::default());
        store.fail_add.store(true, Ordering::Relaxed);
        let cache = ContractCache::new(store.clone());

        let err = cache.insert(&[(h(4), bc(0xDD))]).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)));
        assert!(cache.memory.get(&h(4)).is_none(), "failed store write must not populate memory");
    }

    #[test]
    fn insert_empty_is_noop() {
        let store = Arc::new(FakeStore::default());
        let cache = ContractCache::new(store.clone());
        cache.insert(&[]).unwrap();
        assert_eq!(store.add_calls(), 0);
    }

    #[test]
    fn stats_track_hits_misses_and_inserts() {
        let store = Arc::new(FakeStore::default());
        let cache = ContractCache::new(store.clone());
        cache.insert(&[(h(5), bc(0xEE))]).unwrap();

        let _ = cache.get(&[h(5), h(5), h(99)]).unwrap();
        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.inserts, 1);
    }

    #[test]
    fn eviction_respects_byte_budget() {
        // Each entry weighs 128 (overhead) + 1024 (bytes) = 1152; budget 3072 fits 2.
        let store = Arc::new(FakeStore::default());
        let cache = ContractCache::with_config(
            store.clone(),
            ContractCacheConfig { max_bytes: 3 * 1024, estimated_items: 8 },
        );

        for i in 0..10u8 {
            cache.insert(&[(h(i), bc_sized(1024, i))]).unwrap();
        }

        let stats = cache.stats();
        assert!(
            stats.weight <= 3 * 1024,
            "memory weight {} must be bounded by max_bytes",
            stats.weight,
        );
        assert!(
            stats.len >= 1 && stats.len <= 2,
            "weight budget fits at most 2 entries; len={}",
            stats.len,
        );
    }
}
