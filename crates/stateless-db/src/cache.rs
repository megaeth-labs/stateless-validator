//! In-memory write-through cache for contract bytecodes.

use std::{collections::HashMap, sync::Arc};

use alloy_primitives::B256;
use dashmap::DashMap;
use revm::state::Bytecode;
use stateless_core::db::{ContractStore, StoreResult};

/// In-memory contract bytecode cache backed by persistent storage.
///
/// Reads check the in-memory `DashMap` first, falling back to the persistent store.
/// Writes go to both memory and disk (write-through).
pub struct ContractCache {
    memory: DashMap<B256, Bytecode>,
    store: Arc<dyn ContractStore>,
}

impl ContractCache {
    /// Creates a new contract cache backed by the given persistent store.
    pub fn new(store: Arc<dyn ContractStore>) -> Self {
        Self { memory: DashMap::new(), store }
    }

    /// Retrieves contract bytecodes, checking memory first then persistent store.
    ///
    /// Returns `(found, missing)`.
    pub fn get(&self, hashes: &[B256]) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
        let mut found = HashMap::new();
        let mut not_in_memory = Vec::new();

        for &hash in hashes {
            if let Some(entry) = self.memory.get(&hash) {
                found.insert(hash, entry.value().clone());
            } else {
                not_in_memory.push(hash);
            }
        }

        if not_in_memory.is_empty() {
            return Ok((found, Vec::new()));
        }

        let (from_disk, missing) = self.store.get_contracts(&not_in_memory)?;

        for (hash, bytecode) in &from_disk {
            self.memory.insert(*hash, bytecode.clone());
        }
        found.extend(from_disk);

        Ok((found, missing))
    }

    /// Adds contract bytecodes to both memory cache and persistent store (write-through).
    pub fn insert(&self, codes: &[(B256, Bytecode)]) -> StoreResult<()> {
        if codes.is_empty() {
            return Ok(());
        }

        self.store.add_contracts(codes)?;

        for (hash, bytecode) in codes {
            self.memory.insert(*hash, bytecode.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use alloy_primitives::Bytes;
    use stateless_core::db::StoreError;

    use super::*;

    fn bc(b: u8) -> Bytecode {
        Bytecode::new_raw(Bytes::from(vec![b]))
    }

    fn h(n: u8) -> B256 {
        B256::from([n; 32])
    }

    /// In-memory `ContractStore` that tracks hit counts and can be toggled to fail on writes.
    #[derive(Default)]
    struct FakeStore {
        data: dashmap::DashMap<B256, Bytecode>,
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
        ) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
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

        fn add_contracts(&self, codes: &[(B256, Bytecode)]) -> StoreResult<()> {
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
        cache.memory.insert(h(1), bc(0xAA));

        let (found, missing) = cache.get(&[h(1)]).unwrap();
        assert_eq!(found[&h(1)].bytes_slice(), bc(0xAA).bytes_slice());
        assert!(missing.is_empty());
        assert_eq!(store.get_calls(), 0, "memory hit must not hit store");
    }

    #[test]
    fn get_populates_memory_on_store_hit() {
        let store = Arc::new(FakeStore::default());
        store.data.insert(h(2), bc(0xBB));
        let cache = ContractCache::new(store.clone());

        let (found, missing) = cache.get(&[h(2)]).unwrap();
        assert_eq!(found[&h(2)].bytes_slice(), bc(0xBB).bytes_slice());
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
        cache.insert(&[(h(3), bc(0xCC))]).unwrap();

        assert_eq!(store.add_calls(), 1, "insert must write through to store");
        assert_eq!(store.data.get(&h(3)).unwrap().value().bytes_slice(), bc(0xCC).bytes_slice());
        assert_eq!(cache.memory.get(&h(3)).unwrap().value().bytes_slice(), bc(0xCC).bytes_slice());
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
}
