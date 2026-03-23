//! HTTP RPC Response Cache
//!
//! Caches pre-serialized JSON responses for specific RPC methods to avoid redundant
//! serialization and computation.
//!
//! # Design
//!
//! - **Cache Key**: `(CachedResource, block_number, ResponseVariant)`
//! - **Secondary Index**: `block_hash` -> `block_number` for reorg invalidation
//! - **Eviction**: S3-FIFO algorithm via `quick_cache` with memory-based weighting

use std::{
    collections::{HashMap, HashSet},
    hash::RandomState,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use alloy_primitives::B256;
use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use quick_cache::{Lifecycle, Weighter, sync::Cache};
use tracing::{debug, trace};

use crate::metrics::{CACHE_TYPE_DEBUG_TRACE, CACHE_TYPE_TRACE, CacheMetrics};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default maximum memory for the response cache (1 GB).
pub const DEFAULT_RESPONSE_CACHE_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Default estimated number of cached responses.
pub const DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS: usize = 1_000;

/// Configuration for the response cache.
#[derive(Debug, Clone, Copy)]
pub struct ResponseCacheConfig {
    /// Maximum memory for the cache in bytes.
    pub max_bytes: u64,
    /// Estimated number of items for initial capacity.
    pub estimated_items: usize,
}

impl ResponseCacheConfig {
    /// Creates a new configuration with the given parameters.
    pub const fn new(max_bytes: u64, estimated_items: usize) -> Self {
        Self { max_bytes, estimated_items }
    }
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_RESPONSE_CACHE_MAX_BYTES,
            estimated_items: DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache Key Types
// ---------------------------------------------------------------------------

/// Cached resource types for RPC response caching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CachedResource {
    /// Debug trace block data (from `debug_traceBlockByNumber` or `debug_traceBlockByHash`)
    DebugTraceBlock,
    /// Parity trace block data (from `trace_block`)
    TraceBlock,
}

/// Tracer types for `debug_traceBlock` methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TracerType {
    /// No tracer specified (default struct logger)
    #[default]
    Default,
    /// callTracer - traces call frames
    CallTracer,
    /// prestateTracer - returns prestate of touched accounts
    PrestateTracer,
    /// 4byteTracer - collects function selectors
    FourByteTracer,
    /// noopTracer - no-op tracer for benchmarking
    NoopTracer,
    /// flatCallTracer - flat call traces
    FlatCallTracer,
}

impl TracerType {
    /// Parses a tracer name string into a [`TracerType`].
    #[allow(dead_code)] // Used in tests
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "callTracer" => Some(Self::CallTracer),
            "prestateTracer" => Some(Self::PrestateTracer),
            "4byteTracer" => Some(Self::FourByteTracer),
            "noopTracer" => Some(Self::NoopTracer),
            "flatCallTracer" => Some(Self::FlatCallTracer),
            _ => None,
        }
    }

    /// Creates a TracerType from GethDebugTracingOptions.
    pub fn from_geth_options(opts: &GethDebugTracingOptions) -> Self {
        use alloy_rpc_types_trace::geth::{GethDebugBuiltInTracerType, GethDebugTracerType};

        match &opts.tracer {
            None => Self::Default,
            Some(GethDebugTracerType::BuiltInTracer(builtin)) => match builtin {
                GethDebugBuiltInTracerType::CallTracer => Self::CallTracer,
                GethDebugBuiltInTracerType::PreStateTracer => Self::PrestateTracer,
                GethDebugBuiltInTracerType::FourByteTracer => Self::FourByteTracer,
                GethDebugBuiltInTracerType::NoopTracer => Self::NoopTracer,
                GethDebugBuiltInTracerType::FlatCallTracer => Self::FlatCallTracer,
                // MuxTracer and any future tracers fall back to Default with config hash
                _ => Self::Default,
            },
            // JS tracers get their own unique hash via config
            Some(GethDebugTracerType::JsTracer(_)) => Self::Default,
        }
    }
}

/// Response variant that distinguishes different parameter combinations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum ResponseVariant {
    /// Default variant (no special parameters).
    #[default]
    Default,
    /// Tracer variant for debug methods (tracer type + optional config hash).
    Tracer(TracerType, Option<u64>),
}

impl ResponseVariant {
    /// Creates a Tracer variant from GethDebugTracingOptions.
    pub fn from_geth_options(opts: &GethDebugTracingOptions) -> Self {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };

        let tracer_type = TracerType::from_geth_options(opts);

        // Hash the tracer config for cache key discrimination
        let config_hash = if opts.tracer_config.is_null() {
            None
        } else {
            let mut hasher = DefaultHasher::new();
            // Hash the debug representation of the config
            format!("{:?}", opts.tracer_config).hash(&mut hasher);
            // Also hash relevant default options
            format!("{:?}", opts.config).hash(&mut hasher);
            Some(hasher.finish())
        };

        Self::Tracer(tracer_type, config_hash)
    }
}

/// Cache key: resource type + block number + response variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResponseCacheKey {
    /// The cached resource type.
    pub resource: CachedResource,
    /// The block number.
    pub block_number: u64,
    /// The response variant (e.g., tracer type).
    pub variant: ResponseVariant,
}

impl ResponseCacheKey {
    /// Creates a new cache key.
    pub const fn new(
        resource: CachedResource,
        block_number: u64,
        variant: ResponseVariant,
    ) -> Self {
        Self { resource, block_number, variant }
    }
}

// ---------------------------------------------------------------------------
// Cached Response
// ---------------------------------------------------------------------------

/// A cached JSON response entry.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// Pre-serialized JSON result.
    json: Arc<str>,
    /// Cached byte length for efficient weight calculation.
    byte_len: usize,
}

impl CachedResponse {
    /// Creates a new cached response from a JSON value.
    pub fn new(value: serde_json::Value) -> Self {
        let json = serde_json::to_string(&value).unwrap_or_default();
        let byte_len = json.len();
        Self { json: json.into(), byte_len }
    }

    /// Returns the JSON value.
    pub fn as_value(&self) -> serde_json::Value {
        serde_json::from_str(&self.json).unwrap_or(serde_json::Value::Null)
    }

    /// Returns the byte length of the cached JSON.
    #[allow(dead_code)] // Used in tests
    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }
}

// ---------------------------------------------------------------------------
// Cache Weighter
// ---------------------------------------------------------------------------

/// Weighter for response cache entries based on memory usage.
#[derive(Debug, Clone, Default)]
pub struct ResponseCacheWeighter;

impl Weighter<ResponseCacheKey, CachedResponse> for ResponseCacheWeighter {
    fn weight(&self, _key: &ResponseCacheKey, val: &CachedResponse) -> u64 {
        const ENTRY_OVERHEAD: u64 = 128;
        ENTRY_OVERHEAD + val.byte_len as u64
    }
}

// ---------------------------------------------------------------------------
// Secondary Indices for Reorg Handling
// ---------------------------------------------------------------------------

/// Secondary indices for block hash/number mapping and cache key tracking.
/// Uses a single lock to ensure consistency across all three maps.
struct SecondaryIndices {
    inner: std::sync::RwLock<SecondaryIndicesInner>,
}

struct SecondaryIndicesInner {
    hash_to_number: HashMap<B256, u64>,
    number_to_hash: HashMap<u64, B256>,
    number_to_keys: HashMap<u64, HashSet<ResponseCacheKey>>,
}

impl SecondaryIndices {
    fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(SecondaryIndicesInner {
                hash_to_number: HashMap::new(),
                number_to_hash: HashMap::new(),
                number_to_keys: HashMap::new(),
            }),
        }
    }

    fn get_number_by_hash(&self, hash: &B256) -> Option<u64> {
        self.inner.read().unwrap().hash_to_number.get(hash).copied()
    }

    fn insert(&self, block_hash: B256, block_number: u64, key: ResponseCacheKey) {
        let mut inner = self.inner.write().unwrap();
        inner.hash_to_number.insert(block_hash, block_number);
        inner.number_to_hash.insert(block_number, block_hash);
        inner.number_to_keys.entry(block_number).or_default().insert(key);
    }

    fn remove_block(&self, block_number: u64) -> Option<HashSet<ResponseCacheKey>> {
        let mut inner = self.inner.write().unwrap();
        if let Some(hash) = inner.number_to_hash.remove(&block_number) {
            inner.hash_to_number.remove(&hash);
        }
        inner.number_to_keys.remove(&block_number)
    }

    fn remove_key(&self, key: &ResponseCacheKey) {
        let mut inner = self.inner.write().unwrap();
        let block_number = key.block_number;
        if let Some(keys) = inner.number_to_keys.get_mut(&block_number) {
            keys.remove(key);
            if keys.is_empty() {
                inner.number_to_keys.remove(&block_number);
                if let Some(hash) = inner.number_to_hash.remove(&block_number) {
                    inner.hash_to_number.remove(&hash);
                }
            }
        }
    }
}

#[derive(Clone)]
struct EvictionCleanupLifecycle {
    indices: Arc<SecondaryIndices>,
}

impl Lifecycle<ResponseCacheKey, CachedResponse> for EvictionCleanupLifecycle {
    type RequestState = ();

    fn begin_request(&self) -> Self::RequestState {}

    fn on_evict(&self, _state: &mut (), key: ResponseCacheKey, _val: CachedResponse) {
        self.indices.remove_key(&key);
    }
}

// ---------------------------------------------------------------------------
// Response Cache
// ---------------------------------------------------------------------------

/// Thread-safe response cache for RPC responses.
///
/// Caches pre-serialized JSON responses to avoid redundant trace computation
/// and serialization. Supports request coalescing via `get_or_compute`.
#[derive(Clone)]
pub struct ResponseCache {
    inner: Arc<ResponseCacheInner>,
}

struct ResponseCacheInner {
    cache: Cache<
        ResponseCacheKey,
        CachedResponse,
        ResponseCacheWeighter,
        RandomState,
        EvictionCleanupLifecycle,
    >,
    indices: Arc<SecondaryIndices>,
    /// Statistics
    hits: AtomicU64,
    misses: AtomicU64,
    /// Prometheus metrics for debug trace cache
    metrics_debug_trace: CacheMetrics,
    /// Prometheus metrics for parity trace cache
    metrics_trace: CacheMetrics,
}

impl std::fmt::Debug for ResponseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseCache")
            .field("len", &self.inner.cache.len())
            .field("weight", &self.inner.cache.weight())
            .field("hits", &self.inner.hits.load(Ordering::Relaxed))
            .field("misses", &self.inner.misses.load(Ordering::Relaxed))
            .finish()
    }
}

impl ResponseCache {
    /// Creates a new response cache with the given configuration.
    pub fn new(config: ResponseCacheConfig) -> Self {
        let indices = Arc::new(SecondaryIndices::new());
        let lifecycle = EvictionCleanupLifecycle { indices: indices.clone() };

        let cache = Cache::with(
            config.estimated_items,
            config.max_bytes,
            ResponseCacheWeighter,
            RandomState::default(),
            lifecycle,
        );

        Self {
            inner: Arc::new(ResponseCacheInner {
                cache,
                indices,
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                metrics_debug_trace: CacheMetrics::new_for_cache(CACHE_TYPE_DEBUG_TRACE),
                metrics_trace: CacheMetrics::new_for_cache(CACHE_TYPE_TRACE),
            }),
        }
    }

    /// Returns the cache metrics for a given resource type.
    fn metrics_for_resource(&self, resource: CachedResource) -> &CacheMetrics {
        match resource {
            CachedResource::DebugTraceBlock => &self.inner.metrics_debug_trace,
            CachedResource::TraceBlock => &self.inner.metrics_trace,
        }
    }

    /// Retrieves a cached response.
    #[allow(dead_code)] // Used in tests
    pub fn get(
        &self,
        resource: CachedResource,
        block_number: u64,
        variant: ResponseVariant,
    ) -> Option<serde_json::Value> {
        let key = ResponseCacheKey::new(resource, block_number, variant);
        let result = self.inner.cache.get(&key);
        let metrics = self.metrics_for_resource(resource);
        if result.is_some() {
            self.inner.hits.fetch_add(1, Ordering::Relaxed);
            metrics.record_hit();
        } else {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
            metrics.record_miss();
        }
        result.map(|r| r.as_value())
    }

    /// Retrieves a cached response by block hash.
    ///
    /// First looks up the block number from the hash->number index,
    /// then retrieves the cached response.
    pub fn get_by_hash(
        &self,
        resource: CachedResource,
        block_hash: B256,
        variant: ResponseVariant,
    ) -> Option<(serde_json::Value, u64)> {
        // Look up block number from hash
        let block_number = self.inner.indices.get_number_by_hash(&block_hash)?;

        let key = ResponseCacheKey::new(resource, block_number, variant);
        let result = self.inner.cache.get(&key);
        let metrics = self.metrics_for_resource(resource);
        if result.is_some() {
            self.inner.hits.fetch_add(1, Ordering::Relaxed);
            metrics.record_hit();
        } else {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
            metrics.record_miss();
        }
        result.map(|r| (r.as_value(), block_number))
    }

    /// Inserts a response into the cache and updates secondary indices.
    #[allow(dead_code)] // Used in tests
    pub fn insert(
        &self,
        resource: CachedResource,
        block_number: u64,
        block_hash: B256,
        variant: ResponseVariant,
        response: serde_json::Value,
    ) {
        let key = ResponseCacheKey::new(resource, block_number, variant);
        let cached = CachedResponse::new(response);

        self.inner.cache.insert(key.clone(), cached);
        self.inner.indices.insert(block_hash, block_number, key);
        self.update_size_metrics();
    }

    /// Gets a cached response or computes it, coalescing concurrent requests for the same key.
    ///
    /// This is the primary entry point for cache usage. If a response is already cached,
    /// it returns immediately. Otherwise, it computes the response and caches it.
    /// Concurrent requests for the same key will wait for the first computation to complete.
    #[allow(dead_code)] // May be used in future when timing isn't needed
    pub async fn get_or_compute<F, Fut, E>(
        &self,
        resource: CachedResource,
        block_number: u64,
        block_hash: B256,
        variant: ResponseVariant,
        compute: F,
    ) -> Result<serde_json::Value, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, E>>,
    {
        let key = ResponseCacheKey::new(resource, block_number, variant.clone());
        let metrics = self.metrics_for_resource(resource);

        match self.inner.cache.get_value_or_guard_async(&key).await {
            Ok(cached) => {
                self.inner.hits.fetch_add(1, Ordering::Relaxed);
                metrics.record_hit();
                trace!(
                    block_number,
                    resource = ?resource,
                    "Cache hit"
                );
                Ok(cached.as_value())
            }
            Err(guard) => {
                let result = compute().await?;
                let cached = CachedResponse::new(result.clone());
                let byte_len = cached.byte_len;
                let _ = guard.insert(cached);

                self.inner.indices.insert(block_hash, block_number, key);
                self.update_size_metrics();

                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                metrics.record_miss();

                debug!(
                    block_number,
                    resource = ?resource,
                    response_bytes = byte_len,
                    "Cache miss, computed and stored"
                );

                Ok(result)
            }
        }
    }

    /// Invalidates all cache entries for the given block hashes (used during reorgs).
    pub fn invalidate_blocks(&self, block_hashes: &[B256]) {
        let mut invalidated_count = 0;

        for &block_hash in block_hashes {
            // Get block number first (read lock)
            let block_number = self.inner.indices.get_number_by_hash(&block_hash);
            if let Some(block_number) = block_number {
                // Remove the block and get its keys (write lock)
                if let Some(keys) = self.inner.indices.remove_block(block_number) {
                    for key in keys {
                        self.inner.cache.remove(&key);
                        invalidated_count += 1;
                    }
                }
            }
        }

        if invalidated_count > 0 {
            debug!(
                blocks = block_hashes.len(),
                entries = invalidated_count,
                "Cache entries invalidated"
            );
        }
    }

    /// Returns the number of cached entries.
    #[allow(dead_code)] // Used in tests
    pub fn len(&self) -> usize {
        self.inner.cache.len()
    }

    /// Returns true if the cache is empty.
    #[allow(dead_code)] // Used in tests
    pub fn is_empty(&self) -> bool {
        self.inner.cache.is_empty()
    }

    /// Returns the current memory weight of the cache.
    #[allow(dead_code)] // Used in tests
    pub fn weight(&self) -> u64 {
        self.inner.cache.weight()
    }

    /// Updates prometheus cache size gauges with current cache state.
    fn update_size_metrics(&self) {
        let entry_count = self.inner.cache.len();
        let total_bytes = self.inner.cache.weight() as usize;
        self.inner.metrics_debug_trace.set_size(entry_count, total_bytes);
        self.inner.metrics_trace.set_size(entry_count, total_bytes);
    }

    /// Returns cache statistics and updates prometheus metrics.
    pub fn stats(&self) -> CacheStats {
        let entry_count = self.inner.cache.len();
        let total_bytes = self.inner.cache.weight();

        // Update prometheus cache size metrics (both types share the same cache)
        self.inner.metrics_debug_trace.set_size(entry_count, total_bytes as usize);
        self.inner.metrics_trace.set_size(entry_count, total_bytes as usize);

        CacheStats {
            entry_count: entry_count as u64,
            total_bytes,
            hits: self.inner.hits.load(Ordering::Relaxed),
            misses: self.inner.misses.load(Ordering::Relaxed),
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries in cache.
    pub entry_count: u64,
    /// Total bytes cached.
    pub total_bytes: u64,
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
}

impl CacheStats {
    /// Returns the cache hit rate as a percentage.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { (self.hits as f64 / total as f64) * 100.0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_type_parse() {
        assert_eq!(TracerType::parse("callTracer"), Some(TracerType::CallTracer));
        assert_eq!(TracerType::parse("prestateTracer"), Some(TracerType::PrestateTracer));
        assert_eq!(TracerType::parse("4byteTracer"), Some(TracerType::FourByteTracer));
        assert_eq!(TracerType::parse("unknown"), None);
    }

    #[test]
    fn test_cache_key_equality() {
        let key1 = ResponseCacheKey::new(
            CachedResource::DebugTraceBlock,
            100,
            ResponseVariant::Tracer(TracerType::CallTracer, None),
        );
        let key2 = ResponseCacheKey::new(
            CachedResource::DebugTraceBlock,
            100,
            ResponseVariant::Tracer(TracerType::CallTracer, None),
        );
        let key3 = ResponseCacheKey::new(
            CachedResource::DebugTraceBlock,
            100,
            ResponseVariant::Tracer(TracerType::PrestateTracer, None),
        );

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let config = ResponseCacheConfig { max_bytes: 1_000_000, estimated_items: 100 };
        let cache = ResponseCache::new(config);

        let block_number = 100u64;
        let block_hash = B256::from([1u8; 32]);
        let variant = ResponseVariant::Tracer(TracerType::CallTracer, None);
        let response = serde_json::json!({"test": true});

        cache.insert(
            CachedResource::DebugTraceBlock,
            block_number,
            block_hash,
            variant.clone(),
            response.clone(),
        );

        let retrieved = cache.get(CachedResource::DebugTraceBlock, block_number, variant);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), response);
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let config = ResponseCacheConfig { max_bytes: 1_000_000, estimated_items: 100 };
        let cache = ResponseCache::new(config);

        let block_hash = B256::from([1u8; 32]);
        let variant = ResponseVariant::Tracer(TracerType::Default, None);

        cache.insert(
            CachedResource::DebugTraceBlock,
            100,
            block_hash,
            variant.clone(),
            serde_json::json!({}),
        );

        assert_eq!(cache.len(), 1);

        cache.invalidate_blocks(&[block_hash]);

        assert_eq!(cache.len(), 0);
        assert!(cache.get(CachedResource::DebugTraceBlock, 100, variant).is_none());
    }

    #[tokio::test]
    async fn test_get_or_compute() {
        let config = ResponseCacheConfig { max_bytes: 1_000_000, estimated_items: 100 };
        let cache = ResponseCache::new(config);

        let block_hash = B256::from([1u8; 32]);
        let variant = ResponseVariant::Tracer(TracerType::Default, None);

        // First call should compute
        let result = cache
            .get_or_compute(
                CachedResource::DebugTraceBlock,
                100,
                block_hash,
                variant.clone(),
                || async { Ok::<_, ()>(serde_json::json!({"computed": true})) },
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::json!({"computed": true}));
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 0);

        // Second call should hit cache
        let result2 = cache
            .get_or_compute(CachedResource::DebugTraceBlock, 100, block_hash, variant, || async {
                Ok::<_, ()>(serde_json::json!({"should_not_see": true}))
            })
            .await;

        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), serde_json::json!({"computed": true}));
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_response_variant_default() {
        let default = ResponseVariant::Default;
        assert_eq!(default, ResponseVariant::default());
    }

    #[test]
    fn test_cached_resource_variants() {
        // Ensure all resource types are distinct
        assert_ne!(CachedResource::DebugTraceBlock, CachedResource::TraceBlock);
    }

    #[test]
    fn test_cache_stats_hit_rate() {
        let stats = CacheStats { entry_count: 10, total_bytes: 1000, hits: 80, misses: 20 };
        assert!((stats.hit_rate() - 80.0).abs() < 0.01);

        // Test zero case
        let empty_stats = CacheStats { entry_count: 0, total_bytes: 0, hits: 0, misses: 0 };
        assert_eq!(empty_stats.hit_rate(), 0.0);
    }

    #[test]
    fn test_cached_response() {
        let value = serde_json::json!({"key": "value", "number": 42});
        let cached = CachedResponse::new(value.clone());

        assert!(cached.byte_len() > 0);
        assert_eq!(cached.as_value(), value);
    }

    #[test]
    fn test_response_cache_key_hash() {
        use std::collections::HashSet;

        let key1 =
            ResponseCacheKey::new(CachedResource::DebugTraceBlock, 100, ResponseVariant::Default);
        let key2 =
            ResponseCacheKey::new(CachedResource::DebugTraceBlock, 100, ResponseVariant::Default);
        let key3 = ResponseCacheKey::new(CachedResource::TraceBlock, 100, ResponseVariant::Default);

        let mut set = HashSet::new();
        set.insert(key1.clone());
        assert!(set.contains(&key2));
        assert!(!set.contains(&key3));
    }

    #[tokio::test]
    async fn test_cache_different_variants_same_block() {
        let config = ResponseCacheConfig { max_bytes: 1_000_000, estimated_items: 100 };
        let cache = ResponseCache::new(config);

        let block_hash = B256::from([1u8; 32]);
        let variant1 = ResponseVariant::Tracer(TracerType::CallTracer, None);
        let variant2 = ResponseVariant::Tracer(TracerType::PrestateTracer, None);

        // Insert with different variants
        cache.insert(
            CachedResource::DebugTraceBlock,
            100,
            block_hash,
            variant1.clone(),
            serde_json::json!({"tracer": "call"}),
        );
        cache.insert(
            CachedResource::DebugTraceBlock,
            100,
            block_hash,
            variant2.clone(),
            serde_json::json!({"tracer": "prestate"}),
        );

        // Both should be cached separately
        let result1 = cache.get(CachedResource::DebugTraceBlock, 100, variant1);
        let result2 = cache.get(CachedResource::DebugTraceBlock, 100, variant2);

        assert_eq!(result1.unwrap(), serde_json::json!({"tracer": "call"}));
        assert_eq!(result2.unwrap(), serde_json::json!({"tracer": "prestate"}));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_tracer_type_all_variants() {
        assert_eq!(TracerType::parse("callTracer"), Some(TracerType::CallTracer));
        assert_eq!(TracerType::parse("prestateTracer"), Some(TracerType::PrestateTracer));
        assert_eq!(TracerType::parse("4byteTracer"), Some(TracerType::FourByteTracer));
        assert_eq!(TracerType::parse("noopTracer"), Some(TracerType::NoopTracer));
        assert_eq!(TracerType::parse("flatCallTracer"), Some(TracerType::FlatCallTracer));
        assert_eq!(TracerType::parse("unknown"), None);
    }

    #[test]
    fn test_response_cache_config_default() {
        let config = ResponseCacheConfig::default();
        assert_eq!(config.max_bytes, DEFAULT_RESPONSE_CACHE_MAX_BYTES);
        assert_eq!(config.estimated_items, DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS);
    }

    #[tokio::test]
    async fn test_cache_empty_checks() {
        let config = ResponseCacheConfig { max_bytes: 1_000_000, estimated_items: 100 };
        let cache = ResponseCache::new(config);

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.weight(), 0);

        cache.insert(
            CachedResource::DebugTraceBlock,
            100,
            B256::from([1u8; 32]),
            ResponseVariant::Default,
            serde_json::json!({}),
        );

        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert!(cache.weight() > 0);
    }
}
