//! HTTP RPC Response Cache
//!
//! Caches pre-serialized JSON responses for the block-level trace methods.
//! Entries are [`RawJson`] — the exact bytes produced by the fill request's one
//! serialization — and a hit is an `Arc` clone spliced verbatim into the reply, so the
//! JSON tree is never re-parsed or re-serialized on either side of the cache.
//!
//! # Design
//!
//! - **Cache Key**: `(CachedResource, block_hash, ResponseVariant)` — the hash is part of the
//!   identity, so an entry is an immutable fact about that exact block: by-hash requests are
//!   structurally unable to poison other blocks' entries, and by-number requests resolve number →
//!   canonical hash *before* the lookup, so a reorged height simply resolves to the new hash and
//!   misses cleanly. No reorg validation happens at serve time.
//! - **Variants**: parsed, typed tracer configs — never caller-controlled raw JSON — so the key
//!   space per tracer is a small closed set: equivalent configs (reordered keys, unknown fields,
//!   explicit null) collapse onto one entry and cannot be minted into unlimited keys.
//! - **Secondary Index**: `block_hash -> keys`, used only for reorg invalidation from chain sync
//!   and for eviction cleanup.
//! - **Eviction**: S3-FIFO algorithm via `quick_cache` with memory-based weighting.

use std::{
    collections::{HashMap, HashSet},
    hash::RandomState,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use alloy_primitives::B256;
use alloy_rpc_types_trace::geth::{
    CallConfig, FlatCallConfig, GethDebugTracerConfig, GethDebugTracingOptions,
    GethDefaultTracingOptions, PreStateConfig,
};
use quick_cache::{Lifecycle, Weighter, sync::Cache};
use tracing::debug;

use crate::{
    metrics::{CACHE_TYPE_DEBUG_TRACE, CACHE_TYPE_TRACE, CacheMetrics, CacheStats},
    raw_json::RawJson,
};

// Configuration
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

// Cache Key Types
/// Cached resource types for RPC response caching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CachedResource {
    /// Debug trace block data (from `debug_traceBlockByNumber` or `debug_traceBlockByHash`)
    DebugTraceBlock,
    /// Parity trace block data (from `trace_block`)
    TraceBlock,
}

/// Hashable mirror of alloy's [`CallConfig`] (upstream derives `Eq` but not `Hash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CallConfigKey {
    only_top_call: Option<bool>,
    with_log: Option<bool>,
}

impl From<CallConfig> for CallConfigKey {
    fn from(config: CallConfig) -> Self {
        Self { only_top_call: config.only_top_call, with_log: config.with_log }
    }
}

/// Hashable mirror of alloy's [`PreStateConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PreStateConfigKey {
    diff_mode: Option<bool>,
    disable_code: Option<bool>,
    disable_storage: Option<bool>,
}

impl From<PreStateConfig> for PreStateConfigKey {
    fn from(config: PreStateConfig) -> Self {
        Self {
            diff_mode: config.diff_mode,
            disable_code: config.disable_code,
            disable_storage: config.disable_storage,
        }
    }
}

/// Hashable mirror of alloy's [`FlatCallConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FlatCallConfigKey {
    convert_parity_errors: Option<bool>,
    include_precompiles: Option<bool>,
}

impl From<FlatCallConfig> for FlatCallConfigKey {
    fn from(config: FlatCallConfig) -> Self {
        Self {
            convert_parity_errors: config.convert_parity_errors,
            include_precompiles: config.include_precompiles,
        }
    }
}

/// Cache variant: which whitelisted request shape produced the response, discriminated by
/// the *parsed* tracer config — a small closed key space per tracer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ResponseVariant {
    /// No tracer-affecting parameters: parity `trace_block`, and the bare default
    /// struct-logger `debug_traceBlock*` shape (the resource discriminates the two).
    #[default]
    Default,
    /// callTracer with its parsed config.
    CallTracer(CallConfigKey),
    /// prestateTracer with its parsed config.
    PrestateTracer(PreStateConfigKey),
    /// flatCallTracer with its parsed config.
    FlatCallTracer(FlatCallConfigKey),
    /// 4byteTracer never reads `tracerConfig`, so the variant carries none and any config
    /// collapses here.
    FourByteTracer,
    /// noopTracer never reads `tracerConfig`; same collapse.
    NoopTracer,
}

impl ResponseVariant {
    /// Metrics shape label; every value is listed in [`crate::metrics::REQUEST_SHAPES`].
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::CallTracer(_) => "call_tracer",
            Self::PrestateTracer(_) => "prestate_tracer",
            Self::FlatCallTracer(_) => "flat_call_tracer",
            Self::FourByteTracer => "four_byte_tracer",
            Self::NoopTracer => "noop_tracer",
        }
    }
}

/// Classification of a trace request's parameters — the single source of truth shared by
/// the cache whitelist, the shape metrics, and malformed-config rejection.
#[derive(Debug)]
pub enum RequestShape {
    /// Whitelisted: the response is fully determined by `(resource, block_hash, variant)`.
    Cacheable(ResponseVariant),
    /// Valid but must bypass the cache (read and write); carries its metrics label.
    Bypass(&'static str),
    /// A config-reading builtin (call/prestate/flatCall) with a type-malformed
    /// `tracerConfig`: the request must be rejected before executing. The label is the
    /// tracer's own shape label.
    InvalidTracerConfig {
        /// Shape label of the tracer whose config failed to parse.
        label: &'static str,
        /// The deserialization failure.
        error: serde_json::Error,
    },
}

impl RequestShape {
    /// Classifies the request parameters, parsing the typed tracer config exactly once.
    ///
    /// Cacheable: the five known built-in tracers (keyed by their *parsed* config) and the
    /// bare default struct-logger request (no tracer, no `tracerConfig`, default
    /// `opts.config` — those flags change struct-logger output).
    ///
    /// Bypassed: JS tracers (the response depends on the tracer source, which has no place
    /// in a bounded key), `muxTracer`, and struct-logger requests with non-default
    /// `opts.config`.
    pub fn classify(opts: &GethDebugTracingOptions) -> Self {
        use alloy_rpc_types_trace::geth::{GethDebugBuiltInTracerType, GethDebugTracerType};

        match &opts.tracer {
            None => {
                let pure_default = opts.tracer_config.is_null() &&
                    opts.config == GethDefaultTracingOptions::default();
                if pure_default {
                    Self::Cacheable(ResponseVariant::Default)
                } else {
                    Self::Bypass("struct_logger_config")
                }
            }
            Some(GethDebugTracerType::BuiltInTracer(builtin)) => match builtin {
                GethDebugBuiltInTracerType::CallTracer => Self::config_variant(
                    opts,
                    GethDebugTracerConfig::into_call_config,
                    "call_tracer",
                    |config: CallConfig| ResponseVariant::CallTracer(config.into()),
                ),
                GethDebugBuiltInTracerType::PreStateTracer => Self::config_variant(
                    opts,
                    GethDebugTracerConfig::into_pre_state_config,
                    "prestate_tracer",
                    |config: PreStateConfig| ResponseVariant::PrestateTracer(config.into()),
                ),
                GethDebugBuiltInTracerType::FlatCallTracer => Self::config_variant(
                    opts,
                    GethDebugTracerConfig::into_flat_call_config,
                    "flat_call_tracer",
                    |config: FlatCallConfig| ResponseVariant::FlatCallTracer(config.into()),
                ),
                GethDebugBuiltInTracerType::FourByteTracer => {
                    Self::Cacheable(ResponseVariant::FourByteTracer)
                }
                GethDebugBuiltInTracerType::NoopTracer => {
                    Self::Cacheable(ResponseVariant::NoopTracer)
                }
                // Exhaustive on purpose: a future alloy builtin variant must make an
                // explicit cache-whitelist decision here instead of silently bypassing.
                GethDebugBuiltInTracerType::MuxTracer => Self::Bypass("mux_tracer"),
            },
            Some(GethDebugTracerType::JsTracer(_)) => Self::Bypass("js_tracer"),
        }
    }

    /// Classifies one config-reading builtin: `parse` is alloy's own typed-config
    /// conversion (null → default, unknown fields ignored), so alloy stays authoritative
    /// for what counts as malformed.
    fn config_variant<C>(
        opts: &GethDebugTracingOptions,
        parse: fn(GethDebugTracerConfig) -> Result<C, serde_json::Error>,
        label: &'static str,
        wrap: fn(C) -> ResponseVariant,
    ) -> Self {
        match parse(opts.tracer_config.clone()) {
            Ok(config) => Self::Cacheable(wrap(config)),
            Err(error) => Self::InvalidTracerConfig { label, error },
        }
    }

    /// Metrics shape label for this request.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Cacheable(variant) => variant.label(),
            Self::Bypass(label) => label,
            Self::InvalidTracerConfig { label, .. } => label,
        }
    }

    /// The cache variant, `Some` only for whitelisted shapes.
    pub fn cache_variant(&self) -> Option<ResponseVariant> {
        match self {
            Self::Cacheable(variant) => Some(*variant),
            _ => None,
        }
    }
}

/// Cache key: resource type + block hash + response variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseCacheKey {
    /// The cached resource type.
    pub resource: CachedResource,
    /// The exact block the response was computed for.
    pub block_hash: B256,
    /// The response variant (parsed tracer shape).
    pub variant: ResponseVariant,
}

impl ResponseCacheKey {
    /// Creates a new cache key.
    pub const fn new(resource: CachedResource, block_hash: B256, variant: ResponseVariant) -> Self {
        Self { resource, block_hash, variant }
    }
}

// Cache Weighter
/// Weighter for response cache entries based on memory usage.
#[derive(Debug, Clone, Default)]
pub struct ResponseCacheWeighter;

impl Weighter<ResponseCacheKey, RawJson> for ResponseCacheWeighter {
    fn weight(&self, _key: &ResponseCacheKey, val: &RawJson) -> u64 {
        const ENTRY_OVERHEAD: u64 = 128;
        ENTRY_OVERHEAD + val.byte_len() as u64
    }
}

// Secondary Index for Reorg Invalidation + Eviction Cleanup
/// `block_hash -> keys` reverse index: lets chain sync invalidate every variant cached for
/// a reverted hash, and lets the eviction lifecycle keep itself consistent.
struct HashIndex {
    inner: std::sync::RwLock<HashMap<B256, HashSet<ResponseCacheKey>>>,
}

impl HashIndex {
    fn new() -> Self {
        Self { inner: std::sync::RwLock::new(HashMap::new()) }
    }

    fn insert(&self, key: ResponseCacheKey) {
        self.inner.write().unwrap().entry(key.block_hash).or_default().insert(key);
    }

    fn remove_hash(&self, hash: &B256) -> Option<HashSet<ResponseCacheKey>> {
        self.inner.write().unwrap().remove(hash)
    }

    fn remove_key(&self, key: &ResponseCacheKey) {
        let mut inner = self.inner.write().unwrap();
        if let Some(keys) = inner.get_mut(&key.block_hash) {
            keys.remove(key);
            if keys.is_empty() {
                inner.remove(&key.block_hash);
            }
        }
    }

    fn clear(&self) -> Vec<ResponseCacheKey> {
        self.inner.write().unwrap().drain().flat_map(|(_, keys)| keys).collect()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }
}

#[derive(Clone)]
struct EvictionCleanupLifecycle {
    index: Arc<HashIndex>,
}

impl Lifecycle<ResponseCacheKey, RawJson> for EvictionCleanupLifecycle {
    type RequestState = ();

    fn begin_request(&self) -> Self::RequestState {}

    fn on_evict(&self, _state: &mut (), key: ResponseCacheKey, _val: RawJson) {
        self.index.remove_key(&key);
    }
}

// Response Cache
/// Thread-safe response cache for block-level trace responses, keyed by block hash.
#[derive(Clone)]
pub struct ResponseCache {
    inner: Arc<ResponseCacheInner>,
}

struct ResponseCacheInner {
    cache: Cache<
        ResponseCacheKey,
        RawJson,
        ResponseCacheWeighter,
        RandomState,
        EvictionCleanupLifecycle,
    >,
    index: Arc<HashIndex>,
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
        let index = Arc::new(HashIndex::new());
        let lifecycle = EvictionCleanupLifecycle { index: index.clone() };

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
                index,
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

    /// Retrieves a cached response for the exact block hash, recording hit/miss
    /// accounting. A hit is an `Arc` clone of the stored bytes — no parsing, no copy.
    pub fn get(
        &self,
        resource: CachedResource,
        block_hash: B256,
        variant: ResponseVariant,
    ) -> Option<RawJson> {
        let key = ResponseCacheKey::new(resource, block_hash, variant);
        let result = self.inner.cache.get(&key);
        let metrics = self.metrics_for_resource(resource);
        if result.is_some() {
            self.inner.hits.fetch_add(1, Ordering::Relaxed);
            metrics.record_hit();
        } else {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
            metrics.record_miss();
        }
        result
    }

    /// Inserts a response computed for the exact block hash, sharing the reply's
    /// already-serialized bytes (an `Arc` clone — nothing is re-serialized or copied).
    ///
    /// The index is registered *before* the cache write: if `quick_cache` immediately
    /// weight-evicts the just-inserted key, `on_evict -> remove_key` then self-heals the
    /// index. (Same-key replacement and explicit `remove` fire no `on_evict`.) The other
    /// interleaving — an `invalidate_blocks` landing between the two steps — leaves the
    /// entry cached but unindexed, which is harmless: a hash-keyed entry is still a true
    /// fact for by-hash reads and unreachable by-number, so it merely occupies weight
    /// until eviction.
    pub fn insert(
        &self,
        resource: CachedResource,
        block_hash: B256,
        variant: ResponseVariant,
        response: &RawJson,
    ) {
        let key = ResponseCacheKey::new(resource, block_hash, variant);
        self.inner.index.insert(key);
        self.inner.cache.insert(key, response.clone());
        self.update_size_metrics();
    }

    /// Invalidates all cache entries for the given block hashes (used during reorgs; pure
    /// memory hygiene — a dead hash's entries are unreachable by number-keyed requests,
    /// which resolve number -> canonical hash before the lookup).
    pub fn invalidate_blocks(&self, block_hashes: &[B256]) {
        let mut invalidated_count = 0;

        for block_hash in block_hashes {
            if let Some(keys) = self.inner.index.remove_hash(block_hash) {
                for key in keys {
                    self.inner.cache.remove(&key);
                    invalidated_count += 1;
                }
            }
        }

        if invalidated_count > 0 {
            debug!(
                blocks = block_hashes.len(),
                entries = invalidated_count,
                "Cache entries invalidated"
            );
            self.update_size_metrics();
        }
    }

    /// Invalidates all cache entries (used during stale anchor reset).
    pub fn invalidate_all(&self) {
        let keys = self.inner.index.clear();
        for key in &keys {
            self.inner.cache.remove(key);
        }
        if !keys.is_empty() {
            debug!(entries = keys.len(), "Cache fully invalidated");
            self.update_size_metrics();
        }
    }

    /// Returns the number of cached entries.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.cache.len()
    }

    /// Returns true if the cache is empty.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner.cache.is_empty()
    }

    /// Returns the current memory weight of the cache.
    #[cfg(test)]
    pub fn weight(&self) -> u64 {
        self.inner.cache.weight()
    }

    /// True when the hash index holds no entries.
    #[cfg(test)]
    fn index_is_empty(&self) -> bool {
        self.inner.index.is_empty()
    }

    /// Updates the prometheus cache size gauges and returns `(entry_count, total_bytes)`
    /// as read. (Both resource types share one cache, so both labels report the same
    /// totals.)
    fn update_size_metrics(&self) -> (usize, u64) {
        let entry_count = self.inner.cache.len();
        let total_bytes = self.inner.cache.weight();
        self.inner.metrics_debug_trace.set_size(entry_count, total_bytes as usize);
        self.inner.metrics_trace.set_size(entry_count, total_bytes as usize);
        (entry_count, total_bytes)
    }

    /// Returns cache statistics and updates prometheus metrics.
    pub fn stats(&self) -> CacheStats {
        let (entry_count, total_bytes) = self.update_size_metrics();
        CacheStats {
            entry_count: entry_count as u64,
            total_bytes,
            hits: self.inner.hits.load(Ordering::Relaxed),
            misses: self.inner.misses.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_rpc_types_trace::geth::{
        GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType,
    };
    use serde_json::json;

    use super::*;

    fn builtin_opts(tracer: GethDebugBuiltInTracerType) -> GethDebugTracingOptions {
        GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(tracer)),
            ..Default::default()
        }
    }

    fn with_config(
        tracer: GethDebugBuiltInTracerType,
        config: serde_json::Value,
    ) -> GethDebugTracingOptions {
        GethDebugTracingOptions {
            tracer_config: GethDebugTracerConfig(config),
            ..builtin_opts(tracer)
        }
    }

    fn variant_of(opts: &GethDebugTracingOptions) -> ResponseVariant {
        RequestShape::classify(opts).cache_variant().expect("expected cacheable shape")
    }

    #[test]
    fn classify_structlogger_requires_pure_default() {
        let bare = GethDebugTracingOptions::default();
        assert_eq!(variant_of(&bare), ResponseVariant::Default);

        // Struct-logger flags change struct-logger output, so any non-default config must
        // bypass the cache instead of colliding with the bare-default entry.
        let with_flags = GethDebugTracingOptions {
            config: GethDefaultTracingOptions { disable_storage: Some(true), ..Default::default() },
            ..Default::default()
        };
        assert!(matches!(
            RequestShape::classify(&with_flags),
            RequestShape::Bypass("struct_logger_config")
        ));

        let with_tracer_config = GethDebugTracingOptions {
            tracer_config: GethDebugTracerConfig(json!({"some": "config"})),
            ..Default::default()
        };
        assert!(matches!(
            RequestShape::classify(&with_tracer_config),
            RequestShape::Bypass("struct_logger_config")
        ));
    }

    #[test]
    fn classify_bypasses_js_and_mux() {
        let js = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::JsTracer("{fault: () => {}}".to_string())),
            ..Default::default()
        };
        assert!(matches!(RequestShape::classify(&js), RequestShape::Bypass("js_tracer")));

        let mux = builtin_opts(GethDebugBuiltInTracerType::MuxTracer);
        assert!(matches!(RequestShape::classify(&mux), RequestShape::Bypass("mux_tracer")));
    }

    /// The reviewer's blocking case: `tracerConfig` must not be able to mint unlimited
    /// distinct keys. Equivalent configs — reordered keys, unknown fields, explicit null —
    /// all collapse onto the same parsed variant.
    #[test]
    fn variant_collapses_equivalent_configs() {
        let call = GethDebugBuiltInTracerType::CallTracer;

        // Key order is irrelevant after parsing.
        let ordered = with_config(call, json!({"onlyTopCall": true, "withLog": true}));
        let reversed = with_config(call, json!({"withLog": true, "onlyTopCall": true}));
        assert_eq!(variant_of(&ordered), variant_of(&reversed));

        // Unknown fields are dropped by serde and cannot split (or flood) entries.
        let padded = with_config(call, json!({"onlyTopCall": true, "pad": 12345}));
        let plain = with_config(call, json!({"onlyTopCall": true}));
        assert_eq!(variant_of(&padded), variant_of(&plain));
        let junk_only = with_config(call, json!({"some": "config"}));
        assert_eq!(variant_of(&junk_only), variant_of(&builtin_opts(call)));

        // Explicit null equals bare.
        let null_config = with_config(call, serde_json::Value::Null);
        assert_eq!(variant_of(&null_config), variant_of(&builtin_opts(call)));

        // Semantically different configs stay distinct.
        let top_only = with_config(call, json!({"onlyTopCall": true}));
        let with_log = with_config(call, json!({"withLog": true}));
        let bare = builtin_opts(call);
        assert_ne!(variant_of(&top_only), variant_of(&with_log));
        assert_ne!(variant_of(&top_only), variant_of(&bare));
        assert_ne!(variant_of(&with_log), variant_of(&bare));

        // Top-level opts.config never affects builtin tracers, so it stays out of the key.
        let call_with_flags = GethDebugTracingOptions {
            config: GethDefaultTracingOptions { disable_storage: Some(true), ..Default::default() },
            ..builtin_opts(call)
        };
        assert_eq!(variant_of(&call_with_flags), variant_of(&builtin_opts(call)));
    }

    /// call/prestate/flatCall read their config, so a type-malformed one is a client error
    /// instead of a silent fallback to defaults. Malformed means a wrong-typed value on a
    /// field the tracer's own config declares (an unknown field is ignored — see
    /// `variant_collapses_equivalent_configs`), or a non-object config document.
    #[test]
    fn classify_rejects_malformed_config_on_config_reading_builtins() {
        let cases = [
            (GethDebugBuiltInTracerType::CallTracer, "call_tracer", "onlyTopCall"),
            (GethDebugBuiltInTracerType::PreStateTracer, "prestate_tracer", "diffMode"),
            (GethDebugBuiltInTracerType::FlatCallTracer, "flat_call_tracer", "convertParityErrors"),
        ];
        for (tracer, expected_label, field) in cases {
            let opts = with_config(tracer, json!({field: "yes"}));
            match RequestShape::classify(&opts) {
                RequestShape::InvalidTracerConfig { label, .. } => {
                    assert_eq!(label, expected_label)
                }
                other => panic!("expected InvalidTracerConfig, got {other:?}"),
            }
            let opts = with_config(tracer, json!(5));
            assert!(matches!(
                RequestShape::classify(&opts),
                RequestShape::InvalidTracerConfig { .. }
            ));
        }
    }

    /// noop/4byte never read tracerConfig (neither does geth), so even malformed configs
    /// collapse onto their config-less variant instead of erroring or splitting entries.
    #[test]
    fn noop_fourbyte_collapse_any_tracer_config() {
        for (tracer, expected) in [
            (GethDebugBuiltInTracerType::NoopTracer, ResponseVariant::NoopTracer),
            (GethDebugBuiltInTracerType::FourByteTracer, ResponseVariant::FourByteTracer),
        ] {
            assert_eq!(variant_of(&builtin_opts(tracer)), expected);
            assert_eq!(variant_of(&with_config(tracer, json!({"junk": 1}))), expected);
            assert_eq!(variant_of(&with_config(tracer, json!({"onlyTopCall": "yes"}))), expected);
        }
    }

    #[test]
    fn classify_all_builtins_distinct() {
        let variants: Vec<_> = [
            GethDebugBuiltInTracerType::CallTracer,
            GethDebugBuiltInTracerType::PreStateTracer,
            GethDebugBuiltInTracerType::FourByteTracer,
            GethDebugBuiltInTracerType::NoopTracer,
            GethDebugBuiltInTracerType::FlatCallTracer,
        ]
        .into_iter()
        .map(|t| variant_of(&builtin_opts(t)))
        .collect();
        let unique: HashSet<_> = variants.iter().copied().collect();
        assert_eq!(unique.len(), variants.len());
    }

    /// The classification is the single source of truth: every label is registered for
    /// metrics, and "cacheable" is exactly the complement of the bypass/invalid shapes.
    #[test]
    fn shape_label_matches_cacheability() {
        let bypass = ["struct_logger_config", "js_tracer", "mux_tracer"];
        let cases = [
            GethDebugTracingOptions::default(),
            builtin_opts(GethDebugBuiltInTracerType::CallTracer),
            builtin_opts(GethDebugBuiltInTracerType::PreStateTracer),
            builtin_opts(GethDebugBuiltInTracerType::FourByteTracer),
            builtin_opts(GethDebugBuiltInTracerType::NoopTracer),
            builtin_opts(GethDebugBuiltInTracerType::FlatCallTracer),
            builtin_opts(GethDebugBuiltInTracerType::MuxTracer),
            GethDebugTracingOptions {
                tracer: Some(GethDebugTracerType::JsTracer("{}".to_string())),
                ..Default::default()
            },
            GethDebugTracingOptions {
                config: GethDefaultTracingOptions {
                    disable_storage: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ];

        let mut seen = HashSet::new();
        for opts in &cases {
            let shape = RequestShape::classify(opts);
            let label = shape.label();
            seen.insert(label);
            assert!(
                crate::metrics::REQUEST_SHAPES.contains(&label),
                "shape {label} must be pre-registered"
            );
            assert_eq!(
                shape.cache_variant().is_some(),
                !bypass.contains(&label),
                "cacheability must match the shape classification for {label}"
            );
        }
        assert_eq!(seen.len(), cases.len(), "every case must map to a distinct label");

        // Malformed configs keep the tracer's own label but are neither cacheable nor bypass.
        let malformed =
            with_config(GethDebugBuiltInTracerType::CallTracer, json!({"onlyTopCall": "yes"}));
        let shape = RequestShape::classify(&malformed);
        assert_eq!(shape.label(), "call_tracer");
        assert!(shape.cache_variant().is_none());
    }

    /// Key identity (Eq + Hash, exercised through a `HashSet`) discriminates on every
    /// component: resource, block hash, and variant.
    #[test]
    fn test_cache_key_identity() {
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);
        let call = ResponseVariant::CallTracer(CallConfigKey::default());
        let key = |resource, hash, variant| ResponseCacheKey::new(resource, hash, variant);

        let mut set = HashSet::new();
        set.insert(key(CachedResource::DebugTraceBlock, h1, call));
        assert!(set.contains(&key(CachedResource::DebugTraceBlock, h1, call)));
        assert!(!set.contains(&key(CachedResource::TraceBlock, h1, call)));
        assert!(!set.contains(&key(CachedResource::DebugTraceBlock, h2, call)));
        assert!(!set.contains(&key(CachedResource::DebugTraceBlock, h1, ResponseVariant::Default)));
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100));
        let hash = B256::from([1u8; 32]);
        let value =
            RawJson::try_new(&json!([{"txHash": "0x01", "result": {}}])).expect("serialize");
        assert!(cache.is_empty());
        assert_eq!((cache.len(), cache.weight()), (0, 0));

        assert!(
            cache.get(CachedResource::DebugTraceBlock, hash, ResponseVariant::Default).is_none()
        );
        cache.insert(CachedResource::DebugTraceBlock, hash, ResponseVariant::Default, &value);
        let hit = cache
            .get(CachedResource::DebugTraceBlock, hash, ResponseVariant::Default)
            .expect("inserted entry must hit");
        assert!(
            hit.shares_bytes_with(&value),
            "a hit must be an Arc clone of the inserted bytes, not a copy"
        );

        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert!(cache.weight() > 0);
        let stats = cache.stats();
        assert_eq!((stats.hits, stats.misses), (1, 1));
    }

    #[test]
    fn test_cache_invalidation() {
        let cache = ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100));
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);
        let call = ResponseVariant::CallTracer(CallConfigKey::default());

        cache.insert(
            CachedResource::DebugTraceBlock,
            h1,
            ResponseVariant::Default,
            &RawJson::try_new(&json!({"v": 1})).expect("serialize"),
        );
        cache.insert(
            CachedResource::TraceBlock,
            h1,
            ResponseVariant::Default,
            &RawJson::try_new(&json!({"v": 2})).expect("serialize"),
        );
        cache.insert(
            CachedResource::DebugTraceBlock,
            h2,
            call,
            &RawJson::try_new(&json!({"v": 3})).expect("serialize"),
        );
        assert_eq!(cache.len(), 3);

        // Every variant cached for the reverted hash goes; other hashes survive.
        cache.invalidate_blocks(&[h1]);
        assert!(cache.get(CachedResource::DebugTraceBlock, h1, ResponseVariant::Default).is_none());
        assert!(cache.get(CachedResource::TraceBlock, h1, ResponseVariant::Default).is_none());
        assert_eq!(
            cache.get(CachedResource::DebugTraceBlock, h2, call).map(|r| r.as_str().to_owned()),
            Some(r#"{"v":3}"#.to_owned())
        );
        assert_eq!(cache.len(), 1);

        cache.invalidate_all();
        assert_eq!(cache.len(), 0);
        assert!(cache.index_is_empty());
    }

    #[test]
    fn test_cache_different_variants_same_hash() {
        let cache = ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100));
        let hash = B256::from([1u8; 32]);
        let call = ResponseVariant::CallTracer(CallConfigKey::default());
        let prestate = ResponseVariant::PrestateTracer(PreStateConfigKey::default());

        let call_response = RawJson::try_new(&json!({"tracer": "call"})).expect("serialize");
        let prestate_response =
            RawJson::try_new(&json!({"tracer": "prestate"})).expect("serialize");
        cache.insert(CachedResource::DebugTraceBlock, hash, call, &call_response);
        cache.insert(CachedResource::DebugTraceBlock, hash, prestate, &prestate_response);

        assert_eq!(cache.len(), 2);
        assert!(
            cache
                .get(CachedResource::DebugTraceBlock, hash, call)
                .is_some_and(|r| r.shares_bytes_with(&call_response))
        );
        assert!(
            cache
                .get(CachedResource::DebugTraceBlock, hash, prestate)
                .is_some_and(|r| r.shares_bytes_with(&prestate_response))
        );
    }

    /// Weight-pressure eviction must clean the hash index (via the lifecycle), so a later
    /// invalidation for the evicted hash is a no-op and nothing leaks.
    #[test]
    fn eviction_cleans_hash_index() {
        // Budget fits roughly one entry; inserting more forces evictions.
        let payload = RawJson::try_new(&json!({"data": "x".repeat(512)})).expect("serialize");
        let one_weight = 128 + payload.byte_len() as u64;
        let cache = ResponseCache::new(ResponseCacheConfig::new(one_weight * 3 / 2, 4));

        let hashes: Vec<B256> = (1..=4u8).map(|i| B256::from([i; 32])).collect();
        for hash in &hashes {
            cache.insert(
                CachedResource::DebugTraceBlock,
                *hash,
                ResponseVariant::Default,
                &payload,
            );
        }

        assert!(cache.weight() <= one_weight * 3 / 2);
        assert!(cache.len() <= 2);

        // Invalidating every hash (evicted or resident) drains cache and index completely.
        cache.invalidate_blocks(&hashes);
        assert_eq!(cache.len(), 0);
        assert!(cache.index_is_empty(), "eviction must not leak index entries");
    }

    /// Trivial derives and constants: variant/resource discriminants and the default config.
    #[test]
    fn test_defaults_and_discriminants() {
        assert_eq!(ResponseVariant::default(), ResponseVariant::Default);
        assert_ne!(CachedResource::DebugTraceBlock, CachedResource::TraceBlock);
        let config = ResponseCacheConfig::default();
        assert_eq!(config.max_bytes, DEFAULT_RESPONSE_CACHE_MAX_BYTES);
        assert_eq!(config.estimated_items, DEFAULT_RESPONSE_CACHE_ESTIMATED_ITEMS);
    }

    #[test]
    fn test_cache_stats_hit_rate() {
        let stats = CacheStats { entry_count: 0, total_bytes: 0, hits: 80, misses: 20 };
        assert!((stats.hit_rate() - 80.0).abs() < f64::EPSILON);
        let empty = CacheStats { entry_count: 0, total_bytes: 0, hits: 0, misses: 0 };
        assert!((empty.hit_rate() - 0.0).abs() < f64::EPSILON);
    }
}
