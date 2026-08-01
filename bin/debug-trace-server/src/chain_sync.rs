//! Trace server pipeline components.
//!
//! Provides [`TraceProcessor`] (pass-through, no validation) and
//! [`TraceHooks`] (block storage + cache invalidation) for the shared pipeline
//! in [`stateless_core::pipeline::run_pipeline`].

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::{BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag};
use eyre::Result;
use op_alloy_rpc_types::Transaction;
use stateless_common::RpcClient;
use stateless_core::{
    LightWitness,
    db::BlockMeta,
    pipeline::{BlockFetcher, BlockProcessor, PipelineHooks},
};

use crate::{
    data_provider::CanonicalHashMemo, metrics, response_cache::ResponseCache, server_db::BlockStore,
};

/// Blocks within this distance of the last observed remote head are "frontier-fresh": their
/// witness may still be generating upstream, so the generator gets a short exclusive grace
/// ([`GENERATOR_WITNESS_GRACE`]) instead of a rotation to the fallback endpoints — those
/// receive witnesses from the same generation pipeline and cannot be ahead of it, so
/// rotating on a fresh miss burns a fallback round trip per block and exposes every fresh
/// block to fallback stalls, for nothing. Far above the fetcher's in-flight window (so all
/// steady-state tip-following fetches qualify), far below any real catch-up depth or the
/// generator's retention (so deep catch-up keeps full failover from the first attempt).
const FRONTIER_FRESHNESS_BLOCKS: u64 = 256;

/// Exclusive grace the generator gets for a frontier-fresh witness (retried with round
/// backoff) before the fetch falls back to the full provider chain. Comfortably above
/// routine generation lag; small enough that a genuinely unavailable fresh witness (the
/// generator is down, or the witness was never written) only delays failover by this much
/// before the fetch behaves exactly as it did without frontier routing.
///
/// The grace is enforced by a caller-side timeout around a deadline-less probe, not by the
/// RPC client's deadline: expiry is an internal routing budget, not a failed logical call,
/// and must not increment the upstream deadline-exceeded counter that alerting reads as
/// real witness-fetch failures.
///
/// Doubles as the trust horizon for the head observation behind the freshness test: a
/// block is at least as old as the anchor that classified it, so once the anchor exceeds
/// the grace, "not generated yet" is no longer a plausible reason for a missing witness
/// and the grace has nothing left to buy (see `remote_head`).
const GENERATOR_WITNESS_GRACE: Duration = Duration::from_secs(6);

/// Fetcher for the trace server: fetches blocks + witnesses, discards MPT witness.
///
/// Witnesses go through the zero-validation light decode (`get_witness_light`):
/// the server never verifies the proof, so the full decode's per-point
/// elliptic-curve work bought nothing.
///
/// Witness fetches route by block freshness against the last remote head observed by
/// [`Self::latest_block_number`] (which the pipeline polls to place the frontier):
/// frontier-fresh blocks — near a recently observed head; a stale anchor never grants the
/// grace — give the generator an exclusive grace first (its "witness not found" means
/// "not generated yet", not "ask someone else") and only fall back to the full endpoint
/// chain when the grace expires; everything else (deep catch-up, where the generator may
/// have pruned the block) uses the full chain from the first attempt.
/// The request-serving twin of this policy is `witness_route` in `data_provider.rs`
/// (local-tip anchor, skip-generator direction); both gate on the CLI-declared generator.
pub struct TraceFetcher {
    rpc_client: Arc<RpcClient>,
    /// Frontier routing switch: true iff the CLI declared witness endpoint 0 as the
    /// generator (`--witness-generator-endpoint`) with at least one fallback behind it —
    /// `routing_configured` in `main.rs`, the same startup-fixed predicate the request
    /// path gates on via `can_skip_generator`. CLI knowledge, not derivable from the
    /// client; false means no endpoint is special and the grace is disabled — plain
    /// failover.
    frontier_routing: bool,
    /// Last remote head observed by [`Self::latest_block_number`] and when — the freshness
    /// anchor for witness routing. `None` until the first successful poll, which classifies
    /// every block as non-fresh (full-chain fetch) rather than guessing. The observation
    /// instant bounds the anchor's trust: the pipeline re-polls the tip only when its spawn
    /// window runs past the ceiling, so a long catch-up stretch leaves the anchor stale
    /// while the real head — and the generator's pruning horizon — move on.
    remote_head: Mutex<Option<(u64, Instant)>>,
    /// [`GENERATOR_WITNESS_GRACE`], which is also the anchor-trust horizon; a field so
    /// tests can shrink it.
    generator_grace: Duration,
}

impl TraceFetcher {
    pub fn new(rpc_client: Arc<RpcClient>, frontier_routing: bool) -> Self {
        Self {
            rpc_client,
            frontier_routing,
            remote_head: Mutex::new(None),
            generator_grace: GENERATOR_WITNESS_GRACE,
        }
    }

    /// Records a just-observed remote head as the freshness anchor.
    fn note_remote_head(&self, head: u64) {
        *self.remote_head.lock().unwrap() = Some((head, Instant::now()));
    }

    /// Witness fetch with frontier-aware provider routing; see the type-level doc.
    async fn fetch_witness(&self, number: u64, hash: BlockHash) -> LightWitness {
        // Fresh = near a *recently* observed remote head; an unobserved head (`None`)
        // classifies as non-fresh. The age gate keeps a stale anchor from granting the
        // grace: during a long catch-up stretch the pipeline does not re-poll the tip, and
        // the real head may meanwhile advance past the generator's retention — the tail of
        // such a stretch would then burn the full grace per block on pruned witnesses.
        let fresh = match *self.remote_head.lock().unwrap() {
            Some((head, at)) => {
                head.saturating_sub(number) <= FRONTIER_FRESHNESS_BLOCKS &&
                    at.elapsed() <= self.generator_grace
            }
            None => false,
        };
        if fresh && self.frontier_routing {
            let probe = self.rpc_client.get_witness_light_first_provider_only(number, hash);
            if let Ok((light, _mpt)) = tokio::time::timeout(self.generator_grace, probe).await {
                return light;
            }
            // Grace expired: the witness is genuinely unavailable at the generator (down,
            // or never written). Fall through to the full chain — the pre-routing shape.
        }
        self.rpc_client.get_witness_light(number, hash).await.0
    }
}

impl BlockFetcher for TraceFetcher {
    type Output = (Block<Transaction>, LightWitness);

    async fn fetch(&self, block_number: u64) -> Result<(Block<Transaction>, LightWitness)> {
        // Fetch header first to pin the block hash, then witness + full block in parallel.
        // Matches the shape used by `DataProvider::do_fetch_block_data` — ~halves the wall
        // clock under chain-sync load by overlapping the witness fetch with the full-block
        // fetch instead of serializing all three round trips.
        let block_hash = self.rpc_client.get_block_hash(block_number).await;
        let (light, block_res) = tokio::join!(
            self.fetch_witness(block_number, block_hash),
            self.rpc_client.get_block(BlockId::Number(block_number.into()), true),
        );
        Ok((block_res, light))
    }

    async fn latest_block_number(&self) -> Result<u64> {
        let head = self.rpc_client.get_latest_block_number().await;
        self.note_remote_head(head);
        Ok(head)
    }

    async fn block_hash(&self, block_number: u64) -> Result<BlockHash> {
        Ok(self.rpc_client.get_block_hash(block_number).await)
    }

    async fn latest_block_meta(&self) -> Result<BlockMeta> {
        let header =
            self.rpc_client.get_header(BlockId::Number(BlockNumberOrTag::Latest), false).await;
        Ok(BlockMeta::from_header(&header))
    }
}

/// Block data after "processing" — just metadata + carried data for storage.
pub struct TraceProcessedBlock {
    pub block: Block<Transaction>,
    pub witness: LightWitness,
    pub meta: BlockMeta,
}

impl stateless_core::ProcessedBlock for TraceProcessedBlock {
    fn block_number(&self) -> BlockNumber {
        self.meta.block_number
    }

    fn block_hash(&self) -> BlockHash {
        self.meta.block_hash
    }

    fn parent_hash(&self) -> BlockHash {
        self.block.header.parent_hash
    }

    fn to_block_meta(&self) -> BlockMeta {
        self.meta.clone()
    }
}

/// Processor for the trace server: no validation, just construct metadata.
pub struct TraceProcessor;

impl BlockProcessor for TraceProcessor {
    type Input = (Block<Transaction>, LightWitness);
    type Output = TraceProcessedBlock;
    // Infallible: `process` below only rehydrates `BlockMeta` from fields the fetcher
    // already validated. If a future edit introduces a fallible step, the compiler will
    // force the author to pick a real error type rather than silently classifying every
    // failure as retry-able.
    type Error = std::convert::Infallible;

    async fn process(
        &self,
        (block, witness): Self::Input,
    ) -> std::result::Result<TraceProcessedBlock, Self::Error> {
        let meta = BlockMeta::from_header(&block.header);
        Ok(TraceProcessedBlock { block, witness, meta })
    }
}

/// Pipeline hooks for the trace server: store block data before advancing, invalidate
/// the response cache and the canonical-hash memo on reorg / stale-reset events.
pub struct TraceHooks {
    pub db: Arc<dyn BlockStore>,
    pub response_cache: Option<ResponseCache>,
    pub canonical_hash_memo: CanonicalHashMemo,
    pub chain_sync_metrics: metrics::ChainSyncMetrics,
}

impl TraceHooks {
    pub fn new(
        db: Arc<dyn BlockStore>,
        response_cache: Option<ResponseCache>,
        canonical_hash_memo: CanonicalHashMemo,
    ) -> Self {
        Self {
            db,
            response_cache,
            canonical_hash_memo,
            chain_sync_metrics: metrics::ChainSyncMetrics::create(),
        }
    }
}

impl PipelineHooks for TraceHooks {
    type Output = TraceProcessedBlock;

    fn pre_advance(&self, items: &[TraceProcessedBlock]) -> eyre::Result<()> {
        let pairs: Vec<_> = items.iter().map(|i| (i.block.clone(), i.witness.clone())).collect();
        Ok(self.db.store_block_data(&pairs)?)
    }

    fn post_advance(&self, new_tip: &BlockMeta) -> eyre::Result<()> {
        self.chain_sync_metrics.set_chain_height(new_tip.block_number);
        Ok(())
    }

    fn on_reorg(
        &self,
        _rollback_to: BlockNumber,
        depth: u64,
        reverted_hashes: &[BlockHash],
    ) -> eyre::Result<()> {
        if !reverted_hashes.is_empty() {
            self.chain_sync_metrics.record_reorg(reverted_hashes.len() as u64);
            if let Some(cache) = &self.response_cache {
                tracing::info!(
                    count = reverted_hashes.len(),
                    "Invalidating response cache for reorged blocks"
                );
                cache.invalidate_blocks(reverted_hashes);
            }
        }
        self.canonical_hash_memo.on_reorg(depth);
        Ok(())
    }

    fn on_stale_reset(&self, _new_anchor: &BlockMeta) -> eyre::Result<()> {
        if let Some(cache) = &self.response_cache {
            cache.invalidate_all();
        }
        // Belt-and-braces: memoized bindings are depth-final by construction, but a stale
        // reset means we fell far behind and re-anchored blind to whatever happened
        // upstream meanwhile — drop the memo with the response cache; it refills lazily
        // at one header fetch per height.
        self.canonical_hash_memo.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use alloy_primitives::B256;
    use stateless_common::{BackoffPolicy, RpcClientConfig, RpcMetrics, witness_encoding};
    use stateless_core::withdrawals::MptWitness;
    use stateless_test_utils::fixtures::TestFixtures;

    use super::*;
    use crate::{
        data_provider::test_support::{scripted_witness_rpc, start_mock_rpc},
        server_db::test_support::{StubBlockStore, make_block_meta},
    };

    /// A real `(number, hash, wire response, expected light witness)` from the synthetic
    /// fixtures, encoded with the production wire format.
    fn fixture_wire() -> (u64, BlockHash, String, LightWitness) {
        let fixtures = TestFixtures::synthetic();
        let (number, hash) = fixtures.paired_blocks().into_iter().next().expect("paired fixture");
        let salt = &fixtures.salt_witnesses[&hash];
        let mpt: MptWitness = fixtures.mpt_witness(&hash);
        let wire =
            witness_encoding::encode_witness_response(salt, &mpt).expect("encode fixture witness");
        (number, hash, wire, LightWitness::from(salt))
    }

    /// Fetcher over the given witness endpoints with millisecond retry backoff, a dummy
    /// RPC endpoint, and the given routing switch, generator grace, and RPC metrics.
    fn test_fetcher(
        witness_urls: &[&str],
        frontier_routing: bool,
        grace: Duration,
        metrics: Option<Arc<dyn RpcMetrics>>,
    ) -> TraceFetcher {
        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2)),
            per_attempt_timeout: Duration::from_millis(500),
            metrics,
            ..RpcClientConfig::trace_server()
        };
        let rpc_client = Arc::new(
            RpcClient::new_with_config(&["http://127.0.0.1:9/"], witness_urls, config, None)
                .unwrap(),
        );
        let mut fetcher = TraceFetcher::new(rpc_client, frontier_routing);
        fetcher.generator_grace = grace;
        fetcher
    }

    /// A frontier-fresh miss stays on the generator: retried through the grace and served
    /// there, with the fallback never contacted.
    #[tokio::test]
    async fn fresh_witness_miss_retries_generator_without_touching_fallback() {
        let (number, hash, wire, light) = fixture_wire();
        let (_gen, gen_url, gen_hits) = scripted_witness_rpc(2, Some(wire)).await;
        let (_fb, fb_url, fb_hits) = scripted_witness_rpc(0, None).await;
        let fetcher = test_fetcher(&[&gen_url, &fb_url], true, Duration::from_secs(10), None);
        fetcher.note_remote_head(number);

        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert_eq!(
            fb_hits.load(Ordering::Relaxed),
            0,
            "a fresh miss must not rotate to the fallback"
        );
        assert_eq!(gen_hits.load(Ordering::Relaxed), 3, "two misses, then the served round");
    }

    /// Blocks far below the observed head (deep catch-up) keep full failover from the
    /// first attempt: the generator's miss rotates straight to the fallback, no grace.
    #[tokio::test]
    async fn stale_witness_miss_fails_over_immediately() {
        let (number, hash, wire, light) = fixture_wire();
        let (_gen, gen_url, gen_hits) = scripted_witness_rpc(0, None).await;
        let (_fb, fb_url, fb_hits) = scripted_witness_rpc(0, Some(wire)).await;
        let fetcher = test_fetcher(&[&gen_url, &fb_url], true, Duration::from_secs(30), None);
        fetcher.note_remote_head(number + FRONTIER_FRESHNESS_BLOCKS + 1);

        let start = Instant::now();
        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert_eq!(gen_hits.load(Ordering::Relaxed), 1);
        assert_eq!(fb_hits.load(Ordering::Relaxed), 1);
        assert!(start.elapsed() < Duration::from_secs(5), "no generator grace on stale blocks");
    }

    /// With frontier routing off (no CLI-declared generator, or no fallback behind it) no
    /// endpoint is special: even a frontier-fresh miss rotates to the second endpoint in
    /// the same round — plain failover, mirroring the request path's
    /// `fetch_witness_without_generator_never_skips`.
    #[tokio::test]
    async fn no_declared_generator_keeps_plain_failover() {
        let (number, hash, wire, light) = fixture_wire();
        let (_first, first_url, first_hits) = scripted_witness_rpc(0, None).await;
        let (_second, second_url, second_hits) = scripted_witness_rpc(0, Some(wire)).await;
        let fetcher =
            test_fetcher(&[&first_url, &second_url], false, Duration::from_secs(30), None);
        fetcher.note_remote_head(number);

        let start = Instant::now();
        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert_eq!(first_hits.load(Ordering::Relaxed), 1);
        assert_eq!(second_hits.load(Ordering::Relaxed), 1);
        assert!(start.elapsed() < Duration::from_secs(5), "no grace without a generator");
    }

    /// Before the first head poll nothing classifies as fresh: full-chain behavior, no
    /// grace granted to a generator that may have pruned the block.
    #[tokio::test]
    async fn unknown_head_classifies_as_not_fresh() {
        let (number, hash, wire, light) = fixture_wire();
        let (_gen, gen_url, _gen_hits) = scripted_witness_rpc(0, None).await;
        let (_fb, fb_url, fb_hits) = scripted_witness_rpc(0, Some(wire)).await;
        let fetcher = test_fetcher(&[&gen_url, &fb_url], true, Duration::from_secs(30), None);

        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert_eq!(fb_hits.load(Ordering::Relaxed), 1, "unknown head must use the full chain");
    }

    /// Freshness needs a *recent* head observation, not just block-number proximity:
    /// during a long catch-up stretch the pipeline does not re-poll the tip, and the real
    /// head may meanwhile advance past the generator's retention — so an anchor older than
    /// the grace horizon downgrades to full-chain failover from the first attempt instead
    /// of burning the grace per block on pruned witnesses.
    #[tokio::test]
    async fn stale_head_observation_disables_the_grace() {
        let (number, hash, wire, light) = fixture_wire();
        let (_gen, gen_url, gen_hits) = scripted_witness_rpc(0, None).await;
        let (_fb, fb_url, fb_hits) = scripted_witness_rpc(0, Some(wire)).await;
        let fetcher = test_fetcher(&[&gen_url, &fb_url], true, Duration::from_millis(500), None);
        *fetcher.remote_head.lock().unwrap() =
            Some((number, Instant::now() - Duration::from_secs(2)));

        let start = Instant::now();
        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert_eq!(gen_hits.load(Ordering::Relaxed), 1, "no grace retries on a stale anchor");
        assert_eq!(fb_hits.load(Ordering::Relaxed), 1);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// Counts `on_rpc_deadline_exceeded` calls; every other [`RpcMetrics`] hook keeps its
    /// default no-op.
    struct DeadlineCounter(AtomicUsize);

    impl stateless_common::RpcMetrics for DeadlineCounter {
        fn on_rpc_attempt(
            &self,
            _method: stateless_common::RpcMethod,
            _provider: &str,
            _outcome: stateless_common::metrics::RpcAttemptOutcome,
            _duration_secs: f64,
        ) {
        }
        fn on_witness_fetch(&self, _breakdown: stateless_common::WitnessSizeBreakdown) {}
        fn on_rpc_deadline_exceeded(&self, _method: stateless_common::RpcMethod, _secs: f64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A downed generator costs at most the grace on a fresh block: the fetch then falls
    /// back to the full chain and succeeds on the fallback — and the expired grace is an
    /// internal routing budget, so it must not count as an upstream deadline-exceeded
    /// (alerting reads that metric as real witness-fetch failures).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fresh_fetch_falls_back_after_grace_when_generator_is_down() {
        let (number, hash, wire, light) = fixture_wire();
        // Bind-then-drop: connections to this port are refused instantly.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let gen_url = format!("http://{}", dead.local_addr().unwrap());
        drop(dead);
        let (_fb, fb_url, fb_hits) = scripted_witness_rpc(0, Some(wire)).await;
        let deadline_exceeded = Arc::new(DeadlineCounter(AtomicUsize::new(0)));
        let fetcher = test_fetcher(
            &[&gen_url, &fb_url],
            true,
            Duration::from_millis(300),
            Some(Arc::clone(&deadline_exceeded) as _),
        );
        fetcher.note_remote_head(number);

        let start = Instant::now();
        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert!(
            start.elapsed() >= Duration::from_millis(300),
            "the generator keeps its grace before failover"
        );
        assert!(fb_hits.load(Ordering::Relaxed) >= 1);
        assert_eq!(
            deadline_exceeded.0.load(Ordering::Relaxed),
            0,
            "an expired grace must not record an upstream deadline-exceeded"
        );
    }

    /// `latest_block_number` feeds the freshness anchor.
    #[tokio::test]
    async fn latest_block_number_updates_the_freshness_anchor() {
        let (_handle, url, _hits) = start_mock_rpc(0x64).await;
        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let fetcher = TraceFetcher::new(rpc_client, true);
        assert!(fetcher.remote_head.lock().unwrap().is_none());

        assert_eq!(fetcher.latest_block_number().await.unwrap(), 0x64);
        assert_eq!(fetcher.remote_head.lock().unwrap().map(|(head, _)| head), Some(0x64));
    }

    fn test_memo() -> CanonicalHashMemo {
        CanonicalHashMemo::new(16)
    }

    /// A stale reset drops every memoized number → hash binding along with the response
    /// cache: the node re-anchored blind to whatever happened upstream in between.
    #[test]
    fn stale_reset_clears_canonical_hash_memo() {
        let memo = test_memo();
        memo.insert(42, B256::from([1u8; 32]));
        let hooks = TraceHooks::new(Arc::new(StubBlockStore::default()), None, memo.clone());
        hooks.on_stale_reset(&make_block_meta(100)).unwrap();
        assert!(memo.get(&42).is_none());
    }

    /// The reorg hook forwards the depth to the memo, which owns the clearing policy:
    /// shallow reorgs leave it intact, deep ones drop it (the exact boundary is pinned by
    /// the memo's own test in `data_provider`).
    #[test]
    fn reorg_depth_reaches_the_memo() {
        let memo = test_memo();
        memo.insert(42, B256::from([1u8; 32]));
        let hooks = TraceHooks::new(Arc::new(StubBlockStore::default()), None, memo.clone());

        hooks.on_reorg(10, 1, &[Default::default()]).unwrap();
        assert!(memo.get(&42).is_some(), "a shallow reorg must not clear the memo");

        hooks.on_reorg(10, 1_000, &[Default::default()]).unwrap();
        assert!(memo.get(&42).is_none(), "a deep reorg must clear the memo");
    }

    /// A reorg evicts exactly the reverted hashes' entries — across resources — and leaves
    /// other blocks' entries alone. This is memory hygiene, not correctness: dead entries
    /// are unreachable by-number anyway, since number-keyed reads resolve the canonical
    /// hash before the lookup.
    #[test]
    fn reorg_invalidates_hash_keyed_entries() {
        use crate::response_cache::{CachedResource, ResponseCacheConfig, ResponseVariant};

        let cache = ResponseCache::new(ResponseCacheConfig::new(1_000_000, 100));
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);
        let entries = [
            (CachedResource::DebugTraceBlock, h1),
            (CachedResource::TraceBlock, h1),
            (CachedResource::DebugTraceBlock, h2),
        ];
        for (resource, hash) in entries {
            cache.insert(resource, hash, ResponseVariant::Default, &serde_json::json!({"v": 1}));
        }

        let hooks =
            TraceHooks::new(Arc::new(StubBlockStore::default()), Some(cache.clone()), test_memo());
        hooks.on_reorg(10, 1, &[h1]).unwrap();

        assert!(cache.get(CachedResource::DebugTraceBlock, h1, ResponseVariant::Default).is_none());
        assert!(cache.get(CachedResource::TraceBlock, h1, ResponseVariant::Default).is_none());
        assert!(
            cache.get(CachedResource::DebugTraceBlock, h2, ResponseVariant::Default).is_some(),
            "untouched blocks must survive the reorg invalidation"
        );
    }
}
