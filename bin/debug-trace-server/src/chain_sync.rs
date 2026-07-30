//! Trace server pipeline components.
//!
//! Provides [`TraceProcessor`] (pass-through, no validation) and
//! [`TraceHooks`] (block storage + cache invalidation) for the shared pipeline
//! in [`stateless_core::pipeline::run_pipeline`].

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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

use crate::{metrics, response_cache::ResponseCache, server_db::BlockStore};

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
const GENERATOR_WITNESS_GRACE: Duration = Duration::from_secs(6);

/// Fetcher for the trace server: fetches blocks + witnesses, discards MPT witness.
///
/// Witnesses go through the zero-validation light decode (`get_witness_light`):
/// the server never verifies the proof, so the full decode's per-point
/// elliptic-curve work bought nothing.
///
/// Witness fetches route by block freshness against the last remote head observed by
/// [`Self::latest_block_number`] (which the pipeline polls to place the frontier):
/// frontier-fresh blocks give the generator an exclusive grace first — its "witness not
/// found" means "not generated yet", not "ask someone else" — and only fall back to the
/// full endpoint chain when the grace expires; everything else (deep catch-up, where the
/// generator may have pruned the block) uses the full chain from the first attempt.
/// The request-serving twin of this policy is `witness_route` in `data_provider.rs`
/// (local-tip anchor, skip-generator direction); both gate on the CLI-declared generator.
pub struct TraceFetcher {
    rpc_client: Arc<RpcClient>,
    /// Whether witness endpoint 0 is the CLI-declared generator
    /// (`--witness-generator-endpoint`). CLI knowledge, not derivable from the client;
    /// without it no endpoint is special and the grace is disabled — plain failover,
    /// matching the request path's `can_skip_generator` gate.
    generator_first: bool,
    /// Last remote head observed by [`Self::latest_block_number`] — the freshness anchor
    /// for witness routing. `u64::MAX` until the first successful poll, which classifies
    /// every block as non-fresh (full-chain fetch) rather than guessing.
    remote_head: AtomicU64,
    /// [`GENERATOR_WITNESS_GRACE`], as a field so tests can shrink it.
    generator_grace: Duration,
}

impl TraceFetcher {
    pub fn new(rpc_client: Arc<RpcClient>, generator_first: bool) -> Self {
        Self {
            rpc_client,
            generator_first,
            remote_head: AtomicU64::new(u64::MAX),
            generator_grace: GENERATOR_WITNESS_GRACE,
        }
    }

    /// Witness fetch with frontier-aware provider routing; see the type-level doc.
    async fn fetch_witness(&self, number: u64, hash: BlockHash) -> LightWitness {
        let head = self.remote_head.load(Ordering::Relaxed);
        // `u64::MAX` (head not yet observed) saturates to "very far below the head" and
        // correctly classifies as non-fresh.
        let fresh = head.saturating_sub(number) <= FRONTIER_FRESHNESS_BLOCKS;
        if fresh && self.generator_first && self.rpc_client.witness_provider_count() > 1 {
            let grace = Instant::now() + self.generator_grace;
            if let Ok((light, _mpt)) = self
                .rpc_client
                .get_witness_light_first_provider_only(number, hash, Some(grace))
                .await
            {
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
        self.remote_head.store(head, Ordering::Relaxed);
        Ok(head)
    }

    async fn block_hash(&self, block_number: u64) -> Result<BlockHash> {
        Ok(self.rpc_client.get_block_hash(block_number).await)
    }

    async fn latest_block_meta(&self) -> Result<BlockMeta> {
        let header =
            self.rpc_client.get_header(BlockId::Number(BlockNumberOrTag::Latest), false).await;
        Ok(BlockMeta {
            block_number: header.number,
            block_hash: header.hash,
            post_state_root: header.state_root,
            post_withdrawals_root: header.withdrawals_root.unwrap_or_default(),
        })
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
        let meta = BlockMeta {
            block_number: block.header.number,
            block_hash: block.header.hash,
            post_state_root: block.header.state_root,
            post_withdrawals_root: block.header.withdrawals_root.unwrap_or_default(),
        };
        Ok(TraceProcessedBlock { block, witness, meta })
    }
}

/// Pipeline hooks for the trace server: store block data before advancing,
/// invalidate cache on reorg.
pub struct TraceHooks {
    pub db: Arc<dyn BlockStore>,
    pub response_cache: Option<ResponseCache>,
    pub chain_sync_metrics: metrics::ChainSyncMetrics,
}

impl TraceHooks {
    pub fn new(db: Arc<dyn BlockStore>, response_cache: Option<ResponseCache>) -> Self {
        Self { db, response_cache, chain_sync_metrics: metrics::ChainSyncMetrics::create() }
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
        _depth: u64,
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
        Ok(())
    }

    fn on_stale_reset(&self, _new_anchor: &BlockMeta) -> eyre::Result<()> {
        if let Some(cache) = &self.response_cache {
            cache.invalidate_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicUsize};

    use alloy_primitives::{B256, map::HashMap};
    use revm::state::Bytecode;
    use stateless_common::{BackoffPolicy, RpcClientConfig, witness_encoding};
    use stateless_core::{StoreResult, withdrawals::MptWitness};
    use stateless_test_utils::fixtures::TestFixtures;

    use super::*;

    /// Serves `mega_getBlockWitness`: "not generated yet" errors for the first
    /// `misses_before_serve` calls, then `wire` forever (always errors when `wire` is
    /// `None`), counting every call.
    async fn scripted_witness_rpc(
        misses_before_serve: usize,
        wire: Option<String>,
    ) -> (jsonrpsee::server::ServerHandle, String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let mut module = jsonrpsee::server::RpcModule::new((hits.clone(), wire));
        module
            .register_method("mega_getBlockWitness", move |_p, (hits, wire), _| {
                let call = hits.fetch_add(1, Ordering::Relaxed);
                match wire {
                    Some(wire) if call >= misses_before_serve => Ok(wire.clone()),
                    _ => Err(jsonrpsee::types::ErrorObjectOwned::owned::<()>(
                        -32602,
                        "Failed to get witness: not generated yet",
                        None,
                    )),
                }
            })
            .unwrap();
        let server =
            jsonrpsee::server::ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (server.start(module), url, hits)
    }

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
    /// RPC endpoint, and the given generator grace.
    fn test_fetcher(witness_urls: &[&str], grace: Duration) -> TraceFetcher {
        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2)),
            per_attempt_timeout: Duration::from_millis(500),
            ..RpcClientConfig::trace_server()
        };
        let rpc_client = Arc::new(
            RpcClient::new_with_config(&["http://127.0.0.1:9/"], witness_urls, config, None)
                .unwrap(),
        );
        TraceFetcher { generator_grace: grace, ..TraceFetcher::new(rpc_client, true) }
    }

    /// A frontier-fresh miss stays on the generator: retried through the grace and served
    /// there, with the fallback never contacted.
    #[tokio::test]
    async fn fresh_witness_miss_retries_generator_without_touching_fallback() {
        let (number, hash, wire, light) = fixture_wire();
        let (_gen, gen_url, gen_hits) = scripted_witness_rpc(2, Some(wire)).await;
        let (_fb, fb_url, fb_hits) = scripted_witness_rpc(0, None).await;
        let fetcher = test_fetcher(&[&gen_url, &fb_url], Duration::from_secs(10));
        fetcher.remote_head.store(number, Ordering::Relaxed);

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
        let fetcher = test_fetcher(&[&gen_url, &fb_url], Duration::from_secs(30));
        fetcher.remote_head.store(number + FRONTIER_FRESHNESS_BLOCKS + 1, Ordering::Relaxed);

        let start = Instant::now();
        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert_eq!(gen_hits.load(Ordering::Relaxed), 1);
        assert_eq!(fb_hits.load(Ordering::Relaxed), 1);
        assert!(start.elapsed() < Duration::from_secs(5), "no generator grace on stale blocks");
    }

    /// Without a CLI-declared generator no endpoint is special: even a frontier-fresh
    /// miss rotates to the second endpoint in the same round — plain failover, mirroring
    /// the request path's `fetch_witness_without_generator_never_skips`.
    #[tokio::test]
    async fn no_declared_generator_keeps_plain_failover() {
        let (number, hash, wire, light) = fixture_wire();
        let (_first, first_url, first_hits) = scripted_witness_rpc(0, None).await;
        let (_second, second_url, second_hits) = scripted_witness_rpc(0, Some(wire)).await;
        let fetcher = TraceFetcher {
            generator_first: false,
            ..test_fetcher(&[&first_url, &second_url], Duration::from_secs(30))
        };
        fetcher.remote_head.store(number, Ordering::Relaxed);

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
        let fetcher = test_fetcher(&[&gen_url, &fb_url], Duration::from_secs(30));

        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert_eq!(fb_hits.load(Ordering::Relaxed), 1, "unknown head must use the full chain");
    }

    /// A downed generator costs at most the grace on a fresh block: the fetch then falls
    /// back to the full chain and succeeds on the fallback.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fresh_fetch_falls_back_after_grace_when_generator_is_down() {
        let (number, hash, wire, light) = fixture_wire();
        // Bind-then-drop: connections to this port are refused instantly.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let gen_url = format!("http://{}", dead.local_addr().unwrap());
        drop(dead);
        let (_fb, fb_url, fb_hits) = scripted_witness_rpc(0, Some(wire)).await;
        let fetcher = test_fetcher(&[&gen_url, &fb_url], Duration::from_millis(300));
        fetcher.remote_head.store(number, Ordering::Relaxed);

        let start = Instant::now();
        let got = fetcher.fetch_witness(number, hash).await;

        assert_eq!(got, light);
        assert!(
            start.elapsed() >= Duration::from_millis(300),
            "the generator keeps its grace before failover"
        );
        assert!(fb_hits.load(Ordering::Relaxed) >= 1);
    }

    /// `latest_block_number` feeds the freshness anchor.
    #[tokio::test]
    async fn latest_block_number_updates_the_freshness_anchor() {
        let mut module = jsonrpsee::server::RpcModule::new(());
        module.register_method("eth_blockNumber", |_, _, _| "0x64").unwrap();
        let server =
            jsonrpsee::server::ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        let _handle = server.start(module);

        let rpc_client = Arc::new(
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::trace_server(), None)
                .unwrap(),
        );
        let fetcher = TraceFetcher::new(rpc_client, true);
        assert_eq!(fetcher.remote_head.load(Ordering::Relaxed), u64::MAX);

        assert_eq!(fetcher.latest_block_number().await.unwrap(), 0x64);
        assert_eq!(fetcher.remote_head.load(Ordering::Relaxed), 0x64);
    }

    fn make_block_meta(block_number: u64) -> BlockMeta {
        BlockMeta {
            block_number,
            block_hash: Default::default(),
            post_state_root: Default::default(),
            post_withdrawals_root: Default::default(),
        }
    }

    #[test]
    fn test_trace_hooks_reorg_without_cache() {
        let hooks = TraceHooks::new(Arc::new(MockBlockStore), None);
        hooks.on_reorg(10, 2, &[Default::default()]).unwrap();
    }

    #[test]
    fn test_trace_hooks_stale_reset() {
        let hooks = TraceHooks::new(Arc::new(MockBlockStore), None);
        hooks.on_stale_reset(&make_block_meta(100)).unwrap();
    }

    // Minimal mock for test compilation
    struct MockBlockStore;
    impl stateless_core::ContractStore for MockBlockStore {
        fn get_contracts(&self, _: &[B256]) -> StoreResult<(HashMap<B256, Bytecode>, Vec<B256>)> {
            Ok((Default::default(), vec![]))
        }
        fn add_contracts(&self, _: &[(B256, Bytecode)]) -> StoreResult<()> {
            Ok(())
        }
    }
    impl stateless_core::ChainStore for MockBlockStore {
        fn get_canonical_tip(&self) -> StoreResult<Option<BlockMeta>> {
            Ok(None)
        }
        fn get_anchor(&self) -> StoreResult<Option<BlockMeta>> {
            Ok(None)
        }
        fn advance_chain(&self, _: &[BlockMeta]) -> StoreResult<()> {
            Ok(())
        }
        fn get_block_hash(&self, _: BlockNumber) -> StoreResult<Option<BlockHash>> {
            Ok(None)
        }
        fn rollback_chain(&self, _: BlockNumber) -> StoreResult<()> {
            Ok(())
        }
        fn reset_to_anchor(&self, _: &BlockMeta) -> StoreResult<()> {
            Ok(())
        }
    }
    impl stateless_core::DivergenceLookups for MockBlockStore {
        fn get_hash(&self, _: BlockNumber) -> StoreResult<Option<BlockHash>> {
            Ok(None)
        }
        fn get_earliest(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
            Ok(None)
        }
    }
    impl BlockStore for MockBlockStore {
        fn prune_chain(&self, _: BlockNumber) -> StoreResult<u64> {
            Ok(0)
        }
        fn store_block_data(&self, _: &[(Block<Transaction>, LightWitness)]) -> StoreResult<()> {
            Ok(())
        }
        fn get_block_and_witness(
            &self,
            _: BlockHash,
        ) -> StoreResult<(Block<Transaction>, LightWitness)> {
            Err(stateless_core::StoreError::Corrupt("not implemented".into()))
        }
    }
}
