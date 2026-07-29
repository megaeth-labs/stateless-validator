//! Trace server pipeline components.
//!
//! Provides [`TraceProcessor`] (pass-through, no validation) and
//! [`TraceHooks`] (block storage + cache invalidation) for the shared pipeline
//! in [`stateless_core::pipeline::run_pipeline`].

use std::sync::Arc;

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

/// Fetcher for the trace server: fetches blocks + witnesses, discards MPT witness.
///
/// Witnesses go through the zero-validation light decode (`get_witness_light`):
/// the server never verifies the proof, so the full decode's per-point
/// elliptic-curve work bought nothing.
///
/// Witness fetches deliberately use the full endpoint chain (no age-based routing): the sync
/// frontier trails the remote head by only `tip_buffer`, inside the generator's retention —
/// except during deep catch-up with `--blocks-to-keep` beyond that retention, where each
/// pruned block burns one generator probe before failover (accepted; routing here would need
/// a remote-head anchor instead of the local tip).
pub struct TraceFetcher {
    pub rpc_client: Arc<RpcClient>,
}

impl BlockFetcher for TraceFetcher {
    type Output = (Block<Transaction>, LightWitness);

    async fn fetch(&self, block_number: u64) -> Result<(Block<Transaction>, LightWitness)> {
        // Fetch header first to pin the block hash, then witness + full block in parallel.
        // Matches the shape used by `DataProvider::do_fetch_block_data` — ~halves the wall
        // clock under chain-sync load by overlapping the witness fetch with the full-block
        // fetch instead of serializing all three round trips.
        let block_hash = self.rpc_client.get_block_hash(block_number).await;
        let (witness_res, block_res) = tokio::join!(
            self.rpc_client.get_witness_light(block_number, block_hash),
            self.rpc_client.get_block(BlockId::Number(block_number.into()), true),
        );
        let (light, _mpt) = witness_res;
        Ok((block_res, light))
    }

    async fn latest_block_number(&self) -> Result<u64> {
        Ok(self.rpc_client.get_latest_block_number().await)
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
    use std::sync::Arc;

    use alloy_primitives::B256;

    use super::*;
    use crate::server_db::test_support::{StubBlockStore, make_block_meta};

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
