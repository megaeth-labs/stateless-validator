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
    BlockStore, LightWitness,
    db::BlockMeta,
    pipeline::{BlockFetcher, BlockProcessor, ErrorAction, PipelineHooks},
};

use crate::{metrics, response_cache::ResponseCache};

/// Fetcher for the trace server: fetches blocks + witnesses, discards MPT witness,
/// converts SALT witness to [`LightWitness`].
pub struct TraceFetcher {
    pub rpc_client: Arc<RpcClient>,
}

impl BlockFetcher for TraceFetcher {
    type Output = (Block<Transaction>, LightWitness);

    async fn fetch(&self, block_number: u64) -> Result<(Block<Transaction>, LightWitness)> {
        let block_hash = self.rpc_client.get_block_hash(block_number).await?;
        let (salt, _mpt) = self.rpc_client.get_witness(block_number, block_hash).await?;
        let block = self.rpc_client.get_block(BlockId::Number(block_number.into()), true).await?;
        Ok((block, LightWitness::from(&salt)))
    }

    async fn latest_block_number(&self) -> Result<u64> {
        self.rpc_client.get_latest_block_number().await
    }

    async fn block_hash(&self, block_number: u64) -> Result<BlockHash> {
        self.rpc_client.get_block_hash(block_number).await
    }

    async fn latest_block_meta(&self) -> Result<BlockMeta> {
        let header =
            self.rpc_client.get_header(BlockId::Number(BlockNumberOrTag::Latest), false).await?;
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
    type Error = eyre::Report;

    async fn process(
        &self,
        (block, witness): Self::Input,
    ) -> std::result::Result<TraceProcessedBlock, eyre::Report> {
        let meta = BlockMeta {
            block_number: block.header.number,
            block_hash: block.header.hash,
            post_state_root: block.header.state_root,
            post_withdrawals_root: block.header.withdrawals_root.unwrap_or_default(),
        };
        Ok(TraceProcessedBlock { block, witness, meta })
    }

    fn error_action(&self, _: &eyre::Report) -> ErrorAction {
        // TraceProcessor doesn't validate — errors are IO/transient, worth retrying
        ErrorAction::Retry
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
        self.db.store_block_data(&pairs)
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
    use std::sync::Arc;

    use super::*;

    fn make_block_meta(block_number: u64) -> BlockMeta {
        BlockMeta {
            block_number,
            block_hash: Default::default(),
            post_state_root: Default::default(),
            post_withdrawals_root: Default::default(),
        }
    }

    #[test]
    fn test_trace_processed_block_implements_trait() {
        let meta = make_block_meta(42);
        assert_eq!(meta.block_number, 42);

        // verify_continuity should be no-op for TraceProcessedBlock
        // (tested indirectly via ProcessedBlock default impl)
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
        fn get_contracts(
            &self,
            _: &[alloy_primitives::B256],
        ) -> eyre::Result<(
            std::collections::HashMap<alloy_primitives::B256, revm::state::Bytecode>,
            Vec<alloy_primitives::B256>,
        )> {
            Ok((Default::default(), vec![]))
        }
        fn add_contracts(
            &self,
            _: &[(alloy_primitives::B256, revm::state::Bytecode)],
        ) -> eyre::Result<()> {
            Ok(())
        }
    }
    impl stateless_core::ChainStore for MockBlockStore {
        fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
            Ok(None)
        }
        fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
            Ok(None)
        }
        fn advance_chain(&self, _: &[BlockMeta]) -> eyre::Result<()> {
            Ok(())
        }
        fn get_block_hash(&self, _: BlockNumber) -> eyre::Result<Option<BlockHash>> {
            Ok(None)
        }
        fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
            Ok(None)
        }
        fn rollback_chain(&self, _: BlockNumber) -> eyre::Result<()> {
            Ok(())
        }
        fn reset_to_anchor(&self, _: &BlockMeta) -> eyre::Result<()> {
            Ok(())
        }
    }
    impl stateless_core::PrunableChainStore for MockBlockStore {
        fn prune_chain(&self, _: BlockNumber) -> eyre::Result<u64> {
            Ok(0)
        }
    }
    impl stateless_core::BlockStore for MockBlockStore {
        fn store_block_data(&self, _: &[(Block<Transaction>, LightWitness)]) -> eyre::Result<()> {
            Ok(())
        }
        fn get_block_and_witness(
            &self,
            _: BlockHash,
        ) -> eyre::Result<(Block<Transaction>, LightWitness)> {
            Err(eyre::eyre!("not implemented"))
        }
    }
}
