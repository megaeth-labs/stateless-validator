//! Chain synchronization for the debug-trace-server binary.
//!
//! Contains the [`chain_monitor`] (fetcher lifecycle + reorg/stale detection)
//! and [`trace_chain_advancer`] (DB writes + reorg callback).

use std::{sync::Arc, time::Instant};

use alloy_primitives::{B256, BlockNumber};
use alloy_rpc_types_eth::{Block, BlockId};
use eyre::{Result, anyhow};
use op_alloy_rpc_types::Transaction;
use stateless_core::{
    LightWitness, RpcClient,
    chain_sync::{ChainSyncConfig, block_fetcher, find_divergence_point},
    db::{BlockMeta, BlockStore, ChainStore},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Events sent from [`chain_monitor`] to [`trace_chain_advancer`] through a channel.
pub enum ChainSyncEvent {
    /// New blocks fetched from RPC, ready to store and advance.
    NewBlocks(Vec<(Block<Transaction>, LightWitness)>),
    /// Chain reorg detected — advancer must roll back and invalidate caches.
    Reorg { rollback_to: BlockNumber, reverted_hashes: Vec<B256> },
    /// Local data is too stale — reset the anchor to this block.
    ResetAnchor {
        block_number: BlockNumber,
        block_hash: alloy_primitives::BlockHash,
        state_root: B256,
        withdrawals_root: B256,
    },
}

/// Chain monitor for `debug-trace-server`.
///
/// Manages the [`block_fetcher`] lifecycle, detects reorgs and stale data,
/// and forwards fetched blocks as [`ChainSyncEvent`]s to the advancer.
/// All DB access is read-only via [`ChainStore`].
pub async fn chain_monitor(
    client: Arc<RpcClient>,
    db: Arc<dyn ChainStore>,
    advancer_tx: kanal::Sender<ChainSyncEvent>,
    config: Arc<ChainSyncConfig>,
    shutdown: CancellationToken,
) -> Result<()> {
    let advancer_tx = advancer_tx.to_async();
    info!("[Monitor] Starting chain monitor");

    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }

        // Determine where to start fetching from DB tip
        let start_block = match db.get_canonical_tip()? {
            Some(tip) => tip.block_number + 1,
            None => return Err(anyhow!("Local chain is empty")),
        };

        // Spawn a block_fetcher with LightWitness transform
        let (fetch_tx, fetch_rx) =
            kanal::bounded::<(Block<Transaction>, LightWitness)>(config.fetch_channel_capacity);
        let fetch_rx = fetch_rx.to_async();
        let fetcher_shutdown = CancellationToken::new();
        let mut fetcher_handle = tokio::task::spawn(block_fetcher(
            Arc::clone(&client),
            fetch_tx,
            start_block,
            Arc::clone(&config),
            fetcher_shutdown.clone(),
            |block, salt_witness, _mpt_witness| (block, LightWitness::from(&salt_witness)),
            None::<fn(u64)>,
        ));

        info!(start_block, "[Monitor] Fetcher spawned");

        // Inner loop: forward blocks + periodic reorg check
        let mut last_reorg_check = Instant::now();
        let reorg_check_interval = config.tracker_poll_interval * 10;
        let mut restart = false;

        loop {
            // Receive next fetched block, or detect fetcher crash/error
            let item = tokio::select! {
                r = fetch_rx.recv() => match r {
                    Ok(item) => Some(item),
                    Err(_) => {
                        // Channel closed — check if fetcher errored
                        if let Ok(Err(e)) = fetcher_handle.await {
                            error!(error = %e, "[Monitor] Fetcher exited with error");
                        }
                        break;
                    }
                },
                r = &mut fetcher_handle => {
                    // Fetcher task completed (error or panic)
                    match r {
                        Ok(Err(e)) => error!(error = %e, "[Monitor] Fetcher exited with error"),
                        Err(e) => error!(error = %e, "[Monitor] Fetcher panicked"),
                        Ok(Ok(())) => info!("[Monitor] Fetcher exited cleanly"),
                    }
                    break;
                },
                _ = tokio::time::sleep(config.tracker_poll_interval) => None,
                _ = shutdown.cancelled() => {
                    fetcher_shutdown.cancel();
                    return Ok(());
                }
            };

            // Accumulate batch from channel
            let mut batch = Vec::new();
            if let Some(item) = item {
                batch.push(item);
                // Drain any additional ready items
                while let Ok(Some(item)) = fetch_rx.try_recv() {
                    batch.push(item);
                }
            }

            // Forward batch to advancer
            if !batch.is_empty() {
                advancer_tx
                    .send(ChainSyncEvent::NewBlocks(batch))
                    .await
                    .map_err(|_| anyhow!("Advancer channel closed"))?;
            }

            // Periodic reorg/stale check
            if last_reorg_check.elapsed() < reorg_check_interval {
                continue;
            }
            last_reorg_check = Instant::now();

            // Stale data detection
            let Some(canonical_tip) = db.get_canonical_tip()? else {
                continue;
            };
            let (tip_number, tip_hash) = (canonical_tip.block_number, canonical_tip.block_hash);

            let chain_latest = match client.get_latest_block_number().await {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, "[Monitor] Failed to get chain latest");
                    continue;
                }
            };

            if chain_latest > tip_number + config.pruner_blocks_to_keep {
                warn!(
                    tip_number,
                    chain_latest, "[Monitor] Local data is too stale, resetting anchor"
                );
                let header = match client.get_header(BlockId::latest(), false).await {
                    Ok(header) => header,
                    Err(e) => {
                        warn!(
                            error = %e,
                            "[Monitor] Failed to fetch latest header for anchor reset, retrying"
                        );
                        continue;
                    }
                };
                fetcher_shutdown.cancel();
                advancer_tx
                    .send(ChainSyncEvent::ResetAnchor {
                        block_number: header.number,
                        block_hash: header.hash,
                        state_root: header.state_root,
                        withdrawals_root: header.withdrawals_root.unwrap_or_default(),
                    })
                    .await
                    .map_err(|_| anyhow!("Advancer channel closed"))?;
                restart = true;
                break;
            }

            // Reorg detection
            match client.get_block_hash(tip_number).await {
                Ok(hash) if hash != tip_hash => {
                    warn!(
                        block_number = tip_number,
                        expected_hash = %tip_hash,
                        actual_hash = %hash,
                        "[Monitor] Hash mismatch, resolving reorg"
                    );
                    fetcher_shutdown.cancel();
                    let rollback_to = match find_divergence_point(
                        &client,
                        &|n| db.get_block_hash(n),
                        &|| db.get_earliest_block(),
                        tip_number,
                    )
                    .await
                    {
                        Ok(rollback_to) => rollback_to,
                        Err(e) => {
                            warn!(
                                block_number = tip_number,
                                error = %e,
                                "[Monitor] Failed to resolve reorg, restarting fetcher"
                            );
                            restart = true;
                            break;
                        }
                    };

                    let mut reverted_hashes = Vec::new();
                    for n in (rollback_to + 1)..=tip_number {
                        if let Ok(Some(h)) = db.get_block_hash(n) {
                            reverted_hashes.push(h);
                        }
                    }

                    advancer_tx
                        .send(ChainSyncEvent::Reorg { rollback_to, reverted_hashes })
                        .await
                        .map_err(|_| anyhow!("Advancer channel closed"))?;
                    restart = true;
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "[Monitor] Network error validating tip");
                }
                _ => {}
            }
        }

        if !restart {
            // Fetcher ended unexpectedly, wait before restarting
            tokio::select! {
                _ = tokio::time::sleep(config.tracker_error_sleep) => {}
                _ = shutdown.cancelled() => return Ok(()),
            }
        }

        // Brief pause before restarting to let advancer process events
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            _ = shutdown.cancelled() => return Ok(()),
        }
    }
}

/// DB-write side of the debug-trace-server chain sync pipeline.
///
/// Receives [`ChainSyncEvent`]s from the fetcher, stores blocks, advances the
/// canonical chain, and handles reorgs. All DB mutations go through [`BlockStore`].
pub async fn trace_chain_advancer<F>(
    db: Arc<dyn BlockStore>,
    rx: kanal::Receiver<ChainSyncEvent>,
    on_reorg: Option<F>,
    shutdown: CancellationToken,
) -> Result<()>
where
    F: Fn(&[B256]) + Send + Sync,
{
    let rx = rx.to_async();
    info!("[TraceAdvancer] Starting");

    loop {
        let event = tokio::select! {
            r = rx.recv() => match r {
                Ok(event) => event,
                Err(_) => {
                    info!("[TraceAdvancer] Channel closed, stopping");
                    return Ok(());
                }
            },
            _ = shutdown.cancelled() => {
                info!("[TraceAdvancer] Shutting down gracefully");
                return Ok(());
            }
        };

        match event {
            ChainSyncEvent::NewBlocks(blocks) => {
                let count = blocks.len();
                let start = Instant::now();

                db.store_block_data(&blocks)?;

                // Build BlockMetas from block headers for chain advancement
                let chain_tips: Vec<BlockMeta> = blocks
                    .iter()
                    .map(|(block, _)| BlockMeta {
                        block_number: block.header.number,
                        block_hash: block.header.hash,
                        post_state_root: block.header.state_root,
                        post_withdrawals_root: block.header.withdrawals_root.unwrap_or_default(),
                    })
                    .collect();
                db.advance_chain(&chain_tips)?;

                info!(
                    blocks = count,
                    ms = start.elapsed().as_millis() as u64,
                    "[TraceAdvancer] Stored and advanced"
                );
            }
            ChainSyncEvent::Reorg { rollback_to, reverted_hashes } => {
                warn!(
                    rollback_to,
                    reverted = reverted_hashes.len(),
                    "[TraceAdvancer] Processing reorg"
                );
                db.rollback_chain(rollback_to)?;
                if let Some(ref callback) = on_reorg {
                    callback(&reverted_hashes);
                }
            }
            ChainSyncEvent::ResetAnchor {
                block_number,
                block_hash,
                state_root,
                withdrawals_root,
            } => {
                info!(block_number, %block_hash, "[TraceAdvancer] Resetting anchor");
                db.reset_to_anchor(&BlockMeta {
                    block_number,
                    block_hash,
                    post_state_root: state_root,
                    post_withdrawals_root: withdrawals_root,
                })?;
            }
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        sync::Mutex,
    };

    use alloy_primitives::BlockHash;

    use super::*;

    // -----------------------------------------------------------------------
    // In-memory mock ChainStore for testing pipeline logic without redb
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockChainStoreInner {
        chain: BTreeMap<u64, BlockMeta>,
        anchor: Option<BlockMeta>,
        blocks: Vec<(Block<Transaction>, LightWitness)>,
    }

    struct MockChainStore {
        inner: Mutex<MockChainStoreInner>,
    }

    impl MockChainStore {
        fn with_anchor(anchor: BlockMeta) -> Self {
            let mut inner = MockChainStoreInner::default();
            inner.chain.insert(anchor.block_number, anchor.clone());
            inner.anchor = Some(anchor);
            Self { inner: Mutex::new(inner) }
        }

        fn tip(&self) -> Option<BlockMeta> {
            let inner = self.inner.lock().unwrap();
            inner.chain.values().last().cloned()
        }

        fn chain_len(&self) -> usize {
            self.inner.lock().unwrap().chain.len()
        }

        fn stored_blocks_count(&self) -> usize {
            self.inner.lock().unwrap().blocks.len()
        }
    }

    impl stateless_core::db::ContractStore for MockChainStore {
        fn get_contracts(
            &self,
            _hashes: &[B256],
        ) -> eyre::Result<(HashMap<B256, revm::state::Bytecode>, Vec<B256>)> {
            Ok((HashMap::new(), vec![]))
        }

        fn add_contracts(&self, _codes: &[(B256, revm::state::Bytecode)]) -> eyre::Result<()> {
            Ok(())
        }
    }

    impl ChainStore for MockChainStore {
        fn get_canonical_tip(&self) -> eyre::Result<Option<BlockMeta>> {
            Ok(self.tip())
        }

        fn get_anchor(&self) -> eyre::Result<Option<BlockMeta>> {
            Ok(self.inner.lock().unwrap().anchor.clone())
        }

        fn advance_chain(&self, blocks: &[BlockMeta]) -> eyre::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            for block in blocks {
                inner.chain.insert(block.block_number, block.clone());
            }
            Ok(())
        }

        fn get_block_hash(&self, block_number: BlockNumber) -> eyre::Result<Option<BlockHash>> {
            Ok(self.inner.lock().unwrap().chain.get(&block_number).map(|b| b.block_hash))
        }

        fn get_earliest_block(&self) -> eyre::Result<Option<(BlockNumber, BlockHash)>> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .chain
                .values()
                .next()
                .map(|b| (b.block_number, b.block_hash)))
        }

        fn rollback_chain(&self, to_block: BlockNumber) -> eyre::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.chain.retain(|&n, _| n <= to_block);
            Ok(())
        }

        fn reset_to_anchor(&self, anchor: &BlockMeta) -> eyre::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.chain.clear();
            inner.chain.insert(anchor.block_number, anchor.clone());
            inner.anchor = Some(anchor.clone());
            Ok(())
        }
    }

    impl stateless_core::db::PrunableChainStore for MockChainStore {
        fn prune_chain(&self, before_block: BlockNumber) -> eyre::Result<u64> {
            let mut inner = self.inner.lock().unwrap();
            let before: Vec<u64> =
                inner.chain.keys().filter(|&&n| n < before_block).copied().collect();
            let count = before.len() as u64;
            for n in before {
                inner.chain.remove(&n);
            }
            Ok(count)
        }
    }

    impl BlockStore for MockChainStore {
        fn store_block_data(
            &self,
            blocks: &[(Block<Transaction>, LightWitness)],
        ) -> eyre::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            for b in blocks {
                inner.blocks.push(b.clone());
            }
            Ok(())
        }

        fn get_block_and_witness(
            &self,
            _block_hash: BlockHash,
        ) -> eyre::Result<(Block<Transaction>, LightWitness)> {
            Err(eyre::eyre!("not implemented in mock"))
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Helper to create a minimal Block with the given number and hash.
    fn make_test_block(
        number: u64,
        hash: B256,
        state_root: B256,
        withdrawals_root: B256,
    ) -> Block<Transaction> {
        let mut header = alloy_rpc_types_eth::Header::<alloy_consensus::Header>::default();
        header.inner.number = number;
        header.hash = hash;
        header.inner.state_root = state_root;
        header.inner.withdrawals_root = Some(withdrawals_root);
        Block { header, ..Default::default() }
    }

    /// Helper to create an empty LightWitness.
    fn empty_light_witness() -> LightWitness {
        LightWitness {
            kvs: std::collections::BTreeMap::new(),
            levels: rustc_hash::FxHashMap::default(),
        }
    }

    // -----------------------------------------------------------------------
    // trace_chain_advancer tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_trace_chain_advancer_new_blocks() {
        let anchor = BlockMeta {
            block_number: 10,
            block_hash: BlockHash::from([10u8; 32]),
            post_state_root: B256::from([110u8; 32]),
            post_withdrawals_root: B256::from([210u8; 32]),
        };
        let store = Arc::new(MockChainStore::with_anchor(anchor));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store) as Arc<dyn BlockStore>;
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(trace_chain_advancer::<fn(&[B256])>(
            store_clone,
            rx,
            None,
            shutdown_clone,
        ));

        let block = make_test_block(
            11,
            B256::from([11u8; 32]),
            B256::from([111u8; 32]),
            B256::from([211u8; 32]),
        );
        let witness = empty_light_witness();

        tx.send(ChainSyncEvent::NewBlocks(vec![(block, witness)])).unwrap();
        drop(tx);

        handle.await.unwrap().unwrap();

        // Chain should have advanced to block 11
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 11);
        assert_eq!(store.stored_blocks_count(), 1);
    }

    #[tokio::test]
    async fn test_trace_chain_advancer_reorg() {
        let anchor = BlockMeta {
            block_number: 5,
            block_hash: BlockHash::from([5u8; 32]),
            post_state_root: B256::from([105u8; 32]),
            post_withdrawals_root: B256::from([205u8; 32]),
        };
        let store = Arc::new(MockChainStore::with_anchor(anchor));

        // Advance chain to block 10
        let blocks: Vec<BlockMeta> = (6..=10)
            .map(|n| BlockMeta {
                block_number: n,
                block_hash: BlockHash::from([n as u8; 32]),
                post_state_root: B256::from([(n + 100) as u8; 32]),
                post_withdrawals_root: B256::from([(n + 200) as u8; 32]),
            })
            .collect();
        store.advance_chain(&blocks).unwrap();

        let shutdown = CancellationToken::new();
        let (tx, rx) = kanal::bounded(16);

        let reorged = Arc::new(Mutex::new(Vec::<B256>::new()));
        let reorged_clone = Arc::clone(&reorged);
        let on_reorg = move |hashes: &[B256]| {
            reorged_clone.lock().unwrap().extend_from_slice(hashes);
        };

        let store_clone = Arc::clone(&store) as Arc<dyn BlockStore>;
        let shutdown_clone = shutdown.clone();
        let handle =
            tokio::spawn(trace_chain_advancer(store_clone, rx, Some(on_reorg), shutdown_clone));

        // Send reorg event: rollback to block 7, reverting blocks 8, 9, 10
        let reverted_hashes: Vec<B256> = (8..=10).map(|n| B256::from([n as u8; 32])).collect();
        tx.send(ChainSyncEvent::Reorg { rollback_to: 7, reverted_hashes: reverted_hashes.clone() })
            .unwrap();
        drop(tx);

        handle.await.unwrap().unwrap();

        // Chain should be rolled back to block 7
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 7);

        // Callback should have been invoked with reverted hashes
        let reorged = reorged.lock().unwrap();
        assert_eq!(reorged.len(), 3);
    }

    #[tokio::test]
    async fn test_trace_chain_advancer_reset_anchor() {
        let anchor = BlockMeta {
            block_number: 5,
            block_hash: BlockHash::from([5u8; 32]),
            post_state_root: B256::from([105u8; 32]),
            post_withdrawals_root: B256::from([205u8; 32]),
        };
        let store = Arc::new(MockChainStore::with_anchor(anchor));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store) as Arc<dyn BlockStore>;
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(trace_chain_advancer::<fn(&[B256])>(
            store_clone,
            rx,
            None,
            shutdown_clone,
        ));

        // Send reset anchor event
        tx.send(ChainSyncEvent::ResetAnchor {
            block_number: 100,
            block_hash: B256::from([100u8; 32]),
            state_root: B256::from([200u8; 32]),
            withdrawals_root: B256::from([201u8; 32]),
        })
        .unwrap();
        drop(tx);

        handle.await.unwrap().unwrap();

        // Chain should be reset to the new anchor
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 100);
        assert_eq!(store.chain_len(), 1);
    }
}
