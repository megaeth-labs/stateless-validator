//! Chain synchronization for the stateless validator binary.
//!
//! Contains the validation-specific [`chain_advancer`] (ordering + persistence) and
//! [`validator_reorg_monitor`] (reorg detection + rollback).

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use alloy_primitives::BlockNumber;
use eyre::{Result, anyhow};
use stateless_core::{
    RpcClient,
    chain_sync::find_divergence_point,
    db::{BlockMeta, ChainStore, ValidatedBlock, ValidationFailure},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Result of reorg detection — signals the validator to restart its pipeline.
#[derive(Debug)]
pub struct ReorgEvent {
    /// Block number to roll back to (inclusive).
    pub rollback_to: BlockNumber,
    /// Depth of the reorg (number of reverted blocks).
    pub depth: u64,
}

/// Monitors the validator's canonical chain for reorgs.
///
/// Periodically compares the local canonical tip hash with the remote RPC.
/// On mismatch, finds the divergence point, rolls back the chain, and returns
/// a [`ReorgEvent`] signaling the caller to restart the pipeline.
pub async fn validator_reorg_monitor(
    client: Arc<RpcClient>,
    store: Arc<dyn ChainStore>,
    check_interval: Duration,
    shutdown: CancellationToken,
) -> Result<ReorgEvent> {
    info!("[ReorgMonitor] Starting");

    loop {
        tokio::select! {
            _ = tokio::time::sleep(check_interval) => {}
            _ = shutdown.cancelled() => {
                return Err(anyhow!("Shutdown requested"));
            }
        }

        let Some(tip) = store.get_canonical_tip()? else {
            continue;
        };

        // Compare local tip hash with RPC
        let remote_hash = match client.get_block_hash(tip.block_number).await {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "[ReorgMonitor] Failed to get remote hash, retrying");
                continue;
            }
        };

        if remote_hash == tip.block_hash {
            continue; // chain is consistent
        }

        warn!(
            block_number = tip.block_number,
            local_hash = %tip.block_hash,
            remote_hash = %remote_hash,
            "[ReorgMonitor] Hash mismatch detected, resolving reorg"
        );

        let rollback_to = find_divergence_point(
            &client,
            &|n| store.get_block_hash(n),
            &|| store.get_earliest_block(),
            tip.block_number,
        )
        .await?;

        let depth = tip.block_number.saturating_sub(rollback_to);
        warn!(rollback_to, depth, "[ReorgMonitor] Rolling back chain");

        store.rollback_chain(rollback_to)?;

        return Ok(ReorgEvent { rollback_to, depth });
    }
}

/// Collects validation results and advances the canonical chain in block-number order.
///
/// Receives results from workers (potentially out of order), buffers them,
/// and advances the canonical tip in strict sequence. Batches multiple consecutive
/// blocks into a single persistence write.
///
/// The optional `on_advance` callback is invoked after each batch of blocks is
/// persisted, receiving the new tip block number. Use this to update metrics or
/// notify external systems.
///
/// If any validation fails, returns `Err` immediately (process should exit).
pub async fn chain_advancer<F>(
    rx: kanal::Receiver<std::result::Result<ValidatedBlock, ValidationFailure>>,
    store: Arc<dyn ChainStore>,
    initial_tip: BlockMeta,
    shutdown: CancellationToken,
    on_advance: Option<F>,
) -> Result<()>
where
    F: Fn(u64) + Send + Sync,
{
    let rx = rx.to_async();
    let mut next_expected = initial_tip.block_number + 1;
    let mut current_tip = initial_tip;
    let mut buffer: BTreeMap<u64, ValidatedBlock> = BTreeMap::new();

    info!(start_block = next_expected, "[Advancer] Starting chain advancer");

    loop {
        // Receive next result
        let result = tokio::select! {
            r = rx.recv() => match r {
                Ok(r) => r,
                Err(_) => {
                    info!("[Advancer] Channel closed, stopping");
                    return Ok(());
                }
            },
            _ = shutdown.cancelled() => {
                info!("[Advancer] Shutting down gracefully");
                return Ok(());
            }
        };

        match result {
            Err(failure) => {
                error!(
                    block_number = failure.block_number,
                    block_hash = %failure.block_hash,
                    error = %failure.error,
                    "[Advancer] Validation failed, terminating"
                );
                return Err(eyre::eyre!(
                    "Block {} ({}) validation failed: {}",
                    failure.block_number,
                    failure.block_hash,
                    failure.error
                ));
            }
            Ok(validated) => {
                debug!(
                    block_number = validated.block_number,
                    "[Advancer] Received validated block"
                );
                buffer.insert(validated.block_number, validated);
            }
        }

        // Drain consecutive blocks from buffer
        let mut new_blocks = Vec::new();
        while let Some(validated) = buffer.remove(&next_expected) {
            // Verify state root continuity
            if validated.pre_state_root != current_tip.post_state_root {
                return Err(eyre::eyre!(
                    "Block {} pre_state_root mismatch: expected {:?}, got {:?}",
                    validated.block_number,
                    current_tip.post_state_root,
                    validated.pre_state_root
                ));
            }
            if validated.pre_withdrawals_root != current_tip.post_withdrawals_root {
                return Err(eyre::eyre!(
                    "Block {} pre_withdrawals_root mismatch: expected {:?}, got {:?}",
                    validated.block_number,
                    current_tip.post_withdrawals_root,
                    validated.pre_withdrawals_root
                ));
            }

            current_tip = BlockMeta {
                block_number: validated.block_number,
                block_hash: validated.block_hash,
                post_state_root: validated.post_state_root,
                post_withdrawals_root: validated.post_withdrawals_root,
            };
            new_blocks.push(current_tip.clone());
            next_expected += 1;
        }

        // Batch-persist new blocks and update tip
        if !new_blocks.is_empty() {
            let advanced = new_blocks.len();
            store.advance_chain(&new_blocks)?;
            if let Some(ref callback) = on_advance {
                callback(current_tip.block_number);
            }
            debug!(
                tip = current_tip.block_number,
                advanced = advanced,
                buffered = buffer.len(),
                "[Advancer] Chain advanced"
            );
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

    use alloy_primitives::{B256, BlockHash, BlockNumber};

    use super::*;

    // -----------------------------------------------------------------------
    // In-memory mock ChainStore for testing pipeline logic without redb
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockChainStoreInner {
        chain: BTreeMap<u64, BlockMeta>,
        anchor: Option<BlockMeta>,
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

    // -----------------------------------------------------------------------
    // Helper to build ValidatedBlock with state-root continuity
    // -----------------------------------------------------------------------

    fn make_validated_block(number: u64, pre_state: B256, pre_withdrawals: B256) -> ValidatedBlock {
        ValidatedBlock {
            block_number: number,
            block_hash: BlockHash::from([number as u8; 32]),
            post_state_root: B256::from([(number + 100) as u8; 32]),
            post_withdrawals_root: B256::from([(number + 200) as u8; 32]),
            pre_state_root: pre_state,
            pre_withdrawals_root: pre_withdrawals,
        }
    }

    fn make_initial_tip(number: u64) -> BlockMeta {
        BlockMeta {
            block_number: number,
            block_hash: BlockHash::from([number as u8; 32]),
            post_state_root: B256::from([(number + 100) as u8; 32]),
            post_withdrawals_root: B256::from([(number + 200) as u8; 32]),
        }
    }

    // -----------------------------------------------------------------------
    // Mock RPC server for reorg monitor tests
    // -----------------------------------------------------------------------

    async fn start_mock_rpc(
        remote_hashes: HashMap<u64, BlockHash>,
    ) -> (jsonrpsee::server::ServerHandle, String) {
        use jsonrpsee::{RpcModule, server::ServerBuilder};

        let mut module = RpcModule::new(remote_hashes);
        module
            .register_method("eth_getHeaderByNumber", |params, ctx, _| {
                let (hex_number,): (String,) = params.parse().unwrap();
                let block_number =
                    u64::from_str_radix(hex_number.strip_prefix("0x").unwrap_or(&hex_number), 16)
                        .unwrap();
                let hash = ctx.get(&block_number).copied().unwrap_or_default();
                Ok::<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>(serde_json::json!({
                    "hash": hash,
                    "number": format!("0x{block_number:x}"),
                    "parentHash": B256::ZERO,
                    "timestamp": "0x0",
                    "stateRoot": B256::ZERO,
                    "transactionsRoot": B256::ZERO,
                    "receiptsRoot": B256::ZERO,
                    "logsBloom": alloy_primitives::Bloom::ZERO,
                    "gasUsed": "0x0",
                    "gasLimit": "0x0",
                    "mixHash": B256::ZERO,
                    "nonce": "0x0000000000000000",
                    "extraData": "0x",
                    "difficulty": "0x0",
                    "sha3Uncles": B256::ZERO,
                    "miner": alloy_primitives::Address::ZERO,
                    "baseFeePerGas": "0x0"
                }))
            })
            .unwrap();

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        let handle = server.start(module);
        (handle, url)
    }

    // -----------------------------------------------------------------------
    // chain_advancer tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_chain_advancer_sequential_delivery() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Send blocks 11, 12, 13 in order
        let block11 = make_validated_block(
            11,
            initial_tip.post_state_root,
            initial_tip.post_withdrawals_root,
        );
        let block12 =
            make_validated_block(12, block11.post_state_root, block11.post_withdrawals_root);
        let block13 =
            make_validated_block(13, block12.post_state_root, block12.post_withdrawals_root);

        tx.send(Ok(block11)).unwrap();
        tx.send(Ok(block12)).unwrap();
        tx.send(Ok(block13)).unwrap();

        // Close channel to let advancer finish
        drop(tx);
        handle.await.unwrap().unwrap();

        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 13);
    }

    #[tokio::test]
    async fn test_chain_advancer_out_of_order_delivery() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Build a chain: 11 -> 12 -> 13
        let block11 = make_validated_block(
            11,
            initial_tip.post_state_root,
            initial_tip.post_withdrawals_root,
        );
        let block12 =
            make_validated_block(12, block11.post_state_root, block11.post_withdrawals_root);
        let block13 =
            make_validated_block(13, block12.post_state_root, block12.post_withdrawals_root);

        // Send out of order: 13, 12, 11
        tx.send(Ok(block13)).unwrap();
        tx.send(Ok(block12)).unwrap();

        // After sending 13, 12 — neither should be advanced yet (missing 11)
        tokio::time::sleep(Duration::from_millis(50)).await;
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 10, "tip should still be 10 until block 11 arrives");

        // Now send 11 — all three should drain
        tx.send(Ok(block11)).unwrap();
        drop(tx);
        handle.await.unwrap().unwrap();

        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 13);
    }

    #[tokio::test]
    async fn test_chain_advancer_state_root_mismatch() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Send block 11 with wrong pre_state_root
        let bad_block = ValidatedBlock {
            block_number: 11,
            block_hash: BlockHash::from([11u8; 32]),
            post_state_root: B256::from([0xAAu8; 32]),
            post_withdrawals_root: B256::from([0xBBu8; 32]),
            pre_state_root: B256::from([0xFFu8; 32]), // wrong!
            pre_withdrawals_root: initial_tip.post_withdrawals_root,
        };

        tx.send(Ok(bad_block)).unwrap();
        drop(tx);

        let result = handle.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("pre_state_root mismatch"));
    }

    #[tokio::test]
    async fn test_chain_advancer_validation_failure_propagation() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Send a validation failure
        tx.send(Err(ValidationFailure {
            block_number: 11,
            block_hash: BlockHash::from([11u8; 32]),
            error: "execution reverted".to_string(),
        }))
        .unwrap();
        drop(tx);

        let result = handle.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("execution reverted"));
    }

    #[tokio::test]
    async fn test_chain_advancer_shutdown() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (_tx, rx) =
            kanal::bounded::<std::result::Result<ValidatedBlock, ValidationFailure>>(16);

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip,
            shutdown_clone,
            None::<fn(u64)>,
        ));

        // Cancel shutdown — advancer should exit cleanly
        shutdown.cancel();
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // chain_advancer callback test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_chain_advancer_invokes_callback() {
        let initial_tip = make_initial_tip(10);
        let store = Arc::new(MockChainStore::with_anchor(initial_tip.clone()));
        let shutdown = CancellationToken::new();

        let (tx, rx) = kanal::bounded(16);

        let callback_values = Arc::new(Mutex::new(Vec::<u64>::new()));
        let cb = {
            let values = Arc::clone(&callback_values);
            move |block_number: u64| {
                values.lock().unwrap().push(block_number);
            }
        };

        let store_clone = Arc::clone(&store);
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(chain_advancer(
            rx,
            store_clone,
            initial_tip.clone(),
            shutdown_clone,
            Some(cb),
        ));

        let block11 = make_validated_block(
            11,
            initial_tip.post_state_root,
            initial_tip.post_withdrawals_root,
        );
        let block12 =
            make_validated_block(12, block11.post_state_root, block11.post_withdrawals_root);

        tx.send(Ok(block11)).unwrap();
        tx.send(Ok(block12)).unwrap();
        drop(tx);

        handle.await.unwrap().unwrap();

        let values = callback_values.lock().unwrap();
        // Callback should have been invoked with the tip block numbers after each advance
        assert!(values.contains(&11) || values.contains(&12));
        // The last call should be for block 12
        assert_eq!(*values.last().unwrap(), 12);
    }

    // -----------------------------------------------------------------------
    // validator_reorg_monitor tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validator_reorg_monitor_detects_reorg() {
        // Local chain: blocks 1..=10, all with hash [n; 32]
        let anchor = make_initial_tip(1);
        let store = Arc::new(MockChainStore::with_anchor(anchor));
        let blocks: Vec<BlockMeta> = (2..=10)
            .map(|n| BlockMeta {
                block_number: n,
                block_hash: BlockHash::from([n as u8; 32]),
                post_state_root: B256::from([(n + 100) as u8; 32]),
                post_withdrawals_root: B256::from([(n + 200) as u8; 32]),
            })
            .collect();
        store.advance_chain(&blocks).unwrap();

        // Remote: blocks 1..=8 match, 9 and 10 diverge
        let mut remote = HashMap::new();
        for n in 1..=8 {
            remote.insert(n, B256::from([n as u8; 32]));
        }
        remote.insert(9, B256::from([0xA9u8; 32]));
        remote.insert(10, B256::from([0xAAu8; 32]));

        let (handle, url) = start_mock_rpc(remote).await;
        let client = Arc::new(stateless_core::RpcClient::new(&url, &url).unwrap());

        let shutdown = CancellationToken::new();
        let event = validator_reorg_monitor(
            client,
            store.clone() as Arc<dyn ChainStore>,
            Duration::from_millis(10),
            shutdown,
        )
        .await
        .unwrap();

        assert_eq!(event.rollback_to, 8);
        assert_eq!(event.depth, 2);

        // Chain should be rolled back
        let tip = store.tip().unwrap();
        assert_eq!(tip.block_number, 8);

        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_validator_reorg_monitor_shutdown() {
        let anchor = make_initial_tip(1);
        let store = Arc::new(MockChainStore::with_anchor(anchor));

        // Remote matches local — no reorg
        let mut remote = HashMap::new();
        remote.insert(1, B256::from([1u8; 32]));

        let (handle, url) = start_mock_rpc(remote).await;
        let client = Arc::new(stateless_core::RpcClient::new(&url, &url).unwrap());

        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let result = validator_reorg_monitor(
            client,
            store as Arc<dyn ChainStore>,
            Duration::from_millis(10),
            shutdown,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Shutdown"));
        handle.stop().unwrap();
    }
}
