use std::{sync::Arc, time::Duration};

use alloy_primitives::{B256, BlockHash, BlockNumber, map::HashMap};
use eyre::{Result, anyhow};
use revm::state::Bytecode;
use tokio_util::sync::CancellationToken;

use super::{
    BlockFetcher, BlockProcessor, DivergenceError, ErrorAction, PipelineConfig, PipelineHooks,
    PipelineOutcome, ProcessedBlock, advancer::chain_advancer, block_fetcher,
    find_divergence_point, run_pipeline, worker::spawn_workers,
};
use crate::{ChainStore, StoreResult, db::BlockMeta};

#[test]
fn test_pipeline_config_default_uses_cpu_count() {
    let config = PipelineConfig::default();
    let cpus = num_cpus::get_physical();
    assert_eq!(config.concurrent_workers, cpus);
    assert_eq!(config.channel_capacity(), 2 * cpus);
    assert_eq!(config.fetcher_max_in_flight(), 2 * cpus);
}

#[test]
fn test_pipeline_config_default_stale_disabled() {
    assert!(PipelineConfig::default().stale_reset_threshold.is_none());
}

#[test]
fn test_pipeline_config_default_tip_buffer_disabled() {
    // Default is 0 (disabled). Binaries that race the upstream witness generator opt into a
    // nonzero buffer at construction time.
    assert_eq!(PipelineConfig::default().tip_buffer, 0);
}

// Mock types for tests
#[derive(Clone, Debug)]
struct MockBlock {
    number: u64,
    hash: BlockHash,
    parent: BlockHash,
    state_root: B256,
}

impl ProcessedBlock for MockBlock {
    fn block_number(&self) -> BlockNumber {
        self.number
    }
    fn block_hash(&self) -> BlockHash {
        self.hash
    }
    fn parent_hash(&self) -> BlockHash {
        self.parent
    }
    fn to_block_meta(&self) -> BlockMeta {
        BlockMeta {
            block_number: self.number,
            block_hash: self.hash,
            post_state_root: self.state_root,
            post_withdrawals_root: B256::ZERO,
        }
    }
}

struct NoopHooks;
impl PipelineHooks for NoopHooks {
    type Output = MockBlock;
}

struct MockStore {
    chain: std::sync::Mutex<std::collections::BTreeMap<u64, BlockMeta>>,
    anchor: BlockMeta,
}

impl MockStore {
    fn new(anchor: BlockMeta) -> Self {
        let mut chain = std::collections::BTreeMap::new();
        chain.insert(anchor.block_number, anchor.clone());
        Self { chain: std::sync::Mutex::new(chain), anchor }
    }
}

impl crate::ContractStore for MockStore {
    fn get_contracts(&self, _: &[B256]) -> StoreResult<(HashMap<B256, Arc<Bytecode>>, Vec<B256>)> {
        Ok((HashMap::default(), vec![]))
    }
    fn add_contracts(&self, _: &[(B256, Arc<Bytecode>)]) -> StoreResult<()> {
        Ok(())
    }
}

impl ChainStore for MockStore {
    fn get_canonical_tip(&self) -> StoreResult<Option<BlockMeta>> {
        Ok(self.chain.lock().unwrap().values().next_back().cloned())
    }
    fn get_anchor(&self) -> StoreResult<Option<BlockMeta>> {
        Ok(Some(self.anchor.clone()))
    }
    fn advance_chain(&self, blocks: &[BlockMeta]) -> StoreResult<()> {
        let mut chain = self.chain.lock().unwrap();
        for b in blocks {
            chain.insert(b.block_number, b.clone());
        }
        Ok(())
    }
    fn get_block_hash(&self, n: BlockNumber) -> StoreResult<Option<BlockHash>> {
        Ok(self.chain.lock().unwrap().get(&n).map(|m| m.block_hash))
    }
    fn get_earliest_block(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
        Ok(self.chain.lock().unwrap().first_key_value().map(|(&n, m)| (n, m.block_hash)))
    }
    fn rollback_chain(&self, to_block: BlockNumber) -> StoreResult<()> {
        self.chain.lock().unwrap().retain(|&n, _| n <= to_block);
        Ok(())
    }
    fn reset_to_anchor(&self, anchor: &BlockMeta) -> StoreResult<()> {
        let mut chain = self.chain.lock().unwrap();
        chain.clear();
        chain.insert(anchor.block_number, anchor.clone());
        Ok(())
    }
}

/// Mock fetcher that only provides block hashes (for advancer/divergence tests).
struct MockFetcher {
    hashes: HashMap<u64, BlockHash>,
}

impl BlockFetcher for MockFetcher {
    type Output = ();

    async fn fetch(&self, _: u64) -> Result<()> {
        unimplemented!("not used in advancer/divergence tests")
    }
    async fn latest_block_number(&self) -> Result<u64> {
        Ok(*self.hashes.keys().max().unwrap_or(&0))
    }
    async fn block_hash(&self, n: u64) -> Result<BlockHash> {
        self.hashes.get(&n).copied().ok_or_else(|| anyhow!("Block {n} not found"))
    }
    async fn latest_block_meta(&self) -> Result<BlockMeta> {
        unimplemented!("not used in advancer/divergence tests")
    }
}

fn make_hash(n: u64) -> BlockHash {
    BlockHash::from([n as u8; 32])
}

fn make_block(number: u64, parent: BlockHash) -> MockBlock {
    MockBlock {
        number,
        hash: make_hash(number),
        parent,
        state_root: B256::from([number as u8 + 1; 32]),
    }
}

fn make_tip(n: u64) -> BlockMeta {
    BlockMeta {
        block_number: n,
        block_hash: make_hash(n),
        post_state_root: B256::from([n as u8 + 1; 32]),
        post_withdrawals_root: B256::ZERO,
    }
}

// chain_advancer tests

/// Test-only input to `run_advancer`: either a `MockBlock` or a synthetic failure whose
/// message is stringified. `run_advancer` lifts the latter to the typed `Arc<dyn Error>`
/// that workers emit in production.
type AdvancerStep = std::result::Result<MockBlock, (String, ErrorAction)>;

async fn run_advancer(
    tip: BlockMeta,
    rpc_hashes: HashMap<u64, BlockHash>,
    blocks: Vec<AdvancerStep>,
) -> (Result<PipelineOutcome>, MockStore) {
    let store = MockStore::new(tip.clone());
    let fetcher = MockFetcher { hashes: rpc_hashes };
    let hooks = NoopHooks;
    let (tx, rx) = kanal::bounded(16);

    {
        let tx_async = tx.to_async();
        for b in blocks {
            // Workers erase per-processor error types to `Arc<dyn Error + Send + Sync>` —
            // tests wrap their synthetic message into `TestError` to match that shape.
            let msg: std::result::Result<
                MockBlock,
                (Arc<dyn std::error::Error + Send + Sync>, ErrorAction),
            > = match b {
                Ok(v) => Ok(v),
                Err((msg, action)) => Err((
                    Arc::new(TestError(msg)) as Arc<dyn std::error::Error + Send + Sync>,
                    action,
                )),
            };
            tx_async.send(msg).await.unwrap();
        }
    }

    let result = chain_advancer(&fetcher, &store, &hooks, rx, tip, CancellationToken::new()).await;
    (result, store)
}

#[tokio::test]
async fn test_chain_advancer_sequential() {
    let tip = make_tip(10);
    let blocks = vec![
        Ok(make_block(11, make_hash(10))),
        Ok(make_block(12, make_hash(11))),
        Ok(make_block(13, make_hash(12))),
    ];
    let (result, store) = run_advancer(tip, HashMap::default(), blocks).await;
    assert!(matches!(result.unwrap(), PipelineOutcome::Shutdown));
    assert_eq!(store.get_canonical_tip().unwrap().unwrap().block_number, 13);
}

#[tokio::test]
async fn test_chain_advancer_out_of_order() {
    let tip = make_tip(10);
    let blocks = vec![
        Ok(make_block(13, make_hash(12))),
        Ok(make_block(12, make_hash(11))),
        Ok(make_block(11, make_hash(10))),
    ];
    let (result, store) = run_advancer(tip, HashMap::default(), blocks).await;
    assert!(matches!(result.unwrap(), PipelineOutcome::Shutdown));
    assert_eq!(store.get_canonical_tip().unwrap().unwrap().block_number, 13);
}

/// `MockBlock` that fails `verify_continuity`. Used only by the companion test below —
/// `MockBlock`'s default `verify_continuity` returns `Ok`, so it can't exercise the
/// `advancer.rs:109` branch that treats a continuity failure as Fatal.
#[derive(Clone, Debug)]
struct BadBlock(MockBlock);
impl ProcessedBlock for BadBlock {
    fn block_number(&self) -> BlockNumber {
        self.0.block_number()
    }
    fn block_hash(&self) -> BlockHash {
        self.0.block_hash()
    }
    fn parent_hash(&self) -> BlockHash {
        self.0.parent_hash()
    }
    fn to_block_meta(&self) -> BlockMeta {
        self.0.to_block_meta()
    }
    fn verify_continuity(&self, _previous_tip: &BlockMeta) -> Result<()> {
        Err(eyre::eyre!("state root mismatch"))
    }
}

/// `NoopHooks` is locked to `Output = MockBlock`; the verify_continuity test needs
/// `Output = BadBlock`.
struct BadBlockHooks;
impl PipelineHooks for BadBlockHooks {
    type Output = BadBlock;
}

/// Run `chain_advancer` against a stream of `BadBlock` inputs. Modelled on `run_advancer`
/// but specialized — generalizing the original would cascade through ~6 helper types for
/// a single test case.
async fn run_bad_block_advancer(tip: BlockMeta, blocks: Vec<BadBlock>) -> Result<PipelineOutcome> {
    let store = MockStore::new(tip.clone());
    let fetcher = MockFetcher { hashes: HashMap::default() };
    let hooks = BadBlockHooks;
    let (tx, rx) = kanal::bounded::<
        std::result::Result<BadBlock, (Arc<dyn std::error::Error + Send + Sync>, ErrorAction)>,
    >(16);

    {
        let tx_async = tx.to_async();
        for b in blocks {
            tx_async.send(Ok(b)).await.unwrap();
        }
    }

    chain_advancer(&fetcher, &store, &hooks, rx, tip, CancellationToken::new()).await
}

/// Covers the `verify_continuity` → Fatal branch in `chain_advancer` (`advancer.rs:109`).
/// The existing `test_chain_advancer_fatal_error_halts` exercises the worker-error Fatal
/// branch instead — they're separate paths.
#[tokio::test]
async fn test_chain_advancer_verify_continuity_failure_halts() {
    let tip = make_tip(10);
    let blocks = vec![BadBlock(make_block(11, make_hash(10)))];
    let result = run_bad_block_advancer(tip, blocks).await;
    match result.unwrap() {
        PipelineOutcome::Fatal(msg) => {
            assert!(
                msg.contains("state root mismatch"),
                "Fatal message must carry the verify_continuity error: {msg}"
            );
        }
        other => panic!("expected Fatal, got {other:?}"),
    }
}

#[tokio::test]
async fn test_chain_advancer_fatal_error_halts() {
    let tip = make_tip(10);
    let blocks = vec![Err(("state root mismatch".to_string(), ErrorAction::Halt))];
    let (result, _) = run_advancer(tip, HashMap::default(), blocks).await;
    match result.unwrap() {
        PipelineOutcome::Fatal(msg) => assert!(msg.contains("state root mismatch")),
        other => panic!("Expected Fatal, got {other:?}"),
    }
}

#[tokio::test]
async fn test_chain_advancer_transient_error_returns_retry_outcome() {
    let tip = make_tip(10);
    let blocks = vec![Err(("RPC timeout".to_string(), ErrorAction::Retry))];
    let (result, _) = run_advancer(tip, HashMap::default(), blocks).await;
    // Retry errors are surfaced as `PipelineOutcome::Retry`, not `Err`. The outer
    // `run_pipeline` loop matches on the variant explicitly and runs the common
    // transient-restart recovery path.
    match result.unwrap() {
        PipelineOutcome::Retry(msg) => {
            assert!(
                msg.contains("RPC timeout"),
                "retry reason must carry the worker message: {msg}"
            );
        }
        other => panic!("expected Retry outcome, got {other:?}"),
    }
}

#[tokio::test]
async fn test_chain_advancer_shutdown() {
    let tip = make_tip(10);
    let store = MockStore::new(tip.clone());
    let fetcher = MockFetcher { hashes: HashMap::default() };
    let hooks = NoopHooks;
    let (_tx, rx) = kanal::bounded::<
        std::result::Result<MockBlock, (Arc<dyn std::error::Error + Send + Sync>, ErrorAction)>,
    >(16);
    let shutdown = CancellationToken::new();
    shutdown.cancel();

    let outcome = chain_advancer(&fetcher, &store, &hooks, rx, tip, shutdown).await.unwrap();
    assert!(matches!(outcome, PipelineOutcome::Shutdown));
}

#[tokio::test]
async fn test_chain_advancer_reorg_detected() {
    let tip = make_tip(10);
    let mut rpc_hashes = HashMap::default();
    rpc_hashes.insert(10, make_hash(10));

    let bad_block = MockBlock {
        number: 11,
        hash: make_hash(11),
        parent: BlockHash::from([0xFF; 32]),
        state_root: B256::ZERO,
    };
    let (result, _) = run_advancer(tip, rpc_hashes, vec![Ok(bad_block)]).await;
    match result.unwrap() {
        PipelineOutcome::Reorg(event) => assert_eq!(event.rollback_to, 10),
        other => panic!("Expected Reorg, got {other:?}"),
    }
}

/// Reorg detected mid-batch: block 11 threads through, block 12 has a bad parent. Before the
/// fix, the advancer called `find_divergence_point` with the *in-memory* tip (11), which
/// drove the binary search into `get_hash(11)` — returning `None` because 11 was never
/// persisted — and raised `DivergenceError::LocalChainCorrupt`, masking a legitimate reorg
/// as a fatal error. With the fix, divergence search uses the persisted tip (10), and the
/// reported `depth` / `reverted_hashes` agree.
#[tokio::test]
async fn test_chain_advancer_reorg_mid_batch_uses_persisted_tip() {
    let tip = make_tip(10);
    let mut rpc_hashes = HashMap::default();
    rpc_hashes.insert(10, make_hash(10));

    // Send block 12 before block 11 so they sit in the buffer together: the first recv only
    // buffers 12 (no advance, since `next_expected=11`), the second recv brings in 11, and the
    // inner while-let drains both in one pass — 11 passes parent-hash (`current_tip` advances
    // in memory to 11), then 12 fails parent-hash → reorg detected with the store still at 10.
    let block_11 = make_block(11, make_hash(10));
    let block_12 = MockBlock {
        number: 12,
        hash: make_hash(12),
        parent: BlockHash::from([0xFF; 32]), // wrong parent → reorg
        state_root: B256::ZERO,
    };
    let (result, _) = run_advancer(tip, rpc_hashes, vec![Ok(block_12), Ok(block_11)]).await;

    match result.unwrap() {
        PipelineOutcome::Reorg(event) => {
            assert_eq!(event.rollback_to, 10, "divergence resolves to the persisted tip");
            assert_eq!(
                event.depth, 0,
                "depth must be computed against persisted tip (10), not in-memory (11)"
            );
            assert!(
                event.reverted_hashes.is_empty(),
                "no hashes in (rollback_to..=persisted_tip] to revert"
            );
        }
        other => panic!("Expected Reorg, got {other:?}"),
    }
}

// find_divergence_point tests

/// Minimal `DivergenceLookups` impl backed by a HashMap of block-number → hash for
/// the `find_divergence_point` tests. Replaces the earlier pair of closures.
struct MapLookups {
    hashes: HashMap<u64, BlockHash>,
    earliest: u64,
}

impl crate::pipeline::DivergenceLookups for MapLookups {
    fn get_hash(&self, n: BlockNumber) -> StoreResult<Option<BlockHash>> {
        Ok(self.hashes.get(&n).copied())
    }
    fn get_earliest(&self) -> StoreResult<Option<(BlockNumber, BlockHash)>> {
        Ok(self.hashes.get(&self.earliest).map(|&h| (self.earliest, h)))
    }
}

#[tokio::test]
async fn test_find_divergence_single_block_reorg() {
    let mut local = HashMap::default();
    let mut remote = HashMap::default();
    for n in 1..=10 {
        local.insert(n, make_hash(n));
        if n <= 9 {
            remote.insert(n, make_hash(n));
        } else {
            remote.insert(n, BlockHash::from([0xFF; 32]));
        }
    }

    let fetcher = MockFetcher { hashes: remote };
    let lookups = MapLookups { hashes: local, earliest: 1 };
    let result = find_divergence_point(&fetcher, &lookups, 10).await.unwrap();

    assert_eq!(result, 9);
}

#[tokio::test]
async fn test_find_divergence_multi_block_reorg() {
    let mut local = HashMap::default();
    let mut remote = HashMap::default();
    for n in 1..=10 {
        if n <= 5 {
            let hash = make_hash(n);
            local.insert(n, hash);
            remote.insert(n, hash);
        } else {
            local.insert(n, make_hash(n));
            remote.insert(n, BlockHash::from([(n + 128) as u8; 32]));
        }
    }

    let fetcher = MockFetcher { hashes: remote };
    let lookups = MapLookups { hashes: local, earliest: 1 };
    let result = find_divergence_point(&fetcher, &lookups, 10).await.unwrap();

    assert_eq!(result, 5);
}

#[tokio::test]
async fn test_find_divergence_catastrophic() {
    let mut local = HashMap::default();
    let mut remote = HashMap::default();
    for n in 1..=5 {
        local.insert(n, make_hash(n));
        remote.insert(n, BlockHash::from([(n + 128) as u8; 32]));
    }

    let fetcher = MockFetcher { hashes: remote };
    let lookups = MapLookups { hashes: local, earliest: 1 };
    let result = find_divergence_point(&fetcher, &lookups, 5).await;

    assert!(matches!(result, Err(DivergenceError::CatastrophicReorg { .. })));
}

// spawn_workers tests

/// Minimal `std::error::Error` for the mock processors — `BlockProcessor::Error` now
/// requires `Error + Send + Sync`, and bare `String` doesn't satisfy that. Single
/// `#[error("{0}")]` constructor keeps the tests readable.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct TestError(String);

struct DoubleProcessor;
impl BlockProcessor for DoubleProcessor {
    type Input = u64;
    type Output = MockBlock;
    type Error = TestError;

    async fn process(&self, input: u64) -> std::result::Result<MockBlock, TestError> {
        Ok(MockBlock {
            number: input,
            hash: make_hash(input),
            parent: make_hash(input - 1),
            state_root: B256::ZERO,
        })
    }
}

#[tokio::test]
async fn test_spawn_workers_processes_all() {
    let processor = Arc::new(DoubleProcessor);
    let (fetch_tx, fetch_rx) = kanal::bounded::<u64>(16);
    let (result_tx, result_rx) = kanal::bounded(16);

    let handles = spawn_workers(processor, fetch_rx, result_tx, 2);

    let fetch_tx = fetch_tx.to_async();
    for i in 1..=5 {
        fetch_tx.send(i).await.unwrap();
    }
    drop(fetch_tx);

    let result_rx = result_rx.to_async();
    let mut results = Vec::new();
    while let Ok(r) = result_rx.recv().await {
        results.push(r.unwrap().number);
    }

    results.sort();
    assert_eq!(results, vec![1, 2, 3, 4, 5]);

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_spawn_workers_propagates_error() {
    struct FailProcessor;
    impl BlockProcessor for FailProcessor {
        type Input = u64;
        type Output = MockBlock;
        type Error = TestError;

        async fn process(&self, _: u64) -> std::result::Result<MockBlock, TestError> {
            Err(TestError("boom".to_string()))
        }
    }

    let processor = Arc::new(FailProcessor);
    let (fetch_tx, fetch_rx) = kanal::bounded::<u64>(16);
    let (result_tx, result_rx) = kanal::bounded(16);

    let _handles = spawn_workers(processor, fetch_rx, result_tx, 1);

    let fetch_tx = fetch_tx.to_async();
    fetch_tx.send(1).await.unwrap();
    drop(fetch_tx);

    let result_rx = result_rx.to_async();
    let result = result_rx.recv().await.unwrap();
    assert!(result.is_err());
    let (err, action) = result.unwrap_err();
    // Display round-trips the original message via `TestError`'s `#[error("{0}")]`.
    assert_eq!(err.to_string(), "boom");
    // Default error_action is Halt
    assert_eq!(action, ErrorAction::Halt);
}

/// Streaming regression: with the previous `join_all` batching all 4 blocks in a batch
/// completed together, so a slow block held everyone back. With `JoinSet` streaming, the
/// 3 fast blocks must be sent downstream before the slow one.
///
/// Uses an explicit oneshot gate (not a sleep) to hold the slow block until the test has
/// observed the 3 fast blocks — the ordering invariant is independent of wall-clock timing.
#[tokio::test]
async fn test_block_fetcher_streams_out_of_order() {
    use tokio::sync::{Mutex, oneshot};

    /// Holds `slow_block` on a oneshot gate; all other blocks return immediately.
    struct SlowFetcher {
        latest: u64,
        slow_block: u64,
        gate: Mutex<Option<oneshot::Receiver<()>>>,
    }

    impl BlockFetcher for SlowFetcher {
        type Output = u64;
        async fn fetch(&self, bn: u64) -> eyre::Result<u64> {
            if bn == self.slow_block &&
                let Some(rx) = self.gate.lock().await.take()
            {
                let _ = rx.await;
            }
            Ok(bn)
        }
        async fn latest_block_number(&self) -> eyre::Result<u64> {
            Ok(self.latest)
        }
        async fn block_hash(&self, _: u64) -> eyre::Result<BlockHash> {
            unreachable!()
        }
        async fn latest_block_meta(&self) -> eyre::Result<BlockMeta> {
            unreachable!()
        }
    }

    let (start, slow) = (100u64, 102u64);
    let (gate_tx, gate_rx) = oneshot::channel::<()>();
    let fetcher = Arc::new(SlowFetcher {
        latest: start + 3,
        slow_block: slow,
        gate: Mutex::new(Some(gate_rx)),
    });
    let (tx, rx) = kanal::bounded::<u64>(8);
    let config = Arc::new(PipelineConfig {
        concurrent_workers: 2, // → fetcher_max_in_flight() = 4, window holds all 4 blocks
        sync_target: Some(start + 3), // fetcher exits cleanly after block 103
        poll_interval: Duration::from_millis(10),
        ..PipelineConfig::default()
    });
    let handle = tokio::spawn(block_fetcher(fetcher, tx, start, config, CancellationToken::new()));

    // Slow block is gated — the first 3 results must be the fast blocks, regardless of
    // scheduling or CI load.
    let rx = rx.to_async();
    let recv_with_timeout =
        async || tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
    let mut first_three =
        [recv_with_timeout().await, recv_with_timeout().await, recv_with_timeout().await];
    first_three.sort();
    assert_eq!(first_three, [start, start + 1, start + 3], "streaming broken: {first_three:?}");

    // Release the slow block — the 4th (final) result must be it.
    gate_tx.send(()).unwrap();
    let last = recv_with_timeout().await;
    assert_eq!(last, slow);

    // Fetcher exits cleanly after sync_target.
    assert!(tokio::time::timeout(Duration::from_secs(5), handle).await.is_ok());
}

/// `tip_buffer` must keep the fetcher from spawning any fetch within that distance of the
/// remote tip, so the upstream witness generator has headroom.
#[tokio::test]
async fn test_block_fetcher_respects_tip_buffer() {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Records the highest block number ever passed to `fetch()`.
    struct TrackingFetcher(u64, Arc<AtomicU64>);
    impl BlockFetcher for TrackingFetcher {
        type Output = u64;
        async fn fetch(&self, bn: u64) -> eyre::Result<u64> {
            self.1.fetch_max(bn, Ordering::Relaxed);
            Ok(bn)
        }
        async fn latest_block_number(&self) -> eyre::Result<u64> {
            Ok(self.0)
        }
        async fn block_hash(&self, _: u64) -> eyre::Result<BlockHash> {
            unreachable!()
        }
        async fn latest_block_meta(&self) -> eyre::Result<BlockMeta> {
            unreachable!()
        }
    }

    let (start, latest, buffer) = (100u64, 110u64, 3u64);
    let highest = Arc::new(AtomicU64::new(0));

    let (tx, rx) = kanal::bounded::<u64>(64);
    let config = Arc::new(PipelineConfig {
        concurrent_workers: 2,
        poll_interval: Duration::from_millis(10),
        tip_buffer: buffer,
        ..PipelineConfig::default()
    });
    let shutdown = CancellationToken::new();

    // Drain so tx.send never blocks.
    let drain = tokio::spawn(async move {
        let rx = rx.to_async();
        while rx.recv().await.is_ok() {}
    });
    let fetcher_handle = tokio::spawn(block_fetcher(
        Arc::new(TrackingFetcher(latest, highest.clone())),
        tx,
        start,
        config,
        shutdown.clone(),
    ));

    // Poll until the ceiling is visibly pinned — two consecutive samples equal AND at the
    // expected ceiling. No wall-clock dependence on a fixed settle duration.
    let expected_ceiling = latest - buffer;
    let mut prev = 0u64;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let cur = highest.load(Ordering::Relaxed);
        if cur == prev && cur == expected_ceiling {
            break;
        }
        prev = cur;
    }
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), fetcher_handle).await;
    drain.abort();

    let h = highest.load(Ordering::Relaxed);
    assert_eq!(h, expected_ceiling, "fetcher respected tip_buffer={buffer} below tip={latest}");
}

/// Regression: a persistently-failing block must not let the fetch window grow
/// unboundedly while the chain advances. The spawn-window cap bounds the highest
/// block we ever attempt to `stuck + max_window - 1` (since `base_block` can reach
/// `stuck` itself via contiguous-sent drain below it).
#[tokio::test]
async fn test_block_fetcher_bounded_window_under_stall() {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Fails block `stuck`; records the highest `bn` ever requested.
    struct StallFetcher(u64, u64, Arc<AtomicU64>); // (latest, stuck, highest)

    impl BlockFetcher for StallFetcher {
        type Output = u64;
        async fn fetch(&self, bn: u64) -> eyre::Result<u64> {
            self.2.fetch_max(bn, Ordering::Relaxed);
            if bn == self.1 { Err(eyre::eyre!("stuck")) } else { Ok(bn) }
        }
        async fn latest_block_number(&self) -> eyre::Result<u64> {
            Ok(self.0)
        }
        async fn block_hash(&self, _: u64) -> eyre::Result<BlockHash> {
            unreachable!()
        }
        async fn latest_block_meta(&self) -> eyre::Result<BlockMeta> {
            unreachable!()
        }
    }

    let (start, stuck, latest) = (100u64, 105u64, 10_100u64);
    let workers = 2;
    let max_in_flight = 2 * workers; // matches PipelineConfig::fetcher_max_in_flight()
    let max_window = 4 * max_in_flight as u64; // matches FETCH_WINDOW_MULTIPLIER
    let highest = Arc::new(AtomicU64::new(0));

    let (tx, rx) = kanal::bounded::<u64>(1024);
    let config = Arc::new(PipelineConfig {
        concurrent_workers: workers,
        poll_interval: Duration::from_millis(10),
        ..PipelineConfig::default()
    });
    let shutdown = CancellationToken::new();

    // Drain so `tx.send` never blocks — isolate the window cap as the sole limiter.
    let drain = tokio::spawn(async move {
        let rx = rx.to_async();
        while rx.recv().await.is_ok() {}
    });
    let fetcher = tokio::spawn(block_fetcher(
        Arc::new(StallFetcher(latest, stuck, highest.clone())),
        tx,
        start,
        config,
        shutdown.clone(),
    ));

    // Poll until the spawn-window cap has visibly pinned `highest` (two consecutive samples
    // match AND the cap has been reached). Terminates as soon as the invariant is exercised,
    // regardless of scheduler speed — no wall-clock dependence on a fixed settle duration.
    let mut prev = 0u64;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let cur = highest.load(Ordering::Relaxed);
        if cur == prev && cur >= stuck {
            break;
        }
        prev = cur;
    }
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), fetcher).await;
    drain.abort();

    let h = highest.load(Ordering::Relaxed);
    let ceiling = stuck + max_window;
    assert!(h < ceiling, "attempted {h}, expected < {ceiling}; without cap would reach ~{latest}");
}

#[test]
fn processed_block_verify_continuity_default_ok() {
    let prev = make_tip(9);
    let block = make_block(10, make_hash(9));
    block.verify_continuity(&prev).unwrap();
}

#[test]
fn block_processor_defaults() {
    struct P;
    impl BlockProcessor for P {
        type Input = u64;
        type Output = MockBlock;
        type Error = TestError;

        async fn process(&self, _: u64) -> std::result::Result<MockBlock, TestError> {
            unreachable!()
        }
    }
    let p = P;
    assert_eq!(p.error_action(&TestError("any".to_string())), ErrorAction::Halt);
    p.on_task_done(0, true);
    p.on_task_done(1, false);
}

#[test]
fn pipeline_hooks_defaults_are_noop() {
    let hooks = NoopHooks;
    let tip = make_tip(10);
    hooks.pre_advance(&[]).unwrap();
    hooks.post_advance(&tip).unwrap();
    hooks.on_reorg(5, 2, &[make_hash(11), make_hash(12)]).unwrap();
    hooks.on_stale_reset(&tip).unwrap();
}

#[tokio::test]
async fn block_fetcher_arc_blanket_forwards_all_methods() {
    struct FullFetcher;
    impl BlockFetcher for FullFetcher {
        type Output = u64;
        async fn fetch(&self, bn: u64) -> Result<u64> {
            Ok(bn)
        }
        async fn latest_block_number(&self) -> Result<u64> {
            Ok(7)
        }
        async fn block_hash(&self, _: u64) -> Result<BlockHash> {
            Ok(make_hash(7))
        }
        async fn latest_block_meta(&self) -> Result<BlockMeta> {
            Ok(make_tip(7))
        }
    }
    let full: Arc<FullFetcher> = Arc::new(FullFetcher);
    assert_eq!(full.fetch(3).await.unwrap(), 3);
    assert_eq!(full.latest_block_number().await.unwrap(), 7);
    assert_eq!(full.block_hash(0).await.unwrap(), make_hash(7));
    assert_eq!(full.latest_block_meta().await.unwrap().block_number, 7);
}

/// Pass-through processor shared by the `run_pipeline_*` tests.
struct PassThrough;
impl BlockProcessor for PassThrough {
    type Input = MockBlock;
    type Output = MockBlock;
    type Error = TestError;
    async fn process(&self, b: MockBlock) -> std::result::Result<MockBlock, TestError> {
        Ok(b)
    }
}

#[tokio::test]
async fn run_pipeline_reaches_sync_target() {
    struct TargetFetcher {
        latest: u64,
    }
    impl BlockFetcher for TargetFetcher {
        type Output = MockBlock;
        async fn fetch(&self, bn: u64) -> Result<MockBlock> {
            Ok(make_block(bn, make_hash(bn - 1)))
        }
        async fn latest_block_number(&self) -> Result<u64> {
            Ok(self.latest)
        }
        async fn block_hash(&self, bn: u64) -> Result<BlockHash> {
            Ok(make_hash(bn))
        }
        async fn latest_block_meta(&self) -> Result<BlockMeta> {
            Ok(make_tip(self.latest))
        }
    }

    let store = Arc::new(MockStore::new(make_tip(10)));
    let config = Arc::new(PipelineConfig {
        concurrent_workers: 1,
        sync_target: Some(13),
        poll_interval: Duration::from_millis(10),
        ..PipelineConfig::default()
    });

    tokio::time::timeout(
        Duration::from_secs(10),
        run_pipeline(
            Arc::new(TargetFetcher { latest: 13 }),
            Arc::clone(&store),
            Arc::new(PassThrough),
            Arc::new(NoopHooks),
            config,
            CancellationToken::new(),
        ),
    )
    .await
    .expect("run_pipeline did not finish within timeout")
    .expect("run_pipeline returned error");

    assert_eq!(store.get_canonical_tip().unwrap().unwrap().block_number, 13);
}

#[tokio::test]
async fn run_pipeline_returns_on_pre_cancelled_shutdown() {
    struct NoopFetcher;
    impl BlockFetcher for NoopFetcher {
        type Output = MockBlock;
        async fn fetch(&self, _: u64) -> Result<MockBlock> {
            unreachable!("shutdown cancels before fetch")
        }
        async fn latest_block_number(&self) -> Result<u64> {
            Ok(0)
        }
        async fn block_hash(&self, _: u64) -> Result<BlockHash> {
            unreachable!()
        }
        async fn latest_block_meta(&self) -> Result<BlockMeta> {
            Ok(make_tip(0))
        }
    }

    let shutdown = CancellationToken::new();
    shutdown.cancel();

    tokio::time::timeout(
        Duration::from_secs(5),
        run_pipeline(
            Arc::new(NoopFetcher),
            Arc::new(MockStore::new(make_tip(0))),
            Arc::new(PassThrough),
            Arc::new(NoopHooks),
            Arc::new(PipelineConfig::default()),
            shutdown,
        ),
    )
    .await
    .expect("pre-cancelled shutdown did not return within timeout")
    .unwrap();
}
