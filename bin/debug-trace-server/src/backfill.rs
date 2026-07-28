//! Resumable, self-verifying canonical-index backfill.
//!
//! Extends the permanent CANONICAL_CHAIN index downward from the history floor toward
//! genesis, so number -> hash resolution for historical by-number trace requests is
//! answered from the local database instead of hitting upstream per request.
//!
//! # Design
//! - **Resume cursor**: the persisted history floor. Every applied batch atomically writes its rows
//!   and moves the floor in one transaction ([`ServerDB::backfill_canonical`]), so a restart
//!   resumes exactly where the last durable batch ended.
//! - **Self-verifying**: headers are fetched with `verify_hash = true` (the RPC client recomputes
//!   `hash_slow()` and rejects mismatches), and every batch must chain hash -> parent_hash downward
//!   from the already-trusted floor. A provider cannot inject a wrong header without breaking that
//!   chain.
//! - **Island skip**: rows already present directly below the floor (history preserved across a
//!   stale reset) are walked over with an empty batch instead of refetched.
//! - **Durability batching**: batches commit at [`redb::Durability::None`], with an `Immediate`
//!   commit every [`BARRIER_EVERY`] batches and a barrier at every exit, so a crash loses at most
//!   one barrier window of refetchable work.
//! - **Network errors are never fatal**: a failed or unverifiable batch is dropped, backed off
//!   (doubling up to [`MAX_BACKOFF`]), and retried. Database errors are task-fatal.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag, Header};
use futures::{StreamExt, TryStreamExt};
use stateless_common::RpcClient;
use stateless_core::{ChainStore, db::BlockMeta};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    metrics::BackfillMetrics,
    server_db::{BackfillApply, ServerDB},
};

/// Immediate-durability cadence, in applied batches.
const BARRIER_EVERY: u64 = 16;

/// Retry-backoff cap.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Tuning for [`run_backfill`].
#[derive(Debug, Clone)]
pub struct BackfillConfig {
    /// Headers fetched and applied per batch.
    pub batch_size: u64,
    /// Concurrent in-flight header fetches within a batch (additionally bounded by the
    /// RPC client's shared data semaphore).
    pub max_concurrent_headers: usize,
    /// Optional pause between batches, to keep the backfill from crowding out
    /// request-serving fetches.
    pub throttle: Duration,
    /// Initial retry backoff after a failed batch (doubles up to [`MAX_BACKOFF`]).
    pub backoff: Duration,
    /// Deadline for one header fetch; failures back off and retry, so generous is fine.
    pub header_timeout: Duration,
}

impl Default for BackfillConfig {
    fn default() -> Self {
        Self {
            batch_size: 1024,
            max_concurrent_headers: 32,
            throttle: Duration::ZERO,
            backoff: Duration::from_secs(1),
            header_timeout: Duration::from_secs(30),
        }
    }
}

/// Runs the backfill until the floor reaches genesis or `shutdown` fires.
///
/// Safe to leave enabled across restarts: with the floor already at 0 there is nothing to
/// extend and the task exits after a durability barrier.
pub async fn run_backfill(
    db: Arc<ServerDB>,
    rpc_client: Arc<RpcClient>,
    config: BackfillConfig,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    let metrics = BackfillMetrics::create();

    let Some(mut floor) = db.ensure_history_floor()? else {
        info!("Backfill idle: no local chain to extend (no anchor yet)");
        return Ok(());
    };
    info!(
        floor = floor.block_number,
        batch_size = config.batch_size,
        "Canonical-index backfill starting"
    );
    metrics.set_floor(floor.block_number);

    // The hash the next descending step must produce: the parent hash of the current floor
    // block. Canonical rows don't store parent hashes, so it is fetched (hash-verified)
    // from the floor's own header.
    let Some(mut expected_hash) = seed_expected_hash(&rpc_client, &floor, &config, &shutdown).await
    else {
        return stop_at_shutdown(&db, floor.block_number);
    };

    let mut batches_applied: u64 = 0;
    let mut backoff = config.backoff;
    let mut warned_missing_withdrawals = false;

    while floor.block_number > 0 {
        if shutdown.is_cancelled() {
            return stop_at_shutdown(&db, floor.block_number);
        }

        // Island skip: history already present directly below the floor.
        match db.get_block_hash(floor.block_number - 1)? {
            Some(hash) if hash == expected_hash => {
                if let Some(bottom) = db.scan_contiguous_below(floor.block_number)? {
                    match db.backfill_canonical(
                        floor.block_number,
                        &[],
                        &bottom,
                        redb::Durability::None,
                    )? {
                        BackfillApply::Applied => {
                            info!(
                                from = floor.block_number,
                                to = bottom.block_number,
                                "Backfill skipped over an existing history island"
                            );
                            floor = bottom;
                            metrics.set_floor(floor.block_number);
                        }
                        BackfillApply::FloorMoved { current } => {
                            warn_floor_moved(floor.block_number, &current);
                            floor = current;
                            metrics.set_floor(floor.block_number);
                        }
                    }
                    let Some(hash) =
                        seed_expected_hash(&rpc_client, &floor, &config, &shutdown).await
                    else {
                        return stop_at_shutdown(&db, floor.block_number);
                    };
                    expected_hash = hash;
                    continue;
                }
            }
            Some(other) => {
                // A row that contradicts the verified chain (the chain has never reorged,
                // so this is a data anomaly, not an expected state): refetch over it — the
                // batch insert overwrites it with hash-verified data.
                warn!(
                    block_number = floor.block_number - 1,
                    stored = %other,
                    expected = %expected_hash,
                    "Row below the floor does not match the verified chain; refetching over it"
                );
            }
            None => {}
        }

        // Fetch the next descending batch [lo, hi], order-preserving, hash-verified.
        let hi = floor.block_number - 1;
        let lo = hi.saturating_sub(config.batch_size - 1);
        let batch = match fetch_batch(&rpc_client, lo, hi, &config).await {
            Ok(batch) => batch,
            Err(e) => {
                warn!(lo, hi, error = %e, "Backfill batch fetch failed; backing off");
                if sleep_or_shutdown(backoff, &shutdown).await {
                    return stop_at_shutdown(&db, floor.block_number);
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        if let Err(e) = verify_linkage(&batch, lo, expected_hash) {
            warn!(lo, hi, error = %e, "Backfill batch failed linkage verification; backing off");
            if sleep_or_shutdown(backoff, &shutdown).await {
                return stop_at_shutdown(&db, floor.block_number);
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
            continue;
        }
        backoff = config.backoff;

        let metas: Vec<BlockMeta> = batch
            .iter()
            .map(|h| {
                if h.withdrawals_root.is_none() && !warned_missing_withdrawals {
                    warned_missing_withdrawals = true;
                    warn!(
                        block_number = h.number,
                        "Header without withdrawals_root; storing the zero root"
                    );
                }
                BlockMeta {
                    block_number: h.number,
                    block_hash: h.hash,
                    post_state_root: h.state_root,
                    post_withdrawals_root: h.withdrawals_root.unwrap_or_default(),
                }
            })
            .collect();
        let parent_of_batch = batch[0].parent_hash;

        // Periodic Immediate commit; everything else rides Durability::None.
        let durability = if (batches_applied + 1).is_multiple_of(BARRIER_EVERY) {
            redb::Durability::Immediate
        } else {
            redb::Durability::None
        };
        match db.backfill_canonical(floor.block_number, &metas, &metas[0], durability)? {
            BackfillApply::Applied => {
                batches_applied += 1;
                metrics.record_batch(metas.len() as u64, metas[0].block_number);
                debug!(floor = metas[0].block_number, rows = metas.len(), "Backfill batch applied");
                expected_hash = parent_of_batch;
                floor = metas.into_iter().next().expect("non-empty batch");
            }
            BackfillApply::FloorMoved { current } => {
                warn_floor_moved(floor.block_number, &current);
                floor = current;
                metrics.set_floor(floor.block_number);
                let Some(hash) = seed_expected_hash(&rpc_client, &floor, &config, &shutdown).await
                else {
                    return stop_at_shutdown(&db, floor.block_number);
                };
                expected_hash = hash;
            }
        }

        if !config.throttle.is_zero() && sleep_or_shutdown(config.throttle, &shutdown).await {
            return stop_at_shutdown(&db, floor.block_number);
        }
    }

    // Terminated at genesis. `expected_hash` is now genesis's parent hash.
    if expected_hash != B256::ZERO {
        warn!(
            parent_hash = %expected_hash,
            "Genesis parent hash is not zero — unexpected chain shape (index kept)"
        );
    }
    db.durability_barrier()?;
    metrics.set_floor(0);
    info!("Canonical-index backfill complete: the full number -> hash history is local");
    Ok(())
}

/// Persists pending `Durability::None` progress and logs the stop. Every shutdown exit
/// funnels through here so progress made since the last barrier is never lost to a clean
/// stop.
fn stop_at_shutdown(db: &ServerDB, floor: u64) -> eyre::Result<()> {
    db.durability_barrier()?;
    info!(floor, "Backfill stopping at shutdown (progress persisted)");
    Ok(())
}

/// Sleeps for `duration`, returning `true` if shutdown fired during the sleep.
async fn sleep_or_shutdown(duration: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = shutdown.cancelled() => true,
    }
}

fn warn_floor_moved(expected: u64, current: &BlockMeta) {
    warn!(
        expected,
        current = current.block_number,
        "History floor moved underneath the backfill (stale reset); reseeding"
    );
}

/// Fetches the parent hash of `floor`'s block — by hash, `verify_hash = true` — retrying
/// with backoff. `None` means shutdown fired first.
async fn seed_expected_hash(
    rpc_client: &RpcClient,
    floor: &BlockMeta,
    config: &BackfillConfig,
    shutdown: &CancellationToken,
) -> Option<B256> {
    let mut backoff = config.backoff;
    loop {
        if shutdown.is_cancelled() {
            return None;
        }
        let deadline = Instant::now() + config.header_timeout;
        match rpc_client
            .get_header_with_deadline(BlockId::Hash(floor.block_hash.into()), true, Some(deadline))
            .await
        {
            Ok(header) => return Some(header.parent_hash),
            Err(e) => {
                warn!(
                    block_number = floor.block_number,
                    error = %e,
                    "Backfill floor-header fetch failed; backing off"
                );
                if sleep_or_shutdown(backoff, shutdown).await {
                    return None;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Fetches headers `lo..=hi` by number with `verify_hash = true`; `buffered` preserves
/// order, so `result[i]` is the header of `lo + i`.
async fn fetch_batch(
    rpc_client: &RpcClient,
    lo: u64,
    hi: u64,
    config: &BackfillConfig,
) -> eyre::Result<Vec<Header>> {
    futures::stream::iter(lo..=hi)
        .map(|n| async move {
            let deadline = Instant::now() + config.header_timeout;
            rpc_client
                .get_header_with_deadline(
                    BlockId::Number(BlockNumberOrTag::Number(n)),
                    true,
                    Some(deadline),
                )
                .await
                .map_err(|e| eyre::eyre!("header {n}: {e}"))
        })
        .buffered(config.max_concurrent_headers)
        .try_collect()
        .await
}

/// Verifies the batch covers exactly `lo..` ascending and chains hash -> parent_hash up to
/// `expected_hash` (the parent of the block directly above the batch). Combined with
/// `verify_hash = true` fetches, a passing batch is cryptographically bound to the trusted
/// floor.
fn verify_linkage(batch: &[Header], lo: u64, expected_hash: B256) -> eyre::Result<()> {
    let last = batch.last().ok_or_else(|| eyre::eyre!("empty batch"))?;
    eyre::ensure!(
        last.hash == expected_hash,
        "top of batch ({}) does not link to the floor: got {}, expected {expected_hash}",
        last.number,
        last.hash
    );
    for (i, header) in batch.iter().enumerate() {
        eyre::ensure!(
            header.number == lo + i as u64,
            "batch out of order at index {i}: got {}, expected {}",
            header.number,
            lo + i as u64
        );
    }
    for pair in batch.windows(2) {
        eyre::ensure!(
            pair[0].hash == pair[1].parent_hash,
            "hash chain broken between {} and {}",
            pair[0].number,
            pair[1].number
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    use jsonrpsee::{server::ServerHandle, types::ErrorObjectOwned};
    use stateless_common::{BackoffPolicy, RpcClientConfig};
    use stateless_core::DivergenceLookups;

    use super::*;
    use crate::{data_provider::test_support::serve, server_db::ServerDB};

    /// A `len`-block chain (numbers `0..len`) with real `hash_slow()` linkage, so the
    /// backfill's `verify_hash = true` fetches and parent-hash checks pass only for
    /// genuinely consistent data. Headers carry no withdrawals root — pinning the
    /// `unwrap_or_default()` path every run.
    fn make_chain(len: u64) -> Vec<Header> {
        let mut headers = Vec::with_capacity(len as usize);
        let mut parent = B256::ZERO;
        for number in 0..len {
            let inner =
                alloy_consensus::Header { number, parent_hash: parent, ..Default::default() };
            let hash = inner.hash_slow();
            parent = hash;
            headers.push(Header { hash, inner, ..Default::default() });
        }
        headers
    }

    fn meta_of(header: &Header) -> BlockMeta {
        BlockMeta {
            block_number: header.number,
            block_hash: header.hash,
            post_state_root: header.state_root,
            post_withdrawals_root: header.withdrawals_root.unwrap_or_default(),
        }
    }

    /// Mock chain endpoint state: headers indexed by number, a failure threshold (numbers
    /// below it error), a by-number fetch log, and a one-shot hook fired on the first
    /// by-number fetch (for racing a stale reset against the backfill).
    struct MockChain {
        headers: Vec<Header>,
        fail_below: AtomicU64,
        number_hits: Mutex<Vec<u64>>,
        on_first_number_fetch: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl MockChain {
        fn new(headers: Vec<Header>) -> Arc<Self> {
            Arc::new(Self {
                headers,
                fail_below: AtomicU64::new(0),
                number_hits: Mutex::new(Vec::new()),
                on_first_number_fetch: Mutex::new(None),
            })
        }
    }

    /// Serves `eth_getHeaderByNumber` + `eth_getHeaderByHash` from the mock chain.
    async fn start_chain_rpc(chain: Arc<MockChain>) -> (ServerHandle, String) {
        serve(chain, |m| {
            m.register_method("eth_getHeaderByNumber", |params, ctx, _| {
                let (hex,): (String,) = params.parse().unwrap();
                let n = u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(&hex), 16).unwrap();
                if let Some(hook) = ctx.on_first_number_fetch.lock().unwrap().take() {
                    hook();
                }
                ctx.number_hits.lock().unwrap().push(n);
                if n < ctx.fail_below.load(Ordering::Relaxed) {
                    return Err(ErrorObjectOwned::owned::<()>(-32000, "synthetic failure", None));
                }
                ctx.headers.get(n as usize).cloned().ok_or_else(|| {
                    ErrorObjectOwned::owned::<()>(-32000, "unknown block number", None)
                })
            })
            .unwrap();
            m.register_method("eth_getHeaderByHash", |params, ctx, _| {
                let (hash,): (B256,) = params.parse().unwrap();
                ctx.headers.iter().find(|h| h.hash == hash).cloned().ok_or_else(|| {
                    ErrorObjectOwned::owned::<()>(-32000, "unknown block hash", None)
                })
            })
            .unwrap();
        })
        .await
    }

    fn fast_client(url: &str) -> Arc<RpcClient> {
        let config = RpcClientConfig {
            rpc_retry: BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2)),
            per_attempt_timeout: Duration::from_millis(500),
            ..RpcClientConfig::trace_server()
        };
        Arc::new(RpcClient::new_with_config(&[url], &[url], config, None).unwrap())
    }

    fn fast_config(batch_size: u64) -> BackfillConfig {
        BackfillConfig {
            batch_size,
            max_concurrent_headers: 4,
            throttle: Duration::ZERO,
            backoff: Duration::from_millis(10),
            header_timeout: Duration::from_millis(300),
        }
    }

    fn temp_db() -> (tempfile::TempDir, Arc<ServerDB>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ServerDB::new(dir.path().join("server.redb")).unwrap());
        (dir, db)
    }

    /// Full run: from a tip anchor down to genesis, every number resolves to the mock
    /// chain's hash, and a second run over the completed index is an immediate no-op.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backfill_runs_to_genesis() {
        let headers = make_chain(30);
        let chain = MockChain::new(headers.clone());
        let (handle, url) = start_chain_rpc(Arc::clone(&chain)).await;
        let (_dir, db) = temp_db();
        ChainStore::advance_chain(&*db, &[meta_of(&headers[29])]).unwrap();

        let rpc = fast_client(&url);
        run_backfill(Arc::clone(&db), Arc::clone(&rpc), fast_config(7), CancellationToken::new())
            .await
            .unwrap();

        assert_eq!(DivergenceLookups::get_earliest(&*db).unwrap().unwrap().0, 0);
        for header in &headers {
            assert_eq!(
                ChainStore::get_block_hash(&*db, header.number).unwrap(),
                Some(header.hash),
                "block {}",
                header.number
            );
        }

        // Re-run over the completed index: nothing to extend, immediate clean exit.
        run_backfill(db, rpc, fast_config(7), CancellationToken::new()).await.unwrap();
        handle.stop().unwrap();
    }

    /// A failing provider stalls the backfill (bounded backoff, floor parked at the failure
    /// edge) without killing it; a clean shutdown persists progress, and a rerun against
    /// the healed provider resumes from the parked floor down to genesis.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backfill_stalls_on_failures_then_resumes() {
        let headers = make_chain(30);
        let chain = MockChain::new(headers.clone());
        chain.fail_below.store(15, Ordering::Relaxed);
        let (handle, url) = start_chain_rpc(Arc::clone(&chain)).await;
        let (_dir, db) = temp_db();
        ChainStore::advance_chain(&*db, &[meta_of(&headers[29])]).unwrap();

        let rpc = fast_client(&url);
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_backfill(
            Arc::clone(&db),
            Arc::clone(&rpc),
            fast_config(7),
            shutdown.clone(),
        ));

        // Descends 29 -> 22 -> 15 (batches of 7), then parks: every batch below needs
        // block 14, which the provider refuses.
        let mut parked = false;
        for _ in 0..200 {
            if DivergenceLookups::get_earliest(&*db).unwrap().unwrap().0 == 15 {
                parked = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(parked, "floor must park at the failure edge");
        assert!(!task.is_finished(), "a failing provider must not kill the task");

        shutdown.cancel();
        task.await.unwrap().unwrap();

        // Provider healed: a rerun resumes from 15 and completes.
        chain.fail_below.store(0, Ordering::Relaxed);
        run_backfill(Arc::clone(&db), rpc, fast_config(7), CancellationToken::new()).await.unwrap();
        assert_eq!(DivergenceLookups::get_earliest(&*db).unwrap().unwrap().0, 0);
        assert_eq!(ChainStore::get_block_hash(&*db, 3).unwrap(), Some(headers[3].hash));
        handle.stop().unwrap();
    }

    /// History islands below the floor (rows preserved across a stale reset) are walked
    /// over without refetching their headers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backfill_skips_islands_without_refetching() {
        let headers = make_chain(30);
        let chain = MockChain::new(headers.clone());
        let (handle, url) = start_chain_rpc(Arc::clone(&chain)).await;
        let (_dir, db) = temp_db();

        // Island 10..=18 from a previous life, then a preserving reset stranded it below
        // the new anchor at 29.
        let island: Vec<BlockMeta> = (10..=18).map(|n| meta_of(&headers[n])).collect();
        ChainStore::advance_chain(&*db, &island).unwrap();
        ChainStore::reset_to_anchor(&*db, &meta_of(&headers[29])).unwrap();

        // Batches of 5 land the floor exactly on the island top: 29 -> 24 -> 19 -> skip
        // -> 10 -> 5 -> 0.
        run_backfill(Arc::clone(&db), fast_client(&url), fast_config(5), CancellationToken::new())
            .await
            .unwrap();

        assert_eq!(DivergenceLookups::get_earliest(&*db).unwrap().unwrap().0, 0);
        for header in &headers {
            assert_eq!(
                ChainStore::get_block_hash(&*db, header.number).unwrap(),
                Some(header.hash),
                "block {}",
                header.number
            );
        }
        let hits = chain.number_hits.lock().unwrap();
        assert!(
            hits.iter().all(|n| !(10..=18).contains(n)),
            "island headers must not be refetched; by-number fetches: {hits:?}"
        );
        handle.stop().unwrap();
    }

    /// A stale reset racing the backfill moves the floor mid-batch: the CAS rejects the
    /// stale batch (FloorMoved), the task reseeds from the new floor, and still completes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backfill_reseeds_after_stale_reset() {
        let headers = make_chain(30);
        let chain = MockChain::new(headers.clone());
        let (_dir, db) = temp_db();
        ChainStore::advance_chain(&*db, &[meta_of(&headers[29])]).unwrap();

        // On the first by-number fetch — while the first batch (22..=28) is in flight —
        // a stale reset moves the anchor/floor to 25 and drops the rows above it.
        let reset_target = meta_of(&headers[25]);
        {
            let db = Arc::clone(&db);
            *chain.on_first_number_fetch.lock().unwrap() = Some(Box::new(move || {
                ChainStore::reset_to_anchor(&*db, &reset_target).unwrap();
            }));
        }
        let (handle, url) = start_chain_rpc(Arc::clone(&chain)).await;

        run_backfill(Arc::clone(&db), fast_client(&url), fast_config(7), CancellationToken::new())
            .await
            .unwrap();

        assert_eq!(DivergenceLookups::get_earliest(&*db).unwrap().unwrap().0, 0);
        for n in 0..=25u64 {
            assert_eq!(
                ChainStore::get_block_hash(&*db, n).unwrap(),
                Some(headers[n as usize].hash),
                "block {n}"
            );
        }
        // The dropped stale batch (26..=28 above the new anchor) must not have landed.
        for n in 26..=28u64 {
            assert_eq!(ChainStore::get_block_hash(&*db, n).unwrap(), None, "block {n}");
        }
        handle.stop().unwrap();
    }

    /// Linkage verification: a provider serving a self-consistent but wrong-parent header
    /// (hash_slow passes, chain does not) cannot get its batch applied.
    #[test]
    fn verify_linkage_rejects_broken_chains() {
        let headers = make_chain(5);

        // Correct batch 1..=3 under expected parent-of-4.
        assert!(verify_linkage(&headers[1..4], 1, headers[4].parent_hash).is_ok());
        // Wrong anchor hash.
        assert!(verify_linkage(&headers[1..4], 1, B256::ZERO).is_err());
        // Gap: [1, 3] misses 2.
        let gapped = [headers[1].clone(), headers[3].clone()];
        assert!(verify_linkage(&gapped, 1, headers[4].parent_hash).is_err());
        // A tampered header breaks the parent link even though its own fields are valid.
        let mut forged = headers[1..4].to_vec();
        forged[1] = {
            let inner = alloy_consensus::Header {
                number: 2,
                parent_hash: B256::from([0xAA; 32]),
                ..Default::default()
            };
            Header { hash: inner.hash_slow(), inner, ..Default::default() }
        };
        assert!(verify_linkage(&forged, 1, headers[4].parent_hash).is_err());
        // Empty batch.
        assert!(verify_linkage(&[], 1, B256::ZERO).is_err());
    }
}
