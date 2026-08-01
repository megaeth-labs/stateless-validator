//! Pipeline + signal handling + optional validation reporter.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy_primitives::B256;
use eyre::Result;
use stateless_common::RpcClient;
use stateless_core::{
    BisectResolver, ChainStore, PipelineConfig, chain_spec::ChainSpec, pipeline::run_pipeline,
};
use stateless_db::ContractCache;
use tokio::{signal, task};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    chain_sync::{ValidatorFetcher, ValidatorHooks, ValidatorProcessor},
    r2_witness::R2WitnessClient,
    validator_db::ValidatorDB,
};

/// Attempts for the final shutdown report (first try + retries).
const FINAL_REPORT_ATTEMPTS: usize = 3;
/// Sleep between final-report attempts.
const FINAL_REPORT_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Starts the validator pipeline, optional reporter, and signal handlers.
///
/// Cleanly drains on SIGINT/SIGTERM and returns either the pipeline result or `Ok(())`
/// on signal. Exception: on a fixed-range run (`--end-block`), a final validation report
/// that cannot land (or a detected validation gap) fails the run — a slice has no later
/// restart to re-report, so exiting 0 would let an orchestrator record the slice as
/// complete while upstream never saw the tip.
pub async fn run_with_signals(
    client: Arc<RpcClient>,
    r2_witness: Option<Arc<R2WitnessClient>>,
    validator_db: Arc<ValidatorDB>,
    contract_cache: Arc<ContractCache>,
    chain_spec: Arc<ChainSpec>,
    report_validation: bool,
    pipeline_config: PipelineConfig,
) -> Result<()> {
    let config = Arc::new(pipeline_config);
    let is_slice_run = config.sync_target.is_some();
    info!(
        concurrent_workers = config.concurrent_workers,
        poll_interval = ?config.poll_interval,
        error_restart_delay = ?config.error_restart_delay,
        "Starting pipeline",
    );
    info!(enabled = report_validation, "Validation result reporting");

    let shutdown = CancellationToken::new();
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .map_err(|e| eyre::eyre!("Failed to register SIGTERM handler: {e}"))?;

    let fetcher = Arc::new(ValidatorFetcher { rpc_client: client.clone(), r2_witness });
    let processor =
        Arc::new(ValidatorProcessor { chain_spec, contract_cache, rpc_client: client.clone() });
    let hooks = Arc::new(ValidatorHooks);

    // Last tip accepted upstream, shared between the periodic reporter and the final flush so
    // the flush only covers the still-unreported tail instead of re-sending anchor→tip.
    let last_reported = Arc::new(AtomicU64::new(0));

    let reporter = if report_validation {
        Some(task::spawn(validation_reporter(
            Arc::clone(&client),
            Arc::clone(&validator_db),
            Duration::from_secs(1),
            shutdown.clone(),
            Arc::clone(&last_reported),
        )))
    } else {
        info!("Validation reporter disabled");
        None
    };

    // Snapshot the canonical tip before the pipeline runs so we can report
    // `first_validated = initial_tip + 1 .. final_tip` at shutdown.
    let initial_tip = validator_db.get_canonical_tip()?.map(|t| t.block_number);

    let mut pipeline_handle = tokio::spawn(run_pipeline(
        fetcher,
        Arc::clone(&validator_db),
        processor,
        hooks,
        config,
        shutdown.clone(),
        BisectResolver,
    ));

    // Signal wins → drain; pipeline wins → already done.
    let (mut result, needs_drain): (Result<()>, bool) = tokio::select! {
        res = &mut pipeline_handle => {
            let r = res.unwrap_or_else(|e| Err(eyre::eyre!("Pipeline task panicked: {e}")));
            (r, false)
        }
        _ = signal::ctrl_c() => {
            info!("SIGINT received, shutting down");
            (Ok(()), true)
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received, shutting down");
            (Ok(()), true)
        }
    };

    shutdown.cancel();

    // Let in-flight block validation and DB commits complete before the runtime drops.
    // Bound generously: a worker mid-validation on a heavy block can take >1s, the advancer
    // still has to commit to redb, and `await_handles` waits up to its own configured cap.
    let drain_timeout = Duration::from_secs(60);
    if needs_drain && tokio::time::timeout(drain_timeout, &mut pipeline_handle).await.is_err() {
        warn!(timeout = ?drain_timeout, "Pipeline did not drain within timeout");
    }

    if let Some(reporter) = reporter {
        let _ = tokio::time::timeout(Duration::from_secs(3), reporter).await;
    }

    // Final report of the validated tail, sent after the pipeline (and any drain) has stopped
    // and the periodic reporter was joined. The reporter exits the moment the pipeline does, so
    // blocks validated since its last accepted report would otherwise go unreported — and an
    // `--end-block` slice run has no later restart to re-report them, hence the bounded retries
    // (the periodic loop's next tick is its retry). The shared `last_reported` makes this a
    // no-op when the reporter already landed the tip; a reporter wedged past the 3s join above
    // cannot regress upstream either way: reports apply through a forward-only cursor.
    if report_validation {
        let mut flush_failure: Option<eyre::Report> = None;
        for attempt in 1..=FINAL_REPORT_ATTEMPTS {
            match report_range_once(&client, &validator_db, &last_reported).await {
                Ok(true) => break,
                Ok(false) if attempt < FINAL_REPORT_ATTEMPTS => {
                    warn!(attempt, "Final validation report failed, retrying");
                    tokio::time::sleep(FINAL_REPORT_RETRY_DELAY).await;
                }
                Ok(false) => {
                    error!(
                        attempts = FINAL_REPORT_ATTEMPTS,
                        "Final validation report failed; the validated tail may be unreported \
                         upstream"
                    );
                    flush_failure = Some(eyre::eyre!(
                        "final validation report failed after {FINAL_REPORT_ATTEMPTS} attempts; \
                         the validated tail may be unreported upstream"
                    ));
                }
                // A detected validation gap is deterministic — retrying cannot resolve it.
                Err(e) => {
                    error!(error = %e, "Final validation report failed with a non-retryable error");
                    flush_failure = Some(e);
                    break;
                }
            }
        }
        // A chain-following run re-reports anchor→tip on its next start, so an unreported tail
        // heals itself. An `--end-block` slice run has no later restart: fail the run so the
        // orchestrator cannot record the slice as complete. A pipeline error, if any, takes
        // precedence (the flush failure was already logged above).
        if let Some(e) = flush_failure &&
            is_slice_run
        {
            result = result.and(Err(e));
        }
    }

    // Canonical chain advances strictly +1 (advancer enforces parent-hash continuity and
    // rolls back on reorg), so the final tip bounds the validated range exactly.
    match (initial_tip, validator_db.get_canonical_tip()?.map(|t| t.block_number)) {
        (Some(before), Some(after)) if after > before => {
            info!(
                start = before + 1,
                end = after,
                count = after - before,
                "Validated blocks this session",
            );
        }
        _ => info!("No blocks validated this session"),
    }

    result
}

/// Reports validated blocks to the dedicated report endpoint.
///
/// Periodically reads the canonical tip from ValidatorDB and reports the
/// validated range to the upstream node. Exits as soon as `shutdown` fires;
/// `run_with_signals` flushes the final tail afterwards, seeded by the shared
/// `last_reported_block` so the flush skips what already landed here.
async fn validation_reporter(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    report_interval: Duration,
    shutdown: CancellationToken,
    last_reported_block: Arc<AtomicU64>,
) -> Result<()> {
    info!("Starting validation reporter");

    loop {
        tokio::select! {
            _ = tokio::time::sleep(report_interval) => {}
            _ = shutdown.cancelled() => {
                info!("Shutting down gracefully");
                return Ok(());
            }
        }

        report_range_once(&client, &validator_db, &last_reported_block).await?;
    }
}

/// One reporter round: read anchor + tip and report the validated range upstream if the tip
/// differs from `last_reported_block` (updated on an accepted report; a tip that regressed
/// after a reorg rollback is deliberately re-reported).
///
/// Returns `Ok(true)` when the round settled (report accepted, or nothing to report) and
/// `Ok(false)` when the attempt failed in a way a retry could resolve (logged here). The only
/// `Err` is a detected validation gap, which is fatal to the reporter.
async fn report_range_once(
    client: &RpcClient,
    validator_db: &ValidatorDB,
    last_reported_block: &AtomicU64,
) -> Result<bool> {
    let (anchor, tip) = match (validator_db.get_anchor(), validator_db.get_canonical_tip()) {
        (Ok(Some(a)), Ok(Some(t))) => (a, t),
        (Ok(None), _) | (_, Ok(None)) => return Ok(true),
        (Err(e), _) | (_, Err(e)) => {
            warn!(error = %e, "Failed to read anchor/tip, retrying");
            return Ok(false);
        }
    };

    // Relaxed suffices: this is a single monotonic hint, and both users are already ordered —
    // the reporter is the only writer while it runs, and the final flush reads it only after
    // joining the reporter task.
    if tip.block_number == last_reported_block.load(Ordering::Relaxed) {
        return Ok(true);
    }

    let result = client
        .set_validated_blocks(
            (anchor.block_number, B256::from(anchor.block_hash.0)),
            (tip.block_number, B256::from(tip.block_hash.0)),
        )
        .await;

    match result {
        Ok(response) if response.accepted => {
            debug!(
                anchor = anchor.block_number,
                anchor_hash = %anchor.block_hash,
                tip = tip.block_number,
                tip_hash = %tip.block_hash,
                "Reported blocks"
            );
            last_reported_block.store(tip.block_number, Ordering::Relaxed);
            Ok(true)
        }
        Ok(response) => {
            if response.last_validated_block.0 < anchor.block_number {
                return Err(eyre::eyre!(
                    "Validation gap detected: upstream at block {}, but local chain starts at {}",
                    response.last_validated_block.0,
                    anchor.block_number
                ));
            }
            error!(
                upstream_block = ?response.last_validated_block,
                "Report rejected"
            );
            Ok(false)
        }
        Err(e) => {
            error!(error = %e, "Failed to report blocks");
            Ok(false)
        }
    }
}
