//! Pipeline + signal handling + optional validation reporter.

use std::{sync::Arc, time::Duration};

use eyre::Result;
use stateless_common::{BlockRef, RpcClient};
use stateless_core::{ChainStore, PipelineConfig, chain_spec::ChainSpec, pipeline::run_pipeline};
use stateless_db::ContractCache;
use tokio::{signal, task};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    anchor::ValidatorReorgResolver,
    chain_sync::{ValidatorFetcher, ValidatorHooks, ValidatorProcessor},
    metrics::{self, ReportOutcome},
    r2_witness::R2WitnessClient,
    validator_db::ValidatorDB,
};

/// How often the reporter sends the validated chain upstream.
const REPORT_INTERVAL: Duration = Duration::from_secs(1);
/// Attempts for the final shutdown report (first try + retries).
const FINAL_REPORT_ATTEMPTS: usize = 3;
/// Sleep between final-report attempts.
const FINAL_REPORT_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Starts the validator pipeline, optional reporter, and signal handlers.
///
/// Cleanly drains on SIGINT/SIGTERM and returns either the pipeline result or `Ok(())`
/// on signal. Exception: on a fixed-range run (`--end-block`), a final validation report
/// that cannot land fails the run — a slice has no later restart to re-report, so exiting 0
/// would let an orchestrator record the slice as complete while upstream never saw the tip.
pub async fn run_with_signals(
    client: Arc<RpcClient>,
    r2_witness: Option<Arc<R2WitnessClient>>,
    validator_db: Arc<ValidatorDB>,
    contract_cache: Arc<ContractCache>,
    chain_spec: Arc<ChainSpec>,
    pipeline_config: PipelineConfig,
) -> Result<()> {
    let report_validation = client.reports_validation();
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

    let fetcher = Arc::new(ValidatorFetcher::new(client.clone(), r2_witness));
    let processor =
        Arc::new(ValidatorProcessor { chain_spec, contract_cache, rpc_client: client.clone() });
    let hooks = Arc::new(ValidatorHooks);

    // Cancelled once the pipeline has stopped (and drained), so the reporter's final flush sees
    // the last validated block. The reporter is the only task that ever reports: a receiver
    // replaces its recorded chain with each accepted report, so a second sender racing it could
    // land an older chain after a newer one.
    let stop_reporting = CancellationToken::new();
    let reporter = if report_validation {
        Some(task::spawn(validation_reporter(
            Arc::clone(&client),
            Arc::clone(&validator_db),
            stop_reporting.clone(),
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
        ValidatorReorgResolver,
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

    // The reporter finishes the round it may be in, then flushes the validated tail with bounded
    // retries: blocks validated since its last accepted report would otherwise go unreported,
    // and an `--end-block` slice run has no later restart to re-report them.
    stop_reporting.cancel();
    if let Some(reporter) = reporter {
        let flushed = reporter
            .await
            .unwrap_or_else(|e| Err(eyre::eyre!("validation reporter task panicked: {e}")));
        // A chain-following run re-reports the chain on its next start, so an unreported tail
        // heals itself. An `--end-block` slice run has no later restart: fail the run so the
        // orchestrator cannot record the slice as complete. A pipeline error, if any, takes
        // precedence.
        if let Err(e) = flushed {
            error!(error = %e, "Final validation report failed");
            if is_slice_run {
                result = result.and(Err(e));
            }
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

/// Reports the validated chain `(anchor, validated]` to the dedicated report endpoint via
/// `mega_setValidatedChain`, every [`REPORT_INTERVAL`] until `stop` fires, then flushes it once
/// more with up to [`FINAL_REPORT_ATTEMPTS`] attempts.
///
/// Returns `Err` only when that final flush cannot land. Periodic rounds that fail are simply
/// retried on the next tick with whatever the chain is by then.
async fn validation_reporter(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    stop: CancellationToken,
) -> Result<()> {
    info!("Starting validation reporter");
    metrics::init_validated_chain_reports();
    let mut reported = None;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(REPORT_INTERVAL) => {}
            _ = stop.cancelled() => break,
        }
        report_chain_once(&client, &validator_db, &mut reported).await;
    }

    for attempt in 1..=FINAL_REPORT_ATTEMPTS {
        if report_chain_once(&client, &validator_db, &mut reported).await {
            return Ok(());
        }
        if attempt < FINAL_REPORT_ATTEMPTS {
            warn!(attempt, "Final validation report failed, retrying");
            tokio::time::sleep(FINAL_REPORT_RETRY_DELAY).await;
        }
    }
    Err(eyre::eyre!(
        "final validation report failed after {FINAL_REPORT_ATTEMPTS} attempts; the validated \
         tail may be unreported upstream"
    ))
}

/// One reporter round: read the validated chain and send it upstream unless the receiver
/// already accepted exactly this chain (`reported`, updated on acceptance).
///
/// The chain is compared by both ends, hashes included, so a chain that a reorg rewound — lower,
/// or at the same height on a different block — is reported like any other. A chain with nothing
/// validated above its anchor has nothing to report: the receiver takes only `anchor < validated`,
/// and keeps what it had until the next block is validated.
///
/// Returns whether the round settled: the chain was accepted, had been already, or there is
/// nothing to report. A refusal — the receiver does not (yet) hold both blocks on its canonical
/// chain — and a failed call are logged here and settle nothing.
///
/// Every call sent is counted by outcome ([`metrics::on_validated_chain_report`]), since a
/// refusal is a successful RPC to the RPC metrics and a receiver that keeps refusing — say, one
/// that no longer holds the anchor's height — would otherwise show only in the logs.
async fn report_chain_once(
    client: &RpcClient,
    validator_db: &ValidatorDB,
    reported: &mut Option<(BlockRef, BlockRef)>,
) -> bool {
    let chain = match validator_db.validated_chain() {
        Ok(chain) => chain,
        Err(e) => {
            warn!(error = %e, "Failed to read the validated chain, retrying");
            return false;
        }
    };
    let (Some(anchor), Some(validated)) = (chain.anchor, chain.validated) else {
        return true;
    };
    let chain = (
        BlockRef::new(anchor.block_number, anchor.block_hash),
        BlockRef::new(validated.block_number, validated.block_hash),
    );
    if *reported == Some(chain) {
        return true;
    }

    let outcome = client.set_validated_chain(chain.0, chain.1).await;
    let report_outcome = match &outcome {
        Ok(response) if response.accepted => ReportOutcome::Accepted,
        Ok(_) => ReportOutcome::Refused,
        Err(_) => ReportOutcome::Failed,
    };
    metrics::on_validated_chain_report(report_outcome, validated.block_number);

    match outcome {
        Ok(response) if response.accepted => {
            debug!(
                anchor = anchor.block_number,
                anchor_hash = %anchor.block_hash,
                validated = validated.block_number,
                validated_hash = %validated.block_hash,
                "Reported validated chain"
            );
            *reported = Some(chain);
            true
        }
        Ok(response) => {
            warn!(
                anchor = anchor.block_number,
                validated = validated.block_number,
                upstream_anchor = ?response.anchor.map(|b| b.block_number.to::<u64>()),
                upstream_validated = ?response.validated.map(|b| b.block_number.to::<u64>()),
                "Validated chain refused: the receiver does not hold both blocks on its canonical \
                 chain"
            );
            false
        }
        Err(e) => {
            error!(error = %e, "Failed to report the validated chain");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use jsonrpsee::types::ErrorObjectOwned;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use stateless_common::{RpcClientConfig, SetValidatedChainResponse};
    use stateless_core::ChainStore;
    use stateless_test_utils::mock_rpc::serve;

    use super::*;
    use crate::{metrics::names, test_support::make_block_meta};

    /// How the mock receiver answers one `mega_setValidatedChain` call.
    #[derive(Clone, Copy)]
    enum Answer {
        Accept,
        Refuse,
        Fail,
    }

    /// The report series one `step` recorded: each `outcome` count, and the reported height if
    /// it was set.
    fn recorded(rt: &tokio::runtime::Runtime, step: impl Future) -> ([u64; 3], Option<f64>) {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        ::metrics::with_local_recorder(&recorder, || rt.block_on(step));
        let (mut counts, mut height) = ([0; 3], None);
        for (key, _, _, value) in snapshotter.snapshot().into_vec() {
            let key = key.key();
            match value {
                DebugValue::Counter(n) if key.name() == names::VALIDATED_CHAIN_REPORTS => {
                    let outcome = key.labels().find(|l| l.key() == "outcome").unwrap();
                    let slot = ["accepted", "refused", "failed"]
                        .iter()
                        .position(|o| *o == outcome.value())
                        .unwrap();
                    counts[slot] += n;
                }
                DebugValue::Gauge(v) if key.name() == names::REPORTED_VALIDATED_HEIGHT => {
                    height = Some(v.into_inner());
                }
                _ => {}
            }
        }
        (counts, height)
    }

    /// Each call sent counts once under its outcome, and only an accepted one moves the reported
    /// height; a round with nothing new to report sends nothing and counts nothing.
    #[test]
    fn reports_are_counted_by_outcome() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let answers = Arc::new(Mutex::new(VecDeque::new()));
        let (handle, url) = rt.block_on(serve(Arc::clone(&answers), |m| {
            m.register_method("mega_setValidatedChain", |params, answers, _| {
                let (anchor, validated): (BlockRef, BlockRef) = params.parse()?;
                let accepted = match answers.lock().unwrap().pop_front().unwrap() {
                    Answer::Accept => true,
                    Answer::Refuse => false,
                    Answer::Fail => {
                        return Err(ErrorObjectOwned::owned(-32000, "scripted", None::<()>));
                    }
                };
                Ok(SetValidatedChainResponse {
                    accepted,
                    anchor: accepted.then_some(anchor),
                    validated: accepted.then_some(validated),
                })
            })
            .unwrap();
        }));
        let client =
            RpcClient::new_with_config(&[&url], &[&url], RpcClientConfig::default(), Some(&url))
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db = ValidatorDB::new(dir.path().join("test.redb")).unwrap();
        db.reset_to_anchor(&make_block_meta(5)).unwrap();
        let mut reported = None;
        let mut round = |answer: Option<Answer>| {
            answers.lock().unwrap().extend(answer);
            let settled = recorded(&rt, report_chain_once(&client, &db, &mut reported));
            assert!(answers.lock().unwrap().is_empty(), "every scripted answer is used");
            settled
        };

        assert_eq!(round(None), ([0, 0, 0], None), "nothing validated above the anchor yet");

        db.advance_chain(&[make_block_meta(6), make_block_meta(7)]).unwrap();
        assert_eq!(round(Some(Answer::Refuse)), ([0, 1, 0], None));
        assert_eq!(round(Some(Answer::Fail)), ([0, 0, 1], None));
        assert_eq!(round(Some(Answer::Accept)), ([1, 0, 0], Some(7.0)));
        assert_eq!(round(None), ([0, 0, 0], None), "an accepted chain is not sent again");

        rt.block_on(async { handle.stop().unwrap() });
    }
}
