//! Pipeline + signal handling + optional validation reporter.

use std::{sync::Arc, time::Duration};

use alloy_primitives::B256;
use eyre::Result;
use stateless_common::RpcClient;
use stateless_core::{ChainStore, PipelineConfig, chain_spec::ChainSpec, pipeline::run_pipeline};
use stateless_db::ContractCache;
use tokio::{signal, task};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    chain_sync::{ValidatorFetcher, ValidatorHooks, ValidatorProcessor},
    metrics,
    validator_db::ValidatorDB,
};

/// Starts the validator pipeline, optional reporter, and signal handlers.
///
/// Cleanly drains on SIGINT/SIGTERM and returns either the pipeline result or `Ok(())`
/// on signal.
pub async fn run_with_signals(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    contract_cache: Arc<ContractCache>,
    chain_spec: Arc<ChainSpec>,
    report_validation_endpoint: Option<String>,
    pipeline_config: PipelineConfig,
) -> Result<()> {
    let report_validation = report_validation_endpoint.is_some();
    let config = Arc::new(pipeline_config);
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

    let fetcher = Arc::new(ValidatorFetcher {
        rpc_client: client.clone(),
        on_remote_height: metrics::set_remote_chain_height,
    });
    let processor =
        Arc::new(ValidatorProcessor { chain_spec, contract_cache, rpc_client: client.clone() });
    let hooks = Arc::new(ValidatorHooks);

    let reporter = if report_validation {
        Some(task::spawn(validation_reporter(
            client,
            Arc::clone(&validator_db),
            Duration::from_secs(1),
            shutdown.clone(),
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
    ));

    // Signal wins → drain; pipeline wins → already done.
    let (result, needs_drain): (Result<()>, bool) = tokio::select! {
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
/// validated range to the upstream node.
async fn validation_reporter(
    client: Arc<RpcClient>,
    validator_db: Arc<ValidatorDB>,
    report_interval: Duration,
    shutdown: CancellationToken,
) -> Result<()> {
    info!("Starting validation reporter");
    let mut last_reported_block = 0u64;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(report_interval) => {}
            _ = shutdown.cancelled() => {
                info!("Shutting down gracefully");
                return Ok(());
            }
        }

        let (anchor, tip) = match (validator_db.get_anchor(), validator_db.get_canonical_tip()) {
            (Ok(Some(a)), Ok(Some(t))) => (a, t),
            (Ok(None), _) | (_, Ok(None)) => continue,
            (Err(e), _) | (_, Err(e)) => {
                warn!(error = %e, "Failed to read anchor/tip, retrying");
                continue;
            }
        };

        if tip.block_number == last_reported_block {
            continue;
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
                last_reported_block = tip.block_number;
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
            }
            Err(e) => {
                error!(error = %e, "Failed to report blocks");
            }
        }
    }
}
