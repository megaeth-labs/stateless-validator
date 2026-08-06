//! App lifecycle: CLI parsing, tracing/metrics setup, DB construction, and handoff to workers.

use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy_genesis::Genesis;
use alloy_primitives::BlockHash;
use alloy_rpc_types_eth::BlockId;
use clap::{Parser, ValueEnum};
use eyre::Result;
use stateless_common::{
    BackoffPolicy, RedactedSecret, RpcClient, RpcClientConfig, logging::LogArgs,
};
use stateless_core::{ChainStore, ContractStore, chain_spec::ChainSpec, db::BlockMeta};
use stateless_db::ContractCache;
use tracing::{info, warn};

use crate::{metrics, r2_witness::R2WitnessClient, validator_db::ValidatorDB, workers};

/// Where the validator sources witnesses from.
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, Default)]
#[clap(rename_all = "lowercase")]
pub enum WitnessSource {
    /// `mega_getBlockWitness` RPC.
    #[default]
    Rpc,
    /// Straight from the R2 bucket over the S3 API. Requires the `--r2-*` flags.
    R2,
}

/// Database filename for the validator.
pub const VALIDATOR_DB_FILENAME: &str = "validator.redb";

/// Default `--tip-buffer`. The validator races the upstream witness generator, so it stays
/// 3 blocks behind by default. Core's `PipelineConfig::tip_buffer` defaults to `0` because
/// the buffer is opt-in per binary; the validator opts in here.
const DEFAULT_TIP_BUFFER: u64 = 3;

/// Loads or creates a ChainSpec from the database or a genesis file.
pub fn load_or_create_chain_spec(
    validator_db: &ValidatorDB,
    genesis_file: Option<&str>,
) -> Result<ChainSpec> {
    let genesis = match genesis_file {
        Some(path) => {
            info!(path, "Loading genesis from file");
            let genesis = serde_json::from_str::<Genesis>(&std::fs::read_to_string(path)?)?;
            validator_db.store_genesis(&genesis)?;
            genesis
        }
        None => {
            info!("Loading genesis from database");
            validator_db.load_genesis()?.ok_or_else(|| {
                eyre::eyre!("No genesis config found. Please provide --genesis-file on first run.")
            })?
        }
    };

    Ok(ChainSpec::from_genesis(genesis))
}

/// Command line arguments for the stateless validator.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct CommandLineArgs {
    /// Directory path where validator data and database files will be stored.
    #[clap(long, env = "STATELESS_VALIDATOR_DATA_DIR")]
    pub data_dir: String,

    /// One or more JSON-RPC API endpoints for fetching blockchain data (tried in order).
    /// Accepts repeated flags (`--rpc-endpoint a --rpc-endpoint b`) or a comma-separated
    /// list (`--rpc-endpoint a,b`, also via the env var).
    #[clap(
        long,
        env = "STATELESS_VALIDATOR_RPC_ENDPOINT",
        required = true,
        value_delimiter = ',',
        action = clap::ArgAction::Append,
    )]
    pub rpc_endpoint: Vec<String>,

    /// One or more MegaETH JSON-RPC API endpoints for fetching witness data (tried in order).
    /// Accepts repeated flags (`--witness-endpoint a --witness-endpoint b`) or a comma-separated
    /// list (`--witness-endpoint a,b`, also via the env var).
    ///
    /// Required when `--witness-source rpc` (the default); ignored when `--witness-source r2`.
    #[clap(
        long,
        env = "STATELESS_VALIDATOR_WITNESS_ENDPOINT",
        value_delimiter = ',',
        action = clap::ArgAction::Append,
    )]
    pub witness_endpoint: Vec<String>,

    /// Where to source witnesses from: `rpc` (default) or `r2` (requires the `--r2-*` flags).
    #[clap(long, env = "STATELESS_VALIDATOR_WITNESS_SOURCE", value_enum, default_value_t = WitnessSource::Rpc)]
    pub witness_source: WitnessSource,

    /// R2 S3 endpoint origin, e.g. `https://<account>.r2.cloudflarestorage.com` (no bucket path).
    /// Required when `--witness-source r2`.
    #[clap(long, env = "STATELESS_VALIDATOR_R2_ENDPOINT")]
    pub r2_endpoint: Option<String>,

    /// R2 bucket holding the witnesses (e.g. `witness-mainnet`). Required when `--witness-source
    /// r2`.
    #[clap(long, env = "STATELESS_VALIDATOR_R2_BUCKET")]
    pub r2_bucket: Option<String>,

    /// R2 access key id (Object Read). Required when `--witness-source r2`.
    #[clap(long, env = "STATELESS_VALIDATOR_R2_ACCESS_KEY_ID")]
    pub r2_access_key_id: Option<String>,

    /// R2 secret access key. Required when `--witness-source r2`. Prefer the env var over the
    /// flag.
    #[clap(long, env = "STATELESS_VALIDATOR_R2_SECRET_ACCESS_KEY")]
    pub r2_secret_access_key: Option<RedactedSecret>,

    /// Optional inclusive end block: validate up to this height, then stop cleanly. Used to slice
    /// a fixed block range across multiple servers. Omit to follow the chain tip indefinitely.
    /// Note: the run only completes once the chain reaches `end_block + tip_buffer`.
    #[clap(long, env = "STATELESS_VALIDATOR_END_BLOCK")]
    pub end_block: Option<u64>,

    /// Optional trusted block hash to start validation from.
    #[clap(long, env = "STATELESS_VALIDATOR_START_BLOCK")]
    pub start_block: Option<String>,

    /// Path to the genesis JSON file for chain configuration.
    /// Required on first run, optional on subsequent runs (loads from database).
    #[clap(long, env = "STATELESS_VALIDATOR_GENESIS_FILE")]
    pub genesis_file: Option<String>,

    /// Endpoint for reporting validated blocks via mega_setValidatedBlocks RPC.
    /// If not provided, validation reporting is disabled.
    #[clap(long, env = "STATELESS_VALIDATOR_REPORT_VALIDATION_ENDPOINT")]
    pub report_validation_endpoint: Option<String>,

    /// Enable Prometheus metrics endpoint.
    /// When enabled, metrics are exposed at `http://0.0.0.0:<metrics-port>/metrics`.
    #[clap(long, env = "STATELESS_VALIDATOR_METRICS_ENABLED")]
    pub metrics_enabled: bool,

    /// Port for Prometheus metrics HTTP endpoint.
    #[clap(long, env = "STATELESS_VALIDATOR_METRICS_PORT", default_value_t = metrics::DEFAULT_METRICS_PORT)]
    pub metrics_port: u16,

    /// Maximum concurrent in-flight data-endpoint requests (blocks, headers, code, tx).
    /// Omit for unlimited.
    #[clap(long, env = "STATELESS_VALIDATOR_DATA_MAX_CONCURRENT_REQUESTS")]
    pub data_max_concurrent_requests: Option<usize>,

    /// Maximum concurrent in-flight witness fetches, independent of the data cap. Omit for
    /// unlimited. Applies to both RPC witness calls and, with `--witness-source r2`, R2 GETs.
    #[clap(long, env = "STATELESS_VALIDATOR_WITNESS_MAX_CONCURRENT_REQUESTS")]
    pub witness_max_concurrent_requests: Option<usize>,

    /// Fetcher caught-up poll interval (milliseconds). Also rate-limits `eth_blockNumber`.
    /// Lower values reduce tip-following lag at the cost of more RPC traffic when caught up.
    #[clap(long, env = "STATELESS_VALIDATOR_POLL_INTERVAL_MS")]
    pub poll_interval_ms: Option<u64>,

    /// Pipeline restart delay after a transient cycle error (milliseconds).
    #[clap(long, env = "STATELESS_VALIDATOR_ERROR_RESTART_DELAY_MS")]
    pub error_restart_delay_ms: Option<u64>,

    /// Safety margin below the remote tip: the fetcher will not spawn fetches for blocks
    /// `> chain_latest - tip_buffer`. Gives the upstream witness generator headroom to
    /// finish the very block we'd otherwise race it for. `0` disables the buffer. Defaults
    /// to `DEFAULT_TIP_BUFFER`.
    #[clap(long, env = "STATELESS_VALIDATOR_TIP_BUFFER")]
    pub tip_buffer: Option<u64>,

    /// Initial round-level RPC retry backoff (milliseconds). Applied after every provider in a
    /// round has failed; doubles each round up to `--rpc-max-backoff-ms`. With
    /// `--witness-source r2` this also paces R2 witness GET retries.
    #[clap(long, env = "STATELESS_VALIDATOR_RPC_INITIAL_BACKOFF_MS")]
    pub rpc_initial_backoff_ms: Option<u64>,

    /// Cap on round-level RPC retry backoff (milliseconds). With `--witness-source r2` this
    /// also caps R2 witness GET retry backoff.
    #[clap(long, env = "STATELESS_VALIDATOR_RPC_MAX_BACKOFF_MS")]
    pub rpc_max_backoff_ms: Option<u64>,

    /// Per-attempt RPC timeout (milliseconds). Must be ≥ 100ms. With `--witness-source r2` this
    /// also bounds each R2 witness GET.
    #[clap(
        long,
        env = "STATELESS_VALIDATOR_RPC_PER_ATTEMPT_TIMEOUT_MS",
        value_parser = clap::value_parser!(u64).range(100..),
    )]
    pub rpc_per_attempt_timeout_ms: Option<u64>,

    /// Soft cap on rows retained in the canonical-chain table. Old rows are pruned inline
    /// when `advance_chain` exceeds this. Larger values bound the reorg-lookup window;
    /// smaller values reduce redb file growth. Defaults to `DEFAULT_MAX_CHAIN_LENGTH`
    /// (see `stateless_db::DEFAULT_MAX_CHAIN_LENGTH`).
    ///
    /// Must be ≥ 1: a value of 0 would wipe the canonical chain on every advance, forcing
    /// the pipeline to roll back to the anchor each round and loop forever.
    #[clap(
        long,
        env = "STATELESS_VALIDATOR_CANONICAL_CHAIN_MAX_LENGTH",
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    pub canonical_chain_max_length: Option<u64>,

    /// Logging configuration.
    #[command(flatten)]
    pub log: LogArgs,
}

/// Entry point for the validator binary.
///
/// Parses CLI args, initializes tracing and metrics, constructs the RPC client and
/// validator DB, loads or initializes the chain spec + anchor, then hands off to
/// [`workers::run_with_signals`].
pub async fn run() -> Result<()> {
    let args = CommandLineArgs::parse();
    let _log_guard = args.log.init_tracing()?;
    let start = std::time::Instant::now();

    info!(data_dir = %args.data_dir, "Data directory");
    info!(rpc_endpoints = ?args.rpc_endpoint, "RPC endpoints");
    info!(witness_endpoints = ?args.witness_endpoint, "Witness endpoints");
    if let Some(ref genesis_file) = args.genesis_file {
        info!(genesis_file, "Genesis file");
    }

    if args.metrics_enabled {
        let metrics_addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.metrics_port));
        metrics::init_metrics(metrics_addr)?;
        info!(port = args.metrics_port, "Metrics enabled");
    } else {
        info!("Metrics disabled");
    }

    let work_dir = PathBuf::from(args.data_dir);
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| eyre::eyre!("Failed to create data dir {}: {e}", work_dir.display()))?;

    let rpc_defaults = RpcClientConfig::validator();
    let rpc_retry = BackoffPolicy {
        initial: override_ms(args.rpc_initial_backoff_ms, rpc_defaults.rpc_retry.initial),
        max: override_ms(args.rpc_max_backoff_ms, rpc_defaults.rpc_retry.max),
    };
    let per_attempt_timeout =
        override_ms(args.rpc_per_attempt_timeout_ms, rpc_defaults.per_attempt_timeout);
    let rpc_config = RpcClientConfig {
        data_max_concurrent_requests: args.data_max_concurrent_requests,
        witness_max_concurrent_requests: args.witness_max_concurrent_requests,
        rpc_retry,
        per_attempt_timeout,
        ..rpc_defaults
    }
    .with_metrics(Arc::new(metrics::ValidatorMetrics));
    // In R2 mode the RpcClient's witness providers are never used, but its constructor requires
    // a non-empty list — hand it the data endpoints as a placeholder.
    let data_apis: Vec<&str> = args.rpc_endpoint.iter().map(String::as_str).collect();
    let r2_witness = match args.witness_source {
        WitnessSource::Rpc => {
            if args.witness_endpoint.is_empty() {
                return Err(eyre::eyre!(
                    "--witness-endpoint is required with --witness-source rpc (the default)"
                ));
            }
            None
        }
        WitnessSource::R2 => {
            if !args.witness_endpoint.is_empty() {
                warn!(
                    "--witness-endpoint is ignored with --witness-source r2: witnesses come \
                     straight from the R2 bucket, and there is no RPC witness fallback"
                );
            }
            let endpoint = require_r2(&args.r2_endpoint, "--r2-endpoint")?;
            let bucket = require_r2(&args.r2_bucket, "--r2-bucket")?;
            let access_key_id = require_r2(&args.r2_access_key_id, "--r2-access-key-id")?;
            let secret_access_key =
                require_r2(&args.r2_secret_access_key, "--r2-secret-access-key")?;
            // Log the parsed origin, not the raw flag value — the raw string is operator
            // input and this line is info-level.
            let (origin, _) = stateless_r2::endpoint::parse_endpoint(endpoint);
            info!(endpoint = %origin, bucket, "Witness source: R2 (direct S3)");
            Some(Arc::new(R2WitnessClient::new(
                endpoint,
                bucket.to_string(),
                access_key_id.to_string(),
                secret_access_key.to_string(),
                per_attempt_timeout,
                rpc_config.rpc_retry.clone(),
                args.witness_max_concurrent_requests,
            )?))
        }
    };

    let witness_apis: Vec<&str> = if r2_witness.is_some() {
        data_apis.clone()
    } else {
        args.witness_endpoint.iter().map(String::as_str).collect()
    };
    let client = Arc::new(RpcClient::new_with_config(
        &data_apis,
        &witness_apis,
        rpc_config,
        args.report_validation_endpoint.as_deref(),
    )?);
    let validator_db = Arc::new(ValidatorDB::with_max_chain_length(
        work_dir.join(VALIDATOR_DB_FILENAME),
        args.canonical_chain_max_length.unwrap_or(stateless_db::DEFAULT_MAX_CHAIN_LENGTH),
    )?);
    let contract_cache =
        Arc::new(ContractCache::new(Arc::clone(&validator_db) as Arc<dyn ContractStore>));

    let chain_spec =
        Arc::new(load_or_create_chain_spec(&validator_db, args.genesis_file.as_deref())?);
    info!("Chain spec loaded successfully");

    if let Some(start_block_str) = &args.start_block {
        info!(start_block = %start_block_str, "Initializing from start block");

        let block_hash: BlockHash = start_block_str.parse()?;
        // `get_header` retries transient failures forever at the RPC layer, so the binary
        // stays stuck here until the endpoint is reachable — a permanent misconfiguration
        // surfaces as "no forward progress" rather than an arbitrarily bounded retry error.
        let header = client.get_header(BlockId::Hash(block_hash.into()), true).await;

        let anchor = BlockMeta {
            block_number: header.number,
            block_hash: header.hash,
            post_state_root: header.state_root,
            post_withdrawals_root: header
                .withdrawals_root
                .ok_or_else(|| eyre::eyre!("Block {} is missing withdrawals_root", block_hash))?,
        };
        validator_db.reset_to_anchor(&anchor)?;

        info!(
            block_hash = %header.hash,
            block_number = header.number,
            "Successfully initialized from start block"
        );
    } else {
        let tip = validator_db.get_canonical_tip()?.ok_or_else(|| {
            eyre::eyre!(
                "No trusted starting point found. Specify a trusted block with --start-block <blockhash>"
            )
        })?;
        info!(
            block_number = tip.block_number,
            block_hash = %tip.block_hash,
            "Continuing from existing canonical chain"
        );
    }

    // `#[non_exhaustive]` on `PipelineConfig` rules out the struct-update shorthand at the
    // crate boundary — mutate a default instance instead, which is the pattern the attribute
    // is designed around.
    let mut pipeline_config = stateless_core::PipelineConfig::default();
    pipeline_config.poll_interval =
        override_ms(args.poll_interval_ms, pipeline_config.poll_interval);
    pipeline_config.error_restart_delay =
        override_ms(args.error_restart_delay_ms, pipeline_config.error_restart_delay);
    pipeline_config.tip_buffer = args.tip_buffer.unwrap_or(DEFAULT_TIP_BUFFER);
    pipeline_config.sync_target = args.end_block;
    if let Some(end) = args.end_block {
        info!(end_block = end, "Validating up to end block, then stopping");
    }

    let result = workers::run_with_signals(
        client,
        r2_witness,
        validator_db,
        contract_cache,
        chain_spec,
        args.report_validation_endpoint,
        pipeline_config,
    )
    .await;

    info!(elapsed = ?start.elapsed(), "Shutdown complete");
    result
}

/// Returns `ms.map(Duration::from_millis)` if `ms` is `Some`, else `default`.
///
/// Collapses the four `.map(Duration::from_millis).unwrap_or(default)` chains that
/// otherwise spread across the backoff + pipeline-config overrides.
fn override_ms(ms: Option<u64>, default: Duration) -> Duration {
    ms.map(Duration::from_millis).unwrap_or(default)
}

/// Unwraps a required `--r2-*` argument, erroring with the flag name when it is absent.
fn require_r2<'a, T: AsRef<str>>(value: &'a Option<T>, flag: &str) -> Result<&'a str> {
    value
        .as_ref()
        .map(AsRef::as_ref)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| eyre::eyre!("{flag} is required with --witness-source r2"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_r2_rejects_absent_and_empty_values() {
        assert!(require_r2(&None::<String>, "--r2-endpoint").is_err());
        // An env var set to the empty string must not pass as configured.
        assert!(require_r2(&Some(String::new()), "--r2-endpoint").is_err());
        assert_eq!(
            require_r2(&Some("https://x".to_string()), "--r2-endpoint").unwrap(),
            "https://x"
        );
    }
}
