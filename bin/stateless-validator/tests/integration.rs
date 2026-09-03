//! Integration tests for the stateless-validator binary crate.
//!
//! Covers CLI argument parsing and end-to-end pipeline validation against a mock RPC server.
//! Mainnet single-block validation is covered in `crates/stateless-core/src/executor.rs::tests`.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use alloy_primitives::{B256, BlockHash};
use alloy_rpc_types_eth::Block;
use clap::Parser;
use jsonrpsee::server::ServerConfigBuilder;
use jsonrpsee_types::error::{
    CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
};
use stateless_common::{RpcClient, RpcClientConfig, WitnessRequestKeys, encode_witness_response};
use stateless_core::{
    BisectResolver, ChainStore, ContractStore, PipelineConfig, db::BlockMeta,
    pipeline::run_pipeline, withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use stateless_test_utils::{
    fixtures::TestFixtures,
    logging::init_test_logging,
    mock_rpc::{parse_hex_u64, serve_with_config},
};
use stateless_validator::{
    CommandLineArgs, VALIDATOR_DB_FILENAME, ValidatorDB, ValidatorFetcher, ValidatorHooks,
    ValidatorProcessor, load_or_create_chain_spec, run_with_signals,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Argv prefix for tests that exercise an *optional* flag — both required endpoints are
/// already supplied so the parse only depends on the flag under test.
const BASE_ARGS: &[&str] = &[
    "stateless-validator",
    "--data-dir",
    "/tmp/x",
    "--rpc-endpoint",
    "http://rpc",
    "--witness-endpoint",
    "http://w",
];

/// [`BASE_ARGS`] without `--witness-endpoint`, for tests that exercise that flag itself or its
/// absence.
const BASE_ARGS_NO_WITNESS: &[&str] =
    &["stateless-validator", "--data-dir", "/tmp/x", "--rpc-endpoint", "http://rpc"];

/// Verifies that an endpoint flag accepts repeated flags, CSV values, and env var —
/// ensuring container deployments configured purely via env are not silently limited
/// to one endpoint (clap's `value_delimiter` applies to env-var values too).
fn assert_endpoint_accepts_multiple_forms(
    flag: &str,
    env: &str,
    base: &[&str],
    extract: impl Fn(CommandLineArgs) -> Vec<String>,
) {
    let guard = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| {
        extract(CommandLineArgs::try_parse_from(base.iter().chain(extra)).unwrap())
    };

    assert_eq!(parse(&[flag, "http://a,http://b"]), ["http://a", "http://b"]);
    assert_eq!(
        parse(&[flag, "http://a,http://b", flag, "http://c"]),
        ["http://a", "http://b", "http://c"],
    );

    let from_env =
        stateless_test_utils::env::with_env_var(&guard, env, "http://a,http://b", || parse(&[]));
    assert_eq!(from_env, ["http://a", "http://b"]);
}

#[test]
fn witness_endpoint_accepts_multiple_forms() {
    assert_endpoint_accepts_multiple_forms(
        "--witness-endpoint",
        "STATELESS_VALIDATOR_WITNESS_ENDPOINT",
        BASE_ARGS_NO_WITNESS,
        |a| a.witness_endpoint,
    );
}

#[test]
fn rpc_endpoint_accepts_multiple_forms() {
    assert_endpoint_accepts_multiple_forms(
        "--rpc-endpoint",
        "STATELESS_VALIDATOR_RPC_ENDPOINT",
        &["stateless-validator", "--data-dir", "/tmp/x", "--witness-endpoint", "http://w"],
        |a| a.rpc_endpoint,
    );
}

/// Verifies that an optional numeric flag parses as `Some(n)` via CLI and env var,
/// and omission leaves the value `None`.
fn assert_optional_numeric_flag<T>(
    flag: &str,
    env: &str,
    extract: impl Fn(CommandLineArgs) -> Option<T>,
) where
    T: std::str::FromStr + std::fmt::Debug + PartialEq,
    T::Err: std::fmt::Debug,
{
    let guard = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| {
        extract(CommandLineArgs::try_parse_from(BASE_ARGS.iter().chain(extra)).unwrap())
    };

    assert_eq!(parse(&[]), None);
    assert_eq!(parse(&[flag, "7"]), Some("7".parse().unwrap()));

    let from_env = stateless_test_utils::env::with_env_var(&guard, env, "12", || parse(&[]));
    assert_eq!(from_env, Some("12".parse().unwrap()));
}

#[test]
fn data_max_concurrent_requests_flag_and_env() {
    assert_optional_numeric_flag::<usize>(
        "--data-max-concurrent-requests",
        "STATELESS_VALIDATOR_DATA_MAX_CONCURRENT_REQUESTS",
        |a| a.data_max_concurrent_requests,
    );
}

#[test]
fn witness_max_concurrent_requests_flag_and_env() {
    assert_optional_numeric_flag::<usize>(
        "--witness-max-concurrent-requests",
        "STATELESS_VALIDATOR_WITNESS_MAX_CONCURRENT_REQUESTS",
        |a| a.witness_max_concurrent_requests,
    );
}

#[test]
fn r2_max_concurrent_requests_flag_and_env() {
    assert_optional_numeric_flag::<usize>(
        "--r2-max-concurrent-requests",
        "STATELESS_VALIDATOR_R2_MAX_CONCURRENT_REQUESTS",
        |a| a.r2_max_concurrent_requests,
    );
}

#[test]
fn tip_buffer_flag_and_env() {
    assert_optional_numeric_flag::<u64>("--tip-buffer", "STATELESS_VALIDATOR_TIP_BUFFER", |a| {
        a.tip_buffer
    });
}

#[test]
fn end_block_flag_and_env() {
    assert_optional_numeric_flag::<u64>("--end-block", "STATELESS_VALIDATOR_END_BLOCK", |a| {
        a.end_block
    });
}

/// `--witness-source` must default to `rpc`, parse both lowercase values (flag and env), and
/// reject anything else at parse time.
#[test]
fn witness_source_flag_and_env() {
    use stateless_validator::WitnessSource;

    let guard = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| CommandLineArgs::try_parse_from(BASE_ARGS.iter().chain(extra));

    assert_eq!(parse(&[]).unwrap().witness_source, WitnessSource::Rpc);
    assert_eq!(parse(&["--witness-source", "rpc"]).unwrap().witness_source, WitnessSource::Rpc);
    assert_eq!(parse(&["--witness-source", "r2"]).unwrap().witness_source, WitnessSource::R2);
    assert!(parse(&["--witness-source", "s3"]).is_err());

    let from_env = stateless_test_utils::env::with_env_var(
        &guard,
        "STATELESS_VALIDATOR_WITNESS_SOURCE",
        "r2",
        || parse(&[]).unwrap().witness_source,
    );
    assert_eq!(from_env, WitnessSource::R2);
}

/// `--witness-endpoint` is enforced at runtime per witness source (required for `rpc`, ignored
/// for `r2`), so the parse itself must accept its absence in both modes.
#[test]
fn witness_endpoint_is_optional_at_parse_time() {
    // `try_parse_from` reads the env for every `#[clap(env = ...)]` field, so this test
    // must hold the lock too: a sibling's `with_env_var` would otherwise land in this parse.
    let _guard = stateless_test_utils::env::env_lock();
    let parse =
        |extra: &[&str]| CommandLineArgs::try_parse_from(BASE_ARGS_NO_WITNESS.iter().chain(extra));

    assert!(parse(&[]).unwrap().witness_endpoint.is_empty());
    assert!(parse(&["--witness-source", "r2"]).unwrap().witness_endpoint.is_empty());
}

/// The custom-domain R2 target is mutually exclusive with the S3 endpoint, and the Access
/// token pair is all-or-nothing on top of it.
#[test]
fn r2_custom_domain_target_wiring() {
    let _guard = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| CommandLineArgs::try_parse_from(BASE_ARGS.iter().chain(extra));

    assert_eq!(
        parse(&["--r2-custom-domain", "https://witness.example.com"])
            .unwrap()
            .r2_custom_domain
            .as_deref(),
        Some("https://witness.example.com")
    );
    // Every R2 coherence rule is enforced after parsing, by `stateless_common::validate_r2_flags`,
    // so that each error can name the flag — clap's own rejections cannot, this workspace having
    // built it without `error-context`. Parsing therefore accepts all of these shapes; the rules
    // and their messages are covered by that function's own tests.
    const DOMAIN: &str = "https://witness.example.com";
    for shape in [
        &["--r2-custom-domain", DOMAIN, "--r2-endpoint", "https://acc.r2.cloudflarestorage.com"][..],
        &["--r2-custom-domain", DOMAIN, "--r2-access-client-id", "tok"],
        &["--r2-access-client-id", "tok", "--r2-access-client-secret", "sk"],
        &[
            "--r2-custom-domain",
            DOMAIN,
            "--r2-access-client-id",
            "tok",
            "--r2-access-client-secret",
            "sk",
        ],
        &["--r2-custom-domain", DOMAIN, "--r2-connections", "0"],
    ] {
        assert!(parse(shape).is_ok(), "{shape:?} must parse; rejection happens post-parse");
    }
    assert_eq!(
        parse(&["--r2-custom-domain", DOMAIN, "--r2-connections", "8"])
            .unwrap()
            .r2_connections
            .as_deref(),
        Some("8")
    );
}

/// Under the default `--witness-source rpc` the `--r2-*` flags are inert, and a blank value —
/// what a templated env file renders for a variable a given role does not set — must stay
/// inert too.
///
/// This pins the parse layer specifically. `--r2-connections` is text rather than a number for
/// exactly this reason: parsed by clap, a blank line aborts startup before `run` can decide the
/// flags are irrelevant, and it aborts with clap's unnamed value error because this workspace
/// builds clap without `error-context`. The gating of the rules themselves lives in `run` —
/// `validate_r2_flags` is reached only through `build_r2_client`, from the `WitnessSource::R2`
/// arm — which this test cannot observe.
#[test]
fn rpc_mode_tolerates_blank_and_conflicting_r2_values() {
    let _guard = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| CommandLineArgs::try_parse_from(BASE_ARGS.iter().chain(extra));

    assert!(parse(&["--witness-source", "rpc"]).is_ok());
    for blank in [
        ["--r2-bucket", ""],
        ["--r2-custom-domain", ""],
        ["--r2-connections", ""],
        ["--r2-access-client-id", ""],
    ] {
        assert!(
            parse(&blank).is_ok(),
            "a blank {} must parse so it can stay inert in rpc mode",
            blank[0]
        );
    }
    assert!(
        parse(&[
            "--witness-source",
            "rpc",
            "--r2-endpoint",
            "https://acc.r2.cloudflarestorage.com",
            "--r2-custom-domain",
            "https://witness.example.com",
        ])
        .is_ok(),
        "conflicting targets must parse in rpc mode; they are never read there"
    );
}

/// `canonical_chain_max_length` must reject 0 at parse time. A value of 0 would make
/// `advance_chain` prune the entire canonical chain on every successful advance,
/// rolling the pipeline back to the anchor each round and looping forever.
#[test]
fn canonical_chain_max_length_rejects_zero() {
    let parse = |extra: &[&str]| CommandLineArgs::try_parse_from(BASE_ARGS.iter().chain(extra));

    assert_eq!(parse(&[]).unwrap().canonical_chain_max_length, None);
    assert_eq!(
        parse(&["--canonical-chain-max-length", "1"]).unwrap().canonical_chain_max_length,
        Some(1),
    );
    assert!(parse(&["--canonical-chain-max-length", "0"]).is_err());

    let guard = stateless_test_utils::env::env_lock();
    let from_env_zero = stateless_test_utils::env::with_env_var(
        &guard,
        "STATELESS_VALIDATOR_CANONICAL_CHAIN_MAX_LENGTH",
        "0",
        || parse(&[]),
    );
    assert!(from_env_zero.is_err(), "env-var 0 must also be rejected");
}

const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

/// Mock RPC server backing state: all fields pre-decoded so the RPC handlers can respond
/// synchronously. Wraps [`TestFixtures`] and pre-decodes MPT witnesses once.
struct MockServerState {
    fixtures: TestFixtures,
    mpt_witnesses: HashMap<BlockHash, MptWitness>,
    /// Every *accepted* `mega_setValidatedBlocks` call, as `(first_block, last_block)` numbers.
    validated_reports: Arc<Mutex<Vec<(u64, u64)>>>,
    /// Number of upcoming `mega_setValidatedBlocks` calls to reject with an RPC error.
    reject_reports: Arc<std::sync::atomic::AtomicUsize>,
}

impl MockServerState {
    fn new(fixtures: TestFixtures) -> Self {
        let mpt_witnesses = fixtures
            .mpt_witness_bytes
            .keys()
            .map(|hash| (*hash, fixtures.mpt_witness(hash)))
            .collect();
        Self {
            fixtures,
            mpt_witnesses,
            validated_reports: Arc::default(),
            reject_reports: Arc::default(),
        }
    }

    /// Fixture block for a `0x…` hex block number, or the RPC error the handlers return
    /// for unknown blocks. Shared by the by-number block and header handlers.
    fn block_by_number_hex(
        &self,
        hex_number: &str,
    ) -> Result<&Block<op_alloy_rpc_types::Transaction>, ErrorObject<'static>> {
        let block_number = parse_hex_u64(hex_number);
        self.fixtures
            .block_numbers
            .get(&block_number)
            .and_then(|hash| self.fixtures.blocks.get(hash))
            .ok_or_else(|| {
                make_rpc_error(
                    CALL_EXECUTION_FAILED_CODE,
                    format!("Block {block_number} not found"),
                )
            })
    }

    /// Fixture block for a block hash, or the RPC error the handlers return for unknown
    /// blocks. Shared by the by-hash block and header handlers.
    fn block_by_hash(
        &self,
        hash: B256,
    ) -> Result<&Block<op_alloy_rpc_types::Transaction>, ErrorObject<'static>> {
        self.fixtures.blocks.get(&BlockHash::from(hash.0)).ok_or_else(|| {
            make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Block {hash} not found"))
        })
    }
}

fn make_rpc_error(code: i32, msg: String) -> ErrorObject<'static> {
    ErrorObject::owned(code, msg, None::<()>)
}

/// Invalid-params RPC error for a failed `params.parse()`.
fn invalid_params(e: impl std::fmt::Display) -> ErrorObject<'static> {
    make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}"))
}

fn shape_block(
    block: &Block<op_alloy_rpc_types::Transaction>,
    full_block: bool,
) -> Block<op_alloy_rpc_types::Transaction> {
    let mut out = block.clone();
    if !full_block {
        out.transactions = out.transactions.into_hashes();
    }
    out
}

/// Create a temporary ValidatorDB with the anchor set to the first block in test data.
///
/// The returned `TempDir` must be held by the caller for the test's lifetime —
/// dropping it removes the directory, including any redb journal/lock files.
fn setup_test_db(fx: &TestFixtures) -> eyre::Result<(Arc<ValidatorDB>, tempfile::TempDir)> {
    let temp_dir = tempfile::tempdir()?;
    let db = ValidatorDB::new(temp_dir.path().join(VALIDATOR_DB_FILENAME))?;

    let (block_num, block_hash) = fx.min_block();
    let block = &fx.blocks[&block_hash];
    let withdrawals_root = block
        .header
        .withdrawals_root
        .ok_or_else(|| eyre::eyre!("Block {block_hash} missing withdrawals_root"))?;

    let anchor = BlockMeta {
        block_number: block_num,
        block_hash,
        post_state_root: block.header.state_root,
        post_withdrawals_root: withdrawals_root,
    };
    db.reset_to_anchor(&anchor)?;

    Ok((Arc::new(db), temp_dir))
}

/// Start a mock RPC server backed by pre-loaded test fixtures.
async fn setup_mock_rpc_server(
    state: MockServerState,
) -> (jsonrpsee::server::ServerHandle, String) {
    let cfg = ServerConfigBuilder::default().max_response_body_size(MAX_RESPONSE_BODY_SIZE).build();
    serve_with_config(cfg, state, |module| {
        module
            .register_method("eth_getBlockByNumber", |params, ctx, _| {
                let (hex_number, full_block): (String, bool) =
                    params.parse().map_err(invalid_params)?;
                let block = ctx.block_by_number_hex(&hex_number)?;
                Ok::<_, ErrorObject<'static>>(shape_block(block, full_block))
            })
            .unwrap();

        module
            .register_method("eth_getBlockByHash", |params, ctx, _| {
                let (hash, full_block): (B256, bool) = params.parse().map_err(invalid_params)?;
                Ok::<_, ErrorObject<'static>>(shape_block(ctx.block_by_hash(hash)?, full_block))
            })
            .unwrap();

        module
            .register_method("eth_blockNumber", |_params, ctx, _| {
                let (&max_num, _) = ctx.fixtures.block_numbers.last_key_value().unwrap();
                Ok::<String, ErrorObjectOwned>(format!("0x{max_num:x}"))
            })
            .unwrap();

        module
            .register_method("eth_getHeaderByNumber", |params, ctx, _| {
                let (hex_number,): (String,) = params.parse().map_err(invalid_params)?;
                Ok::<_, ErrorObject<'static>>(ctx.block_by_number_hex(&hex_number)?.header.clone())
            })
            .unwrap();

        module
            .register_method("eth_getHeaderByHash", |params, ctx, _| {
                let (hash,): (B256,) = params.parse().map_err(invalid_params)?;
                Ok::<_, ErrorObject<'static>>(ctx.block_by_hash(hash)?.header.clone())
            })
            .unwrap();

        module
            .register_method("eth_getCodeByHash", |params, ctx, _| {
                let (hash,): (B256,) = params.parse().map_err(invalid_params)?;

                let code = ctx.fixtures.contracts.get(&hash).cloned().unwrap_or_default();
                Ok::<_, ErrorObject<'static>>(code.original_bytes())
            })
            .unwrap();

        module
            .register_method("mega_getBlockWitness", |params, ctx, _| {
                let (keys,): (WitnessRequestKeys,) = params.parse().map_err(invalid_params)?;
                let block_hash = BlockHash::from(keys.block_hash.0);

                let salt_witness =
                    ctx.fixtures.salt_witnesses.get(&block_hash).cloned().ok_or_else(|| {
                        make_rpc_error(
                            CALL_EXECUTION_FAILED_CODE,
                            format!("Witness for block {block_hash} not found"),
                        )
                    })?;

                let mpt_witness = ctx.mpt_witnesses.get(&block_hash).cloned().ok_or_else(|| {
                    make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Witness for block {block_hash} not found"),
                    )
                })?;

                let encoded =
                    encode_witness_response(&salt_witness, &mpt_witness).map_err(|e| {
                        make_rpc_error(
                            CALL_EXECUTION_FAILED_CODE,
                            format!("Failed to encode witness: {e}"),
                        )
                    })?;

                Ok::<_, ErrorObject<'static>>(encoded)
            })
            .unwrap();

        module
            .register_method("mega_setValidatedBlocks", |params, ctx, _| {
                use std::sync::atomic::Ordering;
                let (first_block, last_block): ((u64, String), (u64, String)) =
                    params.parse().unwrap();
                if ctx
                    .reject_reports
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
                {
                    return Err(make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        "transient report failure (scripted)".to_string(),
                    ));
                }
                ctx.validated_reports.lock().unwrap().push((first_block.0, last_block.0));
                let last_hash: BlockHash = last_block.1.parse().unwrap();
                Ok::<serde_json::Value, ErrorObjectOwned>(serde_json::json!({
                    "accepted": true,
                    "lastValidatedBlock": [last_block.0, last_hash]
                }))
            })
            .unwrap();
    })
    .await
}

/// Synthetic data integration test: validates consecutive blocks via the streaming pipeline.
#[tokio::test]
async fn integration_test() {
    let _logging = init_test_logging("stateless_validator");
    debug!("=== Loading Synthetic Test Data ===");
    let fx = TestFixtures::synthetic();
    let genesis_file = fx.data_dir.join("genesis.json");

    let max_block_number = fx.max_block().0;
    let sync_target = Some(max_block_number);
    let (validator_db, _tmp) = setup_test_db(&fx).unwrap();
    let contract_cache =
        Arc::new(ContractCache::new(Arc::clone(&validator_db) as Arc<dyn ContractStore>));
    let state = MockServerState::new(fx);
    let (handle, url) = setup_mock_rpc_server(state).await;
    let client = Arc::new(RpcClient::new(&[url.as_str()], &[url.as_str()]).unwrap());

    let chain_spec = Arc::new(
        load_or_create_chain_spec(&validator_db, Some(genesis_file.to_str().unwrap())).unwrap(),
    );

    // `#[non_exhaustive]` rules out struct-update syntax here; mutate a default.
    let mut cfg = PipelineConfig::default();
    cfg.concurrent_workers = 1;
    cfg.sync_target = sync_target;
    let config = Arc::new(cfg);

    let shutdown = CancellationToken::new();
    let fetcher = Arc::new(ValidatorFetcher { rpc_client: client.clone(), r2_witness: None });
    let processor = Arc::new(ValidatorProcessor { chain_spec, contract_cache, rpc_client: client });
    let hooks = Arc::new(ValidatorHooks);

    run_pipeline(
        fetcher,
        Arc::clone(&validator_db),
        processor,
        hooks,
        config,
        shutdown,
        BisectResolver,
    )
    .await
    .unwrap();

    // Verify all fixture blocks were validated and persisted — guards against silent
    // partial-advance failures where the pipeline returns Ok but the DB is short.
    assert_eq!(
        validator_db.get_canonical_tip().unwrap().unwrap().block_number,
        max_block_number,
        "expected validator DB tip to reach max fixture block",
    );

    handle.stop().unwrap();
    info!("Mock RPC server has been shut down");
}

/// Runs `run_with_signals` to the fixtures' max block (`--end-block` → `sync_target`) with
/// reports wired to the mock, failing the first `reject_first_reports` calls. Returns the run
/// result, the accepted reports, and the slice's end block.
async fn run_end_block_slice(
    reject_first_reports: usize,
) -> (eyre::Result<()>, Vec<(u64, u64)>, u64) {
    let fx = TestFixtures::synthetic();
    let genesis_file = fx.data_dir.join("genesis.json");

    let max_block_number = fx.max_block().0;
    let (validator_db, _tmp) = setup_test_db(&fx).unwrap();
    let contract_cache =
        Arc::new(ContractCache::new(Arc::clone(&validator_db) as Arc<dyn ContractStore>));
    let state = MockServerState::new(fx);
    let reports = Arc::clone(&state.validated_reports);
    state.reject_reports.store(reject_first_reports, std::sync::atomic::Ordering::SeqCst);
    let (handle, url) = setup_mock_rpc_server(state).await;
    let client = Arc::new(
        RpcClient::new_with_config(
            &[url.as_str()],
            &[url.as_str()],
            RpcClientConfig::validator(),
            Some(url.as_str()),
        )
        .unwrap(),
    );
    let chain_spec = Arc::new(
        load_or_create_chain_spec(&validator_db, Some(genesis_file.to_str().unwrap())).unwrap(),
    );

    let mut cfg = PipelineConfig::default();
    cfg.concurrent_workers = 1;
    cfg.sync_target = Some(max_block_number);

    let result = run_with_signals(
        client,
        None,
        Arc::clone(&validator_db),
        contract_cache,
        chain_spec,
        true,
        cfg,
    )
    .await;

    handle.stop().unwrap();

    let reports = reports.lock().unwrap().clone();
    (result, reports, max_block_number)
}

/// [`run_end_block_slice`] + asserts the run succeeded and the last accepted report covers the
/// end block; returns all accepted reports.
async fn run_end_block_slice_and_assert_tip_reported(
    reject_first_reports: usize,
) -> Vec<(u64, u64)> {
    let (result, reports, max_block_number) = run_end_block_slice(reject_first_reports).await;
    result.unwrap();

    let &(_, last_reported) =
        reports.last().expect("the run must report validated blocks before exiting");
    assert_eq!(
        last_reported, max_block_number,
        "the final report must cover the end block (got reports: {reports:?})",
    );
    reports
}

/// A fixed-range run must flush its final validated tip before exiting: the periodic reporter
/// is cancelled when the pipeline completes (its 1s tick rarely fires on a short slice) and a
/// slice run has no restart to re-report, so the final flush in `run_with_signals` is the only
/// path.
#[tokio::test]
async fn end_block_run_reports_final_tip() {
    // Logging is enabled only here and in `integration_test`: one representative run per mock
    // shape keeps the suite output readable — the scripted-failure twins would otherwise print
    // alarming ERROR lines that are just their test script.
    let _logging = init_test_logging("stateless_validator");
    run_end_block_slice_and_assert_tip_reported(0).await;
}

/// Like [`end_block_run_reports_final_tip`], but the mock rejects the first report call: the
/// final flush's bounded retry must still land the tip.
#[tokio::test]
async fn end_block_final_report_retries_after_transient_failure() {
    run_end_block_slice_and_assert_tip_reported(1).await;
}

/// If the final flush cannot land within its bounded retries, an `--end-block` slice run must
/// fail rather than exit 0: the slice has no later restart to re-report, so a clean exit would
/// let an orchestrator record the slice as complete while upstream never saw the tip.
#[tokio::test]
async fn end_block_run_fails_when_final_report_never_lands() {
    let (result, reports, _) = run_end_block_slice(usize::MAX).await;
    let err = result.expect_err("run must fail when the validated tail cannot be reported");
    assert!(err.to_string().contains("final validation report failed"), "{err}");
    assert!(reports.is_empty(), "mock rejected every report, yet some landed: {reports:?}");
}
