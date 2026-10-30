//! Integration tests for the stateless-validator binary crate.
//!
//! Covers CLI argument parsing and end-to-end pipeline validation against a mock RPC server.
//! Mainnet single-block validation is covered in `crates/stateless-core/src/executor.rs::tests`.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use alloy_primitives::{B256, BlockHash};
use alloy_rpc_types_eth::Block;
use clap::{CommandFactory, Parser};
use jsonrpsee::server::ServerConfigBuilder;
use jsonrpsee_types::error::{
    CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
};
use stateless_common::{
    BackoffPolicy, BlockRef, R2WitnessTransport, RpcClient, RpcClientConfig,
    SetValidatedChainResponse, WitnessRequestKeys, block_list::parse_block_list,
    encode_witness_payload, encode_witness_response,
};
use stateless_core::{
    BisectResolver, ChainStore, ContractStore, PipelineConfig,
    db::BlockMeta,
    pipeline::{BlockFetcher, run_pipeline},
    withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use stateless_test_utils::{
    fixtures::TestFixtures,
    logging::init_test_logging,
    mock_r2::mock_r2,
    mock_rpc::{parse_hex_u64, serve_with_config},
};
use stateless_validator::{
    CommandLineArgs, R2WitnessClient, VALIDATOR_DB_FILENAME, ValidatorDB, ValidatorFetcher,
    ValidatorHooks, ValidatorProcessor, load_or_create_chain_spec,
    replay::{self, BlockOutcome, ReplayConfig, Status},
    run_with_signals,
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
    // so that both binaries give the same verdict in the same words. Parsing therefore accepts all
    // of these shapes; the rules and their messages are covered by that function's own tests.
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

/// A blank value — what a templated env file renders for a variable a role does not set —
/// must reach the post-parse rules rather than clap, whose messages name no argument in this
/// workspace. `--r2-connections` travels as text for that reason;
/// `app::tests::r2_flags_are_validated_even_with_no_target_configured` covers the rejection.
#[test]
fn blank_r2_values_reach_the_post_parse_rules() {
    let _guard = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| CommandLineArgs::try_parse_from(BASE_ARGS.iter().chain(extra));

    for blank in [
        ["--r2-bucket", ""],
        ["--r2-custom-domain", ""],
        ["--r2-connections", ""],
        ["--r2-access-client-id", ""],
    ] {
        assert!(
            parse(&blank).is_ok(),
            "a blank {} must parse, so the rules can name it rather than clap",
            blank[0]
        );
    }
}

/// `--help` prints an env-backed flag's current value unless the flag sets `hide_env_values`,
/// so every secret `RedactedSecret` keeps out of `Debug` must stay out of the help text too.
#[test]
fn help_hides_r2_secret_values() {
    use stateless_test_utils::env::{env_lock, with_env_vars};
    let guard = env_lock();
    let vars = [
        ("STATELESS_VALIDATOR_R2_ACCESS_CLIENT_ID", "leaked-client-id"),
        ("STATELESS_VALIDATOR_R2_ACCESS_CLIENT_SECRET", "leaked-client-secret"),
        ("STATELESS_VALIDATOR_R2_SECRET_ACCESS_KEY", "leaked-secret-access-key"),
    ];
    // clap reads the env when the command is built, so build it with all three set.
    let help =
        with_env_vars(&guard, &vars, || CommandLineArgs::command().render_long_help().to_string());
    for (name, value) in vars {
        assert!(help.contains(name), "help must still name {name}");
        assert!(!help.contains(value), "help prints the value of {name}");
    }
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

/// `--block-list` replays sparse heights on its own: it excludes every flag that describes a
/// contiguous, chain-following run or reports upstream, needs the genesis named explicitly, and
/// its tuning flags are rejected without it rather than inherited and ignored.
#[test]
fn block_list_flag_combinations() {
    // The conflict rules read the environment too: hold the lock so a test that has
    // `STATELESS_VALIDATOR_END_BLOCK` (or another conflicting variable) set cannot leak into
    // these parses.
    let _env = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| CommandLineArgs::try_parse_from(BASE_ARGS.iter().chain(extra));
    let with_list = ["--block-list", "/tmp/pool.txt", "--genesis-file", "/tmp/genesis.json"];

    let args = parse(&with_list).unwrap();
    assert_eq!(args.block_list.as_deref(), Some(std::path::Path::new("/tmp/pool.txt")));
    assert_eq!(parse(&[]).unwrap().block_list, None);

    let tuned = parse(
        &[
            &with_list[..],
            &[
                "--block-list-timeout-secs",
                "9",
                "--block-list-concurrency",
                "3",
                "--block-list-output-dir",
                "/tmp/out",
            ],
        ]
        .concat(),
    )
    .unwrap();
    assert_eq!(tuned.block_list_timeout_secs, 9);
    // Unset, the timeout is the documented 300 s. That default does not count as setting the
    // flag, or `parse(&[])` above would have failed its `requires`.
    assert_eq!(parse(&with_list).unwrap().block_list_timeout_secs, 300);
    assert_eq!(tuned.block_list_concurrency, Some(3));

    // A stale genesis in the data dir must not be picked up silently.
    assert!(parse(&["--block-list", "/tmp/pool.txt"]).is_err(), "genesis file is required");
    // Chain-following and reporting flags cannot be combined with a sparse replay.
    for conflicting in [
        &["--start-block", TRUSTED_HASH][..],
        &["--force-anchor"][..],
        &["--end-block", "10"][..],
        &["--report-validation-endpoint", "http://report"][..],
    ] {
        let argv = [&with_list[..], conflicting].concat();
        assert!(parse(&argv).is_err(), "{conflicting:?} must conflict with --block-list");
    }
    // Zero would time every block out on its first poll, or never start one.
    for zero in [&["--block-list-timeout-secs", "0"][..], &["--block-list-concurrency", "0"][..]] {
        let argv = [&with_list[..], zero].concat();
        assert!(parse(&argv).is_err(), "{zero:?} must be rejected");
    }
    // Tuning flags mean nothing without a list.
    for orphan in [
        &["--block-list-timeout-secs", "9"][..],
        &["--block-list-concurrency", "3"][..],
        &["--block-list-output-dir", "/tmp/out"][..],
    ] {
        assert!(parse(orphan).is_err(), "{orphan:?} must require --block-list");
    }
}

/// A well-formed block hash, for flags that only need one to parse.
const TRUSTED_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

/// `--start-block` is a block hash, checked when the flags are parsed, and `--force-anchor` is
/// a plain switch; both bind their documented env vars. Which combinations a data dir accepts
/// is decided at startup against the stored chain (`anchor::startup_action`).
#[test]
fn anchor_flags_parse() {
    let guard = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| CommandLineArgs::try_parse_from(BASE_ARGS.iter().chain(extra));

    let args = parse(&["--start-block", TRUSTED_HASH, "--force-anchor"]).unwrap();
    assert_eq!(args.start_block, Some(TRUSTED_HASH.parse().unwrap()));
    assert!(args.force_anchor);
    let args = parse(&[]).unwrap();
    assert_eq!((args.start_block, args.force_anchor), (None, false));
    assert!(parse(&["--start-block", "0x01"]).is_err(), "a start block must be a full hash");

    let from_env = stateless_test_utils::env::with_env_vars(
        &guard,
        &[
            ("STATELESS_VALIDATOR_START_BLOCK", TRUSTED_HASH),
            ("STATELESS_VALIDATOR_FORCE_ANCHOR", "true"),
        ],
        || parse(&[]).unwrap(),
    );
    assert_eq!(from_env.start_block, Some(TRUSTED_HASH.parse().unwrap()));
    assert!(from_env.force_anchor);
}

const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

/// Mock RPC server backing state: all fields pre-decoded so the RPC handlers can respond
/// synchronously. Wraps [`TestFixtures`] and pre-decodes MPT witnesses once.
struct MockServerState {
    fixtures: &'static TestFixtures,
    mpt_witnesses: HashMap<BlockHash, MptWitness>,
    /// Every *accepted* `mega_setValidatedChain` call, as `(anchor, validated)` numbers.
    validated_reports: Arc<Mutex<Vec<(u64, u64)>>>,
    /// Number of upcoming `mega_setValidatedChain` calls to reject with an RPC error.
    reject_reports: Arc<AtomicUsize>,
    /// Number of upcoming `mega_setValidatedChain` calls to refuse with `accepted: false`, as a
    /// receiver that does not hold the reported blocks yet answers.
    refuse_reports: Arc<AtomicUsize>,
    /// Every `mega_getBlockWitness` call, so a test can tell whether the RPC witness path was
    /// used at all.
    witness_requests: Arc<AtomicUsize>,
    /// Requested block number → the number whose block is served instead, to script an
    /// endpoint that answers a by-number lookup with the wrong block.
    number_aliases: HashMap<u64, u64>,
}

impl MockServerState {
    fn new(fixtures: &'static TestFixtures) -> Self {
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
            refuse_reports: Arc::default(),
            witness_requests: Arc::default(),
            number_aliases: HashMap::new(),
        }
    }

    /// Fixture block for a `0x…` hex block number, or the RPC error the handlers return
    /// for unknown blocks. Shared by the by-number block and header handlers.
    fn block_by_number_hex(
        &self,
        hex_number: &str,
    ) -> Result<&Block<op_alloy_rpc_types::Transaction>, ErrorObject<'static>> {
        let requested = parse_hex_u64(hex_number);
        let block_number = self.number_aliases.get(&requested).copied().unwrap_or(requested);
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

    let (_, block_hash) = fx.min_block();
    let anchor = BlockMeta::try_from_header(&fx.blocks[&block_hash].header)
        .ok_or_else(|| eyre::eyre!("Block {block_hash} missing withdrawals_root"))?;
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
                let (hex_number, full_block): (String, bool) = params.parse()?;
                let block = ctx.block_by_number_hex(&hex_number)?;
                Ok::<_, ErrorObject<'static>>(shape_block(block, full_block))
            })
            .unwrap();

        module
            .register_method("eth_getBlockByHash", |params, ctx, _| {
                let (hash, full_block): (B256, bool) = params.parse()?;
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
                let (hex_number,): (String,) = params.parse()?;
                Ok::<_, ErrorObject<'static>>(ctx.block_by_number_hex(&hex_number)?.header.clone())
            })
            .unwrap();

        module
            .register_method("eth_getHeaderByHash", |params, ctx, _| {
                let (hash,): (B256,) = params.parse()?;
                Ok::<_, ErrorObject<'static>>(ctx.block_by_hash(hash)?.header.clone())
            })
            .unwrap();

        module
            .register_method("eth_getCodeByHash", |params, ctx, _| {
                let (hash,): (B256,) = params.parse()?;

                let code = ctx.fixtures.contracts.get(&hash).cloned().unwrap_or_default();
                Ok::<_, ErrorObject<'static>>(code.original_bytes())
            })
            .unwrap();

        module
            .register_method("mega_getBlockWitness", |params, ctx, _| {
                ctx.witness_requests.fetch_add(1, Ordering::SeqCst);
                let (keys,): (WitnessRequestKeys,) = params.parse()?;
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

        // The receiver's contract: `anchor < validated` or invalid params, and both blocks on
        // its canonical chain (here: the fixtures) or `accepted: false` with nothing recorded.
        module
            .register_method("mega_setValidatedChain", |params, ctx, _| {
                let (anchor, validated): (BlockRef, BlockRef) = params.parse()?;
                let take = |counter: &AtomicUsize| {
                    counter
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                };
                if take(&ctx.reject_reports) {
                    return Err(make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        "transient report failure (scripted)".to_string(),
                    ));
                }
                if anchor.block_number >= validated.block_number {
                    return Err(make_rpc_error(INVALID_PARAMS_CODE, "anchor >= validated".into()));
                }
                let canonical = |block: &BlockRef| {
                    ctx.fixtures.block_numbers.get(&block.block_number.to()) ==
                        Some(&block.block_hash)
                };
                if take(&ctx.refuse_reports) || !canonical(&anchor) || !canonical(&validated) {
                    return Ok(SetValidatedChainResponse {
                        accepted: false,
                        anchor: None,
                        validated: None,
                    });
                }
                ctx.validated_reports
                    .lock()
                    .unwrap()
                    .push((anchor.block_number.to(), validated.block_number.to()));
                Ok::<_, ErrorObject<'static>>(SetValidatedChainResponse {
                    accepted: true,
                    anchor: Some(anchor),
                    validated: Some(validated),
                })
            })
            .unwrap();
    })
    .await
}

/// A [`ValidatorFetcher`] over the mock RPC (blocks, hashes, and the RPC witness path) with an
/// [`R2WitnessClient`] on `r2_endpoint` in front of it, plus the mock's RPC witness request
/// counter. Uses the synthetic fixtures' first paired block as the block under fetch.
async fn r2_backed_fetcher(
    r2_endpoint: &str,
) -> (ValidatorFetcher, Arc<AtomicUsize>, jsonrpsee::server::ServerHandle) {
    let state = MockServerState::new(TestFixtures::synthetic_shared());
    let witness_requests = Arc::clone(&state.witness_requests);
    let (handle, url) = setup_mock_rpc_server(state).await;
    let client = Arc::new(RpcClient::new(&[url.as_str()], &[url.as_str()]).unwrap());
    let transport = R2WitnessTransport::new(
        r2_endpoint,
        "witness-test".to_string(),
        "ak".to_string(),
        "sk".to_string(),
        stateless_r2::fetch::FetchTimeouts {
            per_attempt: Duration::from_secs(5),
            connect: stateless_r2::fetch::DEFAULT_CONNECT_TIMEOUT,
        },
        BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(5)),
        None,
    )
    .unwrap();
    let r2 = Arc::new(R2WitnessClient::new(transport, Duration::from_secs(5)));
    (ValidatorFetcher::new(client, Some(r2)), witness_requests, handle)
}

/// The synthetic fixtures' first paired block number: the block every R2 fetcher test fetches.
fn first_paired_block() -> u64 {
    TestFixtures::synthetic_shared().paired_blocks()[0].0
}

/// That block's witness encoded as the R2 object body (the uploader's wire format), for the
/// one test in which R2 actually serves it.
fn first_paired_r2_payload() -> Vec<u8> {
    let (salt_witness, mpt_witness): (_, MptWitness) =
        TestFixtures::synthetic_shared().first_paired_witness();
    encode_witness_payload(&salt_witness, &mpt_witness).expect("fixture witness must encode").1
}

/// With an R2 target configured, a block whose witness is in the bucket is served from R2
/// alone: one GET, and the RPC witness path is never asked.
#[tokio::test]
async fn a_bucket_hit_is_served_without_touching_the_rpc_witness_path() {
    let number = first_paired_block();
    let (r2_endpoint, r2_hits) = mock_r2(vec![(200, first_paired_r2_payload())]).await;
    let (fetcher, witness_requests, handle) = r2_backed_fetcher(&r2_endpoint).await;

    let task = fetcher.fetch(number).await.expect("R2 must serve the block");
    assert_eq!(task.block.header.number, number);
    assert_eq!(r2_hits.load(Ordering::SeqCst), 1, "exactly one R2 GET");
    assert_eq!(witness_requests.load(Ordering::SeqCst), 0, "RPC witness path must stay idle");
    handle.stop().unwrap();
}

/// An R2 miss (the uploader has not reached the block) hands it to the RPC witness path
/// instead of failing the fetch: one R2 GET, one RPC witness call, and the task still carries
/// the witness.
#[tokio::test]
async fn an_r2_miss_falls_back_to_the_rpc_witness_path() {
    let number = first_paired_block();
    let (r2_endpoint, r2_hits) = mock_r2(vec![(404, "<Code>NoSuchKey</Code>")]).await;
    let (fetcher, witness_requests, handle) = r2_backed_fetcher(&r2_endpoint).await;

    let task = fetcher.fetch(number).await.expect("RPC must serve after the R2 miss");
    assert_eq!(task.block.header.number, number);
    assert_eq!(r2_hits.load(Ordering::SeqCst), 1, "a miss is not retried against R2");
    assert_eq!(witness_requests.load(Ordering::SeqCst), 1, "the RPC witness path took over");
    handle.stop().unwrap();
}

/// Synthetic data integration test: validates consecutive blocks via the streaming pipeline.
#[tokio::test]
async fn integration_test() {
    let _logging = init_test_logging("stateless_validator");
    debug!("=== Loading Synthetic Test Data ===");
    let fx = TestFixtures::synthetic_shared();
    let genesis_file = fx.data_dir.join("genesis.json");

    let max_block_number = fx.max_block().0;
    let sync_target = Some(max_block_number);
    let (validator_db, _tmp) = setup_test_db(fx).unwrap();
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
    let fetcher = Arc::new(ValidatorFetcher::new(client.clone(), None));
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

/// How the mock receiver answers the first report calls of a slice run.
#[derive(Clone, Copy)]
enum FirstReports {
    /// Fail this many with an RPC error.
    Fail(usize),
    /// Refuse this many with `accepted: false`.
    Refuse(usize),
}

/// Runs `run_with_signals` to the fixtures' max block (`--end-block` → `sync_target`) with
/// reports wired to the mock, which answers the first ones as `first` scripts. Returns the run
/// result, the accepted reports, and the slice's anchor and end block.
async fn run_end_block_slice(
    first: FirstReports,
) -> (eyre::Result<()>, Vec<(u64, u64)>, (u64, u64)) {
    let fx = TestFixtures::synthetic_shared();
    let genesis_file = fx.data_dir.join("genesis.json");

    let max_block_number = fx.max_block().0;
    let (validator_db, _tmp) = setup_test_db(fx).unwrap();
    let contract_cache =
        Arc::new(ContractCache::new(Arc::clone(&validator_db) as Arc<dyn ContractStore>));
    let state = MockServerState::new(fx);
    let reports = Arc::clone(&state.validated_reports);
    match first {
        FirstReports::Fail(n) => state.reject_reports.store(n, Ordering::SeqCst),
        FirstReports::Refuse(n) => state.refuse_reports.store(n, Ordering::SeqCst),
    }
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

    let result =
        run_with_signals(client, None, Arc::clone(&validator_db), contract_cache, chain_spec, cfg)
            .await;

    handle.stop().unwrap();

    let reports = reports.lock().unwrap().clone();
    (result, reports, (fx.min_block().0, max_block_number))
}

/// [`run_end_block_slice`] + asserts the run succeeded and the last accepted report is the whole
/// validated chain, from the anchor to the end block; returns all accepted reports.
async fn run_end_block_slice_and_assert_tip_reported(first: FirstReports) -> Vec<(u64, u64)> {
    let (result, reports, chain) = run_end_block_slice(first).await;
    result.unwrap();

    let &last_reported =
        reports.last().expect("the run must report validated blocks before exiting");
    assert_eq!(
        last_reported, chain,
        "the final report must be (anchor, end block) (got reports: {reports:?})",
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
    // shape. The scripted-failure twins stay silent, since their ERROR lines are just their
    // test script.
    let _logging = init_test_logging("stateless_validator");
    run_end_block_slice_and_assert_tip_reported(FirstReports::Fail(0)).await;
}

/// Like [`end_block_run_reports_final_tip`], but the mock fails the first report call, or
/// refuses it as a receiver that does not hold the blocks yet does: the final flush's bounded
/// retry must still land the tip.
#[tokio::test]
async fn end_block_final_report_retries_after_transient_failure() {
    run_end_block_slice_and_assert_tip_reported(FirstReports::Fail(1)).await;
    run_end_block_slice_and_assert_tip_reported(FirstReports::Refuse(1)).await;
}

/// If the final flush cannot land within its bounded retries, an `--end-block` slice run must
/// fail rather than exit 0: the slice has no later restart to re-report, so a clean exit would
/// let an orchestrator record the slice as complete while upstream never saw the tip. A
/// receiver that keeps refusing the chain is no different from one that keeps failing.
#[tokio::test]
async fn end_block_run_fails_when_final_report_never_lands() {
    for first in [FirstReports::Fail(usize::MAX), FirstReports::Refuse(usize::MAX)] {
        let (result, reports, _) = run_end_block_slice(first).await;
        let err = result.expect_err("run must fail when the validated tail cannot be reported");
        assert!(err.to_string().contains("final validation report failed"), "{err}");
        assert!(reports.is_empty(), "mock answered no report, yet some landed: {reports:?}");
    }
}

/// A validator-shaped fetcher and processor over `url`, with their DB in `dir`. The DB has no
/// anchor: block-list mode never needs one.
fn block_list_parts(
    dir: &std::path::Path,
    url: &str,
) -> (Arc<ValidatorFetcher>, Arc<ValidatorProcessor>) {
    let genesis_file = TestFixtures::synthetic_shared().data_dir.join("genesis.json");
    let validator_db = Arc::new(ValidatorDB::new(dir.join(VALIDATOR_DB_FILENAME)).unwrap());
    let contract_cache =
        Arc::new(ContractCache::new(Arc::clone(&validator_db) as Arc<dyn ContractStore>));
    let chain_spec = Arc::new(
        load_or_create_chain_spec(&validator_db, Some(genesis_file.to_str().unwrap())).unwrap(),
    );
    let client = Arc::new(RpcClient::new(&[url], &[url]).unwrap());
    let fetcher = Arc::new(ValidatorFetcher::new(client.clone(), None));
    let processor = Arc::new(ValidatorProcessor { chain_spec, contract_cache, rpc_client: client });
    (fetcher, processor)
}

/// Replays `blocks` over the mock RPC, returning the outcomes in completion order and the
/// summary. One block validates at a time whatever `concurrency` is, so a run with more blocks
/// in flight than validate slots also exercises the wait for a slot.
async fn replay_over_mock(
    blocks: Vec<u64>,
    block_timeout: Duration,
    concurrency: usize,
    number_aliases: HashMap<u64, u64>,
) -> (Vec<BlockOutcome>, replay::ReplaySummary) {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut state = MockServerState::new(TestFixtures::synthetic_shared());
    state.number_aliases = number_aliases;
    let (handle, url) = setup_mock_rpc_server(state).await;
    let (fetcher, processor) = block_list_parts(temp_dir.path(), &url);

    let config = ReplayConfig { concurrency, validate_concurrency: 1, block_timeout };
    let mut outcomes = Vec::new();
    let summary = replay::replay_block_list(fetcher, processor, blocks, &config, |outcome| {
        outcomes.push(outcome.clone());
        Ok(())
    })
    .await
    .unwrap();

    handle.stop().unwrap();
    (outcomes, summary)
}

/// A sparse subset of the fixtures replays through the production fetch and validate path:
/// every listed block is visited once, in any order, and nothing outside the list is touched.
#[tokio::test]
async fn block_list_replays_a_non_contiguous_subset() {
    let fx = TestFixtures::synthetic_shared();
    let every_other: Vec<u64> = fx.paired_blocks().into_iter().map(|(n, _)| n).step_by(2).collect();
    assert!(every_other.len() >= 2, "the fixtures need at least three blocks to leave a gap");
    let all: Vec<u64> = fx.paired_blocks().into_iter().map(|(n, _)| n).collect();
    assert!(every_other.len() < all.len(), "the subset must skip some block");

    let (outcomes, summary) =
        replay_over_mock(every_other.clone(), Duration::from_secs(60), 4, HashMap::new()).await;

    let mut seen: Vec<u64> = outcomes.iter().map(|o| o.number).collect();
    seen.sort_unstable();
    assert_eq!(seen, every_other, "exactly the listed blocks, each once");
    for outcome in &outcomes {
        assert_eq!(
            outcome.status,
            Status::Validated,
            "block {} should validate: {:?}",
            outcome.number,
            outcome.message
        );
        assert_eq!(outcome.hash, Some(fx.block_numbers[&outcome.number]));
    }
    assert_eq!(
        (summary.total, summary.validated(), summary.failed.len()),
        (seen.len(), seen.len(), 0)
    );
}

/// A block no endpoint can serve is retried forever by the RPC client; the per-block timeout is
/// what ends it. It must be recorded as `fetch_timeout`, listed for retry, and not stop the run:
/// with a single slot and the failing block first, the blocks behind it only run if a failure
/// frees the slot and the run carries on.
#[tokio::test]
async fn an_unfetchable_block_times_out_without_stopping_the_run() {
    let fx = TestFixtures::synthetic_shared();
    let paired: Vec<u64> = fx.paired_blocks().into_iter().map(|(n, _)| n).collect();
    let (first, last) = (paired[0], *paired.last().unwrap());
    let missing = fx.max_block().0 + 1_000;

    let (outcomes, summary) =
        replay_over_mock(vec![missing, first, last], Duration::from_secs(2), 1, HashMap::new())
            .await;

    let status_of =
        |n: u64| outcomes.iter().find(|o| o.number == n).map(|o| o.status).expect("outcome");
    assert_eq!(status_of(first), Status::Validated);
    assert_eq!(status_of(last), Status::Validated);
    assert_eq!(status_of(missing), Status::FetchTimeout);
    // A timeout says nothing about the block, so it is marked for retry; a pass never is.
    for outcome in &outcomes {
        assert_eq!(outcome.retryable, outcome.number == missing, "{outcome:?}");
    }
    assert_eq!((summary.total, summary.validated(), summary.failed.len()), (3, 2, 1));
    assert_eq!(
        parse_block_list(&summary.failed_list()).unwrap(),
        vec![missing],
        "the retry list names exactly the block that did not validate",
    );
}

/// An endpoint that answers the lookup for one height with another height's block must not turn
/// into a pass for the height that was asked for. The RPC client refuses such a header and keeps
/// retrying, so the block ends as `fetch_timeout`; the block served in its place is never
/// validated on its behalf.
#[tokio::test]
async fn a_block_served_for_the_wrong_height_is_not_counted_as_validated() {
    let fx = TestFixtures::synthetic_shared();
    let paired: Vec<u64> = fx.paired_blocks().into_iter().map(|(n, _)| n).collect();
    let (asked, served) = (paired[0], *paired.last().unwrap());
    assert_ne!(asked, served);

    let (outcomes, summary) =
        replay_over_mock(vec![asked], Duration::from_secs(2), 1, HashMap::from([(asked, served)]))
            .await;

    let [outcome] = outcomes.as_slice() else { panic!("one outcome expected: {outcomes:?}") };
    assert_eq!(outcome.status, Status::FetchTimeout, "{outcome:?}");
    assert_eq!(outcome.hash, None, "no block was accepted for the height");
    assert_eq!((summary.validated(), summary.failed.len()), (0, 1));
}

/// The chain-head read before the first block retries forever like every RPC call, so it is
/// bounded by the per-block timeout: an unreachable endpoint fails the run instead of hanging it.
/// That failure, like any interruption, must not leave the previous run's retry list beside this
/// run's results, where it would be passed back as `--block-list` in place of this run's.
#[tokio::test]
async fn an_unreachable_head_fails_the_run_without_a_stale_retry_list() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dir = temp_dir.path();
    // Nothing listens on port 1, so every attempt is refused and retried.
    let (fetcher, processor) = block_list_parts(dir, "http://127.0.0.1:1");

    let list = dir.join("list.txt");
    let results = dir.join(replay::RESULTS_FILE);
    let failed = dir.join(replay::RETRY_FILE);
    std::fs::write(&list, "1\n2\n").unwrap();
    // What a previous run left behind.
    std::fs::write(&results, "{\"block\":5}\n").unwrap();
    std::fs::write(&failed, "5\n9\n").unwrap();

    let config = ReplayConfig {
        concurrency: 2,
        validate_concurrency: 1,
        block_timeout: Duration::from_secs(1),
    };
    let err = tokio::time::timeout(
        Duration::from_secs(30),
        replay::run(&list, dir, fetcher, processor, &config),
    )
    .await
    .expect("the head read must be bounded")
    .unwrap_err();

    assert!(format!("{err:#}").contains("chain head"), "{err:#}");
    assert_eq!(std::fs::read_to_string(&results).unwrap(), "", "results are truncated");
    let retry = std::fs::read_to_string(&failed).unwrap();
    assert!(parse_block_list(&retry).unwrap().is_empty(), "stale retry list left: {retry:?}");
}
