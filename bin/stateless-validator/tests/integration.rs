//! Integration tests for the stateless-validator binary crate.
//!
//! Covers CLI argument parsing and end-to-end pipeline validation against a mock RPC server.
//! Mainnet single-block validation is covered in `crates/stateless-core/src/executor.rs::tests`.

use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{B256, BlockHash};
use alloy_rpc_types_eth::Block;
use clap::Parser;
use jsonrpsee::{
    RpcModule,
    server::{ServerBuilder, ServerConfigBuilder},
};
use jsonrpsee_types::error::{
    CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
};
use stateless_common::{RpcClient, WitnessRequestKeys, encode_witness_response};
use stateless_core::{
    BisectResolver, BlockValidator, ChainStore, ContractStore, MegaEvmValidator, PipelineConfig,
    chain_spec::ChainSpec,
    db::BlockMeta,
    pipeline::{BlockFetcher, run_pipeline},
    withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use stateless_test_utils::{fixtures::TestFixtures, logging::init_test_logging};
#[cfg(feature = "kona")]
use stateless_validator::KonaValidator;
use stateless_validator::{
    CommandLineArgs, VALIDATOR_DB_FILENAME, ValidatorDB, ValidatorFetcher, ValidatorHooks,
    ValidatorProcessor, load_or_create_chain_spec,
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
        &["stateless-validator", "--data-dir", "/tmp/x", "--rpc-endpoint", "http://rpc"],
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
fn tip_buffer_flag_and_env() {
    assert_optional_numeric_flag::<u64>("--tip-buffer", "STATELESS_VALIDATOR_TIP_BUFFER", |a| {
        a.tip_buffer
    });
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

#[cfg(feature = "kona")]
#[test]
fn kona_validator_binary_exposes_cli() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kona-validator"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "kona-validator --help failed: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Usage: kona-validator"), "unexpected help output: {stdout}");
}

const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

/// Mock RPC server backing state: all fields pre-decoded so the RPC handlers can respond
/// synchronously. Wraps [`TestFixtures`] and pre-decodes MPT witnesses once.
struct MockServerState {
    fixtures: TestFixtures,
    mpt_witnesses: HashMap<BlockHash, MptWitness>,
}

impl MockServerState {
    fn new(fixtures: TestFixtures) -> Self {
        let mpt_witnesses = fixtures
            .mpt_witness_bytes
            .keys()
            .map(|hash| (*hash, fixtures.mpt_witness(hash)))
            .collect();
        Self { fixtures, mpt_witnesses }
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
    let mut module = RpcModule::new(state);

    module
        .register_method("eth_getBlockByNumber", |params, ctx, _| {
            let (hex_number, full_block): (String, bool) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;
            let block_number = u64::from_str_radix(&hex_number[2..], 16).unwrap_or(0);

            let block = ctx
                .fixtures
                .block_numbers
                .get(&block_number)
                .and_then(|hash| ctx.fixtures.blocks.get(hash))
                .ok_or_else(|| {
                    make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Block {block_number} not found"),
                    )
                })?;

            Ok::<_, ErrorObject<'static>>(shape_block(block, full_block))
        })
        .unwrap();

    module
        .register_method("eth_getBlockByHash", |params, ctx, _| {
            let (hash, full_block): (B256, bool) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;

            let block_hash = BlockHash::from(hash.0);
            let block = ctx.fixtures.blocks.get(&block_hash).ok_or_else(|| {
                make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Block {hash} not found"))
            })?;

            Ok::<_, ErrorObject<'static>>(shape_block(block, full_block))
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
            let (hex_number,): (String,) = params.parse().unwrap();
            let block_number = u64::from_str_radix(&hex_number[2..], 16).unwrap_or(0);

            let block = ctx
                .fixtures
                .block_numbers
                .get(&block_number)
                .and_then(|hash| ctx.fixtures.blocks.get(hash))
                .ok_or_else(|| {
                    make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Block {block_number} not found"),
                    )
                })?;

            Ok::<_, ErrorObject<'static>>(block.header.clone())
        })
        .unwrap();

    module
        .register_method("eth_getHeaderByHash", |params, ctx, _| {
            let (hash,): (B256,) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;

            let block_hash = BlockHash::from(hash.0);
            let block = ctx.fixtures.blocks.get(&block_hash).ok_or_else(|| {
                make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Block {hash} not found"))
            })?;

            Ok::<_, ErrorObject<'static>>(block.header.clone())
        })
        .unwrap();

    module
        .register_method("eth_getCodeByHash", |params, ctx, _| {
            let (hash,): (B256,) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;

            let code = ctx.fixtures.contracts.get(&hash).cloned().unwrap_or_default();
            Ok::<_, ErrorObject<'static>>(code.original_bytes())
        })
        .unwrap();

    module
        .register_method("mega_getBlockWitness", |params, ctx, _| {
            let (keys,): (WitnessRequestKeys,) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;
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

            let encoded = encode_witness_response(&salt_witness, &mpt_witness).map_err(|e| {
                make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Failed to encode witness: {e}"))
            })?;

            Ok::<_, ErrorObject<'static>>(encoded)
        })
        .unwrap();

    module
        .register_method("mega_setValidatedBlocks", |params, _ctx, _| {
            let (_first_block, last_block): ((u64, String), (u64, String)) =
                params.parse().unwrap();
            let last_hash: BlockHash = last_block.1.parse().unwrap();
            Ok::<serde_json::Value, ErrorObjectOwned>(serde_json::json!({
                "accepted": true,
                "lastValidatedBlock": [last_block.0, last_hash]
            }))
        })
        .unwrap();

    let cfg = ServerConfigBuilder::default().max_response_body_size(MAX_RESPONSE_BODY_SIZE).build();
    let server = ServerBuilder::default().set_config(cfg).build("0.0.0.0:0").await.unwrap();
    let url = format!("http://{}", server.local_addr().unwrap());
    (server.start(module), url)
}

#[tokio::test]
async fn kona_fetcher_includes_parent_header() {
    let fx = TestFixtures::synthetic();
    let (block_number, block_hash) = fx
        .paired_blocks()
        .into_iter()
        .find(|(_, hash)| fx.blocks.contains_key(&fx.blocks[hash].header.parent_hash))
        .expect("fixture block with local parent");
    let state = MockServerState::new(fx);
    let (handle, url) = setup_mock_rpc_server(state).await;
    let client = Arc::new(RpcClient::new(&[url.as_str()], &[url.as_str()]).unwrap());
    let fetcher = ValidatorFetcher {
        rpc_client: client,
        on_remote_height: |_| {},
        fetch_parent_header: true,
    };

    let task = fetcher.fetch(block_number).await.unwrap();
    let parent_header = task.parent_header.expect("Kona fetcher should fetch parent header");

    assert_eq!(task.block.header.hash, block_hash);
    assert_eq!(parent_header.hash_slow(), task.block.header.parent_hash);

    // The disabled half of the switch: the default (MegaEVM) backend must not request the
    // extra header RPC, and a regression to always-fetch should fail here. Derive the flag
    // from a real MegaEvmValidator exactly like the production wiring does.
    let chain_spec = ChainSpec::from_genesis(
        TestFixtures::synthetic().load_genesis().expect("synthetic genesis"),
    );
    let mega_validator = MegaEvmValidator::new(chain_spec);
    let fetcher = ValidatorFetcher {
        rpc_client: Arc::clone(&fetcher.rpc_client),
        on_remote_height: |_| {},
        fetch_parent_header:
            BlockValidator::<Block<op_alloy_rpc_types::Transaction>>::requires_parent_header(
                &mega_validator,
            ),
    };
    let task = fetcher.fetch(block_number).await.unwrap();
    assert!(task.parent_header.is_none(), "parent header must not be fetched when disabled");

    handle.stop().unwrap();
}

/// Synthetic data integration test: validates consecutive blocks via the streaming pipeline.
async fn run_integration_test_with_validator<V, E>(
    validator_name: &str,
    make_validator: impl FnOnce(&ChainSpec) -> Result<V, E>,
) where
    E: std::fmt::Debug,
    V: BlockValidator<Block<op_alloy_rpc_types::Transaction>> + Send + Sync + 'static,
{
    let _logging = init_test_logging("stateless_validator");
    debug!("=== Loading Synthetic Test Data for {validator_name} ===");
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

    let chain_spec =
        load_or_create_chain_spec(&validator_db, Some(genesis_file.to_str().unwrap())).unwrap();

    // `#[non_exhaustive]` rules out struct-update syntax here; mutate a default.
    let mut cfg = PipelineConfig::default();
    cfg.concurrent_workers = 1;
    cfg.sync_target = sync_target;
    let config = Arc::new(cfg);

    let shutdown = CancellationToken::new();
    let validator = Arc::new(make_validator(&chain_spec).unwrap());
    // Same derivation as production wiring in `workers::run_with_signals`.
    let fetcher = Arc::new(ValidatorFetcher {
        rpc_client: client.clone(),
        on_remote_height: |_| {},
        fetch_parent_header: validator.requires_parent_header(),
    });
    let processor = Arc::new(ValidatorProcessor { validator, contract_cache, rpc_client: client });
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
        "expected {validator_name} validator DB tip to reach max fixture block",
    );

    handle.stop().unwrap();
    info!("Mock RPC server has been shut down for {validator_name}");
}

#[tokio::test]
async fn integration_test_mega_evm_validator() {
    run_integration_test_with_validator("MegaEVM", |chain_spec| {
        Ok::<_, std::convert::Infallible>(MegaEvmValidator::new(chain_spec.clone()))
    })
    .await;
}

#[cfg(feature = "kona")]
#[tokio::test]
async fn integration_test_kona_validator() {
    run_integration_test_with_validator("Kona", KonaValidator::new).await;
}
