//! Integration tests for the stateless-validator binary crate.
//!
//! Covers CLI argument parsing and end-to-end pipeline validation against a mock RPC server.
//! Mainnet single-block validation is covered in `crates/stateless-core/src/executor.rs::tests`.

use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{B256, BlockHash};
use alloy_rpc_types_eth::Block;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use jsonrpsee::{
    RpcModule,
    server::{ServerBuilder, ServerConfigBuilder},
};
use jsonrpsee_types::error::{
    CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
};
use stateless_common::{RpcClient, WitnessRequestKeys};
use stateless_core::{
    ChainStore, ContractStore, PipelineConfig, db::BlockMeta, pipeline::run_pipeline,
    withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use stateless_test_utils::fixtures::TestFixtures;
use stateless_validator::{
    app::{CommandLineArgs, VALIDATOR_DB_FILENAME, load_or_create_chain_spec},
    chain_sync::{ValidatorFetcher, ValidatorHooks, ValidatorProcessor},
    validator_db::ValidatorDB,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

// ---- CLI argument-parsing tests ----

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

/// Verifies that a concurrency cap flag parses as `Some(n)` via CLI and env var,
/// and omission leaves the value `None` (unbounded).
fn assert_concurrency_flag(
    flag: &str,
    env: &str,
    base: &[&str],
    extract: impl Fn(CommandLineArgs) -> Option<usize>,
) {
    let guard = stateless_test_utils::env::env_lock();
    let parse = |extra: &[&str]| {
        extract(CommandLineArgs::try_parse_from(base.iter().chain(extra)).unwrap())
    };

    assert_eq!(parse(&[]), None);
    assert_eq!(parse(&[flag, "7"]), Some(7));

    let from_env = stateless_test_utils::env::with_env_var(&guard, env, "12", || parse(&[]));
    assert_eq!(from_env, Some(12));
}

#[test]
fn data_max_concurrent_requests_flag_and_env() {
    assert_concurrency_flag(
        "--data-max-concurrent-requests",
        "STATELESS_VALIDATOR_DATA_MAX_CONCURRENT_REQUESTS",
        &[
            "stateless-validator",
            "--data-dir",
            "/tmp/x",
            "--rpc-endpoint",
            "http://rpc",
            "--witness-endpoint",
            "http://w",
        ],
        |a| a.data_max_concurrent_requests,
    );
}

#[test]
fn witness_max_concurrent_requests_flag_and_env() {
    assert_concurrency_flag(
        "--witness-max-concurrent-requests",
        "STATELESS_VALIDATOR_WITNESS_MAX_CONCURRENT_REQUESTS",
        &[
            "stateless-validator",
            "--data-dir",
            "/tmp/x",
            "--rpc-endpoint",
            "http://rpc",
            "--witness-endpoint",
            "http://w",
        ],
        |a| a.witness_max_concurrent_requests,
    );
}

// ---- Synthetic-data pipeline integration test ----

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
            .iter()
            .map(|(hash, bytes)| {
                let (w, _): (MptWitness, _) =
                    bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
                        .unwrap_or_else(|e| panic!("decode MptWitness for {hash}: {e}"));
                (*hash, w)
            })
            .collect();
        Self { fixtures, mpt_witnesses }
    }
}

fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::new("warn").add_directive("stateless_validator=debug".parse().unwrap()),
        )
        .try_init();
}

fn make_rpc_error(code: i32, msg: String) -> ErrorObject<'static> {
    ErrorObject::owned(code, msg, None::<()>)
}

/// Create a temporary ValidatorDB with the anchor set to the first block in test data.
fn setup_test_db(fx: &TestFixtures) -> eyre::Result<Arc<ValidatorDB>> {
    let temp_dir = tempfile::tempdir()?;
    let db = ValidatorDB::new(temp_dir.path().join(VALIDATOR_DB_FILENAME))?;
    // Intentionally leak the temp dir — ValidatorDB holds a path into it.
    // The OS will clean it up when the test process exits.
    std::mem::forget(temp_dir);

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

    Ok(Arc::new(db))
}

/// Start a mock RPC server backed by pre-loaded test fixtures.
async fn setup_mock_rpc_server(
    state: MockServerState,
) -> (jsonrpsee::server::ServerHandle, String) {
    let mut module = RpcModule::new(state);

    module
        .register_method("eth_getBlockByNumber", |params, ctx, _| {
            let (hex_number, full_block): (String, bool) = params.parse().unwrap();
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

            let result_block = if full_block {
                block.clone()
            } else {
                Block { transactions: block.transactions.clone().into_hashes(), ..block.clone() }
            };
            Ok::<_, ErrorObject<'static>>(result_block)
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

            let encoded = bincode::serde::encode_to_vec(
                &(salt_witness, mpt_witness),
                bincode::config::legacy(),
            )
            .map_err(|e| {
                make_rpc_error(
                    CALL_EXECUTION_FAILED_CODE,
                    format!("Failed to serialize witness: {e}"),
                )
            })
            .and_then(|raw| {
                zstd::encode_all(raw.as_slice(), 9).map_err(|e| {
                    make_rpc_error(
                        CALL_EXECUTION_FAILED_CODE,
                        format!("Failed to compress witness: {e}"),
                    )
                })
            })
            .map(|compressed| format!("v0:{}", BASE64.encode(compressed)))?;

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

/// Synthetic data integration test: validates consecutive blocks via the streaming pipeline.
#[tokio::test]
async fn integration_test() {
    init_test_logging();
    debug!("=== Loading Synthetic Test Data ===");
    let fx = TestFixtures::synthetic();
    let genesis_file = fx.data_dir.join("genesis.json");

    let sync_target = Some(fx.max_block().0);
    let validator_db = setup_test_db(&fx).unwrap();
    let contract_cache =
        Arc::new(ContractCache::new(Arc::clone(&validator_db) as Arc<dyn ContractStore>));
    let state = MockServerState::new(fx);
    let (handle, url) = setup_mock_rpc_server(state).await;
    let client = Arc::new(RpcClient::new(&[url.as_str()], &[url.as_str()]).unwrap());

    let chain_spec = Arc::new(
        load_or_create_chain_spec(&validator_db, Some(genesis_file.to_str().unwrap())).unwrap(),
    );

    let config = Arc::new(PipelineConfig {
        concurrent_workers: 1,
        sync_target,
        ..PipelineConfig::default()
    });

    let shutdown = CancellationToken::new();
    let fetcher =
        Arc::new(ValidatorFetcher { rpc_client: client.clone(), on_remote_height: |_| {} });
    let processor = Arc::new(ValidatorProcessor { chain_spec, contract_cache, rpc_client: client });
    let hooks = Arc::new(ValidatorHooks);

    run_pipeline(fetcher, validator_db, processor, hooks, config, shutdown).await.unwrap();

    handle.stop().unwrap();
    info!("Mock RPC server has been shut down.");
}
