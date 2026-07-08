//! Replays every mainnet fixture block through the exact execution path the
//! coverage worker uses (LightWitness → WitnessDatabase → replay_block) and
//! checks the gas/receipts-root/logs-bloom sanity triple against the header.
//!
//! Runs uninstrumented — it guards the replay glue in normal CI; coverage
//! capture itself is exercised by the instrumented E2E runs.

use stateless_core::{
    LightWitness, LightWitnessExecutor, WitnessDatabase, WitnessExternalEnv, chain_spec::ChainSpec,
    replay_block,
};
use stateless_test_utils::fixtures::TestFixtures;

#[test]
fn replays_mainnet_fixtures_with_header_sanity() {
    let fixtures = TestFixtures::mainnet_shared();
    let chain_spec = ChainSpec::from_genesis(fixtures.load_genesis().expect("genesis"));
    // WitnessDatabase expects the alloy HashMap flavor; rebuild once.
    let contracts: alloy_primitives::map::HashMap<_, _> =
        fixtures.contracts.iter().map(|(k, v)| (*k, v.clone())).collect();

    let paired = fixtures.paired_blocks();
    assert!(!paired.is_empty(), "no paired fixture blocks found");

    for (number, hash) in paired {
        let block = &fixtures.blocks[&hash];
        let header = &block.header.inner;
        let light = LightWitness::from(&fixtures.salt_witnesses[&hash]);
        let ext_env = WitnessExternalEnv::from_light_witness(&light, number)
            .unwrap_or_else(|e| panic!("env oracle for block {number}: {e}"));
        let executor = LightWitnessExecutor::from(light);
        let db = WitnessDatabase { header, witness: &executor, contracts: &contracts };

        let (_accounts, out) = replay_block(&chain_spec, block, &db, ext_env, None)
            .unwrap_or_else(|e| panic!("replay block {number}: {e}"));

        assert_eq!(out.gas_used, header.gas_used, "gas mismatch at block {number}");
        assert_eq!(
            out.receipts_root, header.receipts_root,
            "receipts root mismatch at block {number}"
        );
        assert_eq!(out.logs_bloom, header.logs_bloom, "logs bloom mismatch at block {number}");
    }
}
