//! Kona-backed block validation for the `kona-validator` binary.
//!
//! [`KonaValidator`] implements the [`BlockValidator`] executor seam by rebuilding the block
//! through mega-kona's stateless `execute_payload` path and requiring the rebuilt,
//! fully-derived consensus header to equal the claimed one.
//! Header equality binds every consensus field to the claimed header: the state-correctness
//! fields (state root, transactions root, receipts root, logs bloom, gas used, withdrawals
//! root, base fee, extra data, blob fields) are derived by kona from the parent header, the
//! raw transactions, and the verified witness — never copied from the claimed header — while
//! the sequencer-chosen inputs (timestamp, prev randao, beneficiary, gas limit, parent beacon
//! block root) are echoed through the payload attributes and trusted, matching
//! `MegaEvmValidator`'s trust model.
//! On mismatch the error lists exactly which fields diverged.
//!
//! Design notes:
//! - **Single execution.** Kona's builder verifies the SALT witness proof against the parent state
//!   root, replays the transactions, and recomputes the SALT state root and the withdrawals-root
//!   MPT internally; nothing is re-executed or re-derived locally.
//! - **Version-decoupled SALT.** Only bincode-encoded bytes cross into kona's `salt` crate, so the
//!   workspace `salt` version does not need to unify with mega-kona's.
//! - **Stats granularity.** Witness verification and SALT-update time happen inside kona and cannot
//!   be measured separately: [`ValidationStats::block_replay_time`] carries the whole validation
//!   wall time and the other timers stay `0.0`; `state_reads`/`state_writes` are not exposed by
//!   kona's outcome and stay `0`.

use std::time::Instant;

use alloy_consensus::Header;
use alloy_eips::eip2718::Encodable2718;
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use alloy_primitives::{
    B64, B256, Bytes, Sealed, keccak256,
    map::{B256Map, HashMap},
};
use alloy_rlp::Decodable;
use alloy_rpc_types_engine::PayloadAttributes;
use bincode::serde::encode_to_vec;
use kona_driver::Executor;
use kona_executor::TrieDBProvider;
use kona_genesis::RollupConfig;
use kona_megaevm::LazyMegaEvmFactory;
use kona_mpt::{NoopTrieHinter, TrieNode, TrieProvider};
use kona_proof::executor::KonaExecutor;
use mega_evm::{MegaHardfork, MegaHardforks};
use op_alloy_consensus::decode_holocene_extra_data;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use revm::state::Bytecode;
use salt::SaltWitness;
use stateless_core::{
    chain_spec::ChainSpec,
    executor::{BlockInput, BlockValidator, ValidationInput, ValidationStats},
    withdrawals::MptWitness,
};
use thiserror::Error;
use tracing::debug;

/// Minimum base fee enforced on MegaETH, in wei.
///
/// Mirrors mega-kona's (private) `MEGAETH_MIN_BASE_FEE`: the floor originates from the L1
/// `SystemConfig` and reaches the block builder through `OpPayloadAttributes::min_base_fee`
/// rather than the Jovian extra-data encoding, so the validator must supply it the same way.
/// A wrong value here is fail-safe: the derived base fee would diverge from the sequencer's
/// and validation would reject the block with a `base_fee_per_gas` field diff.
const MEGAETH_MIN_BASE_FEE: u64 = 1_000_000;

/// Errors raised while adapting stateless-validator inputs to Kona execution.
#[derive(Debug, Error)]
pub enum KonaReplayError {
    #[error("block contains only transaction hashes")]
    BlockIncomplete,

    #[error("Kona validator requires the parent header in ValidationInput")]
    MissingParentHeader,

    #[error("block header is missing parent_beacon_block_root (required by Kona post-Ecotone)")]
    MissingParentBeaconBlockRoot,

    #[error("parent header is missing withdrawals_root (required by Kona post-Isthmus)")]
    MissingParentWithdrawalsRoot,

    #[error(
        "hardfork {0} is scheduled in the mega-kona registry but not supported by this validator"
    )]
    UnsupportedHardfork(&'static str),

    #[error("parent header hash mismatch: expected {expected}, got {actual}")]
    ParentHeaderHashMismatch { expected: B256, actual: B256 },

    #[error("rollup config for chain_id {0} is not present in the mega-kona registry")]
    MissingRollupConfig(u64),

    #[error(
        "hardfork schedule mismatch between genesis file and mega-kona registry for {fork}: \
         genesis {genesis:?}, registry {registry:?}"
    )]
    HardforkMismatch { fork: &'static str, genesis: Option<u64>, registry: Option<u64> },

    #[error("failed to encode SALT witness for the Kona executor: {0}")]
    SaltWitnessEncoding(#[from] bincode::error::EncodeError),

    #[error("invalid EIP-1559 header extra data: {0}")]
    InvalidExtraData(String),

    #[error("Kona provider error: {0}")]
    Provider(#[from] KonaReplayProviderError),

    #[error("Kona execution failed: {0}")]
    Execution(#[from] kona_executor::ExecutorError),

    #[error(
        "rebuilt block header does not match the claimed header: [{field_diffs}] \
         (claimed hash {claimed}, rebuilt hash {actual})"
    )]
    BlockHashMismatch { claimed: B256, actual: B256, field_diffs: String },
}

/// A [`BlockValidator`] backend that validates blocks by rebuilding them through Kona.
#[derive(Debug, Clone)]
pub struct KonaValidator {
    rollup_config: RollupConfig,
}

impl KonaValidator {
    /// Creates a Kona backend for the given chain spec.
    ///
    /// Resolves the rollup config from the mega-kona registry by chain id and fails if the
    /// registry's hardfork schedule disagrees with the operator-supplied genesis file, so a
    /// registry/genesis skew is caught at startup instead of surfacing as opaque per-block
    /// validation failures.
    pub fn new(chain_spec: &ChainSpec) -> Result<Self, KonaReplayError> {
        let rollup_config = kona_registry::ROLLUP_CONFIGS
            .get(&chain_spec.chain_id)
            .cloned()
            .ok_or(KonaReplayError::MissingRollupConfig(chain_spec.chain_id))?;
        check_hardfork_consistency(chain_spec, &rollup_config)?;
        Ok(Self { rollup_config })
    }
}

impl<B: BlockInput> BlockValidator<B> for KonaValidator {
    type Error = KonaReplayError;

    fn validate_block(
        &self,
        input: ValidationInput<'_, B>,
    ) -> Result<ValidationStats, KonaReplayError> {
        let block = input.block;
        if !block.is_complete() {
            return Err(KonaReplayError::BlockIncomplete);
        }
        let header = block.consensus_header();
        let parent_header = input.parent_header.ok_or(KonaReplayError::MissingParentHeader)?;
        // Kona's builder unwraps these internally; reject up front with typed errors instead
        // of panicking on malformed remote input.
        if header.parent_beacon_block_root.is_none() {
            return Err(KonaReplayError::MissingParentBeaconBlockRoot);
        }
        if parent_header.withdrawals_root.is_none() {
            return Err(KonaReplayError::MissingParentWithdrawalsRoot);
        }

        let start = Instant::now();
        let parent_hash = header.parent_hash;
        let provider = KonaReplayProvider::new(
            &input.salt_witness,
            &input.mpt_witness,
            input.contracts,
            parent_header,
            parent_hash,
        )?;
        // Hash authenticity was just verified by `KonaReplayProvider::new`.
        let sealed_parent = Sealed::new_unchecked(parent_header.clone(), parent_hash);
        let mut executor = KonaExecutor::new(
            &self.rollup_config,
            provider,
            NoopTrieHinter,
            LazyMegaEvmFactory::default(),
            None,
        );
        executor.update_safe_head(sealed_parent);

        let attrs = payload_attrs_from_block(block)?;
        debug!(
            block_number = header.number,
            block_hash = %block.block_hash(),
            "Rebuilding block via Kona execute_payload"
        );
        let outcome = kona_proof::block_on(executor.execute_payload(attrs))?;

        // One equality check binds every consensus header field to the claimed header; kona
        // derived them all independently (state root from the verified witness, base fee from
        // the parent, receipts/bloom/gas from execution, withdrawals root from its MPT).
        let rebuilt = outcome.header.inner();
        if rebuilt != header {
            return Err(KonaReplayError::BlockHashMismatch {
                claimed: header.hash_slow(),
                actual: outcome.header.hash(),
                field_diffs: header_field_diffs(header, rebuilt),
            });
        }

        Ok(ValidationStats {
            state_reads: 0,
            state_writes: 0,
            witness_verification_time: 0.0,
            block_replay_time: start.elapsed().as_secs_f64(),
            salt_update_time: 0.0,
        })
    }

    fn requires_parent_header(&self) -> bool {
        true
    }
}

/// Fails on any activation-time disagreement for the hardforks both sides define.
///
/// Kona derives its execution rules (spec id, block limits) exclusively from the registry's
/// [`RollupConfig`], while the rest of the validator honors the genesis file; a silent skew
/// between them would make the two validator binaries enforce different rules.
fn check_hardfork_consistency(
    chain_spec: &ChainSpec,
    rollup_config: &RollupConfig,
) -> Result<(), KonaReplayError> {
    let h = &rollup_config.hardforks;
    let mega = |fork| chain_spec.mega_fork_activation(fork).as_timestamp();
    // Jovian changes the extra-data format (17-byte, carries min_base_fee) and this module
    // only implements the Holocene 9-byte derivation; fail loudly rather than mis-validate.
    if h.jovian_time.is_some() {
        return Err(KonaReplayError::UnsupportedHardfork("jovian"));
    }
    let op = |fork| chain_spec.op_fork_activation(fork).as_timestamp();
    let pairs: [(&'static str, Option<u64>, Option<u64>); 11] = [
        ("holocene", op(OpHardfork::Holocene), h.holocene_time),
        ("isthmus", op(OpHardfork::Isthmus), h.isthmus_time),
        ("mini_rex", mega(MegaHardfork::MiniRex), h.mini_rex_time),
        ("mini_rex_1", mega(MegaHardfork::MiniRex1), h.mini_rex_1_time),
        ("mini_rex_2", mega(MegaHardfork::MiniRex2), h.mini_rex_2_time),
        ("rex", mega(MegaHardfork::Rex), h.rex_time),
        ("rex_1", mega(MegaHardfork::Rex1), h.rex_1_time),
        ("rex_2", mega(MegaHardfork::Rex2), h.rex_2_time),
        ("rex_3", mega(MegaHardfork::Rex3), h.rex_3_time),
        ("rex_4", mega(MegaHardfork::Rex4), h.rex_4_time),
        ("rex_5", mega(MegaHardfork::Rex5), h.rex_5_time),
    ];
    for (fork, genesis, registry) in pairs {
        if genesis != registry {
            return Err(KonaReplayError::HardforkMismatch { fork, genesis, registry });
        }
    }
    Ok(())
}

/// Lists the header fields that differ between the claimed and the kona-rebuilt header.
fn header_field_diffs(claimed: &Header, rebuilt: &Header) -> String {
    macro_rules! diff {
        ($out:ident, $c:ident, $r:ident, $($field:ident),+ $(,)?) => {
            $(
                if $c.$field != $r.$field {
                    $out.push(format!(
                        concat!(stringify!($field), ": claimed {:?}, rebuilt {:?}"),
                        $c.$field, $r.$field
                    ));
                }
            )+
        };
    }
    let mut out = Vec::new();
    diff!(
        out,
        claimed,
        rebuilt,
        parent_hash,
        ommers_hash,
        beneficiary,
        state_root,
        transactions_root,
        receipts_root,
        difficulty,
        number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        mix_hash,
        nonce,
        base_fee_per_gas,
        withdrawals_root,
        blob_gas_used,
        excess_blob_gas,
        parent_beacon_block_root,
        requests_hash,
    );
    if claimed.logs_bloom != rebuilt.logs_bloom {
        out.push("logs_bloom differs".to_string());
    }
    out.join("; ")
}

/// Builds the payload attributes kona needs to rebuild the block.
///
/// Everything is sourced from the claimed header or the raw transactions; fields kona
/// re-derives (base fee, state root, ...) are validated afterwards via header equality.
fn payload_attrs_from_block<B: BlockInput>(
    block: &B,
) -> Result<OpPayloadAttributes, KonaReplayError> {
    let header = block.consensus_header();
    let transactions = block
        .txs_recovered()
        .map(|recovered| {
            let mut bytes = Vec::new();
            recovered.inner().encode_2718(&mut bytes);
            Bytes::from(bytes)
        })
        .collect::<Vec<_>>();

    // Strict decode: a post-Holocene block whose extra data is malformed must fail validation,
    // not silently fall back to default parameters. (All MegaETH chains activate Holocene at
    // genesis, so every block header carries the 9-byte Holocene format.)
    let (elasticity, denominator) = decode_holocene_extra_data(&header.extra_data)
        .map_err(|e| KonaReplayError::InvalidExtraData(e.to_string()))?;
    // op-alloy's decoder checks only length and version byte; zero params are spec-invalid and
    // would otherwise roundtrip decode -> encode and only blow up when validating the CHILD
    // block (zero denominator errors, zero elasticity divides by zero in kona).
    if denominator == 0 || elasticity == 0 {
        return Err(KonaReplayError::InvalidExtraData(format!(
            "EIP-1559 params must be non-zero, got denominator={denominator} \
             elasticity={elasticity}"
        )));
    }
    let mut eip_1559_params = [0u8; 8];
    eip_1559_params[..4].copy_from_slice(&denominator.to_be_bytes());
    eip_1559_params[4..].copy_from_slice(&elasticity.to_be_bytes());

    Ok(OpPayloadAttributes {
        payload_attributes: PayloadAttributes {
            timestamp: header.timestamp,
            prev_randao: header.mix_hash,
            suggested_fee_recipient: header.beneficiary,
            withdrawals: Default::default(),
            parent_beacon_block_root: header.parent_beacon_block_root,
        },
        transactions: Some(transactions),
        no_tx_pool: None,
        gas_limit: Some(header.gas_limit),
        eip_1559_params: Some(B64::from(eip_1559_params)),
        min_base_fee: Some(MEGAETH_MIN_BASE_FEE),
    })
}

/// In-memory [`TrieDBProvider`] backed by the validator's witness bundle.
#[derive(Clone, Debug)]
struct KonaReplayProvider {
    salt_witness: Bytes,
    bytecodes: HashMap<B256, Bytes>,
    trie_nodes: B256Map<Bytes>,
    headers: HashMap<B256, Header>,
}

impl KonaReplayProvider {
    fn new(
        salt_witness: &SaltWitness,
        mpt_witness: &MptWitness,
        contracts: &HashMap<B256, Bytecode>,
        parent_header: &Header,
        parent_hash: B256,
    ) -> Result<Self, KonaReplayError> {
        let actual_parent_hash = parent_header.hash_slow();
        if actual_parent_hash != parent_hash {
            return Err(KonaReplayError::ParentHeaderHashMismatch {
                expected: parent_hash,
                actual: actual_parent_hash,
            });
        }

        let salt_witness = Bytes::from(encode_to_vec(salt_witness, bincode::config::legacy())?);
        // `original_bytes()` is the unpadded code (hash-consistent with the code hash) and a
        // refcounted clone — never the padded analyzed buffer `bytes_slice()` exposes.
        let bytecodes =
            contracts.iter().map(|(hash, bytecode)| (*hash, bytecode.original_bytes())).collect();
        let trie_nodes =
            mpt_witness.state.iter().map(|node| (keccak256(node), node.clone())).collect();
        let headers = HashMap::from_iter([(parent_hash, parent_header.clone())]);

        Ok(Self { salt_witness, bytecodes, trie_nodes, headers })
    }
}

impl TrieProvider for KonaReplayProvider {
    type Error = KonaReplayProviderError;

    fn trie_node_by_hash(&self, key: B256) -> Result<TrieNode, Self::Error> {
        let bytes = self.trie_nodes.get(&key).ok_or(KonaReplayProviderError::TrieNode(key))?;
        TrieNode::decode(&mut bytes.as_ref()).map_err(KonaReplayProviderError::TrieNodeDecode)
    }
}

impl TrieDBProvider for KonaReplayProvider {
    fn bytecode_by_hash(&self, code_hash: B256) -> Result<Bytes, Self::Error> {
        self.bytecodes.get(&code_hash).cloned().ok_or(KonaReplayProviderError::Bytecode(code_hash))
    }

    fn header_by_hash(&self, hash: B256) -> Result<Header, Self::Error> {
        self.headers.get(&hash).cloned().ok_or(KonaReplayProviderError::Header(hash))
    }

    fn salt_witness_by_state_root(
        &self,
        _block_number: u64,
        _parent_hash: B256,
        _state_root: B256,
        _payload_attributes_hash: B256,
    ) -> Result<Bytes, Self::Error> {
        Ok(self.salt_witness.clone())
    }
}

/// Errors raised by [`KonaReplayProvider`] lookups.
#[derive(Debug, Clone, Error)]
pub enum KonaReplayProviderError {
    #[error("missing trie node preimage for {0}")]
    TrieNode(B256),

    #[error("failed to decode trie node: {0}")]
    TrieNodeDecode(alloy_rlp::Error),

    #[error("missing bytecode for {0}")]
    Bytecode(B256),

    #[error("missing header for {0}")]
    Header(B256),
}

#[cfg(test)]
mod tests {
    use alloy_rpc_types_eth::{Block, BlockTransactions};
    use op_alloy_rpc_types::Transaction;
    use stateless_test_utils::{fixtures::TestFixtures, logging::init_test_logging};

    use super::*;

    /// First mainnet fixture block whose parent block is also a fixture.
    fn paired_block_with_parent(fx: &TestFixtures) -> (u64, B256) {
        fx.paired_blocks()
            .into_iter()
            .find(|(_, hash)| fx.blocks.contains_key(&fx.blocks[hash].header.parent_hash))
            .expect("mainnet fixtures must contain a block whose parent is also a fixture")
    }

    fn mainnet_validator(fx: &TestFixtures) -> KonaValidator {
        let chain_spec = ChainSpec::from_genesis(fx.load_genesis().unwrap());
        KonaValidator::new(&chain_spec).unwrap()
    }

    /// Runs validation for `block` (possibly mutated) using fixture witnesses of `hash`.
    fn validate(
        fx: &TestFixtures,
        hash: B256,
        block: &Block<Transaction>,
        parent: &Header,
    ) -> Result<ValidationStats, KonaReplayError> {
        let input = ValidationInput::new(
            block,
            fx.salt_witnesses[&hash].clone(),
            fx.mpt_witness(&hash),
            &fx.contracts,
        )
        .with_parent_header(parent);
        mainnet_validator(fx).validate_block(input)
    }

    #[test]
    fn kona_validator_requires_parent_header() {
        let fx = TestFixtures::mainnet_shared();
        let (_, hash) = paired_block_with_parent(fx);

        let err = mainnet_validator(fx)
            .validate_block(ValidationInput::new(
                &fx.blocks[&hash],
                fx.salt_witnesses[&hash].clone(),
                fx.mpt_witness(&hash),
                &fx.contracts,
            ))
            .unwrap_err();
        assert!(matches!(err, KonaReplayError::MissingParentHeader), "{err:?}");
    }

    #[test]
    fn kona_validator_validate_block_mainnet_fixtures() {
        let _logging = init_test_logging("stateless_validator");
        let fx = TestFixtures::mainnet_shared();
        let validator = mainnet_validator(fx);
        let paired = fx.paired_blocks();
        assert!(!paired.is_empty(), "no paired mainnet fixtures in test_data/mainnet");

        for (number, hash) in paired {
            let block = &fx.blocks[&hash];
            let parent = &fx
                .blocks
                .get(&block.header.parent_hash)
                .unwrap_or_else(|| {
                    panic!(
                        "parent block {} missing for fixture block {number} ({hash})",
                        block.header.parent_hash
                    )
                })
                .header
                .inner;

            let input = ValidationInput::new(
                block,
                fx.salt_witnesses[&hash].clone(),
                fx.mpt_witness(&hash),
                &fx.contracts,
            )
            .with_parent_header(parent);

            let stats = validator
                .validate_block(input)
                .unwrap_or_else(|e| panic!("Kona validation failed for {number} ({hash}): {e:?}"));
            assert!(stats.block_replay_time > 0.0, "replay time should be measured");
        }
    }

    /// Every corrupted post-execution header field must be rejected, and the error must name
    /// the exact field — this exercises the header-equality check that binds the rebuilt
    /// header to the claimed one.
    #[test]
    fn kona_validator_rejects_corrupted_header_fields() {
        let fx = TestFixtures::mainnet_shared();
        let (_, hash) = paired_block_with_parent(fx);
        let parent = fx.blocks[&fx.blocks[&hash].header.parent_hash].header.inner.clone();

        type Mutation = (&'static str, fn(&mut Header));
        let mutations: [Mutation; 5] = [
            ("state_root", |h| h.state_root = B256::repeat_byte(0xAB)),
            ("receipts_root", |h| h.receipts_root = B256::repeat_byte(0xCD)),
            ("gas_used", |h| h.gas_used += 1),
            ("base_fee_per_gas", |h| {
                h.base_fee_per_gas = Some(h.base_fee_per_gas.unwrap_or_default() + 1)
            }),
            ("logs_bloom", |h| h.logs_bloom.0[0] ^= 0xFF),
        ];

        for (field, mutate) in mutations {
            let mut block = fx.blocks[&hash].clone();
            mutate(&mut block.header.inner);

            let err = validate(fx, hash, &block, &parent).unwrap_err();
            match err {
                KonaReplayError::BlockHashMismatch { ref field_diffs, .. } => assert!(
                    field_diffs.contains(field),
                    "diff for corrupted `{field}` should name it, got: {field_diffs}"
                ),
                other => panic!("corrupted `{field}` produced unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn kona_validator_requires_parent_header_flag_is_set() {
        let fx = TestFixtures::mainnet_shared();
        let validator = mainnet_validator(fx);
        // The generic parameter is irrelevant to the flag; pin it to the RPC block type.
        assert!(BlockValidator::<Block<Transaction>>::requires_parent_header(&validator));
    }

    /// Spec-invalid EIP-1559 extra data must be rejected at this block, not deferred to a
    /// failure while validating the child block.
    #[test]
    fn kona_validator_rejects_invalid_extra_data() {
        let fx = TestFixtures::mainnet_shared();
        let (_, hash) = paired_block_with_parent(fx);
        let parent = fx.blocks[&fx.blocks[&hash].header.parent_hash].header.inner.clone();

        // Garbage: wrong length / version byte.
        let mut block = fx.blocks[&hash].clone();
        block.header.inner.extra_data = Bytes::from_static(&[0xde, 0xad]);
        let err = validate(fx, hash, &block, &parent).unwrap_err();
        assert!(matches!(err, KonaReplayError::InvalidExtraData(_)), "{err:?}");

        // Well-formed 9-byte Holocene encoding with a zero denominator.
        let mut block = fx.blocks[&hash].clone();
        block.header.inner.extra_data = Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0, 0, 8]);
        let err = validate(fx, hash, &block, &parent).unwrap_err();
        assert!(matches!(err, KonaReplayError::InvalidExtraData(_)), "{err:?}");
    }

    #[test]
    fn kona_validator_rejects_parent_without_withdrawals_root() {
        let fx = TestFixtures::mainnet_shared();
        let (_, hash) = paired_block_with_parent(fx);
        let mut parent = fx.blocks[&fx.blocks[&hash].header.parent_hash].header.inner.clone();
        parent.withdrawals_root = None;

        let err = validate(fx, hash, &fx.blocks[&hash], &parent).unwrap_err();
        assert!(matches!(err, KonaReplayError::MissingParentWithdrawalsRoot), "{err:?}");
    }

    #[test]
    fn kona_validator_rejects_wrong_parent_header() {
        let fx = TestFixtures::mainnet_shared();
        let (_, hash) = paired_block_with_parent(fx);
        let block = &fx.blocks[&hash];
        // The block's own header is a valid header but not this block's parent.
        let wrong_parent = block.header.inner.clone();

        let err = validate(fx, hash, block, &wrong_parent).unwrap_err();
        assert!(matches!(err, KonaReplayError::ParentHeaderHashMismatch { .. }), "{err:?}");
    }

    #[test]
    fn kona_validator_rejects_hashes_only_block() {
        let fx = TestFixtures::mainnet_shared();
        let (_, hash) = paired_block_with_parent(fx);
        let parent = fx.blocks[&fx.blocks[&hash].header.parent_hash].header.inner.clone();
        let mut block = fx.blocks[&hash].clone();
        block.transactions = BlockTransactions::Hashes(vec![]);

        let err = validate(fx, hash, &block, &parent).unwrap_err();
        assert!(matches!(err, KonaReplayError::BlockIncomplete), "{err:?}");
    }

    #[test]
    fn kona_validator_rejects_missing_parent_beacon_block_root() {
        let fx = TestFixtures::mainnet_shared();
        let (_, hash) = paired_block_with_parent(fx);
        let parent = fx.blocks[&fx.blocks[&hash].header.parent_hash].header.inner.clone();
        let mut block = fx.blocks[&hash].clone();
        block.header.inner.parent_beacon_block_root = None;

        let err = validate(fx, hash, &block, &parent).unwrap_err();
        assert!(matches!(err, KonaReplayError::MissingParentBeaconBlockRoot), "{err:?}");
    }

    #[test]
    fn kona_validator_rejects_unregistered_chain_id() {
        let fx = TestFixtures::mainnet_shared();
        let mut genesis = fx.load_genesis().unwrap();
        genesis.config.chain_id = 424242;
        let chain_spec = ChainSpec::from_genesis(genesis);

        let err = KonaValidator::new(&chain_spec).unwrap_err();
        assert!(matches!(err, KonaReplayError::MissingRollupConfig(424242)), "{err:?}");
    }

    /// A genesis file whose hardfork schedule disagrees with the mega-kona registry must be
    /// rejected at startup — kona derives execution rules from the registry, and a silent
    /// skew would make the two validator binaries enforce different rules.
    #[test]
    fn kona_validator_rejects_genesis_registry_hardfork_skew() {
        let fx = TestFixtures::mainnet_shared();
        let mut genesis = fx.load_genesis().unwrap();
        genesis.config.extra_fields.insert_value("miniRexTime".to_string(), 12_345u64).unwrap();
        let chain_spec = ChainSpec::from_genesis(genesis);

        let err = KonaValidator::new(&chain_spec).unwrap_err();
        assert!(
            matches!(err, KonaReplayError::HardforkMismatch { fork: "mini_rex", .. }),
            "{err:?}"
        );
    }
}
