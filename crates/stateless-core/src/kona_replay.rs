//! Kona-backed block validation for stateless validation.

use std::{boxed::Box, collections::BTreeMap, fmt, vec::Vec};
#[cfg(feature = "std")]
use std::{io::Write, time::Instant};

use alloy_consensus::{
    BlockHeader, Header, TxReceipt, crypto::RecoveryError, proofs::calculate_receipt_root,
    transaction::Recovered,
};
use alloy_eips::{
    calc_next_block_base_fee,
    eip1559::BaseFeeParams,
    eip2718::{Decodable2718, Encodable2718, WithEncoded},
};
use alloy_primitives::{
    Address, B64, Bloom, Bytes, keccak256,
    map::{B256Map, HashMap},
};
use alloy_rlp::Decodable;
use alloy_rpc_types_engine::PayloadAttributes;
use bincode::serde::encode_to_vec;
use kona_driver::Executor;
use kona_executor::{BlockBuildingOutcome, TrieDBProvider};
use kona_genesis::RollupConfig;
use kona_megaevm::{
    LazyMegaBlockExecutorFactory, LazyMegaEvmFactory, MegaChainSpec,
    WitnessExternalEnv as KonaWitnessExternalEnv,
};
use kona_mpt::{NoopTrieHinter, TrieNode, TrieProvider};
use kona_proof::executor::KonaExecutor;
use mega_evm_kona::{
    BlockLimits, MegaBlockExecutionCtx, MegaHardforks, MegaSpecId, MegaTxEnvelope,
    SequencerRegistryConfig,
    alloy_evm::{
        EvmEnv,
        block::{BlockExecutionError, BlockExecutor},
    },
    alloy_op_evm::block::OpAlloyReceiptBuilder,
    revm::{
        context::{BlockEnv, CfgEnv},
        context_interface::block::BlobExcessGasAndPrice,
        database::{
            State,
            in_memory_db::CacheDB,
            states::{BundleAccount, bundle_state::BundleRetention},
        },
        primitives::eip4844::{
            BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN, BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
        },
    },
};
use op_alloy_consensus::decode_holocene_extra_data;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use revm::{
    primitives::{B256, KECCAK_EMPTY, U256},
    state::Bytecode,
};
use salt::{EphemeralSaltState, SaltValue, SaltWitness, StateRoot, StateUpdates, Witness};
use salt_stateless::WitnessProvider;
use thiserror::Error;
use tracing::{debug, trace};

use crate::{
    chain_spec::ChainSpec,
    data_types::{Account, PlainKey, PlainValue},
    executor::{
        BlockExecutionOutput, BlockInput, BlockValidator, ValidationError, ValidationInput,
        ValidationStats,
    },
    withdrawals::{ADDRESS_L2_TO_L1_MESSAGE_PASSER, MptWitness},
};

/// Errors raised while adapting stateless-validator inputs to Kona execution.
#[derive(Debug, Error)]
pub enum KonaReplayError {
    #[error("block contains only transaction hashes")]
    BlockIncomplete,

    #[error("Kona validator requires parent header in ValidationInput")]
    MissingParentHeader,

    #[error("parent header hash mismatch: expected {expected:?}, got {actual:?}")]
    ParentHeaderHashMismatch { expected: alloy_primitives::B256, actual: alloy_primitives::B256 },

    #[error("rollup config for chain_id {0} is not present in mega-kona registry")]
    MissingRollupConfig(u64),

    #[error("failed to encode SALT witness for Kona executor: {0}")]
    SaltWitnessEncoding(#[from] bincode::error::EncodeError),

    #[error("Kona provider error: {0}")]
    Provider(#[from] KonaReplayProviderError),

    #[error("Kona execution failed: {0}")]
    Execution(#[from] kona_executor::ExecutorError),

    #[error("Kona block replay failed during transaction execution: {0}")]
    BlockReplayFailed(#[source] BlockExecutionError),

    #[error("Failed to construct Kona mega-evm environment oracle: {0}")]
    EnvOracleConstructionFailed(#[source] kona_megaevm::WitnessDatabaseError),

    #[error("Invalid Kona EIP-1559 header extra data: {0}")]
    InvalidExtraData(String),

    #[error("Kona transaction signer recovery failed: {0}")]
    Recovery(#[from] RecoveryError),

    #[error("Kona bundle-state generation or validation failed: {0}")]
    BundleStateValidation(#[from] ValidationError),

    #[error("Kona block hash mismatch: claimed {claimed:?}, got {actual:?}")]
    BlockHashMismatch { actual: B256, claimed: B256 },

    #[error("Kona state root mismatch: claimed {claimed}, got {actual}")]
    StateRootMismatch { actual: B256, claimed: B256 },

    #[error("Kona withdrawals root mismatch: claimed {claimed:?}, got {actual:?}")]
    WithdrawalsRootMismatch { actual: Option<B256>, claimed: Option<B256> },

    #[error("Kona receipts root mismatch: claimed {claimed}, got {actual}")]
    ReceiptsRootMismatch { actual: B256, claimed: B256 },

    #[error("Kona logs bloom mismatch: claimed {claimed}, got {actual}")]
    LogsBloomMismatch { actual: Box<Bloom>, claimed: Box<Bloom> },

    #[error("Kona gas used mismatch: claimed {claimed}, got {actual}")]
    GasUsedMismatch { actual: u64, claimed: u64 },
}

/// Kona execution result normalized to the fields the validator checks.
#[derive(Debug, Clone)]
pub struct KonaReplayOutput {
    pub block_hash: B256,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    pub gas_used: u64,
    pub withdrawals_root: Option<B256>,
    pub receipt_count: usize,
}

/// A [`BlockValidator`] backend that validates blocks by rebuilding them through Kona.
#[derive(Debug, Clone)]
pub struct KonaValidator {
    chain_spec: ChainSpec,
    rollup_config: RollupConfig,
}

impl KonaValidator {
    /// Creates a Kona backend for the given chain spec.
    pub fn new(chain_spec: &ChainSpec) -> Result<Self, KonaReplayError> {
        Ok(Self {
            chain_spec: chain_spec.clone(),
            rollup_config: rollup_config_for_chain_id(chain_spec.chain_id)?,
        })
    }
}

impl<B: BlockInput> BlockValidator<B> for KonaValidator {
    type Error = KonaReplayError;

    fn validate_block(
        &self,
        input: ValidationInput<'_, B>,
    ) -> Result<ValidationStats, KonaReplayError> {
        self::validate_block(
            &self.chain_spec,
            input.block,
            input.parent_header.ok_or(KonaReplayError::MissingParentHeader)?,
            input.salt_witness,
            input.mpt_witness,
            input.contracts,
            &self.rollup_config,
            #[cfg(feature = "std")]
            None,
        )
    }
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
        let bytecodes = contracts
            .iter()
            .map(|(hash, bytecode)| (*hash, Bytes::copy_from_slice(bytecode.bytes_slice())))
            .collect();
        let trie_nodes =
            mpt_witness.state.iter().map(|node| (keccak256(node), node.clone())).collect();
        let headers = HashMap::from_iter([(parent_hash, parent_header.clone())]);

        Ok(Self { salt_witness, bytecodes, trie_nodes, headers })
    }
}

impl TrieProvider for KonaReplayProvider {
    type Error = KonaReplayProviderError;

    fn trie_node_by_hash(&self, key: B256) -> Result<TrieNode, Self::Error> {
        trace!(?key, "Kona trie node lookup");
        let bytes = self.trie_nodes.get(&key).ok_or(KonaReplayProviderError::TrieNode(key))?;
        TrieNode::decode(&mut bytes.as_ref()).map_err(KonaReplayProviderError::TrieNodeDecode)
    }
}

impl TrieDBProvider for KonaReplayProvider {
    fn bytecode_by_hash(&self, code_hash: B256) -> Result<Bytes, Self::Error> {
        trace!(?code_hash, "Kona bytecode lookup");
        self.bytecodes.get(&code_hash).cloned().ok_or(KonaReplayProviderError::Bytecode(code_hash))
    }

    fn header_by_hash(&self, hash: B256) -> Result<Header, Self::Error> {
        trace!(?hash, "Kona header lookup");
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

#[derive(Debug, Clone, Error)]
pub enum KonaReplayProviderError {
    #[error("missing trie node preimage for {0:?}")]
    TrieNode(B256),

    #[error("failed to decode trie node: {0}")]
    TrieNodeDecode(alloy_rlp::Error),

    #[error("missing bytecode for {0:?}")]
    Bytecode(B256),

    #[error("missing header for {0:?}")]
    Header(B256),
}

/// Replays one block through Kona's `execute_payload` path.
pub fn execute_payload_with_kona<B: BlockInput>(
    block: &B,
    parent_header: &Header,
    salt_witness: &SaltWitness,
    mpt_witness: &MptWitness,
    contracts: &HashMap<B256, Bytecode>,
    rollup_config: &RollupConfig,
) -> Result<KonaReplayOutput, KonaReplayError> {
    if !block.is_complete() {
        return Err(KonaReplayError::BlockIncomplete);
    }

    let parent_hash = block.consensus_header().parent_hash;
    let provider =
        KonaReplayProvider::new(salt_witness, mpt_witness, contracts, parent_header, parent_hash)?;
    let parent_header = alloy_primitives::Sealed::new_unchecked(parent_header.clone(), parent_hash);
    let mut executor = KonaExecutor::new(
        rollup_config,
        provider,
        NoopTrieHinter,
        LazyMegaEvmFactory::default(),
        None,
    );
    executor.update_safe_head(parent_header);

    let attrs = payload_attrs_from_block(block, rollup_config)?;
    debug!(
        block_number = block.consensus_header().number,
        block_hash = ?block.block_hash(),
        "Executing block via Kona execute_payload"
    );
    let outcome = kona_proof::block_on(executor.execute_payload(attrs))?;

    Ok(output_from_outcome(outcome))
}

/// Generates the bundle-state artifacts used by the Kona validator's local checks.
pub fn generate_bundle_state<B: BlockInput>(
    block: &B,
    parent_header: &Header,
    salt_witness: SaltWitness,
    contracts: &HashMap<B256, Bytecode>,
    rollup_config: &RollupConfig,
) -> Result<HashMap<Address, BundleAccount>, KonaReplayError> {
    if !block.is_complete() {
        return Err(KonaReplayError::BlockIncomplete);
    }

    let header = block.consensus_header();
    let attrs = payload_attrs_from_block(block, rollup_config)?;
    let parent_hash = header.parent_hash;
    let parent_header = alloy_primitives::Sealed::new_unchecked(parent_header.clone(), parent_hash);
    let evm_env = kona_evm_env(header, parent_header.as_ref(), &attrs, rollup_config)?;
    let block_env = evm_env.block_env().clone();

    let contracts = contracts.iter().map(|(hash, bytecode)| (*hash, bytecode.clone())).collect();
    let witness_provider = WitnessProvider::new_with_parent_block(
        salt_witness.clone(),
        contracts,
        parent_header.number,
        parent_hash,
    );
    let mut db = CacheDB::new(witness_provider);
    let mut state = State::builder().with_database(&mut db).with_bundle_update().build();
    let env_oracle = KonaWitnessExternalEnv::new(&salt_witness, block_env.number.saturating_to())
        .map_err(KonaReplayError::EnvOracleConstructionFailed)?;

    let mut executor_factory = LazyMegaBlockExecutorFactory::new(
        mega_chain_spec(rollup_config),
        LazyMegaEvmFactory::default(),
        OpAlloyReceiptBuilder::default(),
    );
    executor_factory.set_ext_envs(env_oracle);

    let timestamp = attrs.payload_attributes.timestamp;
    let mega_chain_spec = mega_chain_spec(rollup_config);
    let block_limits = MegaHardforks::hardfork(&mega_chain_spec, timestamp)
        .map(|fork| BlockLimits::from_hardfork_and_block_gas_limit(fork, block_env.gas_limit))
        .unwrap_or_else(|| BlockLimits::no_limits().with_block_gas_limit(block_env.gas_limit));

    let execution_context = MegaBlockExecutionCtx::new(
        parent_hash,
        attrs.payload_attributes.parent_beacon_block_root,
        Default::default(),
        block_limits,
    );
    let executor = executor_factory.create_executor(&mut state, execution_context, evm_env);
    execute_kona_transactions(executor, attrs)?;

    state.merge_transitions(BundleRetention::PlainState);
    Ok(state.take_bundle().state)
}

/// Replays one block through Kona, then locally regenerates the bundle-state artifacts.
#[allow(clippy::too_many_arguments)]
pub fn replay_block_with_kona<B: BlockInput>(
    block: &B,
    parent_header: &Header,
    salt_witness: &SaltWitness,
    mpt_witness: &MptWitness,
    contracts: &HashMap<B256, Bytecode>,
    rollup_config: &RollupConfig,
) -> Result<(HashMap<Address, BundleAccount>, BlockExecutionOutput), KonaReplayError> {
    let output = execute_payload_with_kona(
        block,
        parent_header,
        salt_witness,
        mpt_witness,
        contracts,
        rollup_config,
    )?;
    let accounts = generate_bundle_state(
        block,
        parent_header,
        salt_witness.clone(),
        contracts,
        rollup_config,
    )?;
    let (state_reads, state_writes) = bundle_state_access_counts(&accounts);

    Ok((
        accounts,
        BlockExecutionOutput {
            receipts_root: output.receipts_root,
            logs_bloom: output.logs_bloom,
            gas_used: output.gas_used,
            state_reads,
            state_writes,
        },
    ))
}

/// Validates a block through Kona and then verifies the locally generated bundle-state artifacts.
#[allow(clippy::too_many_arguments)]
pub fn validate_block<B: BlockInput>(
    _chain_spec: &ChainSpec,
    block: &B,
    parent_header: &Header,
    salt_witness: SaltWitness,
    mpt_witness: MptWitness,
    contracts: &HashMap<B256, Bytecode>,
    rollup_config: &RollupConfig,
    #[cfg(feature = "std")] _writer: Option<Box<dyn Write>>,
) -> Result<ValidationStats, KonaReplayError> {
    // A block carrying only transaction hashes can't be replayed — fail fast before paying
    // the witness proof verification. `replay_block_with_kona` re-checks for direct callers.
    if !block.is_complete() {
        return Err(KonaReplayError::BlockIncomplete);
    }
    let header = block.consensus_header();

    // Verify witness proof against the current state root
    #[cfg(feature = "std")]
    let start = Instant::now();
    let witness = Witness::from(salt_witness.clone());
    witness.verify().map_err(ValidationError::WitnessVerificationFailed)?;
    #[cfg(feature = "std")]
    let witness_verification_time = start.elapsed().as_secs_f64();
    #[cfg(not(feature = "std"))]
    let witness_verification_time = 0.0_f64; // no_std: timing unavailable

    // Replay block transactions
    let (accounts, output) = replay_block_with_kona(
        block,
        parent_header,
        &salt_witness,
        &mpt_witness,
        contracts,
        rollup_config,
    )?;
    #[cfg(feature = "std")]
    let block_replay_time = start.elapsed().as_secs_f64() - witness_verification_time;
    #[cfg(not(feature = "std"))]
    let block_replay_time = 0.0_f64; // no_std: timing unavailable

    // Extract and hash storage updates (only changed values)
    let withdrawal_storage: B256Map<U256> = accounts
        .get(&ADDRESS_L2_TO_L1_MESSAGE_PASSER)
        .map(|a| {
            a.storage
                .iter()
                .filter(|(_, v)| v.previous_or_original_value != v.present_value)
                .map(|(&slot, v)| (keccak256(B256::from(slot)), v.present_value))
                .collect()
        })
        .unwrap_or_default();

    // Flatten Revm's BundleAccount format into plain key-value pairs
    let mut kv_updates: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
    for (address, bundle_account) in accounts {
        if bundle_account.info != bundle_account.original_info {
            // Process account changes
            let account = bundle_account.info.map(|info| Account {
                nonce: info.nonce,
                balance: info.balance,
                codehash: (info.code_hash != KECCAK_EMPTY).then_some(info.code_hash),
            });

            let account_key = PlainKey::Account(address).encode();
            let account_value = account.and_then(|account| {
                (!account.is_empty()).then(|| PlainValue::Account(account).encode())
            });
            kv_updates.insert(account_key, account_value);
        }

        // Process storage changes
        for (slot, value) in bundle_account.storage {
            if value.previous_or_original_value != value.present_value {
                let storage_key =
                    PlainKey::Storage(address, B256::new(slot.to_be_bytes())).encode();
                let storage_value = (!value.present_value.is_zero())
                    .then(|| PlainValue::Storage(value.present_value).encode());
                kv_updates.insert(storage_key, storage_value);
            }
        }
    }

    // Update the SALT state: Apply updates first, then inserts/deletes in deterministic key
    // order (same as Witness::create). This ordering is critical: inserts/deletes may trigger
    // key displacement or bucket expansion, invalidating the witness's direct lookup table.
    let mut witness_state = EphemeralSaltState::new(&witness);
    let mut state_updates = StateUpdates::default();
    let mut inserts_or_deletes = BTreeMap::new();

    for (plain_key, opt_plain_value) in kv_updates {
        if let (Ok(Some((salt_key, old_value))), Some(new_value)) =
            (witness_state.find(&plain_key), &opt_plain_value)
        {
            // Update operation: key exists and new value is not None
            witness_state.update_value(
                &mut state_updates,
                salt_key,
                Some(old_value),
                Some(SaltValue::new(&plain_key, new_value)),
            );
        } else {
            inserts_or_deletes.insert(plain_key, opt_plain_value);
        }
    }
    state_updates.merge(
        witness_state
            .update_fin(&inserts_or_deletes)
            .map_err(ValidationError::StateUpdateFailed)?,
    );

    // Update the state root
    let (state_root, _) = StateRoot::new(&witness)
        .update_fin(&state_updates)
        .map_err(ValidationError::TrieUpdateFailed)?;
    #[cfg(feature = "std")]
    let salt_update_time =
        start.elapsed().as_secs_f64() - witness_verification_time - block_replay_time;
    #[cfg(not(feature = "std"))]
    let salt_update_time = 0.0_f64; // no_std: timing unavailable

    // Check if computed withdrawals root matches the claimed one
    mpt_witness
        .verify(header, withdrawal_storage)
        .map_err(ValidationError::WithdrawalValidationFailed)?;

    // Verify receipts root matches the block header
    if output.receipts_root != header.receipts_root {
        return Err(ValidationError::ReceiptsRootMismatch {
            actual: output.receipts_root,
            claimed: header.receipts_root,
        }
        .into());
    }

    // Verify logs bloom matches the block header
    if output.logs_bloom != header.logs_bloom {
        return Err(ValidationError::LogsBloomMismatch {
            actual: Box::new(output.logs_bloom),
            claimed: Box::new(header.logs_bloom),
        }
        .into());
    }

    // Verify gas used matches the block header
    if output.gas_used != header.gas_used {
        return Err(ValidationError::GasUsedMismatch {
            actual: output.gas_used,
            claimed: header.gas_used,
        }
        .into());
    }

    // Check if computed state root matches claimed state root
    let state_root = B256::from(state_root);
    if state_root != header.state_root {
        return Err(ValidationError::StateRootMismatch {
            actual: state_root,
            claimed: header.state_root,
        }
        .into());
    }

    Ok(ValidationStats {
        state_reads: output.state_reads,
        state_writes: output.state_writes,
        witness_verification_time,
        block_replay_time,
        salt_update_time,
    })
}

/// Loads the registered MegaETH rollup config for the L2 chain id.
pub fn rollup_config_for_chain_id(chain_id: u64) -> Result<RollupConfig, KonaReplayError> {
    kona_registry::ROLLUP_CONFIGS
        .get(&chain_id)
        .cloned()
        .ok_or(KonaReplayError::MissingRollupConfig(chain_id))
}

fn bundle_state_access_counts(accounts: &HashMap<Address, BundleAccount>) -> (usize, usize) {
    let total_accessed: usize = accounts.values().map(|a| 1 + a.storage.len()).sum();

    let state_writes: usize = accounts
        .values()
        .map(|a| {
            (a.info != a.original_info) as usize +
                a.storage
                    .values()
                    .filter(|s| s.previous_or_original_value != s.present_value)
                    .count()
        })
        .sum();

    (total_accessed.saturating_sub(state_writes), state_writes)
}

fn mega_chain_spec(config: &RollupConfig) -> MegaChainSpec {
    let h = &config.hardforks;
    let sequencer_registry_config = match (h.rex5_initial_sequencer, h.rex5_initial_admin) {
        (Some(rex5_initial_sequencer), Some(rex5_initial_admin)) => {
            Some(SequencerRegistryConfig { rex5_initial_sequencer, rex5_initial_admin })
        }
        _ => None,
    };

    MegaChainSpec {
        isthmus_time: h.isthmus_time,
        mini_rex_time: h.mini_rex_time,
        mini_rex_1_time: h.mini_rex_1_time,
        mini_rex_2_time: h.mini_rex_2_time,
        rex_time: h.rex_time,
        rex_1_time: h.rex_1_time,
        rex_2_time: h.rex_2_time,
        rex_3_time: h.rex_3_time,
        rex_4_time: h.rex_4_time,
        rex_5_time: h.rex_5_time,
        sequencer_registry_config,
    }
}

fn kona_evm_env(
    header: &Header,
    parent_header: &Header,
    attrs: &OpPayloadAttributes,
    rollup_config: &RollupConfig,
) -> Result<EvmEnv<MegaSpecId>, KonaReplayError> {
    let (base_fee_params, config_min_base_fee) =
        active_base_fee_params(rollup_config, parent_header, attrs.payload_attributes.timestamp)?;
    let min_base_fee = attrs.min_base_fee.unwrap_or(config_min_base_fee);
    let spec_id = rollup_config.spec_id(attrs.payload_attributes.timestamp);
    let blob_excess_gas_and_price = header.excess_blob_gas.map(|excess| {
        let fraction = if spec_id.is_enabled_in(mega_evm_kona::op_revm::OpSpecId::ISTHMUS) {
            BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE
        } else {
            BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN
        };
        BlobExcessGasAndPrice::new(excess, fraction)
    });
    let next_block_base_fee =
        next_block_base_fee(rollup_config, base_fee_params, parent_header, min_base_fee)
            .unwrap_or_default();

    let block_env = BlockEnv {
        number: U256::from(parent_header.number + 1),
        beneficiary: attrs.payload_attributes.suggested_fee_recipient,
        timestamp: U256::from(attrs.payload_attributes.timestamp),
        gas_limit: attrs.gas_limit.ok_or(kona_executor::ExecutorError::MissingGasLimit)?,
        basefee: next_block_base_fee,
        prevrandao: Some(attrs.payload_attributes.prev_randao),
        blob_excess_gas_and_price,
        ..Default::default()
    };
    let cfg_env = CfgEnv::new()
        .with_chain_id(rollup_config.l2_chain_id.id())
        .with_spec(mega_chain_spec(rollup_config).spec_id(attrs.payload_attributes.timestamp));
    Ok(EvmEnv::new(cfg_env, block_env))
}

fn active_base_fee_params(
    config: &RollupConfig,
    parent_header: &Header,
    payload_timestamp: u64,
) -> Result<(BaseFeeParams, u64), KonaReplayError> {
    if config.is_jovian_active(parent_header.timestamp) {
        return decode_jovian_eip_1559_params_block_header(parent_header);
    }
    if config.is_holocene_active(parent_header.timestamp) {
        return decode_holocene_eip_1559_params_block_header(parent_header)
            .map(|base_fee_params| (base_fee_params, 0));
    }
    if config.is_canyon_active(payload_timestamp) {
        return Ok((config.chain_op_config.post_canyon_params(), 0));
    }
    Ok((config.chain_op_config.pre_canyon_params(), 0))
}

fn decode_holocene_eip_1559_params_block_header(
    header: &Header,
) -> Result<BaseFeeParams, KonaReplayError> {
    let (elasticity, denominator) = decode_holocene_extra_data(header.extra_data())
        .map_err(|e| KonaReplayError::InvalidExtraData(e.to_string()))?;
    if denominator == 0 {
        return Err(KonaReplayError::InvalidExtraData(
            "EIP-1559 denominator cannot be zero".to_string(),
        ));
    }
    Ok(BaseFeeParams {
        elasticity_multiplier: u128::from(elasticity),
        max_change_denominator: u128::from(denominator),
    })
}

fn decode_jovian_eip_1559_params_block_header(
    header: &Header,
) -> Result<(BaseFeeParams, u64), KonaReplayError> {
    let extra_data = header.extra_data();
    if extra_data.len() != 17 {
        return Err(KonaReplayError::InvalidExtraData(
            "Jovian extra data is not the correct length".to_string(),
        ));
    }
    if extra_data[0] != 1 {
        return Err(KonaReplayError::InvalidExtraData(format!(
            "Invalid Jovian EIP-1559 version byte: {}",
            extra_data[0]
        )));
    }
    let denominator =
        u32::from_be_bytes([extra_data[1], extra_data[2], extra_data[3], extra_data[4]]);
    let elasticity =
        u32::from_be_bytes([extra_data[5], extra_data[6], extra_data[7], extra_data[8]]);
    let min_base_fee = u64::from_be_bytes([
        extra_data[9],
        extra_data[10],
        extra_data[11],
        extra_data[12],
        extra_data[13],
        extra_data[14],
        extra_data[15],
        extra_data[16],
    ]);
    if denominator == 0 {
        return Err(KonaReplayError::InvalidExtraData(
            "EIP-1559 denominator cannot be zero".to_string(),
        ));
    }
    Ok((
        BaseFeeParams {
            elasticity_multiplier: u128::from(elasticity),
            max_change_denominator: u128::from(denominator),
        },
        min_base_fee,
    ))
}

fn next_block_base_fee(
    config: &RollupConfig,
    params: BaseFeeParams,
    parent: &Header,
    min_base_fee: u64,
) -> Option<u64> {
    let next = if !config.is_jovian_active(parent.timestamp()) {
        parent.next_block_base_fee(params)?
    } else {
        let gas_used = parent.blob_gas_used().unwrap_or_default().max(parent.gas_used());
        calc_next_block_base_fee(
            gas_used,
            parent.gas_limit(),
            parent.base_fee_per_gas().unwrap_or_default(),
            params,
        )
    };

    Some(next.max(min_base_fee))
}

fn execute_kona_transactions<E>(
    executor: E,
    attrs: OpPayloadAttributes,
) -> Result<(), KonaReplayError>
where
    E: BlockExecutor<Transaction = MegaTxEnvelope>,
{
    let transactions: Vec<WithEncoded<Recovered<MegaTxEnvelope>>> = attrs
        .recovered_transactions_with_encoded()
        .map(|result| {
            result.map(|with_encoded| {
                let raw_bytes: Bytes = with_encoded.encoded_bytes().clone();
                let signer: Address = with_encoded.1.signer();
                let envelope = MegaTxEnvelope::decode_2718(&mut raw_bytes.as_ref())
                    .expect("transaction was already decoded successfully");
                WithEncoded::new(raw_bytes, Recovered::new_unchecked(envelope, signer))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    executor.execute_block(transactions.iter()).map_err(KonaReplayError::BlockReplayFailed)?;
    Ok(())
}

fn output_from_outcome(outcome: BlockBuildingOutcome) -> KonaReplayOutput {
    let logs_bloom = outcome
        .execution_result
        .receipts
        .iter()
        .fold(Bloom::ZERO, |acc, receipt| acc | receipt.bloom());
    let receipts_root = calculate_receipt_root(&outcome.execution_result.receipts);
    KonaReplayOutput {
        block_hash: outcome.header.hash(),
        state_root: outcome.header.state_root,
        receipts_root,
        logs_bloom,
        gas_used: outcome.execution_result.gas_used,
        withdrawals_root: outcome.header.withdrawals_root,
        receipt_count: outcome.execution_result.receipts.len(),
    }
}

fn payload_attrs_from_block<B: BlockInput>(
    block: &B,
    rollup_config: &RollupConfig,
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
        eip_1559_params: Some(holocene_eip_1559_params_from_extra_data(
            &header.extra_data,
            rollup_config,
        )),
        min_base_fee: Some(1_000_000),
    })
}

fn holocene_eip_1559_params_from_extra_data(
    extra_data: &[u8],
    rollup_config: &RollupConfig,
) -> B64 {
    let default = rollup_config.chain_op_config.post_canyon_params();
    let (elasticity, denominator) = decode_holocene_extra_data(extra_data)
        .unwrap_or((default.elasticity_multiplier as u32, default.max_change_denominator as u32));
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&denominator.to_be_bytes());
    out[4..].copy_from_slice(&elasticity.to_be_bytes());
    B64::from(out)
}

impl fmt::Display for KonaReplayOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hash={:?} state_root={:?} receipts_root={:?} gas_used={} receipts={}",
            self.block_hash, self.state_root, self.receipts_root, self.gas_used, self.receipt_count
        )
    }
}

#[cfg(test)]
mod tests {
    use stateless_test_utils::{fixtures::TestFixtures, logging::init_test_logging};

    use super::*;

    #[test]
    fn kona_validator_requires_parent_header() {
        let fx = TestFixtures::mainnet_shared();
        let chain_spec = ChainSpec::from_genesis(fx.load_genesis().unwrap());
        let validator = KonaValidator::new(&chain_spec).unwrap();
        let (_, hash) = *fx.paired_blocks().first().expect("paired mainnet fixtures");

        let err = validator
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
        let _logging = init_test_logging("stateless_core");
        let fx = TestFixtures::mainnet_shared();
        let chain_spec = ChainSpec::from_genesis(fx.load_genesis().unwrap());
        let validator = KonaValidator::new(&chain_spec).unwrap();
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

            validator
                .validate_block(input)
                .unwrap_or_else(|e| panic!("Kona validation failed for {number} ({hash}): {e:?}"));
        }
    }
}
