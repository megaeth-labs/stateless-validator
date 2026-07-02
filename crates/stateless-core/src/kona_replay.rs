//! Kona-backed block replay for stateless validation.

use std::{fmt, vec::Vec};

use alloy_consensus::{Header, TxReceipt, proofs::calculate_receipt_root};
use alloy_eips::Encodable2718;
use alloy_primitives::{
    B64, Bloom, Bytes,
    map::{B256Map, HashMap},
};
use alloy_rlp::Decodable;
use alloy_rpc_types_engine::PayloadAttributes;
use bincode::serde::encode_to_vec;
use kona_driver::Executor;
use kona_executor::{BlockBuildingOutcome, TrieDBProvider};
use kona_genesis::RollupConfig;
use kona_megaevm::LazyMegaEvmFactory;
use kona_mpt::{NoopTrieHinter, TrieNode, TrieProvider};
use kona_proof::executor::KonaExecutor;
use op_alloy_consensus::decode_holocene_extra_data;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use revm::{database::states::BundleAccount, state::Bytecode};
use salt::SaltWitness;
use thiserror::Error;
use tracing::{debug, trace};

use crate::{executor::BlockInput, withdrawals::MptWitness};

/// Errors raised while adapting stateless-validator inputs to Kona execution.
#[derive(Debug, Error)]
pub enum KonaReplayError {
    #[error("block contains only transaction hashes")]
    BlockIncomplete,

    #[error("Kona replay does not support EIP-3155 trace writer yet")]
    TraceUnsupported,

    #[error("rollup config for chain_id {0} is not present in mega-kona registry")]
    MissingRollupConfig(u64),

    #[error("failed to encode SALT witness for Kona executor: {0}")]
    SaltWitnessEncoding(#[from] bincode::error::EncodeError),

    #[error("Kona provider error: {0}")]
    Provider(#[from] KonaReplayProviderError),

    #[error("Kona execution failed: {0}")]
    Execution(#[from] kona_executor::ExecutorError),
}

/// Kona execution result normalized to the fields the validator checks.
#[derive(Debug, Clone)]
pub struct KonaReplayOutput {
    pub block_hash: alloy_primitives::B256,
    pub state_root: alloy_primitives::B256,
    pub receipts_root: alloy_primitives::B256,
    pub logs_bloom: Bloom,
    pub gas_used: u64,
    pub withdrawals_root: Option<alloy_primitives::B256>,
    pub receipt_count: usize,
    pub bundle_state: HashMap<alloy_primitives::Address, BundleAccount>,
    pub state_reads: usize,
    pub state_writes: usize,
}

/// In-memory [`TrieDBProvider`] backed by the validator's witness bundle.
#[derive(Clone, Debug)]
struct KonaReplayProvider {
    salt_witness: Bytes,
    bytecodes: HashMap<alloy_primitives::B256, Bytes>,
    trie_nodes: B256Map<Bytes>,
    headers: HashMap<alloy_primitives::B256, Header>,
}

impl KonaReplayProvider {
    fn new(
        salt_witness: SaltWitness,
        mpt_witness: &MptWitness,
        contracts: &HashMap<alloy_primitives::B256, Bytecode>,
        parent_header: &Header,
        parent_hash: alloy_primitives::B256,
    ) -> Result<Self, KonaReplayError> {
        let salt_witness = Bytes::from(encode_to_vec(salt_witness, bincode::config::legacy())?);
        let bytecodes = contracts
            .iter()
            .map(|(hash, bytecode)| (*hash, Bytes::copy_from_slice(bytecode.bytes_slice())))
            .collect();
        let trie_nodes = mpt_witness
            .state
            .iter()
            .map(|node| (alloy_primitives::keccak256(node), node.clone()))
            .collect();
        let headers = HashMap::from_iter([(parent_hash, parent_header.clone())]);

        Ok(Self { salt_witness, bytecodes, trie_nodes, headers })
    }
}

impl TrieProvider for KonaReplayProvider {
    type Error = KonaReplayProviderError;

    fn trie_node_by_hash(&self, key: alloy_primitives::B256) -> Result<TrieNode, Self::Error> {
        trace!(?key, "Kona trie node lookup");
        let bytes = self.trie_nodes.get(&key).ok_or(KonaReplayProviderError::TrieNode(key))?;
        TrieNode::decode(&mut bytes.as_ref()).map_err(KonaReplayProviderError::TrieNodeDecode)
    }
}

impl TrieDBProvider for KonaReplayProvider {
    fn bytecode_by_hash(&self, code_hash: alloy_primitives::B256) -> Result<Bytes, Self::Error> {
        trace!(?code_hash, "Kona bytecode lookup");
        self.bytecodes.get(&code_hash).cloned().ok_or(KonaReplayProviderError::Bytecode(code_hash))
    }

    fn header_by_hash(&self, hash: alloy_primitives::B256) -> Result<Header, Self::Error> {
        trace!(?hash, "Kona header lookup");
        self.headers.get(&hash).cloned().ok_or(KonaReplayProviderError::Header(hash))
    }

    fn salt_witness_by_state_root(
        &self,
        _block_number: u64,
        _parent_hash: alloy_primitives::B256,
        _state_root: alloy_primitives::B256,
        _payload_attributes_hash: alloy_primitives::B256,
    ) -> Result<Bytes, Self::Error> {
        Ok(self.salt_witness.clone())
    }
}

#[derive(Debug, Clone, Error)]
pub enum KonaReplayProviderError {
    #[error("missing trie node preimage for {0:?}")]
    TrieNode(alloy_primitives::B256),

    #[error("failed to decode trie node: {0}")]
    TrieNodeDecode(alloy_rlp::Error),

    #[error("missing bytecode for {0:?}")]
    Bytecode(alloy_primitives::B256),

    #[error("missing header for {0:?}")]
    Header(alloy_primitives::B256),
}

/// Replays one block through Kona's `execute_payload` path.
pub fn replay_block_with_kona<B: BlockInput>(
    block: &B,
    parent_header: &Header,
    salt_witness: SaltWitness,
    mpt_witness: &MptWitness,
    contracts: &HashMap<alloy_primitives::B256, Bytecode>,
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

/// Loads the registered MegaETH rollup config for the L2 chain id.
pub fn rollup_config_for_chain_id(chain_id: u64) -> Result<RollupConfig, KonaReplayError> {
    kona_registry::ROLLUP_CONFIGS
        .get(&chain_id)
        .cloned()
        .ok_or(KonaReplayError::MissingRollupConfig(chain_id))
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
        bundle_state: outcome.bundle_state,
        state_reads: outcome.state_reads,
        state_writes: outcome.state_writes,
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
