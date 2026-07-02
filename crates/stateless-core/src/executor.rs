//! Block execution and transaction replay for stateless validation.
//!
//! This module provides the core execution logic for validating blocks in a stateless
//! manner. It handles EVM environment setup, transaction replay, and state change
//! computation that feeds into the broader validation pipeline.
//!
//! ## Key Functions
//!
//! - [`validate_block`]: Main validation entry point that orchestrates witness verification,
//!   transaction replay, and state root comparison
//! - [`create_evm_env`]: Creates EVM execution environment from block header and chain
//!   specification
//! - [`replay_block`]: Replays block transactions to compute state changes
//!
//! [`replay_block`] / [`validate_block`] are generic over [`BlockInput`], the minimal block
//! projection they consume (the in-repo impl is the RPC `Block`; embedders supply their own).
//!
//! ## Validation Process
//!
//! 1. Verify witness proof against previous state root
//! 2. Create witness database for transaction execution
//! 3. Replay all transactions in the block using EVM
//! 4. Compute new state root from execution results
//! 5. Compare computed state root with claimed state root
//!
//! The module integrates with the Salt witness system for state reconstruction
//! and uses Revm for transaction execution.

use std::{boxed::Box, collections::BTreeMap, vec::Vec};
#[cfg(feature = "std")]
use std::{io::Write, time::Instant};

use alloy_consensus::transaction::Recovered;
use alloy_evm::EvmEnv;
use alloy_primitives::{
    Address, Bloom, keccak256,
    map::{B256Map, HashMap},
};
use alloy_rpc_types_eth::{Block, BlockTransactions};
use mega_evm::{MegaHardforks, MegaSpecId};
use op_alloy_consensus::OpTxEnvelope;
use op_alloy_rpc_types::Transaction as OpTransaction;
use revm::{
    context::{BlockEnv, CfgEnv},
    database::states::BundleAccount,
    primitives::{B256, KECCAK_EMPTY, U256},
    state::Bytecode,
};
use salt::{EphemeralSaltState, SaltValue, SaltWitness, StateRoot, StateUpdates, Witness};
use thiserror::Error;
use tracing::debug;

use crate::{
    chain_spec::{BLOB_GASPRICE_UPDATE_FRACTION, ChainSpec},
    data_types::{Account, PlainKey, PlainValue},
    evm_database::WitnessDatabaseError,
    kona_replay::{self, KonaReplayError},
    withdrawals::{self, ADDRESS_L2_TO_L1_MESSAGE_PASSER, MptWitness},
};

/// Errors that can occur during block validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Witness proof verification failed: {0}")]
    WitnessVerificationFailed(#[source] salt::ProofError),

    #[error("Failed to validate changes to the withdrawal contract: {0}")]
    WithdrawalValidationFailed(#[source] withdrawals::WithdrawalValidationError),

    #[error("Failed to construct mega-evm environment oracle: {0}")]
    EnvOracleConstructionFailed(#[source] WitnessDatabaseError),

    #[error("Expecting full transaction data, only found hashes")]
    BlockIncomplete,

    #[error("Block replay failed during transaction execution: {0}")]
    BlockReplayFailed(#[source] alloy_evm::block::BlockExecutionError),

    #[error("Kona block replay failed: {0}")]
    KonaReplayFailed(#[source] KonaReplayError),

    #[error("Failed to update salt state: {0}")]
    StateUpdateFailed(#[source] salt::SaltError),

    #[error("Failed to update salt trie: {0}")]
    TrieUpdateFailed(#[source] salt::SaltError),

    #[error("Pre-state root mismatch: expecting {expected:?}, got {actual:?}")]
    PreStateRootMismatch {
        /// The post-state root of the parent block
        expected: B256,
        /// The pre-state root of the witness
        actual: B256,
    },

    #[error("Pre-withdrawals root mismatch: expecting {expected:?}, got {actual:?}")]
    PreWithdrawalsRootMismatch {
        /// The post-withdrawals root of the parent block
        expected: B256,
        /// The pre-withdrawals root of the witness
        actual: B256,
    },

    #[error("State root mismatch: claimed {claimed}, got {actual}")]
    StateRootMismatch {
        /// The computed state root from transaction execution
        actual: B256,
        /// The claimed state root from the block header
        claimed: B256,
    },

    #[error("Receipts root mismatch: claimed {claimed}, got {actual}")]
    ReceiptsRootMismatch {
        /// The computed receipts root from transaction execution
        actual: B256,
        /// The claimed receipts root from the block header
        claimed: B256,
    },

    #[error("Logs bloom mismatch: claimed {claimed}, got {actual}")]
    LogsBloomMismatch {
        /// The computed logs bloom from transaction execution
        actual: Box<Bloom>,
        /// The claimed logs bloom from the block header
        claimed: Box<Bloom>,
    },

    #[error("Gas used mismatch: claimed {claimed}, got {actual}")]
    GasUsedMismatch {
        /// The computed gas used from transaction execution
        actual: u64,
        /// The claimed gas used from the block header
        claimed: u64,
    },

    #[error("Block hash mismatch: claimed {claimed}, got {actual}")]
    BlockHashMismatch {
        /// The computed block hash from Kona block sealing
        actual: B256,
        /// The claimed block hash from the RPC block
        claimed: B256,
    },
}

/// Results from executing block transactions.
///
/// Contains the computed values needed to verify block header fields.
#[derive(Debug, Clone)]
pub struct BlockExecutionOutput {
    /// The computed receipts root from transaction execution
    pub receipts_root: B256,
    /// The aggregated logs bloom from all receipts
    pub logs_bloom: Bloom,
    /// The total gas used by all transactions
    pub gas_used: u64,
    /// Number of accounts/storage slots read during execution
    pub state_reads: usize,
    /// Number of accounts/storage slots changed
    pub state_writes: usize,
}

/// Statistics collected during block validation for metrics.
///
/// The `*_time` fields are measured with `std::time::Instant` and are always `0.0` in
/// `no_std` builds (no monotonic clock available). Consumers that meter or log these
/// values should treat `0.0` as "not measured" when running without the `std` feature.
#[derive(Debug, Clone, Default)]
pub struct ValidationStats {
    /// Number of accounts/storage slots read during execution
    pub state_reads: usize,
    /// Number of accounts/storage slots changed
    pub state_writes: usize,
    /// Time spent verifying the witness proof (seconds; `0.0` in `no_std` builds)
    pub witness_verification_time: f64,
    /// Time spent replaying block transactions (seconds; `0.0` in `no_std` builds)
    pub block_replay_time: f64,
    /// Time spent updating SALT state (seconds; `0.0` in `no_std` builds)
    pub salt_update_time: f64,
}

/// Creates an EVM execution environment from a block header and chain specification.
///
/// This function configures the EVM environment with the appropriate chain settings,
/// block parameters, and gas pricing for transaction execution.
///
/// # Arguments
///
/// * `header` - Block header containing execution parameters (number, timestamp, gas limits, etc.)
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
///
/// # Returns
///
/// Returns an `EvmEnv` configured for executing transactions in the given block context.
/// The environment includes:
/// - Chain configuration with appropriate spec ID for the block number
/// - Block environment with gas limits, timestamps, and fee parameters
/// - Blob gas pricing if excess blob gas is present in the header
///
/// Creates an EVM environment from a block header and chain specification.
///
/// This function sets up the configuration and block environment needed for EVM execution.
pub fn create_evm_env(
    header: &alloy_consensus::Header,
    chain_spec: &ChainSpec,
) -> EvmEnv<MegaSpecId> {
    let cfg_env = CfgEnv::new_with_spec(chain_spec.spec_id(header.timestamp))
        .with_chain_id(chain_spec.chain_id);

    let mut block_env = BlockEnv {
        number: U256::from(header.number),
        beneficiary: header.beneficiary,
        timestamp: U256::from(header.timestamp),
        gas_limit: header.gas_limit,
        basefee: header.base_fee_per_gas.unwrap_or_default(),
        difficulty: header.difficulty,
        prevrandao: Some(header.mix_hash),
        blob_excess_gas_and_price: None,
    };

    if let Some(excess_blob_gas) = header.excess_blob_gas {
        block_env.set_blob_excess_gas_and_price(excess_blob_gas, BLOB_GASPRICE_UPDATE_FRACTION);
    }

    EvmEnv::new(cfg_env, block_env)
}

/// Minimal projection of a block that [`replay_block`] / [`validate_block`] need: the consensus
/// header (every execution/validation field lives there), the block hash (diagnostics only), and
/// the recovered `(transaction, sender)` pairs.
///
/// Abstracting over this lets the same replay path consume either an RPC
/// [`Block<OpTransaction>`] (standalone validator, debug-trace-server) or a host's
/// already-recovered block, without a per-tx rebuild into RPC form. The trait is dependency-clean:
/// the only impl here is for the RPC block; reth-backed impls live in the embedder that already
/// depends on reth.
pub trait BlockInput {
    /// The consensus header carrying all replay/validation fields.
    fn consensus_header(&self) -> &alloy_consensus::Header;
    /// The block hash (used only for diagnostics).
    fn block_hash(&self) -> B256;
    /// Whether full transaction bodies are present. An RPC block carrying only hashes returns
    /// `false`, which [`replay_block`] maps to [`ValidationError::BlockIncomplete`].
    fn is_complete(&self) -> bool;
    /// Recovered `(transaction, sender)` pairs, borrowed — no clone, no signature re-recovery.
    ///
    /// Callers must check [`Self::is_complete`] first: an incomplete block yields an empty
    /// iterator here, not an error.
    fn txs_recovered(&self) -> impl Iterator<Item = Recovered<&OpTxEnvelope>> + '_;
}

impl BlockInput for Block<OpTransaction> {
    fn consensus_header(&self) -> &alloy_consensus::Header {
        &self.header.inner
    }

    fn block_hash(&self) -> B256 {
        self.header.hash
    }

    fn is_complete(&self) -> bool {
        matches!(self.transactions, BlockTransactions::Full(_))
    }

    fn txs_recovered(&self) -> impl Iterator<Item = Recovered<&OpTxEnvelope>> + '_ {
        // Borrow each `Recovered<OpTxEnvelope>` in place via `as_recovered_ref()` — clone-free.
        // The hashes-only case yields `&[]`, but `is_complete()` is checked first so it surfaces
        // as `BlockIncomplete`.
        let full = match &self.transactions {
            BlockTransactions::Full(txs) => txs.as_slice(),
            _ => &[],
        };
        full.iter().map(|tx| tx.inner.inner.as_recovered_ref())
    }
}

/// Replays all transactions in a block to compute state changes.
///
/// This function delegates execution to Kona's `execute_payload` path and converts the replay
/// artifacts back into the validator's historical return shape.
///
/// # Arguments
///
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
/// * `block` - Block containing full transaction data to replay
/// * `parent_header` - Parent header used to initialize Kona's safe head
/// * `salt_witness` - SALT witness used by Kona's witness provider
/// * `mpt_witness` - MPT witness used by Kona's trie provider
/// * `contracts` - Contract bytecode cache for execution
///
/// # Returns
///
/// Returns a tuple containing:
/// - A `HashMap` of cached account states from transaction execution
/// - A `BlockExecutionOutput` with receipts root, logs bloom, and gas used
///
/// # Errors
///
/// - `ValidationError::BlockIncomplete` if the block contains only transaction hashes
/// - `ValidationError::KonaReplayFailed` if Kona execution or input adaptation fails
///
/// # Process
///
/// 1. Build Kona payload attributes from the claimed block
/// 2. Initialize Kona with the parent header and witness-backed provider
/// 3. Execute the payload through `KonaExecutor::execute_payload`
/// 4. Return bundle accounts and execution output (receipts root, logs bloom, gas used)
pub fn replay_block<B: BlockInput>(
    chain_spec: &ChainSpec,
    block: &B,
    parent_header: &alloy_consensus::Header,
    salt_witness: SaltWitness,
    mpt_witness: &MptWitness,
    contracts: &HashMap<B256, Bytecode>,
    #[cfg(feature = "std")] trace_writer: Option<Box<dyn Write>>,
) -> Result<(HashMap<Address, BundleAccount>, BlockExecutionOutput), ValidationError> {
    // A block carrying only transaction hashes can't be replayed.
    if !block.is_complete() {
        return Err(ValidationError::BlockIncomplete);
    }

    #[cfg(feature = "std")]
    if trace_writer.is_some() {
        return Err(ValidationError::KonaReplayFailed(KonaReplayError::TraceUnsupported));
    }

    let header = block.consensus_header();
    debug!(
        block_number = header.number,
        block_hash = ?block.block_hash(),
        "Replay block through Kona"
    );

    let rollup_config = kona_replay::rollup_config_for_chain_id(chain_spec.chain_id)
        .map_err(ValidationError::KonaReplayFailed)?;
    let output = kona_replay::replay_block_with_kona(
        block,
        parent_header,
        salt_witness,
        mpt_witness,
        contracts,
        &rollup_config,
    )
    .map_err(ValidationError::KonaReplayFailed)?;
    if output.block_hash != block.block_hash() {
        return Err(ValidationError::BlockHashMismatch {
            actual: output.block_hash,
            claimed: block.block_hash(),
        });
    }

    Ok((
        output.bundle_state,
        BlockExecutionOutput {
            receipts_root: output.receipts_root,
            logs_bloom: output.logs_bloom,
            gas_used: output.gas_used,
            state_reads: output.state_reads,
            state_writes: output.state_writes,
        },
    ))
}

/// Validates a block by creating a witness, replaying transactions, and comparing state roots.
///
/// This function performs the core validation logic:
/// 1. Creates a Witness from the provided SaltWitness
/// 2. Verifies the witness proof
/// 3. Replays the block transactions using the witness database
/// 4. Check if computed withdrawals root matches the claimed one
/// 5. Verify receipts root matches the block header
/// 6. Computes the new state root and compares it with the expected one
///
/// # Arguments
///
/// * `chain_spec` - Chain specification defining the EVM rules and parameters
/// * `block` - The block to validate containing transactions and header information
/// * `salt_witness` - The salt witness data needed for state validation
/// * `mpt_witness` - The MPT witness data for withdrawal verification
/// * `contracts` - Contract bytecode cache for transaction execution
/// * `writer` - Optional writer for EIP-3155 trace output. When provided, enables step-by-step EVM
///   execution tracing in EIP-3155 format.
///
/// # Returns
///
/// Returns `Ok(ValidationStats)` if validation succeeds, containing state access metrics.
/// Returns `Err(ValidationError)` with the specific validation failure.
pub fn validate_block<B: BlockInput>(
    chain_spec: &ChainSpec,
    block: &B,
    parent_header: &alloy_consensus::Header,
    salt_witness: SaltWitness,
    mpt_witness: MptWitness,
    contracts: &HashMap<B256, Bytecode>,
    #[cfg(feature = "std")] writer: Option<Box<dyn Write>>,
) -> Result<ValidationStats, ValidationError> {
    // A block carrying only transaction hashes can't be replayed — fail fast before paying
    // the witness proof verification. `replay_block` re-checks for direct callers.
    if !block.is_complete() {
        return Err(ValidationError::BlockIncomplete);
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
    let (accounts, output) = replay_block(
        chain_spec,
        block,
        parent_header,
        salt_witness,
        &mpt_witness,
        contracts,
        #[cfg(feature = "std")]
        writer,
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
        });
    }

    // Verify logs bloom matches the block header
    if output.logs_bloom != header.logs_bloom {
        return Err(ValidationError::LogsBloomMismatch {
            actual: Box::new(output.logs_bloom),
            claimed: Box::new(header.logs_bloom),
        });
    }

    // Verify gas used matches the block header
    if output.gas_used != header.gas_used {
        return Err(ValidationError::GasUsedMismatch {
            actual: output.gas_used,
            claimed: header.gas_used,
        });
    }

    // Check if computed state root matches claimed state root
    let state_root = B256::from(state_root);
    if state_root != header.state_root {
        return Err(ValidationError::StateRootMismatch {
            actual: state_root,
            claimed: header.state_root,
        });
    }

    Ok(ValidationStats {
        state_reads: output.state_reads,
        state_writes: output.state_writes,
        witness_verification_time,
        block_replay_time,
        salt_update_time,
    })
}

#[cfg(test)]
mod tests {
    use stateless_test_utils::{fixtures::TestFixtures, logging::init_test_logging};

    use super::*;

    /// Locks the `BlockInput` projection for RPC blocks: completeness, hash/header passthrough,
    /// and clone-free recovered senders (including the empty projection of a hashes-only block).
    #[test]
    fn block_input_projection_for_rpc_block() {
        let fx = TestFixtures::mainnet_shared();
        let (number, hash) = *fx.paired_blocks().first().expect("paired mainnet fixtures");
        let block = &fx.blocks[&hash];

        assert!(block.is_complete());
        assert_eq!(BlockInput::block_hash(block), hash);
        assert_eq!(block.consensus_header().number, number);

        let BlockTransactions::Full(txs) = &block.transactions else {
            panic!("fixture block must carry full transactions");
        };
        assert_eq!(block.txs_recovered().count(), txs.len());
        for (recovered, tx) in block.txs_recovered().zip(txs) {
            assert_eq!(
                recovered.signer(),
                tx.inner.inner.signer(),
                "borrowed projection must keep the RPC-recovered sender"
            );
        }

        let mut hashes_only = block.clone();
        hashes_only.transactions = BlockTransactions::Hashes(Default::default());
        assert!(!hashes_only.is_complete());
        assert_eq!(hashes_only.txs_recovered().count(), 0);
    }

    /// A block carrying only transaction hashes must be rejected as `BlockIncomplete` by the
    /// `is_complete()` gate before any witness verification or replay work.
    #[test]
    fn validate_block_rejects_hashes_only_block() {
        let fx = TestFixtures::mainnet_shared();
        let chain_spec = ChainSpec::from_genesis(fx.load_genesis().unwrap());
        let (_, hash) = *fx.paired_blocks().first().expect("paired mainnet fixtures");
        let mut block = fx.blocks[&hash].clone();
        block.transactions = BlockTransactions::Hashes(Default::default());

        let err = validate_block(
            &chain_spec,
            &block,
            &fx.blocks[&block.header.parent_hash].header.inner,
            fx.salt_witnesses[&hash].clone(),
            fx.mpt_witness(&hash),
            &fx.contracts,
            #[cfg(feature = "std")]
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ValidationError::BlockIncomplete), "{err:?}");
    }

    #[test]
    fn validate_block_mainnet_fixtures() {
        let _logging = init_test_logging("stateless_core");
        let fx = TestFixtures::mainnet_shared();
        let chain_spec = ChainSpec::from_genesis(fx.load_genesis().unwrap());
        let paired = fx.paired_blocks();
        assert!(!paired.is_empty(), "no paired mainnet fixtures in test_data/mainnet");
        for (number, hash) in paired {
            let block = &fx.blocks[&hash];
            let parent_header = &fx
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
            validate_block(
                &chain_spec,
                block,
                parent_header,
                fx.salt_witnesses[&hash].clone(),
                fx.mpt_witness(&hash),
                &fx.contracts,
                #[cfg(feature = "std")]
                None,
            )
            .unwrap_or_else(|e| panic!("validate_block failed for {number} ({hash}): {e:?}"));
        }
    }
}
