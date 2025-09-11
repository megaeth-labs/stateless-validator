//! Block execution logic for replaying transactions using REVM.

use alloy_consensus::transaction::Recovered;
use alloy_evm::{
    EvmEnv, EvmFactory as AlloyEvmFactory,
    block::{BlockExecutor, BlockExecutorFactory as AlloyBlockExecutorFactory},
};
use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition};
use alloy_network_primitives::TransactionResponse;
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use alloy_rpc_types_eth::{Block, BlockTransactions};
use eyre::{Result, eyre};
use mega_evm::{BlockExecutionCtx, BlockExecutorFactory, EvmFactory, SpecId};
use op_alloy_rpc_types::Transaction as OpTransaction;
use op_revm::L1BlockInfo;
use revm::{
    context::{BlockEnv, CfgEnv, ContextTr},
    database::states::StateBuilder,
    handler::EvmTr,
    primitives::{B256, HashMap, KECCAK_EMPTY, U256},
};

use crate::{
    database::WitnessDatabase,
    evm::{Account, PlainKey, PlainValue},
};

/// Chain ID for the EVM configuration
const CHAIN_ID: u64 = 6342;
/// Maximum memory limit for EVM execution (u32::MAX)
const MEMORY_LIMIT: u64 = 4294967295;
/// Default blob gas price update fraction for Cancun (from EIP-4844)
const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3338477;

/// Replays a block's transactions and returns state updates in plain key-value format.
///
/// This function simulates the execution of all transactions within a block using the provided
/// witness-backed database. It configures a REVM instance with Optimism-specific settings,
/// applies each transaction sequentially, and converts the resulting state changes to a plain
/// key-value format suitable for state trie operations.
///
/// # Arguments
///
/// * `block` - The `Block` to be replayed, containing full transaction details.
/// * `db` - A `WitnessDatabase` that provides the necessary pre-state for transaction execution.
///
/// # Returns
///
/// Returns `Ok(HashMap<Vec<u8>, Option<Vec<u8>>>)` containing the state updates in plain format:
/// - Keys are encoded account addresses or storage slot identifiers
/// - Values are encoded account data or storage values (`None` indicates deletion)
///
/// Returns an `Err` if any part of the replay process fails, such as encountering wrong
/// transaction types, issues with block data, or errors during EVM execution.
pub fn replay_block(
    block: Block<OpTransaction>,
    db: &WitnessDatabase,
) -> Result<HashMap<Vec<u8>, Option<Vec<u8>>>> {
    let BlockTransactions::Full(transactions) = block.transactions.clone() else {
        return Err(eyre!("Wrong transaction type, expected full transactions"));
    };

    let mut state = StateBuilder::new().with_database_ref(db).build();

    let block_executor_factory = BlockExecutorFactory::new(
        ChainSpec,
        EvmFactory::default(),
        OpAlloyReceiptBuilder::default(),
    );

    let op_block_execution_ctx = BlockExecutionCtx {
        parent_hash: block.header.parent_hash,
        parent_beacon_block_root: block.header.parent_beacon_block_root,
        extra_data: block.header.extra_data.clone(),
    };

    let evm_env = EvmEnv::new(get_evm_config(), get_block_env(&block)?);

    let mut l1_block_info = L1BlockInfo::default();
    l1_block_info.operator_fee_scalar = Some(U256::ZERO);
    l1_block_info.operator_fee_constant = Some(U256::ZERO);

    let mut evm = block_executor_factory
        .evm_factory()
        .create_evm(&mut state, evm_env);

    // Set L1 block info to fix operator_fee_scalar.expect() when setting blockhash
    *evm.ctx_mut().chain_mut() = l1_block_info;

    let mut block_executor = block_executor_factory.create_executor(evm, op_block_execution_ctx);

    block_executor
        .apply_pre_execution_changes()
        .map_err(|e| eyre!("apply_pre_execution_changes failed: {:?}", e))?;

    for tx in transactions {
        let signer = tx.from();
        let op_tx_envelope = tx.inner.into_inner();
        let recovered = Recovered::new_unchecked(&op_tx_envelope, signer);
        block_executor.execute_transaction(recovered)?;
    }

    block_executor
        .apply_post_execution_changes()
        .map_err(|e| eyre!("apply_post_execution_changes failed: {:?}", e))?;

    // Flatten REVM's CacheAccount format into plain key-value pairs
    let mut kv_updates = HashMap::default();
    for (address, cache_account) in state.cache.accounts {
        if let (Some((info, storage)), _) = cache_account.into_components() {
            // Handle account
            let account = Account {
                nonce: info.nonce,
                balance: info.balance,
                codehash: (info.code_hash != KECCAK_EMPTY).then_some(info.code_hash),
            };

            let account_value =
                (!account.is_empty()).then(|| PlainValue::Account(account).encode());
            kv_updates.insert(PlainKey::Account(address).encode(), account_value);

            // Handle storage
            for (slot, value) in storage {
                let storage_value = (!value.is_zero()).then(|| PlainValue::Storage(value).encode());
                kv_updates.insert(
                    PlainKey::Storage(address, B256::new(slot.to_be_bytes())).encode(),
                    storage_value,
                );
            }
        }
    }

    Ok(kv_updates)
}

/// Creates a `revm::primitives::BlockEnv` from an `alloy_rpc_types_eth::Block`.
///
/// This function extracts necessary header information from the RPC block type
/// and populates a `BlockEnv` structure, which is used by REVM to set the
/// context for block execution.
///
/// # Arguments
///
/// * `block` - A reference to the `Block` object from which to derive the `BlockEnv`.
///
/// # Returns
///
/// Returns `Ok(BlockEnv)` if the conversion is successful.
/// Returns an `Err` if essential block header fields like `number` are missing.
fn get_block_env(block: &Block<OpTransaction>) -> Result<BlockEnv> {
    let header = &block.header;
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

    Ok(block_env)
}

/// Creates a CfgEnv with specific Optimism configurations.
/// The configuration values (e.g., chain_id, memory_limit, spec_id) are
/// typically derived from sequencer logs or chain specifications.
fn get_evm_config() -> CfgEnv<SpecId> {
    let mut cfg_env = CfgEnv::new_with_spec(SpecId::EQUIVALENCE);
    cfg_env.chain_id = CHAIN_ID;
    cfg_env.memory_limit = MEMORY_LIMIT;
    cfg_env
}

#[derive(Default, Clone, Copy)]
struct ChainSpec;

impl EthereumHardforks for ChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        use EthereumHardfork::*;
        match fork {
            Shanghai | Cancun | Prague => ForkCondition::Timestamp(0),
            Osaka => ForkCondition::Never,
            _ => ForkCondition::Block(0),
        }
    }
}

impl OpHardforks for ChainSpec {
    fn op_fork_activation(&self, fork: OpHardfork) -> ForkCondition {
        use OpHardfork::*;
        match fork {
            Bedrock => ForkCondition::Block(0),
            Interop => ForkCondition::Never,
            _ => ForkCondition::Timestamp(0),
        }
    }
}
