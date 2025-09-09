//! This module provides functions for interacting with the EVM, specifically for replaying
//! block transactions using REVM.
use alloy_consensus::transaction::Recovered;
use alloy_evm::{
    EvmEnv, EvmFactory as AlloyEvmFactory, block::BlockExecutor,
    block::BlockExecutorFactory as AlloyBlockExecutorFactory,
};
use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition};
use alloy_network_primitives::TransactionResponse;
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use alloy_rpc_types_eth::{Block, BlockTransactions};
use eyre::{Result, eyre};
use mega_evm::{BlockExecutionCtx, BlockExecutorFactory, EvmFactory, SpecId};
use op_alloy_rpc_types::Transaction as OpTransaction;
use op_revm::L1BlockInfo;
use revm::{
    context::{BlockEnv, CfgEnv, ContextTr},
    database::states::{CacheAccount, StateBuilder},
    handler::EvmTr,
    primitives::{Address, HashMap, U256},
};

use crate::evm::receipts::OpRethReceiptBuilder;
use crate::evm::signed::OpTransactionSigned;
use crate::provider::WitnessProvider;

mod data_types;
mod receipt;
mod receipts;
mod signed;

pub use data_types::*;

/// Replays a block's transactions against a given pre-state represented by a `WitnessProvider`.
///
/// This function simulates the execution of all transactions within a block
/// on the provided witness-backed database. It configures a REVM instance with
/// Optimism-specific settings and applies each transaction sequentially.
///
/// # Arguments
///
/// * `block` - The `Block` to be replayed, containing full transaction details.
/// * `db` - A mutable reference to a `CacheDB` backed by a `WitnessProvider`. This database
///   provides the necessary pre-state for transaction execution and will be updated as transactions
///   are processed.
///
/// # Returns
///
/// Returns `Ok(())` if the block replay is successful. Returns an `Err` if any part of the
/// replay process fails, such as encountering wrong transaction types, issues with
/// block data, or errors during EVM execution.
pub fn replay_block(
    block: Block<OpTransaction>,
    provider: &WitnessProvider,
) -> Result<HashMap<Address, CacheAccount>> {
    let BlockTransactions::Full(transactions) = block.transactions.clone() else {
        return Err(eyre!("Wrong transaction type, expected full transactions"));
    };

    let mut state = StateBuilder::new().with_database_ref(provider).build();

    let block_executor_factory = BlockExecutorFactory::new(
        ChainSpec,
        EvmFactory::default(),
        OpRethReceiptBuilder::default(),
    );

    let op_block_execution_ctx = BlockExecutionCtx {
        parent_hash: block.header.parent_hash,
        parent_beacon_block_root: block.header.parent_beacon_block_root,
        extra_data: block.header.extra_data.clone(),
    };

    let block_env = get_block_env(&block)?;
    let evm_env: EvmEnv<SpecId> = EvmEnv::new(get_evm_config(), block_env);

    let mut l1_block_info = L1BlockInfo::default();
    l1_block_info.operator_fee_scalar = Some(U256::from(0));
    l1_block_info.operator_fee_constant = Some(U256::from(0));

    let mut evm = block_executor_factory
        .evm_factory()
        .create_evm(&mut state, evm_env);

    // to fix l1_block_info.operator_fee_scalar.expect() when set blockhash in apply_pre_execution_changes
    *evm.ctx_mut().chain_mut() = l1_block_info;

    let mut block_executor = block_executor_factory.create_executor(evm, op_block_execution_ctx);

    block_executor
        .apply_pre_execution_changes()
        .map_err(|e| eyre!("apply_pre_execution_changes failed: {:?}", e))?;

    for tx in transactions {
        let signer = tx.from();

        let tx_signed = OpTransactionSigned::from(tx);
        let recovered = Recovered::new_unchecked(&tx_signed, signer);
        let _res = block_executor.execute_transaction(recovered)?;
    }

    block_executor
        .apply_post_execution_changes()
        .map_err(|e| eyre!("apply_post_execution_changes failed: {:?}", e))?;

    Ok(state.cache.accounts)
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
        // Set the blob excess gas and price from the header, if available.
        blob_excess_gas_and_price: None,
    };

    if let Some(excess_blob_gas) = header.excess_blob_gas {
        // Default blob base fee update fraction for Cancun (from EIP-4844)
        const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3338477;
        block_env.set_blob_excess_gas_and_price(excess_blob_gas, BLOB_GASPRICE_UPDATE_FRACTION);
    }

    Ok(block_env)
}

// Creates a CfgEnvWithHandlerCfg with specific Optimism configurations.
// The configuration values (e.g., chain_id, memory_limit, spec_id) are
// typically derived from sequencer logs or chain specifications.
fn get_evm_config() -> CfgEnv<SpecId> {
    let mut cfg_env = CfgEnv::new_with_spec(SpecId::EQUIVALENCE);

    cfg_env.chain_id = 6342;
    cfg_env.memory_limit = 4294967295; // u32::MAX
    cfg_env
}

#[derive(Default, Clone, Copy)]
struct ChainSpec;

impl EthereumHardforks for ChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        match fork {
            EthereumHardfork::Shanghai | EthereumHardfork::Cancun | EthereumHardfork::Prague => {
                ForkCondition::Timestamp(0)
            }
            EthereumHardfork::Osaka => ForkCondition::Never,
            _ => ForkCondition::Block(0),
        }
    }
}

impl OpHardforks for ChainSpec {
    fn op_fork_activation(&self, fork: OpHardfork) -> ForkCondition {
        match fork {
            OpHardfork::Bedrock => ForkCondition::Block(0),
            OpHardfork::Interop => ForkCondition::Never,
            _ => ForkCondition::Timestamp(0),
        }
    }
}
