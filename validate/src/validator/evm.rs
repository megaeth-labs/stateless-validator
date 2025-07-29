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
use revm::{
    context::{BlockEnv, CfgEnv},
    database::states::{CacheAccount, StateBuilder},
    primitives::{Address, HashMap},
};

use crate::validator::WitnessProvider;
use crate::validator::evm::receipts::OpRethReceiptBuilder;
use crate::validator::evm::signed::OpTransactionSigned;

mod receipt;
mod receipts;
mod signed;

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
        ChainSpec::default(),
        EvmFactory::default(),
        OpRethReceiptBuilder::default(),
    );

    let op_block_execution_ctx = BlockExecutionCtx {
        parent_hash: block.header.parent_hash,
        parent_beacon_block_root: block.header.parent_beacon_block_root,
        extra_data: block.header.extra_data.clone(),
    };

    let block_env = get_block_env(&block)?;
    let evm_env: EvmEnv<SpecId> = EvmEnv::new(CfgEnv::default(), block_env);

    let mut block_executor = block_executor_factory.create_executor(
        block_executor_factory
            .evm_factory()
            .create_evm(&mut state, evm_env),
        op_block_execution_ctx,
    );

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

    // let (evm, result) = block_executor
    //     .finish()
    //     .map_err(|e| eyre!("finish failed: {:?}", e))?;

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
        number: header.number,
        beneficiary: header.beneficiary,
        timestamp: header.timestamp,
        gas_limit: header.gas_limit,
        basefee: header.base_fee_per_gas.unwrap_or_default(),
        difficulty: header.difficulty,
        prevrandao: Some(header.mix_hash),
        // Set the blob excess gas and price from the header, if available.
        blob_excess_gas_and_price: None,
    };

    if let Some(excess_blob_gas) = header.excess_blob_gas {
        block_env.set_blob_excess_gas_and_price(excess_blob_gas, true);
    }

    Ok(block_env)
}

// / Creates a `CfgEnvWithHandlerCfg` with specific Optimism configurations.
// /
// / The configuration values (e.g., chain_id, memory_limit, spec_id) are hardcoded
// / here for simplicity, but in a production environment, they would typically be
// / derived from chain specifications or other configuration sources.
// fn get_evm_config() -> CfgEnvWithHandlerCfg {
//     let mut cfg_env = CfgEnv::default();

//     cfg_env.chain_id = 6342;
//     cfg_env.blob_target_and_max_count = vec![(SpecId::CANCUN, 3, 6), (SpecId::PRAGUE, 6, 9)];
//     cfg_env.memory_limit = u32::MAX as u64;

//     CfgEnvWithHandlerCfg {
//         cfg_env,
//         handler_cfg: HandlerCfg {
//             // Set the EVM specification ID. This should be kept up to date with the network's
//             // current hardfork.
//             spec_id: SpecId::PRAGUE,
//             // Enable Optimism-specific EVM rules.
//             is_optimism: true,
//         },
//     }
// }

#[derive(Default, Clone, Copy)]
struct ChainSpec;

impl EthereumHardforks for ChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        match fork {
            EthereumHardfork::Shanghai
            | EthereumHardfork::Cancun
            | EthereumHardfork::Prague
            | EthereumHardfork::Osaka => ForkCondition::Timestamp(0),
            _ => ForkCondition::Block(0),
        }
    }
}

impl OpHardforks for ChainSpec {
    fn op_fork_activation(&self, fork: OpHardfork) -> ForkCondition {
        match fork {
            OpHardfork::Bedrock => ForkCondition::Block(0),
            _ => ForkCondition::Timestamp(0),
        }
    }
}
