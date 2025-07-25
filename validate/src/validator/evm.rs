//! This module provides functions for interacting with the EVM, specifically for replaying
//! block transactions using REVM.
use alloy_evm::EvmEnv;
use alloy_evm::EvmFactory as AlloyEvmFactory;
use alloy_evm::block::BlockExecutorFactory as AlloyBlockExecutorFactory;
use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition};
use alloy_op_evm::block::OpAlloyReceiptBuilder;
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use alloy_rpc_types_eth::{Block, BlockTransactions, Transaction};
use eyre::{Result, eyre};
use mega_evm::{BlockExecutionCtx, BlockExecutorFactory, Context, Evm, EvmFactory, SpecId};
use revm::{
    DatabaseCommit, ExecuteEvm, InspectEvm, Inspector, Journal,
    context::{
        BlockEnv, Cfg, CfgEnv, ContextSetters, ContextTr, TxEnv,
        result::{EVMError, ExecutionResult, ResultAndState},
    },
    database::CacheDB,
    handler::{EthFrame, EvmTr, instructions::InstructionProvider},
    inspector::{InspectorHandler, NoOpInspector},
    interpreter::{Interpreter, InterpreterTypes},
    primitives::{TxKind, U256},
};

use super::WitnessProvider;

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

pub fn replay_block(block: Block, db: &mut CacheDB<WitnessProvider>) -> Result<()> {
    let BlockTransactions::Full(transactions) = block.transactions.clone() else {
        return Err(eyre!("Wrong transaction type, expected full transactions"));
    };

    // The chain_spec is only used by `apply_beacon_root_contract_call` to check if the
    // Cancun hardfork is active at the block's timestamp. A mainnet spec is sufficient for this
    // purpose.
    //let chain_spec = ChainSpecBuilder::mainnet().build();
    // let mut context = Context::new(db, SpecId::MINI_RAX);
    // context.with_block(block_env);

    let block_env = get_block_env(&block)?;
    let evm_env: EvmEnv<SpecId> = EvmEnv::new(CfgEnv::default(), block_env);

    let evm_factory = EvmFactory::default();

    let evm = evm_factory.create_evm(db, evm_env);

    let op_block_execution_ctx = BlockExecutionCtx {
        parent_hash: block.header.parent_hash,
        parent_beacon_block_root: block.header.parent_beacon_block_root,
        extra_data: block.header.extra_data,
    };

    let block_executor_factory = BlockExecutorFactory::new(
        ChainSpec::default(),
        evm_factory,
        OpAlloyReceiptBuilder::default(),
    );

    let block_executor = block_executor_factory.create_executor(evm, op_block_execution_ctx);

    // // Apply the beacon root contract call, a step specific to Optimism chains.
    // apply_beacon_root_contract_call(
    //     &OptimismEvmConfig::default(),
    //     &chain_spec,
    //     block.header.timestamp,
    //     block.header.number.ok_or(eyre!("number is None"))?,
    //     block.header.parent_beacon_block_root,
    //     &mut evm,
    // )
    // .map_err(|e| eyre!("apply_beacon_root_contract_call failed: {:?}", e))?;

    // for tx in transactions {
    //     *evm.tx_mut() = get_tx_env(&tx)?;

    //     // Execute the transaction and commit its changes to the database.
    //     let _result = evm
    //         .transact_commit()
    //         .map_err(|e| eyre!("transact_commit failed: {:?}", e))?;
    // }

    Ok(())
}

/// Converts an `alloy_rpc_types_eth::Transaction` to a `revm::primitives::TxEnv`.
///
/// This function maps the fields from the RPC transaction type to the format required
/// by the REVM for transaction execution. It handles different transaction types
/// (Legacy, EIP-2930, EIP-1559, EIP-4844, EIP-7702, and Optimism's Deposit type).
///
/// # Arguments
///
/// * `tx` - A reference to the `Transaction` object to be converted.
///
/// # Returns
///
/// Returns `Ok(TxEnv)` if the conversion is successful.
/// Returns an `Err` if essential fields are missing for a given transaction type
/// (e.g., `gas_price` for a Legacy transaction) or if the transaction type is unsupported.
// fn get_tx_env(tx: &Transaction) -> Result<TxEnv> {
//     let signature = tx.signature.ok_or(eyre!("signature is None"))?;
//     let transaction = match tx.transaction_type {
//         Some(0) => RethTransaction::Legacy(TxLegacy {
//             chain_id: tx.chain_id,
//             nonce: tx.nonce,
//             gas_price: tx
//                 .gas_price
//                 .ok_or(eyre!("gas_price is None in Legacy tx"))?,
//             gas_limit: tx.gas as u64,
//             to: TxKind::from(tx.to),
//             value: tx.value,
//             input: tx.input.clone(),
//         }),
//         Some(1) => RethTransaction::Eip2930(TxEip2930 {
//             chain_id: tx.chain_id.ok_or(eyre!("chain_id is None in Eip2930 tx"))?,
//             nonce: tx.nonce,
//             gas_price: tx
//                 .gas_price
//                 .ok_or(eyre!("gas_price is None in Eip2930 tx"))?,
//             gas_limit: tx.gas as u64,
//             to: TxKind::from(tx.to),
//             value: tx.value,
//             access_list: tx.access_list.clone().unwrap_or_default(),
//             input: tx.input.clone(),
//         }),
//         Some(2) => RethTransaction::Eip1559(TxEip1559 {
//             chain_id: tx.chain_id.ok_or(eyre!("chain_id is None in Eip1559 tx"))?,
//             nonce: tx.nonce,
//             gas_limit: tx.gas as u64,
//             max_fee_per_gas: tx
//                 .max_fee_per_gas
//                 .ok_or(eyre!("max_fee_per_gas is None in Eip1559 tx"))?,
//             max_priority_fee_per_gas: tx
//                 .max_priority_fee_per_gas
//                 .ok_or(eyre!("max_priority_fee_per_gas is None in Eip1559 tx"))?,

//             to: TxKind::from(tx.to),
//             value: tx.value,
//             access_list: tx.access_list.clone().unwrap_or_default(),
//             input: tx.input.clone(),
//         }),
//         Some(3) => RethTransaction::Eip4844(TxEip4844 {
//             chain_id: tx.chain_id.ok_or(eyre!("chain_id is None in Eip4844 tx"))?,
//             nonce: tx.nonce,
//             gas_limit: tx.gas as u64,
//             max_fee_per_gas: tx
//                 .max_fee_per_gas
//                 .ok_or(eyre!("max_fee_per_gas is None in Eip4844 tx"))?,
//             max_priority_fee_per_gas: tx
//                 .max_priority_fee_per_gas
//                 .ok_or(eyre!("max_priority_fee_per_gas is None in Eip4844 tx"))?,
//             placeholder: None,
//             to: tx.to.ok_or(eyre!("to is None in Eip4844 tx"))?,
//             value: tx.value,
//             access_list: tx.access_list.clone().unwrap_or_default(),
//             blob_versioned_hashes: tx.blob_versioned_hashes.clone().unwrap_or_default(),
//             max_fee_per_blob_gas: tx
//                 .max_fee_per_blob_gas
//                 .ok_or(eyre!("max_fee_per_blob_gas is None in Eip4844 tx"))?,

//             input: tx.input.clone(),
//         }),
//         Some(4) => RethTransaction::Eip7702(TxEip7702 {
//             chain_id: tx.chain_id.ok_or(eyre!("chain_id is None in Eip7702 tx"))?,
//             nonce: tx.nonce,
//             gas_limit: tx.gas as u64,
//             max_fee_per_gas: tx
//                 .max_fee_per_gas
//                 .ok_or(eyre!("max_fee_per_gas is None in Eip7702 tx"))?,
//             max_priority_fee_per_gas: tx
//                 .max_priority_fee_per_gas
//                 .ok_or(eyre!("max_priority_fee_per_gas is None in Eip7702 tx"))?,
//             to: TxKind::from(tx.to),
//             value: tx.value,
//             access_list: tx.access_list.clone().unwrap_or_default(),
//             authorization_list: tx.authorization_list.clone().unwrap_or_default(),
//             input: tx.input.clone(),
//         }),
//         Some(126) => {
//             // This handles the Optimism-specific Deposit transaction type (type 126).
//             // It extracts custom fields like `source_hash`, `mint`, and `is_system_transaction`
//             // from the `other` field of the RPC transaction.
//             let source_hash = if let Some(source_hash_value) = tx.other.get("sourceHash") {
//                 if let Some(source_hash_str) = source_hash_value.as_str() {
//                     source_hash_str.parse().unwrap_or_default()
//                 } else {
//                     B256::default()
//                 }
//             } else {
//                 B256::default()
//             };

//             let mint = if let Some(mint_value) = tx.other.get("mint") {
//                 if let Some(mint_str) = mint_value.as_str() {
//                     U256::from_str(mint_str).ok().map(|v| v.to::<u128>())
//                 } else if let Some(mint_num) = mint_value.as_u64() {
//                     Some(mint_num as u128)
//                 } else {
//                     None
//                 }
//             } else {
//                 None
//             };

//             let is_system_transaction = if let Some(is_system_tx_value) = tx.other.get("isSystemTx")
//             {
//                 is_system_tx_value.as_bool().unwrap_or_default()
//             } else {
//                 false
//             };

//             RethTransaction::Deposit(TxDeposit {
//                 source_hash,
//                 from: tx.from,
//                 to: TxKind::from(tx.to),
//                 mint,
//                 value: tx.value,
//                 gas_limit: tx.gas as u64,
//                 is_system_transaction,
//                 input: tx.input.clone(),
//             })
//         }
//         _ => {
//             return Err(eyre!(
//                 "Unsupported transaction type: {:?}",
//                 tx.transaction_type
//             ));
//         }
//     };

//     let signed_tx = TransactionSigned {
//         hash: tx.hash,
//         signature: Signature {
//             r: signature.r,
//             s: signature.s,
//             odd_y_parity: signature.y_parity.unwrap_or_default().0,
//         },
//         transaction,
//     };

//     let mut env = TxEnv::default();

//     signed_tx.fill_tx_env(&mut env, tx.from);

//     Ok(env)
// }

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
fn get_block_env(block: &Block) -> Result<BlockEnv> {
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
