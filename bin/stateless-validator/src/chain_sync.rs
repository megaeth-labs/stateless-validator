//! Validator-specific pipeline components.
//!
//! Provides [`ValidatorProcessor`] (block validation via [`validate_block`]) and
//! [`ValidatorHooks`] (metrics integration) for the shared pipeline in
//! [`stateless_core::pipeline::run_pipeline`].

use std::{collections::HashSet, sync::Arc};

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use eyre::ensure;
use futures::future;
use op_alloy_rpc_types::Transaction;
use revm::{primitives::KECCAK_EMPTY, state::Bytecode};
use salt::SaltWitness;
use stateless_common::{RpcClient, db::ContractCache};
use stateless_core::{
    chain_spec::ChainSpec,
    data_types::{PlainKey, PlainValue},
    db::BlockMeta,
    executor::validate_block,
    pipeline::{BlockProcessor, PipelineHooks, ProcessedBlock},
    withdrawals::MptWitness,
};
use tokio::task;
use tracing::{error, info};

use crate::metrics;

/// Block with all data needed for validation, flowing through the fetch→worker channel.
#[derive(Clone, Debug)]
pub struct ValidationTask {
    pub block: Block<Transaction>,
    pub salt_witness: SaltWitness,
    pub mpt_witness: MptWitness,
}

/// Result of successfully validating a block, flowing through the worker→advancer channel.
#[derive(Debug, Clone)]
pub struct ValidatedBlock {
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
    pub parent_hash: BlockHash,
    pub post_state_root: B256,
    pub post_withdrawals_root: B256,
    pub pre_state_root: B256,
    pub pre_withdrawals_root: B256,
}

impl ProcessedBlock for ValidatedBlock {
    fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    fn parent_hash(&self) -> BlockHash {
        self.parent_hash
    }

    fn to_block_meta(&self) -> BlockMeta {
        BlockMeta {
            block_number: self.block_number,
            block_hash: self.block_hash,
            post_state_root: self.post_state_root,
            post_withdrawals_root: self.post_withdrawals_root,
        }
    }

    fn verify_continuity(&self, previous_tip: &BlockMeta) -> eyre::Result<()> {
        ensure!(
            self.pre_state_root == previous_tip.post_state_root,
            "State root mismatch at block {}: expected {:?}, got {:?}",
            self.block_number,
            previous_tip.post_state_root,
            self.pre_state_root,
        );
        ensure!(
            self.pre_withdrawals_root == previous_tip.post_withdrawals_root,
            "Withdrawals root mismatch at block {}: expected {:?}, got {:?}",
            self.block_number,
            previous_tip.post_withdrawals_root,
            self.pre_withdrawals_root,
        );
        Ok(())
    }
}

/// Validation failure sent from worker to advancer.
#[derive(Debug)]
pub struct ValidationFailure {
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
    pub error: String,
}

impl std::fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {} ({}) validation failed: {}",
            self.block_number, self.block_hash, self.error
        )
    }
}

/// Block processor for the validator: validates blocks using EVM execution.
pub struct ValidatorProcessor {
    pub chain_spec: Arc<ChainSpec>,
    pub contract_cache: Arc<ContractCache>,
    pub rpc_client: Arc<RpcClient>,
}

impl BlockProcessor for ValidatorProcessor {
    type Input = ValidationTask;
    type Output = ValidatedBlock;
    type Error = ValidationFailure;

    async fn process(
        &self,
        task: ValidationTask,
    ) -> std::result::Result<ValidatedBlock, ValidationFailure> {
        let block_number = task.block.header.number;
        let block_hash = task.block.header.hash;
        let tx_count = task.block.transactions.len() as u64;
        let gas_used = task.block.header.gas_used;
        let start = std::time::Instant::now();

        // Resolve contract codes
        let codehashes = extract_contract_codes(&task.salt_witness);
        let (mut contracts, missing_contracts) = self
            .contract_cache
            .get(&codehashes.iter().copied().collect::<Vec<_>>())
            .map_err(|e| ValidationFailure {
                block_number,
                block_hash,
                error: format!("Failed to get contracts: {e}"),
            })?;

        metrics::on_contract_cache_read(contracts.len() as u64, missing_contracts.len() as u64);

        if !missing_contracts.is_empty() {
            let client = self.rpc_client.clone();
            let codes = future::try_join_all(missing_contracts.iter().map(|&hash| {
                let client = client.clone();
                async move { client.get_code(hash).await }
            }))
            .await
            .map_err(|e| ValidationFailure {
                block_number,
                block_hash,
                error: format!("Failed to fetch contracts: {e}"),
            })?;

            let new_bytecodes: Vec<_> = missing_contracts
                .into_iter()
                .zip(codes.iter())
                .map(|(code_hash, bytes)| {
                    let bytecode = Bytecode::new_raw(bytes.clone());
                    let computed_hash = bytecode.hash_slow();
                    ensure!(
                        computed_hash == code_hash,
                        "RPC provider returned bytecode with unexpected codehash: expected {code_hash:?}, got {computed_hash:?}",
                    );
                    Ok((computed_hash, bytecode))
                })
                .collect::<eyre::Result<_>>()
                .map_err(|e| ValidationFailure {
                    block_number,
                    block_hash,
                    error: format!("Contract hash mismatch: {e}"),
                })?;

            self.contract_cache.insert(&new_bytecodes).map_err(|e| ValidationFailure {
                block_number,
                block_hash,
                error: format!("Failed to cache contracts: {e}"),
            })?;
            contracts.extend(new_bytecodes);
        }

        // Extract fields before moving data into spawn_blocking
        let parent_hash = task.block.header.parent_hash;
        let pre_state_root =
            B256::from(task.salt_witness.state_root().map_err(|e| ValidationFailure {
                block_number,
                block_hash,
                error: format!("Failed to compute state root: {e}"),
            })?);
        let post_state_root = task.block.header.state_root;
        let pre_withdrawals_root = task.mpt_witness.storage_root;
        let post_withdrawals_root =
            task.block.header.withdrawals_root.ok_or(ValidationFailure {
                block_number,
                block_hash,
                error: "Withdrawals root not found in block".to_string(),
            })?;

        // Validate in a blocking thread
        let chain_spec = self.chain_spec.clone();
        let validation_result = task::spawn_blocking(move || {
            validate_block(
                &chain_spec,
                &task.block,
                task.salt_witness,
                task.mpt_witness,
                &contracts,
                None,
            )
        })
        .await
        .map_err(|e| ValidationFailure {
            block_number,
            block_hash,
            error: format!("Validation task panicked: {e}"),
        })?;

        match &validation_result {
            Ok(stats) => {
                info!(block_number, "[Worker] Successfully validated block");
                metrics::on_validation_success(
                    start.elapsed().as_secs_f64(),
                    stats.witness_verification_time,
                    stats.block_replay_time,
                    stats.salt_update_time,
                    tx_count,
                    gas_used,
                    stats.state_reads,
                    stats.state_writes,
                );
                Ok(ValidatedBlock {
                    block_number,
                    block_hash,
                    parent_hash,
                    post_state_root,
                    post_withdrawals_root,
                    pre_state_root,
                    pre_withdrawals_root,
                })
            }
            Err(e) => {
                error!(block_number, error = %e, "[Worker] Failed to validate block");
                Err(ValidationFailure { block_number, block_hash, error: e.to_string() })
            }
        }
    }

    fn on_task_done(&self, worker_id: usize, success: bool) {
        metrics::on_worker_task_done(worker_id, success);
    }
}

/// Pipeline hooks for the validator: metrics updates on advance/reorg.
pub struct ValidatorHooks;

impl PipelineHooks for ValidatorHooks {
    type Output = ValidatedBlock;

    fn post_advance(&self, new_tip: &BlockMeta) -> eyre::Result<()> {
        metrics::set_chain_height(new_tip.block_number);
        Ok(())
    }

    fn on_reorg(
        &self,
        _rollback_to: alloy_primitives::BlockNumber,
        depth: u64,
        _reverted_hashes: &[alloy_primitives::BlockHash],
    ) -> eyre::Result<()> {
        metrics::on_reorg(depth);
        Ok(())
    }
}

/// Returns all contract code hashes from the witness.
fn extract_contract_codes(salt_witness: &SaltWitness) -> HashSet<B256> {
    salt_witness
        .kvs
        .values()
        .filter_map(|salt_val| salt_val.as_ref())
        .filter_map(|val| match (PlainKey::decode(val.key()), PlainValue::decode(val.value())) {
            (PlainKey::Account(_), PlainValue::Account(acc)) => {
                acc.codehash.filter(|&codehash| codehash != KECCAK_EMPTY)
            }
            _ => None,
        })
        .collect()
}
