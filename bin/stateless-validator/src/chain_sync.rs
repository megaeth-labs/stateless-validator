//! Validator-specific pipeline components.
//!
//! Provides [`ValidatorProcessor`] (block validation via [`validate_block`]) and
//! [`ValidatorHooks`] (metrics integration) for the shared pipeline in
//! [`stateless_core::pipeline::run_pipeline`].

use std::{collections::HashSet, sync::Arc};

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, BlockId};
use eyre::{Result, ensure};
use futures::future;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;
use stateless_common::{RpcClient, db::ContractCache};
use stateless_core::{
    chain_spec::ChainSpec,
    data_types::iter_code_hashes,
    db::BlockMeta,
    executor::validate_block,
    pipeline::{BlockFetcher, BlockProcessor, ErrorAction, PipelineHooks, ProcessedBlock},
    withdrawals::MptWitness,
};
use tokio::task;
use tracing::{debug, error};

use crate::metrics;

/// Fetcher for the validator: fetches blocks + witnesses from RPC,
/// wraps in [`ValidationTask`], and records remote chain height for metrics.
pub struct ValidatorFetcher {
    pub rpc_client: Arc<RpcClient>,
    pub on_remote_height: fn(u64),
}

impl BlockFetcher for ValidatorFetcher {
    type Output = ValidationTask;

    async fn fetch(&self, block_number: u64) -> Result<ValidationTask> {
        let block_hash = self.rpc_client.get_block_hash(block_number).await?;
        let (salt_witness, mpt_witness) =
            self.rpc_client.get_witness(block_number, block_hash).await?;
        let block = self.rpc_client.get_block(BlockId::Number(block_number.into()), true).await?;
        Ok(ValidationTask { block, salt_witness, mpt_witness })
    }

    async fn latest_block_number(&self) -> Result<u64> {
        let n = self.rpc_client.get_latest_block_number().await?;
        (self.on_remote_height)(n);
        Ok(n)
    }

    async fn block_hash(&self, block_number: u64) -> Result<BlockHash> {
        self.rpc_client.get_block_hash(block_number).await
    }

    async fn latest_block_meta(&self) -> Result<BlockMeta> {
        let header = self.rpc_client.get_header(BlockId::latest(), false).await?;
        Ok(BlockMeta {
            block_number: header.number,
            block_hash: header.hash,
            post_state_root: header.state_root,
            post_withdrawals_root: header.withdrawals_root.unwrap_or_default(),
        })
    }
}

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
    /// `true` for transient errors (RPC timeout) that are worth retrying.
    /// `false` for deterministic failures (validation mismatch) that should halt.
    pub transient: bool,
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

        let fail = |error: String, transient: bool| ValidationFailure {
            block_number,
            block_hash,
            error,
            transient,
        };

        // Resolve contract codes
        let codehashes: HashSet<B256> = iter_code_hashes(&task.salt_witness.kvs).collect();
        let (mut contracts, missing_contracts) = self
            .contract_cache
            .get(&codehashes.iter().copied().collect::<Vec<_>>())
            .map_err(|e| fail(format!("Failed to get contracts: {e}"), true))?;

        metrics::on_contract_cache_read(contracts.len() as u64, missing_contracts.len() as u64);

        if !missing_contracts.is_empty() {
            let client = self.rpc_client.clone();
            let codes = future::try_join_all(missing_contracts.iter().map(|&hash| {
                let client = client.clone();
                async move { client.get_code(hash).await }
            }))
            .await
            .map_err(|e| fail(format!("Failed to fetch contracts: {e}"), true))?;

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
                .map_err(|e| fail(format!("Contract hash mismatch: {e}"), false))?;

            self.contract_cache
                .insert(&new_bytecodes)
                .map_err(|e| fail(format!("Failed to cache contracts: {e}"), true))?;
            contracts.extend(new_bytecodes);
        }

        // Extract fields before moving data into spawn_blocking
        let parent_hash = task.block.header.parent_hash;
        let pre_state_root = B256::from(
            task.salt_witness
                .state_root()
                .map_err(|e| fail(format!("Failed to compute state root: {e}"), false))?,
        );
        let post_state_root = task.block.header.state_root;
        let pre_withdrawals_root = task.mpt_witness.storage_root;
        let post_withdrawals_root = task
            .block
            .header
            .withdrawals_root
            .ok_or_else(|| fail("Withdrawals root not found in block".to_string(), false))?;

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
        .map_err(|e| fail(format!("Validation task panicked: {e}"), false))?;

        match &validation_result {
            Ok(stats) => {
                debug!(block_number, "[Worker] Successfully validated block");
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
                Err(fail(e.to_string(), false))
            }
        }
    }

    fn error_action(&self, error: &ValidationFailure) -> ErrorAction {
        if error.transient { ErrorAction::Retry } else { ErrorAction::Halt }
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

#[cfg(test)]
mod tests {
    use stateless_core::pipeline::ProcessedBlock;

    use super::*;

    fn make_block_meta(num: u64) -> BlockMeta {
        BlockMeta {
            block_number: num,
            block_hash: BlockHash::from([num as u8; 32]),
            post_state_root: B256::from([(num.wrapping_add(100)) as u8; 32]),
            post_withdrawals_root: B256::from([(num.wrapping_add(200)) as u8; 32]),
        }
    }

    #[test]
    fn test_verify_continuity_success() {
        let tip = make_block_meta(10);
        let validated = ValidatedBlock {
            block_number: 11,
            block_hash: BlockHash::from([11u8; 32]),
            parent_hash: tip.block_hash,
            post_state_root: B256::from([3u8; 32]),
            post_withdrawals_root: B256::from([4u8; 32]),
            pre_state_root: tip.post_state_root,
            pre_withdrawals_root: tip.post_withdrawals_root,
        };
        validated.verify_continuity(&tip).unwrap();
    }

    #[test]
    fn test_verify_continuity_state_root_mismatch() {
        let tip = make_block_meta(10);
        let validated = ValidatedBlock {
            block_number: 11,
            block_hash: BlockHash::from([11u8; 32]),
            parent_hash: tip.block_hash,
            post_state_root: B256::from([3u8; 32]),
            post_withdrawals_root: B256::from([4u8; 32]),
            pre_state_root: B256::from([99u8; 32]),
            pre_withdrawals_root: tip.post_withdrawals_root,
        };
        let err = validated.verify_continuity(&tip).unwrap_err();
        assert!(err.to_string().contains("State root mismatch"));
    }

    #[test]
    fn test_verify_continuity_withdrawals_root_mismatch() {
        let tip = make_block_meta(10);
        let validated = ValidatedBlock {
            block_number: 11,
            block_hash: BlockHash::from([11u8; 32]),
            parent_hash: tip.block_hash,
            post_state_root: B256::from([3u8; 32]),
            post_withdrawals_root: B256::from([4u8; 32]),
            pre_state_root: tip.post_state_root,
            pre_withdrawals_root: B256::from([99u8; 32]),
        };
        let err = validated.verify_continuity(&tip).unwrap_err();
        assert!(err.to_string().contains("Withdrawals root mismatch"));
    }
}
