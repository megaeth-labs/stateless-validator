//! RPC client wrapper with metrics support.
//!
//! Re-exports RpcClient from validator-core and adds metrics tracking.

use std::time::Instant;

use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_eth::{Block, BlockId};
use eyre::Result;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
// Re-export types from validator-core
pub use validator_core::rpc_client::{RpcClient as CoreRpcClient, SetValidatedBlocksResponse};
use validator_core::withdrawals::MptWitness;

use crate::metrics;

/// RPC client wrapper with metrics support
#[derive(Debug, Clone)]
pub struct RpcClient {
    inner: CoreRpcClient,
}

impl RpcClient {
    /// Creates a new RPC client with metrics support
    pub fn new(data_api: &str, witness_api: &str) -> Result<Self> {
        Ok(Self {
            inner: CoreRpcClient::new(data_api, witness_api)?,
        })
    }

    /// Returns a reference to the inner core RPC client
    pub fn inner(&self) -> &CoreRpcClient {
        &self.inner
    }

    /// Gets contract bytecode for a code hash (with metrics)
    pub async fn get_code(&self, hash: B256) -> Result<Bytes> {
        let start = Instant::now();
        let result = self.inner.get_code(hash).await;

        metrics::on_rpc_complete(
            metrics::RpcMethod::EthGetCodeByHash,
            result.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );
        result
    }

    /// Gets a block by its identifier (with metrics)
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let start = Instant::now();
        let result = self.inner.get_block(block_id, full_txs).await;

        metrics::on_rpc_complete(
            metrics::RpcMethod::EthGetBlockByNumber,
            result.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );
        result
    }

    /// Gets the current latest block number (with metrics)
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        let result = self.inner.get_latest_block_number().await;

        metrics::on_rpc_complete(metrics::RpcMethod::EthBlockNumber, result.is_ok(), None);
        result
    }

    /// Gets execution witness data (with metrics)
    pub async fn get_witness(&self, number: u64, hash: B256) -> Result<(SaltWitness, MptWitness)> {
        let start = Instant::now();
        let result = self.inner.get_witness(number, hash).await;

        metrics::on_rpc_complete(
            metrics::RpcMethod::MegaGetBlockWitness,
            result.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );

        if let Ok((witness, mpt_witness)) = &result {
            // Estimate sizes
            let kvs_count = witness.kvs.len();
            let salt_kvs_size = kvs_count * 103;
            let proof_size =
                witness.proof.parents_commitments.len() * 64 + 576 + witness.proof.levels.len() * 5;
            let salt_size = salt_kvs_size + proof_size;
            let mpt_size = 32 + mpt_witness.state.iter().map(|b| b.len()).sum::<usize>();

            metrics::on_witness_fetch(salt_size, kvs_count, salt_kvs_size, mpt_size);
        }

        result
    }

    /// Reports validated blocks (with metrics)
    pub async fn set_validated_blocks(
        &self,
        first_block: (u64, B256),
        last_block: (u64, B256),
    ) -> Result<SetValidatedBlocksResponse> {
        let result = self
            .inner
            .set_validated_blocks(first_block, last_block)
            .await;

        metrics::on_rpc_complete(
            metrics::RpcMethod::MegaSetValidatedBlocks,
            result.is_ok(),
            None,
        );
        result
    }
}
