//! RPC abstraction layer for stateless validation.
//!
//! Defines [`ChainDataProvider`] — the async trait for fetching blockchain data,
//! used by the pipeline without depending on any concrete HTTP client.
//!
//! Concrete implementations and RPC data types live in `stateless-common`.

use std::{future::Future, sync::Arc};

use alloy_primitives::B256;
use alloy_rpc_types_eth::{Block, BlockId};
use eyre::Result;
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;

use crate::withdrawals::MptWitness;

/// Async trait for fetching blockchain data from a remote source.
///
/// This is the abstraction that allows `pipeline` to work without
/// depending on any concrete HTTP client. The concrete `RpcClient`
/// in `stateless-common` implements this trait.
pub trait ChainDataProvider: Send + Sync {
    /// Gets the current latest block number from the blockchain.
    fn get_latest_block_number(&self) -> impl Future<Output = Result<u64>> + Send;

    /// Gets just the block hash for a block number.
    fn get_block_hash(&self, block_number: u64) -> impl Future<Output = Result<B256>> + Send;

    /// Gets execution witness data for a specific block.
    fn get_witness(
        &self,
        number: u64,
        hash: B256,
    ) -> impl Future<Output = Result<(SaltWitness, MptWitness)>> + Send;

    /// Gets a block by its identifier with optional transaction details.
    fn get_block(
        &self,
        block_id: BlockId,
        full_txs: bool,
    ) -> impl Future<Output = Result<Block<Transaction>>> + Send;
}

/// Blanket implementation so `Arc<C>` also implements `ChainDataProvider`.
impl<C: ChainDataProvider> ChainDataProvider for Arc<C> {
    fn get_latest_block_number(&self) -> impl Future<Output = Result<u64>> + Send {
        (**self).get_latest_block_number()
    }

    fn get_block_hash(&self, block_number: u64) -> impl Future<Output = Result<B256>> + Send {
        (**self).get_block_hash(block_number)
    }

    fn get_witness(
        &self,
        number: u64,
        hash: B256,
    ) -> impl Future<Output = Result<(SaltWitness, MptWitness)>> + Send {
        (**self).get_witness(number, hash)
    }

    fn get_block(
        &self,
        block_id: BlockId,
        full_txs: bool,
    ) -> impl Future<Output = Result<Block<Transaction>>> + Send {
        (**self).get_block(block_id, full_txs)
    }
}
