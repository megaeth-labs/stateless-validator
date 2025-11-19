//! RPC client for fetching missing data during stateless validation.
use alloy_consensus::transaction::SignerRecoverable;
use alloy_primitives::{Address, B256, Bytes};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag, BlockTransactions};
use alloy_trie::root::ordered_trie_root_with_encoder;
use eyre::{Context, Result, ensure, eyre};
use futures::future::try_join_all;
use op_alloy_network::{Optimism, TransactionResponse, eip2718::Encodable2718};
use op_alloy_rpc_types::Transaction;
use salt::SaltWitness;
use serde::{Deserialize, Serialize};
use validator_core::withdrawals::MptWitness;

/// Response from mega_setValidatedBlocks RPC call
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetValidatedBlocksResponse {
    pub accepted: bool,
    pub last_validated_block: (u64, B256),
}

/// RPC client for MegaETH blockchain data.
///
/// Fetches contract bytecode, blocks, and witness data during stateless validation.
#[derive(Debug, Clone)]
pub struct RpcClient {
    /// Upstream MegaETH node providing blocks and contract bytecode.
    pub data_provider: RootProvider<Optimism>,
    /// Witness provider for fetching SALT witness data.
    pub witness_provider: RootProvider,
}

impl RpcClient {
    /// Creates a new RPC client connected to MegaETH blockchain nodes.
    ///
    /// # Arguments
    /// * `data_api` - HTTP URL of the standard JSON-RPC endpoint for blocks and contract data
    /// * `witness_api` - HTTP URL of the witness RPC endpoint for SALT witness data
    ///
    /// # Returns
    /// Configured RPC client ready to make requests to the MegaETH blockchain.
    ///
    /// # Errors
    /// Returns error if either API URL is malformed or invalid.
    pub fn new(data_api: &str, witness_api: &str) -> Result<Self> {
        Ok(Self {
            data_provider: ProviderBuilder::<_, _, Optimism>::default()
                .connect_http(data_api.parse().context("Failed to parse API URL")?),
            witness_provider: ProviderBuilder::default()
                .connect_http(witness_api.parse().context("Failed to parse API URL")?),
        })
    }

    /// Gets contract bytecode for multiple addresses at a specific block height.
    ///
    /// # Arguments
    /// * `addresses` - Contract addresses to fetch bytecode for
    /// * `block_number` - Block height to query (supports latest, earliest, pending)
    ///
    /// # Returns
    /// Vector of bytecode in the same order as input addresses. Empty bytecode
    /// is returned for addresses without deployed contracts.
    ///
    /// # Performance
    /// Executes all requests concurrently for optimal performance.
    pub async fn get_code(
        &self,
        addresses: &[Address],
        block_number: BlockNumberOrTag,
    ) -> Result<Vec<Bytes>> {
        try_join_all(addresses.iter().map(|&addr| async move {
            self.data_provider
                .get_code_at(addr)
                .block_id(block_number.into())
                .await
                .context(format!(
                    "get_code_at for address {addr:?} at block {block_number:?}"
                ))
        }))
        .await
    }

    /// Gets a block by its identifier with optional transaction details.
    ///
    /// Performs data integrity checks on the returned block:
    /// - Verifies block_id matches the returned block
    /// - Verifies block hash matches the computed hash from header
    /// - If full transactions: verifies transaction hashes and roots, and signers
    ///
    /// # Arguments
    /// * `block_id` - Block identifier (number, hash, latest, etc.)
    /// * `full_txs` - If true, includes full transaction objects; if false, only transaction hashes
    ///
    /// # Returns
    /// Complete block data including header, transactions, and metadata.
    ///
    /// # Errors
    /// Returns error if block doesn't exist, RPC call fails, or integrity checks fail.
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let block = if full_txs {
            self.data_provider.get_block(block_id).full().await?
        } else {
            self.data_provider.get_block(block_id).await?
        };
        let block = block.ok_or_else(|| eyre!("Block {:?} not found", block_id))?;

        // Verify block_id matches the returned block
        match block_id {
            BlockId::Number(BlockNumberOrTag::Number(num)) => {
                ensure!(
                    block.header.number == num,
                    "Block number mismatch: requested {}, got {}",
                    num,
                    block.header.number
                );
            }
            BlockId::Hash(hash) => {
                ensure!(
                    block.header.hash == hash.block_hash,
                    "Block hash mismatch: requested {:?}, got {:?}",
                    hash.block_hash,
                    block.header.hash
                );
            }
            _ => {} // Skip for latest, earliest, pending, etc.
        }

        // Verify block hash matches the computed hash from header
        ensure!(
            block.header.hash_slow() == block.header.hash,
            "Block hash mismatch: expected {:?}, computed {:?}",
            block.header.hash,
            block.header.hash_slow()
        );

        // Verify transaction hashes and transactions root
        if let BlockTransactions::Full(ref transactions) = block.transactions {
            for tx in transactions {
                let tx_envelope = tx.inner.clone().into_inner();
                ensure!(
                    tx_envelope.trie_hash() == tx.tx_hash(),
                    "Transaction hash mismatch: expected {:?}, computed {:?}",
                    tx.tx_hash(),
                    tx_envelope.trie_hash()
                );

                let recovered = tx_envelope
                    .recover_signer()
                    .map_err(|err| eyre!("Failed to recover signer: {}", err))?;

                ensure!(
                    recovered == tx.from(),
                    "Transaction signer mismatch: expected {:?}, got {:?}",
                    tx.from(),
                    recovered
                );
            }
            let computed_tx_root = ordered_trie_root_with_encoder(transactions, |tx, buf| {
                tx.inner.clone().into_inner().encode_2718(buf)
            });
            ensure!(
                computed_tx_root == block.header.transactions_root,
                "Transactions root mismatch: expected {:?}, computed {:?}",
                block.header.transactions_root,
                computed_tx_root
            );
        }

        Ok(block)
    }

    /// Gets the current latest block number from the blockchain.
    ///
    /// # Returns
    /// The highest block number that has been mined.
    ///
    /// # Errors
    /// Returns error if unable to connect to the blockchain or RPC fails.
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        self.data_provider
            .get_block_number()
            .await
            .context("Failed to get block number")
    }

    /// Gets execution witness data for a specific block.
    ///
    /// # Arguments
    /// * `number` - Block number to fetch witness data for
    /// * `hash` - Block hash to fetch witness data for
    ///
    /// # Returns
    /// [`SaltWitness`] containing state access patterns and execution traces
    /// required for stateless validation.
    ///
    /// # Errors
    /// Returns error if block hash doesn't exist, witness unavailable
    pub async fn get_witness(&self, number: u64, hash: B256) -> Result<(SaltWitness, MptWitness)> {
        self.witness_provider
            .client()
            .request("mega_getBlockWitness", (number.to_string(), hash))
            .await
            .map_err(|e| eyre!("Failed to get witness for block {hash}: {e}"))
    }

    /// Reports a range of validated blocks to the upstream node.
    ///
    /// Notifies the upstream node that the validator has successfully validated
    /// a contiguous range of blocks in its canonical chain.
    ///
    /// # Arguments
    /// * `first_block` - Tuple of (block number, block hash) for the earliest validated block
    /// * `last_block` - Tuple of (block number, block hash) for the latest validated block
    ///
    /// # Returns
    /// [`SetValidatedBlocksResponse`] containing:
    /// - `accepted`: Whether the upstream node accepted the report
    /// - `last_validated_block`: The upstream's current last validated block (number, hash)
    ///
    /// # Errors
    /// Returns error if the RPC call fails or connection is lost.
    pub async fn set_validated_blocks(
        &self,
        first_block: (u64, B256),
        last_block: (u64, B256),
    ) -> Result<SetValidatedBlocksResponse> {
        self.data_provider
            .client()
            .request("mega_setValidatedBlocks", (first_block, last_block))
            .await
            .map_err(|e| eyre!("Failed to set validated blocks: {e}"))
    }
}
