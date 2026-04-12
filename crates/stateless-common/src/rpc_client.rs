//! Concrete RPC client for fetching blockchain data.
//!
//! Provides [`RpcClient`] — the HTTP-based implementation of
//! [`stateless_core::ChainDataProvider`] — for fetching blocks, witnesses, and
//! contract bytecode from MegaETH nodes.

use std::{collections::HashMap, time::Instant};

use alloy_primitives::{B256, Bytes, U64};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag, Header};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use eyre::{Context, Result, ensure, eyre};
use futures::future;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;
use serde::{Deserialize, Serialize};
use stateless_core::withdrawals::MptWitness;
use tracing::trace;

use crate::metrics::{RpcClientConfig, RpcMethod};

/// Request keys for fetching block witness data.
/// Format compatible with both upstream witness endpoint and worker-kv-demo Cloudflare RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessRequestKeys {
    /// Block number as U64.
    pub block_number: U64,
    /// Block hash.
    pub block_hash: B256,
}

/// Response from mega_setValidatedBlocks RPC call
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetValidatedBlocksResponse {
    pub accepted: bool,
    pub last_validated_block: (U64, B256),
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
    /// Optional Cloudflare witness provider for pruned/archived blocks.
    cloudflare_witness_provider: Option<RootProvider>,
    /// Optional dedicated provider for reporting validated blocks.
    report_provider: Option<RootProvider<Optimism>>,
    /// Configuration controlling verification behavior
    config: RpcClientConfig,
}

impl RpcClient {
    /// Creates a new RPC client connected to MegaETH blockchain nodes.
    ///
    /// # Arguments
    /// * `data_api` - HTTP URL of the standard JSON-RPC endpoint for blocks and contract data
    /// * `witness_api` - HTTP URL of the witness RPC endpoint for SALT witness data
    pub fn new(data_api: &str, witness_api: &str) -> Result<Self> {
        Self::new_with_config(data_api, witness_api, RpcClientConfig::default(), None, None)
    }

    /// Creates a new RPC client with custom configuration.
    ///
    /// # Arguments
    /// * `data_api` - HTTP URL of the standard JSON-RPC endpoint for blocks and contract data
    /// * `witness_api` - HTTP URL of the witness RPC endpoint for SALT witness data
    /// * `config` - Configuration controlling verification and transport behavior
    /// * `cloudflare_witness_api` - Optional HTTP URL of the Cloudflare witness endpoint
    /// * `report_api` - Optional HTTP URL of the endpoint for reporting validated blocks
    pub fn new_with_config(
        data_api: &str,
        witness_api: &str,
        config: RpcClientConfig,
        cloudflare_witness_api: Option<&str>,
        report_api: Option<&str>,
    ) -> Result<Self> {
        let cloudflare_witness_provider = cloudflare_witness_api
            .map(|url| -> Result<RootProvider> {
                Ok(ProviderBuilder::default().connect_http(
                    url.parse().context("Failed to parse Cloudflare witness API URL")?,
                ))
            })
            .transpose()?;

        let report_provider = report_api
            .map(|url| -> Result<RootProvider<Optimism>> {
                Ok(ProviderBuilder::<_, _, Optimism>::default()
                    .connect_http(url.parse().context("Failed to parse report API URL")?))
            })
            .transpose()?;

        Ok(Self {
            data_provider: ProviderBuilder::<_, _, Optimism>::default()
                .connect_http(data_api.parse().context("Failed to parse API URL")?),
            witness_provider: ProviderBuilder::default()
                .connect_http(witness_api.parse().context("Failed to parse API URL")?),
            cloudflare_witness_provider,
            report_provider,
            config,
        })
    }

    /// Returns whether block verification is skipped.
    pub fn skip_block_verification(&self) -> bool {
        self.config.skip_block_verification
    }

    /// Records an RPC metrics event if metrics are configured.
    fn record_rpc(&self, method: RpcMethod, success: bool, duration_secs: Option<f64>) {
        if let Some(ref metrics) = self.config.metrics {
            metrics.on_rpc_complete(method, success, duration_secs);
        }
    }

    /// Gets contract bytecode for a code hash.
    pub async fn get_code(&self, hash: B256) -> Result<Bytes> {
        let start = Instant::now();
        let result = self
            .data_provider
            .client()
            .request("eth_getCodeByHash", (hash,))
            .await
            .map_err(|e| eyre!("eth_getCodeByHash for hash {hash:?} failed: {e}"));
        self.record_rpc(
            RpcMethod::EthGetCodeByHash,
            result.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );
        if let Err(ref e) = result {
            trace!(%hash, error = %e, "eth_getCodeByHash failed");
        }
        result
    }

    /// Gets a block by its identifier with optional transaction details.
    ///
    /// If `skip_block_verification` is enabled in config, skips integrity checks.
    /// Otherwise performs ECDSA signature and block hash verification.
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let start = Instant::now();
        let block = self.get_block_unchecked(block_id, full_txs).await;
        self.record_rpc(
            RpcMethod::EthGetBlockByNumber,
            block.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );
        if let Err(ref e) = block {
            trace!(?block_id, error = %e, "get_block failed");
        }
        let block = block?;
        if !self.config.skip_block_verification {
            verify_block_integrity(&block)?;
        }
        Ok(block)
    }

    /// Gets a block by its identifier without integrity checks.
    ///
    /// Use this for trusted data sources (e.g., debug-trace-server fetching from upstream RPC)
    /// where integrity checks are unnecessary overhead.
    pub async fn get_block_unchecked(
        &self,
        block_id: BlockId,
        full_txs: bool,
    ) -> Result<Block<Transaction>> {
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

        Ok(block)
    }

    /// Gets the current latest block number from the blockchain.
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        let result =
            self.data_provider.get_block_number().await.context("Failed to get block number");
        self.record_rpc(RpcMethod::EthBlockNumber, result.is_ok(), None);
        if let Err(ref e) = result {
            trace!(error = %e, "eth_blockNumber failed");
        }
        result
    }

    /// Gets the block header by block ID.
    ///
    /// Uses `eth_getHeaderByNumber` / `eth_getHeaderByHash` instead of `eth_getBlockByNumber`
    /// to avoid transferring the transaction hash list. Even without full transaction objects,
    /// `eth_getBlockByNumber` still returns all transaction hashes, which is significant
    /// at high TPS.
    ///
    /// When `verify_hash` is true, computes `hash_slow()` to verify the header hash matches
    /// the RPC-provided hash. This is important when initializing from a trusted start block
    /// hash, but can be skipped when the header will be verified downstream (e.g., via
    /// `verify_block_integrity`) or when running in a trusted context like the trace server.
    pub async fn get_header(&self, block_id: BlockId, verify_hash: bool) -> Result<Header> {
        let start = Instant::now();
        let result = match block_id {
            BlockId::Hash(hash) => self
                .data_provider
                .client()
                .request::<_, Header>("eth_getHeaderByHash", (hash.block_hash,))
                .await
                .map_err(|e| eyre!("eth_getHeaderByHash for {} failed: {e}", hash.block_hash)),
            BlockId::Number(tag) => self
                .data_provider
                .client()
                .request::<_, Header>("eth_getHeaderByNumber", (tag,))
                .await
                .map_err(|e| eyre!("eth_getHeaderByNumber for {:?} failed: {e}", tag)),
        };
        self.record_rpc(
            RpcMethod::EthGetHeader,
            result.is_ok(),
            Some(start.elapsed().as_secs_f64()),
        );
        let header = result?;

        // Verify block_id matches the returned header
        match block_id {
            BlockId::Number(BlockNumberOrTag::Number(num)) => {
                ensure!(
                    header.number == num,
                    "Header number mismatch: requested {}, got {}",
                    num,
                    header.number
                );
            }
            BlockId::Hash(hash) => {
                ensure!(
                    header.hash == hash.block_hash,
                    "Header hash mismatch: requested {:?}, got {:?}",
                    hash.block_hash,
                    header.hash
                );
            }
            _ => {}
        }

        if verify_hash {
            // Verify header hash matches the computed hash
            ensure!(
                header.hash_slow() == header.hash,
                "Header hash mismatch: expected {:?}, computed {:?}",
                header.hash,
                header.hash_slow()
            );
        }

        Ok(header)
    }

    /// Gets just the block hash for a block number.
    ///
    /// Uses `eth_getHeaderByNumber` to avoid transferring the large transaction hash list
    /// that `eth_getBlockByNumber` would include (e.g., for divergence checking).
    pub async fn get_block_hash(&self, block_number: u64) -> Result<B256> {
        self.get_header(BlockId::Number(BlockNumberOrTag::Number(block_number)), false)
            .await
            .map_err(|e| {
                let err = eyre!("eth_getHeaderByNumber for block {} failed: {e}", block_number);
                trace!(block_number, error = %e, "eth_getHeaderByNumber failed");
                err
            })
            .map(|h| h.hash)
    }

    /// Gets execution witness data for a specific block.
    pub async fn get_witness(&self, number: u64, hash: B256) -> Result<(SaltWitness, MptWitness)> {
        self.fetch_witness_from_provider(
            &self.witness_provider,
            number,
            hash,
            "witness_generator",
            RpcMethod::MegaGetBlockWitness,
        )
        .await
    }

    /// Returns whether a Cloudflare witness provider is configured.
    pub fn has_cloudflare_provider(&self) -> bool {
        self.cloudflare_witness_provider.is_some()
    }

    /// Gets execution witness data from the Cloudflare fallback endpoint.
    ///
    /// Single attempt, no retry (it's a KV lookup, either it exists or it doesn't).
    /// Returns error if Cloudflare provider is not configured.
    pub async fn get_witness_from_cloudflare(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(SaltWitness, MptWitness)> {
        let provider = self
            .cloudflare_witness_provider
            .as_ref()
            .ok_or_else(|| eyre!("Cloudflare witness provider not configured"))?;

        self.fetch_witness_from_provider(
            provider,
            number,
            hash,
            "cloudflare_worker",
            RpcMethod::MegaGetBlockWitnessCloudflare,
        )
        .await
    }

    /// Fetches and decodes witness data from a given provider.
    ///
    /// Both the upstream witness endpoint and the Cloudflare KV endpoint use the same
    /// unified RPC interface: `mega_getBlockWitness` with a `WitnessRequestKeys` parameter,
    /// returning a `"v0:<base64_encoded_data>"` string (zstd-compressed, bincode-serialized).
    async fn fetch_witness_from_provider(
        &self,
        provider: &RootProvider,
        number: u64,
        hash: B256,
        source: &str,
        rpc_method: RpcMethod,
    ) -> Result<(SaltWitness, MptWitness)> {
        let start = Instant::now();
        let keys = WitnessRequestKeys { block_number: U64::from(number), block_hash: hash };
        let result: Result<String> = provider
            .client()
            .request("mega_getBlockWitness", (keys,))
            .await
            .map_err(|e| eyre!("{} witness fetch failed for block {}: {}", source, number, e));

        self.record_rpc(rpc_method, result.is_ok(), Some(start.elapsed().as_secs_f64()));

        if let Err(ref e) = result {
            trace!(block_number = number, %hash, error = %e, "{source} mega_getBlockWitness failed");
        }

        let encoded = result?;

        let decode_start = Instant::now();
        let (salt_witness, mpt_witness) =
            tokio::task::spawn_blocking(move || -> Result<(SaltWitness, MptWitness)> {
                let b64_data = encoded
                    .strip_prefix("v0:")
                    .ok_or_else(|| eyre!("Witness response missing 'v0:' prefix"))?;
                let compressed = BASE64.decode(b64_data).context("base64 decode failed")?;
                let decompressed =
                    zstd::decode_all(compressed.as_slice()).context("zstd decompress failed")?;
                let (witness, _): ((SaltWitness, MptWitness), _) =
                    bincode::serde::decode_from_slice(&decompressed, bincode::config::legacy())
                        .context("bincode deserialize failed")?;
                Ok(witness)
            })
            .await
            .context("decode task failed")??;
        trace!(block_number = number, %hash, decode_ms = decode_start.elapsed().as_millis(), "{source} witness decoded");

        if let Some(ref metrics) = self.config.metrics {
            // Estimate sizes without full serialization (approximate but efficient)
            // SaltKey (8 bytes) + Option<SaltValue> (1 + 94 bytes) ≈ 103 bytes per entry
            let kvs_count = salt_witness.kvs.len();
            let salt_kvs_size = kvs_count * 103;

            // Proof: commitments (64 bytes each) + IPA proof (~576 bytes) + levels (5 bytes
            // each)
            let proof_size = salt_witness.proof.parents_commitments.len() * 64 +
                576 +
                salt_witness.proof.levels.len() * 5;
            let salt_size = salt_kvs_size + proof_size;

            // MptWitness: storage_root (32 bytes) + sum of state bytes
            let mpt_size = 32 + mpt_witness.state.iter().map(|b| b.len()).sum::<usize>();

            metrics.on_witness_fetch(salt_size, kvs_count, salt_kvs_size, mpt_size);
        }

        Ok((salt_witness, mpt_witness))
    }

    /// Reports a range of validated blocks via the dedicated report endpoint.
    pub async fn set_validated_blocks(
        &self,
        first_block: (u64, B256),
        last_block: (u64, B256),
    ) -> Result<SetValidatedBlocksResponse> {
        let provider =
            self.report_provider.as_ref().ok_or_else(|| eyre!("Report provider not configured"))?;
        let result = provider
            .client()
            .request("mega_setValidatedBlocks", (first_block, last_block))
            .await
            .map_err(|e| eyre!("Failed to set validated blocks: {e}"));
        self.record_rpc(RpcMethod::MegaSetValidatedBlocks, result.is_ok(), None);
        if let Err(ref e) = result {
            trace!(error = %e, "mega_setValidatedBlocks failed");
        }
        result
    }

    /// Gets contract bytecode for multiple code hashes concurrently.
    ///
    /// Fetches bytecode for all the given hashes in parallel, filtering out any that fail to fetch.
    pub async fn get_codes(&self, hashes: &[B256]) -> Result<HashMap<B256, Bytecode>> {
        let results = future::join_all(hashes.iter().map(|&hash| async move {
            match self.get_code(hash).await {
                Ok(bytes) => Some((hash, Bytecode::new_raw(bytes))),
                Err(e) => {
                    tracing::trace!("Failed to fetch code for hash {:?}: {}", hash, e);
                    None
                }
            }
        }))
        .await;

        Ok(results.into_iter().flatten().collect())
    }

    /// Gets the transaction by hash and returns its containing block hash.
    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: B256,
    ) -> Result<Option<(Transaction, B256)>> {
        let tx = self
            .data_provider
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(|e| {
                trace!(%tx_hash, error = %e, "get_transaction_by_hash failed");
                e
            })
            .context("Failed to get transaction by hash")?;

        match tx {
            Some(tx) => {
                let block_hash = tx.block_hash.ok_or_else(|| {
                    eyre!("Transaction {} is pending and has no block hash", tx_hash)
                })?;
                Ok(Some((tx, block_hash)))
            }
            None => Ok(None),
        }
    }
}

/// Verifies structural integrity of a block fetched from RPC.
///
/// Checks:
/// 1. **Block Hash**: Verifies the block hash matches the computed hash from the header
/// 2. **Transaction Hashes**: For each transaction, verifies that the transaction hash matches its
///    computed hash
/// 3. **Transaction Signers**: Recovers and verifies the signer for each transaction matches the
///    claimed `from` address
/// 4. **Transactions Root**: Computes the Merkle root of all transactions and verifies it matches
///    the `transactions_root` in the block header
fn verify_block_integrity(block: &Block<Transaction>) -> Result<()> {
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_rpc_types_eth::BlockTransactions;
    use alloy_trie::root::ordered_trie_root_with_encoder;
    use op_alloy_network::{TransactionResponse, eip2718::Encodable2718};

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
                tx_envelope.trie_hash() == *tx_envelope.hash(),
                "Transaction hash mismatch: expected {:?}, computed {:?}",
                tx_envelope.hash(),
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use alloy_primitives::{B256, BlockHash};
    use stateless_core::{
        PipelineConfig, block_fetcher, db::BlockMeta, find_divergence_point, pipeline::BlockFetcher,
    };
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// Test wrapper that implements BlockFetcher by delegating to RpcClient.
    struct TestFetcher(RpcClient);

    impl BlockFetcher for TestFetcher {
        type Output = ();

        async fn fetch(&self, _: u64) -> eyre::Result<()> {
            unimplemented!("not used in these tests")
        }
        async fn latest_block_number(&self) -> eyre::Result<u64> {
            self.0.get_latest_block_number().await
        }
        async fn block_hash(&self, n: u64) -> eyre::Result<BlockHash> {
            self.0.get_block_hash(n).await
        }
        async fn latest_block_meta(&self) -> eyre::Result<BlockMeta> {
            unimplemented!("not used in these tests")
        }
    }

    // RpcClient unit tests
    #[test]
    fn test_new_with_invalid_url() {
        let result = RpcClient::new("not a url", "http://localhost:8545");
        assert!(result.is_err());
    }

    #[test]
    fn test_new_with_valid_url() {
        let result = RpcClient::new("http://localhost:8545", "http://localhost:8546");
        assert!(result.is_ok());
        let client = result.unwrap();
        assert!(!client.has_cloudflare_provider());
    }

    #[test]
    fn test_new_with_cloudflare_provider() {
        let result = RpcClient::new_with_config(
            "http://localhost:8545",
            "http://localhost:8546",
            RpcClientConfig::default(),
            Some("http://localhost:9546"),
            None,
        );
        assert!(result.is_ok());
        let client = result.unwrap();
        assert!(client.has_cloudflare_provider());
    }

    #[test]
    fn test_new_with_invalid_cloudflare_url() {
        let result = RpcClient::new_with_config(
            "http://localhost:8545",
            "http://localhost:8546",
            RpcClientConfig::default(),
            Some("not a url"),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_block_verification() {
        let client = RpcClient::new_with_config(
            "http://localhost:8545",
            "http://localhost:8546",
            RpcClientConfig::validator(),
            None,
            None,
        )
        .unwrap();
        assert!(!client.skip_block_verification());

        let client = RpcClient::new_with_config(
            "http://localhost:8545",
            "http://localhost:8546",
            RpcClientConfig::trace_server(),
            None,
            None,
        )
        .unwrap();
        assert!(client.skip_block_verification());
    }

    // Mock RPC helpers (relocated from stateless-core chain_sync tests)
    /// Starts a minimal mock RPC server that responds to `eth_getHeaderByNumber`
    /// with headers whose hash is derived from `remote_hashes`.
    async fn start_mock_rpc(
        remote_hashes: HashMap<u64, BlockHash>,
    ) -> (jsonrpsee::server::ServerHandle, String) {
        use jsonrpsee::{RpcModule, server::ServerBuilder};

        let mut module = RpcModule::new(remote_hashes);
        module
            .register_method("eth_getHeaderByNumber", |params, ctx, _| {
                let (hex_number,): (String,) = params.parse().unwrap();
                let block_number =
                    u64::from_str_radix(hex_number.strip_prefix("0x").unwrap_or(&hex_number), 16)
                        .unwrap();
                let hash = ctx.get(&block_number).copied().unwrap_or_default();
                Ok::<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>(serde_json::json!({
                    "hash": hash,
                    "number": format!("0x{block_number:x}"),
                    "parentHash": B256::ZERO,
                    "timestamp": "0x0",
                    "stateRoot": B256::ZERO,
                    "transactionsRoot": B256::ZERO,
                    "receiptsRoot": B256::ZERO,
                    "logsBloom": alloy_primitives::Bloom::ZERO,
                    "gasUsed": "0x0",
                    "gasLimit": "0x0",
                    "mixHash": B256::ZERO,
                    "nonce": "0x0000000000000000",
                    "extraData": "0x",
                    "difficulty": "0x0",
                    "sha3Uncles": B256::ZERO,
                    "miner": alloy_primitives::Address::ZERO,
                    "baseFeePerGas": "0x0"
                }))
            })
            .unwrap();

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        let handle = server.start(module);
        (handle, url)
    }

    /// Helper to create local and remote hash maps for divergence tests.
    /// Blocks `earliest..=diverge_at` have matching hashes, blocks
    /// `(diverge_at+1)..=tip` differ.
    fn make_divergence_chains(
        earliest: u64,
        tip: u64,
        diverge_at: u64,
    ) -> (HashMap<u64, BlockHash>, HashMap<u64, BlockHash>) {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        for n in earliest..=tip {
            if n <= diverge_at {
                // Matching hashes
                let hash = BlockHash::from([n as u8; 32]);
                local.insert(n, hash);
                remote.insert(n, hash);
            } else {
                // Divergent hashes
                local.insert(n, BlockHash::from([n as u8; 32]));
                remote.insert(n, BlockHash::from([(n + 128) as u8; 32]));
            }
        }
        (local, remote)
    }

    // find_divergence_point tests

    #[tokio::test]
    async fn test_find_divergence_single_block_reorg() {
        let (local, remote) = make_divergence_chains(1, 10, 9);
        let (handle, url) = start_mock_rpc(remote).await;
        let fetcher = TestFetcher(RpcClient::new(&url, &url).unwrap());

        let result = find_divergence_point(
            &fetcher,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            10,
        )
        .await
        .unwrap();

        assert_eq!(result, 9);
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_find_divergence_multi_block_reorg() {
        let (local, remote) = make_divergence_chains(1, 10, 5);
        let (handle, url) = start_mock_rpc(remote).await;
        let fetcher = TestFetcher(RpcClient::new(&url, &url).unwrap());

        let result = find_divergence_point(
            &fetcher,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            10,
        )
        .await
        .unwrap();

        assert_eq!(result, 5);
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_find_divergence_to_earliest() {
        let (local, remote) = make_divergence_chains(5, 10, 5);
        let (handle, url) = start_mock_rpc(remote).await;
        let fetcher = TestFetcher(RpcClient::new(&url, &url).unwrap());

        let result = find_divergence_point(
            &fetcher,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((5, *local.get(&5).unwrap()))),
            10,
        )
        .await
        .unwrap();

        assert_eq!(result, 5);
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_find_divergence_catastrophic_reorg() {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        for n in 1..=5 {
            local.insert(n, BlockHash::from([n as u8; 32]));
            remote.insert(n, BlockHash::from([(n + 128) as u8; 32]));
        }

        let (handle, url) = start_mock_rpc(remote).await;
        let fetcher = TestFetcher(RpcClient::new(&url, &url).unwrap());

        let result = find_divergence_point(
            &fetcher,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            5,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Catastrophic reorg"));
        handle.stop().unwrap();
    }

    // block_fetcher tests

    /// Starts a mock RPC that serves `eth_blockNumber` (with configurable latest).
    async fn start_block_number_rpc(latest: u64) -> (jsonrpsee::server::ServerHandle, String) {
        use jsonrpsee::{RpcModule, server::ServerBuilder};

        let mut module = RpcModule::new(latest);
        module
            .register_method("eth_blockNumber", |_params, ctx, _| {
                Ok::<String, jsonrpsee::types::ErrorObjectOwned>(format!("0x{:x}", *ctx))
            })
            .unwrap();

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        let handle = server.start(module);
        (handle, url)
    }

    #[tokio::test]
    async fn test_block_fetcher_sync_target_already_reached() {
        let (handle, url) = start_block_number_rpc(100).await;
        let fetcher = Arc::new(TestFetcher(RpcClient::new(&url, &url).unwrap()));

        let (tx, _rx) = kanal::bounded::<()>(16);
        let config = Arc::new(PipelineConfig { sync_target: Some(5), ..PipelineConfig::default() });
        let shutdown = CancellationToken::new();

        let result = block_fetcher(fetcher, tx, 6, config, shutdown).await;

        assert!(result.is_ok());
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_block_fetcher_shutdown_immediate() {
        let (handle, url) = start_block_number_rpc(100).await;
        let fetcher = Arc::new(TestFetcher(RpcClient::new(&url, &url).unwrap()));

        let (tx, _rx) = kanal::bounded::<()>(16);
        let config = Arc::new(PipelineConfig::default());
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let result = block_fetcher(fetcher, tx, 1, config, shutdown).await;

        assert!(result.is_ok());
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_block_fetcher_invokes_latest_block_number() {
        // Verify the fetcher's latest_block_number is called during polling.
        // TestFetcher delegates to RpcClient; the mock returns 42.
        let (handle, url) = start_block_number_rpc(42).await;
        let fetcher = Arc::new(TestFetcher(RpcClient::new(&url, &url).unwrap()));

        let (tx, _rx) = kanal::bounded::<()>(16);
        let config = Arc::new(PipelineConfig {
            poll_interval: Duration::from_secs(60),
            ..PipelineConfig::default()
        });
        let shutdown = CancellationToken::new();

        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            shutdown_clone.cancel();
        });

        // start_block=100 > chain_latest=42, so fetcher enters wait loop,
        // then shutdown fires. This verifies latest_block_number() is called.
        let result = block_fetcher(fetcher, tx, 100, config, shutdown).await;

        assert!(result.is_ok());
        handle.stop().unwrap();
    }
}
