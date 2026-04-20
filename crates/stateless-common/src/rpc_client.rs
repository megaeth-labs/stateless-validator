//! Concrete RPC client for fetching blockchain data.
//!
//! Provides [`RpcClient`] — the HTTP-based client for fetching blocks, witnesses, and
//! contract bytecode from MegaETH nodes.
//!
//! ## Network resilience
//!
//! - **Multi-endpoint data support**: accepts an ordered list of data endpoints; data methods pick
//!   a starting provider via round-robin and, on failure, retry with backoff on that provider
//!   before cycling to the next.
//! - **Multi-endpoint witness support**: accepts an ordered list of witness endpoints;
//!   `get_witness` tries them front-to-back and returns on the first success.
//! - **Concurrency limiting**: two independent [`tokio::sync::Semaphore`]s cap in-flight requests —
//!   one for data-endpoint calls (blocks/headers/code/tx), one for witness fetches — so a burst on
//!   one path cannot starve the other. `set_validated_blocks` is unthrottled.
//! - **Per-call retry with backoff**: data methods automatically retry transient RPC errors with
//!   exponential backoff per provider, cycling through providers in round-robin order after
//!   exhausting retries; `get_witness` does not retry per-provider but falls back to the next
//!   provider instead.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

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
use tokio::sync::Semaphore;
use tracing::trace;

use crate::{
    metrics::{RpcClientConfig, RpcMethod},
    witness_size::WitnessSizeBreakdown,
};

/// Boxed, `'static` future returned by `call()` closures.
type BoxFuture<T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'static>>;

/// Request parameters for `mega_getBlockWitness`, sent to every provider in
/// [`RpcClient::witness_providers`].
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
///
/// Cloning is cheap — all providers are `Arc`-backed internally.
#[derive(Debug, Clone)]
pub struct RpcClient {
    /// Ordered list of data providers. Data methods pick a starting provider via round-robin and
    /// cycle forward on failure (each with its own retry-with-backoff budget).
    data_providers: Vec<RootProvider<Optimism>>,
    /// Round-robin counter for selecting the starting data provider on each call.
    /// Shared across clones so load balancing is global per logical client.
    data_rr_counter: Arc<AtomicUsize>,
    /// Ordered list of witness providers. `get_witness` tries them front-to-back.
    witness_providers: Vec<RootProvider>,
    /// Optional dedicated provider for reporting validated blocks.
    report_provider: Option<RootProvider<Optimism>>,
    /// Configuration controlling verification, retry, and concurrency behavior.
    config: RpcClientConfig,
    /// Semaphore capping concurrent in-flight data-endpoint requests
    /// (blocks, headers, contract bytecode, transactions).
    data_concurrency: Arc<Semaphore>,
    /// Semaphore capping concurrent in-flight witness fetches, independent of the data cap.
    witness_concurrency: Arc<Semaphore>,
}

impl RpcClient {
    /// Creates a new RPC client connected to MegaETH blockchain nodes.
    ///
    /// # Arguments
    /// * `data_apis` - HTTP URLs of the standard JSON-RPC endpoints for blocks and contract data
    ///   (tried in order)
    /// * `witness_apis` - HTTP URLs of the witness RPC endpoints (tried in order)
    pub fn new(data_apis: &[&str], witness_apis: &[&str]) -> Result<Self> {
        Self::new_with_config(data_apis, witness_apis, RpcClientConfig::default(), None)
    }

    /// Creates a new RPC client with custom configuration.
    ///
    /// # Arguments
    /// * `data_apis` - HTTP URLs of the standard JSON-RPC endpoints for blocks and contract data
    ///   (tried in order, non-empty)
    /// * `witness_apis` - HTTP URLs of the witness RPC endpoints (tried in order, non-empty)
    /// * `config` - Configuration controlling verification, retry, and concurrency behavior
    /// * `report_api` - Optional HTTP URL of the endpoint for reporting validated blocks
    pub fn new_with_config(
        data_apis: &[&str],
        witness_apis: &[&str],
        config: RpcClientConfig,
        report_api: Option<&str>,
    ) -> Result<Self> {
        if data_apis.is_empty() {
            return Err(eyre!("At least one data API URL must be provided"));
        }
        if witness_apis.is_empty() {
            return Err(eyre!("At least one witness API URL must be provided"));
        }

        let data_providers = data_apis
            .iter()
            .map(|url| -> Result<RootProvider<Optimism>> {
                Ok(ProviderBuilder::<_, _, Optimism>::default()
                    .connect_http(url.parse().context("Failed to parse data API URL")?))
            })
            .collect::<Result<Vec<_>>>()?;

        let witness_providers = witness_apis
            .iter()
            .map(|url| -> Result<RootProvider> {
                Ok(ProviderBuilder::default()
                    .connect_http(url.parse().context("Failed to parse witness API URL")?))
            })
            .collect::<Result<Vec<_>>>()?;

        let report_provider = report_api
            .map(|url| -> Result<RootProvider<Optimism>> {
                Ok(ProviderBuilder::<_, _, Optimism>::default()
                    .connect_http(url.parse().context("Failed to parse report API URL")?))
            })
            .transpose()?;

        // `.max(1)` guards against `--data-max-concurrent-requests 0` (or the witness
        // equivalent) silently wedging every RPC call — `Semaphore::new(0)` blocks
        // `.acquire()` forever.
        let data_concurrency = Arc::new(Semaphore::new(
            config.data_max_concurrent_requests.unwrap_or(Semaphore::MAX_PERMITS).max(1),
        ));
        let witness_concurrency = Arc::new(Semaphore::new(
            config.witness_max_concurrent_requests.unwrap_or(Semaphore::MAX_PERMITS).max(1),
        ));

        Ok(Self {
            data_providers,
            data_rr_counter: Arc::new(AtomicUsize::new(0)),
            witness_providers,
            report_provider,
            config,
            data_concurrency,
            witness_concurrency,
        })
    }

    /// Returns whether block verification is skipped.
    pub fn skip_block_verification(&self) -> bool {
        self.config.skip_block_verification
    }

    /// Returns the number of configured data endpoints.
    pub fn data_provider_count(&self) -> usize {
        self.data_providers.len()
    }

    /// Returns the number of configured witness endpoints.
    pub fn witness_provider_count(&self) -> usize {
        self.witness_providers.len()
    }

    /// Records an RPC metrics event (final outcome) if metrics are configured.
    fn record_rpc(&self, method: RpcMethod, success: bool, duration_secs: Option<f64>) {
        if let Some(ref metrics) = self.config.metrics {
            metrics.on_rpc_complete(method, success, duration_secs);
        }
    }

    /// Records a transient retry attempt (not the final outcome) if metrics are configured.
    fn record_rpc_retry(&self, method: RpcMethod) {
        if let Some(ref metrics) = self.config.metrics {
            metrics.on_rpc_retry(method);
        }
    }

    /// Wraps a multi-endpoint RPC call with concurrency limiting and exponential-backoff retry.
    ///
    /// Picks a starting data provider via round-robin to spread load across endpoints. For the
    /// selected provider, retries up to `max_retries` with exponential backoff. If all retries
    /// fail, cycles forward in round-robin order to the next provider with a fresh retry budget.
    ///
    /// Records one `record_rpc` per logical call (final outcome); each non-final failure is
    /// recorded via `record_rpc_retry`. The reported duration covers the full call including
    /// prior failed attempts and backoff sleeps, so retry latency is visible in dashboards.
    ///
    /// Does not apply to `get_witness` — that method falls back across providers instead.
    async fn call<T: Send + 'static>(
        &self,
        method: RpcMethod,
        f: impl Fn(RootProvider<Optimism>) -> BoxFuture<Result<T>>,
    ) -> Result<T> {
        let max_retries = self.config.max_retries;
        let start = Instant::now();
        // Safety: constructor guarantees at least one data provider.
        let n = self.data_providers.len();
        // Skip the atomic op when there's a single provider — avoids pointless contention.
        let rr_start =
            if n > 1 { self.data_rr_counter.fetch_add(1, Ordering::Relaxed) % n } else { 0 };
        let mut last_err = None;

        for offset in 0..n {
            let provider_idx = (rr_start + offset) % n;
            let provider = &self.data_providers[provider_idx];
            let mut backoff_ms = self.config.initial_backoff_ms;

            for attempt in 0..=max_retries {
                let _permit = self
                    .data_concurrency
                    .acquire()
                    .await
                    .expect("data concurrency semaphore closed unexpectedly");

                match f(provider.clone()).await {
                    Ok(v) => {
                        self.record_rpc(method, true, Some(start.elapsed().as_secs_f64()));
                        return Ok(v);
                    }
                    Err(e) if attempt < max_retries => {
                        self.record_rpc_retry(method);
                        // `_permit` is bound in the `for attempt` loop body, so its
                        // implicit drop is at end-of-iteration — i.e. *after* the sleep
                        // below. Explicit drop here releases the slot for other callers
                        // during backoff.
                        drop(_permit);
                        let jitter_ms = fastrand::u64(0..=backoff_ms / 2);
                        let sleep_ms = (backoff_ms + jitter_ms).min(self.config.max_backoff_ms);
                        tracing::warn!(
                            method = method.as_str(),
                            attempt,
                            provider_idx,
                            error = %e,
                            sleep_ms,
                            "RPC call failed, retrying",
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(self.config.max_backoff_ms);
                    }
                    Err(e) => {
                        if offset + 1 < n {
                            self.record_rpc_retry(method);
                            tracing::warn!(
                                method = method.as_str(),
                                provider_idx,
                                error = %e,
                                "All retries exhausted for data provider, trying next",
                            );
                        }
                        last_err = Some(e);
                        break;
                    }
                }
            }
        }

        self.record_rpc(method, false, Some(start.elapsed().as_secs_f64()));
        Err(last_err.expect("data_providers is non-empty"))
    }

    /// Gets contract bytecode for a code hash.
    pub async fn get_code(&self, hash: B256) -> Result<Bytes> {
        self.call(RpcMethod::EthGetCodeByHash, move |provider| {
            Box::pin(async move {
                provider.client().request("eth_getCodeByHash", (hash,)).await.map_err(|e| {
                    trace!(%hash, error = %e, "eth_getCodeByHash failed");
                    eyre!("eth_getCodeByHash for hash {hash:?} failed: {e}")
                })
            })
        })
        .await
    }

    /// Gets a block by its identifier with optional transaction details.
    ///
    /// If `skip_block_verification` is enabled in config, skips integrity checks.
    /// Otherwise performs ECDSA signature and block hash verification.
    pub async fn get_block(&self, block_id: BlockId, full_txs: bool) -> Result<Block<Transaction>> {
        let block = self
            .call(RpcMethod::EthGetBlockByNumber, move |provider| {
                Box::pin(async move { do_get_block_unchecked(&provider, block_id, full_txs).await })
            })
            .await?;

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
        self.call(RpcMethod::EthGetBlockByNumber, move |provider| {
            Box::pin(async move { do_get_block_unchecked(&provider, block_id, full_txs).await })
        })
        .await
    }

    /// Gets the current latest block number from the blockchain.
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        self.call(RpcMethod::EthBlockNumber, move |provider| {
            Box::pin(async move {
                provider.get_block_number().await.context("Failed to get block number").map_err(
                    |e| {
                        trace!(error = %e, "eth_blockNumber failed");
                        e
                    },
                )
            })
        })
        .await
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
        self.call(RpcMethod::EthGetHeader, move |provider| {
            Box::pin(async move {
                do_get_header(&provider, block_id, verify_hash).await.map_err(|e| {
                    trace!(?block_id, error = %e, "get_header failed");
                    e
                })
            })
        })
        .await
    }

    /// Gets just the block hash for a block number.
    ///
    /// Delegates to `get_header` (which handles retry and concurrency limiting).
    pub async fn get_block_hash(&self, block_number: u64) -> Result<B256> {
        self.get_header(BlockId::Number(BlockNumberOrTag::Number(block_number)), false)
            .await
            .map_err(|e| {
                trace!(block_number, error = %e, "eth_getHeaderByNumber failed");
                eyre!("eth_getHeaderByNumber for block {} failed: {e}", block_number)
            })
            .map(|h| h.hash)
    }

    /// Gets execution witness data for a specific block.
    ///
    /// Tries each configured witness provider in order; returns on the first success.
    /// If all providers fail, returns the error from the last provider attempted.
    pub async fn get_witness(&self, number: u64, hash: B256) -> Result<(SaltWitness, MptWitness)> {
        // Hoisted above the provider loop so the recorded duration covers the full
        // end-to-end fetch including any failed fallback attempts — matches `call()`'s
        // documented "full call including prior failed attempts" semantics.
        let start = Instant::now();
        let mut last_err = eyre!("no witness providers configured");

        for (idx, provider) in self.witness_providers.iter().enumerate() {
            let _permit = self
                .witness_concurrency
                .acquire()
                .await
                .expect("witness concurrency semaphore closed unexpectedly");

            match fetch_witness_raw(provider, number, hash).await {
                Ok((salt_witness, mpt_witness)) => {
                    self.record_rpc(
                        RpcMethod::MegaGetBlockWitness,
                        true,
                        Some(start.elapsed().as_secs_f64()),
                    );
                    trace!(
                        block_number = number,
                        %hash,
                        provider_idx = idx,
                        "Witness fetched successfully",
                    );
                    if let Some(ref metrics) = self.config.metrics {
                        metrics.on_witness_fetch(WitnessSizeBreakdown::new(
                            &salt_witness,
                            &mpt_witness,
                        ));
                    }
                    return Ok((salt_witness, mpt_witness));
                }
                Err(e) => {
                    if idx + 1 < self.witness_providers.len() {
                        self.record_rpc_retry(RpcMethod::MegaGetBlockWitness);
                        tracing::warn!(
                            block_number = number,
                            %hash,
                            provider_idx = idx,
                            error = %e,
                            "Witness provider failed, trying next",
                        );
                    } else {
                        tracing::warn!(
                            block_number = number,
                            %hash,
                            provider_idx = idx,
                            error = %e,
                            "Witness provider failed",
                        );
                    }
                    last_err = e;
                }
            }
        }

        // All providers exhausted: record the single final failure outcome.
        self.record_rpc(RpcMethod::MegaGetBlockWitness, false, Some(start.elapsed().as_secs_f64()));
        Err(last_err)
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
            .map_err(|e| {
                trace!(error = %e, "mega_setValidatedBlocks failed");
                eyre!("Failed to set validated blocks: {e}")
            });
        self.record_rpc(RpcMethod::MegaSetValidatedBlocks, result.is_ok(), None);
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
            .call(RpcMethod::EthGetTransactionByHash, move |provider| {
                Box::pin(async move {
                    provider.get_transaction_by_hash(tx_hash).await.map_err(|e| {
                        trace!(%tx_hash, error = %e, "get_transaction_by_hash failed");
                        eyre::Error::from(e)
                    })
                })
            })
            .await
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

/// Fetches a block by ID without integrity verification.
async fn do_get_block_unchecked(
    provider: &RootProvider<Optimism>,
    block_id: BlockId,
    full_txs: bool,
) -> Result<Block<Transaction>> {
    let block = if full_txs {
        provider.get_block(block_id).full().await?
    } else {
        provider.get_block(block_id).await?
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

/// Fetches a block header by block ID with optional hash verification.
async fn do_get_header(
    provider: &RootProvider<Optimism>,
    block_id: BlockId,
    verify_hash: bool,
) -> Result<Header> {
    let result = match block_id {
        BlockId::Hash(hash) => provider
            .client()
            .request::<_, Header>("eth_getHeaderByHash", (hash.block_hash,))
            .await
            .map_err(|e| eyre!("eth_getHeaderByHash for {} failed: {e}", hash.block_hash)),
        BlockId::Number(tag) => provider
            .client()
            .request::<_, Header>("eth_getHeaderByNumber", (tag,))
            .await
            .map_err(|e| eyre!("eth_getHeaderByNumber for {:?} failed: {e}", tag)),
    };

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
        ensure!(
            header.hash_slow() == header.hash,
            "Header hash mismatch: expected {:?}, computed {:?}",
            header.hash,
            header.hash_slow()
        );
    }

    Ok(header)
}

/// Fetches and decodes witness data from a single RPC provider (one attempt, no retry).
///
/// Format: `"v0:<base64>"` string → base64-decode → zstd-decompress → bincode-legacy-decode
/// into `(SaltWitness, MptWitness)`.
async fn fetch_witness_raw(
    provider: &RootProvider,
    number: u64,
    hash: B256,
) -> Result<(SaltWitness, MptWitness)> {
    let keys = WitnessRequestKeys { block_number: U64::from(number), block_hash: hash };
    let encoded: String = provider
        .client()
        .request("mega_getBlockWitness", (keys,))
        .await
        .map_err(|e| eyre!("mega_getBlockWitness failed for block {number}: {e}"))?;

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
        .context("decode task panicked")??;

    trace!(
        block_number = number,
        %hash,
        decode_ms = decode_start.elapsed().as_millis(),
        "Witness decoded",
    );

    Ok((salt_witness, mpt_witness))
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
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use alloy_primitives::BlockHash;
    use jsonrpsee::{
        RpcModule,
        server::{ServerBuilder, ServerHandle},
        types::ErrorObjectOwned,
    };
    use stateless_core::{
        PipelineConfig, block_fetcher, db::BlockMeta, find_divergence_point, pipeline::BlockFetcher,
    };
    use tokio_util::sync::CancellationToken;

    use super::*;

    const LOCALHOST_A: &str = "http://localhost:8545";
    const LOCALHOST_B: &str = "http://localhost:8546";

    /// Test wrapper that implements BlockFetcher by delegating to RpcClient.
    struct TestFetcher(RpcClient);

    impl BlockFetcher for TestFetcher {
        type Output = ();
        async fn fetch(&self, _: u64) -> eyre::Result<()> {
            unimplemented!("not used")
        }
        async fn latest_block_number(&self) -> eyre::Result<u64> {
            self.0.get_latest_block_number().await
        }
        async fn block_hash(&self, n: u64) -> eyre::Result<BlockHash> {
            self.0.get_block_hash(n).await
        }
        async fn latest_block_meta(&self) -> eyre::Result<BlockMeta> {
            unimplemented!("not used")
        }
    }

    fn client_at(url: &str) -> RpcClient {
        RpcClient::new(&[url], &[url]).unwrap()
    }

    fn fetcher_at(url: &str) -> Arc<TestFetcher> {
        Arc::new(TestFetcher(client_at(url)))
    }

    fn err_obj(msg: &'static str) -> ErrorObjectOwned {
        ErrorObjectOwned::owned::<()>(-32000, msg, None)
    }

    fn parse_hex_u64(s: &str) -> u64 {
        u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).unwrap()
    }

    /// Minimal valid [`Header`] with `hash`/`number` populated; all other fields default.
    fn header_stub(number: u64, hash: BlockHash) -> Header {
        Header {
            hash,
            inner: alloy_consensus::Header { number, ..Default::default() },
            ..Default::default()
        }
    }

    /// Starts a jsonrpsee server bound to a random port and registers methods via `register`.
    async fn serve<Ctx: Send + Sync + 'static>(
        ctx: Ctx,
        register: impl FnOnce(&mut RpcModule<Ctx>),
    ) -> (ServerHandle, String) {
        let mut module = RpcModule::new(ctx);
        register(&mut module);
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (server.start(module), url)
    }

    /// Serves `eth_getHeaderByNumber` with headers derived from `hashes`.
    async fn start_mock_rpc(hashes: HashMap<u64, BlockHash>) -> (ServerHandle, String) {
        serve(hashes, |m| {
            m.register_method("eth_getHeaderByNumber", |params, ctx, _| {
                let (hex,): (String,) = params.parse().unwrap();
                let n = parse_hex_u64(&hex);
                Ok::<_, ErrorObjectOwned>(header_stub(n, ctx.get(&n).copied().unwrap_or_default()))
            })
            .unwrap();
        })
        .await
    }

    /// Serves `eth_blockNumber` returning `latest`; fails the first `fail_first` calls.
    /// Returns the hit counter so tests can inspect per-endpoint call counts.
    async fn start_counting_block_number_rpc(
        latest: u64,
        fail_first: usize,
    ) -> (ServerHandle, String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let (handle, url) = serve((latest, fail_first, hits.clone()), |m| {
            m.register_method("eth_blockNumber", |_p, (latest, fail_first, hits), _| {
                if hits.fetch_add(1, Ordering::Relaxed) < *fail_first {
                    Err::<String, _>(err_obj("synthetic failure"))
                } else {
                    Ok(format!("0x{:x}", *latest))
                }
            })
            .unwrap();
        })
        .await;
        (handle, url, hits)
    }

    /// Shortcut for tests that don't care about per-endpoint hit counts.
    async fn start_block_number_rpc(latest: u64) -> (ServerHandle, String) {
        let (h, u, _) = start_counting_block_number_rpc(latest, 0).await;
        (h, u)
    }

    /// Builds paired local/remote hash maps that agree on `earliest..=diverge_at` and diverge
    /// on `(diverge_at+1)..=tip`.
    fn make_divergence_chains(
        earliest: u64,
        tip: u64,
        diverge_at: u64,
    ) -> (HashMap<u64, BlockHash>, HashMap<u64, BlockHash>) {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();
        for n in earliest..=tip {
            local.insert(n, BlockHash::from([n as u8; 32]));
            let remote_hash = if n <= diverge_at { [n as u8; 32] } else { [(n + 128) as u8; 32] };
            remote.insert(n, BlockHash::from(remote_hash));
        }
        (local, remote)
    }

    /// Runs `find_divergence_point` against a mock server and asserts the expected split.
    async fn assert_divergence(earliest: u64, tip: u64, diverge_at: u64, expected: u64) {
        let (local, remote) = make_divergence_chains(earliest, tip, diverge_at);
        let (handle, url) = start_mock_rpc(remote).await;
        let fetcher = TestFetcher(client_at(&url));
        let result = find_divergence_point(
            &fetcher,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((earliest, *local.get(&earliest).unwrap()))),
            tip,
        )
        .await
        .unwrap();
        assert_eq!(result, expected);
        handle.stop().unwrap();
    }

    #[test]
    fn test_new_validates_urls_and_counts_providers() {
        assert!(RpcClient::new(&["not a url"], &[LOCALHOST_A]).is_err());
        assert!(RpcClient::new(&[LOCALHOST_A], &["not a url"]).is_err());
        assert!(
            RpcClient::new(&[], &[LOCALHOST_A])
                .unwrap_err()
                .to_string()
                .contains("At least one data API")
        );
        assert!(
            RpcClient::new(&[LOCALHOST_A], &[])
                .unwrap_err()
                .to_string()
                .contains("At least one witness API")
        );

        for endpoints in [&[LOCALHOST_B][..], &[LOCALHOST_B, "http://localhost:8547"]] {
            assert_eq!(
                RpcClient::new(&[LOCALHOST_A], endpoints).unwrap().witness_provider_count(),
                endpoints.len()
            );
            assert_eq!(
                RpcClient::new(endpoints, &[LOCALHOST_A]).unwrap().data_provider_count(),
                endpoints.len()
            );
        }
    }

    #[test]
    fn test_config_propagates_to_client() {
        let make = |config| {
            RpcClient::new_with_config(&[LOCALHOST_A], &[LOCALHOST_B], config, None).unwrap()
        };
        assert!(!make(RpcClientConfig::validator()).skip_block_verification());
        assert!(make(RpcClientConfig::trace_server()).skip_block_verification());
        // `Some(0)` must not produce a permanently-blocked semaphore.
        let zero = make(RpcClientConfig {
            data_max_concurrent_requests: Some(0),
            witness_max_concurrent_requests: Some(0),
            ..Default::default()
        });
        assert_eq!(zero.data_concurrency.available_permits(), 1);
        assert_eq!(zero.witness_concurrency.available_permits(), 1);
        let client = make(RpcClientConfig {
            data_max_concurrent_requests: Some(10),
            witness_max_concurrent_requests: Some(2),
            ..Default::default()
        });
        assert_eq!(client.data_concurrency.available_permits(), 10);
        assert_eq!(client.witness_concurrency.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_find_divergence_single_block_reorg() {
        assert_divergence(1, 10, 9, 9).await;
    }

    #[tokio::test]
    async fn test_find_divergence_multi_block_reorg() {
        assert_divergence(1, 10, 5, 5).await;
    }

    #[tokio::test]
    async fn test_find_divergence_to_earliest() {
        assert_divergence(5, 10, 5, 5).await;
    }

    #[tokio::test]
    async fn test_find_divergence_catastrophic_reorg() {
        let (local, remote) = make_divergence_chains(1, 5, 0); // no agreement at all
        let (handle, url) = start_mock_rpc(remote).await;
        let fetcher = TestFetcher(client_at(&url));

        let result = find_divergence_point(
            &fetcher,
            &|n| Ok(local.get(&n).copied()),
            &|| Ok(Some((1, *local.get(&1).unwrap()))),
            5,
        )
        .await;

        assert!(result.unwrap_err().to_string().contains("Catastrophic reorg"));
        handle.stop().unwrap();
    }

    /// Holds references that must outlive the fetcher under test (server handle, rx).
    struct FetcherHarness {
        handle: ServerHandle,
        fetcher: Arc<TestFetcher>,
        tx: kanal::Sender<()>,
        _rx: kanal::Receiver<()>,
        config: Arc<PipelineConfig>,
        shutdown: CancellationToken,
    }

    /// Common setup for block_fetcher tests. `config_fn` mutates the default `PipelineConfig`.
    async fn fetcher_harness(
        latest: u64,
        config_fn: impl FnOnce(&mut PipelineConfig),
    ) -> FetcherHarness {
        let (handle, url) = start_block_number_rpc(latest).await;
        let (tx, _rx) = kanal::bounded::<()>(16);
        let mut config = PipelineConfig::default();
        config_fn(&mut config);
        FetcherHarness {
            handle,
            fetcher: fetcher_at(&url),
            tx,
            _rx,
            config: Arc::new(config),
            shutdown: CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn test_block_fetcher_sync_target_already_reached() {
        let h = fetcher_harness(100, |c| c.sync_target = Some(5)).await;
        assert!(block_fetcher(h.fetcher, h.tx, 6, h.config, h.shutdown).await.is_ok());
        h.handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_block_fetcher_shutdown_immediate() {
        let h = fetcher_harness(100, |_| {}).await;
        h.shutdown.cancel();
        assert!(block_fetcher(h.fetcher, h.tx, 1, h.config, h.shutdown).await.is_ok());
        h.handle.stop().unwrap();
    }

    #[tokio::test]
    async fn test_block_fetcher_invokes_latest_block_number() {
        let h = fetcher_harness(42, |c| c.poll_interval = Duration::from_secs(60)).await;
        let canceller = h.shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            canceller.cancel();
        });
        assert!(block_fetcher(h.fetcher, h.tx, 100, h.config, h.shutdown).await.is_ok());
        h.handle.stop().unwrap();
    }

    /// Asserts that `call()` spreads load across data providers via round-robin.
    ///
    /// Two healthy mocks, 10 calls, both must receive ≥ 3 hits (perfect distribution = 5/5).
    /// Proves the counter cycles the starting provider instead of always hitting `[0]`.
    #[tokio::test]
    async fn test_call_round_robins_across_healthy_providers() {
        let (h1, url1, hits1) = start_counting_block_number_rpc(10, 0).await;
        let (h2, url2, hits2) = start_counting_block_number_rpc(10, 0).await;

        let client = RpcClient::new(&[url1.as_str(), url2.as_str()], &[url1.as_str()]).unwrap();
        for _ in 0..10 {
            client.get_latest_block_number().await.unwrap();
        }

        let (a, b) = (hits1.load(Ordering::Relaxed), hits2.load(Ordering::Relaxed));
        assert_eq!(a + b, 10, "all calls should have succeeded");
        assert!(a >= 3 && b >= 3, "round-robin should distribute load: got {a}/{b}");

        h1.stop().unwrap();
        h2.stop().unwrap();
    }

    /// Asserts that `call()` retries exhaust on a failing provider, then falls
    /// back to the next provider in round-robin order.
    #[tokio::test]
    async fn test_call_falls_back_across_providers_on_exhausted_retries() {
        // Invariant: attempts per provider = max_retries + 1. Here max_retries=1 → 2 attempts
        // per provider, so `fail_first` must equal 2 to fully exhaust one provider's budget
        // before fallback. If either number changes, update the other accordingly — the
        // `a + b == 3` assertion below is 2 failed attempts on one provider + 1 successful
        // attempt on the other.
        let config = RpcClientConfig {
            max_retries: 1,
            initial_backoff_ms: 1,
            max_backoff_ms: 2,
            ..Default::default()
        };
        let (ha, url_a, hits_a) = start_counting_block_number_rpc(42, 2).await;
        let (hb, url_b, hits_b) = start_counting_block_number_rpc(42, 0).await;

        let client = RpcClient::new_with_config(
            &[url_a.as_str(), url_b.as_str()],
            &[url_a.as_str()],
            config,
            None,
        )
        .unwrap();

        assert_eq!(client.get_latest_block_number().await.unwrap(), 42);

        let (a, b) = (hits_a.load(Ordering::Relaxed), hits_b.load(Ordering::Relaxed));
        // One provider exhausted (max_retries + 1 = 2) attempts, the other served the final
        // success (≥ 1) → total 3 hits.
        assert_eq!(a + b, 3, "expected 2 retries on one + 1 success on the other, got {a}/{b}");
        assert!(a >= 1 && b >= 1, "both providers should have been tried: got {a}/{b}");

        ha.stop().unwrap();
        hb.stop().unwrap();
    }
}
