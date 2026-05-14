//! Pluggable source for the data that's *not* the witness: full blocks and contract bytecode.
//!
//! Witness fetching stays on [`RpcClient`] directly — only replayers produce witnesses, so
//! that path is always remote. Blocks and bytecode, however, are available locally to any
//! validator embedded in a full node, so they are pulled through this trait instead.
//!
//! The trait is intentionally object-safe so the worker pool can hold an
//! `Arc<dyn LocalDataSource>` without monomorphizing on the impl.

use std::{collections::HashMap, sync::Arc, time::Instant};

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::{Block, BlockId};
use async_trait::async_trait;
use op_alloy_rpc_types::Transaction as OpTransaction;
use revm::state::Bytecode;

use crate::rpc_client::{CodeFetchError, RpcClient, RpcDeadlineExceeded};

/// Errors a [`LocalDataSource`] may surface.
#[derive(Debug, thiserror::Error)]
pub enum LocalDataError {
    #[error(transparent)]
    Deadline(#[from] RpcDeadlineExceeded),

    #[error(transparent)]
    CodeFetch(CodeFetchError),

    #[error("block not found locally: number={number} hash={hash:?}")]
    BlockMissing { number: BlockNumber, hash: BlockHash },

    #[error("local provider error: {0}")]
    Provider(Box<dyn std::error::Error + Send + Sync>),
}

// Split `CodeFetchError::Deadline` into `LocalDataError::Deadline` so the deadline condition
// has exactly one path through the error type — otherwise callers must match both
// `LocalDataError::Deadline(_)` and
// `LocalDataError::CodeFetch(CodeFetchError::Deadline(_))`.
impl From<CodeFetchError> for LocalDataError {
    fn from(e: CodeFetchError) -> Self {
        match e {
            CodeFetchError::Deadline(d) => Self::Deadline(d),
            other => Self::CodeFetch(other),
        }
    }
}

#[async_trait]
pub trait LocalDataSource: Send + Sync + 'static {
    /// Fetch the RPC-format block at `(number, hash)`. `hash` is authoritative; `number` is
    /// for diagnostics. `deadline` is best-effort — local-DB impls may ignore it.
    async fn block_by_hash(
        &self,
        number: BlockNumber,
        hash: BlockHash,
        deadline: Option<Instant>,
    ) -> Result<Block<OpTransaction>, LocalDataError>;

    /// Fetch contract bytecode for a deduplicated list of codehashes. Each returned
    /// bytecode's keccak must match the requested hash.
    ///
    /// All-or-nothing: returns a complete map (one entry per requested hash) on success,
    /// or `Err` on any miss. Partial results are forbidden — they would silently feed
    /// missing bytecode into the EVM. Implementations should report missing hashes as
    /// `LocalDataError::Provider`.
    async fn codes_by_hashes(
        &self,
        hashes: &[B256],
        deadline: Option<Instant>,
    ) -> Result<HashMap<B256, Arc<Bytecode>>, LocalDataError>;
}

#[async_trait]
impl LocalDataSource for RpcClient {
    async fn block_by_hash(
        &self,
        _number: BlockNumber,
        hash: BlockHash,
        deadline: Option<Instant>,
    ) -> Result<Block<OpTransaction>, LocalDataError> {
        self.get_block_with_deadline(BlockId::Hash(hash.into()), true, deadline)
            .await
            .map_err(LocalDataError::from)
    }

    async fn codes_by_hashes(
        &self,
        hashes: &[B256],
        deadline: Option<Instant>,
    ) -> Result<HashMap<B256, Arc<Bytecode>>, LocalDataError> {
        self.get_codes_with_deadline(hashes, true, deadline).await.map_err(LocalDataError::from)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct InMemorySource {
        blocks: Mutex<HashMap<BlockHash, Block<OpTransaction>>>,
        codes: Mutex<HashMap<B256, Arc<Bytecode>>>,
    }

    #[async_trait]
    impl LocalDataSource for InMemorySource {
        async fn block_by_hash(
            &self,
            number: BlockNumber,
            hash: BlockHash,
            _deadline: Option<Instant>,
        ) -> Result<Block<OpTransaction>, LocalDataError> {
            self.blocks
                .lock()
                .unwrap()
                .get(&hash)
                .cloned()
                .ok_or(LocalDataError::BlockMissing { number, hash })
        }

        async fn codes_by_hashes(
            &self,
            hashes: &[B256],
            _deadline: Option<Instant>,
        ) -> Result<HashMap<B256, Arc<Bytecode>>, LocalDataError> {
            let guard = self.codes.lock().unwrap();
            let mut out = HashMap::with_capacity(hashes.len());
            for &h in hashes {
                let bc = guard.get(&h).cloned().ok_or_else(|| {
                    LocalDataError::Provider(
                        format!("bytecode not found locally: codehash={h:?}").into(),
                    )
                })?;
                out.insert(h, bc);
            }
            Ok(out)
        }
    }

    #[tokio::test]
    async fn in_memory_block_missing_returns_typed_error() {
        let src = InMemorySource::default();
        let h = B256::from([9u8; 32]);
        let err = src.block_by_hash(100, h, None).await.unwrap_err();
        assert!(matches!(err, LocalDataError::BlockMissing { number: 100, hash } if hash == h));
    }

    #[tokio::test]
    async fn in_memory_codes_all_present_returns_full_map() {
        let src = InMemorySource::default();
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);
        src.codes.lock().unwrap().insert(h1, Arc::new(Bytecode::new_raw(vec![0x60].into())));
        src.codes.lock().unwrap().insert(h2, Arc::new(Bytecode::new_raw(vec![0x61].into())));

        let got = src.codes_by_hashes(&[h1, h2], None).await.unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.contains_key(&h1));
        assert!(got.contains_key(&h2));
    }

    #[tokio::test]
    async fn in_memory_codes_errors_on_missing() {
        let src = InMemorySource::default();
        let h1 = B256::from([1u8; 32]);
        let h_unknown = B256::from([3u8; 32]);
        src.codes.lock().unwrap().insert(h1, Arc::new(Bytecode::new_raw(vec![0x60].into())));

        let err = src.codes_by_hashes(&[h1, h_unknown], None).await.unwrap_err();
        assert!(matches!(err, LocalDataError::Provider(_)), "expected Provider error, got {err:?}");
    }
}
