//! Vendored from reth v1.6.0 (commit d8451e54e, crates/evm/execution-errors/src/trie.rs (SparseTrieError portion)), trimmed to the
//! serial sparse trie needed by withdrawal MPT witness verification.
//!
//! reth v2.3.0's sparse tries moved to a V2 node model that merges extension
//! nodes into their child branches; an extension whose child branch is absent
//! from the witness (a legal, minimal exclusion proof — the child is never
//! needed to split the extension on insert) cannot be represented and is
//! silently dropped on reveal, breaking withdrawal-slot inserts that split
//! such extensions. The MegaETH witness format is frozen upstream, so the
//! proven v1.6.0 semantics are pinned here instead.
//!
//! Local changes: import paths only (crate-relative + vendored errors);
//! test modules and metrics are not carried over. Do not edit otherwise.

use alloc::boxed::Box;
use alloy_primitives::B256;
use reth_trie_common::Nibbles;
use thiserror::Error;

/// Result type with [`SparseTrieError`] as error.
pub type SparseTrieResult<Ok> = Result<Ok, SparseTrieError>;

/// Error encountered in `SparseTrie`.
#[derive(Error, Debug)]
#[error(transparent)]
pub struct SparseTrieError(#[from] Box<SparseTrieErrorKind>);

impl<T: Into<SparseTrieErrorKind>> From<T> for SparseTrieError {
    #[cold]
    fn from(value: T) -> Self {
        Self(Box::new(value.into()))
    }
}

impl SparseTrieError {
    /// Returns the error kind.
    pub const fn kind(&self) -> &SparseTrieErrorKind {
        &self.0
    }

    /// Consumes the error and returns the error kind.
    pub fn into_kind(self) -> SparseTrieErrorKind {
        *self.0
    }
}

/// [`SparseTrieError`] kind.
#[derive(Error, Debug)]
pub enum SparseTrieErrorKind {
    /// Sparse trie is still blind. Thrown on attempt to update it.
    #[error("sparse trie is blind")]
    Blind,
    /// Encountered blinded node on update.
    #[error("attempted to update blind node at {path:?}: {hash}")]
    BlindedNode {
        /// Blind node path.
        path: Nibbles,
        /// Node hash
        hash: B256,
    },
    /// Encountered unexpected node at path when revealing.
    #[error("encountered an invalid node at path {path:?} when revealing: {node:?}")]
    Reveal {
        /// Path to the node.
        path: Nibbles,
        /// Node that was at the path when revealing.
        node: Box<dyn core::fmt::Debug + Send>,
    },
    /// RLP error.
    #[error(transparent)]
    Rlp(#[from] alloy_rlp::Error),
    /// Node not found in provider during revealing.
    #[error("node {path:?} not found in provider during removal")]
    NodeNotFoundInProvider {
        /// Path to the missing node.
        path: Nibbles,
    },
    /// Other.
    #[error(transparent)]
    Other(#[from] Box<dyn core::error::Error + Send>),
}
