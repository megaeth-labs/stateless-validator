//! Vendored from reth v1.6.0 (commit d8451e54e, crates/trie/sparse/src/provider.rs), trimmed to the
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

//! Traits and default implementations related to retrieval of blinded trie nodes.

use alloy_primitives::{B256, Bytes};
use reth_trie_common::{Nibbles, TrieMask};

use super::SparseTrieError;

/// Factory for instantiating trie node providers.
#[auto_impl::auto_impl(&)]
pub trait TrieNodeProviderFactory {
    /// Type capable of fetching blinded account nodes.
    type AccountNodeProvider: TrieNodeProvider;
    /// Type capable of fetching blinded storage nodes.
    type StorageNodeProvider: TrieNodeProvider;

    /// Returns blinded account node provider.
    fn account_node_provider(&self) -> Self::AccountNodeProvider;

    /// Returns blinded storage node provider.
    fn storage_node_provider(&self, account: B256) -> Self::StorageNodeProvider;
}

/// Revealed blinded trie node.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct RevealedNode {
    /// Raw trie node.
    pub node: Bytes,
    /// Branch node tree mask, if any.
    pub tree_mask: Option<TrieMask>,
    /// Branch node hash mask, if any.
    pub hash_mask: Option<TrieMask>,
}

/// Trie node provider for retrieving trie nodes.
#[auto_impl::auto_impl(&)]
pub trait TrieNodeProvider {
    /// Retrieve trie node by path.
    fn trie_node(&self, path: &Nibbles) -> Result<Option<RevealedNode>, SparseTrieError>;
}

/// Default trie node provider factory that creates [`DefaultTrieNodeProviderFactory`].
#[derive(PartialEq, Eq, Clone, Default, Debug)]
pub struct DefaultTrieNodeProviderFactory;

impl TrieNodeProviderFactory for DefaultTrieNodeProviderFactory {
    type AccountNodeProvider = DefaultTrieNodeProvider;
    type StorageNodeProvider = DefaultTrieNodeProvider;

    fn account_node_provider(&self) -> Self::AccountNodeProvider {
        DefaultTrieNodeProvider
    }

    fn storage_node_provider(&self, _account: B256) -> Self::StorageNodeProvider {
        DefaultTrieNodeProvider
    }
}

/// Default trie node provider that always returns `Ok(None)`.
#[derive(PartialEq, Eq, Clone, Default, Debug)]
pub struct DefaultTrieNodeProvider;

impl TrieNodeProvider for DefaultTrieNodeProvider {
    fn trie_node(&self, _path: &Nibbles) -> Result<Option<RevealedNode>, SparseTrieError> {
        Ok(None)
    }
}

/// Right pad the path with 0s and return as [`B256`].
#[inline]
pub fn pad_path_to_key(path: &Nibbles) -> B256 {
    let mut padded = path.pack();
    padded.resize(32, 0);
    B256::from_slice(&padded)
}
