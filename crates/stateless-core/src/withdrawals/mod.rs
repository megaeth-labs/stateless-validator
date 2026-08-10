//! MPT (Merkle Patricia Trie) witness verification for L2→L1 withdrawal storage.
//!
//! This module verifies storage state transitions for the L2ToL1MessagePasser contract,
//! which stores commitments to withdrawal transactions. Given a pre-state witness and
//! storage updates from block execution, it cryptographically proves the storage root
//! transition is valid.
//!
//! The trie machinery lives in [`sparse_trie`], vendored from reth v1.6.0: the witness
//! format is frozen upstream and can contain extension nodes whose child branch is
//! absent (a minimal exclusion proof), a shape reth v2.3.0's V2 sparse tries cannot
//! represent.

#[allow(dead_code)]
mod sparse_trie;

use std::{
    collections::VecDeque,
    string::{String, ToString},
    vec::Vec,
};

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256, map::B256Map};
use alloy_rlp::Decodable;
use reth_trie_common::{EMPTY_ROOT_HASH, Nibbles, RlpNode, TrieNode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use self::sparse_trie::{
    SerialSparseTrie, SparseTrie, SparseTrieInterface, TrieMasks,
    provider::DefaultTrieNodeProvider,
};

/// L2 contract `L2ToL1MessagePasser`, storing commitments to withdrawal transactions.
pub const ADDRESS_L2_TO_L1_MESSAGE_PASSER: Address =
    address!("0x4200000000000000000000000000000000000016");

/// Error type for withdrawal validation
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WithdrawalValidationError {
    #[error("Missing withdrawals_root in block header")]
    MissingWithdrawalsRoot,

    #[error("Trie operation failed: {0}")]
    TrieOperationFailed(String),

    #[error("Pre-state root mismatch: expected {expected:?}, got {actual:?}")]
    PreStateRootMismatch { expected: B256, actual: B256 },

    #[error("Post-state root mismatch: expected {expected:?}, got {actual:?}")]
    PostStateRootMismatch { expected: B256, actual: B256 },
}

/// Pre-state witness for the L2ToL1MessagePasser contract storage trie.
///
/// Contains the storage root and trie nodes needed to verify storage state
/// transitions during withdrawal processing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MptWitness {
    /// The pre-state storage root of the L2ToL1MessagePasser contract
    pub storage_root: B256,
    /// RLP-encoded trie nodes proving the pre-state
    pub state: Vec<Bytes>,
}

impl MptWitness {
    /// Verifies a storage state transition for the L2ToL1MessagePasser contract.
    ///
    /// Proves that applying storage updates to the pre-state witness produces the
    /// expected post-state root from the block header.
    ///
    /// # Process
    ///
    /// 1. Reveals the storage trie via BFS from `storage_root`, verifies the pre-state root
    /// 2. Applies storage updates (inserts non-zero, removes zero values)
    /// 3. Computes the post-state root, verifies against `header.withdrawals_root`
    ///
    /// # Arguments
    ///
    /// * `header` - Block header with expected `withdrawals_root` (post-state root)
    /// * `storage_updates` - Hashed storage slot updates from block execution (slot hash → value)
    ///
    /// # Errors
    ///
    /// * `MissingWithdrawalsRoot` - Header lacks `withdrawals_root` field
    /// * `PreStateRootMismatch` - Witness doesn't match expected pre-state root
    /// * `PostStateRootMismatch` - Computed post-state doesn't match header
    /// * `TrieOperationFailed` - Trie reveal/update/removal failed
    pub fn verify(
        &self,
        header: &Header,
        storage_updates: B256Map<U256>,
    ) -> Result<(), WithdrawalValidationError> {
        let expected_post_root =
            header.withdrawals_root.ok_or(WithdrawalValidationError::MissingWithdrawalsRoot)?;

        let mut trie = self.reveal()?;

        // Verify the pre-state root. `root()` returns `None` when the trie is still
        // blind, which happens when `storage_root` is non-empty but the witness lacks
        // the root node; the check below catches that as a mismatch.
        let pre_root = trie.root().unwrap_or(EMPTY_ROOT_HASH);
        if pre_root != self.storage_root {
            return Err(WithdrawalValidationError::PreStateRootMismatch {
                expected: self.storage_root,
                actual: pre_root,
            });
        }

        // Apply storage updates from block execution
        for (slot, value) in storage_updates {
            let nibbles = Nibbles::unpack(slot);
            if !value.is_zero() {
                let encoded = alloy_rlp::encode_fixed_size(&value).to_vec();
                trie.update_leaf(nibbles, encoded, DefaultTrieNodeProvider)
                    .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;
            } else {
                trie.remove_leaf(&nibbles, DefaultTrieNodeProvider)
                    .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;
            }
        }

        // Verify the post-state root (same blind-trie caveat as the pre-state).
        let post_root = trie.root().unwrap_or(EMPTY_ROOT_HASH);
        if post_root != expected_post_root {
            return Err(WithdrawalValidationError::PostStateRootMismatch {
                expected: expected_post_root,
                actual: post_root,
            });
        }

        Ok(())
    }

    /// Reveals the witness into a sparse storage trie via BFS from `storage_root`.
    ///
    /// Nodes referenced by hash but absent from the witness stay blind — legal for
    /// subtrees the block does not touch (and, for extension children, even for
    /// inserts that split the extension). An empty `storage_root` yields a
    /// revealed-empty trie so that first-ever withdrawals can insert into it.
    fn reveal(&self) -> Result<SparseTrie, WithdrawalValidationError> {
        if self.storage_root == EMPTY_ROOT_HASH {
            return Ok(SparseTrie::revealed_empty());
        }

        let witness_map: B256Map<&Bytes> =
            self.state.iter().map(|node| (keccak256(node.as_ref()), node)).collect();

        let trie_err = |e: sparse_trie::SparseTrieError| {
            WithdrawalValidationError::TrieOperationFailed(e.to_string())
        };

        let mut trie = SparseTrie::<SerialSparseTrie>::blind();
        let mut queue = VecDeque::from([(self.storage_root, Nibbles::default())]);
        while let Some((hash, path)) = queue.pop_front() {
            // Nodes referenced by hash but not present stay blind.
            let Some(bytes) = witness_map.get(&hash) else { continue };
            let node = TrieNode::decode(&mut &bytes[..])
                .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;

            // Queue hash-referenced children; inline children are revealed as part of
            // their parent node.
            match &node {
                TrieNode::Branch(branch) => {
                    for (idx, maybe_child) in branch.as_ref().children() {
                        if let Some(child_hash) = maybe_child.and_then(RlpNode::as_hash) {
                            let mut child_path = path;
                            child_path.push_unchecked(idx);
                            queue.push_back((child_hash, child_path));
                        }
                    }
                }
                TrieNode::Extension(ext) => {
                    if let Some(child_hash) = ext.child.as_hash() {
                        let mut child_path = path;
                        child_path.extend(&ext.key);
                        queue.push_back((child_hash, child_path));
                    }
                }
                TrieNode::Leaf(_) | TrieNode::EmptyRoot => {}
            }

            // BFS visits parents before children, so the root is always first.
            if path.is_empty() {
                trie.reveal_root(node, TrieMasks::none(), false).map_err(trie_err)?;
            } else {
                trie.as_revealed_mut()
                    .expect("root node is revealed first")
                    .reveal_node(path, node, TrieMasks::none())
                    .map_err(trie_err)?;
            }
        }

        Ok(trie)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use WithdrawalValidationError::*;
    use alloy_primitives::b256;
    use alloy_rlp::Encodable;
    use reth_trie_common::{BranchNode, ExtensionNode, LeafNode};

    use super::*;

    const SLOT: B256 = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    const BOGUS: B256 = b256!("0xdeadbeef00000000000000000000000000000000000000000000000000000000");

    /// One-leaf storage trie for `SLOT → value`: returns (root, [leaf_bytes]).
    fn leaf(value: u64) -> (B256, Vec<Bytes>) {
        let value_rlp = alloy_rlp::encode_fixed_size(&U256::from(value)).to_vec();
        let mut rlp = Vec::new();
        TrieNode::Leaf(LeafNode::new(Nibbles::unpack(SLOT), value_rlp)).encode(&mut rlp);
        let bytes = Bytes::from(rlp);
        (keccak256(&bytes), vec![bytes])
    }

    fn run(
        storage_root: B256,
        state: Vec<Bytes>,
        expected: Option<B256>,
        updates: &[(B256, U256)],
    ) -> Result<(), WithdrawalValidationError> {
        let header = Header { withdrawals_root: expected, ..Default::default() };
        MptWitness { storage_root, state }.verify(&header, updates.iter().copied().collect())
    }

    #[test]
    fn missing_withdrawals_root() {
        assert_eq!(run(EMPTY_ROOT_HASH, vec![], None, &[]), Err(MissingWithdrawalsRoot));
    }

    #[test]
    fn empty_trie_verifies() {
        run(EMPTY_ROOT_HASH, vec![], Some(EMPTY_ROOT_HASH), &[]).unwrap();
    }

    #[test]
    fn non_empty_trie_no_updates_verifies() {
        let (root, state) = leaf(42);
        run(root, state, Some(root), &[]).unwrap();
    }

    #[test]
    fn leaf_update_changes_root() {
        let (pre, state) = leaf(42);
        let (post, _) = leaf(99);
        run(pre, state, Some(post), &[(SLOT, U256::from(99u64))]).unwrap();
    }

    #[test]
    fn leaf_removal_collapses_to_empty() {
        let (root, state) = leaf(42);
        run(root, state, Some(EMPTY_ROOT_HASH), &[(SLOT, U256::ZERO)]).unwrap();
    }

    #[test]
    fn pre_state_mismatch() {
        assert!(matches!(
            run(BOGUS, vec![], Some(EMPTY_ROOT_HASH), &[]),
            Err(PreStateRootMismatch { .. })
        ));
    }

    #[test]
    fn post_state_mismatch() {
        let (root, state) = leaf(42);
        assert!(matches!(
            run(root, state, Some(EMPTY_ROOT_HASH), &[]),
            Err(PostStateRootMismatch { .. })
        ));
    }

    /// Attack: claimed pre-state root non-empty, witness nodes omitted.
    #[test]
    fn missing_nodes() {
        let (root, _) = leaf(42);
        assert!(matches!(run(root, vec![], Some(root), &[]), Err(PreStateRootMismatch { .. })));
    }

    /// Attack: tampered node bytes → hash mismatch → treated as missing.
    #[test]
    fn tampered_node() {
        let (root, mut state) = leaf(42);
        let mut bytes = state[0].to_vec();
        *bytes.last_mut().unwrap() ^= 0x01;
        state[0] = Bytes::from(bytes);
        assert!(matches!(run(root, state, Some(root), &[]), Err(PreStateRootMismatch { .. })));
    }

    /// Attack: update targets a slot whose subtree is missing.
    #[test]
    fn update_on_missing_subtree() {
        let (root, _) = leaf(42);
        assert!(matches!(
            run(root, vec![], Some(root), &[(SLOT, U256::from(99u64))]),
            Err(PreStateRootMismatch { .. } | TrieOperationFailed(_))
        ));
    }

    /// First-ever withdrawal: empty pre-state storage trie, one new non-zero slot.
    /// Exercises the `EMPTY_ROOT_HASH` pre-state path where the trie starts
    /// revealed-empty so the insert can proceed.
    #[test]
    fn empty_pre_state_with_new_leaf() {
        let (post, _) = leaf(42);
        run(EMPTY_ROOT_HASH, vec![], Some(post), &[(SLOT, U256::from(42u64))]).unwrap();
    }

    /// Regression: an insert that splits an extension node whose child branch is
    /// absent from the witness (a legal minimal exclusion proof — splitting never
    /// reads the child). reth v2.3.0's V2 sparse tries drop such extensions on
    /// reveal and then fail the insert with "attempted to update blind node";
    /// the vendored v1.6.0 trie must handle it.
    ///
    /// Trie shape: root extension (key = first 63 nibbles of `SLOT`) → branch with
    /// leaf children at `SLOT`'s last nibble (1) and at nibble 2. The witness
    /// contains only the extension node; the update inserts a slot diverging at the
    /// extension's first key nibble.
    #[test]
    fn insert_splitting_extension_with_absent_child_branch() {
        let leaf_node = |value: u64| {
            let value_rlp = alloy_rlp::encode_fixed_size(&U256::from(value)).to_vec();
            TrieNode::Leaf(LeafNode::new(Nibbles::default(), value_rlp))
        };
        let rlp_of = |node: &TrieNode| {
            let mut buf = Vec::new();
            node.encode(&mut buf);
            RlpNode::from_rlp(&buf)
        };

        // Child branch of the extension: two empty-key leaves at nibbles 1 and 2.
        let branch = TrieNode::Branch(BranchNode::new(
            vec![rlp_of(&leaf_node(7)), rlp_of(&leaf_node(8))],
            0b0110.into(),
        ));
        let mut branch_rlp = Vec::new();
        branch.encode(&mut branch_rlp);
        let branch_hash = keccak256(&branch_rlp);

        // Root extension covering the first 63 nibbles of SLOT.
        let ext_key = Nibbles::unpack(SLOT).slice(0..63);
        let ext =
            TrieNode::Extension(ExtensionNode::new(ext_key, RlpNode::word_rlp(&branch_hash)));
        let mut ext_rlp = Vec::new();
        ext.encode(&mut ext_rlp);
        let pre_root = keccak256(&ext_rlp);

        // Insert a slot that diverges from the extension key at nibble 0.
        let diverging_slot =
            b256!("0x2111111111111111111111111111111111111111111111111111111111111111");

        // Expected post-state: branch at the root splitting nibble 1 (old subtree,
        // reached via the shortened extension) from nibble 2 (the new leaf).
        let shortened_ext = TrieNode::Extension(ExtensionNode::new(
            ext_key.slice(1..),
            RlpNode::word_rlp(&branch_hash),
        ));
        let new_leaf = TrieNode::Leaf(LeafNode::new(
            Nibbles::unpack(diverging_slot).slice(1..),
            alloy_rlp::encode_fixed_size(&U256::from(9u64)).to_vec(),
        ));
        let split_branch = TrieNode::Branch(BranchNode::new(
            vec![rlp_of(&shortened_ext), rlp_of(&new_leaf)],
            0b0110.into(),
        ));
        let mut split_rlp = Vec::new();
        split_branch.encode(&mut split_rlp);
        let expected_post_root = keccak256(&split_rlp);

        // Witness: extension only — the child branch is intentionally absent.
        run(
            pre_root,
            vec![Bytes::from(ext_rlp)],
            Some(expected_post_root),
            &[(diverging_slot, U256::from(9u64))],
        )
        .unwrap();
    }
}
