//! MPT (Merkle Patricia Trie) witness verification for Ethereum Account storage.
//!
//! This module provides functionality to verify storage state transitions using
//! MPT witnesses. It reconstructs the old state from witness data, applies storage
//! updates, and verifies the new state root.

use alloy_primitives::{Address, B256, Bytes, address, keccak256, map::B256Map};
use alloy_rlp::Decodable;
use reth_trie::Nibbles;
use reth_trie_common::HashedStorage;
use reth_trie_common::{EMPTY_ROOT_HASH, TrieNode};
use reth_trie_sparse::SparseTrieInterface;
use reth_trie_sparse::{
    SerialSparseTrie, SparseTrie, TrieMasks, provider::DefaultTrieNodeProvider,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use thiserror::Error;

/// Number of children in a branch node (0-15, hex digits)
const BRANCH_NODE_CHILDREN: usize = 16;

/// The L2 contract `L2ToL1MessagePasser`, stores commitments to withdrawal transactions.
pub const ADDRESS_L2_TO_L1_MESSAGE_PASSER: Address =
    address!("0x4200000000000000000000000000000000000016");

/// Represents the execution witness of the withdrawal contract
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MptWitness {
    /// The root hash of the L2ToL1MessagePasser contract storage trie
    pub withdrawals_root: B256,
    /// The witness trie nodes of the withdrawal account storage trie
    pub state: Vec<Bytes>,
}

impl MptWitness {
    /// Verifies a storage state transition using an MPT witness.
    ///
    /// This function performs the following steps:
    /// 1. Reconstructs the old storage state from the witness data
    /// 2. Verifies that the reconstructed state matches `old_storage_root`
    /// 3. Applies the storage updates from `new_storage`
    /// 4. Verifies that the final state matches `new_storage_root`
    ///
    /// # Arguments
    ///
    /// * `new_storage_root` - The expected root hash of the storage trie after updates
    /// * `witness` - Map of node hashes to their RLP-encoded trie nodes
    /// * `new_storage` - The storage updates to apply (insertions and deletions)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the witness verification succeeds, or an error describing
    /// what went wrong during verification.
    ///
    /// # Errors
    ///
    /// This function can return various errors including:
    /// - `MissingNode` if a required node is not in the witness
    /// - `OldStateRootMismatch` if the reconstructed old state doesn't match
    /// - `NewStateRootMismatch` if the calculated new state doesn't match
    pub fn verify(
        &self,
        new_storage_root: B256,
        partial_new_storage: HashedStorage,
    ) -> Result<(), MptWitnessError> {
        let witness = self
            .state
            .iter()
            .map(|node| (keccak256(node), node.clone()))
            .collect::<B256Map<_>>();
        let old_storage_root = self.withdrawals_root;

        // Phase 1: Reconstruct the old storage state from witness
        let mut sparse_trie = reconstruct_trie_from_witness(old_storage_root, &witness)?;

        // Phase 2: Verify the reconstructed old state
        let calculated_root = sparse_trie
            .root()
            .ok_or_else(|| MptWitnessError::Trie("Trie not revealed".to_string()))?;
        if calculated_root != old_storage_root {
            return Err(MptWitnessError::OldRootMismatch {
                expected: old_storage_root,
                calculated: calculated_root,
            });
        }

        // Phase 3: Apply storage updates
        apply_storage_updates(&mut sparse_trie, partial_new_storage)?;

        // Phase 4: Verify the new state
        let calculated_root = sparse_trie
            .root()
            .ok_or_else(|| MptWitnessError::Trie("Trie not revealed".to_string()))?;
        if calculated_root != new_storage_root {
            return Err(MptWitnessError::NewRootMismatch {
                expected: new_storage_root,
                calculated: calculated_root,
            });
        }
        Ok(())
    }
}

/// Error type for MPT witness verification
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MptWitnessError {
    #[error("Node not found in mpt witness: {0:?}")]
    MissingNode(B256),

    #[error("Node decode failed: {0}")]
    Decode(String),

    #[error("Trie error: {0}")]
    Trie(String),

    #[error("Old state root mismatch: expected {expected:?}, calculated {calculated:?}")]
    OldRootMismatch { expected: B256, calculated: B256 },

    #[error("New state root mismatch: expected {expected:?}, calculated {calculated:?}")]
    NewRootMismatch { expected: B256, calculated: B256 },
}

/// Reconstructs a sparse trie from witness data using BFS traversal.
fn reconstruct_trie_from_witness(
    root_hash: B256,
    witness: &B256Map<Bytes>,
) -> Result<SparseTrie<SerialSparseTrie>, MptWitnessError> {
    if root_hash == EMPTY_ROOT_HASH {
        return Ok(SparseTrie::revealed_empty());
    }

    let mut sparse_trie = SparseTrie::<SerialSparseTrie>::default();
    let mut queue = VecDeque::from([(root_hash, Nibbles::default())]);
    let mut visited_hashes = HashSet::from([root_hash]);

    while let Some((hash, path)) = queue.pop_front() {
        let node_bytes = witness
            .get(&hash)
            .ok_or(MptWitnessError::MissingNode(hash))?;

        let node = TrieNode::decode(&mut node_bytes.as_ref())
            .map_err(|e| MptWitnessError::Decode(e.to_string()))?;

        if path.is_empty() {
            // This is the root node
            sparse_trie
                .reveal_root(node.clone(), TrieMasks::none(), false)
                .map_err(|e| MptWitnessError::Trie(e.to_string()))?;
        } else {
            // This is a non-root node
            sparse_trie
                .as_revealed_mut()
                .ok_or_else(|| MptWitnessError::Trie("Trie not revealed".to_string()))?
                .reveal_node(path, node.clone(), TrieMasks::none())
                .map_err(|e| MptWitnessError::Trie(e.to_string()))?;
        };

        // Enqueue child nodes for processing
        match node {
            TrieNode::Branch(branch) => {
                let mut stack_ptr = 0;
                for idx in 0..BRANCH_NODE_CHILDREN {
                    #[allow(clippy::cast_possible_truncation)]
                    let idx_u8 = idx as u8;
                    if branch.state_mask.is_bit_set(idx_u8) {
                        if let Some(child_hash) = branch.stack[stack_ptr].as_hash()
                            && witness.contains_key(&child_hash)
                            && visited_hashes.insert(child_hash)
                        {
                            let mut child_path = path;
                            child_path.push_unchecked(idx_u8);
                            queue.push_back((child_hash, child_path));
                        }

                        stack_ptr += 1;
                    }
                }
            }
            TrieNode::Extension(ext) => {
                if let Some(child_hash) = ext.child.as_hash()
                    && witness.contains_key(&child_hash)
                    && visited_hashes.insert(child_hash)
                {
                    let mut child_path = path;
                    child_path.extend(&ext.key);
                    queue.push_back((child_hash, child_path));
                }
            }
            _ => {
                // Leaf nodes have no children
            }
        }
    }

    Ok(sparse_trie)
}

/// Applies storage updates to the sparse trie.
fn apply_storage_updates(
    sparse_trie: &mut SparseTrie<SerialSparseTrie>,
    new_storage: HashedStorage,
) -> Result<(), MptWitnessError> {
    for (hashed_slot, value) in new_storage.storage.iter() {
        let nibbles = Nibbles::unpack(*hashed_slot);

        if !value.is_zero() {
            // Insert or update the storage slot
            let encoded_value = alloy_rlp::encode_fixed_size(value).to_vec();
            sparse_trie
                .update_leaf(nibbles, encoded_value, DefaultTrieNodeProvider)
                .map_err(|e| MptWitnessError::Trie(e.to_string()))?;
        } else {
            // Remove the storage slot (value is zero)
            sparse_trie
                .remove_leaf(&nibbles, DefaultTrieNodeProvider)
                .map_err(|e| MptWitnessError::Trie(e.to_string()))?;
        }
    }
    Ok(())
}
