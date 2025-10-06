//! MPT (Merkle Patricia Trie) witness verification for L2→L1 withdrawal storage.
//!
//! This module verifies storage state transitions for the L2ToL1MessagePasser contract,
//! which stores commitments to withdrawal transactions. Given a pre-state witness and
//! storage updates from block execution, it cryptographically proves the storage root
//! transition is valid.

use alloy_primitives::{Address, B256, Bytes, address, keccak256, map::B256Map};
use alloy_rlp::Decodable;
use alloy_rpc_types_eth::Header;
use reth_trie::Nibbles;
use reth_trie_common::HashedStorage;
use reth_trie_common::{EMPTY_ROOT_HASH, TrieNode};
use reth_trie_sparse::SparseTrieInterface;
use reth_trie_sparse::{
    SerialSparseTrie, SparseTrie, TrieMasks, provider::DefaultTrieNodeProvider,
};
use revm::database::states::CacheAccount;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use thiserror::Error;

/// Number of children in an MPT branch node (0-15, hex digits)
const BRANCH_NODE_CHILDREN: u8 = 16;

/// L2 contract `L2ToL1MessagePasser`, storing commitments to withdrawal transactions.
pub const ADDRESS_L2_TO_L1_MESSAGE_PASSER: Address =
    address!("0x4200000000000000000000000000000000000016");

/// Error type for withdrawal validation
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WithdrawalValidationError {
    #[error("Missing withdrawals_root in block header")]
    MissingWithdrawalsRoot,

    #[error("Witness node not found: {0:?}")]
    WitnessNodeNotFound(B256),

    #[error("RLP decode failed: {0}")]
    RlpDecodeFailed(String),

    #[error("Trie operation failed: {0}")]
    TrieOperationFailed(String),

    #[error("Trie not revealed")]
    TrieNotRevealed,

    #[error("Pre-state root mismatch: expected {expected:?}, got {actual:?}")]
    PreStateRootMismatch { expected: B256, actual: B256 },

    #[error("Post-state root mismatch: expected {expected:?}, got {actual:?}")]
    PostStateRootMismatch { expected: B256, actual: B256 },
}

/// Pre-state witness for the L2ToL1MessagePasser contract storage trie.
///
/// Contains the storage root and trie nodes needed to verify storage state
/// transitions during withdrawal processing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// 1. Reconstructs pre-state trie from witness, verifies against `storage_root`
    /// 2. Applies storage updates (inserts non-zero, removes zero values)
    /// 3. Computes post-state root, verifies against `header.withdrawals_root`
    ///
    /// # Arguments
    ///
    /// * `header` - Block header with expected `withdrawals_root` (post-state root)
    /// * `account` - Storage updates from block execution, or `None` for no changes
    ///
    /// # Errors
    ///
    /// * `MissingWithdrawalsRoot` - Header lacks `withdrawals_root` field
    /// * `PreStateRootMismatch` - Witness doesn't match expected pre-state root
    /// * `PostStateRootMismatch` - Computed post-state doesn't match header
    /// * `WitnessNodeNotFound` - Required trie node missing from witness
    /// * `RlpDecodeFailed` - Invalid RLP encoding in witness node
    /// * `TrieOperationFailed` - Trie update/removal failed
    /// * `TrieNotRevealed` - Trie not revealed before root computation
    pub fn verify(
        &self,
        header: &Header,
        account: Option<CacheAccount>,
    ) -> Result<(), WithdrawalValidationError> {
        let expected_post_root = header
            .withdrawals_root
            .ok_or(WithdrawalValidationError::MissingWithdrawalsRoot)?;

        // Extract and hash storage updates from the account
        let storage_updates = account
            .and_then(|a| a.account.map(|acc| acc.storage))
            .map(|slots| HashedStorage {
                wiped: false,
                storage: slots
                    .into_iter()
                    .map(|(k, v)| (keccak256(B256::from(k)), v))
                    .collect(),
            })
            .unwrap_or_default();

        // Build node lookup: hash → RLP bytes
        let nodes = self
            .state
            .iter()
            .map(|node| (keccak256(node), node.clone()))
            .collect::<B256Map<_>>();

        // Reconstruct and verify pre-state
        let mut trie = rebuild_trie(self.storage_root, &nodes)?;
        let root = trie
            .root()
            .ok_or(WithdrawalValidationError::TrieNotRevealed)?;
        if root != self.storage_root {
            return Err(WithdrawalValidationError::PreStateRootMismatch {
                expected: self.storage_root,
                actual: root,
            });
        }

        // Apply storage updates from block execution
        for (slot, value) in storage_updates.storage.iter() {
            let nibbles = Nibbles::unpack(*slot);
            if !value.is_zero() {
                let encoded = alloy_rlp::encode_fixed_size(value).to_vec();
                trie.update_leaf(nibbles, encoded, DefaultTrieNodeProvider)
                    .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;
            } else {
                trie.remove_leaf(&nibbles, DefaultTrieNodeProvider)
                    .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;
            }
        }

        // Verify post-state
        let root = trie
            .root()
            .ok_or(WithdrawalValidationError::TrieNotRevealed)?;
        if root != expected_post_root {
            return Err(WithdrawalValidationError::PostStateRootMismatch {
                expected: expected_post_root,
                actual: root,
            });
        }

        Ok(())
    }
}

/// Reconstructs a sparse trie from witness nodes using breadth-first traversal.
///
/// Reveals nodes from the witness in BFS order, ensuring parents are revealed
/// before children (required by sparse trie API). "Revealing" decodes the RLP
/// node and registers it in the trie structure.
///
/// # Arguments
///
/// * `root_hash` - Storage root to reconstruct (returns empty trie if `EMPTY_ROOT_HASH`)
/// * `nodes` - Map of node hashes to RLP-encoded trie node data
///
/// # Returns
///
/// Sparse trie with all witness nodes revealed, ready for updates or root computation
///
/// # Errors
///
/// * `WitnessNodeNotFound` - Node hash not found in `nodes` map
/// * `RlpDecodeFailed` - Node data failed RLP decoding
/// * `TrieOperationFailed` - Sparse trie rejected node reveal
/// * `TrieNotRevealed` - Child reveal attempted before parent revealed
fn rebuild_trie(
    root_hash: B256,
    nodes: &B256Map<Bytes>,
) -> Result<SparseTrie<SerialSparseTrie>, WithdrawalValidationError> {
    if root_hash == EMPTY_ROOT_HASH {
        return Ok(SparseTrie::revealed_empty());
    }

    let mut trie = SparseTrie::<SerialSparseTrie>::default();
    let mut queue = VecDeque::from([(root_hash, Nibbles::default())]);
    let mut visited = HashSet::from([root_hash]);

    while let Some((hash, path)) = queue.pop_front() {
        // Decode node from witness
        let bytes = nodes
            .get(&hash)
            .ok_or(WithdrawalValidationError::WitnessNodeNotFound(hash))?;
        let node = TrieNode::decode(&mut bytes.as_ref())
            .map_err(|e| WithdrawalValidationError::RlpDecodeFailed(e.to_string()))?;

        // Reveal node in trie
        if path.is_empty() {
            trie.reveal_root(node.clone(), TrieMasks::none(), false)
                .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;
        } else {
            trie.as_revealed_mut()
                .ok_or(WithdrawalValidationError::TrieNotRevealed)?
                .reveal_node(path, node.clone(), TrieMasks::none())
                .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;
        }

        // Helper to enqueue unvisited child nodes
        let mut enqueue = |child_hash: B256, child_path: Nibbles| {
            if nodes.contains_key(&child_hash) && visited.insert(child_hash) {
                queue.push_back((child_hash, child_path));
            }
        };

        // Enqueue child nodes for BFS traversal
        match node {
            TrieNode::Branch(branch) => {
                let mut stack_ptr = 0;
                for idx in 0..BRANCH_NODE_CHILDREN {
                    if branch.state_mask.is_bit_set(idx) {
                        if let Some(child_hash) = branch.stack[stack_ptr].as_hash() {
                            let mut child_path = path;
                            child_path.push_unchecked(idx);
                            enqueue(child_hash, child_path);
                        }
                        stack_ptr += 1;
                    }
                }
            }
            TrieNode::Extension(ext) => {
                if let Some(child_hash) = ext.child.as_hash() {
                    let mut child_path = path;
                    child_path.extend(&ext.key);
                    enqueue(child_hash, child_path);
                }
            }
            TrieNode::Leaf(_) | TrieNode::EmptyRoot => {}
        }
    }

    Ok(trie)
}
