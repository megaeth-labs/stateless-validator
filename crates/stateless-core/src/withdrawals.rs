//! MPT (Merkle Patricia Trie) witness verification for L2→L1 withdrawal storage.
//!
//! This module verifies storage state transitions for the L2ToL1MessagePasser contract,
//! which stores commitments to withdrawal transactions. Given a pre-state witness and
//! storage updates from block execution, it cryptographically proves the storage root
//! transition is valid.

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256, map::B256Map};
use alloy_rlp::Encodable;
use alloy_rpc_types_eth::Header;
use reth_trie::Nibbles;
use reth_trie_common::{EMPTY_ROOT_HASH, LeafNode, TrieAccount, TrieNode};
use reth_trie_sparse::{
    SerialSparseTrie, SparseStateTrie, provider::DefaultTrieNodeProviderFactory,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    /// 1. Synthesizes an account-level state witness wrapping the storage witness
    /// 2. Reveals the trie via BFS, verifies pre-state root against `storage_root`
    /// 3. Applies storage updates (inserts non-zero, removes zero values)
    /// 4. Computes post-state root, verifies against `header.withdrawals_root`
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

        // Synthesize account-level witness and reveal via BFS
        let (synthesized_state_root, witness_map, hashed_address) = synthesize_state_witness(self);

        let mut state_trie = SparseStateTrie::<SerialSparseTrie>::default();
        state_trie
            .reveal_witness(synthesized_state_root, &witness_map)
            .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;

        // Verify pre-state root
        let pre_root = state_trie.storage_root(hashed_address).unwrap_or(EMPTY_ROOT_HASH);
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
                state_trie
                    .update_storage_leaf(
                        hashed_address,
                        nibbles,
                        encoded,
                        DefaultTrieNodeProviderFactory,
                    )
                    .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;
            } else {
                state_trie
                    .remove_storage_leaf(hashed_address, &nibbles, DefaultTrieNodeProviderFactory)
                    .map_err(|e| WithdrawalValidationError::TrieOperationFailed(e.to_string()))?;
            }
        }

        // Verify post-state root
        let post_root = state_trie.storage_root(hashed_address).unwrap_or(EMPTY_ROOT_HASH);
        if post_root != expected_post_root {
            return Err(WithdrawalValidationError::PostStateRootMismatch {
                expected: expected_post_root,
                actual: post_root,
            });
        }

        Ok(())
    }
}

/// Wraps a storage-only `MptWitness` as a single-account state witness so that
/// `SparseStateTrie::reveal_witness` can BFS-reveal the storage nodes automatically.
///
/// `reveal_witness` expects an account-level state trie, but `MptWitness` only contains
/// storage nodes for the L2ToL1MessagePasser contract. This helper synthesizes a one-leaf
/// account trie whose `TrieAccount.storage_root` points to the real storage witness,
/// allowing the existing BFS traversal to discover and reveal all storage nodes.
///
/// Returns `(synthesized_state_root, witness_map, hashed_address)`.
fn synthesize_state_witness(witness: &MptWitness) -> (B256, B256Map<Bytes>, B256) {
    let mut witness_map: B256Map<Bytes> =
        witness.state.iter().map(|node| (keccak256(node), node.clone())).collect();

    let hashed_address = keccak256(ADDRESS_L2_TO_L1_MESSAGE_PASSER);
    let trie_account = TrieAccount {
        nonce: 0,
        balance: U256::ZERO,
        storage_root: witness.storage_root,
        code_hash: KECCAK_EMPTY,
    };
    let mut account_rlp = Vec::new();
    trie_account.encode(&mut account_rlp);
    let account_leaf = TrieNode::Leaf(LeafNode::new(Nibbles::unpack(hashed_address), account_rlp));
    let mut leaf_rlp = Vec::new();
    account_leaf.encode(&mut leaf_rlp);
    let leaf_bytes = Bytes::from(leaf_rlp);
    let synthesized_state_root = keccak256(&leaf_bytes);
    witness_map.insert(synthesized_state_root, leaf_bytes);

    (synthesized_state_root, witness_map, hashed_address)
}
