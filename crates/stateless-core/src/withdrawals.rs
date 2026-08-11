//! MPT (Merkle Patricia Trie) witness verification for L2→L1 withdrawal storage.
//!
//! This module verifies storage state transitions for the L2ToL1MessagePasser contract,
//! which stores commitments to withdrawal transactions. Given a pre-state witness and
//! storage updates from block execution, it cryptographically proves the storage root
//! transition is valid: the witnessed trie is rebuilt with [`alloy_trie::HashBuilder`]
//! once without updates (must reproduce `storage_root`) and once with them (must
//! reproduce the header's `withdrawals_root`); updates the witness cannot prove fail
//! closed.

use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256, map::B256Map};
use alloy_rlp::Decodable;
use alloy_trie::{
    EMPTY_ROOT_HASH, HashBuilder, Nibbles,
    nodes::{BranchNode, RlpNode, TrieNode},
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

fn trie_error(msg: impl ToString) -> WithdrawalValidationError {
    WithdrawalValidationError::TrieOperationFailed(msg.to_string())
}

/// A pending slot update: `Some(rlp)` inserts or overwrites the leaf, `None` removes it.
type LeafUpdate = Option<Vec<u8>>;
/// Sorted (by path) pending updates, sliced narrower at every recursion step.
type Updates = [(Nibbles, LeafUpdate)];

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
    /// 1. Linearizes the witness with no updates; the rebuilt root must equal `storage_root`
    /// 2. Linearizes it again with the updates applied (inserts non-zero, removes zero values)
    /// 3. The rebuilt post-state root must equal `header.withdrawals_root`
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
    /// * `TrieOperationFailed` - Malformed witness node, or an update the witness cannot prove
    pub fn verify(
        &self,
        header: &Header,
        storage_updates: B256Map<U256>,
    ) -> Result<(), WithdrawalValidationError> {
        let expected_post_root =
            header.withdrawals_root.ok_or(WithdrawalValidationError::MissingWithdrawalsRoot)?;

        let mut updates: Vec<(Nibbles, LeafUpdate)> = storage_updates
            .into_iter()
            .map(|(slot, value)| {
                let update =
                    (!value.is_zero()).then(|| alloy_rlp::encode_fixed_size(&value).to_vec());
                (Nibbles::unpack(slot), update)
            })
            .collect();
        updates.sort_unstable_by_key(|(path, _)| *path);

        let linearizer = Linearizer {
            nodes: self.state.iter().map(|node| (keccak256(node.as_ref()), node)).collect(),
        };

        // Pre-state: rebuilding the witnessed trie with no updates must reproduce
        // `storage_root` exactly. Besides authenticating the witness, this self-checks
        // the linearization walk on this very witness before its post-state output is
        // trusted.
        let pre_root = linearizer.compute_root(self.storage_root, &[])?;
        if pre_root != self.storage_root {
            return Err(WithdrawalValidationError::PreStateRootMismatch {
                expected: self.storage_root,
                actual: pre_root,
            });
        }

        // With no updates the post-state is the pre-state just verified above.
        let post_root = if updates.is_empty() {
            pre_root
        } else {
            linearizer.compute_root(self.storage_root, &updates)?
        };
        if post_root != expected_post_root {
            return Err(WithdrawalValidationError::PostStateRootMismatch {
                expected: expected_post_root,
                actual: post_root,
            });
        }

        Ok(())
    }
}

/// Streams the (post-update) content of a witnessed storage trie into a
/// [`HashBuilder`] in sorted order.
struct Linearizer<'a> {
    /// Content-addressed witness nodes: `keccak(rlp) → rlp`.
    nodes: B256Map<&'a Bytes>,
}

impl Linearizer<'_> {
    /// Rebuilds the trie root that results from applying `updates` to the witnessed
    /// trie rooted at `root`.
    fn compute_root(
        &self,
        root: B256,
        updates: &Updates,
    ) -> Result<B256, WithdrawalValidationError> {
        let mut hb = HashBuilder::default();
        if root == EMPTY_ROOT_HASH {
            // Nothing exists: inserts materialize, removals of absent slots are no-ops.
            add_insert_leaves(&mut hb, updates);
        } else if self.nodes.contains_key(&root) {
            self.emit_subtree(&mut hb, &RlpNode::word_rlp(&root), Nibbles::default(), updates)?;
        } else {
            // The root node is absent, so the witness proves nothing; report the
            // reconstruction as empty and let the pre-state check flag the mismatch.
            return Ok(EMPTY_ROOT_HASH);
        }
        Ok(hb.root())
    }

    /// Decodes the trie node behind `node_ref`: from the witness for hash references
    /// (`None` when absent), or in place for inline (< 32 byte) nodes.
    fn resolve(&self, node_ref: &RlpNode) -> Result<Option<TrieNode>, WithdrawalValidationError> {
        let bytes: &[u8] = match node_ref.as_hash() {
            Some(hash) => match self.nodes.get(&hash) {
                Some(bytes) => bytes,
                None => return Ok(None),
            },
            None => node_ref,
        };
        TrieNode::decode(&mut &bytes[..]).map(Some).map_err(trie_error)
    }

    /// Emits the final content of the subtree at `path` (referenced by `node_ref`)
    /// into `hb`, applying `updates` (all of which lie strictly under `path`).
    ///
    /// Witnessed nodes are always expanded — leaves become `add_leaf` entries and
    /// unwitnessed children become `add_branch` entries — so the pre- and post-state
    /// passes exercise the identical walk.
    fn emit_subtree(
        &self,
        hb: &mut HashBuilder,
        node_ref: &RlpNode,
        path: Nibbles,
        updates: &Updates,
    ) -> Result<(), WithdrawalValidationError> {
        let Some(node) = self.resolve(node_ref)? else {
            if updates.is_empty() {
                // Untouched subtree: its position and hash are invariant under edits
                // elsewhere, so the opaque hash stands in for the whole region.
                hb.add_branch(
                    path,
                    node_ref.as_hash().expect("inline nodes always resolve"),
                    false,
                );
                return Ok(());
            }
            return Err(trie_error(format!("update descends into unwitnessed subtree at {path:?}")));
        };

        match node {
            TrieNode::EmptyRoot => {
                // Valid only as the root of an empty trie, which `compute_root`
                // short-circuits; as a child this is a malformed witness.
                Err(trie_error(format!("unexpected empty trie node at {path:?}")))
            }
            TrieNode::Leaf(leaf) => {
                let full = path.join(&leaf.key);
                // The leaf is the region's only occupant: a removal of any other path
                // is a proven no-op, and a write at `full` supersedes the leaf (its
                // replacement, if any, is the first entry of `rest`).
                let (before, rest) = updates.split_at(updates.partition_point(|(p, _)| p < &full));
                add_insert_leaves(hb, before);
                if rest.first().is_none_or(|(p, _)| p != &full) {
                    hb.add_leaf(full, &leaf.value);
                }
                add_insert_leaves(hb, rest);
                Ok(())
            }
            TrieNode::Extension(ext) => {
                let boundary = path.join(&ext.key);
                let (before, under, after) = split_at_prefix(updates, &boundary);
                // Updates diverging inside the extension key are proven to target
                // absent slots: removals are no-ops, inserts become fresh leaves.
                // The extension split this implies (and the child hash it reuses)
                // falls out of the emitted stream — the child is never read.
                add_insert_leaves(hb, before);
                self.emit_subtree(hb, &ext.child, boundary, under)?;
                add_insert_leaves(hb, after);
                Ok(())
            }
            TrieNode::Branch(branch) => {
                let regions = child_regions(&branch, &path, updates);

                // A branch that ends up with a single surviving region collapses: the
                // survivor merges upward. That is derived by the `HashBuilder` from
                // the stream — except when the sole survivor is an untouched
                // unwitnessed subtree, whose node kind (and thus merged shape) is
                // unknowable. reth v1.6.0's sparse trie failed the same way, via its
                // empty node provider.
                let mut survivors = Vec::new();
                for region in &regions {
                    if self.region_survives(region, path)? {
                        survivors.push(region);
                    }
                }
                if let [sole] = survivors[..] &&
                    sole.updates.is_empty() &&
                    let Some(child) = &sole.child &&
                    let Some(hash) = child.as_hash() &&
                    !self.nodes.contains_key(&hash)
                {
                    return Err(trie_error(format!(
                        "branch collapse at {path:?} adopts unwitnessed subtree at child {:x}",
                        sole.idx
                    )));
                }

                for region in regions {
                    let mut child_path = path;
                    child_path.push_unchecked(region.idx);
                    match region.child {
                        Some(child) => self.emit_subtree(hb, &child, child_path, region.updates)?,
                        None => {
                            // Empty slot: absence is proven by the branch mask, so
                            // removals are no-ops and inserts are fresh leaves.
                            add_insert_leaves(hb, region.updates);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Whether a branch child region still holds any content after its updates.
    fn region_survives(
        &self,
        region: &ChildRegion<'_>,
        path: Nibbles,
    ) -> Result<bool, WithdrawalValidationError> {
        // Any insert keeps the region alive; untouched existing content survives
        // (`survives_removals` returns true immediately for an empty update set).
        if region.updates.iter().any(|(_, update)| update.is_some()) {
            return Ok(true);
        }
        match &region.child {
            None => Ok(false),
            Some(child) => {
                let mut child_path = path;
                child_path.push_unchecked(region.idx);
                self.survives_removals(child, child_path, region.updates)
            }
        }
    }

    /// Whether the subtree at `path` still holds content after applying `removals`
    /// (a region whose updates are all `None`).
    fn survives_removals(
        &self,
        node_ref: &RlpNode,
        path: Nibbles,
        removals: &Updates,
    ) -> Result<bool, WithdrawalValidationError> {
        debug_assert!(removals.iter().all(|(_, update)| update.is_none()));
        if removals.is_empty() {
            return Ok(true);
        }
        let Some(node) = self.resolve(node_ref)? else {
            return Err(trie_error(format!(
                "removal descends into unwitnessed subtree at {path:?}"
            )));
        };
        match node {
            TrieNode::EmptyRoot => Ok(false),
            TrieNode::Leaf(leaf) => {
                let full = path.join(&leaf.key);
                Ok(!removals.iter().any(|(p, _)| *p == full))
            }
            TrieNode::Extension(ext) => {
                let boundary = path.join(&ext.key);
                let (_, under, _) = split_at_prefix(removals, &boundary);
                self.survives_removals(&ext.child, boundary, under)
            }
            TrieNode::Branch(branch) => {
                for region in child_regions(&branch, &path, removals) {
                    if self.region_survives(&region, path)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

/// One branch child slot together with the updates that fall under it.
struct ChildRegion<'a> {
    /// The child's nibble index within the branch.
    idx: u8,
    /// The child reference from the branch stack; `None` for an empty slot.
    child: Option<RlpNode>,
    /// The updates whose paths run through this slot.
    updates: &'a Updates,
}

/// Partitions `updates` (sorted, all lying under `path`) into the branch's 16 child
/// regions. Each region is a contiguous run because the paths are sorted and grouped
/// by their nibble at depth `path.len()`.
fn child_regions<'a>(
    branch: &BranchNode,
    path: &Nibbles,
    updates: &'a Updates,
) -> Vec<ChildRegion<'a>> {
    let mut regions = Vec::with_capacity(16);
    let mut rest = updates;
    for (idx, child) in branch.as_ref().children() {
        let split = rest.partition_point(|(p, _)| p.get_unchecked(path.len()) <= idx);
        let (region, tail) = rest.split_at(split);
        rest = tail;
        regions.push(ChildRegion { idx, child: child.cloned(), updates: region });
    }
    debug_assert!(rest.is_empty());
    regions
}

/// Emits the inserted leaves of `updates` into `hb`. Only valid where the removals in
/// `updates` are proven no-ops (their target region is known to hold no such leaves).
fn add_insert_leaves(hb: &mut HashBuilder, updates: &Updates) {
    for (path, update) in updates {
        if let Some(value) = update {
            hb.add_leaf(*path, value);
        }
    }
}

/// Splits sorted `updates` around the region prefixed by `prefix`:
/// `(diverging before, under prefix, diverging after)`.
///
/// The prefixed region is one contiguous run in sorted order, so two partition
/// points delimit it.
fn split_at_prefix<'u>(
    updates: &'u Updates,
    prefix: &Nibbles,
) -> (&'u Updates, &'u Updates, &'u Updates) {
    let lo = updates.partition_point(|(p, _)| p < prefix);
    let hi = lo + updates[lo..].partition_point(|(p, _)| p.starts_with(prefix));
    (&updates[..lo], &updates[lo..hi], &updates[hi..])
}

#[cfg(test)]
mod tests {
    use std::vec;

    use WithdrawalValidationError::*;
    use alloy_primitives::b256;
    use alloy_rlp::Encodable;
    use alloy_trie::nodes::{BranchNode, ExtensionNode, LeafNode};

    use super::*;

    const SLOT: B256 = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    /// A second slot diverging from `SLOT` at the first nibble.
    const SLOT_B: B256 =
        b256!("0x2111111111111111111111111111111111111111111111111111111111111111");
    const BOGUS: B256 = b256!("0xdeadbeef00000000000000000000000000000000000000000000000000000000");

    fn encoded(node: &TrieNode) -> Bytes {
        let mut rlp = Vec::new();
        node.encode(&mut rlp);
        Bytes::from(rlp)
    }

    fn rlp_of(node: &TrieNode) -> RlpNode {
        node.rlp(&mut Vec::new())
    }

    fn value_rlp(value: u64) -> Vec<u8> {
        alloy_rlp::encode_fixed_size(&U256::from(value)).to_vec()
    }

    /// A leaf node holding `value` under the trailing `key` nibbles.
    fn leaf_node(key: Nibbles, value: u64) -> TrieNode {
        TrieNode::Leaf(LeafNode::new(key, value_rlp(value)))
    }

    /// One-leaf storage trie for `SLOT → value`: returns (root, [leaf_bytes]).
    fn leaf(value: u64) -> (B256, Vec<Bytes>) {
        let bytes = encoded(&leaf_node(Nibbles::unpack(SLOT), value));
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
    #[test]
    fn empty_pre_state_with_new_leaf() {
        let (post, _) = leaf(42);
        run(EMPTY_ROOT_HASH, vec![], Some(post), &[(SLOT, U256::from(42u64))]).unwrap();
    }

    /// Regression: an insert that splits an extension node whose child branch is
    /// absent from the witness (a legal minimal exclusion proof — splitting never
    /// reads the child). reth v2.3.0's V2 sparse tries cannot represent this shape;
    /// the `HashBuilder` linearization needs only the child hash the extension
    /// itself carries.
    ///
    /// Trie shape: root extension (key = first 63 nibbles of `SLOT`) → branch with
    /// leaf children at `SLOT`'s last nibble (1) and at nibble 2. The witness
    /// contains only the extension node; the update inserts a slot diverging at the
    /// extension's first key nibble.
    #[test]
    fn insert_splitting_extension_with_absent_child_branch() {
        let (pre_root, witness, branch_hash) = ext_with_absent_branch();

        // Expected post-state: branch at the root splitting nibble 1 (old subtree,
        // reached via the shortened extension) from nibble 2 (the new leaf).
        let ext_key = Nibbles::unpack(SLOT).slice(0..63);
        let shortened_ext = TrieNode::Extension(ExtensionNode::new(
            ext_key.slice(1..),
            RlpNode::word_rlp(&branch_hash),
        ));
        let new_leaf = leaf_node(Nibbles::unpack(SLOT_B).slice(1..), 9);
        let split_branch = TrieNode::Branch(BranchNode::new(
            vec![rlp_of(&shortened_ext), rlp_of(&new_leaf)],
            0b0110.into(),
        ));
        let expected_post_root = keccak256(encoded(&split_branch));

        run(pre_root, witness, Some(expected_post_root), &[(SLOT_B, U256::from(9u64))]).unwrap();
    }

    /// A zero-write to a slot that provably diverges inside a witnessed extension
    /// key is a no-op: the post root equals the pre root.
    #[test]
    fn diverging_removal_is_noop() {
        let (pre_root, witness, _) = ext_with_absent_branch();
        run(pre_root, witness, Some(pre_root), &[(SLOT_B, U256::ZERO)]).unwrap();
    }

    /// Root extension (key = first 63 nibbles of `SLOT`) whose child branch — two
    /// empty-key leaves at nibbles 1 and 2 — is intentionally absent from the
    /// witness: returns `(pre_root, witness, branch_hash)`.
    fn ext_with_absent_branch() -> (B256, Vec<Bytes>, B256) {
        let branch = TrieNode::Branch(BranchNode::new(
            vec![
                rlp_of(&leaf_node(Nibbles::default(), 7)),
                rlp_of(&leaf_node(Nibbles::default(), 8)),
            ],
            0b0110.into(),
        ));
        let branch_hash = keccak256(encoded(&branch));
        let ext = TrieNode::Extension(ExtensionNode::new(
            Nibbles::unpack(SLOT).slice(0..63),
            RlpNode::word_rlp(&branch_hash),
        ));
        let ext_rlp = encoded(&ext);
        (keccak256(&ext_rlp), vec![ext_rlp], branch_hash)
    }

    /// Two-leaf trie: root branch holding `SLOT` under nibble 1 and `SLOT_B` under
    /// nibble 2, all nodes witnessed. Returns `(root, witness)`.
    fn two_leaf_branch() -> (B256, Vec<Bytes>) {
        let leaf_a = leaf_node(Nibbles::unpack(SLOT).slice(1..), 7);
        let leaf_b = leaf_node(Nibbles::unpack(SLOT_B).slice(1..), 8);
        let branch = TrieNode::Branch(BranchNode::new(
            vec![rlp_of(&leaf_a), rlp_of(&leaf_b)],
            0b0110.into(),
        ));
        let branch_rlp = encoded(&branch);
        (keccak256(&branch_rlp), vec![branch_rlp, encoded(&leaf_a), encoded(&leaf_b)])
    }

    /// Removing one of two leaves collapses the root branch into the surviving
    /// leaf, whose node is witnessed — the merged single-leaf root must come out.
    #[test]
    fn removal_collapse_merges_witnessed_sibling() {
        let (root, state) = two_leaf_branch();
        let expected = keccak256(encoded(&leaf_node(Nibbles::unpack(SLOT_B), 8)));
        run(root, state, Some(expected), &[(SLOT, U256::ZERO)]).unwrap();
    }

    /// Same collapse, but the surviving sibling's node is absent from the witness:
    /// its merged shape is unknowable, so verification must fail closed.
    #[test]
    fn removal_collapse_with_unwitnessed_survivor_errors() {
        let (root, mut state) = two_leaf_branch();
        state.truncate(2); // drop leaf_b — the survivor
        assert!(matches!(
            run(root, state, Some(root), &[(SLOT, U256::ZERO)]),
            Err(TrieOperationFailed(_))
        ));
    }

    /// An update descending into an unwitnessed branch child must fail closed.
    #[test]
    fn update_descending_into_unwitnessed_subtree_errors() {
        let (root, mut state) = two_leaf_branch();
        state.truncate(2); // drop leaf_b; SLOT_B's region is now opaque
        assert!(matches!(
            run(root, state, Some(root), &[(SLOT_B, U256::from(9u64))]),
            Err(TrieOperationFailed(_))
        ));
    }
}
