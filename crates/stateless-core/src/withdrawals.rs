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

/// Nibbles in a storage-trie key: slots are keyed by their 32-byte hash. [`Nibbles`] caps at
/// this length and treats a longer path as an invariant violation (undefined behavior in
/// release builds), so no path is ever built past it.
const KEY_NIBBLES: usize = 64;

/// `path` extended by `key`, or an error when the result would outgrow a storage-trie key.
///
/// Every join and push in the walk goes through this bound (directly, or via
/// [`child_regions`] for branch children): the walk also runs over witness bytes that are only
/// hash-linked to a claimed root, so a structurally impossible trie must be refused rather
/// than followed.
fn join_path(path: &Nibbles, key: &Nibbles) -> Result<Nibbles, WithdrawalValidationError> {
    if path.len() + key.len() > KEY_NIBBLES {
        return Err(trie_error(format!(
            "node path at {path:?} extends past the {KEY_NIBBLES}-nibble key length"
        )));
    }
    Ok(path.join(key))
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
    /// * `TrieOperationFailed` - Malformed or missing witness node (including the root), or an
    ///   update the witness cannot prove
    ///
    /// # Untrusted witness bytes
    ///
    /// The first pass walks nodes that are only hash-linked to the *claimed* `storage_root`;
    /// only a caller that anchors that root to the parent block (see `ValidationOptions`)
    /// pins them to the chain. The walk therefore refuses any shape no 32-byte-keyed trie
    /// has — a path past [`KEY_NIBBLES`], a leaf not ending at exactly that depth, an
    /// extension with an empty key — as `TrieOperationFailed`. That keeps recursion depth
    /// bounded by the key length and keeps the emitted keys prefix-free and strictly
    /// increasing (children in nibble order, each strictly under its parent's path), which is
    /// what `HashBuilder`'s ordering `assert!`s require.
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
            // The root node is absent, so the witness proves nothing about this trie. Say so
            // here rather than hand back a root that was never computed, so no caller owes
            // this walk a follow-up comparison to stay fail-closed.
            return Err(trie_error(format!("witness lacks the root node {root}")));
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
                let full = join_path(&path, &leaf.key)?;
                if full.len() != KEY_NIBBLES {
                    return Err(trie_error(format!(
                        "leaf at {full:?} does not end at the {KEY_NIBBLES}-nibble key depth"
                    )));
                }
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
                let boundary = extension_boundary(&path, &ext.key)?;
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
                let regions = child_regions(&branch, &path, updates)?;

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
                let full = join_path(&path, &leaf.key)?;
                Ok(!removals.iter().any(|(p, _)| *p == full))
            }
            TrieNode::Extension(ext) => {
                let boundary = extension_boundary(&path, &ext.key)?;
                let (_, under, _) = split_at_prefix(removals, &boundary);
                self.survives_removals(&ext.child, boundary, under)
            }
            TrieNode::Branch(branch) => {
                for region in child_regions(&branch, &path, removals)? {
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

/// `path` extended by an extension node's `key`, refusing the shapes no trie has.
///
/// An extension always consumes at least one nibble: an empty key would let a chain of
/// extensions recurse without descending, so it is rejected rather than followed.
fn extension_boundary(path: &Nibbles, key: &Nibbles) -> Result<Nibbles, WithdrawalValidationError> {
    if key.is_empty() {
        return Err(trie_error(format!("extension with an empty key at {path:?}")));
    }
    join_path(path, key)
}

/// Partitions `updates` (sorted, all lying under `path`) into the branch's 16 child
/// regions. Each region is a contiguous run because the paths are sorted and grouped
/// by their nibble at depth `path.len()`.
///
/// Every update must land in some region. That holds because `children()` yields all 16
/// nibble slots (`None` for unset ones), so the last slot's region takes whatever is left;
/// should an alloy-trie upgrade ever narrow the iteration to populated children, the
/// leftover is an error here rather than an update silently dropped from a release build.
fn child_regions<'a>(
    branch: &BranchNode,
    path: &Nibbles,
    updates: &'a Updates,
) -> Result<Vec<ChildRegion<'a>>, WithdrawalValidationError> {
    // A branch at the full key depth has no room for a nibble below it.
    if path.len() >= KEY_NIBBLES {
        return Err(trie_error(format!(
            "branch at {path:?} sits at the full {KEY_NIBBLES}-nibble key depth"
        )));
    }
    let mut regions = Vec::with_capacity(16);
    let mut rest = updates;
    for (idx, child) in branch.as_ref().children() {
        let split = rest.partition_point(|(p, _)| p.get_unchecked(path.len()) <= idx);
        let (region, tail) = rest.split_at(split);
        rest = tail;
        regions.push(ChildRegion { idx, child: child.cloned(), updates: region });
    }
    if !rest.is_empty() {
        return Err(trie_error(format!(
            "{} update(s) fell outside the 16 child slots of the branch at {path:?}",
            rest.len()
        )));
    }
    Ok(regions)
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
    use std::{collections::BTreeMap, vec};

    use WithdrawalValidationError::*;
    use alloy_primitives::b256;
    use alloy_rlp::Encodable;
    use alloy_trie::{
        nodes::{BranchNode, ExtensionNode, LeafNode},
        proof::ProofRetainer,
    };

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
            Err(TrieOperationFailed(_))
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
        assert!(matches!(run(root, vec![], Some(root), &[]), Err(TrieOperationFailed(_))));
    }

    /// Attack: tampered node bytes → hash mismatch → treated as missing.
    #[test]
    fn tampered_node() {
        let (root, mut state) = leaf(42);
        let mut bytes = state[0].to_vec();
        *bytes.last_mut().unwrap() ^= 0x01;
        state[0] = Bytes::from(bytes);
        assert!(matches!(run(root, state, Some(root), &[]), Err(TrieOperationFailed(_))));
    }

    /// Attack: update targets a slot whose subtree is missing.
    #[test]
    fn update_on_missing_subtree() {
        let (root, _) = leaf(42);
        assert!(matches!(
            run(root, vec![], Some(root), &[(SLOT, U256::from(99u64))]),
            Err(TrieOperationFailed(_))
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

    /// Root of the storage trie holding `state`, built independently of [`Linearizer`]: every
    /// leaf streamed into a `HashBuilder` in key order.
    fn reference_root(state: &BTreeMap<B256, U256>) -> B256 {
        let mut hb = HashBuilder::default();
        for (slot, value) in state {
            hb.add_leaf(Nibbles::unpack(slot), &alloy_rlp::encode_fixed_size(value));
        }
        hb.root()
    }

    /// The pre-state root of `state` and a minimal witness for it: the nodes on the paths to
    /// `targets`, exactly as the proof retainer of the same builder emits them. An absent
    /// target gets an exclusion proof — the path nodes down to where its key would diverge —
    /// so the witness never contains the subtrees an insert or a no-op removal cannot read.
    fn minimal_witness(state: &BTreeMap<B256, U256>, targets: &[B256]) -> (B256, Vec<Bytes>) {
        let retainer = ProofRetainer::new(targets.iter().map(Nibbles::unpack).collect());
        let mut hb = HashBuilder::default().with_proof_retainer(retainer);
        for (slot, value) in state {
            hb.add_leaf(Nibbles::unpack(slot), &alloy_rlp::encode_fixed_size(value));
        }
        let root = hb.root();
        (root, hb.take_proof_nodes().into_inner().into_values().collect())
    }

    /// An insert into an empty branch slot whose nibble lies below, between, or above the
    /// populated children (children sit at nibbles 1 and 2) must land in the post root:
    /// `child_regions` has to hand every update to some slot, including the empty ones past
    /// the last populated child.
    #[test]
    fn insert_into_empty_branch_slot_matches_reference_for_every_nibble() {
        let (root, state) = two_leaf_branch();
        let pre = BTreeMap::from([(SLOT, U256::from(7u64)), (SLOT_B, U256::from(8u64))]);
        assert_eq!(root, reference_root(&pre), "fixture trie disagrees with the reference");

        for first_nibble in [0x0u8, 0x3, 0x8, 0xF] {
            let mut bytes = [0x11u8; 32];
            bytes[0] = (first_nibble << 4) | 0x1;
            let slot = B256::from(bytes);
            let mut post = pre.clone();
            post.insert(slot, U256::from(9u64));
            run(root, state.clone(), Some(reference_root(&post)), &[(slot, U256::from(9u64))])
                .unwrap_or_else(|e| panic!("insert at first nibble {first_nibble:#x}: {e:?}"));
        }
    }

    /// An extension always consumes at least one nibble; an empty key is no trie's shape and
    /// is refused instead of followed (a chain of them would recurse without descending).
    #[test]
    fn extension_with_empty_key_is_rejected() {
        let leaf = leaf_node(Nibbles::unpack(SLOT), 7);
        let ext = TrieNode::Extension(ExtensionNode::new(Nibbles::default(), rlp_of(&leaf)));
        let ext_rlp = encoded(&ext);
        let root = keccak256(&ext_rlp);
        match run(root, vec![ext_rlp, encoded(&leaf)], Some(root), &[]) {
            Err(TrieOperationFailed(msg)) if msg.contains("empty key") => {}
            other => panic!("expected the empty-key rejection, got {other:?}"),
        }
    }

    /// A leaf must end exactly at the 64-nibble key depth: anything shorter would make the
    /// emitted key set non-prefix-free, which `HashBuilder` does not guard against.
    #[test]
    fn leaf_not_ending_at_key_depth_is_rejected() {
        let short = encoded(&leaf_node(Nibbles::unpack(SLOT).slice(1..), 7));
        let root = keccak256(&short);
        match run(root, vec![short], Some(root), &[]) {
            Err(TrieOperationFailed(msg)) if msg.contains("key depth") => {}
            other => panic!("expected the key-depth rejection, got {other:?}"),
        }
    }

    /// A path that would outgrow a storage-trie key is refused before any `Nibbles` is
    /// built past its 64-nibble capacity: here a full-length leaf key hangs under a branch.
    #[test]
    fn path_past_the_key_length_is_rejected() {
        let too_long = leaf_node(Nibbles::unpack(SLOT), 7);
        let other = leaf_node(Nibbles::unpack(SLOT_B).slice(1..), 8);
        let branch = TrieNode::Branch(BranchNode::new(
            vec![rlp_of(&too_long), rlp_of(&other)],
            0b0110.into(),
        ));
        let branch_rlp = encoded(&branch);
        let root = keccak256(&branch_rlp);
        let state = vec![branch_rlp, encoded(&too_long), encoded(&other)];
        match run(root, state, Some(root), &[]) {
            Err(TrieOperationFailed(msg)) if msg.contains("past the 64-nibble key length") => {}
            other => panic!("expected the path-length rejection, got {other:?}"),
        }
    }

    /// xorshift64*: a fixed seed keeps the differential run deterministic, and the failing
    /// case index in an assertion message pinpoints a reproduction.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn slot(&mut self) -> B256 {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_be_bytes());
            }
            B256::from(bytes)
        }

        /// A slot sharing a random-length nibble prefix with `base`, so the tries grow
        /// extensions and branches instead of a flat fan-out.
        fn near(&mut self, base: &B256) -> B256 {
            let keep = self.below(KEY_NIBBLES);
            let fresh = Nibbles::unpack(self.slot());
            let base = Nibbles::unpack(base);
            let mut bytes = [0u8; 32];
            for (i, byte) in bytes.iter_mut().enumerate() {
                let nibble = |k: usize| {
                    if k < keep { base.get_unchecked(k) } else { fresh.get_unchecked(k) }
                };
                *byte = (nibble(2 * i) << 4) | nibble(2 * i + 1);
            }
            B256::from(bytes)
        }

        fn value(&mut self) -> U256 {
            if self.below(4) == 0 {
                U256::from_limbs([self.next() | 1, self.next(), self.next(), self.next()])
            } else {
                U256::from(1 + self.below(1000) as u64)
            }
        }

        fn pick(&mut self, state: &BTreeMap<B256, U256>) -> Option<B256> {
            (!state.is_empty()).then(|| *state.keys().nth(self.below(state.len())).unwrap())
        }
    }

    /// Differential test: random storage trie, reference roots from a `HashBuilder` over the
    /// full pre- and post-state, a minimal (sometimes partial or padded) witness, a random mix
    /// of inserts, overwrites, removals and removals of absent slots. Verification must either
    /// reproduce the reference post root or fail closed with `TrieOperationFailed` — never a
    /// root mismatch, which would be a plausible-but-wrong linearization.
    ///
    /// Two cases must not fail closed: a witness covering every key, and a minimal witness
    /// when no update removes an existing slot (only a removal can collapse a branch onto a
    /// sibling the exclusion proof leaves out).
    #[test]
    fn linearization_matches_hash_builder_reference() {
        const CASES: usize = 6000;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let (mut verified, mut failed_closed) = (0usize, 0usize);

        for case in 0..CASES {
            let mut pre = BTreeMap::new();
            for _ in 0..rng.below(26) {
                let slot = match rng.pick(&pre) {
                    Some(base) if rng.below(4) != 0 => rng.near(&base),
                    _ => rng.slot(),
                };
                pre.insert(slot, rng.value());
            }

            let mut updates = BTreeMap::new();
            for _ in 0..rng.below(7) {
                let slot = match rng.pick(&pre) {
                    Some(base) => match rng.below(3) {
                        0 => base,
                        1 => rng.near(&base),
                        _ => rng.slot(),
                    },
                    None => rng.slot(),
                };
                let value = if rng.below(2) == 0 { U256::ZERO } else { rng.value() };
                updates.insert(slot, value);
            }
            let removes_existing =
                updates.iter().any(|(slot, value)| value.is_zero() && pre.contains_key(slot));

            let mut post = pre.clone();
            for (slot, value) in &updates {
                if value.is_zero() {
                    post.remove(slot);
                } else {
                    post.insert(*slot, *value);
                }
            }

            let update_slots: Vec<B256> = updates.keys().copied().collect();
            let mode = rng.below(5);
            let targets: Vec<B256> = match mode {
                // Every key witnessed.
                0 => pre.keys().chain(updates.keys()).copied().collect(),
                // Partial: each update's proof kept with probability 1/2.
                3 => update_slots.iter().copied().filter(|_| rng.below(2) == 0).collect(),
                // Padded with proofs for existing slots the updates do not touch.
                4 => update_slots.iter().copied().chain(rng.pick(&pre)).collect(),
                // Minimal: exactly the updated slots.
                _ => update_slots.clone(),
            };
            let (root, witness) = minimal_witness(&pre, &targets);
            assert_eq!(root, reference_root(&pre), "case {case}: reference pre root");

            let update_list: Vec<(B256, U256)> = updates.into_iter().collect();
            let result = run(root, witness, Some(reference_root(&post)), &update_list);
            let describe = || {
                format!(
                    "case {case}, mode {mode}: {} pre slots, updates {update_list:?}",
                    pre.len()
                )
            };

            match &result {
                Ok(()) => verified += 1,
                Err(TrieOperationFailed(_)) => {
                    failed_closed += 1;
                    assert_ne!(mode, 0, "a full witness must verify ({})", describe());
                    assert!(
                        removes_existing || mode == 3,
                        "a minimal witness without removals must verify ({}): {result:?}",
                        describe()
                    );
                }
                Err(other) => panic!("wrong root accepted-or-rejected ({}): {other:?}", describe()),
            }
        }

        // The run must exercise both outcomes, or the generator has gone vacuous.
        assert!(verified > CASES / 2, "only {verified}/{CASES} cases verified");
        assert!(failed_closed > 0, "no case exercised the fail-closed path");
    }
}
