//! Vendored from reth v1.6.0 (commit d8451e54e, crates/trie/sparse/src/trie.rs (non-test portion)),
//! trimmed to the serial sparse trie needed by withdrawal MPT witness verification.
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

use alloc::{
    borrow::Cow,
    boxed::Box,
    fmt,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use alloy_primitives::{
    B256, hex, keccak256,
    map::{Entry, HashMap, HashSet},
};
use alloy_rlp::Decodable;
use reth_trie_common::{
    BranchNodeCompact, BranchNodeRef, CHILD_INDEX_RANGE, EMPTY_ROOT_HASH, ExtensionNodeRef,
    LeafNodeRef, Nibbles, RlpNode, TrieMask, TrieNode,
    prefix_set::{PrefixSet, PrefixSetMut},
};
use smallvec::SmallVec;
use tracing::trace;

use super::{
    LeafLookup, LeafLookupError, RevealedSparseNode, SparseTrieErrorKind, SparseTrieInterface,
    SparseTrieResult, SparseTrieUpdates, TrieMasks,
    provider::{RevealedNode, TrieNodeProvider},
};

/// The level below which the sparse trie hashes are calculated in
/// [`SerialSparseTrie::update_subtrie_hashes`].
const SPARSE_TRIE_SUBTRIE_HASHES_LEVEL: usize = 2;

/// A sparse trie that is either in a "blind" state (no nodes are revealed, root node hash is
/// unknown) or in a "revealed" state (root node has been revealed and the trie can be updated).
///
/// In blind mode the trie does not contain any decoded node data, which saves memory but
/// prevents direct access to node contents. The revealed mode stores decoded nodes along
/// with additional information such as values, allowing direct manipulation.
///
/// The sparse trie design is optimised for:
/// 1. Memory efficiency - only revealed nodes are loaded into memory
/// 2. Update tracking - changes to the trie structure can be tracked and selectively persisted
/// 3. Incremental operations - nodes can be revealed as needed without loading the entire trie.
///    This is what gives rise to the notion of a "sparse" trie.
#[derive(PartialEq, Eq, Debug)]
pub enum SparseTrie<T = SerialSparseTrie> {
    /// The trie is blind -- no nodes have been revealed
    ///
    /// This is the default state. In this state, the trie cannot be directly queried or modified
    /// until nodes are revealed.
    ///
    /// In this state the `SparseTrie` can optionally carry with it a cleared `SerialSparseTrie`.
    /// This allows for reusing the trie's allocations between payload executions.
    Blind(Option<Box<T>>),
    /// Some nodes in the Trie have been revealed.
    ///
    /// In this state, the trie can be queried and modified for the parts
    /// that have been revealed. Other parts remain blind and require revealing
    /// before they can be accessed.
    Revealed(Box<T>),
}

impl<T: Default> Default for SparseTrie<T> {
    fn default() -> Self {
        Self::Blind(None)
    }
}

impl<T: SparseTrieInterface + Default> SparseTrie<T> {
    /// Creates a new revealed but empty sparse trie with `SparseNode::Empty` as root node.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use reth_trie_sparse::{provider::DefaultTrieNodeProvider, SerialSparseTrie, SparseTrie};
    ///
    /// let trie = SparseTrie::<SerialSparseTrie>::revealed_empty();
    /// assert!(!trie.is_blind());
    /// ```
    pub fn revealed_empty() -> Self {
        Self::Revealed(Box::default())
    }

    /// Reveals the root node, converting a blind trie into a revealed one.
    ///
    /// If the trie is blinded, its root node is replaced with `root`.
    ///
    /// The `masks` are used to determine how the node's children are stored.
    /// The `retain_updates` flag controls whether changes to the trie structure
    /// should be tracked.
    ///
    /// # Returns
    ///
    /// A mutable reference to the underlying [`SparseTrieInterface`].
    pub fn reveal_root(
        &mut self,
        root: TrieNode,
        masks: TrieMasks,
        retain_updates: bool,
    ) -> SparseTrieResult<&mut T> {
        // if `Blind`, we initialize the revealed trie with the given root node, using a
        // pre-allocated trie if available.
        if self.is_blind() {
            let mut revealed_trie = if let Self::Blind(Some(cleared_trie)) = core::mem::take(self) {
                cleared_trie
            } else {
                Box::default()
            };

            *revealed_trie = revealed_trie.with_root(root, masks, retain_updates)?;
            *self = Self::Revealed(revealed_trie);
        }

        Ok(self.as_revealed_mut().unwrap())
    }
}

impl<T: SparseTrieInterface> SparseTrie<T> {
    /// Creates a new blind sparse trie.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use reth_trie_sparse::{provider::DefaultTrieNodeProvider, SerialSparseTrie, SparseTrie};
    ///
    /// let trie = SparseTrie::<SerialSparseTrie>::blind();
    /// assert!(trie.is_blind());
    /// let trie = SparseTrie::<SerialSparseTrie>::default();
    /// assert!(trie.is_blind());
    /// ```
    pub const fn blind() -> Self {
        Self::Blind(None)
    }

    /// Returns `true` if the sparse trie has no revealed nodes.
    pub const fn is_blind(&self) -> bool {
        matches!(self, Self::Blind(_))
    }

    /// Returns `true` if the sparse trie is revealed.
    pub const fn is_revealed(&self) -> bool {
        matches!(self, Self::Revealed(_))
    }

    /// Returns an immutable reference to the underlying revealed sparse trie.
    ///
    /// Returns `None` if the trie is blinded.
    pub const fn as_revealed_ref(&self) -> Option<&T> {
        if let Self::Revealed(revealed) = self { Some(revealed) } else { None }
    }

    /// Returns a mutable reference to the underlying revealed sparse trie.
    ///
    /// Returns `None` if the trie is blinded.
    pub fn as_revealed_mut(&mut self) -> Option<&mut T> {
        if let Self::Revealed(revealed) = self { Some(revealed) } else { None }
    }

    /// Wipes the trie by removing all nodes and values,
    /// and resetting the trie to only contain an empty root node.
    ///
    /// Note: This method will error if the trie is blinded.
    pub fn wipe(&mut self) -> SparseTrieResult<()> {
        let revealed = self.as_revealed_mut().ok_or(SparseTrieErrorKind::Blind)?;
        revealed.wipe();
        Ok(())
    }

    /// Calculates the root hash of the trie.
    ///
    /// This will update any remaining dirty nodes before computing the root hash.
    /// "dirty" nodes are nodes that need their hashes to be recomputed because one or more of their
    /// children's hashes have changed.
    ///
    /// # Returns
    ///
    /// - `Some(B256)` with the calculated root hash if the trie is revealed.
    /// - `None` if the trie is still blind.
    pub fn root(&mut self) -> Option<B256> {
        Some(self.as_revealed_mut()?.root())
    }

    /// Returns the root hash along with any accumulated update information.
    ///
    /// This is useful for when you need both the root hash and information about
    /// what nodes were modified, which can be used to efficiently update
    /// an external database.
    ///
    /// # Returns
    ///
    /// An `Option` tuple consisting of:
    ///  - The trie root hash (`B256`).
    ///  - A [`SparseTrieUpdates`] structure containing information about updated nodes.
    ///  - `None` if the trie is still blind.
    pub fn root_with_updates(&mut self) -> Option<(B256, SparseTrieUpdates)> {
        let revealed = self.as_revealed_mut()?;
        Some((revealed.root(), revealed.take_updates()))
    }

    /// Returns a [`SparseTrie::Blind`] based on this one. If this instance was revealed, or was
    /// itself a `Blind` with a pre-allocated [`SparseTrieInterface`], this will return
    /// a `Blind` carrying a cleared pre-allocated [`SparseTrieInterface`].
    pub fn clear(self) -> Self {
        match self {
            Self::Blind(_) => self,
            Self::Revealed(mut trie) => {
                trie.clear();
                Self::Blind(Some(trie))
            }
        }
    }

    /// Updates (or inserts) a leaf at the given key path with the specified RLP-encoded value.
    ///
    /// # Errors
    ///
    /// Returns an error if the trie is still blind, or if the update fails.
    pub fn update_leaf(
        &mut self,
        path: Nibbles,
        value: Vec<u8>,
        provider: impl TrieNodeProvider,
    ) -> SparseTrieResult<()> {
        let revealed = self.as_revealed_mut().ok_or(SparseTrieErrorKind::Blind)?;
        revealed.update_leaf(path, value, provider)?;
        Ok(())
    }

    /// Removes a leaf node at the specified key path.
    ///
    /// # Errors
    ///
    /// Returns an error if the trie is still blind, or if the leaf cannot be removed
    pub fn remove_leaf(
        &mut self,
        path: &Nibbles,
        provider: impl TrieNodeProvider,
    ) -> SparseTrieResult<()> {
        let revealed = self.as_revealed_mut().ok_or(SparseTrieErrorKind::Blind)?;
        revealed.remove_leaf(path, provider)?;
        Ok(())
    }
}

/// The representation of revealed sparse trie.
///
/// The revealed sparse trie contains the actual trie structure with nodes, values, and
/// tracking for changes. It supports operations like inserting, updating, and removing
/// nodes.
///
///
/// ## Invariants
///
/// - The root node is always present in `nodes` collection.
/// - Each leaf entry in `nodes` collection must have a corresponding entry in `values` collection.
///   The opposite is also true.
/// - All keys in `values` collection are full leaf paths.
#[derive(Clone, PartialEq, Eq)]
pub struct SerialSparseTrie {
    /// Map from a path (nibbles) to its corresponding sparse trie node.
    /// This contains all of the revealed nodes in trie.
    nodes: HashMap<Nibbles, SparseNode>,
    /// When a branch is set, the corresponding child subtree is stored in the database.
    branch_node_tree_masks: HashMap<Nibbles, TrieMask>,
    /// When a bit is set, the corresponding child is stored as a hash in the database.
    branch_node_hash_masks: HashMap<Nibbles, TrieMask>,
    /// Map from leaf key paths to their values.
    /// All values are stored here instead of directly in leaf nodes.
    values: HashMap<Nibbles, Vec<u8>>,
    /// Set of prefixes (key paths) that have been marked as updated.
    /// This is used to track which parts of the trie need to be recalculated.
    prefix_set: PrefixSetMut,
    /// Optional tracking of trie updates for later use.
    updates: Option<SparseTrieUpdates>,
    /// Reusable buffer for RLP encoding of nodes.
    rlp_buf: Vec<u8>,
}

impl fmt::Debug for SerialSparseTrie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerialSparseTrie")
            .field("nodes", &self.nodes)
            .field("branch_tree_masks", &self.branch_node_tree_masks)
            .field("branch_hash_masks", &self.branch_node_hash_masks)
            .field("values", &self.values)
            .field("prefix_set", &self.prefix_set)
            .field("updates", &self.updates)
            .field("rlp_buf", &hex::encode(&self.rlp_buf))
            .finish_non_exhaustive()
    }
}

/// Turns a [`Nibbles`] into a [`String`] by concatenating each nibbles' hex character.
fn encode_nibbles(nibbles: &Nibbles) -> String {
    let encoded = hex::encode(nibbles.pack());
    encoded[..nibbles.len()].to_string()
}

impl fmt::Display for SerialSparseTrie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This prints the trie in preorder traversal, using a stack
        let mut stack = Vec::new();
        let mut visited = HashSet::new();

        // 4 spaces as indent per level
        const INDENT: &str = "    ";

        // Track both path and depth
        stack.push((Nibbles::default(), self.nodes_ref().get(&Nibbles::default()).unwrap(), 0));

        while let Some((path, node, depth)) = stack.pop() {
            if !visited.insert(path) {
                continue;
            }

            // Add indentation if alternate flag (#) is set
            if f.alternate() {
                write!(f, "{}", INDENT.repeat(depth))?;
            }

            let packed_path = if depth == 0 { String::from("Root") } else { encode_nibbles(&path) };

            match node {
                SparseNode::Empty | SparseNode::Hash(_) => {
                    writeln!(f, "{packed_path} -> {node:?}")?;
                }
                SparseNode::Leaf { key, .. } => {
                    // we want to append the key to the path
                    let mut full_path = path;
                    full_path.extend(key);
                    let packed_path = encode_nibbles(&full_path);

                    writeln!(f, "{packed_path} -> {node:?}")?;
                }
                SparseNode::Extension { key, .. } => {
                    writeln!(f, "{packed_path} -> {node:?}")?;

                    // push the child node onto the stack with increased depth
                    let mut child_path = path;
                    child_path.extend(key);
                    if let Some(child_node) = self.nodes_ref().get(&child_path) {
                        stack.push((child_path, child_node, depth + 1));
                    }
                }
                SparseNode::Branch { state_mask, .. } => {
                    writeln!(f, "{packed_path} -> {node:?}")?;

                    for i in CHILD_INDEX_RANGE.rev() {
                        if state_mask.is_bit_set(i) {
                            let mut child_path = path;
                            child_path.push_unchecked(i);
                            if let Some(child_node) = self.nodes_ref().get(&child_path) {
                                stack.push((child_path, child_node, depth + 1));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for SerialSparseTrie {
    fn default() -> Self {
        Self {
            nodes: HashMap::from_iter([(Nibbles::default(), SparseNode::Empty)]),
            branch_node_tree_masks: HashMap::default(),
            branch_node_hash_masks: HashMap::default(),
            values: HashMap::default(),
            prefix_set: PrefixSetMut::default(),
            updates: None,
            rlp_buf: Vec::new(),
        }
    }
}

impl SparseTrieInterface for SerialSparseTrie {
    fn with_root(
        mut self,
        root: TrieNode,
        masks: TrieMasks,
        retain_updates: bool,
    ) -> SparseTrieResult<Self> {
        self = self.with_updates(retain_updates);

        // A fresh/cleared `SerialSparseTrie` has a `SparseNode::Empty` at its root. Delete that
        // so we can reveal the new root node.
        let path = Nibbles::default();
        let _removed_root = self.nodes.remove(&path).expect("root node should exist");
        debug_assert_eq!(_removed_root, SparseNode::Empty);

        self.reveal_node(path, root, masks)?;
        Ok(self)
    }

    fn with_updates(mut self, retain_updates: bool) -> Self {
        if retain_updates {
            self.updates = Some(SparseTrieUpdates::default());
        }
        self
    }

    fn reserve_nodes(&mut self, additional: usize) {
        self.nodes.reserve(additional);
    }
    fn reveal_node(
        &mut self,
        path: Nibbles,
        node: TrieNode,
        masks: TrieMasks,
    ) -> SparseTrieResult<()> {
        // If the node is already revealed and it's not a hash node, do nothing.
        if self.nodes.get(&path).is_some_and(|node| !node.is_hash()) {
            return Ok(())
        }

        if let Some(tree_mask) = masks.tree_mask {
            self.branch_node_tree_masks.insert(path, tree_mask);
        }
        if let Some(hash_mask) = masks.hash_mask {
            self.branch_node_hash_masks.insert(path, hash_mask);
        }

        match node {
            TrieNode::EmptyRoot => {
                // For an empty root, ensure that we are at the root path.
                debug_assert!(path.is_empty());
                self.nodes.insert(path, SparseNode::Empty);
            }
            TrieNode::Branch(branch) => {
                // For a branch node, iterate over all potential children
                let mut stack_ptr = branch.as_ref().first_child_index();
                for idx in CHILD_INDEX_RANGE {
                    if branch.state_mask.is_bit_set(idx) {
                        let mut child_path = path;
                        child_path.push_unchecked(idx);
                        // Reveal each child node or hash it has
                        self.reveal_node_or_hash(child_path, &branch.stack[stack_ptr])?;
                        stack_ptr += 1;
                    }
                }
                // Update the branch node entry in the nodes map, handling cases where a blinded
                // node is now replaced with a revealed node.
                match self.nodes.entry(path) {
                    Entry::Occupied(mut entry) => match entry.get() {
                        // Replace a hash node with a fully revealed branch node.
                        SparseNode::Hash(hash) => {
                            entry.insert(SparseNode::Branch {
                                state_mask: branch.state_mask,
                                // Memoize the hash of a previously blinded node in a new branch
                                // node.
                                hash: Some(*hash),
                                store_in_db_trie: Some(
                                    masks.hash_mask.is_some_and(|mask| !mask.is_empty()) ||
                                        masks.tree_mask.is_some_and(|mask| !mask.is_empty()),
                                ),
                            });
                        }
                        // Branch node already exists, or an extension node was placed where a
                        // branch node was before.
                        SparseNode::Branch { .. } | SparseNode::Extension { .. } => {}
                        // All other node types can't be handled.
                        node @ (SparseNode::Empty | SparseNode::Leaf { .. }) => {
                            return Err(SparseTrieErrorKind::Reveal {
                                path: *entry.key(),
                                node: Box::new(node.clone()),
                            }
                            .into())
                        }
                    },
                    Entry::Vacant(entry) => {
                        entry.insert(SparseNode::new_branch(branch.state_mask));
                    }
                }
            }
            TrieNode::Extension(ext) => match self.nodes.entry(path) {
                Entry::Occupied(mut entry) => match entry.get() {
                    // Replace a hash node with a revealed extension node.
                    SparseNode::Hash(hash) => {
                        let mut child_path = *entry.key();
                        child_path.extend(&ext.key);
                        entry.insert(SparseNode::Extension {
                            key: ext.key,
                            // Memoize the hash of a previously blinded node in a new extension
                            // node.
                            hash: Some(*hash),
                            store_in_db_trie: None,
                        });
                        self.reveal_node_or_hash(child_path, &ext.child)?;
                    }
                    // Extension node already exists, or an extension node was placed where a branch
                    // node was before.
                    SparseNode::Extension { .. } | SparseNode::Branch { .. } => {}
                    // All other node types can't be handled.
                    node @ (SparseNode::Empty | SparseNode::Leaf { .. }) => {
                        return Err(SparseTrieErrorKind::Reveal {
                            path: *entry.key(),
                            node: Box::new(node.clone()),
                        }
                        .into())
                    }
                },
                Entry::Vacant(entry) => {
                    let mut child_path = *entry.key();
                    child_path.extend(&ext.key);
                    entry.insert(SparseNode::new_ext(ext.key));
                    self.reveal_node_or_hash(child_path, &ext.child)?;
                }
            },
            TrieNode::Leaf(leaf) => match self.nodes.entry(path) {
                Entry::Occupied(mut entry) => match entry.get() {
                    // Replace a hash node with a revealed leaf node and store leaf node value.
                    SparseNode::Hash(hash) => {
                        let mut full = *entry.key();
                        full.extend(&leaf.key);
                        self.values.insert(full, leaf.value.clone());
                        entry.insert(SparseNode::Leaf {
                            key: leaf.key,
                            // Memoize the hash of a previously blinded node in a new leaf
                            // node.
                            hash: Some(*hash),
                        });
                    }
                    // Left node already exists.
                    SparseNode::Leaf { .. } => {}
                    // All other node types can't be handled.
                    node @ (SparseNode::Empty |
                    SparseNode::Extension { .. } |
                    SparseNode::Branch { .. }) => {
                        return Err(SparseTrieErrorKind::Reveal {
                            path: *entry.key(),
                            node: Box::new(node.clone()),
                        }
                        .into())
                    }
                },
                Entry::Vacant(entry) => {
                    let mut full = *entry.key();
                    full.extend(&leaf.key);
                    entry.insert(SparseNode::new_leaf(leaf.key));
                    self.values.insert(full, leaf.value.clone());
                }
            },
        }

        Ok(())
    }

    fn reveal_nodes(&mut self, mut nodes: Vec<RevealedSparseNode>) -> SparseTrieResult<()> {
        nodes.sort_unstable_by_key(|node| node.path);
        for node in nodes {
            self.reveal_node(node.path, node.node, node.masks)?;
        }
        Ok(())
    }

    fn update_leaf<P: TrieNodeProvider>(
        &mut self,
        full_path: Nibbles,
        value: Vec<u8>,
        provider: P,
    ) -> SparseTrieResult<()> {
        self.prefix_set.insert(full_path);
        let existing = self.values.insert(full_path, value);
        if existing.is_some() {
            // trie structure unchanged, return immediately
            return Ok(())
        }

        let mut current = Nibbles::default();
        while let Some(node) = self.nodes.get_mut(&current) {
            match node {
                SparseNode::Empty => {
                    *node = SparseNode::new_leaf(full_path);
                    break
                }
                &mut SparseNode::Hash(hash) => {
                    return Err(SparseTrieErrorKind::BlindedNode { path: current, hash }.into())
                }
                SparseNode::Leaf { key: current_key, .. } => {
                    current.extend(current_key);

                    // this leaf is being updated
                    if current == full_path {
                        unreachable!("we already checked leaf presence in the beginning");
                    }

                    // find the common prefix
                    let common = current.common_prefix_length(&full_path);

                    // update existing node
                    let new_ext_key = current.slice(current.len() - current_key.len()..common);
                    *node = SparseNode::new_ext(new_ext_key);

                    // create a branch node and corresponding leaves
                    self.nodes.reserve(3);
                    self.nodes.insert(
                        current.slice(..common),
                        SparseNode::new_split_branch(
                            current.get_unchecked(common),
                            full_path.get_unchecked(common),
                        ),
                    );
                    self.nodes.insert(
                        full_path.slice(..=common),
                        SparseNode::new_leaf(full_path.slice(common + 1..)),
                    );
                    self.nodes.insert(
                        current.slice(..=common),
                        SparseNode::new_leaf(current.slice(common + 1..)),
                    );

                    break;
                }
                SparseNode::Extension { key, .. } => {
                    current.extend(key);

                    if !full_path.starts_with(&current) {
                        // find the common prefix
                        let common = current.common_prefix_length(&full_path);
                        *key = current.slice(current.len() - key.len()..common);

                        // If branch node updates retention is enabled, we need to query the
                        // extension node child to later set the hash mask for a parent branch node
                        // correctly.
                        if self.updates.is_some() {
                            // Check if the extension node child is a hash that needs to be revealed
                            if self.nodes.get(&current).unwrap().is_hash() {
                                if let Some(RevealedNode { node, tree_mask, hash_mask }) =
                                    provider.trie_node(&current)?
                                {
                                    let decoded = TrieNode::decode(&mut &node[..])?;
                                    trace!(
                                        target: "trie::sparse",
                                        ?current,
                                        ?decoded,
                                        ?tree_mask,
                                        ?hash_mask,
                                        "Revealing extension node child",
                                    );
                                    self.reveal_node(
                                        current,
                                        decoded,
                                        TrieMasks { hash_mask, tree_mask },
                                    )?;
                                }
                            }
                        }

                        // create state mask for new branch node
                        // NOTE: this might overwrite the current extension node
                        self.nodes.reserve(3);
                        let branch = SparseNode::new_split_branch(
                            current.get_unchecked(common),
                            full_path.get_unchecked(common),
                        );
                        self.nodes.insert(current.slice(..common), branch);

                        // create new leaf
                        let new_leaf = SparseNode::new_leaf(full_path.slice(common + 1..));
                        self.nodes.insert(full_path.slice(..=common), new_leaf);

                        // recreate extension to previous child if needed
                        let key = current.slice(common + 1..);
                        if !key.is_empty() {
                            self.nodes.insert(current.slice(..=common), SparseNode::new_ext(key));
                        }

                        break;
                    }
                }
                SparseNode::Branch { state_mask, .. } => {
                    let nibble = full_path.get_unchecked(current.len());
                    current.push_unchecked(nibble);
                    if !state_mask.is_bit_set(nibble) {
                        state_mask.set_bit(nibble);
                        let new_leaf = SparseNode::new_leaf(full_path.slice(current.len()..));
                        self.nodes.insert(current, new_leaf);
                        break;
                    }
                }
            };
        }

        Ok(())
    }

    fn remove_leaf<P: TrieNodeProvider>(
        &mut self,
        full_path: &Nibbles,
        provider: P,
    ) -> SparseTrieResult<()> {
        if self.values.remove(full_path).is_none() {
            if let Some(&SparseNode::Hash(hash)) = self.nodes.get(full_path) {
                // Leaf is present in the trie, but it's blinded.
                return Err(SparseTrieErrorKind::BlindedNode { path: *full_path, hash }.into())
            }

            trace!(target: "trie::sparse", ?full_path, "Leaf node is not present in the trie");
            // Leaf is not present in the trie.
            return Ok(())
        }
        self.prefix_set.insert(*full_path);

        // If the path wasn't present in `values`, we still need to walk the trie and ensure that
        // there is no node at the path. When a leaf node is a blinded `Hash`, it will have an entry
        // in `nodes`, but not in the `values`.

        let mut removed_nodes = self.take_nodes_for_path(full_path)?;
        // Pop the first node from the stack which is the leaf node we want to remove.
        let mut child = removed_nodes.pop().expect("leaf exists");
        #[cfg(debug_assertions)]
        {
            let mut child_path = child.path;
            let SparseNode::Leaf { key, .. } = &child.node else { panic!("expected leaf node") };
            child_path.extend(key);
            assert_eq!(&child_path, full_path);
        }

        // If we don't have any other removed nodes, insert an empty node at the root.
        if removed_nodes.is_empty() {
            debug_assert!(self.nodes.is_empty());
            self.nodes.insert(Nibbles::default(), SparseNode::Empty);

            return Ok(())
        }

        // Walk the stack of removed nodes from the back and re-insert them back into the trie,
        // adjusting the node type as needed.
        while let Some(removed_node) = removed_nodes.pop() {
            let removed_path = removed_node.path;

            let new_node = match &removed_node.node {
                SparseNode::Empty => return Err(SparseTrieErrorKind::Blind.into()),
                &SparseNode::Hash(hash) => {
                    return Err(SparseTrieErrorKind::BlindedNode { path: removed_path, hash }.into())
                }
                SparseNode::Leaf { .. } => {
                    unreachable!("we already popped the leaf node")
                }
                SparseNode::Extension { key, .. } => {
                    // If the node is an extension node, we need to look at its child to see if we
                    // need to merge them.
                    match &child.node {
                        SparseNode::Empty => return Err(SparseTrieErrorKind::Blind.into()),
                        &SparseNode::Hash(hash) => {
                            return Err(
                                SparseTrieErrorKind::BlindedNode { path: child.path, hash }.into()
                            )
                        }
                        // For a leaf node, we collapse the extension node into a leaf node,
                        // extending the key. While it's impossible to encounter an extension node
                        // followed by a leaf node in a complete trie, it's possible here because we
                        // could have downgraded the extension node's child into a leaf node from
                        // another node type.
                        SparseNode::Leaf { key: leaf_key, .. } => {
                            self.nodes.remove(&child.path);

                            let mut new_key = *key;
                            new_key.extend(leaf_key);
                            SparseNode::new_leaf(new_key)
                        }
                        // For an extension node, we collapse them into one extension node,
                        // extending the key
                        SparseNode::Extension { key: extension_key, .. } => {
                            self.nodes.remove(&child.path);

                            let mut new_key = *key;
                            new_key.extend(extension_key);
                            SparseNode::new_ext(new_key)
                        }
                        // For a branch node, we just leave the extension node as-is.
                        SparseNode::Branch { .. } => removed_node.node,
                    }
                }
                &SparseNode::Branch { mut state_mask, hash: _, store_in_db_trie: _ } => {
                    // If the node is a branch node, we need to check the number of children left
                    // after deleting the child at the given nibble.

                    if let Some(removed_nibble) = removed_node.unset_branch_nibble {
                        state_mask.unset_bit(removed_nibble);
                    }

                    // If only one child is left set in the branch node, we need to collapse it.
                    if state_mask.count_bits() == 1 {
                        let child_nibble =
                            state_mask.first_set_bit_index().expect("state mask is not empty");

                        // Get full path of the only child node left.
                        let mut child_path = removed_path;
                        child_path.push_unchecked(child_nibble);

                        trace!(target: "trie::sparse", ?removed_path, ?child_path, "Branch node has only one child");

                        if self.nodes.get(&child_path).unwrap().is_hash() {
                            trace!(target: "trie::sparse", ?child_path, "Retrieving remaining blinded branch child");
                            if let Some(RevealedNode { node, tree_mask, hash_mask }) =
                                provider.trie_node(&child_path)?
                            {
                                let decoded = TrieNode::decode(&mut &node[..])?;
                                trace!(
                                    target: "trie::sparse",
                                    ?child_path,
                                    ?decoded,
                                    ?tree_mask,
                                    ?hash_mask,
                                    "Revealing remaining blinded branch child"
                                );
                                self.reveal_node(
                                    child_path,
                                    decoded,
                                    TrieMasks { hash_mask, tree_mask },
                                )?;
                            }
                        }

                        // Get the only child node.
                        let child = self.nodes.get(&child_path).unwrap();

                        let mut delete_child = false;
                        let new_node = match child {
                            SparseNode::Empty => return Err(SparseTrieErrorKind::Blind.into()),
                            &SparseNode::Hash(hash) => {
                                return Err(SparseTrieErrorKind::BlindedNode {
                                    path: child_path,
                                    hash,
                                }
                                .into())
                            }
                            // If the only child is a leaf node, we downgrade the branch node into a
                            // leaf node, prepending the nibble to the key, and delete the old
                            // child.
                            SparseNode::Leaf { key, .. } => {
                                delete_child = true;

                                let mut new_key = Nibbles::from_nibbles_unchecked([child_nibble]);
                                new_key.extend(key);
                                SparseNode::new_leaf(new_key)
                            }
                            // If the only child node is an extension node, we downgrade the branch
                            // node into an even longer extension node, prepending the nibble to the
                            // key, and delete the old child.
                            SparseNode::Extension { key, .. } => {
                                delete_child = true;

                                let mut new_key = Nibbles::from_nibbles_unchecked([child_nibble]);
                                new_key.extend(key);
                                SparseNode::new_ext(new_key)
                            }
                            // If the only child is a branch node, we downgrade the current branch
                            // node into a one-nibble extension node.
                            SparseNode::Branch { .. } => {
                                SparseNode::new_ext(Nibbles::from_nibbles_unchecked([child_nibble]))
                            }
                        };

                        if delete_child {
                            self.nodes.remove(&child_path);
                        }

                        if let Some(updates) = self.updates.as_mut() {
                            updates.updated_nodes.remove(&removed_path);
                            updates.removed_nodes.insert(removed_path);
                        }

                        new_node
                    }
                    // If more than one child is left set in the branch, we just re-insert it as-is.
                    else {
                        SparseNode::new_branch(state_mask)
                    }
                }
            };

            child = RemovedSparseNode {
                path: removed_path,
                node: new_node.clone(),
                unset_branch_nibble: None,
            };
            trace!(target: "trie::sparse", ?removed_path, ?new_node, "Re-inserting the node");
            self.nodes.insert(removed_path, new_node);
        }

        Ok(())
    }

    fn root(&mut self) -> B256 {
        // Take the current prefix set
        let mut prefix_set = core::mem::take(&mut self.prefix_set).freeze();
        let rlp_node = self.rlp_node_allocate(&mut prefix_set);
        if let Some(root_hash) = rlp_node.as_hash() { root_hash } else { keccak256(rlp_node) }
    }

    fn update_subtrie_hashes(&mut self) {
        self.update_rlp_node_level(SPARSE_TRIE_SUBTRIE_HASHES_LEVEL);
    }

    fn get_leaf_value(&self, full_path: &Nibbles) -> Option<&Vec<u8>> {
        self.values.get(full_path)
    }

    fn updates_ref(&self) -> Cow<'_, SparseTrieUpdates> {
        self.updates.as_ref().map_or(Cow::Owned(SparseTrieUpdates::default()), Cow::Borrowed)
    }

    fn take_updates(&mut self) -> SparseTrieUpdates {
        self.updates.take().unwrap_or_default()
    }

    fn wipe(&mut self) {
        self.nodes = HashMap::from_iter([(Nibbles::default(), SparseNode::Empty)]);
        self.values = HashMap::default();
        self.prefix_set = PrefixSetMut::all();
        self.updates = self.updates.is_some().then(SparseTrieUpdates::wiped);
    }

    fn clear(&mut self) {
        self.nodes.clear();
        self.nodes.insert(Nibbles::default(), SparseNode::Empty);

        self.branch_node_tree_masks.clear();
        self.branch_node_hash_masks.clear();
        self.values.clear();
        self.prefix_set.clear();
        self.updates = None;
        self.rlp_buf.clear();
    }

    fn find_leaf(
        &self,
        full_path: &Nibbles,
        expected_value: Option<&Vec<u8>>,
    ) -> Result<LeafLookup, LeafLookupError> {
        // Helper function to check if a value matches the expected value
        fn check_value_match(
            actual_value: &Vec<u8>,
            expected_value: Option<&Vec<u8>>,
            path: &Nibbles,
        ) -> Result<(), LeafLookupError> {
            if let Some(expected) = expected_value {
                if actual_value != expected {
                    return Err(LeafLookupError::ValueMismatch {
                        path: *path,
                        expected: Some(expected.clone()),
                        actual: actual_value.clone(),
                    });
                }
            }
            Ok(())
        }

        let mut current = Nibbles::default(); // Start at the root

        // Inclusion proof
        //
        // First, do a quick check if the value exists in our values map.
        // We assume that if there exists a leaf node, then its value will
        // be in the `values` map.
        if let Some(actual_value) = self.values.get(full_path) {
            // We found the leaf, check if the value matches (if expected value was provided)
            check_value_match(actual_value, expected_value, full_path)?;
            return Ok(LeafLookup::Exists);
        }

        // If the value does not exist in the `values` map, then this means that the leaf either:
        // - Does not exist in the trie
        // - Is missing from the witness
        // We traverse the trie to find the location where this leaf would have been, showing
        // that it is not in the trie. Or we find a blinded node, showing that the witness is
        // not complete.
        while current.len() < full_path.len() {
            match self.nodes.get(&current) {
                Some(SparseNode::Empty) | None => {
                    // None implies no node is at the current path (even in the full trie)
                    // Empty node means there is a node at this path and it is "Empty"
                    return Ok(LeafLookup::NonExistent);
                }
                Some(&SparseNode::Hash(hash)) => {
                    // We hit a blinded node - cannot determine if leaf exists
                    return Err(LeafLookupError::BlindedNode { path: current, hash });
                }
                Some(SparseNode::Leaf { key, .. }) => {
                    // We found a leaf node before reaching our target depth
                    current.extend(key);
                    if &current == full_path {
                        // This should have been handled by our initial values map check
                        if let Some(value) = self.values.get(full_path) {
                            check_value_match(value, expected_value, full_path)?;
                            return Ok(LeafLookup::Exists);
                        }
                    }

                    // The leaf node's path doesn't match our target path,
                    // providing an exclusion proof
                    return Ok(LeafLookup::NonExistent);
                }
                Some(SparseNode::Extension { key, .. }) => {
                    // Temporarily append the extension key to `current`
                    let saved_len = current.len();
                    current.extend(key);

                    if full_path.len() < current.len() || !full_path.starts_with(&current) {
                        current.truncate(saved_len); // restore
                        return Ok(LeafLookup::NonExistent);
                    }
                    // Prefix matched, so we keep walking with the longer `current`.
                }
                Some(SparseNode::Branch { state_mask, .. }) => {
                    // Check if branch has a child at the next nibble in our path
                    let nibble = full_path.get_unchecked(current.len());
                    if !state_mask.is_bit_set(nibble) {
                        // No child at this nibble - exclusion proof
                        return Ok(LeafLookup::NonExistent);
                    }

                    // Continue down the branch
                    current.push_unchecked(nibble);
                }
            }
        }

        // We've traversed to the end of the path and didn't find a leaf
        // Check if there's a node exactly at our target path
        match self.nodes.get(full_path) {
            Some(SparseNode::Leaf { key, .. }) if key.is_empty() => {
                // We found a leaf with an empty key (exact match)
                // This should be handled by the values map check above
                if let Some(value) = self.values.get(full_path) {
                    check_value_match(value, expected_value, full_path)?;
                    return Ok(LeafLookup::Exists);
                }
            }
            Some(&SparseNode::Hash(hash)) => {
                return Err(LeafLookupError::BlindedNode { path: *full_path, hash });
            }
            _ => {
                // No leaf at exactly the target path
                return Ok(LeafLookup::NonExistent);
            }
        }

        // If we get here, there's no leaf at the target path
        Ok(LeafLookup::NonExistent)
    }
}

impl SerialSparseTrie {
    /// Creates a new revealed sparse trie from the given root node.
    ///
    /// This function initializes the internal structures and then reveals the root.
    /// It is a convenient method to create a trie when you already have the root node available.
    ///
    /// # Arguments
    ///
    /// * `root` - The root node of the trie
    /// * `masks` - Trie masks for root branch node
    /// * `retain_updates` - Whether to track updates
    ///
    /// # Returns
    ///
    /// Self if successful, or an error if revealing fails.
    pub fn from_root(
        root: TrieNode,
        masks: TrieMasks,
        retain_updates: bool,
    ) -> SparseTrieResult<Self> {
        Self::default().with_root(root, masks, retain_updates)
    }

    /// Returns a reference to the current sparse trie updates.
    ///
    /// If no updates have been made/recorded, returns an empty update set.
    pub fn updates_ref(&self) -> Cow<'_, SparseTrieUpdates> {
        self.updates.as_ref().map_or(Cow::Owned(SparseTrieUpdates::default()), Cow::Borrowed)
    }

    /// Returns an immutable reference to all nodes in the sparse trie.
    pub const fn nodes_ref(&self) -> &HashMap<Nibbles, SparseNode> {
        &self.nodes
    }

    /// Reveals either a node or its hash placeholder based on the provided child data.
    ///
    /// When traversing the trie, we often encounter references to child nodes that
    /// are either directly embedded or represented by their hash. This method
    /// handles both cases:
    ///
    /// 1. If the child data represents a hash (32+1=33 bytes), store it as a hash node
    /// 2. Otherwise, decode the data as a [`TrieNode`] and recursively reveal it using
    ///    `reveal_node`
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if successful, or an error if the node cannot be revealed.
    ///
    /// # Error Handling
    ///
    /// Will error if there's a conflict between a new hash node and an existing one
    /// at the same path
    fn reveal_node_or_hash(&mut self, path: Nibbles, child: &[u8]) -> SparseTrieResult<()> {
        if child.len() == B256::len_bytes() + 1 {
            let hash = B256::from_slice(&child[1..]);
            match self.nodes.entry(path) {
                Entry::Occupied(entry) => match entry.get() {
                    // Hash node with a different hash can't be handled.
                    SparseNode::Hash(previous_hash) if previous_hash != &hash => {
                        return Err(SparseTrieErrorKind::Reveal {
                            path: *entry.key(),
                            node: Box::new(SparseNode::Hash(hash)),
                        }
                        .into())
                    }
                    _ => {}
                },
                Entry::Vacant(entry) => {
                    entry.insert(SparseNode::Hash(hash));
                }
            }
            return Ok(())
        }

        self.reveal_node(path, TrieNode::decode(&mut &child[..])?, TrieMasks::none())
    }

    /// Traverse the trie from the root down to the leaf at the given path,
    /// removing and collecting all nodes along that path.
    ///
    /// This helper function is used during leaf removal to extract the nodes of the trie
    /// that will be affected by the deletion. These nodes are then re-inserted and modified
    /// as needed (collapsing extension nodes etc) given that the leaf has now been removed.
    ///
    /// # Returns
    ///
    /// Returns a vector of [`RemovedSparseNode`] representing the nodes removed during the
    /// traversal.
    ///
    /// # Errors
    ///
    /// Returns an error if a blinded node or an empty node is encountered unexpectedly,
    /// as these prevent proper removal of the leaf.
    fn take_nodes_for_path(&mut self, path: &Nibbles) -> SparseTrieResult<Vec<RemovedSparseNode>> {
        let mut current = Nibbles::default(); // Start traversal from the root
        let mut nodes = Vec::new(); // Collect traversed nodes

        while let Some(node) = self.nodes.remove(&current) {
            match &node {
                SparseNode::Empty => return Err(SparseTrieErrorKind::Blind.into()),
                &SparseNode::Hash(hash) => {
                    return Err(SparseTrieErrorKind::BlindedNode { path: current, hash }.into())
                }
                SparseNode::Leaf { key: _key, .. } => {
                    // Leaf node is always the one that we're deleting, and no other leaf nodes can
                    // be found during traversal.

                    #[cfg(debug_assertions)]
                    {
                        let mut current = current;
                        current.extend(_key);
                        assert_eq!(&current, path);
                    }

                    nodes.push(RemovedSparseNode {
                        path: current,
                        node,
                        unset_branch_nibble: None,
                    });
                    break
                }
                SparseNode::Extension { key, .. } => {
                    #[cfg(debug_assertions)]
                    {
                        let mut current = current;
                        current.extend(key);
                        assert!(
                            path.starts_with(&current),
                            "path: {path:?}, current: {current:?}, key: {key:?}",
                        );
                    }

                    let path = current;
                    current.extend(key);
                    nodes.push(RemovedSparseNode { path, node, unset_branch_nibble: None });
                }
                SparseNode::Branch { state_mask, .. } => {
                    let nibble = path.get_unchecked(current.len());
                    debug_assert!(
                        state_mask.is_bit_set(nibble),
                        "current: {current:?}, path: {path:?}, nibble: {nibble:?}, state_mask: {state_mask:?}",
                    );

                    // If the branch node has a child that is a leaf node that we're removing,
                    // we need to unset this nibble.
                    // Any other branch nodes will not require unsetting the nibble, because
                    // deleting one leaf node can not remove the whole path
                    // where the branch node is located.
                    let mut child_path = current;
                    child_path.push_unchecked(nibble);
                    let unset_branch_nibble = self
                        .nodes
                        .get(&child_path)
                        .is_some_and(move |node| match node {
                            SparseNode::Leaf { key, .. } => {
                                // Get full path of the leaf node
                                child_path.extend(key);
                                &child_path == path
                            }
                            _ => false,
                        })
                        .then_some(nibble);

                    nodes.push(RemovedSparseNode { path: current, node, unset_branch_nibble });

                    current.push_unchecked(nibble);
                }
            }
        }

        Ok(nodes)
    }

    /// Recalculates and updates the RLP hashes of nodes deeper than or equal to the specified
    /// `depth`.
    ///
    /// The root node is considered to be at level 0. This method is useful for optimizing
    /// hash recalculations after localized changes to the trie structure:
    ///
    /// This function identifies all nodes that have changed (based on the prefix set) at the given
    /// depth and recalculates their RLP representation.
    pub fn update_rlp_node_level(&mut self, depth: usize) {
        // Take the current prefix set
        let mut prefix_set = core::mem::take(&mut self.prefix_set).freeze();
        let mut buffers = RlpNodeBuffers::default();

        // Get the nodes that have changed at the given depth.
        let (targets, new_prefix_set) = self.get_changed_nodes_at_depth(&mut prefix_set, depth);
        // Update the prefix set to the prefix set of the nodes that still need to be updated.
        self.prefix_set = new_prefix_set;

        trace!(target: "trie::sparse", ?depth, ?targets, "Updating nodes at depth");

        let mut temp_rlp_buf = core::mem::take(&mut self.rlp_buf);
        for (level, path) in targets {
            buffers.path_stack.push(RlpNodePathStackItem {
                level,
                path,
                is_in_prefix_set: Some(true),
            });
            self.rlp_node(&mut prefix_set, &mut buffers, &mut temp_rlp_buf);
        }
        self.rlp_buf = temp_rlp_buf;
    }

    /// Returns a list of (level, path) tuples identifying the nodes that have changed at the
    /// specified depth, along with a new prefix set for the paths above the provided depth that
    /// remain unchanged.
    ///
    /// Leaf nodes with a depth less than `depth` are returned too.
    ///
    /// This method helps optimize hash recalculations by identifying which specific
    /// nodes need to be updated at each level of the trie.
    ///
    /// # Parameters
    ///
    /// - `prefix_set`: The current prefix set tracking which paths need updates.
    /// - `depth`: The minimum depth (relative to the root) to include nodes in the targets.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - A vector of `(level, Nibbles)` pairs for nodes that require updates at or below the
    ///   specified depth.
    /// - A `PrefixSetMut` containing paths shallower than the specified depth that still need to be
    ///   tracked for future updates.
    fn get_changed_nodes_at_depth(
        &self,
        prefix_set: &mut PrefixSet,
        depth: usize,
    ) -> (Vec<(usize, Nibbles)>, PrefixSetMut) {
        let mut unchanged_prefix_set = PrefixSetMut::default();
        let mut paths = Vec::from([(Nibbles::default(), 0)]);
        let mut targets = Vec::new();

        while let Some((mut path, level)) = paths.pop() {
            match self.nodes.get(&path).unwrap() {
                SparseNode::Empty | SparseNode::Hash(_) => {}
                SparseNode::Leaf { key: _, hash } => {
                    if hash.is_some() && !prefix_set.contains(&path) {
                        continue
                    }

                    targets.push((level, path));
                }
                SparseNode::Extension { key, hash, store_in_db_trie: _ } => {
                    if hash.is_some() && !prefix_set.contains(&path) {
                        continue
                    }

                    if level >= depth {
                        targets.push((level, path));
                    } else {
                        unchanged_prefix_set.insert(path);

                        path.extend(key);
                        paths.push((path, level + 1));
                    }
                }
                SparseNode::Branch { state_mask, hash, store_in_db_trie: _ } => {
                    if hash.is_some() && !prefix_set.contains(&path) {
                        continue
                    }

                    if level >= depth {
                        targets.push((level, path));
                    } else {
                        unchanged_prefix_set.insert(path);

                        for bit in CHILD_INDEX_RANGE.rev() {
                            if state_mask.is_bit_set(bit) {
                                let mut child_path = path;
                                child_path.push_unchecked(bit);
                                paths.push((child_path, level + 1));
                            }
                        }
                    }
                }
            }
        }

        (targets, unchanged_prefix_set)
    }

    /// Look up or calculate the RLP of the node at the root path.
    ///
    /// # Panics
    ///
    /// If the node at provided path does not exist.
    pub fn rlp_node_allocate(&mut self, prefix_set: &mut PrefixSet) -> RlpNode {
        let mut buffers = RlpNodeBuffers::new_with_root_path();
        let mut temp_rlp_buf = core::mem::take(&mut self.rlp_buf);
        let result = self.rlp_node(prefix_set, &mut buffers, &mut temp_rlp_buf);
        self.rlp_buf = temp_rlp_buf;

        result
    }

    /// Looks up or computes the RLP encoding of the node specified by the current
    /// path in the provided buffers.
    ///
    /// The function uses a stack (`RlpNodeBuffers::path_stack`) to track the traversal and
    /// accumulate RLP encodings.
    ///
    /// # Parameters
    ///
    /// - `prefix_set`: The set of trie paths that need their nodes updated.
    /// - `buffers`: The reusable buffers for stack management and temporary RLP values.
    ///
    /// # Panics
    ///
    /// If the node at provided path does not exist.
    pub fn rlp_node(
        &mut self,
        prefix_set: &mut PrefixSet,
        buffers: &mut RlpNodeBuffers,
        rlp_buf: &mut Vec<u8>,
    ) -> RlpNode {
        let _starting_path = buffers.path_stack.last().map(|item| item.path);

        'main: while let Some(RlpNodePathStackItem { level, path, mut is_in_prefix_set }) =
            buffers.path_stack.pop()
        {
            let node = self.nodes.get_mut(&path).unwrap();
            trace!(
                target: "trie::sparse",
                ?_starting_path,
                ?level,
                ?path,
                ?is_in_prefix_set,
                ?node,
                "Popped node from path stack"
            );

            // Check if the path is in the prefix set.
            // First, check the cached value. If it's `None`, then check the prefix set, and update
            // the cached value.
            let mut prefix_set_contains =
                |path: &Nibbles| *is_in_prefix_set.get_or_insert_with(|| prefix_set.contains(path));

            let (rlp_node, node_type) = match node {
                SparseNode::Empty => (RlpNode::word_rlp(&EMPTY_ROOT_HASH), SparseNodeType::Empty),
                SparseNode::Hash(hash) => (RlpNode::word_rlp(hash), SparseNodeType::Hash),
                SparseNode::Leaf { key, hash } => {
                    let mut path = path;
                    path.extend(key);
                    if let Some(hash) = hash.filter(|_| !prefix_set_contains(&path)) {
                        (RlpNode::word_rlp(&hash), SparseNodeType::Leaf)
                    } else {
                        let value = self.values.get(&path).unwrap();
                        rlp_buf.clear();
                        let rlp_node = LeafNodeRef { key, value }.rlp(rlp_buf);
                        *hash = rlp_node.as_hash();
                        (rlp_node, SparseNodeType::Leaf)
                    }
                }
                SparseNode::Extension { key, hash, store_in_db_trie } => {
                    let mut child_path = path;
                    child_path.extend(key);
                    if let Some((hash, store_in_db_trie)) =
                        hash.zip(*store_in_db_trie).filter(|_| !prefix_set_contains(&path))
                    {
                        (
                            RlpNode::word_rlp(&hash),
                            SparseNodeType::Extension { store_in_db_trie: Some(store_in_db_trie) },
                        )
                    } else if buffers.rlp_node_stack.last().is_some_and(|e| e.path == child_path) {
                        let RlpNodeStackItem {
                            path: _,
                            rlp_node: child,
                            node_type: child_node_type,
                        } = buffers.rlp_node_stack.pop().unwrap();
                        rlp_buf.clear();
                        let rlp_node = ExtensionNodeRef::new(key, &child).rlp(rlp_buf);
                        *hash = rlp_node.as_hash();

                        let store_in_db_trie_value = child_node_type.store_in_db_trie();

                        trace!(
                            target: "trie::sparse",
                            ?path,
                            ?child_path,
                            ?child_node_type,
                            "Extension node"
                        );

                        *store_in_db_trie = store_in_db_trie_value;

                        (
                            rlp_node,
                            SparseNodeType::Extension {
                                // Inherit the `store_in_db_trie` flag from the child node, which is
                                // always the branch node
                                store_in_db_trie: store_in_db_trie_value,
                            },
                        )
                    } else {
                        // need to get rlp node for child first
                        buffers.path_stack.extend([
                            RlpNodePathStackItem { level, path, is_in_prefix_set },
                            RlpNodePathStackItem {
                                level: level + 1,
                                path: child_path,
                                is_in_prefix_set: None,
                            },
                        ]);
                        continue
                    }
                }
                SparseNode::Branch { state_mask, hash, store_in_db_trie } => {
                    if let Some((hash, store_in_db_trie)) =
                        hash.zip(*store_in_db_trie).filter(|_| !prefix_set_contains(&path))
                    {
                        buffers.rlp_node_stack.push(RlpNodeStackItem {
                            path,
                            rlp_node: RlpNode::word_rlp(&hash),
                            node_type: SparseNodeType::Branch {
                                store_in_db_trie: Some(store_in_db_trie),
                            },
                        });
                        continue
                    }
                    let retain_updates = self.updates.is_some() && prefix_set_contains(&path);

                    buffers.branch_child_buf.clear();
                    // Walk children in a reverse order from `f` to `0`, so we pop the `0` first
                    // from the stack and keep walking in the sorted order.
                    for bit in CHILD_INDEX_RANGE.rev() {
                        if state_mask.is_bit_set(bit) {
                            let mut child = path;
                            child.push_unchecked(bit);
                            buffers.branch_child_buf.push(child);
                        }
                    }

                    buffers
                        .branch_value_stack_buf
                        .resize(buffers.branch_child_buf.len(), Default::default());
                    let mut added_children = false;

                    let mut tree_mask = TrieMask::default();
                    let mut hash_mask = TrieMask::default();
                    let mut hashes = Vec::new();
                    for (i, child_path) in buffers.branch_child_buf.iter().enumerate() {
                        if buffers.rlp_node_stack.last().is_some_and(|e| &e.path == child_path) {
                            let RlpNodeStackItem {
                                path: _,
                                rlp_node: child,
                                node_type: child_node_type,
                            } = buffers.rlp_node_stack.pop().unwrap();

                            // Update the masks only if we need to retain trie updates
                            if retain_updates {
                                // SAFETY: it's a child, so it's never empty
                                let last_child_nibble = child_path.last().unwrap();

                                // Determine whether we need to set trie mask bit.
                                let should_set_tree_mask_bit = if let Some(store_in_db_trie) =
                                    child_node_type.store_in_db_trie()
                                {
                                    // A branch or an extension node explicitly set the
                                    // `store_in_db_trie` flag
                                    store_in_db_trie
                                } else {
                                    // A blinded node has the tree mask bit set
                                    child_node_type.is_hash() &&
                                        self.branch_node_tree_masks.get(&path).is_some_and(
                                            |mask| mask.is_bit_set(last_child_nibble),
                                        )
                                };
                                if should_set_tree_mask_bit {
                                    tree_mask.set_bit(last_child_nibble);
                                }

                                // Set the hash mask. If a child node is a revealed branch node OR
                                // is a blinded node that has its hash mask bit set according to the
                                // database, set the hash mask bit and save the hash.
                                let hash = child.as_hash().filter(|_| {
                                    child_node_type.is_branch() ||
                                        (child_node_type.is_hash() &&
                                            self.branch_node_hash_masks
                                                .get(&path)
                                                .is_some_and(|mask| {
                                                    mask.is_bit_set(last_child_nibble)
                                                }))
                                });
                                if let Some(hash) = hash {
                                    hash_mask.set_bit(last_child_nibble);
                                    hashes.push(hash);
                                }
                            }

                            // Insert children in the resulting buffer in a normal order,
                            // because initially we iterated in reverse.
                            // SAFETY: i < len and len is never 0
                            let original_idx = buffers.branch_child_buf.len() - i - 1;
                            buffers.branch_value_stack_buf[original_idx] = child;
                            added_children = true;
                        } else {
                            debug_assert!(!added_children);
                            buffers.path_stack.push(RlpNodePathStackItem {
                                level,
                                path,
                                is_in_prefix_set,
                            });
                            buffers.path_stack.extend(buffers.branch_child_buf.drain(..).map(
                                |path| RlpNodePathStackItem {
                                    level: level + 1,
                                    path,
                                    is_in_prefix_set: None,
                                },
                            ));
                            continue 'main
                        }
                    }

                    trace!(
                        target: "trie::sparse",
                        ?path,
                        ?tree_mask,
                        ?hash_mask,
                        "Branch node masks"
                    );

                    rlp_buf.clear();
                    let branch_node_ref =
                        BranchNodeRef::new(&buffers.branch_value_stack_buf, *state_mask);
                    let rlp_node = branch_node_ref.rlp(rlp_buf);
                    *hash = rlp_node.as_hash();

                    // Save a branch node update only if it's not a root node, and we need to
                    // persist updates.
                    let store_in_db_trie_value = if let Some(updates) =
                        self.updates.as_mut().filter(|_| retain_updates && !path.is_empty())
                    {
                        let store_in_db_trie = !tree_mask.is_empty() || !hash_mask.is_empty();
                        if store_in_db_trie {
                            // Store in DB trie if there are either any children that are stored in
                            // the DB trie, or any children represent hashed values
                            hashes.reverse();
                            let branch_node = BranchNodeCompact::new(
                                *state_mask,
                                tree_mask,
                                hash_mask,
                                hashes,
                                hash.filter(|_| path.is_empty()),
                            );
                            updates.updated_nodes.insert(path, branch_node);
                        } else if self
                            .branch_node_tree_masks
                            .get(&path)
                            .is_some_and(|mask| !mask.is_empty()) ||
                            self.branch_node_hash_masks
                                .get(&path)
                                .is_some_and(|mask| !mask.is_empty())
                        {
                            // If new tree and hash masks are empty, but previously they weren't, we
                            // need to remove the node update and add the node itself to the list of
                            // removed nodes.
                            updates.updated_nodes.remove(&path);
                            updates.removed_nodes.insert(path);
                        } else if self
                            .branch_node_tree_masks
                            .get(&path)
                            .is_none_or(|mask| mask.is_empty()) &&
                            self.branch_node_hash_masks
                                .get(&path)
                                .is_none_or(|mask| mask.is_empty())
                        {
                            // If new tree and hash masks are empty, and they were previously empty
                            // as well, we need to remove the node update.
                            updates.updated_nodes.remove(&path);
                        }

                        store_in_db_trie
                    } else {
                        false
                    };
                    *store_in_db_trie = Some(store_in_db_trie_value);

                    (
                        rlp_node,
                        SparseNodeType::Branch { store_in_db_trie: Some(store_in_db_trie_value) },
                    )
                }
            };

            trace!(
                target: "trie::sparse",
                ?_starting_path,
                ?level,
                ?path,
                ?node,
                ?node_type,
                ?is_in_prefix_set,
                "Added node to rlp node stack"
            );

            buffers.rlp_node_stack.push(RlpNodeStackItem { path, rlp_node, node_type });
        }

        debug_assert_eq!(buffers.rlp_node_stack.len(), 1);
        buffers.rlp_node_stack.pop().unwrap().rlp_node
    }
}

/// Enum representing sparse trie node type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseNodeType {
    /// Empty trie node.
    Empty,
    /// A placeholder that stores only the hash for a node that has not been fully revealed.
    Hash,
    /// Sparse leaf node.
    Leaf,
    /// Sparse extension node.
    Extension {
        /// A flag indicating whether the extension node should be stored in the database.
        store_in_db_trie: Option<bool>,
    },
    /// Sparse branch node.
    Branch {
        /// A flag indicating whether the branch node should be stored in the database.
        store_in_db_trie: Option<bool>,
    },
}

impl SparseNodeType {
    /// Returns true if the node is a hash node.
    pub const fn is_hash(&self) -> bool {
        matches!(self, Self::Hash)
    }

    /// Returns true if the node is a branch node.
    pub const fn is_branch(&self) -> bool {
        matches!(self, Self::Branch { .. })
    }

    /// Returns true if the node should be stored in the database.
    pub const fn store_in_db_trie(&self) -> Option<bool> {
        match *self {
            Self::Extension { store_in_db_trie } | Self::Branch { store_in_db_trie } => {
                store_in_db_trie
            }
            _ => None,
        }
    }
}

/// Enum representing trie nodes in sparse trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparseNode {
    /// Empty trie node.
    Empty,
    /// The hash of the node that was not revealed.
    Hash(B256),
    /// Sparse leaf node with remaining key suffix.
    Leaf {
        /// Remaining key suffix for the leaf node.
        key: Nibbles,
        /// Pre-computed hash of the sparse node.
        /// Can be reused unless this trie path has been updated.
        hash: Option<B256>,
    },
    /// Sparse extension node with key.
    Extension {
        /// The key slice stored by this extension node.
        key: Nibbles,
        /// Pre-computed hash of the sparse node.
        /// Can be reused unless this trie path has been updated.
        ///
        /// If [`None`], then the value is not known and should be calculated from scratch.
        hash: Option<B256>,
        /// Pre-computed flag indicating whether the trie node should be stored in the database.
        /// Can be reused unless this trie path has been updated.
        ///
        /// If [`None`], then the value is not known and should be calculated from scratch.
        store_in_db_trie: Option<bool>,
    },
    /// Sparse branch node with state mask.
    Branch {
        /// The bitmask representing children present in the branch node.
        state_mask: TrieMask,
        /// Pre-computed hash of the sparse node.
        /// Can be reused unless this trie path has been updated.
        ///
        /// If [`None`], then the value is not known and should be calculated from scratch.
        hash: Option<B256>,
        /// Pre-computed flag indicating whether the trie node should be stored in the database.
        /// Can be reused unless this trie path has been updated.
        ///
        /// If [`None`], then the value is not known and should be calculated from scratch.
        store_in_db_trie: Option<bool>,
    },
}

impl SparseNode {
    /// Create new sparse node from [`TrieNode`].
    pub fn from_node(node: TrieNode) -> Self {
        match node {
            TrieNode::EmptyRoot => Self::Empty,
            TrieNode::Leaf(leaf) => Self::new_leaf(leaf.key),
            TrieNode::Extension(ext) => Self::new_ext(ext.key),
            TrieNode::Branch(branch) => Self::new_branch(branch.state_mask),
        }
    }

    /// Create new [`SparseNode::Branch`] from state mask.
    pub const fn new_branch(state_mask: TrieMask) -> Self {
        Self::Branch { state_mask, hash: None, store_in_db_trie: None }
    }

    /// Create new [`SparseNode::Branch`] with two bits set.
    pub const fn new_split_branch(bit_a: u8, bit_b: u8) -> Self {
        let state_mask = TrieMask::new(
            // set bits for both children
            (1u16 << bit_a) | (1u16 << bit_b),
        );
        Self::Branch { state_mask, hash: None, store_in_db_trie: None }
    }

    /// Create new [`SparseNode::Extension`] from the key slice.
    pub const fn new_ext(key: Nibbles) -> Self {
        Self::Extension { key, hash: None, store_in_db_trie: None }
    }

    /// Create new [`SparseNode::Leaf`] from leaf key and value.
    pub const fn new_leaf(key: Nibbles) -> Self {
        Self::Leaf { key, hash: None }
    }

    /// Returns `true` if the node is a hash node.
    pub const fn is_hash(&self) -> bool {
        matches!(self, Self::Hash(_))
    }

    /// Returns the hash of the node if it exists.
    pub const fn hash(&self) -> Option<B256> {
        match self {
            Self::Empty => None,
            Self::Hash(hash) => Some(*hash),
            Self::Leaf { hash, .. } | Self::Extension { hash, .. } | Self::Branch { hash, .. } => {
                *hash
            }
        }
    }

    /// Sets the hash of the node for testing purposes.
    ///
    /// For [`SparseNode::Empty`] and [`SparseNode::Hash`] nodes, this method does nothing.
    #[cfg(test)]
    pub const fn set_hash(&mut self, new_hash: Option<B256>) {
        match self {
            Self::Empty | Self::Hash(_) => {
                // Cannot set hash for Empty or Hash nodes
            }
            Self::Leaf { hash, .. } | Self::Extension { hash, .. } | Self::Branch { hash, .. } => {
                *hash = new_hash;
            }
        }
    }
}

/// A helper struct used to store information about a node that has been removed
/// during a deletion operation.
#[derive(Debug)]
struct RemovedSparseNode {
    /// The path at which the node was located.
    path: Nibbles,
    /// The removed node
    node: SparseNode,
    /// For branch nodes, an optional nibble that should be unset due to the node being removed.
    ///
    /// During leaf deletion, this identifies the specific branch nibble path that
    /// connects to the leaf being deleted. Then when restructuring the trie after deletion,
    /// this nibble position will be cleared from the branch node's to
    /// indicate that the child no longer exists.
    ///
    /// This is only set for branch nodes that have a direct path to the leaf being deleted.
    unset_branch_nibble: Option<u8>,
}

/// Collection of reusable buffers for [`SerialSparseTrie::rlp_node`] calculations.
///
/// These buffers reduce allocations when computing RLP representations during trie updates.
#[derive(Debug, Default)]
pub struct RlpNodeBuffers {
    /// Stack of RLP node paths
    path_stack: Vec<RlpNodePathStackItem>,
    /// Stack of RLP nodes
    rlp_node_stack: Vec<RlpNodeStackItem>,
    /// Reusable branch child path
    branch_child_buf: SmallVec<[Nibbles; 16]>,
    /// Reusable branch value stack
    branch_value_stack_buf: SmallVec<[RlpNode; 16]>,
}

impl RlpNodeBuffers {
    /// Creates a new instance of buffers with the root path on the stack.
    fn new_with_root_path() -> Self {
        Self {
            path_stack: vec![RlpNodePathStackItem {
                level: 0,
                path: Nibbles::default(),
                is_in_prefix_set: None,
            }],
            rlp_node_stack: Vec::new(),
            branch_child_buf: SmallVec::<[Nibbles; 16]>::new_const(),
            branch_value_stack_buf: SmallVec::<[RlpNode; 16]>::new_const(),
        }
    }
}

/// RLP node path stack item.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RlpNodePathStackItem {
    /// Level at which the node is located. Higher numbers correspond to lower levels in the trie.
    pub level: usize,
    /// Path to the node.
    pub path: Nibbles,
    /// Whether the path is in the prefix set. If [`None`], then unknown yet.
    pub is_in_prefix_set: Option<bool>,
}

/// RLP node stack item.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RlpNodeStackItem {
    /// Path to the node.
    pub path: Nibbles,
    /// RLP node.
    pub rlp_node: RlpNode,
    /// Type of the node.
    pub node_type: SparseNodeType,
}

impl SparseTrieUpdates {
    /// Create new wiped sparse trie updates.
    pub fn wiped() -> Self {
        Self { wiped: true, ..Default::default() }
    }

    /// Clears the updates, but keeps the backing data structures allocated.
    ///
    /// Sets `wiped` to `false`.
    pub fn clear(&mut self) {
        self.updated_nodes.clear();
        self.removed_nodes.clear();
        self.wiped = false;
    }

    /// Extends the updates with another set of updates.
    pub fn extend(&mut self, other: Self) {
        self.updated_nodes.extend(other.updated_nodes);
        self.removed_nodes.extend(other.removed_nodes);
        self.wiped |= other.wiped;
    }
}
