//! Dense bitset over the (append-only) dense counter-id space.
//!
//! Pattern bitmaps are small (tens of KB) and the id space only grows, so a
//! plain `Vec<u64>` beats pulling in a compressed-bitmap dependency. Older
//! bitmaps are simply shorter; all operations treat missing tail words as zero.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitSet {
    words: Vec<u64>,
}

impl BitSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_indices(indices: impl IntoIterator<Item = u32>) -> Self {
        let mut s = Self::new();
        for i in indices {
            s.insert(i);
        }
        s
    }

    pub fn insert(&mut self, idx: u32) {
        let word = (idx / 64) as usize;
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= 1u64 << (idx % 64);
    }

    pub fn count_ones(&self) -> u64 {
        self.words.iter().map(|w| w.count_ones() as u64).sum()
    }

    /// Number of bits set in `self` that are not set in `other`.
    pub fn andnot_count(&self, other: &BitSet) -> u64 {
        self.words
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let o = other.words.get(i).copied().unwrap_or(0);
                (w & !o).count_ones() as u64
            })
            .sum()
    }

    pub fn union_with(&mut self, other: &BitSet) {
        if other.words.len() > self.words.len() {
            self.words.resize(other.words.len(), 0);
        }
        for (i, w) in other.words.iter().enumerate() {
            self.words[i] |= w;
        }
    }

    pub fn is_subset_of(&self, other: &BitSet) -> bool {
        self.andnot_count(other) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() {
        let a = BitSet::from_indices([1, 5, 100, 1000]);
        let b = BitSet::from_indices([5, 100]);
        assert_eq!(a.count_ones(), 4);
        assert!(b.is_subset_of(&a));
        assert!(!a.is_subset_of(&b));
        assert_eq!(a.andnot_count(&b), 2);

        let mut u = b.clone();
        u.union_with(&a);
        assert_eq!(u, a);

        // Different trailing-zero lengths still compare equal in behavior.
        let c = BitSet::from_indices([1]);
        assert_eq!(c.andnot_count(&a), 0);
        assert!(c.is_subset_of(&a));
    }
}
