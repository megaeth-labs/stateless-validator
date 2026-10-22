//! Plain `Vec<u64>` bitset over the append-only dense counter-id space. Older bitmaps are
//! simply shorter: all operations treat missing tail words as zero.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BitSet {
    words: Vec<u64>,
}

/// Set equality, as every other operation reads it: missing tail words are zero, so two equal
/// sets whose word vectors differ only by trailing zero words compare equal. Pattern identity
/// (`store::resolve_pattern_slot`) rests on this.
impl PartialEq for BitSet {
    fn eq(&self, other: &Self) -> bool {
        let (long, short) =
            if self.words.len() >= other.words.len() { (self, other) } else { (other, self) };
        long.words.iter().enumerate().all(|(i, w)| *w == short.words.get(i).copied().unwrap_or(0))
    }
}

impl Eq for BitSet {}

impl BitSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_indices(indices: impl IntoIterator<Item = u32>) -> Self {
        let mut s = Self::new();
        for i in indices {
            s.insert(i);
        }
        // Unordered indices grow the words by doubling; a long-lived bitmap keeps no slack.
        s.words.shrink_to_fit();
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

    /// Short-circuits on the first word disproving subset-hood: the dominance scans' hot kernel.
    pub fn is_subset_of(&self, other: &BitSet) -> bool {
        self.words
            .iter()
            .enumerate()
            .all(|(i, w)| w & !other.words.get(i).copied().unwrap_or(0) == 0)
    }

    /// Iterates the indices of all set bits, ascending.
    pub fn iter_ones(&self) -> impl Iterator<Item = u32> + '_ {
        self.words.iter().enumerate().flat_map(|(wi, &word)| {
            let base = (wi as u32) * 64;
            std::iter::from_fn({
                let mut w = word;
                move || {
                    if w == 0 {
                        None
                    } else {
                        let bit = w.trailing_zeros();
                        w &= w - 1;
                        Some(base + bit)
                    }
                }
            })
        })
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

    /// Equality is set equality: trailing zero words never tell two equal sets apart.
    #[test]
    fn equality_ignores_trailing_zero_words() {
        let padded = BitSet { words: vec![0b10, 0, 0] };
        assert_eq!(padded, BitSet::from_indices([1]));
        assert_eq!(BitSet::from_indices([1]), padded);
        assert_ne!(padded, BitSet::from_indices([1, 64]));
        assert_eq!(BitSet { words: vec![0] }, BitSet::new());
    }
}
