//! Greedy set cover over the stored coverage patterns.
//!
//! The selection ALWAYS covers the full universe: greedy runs until no candidate adds a
//! counter, dominated patterns add no unique counter, and redundancy elimination only drops
//! picks the rest cover. Minimality is best-effort on top, never at its expense. Gain ties go
//! to the higher block number, so a store always yields the same selection.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use clap::Args;
use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    bitset::BitSet,
    spool::DataDir,
    store::{BINARY_ID, PatternRecord, Store},
};

#[derive(Args, Debug, Clone)]
pub struct SetCoverArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Output manifest path (default: <data-dir>/manifest.json).
    #[clap(long)]
    pub manifest_out: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub binary_id: String,
    /// Universe stamp of the source store: the scope the cover is guaranteed to cover, and the
    /// only one `report` will measure it against (see `report::check_manifest`).
    pub universe: String,
    pub generated_at_unix: u64,
    /// Items in the universe, every one of which the cover covers (see the module docs).
    pub universe_counters: u64,
    pub blocks: Vec<ManifestBlock>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestBlock {
    pub number: u64,
    pub hash: String,
    pub pattern: String,
    /// Counters this block newly contributed at its selection step.
    pub gain: u64,
    /// Total counters this block's pattern covers on its own.
    pub bits: u64,
}

impl Manifest {
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("read manifest {}", path.display()))?;
        serde_json::from_str(&text).wrap_err_with(|| format!("parse manifest {}", path.display()))
    }
}

impl ManifestBlock {
    /// The pattern key, which names the block's archived profile.
    pub fn pattern_key(&self) -> Result<u64> {
        u64::from_str_radix(&self.pattern, 16)
            .wrap_err_with(|| format!("bad pattern key {:?} in manifest", self.pattern))
    }
}

/// Seconds since the Unix epoch, for provenance stamps.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn run(args: SetCoverArgs) -> Result<()> {
    let dirs = DataDir::new(&args.data_dir);
    let store = Store::open_for_build(&dirs.store_path(), BINARY_ID)?;
    // Patterns only: selection needs no block records; the picks' hashes are looked up after.
    let patterns = store.patterns()?;

    info!(patterns = patterns.len(), "computing greedy set cover");
    let outcome = select_cover(&patterns);
    info!(
        pruned = patterns.len() - outcome.antichain.len(),
        antichain = outcome.antichain.len(),
        "dominated patterns excluded from the candidates"
    );
    for rep in &outcome.redundant_removed {
        info!(block = rep, "selected early but redundant after later picks — removed");
    }

    let universe_counters = outcome.universe_counters;
    let representatives: Vec<u64> = outcome.selected.iter().map(|(_, rep, _)| *rep).collect();
    let records = store.block_records(&representatives)?;
    let blocks: Vec<ManifestBlock> = outcome
        .selected
        .iter()
        .map(|(key, rep, gain)| {
            let rec = &patterns[key];
            let hash =
                records.get(rep).map(|b| format!("{:#x}", b.hash)).unwrap_or_else(|| "0x0".into());
            ManifestBlock {
                number: *rep,
                hash,
                pattern: format!("{key:016x}"),
                gain: *gain,
                bits: rec.bits,
            }
        })
        .collect();

    let manifest = Manifest {
        binary_id: BINARY_ID.into(),
        // The store's own stamp, so it cannot drift from the scan that produced the profiles.
        universe: store.universe()?,
        generated_at_unix: unix_now(),
        universe_counters,
        blocks,
    };

    let out = args.manifest_out.unwrap_or_else(|| dirs.manifest_path());
    crate::spool::write_atomic(&out, serde_json::to_string_pretty(&manifest)?.as_bytes())?;
    info!(
        selected = manifest.blocks.len(),
        covered = universe_counters,
        out = %out.display(),
        "set cover written"
    );
    for b in &manifest.blocks {
        info!(block = b.number, gain = b.gain, bits = b.bits, "selected");
    }
    Ok(())
}

/// Result of the pure set-cover algorithm.
pub struct CoverOutcome {
    /// The final cover in selection order: `(pattern_key, representative, gain)`.
    pub selected: Vec<(u64, u64, u64)>,
    /// Keys of the antichain (see [`antichain`]): the only cover candidates.
    pub antichain: Vec<u64>,
    /// Representatives dropped by redundancy elimination (not in `selected`; for logging).
    pub redundant_removed: Vec<u64>,
    /// Size of the universe, which `selected` always covers in full.
    pub universe_counters: u64,
}

/// Number of counters any pattern covers: the universe.
pub fn universe_size(patterns: &HashMap<u64, PatternRecord>) -> u64 {
    let mut universe = BitSet::new();
    for rec in patterns.values() {
        universe.union_with(&rec.bitmap);
    }
    universe.count_ones()
}

/// Pure greedy set cover with antichain pruning and a final redundancy-elimination pass.
pub fn select_cover(patterns: &HashMap<u64, PatternRecord>) -> CoverOutcome {
    let universe_counters = universe_size(patterns);

    // Antichain prune: a dominated pattern never improves the cover, and could win a tie-break
    // and select a block with no archived profile (the judge never archives a dominated one).
    let antichain = antichain(patterns);
    let mut remaining: Vec<(u64, &PatternRecord)> =
        antichain.iter().map(|key| (*key, &patterns[key])).collect();

    // Greedy: max gain; ties go to the higher block number (representatives are unique per
    // pattern, so the `(gain, block)` key never ties).
    let mut covered = BitSet::new();
    let mut selected: Vec<(u64, u64, u64)> = Vec::new();
    loop {
        let best = remaining
            .iter()
            .enumerate()
            .map(|(idx, (_, rec))| (rec.bitmap.andnot_count(&covered), rec.representative, idx))
            .filter(|&(gain, _, _)| gain > 0)
            .max_by_key(|&(gain, block, _)| (gain, block));
        let Some((gain, _, idx)) = best else { break };
        let (key, rec) = remaining.swap_remove(idx);
        covered.union_with(&rec.bitmap);
        selected.push((key, rec.representative, gain));
    }
    debug_assert_eq!(covered.count_ones(), universe_counters, "the antichain spans the universe");

    // Redundancy elimination: drop picks the others' union covers. One pass suffices: dropping
    // a pick only shrinks the others' union, so a pick found necessary stays necessary.
    let mut keep = vec![true; selected.len()];
    for i in 0..selected.len() {
        let mut others = BitSet::new();
        for (j, (other_key, _, _)) in selected.iter().enumerate() {
            if j != i && keep[j] {
                others.union_with(&patterns[other_key].bitmap);
            }
        }
        keep[i] = !patterns[&selected[i].0].bitmap.is_subset_of(&others);
    }
    let (kept, removed): (Vec<_>, Vec<_>) =
        selected.into_iter().zip(keep).partition(|(_, keep)| *keep);
    let selected: Vec<(u64, u64, u64)> = kept.into_iter().map(|(pick, _)| pick).collect();
    let removed: Vec<u64> = removed.into_iter().map(|((_, rep, _), _)| rep).collect();

    CoverOutcome { selected, antichain, redundant_removed: removed, universe_counters }
}

/// Keys of the antichain: the patterns no other pattern strictly dominates.
///
/// Patterns are visited in descending `bits`, so every possible dominator (it needs strictly
/// more bits) is classified first. Domination is transitive, so testing against kept patterns
/// alone is complete: a pruned dominator was itself dominated by a kept pattern, which then
/// dominates the candidate too — the kept set is exactly the maximal elements, whatever the tie
/// order. An inverted index bounds the search: a superset must contain the candidate's rarest
/// counter, and a counter no kept pattern has proves the candidate maximal outright.
pub(crate) fn antichain(patterns: &HashMap<u64, PatternRecord>) -> Vec<u64> {
    let mut ordered: Vec<(&u64, &PatternRecord)> = patterns.iter().collect();
    ordered.sort_by_key(|(_, r)| std::cmp::Reverse(r.bits));

    let mut kept: Vec<(&u64, &PatternRecord)> = Vec::new();
    // postings[counter] = indices into `kept` of the patterns containing it.
    let mut postings: Vec<Vec<u32>> = Vec::new();

    for (key, rec) in ordered {
        // Shortest posting list among the candidate's counters, unless one is in no kept pattern.
        let mut shortest: Option<&[u32]> = None;
        let mut has_unseen_counter = false;
        for counter in rec.bitmap.iter_ones() {
            match postings.get(counter as usize) {
                Some(list) if !list.is_empty() => {
                    if shortest.is_none_or(|s| list.len() < s.len()) {
                        shortest = Some(list);
                    }
                }
                _ => {
                    has_unseen_counter = true;
                    break;
                }
            }
        }

        let dominated = if has_unseen_counter {
            false
        } else {
            match shortest {
                Some(list) => list.iter().any(|&i| kept[i as usize].1.dominates(rec)),
                // No counters at all: every non-empty kept pattern dominates it.
                None => kept.iter().any(|(_, k)| k.dominates(rec)),
            }
        };

        if !dominated {
            let index = kept.len() as u32;
            for counter in rec.bitmap.iter_ones() {
                let counter = counter as usize;
                if counter >= postings.len() {
                    postings.resize_with(counter + 1, Vec::new);
                }
                postings[counter].push(index);
            }
            kept.push((key, rec));
        }
    }

    kept.into_iter().map(|(key, _)| *key).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::store::{PatternRecord, test_support::pattern as pat};

    fn cover(patterns: &HashMap<u64, PatternRecord>) -> (Vec<u64>, CoverOutcome) {
        let outcome = select_cover(patterns);
        let mut blocks: Vec<u64> = outcome.selected.iter().map(|(_, rep, _)| *rep).collect();
        blocks.sort_unstable();
        (blocks, outcome)
    }

    /// Obviously correct quadratic oracle: every pattern against every earlier kept one.
    fn antichain_reference(patterns: &HashMap<u64, PatternRecord>) -> Vec<u64> {
        let mut ordered: Vec<(&u64, &PatternRecord)> = patterns.iter().collect();
        ordered.sort_by_key(|(_, r)| std::cmp::Reverse(r.bits));
        let mut keep = vec![true; ordered.len()];
        for i in 0..ordered.len() {
            for j in 0..i {
                if keep[j] && ordered[j].1.dominates(ordered[i].1) {
                    keep[i] = false;
                    break;
                }
            }
        }
        let mut kept: Vec<u64> =
            ordered.iter().zip(keep).filter(|(_, keep)| *keep).map(|((key, _), _)| **key).collect();
        kept.sort_unstable();
        kept
    }

    /// xorshift64* — a deterministic stream without a dev-dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Hub patterns plus many derived by dropping counters (real stores are mostly dominated),
    /// salted with unrelated patterns, equal-bitmap twins and an empty pattern.
    fn random_store(
        seed: u64,
        universe: u32,
        hubs: usize,
        derived: usize,
    ) -> HashMap<u64, PatternRecord> {
        let mut rng = Rng(seed | 1);
        let mut patterns: HashMap<u64, PatternRecord> = HashMap::new();
        let mut next_key = 1u64;
        let mut push = |bits: Vec<u32>, patterns: &mut HashMap<u64, PatternRecord>| {
            patterns.insert(next_key, pat(&bits, next_key));
            next_key += 1;
        };

        let mut hub_bits: Vec<Vec<u32>> = Vec::new();
        for _ in 0..hubs {
            let density = 20 + rng.below(60);
            let bits: Vec<u32> = (0..universe).filter(|_| rng.below(100) < density).collect();
            hub_bits.push(bits.clone());
            push(bits, &mut patterns);
        }
        for _ in 0..derived {
            let hub = &hub_bits[rng.below(hubs as u64) as usize];
            let drop = rng.below(8); // 0 = an equal-bitmap twin of the hub
            let bits: Vec<u32> = hub
                .iter()
                .copied()
                .filter(|_| drop == 0 || rng.below(hub.len() as u64 + 1) >= drop)
                .collect();
            push(bits, &mut patterns);
        }
        for _ in 0..hubs {
            let bits: Vec<u32> = (0..universe).filter(|_| rng.below(100) < 5).collect();
            push(bits, &mut patterns);
        }
        push(Vec::new(), &mut patterns);
        patterns
    }

    /// The indexed antichain keeps exactly the patterns the quadratic oracle does.
    #[test]
    fn indexed_antichain_matches_the_quadratic_oracle() {
        for seed in 1..=12u64 {
            let patterns = random_store(seed, 96 + (seed as u32 * 17) % 160, 12, 900);
            let expect = antichain_reference(&patterns);

            let mut kept = antichain(&patterns);
            kept.sort_unstable();

            assert_eq!(kept, expect, "kept set diverged (seed {seed})");
            assert!(
                kept.len() < patterns.len() && kept.len() > 1,
                "degenerate store (seed {seed})"
            );
        }
    }

    /// An empty bitmap (the fallback scan) is dominated by any non-empty pattern, kept only alone.
    #[test]
    fn empty_pattern_is_dominated_unless_alone() {
        let alone: HashMap<u64, PatternRecord> = [(1, pat(&[], 10))].into();
        assert_eq!(antichain(&alone), vec![1]);

        let with_other: HashMap<u64, PatternRecord> =
            [(1, pat(&[], 10)), (2, pat(&[7], 20))].into();
        assert_eq!(antichain(&with_other), vec![2]);
    }

    /// Full coverage is always reached and dominated patterns never selected.
    #[test]
    fn covers_universe_and_prunes_dominated() {
        let patterns: HashMap<u64, PatternRecord> = [
            (1, pat(&[0, 1, 2, 3], 10)), // dominator
            (2, pat(&[0, 1], 20)),       // strict subset of 1 → pruned
            (3, pat(&[4, 5], 30)),
            (4, pat(&[5], 40)), // strict subset of 3 → pruned
        ]
        .into();
        let (blocks, outcome) = cover(&patterns);
        assert_eq!(blocks, vec![10, 30]);
        assert_eq!(outcome.universe_counters, 6);
        let mut antichain = outcome.antichain.clone();
        antichain.sort_unstable();
        assert_eq!(antichain, vec![1, 3]);
    }

    /// Equal-bits patterns with different bitmaps must BOTH survive the prune.
    #[test]
    fn equal_bits_distinct_patterns_both_survive() {
        let patterns: HashMap<u64, PatternRecord> =
            [(1, pat(&[0, 1], 10)), (2, pat(&[2, 3], 20))].into();
        let (blocks, outcome) = cover(&patterns);
        assert_eq!(blocks, vec![10, 20]);
        assert_eq!(outcome.antichain.len(), 2);
    }

    /// A gain tie goes to the higher block, not to whatever map iteration order yields.
    #[test]
    fn gain_ties_go_to_the_higher_block() {
        let patterns: HashMap<u64, PatternRecord> =
            [(1, pat(&[0, 1], 55)), (2, pat(&[2, 3], 99))].into();
        assert_eq!(select_cover(&patterns).selected[0].1, 99);
    }

    /// {a,b} + {c} vs {a,b,c}: only the superset is selected.
    #[test]
    fn superset_pattern_makes_smaller_ones_redundant() {
        let patterns: HashMap<u64, PatternRecord> = [
            (1, pat(&[0, 1], 10)),
            (2, pat(&[2], 20)),
            (3, pat(&[0, 1, 2], 30)), // dominates 1 and 2 → both pruned
        ]
        .into();
        let (blocks, _) = cover(&patterns);
        assert_eq!(blocks, vec![30]);
    }

    /// A first big pick that later picks fully cover is removed from the final set.
    #[test]
    fn redundancy_elimination_drops_covered_first_pick() {
        // A (biggest) is picked first; B and C each add a fresh counter, and then A ⊆ B∪C.
        let patterns: HashMap<u64, PatternRecord> = [
            (1, pat(&[0, 1, 2, 3, 4, 5], 10)),
            (2, pat(&[0, 1, 2, 6], 20)),
            (3, pat(&[3, 4, 5, 7], 30)),
        ]
        .into();
        let (blocks, outcome) = cover(&patterns);
        assert_eq!(blocks, vec![20, 30]);
        assert!(outcome.redundant_removed.contains(&10));
    }
}
