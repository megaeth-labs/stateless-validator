//! Greedy set cover over the stored coverage patterns.
//!
//! Completeness contract: the selected set ALWAYS covers the full universe —
//! greedy runs until no candidate adds a counter, and neither the antichain
//! prune (dominated patterns contribute no unique counters) nor the
//! redundancy-elimination pass (only drops picks fully covered by the rest)
//! can reduce coverage. Minimality is best-effort on top of that, never at
//! its expense.
//!
//! Selection is churn-damped: ties are broken in favor of patterns already in
//! the incumbent manifest, then by freshness. A final redundancy-elimination
//! pass drops any selected block whose bitmap is covered by the union of the
//! others.

use std::{collections::HashSet, path::PathBuf};

use clap::Args;
use eyre::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    bitset::BitSet,
    spool::DataDir,
    store::{Store, current_binary_id},
};

#[derive(Args, Debug, Clone)]
pub struct SetCoverArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Output manifest path (default: <data-dir>/manifest.json).
    #[clap(long)]
    pub manifest_out: Option<PathBuf>,
    /// Previous manifest whose patterns get tie-break preference (churn
    /// damping). Matched by pattern rather than block: a pattern's
    /// representative moves to the lightest block that produced it, so a later
    /// backfill can change which block stands for an unchanged pattern.
    #[clap(long)]
    pub incumbent_manifest: Option<PathBuf>,
    /// Delete the archived profiles of dominated patterns once the manifest is
    /// written. Off by default because it is irreversible and reaches past
    /// this run: a pattern an EARLIER manifest selected can become dominated
    /// by a later backfill, and deleting its profile breaks `report` on that
    /// manifest for good — the pattern stays known, so it is never archived
    /// again.
    #[clap(long)]
    pub prune_profiles: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub binary_id: String,
    /// The universe stamp of the store the cover was computed from — the
    /// scope its blocks are guaranteed to cover. `report` refuses to measure
    /// the set against any other scope: the archived profiles hold counters
    /// for every instrumented crate, so llvm-cov would happily report a wider
    /// scope than the cover was built for, and read the gap as uncovered code.
    /// Absent in manifests written before it was recorded.
    #[serde(default)]
    pub universe: Option<String>,
    pub generated_at_unix: u64,
    pub universe_counters: u64,
    pub covered_counters: u64,
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

pub fn run(args: SetCoverArgs) -> Result<()> {
    let dirs = DataDir::new(&args.data_dir);
    // `Store::open` creates a missing store — on a mistyped --data-dir that
    // would silently produce a 0-block manifest (and pin the fresh store to
    // this binary_id). Require an existing store instead.
    ensure!(
        dirs.store_path().exists(),
        "no store at {} — run backfill first (set-cover never creates one)",
        dirs.store_path().display()
    );
    let binary_id = current_binary_id();
    // No filter check: set-cover consumes whatever universe the store holds.
    let store = Store::open(&dirs.store_path(), &binary_id, None)?;
    // Patterns only: selection never looks at a block record, and the hashes
    // of the few selected representatives are point lookups afterwards.
    let patterns = store.load_patterns()?;

    let incumbents: HashSet<u64> = match &args.incumbent_manifest {
        Some(path) => {
            let manifest: Manifest = serde_json::from_str(
                &std::fs::read_to_string(path)
                    .wrap_err_with(|| format!("read incumbent manifest {}", path.display()))?,
            )?;
            manifest
                .blocks
                .iter()
                .map(|b| {
                    u64::from_str_radix(&b.pattern, 16).wrap_err_with(|| {
                        format!("bad pattern key {} in {}", b.pattern, path.display())
                    })
                })
                .collect::<Result<_>>()?
        }
        None => HashSet::new(),
    };

    info!(patterns = patterns.len(), incumbents = incumbents.len(), "computing greedy set cover");

    let outcome = select_cover(&patterns, &incumbents);
    info!(
        pruned = outcome.pruned_dominated.len(),
        antichain = patterns.len() - outcome.pruned_dominated.len(),
        "dominated patterns excluded from the candidates"
    );
    // `selected` no longer contains these (select_cover drops them), so the
    // removal set itself is the only place they can be reported from.
    for rep in &outcome.redundant_removed {
        info!(block = rep, "selected early but redundant after later picks — removed");
    }

    let universe_counters = outcome.universe_counters;
    let covered_counters = outcome.covered_counters;
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
        binary_id,
        // What backfill stamped the store with, not a re-derivation from
        // flags: it cannot drift from the scan that produced the profiles.
        universe: store.universe()?,
        generated_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        universe_counters,
        covered_counters,
        blocks,
    };

    let out = args.manifest_out.unwrap_or_else(|| dirs.manifest_path());
    crate::spool::write_atomic(&out, serde_json::to_string_pretty(&manifest)?.as_bytes())?;
    info!(
        selected = manifest.blocks.len(),
        covered = covered_counters,
        universe = universe_counters,
        out = %out.display(),
        "set cover written"
    );
    for b in &manifest.blocks {
        info!(block = b.number, gain = b.gain, bits = b.bits, "selected");
    }

    // Only after the manifest is durably written: a failure above must not
    // leave the store with neither the old profiles nor a new manifest.
    if args.prune_profiles {
        let removed = outcome
            .pruned_dominated
            .iter()
            .filter(|key| std::fs::remove_file(dirs.archived_profile(**key)).is_ok())
            .count();
        info!(removed, "archived profiles of dominated patterns deleted (--prune-profiles)");
    }
    Ok(())
}

/// Result of the pure set-cover algorithm.
pub struct CoverOutcome {
    /// The final cover in selection order: `(pattern_key, representative,
    /// gain)`. Redundancy-eliminated picks are already removed.
    pub selected: Vec<(u64, u64, u64)>,
    /// Pattern keys strictly dominated by another pattern (excluded from the
    /// candidate pool; their archived profiles are safe to delete).
    pub pruned_dominated: Vec<u64>,
    /// Representatives dropped by the redundancy-elimination pass (for
    /// logging; no longer present in `selected`).
    pub redundant_removed: std::collections::HashSet<u64>,
    pub universe_counters: u64,
    pub covered_counters: u64,
}

/// Pure greedy set cover with antichain pruning, incumbent-biased
/// tie-breaking (`incumbents` are pattern keys), and a final
/// redundancy-elimination pass. No I/O — the fs side effects (deleting pruned
/// profiles) belong to the caller.
pub fn select_cover(
    patterns: &std::collections::HashMap<u64, crate::store::PatternRecord>,
    incumbents: &HashSet<u64>,
) -> CoverOutcome {
    let mut universe = BitSet::new();
    for rec in patterns.values() {
        universe.union_with(&rec.bitmap);
    }
    let universe_counters = universe.count_ones();

    // Antichain prune: a strict subset of another pattern can never improve
    // the cover — and if left in, it could win a gain tie-break and select a
    // block whose profile was never archived (dominated patterns skip the
    // archive at promotion time).
    let (mut remaining, pruned_dominated) = split_antichain(patterns);

    // Greedy: max gain; ties prefer incumbents (churn damping), then the
    // higher block number.
    let mut covered = BitSet::new();
    let mut selected: Vec<(u64, u64, u64)> = Vec::new();
    loop {
        let mut best: Option<(u64, bool, u64, usize)> = None; // (gain, incumbent, block, idx)
        for (idx, (key, rec)) in remaining.iter().enumerate() {
            let gain = rec.bitmap.andnot_count(&covered);
            if gain == 0 {
                continue;
            }
            let candidate = (gain, incumbents.contains(*key), rec.representative, idx);
            if best.is_none_or(|b| (candidate.0, candidate.1, candidate.2) > (b.0, b.1, b.2)) {
                best = Some(candidate);
            }
        }
        let Some((gain, _inc, _blk, idx)) = best else { break };
        let (key, rec) = remaining.swap_remove(idx);
        covered.union_with(&rec.bitmap);
        selected.push((*key, rec.representative, gain));
    }

    // Redundancy elimination: drop picks fully covered by the union of the
    // others (an early large pick can become redundant after later picks).
    let mut removed: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut pruned = true;
    while pruned {
        pruned = false;
        for i in 0..selected.len() {
            let (key, rep, _) = selected[i];
            if removed.contains(&rep) {
                continue;
            }
            let mut others = BitSet::new();
            for (j, (other_key, other_rep, _)) in selected.iter().enumerate() {
                if i != j && !removed.contains(other_rep) {
                    others.union_with(&patterns[other_key].bitmap);
                }
            }
            if patterns[&key].bitmap.is_subset_of(&others) {
                removed.insert(rep);
                pruned = true;
                break;
            }
        }
    }

    // The cover is final here: drop eliminated picks so every consumer sees
    // the true selection (removed reps stay available for logging).
    selected.retain(|(_, rep, _)| !removed.contains(rep));

    CoverOutcome {
        selected,
        pruned_dominated,
        redundant_removed: removed,
        universe_counters,
        covered_counters: covered.count_ones(),
    }
}

/// Splits the patterns into the antichain — those no other pattern strictly
/// dominates — and the keys of the dominated rest.
///
/// Patterns are visited in descending `bits` order, so every possible
/// dominator of a pattern (it needs strictly more bits) is classified before
/// the pattern is reached. Domination is transitive, so testing against the
/// kept set alone is complete: a pruned dominator was itself dominated by a
/// kept pattern, which then dominates the candidate too. The kept set is
/// therefore exactly the maximal elements, whatever order ties are visited in.
///
/// The naive form of this — test each pattern against every earlier one — is
/// quadratic in the pattern count, and at full-history scale that scan, not
/// the greedy cover, is where the time goes. Two things cut it down:
///
/// - only kept patterns are ever scanned (the dominated majority never dominates anything a kept
///   pattern does not), and
/// - an inverted index from counter to the kept patterns containing it turns "who could be a
///   superset of this candidate?" into "who contains its rarest counter?" — a superset must contain
///   every counter the candidate has, so the shortest posting list bounds the search, and a counter
///   no kept pattern has proves the candidate maximal outright.
fn split_antichain(
    patterns: &std::collections::HashMap<u64, crate::store::PatternRecord>,
) -> (Vec<(&u64, &crate::store::PatternRecord)>, Vec<u64>) {
    let mut ordered: Vec<(&u64, &crate::store::PatternRecord)> = patterns.iter().collect();
    ordered.sort_by_key(|(_, r)| std::cmp::Reverse(r.bits));

    let mut kept: Vec<(&u64, &crate::store::PatternRecord)> = Vec::new();
    let mut pruned_dominated = Vec::new();
    // postings[counter] = indices into `kept` of the patterns containing it.
    let mut postings: Vec<Vec<u32>> = Vec::new();

    for (key, rec) in ordered {
        // The shortest posting list among the candidate's counters; `None`
        // once some counter turns out to be in no kept pattern at all.
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

        if dominated {
            pruned_dominated.push(*key);
        } else {
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

    (kept, pruned_dominated)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::store::PatternRecord;

    fn pat(bits: &[u32], rep: u64) -> PatternRecord {
        let bitmap = BitSet::from_indices(bits.iter().copied());
        PatternRecord {
            bits: bitmap.count_ones(),
            bitmap,
            first_block: rep,
            last_block: rep,
            hit_count: 1,
            representative: rep,
            representative_elapsed_ms: 100,
        }
    }

    fn cover(patterns: &HashMap<u64, PatternRecord>) -> (Vec<u64>, CoverOutcome) {
        let outcome = select_cover(patterns, &HashSet::new());
        let mut blocks: Vec<u64> = outcome.selected.iter().map(|(_, rep, _)| *rep).collect();
        blocks.sort_unstable();
        (blocks, outcome)
    }

    /// The quadratic scan `split_antichain` replaced, kept as the oracle: it
    /// is obviously correct (every pattern against every earlier kept one),
    /// just unusable at scale.
    fn split_antichain_reference(patterns: &HashMap<u64, PatternRecord>) -> (Vec<u64>, Vec<u64>) {
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
        let (mut kept, mut pruned) = (Vec::new(), Vec::new());
        for (i, (key, _)) in ordered.iter().enumerate() {
            if keep[i] { kept.push(**key) } else { pruned.push(**key) }
        }
        kept.sort_unstable();
        pruned.sort_unstable();
        (kept, pruned)
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

    /// Hub patterns plus many patterns derived from them by dropping
    /// counters — the shape real stores have (a few percent maximal, the rest
    /// dominated) — salted with unrelated patterns, equal-bitmap twins (which
    /// must never dominate each other) and an empty pattern.
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

    /// The indexed split must classify every pattern exactly as the quadratic
    /// oracle does, on stores shaped like real ones.
    #[test]
    fn indexed_antichain_split_matches_the_quadratic_oracle() {
        for seed in 1..=12u64 {
            let patterns = random_store(seed, 96 + (seed as u32 * 17) % 160, 12, 900);
            let (expect_kept, expect_pruned) = split_antichain_reference(&patterns);

            let (kept, pruned) = split_antichain(&patterns);
            let mut kept: Vec<u64> = kept.iter().map(|(k, _)| **k).collect();
            let mut pruned = pruned;
            kept.sort_unstable();
            pruned.sort_unstable();

            assert_eq!(kept, expect_kept, "kept set diverged (seed {seed})");
            assert_eq!(pruned, expect_pruned, "pruned set diverged (seed {seed})");
            assert!(!pruned.is_empty() && kept.len() > 1, "degenerate store (seed {seed})");
        }
    }

    /// An empty bitmap has no counter to look up, so it takes the fallback
    /// scan: it is dominated by any non-empty pattern, and kept only alone.
    #[test]
    fn empty_pattern_is_dominated_unless_alone() {
        let alone: HashMap<u64, PatternRecord> = [(1, pat(&[], 10))].into();
        let (kept, pruned) = split_antichain(&alone);
        assert_eq!((kept.len(), pruned.len()), (1, 0));

        let with_other: HashMap<u64, PatternRecord> =
            [(1, pat(&[], 10)), (2, pat(&[7], 20))].into();
        let (kept, pruned) = split_antichain(&with_other);
        assert_eq!(kept.iter().map(|(k, _)| **k).collect::<Vec<_>>(), vec![2]);
        assert_eq!(pruned, vec![1]);
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
        assert_eq!(outcome.covered_counters, outcome.universe_counters);
        let mut pruned = outcome.pruned_dominated.clone();
        pruned.sort_unstable();
        assert_eq!(pruned, vec![2, 4]);
    }

    /// Equal-bits patterns with different bitmaps must BOTH survive the prune
    /// (the guard is strictly `bits >`, never `>=`).
    #[test]
    fn equal_bits_distinct_patterns_both_survive() {
        let patterns: HashMap<u64, PatternRecord> =
            [(1, pat(&[0, 1], 10)), (2, pat(&[2, 3], 20))].into();
        let (blocks, outcome) = cover(&patterns);
        assert_eq!(blocks, vec![10, 20]);
        assert!(outcome.pruned_dominated.is_empty());
    }

    /// On a gain tie, the incumbent pattern wins (churn damping) — whichever
    /// block represents it now. The previous manifest selected pattern 1
    /// through some block; a later backfill re-homed it to block 55, which no
    /// manifest ever named, and it must still win the tie.
    #[test]
    fn incumbent_wins_gain_ties() {
        // Two disjoint equal-size patterns; both must be picked, but the
        // FIRST pick (order) must be the incumbent regardless of block number.
        let patterns: HashMap<u64, PatternRecord> =
            [(1, pat(&[0, 1], 55)), (2, pat(&[2, 3], 99))].into();
        let incumbents: HashSet<u64> = [1].into();
        let outcome = select_cover(&patterns, &incumbents);
        assert_eq!(outcome.selected[0].1, 55, "incumbent must be picked first on a tie");

        // Without incumbency the higher block number wins the tie.
        let outcome = select_cover(&patterns, &HashSet::new());
        assert_eq!(outcome.selected[0].1, 99);
    }

    /// The {a,b}+{c} vs {a,b,c} shape: greedy picks the superset first and
    /// the smaller earlier patterns are never selected at all.
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

    /// Redundancy elimination: a first big pick that later picks fully cover
    /// gets removed from the final set.
    #[test]
    fn redundancy_elimination_drops_covered_first_pick() {
        // A = {0..5} (biggest, picked first). B = {0,1,2,6}, C = {3,4,5,7}.
        // After B and C are picked (each adds a fresh counter), A ⊆ B∪C.
        let patterns: HashMap<u64, PatternRecord> = [
            (1, pat(&[0, 1, 2, 3, 4, 5], 10)),
            (2, pat(&[0, 1, 2, 6], 20)),
            (3, pat(&[3, 4, 5, 7], 30)),
        ]
        .into();
        let (blocks, outcome) = cover(&patterns);
        assert_eq!(blocks, vec![20, 30]);
        assert!(outcome.redundant_removed.contains(&10));
        // Coverage is still complete without the removed pick.
        assert_eq!(outcome.covered_counters, outcome.universe_counters);
    }
}
