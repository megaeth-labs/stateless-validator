//! Greedy set cover over the stored coverage patterns.
//!
//! Completeness contract: the selected set ALWAYS covers the full universe —
//! greedy runs until no candidate adds a counter, and neither the antichain
//! prune (dominated patterns contribute no unique counters) nor the
//! redundancy-elimination pass (only drops picks fully covered by the rest)
//! can reduce coverage. Minimality is best-effort on top of that, never at
//! its expense.
//!
//! Selection is churn-damped: ties are broken in favor of blocks already in
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
    store::{Store, current_binary_id, elapsed_stats},
};

#[derive(Args, Debug, Clone)]
pub struct SetCoverArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Output manifest path (default: <data-dir>/manifest.json).
    #[clap(long)]
    pub manifest_out: Option<PathBuf>,
    /// Previous manifest whose blocks get tie-break preference (churn damping).
    #[clap(long)]
    pub incumbent_manifest: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub binary_id: String,
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
    let snapshot = store.load()?;

    // E3 datapoint: worker wall-clock per successfully replayed block.
    {
        let mut v: Vec<u64> = snapshot
            .blocks
            .values()
            .filter(|b| matches!(b.status, crate::store::BlockStatus::Ok))
            .map(|b| b.elapsed_ms)
            .collect();
        if let Some((avg, p50, p95, max)) = elapsed_stats(&mut v) {
            info!(
                blocks = v.len(),
                avg_ms = %format!("{avg:.0}"),
                p50_ms = p50,
                p95_ms = p95,
                max_ms = max,
                "per-block worker time (replay + profraw + bitmap)"
            );
        }
    }

    let incumbents: HashSet<u64> = match &args.incumbent_manifest {
        Some(path) => {
            let manifest: Manifest = serde_json::from_str(
                &std::fs::read_to_string(path)
                    .wrap_err_with(|| format!("read incumbent manifest {}", path.display()))?,
            )?;
            manifest.blocks.iter().map(|b| b.number).collect()
        }
        None => HashSet::new(),
    };

    info!(
        patterns = snapshot.patterns.len(),
        incumbents = incumbents.len(),
        "computing greedy set cover"
    );

    let outcome = select_cover(&snapshot.patterns, &incumbents);
    // The pruned patterns' archived profiles are dead weight — delete them
    // (the fs side effect lives here, outside the pure algorithm core).
    for key in &outcome.pruned_dominated {
        let _ = std::fs::remove_file(dirs.archived_profile(*key));
    }
    info!(
        pruned = outcome.pruned_dominated.len(),
        antichain = snapshot.patterns.len() - outcome.pruned_dominated.len(),
        "dominated patterns excluded (their archived profiles deleted)"
    );
    // `selected` no longer contains these (select_cover drops them), so the
    // removal set itself is the only place they can be reported from.
    for rep in &outcome.redundant_removed {
        info!(block = rep, "selected early but redundant after later picks — removed");
    }

    let universe_counters = outcome.universe_counters;
    let covered_counters = outcome.covered_counters;
    let blocks: Vec<ManifestBlock> = outcome
        .selected
        .iter()
        .map(|(key, rep, gain)| {
            let rec = &snapshot.patterns[key];
            let hash = snapshot
                .blocks
                .get(rep)
                .map(|b| format!("{:#x}", b.hash))
                .unwrap_or_else(|| "0x0".into());
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
/// tie-breaking, and a final redundancy-elimination pass. No I/O — the fs
/// side effects (deleting pruned profiles) belong to the caller.
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
    let mut remaining: Vec<(&u64, &crate::store::PatternRecord)> = patterns.iter().collect();
    remaining.sort_by_key(|(_, r)| std::cmp::Reverse(r.bits));
    let mut keep = vec![true; remaining.len()];
    let mut pruned_dominated = Vec::new();
    for i in 0..remaining.len() {
        for j in 0..i {
            if keep[j] && remaining[j].1.dominates(remaining[i].1) {
                keep[i] = false;
                pruned_dominated.push(*remaining[i].0);
                break;
            }
        }
    }
    let mut it = keep.iter();
    remaining.retain(|_| *it.next().unwrap());

    // Greedy: max gain; ties prefer incumbents (churn damping), then the
    // higher block number.
    let mut covered = BitSet::new();
    let mut selected: Vec<(u64, u64, u64)> = Vec::new();
    loop {
        let mut best: Option<(u64, bool, u64, usize)> = None; // (gain, incumbent, block, idx)
        for (idx, (_key, rec)) in remaining.iter().enumerate() {
            let gain = rec.bitmap.andnot_count(&covered);
            if gain == 0 {
                continue;
            }
            let candidate =
                (gain, incumbents.contains(&rec.representative), rec.representative, idx);
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

    fn cover(
        patterns: &HashMap<u64, PatternRecord>,
        incumbents: &[u64],
    ) -> (Vec<u64>, CoverOutcome) {
        let incumbents: HashSet<u64> = incumbents.iter().copied().collect();
        let outcome = select_cover(patterns, &incumbents);
        let mut blocks: Vec<u64> = outcome.selected.iter().map(|(_, rep, _)| *rep).collect();
        blocks.sort_unstable();
        (blocks, outcome)
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
        let (blocks, outcome) = cover(&patterns, &[]);
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
        let (blocks, outcome) = cover(&patterns, &[]);
        assert_eq!(blocks, vec![10, 20]);
        assert!(outcome.pruned_dominated.is_empty());
    }

    /// On a gain tie, the incumbent block wins (churn damping).
    #[test]
    fn incumbent_wins_gain_ties() {
        // Two disjoint equal-size patterns; both must be picked, but the
        // FIRST pick (order) must be the incumbent regardless of block number.
        let patterns: HashMap<u64, PatternRecord> =
            [(1, pat(&[0, 1], 10)), (2, pat(&[2, 3], 99))].into();
        let incumbents: HashSet<u64> = [10].into();
        let outcome = select_cover(&patterns, &incumbents);
        assert_eq!(outcome.selected[0].1, 10, "incumbent must be picked first on a tie");

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
        let (blocks, _) = cover(&patterns, &[]);
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
        let (blocks, outcome) = cover(&patterns, &[]);
        assert_eq!(blocks, vec![20, 30]);
        assert!(outcome.redundant_removed.contains(&10));
        // Coverage is still complete without the removed pick.
        assert_eq!(outcome.covered_counters, outcome.universe_counters);
    }
}
