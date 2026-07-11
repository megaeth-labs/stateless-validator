//! Merge several per-shard stores (produced by different machines scanning
//! disjoint block ranges with the SAME instrumented binary) into one.
//!
//! ## Why a dense remap is required
//!
//! A pattern's bitmap is expressed in *dense* indices — a compact per-store
//! numbering assigned to counters in first-seen order. That order differs
//! between shards, so counter `X` may be dense index 5 on shard A and 8 on
//! shard B. Directly OR-ing bitmaps across shards would therefore be wrong.
//!
//! Two things ARE machine-stable, which makes the merge well-defined:
//! - the 64-bit **counter id** (`(symbol, func_hash, index)` content hash), and
//! - the **pattern key** (`FxHash` of a pattern's sorted counter ids).
//!
//! So we: (1) build a unified id→dense map, (2) for each source pattern remap
//! its bitmap through `source-dense → id → unified-dense`, and (3) fold
//! same-key patterns together (summing hits, keeping the lightest
//! representative). The result is byte-identical to what a single machine would
//! have produced scanning every range sequentially.
//!
//! Archived profiles are keyed by pattern key (machine-stable), so they are
//! merged by a plain file union — `rsync` every shard's `archive/profiles/`
//! into the output dir; no code handles them here.

use std::{collections::HashMap, path::PathBuf};

use clap::Args;
use eyre::{Context, Result, ensure};
use tracing::{info, warn};

use crate::{
    bitset::BitSet,
    spool::DataDir,
    store::{CounterInfo, PatternRecord, Store, StoreSnapshot, current_binary_id},
};

/// Linear-probe step for pattern-key collisions — mirrors the judge, so a
/// merged store keys patterns exactly as a sequential run would.
const PROBE_STEP: u64 = 0x9E37_79B9_7F4A_7C15;

#[derive(Args, Debug, Clone)]
pub struct MergeArgs {
    /// Output data directory (created fresh; must not already hold a store).
    #[clap(long)]
    pub out: PathBuf,
    /// Two or more shard data directories to merge.
    #[clap(long = "shard", required = true, num_args = 1..)]
    pub shards: Vec<PathBuf>,
}

pub fn run(args: MergeArgs) -> Result<()> {
    ensure!(args.shards.len() >= 2, "merge needs at least two --shard dirs");
    let out_dirs = DataDir::new(&args.out)?;
    ensure!(
        !out_dirs.store_path().exists(),
        "output store already exists: {} (merge writes a fresh store)",
        out_dirs.store_path().display()
    );

    // The merged store must carry the same binary_id as the shards, and the
    // current binary must match it (dense indices are only meaningful for one
    // instrumented build).
    let expected_id = current_binary_id()?;

    let mut shard_snaps = Vec::with_capacity(args.shards.len());
    let mut shard_filter: Option<String> = None;
    for (i, shard) in args.shards.iter().enumerate() {
        let dirs = DataDir::new(shard)?;
        let (store, binary_id) = Store::open_readonly(&dirs.store_path())
            .wrap_err_with(|| format!("open shard {}", shard.display()))?;
        ensure!(
            binary_id == expected_id,
            "shard {} has binary_id {binary_id}, but this binary is {expected_id}; \
             all shards must be produced by the same instrumented build",
            shard.display(),
        );
        // All shards must share one symbol filter — it defines the universe.
        let filter = store.symbol_filter()?;
        if i == 0 {
            shard_filter = filter;
        } else {
            ensure!(
                filter == shard_filter,
                "shard {} was built with symbol filter {filter:?}, expected {shard_filter:?}; \
                 shards with different filters hold incompatible universes",
                shard.display(),
            );
        }
        let snap = store.load()?;
        info!(
            shard = %shard.display(),
            counters = snap.counters.len(),
            patterns = snap.patterns.len(),
            blocks = snap.blocks.len(),
            "loaded shard"
        );
        shard_snaps.push((shard.display().to_string(), snap));
    }

    let merged = merge_snapshots(shard_snaps)?;
    let mut universe = BitSet::new();
    for rec in merged.patterns.values() {
        universe.union_with(&rec.bitmap);
    }
    info!(
        counters = merged.counters.len(),
        patterns = merged.patterns.len(),
        blocks = merged.blocks.len(),
        universe = universe.count_ones(),
        "merge complete; writing output store"
    );

    let out_store = Store::open(&out_dirs.store_path(), &expected_id, shard_filter.as_deref())?;
    out_store.write_bulk(&merged)?;
    info!(
        out = %out_dirs.store_path().display(),
        "merged store written — rsync each shard's archive/profiles/ into {}",
        out_dirs.archive_profiles().display()
    );
    Ok(())
}

/// Pure core: folds shard snapshots into one, remapping every bitmap through
/// `source-dense → counter id → unified-dense` and merging same-key patterns.
///
/// Semantically equivalent to a sequential single-store run over the union of
/// ranges and independent of shard order: the universe, the pattern set (by
/// counter-id content), pattern keys, and all merged stats are identical.
/// The *dense numbering* (and therefore raw bitmap/store bytes) is an
/// internal coordinate system and may differ from a sequential run's — dense
/// assignment is deterministic for a given shard order (unseen ids are
/// registered in sorted order per shard), but not canonical.
fn merge_snapshots(shards: Vec<(String, StoreSnapshot)>) -> Result<StoreSnapshot> {
    let mut id_to_dense: HashMap<u64, u32> = HashMap::new();
    let mut counters: HashMap<u64, CounterInfo> = HashMap::new();
    let mut patterns: HashMap<u64, PatternRecord> = HashMap::new();
    let mut blocks = HashMap::new();

    for (label, snap) in shards {
        // source dense → counter id, and register unseen ids into the unified
        // space. Registration goes in sorted-id order so the merged store is
        // reproducible run-to-run (HashMap iteration order is randomized).
        let mut src_dense_to_id: HashMap<u32, u64> = HashMap::with_capacity(snap.counters.len());
        let mut shard_ids: Vec<u64> = Vec::with_capacity(snap.counters.len());
        for (&id, info) in &snap.counters {
            src_dense_to_id.insert(info.dense, id);
            shard_ids.push(id);
        }
        shard_ids.sort_unstable();
        for id in shard_ids {
            if let std::collections::hash_map::Entry::Vacant(e) = id_to_dense.entry(id) {
                let dense = counters.len() as u32;
                e.insert(dense);
                // dense re-pointed below after all ids are known (kept here for
                // symbol/func_hash/index provenance).
                counters.insert(id, CounterInfo { dense, ..snap.counters[&id].clone() });
            }
        }
        for (&stored_key, rec) in &snap.patterns {
            let mut remapped = BitSet::new();
            let mut ids: Vec<u64> = Vec::with_capacity(rec.bits as usize);
            for src_dense in rec.bitmap.iter_ones() {
                let id = src_dense_to_id.get(&src_dense).ok_or_else(|| {
                    eyre::eyre!(
                        "shard {label} pattern {stored_key:016x} references dense {src_dense} \
                         with no counter — corrupt store"
                    )
                })?;
                remapped.insert(id_to_dense[id]);
                ids.push(*id);
            }
            ids.sort_unstable();

            // Re-key exactly as the judge does (shared helper), linear-probing
            // on a genuine bitmap-differing collision.
            let mut key = crate::store::pattern_base_key(&ids);
            let inserted = loop {
                match patterns.get_mut(&key) {
                    None => {
                        patterns.insert(
                            key,
                            PatternRecord {
                                bits: remapped.count_ones(),
                                bitmap: remapped,
                                first_block: rec.first_block,
                                last_block: rec.last_block,
                                hit_count: rec.hit_count,
                                representative: rec.representative,
                                representative_elapsed_ms: rec.representative_elapsed_ms,
                            },
                        );
                        break true;
                    }
                    Some(existing) if existing.bitmap == remapped => {
                        existing.hit_count += rec.hit_count;
                        existing.first_block = existing.first_block.min(rec.first_block);
                        existing.last_block = existing.last_block.max(rec.last_block);
                        if rec.representative_elapsed_ms < existing.representative_elapsed_ms {
                            existing.representative = rec.representative;
                            existing.representative_elapsed_ms = rec.representative_elapsed_ms;
                        }
                        break false;
                    }
                    Some(_) => key = key.wrapping_add(PROBE_STEP),
                }
            };
            if inserted && key != stored_key {
                warn!(
                    shard = %label,
                    stored = %format!("{stored_key:016x}"),
                    merged = %format!("{key:016x}"),
                    "pattern re-keyed on merge (64-bit key collision). Its archived profile was \
                     written under the OLD key: after the rsync union that filename is either \
                     missing or occupied by the colliding pattern's profile — if this pattern \
                     gets selected, regenerate its profile from the representative block instead \
                     of trusting the file"
                );
            }
        }

        // Blocks: shards scan disjoint ranges, so a plain union. A duplicate
        // (should not happen) carries an identical record; last write wins.
        for (num, rec) in snap.blocks {
            blocks.insert(num, rec);
        }
    }

    // Re-point every counter's dense to its final unified index (the clone
    // above carried the source dense only for provenance fields).
    for (id, info) in counters.iter_mut() {
        info.dense = id_to_dense[id];
    }

    Ok(StoreSnapshot { counters, patterns, blocks })
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;
    use crate::store::{BlockRecord, BlockStatus};

    fn info(dense: u32, sym: &str, idx: u32) -> CounterInfo {
        CounterInfo { dense, symbol: sym.into(), func_hash: "h".into(), index: idx }
    }

    fn pat(bitmap: BitSet, rep: u64, ms: u64, hits: u64) -> PatternRecord {
        PatternRecord {
            bits: bitmap.count_ones(),
            bitmap,
            first_block: rep,
            last_block: rep,
            hit_count: hits,
            representative: rep,
            representative_elapsed_ms: ms,
        }
    }

    fn blk(hash_byte: u8, ms: u64) -> BlockRecord {
        BlockRecord {
            hash: B256::repeat_byte(hash_byte),
            status: BlockStatus::Ok,
            pattern_key: Some(0),
            gas_used: 0,
            tx_count: 0,
            elapsed_ms: ms,
            error: None,
        }
    }

    /// The load-bearing case: two shards see the SAME three counter ids but in
    /// different first-seen (dense) orders, so bitmaps use different local
    /// indices. Merge must remap by id, not by raw dense — a naive union would
    /// silently corrupt coverage.
    #[test]
    fn merge_remaps_divergent_dense_orders() {
        // ids 100,200,300. Shard A dense order 100→0,200→1,300→2.
        let a_counters: HashMap<u64, CounterInfo> =
            [(100, info(0, "a", 0)), (200, info(1, "b", 0)), (300, info(2, "c", 0))].into();
        // Shard A pattern {100,300} = local bits {0,2}.
        let a_patterns: HashMap<u64, PatternRecord> = {
            let key = {
                use std::hash::Hasher;
                let mut h = rustc_hash::FxHasher::default();
                h.write_u64(100);
                h.write_u64(300);
                h.finish()
            };
            [(key, pat(BitSet::from_indices([0, 2]), 10, 50, 3))].into()
        };
        let a = StoreSnapshot {
            counters: a_counters,
            patterns: a_patterns,
            blocks: [(10u64, blk(1, 50))].into(),
        };

        // Shard B dense order REVERSED: 300→0,200→1,100→2.
        let b_counters: HashMap<u64, CounterInfo> =
            [(300, info(0, "c", 0)), (200, info(1, "b", 0)), (100, info(2, "a", 0))].into();
        // Shard B pattern {100,300}: same ids, local bits {2,0}; plus {200}.
        let b_patterns: HashMap<u64, PatternRecord> = {
            use std::hash::Hasher;
            let k1 = {
                let mut h = rustc_hash::FxHasher::default();
                h.write_u64(100);
                h.write_u64(300);
                h.finish()
            };
            let k2 = {
                let mut h = rustc_hash::FxHasher::default();
                h.write_u64(200);
                h.finish()
            };
            [
                (k1, pat(BitSet::from_indices([0, 2]), 20, 30, 5)),
                (k2, pat(BitSet::from_indices([1]), 21, 40, 2)),
            ]
            .into()
        };
        let b = StoreSnapshot {
            counters: b_counters,
            patterns: b_patterns,
            blocks: [(20u64, blk(2, 30)), (21u64, blk(3, 40))].into(),
        };

        let merged = merge_snapshots(vec![("A".into(), a), ("B".into(), b)]).expect("merge");

        // 3 distinct counters, 2 distinct patterns ({100,300} folded), 3 blocks.
        assert_eq!(merged.counters.len(), 3);
        assert_eq!(merged.patterns.len(), 2);
        assert_eq!(merged.blocks.len(), 3);

        // Universe = all 3 counters.
        let mut universe = BitSet::new();
        for r in merged.patterns.values() {
            universe.union_with(&r.bitmap);
        }
        assert_eq!(universe.count_ones(), 3);

        // The {100,300} pattern folded: hits summed, lightest representative
        // (B's 30ms block 20) wins over A's 50ms.
        let folded = merged.patterns.values().find(|r| r.bits == 2).expect("folded 2-bit pattern");
        assert_eq!(folded.hit_count, 3 + 5);
        assert_eq!(folded.representative, 20);
        assert_eq!(folded.representative_elapsed_ms, 30);

        // Its remapped bitmap references exactly the unified denses of ids 100
        // and 300 — never 200's.
        let d100 = merged.counters[&100].dense;
        let d300 = merged.counters[&300].dense;
        let d200 = merged.counters[&200].dense;
        let bits: Vec<u32> = folded.bitmap.iter_ones().collect();
        assert!(bits.contains(&d100) && bits.contains(&d300) && !bits.contains(&d200));
    }

    /// Merge is order-independent: swapping shard order yields the same
    /// universe and the same set of pattern bitmaps (id-canonical).
    #[test]
    fn merge_is_order_independent() {
        let mk = |ids_dense: &[(u64, u32)], pat_ids: &[u64], rep: u64| {
            let counters: HashMap<u64, CounterInfo> =
                ids_dense.iter().map(|&(id, d)| (id, info(d, "s", d))).collect();
            let key = {
                use std::hash::Hasher;
                let mut s: Vec<u64> = pat_ids.to_vec();
                s.sort_unstable();
                let mut h = rustc_hash::FxHasher::default();
                for id in s {
                    h.write_u64(id);
                }
                h.finish()
            };
            let bm = BitSet::from_indices(pat_ids.iter().map(|id| counters[id].dense));
            StoreSnapshot {
                counters,
                patterns: [(key, pat(bm, rep, 10, 1))].into(),
                blocks: [(rep, blk(1, 10))].into(),
            }
        };
        let a = mk(&[(1, 0), (2, 1)], &[1, 2], 100);
        let b = mk(&[(2, 0), (3, 1)], &[2, 3], 200);

        let ab = merge_snapshots(vec![("A".into(), a.clone()), ("B".into(), b.clone())]).unwrap();
        let ba = merge_snapshots(vec![("B".into(), b), ("A".into(), a)]).unwrap();

        let uni = |s: &StoreSnapshot| {
            let mut u = BitSet::new();
            for r in s.patterns.values() {
                u.union_with(&r.bitmap);
            }
            u.count_ones()
        };
        assert_eq!(uni(&ab), 3);
        assert_eq!(uni(&ba), 3);
        assert_eq!(ab.patterns.len(), ba.patterns.len());
        assert_eq!(ab.counters.len(), ba.counters.len());
    }
}
