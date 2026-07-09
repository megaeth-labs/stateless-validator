//! Greedy set cover over the stored coverage patterns.
//!
//! Selection is churn-damped: ties are broken in favor of blocks already in
//! the incumbent manifest, then by freshness. A final redundancy-elimination
//! pass drops any selected block whose bitmap is covered by the union of the
//! others.

use std::{collections::HashSet, path::PathBuf};

use clap::Args;
use eyre::{Context, Result};
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
    let dirs = DataDir::new(&args.data_dir)?;
    let binary_id = current_binary_id()?;
    let store = Store::open(&dirs.store_path(), &binary_id)?;
    let snapshot = store.load()?;

    // E3 datapoint: worker wall-clock per successfully replayed block.
    {
        let mut v: Vec<u64> = snapshot
            .blocks
            .values()
            .filter(|b| matches!(b.status, crate::store::BlockStatus::Ok))
            .map(|b| b.elapsed_ms)
            .collect();
        if !v.is_empty() {
            v.sort_unstable();
            let avg = v.iter().sum::<u64>() as f64 / v.len() as f64;
            info!(
                blocks = v.len(),
                avg_ms = %format!("{avg:.0}"),
                p50_ms = v[v.len() / 2],
                p95_ms = v[(v.len() * 95 / 100).min(v.len() - 1)],
                max_ms = v[v.len() - 1],
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

    // Candidates: (pattern_key, record). Universe = union of all patterns.
    let mut universe = BitSet::new();
    for rec in snapshot.patterns.values() {
        universe.union_with(&rec.bitmap);
    }
    let universe_counters = universe.count_ones();
    info!(
        patterns = snapshot.patterns.len(),
        universe = universe_counters,
        incumbents = incumbents.len(),
        "computing greedy set cover"
    );

    let mut covered = BitSet::new();
    let mut remaining: Vec<(&u64, &crate::store::PatternRecord)> =
        snapshot.patterns.iter().collect();

    // Antichain prune: dominated patterns can never improve the cover, and a
    // dominated pattern could otherwise win a gain tie-break and select a
    // block whose profile was never archived. Their archived profiles (from
    // before the dominator appeared) are deleted here.
    remaining.sort_by_key(|(_, r)| std::cmp::Reverse(r.bits));
    let mut keep = vec![true; remaining.len()];
    for i in 0..remaining.len() {
        for j in 0..i {
            if keep[j] &&
                remaining[j].1.bits > remaining[i].1.bits &&
                remaining[i].1.bitmap.is_subset_of(&remaining[j].1.bitmap)
            {
                keep[i] = false;
                let _ = std::fs::remove_file(dirs.archived_profile(*remaining[i].0));
                break;
            }
        }
    }
    let before = remaining.len();
    let mut it = keep.iter();
    remaining.retain(|_| *it.next().unwrap());
    info!(
        pruned = before - remaining.len(),
        antichain = remaining.len(),
        "dominated patterns excluded (their archived profiles deleted)"
    );
    let mut selected: Vec<(u64, u64, u64)> = Vec::new(); // (pattern_key, representative, gain)

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

    // Redundancy elimination: drop blocks fully covered by the union of the rest.
    let mut pruned = true;
    while pruned {
        pruned = false;
        for i in 0..selected.len() {
            let mut others = BitSet::new();
            for (j, (key, _, _)) in selected.iter().enumerate() {
                if i != j {
                    others.union_with(&snapshot.patterns[key].bitmap);
                }
            }
            let (key, rep, _) = selected[i];
            if snapshot.patterns[&key].bitmap.is_subset_of(&others) {
                info!(block = rep, "redundant after later picks, removing");
                selected.remove(i);
                pruned = true;
                break;
            }
        }
    }

    let covered_counters = covered.count_ones();
    let blocks: Vec<ManifestBlock> = selected
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
