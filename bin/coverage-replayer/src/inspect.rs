//! Read-only store inspection: block/pattern/counter statistics.
//!
//! Unlike every other subcommand, `inspect` skips the binary-id namespace
//! check so a store produced on another machine/build (e.g. copied from the
//! server) can be analyzed locally. It never writes.

use std::{collections::HashMap, path::PathBuf};

use clap::Args;
use eyre::Result;

use crate::{
    bitset::BitSet,
    spool::DataDir,
    store::{BlockStatus, Store},
};

#[derive(Args, Debug, Clone)]
pub struct InspectArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// How many top entries to print in rankings.
    #[clap(long, default_value_t = 10)]
    pub top: usize,
}

pub fn run(args: InspectArgs) -> Result<()> {
    let dirs = DataDir::new(&args.data_dir)?;
    let (store, binary_id) = Store::open_readonly(&dirs.store_path())?;
    let snapshot = store.load()?;

    println!("binary_id: {binary_id}");
    println!();

    // ---- blocks ----
    let total = snapshot.blocks.len();
    let mut ok = 0usize;
    let mut divergent = 0usize;
    let mut errors = 0usize;
    let mut elapsed: Vec<u64> = Vec::with_capacity(total);
    let mut txs = 0u64;
    let mut gas = 0u128;
    for rec in snapshot.blocks.values() {
        match rec.status {
            BlockStatus::Ok => {
                ok += 1;
                elapsed.push(rec.elapsed_ms);
                txs += rec.tx_count;
                gas += rec.gas_used as u128;
            }
            BlockStatus::Divergent => divergent += 1,
            BlockStatus::Error => errors += 1,
        }
    }
    elapsed.sort_unstable();
    println!("blocks: total={total} ok={ok} divergent={divergent} error={errors}");
    if !elapsed.is_empty() {
        let avg = elapsed.iter().sum::<u64>() as f64 / elapsed.len() as f64;
        println!(
            "worker elapsed_ms: avg={avg:.0} p50={} p95={} max={}",
            elapsed[elapsed.len() / 2],
            elapsed[(elapsed.len() * 95 / 100).min(elapsed.len() - 1)],
            elapsed[elapsed.len() - 1],
        );
        println!("txs total={txs}  gas total={gas}");
    }
    if errors > 0 || divergent > 0 {
        println!("quarantined blocks:");
        for (n, rec) in &snapshot.blocks {
            if rec.status != BlockStatus::Ok {
                println!("  {n}: {:?} {}", rec.status, rec.error.as_deref().unwrap_or(""));
            }
        }
    }
    println!();

    // ---- patterns ----
    let mut universe = BitSet::new();
    for rec in snapshot.patterns.values() {
        universe.union_with(&rec.bitmap);
    }
    let universe_bits = universe.count_ones();
    let mut hits: Vec<(&u64, &crate::store::PatternRecord)> = snapshot.patterns.iter().collect();
    let singletons = hits.iter().filter(|(_, r)| r.hit_count == 1).count();
    let bits: Vec<u64> = hits.iter().map(|(_, r)| r.bits).collect();
    let (bits_min, bits_max) = (bits.iter().min().copied(), bits.iter().max().copied());
    let bits_avg = bits.iter().sum::<u64>() as f64 / bits.len().max(1) as f64;
    println!(
        "patterns: {} (singletons={} = {:.1}%)  universe={} counters (of {} ever seen)",
        hits.len(),
        singletons,
        100.0 * singletons as f64 / hits.len().max(1) as f64,
        universe_bits,
        snapshot.counters.len(),
    );
    println!(
        "pattern bits: min={} avg={bits_avg:.0} max={}",
        bits_min.unwrap_or(0),
        bits_max.unwrap_or(0)
    );

    hits.sort_by_key(|(_, r)| std::cmp::Reverse(r.hit_count));
    println!("top {} patterns by hit_count:", args.top);
    for (key, rec) in hits.iter().take(args.top) {
        println!(
            "  {key:016x}  hits={:<6} bits={:<6} representative={} ({}..={})",
            rec.hit_count, rec.bits, rec.representative, rec.first_block, rec.last_block
        );
    }
    println!();

    // ---- counter rarity: how fragile is the universe? ----
    let mut coverage_count: HashMap<u32, u32> = HashMap::new();
    for (_, rec) in &hits {
        // Recover dense indices from the bitmap words.
        for (word_idx, _) in rec.bitmap.words().iter().enumerate() {
            let word = rec.bitmap.words()[word_idx];
            let mut w = word;
            while w != 0 {
                let bit = w.trailing_zeros();
                *coverage_count.entry((word_idx as u32) * 64 + bit).or_default() += 1;
                w &= w - 1;
            }
        }
    }
    let rare1 = coverage_count.values().filter(|&&c| c == 1).count();
    let rare2 = coverage_count.values().filter(|&&c| c <= 2).count();
    println!(
        "counter rarity: covered-by-exactly-1-pattern={rare1} ({:.1}% of universe), <=2 patterns={rare2}",
        100.0 * rare1 as f64 / universe_bits.max(1) as f64
    );

    // ---- growth curve: patterns & universe by first-seen block ----
    {
        let mut by_first: Vec<(&crate::store::PatternRecord, u64)> =
            snapshot.patterns.values().map(|r| (r, r.first_block)).collect();
        by_first.sort_by_key(|(_, fb)| *fb);
        if let (Some((_, lo)), Some((_, hi))) = (by_first.first(), by_first.last()) {
            let (lo, hi) = (*lo, (*hi).max(lo + 1));
            let buckets = 10u64;
            let width = (hi - lo).div_ceil(buckets);
            println!();
            println!("growth by first-seen block ({buckets} buckets of {width} blocks):");
            let mut cum = BitSet::new();
            let mut idx = 0usize;
            for b in 0..buckets {
                let end = lo + width * (b + 1);
                let mut new_patterns = 0u64;
                while idx < by_first.len() && by_first[idx].1 < end {
                    cum.union_with(&by_first[idx].0.bitmap);
                    new_patterns += 1;
                    idx += 1;
                }
                println!(
                    "  ..{end:>10}: +{new_patterns:<5} patterns, universe={}",
                    cum.count_ones()
                );
            }
        }
    }

    // ---- antichain estimate: how many patterns survive dominated-pruning? ----
    {
        let mut recs: Vec<&crate::store::PatternRecord> = snapshot.patterns.values().collect();
        // A pattern can only be dominated by one with >= bits; sort desc so we
        // scan potential dominators first and can stop early.
        recs.sort_by_key(|r| std::cmp::Reverse(r.bits));
        let mut dominated = 0usize;
        for i in 0..recs.len() {
            for j in 0..i {
                if recs[j].bits > recs[i].bits && recs[i].bitmap.is_subset_of(&recs[j].bitmap) {
                    dominated += 1;
                    break;
                }
            }
        }
        println!();
        println!(
            "antichain estimate: {} of {} patterns are strictly dominated ({:.1}%) — prunable \
             along with their archived profiles",
            dominated,
            recs.len(),
            100.0 * dominated as f64 / recs.len().max(1) as f64
        );
    }

    // ---- greedy set cover (read-only preview, same tie-breaking as set-cover) ----
    {
        let mut covered = BitSet::new();
        let mut remaining: Vec<(&u64, &crate::store::PatternRecord)> =
            snapshot.patterns.iter().collect();
        let mut picks = 0usize;
        println!();
        println!("greedy selection preview:");
        loop {
            let mut best: Option<(u64, u64, usize)> = None; // (gain, block, idx)
            for (i, (_, rec)) in remaining.iter().enumerate() {
                let gain = rec.bitmap.andnot_count(&covered);
                if gain > 0 && best.is_none_or(|b| (gain, rec.representative) > (b.0, b.1)) {
                    best = Some((gain, rec.representative, i));
                }
            }
            let Some((gain, block, i)) = best else { break };
            let (_, rec) = remaining.swap_remove(i);
            covered.union_with(&rec.bitmap);
            picks += 1;
            println!("  {block:>12}  gain={gain:<6} bits={}", rec.bits);
        }
        println!("  => {picks} blocks cover {}/{}", covered.count_ones(), universe_bits);
    }

    // ---- manifest ----
    let manifest_path = dirs.manifest_path();
    if manifest_path.exists() {
        let manifest: crate::setcover::Manifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
        println!();
        println!(
            "manifest: {} blocks cover {}/{} counters (generated_at_unix={})",
            manifest.blocks.len(),
            manifest.covered_counters,
            manifest.universe_counters,
            manifest.generated_at_unix
        );
    }
    Ok(())
}
