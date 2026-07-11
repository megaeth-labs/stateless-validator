//! Read-only store inspection: block/pattern/counter statistics.
//!
//! Unlike every other subcommand, `inspect` skips the binary-id namespace
//! check so a store produced on another machine/build (e.g. copied from the
//! server) can be analyzed locally. It never writes.

use std::path::PathBuf;

use clap::Args;
use eyre::Result;

use crate::{
    bitset::BitSet,
    setcover::select_cover,
    spool::DataDir,
    store::{BlockStatus, Store, elapsed_stats},
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
    let dirs = DataDir::new(&args.data_dir);
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
    println!("blocks: total={total} ok={ok} divergent={divergent} error={errors}");
    if let Some((avg, p50, p95, max)) = elapsed_stats(&mut elapsed) {
        println!("worker elapsed_ms: avg={avg:.0} p50={p50} p95={p95} max={max}");
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
    // Dense indices are contiguous, so a Vec beats a HashMap here.
    let mut coverage_count: Vec<u32> = vec![0; snapshot.counters.len()];
    for (_, rec) in &hits {
        for dense in rec.bitmap.iter_ones() {
            if let Some(c) = coverage_count.get_mut(dense as usize) {
                *c += 1;
            }
        }
    }
    let rare1 = coverage_count.iter().filter(|&&c| c == 1).count();
    let rare2 = coverage_count.iter().filter(|&&c| c > 0 && c <= 2).count();
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
                // The last bucket takes everything left: with `(hi - lo)` an
                // exact multiple of the bucket count, `end == hi` and a
                // strict `<` would silently drop the patterns first seen at
                // `hi` (at least one always exists).
                let last = b + 1 == buckets;
                let end = lo + width * (b + 1);
                let mut new_patterns = 0u64;
                while idx < by_first.len() && (last || by_first[idx].1 < end) {
                    cum.union_with(&by_first[idx].0.bitmap);
                    new_patterns += 1;
                    idx += 1;
                }
                println!(
                    "  ..{:>10}: +{new_patterns:<5} patterns, universe={}",
                    end.min(hi),
                    cum.count_ones()
                );
            }
        }
    }

    // ---- set-cover dry run: THE algorithm (select_cover), not a copy — the
    // antichain count and the selection preview cannot drift from a real
    // `set-cover` run (no incumbents, and no fs side effects here).
    {
        let outcome = select_cover(&snapshot.patterns, &Default::default());
        println!();
        println!(
            "antichain: {} of {} patterns are strictly dominated ({:.1}%) — prunable \
             along with their archived profiles",
            outcome.pruned_dominated.len(),
            snapshot.patterns.len(),
            100.0 * outcome.pruned_dominated.len() as f64 / snapshot.patterns.len().max(1) as f64
        );
        println!();
        println!("greedy selection preview (matches a real set-cover run, no incumbents):");
        for (key, rep, gain) in &outcome.selected {
            println!("  {rep:>12}  gain={gain:<6} bits={}", snapshot.patterns[key].bits);
        }
        println!(
            "  => {} blocks cover {}/{}",
            outcome.selected.len(),
            outcome.covered_counters,
            outcome.universe_counters
        );
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
