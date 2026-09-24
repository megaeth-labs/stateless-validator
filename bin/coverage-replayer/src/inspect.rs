//! Read-only store inspection: block/pattern/counter statistics.
//!
//! Unlike every other subcommand, `inspect` skips the binary-id namespace
//! check so a store produced on another machine/build (e.g. copied from the
//! server) can be analyzed locally. It never writes.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
};

use clap::Args;
use eyre::Result;

use crate::{
    bitset::BitSet,
    setcover::select_cover,
    spool::DataDir,
    store::{BlockStatus, PatternRecord, Store, elapsed_stats},
};

#[derive(Args, Debug, Clone)]
pub struct InspectArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// How many top entries to print in rankings.
    #[clap(long, default_value_t = 10)]
    pub top: usize,
    /// Also write the candidate block pool here, in the one-block-per-line
    /// form `backfill --blocks-file` reads.
    ///
    /// The pool is the ANTICHAIN's representatives, not the greedy cover.
    /// The cover is minimal only for the counter universe of the build that
    /// filled this store; a later build splits patterns this one merged, and
    /// a cover carries no slack to absorb that. Everything left out was
    /// strictly dominated — its coverage a subset of a kept block's — which
    /// is the closest available stand-in for "adds nothing" and survives a
    /// rebuild far better. Bitmaps die with the build; block numbers do not.
    #[clap(long)]
    pub dump_pool: Option<PathBuf>,
    /// Skip the antichain statistics and the greedy selection preview. They
    /// run the real set-cover algorithm, which on a full-history store is
    /// about half of this command's time; everything else is a single pass
    /// over the tables. Incompatible with `--dump-pool`, which is made of the
    /// antichain.
    #[clap(long, conflicts_with = "dump_pool")]
    pub no_cover_preview: bool,
    /// With `--dump-pool`, additionally take up to this many other blocks per
    /// antichain pattern. Blocks that share a pattern under this build can
    /// split under another, so a few siblings buy slack against exactly the
    /// case the representative alone would lose.
    #[clap(long, default_value_t = 0)]
    pub pool_siblings: usize,
}

pub fn run(args: InspectArgs) -> Result<()> {
    let dirs = DataDir::new(&args.data_dir);
    let (store, binary_id) = Store::open_readonly(&dirs.store_path())?;
    let patterns = store.patterns()?;

    println!("binary_id: {binary_id}");
    println!();

    // ---- blocks: one streaming pass, folded into totals ----
    let mut total = 0usize;
    let mut ok = 0usize;
    let mut elapsed: Vec<u64> = Vec::new();
    let mut txs = 0u64;
    let mut gas = 0u128;
    let mut quarantined: Vec<(u64, BlockStatus, String)> = Vec::new();
    store.blocks(.., |number, rec| {
        total += 1;
        if rec.status == BlockStatus::Ok {
            ok += 1;
            elapsed.push(rec.elapsed_ms);
            txs += rec.tx_count;
            gas += rec.gas_used as u128;
        } else {
            quarantined.push((number, rec.status, rec.error.unwrap_or_default()));
        }
    })?;
    let divergent = quarantined.iter().filter(|q| q.1 == BlockStatus::Divergent).count();
    let errors = quarantined.len() - divergent;
    println!("blocks: total={total} ok={ok} divergent={divergent} error={errors}");
    if let Some((avg, p50, p95, max)) = elapsed_stats(&mut elapsed) {
        println!("worker elapsed_ms: avg={avg:.0} p50={p50} p95={p95} max={max}");
        println!("txs total={txs}  gas total={gas}");
    }
    drop(elapsed);
    if !quarantined.is_empty() {
        println!("quarantined blocks:");
        for (n, status, error) in &quarantined {
            println!("  {n}: {status:?} {error}");
        }
    }
    println!();

    // ---- patterns ----
    let mut universe = BitSet::new();
    for rec in patterns.values() {
        universe.union_with(&rec.bitmap);
    }
    let universe_bits = universe.count_ones();
    let mut hits: Vec<(&u64, &PatternRecord)> = patterns.iter().collect();
    let singletons = hits.iter().filter(|(_, r)| r.hit_count == 1).count();
    let bits: Vec<u64> = hits.iter().map(|(_, r)| r.bits).collect();
    let (bits_min, bits_max) = (bits.iter().min().copied(), bits.iter().max().copied());
    let bits_avg = bits.iter().sum::<u64>() as f64 / bits.len().max(1) as f64;
    println!(
        "patterns: {} (singletons={} = {:.1}%)  universe={} counters",
        hits.len(),
        singletons,
        100.0 * singletons as f64 / hits.len().max(1) as f64,
        universe_bits,
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
    // Dense indices are contiguous from 0, one per universe item, so a Vec
    // beats a HashMap here.
    let mut coverage_count: Vec<u32> = vec![0; universe_bits as usize];
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
        let mut by_first: Vec<(&PatternRecord, u64)> =
            patterns.values().map(|r| (r, r.first_block)).collect();
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
    if !args.no_cover_preview {
        let outcome = select_cover(&patterns, &Default::default());
        println!();
        println!(
            "antichain: {} of {} patterns are strictly dominated ({:.1}%) — prunable \
             along with their archived profiles",
            outcome.pruned_dominated.len(),
            patterns.len(),
            100.0 * outcome.pruned_dominated.len() as f64 / patterns.len().max(1) as f64
        );
        println!();
        println!("greedy selection preview (matches a real set-cover run, no incumbents):");
        for (key, rep, gain) in &outcome.selected {
            println!("  {rep:>12}  gain={gain:<6} bits={}", patterns[key].bits);
        }
        println!(
            "  => {} blocks cover {}/{}",
            outcome.selected.len(),
            outcome.covered_counters,
            outcome.universe_counters
        );

        if let Some(path) = &args.dump_pool {
            let dominated: HashSet<u64> = outcome.pruned_dominated.iter().copied().collect();
            let siblings = collect_siblings(&store, &patterns, &dominated, args.pool_siblings)?;
            let written =
                write_pool(path, &patterns, &dominated, &siblings, args.pool_siblings, &binary_id)?;
            println!();
            println!("candidate pool: {written} blocks written to {}", path.display());
        }
    }

    // ---- manifest ----
    let manifest_path = dirs.manifest_path();
    if manifest_path.exists() {
        let manifest = crate::setcover::Manifest::read(&manifest_path)?;
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

/// Writes the candidate pool as a block list: `#` comment header carrying
/// provenance, then one decimal block number per line, ascending. Returns
/// how many blocks were written.
///
/// Concatenating several shards' pools and sorting is a valid union: block
/// numbers are machine-stable, and a per-shard antichain is a superset of
/// the global one (a pattern dominated only by one in another shard stays in
/// its own shard's antichain), so the union errs toward keeping blocks.
fn write_pool(
    path: &Path,
    patterns: &HashMap<u64, PatternRecord>,
    dominated: &HashSet<u64>,
    siblings: &HashMap<u64, Vec<u64>>,
    siblings_per_pattern: usize,
    binary_id: &str,
) -> Result<usize> {
    let antichain: Vec<u64> = patterns.keys().copied().filter(|k| !dominated.contains(k)).collect();

    let mut blocks: BTreeSet<u64> = antichain.iter().map(|k| patterns[k].representative).collect();
    blocks.extend(siblings.values().flatten());

    let generated_at = crate::setcover::unix_now();
    let mut out = String::new();
    out.push_str("# coverage-replayer candidate pool (antichain representatives)\n");
    out.push_str(&format!("# binary_id: {binary_id}\n"));
    out.push_str(&format!("# generated_at_unix: {generated_at}\n"));
    out.push_str(&format!(
        "# patterns: {} total, {} antichain, {} dominated\n",
        patterns.len(),
        antichain.len(),
        dominated.len(),
    ));
    out.push_str(&format!("# siblings_per_pattern: {siblings_per_pattern}\n"));
    out.push_str(&format!("# blocks: {}\n", blocks.len()));
    for n in &blocks {
        out.push_str(&format!("{n}\n"));
    }
    crate::spool::write_atomic(path, out.as_bytes())?;
    Ok(blocks.len())
}

/// Up to `per_pattern` blocks of each antichain pattern besides its
/// representative — always the lowest-numbered ones, so a pool does not
/// depend on iteration order. One streaming pass over BLOCKS, holding at most
/// `per_pattern` numbers per pattern; skipped entirely for the default of 0.
fn collect_siblings(
    store: &Store<redb::ReadOnlyDatabase>,
    patterns: &HashMap<u64, PatternRecord>,
    dominated: &HashSet<u64>,
    per_pattern: usize,
) -> Result<HashMap<u64, Vec<u64>>> {
    let mut siblings: HashMap<u64, Vec<u64>> = HashMap::new();
    if per_pattern == 0 {
        return Ok(siblings);
    }
    store.blocks(.., |number, rec| {
        let Some(key) = rec.pattern_key else { return };
        if rec.status != BlockStatus::Ok || dominated.contains(&key) {
            return;
        }
        let Some(pattern) = patterns.get(&key) else { return };
        if pattern.representative == number {
            return;
        }
        // Rows arrive in ascending block order, so the first `per_pattern`
        // seen are the lowest.
        let kept = siblings.entry(key).or_default();
        if kept.len() < per_pattern {
            kept.push(number);
        }
    })?;
    Ok(siblings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        setcover::CoverOutcome,
        store::{BlockRecord, test_support::pattern as pat},
    };

    fn block(pattern_key: u64) -> BlockRecord {
        crate::store::test_support::block(BlockStatus::Ok, Some(pattern_key))
    }

    fn dominated(outcome: &CoverOutcome) -> HashSet<u64> {
        outcome.pruned_dominated.iter().copied().collect()
    }

    /// A, B (equal bits, overlapping) and C, none dominated. Greedy reaches
    /// full coverage with B and C alone, so A's block is exactly the kind the
    /// cover discards and the pool must keep — that gap is the whole reason
    /// the pool is the antichain rather than the manifest.
    fn three_patterns() -> HashMap<u64, PatternRecord> {
        [(1, pat(&[0, 1, 2, 3], 10)), (2, pat(&[0, 1, 2, 4], 20)), (3, pat(&[3, 4], 30))].into()
    }

    #[test]
    fn pool_keeps_the_antichain_block_the_cover_drops() {
        let patterns = three_patterns();
        let outcome = select_cover(&patterns, &Default::default());

        let cover: Vec<u64> = outcome.selected.iter().map(|(_, rep, _)| *rep).collect();
        assert_eq!(cover, vec![20, 30], "greedy reaches full coverage without block 10");
        assert!(outcome.pruned_dominated.is_empty(), "no pattern is dominated here");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.txt");
        let written = write_pool(
            &path,
            &patterns,
            &dominated(&outcome),
            &HashMap::new(),
            0,
            "megaevm:test:fx0",
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let blocks: Vec<u64> =
            text.lines().filter(|l| !l.starts_with('#')).map(|l| l.parse().unwrap()).collect();
        assert_eq!(blocks, vec![10, 20, 30]);
        assert_eq!(written, 3);
        assert!(
            !cover.contains(&10) && blocks.contains(&10),
            "block 10 is the antichain member the cover leaves out"
        );
    }

    /// The header is provenance a pool file carries across a rebuild, and
    /// `backfill --blocks-file` must skip every line of it.
    #[test]
    fn pool_header_records_provenance_and_stays_commented() {
        let patterns = three_patterns();
        let outcome = select_cover(&patterns, &Default::default());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.txt");
        write_pool(
            &path,
            &patterns,
            &dominated(&outcome),
            &HashMap::new(),
            0,
            "megaevm:19f3965962c4:fxdeadbeef",
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# binary_id: megaevm:19f3965962c4:fxdeadbeef"), "{text}");
        assert!(text.contains("# patterns: 3 total, 3 antichain, 0 dominated"), "{text}");
        assert!(text.contains("# siblings_per_pattern: 0"), "{text}");
        assert!(text.contains("# blocks: 3"), "{text}");
        assert!(
            text.lines().take_while(|l| l.starts_with('#')).count() == 6,
            "every header line must be commented: {text}"
        );
    }

    /// `run` end to end over a real redb store: the pool must come out of the
    /// same antichain the dry run computes, and `--no-cover-preview` must
    /// leave the rest of the report working.
    #[test]
    fn run_exports_the_pool_from_a_real_store() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        {
            let store = Store::open(&data_dir.join("store.redb"), "megaevm:test:fx0", "u").unwrap();
            // 10 ⊃ 20 (dominated); 30 is unrelated. Counters 0..=3, dense = id.
            for (block_number, bits) in [(10u64, vec![0u32, 1, 2]), (20, vec![0, 1]), (30, vec![3])]
            {
                let counters: Vec<(u64, crate::store::CounterInfo)> = bits
                    .iter()
                    .map(|&b| {
                        let info = crate::store::CounterInfo {
                            dense: b,
                            location: "s".into(),
                            kind: "h".into(),
                            line: b,
                        };
                        (b as u64, info)
                    })
                    .collect();
                store
                    .commit_block(
                        block_number,
                        &block(block_number),
                        &counters,
                        Some((block_number, &pat(&bits, block_number))),
                    )
                    .unwrap();
            }
            store.flush().unwrap();
        }

        let pool = dir.path().join("pool.txt");
        run(InspectArgs {
            data_dir: data_dir.clone(),
            top: 3,
            dump_pool: Some(pool.clone()),
            pool_siblings: 0,
            no_cover_preview: false,
        })
        .unwrap();
        let blocks: Vec<u64> = std::fs::read_to_string(&pool)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.parse().unwrap())
            .collect();
        assert_eq!(blocks, vec![10, 30], "block 20's pattern is dominated by block 10's");

        run(InspectArgs {
            data_dir,
            top: 3,
            dump_pool: None,
            pool_siblings: 0,
            no_cover_preview: true,
        })
        .unwrap();
    }

    /// Siblings come from a streaming pass over the BLOCKS table of a real
    /// store, and which ones are kept must not depend on anything but the
    /// data — two runs over the same store have to name the same blocks or a
    /// pool stops being reproducible.
    #[test]
    fn pool_siblings_are_the_lowest_and_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("store.redb");
        let patterns = three_patterns();
        {
            let store = Store::open(&store_path, "id", "u").unwrap();
            // Pattern 1 (representative 10) also occurs at 11, 54, 77, 999;
            // pattern 3 (representative 30) at 31 — a second pattern, so the
            // test pins the per-pattern cap rather than one pattern's luck.
            for (number, key) in
                [(999u64, 1u64), (10, 1), (77, 1), (11, 1), (54, 1), (20, 2), (30, 3), (31, 3)]
            {
                store.commit_block(number, &block(key), &[], Some((key, &patterns[&key]))).unwrap();
            }
            store.flush().unwrap();
        }
        let (store, _) = Store::open_readonly(&store_path).unwrap();
        let outcome = select_cover(&patterns, &Default::default());

        let read_pool = |per_pattern: usize, name: &str| -> Vec<u64> {
            let path = dir.path().join(name);
            let dominated = dominated(&outcome);
            let siblings = collect_siblings(&store, &patterns, &dominated, per_pattern).unwrap();
            write_pool(&path, &patterns, &dominated, &siblings, per_pattern, "id").unwrap();
            std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .filter(|l| !l.starts_with('#'))
                .map(|l| l.parse().unwrap())
                .collect()
        };

        assert_eq!(read_pool(0, "a.txt"), vec![10, 20, 30], "0 siblings = representatives only");
        // Two lowest non-representative blocks of pattern 1: 11 and 54.
        assert_eq!(read_pool(2, "b.txt"), vec![10, 11, 20, 30, 31, 54]);
        assert_eq!(read_pool(2, "c.txt"), read_pool(2, "d.txt"), "same store, same pool");
    }
}
