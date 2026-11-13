//! Read-only store inspection: block/pattern/counter statistics. Unlike every other subcommand
//! it skips the binary-id check, so another build's store can be analyzed. It never writes.

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use clap::Args;
use eyre::Result;

use crate::{
    setcover::{antichain, select_cover, universe_size},
    spool::DataDir,
    store::{BlockStatus, ElapsedStats, PatternRecord, Store},
};

#[derive(Args, Debug, Clone)]
pub struct InspectArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// How many top entries to print in rankings.
    #[clap(long, default_value_t = 10)]
    pub top: usize,
    /// Also write the candidate block pool here, in the form `backfill --blocks-file` reads.
    ///
    /// The pool is the ANTICHAIN's representatives, not the greedy cover: a cover is minimal
    /// only for this build's universe and has no slack when a later build splits patterns this
    /// one merged. Only strictly dominated patterns are left out.
    #[clap(long)]
    pub dump_pool: Option<PathBuf>,
    /// Skip the antichain statistics and the greedy selection preview (they run the real
    /// set-cover).
    #[clap(long)]
    pub no_cover_preview: bool,
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
    let mut elapsed = ElapsedStats::default();
    let mut txs = 0u64;
    let mut gas = 0u128;
    let mut quarantined: Vec<(u64, BlockStatus, String)> = Vec::new();
    store.blocks(.., |number, rec| {
        total += 1;
        if rec.status == BlockStatus::Ok {
            ok += 1;
            elapsed.record(rec.elapsed_ms);
            txs += rec.tx_count;
            gas += rec.gas_used as u128;
        } else {
            quarantined.push((number, rec.status, rec.error.unwrap_or_default()));
        }
    })?;
    let divergent = quarantined.iter().filter(|q| q.1 == BlockStatus::Divergent).count();
    let errors = quarantined.len() - divergent;
    println!("blocks: total={total} ok={ok} divergent={divergent} error={errors}");
    if let Some((avg, p50, p95, max)) = elapsed.summary() {
        println!("worker elapsed_ms: avg={avg:.0} p50={p50} p95={p95} max={max}");
        println!("txs total={txs}  gas total={gas}");
    }
    if !quarantined.is_empty() {
        println!("quarantined blocks:");
        for (n, status, error) in &quarantined {
            println!("  {n}: {status:?} {error}");
        }
    }
    println!();

    // ---- patterns ----
    let universe_bits = universe_size(&patterns);
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

    // ---- set-cover dry run: `select_cover` itself, so it cannot drift from `set-cover` ----
    let mut preview_antichain = None;
    if !args.no_cover_preview {
        let outcome = select_cover(&patterns);
        let dominated = patterns.len() - outcome.antichain.len();
        println!();
        println!(
            "antichain: {dominated} of {} patterns are strictly dominated ({:.1}%) — never cover \
             candidates",
            patterns.len(),
            100.0 * dominated as f64 / patterns.len().max(1) as f64
        );
        println!();
        println!("greedy selection preview (matches a real set-cover run):");
        for (key, rep, gain) in &outcome.selected {
            println!("  {rep:>12}  gain={gain:<6} bits={}", patterns[key].bits);
        }
        println!(
            "  => {} blocks cover all {} counters",
            outcome.selected.len(),
            outcome.universe_counters
        );
        preview_antichain = Some(outcome.antichain);
    }

    if let Some(path) = &args.dump_pool {
        let antichain = preview_antichain.unwrap_or_else(|| antichain(&patterns));
        let written = write_pool(path, &patterns, &antichain, &binary_id)?;
        println!();
        println!("candidate pool: {written} blocks written to {}", path.display());
    }

    // ---- manifest ----
    let manifest_path = dirs.manifest_path();
    if manifest_path.exists() {
        let manifest = crate::setcover::Manifest::read(&manifest_path)?;
        println!();
        println!(
            "manifest: {} blocks cover {} counters (generated_at_unix={})",
            manifest.blocks.len(),
            manifest.universe_counters,
            manifest.generated_at_unix
        );
    }
    Ok(())
}

/// Writes the pool: a `#` provenance header, then one block number per line, ascending.
/// Returns the block count. Several shards' pools concatenate into a valid union: a per-shard
/// antichain is a superset of the global one, so the union errs toward keeping blocks.
fn write_pool(
    path: &Path,
    patterns: &HashMap<u64, PatternRecord>,
    antichain: &[u64],
    binary_id: &str,
) -> Result<usize> {
    let blocks: BTreeSet<u64> = antichain.iter().map(|k| patterns[k].representative).collect();

    let generated_at = crate::setcover::unix_now();
    let mut out = String::new();
    out.push_str("# coverage-replayer candidate pool (antichain representatives)\n");
    out.push_str(&format!("# binary_id: {binary_id}\n"));
    out.push_str(&format!("# generated_at_unix: {generated_at}\n"));
    out.push_str(&format!(
        "# patterns: {} total, {} antichain, {} dominated\n",
        patterns.len(),
        antichain.len(),
        patterns.len() - antichain.len(),
    ));
    out.push_str(&format!("# blocks: {}\n", blocks.len()));
    for n in &blocks {
        out.push_str(&format!("{n}\n"));
    }
    stateless_common::atomic_write::write_atomic(path, out.as_bytes())?;
    Ok(blocks.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        BlockRecord,
        test_support::{pattern as pat, temp_store},
    };

    fn block(pattern_key: u64) -> BlockRecord {
        crate::store::test_support::block(BlockStatus::Ok, Some(pattern_key))
    }

    /// A, B (equal bits, overlapping) and C, none dominated: greedy covers all with B and C,
    /// so A's block is one the cover discards and the pool must keep.
    fn three_patterns() -> HashMap<u64, PatternRecord> {
        [(1, pat(&[0, 1, 2, 3], 10)), (2, pat(&[0, 1, 2, 4], 20)), (3, pat(&[3, 4], 30))].into()
    }

    #[test]
    fn pool_keeps_the_antichain_block_the_cover_drops() {
        let patterns = three_patterns();
        let outcome = select_cover(&patterns);

        let cover: Vec<u64> = outcome.selected.iter().map(|(_, rep, _)| *rep).collect();
        assert_eq!(cover, vec![20, 30], "greedy reaches full coverage without block 10");
        assert_eq!(outcome.antichain.len(), patterns.len(), "no pattern is dominated here");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.txt");
        let written = write_pool(&path, &patterns, &outcome.antichain, "megaevm:test:fx0").unwrap();

        // Read back through the reader `backfill --blocks-file` uses: the format contract.
        let blocks = stateless_common::block_list::read_block_list(&path).unwrap();
        assert_eq!(blocks, vec![10, 20, 30]);
        assert_eq!(written, 3);
        assert!(
            !cover.contains(&10) && blocks.contains(&10),
            "block 10 is the antichain member the cover leaves out"
        );
    }

    /// Every provenance header line must be a comment `backfill --blocks-file` skips.
    #[test]
    fn pool_header_records_provenance_and_stays_commented() {
        let patterns = three_patterns();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.txt");
        write_pool(&path, &patterns, &antichain(&patterns), "megaevm:19f3965962c4:fxdeadbeef")
            .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# binary_id: megaevm:19f3965962c4:fxdeadbeef"), "{text}");
        assert!(text.contains("# patterns: 3 total, 3 antichain, 0 dominated"), "{text}");
        assert!(text.contains("# blocks: 3"), "{text}");
        assert!(
            text.lines().take_while(|l| l.starts_with('#')).count() == 5,
            "every header line must be commented: {text}"
        );
    }

    /// `run` over a real store: the pool is the antichain, with or without the cover preview.
    #[test]
    fn run_exports_the_pool_from_a_real_store() {
        let (dir, dirs, store) = temp_store();
        // 10 ⊃ 20 (dominated); 30 is unrelated. Counters 0..=3, dense = id.
        for (block_number, bits) in [(10u64, vec![0u32, 1, 2]), (20, vec![0, 1]), (30, vec![3])] {
            let counters: Vec<(u64, u32)> = bits.iter().map(|&b| (b as u64, b)).collect();
            let pattern = pat(&bits, block_number);
            store
                .commit_block(
                    block_number,
                    &block(block_number),
                    &counters,
                    Some((block_number, &pattern)),
                )
                .unwrap();
        }
        store.flush().unwrap();
        drop(store);

        for no_cover_preview in [false, true] {
            let pool = dir.path().join(format!("pool-{no_cover_preview}.txt"));
            let data_dir = dirs.root.clone();
            run(InspectArgs { data_dir, top: 3, dump_pool: Some(pool.clone()), no_cover_preview })
                .unwrap();
            let blocks = stateless_common::block_list::read_block_list(&pool).unwrap();
            assert_eq!(blocks, vec![10, 30], "block 20's pattern is dominated by block 10's");
        }
    }
}
