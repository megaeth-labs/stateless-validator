//! Canonical-chain scale benchmark: disk footprint and read/write performance of the
//! permanent CANONICAL_CHAIN index at production row counts.
//!
//! The debug-trace-server keeps the number -> hash index forever and backfills it to
//! genesis, so this measures the exact write shape the backfill uses (one transaction per
//! descending batch: N chain-row inserts + the history-floor row, at a chosen durability)
//! and the point-read pattern canonical-hash resolution uses.
//!
//! Run with `cargo bench -p stateless-db --bench canonical_chain_scale`.
//!
//! Environment knobs:
//! - `CANONICAL_BENCH_SIZES` — comma-separated row counts (default `100000,1000000,10000000`; add
//!   `25000000` for the full-history projection point).
//! - `CANONICAL_BENCH_MIXED` — set (any value) to also measure reads while a writer appends.

use std::{
    hint::black_box,
    path::Path,
    time::{Duration, Instant},
};

use redb::{Durability, ReadableDatabase};
use stateless_core::db::BlockMeta;
use stateless_db::{
    ANCHOR_BLOCK, CANONICAL_CHAIN, Database, HISTORY_FLOOR_KEY, block_meta_to_tuple,
};

/// Rows written per configuration in the write-throughput matrix.
const WRITE_MATRIX_ROWS: u64 = 200_000;

/// Point reads sampled per latency phase.
const READ_SAMPLES: usize = 20_000;

/// Immediate-durability barrier cadence for the `None`-durability configurations,
/// mirroring the backfill task.
const BARRIER_EVERY: u64 = 16;

fn main() {
    let sizes = std::env::var("CANONICAL_BENCH_SIZES")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().parse::<u64>().expect("CANONICAL_BENCH_SIZES: invalid count"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|_| vec![100_000, 1_000_000, 10_000_000]);
    let mixed = std::env::var_os("CANONICAL_BENCH_MIXED").is_some();

    write_throughput_matrix();

    for &rows in &sizes {
        scale_report(rows, mixed);
    }
}

/// Write throughput for batch size x durability, on a fresh DB each, at a fixed row count
/// (so `Immediate` configurations stay affordable).
fn write_throughput_matrix() {
    println!("write throughput ({WRITE_MATRIX_ROWS} rows per configuration, fresh DB each)");
    println!("  batch  | durability            |     rows/s | wall time");
    for &batch in &[1_024u64, 10_240] {
        for &immediate in &[true, false] {
            let dir = tempfile::tempdir().unwrap();
            let db = open_db(&dir.path().join("bench.redb"));
            let start = Instant::now();
            build_descending(&db, WRITE_MATRIX_ROWS, batch, immediate);
            let elapsed = start.elapsed();
            let label = if immediate { "Immediate" } else { "None+barrier/16" };
            println!(
                "  {batch:>6} | {label:<21} | {:>10.0} | {:.2?}",
                WRITE_MATRIX_ROWS as f64 / elapsed.as_secs_f64(),
                elapsed,
            );
        }
    }
    println!();
}

/// Builds an index of `rows` rows, then reports disk footprint, hot reads, reopened reads,
/// and (optionally) reads under concurrent writes.
fn scale_report(rows: u64, mixed: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.redb");
    let db = open_db(&path);

    // Build with the backfill's daily-driver configuration: 10240-row batches at
    // Durability::None with an Immediate barrier every 16 batches.
    let start = Instant::now();
    build_descending(&db, rows, 10_240, false);
    let build = start.elapsed();

    let file_bytes = std::fs::metadata(&path).unwrap().len();
    let bytes_per_row = file_bytes as f64 / rows as f64;
    println!("scale report: {rows} rows");
    println!(
        "  build: {build:.2?} ({:.0} rows/s, batch 10240, None + barrier/16)",
        rows as f64 / build.as_secs_f64()
    );
    println!(
        "  disk: {file_bytes} B ({:.1} MiB), {bytes_per_row:.1} B/row",
        file_bytes as f64 / (1024.0 * 1024.0)
    );
    for projection in [22_400_000u64, 25_000_000] {
        println!(
            "  projected at {projection} rows: {:.2} GiB",
            bytes_per_row * projection as f64 / (1024.0 * 1024.0 * 1024.0)
        );
    }

    let hot = read_latencies(&db, rows);
    print_percentiles("point reads (hot)", &hot);

    // Reopen: a fresh redb instance starts with an empty read cache (the OS page cache may
    // still be warm, so this is an upper bound on cache-cold behavior, not disk-cold).
    drop(db);
    let db = open_db(&path);
    let reopened = read_latencies(&db, rows);
    print_percentiles("point reads (reopened)", &reopened);

    if mixed {
        let db = std::sync::Arc::new(db);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let db = std::sync::Arc::clone(&db);
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                // Append rows above the existing range while readers run.
                let mut next = rows + 1;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    write_batch(&db, next, next + 1_023, Durability::None);
                    next += 1_024;
                }
            })
        };
        let under_write = read_latencies(&db, rows);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().unwrap();
        print_percentiles("point reads (concurrent writer)", &under_write);
    }
    println!();
}

fn open_db(path: &Path) -> Database {
    let db = Database::create(path).unwrap();
    let txn = db.begin_write().unwrap();
    txn.open_table(CANONICAL_CHAIN).unwrap();
    txn.open_table(ANCHOR_BLOCK).unwrap();
    txn.commit().unwrap();
    db
}

/// Deterministic row content for block `n` (fixed-width, like production rows).
fn meta(n: u64) -> BlockMeta {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&n.to_be_bytes());
    hash[8..16].copy_from_slice(&n.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
    BlockMeta {
        block_number: n,
        block_hash: hash.into(),
        post_state_root: hash.into(),
        post_withdrawals_root: hash.into(),
    }
}

/// One backfill-shaped transaction: insert rows `lo..=hi` plus the floor row, committed at
/// `durability`.
fn write_batch(db: &Database, lo: u64, hi: u64, durability: Durability) {
    let mut txn = db.begin_write().unwrap();
    txn.set_durability(durability).unwrap();
    {
        let mut chain = txn.open_table(CANONICAL_CHAIN).unwrap();
        for n in lo..=hi {
            let m = meta(n);
            chain
                .insert(n, (m.block_hash.0, m.post_state_root.0, m.post_withdrawals_root.0))
                .unwrap();
        }
        let mut anchor = txn.open_table(ANCHOR_BLOCK).unwrap();
        anchor.insert(HISTORY_FLOOR_KEY, block_meta_to_tuple(&meta(lo))).unwrap();
    }
    txn.commit().unwrap();
}

/// Writes rows `1..=rows` in descending backfill order. `always_immediate` commits every
/// batch at `Immediate`; otherwise batches ride `None` with an `Immediate` barrier every
/// [`BARRIER_EVERY`] batches and at the end.
fn build_descending(db: &Database, rows: u64, batch: u64, always_immediate: bool) {
    let mut hi = rows;
    let mut batches = 0u64;
    while hi >= 1 {
        let lo = hi.saturating_sub(batch - 1).max(1);
        batches += 1;
        let durability = if always_immediate || batches.is_multiple_of(BARRIER_EVERY) {
            Durability::Immediate
        } else {
            Durability::None
        };
        write_batch(db, lo, hi, durability);
        if lo == 1 {
            break;
        }
        hi = lo - 1;
    }
    // Final barrier, as the backfill does at exit.
    let mut txn = db.begin_write().unwrap();
    txn.set_durability(Durability::Immediate).unwrap();
    txn.commit().unwrap();
}

/// Per-read latencies for [`READ_SAMPLES`] uniform random point lookups in `1..=rows`,
/// through a fresh read transaction each (the canonical-hash resolution pattern).
fn read_latencies(db: &Database, rows: u64) -> Vec<Duration> {
    let mut rng: u64 = 0x2545_F491_4F6C_DD1D;
    let mut samples = Vec::with_capacity(READ_SAMPLES);
    for _ in 0..READ_SAMPLES {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let n = 1 + (rng >> 16) % rows;
        let start = Instant::now();
        let txn = db.begin_read().unwrap();
        let chain = txn.open_table(CANONICAL_CHAIN).unwrap();
        let row = chain.get(n).unwrap().map(|v| v.value().0);
        samples.push(start.elapsed());
        black_box(row);
    }
    samples
}

fn print_percentiles(label: &str, samples: &[Duration]) {
    let mut sorted = samples.to_vec();
    sorted.sort();
    let pick = |p: f64| sorted[((sorted.len() - 1) as f64 * p) as usize];
    println!(
        "  {label}: p50 {:.2?}, p90 {:.2?}, p99 {:.2?} ({} samples)",
        pick(0.50),
        pick(0.90),
        pick(0.99),
        sorted.len(),
    );
}
