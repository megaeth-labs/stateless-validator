//! Compares zstd levels for the witness payload — compression time, decompression time, and
//! compressed size at the current producer level ([`WITNESS_ZSTD_LEVEL`]) vs the previous
//! level 9 — on two payloads: the largest mainnet fixture witness and a real large one
//! (block 6906405, ~6.3 MiB uncompressed) committed at `test_data/mainnet/bench/6906405.zst`
//! (the raw zstd body of a `mega_getBlockWitness` `v0:` response).
//!
//! Run with `cargo bench -p stateless-common --bench witness_zstd_level`.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use stateless_common::{WITNESS_ZSTD_LEVEL, encode_witness_payload};
use stateless_test_utils::fixtures::TestFixtures;

/// Previous producer compression level, kept as the comparison baseline.
const PREVIOUS_LEVEL: i32 = 9;

/// Measured runs per operation (the median is reported), each preceded by a short warmup.
const RUNS: usize = 30;

/// Committed large mainnet witness payload (see module docs).
const BIG_WITNESS_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../test_data/mainnet/bench/6906405.zst");

/// Timing and size results for one compression level.
struct LevelReport {
    level: i32,
    compress: Duration,
    decompress: Duration,
    compressed_size: usize,
}

fn main() {
    for (source, raw) in payloads() {
        let reports =
            [measure_level(&raw, WITNESS_ZSTD_LEVEL), measure_level(&raw, PREVIOUS_LEVEL)];

        println!("witness zstd level comparison ({source}, median of {RUNS} runs)");
        println!(
            "  uncompressed payload: {} B ({:.2} MiB)",
            raw.len(),
            raw.len() as f64 / (1024.0 * 1024.0)
        );
        println!();
        println!("  level |   compress | decompress | compressed size | ratio");
        for report in &reports {
            println!(
                "  {:>5} | {:>10} | {:>10} | {:>13} B | {:.2}x",
                report.level,
                format_ms(report.compress),
                format_ms(report.decompress),
                report.compressed_size,
                raw.len() as f64 / report.compressed_size as f64,
            );
        }

        let [current, previous] = &reports;
        println!();
        println!(
            "  level {WITNESS_ZSTD_LEVEL} vs level {PREVIOUS_LEVEL}: compresses {:.1}x faster, \
             output {:+.1}% size, decompress {:+.1}% time",
            previous.compress.as_secs_f64() / current.compress.as_secs_f64(),
            percent_delta(current.compressed_size as f64, previous.compressed_size as f64),
            percent_delta(current.decompress.as_secs_f64(), previous.decompress.as_secs_f64()),
        );
        println!();
    }
}

/// The benched payloads, as `(source_label, uncompressed_payload)`: the bincode-legacy
/// `(SaltWitness, MptWitness)` bytes that `encode_witness_payload` compresses.
fn payloads() -> [(String, Vec<u8>); 2] {
    let fixtures = TestFixtures::mainnet();
    // Round-trip via the production encoder so the wire format stays defined in one place.
    let (fixture_block, fixture_payload) = fixtures
        .paired_blocks()
        .into_iter()
        .map(|(number, hash)| {
            let mpt_witness = fixtures.mpt_witness(&hash);
            let (uncompressed_size, compressed) =
                encode_witness_payload(&fixtures.salt_witnesses[&hash], &mpt_witness)
                    .expect("encode witness");
            (number, uncompressed_size, compressed)
        })
        .max_by_key(|(_, uncompressed_size, _)| *uncompressed_size)
        .map(|(number, _, compressed)| {
            let payload =
                zstd::decode_all(compressed.as_slice()).expect("roundtrip witness payload");
            (number, payload)
        })
        .expect("at least one paired witness");

    let big_compressed =
        std::fs::read(BIG_WITNESS_PATH).unwrap_or_else(|e| panic!("read {BIG_WITNESS_PATH}: {e}"));
    let big_payload =
        zstd::decode_all(big_compressed.as_slice()).expect("decompress big witness payload");

    [
        (format!("mainnet block {fixture_block} witness, largest fixture"), fixture_payload),
        ("mainnet block 6906405 witness".into(), big_payload),
    ]
}

/// Measures compression and decompression of `raw` at `level`; decompression runs on that
/// level's own compressed output.
fn measure_level(raw: &[u8], level: i32) -> LevelReport {
    let compressed = zstd::encode_all(raw, level).expect("compress");
    let compress = median_time(|| zstd::encode_all(black_box(raw), level).expect("compress"));
    let decompress =
        median_time(|| zstd::decode_all(black_box(compressed.as_slice())).expect("decompress"));
    LevelReport { level, compress, decompress, compressed_size: compressed.len() }
}

/// Median wall time of `op` over [`RUNS`] measured runs, after 3 warmup runs.
fn median_time<T>(mut op: impl FnMut() -> T) -> Duration {
    for _ in 0..3 {
        black_box(op());
    }
    let mut samples: Vec<Duration> = (0..RUNS)
        .map(|_| {
            let start = Instant::now();
            black_box(op());
            start.elapsed()
        })
        .collect();
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Relative difference of `value` vs `baseline`, in percent.
fn percent_delta(value: f64, baseline: f64) -> f64 {
    (value - baseline) / baseline * 100.0
}

fn format_ms(duration: Duration) -> String {
    format!("{:.2} ms", duration.as_secs_f64() * 1e3)
}
