//! Human-readable coverage report for the selected block set.
//!
//! Merges the archived profiles of the selected representatives and prints
//! llvm-cov's branch/region/line totals plus the per-file table for the
//! measured scope.
//!
//! How to read it against the manifest: the cover is complete at the level
//! the tool measures — every source region and branch arm any replayed block
//! covered is covered by the selected set — and lines, functions and branches
//! here match a report over the whole scan exactly. The *region* total can
//! trail it by a region or two in a const-generic family (revm's
//! `push::<N>`). llvm-cov summarizes a generic function by its best single
//! instantiation rather than by the union across instantiations, so the same
//! source regions, covered through different instantiations by different
//! selected blocks, count for less than when one block's instantiation covers
//! them all. No source region is missing in that case; the items are keyed by
//! source span precisely so that which instantiation ran does not matter.
//!
//! Run-once initializers (the per-hardfork precompile tables) read as
//! uncovered: no block is credited with them — see `worker::warm_up`.

use std::{path::PathBuf, process::Command};

use clap::Args;
use eyre::{Context, Result, ensure};
use tracing::info;

use crate::{llvm::LlvmArgs, setcover::Manifest, spool::DataDir};

#[derive(Args, Debug, Clone)]
pub struct ReportArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Manifest to report on (default: <data-dir>/manifest.json).
    #[clap(long)]
    pub manifest: Option<PathBuf>,
    #[clap(flatten)]
    pub llvm: LlvmArgs,
}

pub fn run(args: ReportArgs) -> Result<()> {
    ensure!(
        crate::profile_rt::is_instrumented_build(),
        "report must run from the instrumented build (its binary embeds the coverage map)"
    );
    let dirs = DataDir::new(&args.data_dir);
    let manifest_path = args.manifest.unwrap_or_else(|| dirs.manifest_path());
    let manifest = Manifest::read(&manifest_path)?;
    ensure!(!manifest.blocks.is_empty(), "manifest has no blocks — run set-cover first");
    let llvm = args.llvm.resolve()?;
    info!(dirs = ?llvm.source_dirs, "report scope");
    check_manifest(
        &manifest,
        &manifest_path,
        &crate::store::current_binary_id(),
        &llvm.universe(),
    )?;

    // A directory of this run's own, removed on every exit path. Outside the
    // data dir: that belongs to whichever backfill holds its store.
    let work = tempfile::Builder::new()
        .prefix("coverage-report-")
        .tempdir()
        .wrap_err("create a work dir for the report")?;
    // Archived per-pattern profiles are zstd'd sparse profdata; inflate them
    // for llvm-profdata (profdata files are valid merge inputs).
    let mut profiles = Vec::new();
    for b in &manifest.blocks {
        let z = dirs.archived_profile(b.pattern_key()?);
        ensure!(z.exists(), "archived profile missing for pattern {}: {}", b.pattern, z.display());
        let raw = zstd::decode_all(&std::fs::read(&z)?[..])
            .wrap_err_with(|| format!("decompress {}", z.display()))?;
        let profile = work.path().join(format!("{}.profdata", b.pattern));
        std::fs::write(&profile, &raw)?;
        profiles.push(profile);
    }
    let merged = work.path().join("selected.profdata");
    llvm.merge_sparse(&profiles, &merged)?;

    let exe = crate::profile_rt::own_executable()?;
    check_profiles_evaluate(
        llvm.covered_items(&exe, &merged)?.len() as u64,
        manifest.covered_counters,
    )?;

    let report = Command::new(&llvm.cov)
        .arg("report")
        .arg(&exe)
        .arg(format!("--instr-profile={}", merged.display()))
        .args(&llvm.source_dirs)
        .output()?;
    ensure!(
        report.status.success(),
        "llvm-cov report failed: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let table = String::from_utf8_lossy(&report.stdout);

    info!(
        blocks = manifest.blocks.len(),
        universe_counters = manifest.universe_counters,
        "coverage report for selected set (branch-granular counters: see manifest)"
    );
    println!("{table}");
    println!("selected blocks:");
    for b in &manifest.blocks {
        println!(
            "  {:>10}  gain={:<6} bits={:<6} pattern={}  {}",
            b.number, b.gain, b.bits, b.pattern, b.hash
        );
    }
    Ok(())
}

/// Whether the selected profiles, read through THIS binary's coverage map,
/// still hold the coverage the cover recorded for them.
///
/// A profile names each function instance by its symbol, and llvm-cov cannot
/// match a profile to a build whose symbols differ: it reports that code
/// uncovered. `binary_id` covers the causes it can see — the measured
/// sources, the toolchain, the lockfile — but not features or compiler flags.
/// Re-deriving the covered items is the direct check, whatever the cause: the
/// same extraction the scan ran, so on the build that scanned it it
/// reproduces the manifest's count exactly.
fn check_profiles_evaluate(evaluated: u64, recorded: u64) -> Result<()> {
    ensure!(
        evaluated == recorded,
        "the selected profiles evaluate to {evaluated} covered items under this binary, but the \
         cover recorded {recorded}: this binary's coverage map is not the one the scan measured \
         (a rebuild with other dependencies renamed the instances the profiles are keyed by), \
         so the report would misstate the coverage. Report with the binary that ran the scan, \
         or re-sweep the scan's blocks into a fresh data dir with this one"
    );
    Ok(())
}

/// Whether `manifest` may be reported by this binary over this scope.
///
/// Both halves guard against a report that runs fine and is wrong. The
/// archived profiles only mean something against the coverage map of the
/// build that wrote them: on a `binary_id` mismatch llvm-cov drops every
/// function whose hash differs and reports it uncovered. And the cover only
/// promises the scope it was computed over: the profiles hold counters for
/// every instrumented crate, so a wider scope reports cleanly while reading
/// whatever the cover never had to reach as uncovered code.
fn check_manifest(
    manifest: &Manifest,
    manifest_path: &std::path::Path,
    binary_id: &str,
    universe: &str,
) -> Result<()> {
    ensure!(
        manifest.binary_id == binary_id,
        "manifest {} was generated by binary_id {}, this binary is {binary_id}: its profiles \
         belong to another instrumented build",
        manifest_path.display(),
        manifest.binary_id,
    );
    ensure!(
        manifest.universe == universe,
        "manifest {} covers the universe {:?}, but this report measures {universe:?}: pass the \
         --source-dir scope the scan used",
        manifest_path.display(),
        manifest.universe,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn manifest(binary_id: &str, universe: &str) -> Manifest {
        Manifest {
            binary_id: binary_id.into(),
            universe: universe.into(),
            generated_at_unix: 0,
            universe_counters: 1,
            covered_counters: 1,
            blocks: Vec::new(),
        }
    }

    /// A cover only promises the scope it was computed over. Reporting it over
    /// another — wider, or with a root swapped — must be refused, not rendered
    /// as a clean report whose gap reads as uncovered code.
    #[test]
    fn a_manifest_is_only_reported_over_the_scope_it_covers() {
        let path = Path::new("/d/manifest.json");
        let scan = "regions+branch-arms/v3:30ce038,revm-handler-8.1.0";
        let m = manifest("id", scan);

        check_manifest(&m, path, "id", scan).expect("same scope, same build");

        let wider = "regions+branch-arms/v3:30ce038,revm-context-8.0.4,revm-handler-8.1.0";
        let err = check_manifest(&m, path, "id", wider).expect_err("wider scope must fail");
        assert!(err.to_string().contains("covers the universe"), "{err}");
        assert!(err.to_string().contains(wider), "must name the requested scope: {err}");

        let err = check_manifest(&m, path, "other", scan).expect_err("other build must fail");
        assert!(err.to_string().contains("binary_id"), "{err}");
    }

    /// Profiles that no longer evaluate to what the cover recorded — fewer items
    /// through a renamed instance, or more — must stop the report rather than
    /// print a table that misstates the coverage.
    #[test]
    fn a_report_refuses_profiles_that_no_longer_evaluate_to_the_recorded_cover() {
        check_profiles_evaluate(13_060, 13_060).expect("the scanning build reproduces the count");
        for evaluated in [12_900, 13_100] {
            let err = check_profiles_evaluate(evaluated, 13_060).expect_err("must refuse");
            assert!(err.to_string().contains("recorded 13060"), "{err}");
        }
    }
}
