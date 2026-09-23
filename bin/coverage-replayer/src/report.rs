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

use std::{path::PathBuf, process::Command};

use clap::Args;
use eyre::{Context, Result, ensure};
use tracing::{info, warn};

use crate::{llvm, setcover::Manifest, spool::DataDir};

#[derive(Args, Debug, Clone)]
pub struct ReportArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Manifest to report on (default: <data-dir>/manifest.json).
    #[clap(long)]
    pub manifest: Option<PathBuf>,
    /// Source directories passed to llvm-cov as the report scope. Default:
    /// auto-detect the mega-evm checkout from ./Cargo.lock.
    ///
    /// IMPORTANT: restricting the scope is not just focus — reporting over the
    /// full covmap crashes llvm-cov (LLVM bug in instantiation-group handling
    /// for some dependency files); scoping to mega-evm sources avoids it.
    #[clap(long = "source-dir")]
    pub source_dirs: Vec<PathBuf>,
    /// Explicit llvm-profdata path (default: auto-detect).
    #[clap(long)]
    pub llvm_profdata: Option<String>,
    /// Explicit llvm-cov path (default: auto-detect).
    #[clap(long)]
    pub llvm_cov: Option<String>,
}

pub fn run(args: ReportArgs) -> Result<()> {
    ensure!(
        crate::profile_rt::is_instrumented_build(),
        "report must run from the instrumented build (its binary embeds the coverage map)"
    );
    let dirs = DataDir::new(&args.data_dir);
    dirs.ensure_layout()?;
    let manifest_path = args.manifest.unwrap_or_else(|| dirs.manifest_path());
    let manifest: Manifest = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .wrap_err_with(|| format!("read manifest {}", manifest_path.display()))?,
    )?;
    ensure!(!manifest.blocks.is_empty(), "manifest has no blocks — run set-cover first");
    let source_dirs = llvm::resolve_source_dirs(&args.source_dirs)?;
    info!(dirs = ?source_dirs, "report scope");
    check_manifest(
        &manifest,
        &manifest_path,
        &crate::store::current_binary_id(),
        &llvm::universe_stamp(&source_dirs),
    )?;

    let llvm_profdata = llvm::find_tool("llvm-profdata", args.llvm_profdata.as_deref())?;
    let llvm_cov = llvm::find_tool("llvm-cov", args.llvm_cov.as_deref())?;

    // Archived per-pattern profiles are zstd'd sparse profdata; inflate to tmp
    // for llvm-profdata (profdata files are valid merge inputs).
    let mut profraws = Vec::new();
    for b in &manifest.blocks {
        let key = u64::from_str_radix(&b.pattern, 16)
            .wrap_err_with(|| format!("bad pattern key {}", b.pattern))?;
        let z = dirs.archived_profile(key);
        ensure!(z.exists(), "archived profile missing for pattern {}: {}", b.pattern, z.display());
        let raw = zstd::decode_all(&std::fs::read(&z)?[..])
            .wrap_err_with(|| format!("decompress {}", z.display()))?;
        let tmp = dirs.tmp().join(format!("report_{}.profdata", b.pattern));
        crate::spool::write_atomic(&tmp, &raw)?;
        profraws.push(tmp);
    }

    let merged = dirs.tmp().join("selected.profdata");
    let out = Command::new(&llvm_profdata)
        .arg("merge")
        .arg("-sparse")
        .args(&profraws)
        .arg("-o")
        .arg(&merged)
        .output()?;
    for p in &profraws {
        let _ = std::fs::remove_file(p);
    }
    ensure!(
        out.status.success(),
        "llvm-profdata merge failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let exe = std::env::current_exe()?;
    // The same silent omission the per-block export guards against: llvm-cov
    // answers a root it cannot match with a warning and a success exit, so a
    // stale one drops out of the table while the totals still read as a
    // whole-scope report. `report` prints paths with their common prefix
    // stripped, so the check reads a summary export instead, whose filenames
    // are absolute.
    let summary = Command::new(&llvm_cov)
        .arg("export")
        .arg(&exe)
        .arg(format!("--instr-profile={}", merged.display()))
        .arg("--format=text")
        .arg("--summary-only")
        .args(&source_dirs)
        .output()?;
    ensure!(
        summary.status.success(),
        "llvm-cov export --summary-only failed: {}",
        String::from_utf8_lossy(&summary.stderr)
    );
    llvm::ensure_export_covers_every_root(&String::from_utf8_lossy(&summary.stdout), &source_dirs)?;

    let report = Command::new(&llvm_cov)
        .arg("report")
        .arg(&exe)
        .arg(format!("--instr-profile={}", merged.display()))
        .args(&source_dirs)
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
    match &manifest.universe {
        Some(covered) => ensure!(
            covered == universe,
            "manifest {} covers the universe {covered:?}, but this report measures {universe:?}: \
             pass the --source-dir scope the scan used",
            manifest_path.display(),
        ),
        None => warn!(
            manifest = %manifest_path.display(),
            "manifest predates recording its universe — the scope cannot be checked against \
             the one it was computed over; re-run set-cover to record it"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn manifest(binary_id: &str, universe: Option<&str>) -> Manifest {
        Manifest {
            binary_id: binary_id.into(),
            universe: universe.map(Into::into),
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
        let scan = "regions+branch-arms/v2:30ce038,revm-handler-8.1.0";
        let m = manifest("id", Some(scan));

        check_manifest(&m, path, "id", scan).expect("same scope, same build");

        let wider = "regions+branch-arms/v2:30ce038,revm-context-8.0.4,revm-handler-8.1.0";
        let err = check_manifest(&m, path, "id", wider).expect_err("wider scope must fail");
        assert!(err.to_string().contains("covers the universe"), "{err}");
        assert!(err.to_string().contains(wider), "must name the requested scope: {err}");

        let err = check_manifest(&m, path, "other", scan).expect_err("other build must fail");
        assert!(err.to_string().contains("binary_id"), "{err}");
    }

    /// Manifests written before the universe was recorded still report — the
    /// build check applies, the scope cannot be checked, and a warning says so.
    #[test]
    fn a_manifest_without_a_universe_is_checked_on_build_alone() {
        let m = manifest("id", None);
        check_manifest(&m, Path::new("/d/m.json"), "id", "anything").expect("build matches");
        let err = check_manifest(&m, Path::new("/d/m.json"), "other", "anything")
            .expect_err("build differs");
        assert!(err.to_string().contains("binary_id"), "{err}");

        // And such a manifest still parses: the field is optional on disk.
        let old = r#"{"binary_id":"id","generated_at_unix":0,"universe_counters":1,
                      "covered_counters":1,"blocks":[]}"#;
        let parsed: Manifest = serde_json::from_str(old).expect("pre-universe manifest parses");
        assert_eq!(parsed.universe, None);
    }
}
