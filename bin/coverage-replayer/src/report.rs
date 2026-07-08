//! Human-readable coverage report for the selected block set.
//!
//! This is the only place llvm-cov runs: merge the archived profraws of the
//! selected representatives and print branch/region/line totals plus the
//! per-file table filtered to the crates of interest.

use std::{path::PathBuf, process::Command};

use clap::Args;
use eyre::{Context, Result, ensure};
use tracing::info;

use crate::{llvm, setcover::Manifest, spool::DataDir};

#[derive(Args, Debug, Clone)]
pub struct ReportArgs {
    /// Root data directory (same as backfill).
    #[clap(long, env = "COVERAGE_REPLAYER_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Manifest to report on (default: <data-dir>/manifest.json).
    #[clap(long)]
    pub manifest: Option<PathBuf>,
    /// Substring filter on source file paths in the per-file table.
    #[clap(long, default_value = "mega-evm")]
    pub path_filter: String,
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
    let dirs = DataDir::new(&args.data_dir)?;
    let manifest_path = args.manifest.unwrap_or_else(|| dirs.manifest_path());
    let manifest: Manifest = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .wrap_err_with(|| format!("read manifest {}", manifest_path.display()))?,
    )?;
    ensure!(!manifest.blocks.is_empty(), "manifest has no blocks — run set-cover first");

    let llvm_profdata = llvm::find_tool("llvm-profdata", args.llvm_profdata.as_deref())?;
    let llvm_cov = llvm::find_tool("llvm-cov", args.llvm_cov.as_deref())?;

    let mut profraws = Vec::new();
    for b in &manifest.blocks {
        let p = dirs.archived_profraw(b.number);
        ensure!(p.exists(), "archived profraw missing for block {}: {}", b.number, p.display());
        profraws.push(p);
    }

    let merged = dirs.tmp().join("selected.profdata");
    let out = Command::new(&llvm_profdata)
        .arg("merge")
        .arg("-sparse")
        .args(&profraws)
        .arg("-o")
        .arg(&merged)
        .output()?;
    ensure!(
        out.status.success(),
        "llvm-profdata merge failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let exe = std::env::current_exe()?;
    let report = Command::new(&llvm_cov)
        .arg("report")
        .arg(&exe)
        .arg(format!("--instr-profile={}", merged.display()))
        .output()?;
    ensure!(
        report.status.success(),
        "llvm-cov report failed: {}",
        String::from_utf8_lossy(&report.stderr)
    );

    info!(
        blocks = manifest.blocks.len(),
        universe_counters = manifest.universe_counters,
        "coverage report for selected set (branch-granular counters: see manifest)"
    );
    let text = String::from_utf8_lossy(&report.stdout);
    let mut printed_header = false;
    for line in text.lines() {
        let is_header = line.starts_with("Filename") || line.starts_with('-');
        let is_total = line.starts_with("TOTAL");
        if is_header && !printed_header {
            println!("{line}");
            if line.starts_with('-') {
                printed_header = true;
            }
            continue;
        }
        if is_total || line.contains(&args.path_filter) {
            println!("{line}");
        }
    }
    println!("\nselected blocks:");
    for b in &manifest.blocks {
        println!(
            "  {:>10}  gain={:<6} bits={:<6} pattern={}  {}",
            b.number, b.gain, b.bits, b.pattern, b.hash
        );
    }
    Ok(())
}
