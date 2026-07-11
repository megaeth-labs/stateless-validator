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

    let source_dirs = if args.source_dirs.is_empty() {
        let detected = detect_mega_evm_checkout().ok_or_else(|| {
            eyre::eyre!(
                "could not find the mega-evm checkout for the built-against rev under \
                 ~/.cargo/git/checkouts; pass --source-dir explicitly"
            )
        })?;
        info!(dir = %detected.display(), "auto-detected mega-evm sources");
        vec![detected]
    } else {
        args.source_dirs.clone()
    };

    let exe = std::env::current_exe()?;
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

    info!(
        blocks = manifest.blocks.len(),
        universe_counters = manifest.universe_counters,
        "coverage report for selected set (branch-granular counters: see manifest)"
    );
    println!("{}", String::from_utf8_lossy(&report.stdout));
    println!("selected blocks:");
    for b in &manifest.blocks {
        println!(
            "  {:>10}  gain={:<6} bits={:<6} pattern={}  {}",
            b.number, b.gain, b.bits, b.pattern, b.hash
        );
    }
    Ok(())
}

/// Finds the cargo git checkout of the mega-evm rev this binary was BUILT
/// against (embedded by build.rs) — no runtime Cargo.lock parsing, no cwd
/// dependence, and the rev can never disagree with the instrumented build.
fn detect_mega_evm_checkout() -> Option<PathBuf> {
    let rev: String = env!("COVERAGE_MEGA_EVM_REV").chars().take(7).collect();
    if rev.len() != 7 {
        return None;
    }
    let home = std::env::var_os("HOME")?;
    let checkouts = PathBuf::from(home).join(".cargo").join("git").join("checkouts");
    for entry in std::fs::read_dir(checkouts).ok()?.flatten() {
        if entry.file_name().to_string_lossy().starts_with("mega-evm-") {
            let candidate = entry.path().join(&rev);
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }
    None
}
