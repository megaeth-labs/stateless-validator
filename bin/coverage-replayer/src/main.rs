//! coverage-replayer: derive a small set of mainnet blocks reproducing all the execution coverage
//! a chain scan observed, of mega-evm and the revm engine it drives (`measured-crates.txt`).
//!
//! `backfill` replays blocks under LLVM branch instrumentation in resident worker subprocesses;
//! a judge dedups the per-block bitmaps into "patterns" in a redb store. A bit is an *evaluated*
//! item (a region entry or branch arm as llvm-cov computes it), not a physical counter: see
//! `llvm.rs`. `set-cover` picks a greedy, irredundant (not necessarily minimum) block set covering
//! every item, `report` renders llvm-cov output for it, and `inspect` prints store statistics and
//! exports the candidate pool.
//!
//! ## Carrying a scan across a mega-evm bump
//!
//! Bitmaps belong to one instrumented build ([`store::current_binary_id`]), so `backfill` and
//! `set-cover` refuse an old store; the *block numbers* survive, so the tool carries those over:
//!
//! ```text
//! inspect --dump-pool pool.txt   (old build; read-only, no binary-id check)
//!   └─ cat pool*.txt > union.txt     (across stores; sorted and deduped on read)
//!        └─ backfill --blocks-file union.txt    (new build, fresh data-dir)
//!             └─ set-cover → report             (new minimal set)
//! ```
//!
//! The pool is the antichain's representatives, not the old minimal set, which has no slack once a
//! new build splits patterns. `inspect` alone skips the binary-id check, so it reads old stores.

mod backfill;
mod bitset;
mod inspect;
mod llvm;
mod profile_rt;
mod proto;
mod report;
mod setcover;
mod spool;
mod store;
mod worker;

use clap::{Parser, Subcommand};
use eyre::Result;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[clap(name = "coverage-replayer", version, about)]
struct Cli {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Replay blocks under coverage instrumentation and store what each covered.
    Backfill(backfill::BackfillArgs),
    /// Compute the greedy covering block set from the pattern store.
    SetCover(setcover::SetCoverArgs),
    /// Print an llvm-cov report for the currently selected set.
    Report(report::ReportArgs),
    /// Read-only store statistics (works on stores from other builds).
    Inspect(inspect::InspectArgs),
    /// Internal: resident worker subprocess (spawned by backfill).
    #[clap(hide = true)]
    InternalWorker(worker::WorkerArgs),
}

fn main() -> Result<()> {
    profile_rt::suppress_default_profile();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().cmd {
        Cmd::InternalWorker(args) => worker::run(args),
        Cmd::Backfill(args) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(backfill::run(args)),
        Cmd::SetCover(args) => setcover::run(args),
        Cmd::Report(args) => report::run(args),
        Cmd::Inspect(args) => inspect::run(args),
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, error::ErrorKind};

    use super::*;

    /// `--help` needs clap's `help` feature, which `default-features = false` drops: this pins
    /// the workspace's clap features against that trim.
    #[test]
    fn help_is_available_on_the_root_and_on_subcommands() {
        for argv in [
            vec!["coverage-replayer", "--help"],
            vec!["coverage-replayer", "inspect", "--help"],
            vec!["coverage-replayer", "backfill", "--help"],
        ] {
            let err = Cli::try_parse_from(&argv).expect_err("--help exits via an Err");
            assert_eq!(err.kind(), ErrorKind::DisplayHelp, "{argv:?} produced {err}");
        }
    }

    /// An unknown flag must name itself and print usage (clap's `error-context` and `usage`).
    #[test]
    fn unknown_flags_report_the_offender_and_usage() {
        let err = Cli::try_parse_from(["coverage-replayer", "inspect", "--bogus"])
            .expect_err("unknown flag must fail");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("--bogus"), "error must name the flag: {rendered}");
        assert!(rendered.contains("Usage:"), "error must carry usage: {rendered}");
    }

    /// The pool comes from the cover pass, so `--dump-pool` must conflict with skipping it.
    #[test]
    fn pool_export_conflicts_with_skipping_the_cover_pass() {
        let base = ["coverage-replayer", "inspect", "--data-dir", "/d"];
        let parse = |extra: &[&str]| Cli::try_parse_from(base.iter().chain(extra.iter()));

        let err = parse(&["--no-cover-preview", "--dump-pool", "/p"]).expect_err("must conflict");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict, "{err}");
        parse(&["--no-cover-preview"]).expect("alone is fine");
        parse(&["--dump-pool", "/p"]).expect("alone is fine");
    }

    #[test]
    fn cli_definition_is_well_formed() {
        Cli::command().debug_assert();
    }
}
