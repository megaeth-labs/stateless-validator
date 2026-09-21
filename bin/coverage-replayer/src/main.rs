//! coverage-replayer: derive the minimal set of mainnet blocks that maximizes
//! mega-evm branch coverage.
//!
//! `backfill` replays a block range under LLVM branch instrumentation:
//! resident worker subprocesses execute each block (reset counters → replay →
//! capture), and a judge dedups the resulting per-block coverage bitmaps into
//! "patterns" in a redb store. `set-cover` computes the minimal block set
//! covering every branch counter ever observed, `report` renders an llvm-cov
//! summary for that set, `inspect` prints store statistics, and `merge`
//! combines per-machine shard stores from a distributed scan.
//!
//! ## Carrying a scan across a mega-evm bump
//!
//! Counter ids — and therefore every stored bitmap — belong to one
//! instrumented build (see [`store::current_binary_id`]). When mega-evm or
//! the toolchain moves, `backfill`, `set-cover` and `merge` all refuse the
//! old store, and a full re-sweep of mainnet history costs weeks. What
//! survives the bump is the *block numbers*, so the tool carries them over
//! instead of the bitmaps:
//!
//! ```text
//! inspect --dump-pool pool.txt   (old build; read-only, no binary-id check)
//!   └─ cat pool*.txt | sort -un > union.txt     (across shards, if sharded)
//!        └─ backfill --blocks-file union.txt    (new build, fresh data-dir)
//!             └─ set-cover → report             (new minimal set)
//! ```
//!
//! The pool is the antichain's representatives rather than the previous
//! minimal set: a cover is minimal only for the universe that produced it and
//! has no slack once a new build splits patterns the old one merged. `inspect`
//! is the one subcommand that skips the binary-id check, so the pool can be
//! extracted from an old store at any time — including long after the bump.

mod backfill;
mod bitset;
mod inspect;
mod llvm;
mod merge;
mod profile_rt;
mod proto;
mod r2;
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

// The variants differ in size because `BackfillArgs` carries the whole
// fetch/witness/R2 configuration while the others take a data-dir and a flag
// or two. One `Cmd` is built per process, straight into a `match` — boxing it
// would only add an allocation and a clap indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Cmd {
    /// Replay a block range, ingest branch-granular coverage bitmaps.
    Backfill(backfill::BackfillArgs),
    /// Compute the greedy minimal block set from the pattern store.
    SetCover(setcover::SetCoverArgs),
    /// Print an llvm-cov report for the currently selected set.
    Report(report::ReportArgs),
    /// Read-only store statistics (works on stores from other builds).
    Inspect(inspect::InspectArgs),
    /// Merge per-shard stores (disjoint ranges, same build) into one.
    Merge(merge::MergeArgs),
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
        Cmd::Merge(args) => merge::run(args),
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, error::ErrorKind};

    use super::*;

    /// `--help` is a clap *feature*, not something the derive gives you: with
    /// `default-features = false` and the `help` feature trimmed, every
    /// `--help` becomes `UnknownArgument` and errors lose their usage line.
    /// This pins the workspace's clap features against that trim.
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

    /// The companion half: an unknown flag must name itself and print usage,
    /// which needs `error-context` and `usage`.
    #[test]
    fn unknown_flags_report_the_offender_and_usage() {
        let err = Cli::try_parse_from(["coverage-replayer", "inspect", "--bogus"])
            .expect_err("unknown flag must fail");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("--bogus"), "error must name the flag: {rendered}");
        assert!(rendered.contains("Usage:"), "error must carry usage: {rendered}");
    }

    /// A pool is made of the antichain, so asking for one while skipping the
    /// pass that computes it is a contradiction clap must reject up front —
    /// not a run that silently writes nothing.
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
