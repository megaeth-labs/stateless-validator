//! coverage-replayer: continuously derive the minimal mainnet block set that
//! maximizes mega-evm code coverage.
//!
//! See `validator-data/2026-07-08-coverage-replayer-design.md` for the design.
//! M1 scope: `backfill` (range replay → pattern store), `set-cover`, `report`,
//! plus the hidden `internal-worker` subprocess mode.

mod backfill;
mod bitset;
mod inspect;
mod llvm;
mod merge;
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
