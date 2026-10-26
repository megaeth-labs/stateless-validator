//! Replay an explicit list of block numbers through the validator's own fetch and validate path.
//!
//! The chain-following pipeline advances over a contiguous range, so it cannot visit a sparse
//! set of heights. This mode instead drives [`ValidatorFetcher::fetch`] and
//! [`ValidatorProcessor::process`] directly, the same two components the pipeline runs, so a
//! block that passes here is accepted by the production validator.
//!
//! Nothing here touches the canonical chain: no anchor is set, no tip advances, and nothing is
//! reported upstream. Each block is validated on its own, which means a pass establishes that
//! the witness is self-consistent and that replaying the block reproduces its header, but not
//! that the witness's pre-state is the parent block's post-state.

use std::{
    any::Any,
    collections::BTreeSet,
    fs::File,
    io::{BufWriter, Write},
    panic::AssertUnwindSafe,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::BlockHash;
use eyre::{Result, WrapErr, ensure};
use futures::FutureExt;
use stateless_core::pipeline::{BlockFetcher, BlockProcessor};
use tokio::task::JoinSet;
use tracing::info;

use crate::chain_sync::{ValidatorFetcher, ValidatorProcessor};

/// How many of the slowest blocks the summary names.
const SLOWEST_SHOWN: usize = 5;
/// How many failures the printed summary spells out; all of them are in the results file.
const FAILURES_SHOWN: usize = 20;
/// What the retry list holds until the run finishes. It parses as an empty list, which is an
/// error, so an interrupted run's list fails loudly instead of retrying nothing or the wrong set.
const RETRY_LIST_PENDING: &str =
    "# the run did not finish: no retry list was written; see results.jsonl\n";

/// Parses a block list: one decimal block number per line.
///
/// Blank lines and lines starting with `#` are skipped, so a candidate-pool file with its
/// comment header is accepted as is. Duplicates collapse, and the result is ascending, which
/// keeps neighbouring blocks together for the witness bucket and the contract cache. A line that
/// is neither a comment nor a number fails the whole parse naming its line, since silently
/// dropping an entry would shrink the set the run claims to have covered.
pub fn parse_block_list(text: &str) -> Result<Vec<u64>> {
    let mut blocks = BTreeSet::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = line
            .parse::<u64>()
            .wrap_err_with(|| format!("line {}: {line:?} is not a block number", index + 1))?;
        blocks.insert(number);
    }
    ensure!(!blocks.is_empty(), "the block list contains no block numbers");
    Ok(blocks.into_iter().collect())
}

/// How one block's replay ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Witness verified, block replayed, and every header claim reproduced.
    Validated,
    /// The block and its witness were not both fetched within the per-block timeout.
    FetchTimeout,
    /// The fetch ended with an error instead of a block.
    FetchFailed,
    /// Fetching succeeded but validating did not finish within the per-block timeout.
    ProcessTimeout,
    /// The validator rejected the block, or its task panicked.
    ValidationFailed,
}

impl Status {
    /// The stable name written to the results file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::FetchTimeout => "fetch_timeout",
            Self::FetchFailed => "fetch_failed",
            Self::ProcessTimeout => "process_timeout",
            Self::ValidationFailed => "validation_failed",
        }
    }
}

/// The result of replaying one block.
#[derive(Clone, Debug)]
pub struct BlockOutcome {
    pub number: u64,
    /// `None` when the block was never fetched.
    pub hash: Option<BlockHash>,
    pub status: Status,
    /// The validator's error text, verbatim. It is not parsed or bucketed: the error type is
    /// flattened to a string by the processor, and matching on its wording would break silently.
    pub message: Option<String>,
    /// Whether a retry may pass: always for a fetch failure or a timeout, which say nothing about
    /// the block itself, and for a validation failure when the processor judges it transient (a
    /// store error rather than a deterministic mismatch).
    pub retryable: bool,
    pub elapsed: Duration,
}

impl BlockOutcome {
    fn new(number: u64, hash: Option<BlockHash>, status: Status, started: Instant) -> Self {
        Self { number, hash, status, message: None, retryable: false, elapsed: started.elapsed() }
    }

    fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// One results-file line.
    pub fn to_json_line(&self) -> String {
        serde_json::json!({
            "block": self.number,
            "hash": self.hash.map(|hash| hash.to_string()),
            "status": self.status.as_str(),
            "ms": self.elapsed.as_millis() as u64,
            "retryable": self.retryable,
            "message": self.message,
        })
        .to_string()
    }
}

/// Knobs for [`replay_block_list`].
#[derive(Clone, Debug)]
pub struct ReplayConfig {
    /// Blocks fetched or validated at once.
    pub concurrency: usize,
    /// Bound on each of the fetch and the validation of one block. The RPC client retries
    /// transport errors forever, so without it a block the endpoints cannot serve would hold a
    /// slot, and the run, open indefinitely.
    pub block_timeout: Duration,
    /// Minimum gap between progress lines.
    pub progress_every: Duration,
}

/// Totals for a finished run.
#[derive(Clone, Debug, Default)]
pub struct ReplaySummary {
    pub total: usize,
    pub validated: usize,
    pub failed: Vec<BlockOutcome>,
    pub elapsed: Duration,
    /// The slowest blocks, slowest first.
    pub slowest: Vec<(u64, Duration)>,
}

impl ReplaySummary {
    fn record(&mut self, outcome: &BlockOutcome) {
        self.total += 1;
        if outcome.status == Status::Validated {
            self.validated += 1;
        } else {
            self.failed.push(outcome.clone());
        }
        self.slowest.push((outcome.number, outcome.elapsed));
        self.slowest.sort_by_key(|&(_, elapsed)| std::cmp::Reverse(elapsed));
        self.slowest.truncate(SLOWEST_SHOWN);
    }

    /// Blocks per second over the whole run.
    pub fn rate(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 { self.total as f64 / secs } else { 0.0 }
    }

    /// The failed block numbers in the same format the input accepts, so the file can be
    /// handed straight back as `--block-list` to retry exactly the failures.
    pub fn failed_list(&self) -> String {
        let mut numbers: Vec<u64> = self.failed.iter().map(|outcome| outcome.number).collect();
        numbers.sort_unstable();
        let mut text = format!("# blocks that did not validate: {}\n", numbers.len());
        for number in numbers {
            text.push_str(&format!("{number}\n"));
        }
        text
    }

    /// The human-readable end-of-run report.
    pub fn render(&self) -> String {
        let mut out = format!(
            "replayed {} blocks in {:.1}s ({:.1} blocks/s): {} validated, {} not validated\n",
            self.total,
            self.elapsed.as_secs_f64(),
            self.rate(),
            self.validated,
            self.failed.len(),
        );
        let mut statuses: Vec<Status> = self.failed.iter().map(|outcome| outcome.status).collect();
        statuses.sort_by_key(|status| status.as_str());
        statuses.dedup();
        for status in statuses {
            let count = self.failed.iter().filter(|outcome| outcome.status == status).count();
            out.push_str(&format!("  {}: {count}\n", status.as_str()));
        }
        if !self.slowest.is_empty() {
            let slowest: Vec<String> = self
                .slowest
                .iter()
                .map(|(number, elapsed)| format!("{number} ({:.1}s)", elapsed.as_secs_f64()))
                .collect();
            out.push_str(&format!("slowest: {}\n", slowest.join(", ")));
        }
        let mut failed: Vec<&BlockOutcome> = self.failed.iter().collect();
        failed.sort_by_key(|outcome| outcome.number);
        for outcome in failed.iter().take(FAILURES_SHOWN) {
            out.push_str(&format!(
                "  {} {}: {}\n",
                outcome.number,
                outcome.status.as_str(),
                outcome.message.as_deref().unwrap_or("-"),
            ));
        }
        if failed.len() > FAILURES_SHOWN {
            out.push_str(&format!("  ... and {} more\n", failed.len() - FAILURES_SHOWN));
        }
        out
    }
}

/// Fetches and validates one block, bounding each stage by `timeout`.
async fn replay_one(
    fetcher: &ValidatorFetcher,
    processor: &ValidatorProcessor,
    number: u64,
    timeout: Duration,
) -> BlockOutcome {
    let started = Instant::now();
    let task = match tokio::time::timeout(timeout, fetcher.fetch(number)).await {
        Err(_) => {
            return BlockOutcome::new(number, None, Status::FetchTimeout, started)
                .with_message(format!("block and witness not fetched within {timeout:?}"))
                .with_retryable(true);
        }
        Ok(Err(error)) => {
            return BlockOutcome::new(number, None, Status::FetchFailed, started)
                .with_message(format!("{error:#}"))
                .with_retryable(true);
        }
        Ok(Ok(task)) => task,
    };

    let hash = task.block.header.hash;

    match tokio::time::timeout(timeout, processor.process(task)).await {
        Err(_) => BlockOutcome::new(number, Some(hash), Status::ProcessTimeout, started)
            .with_message(format!("not validated within {timeout:?}"))
            .with_retryable(true),
        Ok(Ok(_)) => BlockOutcome::new(number, Some(hash), Status::Validated, started),
        Ok(Err(failure)) => {
            BlockOutcome::new(number, Some(hash), Status::ValidationFailed, started)
                .with_message(failure.error)
                .with_retryable(failure.transient)
        }
    }
}

/// Runs one block's replay, turning a panic inside it into that block's own outcome, timed from
/// when the block started, rather than into a join error that no longer knows which block it was.
async fn settle(number: u64, replay: impl Future<Output = BlockOutcome>) -> BlockOutcome {
    let started = Instant::now();
    AssertUnwindSafe(replay).catch_unwind().await.unwrap_or_else(|panic| {
        BlockOutcome::new(number, None, Status::ValidationFailed, started)
            .with_message(format!("replay panicked: {}", panic_message(&*panic)))
    })
}

/// The text of a panic payload, for the two payload types `panic!` produces.
fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

/// Replays `blocks` with up to `config.concurrency` in flight, handing each finished outcome to
/// `sink` as it completes.
///
/// A failing block never stops the run: it is recorded and the next one starts. The only early
/// exit is `sink` returning an error, which means the results file can no longer be written.
pub async fn replay_block_list(
    fetcher: Arc<ValidatorFetcher>,
    processor: Arc<ValidatorProcessor>,
    blocks: Vec<u64>,
    config: &ReplayConfig,
    mut sink: impl FnMut(&BlockOutcome) -> Result<()>,
) -> Result<ReplaySummary> {
    ensure!(config.concurrency > 0, "concurrency must be at least 1");
    let started = Instant::now();
    let total = blocks.len();

    // The fetcher records the head it last saw and the R2 client reads it to tell a block that
    // is simply not uploaded yet from a hole in the bucket. Seed it once; left at its initial
    // 0, every miss would band as "not uploaded yet" and a real hole would never be flagged.
    // The read retries forever like every RPC call, so it is bounded like a block's stages are.
    let budget = config.block_timeout;
    let head = tokio::time::timeout(budget, fetcher.latest_block_number())
        .await
        .wrap_err_with(|| format!("the chain head was not read within {budget:?}"))??;
    info!(blocks = total, head, concurrency = config.concurrency, "Replaying block list");

    let spawn = |tasks: &mut JoinSet<BlockOutcome>, number: u64| {
        let (fetcher, processor) = (Arc::clone(&fetcher), Arc::clone(&processor));
        let timeout = config.block_timeout;
        tasks.spawn(settle(number, async move {
            replay_one(&fetcher, &processor, number, timeout).await
        }));
    };
    let mut pending = blocks.into_iter();
    let mut tasks = JoinSet::new();
    for number in pending.by_ref().take(config.concurrency) {
        spawn(&mut tasks, number);
    }

    let mut summary = ReplaySummary::default();
    let mut last_progress = Instant::now();
    while let Some(joined) = tasks.join_next().await {
        // `settle` turns a panic into an outcome, so a join error can only be a cancellation.
        let outcome = joined.wrap_err("a replay task was cancelled")?;
        sink(&outcome)?;
        summary.record(&outcome);
        if let Some(number) = pending.next() {
            spawn(&mut tasks, number);
        }

        if last_progress.elapsed() >= config.progress_every {
            last_progress = Instant::now();
            info!(
                done = summary.total,
                total,
                failed = summary.failed.len(),
                rate = format!("{:.1}/s", summary.total as f64 / started.elapsed().as_secs_f64()),
                "Replay progress"
            );
        }
    }

    summary.elapsed = started.elapsed();
    Ok(summary)
}

/// Where a run writes its output, both files truncated at the start.
pub struct Output<'a> {
    /// One JSON object per block, in completion order, flushed as each lands so an interrupted
    /// run keeps what it had.
    pub results: &'a Path,
    /// The retry list: the failed block numbers in the input format, written when the run
    /// finishes. Until then it holds only a comment, so an interrupted run never leaves an
    /// earlier run's list beside its own results.
    pub failed: &'a Path,
}

/// Reads `list`, replays it, writes the output files, prints the summary, and fails when any
/// block did not validate.
pub async fn run(
    list: &Path,
    output: Output<'_>,
    fetcher: Arc<ValidatorFetcher>,
    processor: Arc<ValidatorProcessor>,
    config: &ReplayConfig,
) -> Result<()> {
    // Read the whole list before touching the output files: the retry list written by an
    // earlier run is a legitimate input, and may live where this run's output will.
    let text = std::fs::read_to_string(list)
        .wrap_err_with(|| format!("cannot read the block list {}", list.display()))?;
    let blocks = parse_block_list(&text)?;

    let mut results = BufWriter::new(
        File::create(output.results)
            .wrap_err_with(|| format!("cannot create {}", output.results.display()))?,
    );
    std::fs::write(output.failed, RETRY_LIST_PENDING)
        .wrap_err_with(|| format!("cannot write {}", output.failed.display()))?;
    let summary = replay_block_list(fetcher, processor, blocks, config, |outcome| {
        writeln!(results, "{}", outcome.to_json_line())?;
        results.flush()?;
        Ok(())
    })
    .await?;

    std::fs::write(output.failed, summary.failed_list())
        .wrap_err_with(|| format!("cannot write {}", output.failed.display()))?;
    println!("{}", summary.render());
    println!("results: {}", output.results.display());
    println!("retry list: {}", output.failed.display());

    ensure!(
        summary.failed.is_empty(),
        "{} of {} blocks did not validate",
        summary.failed.len(),
        summary.total
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(number: u64, status: Status, ms: u64) -> BlockOutcome {
        BlockOutcome {
            number,
            hash: None,
            status,
            message: (status != Status::Validated).then(|| format!("boom {number}")),
            retryable: false,
            elapsed: Duration::from_millis(ms),
        }
    }

    #[test]
    fn a_pool_file_parses_with_its_comment_header() {
        let text = "# coverage-replayer candidate pool\n# blocks: 3\n7\n\n  3  \n7\n12\r\n";
        assert_eq!(parse_block_list(text).unwrap(), vec![3, 7, 12]);
    }

    #[test]
    fn a_bad_line_fails_the_parse_and_names_its_line() {
        let error = parse_block_list("1\n2\nxyz\n4\n").unwrap_err().to_string();
        assert!(error.contains("line 3") && error.contains("xyz"), "got: {error}");
        // A trailing comment is not a comment: only whole-line comments are skipped, and a
        // half-parsed entry must not slip through as a smaller number.
        assert!(parse_block_list("5 # five\n").is_err());
        assert!(parse_block_list("-1\n").is_err());
        assert!(parse_block_list("0x10\n").is_err());
    }

    #[test]
    fn an_empty_list_is_an_error_not_a_vacuous_pass() {
        assert!(parse_block_list("").is_err());
        assert!(parse_block_list("# only a header\n\n").is_err());
    }

    #[test]
    fn the_summary_separates_validated_from_failed_and_keeps_the_slowest() {
        let mut summary = ReplaySummary::default();
        for (number, status, ms) in [
            (10, Status::Validated, 40),
            (11, Status::FetchTimeout, 300_000),
            (12, Status::Validated, 90),
            (13, Status::ValidationFailed, 20),
            (14, Status::Validated, 10),
            (15, Status::Validated, 5),
            (16, Status::Validated, 6),
        ] {
            summary.record(&outcome(number, status, ms));
        }
        summary.elapsed = Duration::from_secs(7);

        assert_eq!((summary.total, summary.validated, summary.failed.len()), (7, 5, 2));
        assert_eq!(summary.slowest.len(), SLOWEST_SHOWN);
        assert_eq!(summary.slowest[0].0, 11);
        assert!((summary.rate() - 1.0).abs() < 1e-9);

        // The retry list is ascending, in the input format, and round-trips through the parser.
        assert_eq!(parse_block_list(&summary.failed_list()).unwrap(), vec![11, 13]);

        let report = summary.render();
        assert!(report.contains("5 validated, 2 not validated"), "got: {report}");
        assert!(report.contains("fetch_timeout: 1") && report.contains("validation_failed: 1"));
        assert!(report.contains("13 validation_failed: boom 13"));
    }

    #[test]
    fn a_run_with_no_failures_writes_an_empty_retry_list() {
        let mut summary = ReplaySummary::default();
        summary.record(&outcome(1, Status::Validated, 1));
        assert!(parse_block_list(&summary.failed_list()).is_err(), "no numbers to retry");
        assert!(summary.failed_list().starts_with("# blocks that did not validate: 0"));
    }

    /// A panic is reported against the block that panicked, timed from that block's own start
    /// rather than the run's, for both payload types `panic!` produces.
    #[tokio::test]
    async fn a_panicking_replay_becomes_its_own_blocks_failure() {
        let outcome = settle(42, async { panic!("boom at 42") }).await;
        assert_eq!((outcome.number, outcome.status), (42, Status::ValidationFailed));
        assert!(outcome.message.as_deref().unwrap().contains("boom at 42"), "{outcome:?}");
        assert!(!outcome.retryable, "a panic is a bug, not a transient failure");
        assert!(outcome.elapsed < Duration::from_secs(5), "{:?}", outcome.elapsed);

        let owned = settle(7, async { panic!("{}", String::from("owned payload")) }).await;
        assert!(owned.message.unwrap().contains("owned payload"));
    }

    #[test]
    fn the_pending_retry_list_parses_as_no_blocks() {
        assert!(parse_block_list(RETRY_LIST_PENDING).is_err());
    }

    #[test]
    fn a_result_line_is_one_json_object_with_the_verbatim_message() {
        let line = outcome(8, Status::ValidationFailed, 12).to_json_line();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["block"], 8);
        assert_eq!(value["status"], "validation_failed");
        assert_eq!(value["ms"], 12);
        assert_eq!(value["message"], "boom 8");
        assert!(value["hash"].is_null());
        assert!(!line.contains('\n'));
    }
}
