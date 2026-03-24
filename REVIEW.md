# Code Review Guidelines

## Always check

- New or modified logic has accompanying tests
- PR must not patch upstream dependencies unless there is a strong justification in the PR description
- Any change to a public API or interface must have a clear reason documented in an inline comment or the PR description

## Logging

- Use `tracing` macros (`info!`, `debug!`, `warn!`, `error!`, `trace!`), never `println!` or `eprintln!`
- Use structured key-value fields, not string interpolation: `debug!(tx_count, block_number, "Processed transactions")` not `debug!("Processed {} txs at block {}", tx_count, block_number)`
- Log levels based on frequency: `error!` for unrecoverable, `warn!` for recoverable anomalies, `info!` for infrequent lifecycle events, `debug!` for investigation, `trace!` for high-frequency paths
- `#[instrument]` must use `skip_all` with explicit `fields(...)`

## Metrics

- Recurring counts and durations should be metrics, not logs
- No high-cardinality labels (no tx hashes or addresses as label values)
- Prometheus naming conventions: `snake_case` with unit suffixes (`_seconds`, `_bytes`, `_total`)

## Previous comments

- Before writing new comments, check all previous review threads on this PR
- If a previous comment has been addressed by the latest changes, resolve that thread using:
  `gh api graphql -f query='mutation { resolveReviewThread(input:{threadId:"THREAD_ID"}) { thread { id } } }'`
- To find thread IDs, query:
  `gh api graphql -f query='{ repository(owner:"OWNER", name:"REPO") { pullRequest(number:NUMBER) { reviewThreads(first:50) { nodes { id isResolved comments(first:1) { nodes { body path } } } } } } }'`
- Do not repeat feedback that has already been addressed

## Skip

- Formatting-only changes already enforced by `cargo fmt`
- Lint issues already caught by `cargo clippy`
