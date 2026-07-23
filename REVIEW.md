# Code Review Guidelines

This file holds the **stateless-validator-specific** review rules.
The generic review rubric — mindset, priority order, severity scale, the do-not-flag baseline, reviewer anti-patterns, and previous-thread triage — lives in the centralized `claude-pr-review` action and is applied automatically.
These per-repo rules take precedence wherever they conflict with that baseline.

## Design and architecture

- Use the type system to express semantics — prefer `BlockNumber` over `u64`, newtypes over primitive aliases. Make invalid states unrepresentable.
- Prefer existing types and structs over inventing new ones; only introduce a new type when existing ones carry wrong semantics.
- Respect reth's design patterns and framework conventions — stateless-validator uses reth as a library and should not replace its abstractions.
- Do not patch upstream dependencies unless the PR description gives a strong justification.
- Prefer typed errors (`thiserror` or manual enums) for new library code so callers can match on variants; `eyre` is fine in top-level binary modules and in existing library APIs that already use it.
- Abstract behaviors that depend on the external environment (network, disk, time) behind traits so unit testing is possible.

## Correctness and safety

- Changes to consensus-critical code — EVM execution, witness verification, state root computation, withdrawals — require extra scrutiny.
- Watch for read-check-write without atomicity (lock, CAS, or database constraint), CPU-intensive work that should use `spawn_blocking` inside async contexts, and deadlocks from nested lock acquisition.
- **Fail closed on the terminal publish.** The final step (e.g. `mega_setValidatedBlocks`) must not look like success when the run has no later opportunity to retry (e.g. an `--end-block` slice run) — surface a non-zero exit / `Err` so the orchestrator cannot record the slice as complete while upstream never saw the tip. A chain-following run is the deliberate exception: it re-reports anchor→tip on its next start, so a tolerated final-report miss heals itself.
- **Validate config at the boundary.** Reject or clamp nonsensical config at load: a `*_timeout_ms` of `0` makes `tokio::time::timeout` fail every attempt immediately; an unbounded size/alloc hint invites upfront over-allocation. Require `> 0` (or a clamp) before the value reaches the retry loop.
- **Classify remote errors precisely.** Match known error codes (e.g. a small set of S3 codes), not `body.contains(...)` on response text a proxy can reshape. Give an exhausted-retry cycle an inter-cycle throttle so it doesn't re-burst after a brownout.

## Observability

- Use `tracing` macros, never `println!`/`eprintln!`, with structured key-value fields: `debug!(tx_count, block_number, "Processed transactions")`.
- Field conventions: `snake_case` names, `%err` (Display) for errors, `?hash` (Debug) for complex types.
- Log level by frequency: `error!` unrecoverable, `warn!` recoverable anomalies (slow-log alerts include elapsed/threshold/operation), `info!` lifecycle, `debug!` investigation, `trace!` for >100/s paths.
- `#[instrument]` must use `skip_all` with explicit `fields(...)`; avoid spans on hot paths (>1000/s).
- Prometheus metrics use `snake_case` with unit suffixes (`_seconds`, `_bytes`, `_total`) and no high-cardinality labels (no tx hashes or addresses as values).

## Tests

- Enforce determinism: no `sleep`-based assertions, no wall-clock dependence; use a `SEED` constant where randomness is needed.
- Assert the exact expected value (`assert_eq!` over `assert!`) and the specific error variant (`matches!(result, Err(MyError::Specific(..)))`), not just `is_ok()`/`is_err()`.
- Test side effects and the absence of unintended changes, not only the return value.
- When exact output is hard to specify, assert invariants (round-trip, idempotency, monotonicity) or compare against a simplified reference oracle.
- Derive `Debug`/`PartialEq` on types under test for readable diffs; ban assertion-free tests and bare `unwrap()` used as the only check.
- If a change affects cross-component behavior that unit tests cannot cover, suggest e2e tests (these may live in a separate repo).

## What NOT to flag

- `result_large_err` — not enforced (allow-by-default in clippy).
