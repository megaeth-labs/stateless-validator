# AGENTS.md

This file provides guidance to AI agents (e.g., Claude Code, Codex, Cursor, etc.) when working with code in this repository.

## Project Overview

Stateless validator for MegaETH — validates blocks using SALT witness data without requiring full chain state.
The workspace contains two binaries: `stateless-validator` (chain-following validator) and `debug-trace-server` (RPC server for debug/trace methods).
See `README.md` for detailed documentation and quickstart.

## Build & Development Commands

```bash
# Build
cargo build
cargo build --release

# Test
cargo test                                    # all tests
cargo test -p stateless-core                  # core crate only
cargo test -p stateless-core -- test_name     # single test

# Check compiler errors (preferred over clippy for quick checks)
cargo check
cargo check -p stateless-core

# Lint (CI runs all of these)
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
cargo sort --check --workspace --grouped --order package,workspace,lints,profile,bin,benches,dependencies,dev-dependencies,features
```

The project uses nightly `2026-02-03` toolchain (edition 2024, rust-version 1.95).

## Workspace Structure

| Crate                 | Path                      | Purpose                                                    |
| --------------------- | ------------------------- | ---------------------------------------------------------- |
| `stateless-core`      | `crates/stateless-core`   | Core validation logic, database, EVM execution, RPC client |
| `stateless-common`    | `crates/stateless-common` | Common utilities including logging configuration           |
| `stateless-validator` | `bin/stateless-validator` | Main binary: chain sync, parallel validation workers       |
| `debug-trace-server`  | `bin/debug-trace-server`  | Standalone RPC server for debug/trace methods              |

Additional directories: `test_data/` (integration test fixtures including genesis config), `audits/` (security audit reports).

## Architecture

### Pipeline

Both binaries share a generic three-stage pipeline defined in `stateless-core::pipeline`:

1. **Fetch** — `block_fetcher` pulls blocks + witnesses from a `BlockFetcher` in parallel batches.
2. **Process** — N workers run `BlockProcessor::process` (validator: EVM execution; trace server: pass-through).
3. **Advance** — `chain_advancer` reorders out-of-order results, verifies parent-hash continuity, detects reorgs, and persists via `ChainStore::advance_chain`.

The outer loop (`run_pipeline`) handles reorg rollback + restart, stale-data anchor reset, and transient vs fatal error classification.

### Database

The validator and trace server each have their own `redb`-backed database.
Shared table definitions live in `stateless-common::db`:

- **`ANCHOR_BLOCK`** — Trusted starting point (block number, hash, state root, withdrawals root).
- **`CANONICAL_CHAIN`** — Validated chain progression (block number → hash, state root, withdrawals root).
- **`CONTRACTS`** — On-demand contract bytecode cache (code hash → bincode+lz4 bytecode).
- **`GENESIS_CONFIG`** — Hardfork activation rules (validator only).
- **`BLOCK_DATA`** — Full block content (trace server only).
- **`WITNESSES`** — Light witness data (trace server only).
- **`BLOCK_RECORDS`** — Pruning index mapping (block number, hash) → () (trace server only).

### WitnessDatabase

`WitnessDatabase` implements `revm::DatabaseRef`, providing EVM state from SALT witness data instead of a full state database.
This is the core abstraction enabling stateless validation — block execution sees the same interface as a full node but reads from witness proofs.

### SALT Witness Cryptography

SALT (Small Authentication Large Trie) is the authenticated key-value store that replaces Merkle Patricia Tries for MegaETH state.
It uses a static 4-level, 256-ary complete tree with ~16.7 million leaf nodes (buckets), each containing a dynamic strongly history-independent (SHI) hash table.
Cryptographic commitments use the **Banderwagon** elliptic curve with **IPA** (Inner Product Argument) vector commitments, enabling compact aggregatable proofs.

A `SaltWitness` contains:

- **State subset** — All accessed key-value pairs with inclusion proofs (`Some(value)`) or non-existence proofs (`None`).
- **Cryptographic proof (`SaltProof`)** — Node commitments from queried buckets to the root, plus an aggregated IPA multipoint proof.

During validation, the witness is verified against the block's pre-state root, `WitnessDatabase` serves state reads from the verified witness during EVM execution, and post-execution state deltas are propagated up the trie (max 4 levels) to compute and verify the post-state root.

### Debug/Trace Server

The `debug-trace-server` binary exposes six RPC methods:

- **`debug_traceBlockByNumber`**, **`debug_traceBlockByHash`**, **`debug_traceTransaction`** — Geth-style debug tracing.
- **`debug_getCacheStatus`** — Query the HTTP response cache status.
- **`trace_block`**, **`trace_transaction`** — Parity-style flat call traces.

Two operating modes:

- **Stateless mode** — All data fetched from remote RPC on demand (no `data_dir`).
- **Local cache mode** — With `data_dir`, enables chain sync to pre-fetch blocks into `ValidatorDB` for faster serving.

The server includes an HTTP response cache (`quick_cache`) for pre-serialized JSON and a `DataProvider` with single-flight request coalescing.

### Key Source Files

| File                                          | Purpose                                                                             |
| --------------------------------------------- | ----------------------------------------------------------------------------------- |
| `crates/stateless-core/src/pipeline.rs`       | Generic pipeline: BlockFetcher, run_pipeline, chain_advancer, find_divergence_point |
| `crates/stateless-core/src/executor.rs`       | Block validation and EVM replay                                                     |
| `crates/stateless-core/src/evm_database.rs`   | WitnessDatabase implementing `revm::DatabaseRef`                                    |
| `crates/stateless-core/src/db.rs`             | Abstract storage traits (ChainStore, BlockStore, etc.)                              |
| `crates/stateless-core/src/withdrawals.rs`    | Withdrawal validation and MPT witness handling                                      |
| `crates/stateless-common/src/rpc_client.rs`   | RPC client for blocks, witnesses, and bytecode                                      |
| `crates/stateless-common/src/db.rs`           | Shared redb table definitions and serialization helpers                             |
| `crates/stateless-common/src/metrics.rs`      | RpcMethod, RpcMetrics, RpcClientConfig                                              |
| `bin/stateless-validator/src/chain_sync.rs`   | ValidatorFetcher, ValidatorProcessor, ValidatorHooks                                |
| `bin/stateless-validator/src/main.rs`         | CLI, pipeline startup, validation reporter                                          |
| `bin/debug-trace-server/src/chain_sync.rs`    | TraceFetcher, TraceProcessor, TraceHooks                                            |
| `bin/debug-trace-server/src/rpc_service.rs`   | RPC method definitions and handlers                                                 |
| `bin/debug-trace-server/src/data_provider.rs` | Block data fetching with single-flight coalescing                                   |

## Test Organization

Unit tests are embedded in source files alongside the code they test.
Integration tests live in `bin/debug-trace-server/tests/` (6 modules: cache_metrics, block_tag, consistency, performance, timing_header, prune).
Test data (block JSON files, contract bytecode, witness data) is stored in `test_data/`.

## Version Control

The main branch is `main` and it is protected.
All changes should be made via PRs on GitHub, merged with squash-and-merge.

### Branch naming convention

The naming convention for git branches is `{developer}/{category}/{description}`, where:

- `{developer}` is the (nick)name of the developer.
- `{category}` should indicate what type of modification, e.g., `feat`, `fix`, `doc`, `ci`, `refactor`.
- `{description}` is a short description of the changes (a few words, hyphen-separated).

Example: `alice/feat/add-response-cache`, `bob/fix/prune-canonical-chain`.

### Commit style

Commit messages follow the conventional commits format: `type: description`.
Common types: `feat`, `fix`, `refactor`, `ci`, `perf`, `docs`, `test`.

## Workflows

### Committing changes

When requested to commit changes, first review all changes in the working tree, regardless of whether they are staged.
There may be other changes in the worktree in addition to those made by the agent, which may also need to be included.
If unsure whether some changes should be included in the commit, ask the user.
The commit message should reflect the overall changes of the commit, which may extend beyond the agent's immediate context.

### Creating PRs

When a PR creation is requested, the agent should:

1. Check if the repo is on a branch other than `main`; if not, create and checkout a new branch and inform the user.
2. Commit the changes in the worktree before fixing linting issues.
3. Run lint checks, fix any warnings, then commit if there are changes.
4. Format the code and commit if there are changes.
5. Push to the remote.
6. Use the `gh` CLI tool to create a PR with a `Summary` section at the top of the description.

PRs will be merged with squash-and-merge, so the PR description should serve as the squash commit message.

### Implementing features or bug fixes

When implementing a new feature or bug fix, consider these additional aspects:

1. Should documentation be updated or added?
2. Are there sufficient tests for this change?
3. Run `cargo check` first for quick compiler feedback, then `cargo clippy` for lint issues.

## Caveats for Agents

- **Always test logic changes.**
  Any logic change should be accompanied by tests unless there is a specific reason not to.
- **`cargo sort` is enforced in CI.**
  Dependencies in `Cargo.toml` must follow the grouped-by-family convention with comment headers (e.g., `# alloy`, `# reth`, `# megaeth`, `# misc`) and be sorted alphabetically within each group.
- **Use `default-features = false` for new workspace dependencies.**
  Features are opted-in explicitly; this is the standard convention.
- **Use `cargo check` for quick compiler error feedback.**
  Use `cargo clippy` only when specifically checking lint warnings.
- **Respect `rustfmt.toml` configuration.**
  Key settings: `imports_granularity = "Crate"` (merge imports from same crate) and `group_imports = "StdExternalCrate"` (std, then external, then crate-local).
- **`bincode` v2 with two configs — do not mix them up.**
  This project uses bincode v2; do not use v1-style APIs (e.g., `bincode::serialize`).
  Always use `bincode::serde::decode_from_slice` / `bincode::serde::encode_to_vec`.
  - **RPC witness data** uses `bincode::config::legacy()` (fixed-int encoding, compatible with upstream witness generator which uses bincode 1.x).
    The upstream witness generator serializes `(SaltWitness, MptWitness)` with bincode legacy, then zstd-compresses, then base64-encodes, and sends as a `"v0:<base64>"` JSON-RPC string.
  - **Local DB storage** (contracts, light witnesses) uses `bincode::config::standard()` (varint encoding, more compact) with lz4 compression.
  - These two formats are **not interchangeable**. `legacy()` and `standard()` produce different binary layouts.
- **All persistent state goes through `ValidatorDB`.**
  Do not create separate database files or ad-hoc persistence; use the existing redb tables.
- **Keep documentation up to date.**
  When making changes, check whether related documentation (README, this file) needs updating.
- **One sentence, one line.**
  When writing Markdown files, put each sentence on a separate line.
