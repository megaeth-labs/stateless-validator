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

| Crate                  | Path                          | Purpose                                                                                                                                                                                  |
| ---------------------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `stateless-core`       | `crates/stateless-core`       | Storage traits, pipeline, EVM execution, SALT witness handling, chain spec, error types                                                                                                  |
| `stateless-db`         | `crates/stateless-db`         | redb-backed persistence: table definitions, read/write helpers, `ContractCache`                                                                                                          |
| `stateless-common`     | `crates/stateless-common`     | RPC client, metrics/logging utilities, witness size estimation                                                                                                                           |
| `stateless-test-utils` | `crates/stateless-test-utils` | Test fixtures (blocks, witnesses, contracts) and env-var lock for integration tests                                                                                                      |
| `stateless-r2`         | `crates/stateless-r2`         | Shared R2 witness primitives: SigV4 signer, object-key layout, endpoint parsing, signed PUT, and the retrying witness-object GET fetcher over either the signed S3 API or an unsigned Cloudflare custom domain; consumed by mega-reth's uploaders (write) and both binaries' R2 witness sources (read) |
| `stateless-validator`  | `bin/stateless-validator`     | Main binary: chain sync, parallel validation workers (`app.rs` / `workers.rs` / `main.rs`)                                                                                               |
| `debug-trace-server`   | `bin/debug-trace-server`      | Standalone RPC server for debug/trace methods                                                                                                                                            |

Additional directories: `test_data/` (integration test fixtures including genesis config), `audits/` (security audit reports).

## Architecture

### Pipeline

Both binaries share a generic three-stage pipeline defined in `stateless-core::pipeline`:

1. **Fetch** — `block_fetcher` streams blocks + witnesses from a `BlockFetcher` via a bounded in-flight window (concurrency capped by `fetcher_max_in_flight`).
2. **Process** — N workers run `BlockProcessor::process` (validator: EVM execution; trace server: pass-through).
3. **Advance** — `chain_advancer` reorders out-of-order results, verifies parent-hash continuity, detects reorgs, and persists via `ChainStore::advance_chain`.

The outer loop (`run_pipeline`) handles reorg rollback + restart, stale-data anchor reset, and transient vs fatal error classification.
On a detected reorg, the rollback floor comes from a pluggable `ReorgResolver`: the core `BisectResolver` walks local history via `find_divergence_point`, while an embedder with an externally-supplied floor (e.g. the mega-reth FullNode) provides its own.

### Database

The validator and trace server each own a `redb`-backed database (`ValidatorDB` and `ServerDB`, living in their respective binaries).
The shared persistence layer — table definitions, read/write helpers, serialization, and `ContractCache` — lives in the `stateless-db` crate.
`stateless-core::db` defines only the genuinely-shared storage traits (`ContractStore`, `ChainStore`) plus the `StoreError` / `StoreResult` they return.
Scenario-specific storage lives in the owning binary rather than in core: genesis persistence is inherent on `ValidatorDB`, and block/witness storage with history pruning sits behind a bin-local `BlockStore` trait in the trace server.
The pipeline owns the reorg seams: `DivergenceLookups` (the bisection contract) and `ReorgResolver` (which decides the rollback floor) live in `stateless-core::pipeline`.

- **`ANCHOR_BLOCK`** — Trusted starting point (block number, hash, state root, withdrawals root).
- **`CANONICAL_CHAIN`** — Validated chain progression (block number → hash, state root, withdrawals root); a bounded contiguous window in both binaries, and exactly what reorg bisection trusts.
- **`CONTRACTS`** — Persistent tier of the contract bytecode cache (code hash → bincode+lz4 bytecode). The in-memory tier is the bounded `ContractCache` on top.
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
Responses are serialized exactly once, straight from the trace output into raw JSON bytes (`RawJson`) spliced verbatim into the reply; the cache shares those bytes by `Arc`, so a hit never re-parses or re-serializes the JSON tree.
Inbound JSON-RPC batch entries execute concurrently as independent runtime tasks through the regular per-request pipeline (synchronous trace CPU parallelizes too; spawned-entry CPU folds back into `x-execution-time-ns`/the CPU metric via a response extension) (`rpc_middleware.rs`, bounded by `--batch-item-concurrency`, default 16; 1 restores jsonrpsee's sequential behavior; batch shape observable via `debug_trace_batch_size`), so a batch answers near its slowest entry instead of the sum of its entries.
Inbound admission control (`admission.rs`) bounds what clients may ask of the process — every other concurrency cap here is outbound, and unbounded inline EVM tracing otherwise starves chain sync, the accept loop and the metrics exporter along with the requests — shedding with `-32013 "Request queue is full"`, mega-reth's `ConcurrencyLimiter` contract byte for byte so existing client backoff applies unchanged.
It is deliberately split in two: `AdmissionLayer` (installed *inside* `ConcurrentBatchLayer`, so it sees single calls and every batch entry, since that layer decomposes batches into per-entry `call`s rather than delegating to an inner `batch`) only ever runs a non-blocking CAS against `--admission-max-concurrent` + `--admission-max-queue`, while the execution permit is taken in the handler *after* `check_cache` misses.
That placement is load-bearing, not stylistic: `CancelGuard` arms on a request's first poll and the handler records its arrival synchronously in that same poll, so a middleware gate that parked before the handler would record a cancellation with no matching arrival for every client that hung up while queued — negative, permanent identity drift, worst under exactly the overload the gate exists for; a layer that only CAS-es preserves the invariant by construction, and the permit wait then sits after the arrival is already booked.
It also means a response-cache hit never takes a permit, the typed `RequestShape` is already in hand so the heavy-tracer sub-cap (`--admission-heavy-max-concurrent`, covering `prestateTracer`/JS/`muxTracer` and *every* struct-logger request including the bare default — the flags separating the two struct-logger shapes change output size, not kind — taken *before* the ordinary permit, so heavy requests never occupy execution permits while waiting for each other, and bounded by their own share of the admitted budget — `heavy_max_concurrent x (1 + max_queue / max_concurrent)` — because the gate itself is class-blind, so without it a heavy flood fills the admitted budget while blocking on a sub-cap a fraction of its size and ordinary traffic is shed with most execution permits idle) costs no second parse of attacker-controlled JSON, and what the permits count is blocks actually being fetched and replayed.
The permit wait is clamped to `deadline - witness_timeout` (`DataProvider::permit_cutoff`), so a request that queued away the budget its witness fetch still needs is refused now rather than started and timed out later — the difference between "may reject" and "times out"; the reserve falls back to half the budget when `--witness-timeout` does not fit inside `--block-fetch-timeout` (a legal pair, since the witness sub-deadline is a `min` against the outer one), because reserving all of it would leave a zero-length wait and silently reduce `--admission-max-queue` to a no-op.
Every handler mints its deadline once and passes it to both the permit wait and the fetch (`get_block_data_by_hash`/`get_block_data_for_tx` take it as a parameter for exactly this reason), so the queue is carved out of `--block-fetch-timeout` rather than added on top of it.
`debug_getCacheStatus` and its `timed_` alias are the sole exemption (matched on the `timed_`-stripped name, since the gateway adds that prefix by default and a bare-name comparison would never match production traffic); gating is derived from `metrics::GATE_EXEMPT_METHODS` rather than enumerated, and `assert_admission_covers_module` fails startup if a registered method is missing from `metrics::ALL_METHODS` — the one omission that would both ungate it and collapse its metrics onto `unknown`.
The limiter uses a resizable FIFO `Semaphore` (shrink via `forget_permits` plus a debt counter settled on release) rather than the reference implementation's counter+`Notify`, which has a lost wakeup (its `Notified` is created *after* the capacity check) and never wakes parked waiters on a raise — both regression-tested here.
Occupancy is counted, never derived as `limit - available_permits`: once a shrink leaves debt behind that difference reports the *new* limit, so the admin RPC would answer a retune by claiming it had already taken effect while every old holder was still resident (`occupancy_stays_truthful_while_a_shrink_is_outstanding`).
`--max-response-size` is checked at this server's own serialization point (`RawJson::try_new` in `serialize_reply`/`compute_block_trace`, counted on `debug_trace_response_oversized_total`, classified `TraceError::Request` so an oversized ask never evicts a good block), and `--max-batch-response-size` separately caps the assembled batch — different bounds, because a batch retains every completed entry's body until it finishes, and that accumulation rather than any single response is what has previously exhausted the process; both `heavy_max_concurrent x max_response_size` and `max_concurrent x max_response_size` are logged at startup, and neither bounds a tracer's intermediate allocations — a per-transaction-count gate would, and is not implemented.
`--admin-addr` (loopback enforced at startup, off unless set) serves `admin_getConcurrencyLimit`/`admin_setConcurrencyLimit` on a second listener with no RPC middleware — so a saturated public port cannot shed the call that relieves it — running on its own thread and runtime, since inline EVM tracing on the main runtime would otherwise starve it exactly when it is needed; `maxConcurrent = 0` is refused as unrecoverable.
Every inbound request is accounted for exactly once, so "did any client see a timeout?" is a metric lookup rather than an inference: arrivals are counted by `debug_trace_request_shape_total` before the first await, and each request then lands in exactly one of `debug_trace_rpc_requests_total` (served), `debug_trace_rpc_errors_total{reason}` (failed), or `debug_trace_requests_cancelled_total` (client hung up — recorded from the drop of the request future in `rpc_middleware.rs`, the only layer that observes single calls and batch entries alike), so `shape = requests + errors + cancelled` holds per method.
A shed adds the balanced pair `shape="shed"` / `reason="overloaded"`, recorded by the admission layer from *inside* the returned future — `record_rpc_error` sets the `ERROR_SELF_REPORTED` task-local that tells `settle_response` this non-framework `-32013` is already accounted for, which is what keeps `settle_response` unchanged; recorded from the layer's synchronous prefix instead, every shed would double-count its error and false-fire the `unattributed` drift alarm (`admission_shed_keeps_the_identity_closed` pins both).
A permit refused after the handler already recorded its arrival contributes the outcome side alone.
Requests the framework answers before any handler runs (unknown method, malformed top-level params, unparsable batch entries — recognized by their framework error codes) are folded in by the same middleware as the balanced pair `shape="rejected"` / `reason="rejected"`, an unrecorded error with a non-framework code lands error-side only on `reason="unattributed"` (a handler ran and recorded its arrival but bypassed the error funnel — a code-drift alarm that must stay at zero), and the opts-less `trace_*` methods record their `default` arrival at handler entry; the only deliberate approximation is a batch the server itself aborts over the response-size cap (its killed entries record no outcome rather than masquerade as client hangups) and batch entries that never started when the connection died (on neither side, so `cancelled` undercounts torn-down oversized batches).
The identity is pinned end-to-end by `accounting_identity_holds_end_to_end` in `rpc_middleware.rs`, which drives every terminal path through a real server under a draining local metrics recorder.
The `reason` label splits outcomes that share a JSON-RPC code — `deadline_witness` / `deadline_block` / `not_found` / `invalid_params` / `trace_failed` / `internal` — because a blown witness deadline and an unknown transaction both leave as `-32001` and only the first is an incident; the whole `(method, reason)` grid is pre-registered so an alert on `deadline_witness` reads zero instead of missing from boot.
The Parity `trace_transaction` compatibility behaviour of answering `null` instead of an error still counts as a served request (or the identity would silently lose it), with the swallowed cause kept visible on `debug_trace_null_results_total{reason}`.
HTTP responses negotiate gzip/zstd compression per request via `Accept-Encoding` (kill switch: `--response-compression-disabled`); bodies under 4 KiB stay identity, the stack order lives in `http_middleware()` (compression outside the size/timing layers keeps `x-response-size` at the uncompressed size and `x-execution-time-ns` free of compression CPU), and response-cache hits re-compress per hit.
Body-streaming cost is metered by the outermost middleware layer (`debug_trace_body_cpu_time_seconds` / `debug_trace_wire_bytes_total`, labeled by encoding), since every request-scoped measurement is sealed before the body streams.
The response cache is keyed by `(resource, block hash, typed tracer variant)`; by-number handlers resolve number → canonical hash before the lookup (local `CANONICAL_CHAIN` first, upstream fallback).
It only stores idempotent request shapes: the five built-in tracers (keyed by their parsed typed `tracerConfig`) and the bare default struct-logger request; JS tracers, `muxTracer`, and struct-logger requests with non-default flags bypass it entirely, and a type-malformed `tracerConfig` on call/prestate/flatCall is rejected with `-32602`.
Canonical-hash resolution reads the bounded `CANONICAL_CHAIN` window first (local cache mode), then a bounded in-memory memo of upstream-resolved bindings (`--canonical-hash-memo-capacity`; only depth-final heights are memoized — via the depth gate or a `finalized`-tag binding — so a memoized binding can no longer reorg), and only then upstream — so historical heights resolve locally after first touch within a process lifetime.
The memo's depth gate learns the tip from the window and `latest`-tag lookups, falling back to a throttled upstream `eth_blockNumber` seed (stateless mode with numeric-only traffic); chain sync clears the memo on stale resets and on reorgs at least the safety depth deep.
Tag requests (`latest`/`finalized`/`safe`) bind number → hash in their single upstream header fetch instead of resolving the two separately, and every resolved (number, hash) pair — from a tag, a canonical-hash resolution, or a transaction lookup — is handed to the fetch pipeline, which then skips its own number-discovery header round trip (paid only by raw by-hash requests) and cross-checks the number against the served block's header on every tier, failing typed on a drifted pair (a cold fetch also cancels the doomed witness fetch).
Below the response cache, a bounded in-memory `BlockData` cache keyed by block hash (`--block-data-cache-max-size`, default 1GB, 0 disables) fronts the DB and RPC tiers; block-number lookups resolve number → hash before touching it, so canonicality is never cached and it needs no reorg invalidation.
The cache pins 4 shards (largest cacheable entry = `max_bytes / 4` on any host), counts non-retained inserts, and drops an entry when a trace fails for a data-attributable reason (`TraceError::Data` — bad witness) while request-attributable failures (invalid tracer configs) never evict.
In local cache mode with a `--witness-generator-endpoint` plus at least one fallback `--witness-endpoint`, request-serving witness fetches route by block age: blocks at least `--witness-local-window` blocks below the local tip skip the generator (which prunes beyond its `BACKUP` window) and fetch from the fallbacks; without the generator flag, witness endpoints are plain failover and routing is disabled.
With the `--r2-*` flag group (endpoint, bucket, access key id, secret), every request-serving witness fetch tries a direct SigV4-signed R2 GET (light decode, capped at half the remaining witness budget) before the RPC chain, falling back on any failure; `--r2-max-concurrent-requests` caps R2 GETs separately from the RPC witness semaphore.
`--r2-custom-domain` is the alternative R2 target (mutually exclusive with `--r2-endpoint`, rejected at startup by name): unsigned GETs of `/{key}` through a Cloudflare custom domain fronting the bucket, which negotiates HTTP/2 (many in-flight GETs multiplex over a few connections instead of holding one each against the h1.1-only S3 endpoint) and can serve the immutable witness objects from edge cache; optional `--r2-access-client-id`/`--r2-access-client-secret` attach Cloudflare Access service-token headers (rejected at startup on a non-loopback `http://` domain, and validated as header values there so a stray newline fails by name instead of becoming a per-GET retryable transport error).
Leftover S3 flags alongside the domain are rejected by name rather than silently ignored, the client sends a `User-Agent` (Cloudflare's Browser Integrity Check 403s requests without one), and the configured target is published as `debug_trace_r2_target_info{target}` / `r2_target_info{target}` so the target-less R2 series can be attributed during a rollout.
Every `--r2-*` coherence rule — empty values, target exclusion, leftovers, an incomplete S3 quad, the Access pair, the connection count, and tuning flags with no target — lives in `stateless_common::validate_r2_flags`, so both binaries give the same verdict in the same words; each error names the offending flag, which clap cannot do without its `error-context` feature.
Version selection on the custom domain is pure ALPN (no `http2_prior_knowledge`, so the plaintext loopback path keeps working), which means a grey-clouded record, a non-Cloudflare origin, or a zone with HTTP/2 off degrades to HTTP/1.1 while the h2 tuning goes inert: the fetcher warns once with the protocol it actually got and publishes `..._r2_negotiated_http_version_info{version}`, and `pool_max_idle_per_host` is bounded so the h1.1 fallback cannot accumulate idle sockets that `pool_idle_timeout(None)` would never reap.
One `reqwest::Client` holds exactly one HTTP/2 connection and hyper never opens a second to relieve a saturated one (a pooled h2 connection reports liveness rather than stream capacity, and its dispatch channel is unbounded), so the edge's per-connection stream limit — Cloudflare advertises 100 in the `SETTINGS_MAX_CONCURRENT_STREAMS` it sends on every connection (`CLOUDFLARE_MAX_CONCURRENT_STREAMS`; `nghttp -nv https://<domain>/` reads what a given zone offers) — is a per-process ceiling rather than a per-request one.
`--r2-connections` (default 1) is what lifts it: it holds that many clients and picks one *per attempt*, so a retry leaves the connection that just failed, and one dropped connection no longer takes every in-flight GET down with it — which is the availability argument, and the one that matters in the validator's fallback-less R2 mode.
The pick is work-conserving: a connection with a free permit, searched from a rotating cursor, so a GET is never queued behind a connection whose permits are held by a slow transfer while another sits idle, and one budget of `max` is not silently partitioned into `N` budgets of `max/N` (which queues distinctly worse at the same offered load). Only when every connection is full does a fetch wait, and it waits on the cursor's own pick rather than on whichever has the most room — under saturation that one is the connection that just dropped every GET riding it.
`--r2-max-concurrent-requests` stays the cap across all of them, split evenly and rounded up (rounding down would leave some connection at zero permits and wedge every GET routed to it), so raising the connection count alone spreads the same concurrency thinner instead of raising the ceiling; the per-connection share is what must stay at or below the stream limit, and the fetcher warns at startup when it exceeds it.
The count is published as `debug_trace_r2_connections` / `r2_connections`, and is rejected by name at zero, on a non-numeric or blank value, on the S3 target (HTTP/1.1 already opens a socket per in-flight GET there), and above the cap it divides — more connections than permits would leave some of them permanently idle.
It travels as text and is parsed after clap, so a blank env line — what a templated env file renders for a variable a role does not set — is named rather than aborting startup through clap's unnamed value error, and stays inert on the validator under `--witness-source rpc`, where every `--r2-*` flag is deliberately unread.
On the validator the shared semaphore is `--witness-max-concurrent-requests`, which sizes the RPC gateway too, so the two consumers trade off against each other.
`stateless-common`'s shared JSON-RPC client pins `http1_only`: `stateless-r2` enables reqwest's `http2` feature and Cargo unifies it workspace-wide, which would otherwise move the multi-MB witness RPC payloads onto one non-adaptive h2 connection per host.
Client-side routing, budgets, and fallback match the S3 target, but edge behavior is zone configuration: **a cache rule making these objects cacheable must set 404s to bypass cache**, or a pre-upload frontier miss gets pinned for the negative-cache TTL (stalling the validator's tip-following in its fallback-less R2 mode) and a cached 404 can false-fire the below-band `kind="missing"` bucket-integrity alarm.
The bucket is the same store the public gateway reads and can lead the generator at the frontier (uploader and generator RPC server publish from different files), so frontier hits are real; the frontier band is a small near-tip window (`R2_FRONTIER_WINDOW`, 32 blocks of uploader-lag grace on either side of the local tip — deliberately far narrower than the 4096-block routing window, so a stale catching-up tip cannot silence holes above it), hits there are labeled `witness_r2_frontier` (vs `witness_r2` past the band), the speculative frontier probe runs on an eighth of the remaining stage (vs half for blocks R2 must hold, so degraded R2 cannot burn half of every near-tip request's budget), and a `missing` classifies by band: in-band is the expected probe-ahead outcome (excluded from the alarm), below-band feeds `debug_trace_r2_witness_errors_total{kind="missing"}` (the bucket-integrity alarm, still covering recent-but-below-tip holes), and above-band — only reachable behind a stale catching-up tip — lands on its own `kind="missing_above_tip"` series, visible without flooding the alarm on every catch-up.
Any witness-chain RPC attempt under a deadline is capped at the tightest of three bounds — half the full witness stage (`RpcClientConfig::witness_per_attempt_timeout`, derived from `--witness-timeout`), the global `--rpc-per-attempt-timeout-ms` (an explicitly stricter operator setting is honored, never loosened), and — only while the round still has an untried provider to rotate to — half of what the call still has as the attempt starts (recomputed after any concurrency-permit wait, so neither an old-block-clamped stage, a post-R2 remainder, nor a long permit queue defeats the reserve).
The round's last hop, and every hop of a single-provider chain, takes the remainder whole under the ceiling instead: rotation stays protected without structurally condemning a slow-but-honest transfer, and the witness decode runs outside the attempt window (bounded by the deadline alone), so CPU-bound decode neither burns the reserve nor reads as a provider stall while a corrupt payload still rotates as the provider's error; deadline-less chain-sync fetches keep the general 20s cap so a slower-than-cap transfer still completes.
When a logical upstream call gives up on its deadline it logs one WARN naming the `phase` it died in (`before_attempt` / `permit_wait_clamped` / `attempt_clamped` / `before_backoff`) with `provider` / `round` / `permit_wait_ms` / `attempt_ms`, and the abandoned attempt is recorded as `outcome="deadline_clamped"` rather than dropped; best-effort internal probes (the throttled upstream tip seed) demote that give-up log to debug while the deadline metric still fires, so a probe whose failure is already degraded cannot page as a user-visible incident.
Permit wait is timed separately (`debug_trace_upstream_permit_wait_seconds{method}`) and the acquire is clamped to the deadline (phase `permit_wait_clamped`, cut-short wait still sampled), so queueing behind our own `--witness-max-concurrent-requests` stays distinguishable from endpoint slowness and a saturated queue cannot block a call past its budget unobserved.
The background chain-sync prefetch routes by freshness against the last observed remote head: frontier-fresh blocks give the generator a short exclusive grace (its "witness not found" means "not generated yet" — fallbacks are fed by the same pipeline and cannot be ahead) before falling back to the full endpoint chain, while deep catch-up blocks — and any block classified against a stale head observation (older than the grace, as during a long catch-up stretch when the tip is not re-polled) — use the full chain from the first attempt.

### Key Source Files

| File                                                                                           | Purpose                                                                              |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `crates/stateless-core/src/pipeline/{mod,config,traits,fetcher,divergence,advancer,worker}.rs` | Generic three-stage pipeline split by responsibility                                 |
| `crates/stateless-core/src/executor.rs`                                                        | Block validation and EVM replay (generic over the `BlockInput` projection)           |
| `crates/stateless-core/src/evm_database.rs`                                                    | WitnessDatabase implementing `revm::DatabaseRef`                                     |
| `crates/stateless-core/src/db.rs`                                                              | Shared storage traits (`ContractStore`, `ChainStore`) + `StoreError` / `StoreResult` |
| `crates/stateless-core/src/withdrawals.rs`                                                     | Withdrawal validation and MPT witness handling                                       |
| `crates/stateless-db/src/{lib,tables,helpers,serialize,cache}.rs`                              | Shared redb tables, helpers, serialization, and `ContractCache`                      |
| `crates/stateless-common/src/rpc_client.rs`                                                    | RPC client for blocks, witnesses, and bytecode                                       |
| `crates/stateless-common/src/metrics.rs`                                                       | RpcMethod, RpcMetrics, RpcClientConfig                                               |
| `bin/stateless-validator/src/{main,app,workers,chain_sync,validator_db,metrics}.rs`            | Thin entry, CLI/startup wiring, pipeline+reporter, fetcher/processor, DB             |
| `bin/debug-trace-server/src/chain_sync.rs`                                                     | TraceFetcher, TraceProcessor, TraceHooks                                             |
| `bin/debug-trace-server/src/rpc_service.rs`                                                    | RPC method definitions and handlers                                                  |
| `bin/debug-trace-server/src/rpc_middleware.rs`                                                 | Concurrent execution of inbound JSON-RPC batch entries                               |
| `bin/debug-trace-server/src/data_provider.rs`                                                  | Block data fetching with single-flight coalescing                                    |
| `bin/debug-trace-server/src/block_data_cache.rs`                                               | Bounded in-memory `BlockData` cache keyed by block hash                              |
| `bin/debug-trace-server/src/admission.rs`                                                      | Inbound admission gate: resizable FIFO limiter, guards, `RpcServiceT` layer          |
| `bin/debug-trace-server/src/admin.rs`                                                          | Loopback-only `admin_*` listener for retuning the gate at runtime                    |
| `bin/debug-trace-server/src/r2_witness.rs`                                                     | Direct-from-R2 witness source (light decode, deadline-aware)                         |
| `bin/debug-trace-server/src/server_db.rs`                                                      | Defines + implements the bin-local `BlockStore` trait (backed by `stateless-db`)     |

## Test Organization

Unit tests are embedded in source files alongside the code they test.
Integration tests live in `bin/debug-trace-server/tests/` (6 modules: cache_metrics, block_tag, compression, consistency, performance, timing_header) and in `bin/stateless-validator/tests/integration.rs` (CLI parsing, mock-RPC pipeline, mainnet single-block validation).
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
