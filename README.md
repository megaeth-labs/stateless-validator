# Stateless Validator

A Rust implementation of a stateless blockchain validator specifically designed for MegaETH.
MegaETH is a high-performance, Ethereum-compatible blockchain that achieves exceptional throughput through optimized execution and state management.

This validator enables efficient block verification using cryptographic witness data from [SALT (Small Authentication Large Trie)](https://github.com/megaeth-labs/salt) instead of maintaining full blockchain state.
The stateless approach eliminates the need for validators to run on high-end hardware comparable to sequencer nodes, making it practical to run validator nodes at scale.

## Features

- **Partial Statelessness**: Contract bytecode is fetched on-demand from RPC endpoints and cached locally, rather than included in witness data.
  This hybrid approach dramatically reduces witness size since contract code changes infrequently compared to state data.

- **Embarrassingly Parallel**: Validation workers operate independently on different blocks with no coordination overhead.
  Throughput scales linearly with the number of CPU cores available.

- **Lower Hardware Spec**: Thanks to our novel [SALT (Small Authentication Large Trie)](https://github.com/megaeth-labs/salt) data structure, the witness is significantly smaller than traditional Merkle Patricia Tree (MPT) or Verkle tree approaches.
  This reduces the network bandwidth requirements of stateless validators.

- **Simplicity over Performance**: Designed with simplicity as the core principle.
  The validator uses a minimal, single-threaded executor based on vanilla Revm interpreter and in-memory storage to prioritize simplicity over raw performance.
  This creates a small Trusted Computing Base that can be thoroughly audited, ensuring high confidence in validation correctness.

- **Pluggable Execution Engine**: Supports multiple execution implementations to prevent single points of failure.
  Beyond the default Revm-based executor, the validator also supports an executor based on the formal [K semantics of the EVM](https://github.com/Pi-Squared-Inc/evm-semantics) (developed with Pi²).
  Combined with the hyper-optimized, parallel, JIT-compiled executor on sequencer nodes, this creates three distinct MegaETH client implementations.

## Project Structure

The workspace contains two binaries and five library crates:

| Crate                  | Path                          | Purpose                                                                                                                                                                              |
| ---------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `stateless-core`       | `crates/stateless-core`       | Core validation logic, abstract storage traits, generic pipeline, EVM execution                                                                                                      |
| `stateless-db`         | `crates/stateless-db`         | redb-backed persistence: table definitions, read/write helpers, bounded `ContractCache`                                                                                              |
| `stateless-common`     | `crates/stateless-common`     | Shared utilities: RPC client, logging, metrics                                                                                                                                       |
| `stateless-test-utils` | `crates/stateless-test-utils` | Test fixtures (blocks, witnesses, contracts) and env-var lock for integration tests                                                                                                  |
| `stateless-r2`         | `crates/stateless-r2`         | Shared R2 (S3) witness primitives: SigV4 signer, object-key layout, endpoint parsing, signed PUT/GET with retry; consumed by mega-reth's witness uploaders (write), this repo's validator, and the trace server's historical witness source (read) |
| `stateless-validator`  | `bin/stateless-validator`     | Main binary: chain sync, parallel validation workers                                                                                                                                 |
| `debug-trace-server`   | `bin/debug-trace-server`      | Standalone RPC server for debug/trace methods                                                                                                                                        |

Additional directories: `test_data/` (integration test fixtures including genesis config), `audits/` (security audit reports).

## Quick Start

### Building

```bash
cargo build --release
```

### Running the Validator

```bash
cargo run --release --bin stateless-validator -- \
  --data-dir /path/to/validator/data \
  --rpc-endpoint <public-rpc-endpoint> \
  --witness-endpoint <witness-rpc-endpoint> \
  --genesis-file /path/to/genesis.json \
  --start-block <trusted-block-hash>
```

**Required Arguments:**
- `--data-dir`: Directory for validator database and data files
- `--rpc-endpoint`: JSON-RPC API endpoint URL(s) to retrieve block data.
  Multiple endpoints can be provided via repeated flags or as a comma-separated list (tried in order on failure, with retry-with-backoff per provider).
  The env var `STATELESS_VALIDATOR_RPC_ENDPOINT` accepts the same comma-separated form (e.g. `http://a:8545,http://b:8545`).
- `--witness-endpoint`: MegaETH JSON-RPC API endpoint URL(s) to retrieve witness data.
  Multiple endpoints can be provided via repeated flags or as a comma-separated list (tried in order on failure).
  The env var `STATELESS_VALIDATOR_WITNESS_ENDPOINT` accepts the same comma-separated form (e.g. `http://a:8545,http://b:8545`).
  Required with `--witness-source rpc` (the default); ignored with `--witness-source r2`.

**Optional Arguments:**
- `--genesis-file`: Path to genesis JSON file containing hardfork activation configuration (required on first run, stored in database for subsequent runs)
- `--start-block`: Trusted block hash to initialize validation from (required for first-time setup)
- `--end-block`: Inclusive end block; validate up to this height, then stop cleanly (useful to slice a fixed range across multiple servers)
- `--witness-source`: Where to fetch witnesses from: `rpc` (default) or `r2` (straight from the R2 bucket over the S3 API)
- `--r2-endpoint`, `--r2-bucket`, `--r2-access-key-id`, `--r2-secret-access-key`: R2 connection settings, all required with `--witness-source r2` (prefer the env var for the secret)
- `--report-validation-endpoint`: RPC endpoint URL for reporting validated blocks via `mega_setValidatedBlocks` (disabled if not provided)
- `--metrics-enabled`: Enable Prometheus metrics endpoint (disabled by default)
- `--metrics-port`: Port for Prometheus metrics HTTP endpoint (default: 9090)

### Running the Debug Trace Server

```bash
cargo run --release --bin debug-trace-server -- \
  --rpc-endpoint <public-rpc-endpoint> \
  --witness-endpoint <witness-rpc-endpoint> \
  --addr 0.0.0.0:8545
```

The debug-trace-server exposes Geth-style and Parity-style tracing RPC methods:
- `debug_traceBlockByNumber`, `debug_traceBlockByHash`, `debug_traceTransaction`
- `trace_block`, `trace_transaction`
- `debug_getCacheStatus`

Two operating modes:
- **Stateless mode** (no `--data-dir`): All data fetched from remote RPC on demand.
- **Local cache mode** (with `--data-dir`): Enables chain sync to pre-fetch blocks for faster serving.

**Response cache:**
The HTTP response cache is keyed by `(resource, block hash, tracer variant)` — an entry is an immutable fact about that exact block, so reorgs need no serve-time validation.
Entries hold the reply's raw JSON bytes, serialized exactly once from the trace output and spliced verbatim into every response — a hit shares the bytes by `Arc` instead of re-parsing and re-serializing the JSON tree.
By-number requests resolve their canonical hash before the lookup (local index, then an in-memory memo, then upstream `eth_getHeaderByNumber`), so a reorged height resolves to the new hash and misses cleanly.
Cacheable shapes are the five built-in tracers (`callTracer`, `prestateTracer`, `4byteTracer`, `noopTracer`, `flatCallTracer`, keyed by their parsed, typed `tracerConfig` — equivalent configs collapse onto one entry) and the bare default struct-logger request (no tracer, no `tracerConfig`, default flags).
JS tracers, `muxTracer`, and struct-logger requests with non-default flags bypass the cache and are recomputed on every request; the unimplemented `erc7562Tracer` is rejected with `-32602` before any block data is fetched.
A type-malformed `tracerConfig` on a config-reading builtin (`callTracer`/`prestateTracer`/`flatCallTracer`) is rejected with `-32602 invalid params` instead of being silently traced with default settings.
Disable the cache with `--response-cache-disabled`; `--response-cache-estimated-items` must be at least 1 (the old `=0` disable convention is rejected at startup).

**Concurrent batch execution:**
Entries of an inbound JSON-RPC batch request execute concurrently as independent runtime tasks, so a batch answers near its slowest entry instead of the sum of its entries — including CPU-bound entries, since EVM tracing runs synchronously inline and merely interleaved futures would serialize behind it (jsonrpsee's built-in batch path is strictly sequential).
Each entry still goes through the regular per-request pipeline — response cache, single-flight, witness routing, and per-method metrics apply unchanged — and responses may arrive in any order, matched by `id` as JSON-RPC 2.0 permits.
`--batch-item-concurrency` (default 16) bounds how many entries of one batch run at once, so a single huge batch cannot monopolize downstream resources against concurrently served requests; set it to 1 to restore sequential execution.
The `debug_trace_batch_size` histogram records entries per inbound batch, and CPU burned inside spawned entries is folded back into `x-execution-time-ns` and the request CPU metric, so batch requests do not under-report their cost.

**Response compression:**
Responses negotiate gzip/zstd per request via the client's `Accept-Encoding` header; clients that do not send it keep receiving identity bodies, so nothing changes for consumers that have not opted in.
Bodies under 4 KiB are always served identity: compressing them would cost a per-response encoder allocation and downgrade `Content-Length` to chunked framing for a few dozen saved bytes.
Compression runs at the fastest level while the body streams, so `x-execution-time-ns` excludes its CPU cost — the header reflects request processing and no longer bounds total request cost — and `x-response-size` keeps reporting the uncompressed payload size.
The body-streaming phase is metered separately: `debug_trace_body_cpu_time_seconds` and `debug_trace_wire_bytes_total` (labeled by negotiated encoding) record per-response streaming CPU — compression included — and post-compression wire bytes, which is what tells an operator when compression CPU is worth shedding.
Compressing at the origin also shrinks a fronting CDN's back-to-origin leg, which edge-side compression alone cannot do.
Known trade-off: the response cache stores identity JSON, so an opted-in client pays the (fast-level) compression on every cache hit.
Disable with `--response-compression-disabled`; the flag is read at startup, so shedding compression CPU means a restart and a cold-cache window.

**Canonical-hash memo:**
`CANONICAL_CHAIN` stays a bounded, contiguous sync window; heights outside it resolve number → hash upstream once, and the hash-verified answer is memoized in a bounded in-memory LRU.
Only depth-final heights are memoized (more than a safety depth below the observed tip, so a memoized binding can no longer reorg); shallow and above-tip heights resolve upstream on every request.
The observed tip comes from the local window and `latest`-tag lookups; when neither exists (stateless mode with numeric-only traffic), a throttled upstream `eth_blockNumber` seed learns it, so the memo fills there too.
Resolution order is window → memo → upstream, so historical heights resolve locally after first touch for the lifetime of the process; a restart clears the memo, and reorg bisection reads only the window.
In local cache mode chain sync also clears the memo on a stale reset and on any reorg at least the safety depth deep; in stateless mode the depth margin alone carries the safety argument (assumed deeper reorgs never happen on the target chain).
The memo holds `--canonical-hash-memo-capacity` entries (default 8M, roughly 80 bytes each; it fills lazily, so the cap costs nothing until a deep historical scan uses it).

**Size-based pruning:**
Size-based pruning never removes bodies above `tip - --size-prune-min-retain` (default 256), so a DB file stuck over `--db-max-size` cannot consume the whole body retention.
Because redb files never shrink on their own, a file that crosses `--db-max-size` ratchets body retention down to that floor and keeps it there until `--db-max-size` is raised or the database is rebuilt.

**Block-data cache:**
A bounded in-memory `BlockData` cache keyed by block hash sits between the response cache and the local DB / RPC tiers, so requests that miss the response cache — other tracer variants of a block, and especially `debug_traceTransaction` calls for different transactions of the same block, which are never response-cached — reuse one witness fetch and contract resolution.
Block-number lookups still resolve number → hash against the DB or upstream first, so canonicality is never cached and reorgs need no invalidation here; when a trace fails for a data-attributable reason (the witness cannot replay the block), the entry is dropped so the next request refetches instead of replaying the poisoned data, and each such eviction is counted (`block_data_evictions_total`).
Size it with `--block-data-cache-max-size` (default `1GB`; `0` disables); the cache uses a fixed 4 shards, so the largest cacheable entry is `max_bytes / 4` on every host (~256 MB at the default), and an insert the cache does not retain is counted (`cache_admission_rejects_total`) and logged rather than masquerading as a miss.
The byte budget is an estimate of retained payload, not exact RSS: map/allocator overhead is under-counted, and contract bytecode is charged here *and* in the contract cache (the same refcounted allocations), so evicting an entry can free less than its accounted weight.
Combined default memory across the four caches is roughly 3.1 GB — response cache 1 GB + block-data cache 1 GB + contract cache 512 MB + canonical-hash memo ~0.6 GB at its 8M-entry cap (it fills lazily; the measured working set is 50–130k heights, ~10 MB) — on top of ordinary heap; size hosts (or lower the knobs) accordingly.

**Witness endpoints:**
Declare the internal witness generator via `--witness-generator-endpoint`; `--witness-endpoint` lists the durable fallbacks (e.g. an R2-backed witness service), tried in order.
In local cache mode with a generator plus at least one fallback, requests for blocks at least `--witness-local-window` blocks below the local tip skip the generator and fetch from the fallbacks, because the generator only retains a recent window (its `BACKUP`, deployed at 4096) and probing it for pruned blocks is a guaranteed miss.
The background chain-sync prefetch routes by freshness against the last observed remote head: for frontier-fresh blocks the generator gets a short exclusive grace before the full endpoint chain — its "witness not found" at the frontier means "not generated yet", and the fallbacks receive witnesses from the same generation pipeline, so rotating to them on a fresh miss wastes a round trip per block and exposes tip sync to fallback stalls.
The head observation is trusted as a freshness anchor only while itself recent (no older than the grace): during a long catch-up stretch the tip is not re-polled and the real head may advance past the generator's retention, so blocks near the stale ceiling fall back to full-chain failover from the first attempt instead of burning the grace on pruned witnesses.
Deep catch-up blocks (far below the observed head, where the generator may have pruned the witness) keep full failover from the first attempt.
Without `--witness-generator-endpoint`, historical routing is disabled and the endpoints are plain failover.

**Direct-from-R2 historical witnesses:**
With `--r2-endpoint`, `--r2-bucket`, `--r2-access-key-id`, and `--r2-secret-access-key` (all four together), request-serving witness fetches for historical blocks try a SigV4-signed GET against the bucket before the RPC witness chain.
Object storage tolerates far higher parallelism than a shared RPC gateway and the bucket holds full history, so bulk backfill traffic stops competing with everything else on the public endpoint; any R2 failure (missing object, throttle, transport, corrupt payload — counted in `debug_trace_r2_witness_errors_total{kind}`) falls back to the RPC chain on the remaining witness budget, and the R2 attempt is capped at half that budget so a hung endpoint can never starve the fallback.
Frontier blocks keep the generator path (the bucket receives objects only after the uploader PUTs them), and the route needs a local DB (`--data-dir`) to anchor block age.
`--r2-max-concurrent-requests` caps in-flight GETs separately from `--witness-max-concurrent-requests` — the RPC cap sizes a shared gateway, R2 tolerates far more.

**Witness routing and sync knobs** (each also settable via its `DEBUG_TRACE_SERVER_*` env var):
- `--witness-local-window`: Block-age threshold for the historical witness route (default: 4096; should match the generator's `BACKUP`).
- `--witness-old-block-timeout`: Witness-stage budget in seconds for blocks at or below the local tip (defaults to the full `--witness-timeout` budget, tracking it when raised; lower it to fail fast on pruned blocks).
- `--tip-buffer`: Stay this many blocks behind the upstream head during chain sync so fetches don't race the witness generator (default: 2; must be smaller than `--blocks-to-keep`).

### Environment Variables

Each command-line flag has an equivalent environment variable:

- `STATELESS_VALIDATOR_DATA_DIR` → `--data-dir`
- `STATELESS_VALIDATOR_RPC_ENDPOINT` → `--rpc-endpoint`
- `STATELESS_VALIDATOR_WITNESS_ENDPOINT` → `--witness-endpoint`
- `STATELESS_VALIDATOR_GENESIS_FILE` → `--genesis-file`
- `STATELESS_VALIDATOR_START_BLOCK` → `--start-block`
- `STATELESS_VALIDATOR_END_BLOCK` → `--end-block`
- `STATELESS_VALIDATOR_WITNESS_SOURCE` → `--witness-source`
- `STATELESS_VALIDATOR_R2_ENDPOINT` / `_R2_BUCKET` / `_R2_ACCESS_KEY_ID` / `_R2_SECRET_ACCESS_KEY` → `--r2-*`
- `STATELESS_VALIDATOR_REPORT_VALIDATION_ENDPOINT` → `--report-validation-endpoint`
- `STATELESS_VALIDATOR_METRICS_ENABLED` → `--metrics-enabled` (set to `true` to enable)
- `STATELESS_VALIDATOR_METRICS_PORT` → `--metrics-port`

**Logging Configuration:**
- `STATELESS_LOG_FILE_DIRECTORY`: Directory for log files; enables file logging when set.
  Files rotate daily as `stateless-validator.log.YYYY-MM-DD`.
- `STATELESS_LOG_FILE`: Log level for file output (debug|info|warn|error, default: debug)
- `STATELESS_LOG_STDOUT`: Log level for console output (debug|info|warn|error, default: info)

Command-line arguments take precedence over environment variables.

### Getting Started

The stateless validator requires a trusted starting point and hardfork configuration for security.
On first run, you must specify both a genesis file and a trusted block hash:

```bash
cargo run --bin stateless-validator -- \
  --data-dir ./validator-data \
  --rpc-endpoint https://your-rpc-endpoint.com \
  --witness-endpoint https://your-witness-endpoint.com \
  --genesis-file /path/to/genesis.json \
  --start-block 0x1234567890abcdef...
```

The validator will:
1. Load the genesis file and extract hardfork activation rules, then store this configuration in the database
2. Fetch the specified block from the RPC endpoint
3. Initialize the canonical chain database with this trusted block
4. Begin validation from this anchor point, applying the appropriate EVM rules based on hardfork activation

For subsequent runs, you can omit both `--genesis-file` and `--start-block` to resume from the existing database:

```bash
cargo run --bin stateless-validator -- \
  --data-dir ./validator-data \
  --rpc-endpoint https://your-rpc-endpoint.com \
  --witness-endpoint https://your-witness-endpoint.com
```

## Scope and Trust Model

The stateless validator acts as an **execution client**: it fetches block data from an RPC endpoint and re-executes each block to verify that the **state transition function (STF)** is correct.
It ensures that the computed post-state matches the commitments included in the block, providing execution correctness without maintaining a local state database.

However, the stateless validator **does not verify that the blocks it receives form the canonical chain**.
It will validate whatever sequence of blocks is supplied, including forks, stale heads, or maliciously injected data.
Determining canonicality requires a **consensus client**.
For OP-Stack chains, this role is performed by `op-node`, which derives the canonical L2 chain from L1 and the chain's data-availability (DA) layer and handles reorgs.

### Trust-Minimized Deployment

To avoid trusting a third-party RPC provider to serve you the correct blocks, the recommended setup is:

* **Run `op-node`** to derive the canonical L2 chain from L1 + DA
* **Run a MegaETH replica node** to efficiently sync with the sequencer and serve the derived L2 blocks
* **Run the stateless validator** to independently verify every block's STF

In this configuration, `op-node` ensures you see the correct canonical chain, the replica node provides local block data, and the stateless validator verifies correctness.
This forms a **trust-minimized pipeline**: you rely only on L1 + DA (the rollup's security assumptions) and your own local software, not an external RPC endpoint.

## Architecture

### Pipeline

Both binaries share a generic three-stage pipeline defined in `stateless-core`:

```
 Stage 1: FETCH          block_fetcher
                          Streams blocks + witnesses from RPC via a bounded in-flight window
                          ↓ channel
 Stage 2: PROCESS        N workers × BlockProcessor
                          Validator: validate_block (EVM execution)
                          Trace server: pass-through (no validation)
                          ↓ channel
 Stage 3: ADVANCE        chain_advancer
                          Reorders out-of-order results (BTreeMap)
                          Verifies parent-hash continuity
                          Detects reorgs → rollback + restart
                          Persists via ChainStore::advance_chain()

 Outer loop (run_pipeline):
   Reorg → ReorgResolver decides floor → rollback → restart pipeline
   Stale detection (optional) → reset anchor → restart
```

The pipeline is configured via `PipelineConfig` and customized through trait implementations:
- `BlockProcessor`: Processing logic per block (validation or pass-through)
- `PipelineHooks`: Callbacks for advance/reorg/stale events
- `ProcessedBlock`: Output type of the processing stage
- `ReorgResolver`: Decides the rollback floor on a detected reorg (`BisectResolver` walks local history; embedders can supply an externally-resolved floor)

### Key Source Files

| File                                                                                           | Purpose                                                                                                     |
| ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `crates/stateless-core/src/pipeline/{mod,config,traits,fetcher,divergence,advancer,worker}.rs` | Generic three-stage pipeline split by responsibility                                                        |
| `crates/stateless-core/src/executor.rs`                                                        | Block validation and EVM replay                                                                             |
| `crates/stateless-core/src/db.rs`                                                              | Shared storage traits: `ChainStore`, `ContractStore`, `StoreError` (scenario stores live in their binaries) |
| `crates/stateless-core/src/evm_database.rs`                                                    | `WitnessDatabase` implementing `revm::DatabaseRef`                                                          |
| `crates/stateless-core/src/withdrawals.rs`                                                     | Withdrawal MPT witness verification (witness linearized into `alloy_trie::HashBuilder`)                                                              |
| `crates/stateless-db/src/{lib,tables,helpers,serialize,cache}.rs`                              | Shared redb tables, helpers, serialization, and bounded `ContractCache`                                     |
| `crates/stateless-common/src/rpc_client.rs`                                                    | `RpcClient`: multi-endpoint HTTP client for blocks, witnesses, and bytecode                                 |
| `crates/stateless-common/src/metrics.rs`                                                       | `RpcMethod`, `RpcMetrics`, `RpcClientConfig`                                                                |
| `crates/stateless-common/src/witness_size.rs`                                                  | `WitnessSizeBreakdown` + `estimate_witness_size` for RPC and trace-server metrics                           |
| `crates/stateless-test-utils/src/fixtures.rs`                                                  | `TestFixtures` loader (blocks, SALT/MPT witnesses, contracts, genesis)                                      |
| `bin/stateless-validator/src/{main,app,workers,chain_sync,validator_db,metrics}.rs`            | Thin entry, CLI/startup wiring, pipeline+reporter, fetcher/processor, DB                                    |
| `bin/debug-trace-server/src/chain_sync.rs`                                                     | `TraceFetcher`, `TraceProcessor`, `TraceHooks`                                                              |
| `bin/debug-trace-server/src/rpc_service.rs`                                                    | RPC method definitions and handlers                                                                         |
| `bin/debug-trace-server/src/data_provider.rs`                                                  | Block data fetching with single-flight coalescing                                                           |
| `bin/debug-trace-server/src/block_data_cache.rs`                                               | Bounded in-memory `BlockData` cache keyed by block hash                                                     |
| `bin/debug-trace-server/src/server_db.rs`                                                      | Defines + implements the bin-local `BlockStore` trait, backed by `stateless-db`                             |

### Database

The validator and trace server each have their own `redb`-backed database, sharing common table definitions and helpers from the `stateless-db` crate:

| Table             | Key                        | Value                                                  | Used By                      |
| ----------------- | -------------------------- | ------------------------------------------------------ | ---------------------------- |
| `ANCHOR_BLOCK`    | `"anchor"`                 | `(BlockNumber, BlockHash, StateRoot, WithdrawalsRoot)` | Both                         |
| `CANONICAL_CHAIN` | `BlockNumber`              | `(BlockHash, StateRoot, WithdrawalsRoot)`              | Both                         |
| `CONTRACTS`       | `CodeHash`                 | Bincode+LZ4 `Bytecode`                                 | Both                         |
| `GENESIS_CONFIG`  | `"genesis"`                | JSON `Genesis`                                         | Validator                    |
| `BLOCK_DATA`      | `BlockHash`                | JSON `Block<Transaction>`                              | Trace server                 |
| `WITNESSES`       | `BlockHash`                | Bincode+LZ4 `LightWitness`                             | Trace server                 |
| `BLOCK_RECORDS`   | `(BlockNumber, BlockHash)` | `()`                                                   | Trace server (pruning index) |

In both binaries, `CANONICAL_CHAIN` is a bounded contiguous window — exactly the range reorg bisection trusts.
`CONTRACTS` rows are self-validating on read: an entry that fails to decode or whose bytecode no longer hashes back to its key (disk corruption, or a `Bytecode` encoding change in a dependency upgrade) is treated as a cache miss and transparently re-fetched from RPC, so existing data dirs survive release upgrades without manual clearing.

### SALT Witness Cryptography

SALT (Small Authentication Large Trie) is the authenticated key-value store that replaces Merkle Patricia Tries for MegaETH state.
It uses a static 4-level, 256-ary complete tree with ~16.7 million leaf nodes (buckets), each containing a dynamic strongly history-independent (SHI) hash table.
Cryptographic commitments use the **Banderwagon** elliptic curve with **IPA** (Inner Product Argument) vector commitments, enabling compact aggregatable proofs.

During validation, the witness is verified against the block's pre-state root, `WitnessDatabase` serves state reads from the verified witness during EVM execution, and post-execution state deltas are propagated up the trie (max 4 levels) to compute and verify the post-state root.

## Metrics

The validator exposes Prometheus-compatible metrics when `--metrics-enabled` is set.
Metrics are available at `http://0.0.0.0:<port>/metrics`.

| Metric                                                  | Type      | Description                                         |
| ------------------------------------------------------- | --------- | --------------------------------------------------- |
| `stateless_validator_block_validation_time_seconds`     | Histogram | Block validation time                               |
| `stateless_validator_witness_verification_time_seconds` | Histogram | Witness verification time                           |
| `stateless_validator_block_replay_time_seconds`         | Histogram | EVM execution time                                  |
| `stateless_validator_salt_update_time_seconds`          | Histogram | SALT update time                                    |
| `stateless_validator_transactions_total`                | Counter   | Total transactions validated                        |
| `stateless_validator_gas_used_total`                    | Counter   | Total gas used in validated blocks                  |
| `stateless_validator_block_state_reads`                 | Histogram | State reads per block                               |
| `stateless_validator_block_state_writes`                | Histogram | State writes per block                              |
| `stateless_validator_worker_tasks_completed_total`      | Counter   | Tasks completed per worker (with `worker_id` label) |
| `stateless_validator_worker_tasks_failed_total`         | Counter   | Tasks failed per worker (with `worker_id` label)    |
| `stateless_validator_local_chain_height`                | Gauge     | Current height of local chain                       |
| `stateless_validator_remote_chain_height`               | Gauge     | Current height of remote chain                      |
| `stateless_validator_validation_lag`                    | Gauge     | Blocks pending validation (remote - local)          |
| `stateless_validator_reorgs_detected_total`             | Counter   | Chain reorgs detected                               |
| `stateless_validator_reorg_depth`                       | Histogram | Depth of chain reorganizations                      |
| `stateless_validator_rpc_requests_total`                | Counter   | Total RPC requests (with `method` label)            |
| `stateless_validator_rpc_errors_total`                  | Counter   | RPC errors (with `method` label)                    |
| `stateless_validator_rpc_retry_attempts_total`          | Counter   | RPC transient retries (with `method` label)         |
| `stateless_validator_contract_cache_hits_total`         | Counter   | Contract cache hits                                 |
| `stateless_validator_contract_cache_misses_total`       | Counter   | Contract cache misses                               |

## Development

### Testing

```bash
cargo test                                    # all tests
cargo test -p stateless-core                  # core crate only
cargo test -p stateless-core -- test_name     # single test
```

### Linting

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
cargo sort --check --workspace --grouped --order package,workspace,lints,profile,bin,benches,dependencies,dev-dependencies,features
```

## License

[Add your license information here]
