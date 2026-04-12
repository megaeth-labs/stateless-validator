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

The workspace contains two binaries and two library crates:

| Crate                 | Path                      | Purpose                                                          |
| --------------------- | ------------------------- | ---------------------------------------------------------------- |
| `stateless-core`      | `crates/stateless-core`   | Core validation logic, abstract traits, generic pipeline         |
| `stateless-common`    | `crates/stateless-common` | Shared utilities: RPC client, database helpers, logging, metrics |
| `stateless-validator` | `bin/stateless-validator` | Main binary: chain sync, parallel validation workers             |
| `debug-trace-server`  | `bin/debug-trace-server`  | Standalone RPC server for debug/trace methods                    |

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
- `--rpc-endpoint`: JSON-RPC API endpoint URL to retrieve block data
- `--witness-endpoint`: MegaETH JSON-RPC API endpoint URL to retrieve witness data

**Optional Arguments:**
- `--genesis-file`: Path to genesis JSON file containing hardfork activation configuration (required on first run, stored in database for subsequent runs)
- `--start-block`: Trusted block hash to initialize validation from (required for first-time setup)
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

### Environment Variables

Each command-line flag has an equivalent environment variable:

- `STATELESS_VALIDATOR_DATA_DIR` → `--data-dir`
- `STATELESS_VALIDATOR_RPC_ENDPOINT` → `--rpc-endpoint`
- `STATELESS_VALIDATOR_WITNESS_ENDPOINT` → `--witness-endpoint`
- `STATELESS_VALIDATOR_GENESIS_FILE` → `--genesis-file`
- `STATELESS_VALIDATOR_START_BLOCK` → `--start-block`
- `STATELESS_VALIDATOR_REPORT_VALIDATION_ENDPOINT` → `--report-validation-endpoint`
- `STATELESS_VALIDATOR_METRICS_ENABLED` → `--metrics-enabled` (set to `true` to enable)
- `STATELESS_VALIDATOR_METRICS_PORT` → `--metrics-port`

**Logging Configuration:**
- `STATELESS_VALIDATOR_LOG_FILE_DIRECTORY`: Directory for log files; enables file logging when set.
  Files rotate daily as `stateless-validator.log.YYYY-MM-DD`.
- `STATELESS_VALIDATOR_LOG_FILE`: Log level for file output (debug|info|warn|error, default: debug)
- `STATELESS_VALIDATOR_LOG_STDOUT`: Log level for console output (debug|info|warn|error, default: info)

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
                          Pulls blocks + witnesses from RPC in parallel batches
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
   Reorg → rollback → restart pipeline
   Stale detection (optional) → reset anchor → restart
```

The pipeline is configured via `PipelineConfig` and customized through trait implementations:
- `BlockProcessor`: Processing logic per block (validation or pass-through)
- `PipelineHooks`: Callbacks for advance/reorg/stale events
- `ProcessedBlock`: Output type of the processing stage

### Key Source Files

| File                                          | Purpose                                                                             |
| --------------------------------------------- | ----------------------------------------------------------------------------------- |
| `crates/stateless-core/src/pipeline.rs`       | Generic pipeline: BlockFetcher, run_pipeline, chain_advancer, find_divergence_point |
| `crates/stateless-core/src/executor.rs`       | Block validation and EVM replay                                                     |
| `crates/stateless-core/src/db.rs`             | Storage traits: ChainStore, BlockStore, ContractStore                               |
| `crates/stateless-core/src/evm_database.rs`   | WitnessDatabase implementing `revm::DatabaseRef`                                    |
| `crates/stateless-core/src/withdrawals.rs`    | Withdrawal validation and MPT witness handling                                      |
| `crates/stateless-common/src/rpc_client.rs`   | RpcClient: HTTP-based block/witness/contract fetching                               |
| `crates/stateless-common/src/db.rs`           | Shared redb table definitions and helpers                                           |
| `crates/stateless-common/src/metrics.rs`      | RpcMethod, RpcMetrics, RpcClientConfig                                              |
| `bin/stateless-validator/src/chain_sync.rs`   | ValidatorFetcher, ValidatorProcessor, ValidatorHooks                                |
| `bin/debug-trace-server/src/chain_sync.rs`    | TraceFetcher, TraceProcessor, TraceHooks                                            |
| `bin/debug-trace-server/src/rpc_service.rs`   | RPC method definitions and handlers                                                 |
| `bin/debug-trace-server/src/data_provider.rs` | Block data fetching with single-flight coalescing                                   |

### Database

The validator and trace server each have their own `redb`-backed database, sharing common table definitions from `stateless-common::db`:

| Table             | Key                        | Value                                                  | Used By                      |
| ----------------- | -------------------------- | ------------------------------------------------------ | ---------------------------- |
| `ANCHOR_BLOCK`    | `"anchor"`                 | `(BlockNumber, BlockHash, StateRoot, WithdrawalsRoot)` | Both                         |
| `CANONICAL_CHAIN` | `BlockNumber`              | `(BlockHash, StateRoot, WithdrawalsRoot)`              | Both                         |
| `CONTRACTS`       | `CodeHash`                 | Bincode+LZ4 `Bytecode`                                 | Both                         |
| `GENESIS_CONFIG`  | `"genesis"`                | JSON `Genesis`                                         | Validator                    |
| `BLOCK_DATA`      | `BlockHash`                | JSON `Block<Transaction>`                              | Trace server                 |
| `WITNESSES`       | `BlockHash`                | Bincode+LZ4 `LightWitness`                             | Trace server                 |
| `BLOCK_RECORDS`   | `(BlockNumber, BlockHash)` | `()`                                                   | Trace server (pruning index) |

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
