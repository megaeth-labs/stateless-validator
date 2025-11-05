# Stateless Validator

A Rust implementation of a stateless blockchain validator specifically designed for MegaETH. MegaETH is a high-performance, Ethereum-compatible blockchain that achieves exceptional throughput through optimized execution and state management.

This validator enables efficient block verification using cryptographic witness data from [SALT (Small Authentication Large Trie)](https://github.com/megaeth-labs/salt) instead of maintaining full blockchain state. The stateless approach eliminates the need for validators to run on high-end hardware comparable to sequencer nodes, making it practical to run validator nodes at scale.


## Features

- **Partial Statelessness**: Contract bytecode is fetched on-demand from RPC endpoints and cached locally, rather than included in witness data. This hybrid approach dramatically reduces witness size since contract code changes infrequently compared to state data.

- **Embarrassingly Parallel**: Validation workers operate independently on different blocks with no coordination overhead. Throughput scales linearly with the number of CPU cores available. This horizontally scalable architecture allows you to deploy stateless validators on multi-core machines or even across multiple nodes to easily scale throughput as needed.

- **Lower Hardware Spec**: Thanks to our novel [SALT (Small Authentication Large Trie)](https://github.com/megaeth-labs/salt) data structure, the witness is significantly smaller than traditional Merkle Patricia Tree (MPT) or Verkle tree approaches. This reduces the network bandwidth requirements of stateless validators.

- **Simplicity over Performance**: Designed with simplicity as the core principle. The validator uses a minimal, single-threaded executor based on vanilla Revm interpreter and in-memory storage to prioritize simplicity over raw performance. This creates a small Trusted Computing Base that can be thoroughly audited, ensuring high confidence in validation correctness.

- **Pluggable Execution Engine**: Supports multiple execution implementations to prevent single points of failure. Beyond the default Revm-based executor, the validator also supports an executor based on the formal [K semantics of the EVM](https://github.com/Pi-Squared-Inc/evm-semantics) (developed with Pi²). Combined with the hyper-optimized, parallel, JIT-compiled executor on sequencer nodes, this creates three distinct MegaETH client implementations. This multi-client approach ensures state transition integrity while allowing us to aggressively push the sequencer's performance boundary.

## Project Structure

- **`stateless-validator`**: Main validator binary that coordinates chain synchronization and manages validation workers
- **`validator-core`**: Core library providing validation logic, database operations, and EVM execution
- **`test_data/`**: Integration test data including blocks, witnesses, and contract bytecode

## Quick Start

### Building

```bash
cargo build --release
```

### Running

```bash
STATELESS_VALIDATOR_LOG_FILE_DIRECTORY=/path/to/log_dir \
STATELESS_VALIDATOR_LOG_FILE_FILTER=debug \
STATELESS_VALIDATOR_LOG_STDOUT_FILTER=info \
cargo run --bin stateless-validator -- \
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
- `--report-validation-results`: Enable reporting of validated blocks to the upstream node (disabled by default)

### Environment Variables

Each command-line flag has an equivalent environment variable, which allows you to run the validator without passing long argument lists:

- `STATELESS_VALIDATOR_DATA_DIR` → `--data-dir`
- `STATELESS_VALIDATOR_RPC_ENDPOINT` → `--rpc-endpoint`
- `STATELESS_VALIDATOR_WITNESS_ENDPOINT` → `--witness-endpoint`
- `STATELESS_VALIDATOR_GENESIS_FILE` → `--genesis-file`
- `STATELESS_VALIDATOR_START_BLOCK` → `--start-block`
- `STATELESS_VALIDATOR_REPORT_VALIDATION_RESULTS` → `--report-validation-results` (set to `true` to enable)

**Logging Configuration:**
- `STATELESS_VALIDATOR_LOG_FILE_DIRECTORY`: directory for log files; enables file logging when set. Files rotate daily as stateless-validator.log.YYYY-MM-DD
- `STATELESS_VALIDATOR_LOG_FILE_FILTER`: debug|info|warn|error (default: debug)
- `STATELESS_VALIDATOR_LOG_STDOUT_FILTER`: debug|info|warn|error (default: info)

Log levels: **DEBUG** (detailed diagnostics), **INFO** (key operations), **WARN** (non-critical issues), **ERROR** (serious failures). For production, use `info` for terminal output and `debug` for file logging.

Example:

```bash
export STATELESS_VALIDATOR_DATA_DIR=/path/to/validator/data
export STATELESS_VALIDATOR_RPC_ENDPOINT=<public-rpc-endpoint>
export STATELESS_VALIDATOR_WITNESS_ENDPOINT=<witness-rpc-endpoint>
export STATELESS_VALIDATOR_GENESIS_FILE=/path/to/genesis.json
export STATELESS_VALIDATOR_START_BLOCK=<trusted-block-hash>
export STATELESS_VALIDATOR_REPORT_VALIDATION_RESULTS=false
export STATELESS_VALIDATOR_LOG_FILE_DIRECTORY=/path/to/log_dir
export STATELESS_VALIDATOR_LOG_FILE_FILTER=debug
export STATELESS_VALIDATOR_LOG_STDOUT_FILTER=info

cargo run --release --bin stateless-validator
```

**Note**: Command-line arguments take precedence over environment variables.

### Getting Started

The stateless validator requires a trusted starting point and hardfork configuration for security. On first run, you must specify both a genesis file and a trusted block hash:

```bash
# Initialize from genesis and a trusted block (e.g., genesis or recent finalized block)
cargo run --bin stateless-validator -- \
  --data-dir ./validator-data \
  --rpc-endpoint https://your-rpc-endpoint.com \
  --witness-endpoint https://your-witness-endpoint.com \
  --genesis-file ./genesis/genesis-6342.json \
  --start-block 0x1234567890abcdef...
```

The validator will:
1. Load the genesis file and extract hardfork activation rules, then store this configuration in the database
2. Fetch the specified block from the RPC endpoint
3. Initialize the canonical chain database with this trusted block
4. Begin validation from this anchor point, applying the appropriate EVM rules based on hardfork activation

For subsequent runs, you can omit both `--genesis-file` and `--start-block` to resume from the existing database:

```bash
# Resume validation from existing database
cargo run --bin stateless-validator -- \
  --data-dir ./validator-data \
  --rpc-endpoint https://your-rpc-endpoint.com \
  --witness-endpoint https://your-witness-endpoint.com
```

Alternatively, you can supply either or both flags again to reset the starting block or update the genesis configuration:

```bash
# Reset starting block while keeping existing genesis config
cargo run --bin stateless-validator -- \
  --data-dir ./validator-data \
  --rpc-endpoint https://your-rpc-endpoint.com \
  --witness-endpoint https://your-witness-endpoint.com \
  --start-block 0xnew_trusted_block_hash...

# Update genesis config (e.g., after a hardfork)
cargo run --bin stateless-validator -- \
  --data-dir ./validator-data \
  --rpc-endpoint https://your-rpc-endpoint.com \
  --witness-endpoint https://your-witness-endpoint.com \
  --genesis-file ./genesis/updated-genesis.json
```


## Architecture

The stateless validator employs a transactional database as its central coordination mechanism, enabling reliable state management and seamless communication between all system components. This database-centric architecture ensures data consistency through ACID transactions while providing a foundation that naturally scales from single-node deployments to distributed multi-node configurations.


### Core Components

**Chain Synchronizer**
The main orchestrator that continuously advances the local canonical chain as blocks are successfully validated.

**Remote Chain Tracker**
Background component that maintains a configurable lookahead buffer of unvalidated blocks from the remote chain. It also handles chain reorg and rollback automatically.

**Validation Workers**
Embarrassingly parallel workers that independently claim validation tasks from a queue. Each worker fetches missing contract bytecode, performs stateless validation using SALT witnesses, and stores results. No coordination overhead between workers enables linear throughput scaling.

**History Pruner**
Background component that periodically removes old block data beyond a configurable retention window to maintain constant storage overhead.

**ValidatorDB**
The central coordination database that enables reliable multi-component interaction through ACID transactions. It organizes validator state into 9 specialized tables that support the complete validation workflow:

Chain State Management:
- `CANONICAL_CHAIN`: Local validated blockchain progression (BlockNumber → BlockHash, StateRoot)
- `REMOTE_CHAIN`: Unvalidated lookahead blocks from remote chain (BlockNumber → BlockHash)
- `BLOCK_RECORDS`: Complete fork-aware block history (BlockNumber, BlockHash → ())

Task Coordination:
- `TASK_LIST`: Pending validation work queue (BlockNumber, BlockHash → ())
- `ONGOING_TASKS`: Currently claimed validation tasks (BlockNumber, BlockHash → ())
- `VALIDATION_RESULTS`: Completed validation outcomes (BlockHash → ValidationResult)

Data Storage:
- `BLOCK_DATA`: Full block content and transactions (BlockHash → Block<Transaction>)
- `WITNESSES`: SALT cryptographic witness data (BlockHash → SaltWitness)
- `CONTRACTS`: On-demand contract bytecode cache (CodeHash → Bytecode)
- `GENESIS_CONFIG`: Genesis configuration with hardfork activation rules (singleton key → Genesis JSON)


### Data Flow & Workflow

**1. Block Ingestion**
Remote Chain Tracker fetches new blocks and witnesses in parallel, maintaining a lookahead buffer ahead of the canonical chain tip.

**2. Task Creation**
Blocks from the remote chain are queued as validation tasks with their corresponding witness data and stored in ValidatorDB.

**3. Parallel Validation**
Workers atomically claim tasks from the queue, fetch any missing contract bytecode via RPC, and perform stateless validation using the SALT witness and cached contracts.

**4. Chain Advancement**
The Chain Synchronizer continuously checks for successfully validated blocks and moves them from the remote chain to the canonical chain, ensuring parent-child relationships and state root continuity.

**5. Storage Management**
History Pruner removes old data beyond the retention window to prevent unbounded storage growth.

## Development

### Testing

```bash
cargo test
```

## License

[Add your license information here]
