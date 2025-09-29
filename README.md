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
cargo run --bin stateless-validator -- \
  --data-dir /path/to/validator/data \
  --rpc-endpoint <public-rpc-endpoint>
```

**Required Arguments:**
- `--data-dir` / `-d`: Directory for validator database and data files
- `--rpc-endpoint` / `-r`: JSON-RPC API endpoint URL for retrieve block and witness data

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