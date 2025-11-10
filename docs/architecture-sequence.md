# Stateless Validator Sequence Diagrams

## 1. System Startup and Initialization

```mermaid
sequenceDiagram
    participant Main as Main Process
    participant DB as ReDB Database
    participant RPC as RPC Client
    participant Tracker as Chain Tracker Thread
    participant Workers as Worker Threads
    participant Pruner as Pruner Thread
    participant Reporter as Reporter Thread

    Main->>Main: Parse CLI arguments
    Main->>Main: Initialize logging system
    Main->>RPC: Create RPC client connections
    activate RPC
    Note over RPC: Connect to data & witness endpoints

    Main->>DB: Open/create validator.redb
    activate DB
    DB-->>Main: Database handle

    alt First run (no genesis in DB)
        Main->>Main: Load genesis from file
        Main->>DB: Store in GENESIS_CONFIG
        DB-->>Main: Genesis stored

        opt Start block specified
            Main->>DB: Initialize anchor in CANONICAL_CHAIN
            Note over DB: Set starting block as canonical tip
        end
    else Existing database
        Main->>DB: Load from GENESIS_CONFIG
        DB-->>Main: ChainSpec loaded
    end

    Main->>DB: Recover interrupted tasks
    Note over DB: Move ONGOING_TASKS → TASK_LIST
    DB-->>Main: Tasks recovered

    Main->>Tracker: Spawn tracker thread
    activate Tracker
    Main->>Workers: Spawn N worker threads (N = CPU count)
    activate Workers
    Main->>Pruner: Spawn pruner thread
    activate Pruner

    opt Reporter enabled
        Main->>Reporter: Spawn reporter thread
        activate Reporter
    end

    Main->>Main: Enter chain_sync() loop
    Note over Main: Monitor canonical chain growth

    deactivate RPC
```

## 2. Block Fetching and Task Creation (Tracker)

```mermaid
sequenceDiagram
    participant Tracker as Chain Tracker
    participant DB as ReDB Database
    participant DataRPC as Data RPC Endpoint
    participant WitnessRPC as Witness Endpoint

    loop Every 100ms
        Tracker->>DB: Get local tip from CANONICAL_CHAIN
        activate DB
        DB-->>Tracker: local_tip (block number)
        deactivate DB

        Tracker->>DataRPC: eth_blockNumber()
        activate DataRPC
        DataRPC-->>Tracker: remote_tip
        deactivate DataRPC

        Tracker->>Tracker: Calculate gap = remote_tip - local_tip

        alt gap > 0 (new blocks available)
            Note over Tracker: Fetch blocks in parallel batches

            par Fetch blocks
                Tracker->>DataRPC: eth_getBlockByNumber(N)
                activate DataRPC
                DataRPC-->>Tracker: Block N with full txs
                deactivate DataRPC
            and Fetch more blocks
                Tracker->>DataRPC: eth_getBlockByNumber(N+1)
                activate DataRPC
                DataRPC-->>Tracker: Block N+1 with full txs
                deactivate DataRPC
            end

            par Fetch witnesses
                Tracker->>WitnessRPC: mega_getBlockWitness(N)
                activate WitnessRPC
                WitnessRPC-->>Tracker: SALT witness + MPT witness
                deactivate WitnessRPC
            and Fetch more witnesses
                Tracker->>WitnessRPC: mega_getBlockWitness(N+1)
                activate WitnessRPC
                WitnessRPC-->>Tracker: SALT witness + MPT witness
                deactivate WitnessRPC
            end

            Tracker->>Tracker: Validate chain structure
            Note over Tracker: Check parent hashes & sequential numbers

            alt Chain structure invalid (reorg detected)
                Tracker->>DB: rollback_chain(fork_point)
                activate DB
                Note over DB: Remove blocks from CANONICAL_CHAIN<br/>Remove blocks from REMOTE_CHAIN<br/>Recover tasks to TASK_LIST
                DB-->>Tracker: Rollback complete
                deactivate DB
            else Chain structure valid
                Tracker->>DB: Start write transaction
                activate DB

                Note over DB: ATOMIC OPERATION
                Tracker->>DB: Store in BLOCK_DATA (hash → block JSON)
                Tracker->>DB: Store in WITNESSES (hash → SALT witness)
                Tracker->>DB: Store in MPT_WITNESSES (hash → MPT witness)
                Tracker->>DB: Add to TASK_LIST (number, hash)
                Tracker->>DB: Add to BLOCK_RECORDS (number, hash)
                Tracker->>DB: Add to REMOTE_CHAIN (number → hash)

                Tracker->>DB: Commit transaction
                DB-->>Tracker: All data stored atomically
                deactivate DB

                Note over Tracker,DB: Workers can now validate these blocks
            end
        else gap = 0 (no new blocks)
            Note over Tracker: Sleep 100ms and retry
        end
    end
```

## 3. Block Validation (Worker)

```mermaid
sequenceDiagram
    participant Worker as Validation Worker
    participant DB as ReDB Database
    participant RPC as RPC Client
    participant WitnessDB as WitnessDatabase
    participant EVM as EVM Engine

    loop Validation loop
        Worker->>DB: get_next_task()
        activate DB

        alt Tasks available
            Note over DB: Find first task >= current canonical tip
            DB->>DB: Move (number, hash) from TASK_LIST to ONGOING_TASKS
            DB->>DB: Load from BLOCK_DATA (hash → block)
            DB->>DB: Load from WITNESSES (hash → witness)
            DB->>DB: Load from MPT_WITNESSES (hash → mpt_witness)
            DB-->>Worker: Task with all data
            deactivate DB

            Worker->>Worker: Parse SALT witness
            Worker->>Worker: Create WitnessExternalEnv

            Worker->>Worker: Verify cryptographic proof
            activate Worker

            alt Proof invalid
                Worker->>DB: Store ValidationResult (success=false, error)
                activate DB
                DB-->>Worker: Result stored
                deactivate DB
                Worker->>DB: Remove from ONGOING_TASKS
                activate DB
                DB-->>Worker: Task completed
                deactivate DB
                deactivate Worker
            else Proof valid
                deactivate Worker

                Worker->>WitnessDB: Create WitnessDatabase
                activate WitnessDB
                Note over WitnessDB: Initialize with witness state data

                loop For each transaction in block
                    Worker->>WitnessDB: Get contract code

                    alt Code in witness
                        WitnessDB-->>Worker: Return from witness
                    else Code not in witness
                        WitnessDB->>DB: Check CONTRACTS table
                        activate DB

                        alt Code cached
                            DB-->>WitnessDB: Return cached bytecode
                            deactivate DB
                        else Code not cached
                            deactivate DB
                            WitnessDB->>RPC: eth_getCode(address)
                            activate RPC
                            RPC-->>WitnessDB: Contract bytecode
                            deactivate RPC

                            WitnessDB->>DB: Store in CONTRACTS (codehash → bytecode)
                            activate DB
                            DB-->>WitnessDB: Cached for future use
                            deactivate DB
                        end

                        WitnessDB-->>Worker: Return bytecode
                    end
                end

                Worker->>EVM: Create EVM environment
                activate EVM
                Note over EVM: Configure with block header & ChainSpec

                Worker->>EVM: replay_block(transactions)
                Note over EVM: Execute all transactions

                alt Transaction execution failed
                    EVM-->>Worker: Execution error
                    deactivate EVM
                    deactivate WitnessDB

                    Worker->>DB: Store ValidationResult (success=false, error)
                    activate DB
                    DB-->>Worker: Result stored
                    deactivate DB
                    Worker->>DB: Remove from ONGOING_TASKS
                    activate DB
                    DB-->>Worker: Task completed
                    deactivate DB
                else Execution successful
                    EVM-->>Worker: State changes (REVM cache)
                    deactivate EVM

                    Worker->>Worker: Flatten cache to PlainKey/PlainValue
                    Worker->>Worker: Update SALT state buckets
                    Worker->>Worker: Compute new state root

                    Worker->>Worker: Parse MPT witness
                    Worker->>Worker: Verify withdrawal state transitions

                    alt Roots match expected values
                        Worker->>DB: Store ValidationResult
                        activate DB
                        Note over DB: success=true<br/>pre_state_root<br/>post_state_root<br/>pre_withdrawals_root<br/>post_withdrawals_root<br/>timestamp
                        DB-->>Worker: Result stored
                        deactivate DB

                        Worker->>DB: Remove from ONGOING_TASKS
                        activate DB
                        DB-->>Worker: Task completed
                        deactivate DB
                        deactivate WitnessDB

                        Note over Worker,DB: Block successfully validated!
                    else Roots mismatch
                        deactivate WitnessDB
                        Worker->>DB: Store ValidationResult (success=false, error)
                        activate DB
                        DB-->>Worker: Result stored
                        deactivate DB
                        Worker->>DB: Remove from ONGOING_TASKS
                        activate DB
                        DB-->>Worker: Task completed
                        deactivate DB
                    end
                end
            end
        else No tasks available
            deactivate DB
            Note over Worker: Sleep 500ms and retry
        end
    end
```

## 4. Canonical Chain Growth (Main Sync Loop)

```mermaid
sequenceDiagram
    participant Main as Main Sync Loop
    participant DB as ReDB Database
    participant Log as Logging System

    loop Sync loop
        opt Sync target specified
            Main->>DB: Get canonical tip
            activate DB
            DB-->>Main: current_tip
            deactivate DB

            alt Tip >= sync_target
                Main->>Main: Exit (sync complete)
            end
        end

        Main->>DB: Get first entry from REMOTE_CHAIN
        activate DB
        DB-->>Main: (block_number, block_hash)
        deactivate DB

        alt No remote blocks
            Note over Main: Nothing validated yet, wait
            Main->>Main: Sleep 1s
        else Remote block exists
            Main->>DB: Get from VALIDATION_RESULTS (hash)
            activate DB
            DB-->>Main: ValidationResult
            deactivate DB

            alt Validation failed
                Main->>Log: Critical error - block failed validation
                Note over Main,Log: Block number, hash, error message
                Main->>Main: Exit process (operator intervention needed)
            else Validation succeeded
                Main->>DB: Get parent block from CANONICAL_CHAIN
                activate DB
                DB-->>Main: Parent with post_state_root & post_withdrawals_root
                deactivate DB

                Main->>Main: Verify state continuity
                Note over Main: current.pre_state = parent.post_state<br/>current.pre_withdrawals = parent.post_withdrawals

                alt State discontinuity detected
                    Main->>Log: Critical error - state roots don't match
                    Note over Main,Log: Expected vs actual roots
                    Main->>Main: Exit process
                else State continuous
                    Main->>DB: Start write transaction
                    activate DB

                    Note over DB: ATOMIC OPERATION
                    Main->>DB: Add to CANONICAL_CHAIN
                    Note over DB: (number → hash, post_state, post_withdrawals)
                    Main->>DB: Remove from REMOTE_CHAIN (number)

                    Main->>DB: Commit transaction
                    DB-->>Main: Block canonicalized
                    deactivate DB

                    Main->>Log: Log validated block
                    Note over Log: Block #, hash, state_root, timestamp

                    Note over Main,DB: Canonical tip advanced by 1 block
                    Note over Main: Loop immediately to process next block
                end
            end
        end
    end
```

## 5. Chain Reorganization

```mermaid
sequenceDiagram
    participant Tracker as Chain Tracker
    participant DB as ReDB Database
    participant Log as Logging System

    Note over Tracker: Detected hash mismatch during chain validation

    Tracker->>DB: Get local chain hashes
    activate DB
    DB-->>Tracker: Local block hashes
    deactivate DB

    Tracker->>Tracker: Find fork point
    Note over Tracker: Walk backwards until hashes match

    Tracker->>Log: Log reorg detection
    Note over Log: Fork point, blocks to remove

    Tracker->>DB: Start write transaction
    activate DB

    Note over DB: ATOMIC ROLLBACK OPERATION

    Tracker->>DB: Delete from CANONICAL_CHAIN WHERE number > fork_point
    Note over DB: Remove orphaned canonical blocks

    Tracker->>DB: Delete from REMOTE_CHAIN WHERE number > fork_point
    Note over DB: Remove orphaned remote blocks

    Tracker->>DB: Get all from ONGOING_TASKS
    DB-->>Tracker: List of ongoing tasks

    loop For each ongoing task
        Tracker->>DB: Move task from ONGOING_TASKS to TASK_LIST
        Note over DB: Recover interrupted validations
    end

    Tracker->>DB: Remove stale tasks from TASK_LIST
    Note over DB: Delete tasks already in canonical chain

    Tracker->>DB: Commit transaction
    DB-->>Tracker: Rollback complete
    deactivate DB

    Note over Tracker: Resume fetching from fork point

    Tracker->>Tracker: Continue with new chain
    Note over Tracker,DB: System recovers automatically
```

## 6. History Pruning

```mermaid
sequenceDiagram
    participant Pruner as History Pruner
    participant DB as ReDB Database
    participant Log as Logging System

    loop Every 300 seconds
        Pruner->>Pruner: Sleep 300s

        Pruner->>DB: Get canonical tip from CANONICAL_CHAIN
        activate DB
        DB-->>Pruner: tip_number
        deactivate DB

        Pruner->>Pruner: Calculate cutoff
        Note over Pruner: cutoff = tip - blocks_to_keep<br/>(default: keep 1000 blocks)

        alt cutoff > 0
            Pruner->>DB: Start write transaction
            activate DB

            Pruner->>DB: Collect hashes from BLOCK_RECORDS WHERE number < cutoff
            DB-->>Pruner: List of block hashes to delete

            Note over DB: ATOMIC PRUNING OPERATION

            loop For each table with block data
                Pruner->>DB: Delete from BLOCK_DATA WHERE hash IN (hashes)
                Pruner->>DB: Delete from WITNESSES WHERE hash IN (hashes)
                Pruner->>DB: Delete from MPT_WITNESSES WHERE hash IN (hashes)
                Pruner->>DB: Delete from VALIDATION_RESULTS WHERE hash IN (hashes)
            end

            Pruner->>DB: Delete from BLOCK_RECORDS WHERE number < cutoff
            Note over DB: Remove tracking records

            Pruner->>DB: Commit transaction
            DB-->>Pruner: Pruning complete
            deactivate DB

            Pruner->>Log: Log pruned count
            Note over Log: Blocks removed, storage reclaimed
        else cutoff <= 0
            Note over Pruner: Not enough blocks to prune yet
        end
    end
```

## 7. Validation Reporting (Optional)

```mermaid
sequenceDiagram
    participant Reporter as Validation Reporter
    participant DB as ReDB Database
    participant Upstream as Upstream Node
    participant Log as Logging System

    loop Every 1 second
        Reporter->>Reporter: Sleep 1s

        Reporter->>DB: Get canonical tip from CANONICAL_CHAIN
        activate DB
        DB-->>Reporter: (start_block, end_block)
        deactivate DB

        alt Canonical chain has blocks
            Reporter->>Upstream: mega_setValidatedBlocks(start, end)
            activate Upstream

            alt RPC call successful
                Upstream-->>Reporter: Upstream tip
                deactivate Upstream

                Reporter->>Reporter: Compare upstream tip with local tip

                alt Local tip < upstream tip (validation gap)
                    Reporter->>Log: Warning - validation lagging behind
                    Note over Log: Local tip, upstream tip, gap size
                else Local tip >= upstream tip
                    Note over Reporter: Validation keeping up
                end
            else RPC call failed
                deactivate Upstream
                Reporter->>Log: Error reporting to upstream
                Note over Reporter: Will retry in 1s
            end
        else No canonical blocks yet
            Note over Reporter: Nothing to report, wait
        end
    end
```

## 8. Complete Block Lifecycle with Database State Changes

```mermaid
sequenceDiagram
    autonumber
    participant RPC as RPC Endpoints
    participant Tracker as Tracker
    participant DB as ReDB Database
    participant Worker as Worker
    participant Main as Main Loop
    participant Pruner as Pruner

    Note over DB: Initial State: Empty database or existing canonical chain

    Tracker->>RPC: Fetch new blocks & witnesses
    activate RPC
    RPC-->>Tracker: Block data + SALT witness + MPT witness
    deactivate RPC

    Tracker->>DB: BEGIN TRANSACTION
    activate DB
    Tracker->>DB: INSERT BLOCK_DATA (hash → block JSON)
    Note over DB: State: Block data stored
    Tracker->>DB: INSERT WITNESSES (hash → witness bytes)
    Note over DB: State: Witness data available
    Tracker->>DB: INSERT MPT_WITNESSES (hash → mpt bytes)
    Note over DB: State: MPT witness available
    Tracker->>DB: INSERT TASK_LIST (number, hash)
    Note over DB: State: Task pending for workers
    Tracker->>DB: INSERT BLOCK_RECORDS (number, hash)
    Note over DB: State: Block tracked for pruning
    Tracker->>DB: INSERT REMOTE_CHAIN (number → hash)
    Note over DB: State: Block in unvalidated chain
    Tracker->>DB: COMMIT TRANSACTION
    DB-->>Tracker: All changes committed atomically
    deactivate DB

    Note over DB,Worker: Database State: Block ready for validation

    Worker->>DB: BEGIN TRANSACTION
    activate DB
    Worker->>DB: SELECT FROM TASK_LIST (get first task)
    Worker->>DB: DELETE FROM TASK_LIST (number, hash)
    Note over DB: State: Task removed from queue
    Worker->>DB: INSERT ONGOING_TASKS (number, hash)
    Note over DB: State: Task claimed by worker
    Worker->>DB: SELECT FROM BLOCK_DATA (hash)
    Worker->>DB: SELECT FROM WITNESSES (hash)
    Worker->>DB: SELECT FROM MPT_WITNESSES (hash)
    Worker->>DB: COMMIT TRANSACTION
    DB-->>Worker: Task claimed with all data
    deactivate DB

    Worker->>Worker: Validate block (EVM execution)
    Note over Worker: Cryptographic proof verification<br/>Transaction replay<br/>State root computation

    Worker->>DB: BEGIN TRANSACTION
    activate DB
    Worker->>DB: INSERT VALIDATION_RESULTS (hash → result)
    Note over DB: State: Validation complete (success/failure)
    Worker->>DB: DELETE FROM ONGOING_TASKS (number, hash)
    Note over DB: State: Task no longer ongoing
    Worker->>DB: COMMIT TRANSACTION
    DB-->>Worker: Validation recorded
    deactivate DB

    Note over DB,Main: Database State: Block validated, ready for canonicalization

    Main->>DB: BEGIN TRANSACTION
    activate DB
    Main->>DB: SELECT FROM REMOTE_CHAIN (first entry)
    Main->>DB: SELECT FROM VALIDATION_RESULTS (hash)
    DB-->>Main: Validation result (success + state roots)
    Main->>DB: SELECT FROM CANONICAL_CHAIN (parent block)
    DB-->>Main: Parent's post_state_root & post_withdrawals_root

    Note over Main: Verify state continuity:<br/>current.pre = parent.post

    Main->>DB: INSERT CANONICAL_CHAIN (number → hash, post_state, post_withdrawals)
    Note over DB: State: Block canonicalized
    Main->>DB: DELETE FROM REMOTE_CHAIN (number)
    Note over DB: State: Block no longer in remote chain
    Main->>DB: COMMIT TRANSACTION
    DB-->>Main: Block moved to canonical chain
    deactivate DB

    Note over DB: Database State: Block in canonical chain

    Note over Pruner: Wait 300s...

    Pruner->>DB: BEGIN TRANSACTION
    activate DB
    Pruner->>DB: SELECT FROM CANONICAL_CHAIN (get tip)
    DB-->>Pruner: tip_number

    Note over Pruner: Calculate cutoff = tip - 1000

    Pruner->>DB: SELECT FROM BLOCK_RECORDS (number < cutoff)
    DB-->>Pruner: List of old block hashes

    Pruner->>DB: DELETE FROM BLOCK_DATA (WHERE hash IN ...)
    Note over DB: State: Block data removed
    Pruner->>DB: DELETE FROM WITNESSES (WHERE hash IN ...)
    Note over DB: State: Witness data removed
    Pruner->>DB: DELETE FROM MPT_WITNESSES (WHERE hash IN ...)
    Note over DB: State: MPT witness removed
    Pruner->>DB: DELETE FROM VALIDATION_RESULTS (WHERE hash IN ...)
    Note over DB: State: Validation results removed
    Pruner->>DB: DELETE FROM BLOCK_RECORDS (WHERE number < cutoff)
    Note over DB: State: Records pruned
    Pruner->>DB: COMMIT TRANSACTION
    DB-->>Pruner: Old data pruned
    deactivate DB

    Note over DB: Final State: Only recent blocks retained,<br/>canonical chain continues growing
```

## 9. Database Table Interactions Summary

```mermaid
graph TB
    subgraph "Block Arrival (Tracker)"
        A1[BLOCK_DATA: hash → block]
        A2[WITNESSES: hash → witness]
        A3[MPT_WITNESSES: hash → mpt]
        A4[TASK_LIST: number, hash]
        A5[BLOCK_RECORDS: number, hash]
        A6[REMOTE_CHAIN: number → hash]
    end

    subgraph "Task Claiming (Worker)"
        B1[TASK_LIST: DELETE]
        B2[ONGOING_TASKS: INSERT]
        B3[CONTRACTS: may INSERT]
    end

    subgraph "Validation Complete (Worker)"
        C1[VALIDATION_RESULTS: INSERT]
        C2[ONGOING_TASKS: DELETE]
    end

    subgraph "Canonicalization (Main)"
        D1[CANONICAL_CHAIN: INSERT]
        D2[REMOTE_CHAIN: DELETE]
    end

    subgraph "Pruning (Pruner)"
        E1[BLOCK_DATA: DELETE old]
        E2[WITNESSES: DELETE old]
        E3[MPT_WITNESSES: DELETE old]
        E4[VALIDATION_RESULTS: DELETE old]
        E5[BLOCK_RECORDS: DELETE old]
    end

    A1 --> B1
    A4 --> B1
    B1 --> B2
    B2 --> C1
    C1 --> D1
    A6 --> D2
    D1 --> E1
    A5 --> E5

    style A1 fill:#e3f2fd
    style A4 fill:#fff3e0
    style B2 fill:#fff3e0
    style C1 fill:#e8f5e9
    style D1 fill:#c8e6c9
    style E1 fill:#ffebee
```

---

## Key Takeaways for Database State Management

### Transaction Boundaries
All database operations use **atomic transactions** to ensure consistency:
- **Tracker**: Single transaction to add all block-related data
- **Worker**: Separate transactions for claiming and completing tasks
- **Main Loop**: Single transaction to canonicalize a block
- **Pruner**: Single transaction to remove old data

### State Transitions
Blocks progress through well-defined states:
1. **Fetched** → Stored in BLOCK_DATA, WITNESSES, MPT_WITNESSES
2. **Queued** → Added to TASK_LIST
3. **Claimed** → Moved to ONGOING_TASKS
4. **Validated** → Result in VALIDATION_RESULTS, removed from ONGOING_TASKS
5. **Canonicalized** → In CANONICAL_CHAIN, removed from REMOTE_CHAIN
6. **Pruned** → Removed from all tables after retention period

### Invariants Maintained
- **No orphan data**: BLOCK_RECORDS ensures all blocks can be pruned
- **State continuity**: Each block's pre-state matches parent's post-state
- **Task recovery**: ONGOING_TASKS can be recovered to TASK_LIST on restart
- **Fork handling**: Reorgs properly clean up affected tables

### Concurrency Safety
- **Workers** can process different blocks in parallel (different hash keys)
- **Tracker** and **Main Loop** coordinate via REMOTE_CHAIN table
- **Pruner** only removes old blocks that won't be accessed
- **No race conditions**: Each component owns specific table regions
