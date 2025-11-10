# Stateless Validator Architecture Flowcharts

## 1. System Overview and Component Interaction

```mermaid
flowchart TB
    subgraph External["External Systems"]
        RPC["RPC Endpoint<br/>(Data Provider)"]
        WRPC["Witness Endpoint<br/>(Witness Provider)"]
        Upstream["Upstream Node<br/>(Optional Reporter Target)"]
    end

    subgraph Main["Main Process (Chain Synchronizer)"]
        Init["Initialize System<br/>- Load DB<br/>- Load Genesis<br/>- Setup Logging"]
        Recover["Recover Interrupted Tasks<br/>- Move ONGOING → TASK_LIST"]
        Spawn["Spawn Background Processes"]
        SyncLoop["Main Sync Loop<br/>grow_local_chain()"]
    end

    subgraph Background["Background Processes"]
        Tracker["Remote Chain Tracker<br/>(Thread 1)"]
        Workers["Validation Workers<br/>(Thread 2..N)"]
        Pruner["History Pruner<br/>(Thread N+1)"]
        Reporter["Validation Reporter<br/>(Thread N+2, Optional)"]
    end

    subgraph Database["ReDB Database (validator.redb)"]
        Tables["9 Tables:<br/>- CANONICAL_CHAIN<br/>- REMOTE_CHAIN<br/>- TASK_LIST<br/>- ONGOING_TASKS<br/>- BLOCK_DATA<br/>- WITNESSES<br/>- MPT_WITNESSES<br/>- VALIDATION_RESULTS<br/>- BLOCK_RECORDS<br/>- CONTRACTS<br/>- GENESIS_CONFIG"]
    end

    Init --> Recover
    Recover --> Spawn
    Spawn --> Tracker
    Spawn --> Workers
    Spawn --> Pruner
    Spawn --> Reporter
    Spawn --> SyncLoop

    RPC -.fetch blocks.-> Tracker
    WRPC -.fetch witnesses.-> Tracker
    Tracker -->|write| Tables

    Workers -->|read/write| Tables
    RPC -.fetch code.-> Workers

    SyncLoop -->|read/write| Tables
    Pruner -->|cleanup| Tables
    Reporter -.report validated range.-> Upstream
    Reporter -->|read| Tables

    style Database fill:#e1f5ff
    style External fill:#fff4e1
    style Main fill:#f0f0f0
    style Background fill:#e8f5e9
```

## 2. Database Schema and Relationships

```mermaid
flowchart LR
    subgraph Tables["ReDB Tables"]
        direction TB

        subgraph Chain["Chain State"]
            CC["CANONICAL_CHAIN<br/>BlockNumber → <br/>(Hash, PostStateRoot,<br/>PostWithdrawalsRoot)"]
            RC["REMOTE_CHAIN<br/>BlockNumber → BlockHash"]
            BR["BLOCK_RECORDS<br/>(BlockNumber, Hash) → ()"]
        end

        subgraph Tasks["Task Management"]
            TL["TASK_LIST<br/>(BlockNumber, Hash) → ()"]
            OT["ONGOING_TASKS<br/>(BlockNumber, Hash) → ()"]
        end

        subgraph BlockData["Block & Witness Data"]
            BD["BLOCK_DATA<br/>BlockHash → Vec&lt;u8&gt;<br/>(JSON Block)"]
            W["WITNESSES<br/>BlockHash → Vec&lt;u8&gt;<br/>(SALT Witness)"]
            MW["MPT_WITNESSES<br/>BlockHash → Vec&lt;u8&gt;<br/>(MPT Witness)"]
        end

        subgraph Results["Validation & Cache"]
            VR["VALIDATION_RESULTS<br/>BlockHash → Vec&lt;u8&gt;<br/>(ValidationResult)"]
            CT["CONTRACTS<br/>CodeHash → Vec&lt;u8&gt;<br/>(Bytecode Cache)"]
            GC["GENESIS_CONFIG<br/>'genesis' → Vec&lt;u8&gt;<br/>(ChainSpec)"]
        end
    end

    RC -.references.-> BD
    CC -.references.-> BD
    TL -.references.-> BD
    TL -.references.-> W
    TL -.references.-> MW
    OT -.references.-> BD
    VR -.validates.-> BD
    BR -.tracks all forks.-> BD

    style Chain fill:#e3f2fd
    style Tasks fill:#fff3e0
    style BlockData fill:#f3e5f5
    style Results fill:#e8f5e9
```

## 3. Remote Chain Tracker Flow

```mermaid
flowchart TD
    Start([Tracker Loop Start]) --> GetTips[Get Local & Remote Tips<br/>from DB and RPC]
    GetTips --> CalcGap[Calculate Gap<br/>gap = remote_tip - local_tip]
    CalcGap --> CheckGap{Gap > 0?}

    CheckGap -->|No| Sleep1[Sleep 100ms]
    Sleep1 --> Start

    CheckGap -->|Yes| FetchBlocks[Fetch Blocks in Parallel<br/>from RPC<br/>eth_getBlockByNumber]
    FetchBlocks --> FetchWitnesses[Fetch Witnesses<br/>from Witness Endpoint<br/>mega_getBlockWitness]

    FetchWitnesses --> ValidateChain{Validate Chain<br/>Structure?<br/>- Sequential numbers<br/>- Parent hash links}

    ValidateChain -->|Invalid| Reorg[Detect Reorg<br/>Call rollback_chain]
    Reorg --> Start

    ValidateChain -->|Valid| AddTasks[Add Validation Tasks<br/>Atomic Transaction:<br/>1. Store BLOCK_DATA<br/>2. Store WITNESSES<br/>3. Store MPT_WITNESSES<br/>4. Add to TASK_LIST<br/>5. Record in BLOCK_RECORDS]

    AddTasks --> GrowRemote[Grow Remote Chain<br/>Update REMOTE_CHAIN table]
    GrowRemote --> Start

    FetchBlocks -.RPC Error.-> ErrorSleep[Log Error<br/>Sleep 1s]
    ErrorSleep --> Start

    style Start fill:#e8f5e9
    style AddTasks fill:#fff3e0
    style Reorg fill:#ffebee
    style GrowRemote fill:#e3f2fd
```

## 4. Validation Worker Flow

```mermaid
flowchart TD
    Start([Worker Loop Start]) --> GetTask[Get Next Task<br/>get_next_task]

    GetTask --> CheckTask{Task Available?}

    CheckTask -->|No| Sleep[Sleep 500ms<br/>Idle Wait]
    Sleep --> Start

    CheckTask -->|Yes| MoveTask[Atomic Move:<br/>TASK_LIST → ONGOING_TASKS<br/>Load Block Data & Witnesses]

    MoveTask --> LoadContracts[Load Contract Bytecode<br/>From CONTRACTS cache<br/>or fetch from RPC]

    LoadContracts --> VerifyWitness[Verify SALT Witness<br/>Cryptographic Proof]

    VerifyWitness --> CheckProof{Proof Valid?}

    CheckProof -->|No| RecordFailure[Record Validation Failure<br/>Store in VALIDATION_RESULTS]
    RecordFailure --> Complete

    CheckProof -->|Yes| CreateDB[Create WitnessDatabase<br/>From witness data + contracts]

    CreateDB --> CreateEVM[Create EVM Environment<br/>Block header + ChainSpec]

    CreateEVM --> ReplayTxs[Replay All Transactions<br/>Execute on EVM]

    ReplayTxs --> CheckExec{Execution<br/>Success?}

    CheckExec -->|No| RecordFailure

    CheckExec -->|Yes| ComputeState[Compute State Changes<br/>Flatten REVM cache<br/>Update SALT state]

    ComputeState --> ComputeRoot[Compute New State Root<br/>From updated state]

    ComputeRoot --> VerifyMPT[Verify Withdrawals<br/>Using MPT Witness]

    VerifyMPT --> CompareRoots{Roots Match<br/>Expected?}

    CompareRoots -->|No| RecordFailure

    CompareRoots -->|Yes| RecordSuccess[Record Validation Success<br/>Store in VALIDATION_RESULTS<br/>with pre/post roots]

    RecordSuccess --> Complete[Complete Validation<br/>Remove from ONGOING_TASKS]

    Complete --> Start

    style Start fill:#e8f5e9
    style VerifyWitness fill:#fff3e0
    style RecordFailure fill:#ffebee
    style RecordSuccess fill:#e3f2fd
    style Complete fill:#f3e5f5
```

## 5. Main Sync Loop (grow_local_chain)

```mermaid
flowchart TD
    Start([Sync Loop Start]) --> CheckTarget{Sync Target<br/>Reached?}

    CheckTarget -->|Yes| End([Exit])

    CheckTarget -->|No| GetNext[Get Next Remote Block<br/>First entry from REMOTE_CHAIN]

    GetNext --> HasBlock{Block Exists?}

    HasBlock -->|No| Sleep[Sleep 1s<br/>Wait for validation]
    Sleep --> Start

    HasBlock -->|Yes| GetResult[Get Validation Result<br/>from VALIDATION_RESULTS]

    GetResult --> CheckResult{Validation<br/>Success?}

    CheckResult -->|No| Failed[Block Failed Validation<br/>Log Error & Exit]
    Failed --> End

    CheckResult -->|Yes| CheckParent{Parent State<br/>Matches?<br/>pre_state = parent.post_state<br/>pre_withdrawals = parent.post_withdrawals}

    CheckParent -->|No| StateErr[State Discontinuity Error<br/>Log & Exit]
    StateErr --> End

    CheckParent -->|Yes| MoveToCanonical[Atomic Update:<br/>1. Add to CANONICAL_CHAIN<br/>with post_state & post_withdrawals<br/>2. Remove from REMOTE_CHAIN]

    MoveToCanonical --> LogProgress[Log Validated Block<br/>block_number, hash, state_root]

    LogProgress --> Start

    style Start fill:#e8f5e9
    style CheckResult fill:#fff3e0
    style Failed fill:#ffebee
    style StateErr fill:#ffebee
    style MoveToCanonical fill:#e3f2fd
    style End fill:#f3e5f5
```

## 6. Block Validation Detailed Flow

```mermaid
flowchart TD
    Start([validate_block]) --> ParseWitness[Parse SALT Witness<br/>Extract state buckets]

    ParseWitness --> CreateExtEnv[Create WitnessExternalEnv<br/>Provides bucket capacity]

    CreateExtEnv --> VerifyProof[Verify Cryptographic Proof<br/>witness.verify]

    VerifyProof --> ProofOk{Proof Valid?}

    ProofOk -->|No| Fail1[Return ValidationError<br/>Invalid witness proof]

    ProofOk -->|Yes| CreateWitnessDB[Create WitnessDatabase<br/>- State from witness<br/>- Contracts from cache/RPC<br/>- Historical block hashes]

    CreateWitnessDB --> SetupEVM[Setup EVM Environment<br/>- Block header data<br/>- Chain spec<br/>- EVM hardfork config]

    SetupEVM --> ReplayBlock[Replay Block Transactions<br/>Execute each tx on EVM]

    ReplayBlock --> ExecOk{All Txs<br/>Executed?}

    ExecOk -->|No| Fail2[Return ValidationError<br/>Transaction execution failed]

    ExecOk -->|Yes| ExtractCache[Extract State Changes<br/>Flatten REVM cache to PlainKey/PlainValue]

    ExtractCache --> UpdateState[Update SALT State<br/>Apply account & storage changes<br/>to witness state buckets]

    UpdateState --> ComputeRoot[Compute New State Root<br/>state.state_root]

    ComputeRoot --> ParseMPT[Parse MPT Witness<br/>For L2ToL1MessagePasser contract]

    ParseMPT --> VerifyWithdrawals[Verify Withdrawal State<br/>Check MPT proof<br/>Compare storage roots]

    VerifyWithdrawals --> WithdrawOk{Withdrawals<br/>Valid?}

    WithdrawOk -->|No| Fail3[Return ValidationError<br/>Invalid withdrawal state]

    WithdrawOk -->|Yes| CompareRoots[Compare Computed Roots<br/>vs Expected Roots<br/>- State root<br/>- Withdrawals root]

    CompareRoots --> RootsMatch{Roots Match?}

    RootsMatch -->|No| Fail4[Return ValidationError<br/>State root mismatch]

    RootsMatch -->|Yes| Success[Return ValidationResult<br/>success: true<br/>pre/post state roots<br/>pre/post withdrawal roots]

    Success --> Return([End])
    Fail1 --> Return
    Fail2 --> Return
    Fail3 --> Return
    Fail4 --> Return

    style Start fill:#e8f5e9
    style VerifyProof fill:#fff3e0
    style ReplayBlock fill:#e3f2fd
    style Success fill:#c8e6c9
    style Fail1 fill:#ffebee
    style Fail2 fill:#ffebee
    style Fail3 fill:#ffebee
    style Fail4 fill:#ffebee
    style Return fill:#f3e5f5
```

## 7. History Pruner Flow

```mermaid
flowchart TD
    Start([Pruner Loop Start]) --> Sleep[Sleep 300s<br/>Pruning Interval]

    Sleep --> GetTip[Get Canonical Tip<br/>from CANONICAL_CHAIN]

    GetTip --> CalcCutoff[Calculate Cutoff<br/>cutoff = tip - blocks_to_keep<br/>default: keep 1000 blocks]

    CalcCutoff --> CheckCutoff{Cutoff > 0?}

    CheckCutoff -->|No| Start

    CheckCutoff -->|Yes| PruneRecords["Delete from BLOCK_RECORDS<br/>WHERE block_number &lt; cutoff"]

    PruneRecords --> GetHashes[Collect Block Hashes<br/>to Delete]

    GetHashes --> PruneBlockData["Delete from BLOCK_DATA<br/>WHERE hash IN hashes"]

    PruneBlockData --> PruneWitnesses["Delete from WITNESSES<br/>WHERE hash IN hashes"]

    PruneWitnesses --> PruneMPT["Delete from MPT_WITNESSES<br/>WHERE hash IN hashes"]

    PruneMPT --> PruneResults["Delete from VALIDATION_RESULTS<br/>WHERE hash IN hashes"]

    PruneResults --> LogPrune[Log Pruned Count<br/>Blocks removed]

    LogPrune --> Start

    style Start fill:#e8f5e9
    style CalcCutoff fill:#fff3e0
    style PruneRecords fill:#ffebee
    style LogPrune fill:#e3f2fd
```

## 8. Reorg Handling Flow

```mermaid
flowchart TD
    Start([Detect Reorg]) --> FindFork[Find Fork Point<br/>Compare local & remote hashes<br/>backward from divergence]

    FindFork --> RollbackCanonical[Rollback CANONICAL_CHAIN<br/>Remove blocks > fork_point]

    RollbackCanonical --> RollbackRemote[Rollback REMOTE_CHAIN<br/>Remove blocks > fork_point]

    RollbackRemote --> RecoverTasks[Recover Interrupted Tasks<br/>Move ONGOING_TASKS → TASK_LIST]

    RecoverTasks --> ClearStale[Clear Stale Tasks<br/>Remove tasks already in canonical chain]

    ClearStale --> LogReorg[Log Reorg Details<br/>fork_point, blocks removed]

    LogReorg --> Resume[Resume Normal Operation<br/>Tracker will fetch new chain]

    Resume --> End([Return to Main Loop])

    style Start fill:#ffebee
    style FindFork fill:#fff3e0
    style RecoverTasks fill:#e3f2fd
    style Resume fill:#e8f5e9
    style End fill:#f3e5f5
```

## 9. Data State Transitions

```mermaid
stateDiagram-v2
    [*] --> Fetched: Tracker fetches from RPC

    Fetched --> RemoteChain: Store in REMOTE_CHAIN
    Fetched --> BlockData: Store BLOCK_DATA, WITNESSES, MPT_WITNESSES
    Fetched --> Pending: Add to TASK_LIST

    Pending --> Ongoing: Worker claims task
    Ongoing --> Validating: Load data & start validation

    Validating --> ValidationSuccess: Proof valid & roots match
    Validating --> ValidationFailure: Proof invalid or roots mismatch

    ValidationSuccess --> Validated: Store in VALIDATION_RESULTS
    ValidationFailure --> Validated: Store failure in VALIDATION_RESULTS

    Validated --> CanonicalChain: Main loop advances canonical tip
    CanonicalChain --> Pruned: Pruner removes old data

    RemoteChain --> Reorged: Reorg detected
    Reorged --> Pending: Recover tasks

    Pruned --> [*]

    note right of Fetched
        Block data arrives
        from network
    end note

    note right of Validating
        Cryptographic verification
        + EVM execution
    end note

    note right of CanonicalChain
        Only validated blocks
        enter canonical chain
    end note
```

## 10. Contract Bytecode Caching

```mermaid
flowchart TD
    Start([Worker needs contract]) --> CheckCache{In CONTRACTS<br/>table?}

    CheckCache -->|Yes| UseCache[Load from Cache<br/>Return bytecode]

    CheckCache -->|No| FetchRPC[Fetch from RPC<br/>eth_getCode<br/>for contract address]

    FetchRPC --> RPCSuccess{Fetch<br/>Success?}

    RPCSuccess -->|No| Error[Return Error<br/>Cannot validate block]

    RPCSuccess -->|Yes| StoreCache[Store in CONTRACTS<br/>codehash → bytecode]

    StoreCache --> UseFetched[Return bytecode]

    UseCache --> End([Continue Validation])
    UseFetched --> End
    Error --> End

    style CheckCache fill:#fff3e0
    style UseCache fill:#e3f2fd
    style FetchRPC fill:#ffe0b2
    style StoreCache fill:#c8e6c9
    style Error fill:#ffebee
```

---

## Key Insights for New Developer

### Database Design Principles
1. **Separation of Concerns**: Different tables for chain state, tasks, data, and results
2. **Atomic Operations**: All table updates use transactions for consistency
3. **Efficient Lookups**: Tables keyed by block number or hash for O(1) access
4. **Fork Handling**: BLOCK_RECORDS tracks all forks for efficient pruning

### Data Flow Guarantees
1. **Unvalidated → Validated**: Clear progression through TASK_LIST → ONGOING_TASKS → VALIDATION_RESULTS → CANONICAL_CHAIN
2. **State Continuity**: Each block's pre-state must match parent's post-state
3. **Parallel Safety**: Workers can validate different blocks simultaneously
4. **Reorg Recovery**: System can rollback and recover from chain reorganizations

### Performance Characteristics
1. **Parallel Validation**: Linear throughput scaling with CPU cores
2. **Block Lookahead**: Tracker maintains buffer to keep workers busy
3. **Storage Management**: Automatic pruning prevents unbounded growth
4. **On-demand Caching**: Contract bytecode fetched only when needed
