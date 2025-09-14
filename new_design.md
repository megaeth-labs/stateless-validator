# Stateless Validator Design Document

## Overview

This document outlines the design for a new stateless validator implementation built from the ground up. It's meant to be much cleaner than the current implementation in the codebase.

## Table of Contents

1. [Component Architecture & Interactions]
2. [Validator DB Schema]
3. [ValidatorDB API Design]

---

## Component Architecture & Interactions

### Core Components

#### 1. **Chain Synchronizer or Main Orchestrator**
Manages blockchain synchronization and finality tracking:
- Monitors chain head progression via a remote RPC endpoint
- Tracks block finality status via a remote RPC endpoint
- Manages reorganization detection and recovery
- Fetches block and witness data via a remote RPC endpoint
- Creates validation tasks (i.e., new blocks to be validated) and stores them
  in the ValidationDB for validation workers to pull
- Obtains validation results and use them to drive the progression of the local chain tip
- Prune block and witness data that are too far in the past to keep storage overhead constant

#### 2. **Validator Database (ValidatorDB)**
The central workspace used to coordinate all other components:
- Persists the local chain status
- Used by the main orchestrator to store newly arrived validation tasks
- Used by the main orchestrator to pull validation results
- Used by the validation workers to pull available tasks
- Used by the validation workers to store validation results back

#### 3. **Validation Workers**
Actually performs the validation tasks
- Waits for new tasks to become available in ValidationDB
- Stores the result back to the ValidationDB after validation completes

#### 4. **RPC client and server**
Used by the main orchestrator to communicate with external RPC nodes
- the server is just a remote RPC endpoint (we don't have control over)
- the client logic is already implemented in rpc.rs (although it may not be feature-complete for this new validator implementation)

---

## Validator DB Schema

### Overview
We use the redb as our backend database. It's an embedded database that provides
a BTreeMap-like interface.

### Table Definitions

1. CANONICAL_CHAIN: BlockNumber -> BlockHash
    - Stores our local view of the canonical chain
2. TASK_LIST: (BlockNumber, BlockHash) -> ()
    - Holds all the validation tasks to be taken by validation workers
    - Theoretically, BlockHash itself is sufficient to be the key; but combining the BlockNumber allows us to order the TASK_LIST in ascending order of block numbers
3. ONGOING_TASKS: (BlockNumber, BlockHash) -> ()
    - Holds all the validation tasks that are currently being processed by the workers
4. BLOCK_DATA: BlockHash -> Block
    - Holds the full block needed in validation
5. WITNESSES: BlockHahs -> SaltWitness
    - Holds the witness data needed in validation
6. VALIDATION_RESULTS: BlockHash -> ValidationResult
    - Holds the validation
7. BLOCK_RECORDS: (BlockNumber, BlockHash) -> ()
    - Holds all the validation tasks that we are aware of.
    - In the prescense of chain forks, we may have multiple BlockHashes at the same
      block height; using a compound key that contains the block number allows us to find out all the forks efficiently
8. CONTRACTS: B256 -> BYTECODE
    - Used to cache the contract bytecode that are fetched on-demand

---

## ValidatorDB API Design

The ValidatorDB needs to provide at the following methods for the main orchestrator
and validation workers.

1. add_validation_task
    - invoked by the main orchestrator to add a new block to be validated
    - Writes a new task to TASK_LIST table
    - Writes the associated block data and witness to tables BLOCK_DATA and WITNESSES, respectively
    - record this block in BLOCK_RECORDS table
2. add_contract_code
    - Invoked by validation workers to add needed bytecode before validation starts
3. complete_validation
    - Invoked by validation workers to write validation result into VALIDATION_RESULTS
    - remove the finished task from ONGOING_TASKS
4. restart_ongoing_tasks
    - Invoked by the main orchestrator to move all ONGOING_TASKS back to TASK_LIST
    - Useful when the stateless validator process crashes but some of the tasks are
    still left in the ONGOING_TASKS table
5. get_next_task
    - Invoked by validation workers
    - Move the first task in TASK_LIST into ONGOING_TASK
6. get_validation_result
    - Invoked by the main orchestrator to read the validation result
7. prune_history
    - Invoked by the main orchestrator to remove block records
8. chain_growth
    - Invoked by the main orchestrator to advance the chain by one more block
    - need to check if the given block extends the current CANONICAL_CHAIN and has been validated by the workers
9. chain_rollback
    - Invoked by the main orchestrator in the rare case where the local canonical chain diverges from the remote chain (because the remote chain reorgs)