//! Stateless Validator Core Library
//!
//! This library provides the core functionality for stateless blockchain validation,
//! including witness data handling, file I/O operations, and validation logic.
//!
//! ## Key Components
//!
//! - **BlockFileManager**: Centralized file management for validation, witness, and backup
//!   operations
//! - **Validation Logic**: Core validation algorithms for stateless operation
//!
//! ## Modules
//!
//! - [`database`]: Witness-backed database for REVM
//! - [`data_types`]: EVM-specific data types and encoding utilities
//! - [`executor`]: Block execution logic for replaying transactions
//! - [`chain_sync`]: Chain synchronization utilities

pub mod chain_spec;
pub mod chain_sync;
pub use chain_sync::{
    ChainSyncConfig, DEFAULT_METRICS_PORT, FetchResult, block_fetcher, chain_advancer,
};
pub mod database;
pub mod light_witness;
pub use database::{WitnessDatabase, WitnessDatabaseError, WitnessExternalEnv};
pub mod data_types;
pub use data_types::{PlainKey, PlainValue};
pub mod memory_db;
pub use light_witness::{LightWitness, LightWitnessExecutor};
pub use memory_db::{
    ChainTip, ContractCache, PersistentStore, ValidatedBlock, ValidationFailure, ValidationTask,
};
pub mod storage_traits;
pub use storage_traits::{BlockDataStore, ChainState, TaskQueue, ValidationResultStore};
pub mod validator_db;
pub use validator_db::{ValidationDbError, ValidationDbResult, ValidatorDB};
pub mod executor;
pub use executor::{
    ValidationError, ValidationResult, ValidationStats, replay_block, validate_block,
};
pub mod rpc_client;
pub mod withdrawals;
pub use rpc_client::{
    RpcClient, RpcClientConfig, RpcMethod, RpcMetrics, SetValidatedBlocksResponse,
};
