//! Stateless Validator Core Library
//!
//! This library provides the core functionality for stateless blockchain validation,
//! including witness data handling, file I/O operations, and validation logic.
//!
//! ## Key Components
//!
//! - **Validation Logic**: Core validation algorithms for stateless operation
//! - **Persistence Traits**: Abstract storage interfaces (`ContractStore`, `ChainStore`, etc.)
//!
//! ## Modules
//!
//! - [`evm_database`]: Witness-backed database for REVM
//! - [`data_types`]: EVM-specific data types and encoding utilities
//! - [`executor`]: Block execution logic for replaying transactions
//! - [`pipeline`]: Generic chain sync pipeline

pub mod chain_spec;
pub mod light_witness;
pub use light_witness::{LightWitness, LightWitnessExecutor};
pub mod evm_database;
pub use evm_database::{WitnessDatabase, WitnessDatabaseError, WitnessExternalEnv};
pub mod db;
pub use db::{BlockMeta, BlockStore, ChainStore, ContractStore, GenesisStore, PrunableChainStore};
pub mod data_types;
pub use data_types::{PlainKey, PlainValue};
pub mod executor;
pub use executor::{
    ValidationError, ValidationResult, ValidationStats, replay_block, validate_block,
};
pub mod pipeline;
pub use pipeline::{
    BlockProcessor, PipelineConfig, PipelineHooks, PipelineOutcome, ProcessedBlock, ReorgEvent,
    block_fetcher, find_divergence_point, run_pipeline,
};
pub mod rpc;
pub mod withdrawals;
pub use rpc::ChainDataProvider;
