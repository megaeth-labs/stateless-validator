//! Stateless Validator Core Library
//!
//! Core building blocks for stateless block verification on MegaETH:
//! EVM execution, SALT witness cryptography, a generic chain-sync pipeline,
//! and the abstract storage / RPC traits that the rest of the workspace implements.
//!
//! ## Modules
//!
//! - [`pipeline`]: Generic three-stage chain sync pipeline (fetch → process → advance)
//! - [`executor`]: Block validation via EVM replay
//! - [`evm_database`]: Witness-backed `DatabaseRef` for REVM
//! - [`db`]: Abstract storage traits (`ChainStore`, `ContractStore`, etc.)
//! - [`rpc`]: `ChainDataProvider` trait for abstracting RPC access
//! - [`chain_spec`]: Chain specification and hardfork activation
//! - [`data_types`]: SALT key/value encoding utilities
//! - [`light_witness`]: Fast witness deserialization (skips proof validation)
//! - [`withdrawals`]: MPT witness verification for L2→L1 withdrawals

pub mod chain_spec;
pub mod light_witness;
pub use light_witness::{LightWitness, LightWitnessExecutor};
pub mod evm_database;
pub use evm_database::{WitnessDatabase, WitnessDatabaseError, WitnessExternalEnv};
pub mod db;
pub use db::{BlockMeta, BlockStore, ChainStore, ContractStore, GenesisStore, PrunableChainStore};
pub mod data_types;
pub use data_types::{PlainKey, PlainValue, iter_code_hashes};
pub mod executor;
pub use executor::{
    ValidationError, ValidationResult, ValidationStats, replay_block, validate_block,
};
pub mod pipeline;
pub use pipeline::{
    BlockFetcher, BlockProcessor, ErrorAction, PipelineConfig, PipelineHooks, PipelineOutcome,
    ProcessedBlock, ReorgEvent, block_fetcher, find_divergence_point, run_pipeline,
};
pub mod withdrawals;
