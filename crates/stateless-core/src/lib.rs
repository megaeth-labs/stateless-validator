//! Stateless Validator Core Library
//!
//! Core building blocks for stateless block verification on MegaETH:
//! EVM execution, SALT witness cryptography, a generic chain-sync pipeline,
//! and the abstract storage / RPC traits that the rest of the workspace implements.
//!
//! ## Modules
//!
//! - [`chain_spec`]: Chain specification and hardfork activation
//! - [`light_witness`]: Fast witness deserialization (skips proof validation)
//! - [`evm_database`]: Witness-backed `DatabaseRef` for REVM
//! - [`db`]: Abstract storage traits (`ChainStore`, `ContractStore`, etc.) — requires `std` feature
//! - [`data_types`]: SALT key/value encoding utilities
//! - [`executor`]: Block validation via EVM replay — requires `std` feature
//! - [`pipeline`]: Generic three-stage chain sync pipeline (fetch → process → advance) — requires
//!   `std` feature
//! - [`withdrawals`]: MPT witness verification for L2→L1 withdrawals

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc as std;

pub mod chain_spec;
pub mod light_witness;
pub use light_witness::{LightWitness, LightWitnessExecutor};
#[cfg(feature = "std")]
pub mod evm_database;
#[cfg(feature = "std")]
pub use evm_database::{WitnessDatabase, WitnessDatabaseError, WitnessExternalEnv};
#[cfg(feature = "std")]
pub mod db;
#[cfg(feature = "std")]
pub use db::{
    BlockMeta, BlockStore, ChainStore, ContractStore, GenesisStore, MissingDataKind,
    PrunableChainStore, StoreError, StoreResult, StoreResultExt,
};
pub mod data_types;
pub use data_types::{PlainKey, PlainValue, iter_code_hashes};
#[cfg(feature = "std")]
pub mod executor;
#[cfg(feature = "std")]
pub use executor::{
    ValidationError, ValidationResult, ValidationStats, replay_block, validate_block,
};
#[cfg(feature = "std")]
pub mod pipeline;
#[cfg(feature = "std")]
pub use pipeline::{
    BlockFetcher, BlockProcessor, ErrorAction, PipelineConfig, PipelineHooks, PipelineOutcome,
    ProcessedBlock, ReorgEvent, block_fetcher, find_divergence_point, run_pipeline,
};
pub mod withdrawals;
