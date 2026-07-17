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
//! - [`db`]: Shared storage traits (`ChainStore`, `ContractStore`); scenario stores are bin-local
//! - [`data_types`]: SALT key/value encoding utilities
//! - [`executor`]: Block validation via EVM replay
//! - [`pipeline`]: Generic three-stage chain sync pipeline (fetch → process → advance) — requires
//!   `std` feature
//! - [`withdrawals`]: MPT witness verification for L2→L1 withdrawals

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc as std;

pub mod chain_spec;
pub mod light_witness;
pub use light_witness::{LightWitness, LightWitnessExecutor, LightWitnessFromSalt};
pub mod evm_database;
pub use evm_database::{WitnessDatabase, WitnessDatabaseError, WitnessExternalEnv};
pub mod db;
pub use db::{
    BlockMeta, ChainStore, ContractStore, MissingDataKind, StoreError, StoreResult, StoreResultExt,
};
pub mod data_types;
pub use data_types::{PlainKey, PlainValue, collect_code_hashes, iter_code_hashes};
pub mod executor;
pub use executor::{BlockInput, ValidationError, ValidationStats, replay_block, validate_block};
#[cfg(feature = "std")]
pub mod pipeline;
#[cfg(feature = "std")]
pub use pipeline::{
    BisectResolver, BlockFetcher, BlockProcessor, DivergenceLookups, ErrorAction, PipelineConfig,
    PipelineHooks, PipelineOutcome, ProcessedBlock, ReorgEvent, ReorgResolution, ReorgResolver,
    block_fetcher, find_divergence_point, run_pipeline,
};
pub mod withdrawals;
