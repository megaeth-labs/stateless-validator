//! Stateless Validator Core Library
//!
//! This library provides the core functionality for stateless blockchain validation,
//! including witness data handling, file I/O operations, and validation logic.
//!
//! ## Key Components
//!
//! - **BlockFileManager**: Centralized file management for validation, witness, and backup operations
//! - **Validation Logic**: Core validation algorithms for stateless operation
//!
//! ## Modules
//!
//! - [`database`]: Witness-backed database for REVM
//! - [`data_types`]: EVM-specific data types and encoding utilities
//! - [`executor`]: Block execution logic for replaying transactions

pub mod chain_spec;
mod database;
pub mod validator_db;
pub use validator_db::{ValidationDbError, ValidationDbResult, ValidatorDB};
pub mod data_types;
pub use data_types::{PlainKey, PlainValue};
pub mod executor;
pub use executor::{ValidationError, ValidationResult, replay_block, validate_block};
pub mod withdrawals;
