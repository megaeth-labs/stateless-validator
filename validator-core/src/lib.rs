//! Stateless Validator Core Library
//!
//! This library provides the core functionality for stateless blockchain validation,
//! including witness data handling, file I/O operations, and validation logic.
//!
//! ## Key Components
//!
//! - **StateData**: Wrapper for serialized data with BLAKE3 hash verification (in `storage` module)
//! - **BlockFileManager**: Centralized file management for validation, witness, and backup operations
//! - **Serialization**: Bincode-based serialization with integrity checking (in `storage` module)
//! - **Validation Logic**: Core validation algorithms for stateless operation
//!
//! ## Modules
//!
//! - [`database`]: Witness-backed database for REVM
//! - [`data_types`]: EVM-specific data types and encoding utilities
//! - [`executor`]: Block execution logic for replaying transactions

mod chain_spec;
mod database;
pub mod validator_db;
pub use validator_db::{
    StateData, ValidationResult, ValidatorDB, curent_time_to_u64, deserialized_state_data,
};
pub mod data_types;
pub use data_types::{PlainKey, PlainValue};
pub mod executor;
pub use executor::{ValidationError, validate_block};
