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
//! - [`validator_db`]: Validator database for file system storage, witness data, and backup operations
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use validator_core::{StateData, serialized_state_data, deserialized_state_data, ValidatorDB};
//! use std::path::Path;
//!
//! // Serialize data with hash verification
//! let data = vec![1, 2, 3, 4];
//! let serialized = serialized_state_data(data)?;
//!
//! // Deserialize and verify integrity
//! let state_data = deserialized_state_data(serialized)?;
//!
//! // Use ValidatorDB for file operations
//! let file_mgr = ValidatorDB::new(Path::new("/data"));
//! let (block_num, block_hash) = ValidatorDB::parse_filename("280.0xabc123.w");
//! # Ok::<(), std::io::Error>(())
//! ```

pub mod database;
pub use database::*;
pub mod validator_db;
pub use validator_db::*;
pub mod data_types;
pub use data_types::*;
pub mod executor;
pub use executor::*;
