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
//! - [`manager`]: Validation manager for file system storage, witness data, and backup operations
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use validator_core::{StateData, serialized_state_data, deserialized_state_data, ValidationManager};
//! use std::path::Path;
//!
//! // Serialize data with hash verification
//! let data = vec![1, 2, 3, 4];
//! let serialized = serialized_state_data(data)?;
//!
//! // Deserialize and verify integrity
//! let state_data = deserialized_state_data(serialized)?;
//!
//! // Use ValidationManager for file operations
//! let file_mgr = ValidationManager::new(Path::new("/data"));
//! let (block_num, block_hash) = ValidationManager::parse_filename("280.0xabc123.w");
//! # Ok::<(), std::io::Error>(())
//! ```

pub mod database;
pub use database::*;
pub mod manager;
pub use manager::*;
pub mod data_types;
pub use data_types::*;
pub mod executor;
pub use executor::*;
