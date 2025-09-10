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
//! - [`witness`]: Witness data generation and state management  
//! - [`database`]: Witness-backed database for REVM
//! - [`evm`]: EVM-specific validation logic and data types
//! - [`storage`]: File system storage and backup management
//! - [`client`]: External service communication
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use validator_core::storage::{StateData, serialized_state_data, deserialized_state_data, BlockFileManager};
//! use std::path::Path;
//!
//! // Serialize data with hash verification
//! let data = vec![1, 2, 3, 4];
//! let serialized = serialized_state_data(data)?;
//!
//! // Deserialize and verify integrity
//! let state_data = deserialized_state_data(serialized)?;
//!
//! // Use BlockFileManager for file operations
//! let file_mgr = BlockFileManager::new(Path::new("/data"));
//! let (block_num, block_hash) = BlockFileManager::parse_filename("280.0xabc123.w");
//! # Ok::<(), std::io::Error>(())
//! ```

pub mod witness;
pub use witness::*;
pub mod database;
pub use database::*;
pub mod storage;
pub use storage::*;
pub mod client;
pub use client::*;
pub mod evm;
pub use evm::*;
