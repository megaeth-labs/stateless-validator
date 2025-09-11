//! This module provides functions for interacting with the EVM, specifically for replaying
//! block transactions using REVM.

mod data_types;
mod executor;

pub use data_types::*;
pub use executor::*;
