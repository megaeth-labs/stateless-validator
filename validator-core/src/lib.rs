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
//! - [`chain_sync`]: Chain synchronization utilities

use alloy_primitives::B256;
use revm::primitives::KECCAK_EMPTY;
use salt::SaltWitness;

pub mod chain_spec;
pub mod chain_sync;
pub use chain_sync::{
    ChainSyncConfig, DEFAULT_METRICS_PORT, FetchResult, fetch_blocks_batch, remote_chain_tracker,
};
mod database;
pub mod validator_db;
pub use validator_db::{ValidationDbError, ValidationDbResult, ValidatorDB};
pub mod data_types;
pub use data_types::{PlainKey, PlainValue};
pub mod executor;
pub use executor::{
    ValidationError, ValidationResult, ValidationStats, replay_block, validate_block,
};
pub mod tracing_executor;
pub use tracing_executor::{
    parity_trace_block, parity_trace_transaction, trace_block, trace_transaction,
};
pub mod rpc_client;
pub mod withdrawals;
pub use rpc_client::{RpcClient, SetValidatedBlocksResponse};

/// Extracts all contract code hashes from a SALT witness.
///
/// This function scans the witness for accounts with non-empty bytecode and returns
/// their code hashes. These hashes can then be used to fetch the actual bytecode
/// from an RPC provider.
///
/// # Arguments
/// * `witness` - The SALT witness containing account state
///
/// # Returns
/// A vector of unique code hashes (B256) that need to be fetched
pub fn extract_code_hashes(witness: &SaltWitness) -> Vec<B256> {
    let mut code_hashes: Vec<B256> = witness
        .kvs
        .values()
        .filter_map(|salt_val| salt_val.as_ref())
        .filter_map(
            |val| match (PlainKey::decode(val.key()), PlainValue::decode(val.value())) {
                (PlainKey::Account(_), PlainValue::Account(acc)) => {
                    acc.codehash.filter(|&codehash| codehash != KECCAK_EMPTY)
                }
                _ => None,
            },
        )
        .collect();

    code_hashes.sort();
    code_hashes.dedup();
    code_hashes
}
