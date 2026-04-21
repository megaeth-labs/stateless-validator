//! Shared redb persistence layer for stateless validation.
//!
//! Provides table definitions, serialization helpers, and common database
//! operations used by both `ValidatorDB` (stateless-validator) and
//! `ServerDB` (debug-trace-server).
//!
//! Also contains [`ContractCache`], an in-memory write-through cache
//! backed by any [`stateless_core::db::ContractStore`] implementation.

pub mod cache;
pub mod helpers;
pub mod serialize;
pub mod tables;

pub use cache::ContractCache;
pub use helpers::{
    db_add_contracts, db_advance_chain, db_get_anchor, db_get_block_hash, db_get_canonical_tip,
    db_get_contracts, db_get_earliest_block, db_reset_to_anchor, db_rollback_chain,
};
pub use serialize::{
    decode_block_from_slice, decode_from_slice, encode_block_to_vec, encode_to_vec,
};
pub use tables::{
    ANCHOR_BLOCK, BLOCK_DATA, BLOCK_RECORDS, CANONICAL_CHAIN, CONTRACTS, DEFAULT_MAX_CHAIN_LENGTH,
    Database, GENESIS_CONFIG, WITNESSES, block_meta_from_tuple, block_meta_to_tuple,
};
