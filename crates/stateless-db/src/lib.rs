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
    read_anchor, read_block_hash, read_canonical_tip, read_contracts, read_earliest_block,
    write_add_contracts, write_advance_chain, write_reset_to_anchor, write_rollback_chain,
};
pub use serialize::{
    decode_block_from_slice, decode_from_slice, encode_block_to_vec, encode_to_vec,
};
pub use tables::{
    ANCHOR_BLOCK, BLOCK_DATA, BLOCK_RECORDS, CANONICAL_CHAIN, CONTRACTS, DEFAULT_MAX_CHAIN_LENGTH,
    Database, GENESIS_CONFIG, WITNESSES, block_meta_from_tuple, block_meta_to_tuple,
};
