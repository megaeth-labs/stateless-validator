//! Serial sparse MPT vendored from reth v1.6.0 for withdrawal witness verification.
//!
//! See the module docs in [`trie`] for why this is vendored rather than using
//! `reth-trie-sparse` v2.3.0.

mod errors;
pub use errors::*;

pub mod provider;

mod traits;
pub use traits::*;

mod trie;
pub use trie::*;
