//! Stateless validator binary crate library surface.
//!
//! Exposes the items used by the binary entrypoint ([`main.rs`](../main/index.html))
//! and the integration tests under `tests/`. Internals stay `pub(crate)`.

pub(crate) mod app;
pub(crate) mod chain_sync;
pub(crate) mod metrics;
pub(crate) mod r2_witness;
pub(crate) mod runner;
pub(crate) mod validator_db;

pub use app::{
    CommandLineArgs, VALIDATOR_DB_FILENAME, WitnessSource, load_or_create_chain_spec, run,
};
pub use chain_sync::{ValidationTask, ValidatorFetcher, ValidatorHooks, ValidatorProcessor};
pub use r2_witness::{R2WitnessClient, R2WitnessError};
pub use runner::run_with_signals;
pub use validator_db::ValidatorDB;

/// Fixtures shared by the unit tests of several modules.
#[cfg(test)]
pub(crate) mod test_support {
    use alloy_primitives::{B256, BlockHash};
    use stateless_core::db::BlockMeta;

    /// A deterministic `BlockMeta` derived from `num` alone.
    pub(crate) fn make_block_meta(num: u64) -> BlockMeta {
        BlockMeta {
            block_number: num,
            block_hash: BlockHash::from([num as u8; 32]),
            post_state_root: B256::from([(num.wrapping_add(100)) as u8; 32]),
            post_withdrawals_root: B256::from([(num.wrapping_add(200)) as u8; 32]),
        }
    }
}
