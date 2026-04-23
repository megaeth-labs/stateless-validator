//! Stateless validator binary crate library surface.
//!
//! Exposes the items used by the binary entrypoint ([`main.rs`](../main/index.html))
//! and the integration tests under `tests/`. Internals stay `pub(crate)`.

pub(crate) mod app;
pub(crate) mod chain_sync;
pub(crate) mod metrics;
pub(crate) mod validator_db;
pub(crate) mod workers;

pub use app::{CommandLineArgs, VALIDATOR_DB_FILENAME, load_or_create_chain_spec, run};
pub use chain_sync::{ValidatorFetcher, ValidatorHooks, ValidatorProcessor};
pub use validator_db::ValidatorDB;
