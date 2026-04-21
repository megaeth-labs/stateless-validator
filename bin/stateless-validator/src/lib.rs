//! Stateless validator binary crate library surface.
//!
//! Exposes the modules used by both the binary entrypoint ([`main.rs`](../main/index.html))
//! and the integration tests under `tests/`.

pub mod app;
pub mod chain_sync;
pub(crate) mod metrics;
pub mod validator_db;
pub(crate) mod workers;
