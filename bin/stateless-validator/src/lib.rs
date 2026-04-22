//! Stateless validator binary crate library surface.
//!
//! Exposes the modules used by both the binary entrypoint ([`main.rs`](../main/index.html))
//! and the integration tests under `tests/`.
//!
//! Modules marked `#[doc(hidden)]` are public only so integration tests in `tests/` can
//! reach them; they are not part of a stable API surface for external consumers.

#[doc(hidden)]
pub mod app;
#[doc(hidden)]
pub mod chain_sync;
pub(crate) mod metrics;
#[doc(hidden)]
pub mod validator_db;
pub(crate) mod workers;
