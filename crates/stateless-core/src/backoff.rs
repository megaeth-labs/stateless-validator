//! Shared exponential-backoff policy.
//!
//! Used by both [`RpcClientConfig`](../../stateless_common/struct.RpcClientConfig.html)
//! (per-call retries) and the pipeline's fetcher tip-polling loop (unbounded retries).
//! `initial` is the first sleep duration; subsequent retries double it (with optional jitter
//! applied by the caller) up to `max`. `max_retries = None` signals an unbounded polling
//! loop that should keep trying forever.

use std::time::Duration;

/// Exponential backoff configuration.
#[derive(Debug, Clone)]
pub struct BackoffPolicy {
    /// First retry sleep. Each subsequent retry doubles up to `max`.
    pub initial: Duration,
    /// Upper bound on any single retry sleep.
    pub max: Duration,
    /// Bound on retry count before the caller gives up. `None` means keep retrying forever
    /// (used by long-running polling loops).
    pub max_retries: Option<u32>,
}

impl BackoffPolicy {
    /// Bounded policy with `max_retries` attempts.
    pub const fn bounded(initial: Duration, max: Duration, max_retries: u32) -> Self {
        Self { initial, max, max_retries: Some(max_retries) }
    }

    /// Unbounded policy for polling loops that must keep trying.
    pub const fn unbounded(initial: Duration, max: Duration) -> Self {
        Self { initial, max, max_retries: None }
    }
}
