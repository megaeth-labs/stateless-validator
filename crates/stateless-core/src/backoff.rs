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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_sets_max_retries() {
        let p = BackoffPolicy::bounded(Duration::from_millis(100), Duration::from_secs(1), 5);
        assert_eq!(p.initial, Duration::from_millis(100));
        assert_eq!(p.max, Duration::from_secs(1));
        assert_eq!(p.max_retries, Some(5));
    }

    #[test]
    fn unbounded_has_none_max_retries() {
        let p = BackoffPolicy::unbounded(Duration::from_millis(200), Duration::from_secs(30));
        assert_eq!(p.initial, Duration::from_millis(200));
        assert_eq!(p.max, Duration::from_secs(30));
        assert!(p.max_retries.is_none());
    }

    #[test]
    fn clone_preserves_fields() {
        let p = BackoffPolicy::bounded(Duration::from_millis(1), Duration::from_millis(2), 3);
        let q = p.clone();
        assert_eq!(q.initial, p.initial);
        assert_eq!(q.max, p.max);
        assert_eq!(q.max_retries, p.max_retries);
    }
}
