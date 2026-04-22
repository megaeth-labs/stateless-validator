//! Shared exponential-backoff policy.
//!
//! `initial` is the first sleep duration; the caller doubles it on each subsequent retry up to
//! `max`. Retry termination (if any) lives in the caller — this type only describes the sleep
//! schedule.

use std::time::Duration;

/// Exponential backoff configuration.
#[derive(Debug, Clone)]
pub struct BackoffPolicy {
    /// First retry sleep. Each subsequent retry doubles up to `max`.
    pub initial: Duration,
    /// Upper bound on any single retry sleep.
    pub max: Duration,
}

impl BackoffPolicy {
    /// Creates a new policy with the given `initial` and `max` sleep durations.
    pub const fn new(initial: Duration, max: Duration) -> Self {
        Self { initial, max }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_fields() {
        let p = BackoffPolicy::new(Duration::from_millis(100), Duration::from_secs(1));
        assert_eq!(p.initial, Duration::from_millis(100));
        assert_eq!(p.max, Duration::from_secs(1));
    }

    #[test]
    fn clone_preserves_fields() {
        let p = BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(2));
        let q = p.clone();
        assert_eq!(q.initial, p.initial);
        assert_eq!(q.max, p.max);
    }
}
