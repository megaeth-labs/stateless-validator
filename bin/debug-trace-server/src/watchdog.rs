//! WatchDog for monitoring slow RPC requests.
//!
//! Tracks in-flight RPC requests and logs warnings when requests exceed
//! a configurable duration threshold.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;
use tracing::warn;

/// Default interval for checking slow requests.
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Default threshold for considering a request as slow.
const DEFAULT_SLOW_THRESHOLD: Duration = Duration::from_secs(30);

/// Tracks in-flight RPC requests and periodically checks for slow ones.
#[derive(Clone)]
pub struct WatchDog {
    inner: Arc<WatchDogInner>,
}

struct WatchDogInner {
    requests: Mutex<HashMap<u64, RequestEntry>>,
    next_id: Mutex<u64>,
    slow_threshold: Duration,
}

struct RequestEntry {
    method: String,
    started_at: Instant,
    block_number: Option<u64>,
}

/// Guard that automatically unregisters the request when dropped.
pub struct RequestGuard {
    id: u64,
    watchdog: WatchDog,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let id = self.id;
        let watchdog = self.watchdog.clone();
        // Use try_lock to avoid blocking in drop
        let removed = {
            if let Ok(mut requests) = watchdog.inner.requests.try_lock() {
                requests.remove(&id);
                true
            } else {
                false
            }
        };
        if !removed {
            // Spawn a task to clean up if we can't get the lock immediately
            tokio::spawn(async move {
                watchdog.unregister(id).await;
            });
        }
    }
}

impl WatchDog {
    /// Creates a new WatchDog with the specified slow request threshold.
    pub fn new(slow_threshold: Duration) -> Self {
        Self {
            inner: Arc::new(WatchDogInner {
                requests: Mutex::new(HashMap::new()),
                next_id: Mutex::new(0),
                slow_threshold,
            }),
        }
    }

    /// Creates a new WatchDog with default settings.
    pub fn default_new() -> Self {
        Self::new(DEFAULT_SLOW_THRESHOLD)
    }

    /// Registers a new in-flight request and returns a guard.
    /// The request is automatically unregistered when the guard is dropped.
    pub async fn register(
        &self,
        method: &str,
        block_number: Option<u64>,
    ) -> RequestGuard {
        let mut next_id = self.inner.next_id.lock().await;
        let id = *next_id;
        *next_id += 1;
        drop(next_id);

        let entry = RequestEntry {
            method: method.to_string(),
            started_at: Instant::now(),
            block_number,
        };

        self.inner.requests.lock().await.insert(id, entry);

        RequestGuard {
            id,
            watchdog: self.clone(),
        }
    }

    /// Returns the number of currently in-flight requests.
    pub async fn inflight_count(&self) -> usize {
        self.inner.requests.lock().await.len()
    }

    /// Unregisters a request by ID.
    async fn unregister(&self, id: u64) {
        self.inner.requests.lock().await.remove(&id);
    }

    /// Checks for slow requests and logs warnings.
    /// Returns the number of slow requests found.
    pub async fn check_slow_requests(&self) -> usize {
        let requests = self.inner.requests.lock().await;
        let mut slow_count = 0;

        for (id, entry) in requests.iter() {
            let elapsed = entry.started_at.elapsed();
            if elapsed > self.inner.slow_threshold {
                slow_count += 1;
                warn!(
                    request_id = id,
                    method = %entry.method,
                    block_number = entry.block_number,
                    elapsed_secs = elapsed.as_secs(),
                    threshold_secs = self.inner.slow_threshold.as_secs(),
                    "Slow RPC request detected"
                );
            }
        }

        slow_count
    }

    /// Spawns a background task that periodically checks for slow requests.
    pub fn spawn_checker(self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(DEFAULT_CHECK_INTERVAL);
            loop {
                interval.tick().await;
                let inflight = self.inflight_count().await;
                if inflight > 0 {
                    let slow = self.check_slow_requests().await;
                    if slow > 0 {
                        warn!(
                            inflight_requests = inflight,
                            slow_requests = slow,
                            "WatchDog: slow requests detected"
                        );
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_thresholds() {
        assert_eq!(DEFAULT_CHECK_INTERVAL.as_secs(), 10);
        assert_eq!(DEFAULT_SLOW_THRESHOLD.as_secs(), 30);
    }

    #[tokio::test]
    async fn test_register_unregister() {
        let wd = WatchDog::default_new();
        assert_eq!(wd.inflight_count().await, 0);

        let guard = wd.register("test_method", Some(100)).await;
        assert_eq!(wd.inflight_count().await, 1);

        drop(guard);
        // Give the drop a moment to complete
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(wd.inflight_count().await, 0);
    }

    #[tokio::test]
    async fn test_check_slow_requests() {
        let wd = WatchDog::new(Duration::from_millis(50));
        let _guard = wd.register("slow_method", Some(200)).await;

        // Initially not slow
        let slow = wd.check_slow_requests().await;
        assert_eq!(slow, 0);

        // Wait for threshold
        tokio::time::sleep(Duration::from_millis(100)).await;
        let slow = wd.check_slow_requests().await;
        assert_eq!(slow, 1);
    }
}
