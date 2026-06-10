//! Shared test-logging setup.

use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};

/// Print `debug_target` logs at debug level (everything else at warn), scoped to the returned
/// guard so parallel tests don't fight over a global subscriber.
pub fn init_test_logging(debug_target: &str) -> tracing::subscriber::DefaultGuard {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("warn").add_directive(
            format!("{debug_target}=debug").parse().expect("valid tracing directive"),
        ))
        .set_default()
}
