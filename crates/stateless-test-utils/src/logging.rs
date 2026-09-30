//! Shared test-logging setup.

use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};

/// Log `debug_target` at debug level (everything else at warn), scoped to the returned guard so
/// parallel tests don't fight over a global subscriber. Output goes through libtest's capture,
/// so it shows only for a failing test, or under `--nocapture`.
pub fn init_test_logging(debug_target: &str) -> tracing::subscriber::DefaultGuard {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("warn").add_directive(
            format!("{debug_target}=debug").parse().expect("valid tracing directive"),
        ))
        .with_test_writer()
        .set_default()
}
