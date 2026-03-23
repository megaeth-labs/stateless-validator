use std::{fmt, path::PathBuf};

use clap::{Args, ValueEnum};
use eyre::{Result, anyhow};
use rolling_file::{BasicRollingFileAppender, RollingConditionBasic};
use tracing::info;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer, fmt as tracing_fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

/// Log output format.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum LogFormat {
    /// Human-readable format for console output.
    #[default]
    Terminal,
    /// Structured JSON format (for loki/grafana ingestion).
    Json,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal => write!(f, "terminal"),
            Self::Json => write!(f, "json"),
        }
    }
}

/// ANSI color mode for console output.
///
/// Colored output is useful for visual inspection in a terminal, while
/// color-free output is better when redirecting stdout to a file or pipe.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ColorMode {
    /// Always emit ANSI color codes.
    Always,
    /// Detect TTY and emit colors only when connected to a terminal (default).
    #[default]
    Auto,
    /// Never emit ANSI color codes.
    Never,
}

impl ColorMode {
    /// Resolve to a boolean indicating whether ANSI colors should be used for stdout.
    fn use_color(self) -> bool {
        match self {
            Self::Always => true,
            Self::Auto => std::io::IsTerminal::is_terminal(&std::io::stdout()),
            Self::Never => false,
        }
    }
}

/// Logging configuration exposed as CLI arguments.
///
/// All flags can also be set via environment variables. When both are provided
/// the CLI flag takes precedence (standard `clap` behavior).
///
/// # Example
///
/// Embed in your binary's top-level CLI struct with `#[command(flatten)]`:
///
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Cli {
///     #[command(flatten)]
///     log: LogArgs,
/// }
/// ```
#[derive(Debug, Clone, Args)]
pub struct LogArgs {
    /// Console log filter directives (e.g. "info", "debug").
    #[arg(long = "log.stdout-filter", env = "STATELESS_LOG_STDOUT", default_value = "info")]
    pub log_stdout_filter: String,

    /// Console output format.
    #[arg(
        long = "log.stdout-format",
        env = "STATELESS_LOG_STDOUT_FORMAT",
        default_value = "terminal"
    )]
    pub log_stdout_format: LogFormat,

    /// Color mode for console output.
    #[arg(long = "log.color", env = "STATELESS_LOG_COLOR", default_value = "auto")]
    pub log_color: ColorMode,

    /// Directory for log files. File logging is disabled when unset.
    #[arg(long = "log.file-directory", env = "STATELESS_LOG_FILE_DIRECTORY")]
    pub log_file_directory: Option<PathBuf>,

    /// Log file name.
    #[arg(
        long = "log.file-name",
        env = "STATELESS_LOG_FILE_NAME",
        default_value = "stateless-validator.log"
    )]
    pub log_file_name: String,

    /// File log filter directives.
    #[arg(long = "log.file-filter", env = "STATELESS_LOG_FILE", default_value = "debug")]
    pub log_file_filter: String,

    /// File output format.
    #[arg(long = "log.file-format", env = "STATELESS_LOG_FILE_FORMAT", default_value = "terminal")]
    pub log_file_format: LogFormat,

    /// Maximum log file size in megabytes before rotation.
    #[arg(long = "log.file-max-size", env = "STATELESS_LOG_FILE_MAX_SIZE", default_value_t = 200)]
    pub log_file_max_size: u64,

    /// Maximum number of rotated log files to keep.
    #[arg(long = "log.file-max-files", env = "STATELESS_LOG_FILE_MAX_FILES", default_value_t = 5)]
    pub log_file_max_files: usize,
}

/// Build an [`EnvFilter`] from the given base directive, applying it to
/// workspace crates while defaulting everything else to `warn`.
fn build_env_filter(filter: &str) -> Result<EnvFilter> {
    Ok(EnvFilter::new("warn")
        .add_directive(format!("stateless_core={filter}").parse()?)
        .add_directive(format!("stateless_validator={filter}").parse()?)
        .add_directive(format!("stateless_common={filter}").parse()?)
        .add_directive(format!("debug_trace_server={filter}").parse()?))
}

/// Create a size-based rolling file appender wrapped in a non-blocking writer.
///
/// Returns the non-blocking writer and the [`WorkerGuard`] that **must** be held
/// alive for the lifetime of the program to guarantee log flushing on exit.
fn build_file_writer(
    dir: &PathBuf,
    file_name: &str,
    max_size_mb: u64,
    max_files: usize,
) -> Result<(tracing_appender::non_blocking::NonBlocking, WorkerGuard)> {
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow!("Failed to create log directory {}: {e}", dir.display()))?;

    let file_path = dir.join(file_name);
    let condition = RollingConditionBasic::new().max_size(max_size_mb * 1024 * 1024);
    let appender = BasicRollingFileAppender::new(file_path, condition, max_files)
        .map_err(|e| anyhow!("Failed to create rolling file appender: {e}"))?;

    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
    Ok((non_blocking, guard))
}

/// Migrate legacy `STATELESS_VALIDATOR_LOG_*` env vars to the new `STATELESS_LOG_*` names.
/// Only copies when the new var is not already set, so the new name always takes precedence.
///
/// Must be called **before** `clap::Parser::parse()` so that clap sees the migrated values.
///
/// # Safety
///
/// This mutates process-global environment state. Call it early in `main()` before
/// spawning any threads or starting async runtimes.
pub fn migrate_legacy_env_vars() {
    const LEGACY_MAP: &[(&str, &str)] = &[
        ("STATELESS_VALIDATOR_LOG_STDOUT", "STATELESS_LOG_STDOUT"),
        ("STATELESS_VALIDATOR_LOG_FILE", "STATELESS_LOG_FILE"),
        ("STATELESS_VALIDATOR_LOG_FILE_DIRECTORY", "STATELESS_LOG_FILE_DIRECTORY"),
    ];
    for &(old, new) in LEGACY_MAP {
        if std::env::var(new).is_err() &&
            let Ok(val) = std::env::var(old)
        {
            // SAFETY: called before any multithreaded runtime is started.
            unsafe { std::env::set_var(new, val) };
        }
    }
}

impl LogArgs {
    /// Initialize the global tracing subscriber based on the current configuration.
    ///
    /// Returns an `Option<WorkerGuard>` that **must** be held alive in `main()` —
    /// dropping the guard flushes and closes the file writer. When file logging is
    /// disabled the returned value is `None`.
    pub fn init_tracing(&self) -> Result<Option<WorkerGuard>> {
        let use_color = self.log_color.use_color();

        // Force ANSI off when using JSON on stdout — color codes break JSON parsing.
        let stdout_ansi = match self.log_stdout_format {
            LogFormat::Json => false,
            LogFormat::Terminal => use_color,
        };

        let stdout_filter = build_env_filter(&self.log_stdout_filter)?;

        let stdout_layer: Box<dyn Layer<_> + Send + Sync> = match self.log_stdout_format {
            LogFormat::Terminal => tracing_fmt::layer()
                .with_ansi(stdout_ansi)
                .with_writer(std::io::stdout)
                .with_filter(stdout_filter)
                .boxed(),
            LogFormat::Json => tracing_fmt::layer()
                .json()
                .with_ansi(false)
                .with_writer(std::io::stdout)
                .with_filter(stdout_filter)
                .boxed(),
        };

        // --- optional file layer ---
        let (file_layer, guard) = if let Some(ref dir) = self.log_file_directory {
            let (non_blocking, guard) = build_file_writer(
                dir,
                &self.log_file_name,
                self.log_file_max_size,
                self.log_file_max_files,
            )?;
            let file_filter = build_env_filter(&self.log_file_filter)?;

            let layer: Box<dyn Layer<_> + Send + Sync> = match self.log_file_format {
                LogFormat::Terminal => tracing_fmt::layer()
                    .with_ansi(false)
                    .with_writer(non_blocking)
                    .with_filter(file_filter)
                    .boxed(),
                LogFormat::Json => tracing_fmt::layer()
                    .json()
                    .with_ansi(false)
                    .with_writer(non_blocking)
                    .with_filter(file_filter)
                    .boxed(),
            };

            (Some(layer), Some(guard))
        } else {
            (None, None)
        };

        tracing_subscriber::registry().with(stdout_layer).with(file_layer).init();

        match &self.log_file_directory {
            Some(dir) => info!(
                stdout_filter = %self.log_stdout_filter,
                stdout_format = %self.log_stdout_format,
                file_filter = %self.log_file_filter,
                file_format = %self.log_file_format,
                file_directory = %dir.display(),
                "Logging initialized",
            ),
            None => info!(
                stdout_filter = %self.log_stdout_filter,
                stdout_format = %self.log_stdout_format,
                "Logging initialized (file logging disabled)",
            ),
        }

        Ok(guard)
    }
}
