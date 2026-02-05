//! Logging configuration for debug-trace-server.
//!
//! Provides a flexible logging setup with support for:
//! - Console output with configurable format and color
//! - File output with automatic rolling and cleanup
//! - Multiple format options (console/json)
//! - Configurable filters per layer

use std::path::PathBuf;

use clap::Args;
use eyre::Result;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    EnvFilter, Layer, fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// Default log directory name.
pub const DEFAULT_LOG_DIRECTORY: &str = "logs";

/// Default maximum number of log files to keep.
pub const DEFAULT_LOG_FILE_MAX_FILES: usize = 10;

/// Color mode for console output.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ColorMode {
    /// Automatic color detection based on terminal capabilities.
    #[default]
    Auto,
    /// Always use colors.
    Always,
    /// Never use colors.
    Never,
}

/// Log format for output layers.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum LogFormat {
    /// Human-readable format with timestamps and colors.
    #[default]
    Console,
    /// JSON format for structured logging.
    Json,
}

/// Command-line arguments for logging configuration.
#[derive(Args, Debug, Clone)]
pub struct LogArgs {
    /// Log filter string (e.g., "debug_trace_server=debug,validator_core=info").
    /// Defaults to "debug_trace_server=info" if not specified.
    #[clap(long = "log.filter", env = "DEBUG_TRACE_SERVER_LOG_FILTER")]
    pub filter: Option<String>,

    /// Console output format (console or json).
    #[clap(
        long = "log.console.format",
        env = "DEBUG_TRACE_SERVER_LOG_CONSOLE_FORMAT",
        default_value = "console"
    )]
    pub console_format: LogFormat,

    /// Console color mode (auto, always, or never).
    #[clap(
        long = "log.console.color",
        env = "DEBUG_TRACE_SERVER_LOG_CONSOLE_COLOR",
        default_value = "auto"
    )]
    pub console_color: ColorMode,

    /// Enable file logging.
    #[clap(long = "log.file.enable", env = "DEBUG_TRACE_SERVER_LOG_FILE_ENABLE")]
    pub file_enable: bool,

    /// Directory for log files.
    #[clap(
        long = "log.file.directory",
        env = "DEBUG_TRACE_SERVER_LOG_FILE_DIRECTORY",
        default_value = DEFAULT_LOG_DIRECTORY
    )]
    pub file_directory: PathBuf,

    /// File output format (console or json).
    #[clap(
        long = "log.file.format",
        env = "DEBUG_TRACE_SERVER_LOG_FILE_FORMAT",
        default_value = "json"
    )]
    pub file_format: LogFormat,

    /// Maximum number of log files to keep (older files are deleted).
    #[clap(
        long = "log.file.max-files",
        env = "DEBUG_TRACE_SERVER_LOG_FILE_MAX_FILES",
        default_value_t = DEFAULT_LOG_FILE_MAX_FILES
    )]
    pub file_max_files: usize,

    /// Log file filter (can be different from console filter).
    /// Defaults to the main filter if not specified.
    #[clap(long = "log.file.filter", env = "DEBUG_TRACE_SERVER_LOG_FILE_FILTER")]
    pub file_filter: Option<String>,
}

impl Default for LogArgs {
    fn default() -> Self {
        Self {
            filter: None,
            console_format: LogFormat::Console,
            console_color: ColorMode::Auto,
            file_enable: false,
            file_directory: PathBuf::from(DEFAULT_LOG_DIRECTORY),
            file_format: LogFormat::Json,
            file_max_files: DEFAULT_LOG_FILE_MAX_FILES,
            file_filter: None,
        }
    }
}

impl LogArgs {
    /// Returns the effective console filter.
    pub fn console_filter(&self) -> EnvFilter {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::try_new(
                self.filter.as_deref().unwrap_or("debug_trace_server=info,validator_core=info"),
            )
            .expect("Invalid filter string")
        })
    }

    /// Returns the effective file filter.
    pub fn file_filter(&self) -> EnvFilter {
        let filter_str =
            self.file_filter.as_deref().or(self.filter.as_deref()).unwrap_or("info");
        EnvFilter::try_new(filter_str).expect("Invalid file filter string")
    }

    /// Returns whether ANSI colors should be used based on the color mode.
    pub fn use_ansi(&self) -> bool {
        match self.console_color {
            ColorMode::Auto => atty::is(atty::Stream::Stdout),
            ColorMode::Always => true,
            ColorMode::Never => false,
        }
    }
}

/// Initializes the logging subsystem based on the provided configuration.
///
/// Sets up:
/// - Console layer with configurable format and colors
/// - Optional file layer with daily rotation and configurable format
///
/// # Arguments
/// * `args` - Logging configuration arguments
///
/// # Returns
/// * `Ok(())` - Logging successfully initialized
/// * `Err` - If initialization fails (e.g., cannot create log directory)
pub fn init_logging(args: &LogArgs) -> Result<()> {
    let registry = tracing_subscriber::registry();

    // Build console layer
    let console_layer = match args.console_format {
        LogFormat::Console => {
            let layer = fmt::layer()
                .with_ansi(args.use_ansi())
                .with_target(true)
                .with_level(true)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false);
            layer.with_filter(args.console_filter()).boxed()
        }
        LogFormat::Json => {
            let layer = fmt::layer()
                .json()
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false);
            layer.with_filter(args.console_filter()).boxed()
        }
    };

    // Optionally build file layer
    if args.file_enable {
        std::fs::create_dir_all(&args.file_directory)?;

        let file_appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("debug-trace-server")
            .filename_suffix("log")
            .max_log_files(args.file_max_files)
            .build(&args.file_directory)?;

        let file_layer = match args.file_format {
            LogFormat::Console => {
                let layer = fmt::layer()
                    .with_writer(file_appender)
                    .with_ansi(false)
                    .with_target(true)
                    .with_level(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true);
                layer.with_filter(args.file_filter()).boxed()
            }
            LogFormat::Json => {
                let layer = fmt::layer()
                    .json()
                    .with_writer(file_appender)
                    .with_ansi(false)
                    .with_target(true)
                    .with_level(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true);
                layer.with_filter(args.file_filter()).boxed()
            }
        };

        registry.with(console_layer).with(file_layer).init();
    } else {
        registry.with(console_layer).init();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_log_args() {
        let args = LogArgs::default();
        assert!(args.filter.is_none());
        assert!(matches!(args.console_format, LogFormat::Console));
        assert!(matches!(args.console_color, ColorMode::Auto));
        assert!(!args.file_enable);
        assert_eq!(args.file_max_files, DEFAULT_LOG_FILE_MAX_FILES);
    }

    #[test]
    fn test_console_filter_default() {
        let args = LogArgs::default();
        let filter = args.console_filter();
        // Should not panic
        drop(filter);
    }

    #[test]
    fn test_color_mode_variants() {
        assert!(matches!(ColorMode::Auto, ColorMode::Auto));
        assert!(matches!(ColorMode::Always, ColorMode::Always));
        assert!(matches!(ColorMode::Never, ColorMode::Never));
    }

    #[test]
    fn test_log_format_variants() {
        assert!(matches!(LogFormat::Console, LogFormat::Console));
        assert!(matches!(LogFormat::Json, LogFormat::Json));
    }

    #[test]
    fn test_use_ansi_always() {
        let mut args = LogArgs::default();
        args.console_color = ColorMode::Always;
        assert!(args.use_ansi());
    }

    #[test]
    fn test_use_ansi_never() {
        let mut args = LogArgs::default();
        args.console_color = ColorMode::Never;
        assert!(!args.use_ansi());
    }
}
