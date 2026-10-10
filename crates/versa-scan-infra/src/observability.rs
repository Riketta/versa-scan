//! Observability: `tracing` IS the observability port (facade, no
//! telemetry port) - same exception category as versa-bot.

use tracing_subscriber::EnvFilter;

/// Installs the stdout fmt layer. `debug` lowers the default filter;
/// `RUST_LOG` always wins.
pub fn init(debug: bool) {
    let default = if debug { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
