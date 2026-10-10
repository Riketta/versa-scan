//! Scanner registry: the composition-root table mapping scanner slugs to
//! adapters (the Rust replacement for the C# reflection-based discovery).

use std::sync::Arc;

use anyhow::{Context as _, bail};
use versa_scan_core::ports::driven::scanner::ScannerPort;
use versa_scan_infra::config::Configuration;
use versa_scan_infra::outbound_adapters::scanners::{ClamdScanner, DebugScanner, DefenderScanner};

/// Every scanner slug this build knows about (for `--detect` output).
pub const KNOWN: &[&str] = &["clamd", "defender", "debug"];

/// Builds the configured scanner adapter.
pub fn build(config: &Configuration) -> anyhow::Result<Arc<dyn ScannerPort>> {
    let slug = config
        .worker
        .scanner
        .as_deref()
        .filter(|s| !s.is_empty())
        .context("worker.scanner must be set in the sandbox role")?;
    match slug {
        "clamd" => Ok(Arc::new(ClamdScanner::new(config.clamd_address()))),
        "defender" => Ok(Arc::new(DefenderScanner::new())),
        "debug" => Ok(Arc::new(DebugScanner::new())),
        other => {
            bail!("unknown scanner {other:?} (known: {})", KNOWN.join(", "))
        }
    }
}

/// Probes every known scanner (`vsd --detect`): slug + installed or reason.
pub async fn detect(config: &Configuration) {
    for slug in KNOWN {
        let result = match *slug {
            "clamd" => ClamdScanner::new(config.clamd_address()).is_installed().await,
            "defender" => DefenderScanner::new().is_installed().await,
            "debug" => DebugScanner::new().is_installed().await,
            _ => continue,
        };
        match result {
            Ok(true) => println!("{slug}: installed"),
            Ok(false) => println!("{slug}: NOT installed"),
            Err(err) => println!("{slug}: error ({err})"),
        }
    }
}
