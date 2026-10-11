//! Scanner registry: the composition-root table mapping scanner slugs to
//! adapters (the Rust replacement for the C# reflection-based discovery).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use versa_scan_core::ports::driven::scanner::ScannerPort;
use versa_scan_infra::config::Configuration;
use versa_scan_infra::outbound_adapters::scanners::{
    ClamdScanner, DebugScanner, DefenderScanner, HashBlocklistScanner, YaraXScanner,
};

/// Every scanner slug this build knows about (for `--detect` output).
pub const KNOWN: &[&str] = versa_scan_core::models::KNOWN_SCANNERS;

/// Builds the configured scanner adapter.
pub fn build(config: &Configuration) -> anyhow::Result<Arc<dyn ScannerPort>> {
    let slug = config
        .worker
        .scanner
        .as_deref()
        .filter(|s| !s.is_empty())
        .context("worker.scanner must be set in the sandbox role")?;
    match slug {
        "clamd" => {
            Ok(Arc::new(ClamdScanner::new(config.clamd_address(), config.clamd_concurrent_scans())))
        }
        "defender" => {
            Ok(Arc::new(DefenderScanner::new(Duration::from_secs(config.worker.scan_timeout_secs))))
        }
        "debug" => Ok(Arc::new(DebugScanner::new())),
        "hash-blocklist" => Ok(Arc::new(HashBlocklistScanner::new(config.hash_blocklist_feeds()))),
        "yara-x" => {
            // Per-file engine timeout must stay under the orchestrator's
            // batch timeout so the engine aborts (error reports) before
            // the orchestrator would requeue.
            let timeout = config.yara_x_timeout().min(config.orchestrator_settings().scan_timeout);
            Ok(Arc::new(YaraXScanner::new(config.yara_x_rules_path(), timeout)))
        }
        other => {
            bail!("unknown scanner {other:?} (known: {})", KNOWN.join(", "))
        }
    }
}

/// Probes every known scanner (`vsd --detect`): slug + installed or reason.
pub async fn detect(config: &Configuration) {
    for slug in KNOWN {
        let result = match *slug {
            "clamd" => {
                ClamdScanner::new(config.clamd_address(), config.clamd_concurrent_scans())
                    .is_installed()
                    .await
            }
            "defender" => {
                DefenderScanner::new(Duration::from_secs(config.worker.scan_timeout_secs))
                    .is_installed()
                    .await
            }
            "debug" => DebugScanner::new().is_installed().await,
            "hash-blocklist" => {
                HashBlocklistScanner::new(config.hash_blocklist_feeds()).is_installed().await
            }
            "yara-x" => {
                let timeout =
                    config.yara_x_timeout().min(config.orchestrator_settings().scan_timeout);
                YaraXScanner::new(config.yara_x_rules_path(), timeout).is_installed().await
            }
            _ => continue,
        };
        match result {
            Ok(true) => println!("{slug}: installed"),
            Ok(false) => println!("{slug}: NOT installed"),
            Err(err) => println!("{slug}: error ({err})"),
        }
    }
}
