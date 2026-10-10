//! Worker/CLI configuration: TOML file + `VERSA_SCAN_`-prefixed env
//! overrides, loaded once at startup (no hot reload by design - worker
//! connections are deployment-static, same reasoning as versa-bot's
//! non-reloadable globals).

use std::path::{Path, PathBuf};

use serde::Deserialize;

const DEFAULT_FILE: &str = "versa-scan.toml";
const ENV_PREFIX: &str = "VERSA_SCAN";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusBackend {
    RabbitMq,
    Nats,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkerConfig {
    /// `sandbox` (scan pipeline) or `openbox` (update loop). Hostname-based
    /// detection in the composition root overrides nothing: explicit wins.
    pub role: Option<String>,
    /// Scanner slug (`clamd`, `defender`, `debug`). Required for sandbox.
    pub scanner: Option<String>,
    pub workspace_root: PathBuf,
    pub files_per_batch: usize,
    /// Grace period before an under-filled batch is flushed, milliseconds.
    pub batch_idle_timeout_ms: u64,
    pub scan_timeout_secs: u64,
    pub fetch_concurrency: usize,
    pub max_file_size: u64,
    pub scanner_unavailable_backoff_secs: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            role: None,
            scanner: None,
            workspace_root: PathBuf::from("vl_tasks"),
            files_per_batch: 10,
            batch_idle_timeout_ms: 250,
            scan_timeout_secs: 15 * 60,
            fetch_concurrency: 4,
            max_file_size: 500 * 1024 * 1024,
            scanner_unavailable_backoff_secs: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RabbitMqConfig {
    pub url: String,
    pub prefetch: u32,
}

impl Default for RabbitMqConfig {
    fn default() -> Self {
        Self { url: "amqp://guest:guest@localhost:5672/%2f".to_owned(), prefetch: 20 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NatsConfig {
    pub url: String,
    pub ack_wait_secs: u64,
    pub max_deliver: i32,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self { url: "nats://localhost:4222".to_owned(), ack_wait_secs: 300, max_deliver: 3 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BusConfig {
    pub backend: BusBackend,
    pub rabbitmq: Option<RabbitMqConfig>,
    pub nats: Option<NatsConfig>,
}

impl Default for BusConfig {
    fn default() -> Self {
        Self { backend: BusBackend::RabbitMq, rabbitmq: None, nats: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SelfUpdateConfig {
    pub enabled: bool,
    /// Base URL serving `manifest.txt` (`<semver>;<sha256>`) and archives.
    pub url: String,
    pub check_interval_secs: u64,
    /// Apply automatically; `false` = check + log only.
    pub auto_apply: bool,
}

impl Default for SelfUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "http://updates.local/vsd".to_owned(),
            check_interval_secs: 15 * 60,
            auto_apply: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `tracing` EnvFilter directive; falls back to `info` / `debug`.
    pub filter: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { filter: None }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Configuration {
    pub worker: WorkerConfig,
    pub bus: BusConfig,
    pub self_update: SelfUpdateConfig,
    pub logging: LoggingConfig,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            worker: WorkerConfig::default(),
            bus: BusConfig::default(),
            self_update: SelfUpdateConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file read error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config load error: {0}")]
    Load(String),
}

impl Configuration {
    /// Loads configuration from `path` (default: `versa-scan.toml` in the
    /// current directory) with `VERSA_SCAN_*` env overrides. A missing file
    /// is fine - defaults plus env are a valid deployment.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let file_path = path.unwrap_or_else(|| Path::new(DEFAULT_FILE));
        let mut builder = config::Config::builder();
        if file_path.exists() {
            builder = builder.add_source(config::File::from(file_path));
        } else if path.is_some() {
            return Err(ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("config file not found: {}", file_path.display()),
            )));
        }
        builder = builder.add_source(
            config::Environment::with_prefix(ENV_PREFIX).separator("__").try_parsing(true),
        );
        builder
            .build()
            .map_err(|e| ConfigError::Load(e.to_string()))?
            .try_deserialize()
            .map_err(|e| ConfigError::Load(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn defaults_are_valid() {
        let config = Configuration::default();
        assert_eq!(config.worker.files_per_batch, 10);
        assert_eq!(config.bus.backend, BusBackend::RabbitMq);
    }

    #[test]
    fn parses_toml_snippet() {
        let toml = "
[worker]
role = \"sandbox\"
scanner = \"clamd\"
files_per_batch = 7

[bus]
backend = \"nats\"

[bus.nats]
url = \"nats://broker:4222\"
";
        let config: Configuration = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(config.worker.role.as_deref(), Some("sandbox"));
        assert_eq!(config.worker.scanner.as_deref(), Some("clamd"));
        assert_eq!(config.worker.files_per_batch, 7);
        assert_eq!(config.bus.backend, BusBackend::Nats);
        assert_eq!(config.bus.nats.as_ref().unwrap().url, "nats://broker:4222");
    }
}
