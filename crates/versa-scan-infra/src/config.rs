//! Worker/CLI configuration: TOML file + `VERSA_SCAN_`-prefixed env
//! overrides, loaded once at startup (no hot reload by design - worker
//! connections are deployment-static, same reasoning as versa-bot's
//! non-reloadable globals).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use versa_scan_core::models::worker::{WorkerInfo, WorkerRole};
use versa_scan_core::services::OrchestratorSettings;

const DEFAULT_FILE: &str = "versa-scan.toml";
const ENV_PREFIX: &str = "VERSA_SCAN";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum BusBackend {
    #[serde(rename = "rabbitmq", alias = "rabbit_mq")]
    RabbitMq,
    #[serde(rename = "nats")]
    Nats,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkerConfig {
    /// `sandbox` (scan pipeline) or `openbox` (update loop). Hostname-based
    /// detection in the composition root overrides nothing: explicit wins.
    pub role: Option<String>,
    /// Scanner slug (`clamd`, `yara-x`, `hash-blocklist`, `defender`,
    /// `debug`). Required for sandbox.
    pub scanner: Option<String>,
    pub workspace_root: PathBuf,
    pub files_per_batch: usize,
    /// Grace period before an under-filled batch is flushed, milliseconds.
    pub batch_idle_timeout_ms: u64,
    pub scan_timeout_secs: u64,
    pub fetch_concurrency: usize,
    /// Whole-request download timeout, seconds.
    pub fetch_timeout_secs: u64,
    pub max_file_size: u64,
    pub scanner_unavailable_backoff_secs: u64,
    /// Attempt cap for scanner-unavailable batches before they get error
    /// reports. Higher than the fetch/publish cap (3): an AV daemon restart
    /// is tolerated longer, but nothing loops forever.
    pub scanner_max_attempts: u32,
    /// How long the worker waits for the pipeline's final flush after the
    /// shutdown signal, seconds. The final flush requeues instead of
    /// scanning new batches, so this stays small.
    pub shutdown_grace_secs: u64,
    /// Fetch-host allowlist (`host` or `host:port` suffixes). Empty = allow
    /// any URL the bus carries; set it to the artifact server's address to
    /// stop workers from being pointed at arbitrary hosts.
    pub fetch_allowed_hosts: Vec<String>,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            role: None,
            scanner: None,
            workspace_root: PathBuf::from("workspaces"),
            files_per_batch: 10,
            batch_idle_timeout_ms: 250,
            scan_timeout_secs: 15 * 60,
            fetch_concurrency: 4,
            fetch_timeout_secs: 300,
            max_file_size: 500 * 1024 * 1024,
            scanner_unavailable_backoff_secs: 10,
            scanner_max_attempts: 10,
            shutdown_grace_secs: 10,
            fetch_allowed_hosts: Vec::new(),
        }
    }
}

/// `[clamd]` - clamd daemon endpoint for the `clamd` scanner.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClamdConfig {
    pub address: String,
    /// Parallel INSTREAM connections per batch (clamd multiplexes fine).
    pub concurrent_scans: usize,
}

impl Default for ClamdConfig {
    fn default() -> Self {
        Self { address: "localhost:3310".to_owned(), concurrent_scans: 4 }
    }
}

/// `[yara_x]` - rule source for the `yara-x` scanner.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct YaraXConfig {
    /// Rule file, or directory scanned recursively for `*.yar` / `*.yara`.
    pub rules_path: PathBuf,
    /// Per-file YARA scan timeout, seconds (the engine aborts the scan
    /// internally; this stays under the worker's `scan_timeout_secs`).
    pub timeout_secs: u64,
}

impl Default for YaraXConfig {
    fn default() -> Self {
        Self { rules_path: PathBuf::from("rules"), timeout_secs: 120 }
    }
}

/// `[hash_blocklist]` - sha256 feeds for the `hash-blocklist` scanner.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HashBlocklistConfig {
    /// Feed files: one sha256 hex per line, `#` comments, optional free-form
    /// label after the hash. Missing entries are skipped with a warning.
    pub feeds: Vec<PathBuf>,
}

impl Default for HashBlocklistConfig {
    fn default() -> Self {
        Self { feeds: Vec::new() }
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
        // ack_wait must cover a whole fetch+scan cycle (the redelivery that
        // a too-short wait causes hits the duplicate guard and delays the
        // sample). Default = comfortably above the default scan timeout.
        Self { url: "nats://localhost:4222".to_owned(), ack_wait_secs: 30 * 60, max_deliver: 3 }
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

/// `[artifact]` - the sample store's HTTP exposure. `token` protects it:
/// when set, vscli appends the token to every sample URL it publishes and
/// the embedded artifact server rejects requests without it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactConfig {
    pub token: String,
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self { token: String::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Configuration {
    pub worker: WorkerConfig,
    pub bus: BusConfig,
    pub self_update: SelfUpdateConfig,
    pub logging: LoggingConfig,
    /// clamd scanner endpoint; required when `worker.scanner = "clamd"`.
    pub clamd: Option<ClamdConfig>,
    /// Rule source; required when `worker.scanner = "yara-x"`.
    pub yara_x: Option<YaraXConfig>,
    /// Feed list; required when `worker.scanner = "hash-blocklist"`.
    pub hash_blocklist: Option<HashBlocklistConfig>,
    /// Sample-store HTTP exposure (token auth for the artifact server).
    pub artifact: Option<ArtifactConfig>,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            worker: WorkerConfig::default(),
            bus: BusConfig::default(),
            self_update: SelfUpdateConfig::default(),
            logging: LoggingConfig::default(),
            clamd: None,
            yara_x: None,
            hash_blocklist: None,
            artifact: None,
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
            config::Environment::with_prefix(ENV_PREFIX)
                // `VERSA_SCAN_<SECTION>__<KEY>`: the prefix consumes one `_`,
                // `__` separates nesting levels. Without this the crate
                // expects `VERSA_SCAN__WORKER__SCANNER` (silent no-override).
                .prefix_separator("_")
                .separator("__")
                .try_parsing(true),
        );
        builder
            .build()
            .map_err(|e| ConfigError::Load(e.to_string()))?
            .try_deserialize()
            .map_err(|e| ConfigError::Load(e.to_string()))
    }

    // ------------------------------------------------------------------
    // Mapping helpers: configuration -> core values. The composition roots
    // call these; core never sees the config crate.
    // ------------------------------------------------------------------

    /// Resolves the deployment role: explicit config wins, otherwise the
    /// hostname decides (`<scanner>.openbox...` / `<scanner>.sandbox...`).
    pub fn worker_role(&self, hostname: &str) -> Result<WorkerRole, ConfigError> {
        match self.worker.role.as_deref() {
            Some(role) => role.parse().map_err(|e: versa_scan_core::models::UnknownRole| {
                ConfigError::Load(format!("worker.role: {e}"))
            }),
            None if hostname.contains("openbox") => Ok(WorkerRole::Openbox),
            None if hostname.contains("sandbox") => Ok(WorkerRole::Sandbox),
            None => Err(ConfigError::Load(
                "worker.role not configured and hostname has no sandbox/openbox marker".to_owned(),
            )),
        }
    }

    /// Builds the worker identity stamped into reports.
    pub fn worker_info(&self, role: WorkerRole) -> WorkerInfo {
        WorkerInfo {
            hostname: hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
            os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            role,
        }
    }

    /// Maps worker knobs onto the orchestrator's tuning struct.
    pub fn orchestrator_settings(&self) -> OrchestratorSettings {
        let worker = &self.worker;
        OrchestratorSettings {
            files_per_batch: worker.files_per_batch.max(1),
            batch_idle_timeout: Duration::from_millis(worker.batch_idle_timeout_ms),
            scan_timeout: Duration::from_secs(worker.scan_timeout_secs),
            fetch_concurrency: worker.fetch_concurrency.max(1),
            scanner_backoff: Duration::from_secs(worker.scanner_unavailable_backoff_secs),
            scanner_max_attempts: worker.scanner_max_attempts.clamp(1, u8::MAX as u32) as u8,
        }
    }

    /// clamd endpoint from `[clamd]` (defaults apply when absent).
    pub fn clamd_address(&self) -> String {
        self.clamd.clone().unwrap_or_default().address
    }

    /// Parallel clamd INSTREAM connections (at least 1).
    pub fn clamd_concurrent_scans(&self) -> usize {
        self.clamd.clone().unwrap_or_default().concurrent_scans.max(1)
    }

    /// YARA rule source path from `[yara_x]` (defaults apply when absent).
    pub fn yara_x_rules_path(&self) -> PathBuf {
        self.yara_x.clone().unwrap_or_default().rules_path
    }

    /// Per-file YARA scan timeout from `[yara_x]`.
    pub fn yara_x_timeout(&self) -> Duration {
        Duration::from_secs(self.yara_x.clone().unwrap_or_default().timeout_secs)
    }

    /// sha256 feed paths from `[hash_blocklist]`.
    pub fn hash_blocklist_feeds(&self) -> Vec<std::path::PathBuf> {
        self.hash_blocklist.clone().unwrap_or_default().feeds
    }

    /// Artifact-server bearer token (empty = auth disabled).
    pub fn artifact_token(&self) -> String {
        self.artifact.clone().unwrap_or_default().token
    }

    /// Fetch-host allowlist (empty = allow all).
    pub fn fetch_allowed_hosts(&self) -> Vec<String> {
        self.worker.fetch_allowed_hosts.clone()
    }

    /// Shutdown grace for the pipeline's final flush, seconds.
    pub fn shutdown_grace_secs(&self) -> u64 {
        self.worker.shutdown_grace_secs.max(1)
    }

    /// Cross-field consistency checks the composition root runs at boot:
    /// a NATS `ack_wait` shorter than one fetch+scan cycle makes the broker
    /// redeliver live batches, and the redelivered twins pile onto the
    /// duplicate guard. Refuse to boot on that mismatch.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.bus.backend == BusBackend::Nats {
            let Some(nats) = &self.bus.nats else {
                return Err(ConfigError::Load(
                    "bus.backend = nats requires a [bus.nats] section".to_owned(),
                ));
            };
            let budget = self.worker.scan_timeout_secs + self.worker.fetch_timeout_secs;
            if nats.ack_wait_secs <= budget {
                return Err(ConfigError::Load(format!(
                    "bus.nats.ack_wait_secs ({}) must exceed worker.scan_timeout_secs + \
                     worker.fetch_timeout_secs ({budget}) or live batches get redelivered mid-scan",
                    nats.ack_wait_secs
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn env_overrides_apply() {
        // SAFETY: single-threaded test binary assumptions aside, this key is
        // unique to this test; no other test reads it.
        unsafe {
            std::env::set_var("VERSA_SCAN_YARA_X__RULES_PATH", "from-env/rules.yar");
            std::env::set_var("VERSA_SCAN_WORKER__FILES_PER_BATCH", "3");
        }
        let config = Configuration::load(None).unwrap();
        assert_eq!(config.yara_x_rules_path(), PathBuf::from("from-env/rules.yar"));
        assert_eq!(config.worker.files_per_batch, 3);
    }

    #[test]
    fn defaults_are_valid() {
        let config = Configuration::default();
        assert_eq!(config.worker.files_per_batch, 10);
        assert_eq!(config.bus.backend, BusBackend::RabbitMq);
    }

    #[test]
    fn backend_spellings() {
        for backend in ["rabbitmq", "rabbit_mq", "nats"] {
            let toml = format!("[bus]\nbackend = \"{backend}\"");
            let config: Configuration = config::Config::builder()
                .add_source(config::File::from_str(&toml, config::FileFormat::Toml))
                .build()
                .unwrap()
                .try_deserialize()
                .unwrap_or_else(|e| panic!("backend {backend:?} must parse: {e}"));
            let expected = if backend == "nats" { BusBackend::Nats } else { BusBackend::RabbitMq };
            assert_eq!(config.bus.backend, expected);
        }
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

[clamd]
address = \"clamd.internal:3310\"
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
        assert_eq!(config.clamd_address(), "clamd.internal:3310");
    }

    #[test]
    fn parses_scanner_sections() {
        let toml = "
[yara_x]
rules_path = \"signatures/demo.yar\"
timeout_secs = 30

[hash_blocklist]
feeds = [\"feeds/a.sha256\", \"feeds/b.sha256\"]

[clamd]
address = \"clamd.internal:3310\"
concurrent_scans = 8
";
        let config: Configuration = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(config.yara_x_rules_path(), std::path::PathBuf::from("signatures/demo.yar"));
        assert_eq!(config.yara_x_timeout(), Duration::from_secs(30));
        assert_eq!(config.hash_blocklist_feeds().len(), 2);
        assert_eq!(config.clamd_concurrent_scans(), 8);
    }

    #[test]
    fn scanner_section_defaults_apply_when_absent() {
        let config = Configuration::default();
        assert_eq!(config.yara_x_rules_path(), std::path::PathBuf::from("rules"));
        assert_eq!(config.yara_x_timeout(), Duration::from_secs(120));
        assert!(config.hash_blocklist_feeds().is_empty());
        assert_eq!(config.clamd_concurrent_scans(), 4);
        // Zero concurrent scans is clamped to 1, never a stall.
        let toml = "[clamd]\nconcurrent_scans = 0";
        let config: Configuration = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(config.clamd_concurrent_scans(), 1);
    }

    #[test]
    fn role_detection_explicit_wins_over_hostname() {
        let config = Configuration::default();
        let mut explicit = config.clone();
        explicit.worker.role = Some("openbox".to_owned());
        assert_eq!(explicit.worker_role("clamd.sandbox.example").unwrap(), WorkerRole::Openbox);
        assert_eq!(config.worker_role("clamd.sandbox.example").unwrap(), WorkerRole::Sandbox);
        assert_eq!(config.worker_role("kav.openbox.example").unwrap(), WorkerRole::Openbox);
        assert!(config.worker_role("plain-host").is_err());
    }

    #[test]
    fn orchestrator_settings_mapping() {
        let mut config = Configuration::default();
        config.worker.files_per_batch = 0; // must clamp to 1
        let settings = config.orchestrator_settings();
        assert_eq!(settings.files_per_batch, 1);
        assert_eq!(settings.batch_idle_timeout, Duration::from_millis(250));
        assert_eq!(settings.scan_timeout, Duration::from_secs(900));
    }
}

#[cfg(test)]
mod review_tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    #[test]
    fn new_worker_fields_default_and_parse() {
        let config = Configuration::default();
        assert_eq!(config.worker.scanner_max_attempts, 10);
        assert_eq!(config.worker.shutdown_grace_secs, 10);
        assert!(config.fetch_allowed_hosts().is_empty());
        assert_eq!(config.artifact_token(), "");

        let toml = r#"
[worker]
scanner_max_attempts = 5
shutdown_grace_secs = 2
fetch_allowed_hosts = ["art.local:8080", "art.local"]

[artifact]
token = "s3cret"
"#;
        let config: Configuration = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(config.worker.scanner_max_attempts, 5);
        assert_eq!(config.shutdown_grace_secs(), 2);
        assert_eq!(config.fetch_allowed_hosts(), vec!["art.local:8080", "art.local"]);
        assert_eq!(config.artifact_token(), "s3cret");
    }

    #[test]
    fn nats_ack_wait_must_cover_a_scan_cycle() {
        let mut config = Configuration::default();
        config.bus.backend = BusBackend::Nats;
        config.bus.nats = Some(NatsConfig {
            url: "nats://localhost:4222".to_owned(),
            ack_wait_secs: 1800,
            max_deliver: 3,
        });
        assert!(config.validate().is_ok(), "default ack_wait covers the default scan budget");

        config.bus.nats.as_mut().unwrap().ack_wait_secs = 30;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("ack_wait_secs"), "explains the coupling: {err}");
    }

    #[test]
    fn validation_is_nats_only() {
        // RabbitMQ has no ack_wait; the check must not fire.
        let config = Configuration::default();
        assert!(config.validate().is_ok());
    }
}
