//! Worker self-update adapter.
//!
//! Contract: an HTTP base URL serves `manifest.txt` (`<semver>;<sha256 of
//! zip>`) and `<semver>.zip` archives containing the new binaries. `check`
//! compares the manifest version against the running version; `apply`
//! downloads, hash-verifies, extracts to a staging directory next to the
//! current binary, and swaps it in:
//! - Windows: rename the running exe to `<exe>.old` (works while running),
//!   move the new exe into place; `.old` removal is best-effort (it stays
//!   locked until the process exits and is cleaned up on a later start).
//! - POSIX: replace the file and restore executable permissions.
//!
//! The caller is expected to exit after a successful `apply` so the
//! service manager / task scheduler restarts the new version.

pub mod manifest;
pub mod swap;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use versa_scan_core::ports::driven::self_update::{SelfUpdatePort, Update, UpdateError};

use crate::config::SelfUpdateConfig;

pub struct SelfUpdateAdapter {
    base_url: String,
    client: reqwest::Client,
    current_exe: PathBuf,
    staging_parent: PathBuf,
    current_version: String,
}

impl SelfUpdateAdapter {
    /// Production constructor: uses the running executable and version.
    pub fn new(config: &SelfUpdateConfig) -> Result<Arc<Self>, String> {
        let current_exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let staging_parent = current_exe.parent().expect("exe has a parent").to_path_buf();
        Ok(Arc::new(Self::with_paths(
            &config.url,
            current_exe,
            staging_parent,
            env!("CARGO_PKG_VERSION"),
        )))
    }

    /// Test/diagnostic constructor with explicit paths and version.
    pub fn with_paths(
        base_url: &str,
        current_exe: PathBuf,
        staging_parent: PathBuf,
        current_version: &str,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .connect_timeout(Duration::from_secs(30))
            .user_agent(concat!("versa-scan/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("static client configuration is valid");
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
            current_exe,
            staging_parent,
            current_version: current_version.to_owned(),
        }
    }
}

#[async_trait]
impl SelfUpdatePort for SelfUpdateAdapter {
    async fn check(&self) -> Result<Option<Update>, UpdateError> {
        let manifest_url = format!("{}/manifest.txt", self.base_url);
        let response = self
            .client
            .get(&manifest_url)
            .send()
            .await
            .map_err(|e| UpdateError::Check(format!("manifest fetch: {e}")))?;
        if !response.status().is_success() {
            return Err(UpdateError::Check(format!(
                "manifest fetch returned {}",
                response.status()
            )));
        }
        let text =
            response.text().await.map_err(|e| UpdateError::Check(format!("manifest read: {e}")))?;
        let (version, sha256) = manifest::parse(&text)?;
        if !manifest::version_is_newer(&version, &self.current_version) {
            return Ok(None);
        }
        let url = format!("{}/{}.zip", self.base_url, version);
        Ok(Some(Update { version, url, sha256 }))
    }

    async fn apply(&self, update: &Update) -> Result<(), UpdateError> {
        swap::download_extract_swap(
            &self.client,
            &update.url,
            &update.sha256,
            &self.current_exe,
            &self.staging_parent,
        )
        .await
    }
}

/// A no-op updater for deployments with self-update disabled.
pub struct DisabledUpdater;

#[async_trait]
impl SelfUpdatePort for DisabledUpdater {
    async fn check(&self) -> Result<Option<Update>, UpdateError> {
        Ok(None)
    }

    async fn apply(&self, _update: &Update) -> Result<(), UpdateError> {
        Err(UpdateError::Swap("self-update is disabled".to_owned()))
    }
}

/// Builds the updater from config: `None` when self-update is disabled.
pub fn from_config(config: &SelfUpdateConfig) -> Result<Option<Arc<dyn SelfUpdatePort>>, String> {
    if !config.enabled {
        return Ok(None);
    }
    Ok(Some(SelfUpdateAdapter::new(config)?))
}
