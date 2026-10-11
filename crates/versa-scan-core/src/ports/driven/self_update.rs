//! Worker self-update port: manifest check + hash-verified staged swap.

use async_trait::async_trait;

use crate::models::digest::Sha256Digest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub version: String,
    /// Where the update archive can be downloaded from.
    pub url: String,
    pub sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    #[error("update manifest is malformed: {0}")]
    Manifest(String),
    #[error("update download failed: {0}")]
    Download(String),
    #[error("update hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: Sha256Digest, actual: Sha256Digest },
    #[error("update swap failed: {0}")]
    Swap(String),
    #[error("update check failed: {0}")]
    Check(String),
}

#[async_trait]
pub trait SelfUpdatePort: Send + Sync {
    /// Returns `None` when the deployment is current.
    async fn check(&self) -> Result<Option<Update>, UpdateError>;

    /// Downloads, verifies, stages, and swaps in the update. The process
    /// should exit soon after (adapters pick the restart mechanism per
    /// platform); `apply` returns before that.
    async fn apply(&self, update: &Update) -> Result<(), UpdateError>;
}
