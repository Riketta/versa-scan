//! Sample fetch port: pull a request's content into the batch workspace.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::models::digest::Sha256Digest;
use crate::models::sample::SampleRequest;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The artifact server answered "not found" - the sample is gone; no
    /// amount of retrying helps.
    #[error("sample not found at url")]
    NotFound,
    #[error("sha256 mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: Sha256Digest, actual: Sha256Digest },
    /// Declared size (when non-zero) disagreed with the fetched size.
    #[error("size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    /// Fetched content exceeded the worker's configured limit.
    #[error("sample too large: limit {limit}, got {actual}")]
    TooLarge { limit: u64, actual: u64 },
    #[error("fetch timed out")]
    Timeout,
    /// The URL's host is not on the worker's fetch allowlist (when one is
    /// configured). Deterministic: retrying hits the same policy.
    #[error("fetch host not allowed by fetch_allowed_hosts")]
    Forbidden,
    /// Transient io/transport failure (connection reset, dns, disk full, ...).
    #[error("fetch io error: {0}")]
    Io(String),
}

impl FetchError {
    /// Terminal errors are deterministic: retrying re-fetches the same bytes
    /// and fails the same way. The retry policy reports them instead.
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            FetchError::NotFound
                | FetchError::Forbidden
                | FetchError::HashMismatch { .. }
                | FetchError::SizeMismatch { .. }
                | FetchError::TooLarge { .. }
        )
    }
}

/// A successfully fetched, hash-verified sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedFile {
    /// Path the sample was written to (inside the batch workspace).
    pub path: PathBuf,
    /// Size on disk.
    pub size: u64,
    /// The digest that was verified (re-echoed for logs/reports).
    pub digest: Sha256Digest,
}

/// Downloads samples into the batch workspace. Adapter contract: the file
/// appears at `dest` only after full verification - partial writes go to a
/// temporary name, so a crashed fetch never leaves a scannable half-file.
#[async_trait]
pub trait SampleFetcherPort: Send + Sync {
    async fn fetch(&self, request: &SampleRequest, dest: &Path) -> Result<FetchedFile, FetchError>;
}
