//! The antivirus port - the C# `Antivirus` abstract class, cleaned up.

use std::path::Path;

use async_trait::async_trait;

use crate::models::av::AvProfile;
use crate::models::ids::ScannerId;
use crate::models::verdict::FileVerdict;

/// Result of one scanner run over a batch directory.
///
/// `entries` may cover fewer or more files than were placed on disk; the
/// core's validation reconciles the two (missing file -> synthesized error
/// verdict, extra entry -> warning). Entries are keyed by file name as the
/// scanner reports it (expected to match the on-disk names).
#[derive(Debug, Clone, Default)]
pub struct ScanOutput {
    pub entries: Vec<(String, FileVerdict)>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScannerError {
    /// The scanner implementation is not usable on this machine.
    #[error("scanner is not installed: {0}")]
    NotInstalled(String),
    /// The scanner backend is unreachable right now (daemon down, service
    /// starting). Transient - the orchestrator requeues affected batches.
    #[error("scanner unavailable: {0}")]
    Unavailable(String),
    /// A scan ran but failed (non-zero exit, unparsable report, ...).
    #[error("scan failed: {0}")]
    ScanFailed(String),
    /// Infrastructure error while driving the scanner (spawn, io).
    #[error("scanner io error: {0}")]
    Io(String),
    /// A database update failed.
    #[error("scanner update failed: {0}")]
    Update(String),
}

/// Outcome of a scanner database update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// New bases were downloaded and activated.
    Updated,
    /// The scanner reports its bases are current.
    UpToDate,
}

impl UpdateOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            UpdateOutcome::Updated => "updated",
            UpdateOutcome::UpToDate => "up_to_date",
        }
    }
}

/// One scanner implementation. Exactly one adapter per worker, chosen at the
/// composition root. All methods are cancel-safe from the caller's side:
/// the orchestrator enforces timeouts and may drop the future.
#[async_trait]
pub trait ScannerPort: Send + Sync {
    fn id(&self) -> ScannerId;

    /// Cheap check whether this scanner can run on this machine. Used by the
    /// composition root's optional `--detect` and by the openbox role.
    async fn is_installed(&self) -> Result<bool, ScannerError>;

    /// Scanner metadata snapshot for reports. Called before each scan; a
    /// failure here degrades reports (`av: None`), it never aborts a batch.
    async fn profile(&self) -> Result<AvProfile, ScannerError>;

    /// Scans every file under `dir` (recursively, at the adapter's
    /// discretion) and parses results into per-file verdicts.
    async fn scan(&self, dir: &Path) -> Result<ScanOutput, ScannerError>;

    /// Updates scanner databases (openbox role).
    async fn update(&self) -> Result<UpdateOutcome, ScannerError>;
}
