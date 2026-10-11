//! Batch workspaces: per-batch directories with guaranteed cleanup.
//!
//! Layout: `<root>/<batch_id>/files/<sample_id>`. Every workspace removes its
//! directory on `Drop` (best-effort, logged) - the structural fix for the C#
//! system's disk-fill bug, where task folders were cleaned only by a
//! finalizer that also wrote `taskinfo.txt` into them. A `manifest.json`
//! describing the batch is written when the workspace is created instead.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::models::batch::ScanBatch;

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct WorkspaceManager {
    root: PathBuf,
}

impl WorkspaceManager {
    /// Creates the root directory if missing.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, WorkspaceError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates the on-disk workspace for one batch.
    pub fn create(&self, batch: &ScanBatch) -> Result<BatchWorkspace, WorkspaceError> {
        let dir = self.root.join(batch.id().as_str());
        let files_dir = dir.join("files");
        std::fs::create_dir_all(&files_dir)?;
        let workspace = BatchWorkspace { dir, files_dir };
        workspace.write_manifest(batch)?;
        Ok(workspace)
    }

    /// Removes leftover batch directories from previous runs (e.g. crashes).
    /// Called once at startup. Only directories carrying a `manifest.json`
    /// are removed - a misconfigured workspace_root must not wipe unrelated
    /// operator data.
    pub fn sweep(&self) -> Result<usize, WorkspaceError> {
        let mut removed = 0;
        let mut entries = std::fs::read_dir(&self.root)?;
        while let Some(entry) = entries.next() {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.join("manifest.json").is_file() {
                tracing::info!(dir = %path.display(), "sweeping leftover batch workspace");
                std::fs::remove_dir_all(&path)?;
                removed += 1;
            } else if path.is_dir() {
                tracing::warn!(
                    dir = %path.display(),
                    "directory under workspace_root has no manifest.json; leaving it alone"
                );
            }
        }
        Ok(removed)
    }
}

/// Guard for one batch's on-disk footprint. Removal happens on drop.
#[derive(Debug)]
pub struct BatchWorkspace {
    dir: PathBuf,
    files_dir: PathBuf,
}

#[derive(Serialize)]
struct ManifestFile<'a> {
    sample_id: &'a str,
    url: &'a str,
    sha256: &'a str,
    declared_size: u64,
    local_name: &'a str,
}

#[derive(Serialize)]
struct Manifest<'a> {
    batch_id: &'a str,
    priority: &'a str,
    files: Vec<ManifestFile<'a>>,
}

impl BatchWorkspace {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where fetched samples are placed. Appears only on successful fetch
    /// (adapter contract), so the scanner never sees half-files.
    pub fn files_dir(&self) -> &Path {
        &self.files_dir
    }

    fn write_manifest(&self, batch: &ScanBatch) -> Result<(), WorkspaceError> {
        let manifest = Manifest {
            batch_id: batch.id().as_str(),
            priority: batch.priority().as_str(),
            files: batch
                .files()
                .iter()
                .map(|f| ManifestFile {
                    sample_id: f.request.sample_id.as_str(),
                    url: &f.request.url,
                    sha256: f.request.sha256.as_str(),
                    declared_size: f.request.size,
                    local_name: &f.local_name,
                })
                .collect(),
        };
        let json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| WorkspaceError::Io(std::io::Error::other(e.to_string())))?;
        std::fs::write(self.dir.join("manifest.json"), json)?;
        Ok(())
    }

    /// Explicit removal (idempotent with Drop).
    pub fn close(self) {
        // `self` drops right after; nothing else to do.
    }
}

impl Drop for BatchWorkspace {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.dir) {
            Ok(()) => tracing::debug!(dir = %self.dir.display(), "batch workspace removed"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(dir = %self.dir.display(), error = %err, "failed to remove batch workspace")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::models::batch::BatchAddError;
    use crate::models::digest::Sha256Digest;
    use crate::models::ids::{BatchId, CorrelationId, SampleId};
    use crate::models::priority::Priority;
    use crate::models::sample::{ReportDest, SampleRequest};

    fn request(id: &str) -> SampleRequest {
        SampleRequest {
            sample_id: SampleId::new(id).unwrap(),
            url: "http://art/x".to_owned(),
            sha256: Sha256Digest::from_hex(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap(),
            size: 1,
            priority: Priority::High,
            report_dest: ReportDest::new("reports").unwrap(),
            correlation_id: CorrelationId::new("corr").unwrap(),
            extensions: vec![],
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn create_manifest_and_cleanup() {
        let tmp = std::env::temp_dir().join(format!("vs-ws-test-{}", uuid::Uuid::new_v4()));
        let manager = WorkspaceManager::new(&tmp).unwrap();

        let mut batch = ScanBatch::new(BatchId::new("batch-x").unwrap(), Priority::High, 3);
        assert!(batch.try_add(request("s1")).is_ok());

        let ws = manager.create(&batch).unwrap();
        let dir = ws.dir().to_path_buf();
        assert!(dir.join("files").is_dir());
        let manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
        assert!(manifest.contains("batch-x"));
        assert!(manifest.contains("s1"));
        assert!(manifest.contains("high"));

        drop(ws);
        assert!(!dir.exists(), "workspace removed on drop");

        manager.sweep().unwrap();
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn sweep_removes_leftovers_only() {
        let tmp = std::env::temp_dir().join(format!("vs-ws-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = WorkspaceManager::new(&tmp).unwrap();

        // A crashed batch (manifest present) is swept...
        let stale = tmp.join("stale-batch");
        std::fs::create_dir_all(stale.join("files")).unwrap();
        std::fs::write(stale.join("manifest.json"), "{}").unwrap();
        // ...an operator directory without one is left alone.
        let foreign = tmp.join("not-a-batch");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("precious.txt"), "keep me").unwrap();

        let removed = manager.sweep().unwrap();
        assert_eq!(removed, 1);
        assert!(!stale.exists());
        assert!(foreign.exists(), "foreign directories are never swept");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn duplicate_add_error_displayed() {
        let mut batch = ScanBatch::new(BatchId::new("b").unwrap(), Priority::High, 2);
        assert!(batch.try_add(request("s")).is_ok());
        let err = batch.try_add(request("s"));
        assert!(matches!(err, Err(BatchAddError::DuplicateSample(_))));
    }
}
