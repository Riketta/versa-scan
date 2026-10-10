//! Scanner adapters (`ScannerPort`). One active per worker, chosen at the
//! composition root.
//!
//! - [`debug`] - deterministic verdicts from file names/content; the
//!   test/e2e workhorse.
//! - [`clamd`] - clamd TCP protocol (PING/VERSION/INSTREAM); the
//!   cross-platform real scanner.
//! - [`defender`] - Windows Defender via `MpCmdRun.exe` + PowerShell
//!   status; gracefully unusable off-Windows (path probes fail).

use std::path::Path;

pub mod clamd;
pub mod debug;
pub mod defender;
pub mod proc;

pub use clamd::ClamdScanner;
pub use debug::DebugScanner;
pub use defender::DefenderScanner;

/// Recursive file listing shared by scanner adapters that walk a batch
/// workspace (keyed by file name at the adapter boundary).
pub(crate) fn collect_files_recursive(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!(dir = %dir.display(), error = %err, "workspace walk failed");
            return;
        }
    };
    while let Some(entry) = entries.next() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, out);
        } else {
            out.push(path);
        }
    }
}
