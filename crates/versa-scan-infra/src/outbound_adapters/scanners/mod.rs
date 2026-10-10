//! Scanner adapters (`ScannerPort`). One active per worker, chosen at the
//! composition root.
//!
//! - [`debug`] - deterministic verdicts from file names/content; the
//!   test/e2e workhorse.
//! - [`clamd`] - clamd TCP protocol (PING/VERSION/INSTREAM); the
//!   cross-platform real scanner (ClamAV on Windows and Linux).
//! - [`yara_x`] - embedded pure-Rust YARA-X engine over user rules.
//! - [`hash_blocklist`] - sha256 feed matcher (blocklist feeds).
//! - [`defender`] - Windows Defender via `MpCmdRun.exe` + PowerShell
//!   status; gracefully unusable off-Windows (path probes fail).

use std::path::Path;

pub mod clamd;
pub mod debug;
pub mod defender;
pub mod hash_blocklist;
pub mod proc;
pub mod yara_x;

pub use clamd::ClamdScanner;
pub use debug::DebugScanner;
pub use defender::DefenderScanner;
pub use hash_blocklist::HashBlocklistScanner;
pub use yara_x::YaraXScanner;

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
