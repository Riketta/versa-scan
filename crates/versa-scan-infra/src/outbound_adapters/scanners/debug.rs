//! Debug scanner: deterministic, dependency-free verdicts for tests and
//! local runs. Verdict rules (file name lowercased):
//!
//! - contains `crash`  -> the whole scan fails (`ScannerError::ScanFailed`)
//! - contains `eicar` or content contains `EICAR` -> `Detected`
//! - contains `locked` -> `Skipped(PasswordProtected)`
//! - contains `corrupt` -> `Skipped(Corrupted)`
//! - contains `skip`   -> `Skipped(Other("debug_skip"))`
//! - anything else     -> `Clean`
//!
//! Extras: `.zip`/`.rar` in the name add archive entries; `upx` adds a
//! packer. Raw log lines are always attached (this adapter is debug-only).

use std::collections::BTreeSet;
use std::path::Path;

use async_trait::async_trait;
use versa_scan_core::models::av::AvProfile;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::models::verdict::{FileVerdict, ScanOutcome, SkipReason};
use versa_scan_core::ports::driven::scanner::{
    ScanOutput, ScannerError, ScannerPort, UpdateOutcome,
};

pub struct DebugScanner {
    id: ScannerId,
}

impl DebugScanner {
    pub fn new() -> Self {
        Self { id: ScannerId::new("debug").expect("static slug is valid") }
    }

    fn verdict_for(path: &Path) -> std::io::Result<FileVerdict> {
        let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let content = std::fs::read(path).unwrap_or_default();
        let content_has_eicar = content.windows(5).any(|w| w.eq_ignore_ascii_case(b"EICAR"));

        if name.contains("crash") {
            // The scan-level failure is raised by `scan` once it sees this
            // name; the per-file verdict here is just a fallback.
            return Ok(FileVerdict::error("debug crash requested"));
        }
        if name.contains("eicar") || content_has_eicar {
            return Ok(FileVerdict {
                outcome: ScanOutcome::Detected {
                    detections: vec![versa_scan_core::models::Detection {
                        name: "Win.Test.EICAR".to_owned(),
                        link: None,
                    }],
                },
                ..verdict_extras(&name)
            });
        }
        let reason = if name.contains("locked") {
            Some(SkipReason::PasswordProtected)
        } else if name.contains("corrupt") {
            Some(SkipReason::Corrupted)
        } else if name.contains("skip") {
            Some(SkipReason::Other("debug_skip".to_owned()))
        } else {
            None
        };
        let outcome = match reason {
            Some(reason) => ScanOutcome::Skipped { reason },
            None => ScanOutcome::Clean,
        };
        Ok(FileVerdict { outcome, ..verdict_extras(&name) })
    }
}

fn verdict_extras(name: &str) -> FileVerdict {
    let mut archives = BTreeSet::new();
    let mut packers = BTreeSet::new();
    if name.contains(".zip") {
        archives.insert("zip".to_owned());
    }
    if name.contains(".rar") {
        archives.insert("rar".to_owned());
    }
    if name.contains("upx") {
        packers.insert("upx".to_owned());
    }
    FileVerdict {
        outcome: ScanOutcome::Clean,
        archives,
        packers,
        raw: vec![format!("debug scanned {name}")],
    }
}

impl Default for DebugScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScannerPort for DebugScanner {
    fn id(&self) -> ScannerId {
        self.id.clone()
    }

    async fn is_installed(&self) -> Result<bool, ScannerError> {
        Ok(true)
    }

    async fn profile(&self) -> Result<AvProfile, ScannerError> {
        Ok(AvProfile {
            av_name: "DebugAV".to_owned(),
            av_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            bases_version: Some("test-bases".to_owned()),
            ..Default::default()
        })
    }

    async fn scan(&self, dir: &Path) -> Result<ScanOutput, ScannerError> {
        let mut files = Vec::new();
        super::collect_files_recursive(dir, &mut files);
        files.sort();

        for file in &files {
            if let Some(name) = file.file_name() {
                if name.to_string_lossy().to_lowercase().contains("crash") {
                    return Err(ScannerError::ScanFailed(format!(
                        "debug crash requested via {}",
                        name.to_string_lossy()
                    )));
                }
            }
        }

        let mut entries = Vec::new();
        for file in files {
            let name =
                file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let verdict = DebugScanner::verdict_for(&file)
                .map_err(|e| ScannerError::Io(format!("debug read {}: {e}", file.display())))?;
            entries.push((name, verdict));
        }
        Ok(ScanOutput { entries })
    }

    async fn update(&self) -> Result<UpdateOutcome, ScannerError> {
        Ok(UpdateOutcome::UpToDate)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[tokio::test]
    async fn verdict_rules_apply_by_name_and_content() {
        let tmp = std::env::temp_dir().join(format!("vs-dbgscan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();

        write(&tmp, "clean1.bin", b"hello");
        write(&tmp, "eicar2.exe", b"plain");
        write(&tmp, "innocent3.dll", b"contains EICAR string");
        write(&tmp, "locked4.zip", b"data");
        write(&tmp, "corrupt5.bin", b"data");
        write(&tmp, "packed6.upx", b"data");
        write(&tmp, "skippable7.bin", b"data");
        write(&tmp, "crash8.bin", b"boom");

        let scanner = DebugScanner::new();
        let err = scanner.scan(&tmp).await.unwrap_err();
        assert!(matches!(err, ScannerError::ScanFailed(_)), "crash file fails the scan");

        std::fs::remove_file(tmp.join("crash8.bin")).unwrap();
        let output = scanner.scan(&tmp).await.unwrap();
        let verdict = |name: &str| {
            output
                .entries
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("no verdict for {name}"))
        };

        assert_eq!(verdict("clean1.bin").outcome, ScanOutcome::Clean);
        assert!(matches!(verdict("eicar2.exe").outcome, ScanOutcome::Detected { .. }));
        assert!(matches!(verdict("innocent3.dll").outcome, ScanOutcome::Detected { .. }));
        assert_eq!(
            verdict("locked4.zip").outcome,
            ScanOutcome::Skipped { reason: SkipReason::PasswordProtected }
        );
        assert_eq!(
            verdict("corrupt5.bin").outcome,
            ScanOutcome::Skipped { reason: SkipReason::Corrupted }
        );
        assert_eq!(
            verdict("skippable7.bin").outcome,
            ScanOutcome::Skipped { reason: SkipReason::Other("debug_skip".to_owned()) }
        );

        let packed = verdict("packed6.upx");
        assert!(packed.packers.contains("upx"));
        let zipped = verdict("locked4.zip");
        assert!(zipped.archives.contains("zip"));

        assert_eq!(scanner.id().as_str(), "debug");
        assert_eq!(scanner.profile().await.unwrap().av_name, "DebugAV");

        std::fs::remove_dir_all(&tmp).ok();
    }
}
