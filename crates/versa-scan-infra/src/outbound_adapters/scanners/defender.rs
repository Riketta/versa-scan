//! Windows Defender scanner via `MpCmdRun.exe` (the real implementation of
//! the C# system's empty stub).
//!
//! - Executable resolution: newest `Windows Defender\Platform\<ver>` first,
//!   then `Program Files\Windows Defender\MpCmdRun.exe`.
//! - Scan: `MpCmdRun -Scan -ScanType 3 -File <dir>`; exit 0 = clean, 2 =
//!   threats found, anything else = scan failure. Findings are parsed from
//!   `... Found <name>!` lines and keyed by file name.
//! - Profile: one-shot `Get-MpComputerStatus` (engine + signature
//!   versions), cached after first success.
//! - Update: `MpCmdRun -SignatureUpdate`.
//! - Timeouts terminate the whole process tree (`taskkill /T`).
//!
//! Off-Windows the executable probes simply fail: `is_installed` returns
//! false and the composition root refuses to select this scanner.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;
use versa_scan_core::models::av::AvProfile;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::models::verdict::{Detection, FileVerdict, ScanOutcome};
use versa_scan_core::ports::driven::scanner::{
    ScanOutput, ScannerError, ScannerPort, UpdateOutcome,
};

use super::proc::kill_tree;

const SPAWN_TIMEOUT: Duration = Duration::from_secs(60);
const SCAN_OVERHEAD: Duration = Duration::from_secs(120); // process start/teardown slack

pub struct DefenderScanner {
    id: ScannerId,
    profile_cache: OnceLock<AvProfile>,
}

impl Default for DefenderScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DefenderScanner {
    pub fn new() -> Self {
        Self {
            id: ScannerId::new("defender").expect("static slug is valid"),
            profile_cache: OnceLock::new(),
        }
    }

    /// Newest platform-dir MpCmdRun, falling back to the install dir.
    fn resolve_mpcmdrun() -> Option<PathBuf> {
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_owned());
        let candidates_root = PathBuf::from(
            std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned()),
        )
        .join(r"Microsoft\Windows Defender\Platform");
        if let Ok(entries) = std::fs::read_dir(&candidates_root) {
            let mut versions: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.join("MpCmdRun.exe").is_file())
                .collect();
            versions.sort();
            if let Some(newest) = versions.pop() {
                return Some(newest.join("MpCmdRun.exe"));
            }
        }
        let fallback = PathBuf::from(program_files).join(r"Windows Defender\MpCmdRun.exe");
        fallback.is_file().then_some(fallback)
    }

    async fn run_mpcmdrun(
        exe: &Path,
        args: &[&str],
        timeout: Duration,
    ) -> Result<std::process::Output, ScannerError> {
        let mut command = Command::new(exe);
        command.args(args);
        command.kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW

        let child =
            command.spawn().map_err(|e| ScannerError::Io(format!("mpcmdrun spawn: {e}")))?;
        let pid = child.id();
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(result) => result.map_err(|e| ScannerError::Io(format!("mpcmdrun run: {e}"))),
            Err(_) => {
                if let Some(pid) = pid {
                    kill_tree(pid).await;
                }
                Err(ScannerError::Unavailable(format!("mpcmdrun timed out after {timeout:?}")))
            }
        }
    }

    async fn powershell_status() -> Option<(String, String)> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-MpComputerStatus).AMProductVersion; \
                 (Get-MpComputerStatus).AntivirusSignatureVersion",
            ])
            .creation_flags_cfg()
            .output()
            .await
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        Some((lines.next()?.to_owned(), lines.next()?.to_owned()))
    }

    /// Pure: extracts per-file findings from MpCmdRun output. Keyed by file
    /// name; tolerant to the exact surrounding punctuation, which varies
    /// between Defender versions (refine the fixture when a real VM capture
    /// diverges).
    pub(crate) fn parse_scan_output(stdout: &str) -> Vec<(String, FileVerdict)> {
        let mut entries: Vec<(String, FileVerdict)> = Vec::new();
        for line in stdout.lines() {
            let Some(found_at) = line.find(" Found ") else { continue };
            let (left, right) = line.split_at(found_at);
            let detection_part = right.trim_start_matches(" Found ").trim_end();
            let name_part =
                left.split_whitespace().last().unwrap_or("").trim_end_matches("...").to_owned();
            if name_part.is_empty() || detection_part.is_empty() {
                continue;
            }
            let detection = detection_part.trim_end_matches('!').trim().to_owned();
            let file_name = Path::new(&name_part)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or(name_part);
            let verdict = FileVerdict {
                outcome: ScanOutcome::Detected {
                    detections: vec![Detection { name: detection, link: None }],
                },
                ..Default::default()
            };
            entries.push((file_name, verdict));
        }
        entries
    }
}

/// Windows-only cosmetics (no console windows during scans/tests).
trait CreationFlagsCfg {
    fn creation_flags_cfg(&mut self) -> &mut Self;
}

#[cfg(windows)]
impl CreationFlagsCfg for Command {
    fn creation_flags_cfg(&mut self) -> &mut Self {
        self.creation_flags(0x0800_0000)
    }
}

#[cfg(not(windows))]
impl CreationFlagsCfg for Command {
    fn creation_flags_cfg(&mut self) -> &mut Self {
        self
    }
}

#[async_trait]
impl ScannerPort for DefenderScanner {
    fn id(&self) -> ScannerId {
        self.id.clone()
    }

    async fn is_installed(&self) -> Result<bool, ScannerError> {
        Ok(Self::resolve_mpcmdrun().is_some())
    }

    async fn profile(&self) -> Result<AvProfile, ScannerError> {
        if let Some(profile) = self.profile_cache.get() {
            return Ok(profile.clone());
        }
        let mut profile =
            AvProfile { av_name: "Windows Defender".to_owned(), ..Default::default() };
        if let Some((engine, signature)) = Self::powershell_status().await {
            profile.av_version = Some(engine);
            profile.bases_version = Some(signature);
        }
        let _ = self.profile_cache.set(profile.clone());
        Ok(profile)
    }

    async fn scan(&self, dir: &Path) -> Result<ScanOutput, ScannerError> {
        let Some(exe) = Self::resolve_mpcmdrun() else {
            return Err(ScannerError::NotInstalled("MpCmdRun.exe not found".to_owned()));
        };
        let dir_str = dir.to_string_lossy().to_string();
        let timeout = SPAWN_TIMEOUT + SCAN_OVERHEAD;
        let output =
            Self::run_mpcmdrun(&exe, &["-Scan", "-ScanType", "3", "-File", &dir_str], timeout)
                .await?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let code = output.status.code().unwrap_or(-1);

        let mut entries = Self::parse_scan_output(&stdout);
        match code {
            0 | 2 => {}
            other => {
                return Err(ScannerError::ScanFailed(format!(
                    "MpCmdRun exited with {other}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
        }
        if stdout.contains("ERROR:") {
            return Err(ScannerError::ScanFailed(format!(
                "MpCmdRun reported an error: {}",
                stdout.trim()
            )));
        }

        // Files without a finding line are clean (exit 0/2 with fewer
        // findings than files is normal for Defender directory scans).
        let mut files = Vec::new();
        super::collect_files_recursive(dir, &mut files);
        for file in files {
            let name =
                file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if !entries.iter().any(|(n, _)| *n == name) {
                entries.push((name, FileVerdict::default()));
            }
        }
        Ok(ScanOutput { entries })
    }

    async fn update(&self) -> Result<UpdateOutcome, ScannerError> {
        let Some(exe) = Self::resolve_mpcmdrun() else {
            return Err(ScannerError::NotInstalled("MpCmdRun.exe not found".to_owned()));
        };
        let output = Self::run_mpcmdrun(&exe, &["-SignatureUpdate"], SPAWN_TIMEOUT).await?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() {
            return Err(ScannerError::Update(format!(
                "SignatureUpdate exited with {}: {}",
                output.status.code().unwrap_or(-1),
                text.trim()
            )));
        }
        if text.to_lowercase().contains("already") || text.to_lowercase().contains("up to date") {
            Ok(UpdateOutcome::UpToDate)
        } else {
            Ok(UpdateOutcome::Updated)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;

    /// Fixture shaped after MpCmdRun 4.18 output (refine against a real VM
    /// capture when one is available).
    const FIXTURE_THREATS: &str = "\
Scanning C:\\tasks\\batch-1\\files\\ before scanning.
Scanning  2 file(s).

bad.exe   Found Virus:DOS/EICAR_Test_File!
sub\\nested.dll   Found Trojan:Win32/Wacatac.B!ml

Results:
C:\\tasks\\batch-1\\files\\bad.exe ... Found Virus:DOS/EICAR_Test_File!
C:\\tasks\\batch-1\\files\\sub\\nested.dll ... Found Trojan:Win32/Wacatac.B!ml";

    const FIXTURE_CLEAN: &str = "\
Scanning C:\\tasks\\batch-1\\files\\ before scanning.
Scanning  1 file(s).

No threats found.";

    #[test]
    fn parses_findings_by_file_name() {
        let entries = DefenderScanner::parse_scan_output(FIXTURE_THREATS);
        let verdict = |name: &str| {
            entries
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("no verdict for {name}"))
        };
        let bad = verdict("bad.exe");
        match bad.outcome {
            ScanOutcome::Detected { detections } => {
                // Trailing punctuation is stripped from detection names.
                assert_eq!(detections[0].name, "Virus:DOS/EICAR_Test_File");
            }
            other => panic!("expected detection, got {other:?}"),
        }
        let nested = verdict("nested.dll");
        match nested.outcome {
            ScanOutcome::Detected { detections } => {
                assert_eq!(detections[0].name, "Trojan:Win32/Wacatac.B!ml");
            }
            other => panic!("expected detection, got {other:?}"),
        }
    }

    #[test]
    fn clean_fixture_has_no_findings() {
        assert!(DefenderScanner::parse_scan_output(FIXTURE_CLEAN).is_empty());
    }

    #[tokio::test]
    async fn off_windows_probe_fails_gracefully() {
        // On Windows this resolves the real binary (installed on runners/VMs);
        // elsewhere it must simply report "not installed" without erroring.
        let scanner = DefenderScanner::new();
        let installed = scanner.is_installed().await.unwrap();
        #[cfg(not(windows))]
        assert!(!installed);
        let _ = installed;
    }
}
