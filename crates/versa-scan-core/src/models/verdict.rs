//! Scan verdicts - the typed replacement for the C# report's bool soup
//! (`infected` / `av_error` / `proc_pass` / `proc_corr` / `proc_trust`).

use std::collections::BTreeSet;

/// One malware detection as reported by a scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub name: String,
    /// Reference link (e.g. vendor encyclopedia), when the scanner provides one.
    pub link: Option<String>,
}

/// Why a scanner could not produce a normal verdict for a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    PasswordProtected,
    Corrupted,
    Trusted,
    Oversized,
    /// Anything else the scanner reports as a skip; free-form, scanner-owned.
    Other(String),
}

impl SkipReason {
    /// Wire representation used by the bus DTOs.
    pub fn as_str(&self) -> &str {
        match self {
            SkipReason::PasswordProtected => "password_protected",
            SkipReason::Corrupted => "corrupted",
            SkipReason::Trusted => "trusted",
            SkipReason::Oversized => "oversized",
            SkipReason::Other(other) => other,
        }
    }
}

/// Per-file outcome.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ScanOutcome {
    /// At least one scanner detection.
    Detected { detections: Vec<Detection> },
    /// Normal, no detections.
    #[default]
    Clean,
    /// The scanner recognized the file but cannot/will not scan it normally.
    Skipped { reason: SkipReason },
    /// Processing failed (worker or scanner error for this file).
    Error { message: String },
}

/// Verdict plus scanner-derived extras for one file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileVerdict {
    pub outcome: ScanOutcome,
    /// Archive formats seen (file itself or nested), e.g. `zip`, `rar`.
    pub archives: BTreeSet<String>,
    /// Packers/protectors seen, e.g. `upx`.
    pub packers: BTreeSet<String>,
    /// Raw scanner log lines; only populated in debug mode.
    pub raw: Vec<String>,
}

impl FileVerdict {
    pub fn error(message: impl Into<String>) -> Self {
        Self { outcome: ScanOutcome::Error { message: message.into() }, ..Self::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_reason_wire_names() {
        assert_eq!(SkipReason::PasswordProtected.as_str(), "password_protected");
        assert_eq!(SkipReason::Corrupted.as_str(), "corrupted");
        assert_eq!(SkipReason::Trusted.as_str(), "trusted");
        assert_eq!(SkipReason::Oversized.as_str(), "oversized");
        assert_eq!(SkipReason::Other("encrypted_doc".to_owned()).as_str(), "encrypted_doc");
    }

    #[test]
    fn error_verdict_builds() {
        let v = FileVerdict::error("scan failed");
        assert_eq!(v.outcome, ScanOutcome::Error { message: "scan failed".to_owned() });
        assert!(v.raw.is_empty());
    }
}
