//! Validation: reconciles a scanner's report against the files that were
//! actually placed in the batch workspace. Pure.
//!
//! A missing per-file verdict is synthesized into an explicit error outcome
//! so the requester always gets exactly one report per sample.

use crate::models::batch::BatchFile;
use crate::models::verdict::FileVerdict;
use crate::ports::driven::ScanOutput;

/// One validated file: what the scanner said (or a synthesized error).
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedFile {
    pub file: BatchFile,
    pub verdict: FileVerdict,
    /// True when the verdict came from the scanner; false when synthesized
    /// because the scanner never mentioned the file.
    pub from_scanner: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconcileReport {
    /// Count of files that were expected to be scanned.
    pub expected: usize,
    /// Count of verdicts the scanner produced for those files.
    pub reported: usize,
    /// Scanner entries that matched no expected file (stale/temp files the
    /// scanner noticed). Always logged by the caller.
    pub unexpected: Vec<String>,
}

/// Maps every expected file to a verdict; synthesizes error verdicts for
/// files the scanner failed to mention.
pub fn reconcile(
    files: &[BatchFile],
    output: &ScanOutput,
) -> (Vec<ValidatedFile>, ReconcileReport) {
    let mut report = ReconcileReport { expected: files.len(), reported: 0, ..Default::default() };
    let mut validated = Vec::with_capacity(files.len());

    for file in files {
        match output.entries.iter().find(|(name, _)| *name == file.local_name) {
            Some((_, verdict)) => {
                report.reported += 1;
                validated.push(ValidatedFile {
                    file: file.clone(),
                    verdict: verdict.clone(),
                    from_scanner: true,
                });
            }
            None => {
                validated.push(ValidatedFile {
                    file: file.clone(),
                    verdict: FileVerdict::error("scanner produced no verdict for this file"),
                    from_scanner: false,
                });
            }
        }
    }

    for (name, _) in &output.entries {
        if !files.iter().any(|f| f.local_name == *name) {
            report.unexpected.push(name.clone());
        }
    }

    (validated, report)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::models::batch::ScanBatch;
    use crate::models::digest::Sha256Digest;
    use crate::models::ids::{BatchId, CorrelationId, SampleId};
    use crate::models::priority::Priority;
    use crate::models::sample::{ReportDest, SampleRequest};
    use crate::models::verdict::ScanOutcome;
    use time::OffsetDateTime;

    fn request(id: &str) -> BatchFile {
        BatchFile {
            request: SampleRequest {
                sample_id: SampleId::new(id).unwrap(),
                url: "http://art/x".to_owned(),
                sha256: Sha256Digest::from_hex(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
                .unwrap(),
                size: 1,
                priority: Priority::Normal,
                report_dest: ReportDest::new("reports").unwrap(),
                correlation_id: CorrelationId::new("corr").unwrap(),
                extensions: vec![],
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
            local_name: id.to_owned(),
        }
    }

    #[test]
    fn all_files_covered() {
        let files = vec![request("a"), request("b")];
        let output = ScanOutput {
            entries: vec![
                ("a".to_owned(), FileVerdict::default()),
                ("b".to_owned(), FileVerdict { outcome: ScanOutcome::Clean, ..Default::default() }),
            ],
        };
        let (validated, report) = reconcile(&files, &output);
        assert_eq!(validated.len(), 2);
        assert!(validated.iter().all(|v| v.from_scanner));
        assert_eq!(report.expected, 2);
        assert_eq!(report.reported, 2);
        assert!(report.unexpected.is_empty());
    }

    #[test]
    fn missing_verdict_synthesized() {
        let files = vec![request("a"), request("missing")];
        let output = ScanOutput { entries: vec![("a".to_owned(), FileVerdict::default())] };
        let (validated, report) = reconcile(&files, &output);
        assert_eq!(validated.len(), 2);
        let missing = validated.iter().find(|v| v.file.local_name == "missing").unwrap();
        assert!(!missing.from_scanner);
        assert!(matches!(missing.verdict.outcome, ScanOutcome::Error { .. }));
        assert_eq!(report.reported, 1);
    }

    #[test]
    fn unexpected_entries_flagged() {
        let files = vec![request("a")];
        let output = ScanOutput {
            entries: vec![
                ("a".to_owned(), FileVerdict::default()),
                ("ghost".to_owned(), FileVerdict::default()),
            ],
        };
        let (_, report) = reconcile(&files, &output);
        assert_eq!(report.unexpected, vec!["ghost".to_owned()]);
    }

    #[test]
    fn empty_batch_reconciles_empty() {
        let batch = ScanBatch::new(BatchId::new("b").unwrap(), Priority::Normal, 3);
        let _ = batch; // empty slice equivalent
        let (validated, report) = reconcile(&[], &ScanOutput::default());
        assert!(validated.is_empty());
        assert_eq!(report.expected, 0);
    }
}
