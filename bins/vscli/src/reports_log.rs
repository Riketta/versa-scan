//! Local reports log: every received report is appended as one JSON line
//! (`{"dest": ..., "report": {...}}`), so `vscli reports <sample_id>` can
//! answer without the bus.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use versa_scan_core::models::report::ScanReport;
use versa_scan_core::models::sample::ReportDest;
use versa_scan_infra::wire::ScanReportV1;

#[derive(Debug, thiserror::Error)]
pub enum ReportsLogError {
    #[error("reports log io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("reports log corrupt line {line}: {reason}")]
    Corrupt { line: usize, reason: String },
}

#[derive(Serialize, Deserialize)]
struct LogEntry {
    dest: String,
    report: ScanReportV1,
}

pub struct ReportsLog {
    path: PathBuf,
}

impl ReportsLog {
    /// Opens (creating if needed) the log under the store root.
    pub fn open(root: &Path) -> Result<Self, ReportsLogError> {
        let dir = root.join("reports");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { path: dir.join("reports.jsonl") })
    }

    /// Appends one received report.
    pub fn append(&self, report: &ScanReport) -> Result<(), ReportsLogError> {
        let entry = LogEntry {
            dest: report.report_dest.as_str().to_owned(),
            report: ScanReportV1::from_model(report),
        };
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(
            file,
            "{}",
            serde_json::to_string(&entry)
                .map_err(|e| { ReportsLogError::Io(std::io::Error::other(e.to_string())) })?
        )?;
        Ok(())
    }

    /// All reports ever received, oldest first.
    pub fn load(&self) -> Result<Vec<ScanReport>, ReportsLogError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = std::fs::File::open(&self.path)?;
        let mut reports = Vec::new();
        for (index, line) in std::io::BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: LogEntry = serde_json::from_str(&line)
                .map_err(|e| ReportsLogError::Corrupt { line: index + 1, reason: e.to_string() })?;
            let dest = ReportDest::new(entry.dest);
            let report = entry
                .report
                .to_model(dest)
                .map_err(|e| ReportsLogError::Corrupt { line: index + 1, reason: e.to_string() })?;
            reports.push(report);
        }
        Ok(reports)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use std::time::Duration;
    use versa_scan_core::models::ScanTiming;
    use versa_scan_core::models::ids::{CorrelationId, SampleId, ScannerId};
    use versa_scan_core::models::worker::{WorkerInfo, WorkerRole};

    fn report(sample: &str, dest: &str) -> ScanReport {
        ScanReport {
            sample_id: SampleId::new(sample).unwrap(),
            correlation_id: CorrelationId::new("c").unwrap(),
            scanner: ScannerId::new("clamd").unwrap(),
            report_dest: ReportDest::new(dest),
            worker: WorkerInfo {
                hostname: "h".to_owned(),
                os: "os".to_owned(),
                role: WorkerRole::Sandbox,
            },
            av: None,
            outcome: versa_scan_core::models::ScanOutcome::Clean,
            extras: Default::default(),
            timing: ScanTiming {
                started_at: time::OffsetDateTime::UNIX_EPOCH,
                finished_at: time::OffsetDateTime::UNIX_EPOCH,
                duration: Duration::ZERO,
            },
            attempt: 1,
        }
    }

    #[test]
    fn append_and_load_round_trip() {
        let root = std::env::temp_dir().join(format!("vs-rlog-{}", uuid::Uuid::new_v4()));
        let log = ReportsLog::open(&root).unwrap();
        log.append(&report("a", "dest-a")).unwrap();
        log.append(&report("b", "dest-b")).unwrap();
        let loaded = log.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].sample_id.as_str(), "a");
        assert_eq!(loaded[0].report_dest.as_str(), "dest-a");
        assert_eq!(loaded[1].sample_id.as_str(), "b");
        std::fs::remove_dir_all(&root).ok();
    }
}
