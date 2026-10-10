//! `ScanReport` - the aggregate result published back to the requester.

use std::collections::BTreeSet;

use time::OffsetDateTime;

use super::av::AvProfile;
use super::ids::{CorrelationId, SampleId, ScannerId};
use super::sample::ReportDest;
use super::verdict::ScanOutcome;
use super::worker::WorkerInfo;
use std::time::Duration;

/// Extras a scanner attached to a file verdict.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReportExtras {
    pub archives: BTreeSet<String>,
    pub packers: BTreeSet<String>,
    /// Raw scanner log lines; present only when the worker runs in debug mode.
    pub raw: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTiming {
    pub started_at: OffsetDateTime,
    pub finished_at: OffsetDateTime,
    pub duration: Duration,
}

/// One sample's verdict as one report. Published to the request's
/// `report_dest`; `attempt` is the broker delivery count the worker acted on,
/// letting consumers dedupe re-delivered reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub sample_id: SampleId,
    pub correlation_id: CorrelationId,
    pub scanner: ScannerId,
    pub report_dest: ReportDest,
    pub worker: WorkerInfo,
    /// Scanner state at scan time; `None` when no scan happened
    /// (e.g. fetch failed before the scanner ran).
    pub av: Option<AvProfile>,
    pub outcome: ScanOutcome,
    pub extras: ReportExtras,
    pub timing: ScanTiming,
    pub attempt: u8,
}
