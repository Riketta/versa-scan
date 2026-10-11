//! Wire DTOs (schema 1) for the bus boundary - the ACL between external
//! JSON payloads and internal core models. Everything versioned, validated,
//! and mapped here; adapters never touch core models directly.
//!
//! Shared by both bus adapter edges: inbound listeners parse incoming
//! requests with `to_model`, outbound publishers serialize models with
//! `from_model`.
//!
//! Design notes (docs/DESIGN.md):
//! - Requests carry priority as a string band; RabbitMQ enforces ordering
//!   natively, NATS ignores it.
//! - Reports carry `attempt` so consumers can dedupe redelivered reports.
//! - Timestamps are RFC 3339 UTC (`time::serde::rfc3339`).
//! - Optional/empty fields are omitted to keep payloads small.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use versa_scan_core::models::{
    AvProfile, CorrelationId, Detection, LicenseInfo, Priority, ReportDest, ReportExtras, SampleId,
    SampleRequest, ScanOutcome, ScanReport, ScanTiming, ScannerId, Sha256Digest, SkipReason,
    UnknownRole, WorkerInfo, WorkerRole,
};

/// Current wire schema version.
pub const SCHEMA: u32 = 1;

// ---------------------------------------------------------------------------
// Topology naming: the subject/queue vocabulary of the wire contract.
// ---------------------------------------------------------------------------

/// Request queue (RabbitMQ) / subject root (NATS) for one scanner:
/// `vs.scan.requests.<scanner>`.
pub fn request_queue_name(scanner: &ScannerId) -> String {
    format!("vs.scan.requests.{}", scanner.as_str())
}

/// Subject tree reports live under. Requesters derive per-session report
/// destinations from it (e.g. `vs.scan.reports.<session>.<sample>`).
pub const REPORTS_SUBJECT_ROOT: &str = "vs.scan.reports.";

/// NATS report destination for one sample of one submitting session:
/// `vs.scan.reports.<session>.<sample_id>` (the worker publishes exactly
/// there; the session subscribes `<prefix>.*`).
pub fn nats_report_subject(session: &str, sample_id: &SampleId) -> String {
    format!("{REPORTS_SUBJECT_ROOT}{session}.{}", sample_id.as_str())
}

/// NATS wildcard subscription covering a session's report subjects.
pub fn nats_report_session_wildcard(session: &str) -> String {
    format!("{REPORTS_SUBJECT_ROOT}{session}.>")
}

/// RabbitMQ report queue for one submitting session (shared by all its
/// samples; the requester declares it before publishing requests).
pub fn rabbitmq_report_queue(session: &str) -> String {
    format!("{REPORTS_SUBJECT_ROOT}{session}")
}

/// Mapping/validation failure at the wire boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid wire field `{field}`: {reason}")]
pub struct WireError {
    field: &'static str,
    reason: String,
}

fn invalid<T>(field: &'static str, reason: impl Into<String>) -> Result<T, WireError> {
    Err(WireError { field, reason: reason.into() })
}

// ---------------------------------------------------------------------------
// SampleRequestV1
// ---------------------------------------------------------------------------

/// One scan request as published by a requester (vscli).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SampleRequestV1 {
    pub schema: u32,
    pub sample_id: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub priority: String,
    pub report_dest: String,
    pub correlation_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl SampleRequestV1 {
    pub fn from_model(model: &SampleRequest) -> Self {
        Self {
            schema: SCHEMA,
            sample_id: model.sample_id.as_str().to_owned(),
            url: model.url.clone(),
            sha256: model.sha256.as_str().to_owned(),
            size: model.size,
            priority: model.priority.as_str().to_owned(),
            report_dest: model.report_dest.as_str().to_owned(),
            correlation_id: model.correlation_id.as_str().to_owned(),
            extensions: model.extensions.clone(),
            created_at: model.created_at,
        }
    }

    pub fn to_model(&self) -> Result<SampleRequest, WireError> {
        if self.schema != SCHEMA {
            return invalid("schema", format!("unsupported schema {}", self.schema));
        }
        let sample_id = SampleId::new(&self.sample_id)
            .map_err(|e| WireError { field: "sample_id", reason: e.to_string() })?;
        if !(self.url.starts_with("http://") || self.url.starts_with("https://")) {
            return invalid("url", "must be an http(s) URL");
        }
        let sha256 = Sha256Digest::from_hex(&self.sha256)
            .map_err(|e| WireError { field: "sha256", reason: e.to_string() })?;
        let priority = parse_priority(&self.priority)?;
        let correlation_id = CorrelationId::new(&self.correlation_id)
            .map_err(|e| WireError { field: "correlation_id", reason: e.to_string() })?;
        Ok(SampleRequest {
            sample_id,
            url: self.url.clone(),
            sha256,
            size: self.size,
            priority,
            report_dest: ReportDest::new(&self.report_dest)
                .map_err(|e| WireError { field: "report_dest", reason: e.to_string() })?,
            correlation_id,
            extensions: self.extensions.clone(),
            created_at: self.created_at,
        })
    }
}

fn parse_priority(value: &str) -> Result<Priority, WireError> {
    match value {
        "low" => Ok(Priority::Low),
        "normal" => Ok(Priority::Normal),
        "high" => Ok(Priority::High),
        other => invalid("priority", format!("unknown band {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// ScanReportV1
// ---------------------------------------------------------------------------

/// One sample's verdict as published by a worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReportV1 {
    pub schema: u32,
    pub sample_id: String,
    pub correlation_id: String,
    pub scanner: String,
    pub worker: WorkerInfoV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub av: Option<AvProfileV1>,
    pub outcome: OutcomeV1,
    #[serde(default, skip_serializing_if = "ReportExtrasV1::is_empty")]
    pub extras: ReportExtrasV1,
    pub timing: TimingV1,
    pub attempt: u8,
}

impl ScanReportV1 {
    pub fn from_model(model: &ScanReport) -> Self {
        Self {
            schema: SCHEMA,
            sample_id: model.sample_id.as_str().to_owned(),
            correlation_id: model.correlation_id.as_str().to_owned(),
            scanner: model.scanner.as_str().to_owned(),
            worker: WorkerInfoV1::from_model(&model.worker),
            av: model.av.as_ref().map(AvProfileV1::from_model),
            outcome: OutcomeV1::from_model(&model.outcome),
            extras: ReportExtrasV1::from_model(&model.extras),
            timing: TimingV1::from_model(&model.timing),
            attempt: model.attempt,
        }
    }

    /// `dest` is supplied by the receiving side (it owns the report
    /// destination and knows what it subscribed/declared).
    pub fn to_model(&self, dest: ReportDest) -> Result<ScanReport, WireError> {
        if self.schema != SCHEMA {
            return invalid("schema", format!("unsupported schema {}", self.schema));
        }
        let sample_id = SampleId::new(&self.sample_id)
            .map_err(|e| WireError { field: "sample_id", reason: e.to_string() })?;
        let correlation_id = CorrelationId::new(&self.correlation_id)
            .map_err(|e| WireError { field: "correlation_id", reason: e.to_string() })?;
        let scanner = ScannerId::new(&self.scanner)
            .map_err(|e| WireError { field: "scanner", reason: e.to_string() })?;
        let worker =
            self.worker.to_model().map_err(|e| WireError { field: "worker.role", reason: e })?;
        let av = self.av.as_ref().map(AvProfileV1::to_model);
        let outcome =
            self.outcome.to_model().map_err(|e| WireError { field: "outcome", reason: e })?;
        Ok(ScanReport {
            sample_id,
            correlation_id,
            scanner,
            report_dest: dest,
            worker,
            av,
            outcome,
            extras: self.extras.to_model(),
            timing: self.timing.to_model(),
            attempt: self.attempt,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkerInfoV1 {
    pub hostname: String,
    pub os: String,
    pub role: String,
}

impl WorkerInfoV1 {
    pub fn from_model(model: &WorkerInfo) -> Self {
        Self {
            hostname: model.hostname.clone(),
            os: model.os.clone(),
            role: model.role.as_str().to_owned(),
        }
    }

    fn to_model(&self) -> Result<WorkerInfo, String> {
        let role: WorkerRole = self.role.parse().map_err(|e: UnknownRole| e.to_string())?;
        Ok(WorkerInfo { hostname: self.hostname.clone(), os: self.os.clone(), role })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AvProfileV1 {
    pub av_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub av_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bases_version: Option<String>,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub bases_time: Option<OffsetDateTime>,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub av_updated_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub components: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseV1>,
}

impl AvProfileV1 {
    pub fn from_model(model: &AvProfile) -> Self {
        Self {
            av_name: model.av_name.clone(),
            av_version: model.av_version.clone(),
            bases_version: model.bases_version.clone(),
            bases_time: model.bases_time,
            av_updated_at: model.av_updated_at,
            components: model.components.clone(),
            license: model.license.as_ref().map(LicenseV1::from_model),
        }
    }

    pub fn to_model(&self) -> AvProfile {
        AvProfile {
            av_name: self.av_name.clone(),
            av_version: self.av_version.clone(),
            bases_version: self.bases_version.clone(),
            bases_time: self.bases_time,
            av_updated_at: self.av_updated_at,
            components: self.components.clone(),
            license: self.license.as_ref().map(LicenseV1::to_model),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_type: Option<String>,
    pub valid: bool,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<OffsetDateTime>,
}

impl LicenseV1 {
    pub fn from_model(model: &LicenseInfo) -> Self {
        Self {
            license_type: model.license_type.clone(),
            valid: model.valid,
            expires_at: model.expires_at,
        }
    }

    pub fn to_model(&self) -> LicenseInfo {
        LicenseInfo {
            license_type: self.license_type.clone(),
            valid: self.valid,
            expires_at: self.expires_at,
        }
    }
}

/// Tagged outcome: `{"type": "detected", "detections": [...]}` etc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutcomeV1 {
    Detected { detections: Vec<DetectionV1> },
    Clean,
    Skipped { reason: SkipReasonV1 },
    Error { message: String },
}

impl OutcomeV1 {
    pub fn from_model(model: &ScanOutcome) -> Self {
        match model {
            ScanOutcome::Detected { detections } => OutcomeV1::Detected {
                detections: detections.iter().map(DetectionV1::from_model).collect(),
            },
            ScanOutcome::Clean => OutcomeV1::Clean,
            ScanOutcome::Skipped { reason } => {
                OutcomeV1::Skipped { reason: SkipReasonV1::from_model(reason) }
            }
            ScanOutcome::Error { message } => OutcomeV1::Error { message: message.clone() },
        }
    }

    pub fn to_model(&self) -> Result<ScanOutcome, String> {
        match self {
            OutcomeV1::Detected { detections } => Ok(ScanOutcome::Detected {
                detections: detections
                    .iter()
                    .map(|d| Detection { name: d.name.clone(), link: d.link.clone() })
                    .collect(),
            }),
            OutcomeV1::Clean => Ok(ScanOutcome::Clean),
            OutcomeV1::Skipped { reason } => Ok(ScanOutcome::Skipped { reason: reason.to_model() }),
            OutcomeV1::Error { message } => Ok(ScanOutcome::Error { message: message.clone() }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionV1 {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

impl DetectionV1 {
    pub fn from_model(model: &Detection) -> Self {
        Self { name: model.name.clone(), link: model.link.clone() }
    }
}

/// Wire form of a skip reason: known reasons as fixed strings, anything else
/// passes through verbatim (scanner-owned vocabulary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipReasonV1(pub String);

impl SkipReasonV1 {
    pub fn from_model(model: &SkipReason) -> Self {
        Self(model.as_str().to_owned())
    }

    pub fn to_model(&self) -> SkipReason {
        match self.0.as_str() {
            "password_protected" => SkipReason::PasswordProtected,
            "corrupted" => SkipReason::Corrupted,
            "trusted" => SkipReason::Trusted,
            "oversized" => SkipReason::Oversized,
            other => SkipReason::Other(other.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimingV1 {
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    pub duration_ms: u64,
}

impl TimingV1 {
    pub fn from_model(model: &ScanTiming) -> Self {
        Self {
            started_at: model.started_at,
            finished_at: model.finished_at,
            duration_ms: model.duration.as_millis() as u64,
        }
    }

    pub fn to_model(&self) -> ScanTiming {
        ScanTiming {
            started_at: self.started_at,
            finished_at: self.finished_at,
            duration: Duration::from_millis(self.duration_ms),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReportExtrasV1 {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub archives: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub packers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<String>,
}

impl ReportExtrasV1 {
    pub fn from_model(model: &ReportExtras) -> Self {
        Self {
            archives: model.archives.clone(),
            packers: model.packers.clone(),
            raw: model.raw.clone(),
        }
    }

    pub fn to_model(&self) -> ReportExtras {
        ReportExtras {
            archives: self.archives.clone(),
            packers: self.packers.clone(),
            raw: self.raw.clone(),
        }
    }

    fn is_empty(&self) -> bool {
        self.archives.is_empty() && self.packers.is_empty() && self.raw.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn request() -> SampleRequest {
        SampleRequest {
            sample_id: SampleId::new("s-1").unwrap(),
            url: "http://art:8080/samples/abc".to_owned(),
            sha256: Sha256Digest::from_hex(
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            )
            .unwrap(),
            size: 1337,
            priority: Priority::High,
            report_dest: ReportDest::new("vs.scan.reports.session.s-1").unwrap(),
            correlation_id: CorrelationId::new("corr-1").unwrap(),
            extensions: vec!["exe".to_owned()],
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn request_round_trip() {
        let dto = SampleRequestV1::from_model(&request());
        let json = serde_json::to_string(&dto).unwrap();
        let back: SampleRequestV1 = serde_json::from_str(&json).unwrap();
        let model = back.to_model().unwrap();
        assert_eq!(model.sample_id, request().sample_id);
        assert_eq!(model.sha256, request().sha256);
        assert_eq!(model.priority, Priority::High);
        assert_eq!(model.extensions, vec!["exe".to_owned()]);
    }

    #[test]
    fn request_rejects_bad_schema() {
        let mut dto = SampleRequestV1::from_model(&request());
        dto.schema = 99;
        assert!(dto.to_model().is_err());
    }

    #[test]
    fn request_rejects_bad_url_and_priority() {
        let mut dto = SampleRequestV1::from_model(&request());
        dto.url = "ftp://nope".to_owned();
        assert!(dto.to_model().is_err());
        let mut dto = SampleRequestV1::from_model(&request());
        dto.priority = "urgent".to_owned();
        assert!(dto.to_model().is_err());
    }

    #[test]
    fn request_json_shape_is_stable() {
        let dto = SampleRequestV1::from_model(&request());
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["schema"], 1);
        assert_eq!(json["priority"], "high");
        assert_eq!(
            json["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(json.get("report_dest").is_some());
    }

    fn report(outcome: ScanOutcome) -> ScanReport {
        ScanReport {
            sample_id: SampleId::new("s-1").unwrap(),
            correlation_id: CorrelationId::new("corr-1").unwrap(),
            scanner: ScannerId::new("clamd").unwrap(),
            report_dest: ReportDest::new("vs.scan.reports.session.s-1").unwrap(),
            worker: WorkerInfo {
                hostname: "clamd.sandbox".to_owned(),
                os: "Linux 6.1".to_owned(),
                role: WorkerRole::Sandbox,
            },
            av: Some(AvProfile {
                av_name: "ClamAV".to_owned(),
                av_version: Some("1.0".to_owned()),
                ..Default::default()
            }),
            outcome,
            extras: ReportExtras {
                archives: ["zip".to_owned()].into_iter().collect(),
                packers: Default::default(),
                raw: vec![],
            },
            timing: ScanTiming {
                started_at: time::OffsetDateTime::UNIX_EPOCH,
                finished_at: time::OffsetDateTime::UNIX_EPOCH,
                duration: Duration::from_millis(1500),
            },
            attempt: 2,
        }
    }

    fn dest() -> ReportDest {
        ReportDest::new("vs.scan.reports.session.s-1").unwrap()
    }

    #[test]
    fn report_round_trips_all_outcomes() {
        for outcome in [
            ScanOutcome::Clean,
            ScanOutcome::Detected {
                detections: vec![Detection { name: "Win.Test".to_owned(), link: None }],
            },
            ScanOutcome::Skipped { reason: SkipReason::PasswordProtected },
            ScanOutcome::Skipped { reason: SkipReason::Other("encrypted_doc".to_owned()) },
            ScanOutcome::Error { message: "boom".to_owned() },
        ] {
            let expected = report(outcome.clone());
            let dto = ScanReportV1::from_model(&expected);
            let json = serde_json::to_string(&dto).unwrap();
            let back: ScanReportV1 = serde_json::from_str(&json).unwrap();
            assert_eq!(back.to_model(dest()).unwrap(), expected);
        }
    }

    #[test]
    fn outcome_wire_shape() {
        let detected = serde_json::to_value(OutcomeV1::from_model(&ScanOutcome::Detected {
            detections: vec![Detection { name: "Win.Test".to_owned(), link: None }],
        }))
        .unwrap();
        assert_eq!(detected["type"], "detected");
        assert_eq!(detected["detections"][0]["name"], "Win.Test");

        let skipped = serde_json::to_value(OutcomeV1::from_model(&ScanOutcome::Skipped {
            reason: SkipReason::PasswordProtected,
        }))
        .unwrap();
        assert_eq!(skipped["type"], "skipped");
        assert_eq!(skipped["reason"], "password_protected");
    }

    #[test]
    fn empty_fields_omitted() {
        let mut model = report(ScanOutcome::Clean);
        model.extras.archives.clear();
        model.av = None;
        let json = serde_json::to_value(ScanReportV1::from_model(&model)).unwrap();
        assert!(json.get("av").is_none());
        assert!(json.get("extras").is_none());
    }

    #[test]
    fn topology_names() {
        let scanner = ScannerId::new("clamd").unwrap();
        assert_eq!(request_queue_name(&scanner), "vs.scan.requests.clamd");
    }
}

#[cfg(test)]
mod review_tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    #[test]
    fn session_report_wildcard_matches_multi_token_sample_ids() {
        // Sample ids may contain dots (they are file names); the tail wildcard
        // must be `>` (one-or-more tokens), not `*` (exactly one), or reports
        // for ids like `eicar2.bin` would be invisible to the session waiter.
        let wildcard = nats_report_session_wildcard("sess-1");
        assert!(wildcard.ends_with(".>"), "{wildcard}");
        assert!(!wildcard.ends_with(".*"));
        assert_eq!(wildcard, format!("{REPORTS_SUBJECT_ROOT}sess-1.>"));
    }
}
