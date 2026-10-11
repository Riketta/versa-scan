//! Submit session: store samples, publish one request per (sample,
//! scanner), collect reports until all answered or the timeout hits.
//!
//! Ordering contract: the report listener is opened BEFORE any request is
//! published (a worker can finish a debug scan in milliseconds; a report
//! for an unlistened destination would be lost on RabbitMQ and missed on
//! NATS).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use versa_scan_core::models::ids::{SampleId, ScannerId};
use versa_scan_core::models::priority::Priority;
use versa_scan_core::models::report::ScanReport;
use versa_scan_core::models::sample::{ReportDest, SampleRequest};
use versa_scan_core::models::verdict::ScanOutcome;
use versa_scan_core::ports::driven::request_publisher::{PublishError, RequestPublisherPort};

use crate::reports_log::ReportsLog;
use crate::store::SampleStore;
use versa_scan_infra::inbound_adapters::reports::ReportWaiter;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("store error: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("publish failed: {0}")]
    Publish(#[from] PublishError),
    #[error("report listener failed: {0}")]
    Listener(#[from] versa_scan_infra::inbound_adapters::ListenerError),
    #[error("reports log error: {0}")]
    Log(#[from] crate::reports_log::ReportsLogError),
    #[error("read error for {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone)]
pub struct SubmitOptions {
    /// Resolved scanner slugs (one request per sample per slug).
    pub scanners: Vec<String>,
    pub priority: Priority,
    /// `None` = fire-and-forget; `Some(timeout)` = collect reports.
    pub wait_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct ResultRow {
    pub file: String,
    pub sample_id: SampleId,
    pub scanner: String,
    /// `None` = no report arrived before the timeout.
    pub outcome: Option<ScanOutcome>,
}

pub struct SessionResult {
    pub rows: Vec<ResultRow>,
    /// Every report received during the wait (for the local log).
    pub reports: Vec<ScanReport>,
    /// Rows without a report.
    pub missing: usize,
}

struct Pending {
    file: String,
    sample_id: SampleId,
    sha256: String,
    size: u64,
}

pub struct Session {
    store: Arc<SampleStore>,
    request_publisher: Arc<dyn RequestPublisherPort>,
    waiter: Option<Arc<dyn ReportWaiter>>,
    advertise_base: String,
    /// Artifact-server token appended to every sample URL (`?token=`); the
    /// server rejects requests without it when it is configured. Empty =
    /// auth disabled.
    artifact_token: String,
    /// Per-sample report destination (backend-specific naming).
    report_dest_for: Arc<dyn Fn(&SampleId) -> ReportDest + Send + Sync>,
    /// Where the session's reports arrive (wildcard subject / queue name).
    wait_dest: ReportDest,
}

impl Session {
    pub fn new(
        store: Arc<SampleStore>,
        request_publisher: Arc<dyn RequestPublisherPort>,
        waiter: Option<Arc<dyn ReportWaiter>>,
        advertise_base: String,
        artifact_token: String,
        report_dest_for: Arc<dyn Fn(&SampleId) -> ReportDest + Send + Sync>,
        wait_dest: ReportDest,
    ) -> Self {
        Self {
            store,
            request_publisher,
            waiter,
            advertise_base,
            artifact_token,
            report_dest_for,
            wait_dest,
        }
    }

    pub async fn submit(
        &self,
        inputs: &[PathBuf],
        opts: &SubmitOptions,
        log: Option<&ReportsLog>,
    ) -> Result<SessionResult, SessionError> {
        // 1. Hash + store every input.
        let mut pending: Vec<Pending> = Vec::new();
        for input in inputs {
            let bytes = std::fs::read(input)
                .map_err(|source| SessionError::Read { path: input.clone(), source })?;
            let stored = self.store.put(&bytes)?;
            pending.push(Pending {
                file: file_name(input),
                sample_id: SampleId::new(Uuid::new_v4().to_string()).expect("uuid is a valid id"),
                sha256: stored.sha256,
                size: stored.size,
            });
        }

        // 2. Open the report stream before anything is published.
        let mut stream = match (self.waiter.as_ref(), opts.wait_timeout) {
            (Some(waiter), Some(_)) => Some(waiter.listen(&self.wait_dest).await?),
            _ => None,
        };

        // 3. Publish one request per (sample, scanner).
        let mut expected: Vec<(SampleId, String)> = Vec::new();
        for sample in &pending {
            for scanner in &opts.scanners {
                let request = self.build_request(sample, scanner, &opts.priority);
                self.request_publisher
                    .publish_request(ScannerId::new(scanner).expect("slug validated"), &request)
                    .await?;
                expected.push((sample.sample_id.clone(), scanner.clone()));
            }
        }
        tracing::info!(
            samples = pending.len(),
            scanners = opts.scanners.len(),
            requests = expected.len(),
            "scan requests published"
        );

        // 4. Collect reports until every expected pair is answered.
        let mut outcomes: HashMap<(SampleId, String), ScanOutcome> = HashMap::new();
        let mut reports: Vec<ScanReport> = Vec::new();
        if let (Some(stream), Some(timeout)) = (stream.as_mut(), opts.wait_timeout) {
            let deadline = tokio::time::Instant::now() + timeout;
            while outcomes.len() < expected.len() {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let incoming = match tokio::time::timeout(remaining, stream.next()).await {
                    Err(_elapsed) => break, // deadline hit
                    Ok(None) => {
                        tracing::warn!(
                            received = outcomes.len(),
                            expected = expected.len(),
                            "report stream closed before every report arrived"
                        );
                        break;
                    }
                    Ok(Some(Err(err))) => {
                        tracing::warn!(error = %err, "report stream error; continuing");
                        continue;
                    }
                    Ok(Some(Ok(incoming))) => incoming,
                };
                let report = incoming.report;
                if let Some(log) = log {
                    // Persistence is best-effort: a jsonl io error must not
                    // abort report collection (the table is the product).
                    if let Err(err) = log.append(&report) {
                        tracing::warn!(
                            error = %err,
                            sample_id = %report.sample_id,
                            "failed to persist report to the local log; continuing"
                        );
                    }
                }
                let key = (report.sample_id.clone(), report.scanner.as_str().to_owned());
                if expected.contains(&key) {
                    outcomes.entry(key).or_insert(report.outcome.clone());
                }
                reports.push(report);
            }
        }

        // 5. Assemble rows (file name, then scanner, for stable output).
        let mut rows: Vec<ResultRow> = Vec::new();
        for sample in &pending {
            for scanner in &opts.scanners {
                rows.push(ResultRow {
                    file: sample.file.clone(),
                    sample_id: sample.sample_id.clone(),
                    scanner: scanner.clone(),
                    outcome: outcomes.get(&(sample.sample_id.clone(), scanner.clone())).cloned(),
                });
            }
        }
        rows.sort_by(|a, b| a.file.cmp(&b.file).then(a.scanner.cmp(&b.scanner)));
        let missing = rows.iter().filter(|row| row.outcome.is_none()).count();

        Ok(SessionResult { rows, reports, missing })
    }

    /// Download URL for one stored sample; `?token=` appended when the
    /// artifact server expects one.
    fn sample_url(&self, sha256: &str) -> String {
        let base = format!("{}/samples/{}", self.advertise_base.trim_end_matches('/'), sha256);
        if self.artifact_token.is_empty() {
            base
        } else {
            format!("{base}?token={}", self.artifact_token)
        }
    }

    fn build_request(
        &self,
        sample: &Pending,
        _scanner: &str,
        priority: &Priority,
    ) -> SampleRequest {
        SampleRequest {
            sample_id: sample.sample_id.clone(),
            url: self.sample_url(&sample.sha256),
            sha256: versa_scan_core::models::Sha256Digest::from_hex(&sample.sha256)
                .expect("store digests are valid hex"),
            size: sample.size,
            priority: *priority,
            report_dest: (self.report_dest_for)(&sample.sample_id),
            correlation_id: versa_scan_core::models::CorrelationId::new(Uuid::new_v4().to_string())
                .expect("uuid is a valid id"),
            extensions: Path::new(&sample.file)
                .extension()
                .map(|e| vec![e.to_string_lossy().to_string()])
                .unwrap_or_default(),
            created_at: OffsetDateTime::now_utc(),
        }
        // The scanner slug rides the routing (queue/subject), not the
        // payload; keep `_scanner` referenced for signature clarity.
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string())
}

/// Renders the per-sample/per-scanner result table for terminal output.
pub fn render_table(rows: &[ResultRow]) -> String {
    fn outcome_text(outcome: &Option<ScanOutcome>) -> String {
        match outcome {
            None => "NO REPORT".to_owned(),
            Some(ScanOutcome::Clean) => "clean".to_owned(),
            Some(ScanOutcome::Detected { detections }) if detections.is_empty() => {
                "DETECTED".to_owned()
            }
            Some(ScanOutcome::Detected { detections }) => {
                let names: Vec<String> = detections.iter().map(|d| d.name.clone()).collect();
                format!("DETECTED {}", names.join("; "))
            }
            Some(ScanOutcome::Skipped { reason }) => {
                format!("skipped: {}", reason.as_str())
            }
            Some(ScanOutcome::Error { message }) => format!("ERROR {message}"),
        }
    }

    let file_w = rows.iter().map(|r| r.file.len()).max().unwrap_or(5).max(5);
    let scanner_w = rows.iter().map(|r| r.scanner.len()).max().unwrap_or(7).max(7);
    let mut out = String::new();
    out.push_str(&format!("{:<file_w$}  {:<scanner_w$}  outcome\n", "sample", "scanner"));
    for row in rows {
        out.push_str(&format!(
            "{:<file_w$}  {:<scanner_w$}  {}\n",
            row.file,
            row.scanner,
            outcome_text(&row.outcome)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use tokio_util::sync::CancellationToken;
    use versa_scan_core::models::Detection;
    use versa_scan_core::models::ScanOutcome;
    use versa_scan_core::models::worker::{WorkerInfo, WorkerRole};
    use versa_scan_core::ports::driven::ReportPublisherPort;
    use versa_scan_core::ports::driving::scan_pipeline::{
        Delivery, ScanPipelinePort as PipelinePort,
    };
    use versa_scan_infra::inbound_adapters::ListenerError;
    use versa_scan_infra::inbound_adapters::bus::in_memory::pair;
    use versa_scan_infra::inbound_adapters::reports::{
        BoxReportStream, IncomingReport, ReportItem, ReportStream,
    };
    use versa_scan_infra::outbound_adapters::bus::in_memory::InMemoryPublisher;

    // -------- report queue: fake waiter fed by the fake worker --------

    #[derive(Clone, Default)]
    struct ReportQueue {
        inner: Arc<Mutex<VecDeque<IncomingReport>>>,
    }

    impl ReportQueue {
        fn push(&self, report: IncomingReport) {
            self.inner.lock().push_back(report);
        }

        fn pop(&self) -> Option<IncomingReport> {
            self.inner.lock().pop_front()
        }
    }

    struct ChannelWaiter {
        queue: ReportQueue,
    }

    #[async_trait]
    impl ReportWaiter for ChannelWaiter {
        async fn listen(&self, _dest: &ReportDest) -> Result<BoxReportStream, ListenerError> {
            Ok(Box::new(QueueStream { queue: self.queue.clone() }))
        }
    }

    struct QueueStream {
        queue: ReportQueue,
    }

    #[async_trait]
    impl ReportStream for QueueStream {
        async fn next(&mut self) -> Option<ReportItem> {
            // Tests feed the queue from a concurrent fake worker; a short
            // poll loop is simpler and sufficient here.
            loop {
                if let Some(incoming) = self.queue.pop() {
                    return Some(Ok(incoming));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    // -------- fake worker: pipeline that answers every delivery --------

    struct WorkerPipeline {
        publisher: Arc<InMemoryPublisher>,
        reports_queue: ReportQueue,
    }

    impl PipelinePort for WorkerPipeline {
        fn ingest(self: Arc<Self>, delivery: Delivery) {
            let publisher = Arc::clone(&self.publisher);
            let reports_queue = self.reports_queue.clone();
            tokio::spawn(async move {
                let report = versa_scan_core::models::ScanReport {
                    sample_id: delivery.request.sample_id.clone(),
                    correlation_id: delivery.request.correlation_id.clone(),
                    scanner: ScannerId::new("debug").unwrap(),
                    report_dest: delivery.request.report_dest.clone(),
                    worker: WorkerInfo {
                        hostname: "worker".to_owned(),
                        os: "os".to_owned(),
                        role: WorkerRole::Sandbox,
                    },
                    av: None,
                    outcome: ScanOutcome::Detected {
                        detections: vec![Detection { name: "Win.Test".to_owned(), link: None }],
                    },
                    extras: Default::default(),
                    timing: versa_scan_core::models::ScanTiming {
                        started_at: time::OffsetDateTime::UNIX_EPOCH,
                        finished_at: time::OffsetDateTime::UNIX_EPOCH,
                        duration: Duration::ZERO,
                    },
                    attempt: 1,
                };
                ReportPublisherPort::publish_report(
                    &*publisher,
                    &report,
                    &delivery.request.report_dest,
                )
                .await
                .unwrap();
                reports_queue
                    .push(IncomingReport { report, dest: delivery.request.report_dest.clone() });
                delivery.handle.ack().await;
            });
        }

        fn stream_ended(&self) {}
    }

    // -------- tests --------

    #[tokio::test]
    async fn fire_and_forget_publishes_per_scanner() {
        let dir = std::env::temp_dir().join(format!("vs-sess-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("mal.exe");
        std::fs::write(&input, b"contents").unwrap();

        let store = Arc::new(SampleStore::open(dir.join("store")).unwrap());
        let (_listener, publisher) = pair();

        let session = Session::new(
            Arc::clone(&store),
            publisher.clone(),
            None,
            "http://127.0.0.1:8080".to_owned(),
            String::new(),
            Arc::new(|id: &SampleId| {
                ReportDest::new(format!("dest.{id}")).expect("generated dests are valid")
            }),
            ReportDest::new("dest.wildcard").unwrap(),
        );

        let result = session
            .submit(
                &[input],
                &SubmitOptions {
                    scanners: vec!["clamd".to_owned(), "defender".to_owned()],
                    priority: Priority::Normal,
                    wait_timeout: None,
                },
                None,
            )
            .await
            .unwrap();

        assert_eq!(result.rows.len(), 2);
        assert!(result.rows.iter().all(|r| r.outcome.is_none()));
        assert_eq!(result.missing, 2);
        assert_eq!(publisher.pending(&ScannerId::new("clamd").unwrap()), 1);
        assert_eq!(publisher.pending(&ScannerId::new("defender").unwrap()), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn wait_collects_reports_and_persists() {
        let dir = std::env::temp_dir().join(format!("vs-sess-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("mal.exe");
        std::fs::write(&input, b"contents").unwrap();

        let store = Arc::new(SampleStore::open(dir.join("store")).unwrap());
        let (listener, publisher) = pair();

        let reports_queue = ReportQueue::default();
        let pipeline = Arc::new(WorkerPipeline {
            publisher: publisher.clone(),
            reports_queue: reports_queue.clone(),
        });

        let cancel = CancellationToken::new();
        {
            let pipeline = Arc::clone(&pipeline);
            let cancel = cancel.clone();
            let scanner_id = ScannerId::new("debug").unwrap();
            tokio::spawn(async move {
                versa_scan_infra::inbound_adapters::bus::BusListener::run(
                    &*listener, scanner_id, pipeline, cancel,
                )
                .await
            });
        }

        let reports_log = ReportsLog::open(dir.join("store").as_path()).unwrap();
        let waiter: Arc<dyn ReportWaiter> = Arc::new(ChannelWaiter { queue: reports_queue });

        let session = Session::new(
            Arc::clone(&store),
            publisher.clone(),
            Some(waiter),
            "http://127.0.0.1:8080".to_owned(),
            String::new(),
            Arc::new(|id: &SampleId| {
                ReportDest::new(format!("dest.{id}")).expect("generated dests are valid")
            }),
            ReportDest::new("dest.wildcard").unwrap(),
        );

        let result = session
            .submit(
                &[dir.join("mal.exe")],
                &SubmitOptions {
                    scanners: vec!["debug".to_owned()],
                    priority: Priority::Normal,
                    wait_timeout: Some(Duration::from_secs(5)),
                },
                Some(&reports_log),
            )
            .await
            .unwrap();

        assert_eq!(result.missing, 0, "the fake worker answers every request");
        assert_eq!(result.rows.len(), 1);
        assert!(matches!(result.rows[0].outcome, Some(ScanOutcome::Detected { .. })));

        let persisted = reports_log.load().unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].sample_id, result.rows[0].sample_id);

        let table = render_table(&result.rows);
        assert!(table.contains("DETECTED Win.Test"));

        cancel.cancel();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn timeout_marks_rows_missing() {
        let dir = std::env::temp_dir().join(format!("vs-sess-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("quiet.exe");
        std::fs::write(&input, b"contents").unwrap();

        let store = Arc::new(SampleStore::open(dir.join("store")).unwrap());
        let (listener, publisher) = pair();

        // A pipeline that never answers: the wait must hit the deadline and
        // mark the row missing (with a requeue, the request is not lost).
        struct SilentPipeline;
        impl PipelinePort for SilentPipeline {
            fn ingest(self: Arc<Self>, delivery: Delivery) {
                tokio::spawn(async move { delivery.handle.nak_requeue().await });
            }
            fn stream_ended(&self) {}
        }

        let cancel = CancellationToken::new();
        {
            let cancel = cancel.clone();
            let scanner_id = ScannerId::new("debug").unwrap();
            tokio::spawn(async move {
                versa_scan_infra::inbound_adapters::bus::BusListener::run(
                    &*listener,
                    scanner_id,
                    Arc::new(SilentPipeline),
                    cancel,
                )
                .await
            });
        }

        let reports_log = ReportsLog::open(dir.join("store").as_path()).unwrap();
        let waiter: Arc<dyn ReportWaiter> =
            Arc::new(ChannelWaiter { queue: ReportQueue::default() });

        let session = Session::new(
            Arc::clone(&store),
            publisher.clone(),
            Some(waiter),
            "http://127.0.0.1:8080".to_owned(),
            String::new(),
            Arc::new(|id: &SampleId| {
                ReportDest::new(format!("dest.{id}")).expect("generated dests are valid")
            }),
            ReportDest::new("dest.wildcard").unwrap(),
        );

        let result = session
            .submit(
                &[input],
                &SubmitOptions {
                    scanners: vec!["debug".to_owned()],
                    priority: Priority::Normal,
                    wait_timeout: Some(Duration::from_millis(150)),
                },
                Some(&reports_log),
            )
            .await
            .unwrap();

        assert_eq!(result.missing, 1);
        assert_eq!(result.rows[0].outcome, None);
        assert!(reports_log.load().unwrap().is_empty());

        cancel.cancel();
        std::fs::remove_dir_all(&dir).ok();
    }
}
