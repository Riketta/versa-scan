//! The orchestrator: consume -> plan -> fetch -> scan -> validate -> report
//! -> settle, with guaranteed workspace cleanup and publish-then-ack
//! ordering (the structural fix for the C# system's ack-before-publish loss
//! window).
//!
//! Error philosophy: nothing is silently dropped. Every delivery ends in
//! exactly one of: `ack` (report confirmed published), `nak_requeue`
//! (bounded by the retry policy), or `discard` (terminal - an error report
//! was published first, whenever publishing was possible).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::models::batch::BatchFile;
use crate::models::ids::SampleId;
use crate::models::report::{ReportExtras, ScanReport, ScanTiming};
use crate::models::sample::SampleRequest;
use crate::models::verdict::ScanOutcome;
use crate::models::worker::WorkerInfo;
use crate::ports::bus::{BusError, BusPort, Delivery, DeliveryHandle, RequestStream};
use crate::ports::fetch::{FetchError, FetchedFile, SampleFetcherPort};
use crate::ports::scanner::{ScannerError, ScannerPort};
use crate::services::planner::{BatchPlanner, PlannerEvent};
use crate::services::retry::{Disposition, Failure, RetryPolicy};
use crate::services::validation::reconcile;
use crate::services::workspace::WorkspaceManager;

/// Pipeline tuning knobs (worker config maps onto these).
#[derive(Debug, Clone)]
pub struct OrchestratorSettings {
    pub files_per_batch: usize,
    /// How long an open batch waits for more requests before flushing.
    pub batch_idle_timeout: Duration,
    pub scan_timeout: Duration,
    pub fetch_concurrency: usize,
    /// Cooldown after a scanner-unavailable failure before reconnecting.
    pub scanner_backoff: Duration,
}

impl Default for OrchestratorSettings {
    fn default() -> Self {
        Self {
            files_per_batch: 10,
            batch_idle_timeout: Duration::from_millis(250),
            scan_timeout: Duration::from_secs(15 * 60),
            fetch_concurrency: 4,
            scanner_backoff: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("workspace setup failed: {0}")]
    Workspace(#[from] crate::services::workspace::WorkspaceError),
}

/// Broker delivery record kept while a delivery is inside the planner.
struct DeliveryRecord {
    attempt: u8,
    handle: Arc<dyn DeliveryHandle>,
}

enum Incoming {
    Delivery(Result<Delivery, BusError>),
    Idle,
    Closed,
    Cancelled,
}

pub struct Orchestrator {
    scanner: Arc<dyn ScannerPort>,
    fetcher: Arc<dyn SampleFetcherPort>,
    bus: Arc<dyn BusPort>,
    workspace: WorkspaceManager,
    retry: RetryPolicy,
    settings: OrchestratorSettings,
    worker: WorkerInfo,
}

impl Orchestrator {
    pub fn new(
        scanner: Arc<dyn ScannerPort>,
        fetcher: Arc<dyn SampleFetcherPort>,
        bus: Arc<dyn BusPort>,
        workspace_root: std::path::PathBuf,
        settings: OrchestratorSettings,
        worker: WorkerInfo,
    ) -> Result<Self, OrchestratorError> {
        let workspace = WorkspaceManager::new(workspace_root)?;
        Ok(Self {
            scanner,
            fetcher,
            bus,
            workspace,
            retry: RetryPolicy::default(),
            settings,
            worker,
        })
    }

    /// Runs until cancelled. Connection failures are retried with backoff;
    /// only cancellation ends the loop permanently.
    pub async fn run(self: Arc<Self>, cancel: CancellationToken) {
        // Leftovers from a previous crashed run are not scannable state.
        match self.workspace.sweep() {
            Ok(n) if n > 0 => tracing::warn!(count = n, "swept leftover batch workspaces"),
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %err, "workspace sweep failed"),
        }

        let mut backoff = Duration::from_secs(1);
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match self.bus.consume_requests(self.scanner.id()).await {
                Ok(mut stream) => {
                    tracing::info!(scanner = %self.scanner.id(), "consuming scan requests");
                    backoff = Duration::from_secs(1);
                    self.pump(&mut stream, &cancel).await;
                }
                Err(err) => tracing::warn!(error = %err, "bus consume failed; will retry"),
            }
            if cancel.is_cancelled() {
                break;
            }
            if !sleep_cancel(&cancel, backoff).await {
                break;
            }
            backoff = backoff.saturating_mul(2).min(Duration::from_secs(30));
        }
        tracing::info!(scanner = %self.scanner.id(), "orchestrator stopped");
    }

    /// One consume session: fills batches from the stream and processes each
    /// ready batch inline (highest priority first by planner design).
    async fn pump(&self, stream: &mut Box<dyn RequestStream>, cancel: &CancellationToken) {
        let mut planner = BatchPlanner::new(self.settings.files_per_batch);
        let mut ledger: HashMap<SampleId, DeliveryRecord> = HashMap::new();

        loop {
            if cancel.is_cancelled() {
                break;
            }
            let with_idle = planner.open_priority().is_some();
            match self.next_incoming(stream, cancel, with_idle).await {
                Incoming::Cancelled => break,
                Incoming::Idle => {
                    let event = planner.flush();
                    self.emit(&mut ledger, event, cancel).await;
                }
                Incoming::Closed => {
                    let event = planner.flush();
                    self.emit(&mut ledger, event, cancel).await;
                    self.drain_nak(&mut ledger).await;
                    return;
                }
                Incoming::Delivery(Ok(delivery)) => {
                    // Duplicate guard: a broker redelivery of a request whose
                    // twin is still batched. The original copy will be
                    // scanned and reported; the twin is discarded so it
                    // cannot loop redeliveries.
                    let id = delivery.request.sample_id.clone();
                    if ledger.contains_key(&id) || planner.contains(&id) {
                        tracing::warn!(
                            sample_id = %id,
                            "duplicate delivery while original is in flight; discarding twin"
                        );
                        delivery.handle.discard().await;
                        continue;
                    }
                    let Delivery { request, attempt, handle } = delivery;
                    ledger.insert(request.sample_id.clone(), DeliveryRecord { attempt, handle });
                    let event = planner.feed(request);
                    for id in &event.rejected {
                        // Defensive: the guard above makes this unreachable;
                        // settle anyway so nothing leaks.
                        if let Some(record) = ledger.remove(id) {
                            record.handle.discard().await;
                        }
                    }
                    self.emit(&mut ledger, event, cancel).await;
                }
                Incoming::Delivery(Err(err)) => {
                    tracing::warn!(error = %err, "consume error; flushing and reconnecting");
                    let event = planner.flush();
                    self.emit(&mut ledger, event, cancel).await;
                    self.drain_nak(&mut ledger).await;
                    return;
                }
            }
        }

        // Cancellation: finish what is closed, requeue the rest.
        let event = planner.flush();
        self.emit(&mut ledger, event, cancel).await;
        self.drain_nak(&mut ledger).await;
    }

    async fn next_incoming(
        &self,
        stream: &mut Box<dyn RequestStream>,
        cancel: &CancellationToken,
        with_idle_timeout: bool,
    ) -> Incoming {
        let idle_timeout = self.settings.batch_idle_timeout;
        let idle = async {
            if with_idle_timeout {
                tokio::time::sleep(idle_timeout).await;
                Incoming::Idle
            } else {
                std::future::pending::<Incoming>().await
            }
        };
        let next = stream.next();
        tokio::select! {
            _ = cancel.cancelled() => Incoming::Cancelled,
            _ = idle => Incoming::Idle,
            item = next => match item {
                Some(result) => Incoming::Delivery(result),
                None => Incoming::Closed,
            },
        }
    }

    async fn emit(
        &self,
        ledger: &mut HashMap<SampleId, DeliveryRecord>,
        event: PlannerEvent,
        cancel: &CancellationToken,
    ) {
        for batch in event.ready {
            self.process_batch(batch, ledger, cancel).await;
        }
    }

    /// Naks every still-held delivery (parked batches on shutdown/ reconnect):
    /// the broker redelivers them to a later session.
    async fn drain_nak(&self, ledger: &mut HashMap<SampleId, DeliveryRecord>) {
        for (_, record) in ledger.drain() {
            record.handle.nak_requeue().await;
        }
    }

    async fn process_batch(
        &self,
        batch: crate::models::batch::ScanBatch,
        ledger: &mut HashMap<SampleId, DeliveryRecord>,
        cancel: &CancellationToken,
    ) {
        if batch.is_empty() {
            return;
        }
        tracing::info!(
            batch_id = %batch.id(),
            priority = %batch.priority(),
            files = batch.len(),
            "processing batch"
        );
        let started_at = OffsetDateTime::now_utc();

        let workspace = match self.workspace.create(&batch) {
            Ok(workspace) => workspace,
            Err(err) => {
                tracing::error!(error = %err, "cannot create batch workspace; requeueing");
                self.drain_nak(ledger).await;
                return;
            }
        };
        let _ = cancel; // phases below check cancel between steps

        let files = batch.files().to_vec();
        let fetched = self.fetch_files(&files, &workspace).await;

        let mut ok_files: Vec<BatchFile> = Vec::new();
        for (file, result) in files.into_iter().zip(fetched) {
            match result {
                Ok(_) => ok_files.push(file),
                Err(err) => self.settle_fetch_failure(file, err, ledger, started_at).await,
            }
        }

        if ok_files.is_empty() {
            tracing::info!(batch_id = %batch.id(), "no files fetched; batch skipped");
            return; // workspace drop cleans up
        }

        let av = match self.scanner.profile().await {
            Ok(profile) => Some(profile),
            Err(err) => {
                tracing::warn!(error = %err, "scanner profile unavailable; reports omit AV info");
                None
            }
        };

        let scan = tokio::time::timeout(
            self.settings.scan_timeout,
            self.scanner.scan(workspace.files_dir()),
        )
        .await;

        match scan {
            Err(_) => {
                tracing::error!(
                    batch_id = %batch.id(),
                    timeout = ?self.settings.scan_timeout,
                    "scan timed out; requeueing batch"
                );
                self.requeue_files(&ok_files, ledger).await;
                sleep_cancel(cancel, self.settings.scanner_backoff).await;
            }
            Ok(Err(
                err @ (ScannerError::Unavailable(_)
                | ScannerError::NotInstalled(_)
                | ScannerError::Io(_)),
            )) => {
                tracing::error!(error = %err, "scanner unavailable; requeueing batch");
                self.requeue_files(&ok_files, ledger).await;
                sleep_cancel(cancel, self.settings.scanner_backoff).await;
            }
            Ok(Err(err)) => {
                tracing::error!(error = %err, "scan failed; reporting error per sample");
                let message = err.to_string();
                for file in ok_files {
                    let attempt = ledger
                        .get(&file.request.sample_id)
                        .map(|record| record.attempt)
                        .unwrap_or(0);
                    let report = self.error_report(
                        &file.request,
                        av.clone(),
                        format!("scan failed: {message}"),
                        started_at,
                        attempt,
                    );
                    self.settle_report(&file.request, report, ledger).await;
                }
            }
            Ok(Ok(output)) => {
                let (validated, reconcile_report) = reconcile(&ok_files, &output);
                for unexpected in &reconcile_report.unexpected {
                    tracing::warn!(
                        batch_id = %batch.id(),
                        file = %unexpected,
                        "scanner reported an unexpected file"
                    );
                }
                if reconcile_report.reported != reconcile_report.expected {
                    tracing::warn!(
                        batch_id = %batch.id(),
                        expected = reconcile_report.expected,
                        reported = reconcile_report.reported,
                        "scanned files count mismatch"
                    );
                }
                let finished_at = OffsetDateTime::now_utc();
                let duration = (finished_at - started_at).unsigned_abs();
                for item in validated {
                    let timing = ScanTiming { started_at, finished_at, duration };
                    let attempt = ledger
                        .get(&item.file.request.sample_id)
                        .map(|record| record.attempt)
                        .unwrap_or(0);
                    let report = ScanReport {
                        sample_id: item.file.request.sample_id.clone(),
                        correlation_id: item.file.request.correlation_id.clone(),
                        scanner: self.scanner.id(),
                        report_dest: item.file.request.report_dest.clone(),
                        worker: self.worker.clone(),
                        av: av.clone(),
                        outcome: item.verdict.outcome,
                        extras: ReportExtras {
                            archives: item.verdict.archives,
                            packers: item.verdict.packers,
                            raw: item.verdict.raw,
                        },
                        timing,
                        attempt,
                    };
                    self.settle_report(&item.file.request, report, ledger).await;
                }
            }
        }
        // `workspace` drops here: directory removed, crash or not.
    }

    async fn fetch_files(
        &self,
        files: &[BatchFile],
        workspace: &crate::services::workspace::BatchWorkspace,
    ) -> Vec<Result<FetchedFile, FetchError>> {
        let fetcher = Arc::clone(&self.fetcher);
        futures_util::stream::iter(files.iter().cloned())
            .map(|file| {
                let fetcher = Arc::clone(&fetcher);
                let dest = workspace.files_dir().join(&file.local_name);
                async move { fetcher.fetch(&file.request, &dest).await }
            })
            .buffer_unordered(self.settings.fetch_concurrency.max(1))
            .collect()
            .await
    }

    async fn settle_fetch_failure(
        &self,
        file: BatchFile,
        err: FetchError,
        ledger: &mut HashMap<SampleId, DeliveryRecord>,
        started_at: OffsetDateTime,
    ) {
        let attempt = ledger.get(&file.request.sample_id).map(|record| record.attempt).unwrap_or(1);
        let disposition = self.retry.decide(&Failure::Fetch(err.clone()), attempt);
        tracing::warn!(
            sample_id = %file.request.sample_id,
            error = %err,
            attempt,
            "sample fetch failed"
        );
        match disposition {
            Disposition::Requeue => {
                if let Some(record) = ledger.remove(&file.request.sample_id) {
                    record.handle.nak_requeue().await;
                }
            }
            Disposition::Terminal { message } => {
                let report = self.error_report(&file.request, None, message, started_at, attempt);
                self.settle_report(&file.request, report, ledger).await;
            }
        }
    }

    async fn requeue_files(
        &self,
        files: &[BatchFile],
        ledger: &mut HashMap<SampleId, DeliveryRecord>,
    ) {
        for file in files {
            if let Some(record) = ledger.remove(&file.request.sample_id) {
                record.handle.nak_requeue().await;
            }
        }
    }

    /// Publish-then-settle. Ok publishes confirm before ack; failures follow
    /// the retry policy (requeue while attempts remain).
    async fn settle_report(
        &self,
        request: &SampleRequest,
        report: ScanReport,
        ledger: &mut HashMap<SampleId, DeliveryRecord>,
    ) {
        let record = match ledger.remove(&request.sample_id) {
            Some(record) => record,
            None => {
                tracing::error!(
                    sample_id = %request.sample_id,
                    "no delivery record for report; broker will redeliver"
                );
                return;
            }
        };
        let attempt = record.attempt;
        match self.bus.publish_report(&report, &request.report_dest).await {
            Ok(()) => {
                tracing::info!(sample_id = %request.sample_id, attempt, "report published");
                record.handle.ack().await;
            }
            Err(err) => {
                tracing::warn!(
                    sample_id = %request.sample_id,
                    error = %err,
                    attempt,
                    "report publish failed"
                );
                match self.retry.decide(&Failure::Publish(err.to_string()), attempt) {
                    Disposition::Requeue => record.handle.nak_requeue().await,
                    Disposition::Terminal { .. } => {
                        tracing::error!(
                            sample_id = %request.sample_id,
                            attempt,
                            "publish kept failing; dropping delivery"
                        );
                        record.handle.discard().await;
                    }
                }
            }
        }
    }

    fn error_report(
        &self,
        request: &SampleRequest,
        av: Option<crate::models::av::AvProfile>,
        message: String,
        started_at: OffsetDateTime,
        attempt: u8,
    ) -> ScanReport {
        let now = OffsetDateTime::now_utc();
        ScanReport {
            sample_id: request.sample_id.clone(),
            correlation_id: request.correlation_id.clone(),
            scanner: self.scanner.id(),
            report_dest: request.report_dest.clone(),
            worker: self.worker.clone(),
            av,
            outcome: ScanOutcome::Error { message },
            extras: ReportExtras::default(),
            timing: ScanTiming {
                started_at,
                finished_at: now,
                duration: (now - started_at).unsigned_abs(),
            },
            attempt,
        }
    }
}

/// Returns false when cancelled before the duration elapsed.
async fn sleep_cancel(cancel: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::models::av::AvProfile;
    use crate::models::digest::Sha256Digest;
    use crate::models::ids::{CorrelationId, ScannerId};
    use crate::models::priority::Priority;
    use crate::models::sample::ReportDest;
    use crate::models::verdict::{Detection, FileVerdict, SkipReason};
    use crate::models::worker::WorkerRole;
    use crate::ports::scanner::ScanOutput;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use time::OffsetDateTime;

    // ---------- fakes ----------

    #[derive(Clone, Default)]
    struct FakeHandle {
        ops: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakeHandle {
        fn ops(&self) -> Vec<&'static str> {
            self.ops.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DeliveryHandle for FakeHandle {
        async fn ack(&self) {
            self.ops.lock().unwrap().push("ack");
        }
        async fn nak_requeue(&self) {
            self.ops.lock().unwrap().push("nak");
        }
        async fn discard(&self) {
            self.ops.lock().unwrap().push("discard");
        }
    }

    struct FakeStream {
        queue: Mutex<VecDeque<Delivery>>,
    }

    #[async_trait]
    impl RequestStream for FakeStream {
        async fn next(&mut self) -> Option<Result<Delivery, BusError>> {
            self.queue.lock().unwrap().pop_front().map(Ok)
        }
    }

    struct FakeBus {
        reports: Arc<Mutex<Vec<ScanReport>>>,
        fail_publish: bool,
    }

    #[async_trait]
    impl BusPort for FakeBus {
        async fn publish_request(
            &self,
            _scanner: ScannerId,
            _request: &SampleRequest,
        ) -> Result<(), BusError> {
            Ok(())
        }

        async fn consume_requests(
            &self,
            _scanner: ScannerId,
        ) -> Result<Box<dyn RequestStream>, BusError> {
            Ok(Box::new(FakeStream { queue: Mutex::new(VecDeque::new()) }))
        }

        async fn publish_report(
            &self,
            report: &ScanReport,
            _dest: &ReportDest,
        ) -> Result<(), BusError> {
            if self.fail_publish {
                return Err(BusError::Publish("simulated".to_owned()));
            }
            self.reports.lock().unwrap().push(report.clone());
            Ok(())
        }
    }

    struct FakeFetcher {
        failures: Mutex<HashMap<String, FetchError>>,
    }

    #[async_trait]
    impl SampleFetcherPort for FakeFetcher {
        async fn fetch(
            &self,
            request: &SampleRequest,
            dest: &std::path::Path,
        ) -> Result<FetchedFile, FetchError> {
            if let Some(err) = self.failures.lock().unwrap().get(request.sample_id.as_str()) {
                return Err(err.clone());
            }
            std::fs::write(dest, b"MZ-fake-sample").map_err(|e| FetchError::Io(e.to_string()))?;
            Ok(FetchedFile { path: dest.to_path_buf(), size: 13, digest: request.sha256.clone() })
        }
    }

    fn clone_output(result: &Result<ScanOutput, ScannerError>) -> Result<ScanOutput, ScannerError> {
        match result {
            Ok(output) => Ok(output.clone()),
            Err(err) => Err(err.clone()),
        }
    }

    struct FakeScanner {
        id: ScannerId,
        outputs: Mutex<VecDeque<Result<ScanOutput, ScannerError>>>,
        last: Mutex<Option<Result<ScanOutput, ScannerError>>>,
    }

    impl FakeScanner {
        fn take_result(&self) -> Result<ScanOutput, ScannerError> {
            let popped = self.outputs.lock().unwrap().pop_front();
            match popped {
                Some(result) => {
                    *self.last.lock().unwrap() = Some(clone_output(&result));
                    result
                }
                None => match self.last.lock().unwrap().as_ref() {
                    Some(cached) => clone_output(cached),
                    None => Ok(ScanOutput::default()),
                },
            }
        }
    }

    #[async_trait]
    impl ScannerPort for FakeScanner {
        fn id(&self) -> ScannerId {
            self.id.clone()
        }
        async fn is_installed(&self) -> Result<bool, ScannerError> {
            Ok(true)
        }
        async fn profile(&self) -> Result<AvProfile, ScannerError> {
            Ok(AvProfile { av_name: "FakeAV".to_owned(), ..Default::default() })
        }
        async fn scan(&self, _dir: &std::path::Path) -> Result<ScanOutput, ScannerError> {
            self.take_result()
        }
        async fn update(&self) -> Result<crate::ports::UpdateOutcome, ScannerError> {
            Ok(crate::ports::UpdateOutcome::UpToDate)
        }
    }

    // ---------- helpers ----------

    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn request(id: &str) -> SampleRequest {
        SampleRequest {
            sample_id: SampleId::new(id).unwrap(),
            url: format!("http://art/samples/{id}"),
            sha256: Sha256Digest::from_hex(DIGEST).unwrap(),
            size: 13,
            priority: Priority::Normal,
            report_dest: ReportDest::new("reports"),
            correlation_id: CorrelationId::new("corr").unwrap(),
            extensions: vec![],
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn delivery(id: &str, attempt: u8, handle: FakeHandle) -> Delivery {
        Delivery { request: request(id), attempt, handle: Arc::new(handle) }
    }

    fn worker() -> WorkerInfo {
        WorkerInfo {
            hostname: "test-host".to_owned(),
            os: "TestOS 1.0".to_owned(),
            role: WorkerRole::Sandbox,
        }
    }

    fn settings() -> OrchestratorSettings {
        OrchestratorSettings {
            files_per_batch: 3,
            batch_idle_timeout: Duration::from_millis(30),
            scan_timeout: Duration::from_secs(5),
            fetch_concurrency: 2,
            scanner_backoff: Duration::from_millis(10),
        }
    }

    fn verdict_clean() -> FileVerdict {
        FileVerdict::default()
    }

    fn verdict_detected(name: &str) -> FileVerdict {
        FileVerdict {
            outcome: ScanOutcome::Detected {
                detections: vec![Detection { name: name.to_owned(), link: None }],
            },
            ..Default::default()
        }
    }

    fn clean_output(names: &[&str]) -> ScanOutput {
        ScanOutput { entries: names.iter().map(|n| ((*n).to_owned(), verdict_clean())).collect() }
    }

    struct Rig {
        reports: Arc<Mutex<Vec<ScanReport>>>,
        orch: Arc<Orchestrator>,
        root: std::path::PathBuf,
    }

    fn rig(
        scanner_outputs: VecDeque<Result<ScanOutput, ScannerError>>,
        fetch_failures: HashMap<String, FetchError>,
        fail_publish: bool,
    ) -> Rig {
        let reports = Arc::new(Mutex::new(Vec::new()));
        let root = std::env::temp_dir().join(format!("vs-orch-{}", uuid::Uuid::new_v4()));
        let scanner = FakeScanner {
            id: ScannerId::new("fake").unwrap(),
            outputs: Mutex::new(scanner_outputs),
            last: Mutex::new(None),
        };
        let orch = Arc::new(
            Orchestrator::new(
                Arc::new(scanner),
                Arc::new(FakeFetcher { failures: Mutex::new(fetch_failures) }),
                Arc::new(FakeBus { reports: Arc::clone(&reports), fail_publish }),
                root.clone(),
                settings(),
                worker(),
            )
            .unwrap(),
        );
        Rig { reports, orch, root }
    }

    async fn pump_all(rig: &Rig, deliveries: Vec<Delivery>) {
        let mut stream: Box<dyn RequestStream> =
            Box::new(FakeStream { queue: Mutex::new(deliveries.into_iter().collect()) });
        let cancel = CancellationToken::new();
        rig.orch.pump(&mut stream, &cancel).await;
    }

    fn root_is_clean(root: &std::path::Path) -> bool {
        std::fs::read_dir(root).map(|mut entries| entries.next().is_none()).unwrap_or(true)
    }

    // ---------- tests ----------

    #[tokio::test]
    async fn happy_path_reports_and_acks() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(ScanOutput {
            entries: vec![
                ("clean1".to_owned(), verdict_clean()),
                ("bad1".to_owned(), verdict_detected("Win.Test")),
            ],
        }));
        let rig = rig(outputs, HashMap::new(), false);

        let h1 = FakeHandle::default();
        let h2 = FakeHandle::default();
        pump_all(&rig, vec![delivery("clean1", 1, h1.clone()), delivery("bad1", 1, h2.clone())])
            .await;

        let reports = rig.reports.lock().unwrap().clone();
        assert_eq!(reports.len(), 2);
        for report in &reports {
            assert_eq!(report.scanner.as_str(), "fake");
            assert_eq!(report.av.as_ref().unwrap().av_name, "FakeAV");
            assert_eq!(report.worker.hostname, "test-host");
            assert_eq!(report.attempt, 1);
        }
        let clean = reports.iter().find(|r| r.sample_id.as_str() == "clean1").unwrap();
        assert_eq!(clean.outcome, ScanOutcome::Clean);
        let bad = reports.iter().find(|r| r.sample_id.as_str() == "bad1").unwrap();
        assert!(matches!(bad.outcome, ScanOutcome::Detected { .. }));

        assert_eq!(h1.ops(), vec!["ack"]);
        assert_eq!(h2.ops(), vec!["ack"]);
        assert!(root_is_clean(&rig.root), "workspace must be cleaned up");
    }

    #[tokio::test]
    async fn full_batch_closes_and_remainder_flushes() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(clean_output(&["a", "b", "c"])));
        outputs.push_back(Ok(clean_output(&["d"])));
        let rig = rig(outputs, HashMap::new(), false);

        let handles: Vec<FakeHandle> = (0..4).map(|_| FakeHandle::default()).collect();
        let deliveries = vec![
            delivery("a", 1, handles[0].clone()),
            delivery("b", 1, handles[1].clone()),
            delivery("c", 1, handles[2].clone()),
            delivery("d", 1, handles[3].clone()),
        ];
        pump_all(&rig, deliveries).await;

        let reports = rig.reports.lock().unwrap();
        assert_eq!(reports.len(), 4, "two scans: full batch of 3 + flushed remainder");
        for handle in &handles {
            assert_eq!(handle.ops(), vec!["ack"]);
        }
        drop(reports);
        assert!(root_is_clean(&rig.root));
    }

    #[tokio::test]
    async fn fetch_terminal_error_reports_and_discards() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(clean_output(&["good"])));
        let mut failures = HashMap::new();
        failures.insert("bad".to_owned(), FetchError::NotFound);
        let rig = rig(outputs, failures, false);

        let good_handle = FakeHandle::default();
        let bad_handle = FakeHandle::default();
        pump_all(
            &rig,
            vec![delivery("good", 1, good_handle.clone()), delivery("bad", 1, bad_handle.clone())],
        )
        .await;

        let reports = rig.reports.lock().unwrap();
        assert_eq!(reports.len(), 2, "clean report + terminal fetch error report");
        let bad_report = reports.iter().find(|r| r.sample_id.as_str() == "bad").unwrap();
        assert!(matches!(bad_report.outcome, ScanOutcome::Error { .. }));
        assert!(bad_report.av.is_none(), "no scan happened for a fetch failure");
        let good_report = reports.iter().find(|r| r.sample_id.as_str() == "good").unwrap();
        assert_eq!(good_report.outcome, ScanOutcome::Clean);
        drop(reports);

        assert_eq!(good_handle.ops(), vec!["ack"]);
        assert_eq!(bad_handle.ops(), vec!["ack"], "terminal error was reported, so ack");
        assert!(root_is_clean(&rig.root));
    }

    #[tokio::test]
    async fn fetch_transient_error_requeues() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(clean_output(&["good"])));
        let mut failures = HashMap::new();
        failures.insert("bad".to_owned(), FetchError::Io("conn reset".to_owned()));
        let rig = rig(outputs, failures, false);

        let bad_handle = FakeHandle::default();
        pump_all(&rig, vec![delivery("bad", 1, bad_handle.clone())]).await;

        assert!(rig.reports.lock().unwrap().is_empty());
        assert_eq!(bad_handle.ops(), vec!["nak"]);
        assert!(root_is_clean(&rig.root));
    }

    #[tokio::test]
    async fn scanner_unavailable_requeues_whole_batch() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Err(ScannerError::Unavailable("clamd down".to_owned())));
        let rig = rig(outputs, HashMap::new(), false);

        let h1 = FakeHandle::default();
        let h2 = FakeHandle::default();
        pump_all(&rig, vec![delivery("a", 1, h1.clone()), delivery("b", 1, h2.clone())]).await;

        assert!(rig.reports.lock().unwrap().is_empty());
        assert_eq!(h1.ops(), vec!["nak"]);
        assert_eq!(h2.ops(), vec!["nak"]);
        assert!(root_is_clean(&rig.root));
    }

    #[tokio::test]
    async fn scan_failure_reports_error_and_acks() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Err(ScannerError::ScanFailed("boom".to_owned())));
        let rig = rig(outputs, HashMap::new(), false);

        let handle = FakeHandle::default();
        pump_all(&rig, vec![delivery("a", 1, handle.clone())]).await;

        let reports = rig.reports.lock().unwrap();
        assert_eq!(reports.len(), 1);
        match &reports[0].outcome {
            ScanOutcome::Error { message } => assert!(message.contains("boom")),
            other => panic!("expected error outcome, got {other:?}"),
        }
        drop(reports);
        assert_eq!(handle.ops(), vec!["ack"]);
    }

    #[tokio::test]
    async fn publish_failure_requeues_while_attempts_remain() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(clean_output(&["a"])));
        let rig = rig(outputs, HashMap::new(), true);

        let handle = FakeHandle::default();
        pump_all(&rig, vec![delivery("a", 1, handle.clone())]).await;

        assert!(rig.reports.lock().unwrap().is_empty());
        assert_eq!(handle.ops(), vec!["nak"]);
    }

    #[tokio::test]
    async fn skipped_verdict_round_trips() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(ScanOutput {
            entries: vec![(
                "locked".to_owned(),
                FileVerdict {
                    outcome: ScanOutcome::Skipped { reason: SkipReason::PasswordProtected },
                    ..Default::default()
                },
            )],
        }));
        let rig = rig(outputs, HashMap::new(), false);

        let handle = FakeHandle::default();
        pump_all(&rig, vec![delivery("locked", 1, handle.clone())]).await;

        let reports = rig.reports.lock().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].outcome,
            ScanOutcome::Skipped { reason: SkipReason::PasswordProtected }
        );
        drop(reports);
        assert_eq!(handle.ops(), vec!["ack"]);
    }

    #[tokio::test]
    async fn duplicate_delivery_twin_is_discarded() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(clean_output(&["a"])));
        let rig = rig(outputs, HashMap::new(), false);

        let first = FakeHandle::default();
        let twin = FakeHandle::default();
        pump_all(&rig, vec![delivery("a", 1, first.clone()), delivery("a", 2, twin.clone())]).await;

        let reports = rig.reports.lock().unwrap();
        assert_eq!(reports.len(), 1, "one scan, one report");
        drop(reports);
        assert_eq!(first.ops(), vec!["ack"]);
        assert_eq!(twin.ops(), vec!["discard"]);
    }
}
