//! The orchestrator: the pipeline brain behind [`ScanPipelinePort`].
//! ingest -> plan -> fetch -> scan -> validate -> report -> settle, with
//! guaranteed workspace cleanup and publish-then-ack ordering (acking
//! before the report is confirmed published would open a message-loss
//! window).
//!
//! Direction of dependencies: implements the DRIVING port
//! (`ScanPipelinePort`) - an inbound bus listener feeds it deliveries - and
//! calls DRIVEN ports (`ScannerPort`, `SampleFetcherPort`,
//! `ReportPublisherPort`) to do the work.
//!
//! Error philosophy: nothing is silently dropped. Every delivery ends in
//! exactly one of: `ack` (report confirmed published), `nak_requeue`
//! (bounded by the retry policy), or `discard` (terminal - an error report
//! went out first, whenever publishing was possible).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use parking_lot::Mutex;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::models::batch::BatchFile;
use crate::models::ids::SampleId;
use crate::models::report::{ReportExtras, ScanReport, ScanTiming};
use crate::models::sample::SampleRequest;
use crate::models::verdict::ScanOutcome;
use crate::models::worker::WorkerInfo;
use crate::ports::driven::fetch::{FetchError, FetchedFile, SampleFetcherPort};
use crate::ports::driven::report_publisher::ReportPublisherPort;
use crate::ports::driven::scanner::{ScannerError, ScannerPort};
use crate::ports::driving::scan_pipeline::{Delivery, DeliveryHandle, ScanPipelinePort};
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
    /// Cooldown after a scanner-unavailable failure before the next batch.
    pub scanner_backoff: Duration,
    /// Attempt cap for scanner-unavailable batches before they get error
    /// reports. Higher than the fetch/publish cap: an AV daemon restart is
    /// worth tolerating longer, but it is still bounded (nothing loops
    /// forever).
    pub scanner_max_attempts: u8,
}

impl Default for OrchestratorSettings {
    fn default() -> Self {
        Self {
            files_per_batch: 10,
            batch_idle_timeout: Duration::from_millis(250),
            scan_timeout: Duration::from_secs(15 * 60),
            fetch_concurrency: 4,
            scanner_backoff: Duration::from_secs(10),
            scanner_max_attempts: crate::services::retry::RetryPolicy::DEFAULT_SCANNER_MAX_ATTEMPTS,
        }
    }
}

/// How long a twin delivery (duplicate of one still being processed) waits
/// before its redelivery. Delayed, not discarded: the original normally
/// settles first, and discarding would lose the sample if the original's
/// worker died right after.
pub const TWIN_REQUEUE_DELAY: Duration = Duration::from_secs(60);

/// Upper bound for the per-batch `profile()` call. Metadata must never stall
/// the pipeline; a slow engine degrades reports (`av: None`) instead.
const PROFILE_TIMEOUT_CAP: Duration = Duration::from_secs(60);

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

enum PipelineEvent {
    Delivery(Delivery),
    StreamEnded,
}

pub struct Orchestrator {
    scanner: Arc<dyn ScannerPort>,
    fetcher: Arc<dyn SampleFetcherPort>,
    report_publisher: Arc<dyn ReportPublisherPort>,
    workspace: WorkspaceManager,
    retry: RetryPolicy,
    settings: OrchestratorSettings,
    worker: WorkerInfo,
    events_tx: mpsc::UnboundedSender<PipelineEvent>,
    events_rx: Mutex<Option<mpsc::UnboundedReceiver<PipelineEvent>>>,
}

impl Orchestrator {
    pub fn new(
        scanner: Arc<dyn ScannerPort>,
        fetcher: Arc<dyn SampleFetcherPort>,
        report_publisher: Arc<dyn ReportPublisherPort>,
        workspace_root: std::path::PathBuf,
        settings: OrchestratorSettings,
        worker: WorkerInfo,
    ) -> Result<Self, OrchestratorError> {
        let workspace = WorkspaceManager::new(workspace_root)?;
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let retry = RetryPolicy::default().with_scanner_max_attempts(settings.scanner_max_attempts);
        Ok(Self {
            scanner,
            fetcher,
            report_publisher,
            workspace,
            retry,
            settings,
            worker,
            events_tx,
            events_rx: Mutex::new(Some(events_rx)),
        })
    }

    /// Runs the pipeline until cancelled. Reconnection belongs to the
    /// inbound listener; this loop only reacts to ingested deliveries,
    /// stream-end events, idleness, and cancellation.
    pub async fn run(self: Arc<Self>, cancel: CancellationToken) {
        // Leftovers from a previous crashed run are not scannable state.
        match self.workspace.sweep() {
            Ok(n) if n > 0 => tracing::warn!(count = n, "swept leftover batch workspaces"),
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %err, "workspace sweep failed"),
        }

        let mut rx = match self.events_rx.lock().take() {
            Some(rx) => rx,
            None => {
                tracing::error!("orchestrator run() called twice; refusing");
                return;
            }
        };

        let mut planner = BatchPlanner::new(self.settings.files_per_batch);
        let mut ledger: HashMap<SampleId, DeliveryRecord> = HashMap::new();

        loop {
            if cancel.is_cancelled() {
                break;
            }
            let with_idle = planner.open_priority().is_some();
            let idle = async {
                if with_idle {
                    tokio::time::sleep(self.settings.batch_idle_timeout).await;
                    true
                } else {
                    std::future::pending::<bool>().await
                }
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = idle => {
                    let event = planner.flush();
                    self.emit(&mut ledger, event, &cancel).await;
                }
                item = rx.recv() => match item {
                    None => break,
                    Some(PipelineEvent::Delivery(delivery)) => {
                        self.ingest_delivery(
                            delivery,
                            &mut planner,
                            &mut ledger,
                            &cancel,
                        )
                        .await;
                    }
                    Some(PipelineEvent::StreamEnded) => {
                        tracing::debug!("inbound stream ended; flushing pipeline state");
                        let event = planner.flush();
                        self.emit(&mut ledger, event, &cancel).await;
                        self.drain_nak(&mut ledger).await;
                        planner = BatchPlanner::new(self.settings.files_per_batch);
                    }
                },
            }
        }

        // Cancellation: finish what is closed, requeue the rest.
        let event = planner.flush();
        self.emit(&mut ledger, event, &cancel).await;
        self.drain_nak(&mut ledger).await;
        tracing::info!(scanner = %self.scanner.id(), "orchestrator stopped");
    }

    async fn ingest_delivery(
        &self,
        delivery: Delivery,
        planner: &mut BatchPlanner,
        ledger: &mut HashMap<SampleId, DeliveryRecord>,
        cancel: &CancellationToken,
    ) {
        // Duplicate guard: a broker redelivery of a request whose twin is
        // still batched. The original copy will be scanned and reported; the
        // twin is discarded so it cannot loop redeliveries.
        let id = delivery.request.sample_id.clone();
        if ledger.contains_key(&id) || planner.contains(&id) {
            tracing::warn!(
                sample_id = %id,
                "duplicate delivery while original is in flight; delaying its redelivery"
            );
            delivery.handle.nak_delay(TWIN_REQUEUE_DELAY).await;
            return;
        }
        let Delivery { request, attempt, handle } = delivery;
        ledger.insert(request.sample_id.clone(), DeliveryRecord { attempt, handle });
        let event = planner.feed(request);
        for id in &event.rejected {
            // Defensive: the guard above makes this unreachable; settle
            // anyway so nothing leaks.
            if let Some(record) = ledger.remove(id) {
                record.handle.discard().await;
            }
        }
        self.emit(ledger, event, cancel).await;
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

    /// Naks every still-held delivery (parked batches on stream end or
    /// shutdown): the broker redelivers them to a later session.
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
                tracing::error!(error = %err, "cannot create batch workspace; requeueing batch");
                self.drain_nak(ledger).await;
                return;
            }
        };

        let files = batch.files().to_vec();

        // Cancellation between phases: unstarted work goes back to the
        // broker instead of burning the shutdown grace on a fresh scan.
        if cancel.is_cancelled() {
            self.requeue_files(&files, ledger).await;
            return;
        }

        let fetched = self.fetch_files(&files, &workspace).await;

        let mut ok_files: Vec<BatchFile> = Vec::new();
        for (file, result) in fetched {
            match result {
                Ok(_) => ok_files.push(file),
                Err(err) => self.settle_fetch_failure(file, err, ledger, started_at).await,
            }
        }

        if cancel.is_cancelled() {
            self.requeue_files(&ok_files, ledger).await;
            return; // workspace drop cleans up
        }

        if ok_files.is_empty() {
            tracing::info!(batch_id = %batch.id(), "no files fetched; batch skipped");
            return; // workspace drop cleans up
        }

        let profile_timeout = self.settings.scan_timeout.min(PROFILE_TIMEOUT_CAP);
        let av = match tokio::time::timeout(profile_timeout, self.scanner.profile()).await {
            Ok(Ok(profile)) => Some(profile),
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "scanner profile unavailable; reports omit AV info");
                None
            }
            Err(_) => {
                tracing::warn!(
                    timeout = ?profile_timeout,
                    "scanner profile timed out; reports omit AV info"
                );
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
                self.settle_scanner_unavailable(
                    &batch,
                    &ok_files,
                    ledger,
                    av.clone(),
                    started_at,
                    format!("scan timed out after {:?}", self.settings.scan_timeout),
                    cancel,
                )
                .await;
            }
            Ok(Err(
                err @ (ScannerError::Unavailable(_)
                | ScannerError::NotInstalled(_)
                | ScannerError::Io(_)),
            )) => {
                self.settle_scanner_unavailable(
                    &batch,
                    &ok_files,
                    ledger,
                    av.clone(),
                    started_at,
                    err.to_string(),
                    cancel,
                )
                .await;
            }
            Ok(Err(err)) => {
                tracing::error!(error = %err, "scan failed; reporting error per sample");
                let message = err.to_string();
                for file in ok_files {
                    let attempt =
                        ledger.get(&file.request.sample_id).map_or(0, |record| record.attempt);
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
                    let attempt =
                        ledger.get(&item.file.request.sample_id).map_or(0, |record| record.attempt);
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

    /// Fetches concurrently; results carry their own file - completion
    /// order is arbitrary, so results must never be zipped positionally.
    async fn fetch_files(
        &self,
        files: &[BatchFile],
        workspace: &crate::services::workspace::BatchWorkspace,
    ) -> Vec<(BatchFile, Result<FetchedFile, FetchError>)> {
        let fetcher = Arc::clone(&self.fetcher);
        futures_util::stream::iter(files.iter().cloned())
            .map(|file| {
                let fetcher = Arc::clone(&fetcher);
                let dest = workspace.files_dir().join(&file.local_name);
                // Defense in depth: SampleId is charset-validated at the
                // wire, but a hostile local_name must never escape the
                // batch workspace (id ".." or an absolute path would).
                let in_workspace = dest.starts_with(workspace.files_dir());
                async move {
                    if !in_workspace {
                        return (file, Err(FetchError::Forbidden));
                    }
                    let result = fetcher.fetch(&file.request, &dest).await;
                    (file, result)
                }
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
        let attempt = ledger.get(&file.request.sample_id).map_or(1, |record| record.attempt);
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
                tracing::debug!(
                    sample_id = %file.request.sample_id,
                    attempt = record.attempt,
                    "requeueing delivery"
                );
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
        match self.report_publisher.publish_report(&report, &request.report_dest).await {
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

    /// The scanner could not run (daemon down, service starting, batch
    /// timed out). Bounded requeue via the retry policy's scanner cap -
    /// exhaust it and the samples get error reports instead of looping
    /// forever. Backs off once when anything was requeued.
    async fn settle_scanner_unavailable(
        &self,
        batch: &crate::models::batch::ScanBatch,
        files: &[BatchFile],
        ledger: &mut HashMap<SampleId, DeliveryRecord>,
        av: Option<crate::models::av::AvProfile>,
        started_at: OffsetDateTime,
        detail: String,
        cancel: &CancellationToken,
    ) {
        tracing::warn!(batch_id = %batch.id(), reason = %detail, "scanner unavailable; applying retry policy");
        let mut requeued = 0usize;
        for file in files {
            let attempt = ledger.get(&file.request.sample_id).map_or(1, |record| record.attempt);
            let disposition =
                self.retry.decide(&Failure::ScannerUnavailable(detail.clone()), attempt);
            match disposition {
                Disposition::Requeue => {
                    if let Some(record) = ledger.remove(&file.request.sample_id) {
                        record.handle.nak_requeue().await;
                        requeued += 1;
                    }
                }
                Disposition::Terminal { message } => {
                    let report =
                        self.error_report(&file.request, av.clone(), message, started_at, attempt);
                    self.settle_report(&file.request, report, ledger).await;
                }
            }
        }
        if requeued > 0 {
            sleep_cancel(cancel, self.settings.scanner_backoff).await;
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

impl ScanPipelinePort for Orchestrator {
    fn ingest(self: Arc<Self>, delivery: Delivery) {
        // Unbounded by design: the listener must never stall on the
        // pipeline; prefetch bounds how much the broker pushes anyway.
        let _ = self.events_tx.send(PipelineEvent::Delivery(delivery));
    }

    fn stream_ended(&self) {
        let _ = self.events_tx.send(PipelineEvent::StreamEnded);
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
    use crate::ports::driven::PublishError;
    use crate::ports::driven::ScanOutput;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use time::OffsetDateTime;

    // ---------- fakes ----------

    #[derive(Clone, Default)]
    struct FakeHandle {
        ops: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakeHandle {
        fn ops(&self) -> Vec<&'static str> {
            self.ops.lock().clone()
        }
    }

    #[async_trait]
    impl DeliveryHandle for FakeHandle {
        async fn ack(&self) {
            self.ops.lock().push("ack");
        }
        async fn nak_requeue(&self) {
            self.ops.lock().push("nak");
        }
        async fn discard(&self) {
            self.ops.lock().push("discard");
        }
    }

    struct FakeReportPublisher {
        reports: Arc<Mutex<Vec<ScanReport>>>,
        fail_publish: bool,
    }

    #[async_trait]
    impl ReportPublisherPort for FakeReportPublisher {
        async fn publish_report(
            &self,
            report: &ScanReport,
            _dest: &ReportDest,
        ) -> Result<(), PublishError> {
            if self.fail_publish {
                return Err(PublishError::Publish("simulated".to_owned()));
            }
            self.reports.lock().push(report.clone());
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
            if let Some(err) = self.failures.lock().get(request.sample_id.as_str()) {
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
            let popped = self.outputs.lock().pop_front();
            match popped {
                Some(result) => {
                    *self.last.lock() = Some(clone_output(&result));
                    result
                }
                None => match self.last.lock().as_ref() {
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
        async fn update(&self) -> Result<crate::ports::driven::UpdateOutcome, ScannerError> {
            Ok(crate::ports::driven::UpdateOutcome::UpToDate)
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
            report_dest: ReportDest::new("reports").unwrap(),
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
            scanner_max_attempts: 3,
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
                Arc::new(FakeReportPublisher { reports: Arc::clone(&reports), fail_publish }),
                root.clone(),
                settings(),
                worker(),
            )
            .unwrap(),
        );
        Rig { reports, orch, root }
    }

    fn root_is_clean(root: &std::path::Path) -> bool {
        std::fs::read_dir(root).map_or(true, |mut entries| entries.next().is_none())
    }

    /// Spawns the pipeline, ingests the deliveries, ends the stream, waits
    /// for every delivery to settle, then cancels.
    async fn drive(rig: &Rig, deliveries: Vec<Delivery>, handles: &[FakeHandle]) {
        let cancel = CancellationToken::new();
        let task = {
            let orch = Arc::clone(&rig.orch);
            let cancel = cancel.clone();
            tokio::spawn(async move { orch.run(cancel).await })
        };
        for delivery in deliveries {
            Arc::clone(&rig.orch).ingest(delivery);
        }
        rig.orch.stream_ended();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if handles.iter().all(|handle| !handle.ops().is_empty()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            handles.iter().all(|handle| !handle.ops().is_empty()),
            "deliveries did not settle in time"
        );

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
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
        drive(
            &rig,
            vec![delivery("clean1", 1, h1.clone()), delivery("bad1", 1, h2.clone())],
            &[h1.clone(), h2.clone()],
        )
        .await;

        let reports = rig.reports.lock().clone();
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
        drive(&rig, deliveries, &handles).await;

        let reports = rig.reports.lock();
        assert_eq!(reports.len(), 4, "two scans: full batch of 3 + flushed remainder");
        drop(reports);
        for handle in &handles {
            assert_eq!(handle.ops(), vec!["ack"]);
        }
        assert!(root_is_clean(&rig.root));
    }

    #[tokio::test]
    async fn fetch_terminal_error_reports_and_acks() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(clean_output(&["good"])));
        let mut failures = HashMap::new();
        failures.insert("bad".to_owned(), FetchError::NotFound);
        let rig = rig(outputs, failures, false);

        let good_handle = FakeHandle::default();
        let bad_handle = FakeHandle::default();
        drive(
            &rig,
            vec![delivery("good", 1, good_handle.clone()), delivery("bad", 1, bad_handle.clone())],
            &[good_handle.clone(), bad_handle.clone()],
        )
        .await;

        let reports = rig.reports.lock();
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
        drive(&rig, vec![delivery("bad", 1, bad_handle.clone())], &[bad_handle.clone()]).await;

        assert!(rig.reports.lock().is_empty());
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
        drive(
            &rig,
            vec![delivery("a", 1, h1.clone()), delivery("b", 1, h2.clone())],
            &[h1.clone(), h2.clone()],
        )
        .await;

        assert!(rig.reports.lock().is_empty());
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
        drive(&rig, vec![delivery("a", 1, handle.clone())], &[handle.clone()]).await;

        let reports = rig.reports.lock();
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
        drive(&rig, vec![delivery("a", 1, handle.clone())], &[handle.clone()]).await;

        assert!(rig.reports.lock().is_empty());
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
        drive(&rig, vec![delivery("locked", 1, handle.clone())], &[handle.clone()]).await;

        let reports = rig.reports.lock();
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].outcome,
            ScanOutcome::Skipped { reason: SkipReason::PasswordProtected }
        );
        drop(reports);
        assert_eq!(handle.ops(), vec!["ack"]);
    }

    #[tokio::test]
    async fn scanner_unavailable_reports_errors_at_attempt_cap() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Err(ScannerError::Unavailable("clamd down".to_owned())));
        let rig = rig(outputs, HashMap::new(), false);

        // settings() caps scanner attempts at 3; attempt 3 is the last straw.
        let h1 = FakeHandle::default();
        let h2 = FakeHandle::default();
        drive(
            &rig,
            vec![delivery("a", 3, h1.clone()), delivery("b", 3, h2.clone())],
            &[h1.clone(), h2.clone()],
        )
        .await;

        let reports = rig.reports.lock();
        assert_eq!(reports.len(), 2, "terminal error reports at the cap");
        for report in reports.iter() {
            match &report.outcome {
                ScanOutcome::Error { message } => {
                    assert!(message.contains("scanner unavailable"), "{message}")
                }
                other => panic!("expected error outcome, got {other:?}"),
            }
        }
        drop(reports);
        assert_eq!(h1.ops(), vec!["ack"]);
        assert_eq!(h2.ops(), vec!["ack"]);
    }

    #[tokio::test]
    async fn duplicate_delivery_twin_is_delayed_not_discarded() {
        let mut outputs = VecDeque::new();
        outputs.push_back(Ok(clean_output(&["a"])));
        let rig = rig(outputs, HashMap::new(), false);

        let first = FakeHandle::default();
        let twin = FakeHandle::default();
        drive(
            &rig,
            vec![delivery("a", 1, first.clone()), delivery("a", 2, twin.clone())],
            &[first.clone(), twin.clone()],
        )
        .await;

        let reports = rig.reports.lock();
        assert_eq!(reports.len(), 1, "one scan, one report");
        drop(reports);
        assert_eq!(first.ops(), vec!["ack"]);
        // Delayed requeue, not discard: if the original's worker died right
        // after settling, discarding the twin would lose the sample.
        assert_eq!(twin.ops(), vec!["nak"]);
    }
}
