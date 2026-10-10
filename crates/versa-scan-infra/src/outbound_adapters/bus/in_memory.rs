//! In-memory publisher (outbound edge) + shared state.
//!
//! The in-memory backend's listener (inbound edge) and publishers share one
//! [`InMemoryShared`] state. `nak_requeue` genuinely requeues with
//! attempt+1, so tests exercise real redelivery paths. For tests and local
//! experimentation only - there is no cross-process transport.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::models::report::ScanReport;
use versa_scan_core::models::sample::{ReportDest, SampleRequest};
use versa_scan_core::ports::driven::{PublishError, ReportPublisherPort, RequestPublisherPort};

/// State shared between the in-memory listener and publishers.
#[derive(Default)]
pub struct InMemoryShared {
    pub(crate) queues: Mutex<HashMap<String, VecDeque<PendingDelivery>>>,
    pub(crate) notify: tokio::sync::Notify,
    pub(crate) reports: Mutex<Vec<ScanReport>>,
    pub(crate) settled: Mutex<Vec<(String, &'static str)>>,
}

/// One queued request awaiting redelivery, with its delivery count.
#[derive(Clone)]
pub struct PendingDelivery {
    pub request: SampleRequest,
    pub attempt: u8,
}

/// In-memory publisher implementing both driven publisher ports.
pub struct InMemoryPublisher {
    shared: Arc<InMemoryShared>,
}

impl InMemoryPublisher {
    pub fn new(shared: Arc<InMemoryShared>) -> Self {
        Self { shared }
    }

    /// All reports published so far, in publish order.
    pub fn reports(&self) -> Vec<ScanReport> {
        self.shared.reports.lock().clone()
    }

    /// Settlement log: `(sample_id, "ack" | "nak" | "discard")` in order.
    pub fn settled(&self) -> Vec<(String, &'static str)> {
        self.shared.settled.lock().clone()
    }

    /// Number of undelivered requests queued for `scanner`.
    pub fn pending(&self, scanner: &ScannerId) -> usize {
        self.shared.queues.lock().get(scanner.as_str()).map(|queue| queue.len()).unwrap_or(0)
    }
}

#[async_trait]
impl RequestPublisherPort for InMemoryPublisher {
    async fn publish_request(
        &self,
        scanner: ScannerId,
        request: &SampleRequest,
    ) -> Result<(), PublishError> {
        {
            let mut queues = self.shared.queues.lock();
            queues
                .entry(scanner.as_str().to_owned())
                .or_default()
                .push_back(PendingDelivery { request: request.clone(), attempt: 1 });
        }
        self.shared.notify.notify_one();
        Ok(())
    }
}

#[async_trait]
impl ReportPublisherPort for InMemoryPublisher {
    async fn publish_report(
        &self,
        report: &ScanReport,
        _dest: &ReportDest,
    ) -> Result<(), PublishError> {
        self.shared.reports.lock().push(report.clone());
        Ok(())
    }
}
