//! Publisher for scan reports: the worker's outbound report path.

use async_trait::async_trait;

use crate::models::report::ScanReport;
use crate::models::sample::ReportDest;
use crate::ports::driven::request_publisher::PublishError;

/// Publishes one scan report to the request's report destination. Durable +
/// confirmed before Ok. Contract: the requester owns the destination (queue
/// declaration / subject subscription) and must have it ready before
/// publishing requests; `attempt` lets consumers dedupe redelivered reports.
#[async_trait]
pub trait ReportPublisherPort: Send + Sync {
    async fn publish_report(
        &self,
        report: &ScanReport,
        dest: &ReportDest,
    ) -> Result<(), PublishError>;
}
