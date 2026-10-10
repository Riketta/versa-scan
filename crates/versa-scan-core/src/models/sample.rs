//! A sample dispatch request as it travels from vscli to a worker.

use time::OffsetDateTime;

use super::digest::Sha256Digest;
use super::ids::{CorrelationId, SampleId};
use super::priority::Priority;

/// Where scan reports for a request must be published. Opaque to the core:
/// a RabbitMQ adapter reads it as a queue name, a NATS adapter as a subject.
/// The requester owns the destination and must have it ready (declared /
/// subscribed) before publishing requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReportDest(String);

impl ReportDest {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ReportDest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One sample to scan, as published by a requester.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleRequest {
    pub sample_id: SampleId,
    /// Download URL of the sample content. The artifact server is whatever
    /// the requester runs or points at (vscli embeds one; the address is
    /// deployment configuration, not a core concept).
    pub url: String,
    pub sha256: Sha256Digest,
    /// Declared size in bytes; `0` means unknown (verification skipped).
    pub size: u64,
    pub priority: Priority,
    pub report_dest: ReportDest,
    pub correlation_id: CorrelationId,
    /// File-extension hints (informational; scanners may use them).
    pub extensions: Vec<String>,
    pub created_at: OffsetDateTime,
}
