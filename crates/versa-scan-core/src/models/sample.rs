//! A sample dispatch request as it travels from vscli to a worker.

use time::OffsetDateTime;

use super::digest::Sha256Digest;
use super::ids::{CorrelationId, SampleId};
use super::priority::Priority;

/// Where scan reports for a request must be published. Opaque to the core:
/// a RabbitMQ adapter reads it as a queue name, a NATS adapter as a subject.
/// The requester owns the destination and must have it ready (declared /
/// subscribed) before publishing requests.
///
/// Validated as broker-safe tokens (`[A-Za-z0-9._>*-]`): the value comes
/// off the untrusted bus and is used verbatim as a routing key / subject
/// (`>`/`*` are NATS wildcards - the session waiter subscribes with a
/// `>` tail), so a hostile payload must not be able to smuggle whitespace
/// or path separators into it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReportDest(String);

impl ReportDest {
    pub fn new(value: impl Into<String>) -> Result<Self, crate::models::ids::InvalidId> {
        let value = value.into();
        let invalid = |reason: &str| crate::models::ids::InvalidId::new(reason);
        if value.is_empty() {
            return Err(invalid("ReportDest must not be empty"));
        }
        if value.len() > 256 {
            return Err(invalid("ReportDest longer than 256 chars"));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'>' | b'*'))
        {
            return Err(invalid("ReportDest must only contain [A-Za-z0-9._>*-]"));
        }
        Ok(Self(value))
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn accepts_concrete_subjects_queues_and_nats_wildcards() {
        for ok in [
            "vs.scan.reports.session.s-1",
            "reports",
            "vs.scan.reports.s.x-y_z",
            "vs.scan.reports.session.>", // session waiter wildcard
        ] {
            assert!(ReportDest::new(ok).is_ok(), "must accept {ok:?}");
        }
    }

    #[test]
    fn rejects_empty_hostile_and_whitespace() {
        for bad in [
            "",
            "a b",
            "queue;drop",
            "../escape",
            "dest
line",
            "dest with spaces",
        ] {
            assert!(ReportDest::new(bad).is_err(), "must reject {bad:?}");
        }
    }
}
