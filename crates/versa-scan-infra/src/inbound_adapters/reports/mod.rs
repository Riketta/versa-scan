//! Report listeners (driving edge, CLI side): consume scan reports the
//! workers publish to a session's report destination.
//!
//! `vscli submit --wait` opens the stream BEFORE publishing requests, then
//! collects until every (sample, scanner) pair is answered or the timeout
//! hits. Reports may arrive more than once (at-least-once publishing);
//! dedupe on (sample_id, scanner, attempt) is the caller's call - the
//! stream hands over everything it sees.

pub mod nats;
pub mod rabbitmq;

use std::sync::Arc;

use async_trait::async_trait;
use versa_scan_core::models::report::ScanReport;
use versa_scan_core::models::sample::ReportDest;

pub use super::ListenerError;
use crate::config::{BusBackend, BusConfig};

/// Decoded inbound report plus the destination it arrived on (the
/// requester's routing record for that sample).
pub struct IncomingReport {
    pub report: ScanReport,
    pub dest: ReportDest,
}

pub type ReportItem = Result<IncomingReport, ListenerError>;

/// A live stream of reports for one session destination.
#[async_trait]
pub trait ReportStream: Send {
    /// `None` when the underlying connection/session closed.
    async fn next(&mut self) -> Option<ReportItem>;
}

pub type BoxReportStream = Box<dyn ReportStream>;

/// Builds a report stream for a session destination. One active waiter per
/// CLI invocation.
#[async_trait]
pub trait ReportWaiter: Send + Sync {
    async fn listen(&self, dest: &ReportDest) -> Result<BoxReportStream, ListenerError>;
}

/// Builds the waiter for the configured backend.
pub async fn connect(config: &BusConfig) -> Result<Arc<dyn ReportWaiter>, ListenerError> {
    match config.backend {
        BusBackend::Nats => {
            let cfg = config.nats.clone().ok_or_else(|| {
                ListenerError::Configuration("[bus.nats] section missing".to_owned())
            })?;
            Ok(Arc::new(nats::NatsReportWaiter::connect(&cfg.url).await?))
        }
        BusBackend::RabbitMq => {
            let cfg = config.rabbitmq.clone().ok_or_else(|| {
                ListenerError::Configuration("[bus.rabbitmq] section missing".to_owned())
            })?;
            Ok(Arc::new(rabbitmq::RabbitMqReportWaiter::connect(&cfg.url).await?))
        }
    }
}
