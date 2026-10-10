//! The bus port: work-queue semantics over RabbitMQ / NATS JetStream /
//! in-memory (tests).
//!
//! Contract notes:
//! - Delivery settlement is explicit per message (`ack` / `nak_requeue` /
//!   `discard`). Settlement failures are best-effort inside adapters (logged,
//!   never panic); the core's retry policy is what keeps messages from being
//!   lost.
//! - Priority is carried in the request DTO only. The RabbitMQ adapter
//!   enforces it with `x-max-priority`; the NATS adapter ignores it (design
//!   decision, docs/DESIGN.md). The port itself is priority-blind.
//! - `publish_report` must be durable (persistent messages / JetStream) and
//!   confirm before returning Ok.

use async_trait::async_trait;

use crate::models::ids::ScannerId;
use crate::models::report::ScanReport;
use crate::models::sample::{ReportDest, SampleRequest};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BusError {
    #[error("bus connection failed: {0}")]
    Connection(String),
    #[error("bus channel/publish failed: {0}")]
    Publish(String),
    #[error("bus consume failed: {0}")]
    Consume(String),
    #[error("bus configuration error: {0}")]
    Configuration(String),
}

/// A settled delivery handle. Implemented per adapter; methods are
/// best-effort and idempotent where the broker allows.
#[async_trait]
pub trait DeliveryHandle: Send + Sync {
    /// Message processed; never redeliver.
    async fn ack(&self);
    /// Temporary failure: redeliver (respecting broker redelivery policy).
    async fn nak_requeue(&self);
    /// Permanent failure on our side: do not redeliver.
    async fn discard(&self);
}

/// One consumed scan request plus its settlement handle and the broker's
/// delivery count for it (1 = first delivery).
#[derive(Clone)]
pub struct Delivery {
    pub request: SampleRequest,
    pub attempt: u8,
    pub handle: std::sync::Arc<dyn DeliveryHandle>,
}

/// A stream of scan requests for one scanner. Ends (`None`) when the
/// underlying connection closes; the orchestrator reconnects.
#[async_trait]
pub trait RequestStream: Send {
    async fn next(&mut self) -> Option<Result<Delivery, BusError>>;
}

/// The bus adapter contract. One active adapter per worker (and per CLI
/// invocation); the composition root picks RabbitMQ, NATS, or in-memory.
#[async_trait]
pub trait BusPort: Send + Sync {
    /// Publishes one scan request targeted at `scanner`. Durable + confirmed
    /// before Ok.
    async fn publish_request(
        &self,
        scanner: ScannerId,
        request: &SampleRequest,
    ) -> Result<(), BusError>;

    /// Opens a consuming stream for `scanner`'s request queue/subject.
    async fn consume_requests(
        &self,
        scanner: ScannerId,
    ) -> Result<Box<dyn RequestStream>, BusError>;

    /// Publishes a scan report to `dest` (the request's report destination).
    async fn publish_report(&self, report: &ScanReport, dest: &ReportDest) -> Result<(), BusError>;
}
