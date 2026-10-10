//! Publisher for scan requests: the outbound edge of sample submission
//! (vscli drives this; workers never publish requests).

use async_trait::async_trait;

use crate::models::ids::ScannerId;
use crate::models::sample::SampleRequest;

/// Shared error shape for bus publishers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    #[error("bus connection failed: {0}")]
    Connection(String),
    #[error("publish failed: {0}")]
    Publish(String),
}

/// Publishes one scan request targeted at `scanner`. Durable + confirmed
/// (publisher confirms / JetStream ack) before Ok. Priority rides in the
/// request DTO: enforced natively by RabbitMQ, ignored by NATS (design
/// decision, docs/DESIGN.md).
#[async_trait]
pub trait RequestPublisherPort: Send + Sync {
    async fn publish_request(
        &self,
        scanner: ScannerId,
        request: &SampleRequest,
    ) -> Result<(), PublishError>;
}
