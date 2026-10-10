//! Outbound (driven) bus adapters: they publish scan requests (vscli side)
//! and scan reports (worker side) toward the broker.

pub mod in_memory;
pub mod nats;
pub mod rabbitmq;

use std::sync::Arc;

use versa_scan_core::ports::driven::{PublishError, ReportPublisherPort, RequestPublisherPort};

use crate::config::{BusBackend, BusConfig};

/// The publisher pair for one deployment. Both halves may be the same
/// adapter object (RabbitMQ/NATS); the in-memory backend shares state.
pub struct BusPublishers {
    pub request: Arc<dyn RequestPublisherPort>,
    pub report: Arc<dyn ReportPublisherPort>,
}

/// Builds the publishers for the configured backend. The caller owns the
/// configuration section (`[bus]` + backend subsection).
pub async fn connect(config: &BusConfig) -> Result<BusPublishers, PublishError> {
    match config.backend {
        BusBackend::RabbitMq => {
            let cfg = config.rabbitmq.clone().ok_or_else(|| {
                PublishError::Connection("[bus.rabbitmq] section missing".to_owned())
            })?;
            let publisher = rabbitmq::RabbitMqPublisher::connect(&cfg.url).await?;
            Ok(BusPublishers { request: Arc::new(publisher.clone()), report: Arc::new(publisher) })
        }
        BusBackend::Nats => {
            let cfg = config
                .nats
                .clone()
                .ok_or_else(|| PublishError::Connection("[bus.nats] section missing".to_owned()))?;
            let publisher = nats::NatsPublisher::connect(&cfg.url).await?;
            Ok(BusPublishers { request: Arc::new(publisher.clone()), report: Arc::new(publisher) })
        }
    }
}
