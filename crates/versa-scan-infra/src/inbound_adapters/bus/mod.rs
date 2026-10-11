//! Bus listeners (driving edge): consume scan requests from a broker and
//! feed the core pipeline via `ScanPipelinePort`.
//!
//! Direction contract: a listener owns its broker connection, the consume
//! session loop, and reconnection with backoff; the pipeline owns batching,
//! scanning, publishing, and settlement. Listeners never settle deliveries
//! themselves (except terminating undecodable payloads, which can never
//! parse) and never block the pipeline: `ingest` is non-blocking.

pub mod in_memory;
pub mod nats;
pub mod rabbitmq;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::ports::driving::scan_pipeline::ScanPipelinePort;

use super::ListenerError;
use crate::config::{BusBackend, BusConfig};

/// First reconnect delay; doubles up to [`MAX_BACKOFF`]. Reset after a
/// healthy session so one long broker outage does not tax later blips.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// One active listener per worker, wired at the composition root alongside
/// the pipeline.
#[async_trait]
pub trait BusListener: Send + Sync {
    /// Runs until `cancel`: consumes requests for `scanner`, ingests each
    /// into `pipeline`, and calls `pipeline.stream_ended()` between
    /// sessions. Requires the pipeline's `run()` to be active elsewhere
    /// (spawn it first).
    async fn run(
        &self,
        scanner: ScannerId,
        pipeline: Arc<dyn ScanPipelinePort>,
        cancel: CancellationToken,
    );
}

/// Builds the listener for the configured backend.
pub async fn connect(config: &BusConfig) -> Result<Arc<dyn BusListener>, ListenerError> {
    match config.backend {
        BusBackend::RabbitMq => {
            let cfg = config.rabbitmq.clone().ok_or_else(|| {
                ListenerError::Configuration("[bus.rabbitmq] section missing".to_owned())
            })?;
            let prefetch = u16::try_from(cfg.prefetch).map_err(|_| {
                ListenerError::Configuration(format!(
                    "bus.rabbitmq.prefetch {} does not fit in u16",
                    cfg.prefetch
                ))
            })?;
            Ok(Arc::new(rabbitmq::RabbitMqListener::new(&cfg.url, prefetch)))
        }
        BusBackend::Nats => {
            let cfg = config.nats.clone().ok_or_else(|| {
                ListenerError::Configuration("[bus.nats] section missing".to_owned())
            })?;
            Ok(Arc::new(
                nats::NatsListener::connect(
                    &cfg.url,
                    Duration::from_secs(cfg.ack_wait_secs),
                    i64::from(cfg.max_deliver),
                )
                .await?,
            ))
        }
    }
}

/// Cancel-aware backoff sleep shared by listener sessions. Returns false
/// when cancelled first; `backoff` grows toward [`MAX_BACKOFF`].
pub(crate) async fn backoff_sleep(cancel: &CancellationToken, backoff: &mut Duration) -> bool {
    let slept = tokio::select! {
        _ = cancel.cancelled() => false,
        _ = tokio::time::sleep(*backoff) => true,
    };
    *backoff = (*backoff * 2).min(MAX_BACKOFF);
    slept
}

pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(30);
