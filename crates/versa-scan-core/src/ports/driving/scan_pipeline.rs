//! The scan pipeline's driving port: how an inbound bus adapter feeds
//! deliveries into the core and signals connection lifecycle.
//!
//! Direction contract: the listener owns the broker connection, redelivery
//! loops, and reconnection; the pipeline owns batching, scanning, report
//! publishing, and settlement decisions. Settlement is NEVER inline with
//! ingestion - the pipeline settles each delivery later via its
//! [`DeliveryHandle`] (publish-then-ack is a core invariant).

use std::sync::Arc;

use crate::models::sample::SampleRequest;

/// Settlement handle for one ingested delivery. Implemented by the inbound
/// adapter; methods are best-effort and idempotent where the broker allows.
#[async_trait::async_trait]
pub trait DeliveryHandle: Send + Sync {
    /// Report confirmed published; never redeliver.
    async fn ack(&self);
    /// Temporary failure: hand back to the broker for redelivery.
    async fn nak_requeue(&self);
    /// Permanent failure on our side: do not redeliver.
    async fn discard(&self);
    /// Redeliver later without burning an attempt now (a twin delivery whose
    /// original is still being processed). Backends without delayed naks
    /// fall back to an immediate requeue.
    async fn nak_delay(&self, _delay: std::time::Duration) {
        self.nak_requeue().await;
    }
}

/// One consumed scan request plus its settlement handle and the broker's
/// delivery count (1 = first delivery).
#[derive(Clone)]
pub struct Delivery {
    pub request: SampleRequest,
    pub attempt: u8,
    pub handle: std::sync::Arc<dyn DeliveryHandle>,
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery")
            .field("sample_id", &self.request.sample_id.as_str())
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

/// Implemented by the core pipeline (the orchestrator). All methods are
/// non-blocking: ingestion must never stall the listener.
pub trait ScanPipelinePort: Send + Sync + 'static {
    /// Feeds one delivery into the pipeline. Queues internally; processing
    /// happens on the pipeline's own task.
    fn ingest(self: Arc<Self>, delivery: Delivery);

    /// The inbound stream ended (broker disconnect / channel close). The
    /// pipeline flushes what it can, requeues unsettled deliveries, and
    /// prepares for the listener's next session.
    fn stream_ended(&self);
}
