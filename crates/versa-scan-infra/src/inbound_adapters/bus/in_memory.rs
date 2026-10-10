//! In-memory listener (inbound/driving edge).
//!
//! Pops queued requests and ingests them into the pipeline until cancelled.
//! Never "ends" on its own (no broker to disconnect), so the pipeline's
//! idle flush is what closes under-filled batches; tests may call
//! `stream_ended()` explicitly.

use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::ports::driving::scan_pipeline::{Delivery, DeliveryHandle, ScanPipelinePort};

use super::BusListener;
use crate::outbound_adapters::bus::in_memory::{
    InMemoryPublisher, InMemoryShared, PendingDelivery,
};

pub struct InMemoryListener {
    shared: Arc<InMemoryShared>,
}

impl InMemoryListener {
    pub(crate) fn new(shared: Arc<InMemoryShared>) -> Self {
        Self { shared }
    }

    pub fn settled(&self) -> Vec<(String, &'static str)> {
        self.shared.settled.lock().clone()
    }
}

/// Creates a connected listener + publisher pair sharing one state.
pub fn pair() -> (Arc<InMemoryListener>, Arc<InMemoryPublisher>) {
    let shared = Arc::new(InMemoryShared::default());
    let listener = InMemoryListener::new(Arc::clone(&shared));
    let publisher = InMemoryPublisher::new(shared);
    (Arc::new(listener), Arc::new(publisher))
}

#[async_trait]
impl BusListener for InMemoryListener {
    async fn run(
        &self,
        scanner: ScannerId,
        pipeline: Arc<dyn ScanPipelinePort>,
        cancel: CancellationToken,
    ) {
        loop {
            let next = {
                let mut queues = self.shared.queues.lock();
                queues.get_mut(scanner.as_str()).and_then(|queue| queue.pop_front())
            };
            if let Some(pending) = next {
                let PendingDelivery { request, attempt } = pending;
                let handle = Arc::new(InMemoryHandle {
                    scanner: scanner.as_str().to_owned(),
                    request: request.clone(),
                    attempt,
                    shared: Arc::clone(&self.shared),
                });
                pipeline.clone().ingest(Delivery { request, attempt, handle });
                continue;
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = self.shared.notify.notified() => {}
            }
        }
    }
}

struct InMemoryHandle {
    scanner: String,
    request: versa_scan_core::models::sample::SampleRequest,
    attempt: u8,
    shared: Arc<InMemoryShared>,
}

impl InMemoryHandle {
    fn record(&self, op: &'static str) {
        let sample_id = self.request.sample_id.as_str().to_owned();
        self.shared.settled.lock().push((sample_id, op));
    }
}

#[async_trait]
impl DeliveryHandle for InMemoryHandle {
    async fn ack(&self) {
        self.record("ack");
    }

    async fn nak_requeue(&self) {
        {
            let mut queues = self.shared.queues.lock();
            let queue = queues.entry(self.scanner.clone()).or_default();
            // Requeue at the front with attempt+1 so the core's retry policy
            // sees the extra attempt.
            queue.push_front(PendingDelivery {
                request: self.request.clone(),
                attempt: self.attempt.saturating_add(1),
            });
        }
        self.shared.notify.notify_one();
        self.record("nak");
    }

    async fn discard(&self) {
        self.record("discard");
    }
}
