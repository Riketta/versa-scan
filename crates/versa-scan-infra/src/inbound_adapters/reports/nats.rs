//! NATS report waiter: a plain subscription on the session's wildcard
//! subject (`vs.scan.reports.<session>.*`); workers JetStream-publish each
//! report to the per-sample subject, which live subscribers receive.

use std::pin::Pin;

use async_trait::async_trait;
use futures_util::StreamExt;
use versa_scan_core::models::sample::ReportDest;

use super::{
    BoxReportStream, IncomingReport, ListenerError, ReportItem, ReportStream, ReportWaiter,
};
use crate::wire::ScanReportV1;

pub struct NatsReportWaiter {
    client: async_nats::Client,
}

impl NatsReportWaiter {
    pub async fn connect(url: &str) -> Result<Self, ListenerError> {
        let client = async_nats::connect(url)
            .await
            .map_err(|e| ListenerError::Connection(format!("nats connect: {e}")))?;
        Ok(Self { client })
    }
}

type NatsSubscriber = Pin<Box<dyn futures_util::Stream<Item = async_nats::Message> + Send>>;

struct NatsReportStream {
    inner: NatsSubscriber,
}

impl NatsReportStream {
    fn decode(message: async_nats::Message) -> Result<IncomingReport, String> {
        let dest = ReportDest::new(message.subject.as_str());
        let dto: ScanReportV1 =
            serde_json::from_slice(&message.payload).map_err(|e| format!("json: {e}"))?;
        let report = dto.to_model(dest.clone()).map_err(|e| e.to_string())?;
        Ok(IncomingReport { report, dest })
    }
}

#[async_trait]
impl ReportStream for NatsReportStream {
    async fn next(&mut self) -> Option<ReportItem> {
        loop {
            let message = self.inner.next().await?;
            match Self::decode(message) {
                Ok(incoming) => return Some(Ok(incoming)),
                Err(reason) => {
                    // Reports cannot be requeued; a malformed one is logged
                    // and skipped.
                    tracing::warn!(reason = %reason, "skipped undecodable report");
                    continue;
                }
            }
        }
    }
}

#[async_trait]
impl ReportWaiter for NatsReportWaiter {
    async fn listen(&self, dest: &ReportDest) -> Result<BoxReportStream, ListenerError> {
        // `dest` is the session wildcard (`vs.scan.reports.<session>.*`).
        let subscription = self
            .client
            .subscribe(dest.as_str().to_owned())
            .await
            .map_err(|e| ListenerError::Connection(format!("nats subscribe: {e}")))?;
        let inner: NatsSubscriber = Box::pin(subscription);
        Ok(Box::new(NatsReportStream { inner }))
    }
}
