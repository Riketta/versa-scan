//! NATS report waiter: an ephemeral JetStream pull consumer on the
//! session's wildcard subject (`vs.scan.reports.<session>.*`).
//!
//! Reports are published THROUGH JetStream (JS publish addresses the
//! `$JS.API` subject), so a plain core-NATS subscription would never see
//! them - the waiter must consume from the `VS_SCAN_REPORTS` stream.
//! `DeliverPolicy::New` matches the listen-before-publish ordering (only
//! reports arriving after the subscription are delivered), and the
//! consumer is ephemeral with an inactive threshold so it disappears with
//! the session.

use std::pin::Pin;
use std::time::Duration;

use async_nats::jetstream::consumer::pull::Stream as PullStream;
use async_nats::jetstream::{Context, consumer, stream};
use async_trait::async_trait;
use futures_util::StreamExt;
use versa_scan_core::models::sample::ReportDest;

use super::{
    BoxReportStream, IncomingReport, ListenerError, ReportItem, ReportStream, ReportWaiter,
};
use crate::wire::ScanReportV1;

const REPORTS_STREAM: &str = "VS_SCAN_REPORTS";
/// Ephemeral consumers vanish after this much inactivity.
const CONSUMER_INACTIVITY: Duration = Duration::from_secs(300);

pub struct NatsReportWaiter {
    context: Context,
}

impl NatsReportWaiter {
    pub async fn connect(url: &str) -> Result<Self, ListenerError> {
        let client = async_nats::connect(url)
            .await
            .map_err(|e| ListenerError::Connection(format!("nats connect: {e}")))?;
        Ok(Self { context: async_nats::jetstream::new(client) })
    }
}

type PullStreamError =
    async_nats::error::Error<async_nats::jetstream::consumer::pull::MessagesErrorKind>;

type NatsMessageStream = Pin<
    Box<
        dyn futures_util::Stream<Item = Result<async_nats::jetstream::Message, PullStreamError>>
            + Send,
    >,
>;

struct NatsReportStream {
    inner: NatsMessageStream,
}

impl NatsReportStream {
    fn decode(message: async_nats::jetstream::Message) -> Result<IncomingReport, String> {
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
            let message = match self.inner.next().await? {
                Err(err) => {
                    return Some(Err(ListenerError::Connection(format!("nats consume: {err}"))));
                }
                Ok(message) => message,
            };
            match Self::decode(message) {
                Ok(incoming) => return Some(Ok(incoming)),
                Err(reason) => {
                    // Undecodable reports cannot be requeued; acknowledge
                    // them so they leave the delivery queue and keep the
                    // session alive.
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
        let js_stream = self
            .context
            .get_or_create_stream(stream::Config {
                name: REPORTS_STREAM.to_owned(),
                subjects: vec!["vs.scan.reports.>".to_owned()],
                retention: stream::RetentionPolicy::Limits,
                max_age: Duration::from_secs(7 * 24 * 3600),
                duplicate_window: Duration::from_secs(120),
                ..Default::default()
            })
            .await
            .map_err(|e| ListenerError::Connection(format!("nats reports stream: {e}")))?;
        let pull_consumer = js_stream
            .create_consumer(consumer::pull::Config {
                filter_subject: dest.as_str().to_owned(),
                deliver_policy: consumer::DeliverPolicy::New,
                ack_policy: consumer::AckPolicy::None,
                inactive_threshold: CONSUMER_INACTIVITY,
                ..Default::default()
            })
            .await
            .map_err(|e| ListenerError::Connection(format!("nats consumer: {e}")))?;
        let messages: PullStream = pull_consumer
            .messages()
            .await
            .map_err(|e| ListenerError::Connection(format!("nats pull: {e}")))?;
        let inner: NatsMessageStream = Box::pin(messages);
        Ok(Box::new(NatsReportStream { inner }))
    }
}
