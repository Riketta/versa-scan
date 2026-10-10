//! NATS JetStream listener (`async-nats`, inbound/driving edge).
//!
//! Session loop: ensure the requests stream + the scanner's durable pull
//! consumer (`vs-<scanner>`, filter `vs.scan.requests.<scanner>`, explicit
//! ack), then feed an infinite pull stream into the pipeline. Between
//! sessions it signals `pipeline.stream_ended()` and reconnects with
//! backoff. `attempt` comes from the broker's delivery info (exact).

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream::consumer::pull::Stream as PullStream;
use async_nats::jetstream::message::AckKind;
use async_nats::jetstream::{Context, consumer, stream};
use async_trait::async_trait;
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::ports::driving::scan_pipeline::{Delivery, DeliveryHandle, ScanPipelinePort};

use super::{BusListener, ListenerError, backoff_sleep};
use crate::wire::SampleRequestV1;

const REQUESTS_STREAM: &str = "VS_SCAN_REQUESTS";
const MESSAGES_SUBJECT: &str = "vs.scan.requests.>";
const DUPLICATE_WINDOW: Duration = Duration::from_secs(120);

type PullStreamError =
    async_nats::error::Error<async_nats::jetstream::consumer::pull::MessagesErrorKind>;

type NatsMessageStream = Pin<
    Box<
        dyn futures_util::Stream<Item = Result<async_nats::jetstream::Message, PullStreamError>>
            + Send,
    >,
>;

pub struct NatsListener {
    context: Context,
    ack_wait: Duration,
    max_deliver: i64,
}

impl NatsListener {
    pub async fn connect(
        url: &str,
        ack_wait: Duration,
        max_deliver: i64,
    ) -> Result<Self, ListenerError> {
        let client = async_nats::connect(url)
            .await
            .map_err(|e| ListenerError::Connection(format!("nats connect: {e}")))?;
        let context = async_nats::jetstream::new(client);
        Ok(Self { context, ack_wait, max_deliver })
    }

    /// One pull session; ends on stream close, consume error, or cancel.
    async fn session(
        &self,
        scanner: &ScannerId,
        pipeline: &Arc<dyn ScanPipelinePort>,
        cancel: &CancellationToken,
    ) -> Result<(), async_nats::Error> {
        let durable = format!("vs-{}", scanner.as_str());
        let js_stream = self
            .context
            .get_or_create_stream(stream::Config {
                name: REQUESTS_STREAM.to_owned(),
                subjects: vec![MESSAGES_SUBJECT.to_owned()],
                retention: stream::RetentionPolicy::WorkQueue,
                duplicate_window: DUPLICATE_WINDOW,
                ..Default::default()
            })
            .await?;
        let pull_consumer = js_stream
            .get_or_create_consumer(
                durable.as_str(),
                consumer::pull::Config {
                    durable_name: Some(durable.clone()),
                    filter_subject: format!("vs.scan.requests.{}", scanner.as_str()),
                    ack_policy: consumer::AckPolicy::Explicit,
                    ack_wait: self.ack_wait,
                    max_deliver: self.max_deliver,
                    ..Default::default()
                },
            )
            .await?;
        let messages: PullStream = pull_consumer.messages().await?;
        let mut stream: NatsMessageStream = Box::pin(messages);

        loop {
            let message = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                item = stream.next() => match item {
                    None => return Ok(()),
                    Some(Err(err)) => return Err(Box::new(err)),
                    Some(Ok(message)) => message,
                },
            };
            let outcome = async {
                let dto: SampleRequestV1 =
                    serde_json::from_slice(&message.payload).map_err(|e| format!("json: {e}"))?;
                dto.to_model().map_err(|e| format!("validation: {e}"))
            };
            match outcome.await {
                Ok(request) => {
                    let attempt = message
                        .info()
                        .ok()
                        .and_then(|info| u8::try_from(info.delivered.clamp(1, 255)).ok())
                        .unwrap_or(1);
                    pipeline.clone().ingest(Delivery {
                        request,
                        attempt,
                        handle: Arc::new(NatsHandle { message }),
                    });
                }
                Err(reason) => {
                    // A payload that cannot parse can never parse: term it.
                    if let Err(err) = message.ack_with(AckKind::Term).await {
                        tracing::warn!(error = %err, "failed to terminate undecodable message");
                    }
                    tracing::warn!(reason = %reason, "terminated undecodable nats message");
                }
            }
        }
    }
}

#[async_trait]
impl BusListener for NatsListener {
    async fn run(
        &self,
        scanner: ScannerId,
        pipeline: Arc<dyn ScanPipelinePort>,
        cancel: CancellationToken,
    ) {
        let mut backoff = Duration::from_secs(1);
        loop {
            if cancel.is_cancelled() {
                return;
            }
            match self.session(&scanner, &pipeline, &cancel).await {
                Ok(()) => tracing::debug!(scanner = %scanner, "nats session ended"),
                Err(err) => {
                    tracing::warn!(error = %err, scanner = %scanner, "nats session failed")
                }
            }
            pipeline.stream_ended();
            if !backoff_sleep(&cancel, &mut backoff).await {
                return;
            }
        }
    }
}

#[derive(Clone)]
struct NatsHandle {
    message: async_nats::jetstream::Message,
}

impl NatsHandle {
    fn log(result: Result<(), async_nats::Error>, op: &'static str) {
        if let Err(err) = result {
            tracing::warn!(error = %err, operation = op, "nats settlement failed");
        }
    }
}

#[async_trait]
impl DeliveryHandle for NatsHandle {
    async fn ack(&self) {
        let result = self.message.ack().await;
        Self::log(result, "ack");
    }

    async fn nak_requeue(&self) {
        // Immediate redelivery; attempt counting comes from the broker's
        // delivery info.
        let result = self.message.ack_with(AckKind::Nak(None)).await;
        Self::log(result, "nak");
    }

    async fn discard(&self) {
        let result = self.message.ack_with(AckKind::Term).await;
        Self::log(result, "term");
    }
}
