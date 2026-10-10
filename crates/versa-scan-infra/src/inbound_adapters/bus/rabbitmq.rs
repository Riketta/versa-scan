//! RabbitMQ listener (`lapin`, inbound/driving edge).
//!
//! Session loop: declare the scanner's request queue (durable,
//! `x-max-priority = 2`, matching the publisher), set prefetch, consume
//! with manual ack, and ingest deliveries into the pipeline. Between
//! sessions it signals `pipeline.stream_ended()` and reconnects with
//! backoff. `attempt` is approximate (redelivered flag): 1 or 2.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use lapin::message::Delivery as LapinDelivery;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions, QueueDeclareOptions,
};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{Channel, Connection, ConnectionProperties};
use tokio_util::sync::CancellationToken;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::ports::driving::scan_pipeline::{Delivery, DeliveryHandle, ScanPipelinePort};

use super::{BusListener, ListenerError, backoff_sleep};
use crate::wire::{SampleRequestV1, request_queue_name};

const MAX_PRIORITY_ARG: &str = "x-max-priority";

type LapinDeliveryStream =
    Pin<Box<dyn futures_util::Stream<Item = Result<LapinDelivery, lapin::Error>> + Send>>;

pub struct RabbitMqListener {
    channel: Channel,
    prefetch: u16,
    _connection: Connection,
}

impl RabbitMqListener {
    pub async fn connect(url: &str, prefetch: u16) -> Result<Self, ListenerError> {
        let connection = Connection::connect(url, ConnectionProperties::default())
            .await
            .map_err(|e| ListenerError::Connection(format!("rabbitmq connect: {e}")))?;
        let channel = connection
            .create_channel()
            .await
            .map_err(|e| ListenerError::Connection(format!("rabbitmq channel: {e}")))?;
        Ok(Self { channel, prefetch, _connection: connection })
    }

    fn request_queue_args() -> FieldTable {
        let mut args = FieldTable::default();
        args.insert(MAX_PRIORITY_ARG.into(), AMQPValue::LongInt(2));
        args
    }

    /// One consume session; ends on broker close, consume error, or cancel.
    async fn session(
        &self,
        queue: &str,
        pipeline: &Arc<dyn ScanPipelinePort>,
        cancel: &CancellationToken,
    ) -> Result<(), lapin::Error> {
        self.channel
            .queue_declare(
                queue,
                QueueDeclareOptions { durable: true, ..Default::default() },
                Self::request_queue_args(),
            )
            .await?;
        self.channel.basic_qos(self.prefetch, BasicQosOptions::default()).await?;
        let consumer = self
            .channel
            .basic_consume(queue, "", BasicConsumeOptions::default(), FieldTable::default())
            .await?;
        let mut stream: LapinDeliveryStream = Box::pin(consumer);

        loop {
            let raw = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                item = stream.next() => match item {
                    None => return Ok(()),
                    Some(Err(err)) => return Err(err),
                    Some(Ok(raw)) => raw,
                },
            };
            let attempt = if raw.redelivered { 2 } else { 1 };
            match serde_json::from_slice::<SampleRequestV1>(&raw.data)
                .map_err(|e| format!("json: {e}"))
                .and_then(|dto| dto.to_model().map_err(|e| format!("validation: {e}")))
            {
                Ok(request) => {
                    pipeline.clone().ingest(Delivery {
                        request,
                        attempt,
                        handle: Arc::new(RabbitHandle { acker: raw.acker }),
                    });
                }
                Err(reason) => {
                    // A payload that cannot parse can never parse: terminate
                    // it (no requeue) so it cannot poison the queue forever.
                    let result = raw
                        .acker
                        .nack(BasicNackOptions { requeue: false, ..Default::default() })
                        .await;
                    if let Err(err) = result {
                        tracing::warn!(error = %err, "failed to terminate undecodable delivery");
                    }
                    tracing::warn!(reason = %reason, "terminated undecodable rabbitmq delivery");
                }
            }
        }
    }
}

#[async_trait]
impl BusListener for RabbitMqListener {
    async fn run(
        &self,
        scanner: ScannerId,
        pipeline: Arc<dyn ScanPipelinePort>,
        cancel: CancellationToken,
    ) {
        let queue = request_queue_name(&scanner);
        let mut backoff = Duration::from_secs(1);
        loop {
            if cancel.is_cancelled() {
                return;
            }
            match self.session(&queue, &pipeline, &cancel).await {
                Ok(()) => tracing::debug!(queue = %queue, "rabbitmq session ended"),
                Err(err) => {
                    tracing::warn!(error = %err, queue = %queue, "rabbitmq session failed")
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
struct RabbitHandle {
    acker: lapin::acker::Acker,
}

impl RabbitHandle {
    fn log(result: Result<bool, lapin::Error>, op: &'static str) {
        if let Err(err) = result {
            tracing::warn!(error = %err, operation = op, "rabbitmq settlement failed");
        }
    }
}

#[async_trait]
impl DeliveryHandle for RabbitHandle {
    async fn ack(&self) {
        let result = self.acker.ack(BasicAckOptions::default()).await;
        Self::log(result, "ack");
    }

    async fn nak_requeue(&self) {
        let result =
            self.acker.nack(BasicNackOptions { requeue: true, ..Default::default() }).await;
        Self::log(result, "nack-requeue");
    }

    async fn discard(&self) {
        let result =
            self.acker.nack(BasicNackOptions { requeue: false, ..Default::default() }).await;
        Self::log(result, "discard");
    }
}
