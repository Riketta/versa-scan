//! RabbitMQ listener (`lapin`, inbound/driving edge).
//!
//! Session loop: connect fresh, declare the scanner's request queue
//! (durable, `x-max-priority = 2`, matching the publisher), enable
//! publisher confirms, set prefetch, consume with manual ack, and ingest
//! deliveries into the pipeline. Between sessions it signals
//! `pipeline.stream_ended()`, sleeps with backoff (reset after a healthy
//! session), and reconnects - one broker restart costs a redelivery cycle,
//! not the worker.
//!
//! Attempt counting: AMQP redeliveries carry no count, so requeues are
//! republished with an `x-vs-attempt` header (confirmed publish, then ack
//! of the original) and the original is only retired once the replacement
//! is confirmed queued. That header is what makes the retry policy's bound
//! enforceable on RabbitMQ.

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::StreamExt;
use lapin::message::Delivery as LapinDelivery;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions, BasicQosOptions,
    ConfirmSelectOptions, QueueDeclareOptions,
};
use lapin::publisher_confirm::Confirmation;
use lapin::types::{AMQPValue, FieldTable};
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties};
use tokio_util::sync::CancellationToken;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::ports::driving::scan_pipeline::{Delivery, DeliveryHandle, ScanPipelinePort};

use super::{BusListener, INITIAL_BACKOFF, backoff_sleep};
use crate::wire::{SampleRequestV1, request_queue_name};

const MAX_PRIORITY_ARG: &str = "x-max-priority";
/// Requeue-republish header carrying the next attempt number (the AMQP
/// redelivered flag cannot count). Written by [`RabbitMqHandle::nak_requeue`].
const ATTEMPT_HEADER: &str = "x-vs-attempt";

type LapinDeliveryStream =
    Pin<Box<dyn futures_util::Stream<Item = Result<LapinDelivery, lapin::Error>> + Send>>;

pub struct RabbitMqListener {
    url: String,
    prefetch: u16,
}

impl RabbitMqListener {
    pub fn new(url: impl Into<String>, prefetch: u16) -> Self {
        Self { url: url.into(), prefetch }
    }

    fn request_queue_args() -> FieldTable {
        let mut args = FieldTable::default();
        args.insert(MAX_PRIORITY_ARG.into(), AMQPValue::LongInt(2));
        args
    }

    /// One consume session over a FRESH connection + channel. Ends on broker
    /// close, consume error, or cancel; [`BusListener::run`] opens the next
    /// one, so a broker restart costs one redelivery cycle, not the worker.
    async fn session(
        &self,
        queue: &str,
        pipeline: &Arc<dyn ScanPipelinePort>,
        cancel: &CancellationToken,
    ) -> Result<(), lapin::Error> {
        let connection = Connection::connect(&self.url, ConnectionProperties::default()).await?;
        let channel = connection.create_channel().await?;
        // Publisher confirms for requeue republishes: the original delivery
        // is only acked once the replacement is confirmed queued.
        channel.confirm_select(ConfirmSelectOptions::default()).await?;
        channel
            .queue_declare(
                queue,
                QueueDeclareOptions { durable: true, ..Default::default() },
                Self::request_queue_args(),
            )
            .await?;
        channel.basic_qos(self.prefetch, BasicQosOptions::default()).await?;
        let consumer = channel
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
            let attempt = delivery_attempt(&raw);
            match serde_json::from_slice::<SampleRequestV1>(&raw.data)
                .map_err(|e| format!("json: {e}"))
                .and_then(|dto| dto.to_model().map_err(|e| format!("validation: {e}")))
            {
                Ok(request) => {
                    let handle = Arc::new(RabbitMqHandle {
                        acker: raw.acker,
                        channel: channel.clone(),
                        queue: queue.to_owned(),
                        payload: raw.data.clone(),
                        properties: raw.properties.clone(),
                        attempt,
                    });
                    pipeline.clone().ingest(Delivery { request, attempt, handle });
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

/// Attempt for this delivery: the republish header when present, otherwise
/// the redelivered-flag approximation (foreign publishers, pre-upgrade
/// messages). Never below 1.
fn delivery_attempt(raw: &LapinDelivery) -> u8 {
    let fallback = u8::from(raw.redelivered).saturating_add(1);
    let attempt = raw.properties.headers().as_ref().and_then(|headers| {
        headers.inner().get(ATTEMPT_HEADER).and_then(|value| match value {
            AMQPValue::ShortInt(i) => u8::try_from((*i).max(0)).ok(),
            AMQPValue::LongInt(i) => u8::try_from((*i).max(0)).ok(),
            AMQPValue::ShortUInt(u) => u8::try_from(*u).ok(),
            AMQPValue::LongUInt(u) => u8::try_from(*u).ok(),
            _ => None,
        })
    });
    attempt.unwrap_or(fallback).max(1)
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
        let mut backoff = INITIAL_BACKOFF;
        loop {
            if cancel.is_cancelled() {
                return;
            }
            match self.session(&queue, &pipeline, &cancel).await {
                Ok(()) => {
                    // A session that ended cleanly (cancel / stream close)
                    // must not leave later blips waiting the grown backoff.
                    backoff = INITIAL_BACKOFF;
                    tracing::debug!(queue = %queue, "rabbitmq session ended");
                }
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
struct RabbitMqHandle {
    acker: lapin::acker::Acker,
    channel: Channel,
    queue: String,
    payload: Vec<u8>,
    properties: BasicProperties,
    attempt: u8,
}

impl RabbitMqHandle {
    fn log(result: Result<bool, lapin::Error>, operation: &'static str) {
        if let Err(err) = result {
            tracing::warn!(error = %err, operation, "rabbitmq settlement failed");
        }
    }

    /// Attempt-carrying requeue: republish the request with an incremented
    /// `x-vs-attempt` header and ack the original only after the broker
    /// confirms the replacement. `nack(requeue: true)` cannot carry a
    /// header, and without a header the retry bound is not enforceable.
    async fn requeue_with_attempt(&self) {
        let next_attempt = self.attempt.saturating_add(1).max(2);
        let mut headers = FieldTable::default();
        headers.insert(ATTEMPT_HEADER.into(), AMQPValue::LongInt(i32::from(next_attempt)));
        let properties = self.properties.clone().with_headers(headers);

        let publish = self
            .channel
            .basic_publish(
                "", // default exchange: routing key = queue name
                &self.queue,
                BasicPublishOptions::default(),
                &self.payload.clone(),
                properties,
            )
            .await;
        let confirm = match publish {
            Ok(confirm) => confirm,
            Err(err) => {
                Self::log(Err(err), "requeue-publish");
                // The original stays unacked: the broker redelivers it.
                return;
            }
        };
        match confirm.await {
            // Confirmed queued: retire the original delivery.
            Ok(Confirmation::Ack(_) | Confirmation::NotRequested) => {
                Self::log(self.acker.ack(BasicAckOptions::default()).await, "requeue-ack");
            }
            Ok(Confirmation::Nack(_)) => {
                tracing::warn!(
                    attempt = self.attempt,
                    "broker nacked the requeue republish; original stays unacked for redelivery"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "requeue republish confirm failed; original stays unacked"
                );
            }
        }
    }
}

#[async_trait]
impl DeliveryHandle for RabbitMqHandle {
    async fn ack(&self) {
        Self::log(self.acker.ack(BasicAckOptions::default()).await, "ack");
    }

    async fn nak_requeue(&self) {
        self.requeue_with_attempt().await;
    }

    async fn discard(&self) {
        Self::log(
            self.acker.nack(BasicNackOptions { requeue: false, ..Default::default() }).await,
            "discard",
        );
    }
}
