//! RabbitMQ report waiter: declares the session's report queue (the
//! requester owns declaration - the worker publishes to it via the default
//! exchange) and consumes it with manual acks.

use std::pin::Pin;

use async_trait::async_trait;
use futures_util::StreamExt;
use lapin::message::Delivery as LapinDelivery;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, QueueDeclareOptions};
use lapin::{Channel, Connection, ConnectionProperties};
use versa_scan_core::models::sample::ReportDest;

use super::{
    BoxReportStream, IncomingReport, ListenerError, ReportItem, ReportStream, ReportWaiter,
};
use crate::wire::ScanReportV1;

pub struct RabbitMqReportWaiter {
    channel: Channel,
    _connection: Connection,
}

impl RabbitMqReportWaiter {
    pub async fn connect(url: &str) -> Result<Self, ListenerError> {
        let connection = Connection::connect(url, ConnectionProperties::default())
            .await
            .map_err(|e| ListenerError::Connection(format!("rabbitmq connect: {e}")))?;
        let channel = connection
            .create_channel()
            .await
            .map_err(|e| ListenerError::Connection(format!("rabbitmq channel: {e}")))?;
        Ok(Self { channel, _connection: connection })
    }
}

type LapinDeliveryStream =
    Pin<Box<dyn futures_util::Stream<Item = Result<LapinDelivery, lapin::Error>> + Send>>;

struct RabbitReportStream {
    inner: LapinDeliveryStream,
}

impl RabbitReportStream {
    fn decode(delivery: &LapinDelivery) -> Result<IncomingReport, String> {
        let dest = ReportDest::new(delivery.routing_key.as_str());
        let dto: ScanReportV1 =
            serde_json::from_slice(&delivery.data).map_err(|e| format!("json: {e}"))?;
        let report = dto.to_model(dest.clone()).map_err(|e| e.to_string())?;
        Ok(IncomingReport { report, dest })
    }
}

#[async_trait]
impl ReportStream for RabbitReportStream {
    async fn next(&mut self) -> Option<ReportItem> {
        loop {
            let delivery = self.inner.next().await?;
            match delivery {
                Err(err) => {
                    return Some(Err(ListenerError::Connection(format!(
                        "rabbitmq consume: {err}"
                    ))));
                }
                Ok(delivery) => match Self::decode(&delivery) {
                    Ok(incoming) => {
                        delivery.acker.ack(BasicAckOptions::default()).await.ok();
                        return Some(Ok(incoming));
                    }
                    Err(reason) => {
                        // Undecodable reports cannot be requeued usefully;
                        // terminate them and keep the session alive.
                        delivery
                            .acker
                            .nack(lapin::options::BasicNackOptions {
                                requeue: false,
                                ..Default::default()
                            })
                            .await
                            .ok();
                        tracing::warn!(reason = %reason, "terminated undecodable report");
                        continue;
                    }
                },
            }
        }
    }
}

#[async_trait]
impl ReportWaiter for RabbitMqReportWaiter {
    async fn listen(&self, dest: &ReportDest) -> Result<BoxReportStream, ListenerError> {
        // `dest` is the session queue name; requester-owned declaration,
        // exclusive + auto-delete: it lives exactly as long as this wait.
        self.channel
            .queue_declare(
                dest.as_str(),
                QueueDeclareOptions {
                    durable: false,
                    exclusive: true,
                    auto_delete: true,
                    ..Default::default()
                },
                lapin::types::FieldTable::default(),
            )
            .await
            .map_err(|e| ListenerError::Connection(format!("rabbitmq queue_declare: {e}")))?;
        let consumer = self
            .channel
            .basic_consume(dest.as_str(), "", BasicConsumeOptions::default(), Default::default())
            .await
            .map_err(|e| ListenerError::Connection(format!("rabbitmq basic_consume: {e}")))?;
        let inner: LapinDeliveryStream = Box::pin(consumer);
        Ok(Box::new(RabbitReportStream { inner }))
    }
}
