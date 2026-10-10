//! RabbitMQ publisher (`lapin`, outbound edge).
//!
//! - Requests go to `vs.scan.requests.<scanner>` (declared idempotently with
//!   `x-max-priority = 2`, durable) so a CLI-only deployment still finds the
//!   queue; the worker's listener declares the same shape.
//! - Reports go to the request's `report_dest` queue via the default
//!   exchange; the requester owns its declaration.
//! - Both publishes are persistent and confirmed before Ok.

use async_trait::async_trait;
use lapin::options::{BasicPublishOptions, ConfirmSelectOptions, QueueDeclareOptions};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties};
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::models::priority::Priority;
use versa_scan_core::models::report::ScanReport;
use versa_scan_core::models::sample::{ReportDest, SampleRequest};
use versa_scan_core::ports::driven::{PublishError, ReportPublisherPort, RequestPublisherPort};

use crate::wire::{SampleRequestV1, ScanReportV1, request_queue_name};

const MAX_PRIORITY_ARG: &str = "x-max-priority";
const EXCHANGE: &str = "";

#[derive(Clone)]
pub struct RabbitMqPublisher {
    channel: Channel,
}

impl RabbitMqPublisher {
    pub async fn connect(url: &str) -> Result<Self, PublishError> {
        let connection = Connection::connect(url, ConnectionProperties::default())
            .await
            .map_err(|e| PublishError::Connection(format!("rabbitmq connect: {e}")))?;
        let channel = connection
            .create_channel()
            .await
            .map_err(|e| PublishError::Connection(format!("rabbitmq channel: {e}")))?;
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(|e| PublishError::Connection(format!("rabbitmq confirm_select: {e}")))?;
        Ok(Self { channel })
    }

    fn request_queue_args() -> FieldTable {
        let mut args = FieldTable::default();
        args.insert(MAX_PRIORITY_ARG.into(), AMQPValue::LongInt(2));
        args
    }

    async fn declare_request_queue(&self, queue: &str) -> Result<(), PublishError> {
        self.channel
            .queue_declare(
                queue,
                QueueDeclareOptions { durable: true, ..Default::default() },
                Self::request_queue_args(),
            )
            .await
            .map_err(|e| PublishError::Connection(format!("rabbitmq queue_declare: {e}")))?;
        Ok(())
    }

    async fn publish_confirmed(
        &self,
        routing_key: &str,
        payload: &[u8],
        priority: u8,
    ) -> Result<(), PublishError> {
        let confirm = self
            .channel
            .basic_publish(
                EXCHANGE,
                routing_key,
                BasicPublishOptions::default(),
                payload,
                BasicProperties::default().with_delivery_mode(2).with_priority(priority),
            )
            .await
            .map_err(|e| PublishError::Publish(format!("rabbitmq publish: {e}")))?;
        match confirm.await.map_err(|e| PublishError::Publish(format!("rabbitmq confirm: {e}")))? {
            lapin::publisher_confirm::Confirmation::Ack(_)
            | lapin::publisher_confirm::Confirmation::NotRequested => Ok(()),
            lapin::publisher_confirm::Confirmation::Nack(_) => {
                Err(PublishError::Publish("rabbitmq nacked the publish".to_owned()))
            }
        }
    }
}

#[async_trait]
impl RequestPublisherPort for RabbitMqPublisher {
    async fn publish_request(
        &self,
        scanner: ScannerId,
        request: &SampleRequest,
    ) -> Result<(), PublishError> {
        let queue = request_queue_name(&scanner);
        self.declare_request_queue(&queue).await?;
        let dto = SampleRequestV1::from_model(request);
        let payload = serde_json::to_vec(&dto)
            .map_err(|e| PublishError::Publish(format!("request serialize: {e}")))?;
        // Wire the DTO's priority band onto the AMQP property so the
        // broker's priority queue can order deliveries (High > Normal > Low).
        let priority = match request.priority {
            Priority::Low => 0u8,
            Priority::Normal => 1,
            Priority::High => 2,
        };
        self.publish_confirmed(&queue, &payload, priority).await
    }
}

#[async_trait]
impl ReportPublisherPort for RabbitMqPublisher {
    async fn publish_report(
        &self,
        report: &ScanReport,
        dest: &ReportDest,
    ) -> Result<(), PublishError> {
        let dto = ScanReportV1::from_model(report);
        let payload = serde_json::to_vec(&dto)
            .map_err(|e| PublishError::Publish(format!("report serialize: {e}")))?;
        self.publish_confirmed(dest.as_str(), &payload, 0).await
    }
}
