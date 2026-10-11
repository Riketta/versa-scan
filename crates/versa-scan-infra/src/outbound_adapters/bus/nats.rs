//! NATS JetStream publisher (`async-nats`, outbound edge).
//!
//! Ensures both streams exist (`VS_SCAN_REQUESTS` workqueue over
//! `vs.scan.requests.>`, `VS_SCAN_REPORTS` limits-retention over
//! `vs.scan.reports.>`), then publishes with `Nats-Msg-Id` dedupe:
//! requests dedupe on `<sample_id>.<scanner>`, reports on
//! `<sample_id>.<scanner>.<attempt>` (worker-side republish dedupe).
//! Priority is a deliberate no-op on NATS (docs/DESIGN.md).

use std::time::Duration;

use async_nats::header::HeaderMap;
use async_nats::jetstream::Context;
use async_nats::jetstream::stream;
use async_trait::async_trait;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::models::report::ScanReport;
use versa_scan_core::models::sample::{ReportDest, SampleRequest};
use versa_scan_core::ports::driven::{PublishError, ReportPublisherPort, RequestPublisherPort};

use crate::wire::{SampleRequestV1, ScanReportV1};

const REQUESTS_STREAM: &str = "VS_SCAN_REQUESTS";
const REPORTS_STREAM: &str = "VS_SCAN_REPORTS";
const MESSAGES_SUBJECT: &str = "vs.scan.requests.>";
const REPORTS_SUBJECT: &str = "vs.scan.reports.>";
const NATS_MSG_ID: &str = "Nats-Msg-Id";
const DUPLICATE_WINDOW: Duration = Duration::from_secs(120);
const REPORTS_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Clone)]
pub struct NatsPublisher {
    context: Context,
}

impl NatsPublisher {
    pub async fn connect(url: &str) -> Result<Self, PublishError> {
        let client = async_nats::connect(url)
            .await
            .map_err(|e| PublishError::Connection(format!("nats connect: {e}")))?;
        let context = async_nats::jetstream::new(client);
        ensure_streams(&context).await?;
        Ok(Self { context })
    }

    async fn publish_json_with_msg_id(
        &self,
        subject: &str,
        msg_id: String,
        payload: &[u8],
    ) -> Result<(), PublishError> {
        let mut headers = HeaderMap::new();
        headers.insert(NATS_MSG_ID, msg_id.as_str());
        let ack = self
            .context
            .publish_with_headers(subject.to_owned(), headers, payload.to_vec().into())
            .await
            .map_err(|e| PublishError::Publish(format!("nats publish: {e}")))?;
        ack.await.map_err(|e| PublishError::Publish(format!("nats publish ack: {e}")))?;
        Ok(())
    }
}

pub(crate) async fn ensure_streams(context: &Context) -> Result<(), PublishError> {
    context
        .get_or_create_stream(stream::Config {
            name: REQUESTS_STREAM.to_owned(),
            subjects: vec![MESSAGES_SUBJECT.to_owned()],
            retention: stream::RetentionPolicy::WorkQueue,
            duplicate_window: DUPLICATE_WINDOW,
            ..Default::default()
        })
        .await
        .map_err(|e| PublishError::Connection(format!("nats requests stream: {e}")))?;
    context
        .get_or_create_stream(stream::Config {
            name: REPORTS_STREAM.to_owned(),
            subjects: vec![REPORTS_SUBJECT.to_owned()],
            retention: stream::RetentionPolicy::Limits,
            max_age: REPORTS_MAX_AGE,
            duplicate_window: DUPLICATE_WINDOW,
            ..Default::default()
        })
        .await
        .map_err(|e| PublishError::Connection(format!("nats reports stream: {e}")))?;
    Ok(())
}

#[async_trait]
impl RequestPublisherPort for NatsPublisher {
    async fn publish_request(
        &self,
        scanner: ScannerId,
        request: &SampleRequest,
    ) -> Result<(), PublishError> {
        let dto = SampleRequestV1::from_model(request);
        let payload = serde_json::to_vec(&dto)
            .map_err(|e| PublishError::Publish(format!("request serialize: {e}")))?;
        let subject = format!("vs.scan.requests.{}", scanner.as_str());
        // Dedupe key must include the scanner: `--scanner all` publishes one
        // request per scanner with the same sample_id, and JetStream dedupe
        // is stream-wide on Nats-Msg-Id. Scanner slugs are dot-free, so the
        // composite stays unambiguous (sample ids are charset-validated and
        // dot-tolerant, scanner is always the last token).
        let msg_id = format!("{}.{}", request.sample_id.as_str(), scanner.as_str());
        self.publish_json_with_msg_id(&subject, msg_id, &payload).await
    }
}

#[async_trait]
impl ReportPublisherPort for NatsPublisher {
    async fn publish_report(
        &self,
        report: &ScanReport,
        dest: &ReportDest,
    ) -> Result<(), PublishError> {
        let dto = ScanReportV1::from_model(report);
        let payload = serde_json::to_vec(&dto)
            .map_err(|e| PublishError::Publish(format!("report serialize: {e}")))?;
        let msg_id =
            format!("{}.{}.{}", report.sample_id.as_str(), report.scanner.as_str(), report.attempt);
        self.publish_json_with_msg_id(dest.as_str(), msg_id, &payload).await
    }
}
