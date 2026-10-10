//! Broker integration tests - skipped unless the corresponding env var is
//! set (Linux CI sets them with docker-compose services; see
//! `.github/workflows/ci.yml`, `docker-compose.yaml`):
//!
//! - `VERSA_SCAN_TEST_RABBITMQ` - amqp URL (e.g.
//!   `amqp://guest:guest@localhost:5672/%2f`)
//! - `VERSA_SCAN_TEST_NATS` - nats URL (e.g. `nats://localhost:4222`)
//!
//! Each test uses a unique scanner id / report destination so parallel runs
//! never interfere.

#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use versa_scan_core::models::ids::{CorrelationId, SampleId, ScannerId};
use versa_scan_core::models::priority::Priority;
use versa_scan_core::models::report::{ScanReport, ScanTiming};
use versa_scan_core::models::sample::{ReportDest, SampleRequest};
use versa_scan_core::models::verdict::ScanOutcome;
use versa_scan_core::models::worker::{WorkerInfo, WorkerRole};
use versa_scan_core::ports::driven::report_publisher::ReportPublisherPort;
use versa_scan_core::ports::driven::request_publisher::RequestPublisherPort;
use versa_scan_core::ports::driving::scan_pipeline::{Delivery, ScanPipelinePort};
use versa_scan_infra::inbound_adapters::bus::BusListener;
use versa_scan_infra::outbound_adapters::bus::nats::NatsPublisher;
use versa_scan_infra::outbound_adapters::bus::rabbitmq::RabbitMqPublisher;
use versa_scan_infra::wire::{SampleRequestV1, ScanReportV1};

// ---------------------------------------------------------------- helpers

fn rabbit_url() -> Option<String> {
    std::env::var("VERSA_SCAN_TEST_RABBITMQ").ok().filter(|s| !s.is_empty())
}

fn nats_url() -> Option<String> {
    std::env::var("VERSA_SCAN_TEST_NATS").ok().filter(|s| !s.is_empty())
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn request(id: &str, priority: Priority) -> SampleRequest {
    SampleRequestV1 {
        schema: 1,
        sample_id: id.to_owned(),
        url: format!("http://art:8080/samples/{id}"),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
        size: 1,
        priority: priority.as_str().to_owned(),
        report_dest: unique("vs.scan.reports.test"),
        correlation_id: unique("corr"),
        extensions: vec![],
        created_at: time::OffsetDateTime::now_utc(),
    }
    .to_model()
    .unwrap()
}

fn report(sample_id: &str, scanner: &str) -> ScanReport {
    ScanReport {
        sample_id: SampleId::new(sample_id).unwrap(),
        correlation_id: CorrelationId::new("corr").unwrap(),
        scanner: ScannerId::new(scanner).unwrap(),
        report_dest: ReportDest::new("unused"),
        worker: WorkerInfo {
            hostname: "it-host".to_owned(),
            os: "IT OS".to_owned(),
            role: WorkerRole::Sandbox,
        },
        av: None,
        outcome: ScanOutcome::Clean,
        extras: Default::default(),
        timing: ScanTiming {
            started_at: time::OffsetDateTime::UNIX_EPOCH,
            finished_at: time::OffsetDateTime::UNIX_EPOCH,
            duration: Duration::ZERO,
        },
        attempt: 1,
    }
}

/// Test pipeline: collects deliveries for assertions.
#[derive(Clone)]
struct CollectPipeline {
    tx: mpsc::UnboundedSender<Delivery>,
}

#[async_trait]
impl ScanPipelinePort for CollectPipeline {
    fn ingest(self: Arc<Self>, delivery: Delivery) {
        let _ = self.tx.send(delivery);
    }
    fn stream_ended(&self) {}
}

async fn wait_for<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(value) = f() {
            return value;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_async<T, Fut>(what: &str, mut f: impl FnMut() -> Fut) -> T
where
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(value) = f().await {
            return value;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn spawn_listener(
    listener: Arc<dyn BusListener>,
    scanner: ScannerId,
) -> (mpsc::UnboundedReceiver<Delivery>, CancellationToken, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let pipeline: Arc<dyn ScanPipelinePort> = Arc::new(CollectPipeline { tx });
    let cancel = CancellationToken::new();
    let task = {
        let cancel = cancel.clone();
        tokio::spawn(async move { listener.run(scanner, pipeline, cancel).await })
    };
    (rx, cancel, task)
}

// ---------------------------------------------------------------- rabbitmq

#[tokio::test]
async fn rabbitmq_pubsub_and_ack() {
    let Some(url) = rabbit_url() else {
        eprintln!("skipping: VERSA_SCAN_TEST_RABBITMQ not set");
        return;
    };
    let scanner = ScannerId::new(unique("it-clamd")).unwrap();
    let listener =
        versa_scan_infra::inbound_adapters::bus::rabbitmq::RabbitMqListener::connect(&url, 20)
            .await
            .unwrap();
    let publisher = RabbitMqPublisher::connect(&url).await.unwrap();

    let (mut rx, cancel, task) = spawn_listener(Arc::new(listener), scanner.clone());

    publisher.publish_request(scanner.clone(), &request("r1", Priority::Normal)).await.unwrap();
    publisher.publish_request(scanner.clone(), &request("r2", Priority::Normal)).await.unwrap();

    let d1 = wait_for("first delivery", || rx.try_recv().ok()).await;
    let d2 = wait_for("second delivery", || rx.try_recv().ok()).await;
    assert_eq!(d1.request.sample_id.as_str(), "r1");
    assert_eq!(d2.request.sample_id.as_str(), "r2");
    assert_eq!(d1.attempt, 1);

    d1.handle.ack().await;
    d2.handle.ack().await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn rabbitmq_nak_redelivers() {
    let Some(url) = rabbit_url() else {
        eprintln!("skipping: VERSA_SCAN_TEST_RABBITMQ not set");
        return;
    };
    let scanner = ScannerId::new(unique("it-clamd")).unwrap();
    let listener =
        versa_scan_infra::inbound_adapters::bus::rabbitmq::RabbitMqListener::connect(&url, 20)
            .await
            .unwrap();
    let publisher = RabbitMqPublisher::connect(&url).await.unwrap();

    let (mut rx, cancel, task) = spawn_listener(Arc::new(listener), scanner.clone());
    publisher.publish_request(scanner.clone(), &request("nak1", Priority::Normal)).await.unwrap();

    let first = wait_for("first delivery", || rx.try_recv().ok()).await;
    assert_eq!(first.attempt, 1);
    first.handle.nak_requeue().await;

    let second = wait_for("redelivered", || rx.try_recv().ok()).await;
    assert_eq!(second.request.sample_id.as_str(), "nak1");
    assert_eq!(second.attempt, 2, "redelivered flag maps to attempt 2");
    second.handle.ack().await;

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn rabbitmq_priority_order() {
    let Some(url) = rabbit_url() else {
        eprintln!("skipping: VERSA_SCAN_TEST_RABBITMQ not set");
        return;
    };
    let scanner = ScannerId::new(unique("it-clamd")).unwrap();
    let publisher = RabbitMqPublisher::connect(&url).await.unwrap();

    // Queue both BEFORE the listener starts; the sorted queue must hand the
    // high-priority request first.
    publisher.publish_request(scanner.clone(), &request("low", Priority::Low)).await.unwrap();
    publisher.publish_request(scanner.clone(), &request("high", Priority::High)).await.unwrap();

    let listener =
        versa_scan_infra::inbound_adapters::bus::rabbitmq::RabbitMqListener::connect(&url, 20)
            .await
            .unwrap();
    let (mut rx, cancel, task) = spawn_listener(Arc::new(listener), scanner.clone());

    let first = wait_for("first delivery", || rx.try_recv().ok()).await;
    let second = wait_for("second delivery", || rx.try_recv().ok()).await;
    assert_eq!(first.request.sample_id.as_str(), "high", "priority wins");
    assert_eq!(second.request.sample_id.as_str(), "low");
    first.handle.ack().await;
    second.handle.ack().await;

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn rabbitmq_report_publish_round_trip() {
    let Some(url) = rabbit_url() else {
        eprintln!("skipping: VERSA_SCAN_TEST_RABBITMQ not set");
        return;
    };
    let publisher = RabbitMqPublisher::connect(&url).await.unwrap();

    // The requester owns the report queue declaration.
    let dest_queue = unique("vs.scan.reports.test");
    let connection =
        lapin::Connection::connect(&url, lapin::ConnectionProperties::default()).await.unwrap();
    let channel = connection.create_channel().await.unwrap();
    channel
        .queue_declare(
            &dest_queue,
            lapin::options::QueueDeclareOptions { durable: true, ..Default::default() },
            lapin::types::FieldTable::default(),
        )
        .await
        .unwrap();

    let mut rep = report("rep1", "clamd");
    rep.report_dest = ReportDest::new(dest_queue.clone());
    publisher.publish_report(&rep, &ReportDest::new(dest_queue.clone())).await.unwrap();

    let fetched = wait_for_async("report message", || {
        let channel = channel.clone();
        let dest = dest_queue.clone();
        async move {
            channel
                .basic_get(&dest, lapin::options::BasicGetOptions::default())
                .await
                .ok()
                .flatten()
                .map(|get| get.delivery)
        }
    })
    .await;

    let dto: ScanReportV1 = serde_json::from_slice(&fetched.data).unwrap();
    assert_eq!(dto.sample_id, "rep1");
    assert_eq!(dto.scanner, "clamd");
    assert_eq!(dto.schema, 1);
    fetched.acker.ack(lapin::options::BasicAckOptions::default()).await.unwrap();
}

// -------------------------------------------------------------------- nats

#[tokio::test]
async fn nats_pubsub_and_ack() {
    let Some(url) = nats_url() else {
        eprintln!("skipping: VERSA_SCAN_TEST_NATS not set");
        return;
    };
    let scanner = ScannerId::new(unique("it-clamd")).unwrap();
    let listener = versa_scan_infra::inbound_adapters::bus::nats::NatsListener::connect(
        &url,
        Duration::from_secs(60),
        3,
    )
    .await
    .unwrap();
    let publisher = NatsPublisher::connect(&url).await.unwrap();

    let (mut rx, cancel, task) = spawn_listener(Arc::new(listener), scanner.clone());

    publisher.publish_request(scanner.clone(), &request("n1", Priority::Normal)).await.unwrap();
    publisher.publish_request(scanner.clone(), &request("n2", Priority::Normal)).await.unwrap();

    let d1 = wait_for("first delivery", || rx.try_recv().ok()).await;
    let d2 = wait_for("second delivery", || rx.try_recv().ok()).await;
    assert_eq!(d1.request.sample_id.as_str(), "n1");
    assert_eq!(d2.request.sample_id.as_str(), "n2");
    assert_eq!(d1.attempt, 1);

    d1.handle.ack().await;
    d2.handle.ack().await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn nats_publish_dedupe() {
    let Some(url) = nats_url() else {
        eprintln!("skipping: VERSA_SCAN_TEST_NATS not set");
        return;
    };
    let scanner = ScannerId::new(unique("it-clamd")).unwrap();
    let listener = versa_scan_infra::inbound_adapters::bus::nats::NatsListener::connect(
        &url,
        Duration::from_secs(60),
        3,
    )
    .await
    .unwrap();
    let publisher = NatsPublisher::connect(&url).await.unwrap();

    let (mut rx, cancel, task) = spawn_listener(Arc::new(listener), scanner.clone());
    let req = request("dedupe-me", Priority::Normal);
    publisher.publish_request(scanner.clone(), &req).await.unwrap();
    publisher.publish_request(scanner.clone(), &req).await.unwrap();

    let only = wait_for("the deduplicated delivery", || rx.try_recv().ok()).await;
    assert_eq!(only.request.sample_id.as_str(), "dedupe-me");
    only.handle.ack().await;

    // No second delivery within the window.
    let extra = rx.try_recv().is_ok();
    assert!(!extra, "duplicate publish must be deduped by Nats-Msg-Id");
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn nats_nak_redelivers_with_attempt_count() {
    let Some(url) = nats_url() else {
        eprintln!("skipping: VERSA_SCAN_TEST_NATS not set");
        return;
    };
    let scanner = ScannerId::new(unique("it-clamd")).unwrap();
    let listener = versa_scan_infra::inbound_adapters::bus::nats::NatsListener::connect(
        &url,
        Duration::from_secs(60),
        3,
    )
    .await
    .unwrap();
    let publisher = NatsPublisher::connect(&url).await.unwrap();

    let (mut rx, cancel, task) = spawn_listener(Arc::new(listener), scanner.clone());
    publisher.publish_request(scanner.clone(), &request("nak-n1", Priority::Normal)).await.unwrap();

    let first = wait_for("first delivery", || rx.try_recv().ok()).await;
    assert_eq!(first.attempt, 1);
    first.handle.nak_requeue().await;

    let second = wait_for("redelivered", || rx.try_recv().ok()).await;
    assert_eq!(second.request.sample_id.as_str(), "nak-n1");
    assert_eq!(second.attempt, 2, "delivery count maps to attempt");
    second.handle.ack().await;

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn nats_report_publish_reaches_subscriber() {
    let Some(url) = nats_url() else {
        eprintln!("skipping: VERSA_SCAN_TEST_NATS not set");
        return;
    };
    let publisher = NatsPublisher::connect(&url).await.unwrap();

    // Subscriber (the CLI role) listens on its report destination BEFORE
    // the report is published.
    let dest = unique("vs.scan.reports.test");
    let subscriber = async_nats::connect(&url).await.unwrap();
    let mut sub = subscriber.subscribe(dest.clone()).await.unwrap();

    let rep = report("sub1", "debug");
    publisher.publish_report(&rep, &ReportDest::new(dest.clone())).await.unwrap();

    let message = tokio::time::timeout(Duration::from_secs(10), async move {
        use futures_util::StreamExt;
        sub.next().await
    })
    .await
    .expect("report within timeout")
    .expect("subscription alive");
    let dto: ScanReportV1 = serde_json::from_slice(&message.payload).unwrap();
    assert_eq!(dto.sample_id, "sub1");
    assert_eq!(dto.scanner, "debug");
}
