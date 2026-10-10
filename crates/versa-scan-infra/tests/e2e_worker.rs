//! End-to-end worker test (M3 gate): artifact HTTP server -> HttpFetcher ->
//! Orchestrator (DebugScanner) <- InMemoryListener, reports published via
//! the in-memory publisher. Unit-speed, any OS.

#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use versa_scan_core::models::digest::Sha256Digest;
use versa_scan_core::models::ids::{CorrelationId, SampleId, ScannerId};
use versa_scan_core::models::priority::Priority;
use versa_scan_core::models::report::ScanReport;
use versa_scan_core::models::sample::ReportDest;
use versa_scan_core::models::verdict::ScanOutcome;
use versa_scan_core::models::worker::{WorkerInfo, WorkerRole};
use versa_scan_core::ports::driven::fetch::SampleFetcherPort;
use versa_scan_core::ports::driven::report_publisher::ReportPublisherPort;
use versa_scan_core::ports::driven::request_publisher::RequestPublisherPort;
use versa_scan_core::ports::driven::scanner::ScannerPort;
use versa_scan_core::ports::driving::scan_pipeline::ScanPipelinePort;
use versa_scan_core::services::{Orchestrator, OrchestratorSettings};
use versa_scan_infra::inbound_adapters::bus::{BusListener, in_memory};
use versa_scan_infra::outbound_adapters::fetch::HttpFetcher;
use versa_scan_infra::outbound_adapters::scanners::DebugScanner;

// ---------------------------------------------------------------- artifact server

/// Serves `/<name>` from an in-memory map (minimal HTTP/1.1).
async fn spawn_artifact_server(files: Vec<(String, Vec<u8>)>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let files: Arc<std::collections::HashMap<String, Vec<u8>>> =
        Arc::new(files.into_iter().collect());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let files = Arc::clone(&files);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                        break;
                    }
                    buf.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&buf);
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let name = path.trim_start_matches('/').to_owned();
                let response = match files.get(&name) {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes()
                    .into_iter()
                    .chain(body.iter().copied())
                    .collect::<Vec<u8>>(),
                    None => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                };
                socket.write_all(&response).await.unwrap();
                socket.shutdown().await.unwrap();
            });
        }
    });
    format!("http://{address}")
}

// ---------------------------------------------------------------- helpers

fn sha_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().fold(String::new(), |mut acc, b| {
        acc.push_str(&format!("{b:02x}"));
        acc
    })
}

fn request(base: &str, id: &str, bytes: &[u8]) -> versa_scan_core::models::sample::SampleRequest {
    versa_scan_core::models::sample::SampleRequest {
        sample_id: SampleId::new(id).unwrap(),
        url: format!("{base}/{id}"),
        sha256: Sha256Digest::from_hex(&sha_hex(bytes)).unwrap(),
        size: bytes.len() as u64,
        priority: Priority::Normal,
        report_dest: ReportDest::new("reports"),
        correlation_id: CorrelationId::new("corr").unwrap(),
        extensions: vec![],
        created_at: time::OffsetDateTime::now_utc(),
    }
}

async fn wait_for<T>(what: &str, f: impl Fn() -> Option<T>) -> T {
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

// ---------------------------------------------------------------- the test

#[tokio::test]
async fn end_to_end_submit_fetch_scan_report() {
    // Artifacts: one clean, one detected, one skipped, one oversized (cap 64
    // bytes -> terminal error report).
    let clean = b"just some bytes";
    let eicar = b"X5O!P%@AP[EICAR-TEST-FILE]";
    let locked = b"locked content";
    let oversized = vec![7u8; 512];
    let base = spawn_artifact_server(vec![
        ("clean1.bin".to_owned(), clean.to_vec()),
        ("eicar2.bin".to_owned(), eicar.to_vec()),
        ("locked3.bin".to_owned(), locked.to_vec()),
        ("big4.bin".to_owned(), oversized.clone()),
    ])
    .await;

    let (listener, publisher) = in_memory::pair();
    let workspace_root = std::env::temp_dir().join(format!("vs-e2e-{}", uuid::Uuid::new_v4()));

    let scanner: Arc<dyn ScannerPort> = Arc::new(DebugScanner::new());
    // Max file size below the oversized sample -> terminal TooLarge report.
    let fetcher: Arc<dyn SampleFetcherPort> =
        Arc::new(HttpFetcher::new(Duration::from_secs(10), 64).unwrap());
    let report_publisher: Arc<dyn ReportPublisherPort> = publisher.clone();

    let orchestrator = Arc::new(
        Orchestrator::new(
            scanner,
            fetcher,
            report_publisher,
            workspace_root.clone(),
            OrchestratorSettings {
                files_per_batch: 4,
                batch_idle_timeout: Duration::from_millis(50),
                scan_timeout: Duration::from_secs(10),
                fetch_concurrency: 2,
                scanner_backoff: Duration::from_millis(10),
            },
            WorkerInfo {
                hostname: "e2e-host".to_owned(),
                os: "e2e-os".to_owned(),
                role: WorkerRole::Sandbox,
            },
        )
        .unwrap(),
    );

    let cancel = CancellationToken::new();
    let pipeline_task = {
        let orchestrator = Arc::clone(&orchestrator);
        let cancel = cancel.clone();
        tokio::spawn(async move { orchestrator.run(cancel).await })
    };
    let listener_task = {
        let cancel = cancel.clone();
        let scanner_id = ScannerId::new("debug").unwrap();
        let pipeline: Arc<dyn ScanPipelinePort> = orchestrator;
        tokio::spawn(
            async move { BusListener::run(&*listener, scanner_id, pipeline, cancel).await },
        )
    };

    // Submit: the CLI's role in this dance.
    let requests = [
        request(&base, "clean1.bin", clean),
        request(&base, "eicar2.bin", eicar),
        request(&base, "locked3.bin", locked),
        request(&base, "big4.bin", &oversized),
    ];
    for req in &requests {
        RequestPublisherPort::publish_request(&*publisher, ScannerId::new("debug").unwrap(), req)
            .await
            .unwrap();
    }

    // Collect: all four reports must arrive (3 scanned + 1 terminal fetch error).
    wait_for("all four reports", || {
        let reports = publisher.reports();
        (reports.len() == 4).then_some(reports)
    })
    .await;

    let reports: Vec<ScanReport> = publisher.reports();
    let outcome = |id: &str| {
        reports
            .iter()
            .find(|r| r.sample_id.as_str() == id)
            .map(|r| r.outcome.clone())
            .unwrap_or_else(|| panic!("no report for {id}"))
    };
    assert_eq!(outcome("clean1.bin"), ScanOutcome::Clean);
    assert!(matches!(outcome("eicar2.bin"), ScanOutcome::Detected { .. }));
    assert!(
        matches!(outcome("locked3.bin"), ScanOutcome::Skipped { .. }),
        "locked3 outcome was {:?}",
        outcome("locked3.bin")
    );
    assert!(
        matches!(outcome("big4.bin"), ScanOutcome::Error { .. }),
        "oversized sample gets a terminal error report, never silence"
    );
    for report in &reports {
        assert_eq!(report.worker.hostname, "e2e-host");
        assert_eq!(report.attempt, 1);
    }

    // Every delivery settles as acked: reports were published and confirmed.
    wait_for("all settlements", || {
        let settled = publisher.settled();
        (settled.len() == 4 && settled.iter().all(|(_, op)| *op == "ack")).then_some(settled)
    })
    .await;

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), pipeline_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), listener_task).await;

    // Workspace cleanup guarantee: nothing left behind after the run.
    let leftovers =
        std::fs::read_dir(&workspace_root).map(|mut entries| entries.count()).unwrap_or(0);
    assert_eq!(leftovers, 0, "workspace must be swept after settled runs");
}
