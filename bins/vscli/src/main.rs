//! vscli - the versa-scan CLI (composition root #2): submits samples,
//! serves them to workers over an embedded artifact server, and (with
//! `--wait`) collects reports.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use versa_scan_core::models::priority::Priority;
use versa_scan_core::models::sample::ReportDest;
use versa_scan_core::models::{KNOWN_SCANNERS, SampleId};
use versa_scan_infra::config::Configuration;
use versa_scan_infra::inbound_adapters::reports;
use versa_scan_infra::outbound_adapters::bus;
use vscli::reports_log::ReportsLog;
use vscli::server;
use vscli::session::{Session, SubmitOptions, render_table};
use vscli::store::SampleStore;

#[derive(Parser)]
#[command(name = "vscli", version, about = "versa-scan CLI")]
struct Cli {
    /// Path to the config file (default: ./versa-scan.toml).
    #[arg(long, env = "VSCLI_CONFIG")]
    config: Option<PathBuf>,
    /// Sample store directory (default: per-OS data dir).
    #[arg(long, env = "VSCLI_STORE")]
    store: Option<PathBuf>,
    #[arg(long)]
    debug: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash and store samples, publish scan requests to the bus.
    Submit {
        /// Files to submit.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Sample priority.
        #[arg(short, long, value_enum, default_value = "normal")]
        priority: PriorityArg,
        /// Scanner(s) to scan with: a slug or `all` (every known scanner).
        #[arg(short, long, default_value = "all")]
        scanner: String,
        /// Wait for reports and print a result table.
        #[arg(short = 'w', long)]
        wait: bool,
        /// Report-collection timeout in seconds (with --wait).
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        /// Bind address of the embedded artifact server.
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
        /// Base URL workers use to reach the artifact server (NAT: the
        /// externally reachable host).
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        advertise: String,
    },
    /// Run the artifact server standalone (persistent submissions).
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
    },
    /// Print stored reports for a sample id.
    Reports { sample_id: String },
    /// Show storage and bus status.
    Status,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum PriorityArg {
    Low,
    Normal,
    High,
}

impl From<PriorityArg> for Priority {
    fn from(value: PriorityArg) -> Self {
        match value {
            PriorityArg::Low => Priority::Low,
            PriorityArg::Normal => Priority::Normal,
            PriorityArg::High => Priority::High,
        }
    }
}

fn default_store_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("vscli");
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("vscli");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/vscli");
    }
    PathBuf::from("vscli-store")
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    versa_scan_infra::observability::init(cli.debug);

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "vscli failed");
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Configuration::load(cli.config.as_deref())?;
    let store = Arc::new(SampleStore::open(cli.store.clone().unwrap_or_else(default_store_dir))?);

    match cli.command {
        Command::Submit { paths, priority, scanner, wait, timeout, bind, advertise } => {
            let scanners: Vec<String> = if scanner == "all" {
                KNOWN_SCANNERS.iter().map(|s| s.to_string()).collect()
            } else {
                vec![scanner]
            };
            submit(
                &config,
                &store,
                &paths,
                priority.into(),
                scanners,
                wait,
                timeout,
                &bind,
                &advertise,
            )
            .await
        }
        Command::Serve { bind } => {
            server::serve(store, &bind, &config.artifact_token()).await?;
            Ok(())
        }
        Command::Reports { sample_id } => {
            let log = ReportsLog::open(store.root())?;
            let matches: Vec<_> = log
                .load()?
                .into_iter()
                .filter(|r| r.sample_id.as_str().contains(&sample_id))
                .collect();
            if matches.is_empty() {
                println!("no stored reports for {sample_id:?}");
                return Ok(());
            }
            for report in matches {
                println!(
                    "{}  {}  attempt {}  {}",
                    report.sample_id,
                    report.scanner,
                    report.attempt,
                    outcome_text(&report.outcome),
                );
            }
            Ok(())
        }
        Command::Status => {
            let (count, bytes) = store.stats()?;
            let log = ReportsLog::open(store.root())?;
            let stored_reports = log.load()?.len();
            println!("store:     {} ({} samples, {} bytes)", store.root().display(), count, bytes);
            println!("reports:   {stored_reports} collected");
            println!("bus:       {:?}", config.bus.backend);
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn submit(
    config: &Configuration,
    store: &Arc<SampleStore>,
    paths: &[PathBuf],
    priority: Priority,
    scanners: Vec<String>,
    wait: bool,
    timeout: u64,
    bind: &str,
    advertise: &str,
) -> anyhow::Result<()> {
    for path in paths {
        if !path.is_file() {
            bail!("not a file: {}", path.display());
        }
    }
    // Fail on typos up front: a misspelled slug publishes into a queue no
    // worker will ever consume (and declares it on RabbitMQ).
    for scanner in &scanners {
        if scanner != "all" && !KNOWN_SCANNERS.contains(&scanner.as_str()) {
            bail!("unknown scanner {scanner:?} (known: all, {})", KNOWN_SCANNERS.join(", "));
        }
    }

    let publishers = bus::connect(&config.bus).await.context("bus connect (publishers)")?;
    let waiter = if wait { Some(reports::connect(&config.bus).await?) } else { None };

    // The embedded artifact server must be up (and bound!) before workers
    // fetch; it dies with the submit session (use `vscli serve` for a
    // persistent store). Bind failure used to surface as inexplicable
    // "no report" timeouts - fail loudly instead.
    let mut server_task = {
        let store = Arc::clone(store);
        let bind = bind.to_owned();
        let token = config.artifact_token();
        tokio::spawn(async move { server::serve(store, &bind, &token).await })
    };
    // Wait a beat for the bind outcome: an unbindable port used to surface
    // much later as inexplicable "no report" timeouts.
    match tokio::time::timeout(Duration::from_millis(250), &mut server_task).await {
        Err(_elapsed) => {} // still serving: bound successfully
        Ok(Ok(Ok(()))) => bail!("artifact server exited immediately"),
        Ok(Ok(Err(io))) => bail!("artifact server failed to bind {bind}: {io}"),
        Ok(Err(join)) => bail!("artifact server task panicked: {join}"),
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let (dest_for, wait_dest): (Arc<dyn Fn(&SampleId) -> ReportDest + Send + Sync>, ReportDest) =
        match config.bus.backend {
            versa_scan_infra::config::BusBackend::Nats => {
                let closure_session = session_id.clone();
                (
                    Arc::new(move |id: &SampleId| {
                        ReportDest::new(versa_scan_infra::wire::nats_report_subject(
                            &closure_session,
                            id,
                        ))
                        .expect("generated report dests are valid")
                    }),
                    ReportDest::new(versa_scan_infra::wire::nats_report_session_wildcard(
                        &session_id,
                    ))
                    .expect("generated report dests are valid"),
                )
            }
            versa_scan_infra::config::BusBackend::RabbitMq => {
                let queue = versa_scan_infra::wire::rabbitmq_report_queue(&session_id);
                (
                    Arc::new(move |_id: &SampleId| {
                        ReportDest::new(queue.clone()).expect("generated report dests are valid")
                    }),
                    ReportDest::new(versa_scan_infra::wire::rabbitmq_report_queue(&session_id))
                        .expect("generated report dests are valid"),
                )
            }
        };

    let session = Session::new(
        Arc::clone(store),
        publishers.request.clone(),
        waiter,
        advertise.to_owned(),
        config.artifact_token(),
        dest_for,
        wait_dest,
    );

    let wait_timeout = wait.then_some(Duration::from_secs(timeout));
    let result = session
        .submit(
            paths,
            &SubmitOptions { scanners, priority, wait_timeout },
            Some(&ReportsLog::open(store.root())?),
        )
        .await;

    server_task.abort();

    let result = result?;
    print!("{}", render_table(&result.rows));
    if result.missing > 0 {
        println!("\n{} of {} requests got no report in time", result.missing, result.rows.len());
        bail!("incomplete results");
    }
    if !wait {
        println!("\npublished without waiting (no --wait); sample ids above are per-request");
    }
    Ok(())
}

fn outcome_text(outcome: &versa_scan_core::models::ScanOutcome) -> String {
    use versa_scan_core::models::ScanOutcome;
    match outcome {
        ScanOutcome::Clean => "clean".to_owned(),
        ScanOutcome::Detected { detections } => {
            let names: Vec<String> = detections.iter().map(|d| d.name.clone()).collect();
            format!("DETECTED {}", names.join("; "))
        }
        ScanOutcome::Skipped { reason } => format!("skipped: {}", reason.as_str()),
        ScanOutcome::Error { message } => format!("ERROR {message}"),
    }
}
