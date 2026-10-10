//! vsd - the versa-scan worker daemon (composition root #1).
//!
//! Sandbox role (M3): consume -> batch -> fetch -> scan -> report.
//! Openbox role + self-update land in M5.

mod scanner_registry;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use versa_scan_core::models::worker::WorkerRole;
use versa_scan_core::ports::driven::fetch::SampleFetcherPort;
use versa_scan_core::ports::driving::scan_pipeline::ScanPipelinePort;
use versa_scan_core::services::Orchestrator;
use versa_scan_infra::config::Configuration;
use versa_scan_infra::outbound_adapters::fetch::HttpFetcher;

#[derive(Parser)]
#[command(name = "vsd", version, about = "versa-scan worker daemon")]
struct Cli {
    /// Path to the config file (default: ./versa-scan.toml).
    #[arg(long, env = "VSD_CONFIG")]
    config: Option<PathBuf>,
    /// Lower the default log filter to debug.
    #[arg(long)]
    debug: bool,
    /// Probe every known scanner and exit (replaces the C# reflection scan).
    #[arg(long)]
    detect: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Check the update server for a newer worker version, print, exit.
    UpdateCheck,
    /// Download, verify, and swap in a pending worker update, then exit.
    UpdateApply,
    /// Register the autostart entry for the openbox role (Windows Task
    /// Scheduler / systemd), then exit.
    InstallTask,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    versa_scan_infra::observability::init(cli.debug);

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "vsd failed");
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Configuration::load(cli.config.as_deref())?;
    if cli.detect {
        scanner_registry::detect(&config).await;
        return Ok(());
    }
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "<unknown>".to_owned());
    let role = config.worker_role(&hostname)?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = role.as_str(),
        hostname = %hostname,
        "vsd starting"
    );

    if let Some(command) = cli.command {
        match command {
            Command::UpdateCheck | Command::UpdateApply | Command::InstallTask => {
                bail!("subcommand not implemented yet (milestone M5)")
            }
        }
    }

    match role {
        WorkerRole::Sandbox => run_sandbox(config).await,
        WorkerRole::Openbox => bail!("openbox role (update loop) lands in milestone M5"),
    }
}

async fn run_sandbox(config: Configuration) -> anyhow::Result<()> {
    let scanner = scanner_registry::build(&config)?;
    if !scanner.is_installed().await.unwrap_or(false) {
        bail!(
            "scanner {:?} is not installed/reachable; stopping (use --detect to probe)",
            scanner.id().as_str()
        );
    }
    let profile = scanner.profile().await.unwrap_or_default();
    tracing::info!(scanner = %scanner.id().as_str(), av = %profile.av_name, "scanner ready");

    let publishers = versa_scan_infra::outbound_adapters::bus::connect(&config.bus)
        .await
        .context("bus connect (publishers)")?;
    let listener = versa_scan_infra::inbound_adapters::bus::connect(&config.bus)
        .await
        .context("bus connect (listener)")?;

    let fetcher: Arc<dyn SampleFetcherPort> = Arc::new(
        HttpFetcher::new(
            Duration::from_secs(config.worker.fetch_timeout_secs),
            config.worker.max_file_size,
        )
        .map_err(anyhow::Error::msg)?,
    );

    let orchestrator = Arc::new(
        Orchestrator::new(
            scanner.clone(),
            fetcher,
            publishers.report.clone(),
            config.worker.workspace_root.clone(),
            config.orchestrator_settings(),
            config.worker_info(WorkerRole::Sandbox),
        )
        .context("orchestrator setup")?,
    );

    let cancel = CancellationToken::new();
    tokio::spawn(watch_shutdown(cancel.clone()));

    let pipeline_task = tokio::spawn({
        let orchestrator = Arc::clone(&orchestrator);
        let cancel = cancel.clone();
        async move { orchestrator.run(cancel).await }
    });

    tracing::info!(scanner = %scanner.id().as_str(), "consuming scan requests");
    listener.run(scanner.id(), orchestrator, cancel).await;

    // Listener ended (shutdown signal): give the pipeline a moment to
    // finish its final flush.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), pipeline_task).await;
    tracing::info!("vsd stopped");
    Ok(())
}

async fn watch_shutdown(cancel: CancellationToken) {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutdown signal received");
    cancel.cancel();
}
