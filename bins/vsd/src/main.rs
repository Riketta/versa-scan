//! vsd - the versa-scan worker daemon (composition root #1).
//!
//! Sandbox role: consume -> batch -> fetch -> scan -> report.
//! Openbox role: scanner database updates + worker self-update.
//! `vsd update check|apply` and `vsd install-task` drive the same
//! machinery manually.

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
use versa_scan_core::ports::driven::self_update::SelfUpdatePort;
use versa_scan_core::services::Orchestrator;
use versa_scan_infra::config::Configuration;
use versa_scan_infra::outbound_adapters::fetch::HttpFetcher;
use versa_scan_infra::outbound_adapters::self_update as self_update_adapter;

#[derive(Parser)]
#[command(name = "vsd", version, about = "versa-scan worker daemon")]
struct Cli {
    /// Path to the config file (default: ./versa-scan.toml).
    #[arg(long, env = "VSD_CONFIG")]
    config: Option<PathBuf>,
    /// Lower the default log filter to debug.
    #[arg(long)]
    debug: bool,
    /// Probe every known scanner and exit.
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
    /// Register the autostart entry for the openbox role, then exit.
    InstallTask,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    versa_scan_infra::observability::init(cli.debug);

    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            tracing::error!(error = %err, "vsd failed");
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let config = Configuration::load(cli.config.as_deref())?;
    config.validate()?;
    if cli.detect {
        scanner_registry::detect(&config).await;
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(command) = cli.command {
        let updater = build_updater(&config)?;
        return match command {
            Command::UpdateCheck => update_check(updater).await.map(|()| ExitCode::SUCCESS),
            Command::UpdateApply => update_apply(updater).await.map(|()| ExitCode::SUCCESS),
            Command::InstallTask => {
                vsd::install::install(cli.config.as_deref()).await.map(|()| ExitCode::SUCCESS)
            }
        };
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

    let scanner = scanner_registry::build(&config)?;
    let updater = build_updater(&config)?;
    let worker_info = config.worker_info(role);
    let cancel = CancellationToken::new();
    tokio::spawn(watch_shutdown(cancel.clone()));

    match role {
        WorkerRole::Sandbox => {
            run_sandbox(config, scanner, updater, worker_info, cancel).await?;
            Ok(ExitCode::SUCCESS)
        }
        WorkerRole::Openbox => {
            let restart =
                vsd::openbox::run_with_config(&config, scanner, updater, worker_info, cancel)
                    .await?;
            if restart {
                tracing::info!(
                    code = vsd::openbox::RESTART_EXIT_CODE,
                    "exiting with the restart code so the service manager starts the new version"
                );
                Ok(ExitCode::from(vsd::openbox::RESTART_EXIT_CODE))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

fn build_updater(config: &Configuration) -> anyhow::Result<Option<Arc<dyn SelfUpdatePort>>> {
    self_update_adapter::from_config(&config.self_update).map_err(anyhow::Error::msg)
}

async fn update_check(updater: Option<Arc<dyn SelfUpdatePort>>) -> anyhow::Result<()> {
    let Some(updater) = updater else {
        println!("self-update is disabled ([self_update].enabled = false)");
        return Ok(());
    };
    match updater.check().await? {
        Some(update) => println!("update available: {} ({})", update.version, update.url),
        None => println!("worker is up to date"),
    }
    Ok(())
}

async fn update_apply(updater: Option<Arc<dyn SelfUpdatePort>>) -> anyhow::Result<()> {
    let Some(updater) = updater else {
        bail!("self-update is disabled ([self_update].enabled = false)");
    };
    let Some(update) = updater.check().await? else {
        println!("worker is up to date; nothing to apply");
        return Ok(());
    };
    updater.apply(&update).await?;
    println!("applied worker update {}; restart vsd to run it", update.version);
    Ok(())
}

async fn run_sandbox(
    config: Configuration,
    scanner: Arc<dyn versa_scan_core::ports::driven::scanner::ScannerPort>,
    _updater: Option<Arc<dyn SelfUpdatePort>>,
    worker_info: versa_scan_core::models::WorkerInfo,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
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
            config.fetch_allowed_hosts(),
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
            worker_info,
        )
        .context("orchestrator setup")?,
    );

    let pipeline_task = tokio::spawn({
        let orchestrator = Arc::clone(&orchestrator);
        let cancel = cancel.clone();
        async move { orchestrator.run(cancel).await }
    });

    tracing::info!(scanner = %scanner.id().as_str(), "consuming scan requests");
    listener.run(scanner.id(), orchestrator, cancel).await;

    // Listener ended (shutdown signal): give the pipeline a bounded moment
    // to finish its final flush (configurable; the final flush itself is
    // cancellation-aware and requeues instead of scanning new batches).
    let grace = Duration::from_secs(config.shutdown_grace_secs());
    match tokio::time::timeout(grace, pipeline_task).await {
        Ok(Ok(())) => {}
        Ok(Err(join)) => {
            tracing::error!(error = %join, "pipeline task ended with a panic");
        }
        Err(_elapsed) => {
            tracing::warn!(
                grace_secs = grace.as_secs(),
                "shutdown grace expired; exiting with unsettled work (broker will redeliver)"
            );
        }
    }
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
