//! vsd - the versa-scan worker daemon (composition root #1).
//!
//! Scan pipeline lands in M3; update loop and scheduler registration in M5.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vsd", version, about = "versa-scan worker daemon")]
struct Cli {
    /// Path to the config file (default: ./versa-scan.toml).
    #[arg(long, env = "VSD_CONFIG")]
    config: Option<PathBuf>,
    /// Lower the default log filter to debug.
    #[arg(long)]
    debug: bool,
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
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = versa_scan_infra::config::Configuration::load(cli.config.as_deref())?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = config.worker.role.as_deref().unwrap_or("<auto>"),
        "vsd starting"
    );

    if let Some(command) = cli.command {
        match command {
            Command::UpdateCheck | Command::UpdateApply | Command::InstallTask => {
                anyhow::bail!("subcommand not implemented yet (milestone M5)")
            }
        }
    }

    anyhow::bail!("scan pipeline not wired yet (milestone M3) - config validated, nothing to do")
}
