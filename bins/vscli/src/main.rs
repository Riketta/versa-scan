//! vscli - the versa-scan CLI (composition root #2). Replaces the old
//! backend/frontend for now: submits samples, serves them to workers over an
//! embedded artifact server, and (with `--wait`) collects reports.
//!
//! Implementation lands in M4.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vscli", version, about = "versa-scan CLI")]
struct Cli {
    /// Path to the config file (default: ./versa-scan.toml).
    #[arg(long, env = "VSCLI_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long)]
    debug: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash and store samples, publish scan requests to the bus.
    Submit {
        /// Files (or directories) to submit.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Sample priority.
        #[arg(short, long, value_enum, default_value = "normal")]
        priority: PriorityArg,
        /// Scanner(s) to scan with (`all` = every known scanner).
        #[arg(short, long, default_value = "all")]
        scanner: String,
        /// Wait for reports and print a result table.
        #[arg(short = 'w', long)]
        wait: bool,
    },
    /// Run the embedded artifact server standalone.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
    },
    /// Print stored reports for a sample.
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

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    versa_scan_infra::observability::init(cli.debug);

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let _config = versa_scan_infra::config::Configuration::load(cli.config.as_deref())?;
    match cli.command {
        Command::Submit { .. }
        | Command::Serve { .. }
        | Command::Reports { .. }
        | Command::Status => anyhow::bail!("not implemented yet (milestone M4)"),
    }
}
