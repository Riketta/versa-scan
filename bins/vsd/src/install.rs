//! Autostart registration for the openbox role (`vsd install-task`).
//!
//! - Windows: a Task Scheduler task (`ONSTART`, SYSTEM, highest run level).
//! - Linux: a systemd unit under `/etc/systemd/system` (enable via
//!   `systemctl enable --now versa-scan`; printed after writing).

use anyhow::{Context as _, Result};

const TASK_NAME: &str = "versa-scan";

/// Registers the autostart entry for the current executable.
pub async fn install() -> Result<()> {
    let exe = std::env::current_exe().context("resolve current executable")?;
    #[cfg(windows)]
    {
        let action = format!("\"{}\"", exe.display());
        let output = tokio::process::Command::new("schtasks")
            .args([
                "/Create", "/F", "/RU", "SYSTEM", "/RL", "HIGHEST", "/SC", "ONSTART", "/TN",
                TASK_NAME, "/TR", &action,
            ])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
            .await
            .context("spawn schtasks")?;
        if !output.status.success() {
            anyhow::bail!(
                "schtasks failed ({}): {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        println!("scheduled task {TASK_NAME:?} created for {}", exe.display());
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let unit = format!(
            "# managed by vsd install-task\n\
             [Unit]\n\
             Description=versa-scan worker\n\
             After=network-online.target\n\
             \n\
             [Service]\n\
             ExecStart={}\n\
             Restart=on-failure\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            exe.display()
        );
        let path = format!("/etc/systemd/system/{TASK_NAME}.service");
        std::fs::write(&path, unit).with_context(|| format!("write {path} (root required)"))?;
        println!("systemd unit written to {path}");
        println!("enable it with:  systemctl daemon-reload && systemctl enable --now {TASK_NAME}");
        Ok(())
    }
}
