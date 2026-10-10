//! Process-tree termination for spawned scanner processes.
//!
//! Windows AV CLIs regularly spawn children; a timeout must take the whole
//! tree down (`taskkill /T /F`), not just the direct child. POSIX kills the
//! direct child (good enough for the current adapters; a process-group
//! design can land with the first POSIX CLI scanner that needs it).

use tokio::process::Command;

/// Best-effort process-tree kill. Never panics; failures are logged.
pub async fn kill_tree(pid: u32) {
    #[cfg(windows)]
    {
        match Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
            .await
        {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                tracing::warn!(
                    pid,
                    stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                    "taskkill failed"
                );
            }
            Err(err) => tracing::warn!(pid, error = %err, "taskkill spawn failed"),
        }
    }
    #[cfg(not(windows))]
    {
        // No tree semantics without a process-group contract yet.
        let _ = pid;
        tracing::debug!(pid, "process-tree kill not implemented on this platform");
    }
}
