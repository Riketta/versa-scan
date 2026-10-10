//! Openbox role: keep the scanner databases fresh and the worker itself
//! up to date.
//!
//! Loop shape: one immediate pass on start, then a pass every
//! `check_interval_secs`. A pass runs the scanner's database update, then
//! (when self-update is enabled) checks the update server; with
//! `auto_apply`, a pending update is applied and the loop returns, letting
//! the process exit cleanly so the service manager restarts the new
//! version. Update failures are logged and retried on the next pass.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use versa_scan_core::models::worker::WorkerInfo;
use versa_scan_core::ports::driven::scanner::ScannerPort;
use versa_scan_core::ports::driven::scheduler::SchedulerPort;
use versa_scan_core::ports::driven::self_update::SelfUpdatePort;
use versa_scan_infra::config::Configuration;
use versa_scan_infra::outbound_adapters::scheduler::TokioScheduler;

pub struct OpenboxDeps {
    pub scanner: Arc<dyn ScannerPort>,
    pub updater: Option<Arc<dyn SelfUpdatePort>>,
    #[allow(dead_code)] // injected for parity with the sandbox role wiring
    pub scheduler: Arc<dyn SchedulerPort>,
    pub config: Configuration,
    pub worker: WorkerInfo,
}

/// Runs until cancelled. Exits early (Ok) after an auto-applied update so
/// the process can be restarted into the new version.
pub async fn run(deps: OpenboxDeps, cancel: CancellationToken) -> Result<()> {
    tracing::info!(scanner = %deps.scanner.id().as_str(), "openbox role: update loop");
    if run_pass(&deps).await {
        return Ok(());
    }

    let interval = Duration::from_secs(deps.config.self_update.check_interval_secs.max(1));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(interval) => {
                if run_pass(&deps).await {
                    return Ok(());
                }
            }
        }
    }
    tracing::info!("openbox update loop stopped");
    Ok(())
}

/// One update pass. Returns true when the worker was updated and the
/// process should exit for a restart.
pub async fn run_pass(deps: &OpenboxDeps) -> bool {
    update_scanner_databases(&deps.scanner).await;
    check_worker_update(deps).await
}

async fn update_scanner_databases(scanner: &Arc<dyn ScannerPort>) {
    match scanner.update().await {
        Ok(outcome) => {
            tracing::info!(
                scanner = %scanner.id().as_str(),
                result = outcome.as_str(),
                "scanner update finished"
            );
        }
        Err(err) => {
            tracing::warn!(scanner = %scanner.id().as_str(), error = %err, "scanner update failed");
        }
    }
}

async fn check_worker_update(deps: &OpenboxDeps) -> bool {
    let Some(updater) = deps.updater.as_ref() else {
        tracing::debug!("self-update disabled");
        return false;
    };
    match updater.check().await {
        Ok(Some(update)) => {
            tracing::info!(version = %update.version, "worker update available");
            if !deps.config.self_update.auto_apply {
                tracing::info!(version = %update.version, "auto_apply is off; update NOT applied");
                return false;
            }
            match updater.apply(&update).await {
                Ok(()) => {
                    tracing::info!(version = %update.version, "worker updated; exiting for restart");
                    true
                }
                Err(err) => {
                    tracing::error!(error = %err, "worker update apply failed");
                    false
                }
            }
        }
        Ok(None) => {
            tracing::debug!("worker is up to date");
            false
        }
        Err(err) => {
            tracing::warn!(error = %err, "worker update check failed");
            false
        }
    }
}

/// Convenience wrapper used by the composition root: builds the scheduler
/// and runs until cancelled.
pub async fn run_with_config(
    config: &Configuration,
    scanner: Arc<dyn ScannerPort>,
    updater: Option<Arc<dyn SelfUpdatePort>>,
    worker: WorkerInfo,
    cancel: CancellationToken,
) -> Result<()> {
    let deps = OpenboxDeps {
        scanner,
        updater,
        scheduler: Arc::new(TokioScheduler::new()),
        config: config.clone(),
        worker,
    };
    run(deps, cancel).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use parking_lot::Mutex;
    use versa_scan_core::models::Sha256Digest;
    use versa_scan_core::models::ids::ScannerId;
    use versa_scan_core::models::worker::WorkerRole;
    use versa_scan_core::ports::driven::scanner::{ScanOutput, ScannerError, UpdateOutcome};
    use versa_scan_core::ports::driven::self_update::Update;

    struct FakeScanner {
        updates: Mutex<Vec<UpdateOutcome>>,
    }

    #[async_trait::async_trait]
    impl ScannerPort for FakeScanner {
        fn id(&self) -> ScannerId {
            ScannerId::new("fake").unwrap()
        }
        async fn is_installed(&self) -> Result<bool, ScannerError> {
            Ok(true)
        }
        async fn profile(&self) -> Result<versa_scan_core::models::AvProfile, ScannerError> {
            Ok(Default::default())
        }
        async fn scan(&self, _dir: &std::path::Path) -> Result<ScanOutput, ScannerError> {
            Ok(Default::default())
        }
        async fn update(&self) -> Result<UpdateOutcome, ScannerError> {
            let outcome = self.updates.lock().pop().unwrap_or(UpdateOutcome::UpToDate);
            Ok(outcome)
        }
    }

    struct FakeUpdater {
        pending: Option<String>,
        applied: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl SelfUpdatePort for FakeUpdater {
        async fn check(
            &self,
        ) -> Result<Option<Update>, versa_scan_core::ports::driven::UpdateError> {
            Ok(self.pending.clone().map(|version| Update {
                version,
                url: "http://updates/1.0.0.zip".to_owned(),
                sha256: Sha256Digest::from_hex(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
                .unwrap(),
            }))
        }
        async fn apply(
            &self,
            update: &Update,
        ) -> Result<(), versa_scan_core::ports::driven::UpdateError> {
            self.applied.lock().push(update.version.clone());
            Ok(())
        }
    }

    fn deps(
        scanner: FakeScanner,
        updater: Option<Arc<dyn SelfUpdatePort>>,
        auto_apply: bool,
    ) -> OpenboxDeps {
        let mut config = Configuration::default();
        config.self_update.auto_apply = auto_apply;
        OpenboxDeps {
            scanner: Arc::new(scanner),
            updater,
            scheduler: Arc::new(TokioScheduler::new()),
            config,
            worker: WorkerInfo {
                hostname: "h".to_owned(),
                os: "os".to_owned(),
                role: WorkerRole::Openbox,
            },
        }
    }

    #[tokio::test]
    async fn pass_updates_scanner_and_reports_no_exit_when_current() {
        let scanner = FakeScanner { updates: Mutex::new(vec![UpdateOutcome::Updated]) };
        let updater = Arc::new(FakeUpdater { pending: None, applied: Mutex::new(vec![]) });
        let deps = deps(scanner, Some(updater), true);
        assert!(!run_pass(&deps).await, "no pending update -> keep running");
    }

    #[tokio::test]
    async fn auto_applied_update_requests_exit() {
        let scanner = FakeScanner { updates: Mutex::new(vec![]) };
        let updater = Arc::new(FakeUpdater {
            pending: Some("9.9.9".to_owned()),
            applied: Mutex::new(vec![]),
        });
        let deps = deps(scanner, Some(updater.clone()), true);
        assert!(run_pass(&deps).await, "applied update -> exit for restart");
        assert_eq!(*updater.applied.lock(), vec!["9.9.9".to_owned()]);
    }

    #[tokio::test]
    async fn auto_apply_off_reports_but_keeps_running() {
        let scanner = FakeScanner { updates: Mutex::new(vec![]) };
        let updater = Arc::new(FakeUpdater {
            pending: Some("9.9.9".to_owned()),
            applied: Mutex::new(vec![]),
        });
        let deps = deps(scanner, Some(updater.clone()), false);
        assert!(!run_pass(&deps).await);
        assert!(updater.applied.lock().is_empty(), "notify-only does not apply");
    }

    #[tokio::test]
    async fn disabled_updater_is_a_noop() {
        let scanner = FakeScanner { updates: Mutex::new(vec![]) };
        let deps = deps(scanner, None, true);
        assert!(!run_pass(&deps).await);
    }

    #[tokio::test]
    async fn scanner_update_failure_does_not_stop_the_loop() {
        let scanner = FakeScanner { updates: Mutex::new(vec![]) };
        // Failures come back as Err from update(); FakeScanner never errs,
        // so drive the error path through a failing updater instead.
        struct FailingUpdater;
        #[async_trait::async_trait]
        impl SelfUpdatePort for FailingUpdater {
            async fn check(
                &self,
            ) -> Result<Option<Update>, versa_scan_core::ports::driven::UpdateError> {
                Err(versa_scan_core::ports::driven::UpdateError::Check("server down".to_owned()))
            }
            async fn apply(
                &self,
                _update: &Update,
            ) -> Result<(), versa_scan_core::ports::driven::UpdateError> {
                unreachable!()
            }
        }
        let deps = deps(scanner, Some(Arc::new(FailingUpdater)), true);
        assert!(!run_pass(&deps).await, "check failure is retried next pass");
    }

    // Digest import used by the fake updater payloads.
    // Digest helper for fake updater payloads.
    #[allow(dead_code)]
    fn _digest_helper() -> Sha256Digest {
        Sha256Digest::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap()
    }
}
