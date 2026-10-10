//! Tokio-based scheduler adapter: interval jobs with
//! `MissedTickBehavior::Delay` (a slow job skips missed ticks instead of
//! burst-catching-up), cancellable via handle.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use versa_scan_core::ports::driven::scheduler::{JobCallback, JobHandle, SchedulerPort};

pub struct TokioScheduler;

impl TokioScheduler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TokioScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SchedulerPort for TokioScheduler {
    fn every(&self, name: &str, interval: Duration, job: Arc<dyn JobCallback>) -> JobHandle {
        if interval.is_zero() {
            tracing::error!(job = name, "scheduler interval must be non-zero; job not started");
            let token = CancellationToken::new();
            token.cancel();
            return JobHandle::new(token);
        }
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let name = name.to_owned();
        tokio::spawn(async move {
            let cancel = task_cancel;
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick completes immediately; the contract is "first
            // run after one interval", so consume it.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        tracing::debug!(job = %name, "scheduler tick");
                        job.run().await;
                    }
                }
            }
            tracing::debug!(job = %name, "scheduler job stopped");
        });
        JobHandle::new(cancel)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CounterJob {
        count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl JobCallback for CounterJob {
        async fn run(&self) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn runs_on_interval_and_stops_on_cancel() {
        let scheduler = TokioScheduler::new();
        let count = Arc::new(AtomicUsize::new(0));
        let handle = scheduler.every(
            "counter",
            Duration::from_millis(20),
            Arc::new(CounterJob { count: Arc::clone(&count) }),
        );

        tokio::time::sleep(Duration::from_millis(150)).await;
        let observed = count.load(Ordering::SeqCst);
        assert!(observed >= 2, "expected at least 2 ticks, got {observed}");

        handle.cancel();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let after_cancel = count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(count.load(Ordering::SeqCst), after_cancel, "no ticks after cancel");
    }

    #[tokio::test]
    async fn zero_interval_is_rejected() {
        let scheduler = TokioScheduler::new();
        let count = Arc::new(AtomicUsize::new(0));
        let job_count = Arc::clone(&count);
        let handle =
            scheduler.every("broken", Duration::ZERO, Arc::new(CounterJob { count: job_count }));
        assert!(handle.is_cancelled(), "zero-interval job must not start");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}
