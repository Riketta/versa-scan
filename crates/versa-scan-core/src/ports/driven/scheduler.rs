//! Periodic background jobs (used by the openbox role). Same shape as
//! versa-bot's scheduler contract: non-zero intervals, delayed (not burst)
//! catch-up semantics live in the adapter.

use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

/// A cancellable job handle. Dropping it does NOT cancel - call
/// [`JobHandle::cancel`] (same style as versa-bot's subscription handles).
#[derive(Clone)]
pub struct JobHandle {
    cancel: CancellationToken,
}

impl JobHandle {
    pub fn new(cancel: CancellationToken) -> Self {
        Self { cancel }
    }

    /// Cancels the job's future ticks. Idempotent.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

/// The job body.
#[async_trait]
pub trait JobCallback: Send + Sync {
    async fn run(&self);
}

#[async_trait]
pub trait SchedulerPort: Send + Sync {
    /// Runs `job` every `interval` until the returned handle is cancelled.
    /// Implementations must enforce `interval > 0` (zero is a configuration
    /// error) and skip missed ticks instead of bursting.
    fn every(
        &self,
        name: &str,
        interval: Duration,
        job: std::sync::Arc<dyn JobCallback>,
    ) -> JobHandle;
}
