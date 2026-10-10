//! Retry policy: maps failures to dispositions. Pure.
//!
//! Contract: nothing is ever silently dropped. A failure either requeues the
//! delivery (bounded by `max_attempts`) or produces a terminal error report
//! back to the requester. This replaces the C# system's reject-twice-then-
//! -vanish behavior and its ack-before-publish loss window.

use crate::ports::driven::FetchError;

/// Total delivery attempts allowed per message (first delivery = attempt 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
}

impl RetryPolicy {
    pub const fn new(max_attempts: u8) -> Self {
        Self { max_attempts }
    }

    pub const DEFAULT_MAX_ATTEMPTS: u8 = 3;
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: Self::DEFAULT_MAX_ATTEMPTS }
    }
}

/// A failure the orchestrator hit while processing a delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Fetching the sample failed (classified by `FetchError`).
    Fetch(FetchError),
    /// The scanner backend is unreachable (daemon down, service starting):
    /// the whole batch goes back for a later attempt.
    ScannerUnavailable(String),
    /// A scanner run completed but failed (parse, crash): terminal for the
    /// affected samples - an error report is produced.
    ScannerFailed(String),
    /// Publishing a report failed: the request must come back so the report
    /// can be delivered (attempt-limited).
    Publish(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Hand the delivery back to the broker for redelivery.
    Requeue,
    /// Stop retrying; the message carries a terminal error for the report.
    Terminal { message: String },
}

impl RetryPolicy {
    /// `attempt` is the broker delivery count of the delivery being decided
    /// (1-based, as [`crate::ports::Delivery::attempt`]).
    pub fn decide(&self, failure: &Failure, attempt: u8) -> Disposition {
        let can_retry = attempt < self.max_attempts;
        match failure {
            Failure::Fetch(err) if err.is_terminal() => {
                Disposition::Terminal { message: err.to_string() }
            }
            Failure::Fetch(err) if can_retry => Disposition::Requeue,
            Failure::Fetch(err) => Disposition::Terminal { message: err.to_string() },
            Failure::ScannerUnavailable(detail) if can_retry => {
                let _ = detail;
                Disposition::Requeue
            }
            Failure::ScannerUnavailable(detail) => {
                Disposition::Terminal { message: format!("scanner unavailable: {detail}") }
            }
            Failure::ScannerFailed(detail) => {
                Disposition::Terminal { message: format!("scan failed: {detail}") }
            }
            Failure::Publish(detail) if can_retry => {
                let _ = detail;
                Disposition::Requeue
            }
            Failure::Publish(detail) => {
                Disposition::Terminal { message: format!("report publish failed: {detail}") }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::models::digest::Sha256Digest;

    fn digest() -> Sha256Digest {
        Sha256Digest::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap()
    }

    const POLICY: RetryPolicy = RetryPolicy::new(3);

    #[test]
    fn terminal_fetch_errors_never_requeue() {
        for err in [
            FetchError::NotFound,
            FetchError::HashMismatch { expected: digest(), actual: digest() },
            FetchError::SizeMismatch { expected: 1, actual: 2 },
            FetchError::TooLarge { limit: 10, actual: 20 },
        ] {
            let d = POLICY.decide(&Failure::Fetch(err.clone()), 1);
            assert!(matches!(d, Disposition::Terminal { .. }), "expected terminal for {err:?}");
        }
    }

    #[test]
    fn transient_fetch_errors_requeue_until_limit() {
        let err = Failure::Fetch(FetchError::Io("conn reset".to_owned()));
        assert_eq!(POLICY.decide(&err, 1), Disposition::Requeue);
        assert_eq!(POLICY.decide(&err, 2), Disposition::Requeue);
        let last = POLICY.decide(&err, 3);
        assert!(matches!(last, Disposition::Terminal { .. }));
    }

    #[test]
    fn scanner_unavailable_requeues_then_terminals() {
        let f = Failure::ScannerUnavailable("clamd down".to_owned());
        assert_eq!(POLICY.decide(&f, 1), Disposition::Requeue);
        assert_eq!(POLICY.decide(&f, 2), Disposition::Requeue);
        assert!(matches!(POLICY.decide(&f, 3), Disposition::Terminal { .. }));
    }

    #[test]
    fn scanner_failed_is_terminal_immediately() {
        let f = Failure::ScannerFailed("bad exit code".to_owned());
        assert!(matches!(POLICY.decide(&f, 1), Disposition::Terminal { .. }));
    }

    #[test]
    fn publish_failure_requeues_then_terminals() {
        let f = Failure::Publish("broker nacked".to_owned());
        assert_eq!(POLICY.decide(&f, 1), Disposition::Requeue);
        assert!(matches!(POLICY.decide(&f, 3), Disposition::Terminal { .. }));
    }
}
