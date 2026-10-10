//! versa-scan core: the hexagon.
//!
//! Domain models, driven/driving ports, and the pure services that implement
//! the scan pipeline's brain (batching, retries, validation, orchestration).
//!
//! Dependency contract: this crate never depends on infrastructure - no
//! broker client, no HTTP client, no filesystem paths beyond `std::path`
//! values handed in through ports. `tokio`, `tracing`, `serde`, `time`,
//! `thiserror`, `uuid`, and `futures-util` are facade exceptions (same
//! category as versa-bot's `tracing`-is-the-observability-port rule), so the
//! core stays testable and portable without abstraction ceremony.

pub mod models;
pub mod ports;
pub mod services;
