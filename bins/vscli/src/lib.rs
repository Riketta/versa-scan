//! vscli library: the CLI's driving surface, split out of `main.rs` so the
//! submit/wait/store logic is unit-testable with in-memory adapters.
//!
//! Flow of `submit --wait`:
//! 1. hash + store samples (content-addressed, deduped),
//! 2. start the embedded artifact server (workers download from it),
//! 3. open the report listener for the session (BEFORE publishing),
//! 4. publish one request per (sample, scanner),
//! 5. collect reports until all answered or timeout, print a table,
//! 6. persist every received report to the local log.

pub mod reports_log;
pub mod server;
pub mod session;
pub mod store;
