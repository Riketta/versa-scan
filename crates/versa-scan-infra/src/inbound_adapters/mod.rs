//! Inbound (driving) adapters: they start the core's work.

pub mod bus;
pub mod reports;

/// Shared error shape for inbound bus edges (connection/configuration).
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("bus connection failed: {0}")]
    Connection(String),
    #[error("bus configuration error: {0}")]
    Configuration(String),
}
