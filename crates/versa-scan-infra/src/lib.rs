//! Infrastructure adapters for versa-scan. Everything that touches the
//! outside world lives here; the core never imports this crate.
//!
//! Structure (hexagonal, versa-bot convention):
//! - [`inbound_adapters`] - driving edge: they start the core's work
//!   (bus listeners feed `ScanPipelinePort`).
//! - [`outbound_adapters`] - driven edge: they answer the core's needs
//!   (scanners, fetchers, bus publishers, scheduler, self-update).
//! - [`wire`] - the bus wire contract (schema-versioned DTOs + topology
//!   naming) shared by both bus adapter edges.

pub mod config;
pub mod inbound_adapters;
pub mod observability;
pub mod outbound_adapters;
pub mod wire;
