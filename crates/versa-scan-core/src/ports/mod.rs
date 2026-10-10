//! Ports (contracts between the hexagon and the world).
//!
//! Direction separation (hexagonal):
//! - [`driving`] - inbound edge. Implemented by core services, called by
//!   inbound adapters (things that start work: bus listeners).
//! - [`driven`] - outbound edge. Implemented by outbound adapters, called
//!   by core services (things the core needs: scanners, fetchers,
//!   publishers, scheduler, updater).

pub mod driven;
pub mod driving;
