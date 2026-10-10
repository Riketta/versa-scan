//! vsd library: worker roles and platform registration, split out of
//! `main.rs` so the openbox update loop is testable with fakes.

pub mod install;
pub mod openbox;
pub mod scanner_registry;
