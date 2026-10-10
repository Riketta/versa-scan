//! Ports (driven contracts). Implemented by infrastructure adapters; the
//! core only sees these traits.
//!
//! Cardinality: one active adapter per port per worker, selected and wired at
//! the composition root - exactly versa-bot's "service port" family.

pub mod bus;
pub mod fetch;
pub mod scanner;
pub mod scheduler;
pub mod self_update;

pub use bus::BusError;
pub use bus::BusPort;
pub use bus::Delivery;
pub use bus::DeliveryHandle;
pub use bus::RequestStream;
pub use fetch::FetchError;
pub use fetch::FetchedFile;
pub use fetch::SampleFetcherPort;
pub use scanner::ScanOutput;
pub use scanner::ScannerError;
pub use scanner::ScannerPort;
pub use scanner::UpdateOutcome;
pub use scheduler::JobCallback;
pub use scheduler::JobHandle;
pub use scheduler::SchedulerPort;
pub use self_update::SelfUpdatePort;
pub use self_update::Update;
pub use self_update::UpdateError;
