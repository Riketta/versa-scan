//! Driven ports (outbound edge): contracts the core uses to reach the
//! world. Implemented by outbound adapters, called by core services.
//!
//! One active adapter per port per process, selected and wired at the
//! composition root.

pub mod fetch;
pub mod report_publisher;
pub mod request_publisher;
pub mod scanner;
pub mod scheduler;
pub mod self_update;

pub use fetch::FetchError;
pub use fetch::FetchedFile;
pub use fetch::SampleFetcherPort;
pub use report_publisher::ReportPublisherPort;
pub use request_publisher::PublishError;
pub use request_publisher::RequestPublisherPort;
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
