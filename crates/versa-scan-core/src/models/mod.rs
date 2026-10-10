//! Domain models. Internal vocabulary of the hexagon - infrastructure maps
//! its wire DTOs onto these at the boundary (ACL); nothing here carries
//! wire-format knowledge.

/// Scanner slugs this build knows about. The worker's registry implements
/// these; the CLI's `--scanner all` fans out to every one of them.
pub const KNOWN_SCANNERS: &[&str] = &["clamd", "defender", "debug"];

pub mod av;
pub mod batch;
pub mod digest;
pub mod ids;
pub mod priority;
pub mod report;
pub mod sample;
pub mod verdict;
pub mod worker;

pub use av::AvProfile;
pub use av::LicenseInfo;
pub use batch::BatchAddError;
pub use batch::BatchFile;
pub use batch::ScanBatch;
pub use digest::Sha256Digest;
pub use ids::BatchId;
pub use ids::CorrelationId;
pub use ids::InvalidId;
pub use ids::SampleId;
pub use ids::ScannerId;
pub use priority::Priority;
pub use report::ReportExtras;
pub use report::ScanReport;
pub use report::ScanTiming;
pub use sample::ReportDest;
pub use sample::SampleRequest;
pub use verdict::Detection;
pub use verdict::FileVerdict;
pub use verdict::ScanOutcome;
pub use verdict::SkipReason;
pub use worker::UnknownRole;
pub use worker::WorkerInfo;
pub use worker::WorkerRole;
