//! Core services: pure, unit-tested pipeline components plus one
//! orchestrator wiring them together.

pub mod orchestrator;
pub mod planner;
pub mod retry;
pub mod validation;
pub mod workspace;

pub use orchestrator::Orchestrator;
pub use orchestrator::OrchestratorSettings;
pub use planner::BatchPlanner;
pub use planner::PlannerEvent;
pub use retry::Disposition;
pub use retry::Failure;
pub use retry::RetryPolicy;
pub use validation::reconcile;
pub use workspace::BatchWorkspace;
pub use workspace::WorkspaceManager;
