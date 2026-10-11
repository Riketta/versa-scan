//! Worker deployment identity, resolved by infrastructure at the composition
//! root and stamped into every report.

use std::str::FromStr;

/// Deployment role of a worker instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkerRole {
    /// Scans samples from the bus.
    Sandbox,
    /// Keeps scanner databases fresh; update loop + self-update.
    Openbox,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown worker role {0:?} (expected \"sandbox\" or \"openbox\")")]
pub struct UnknownRole(String);

impl WorkerRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            WorkerRole::Sandbox => "sandbox",
            WorkerRole::Openbox => "openbox",
        }
    }
}

impl FromStr for WorkerRole {
    type Err = UnknownRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sandbox" => Ok(WorkerRole::Sandbox),
            "openbox" => Ok(WorkerRole::Openbox),
            other => Err(UnknownRole(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInfo {
    pub hostname: String,
    /// Human-readable OS string (kernel/version/arch), adapter-formatted.
    pub os: String,
    pub role: WorkerRole,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn role_parses() {
        assert_eq!("sandbox".parse::<WorkerRole>().unwrap(), WorkerRole::Sandbox);
        assert_eq!("openbox".parse::<WorkerRole>().unwrap(), WorkerRole::Openbox);
        assert!("devbox".parse::<WorkerRole>().is_err());
    }
}
