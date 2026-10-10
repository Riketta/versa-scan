//! Dispatch priority. Three bands instead of the C# system's raw 0-100 byte:
//! the only consumers of priority are the RabbitMQ adapter (native
//! `x-max-priority`) and batch preemption logic. NATS ignores priority by
//! design decision (see docs/DESIGN.md).

use std::fmt;

/// Ordered low-to-high: [`Priority::High`] is the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    Low,
    Normal,
    High,
}

impl Priority {
    pub const ALL: [Priority; 3] = [Priority::Low, Priority::Normal, Priority::High];

    /// Wire representation used by the bus DTOs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Priority::Low => "low",
            Priority::Normal => "normal",
            Priority::High => "high",
        }
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_low_to_high() {
        assert!(Priority::Low < Priority::Normal);
        assert!(Priority::Normal < Priority::High);
    }

    #[test]
    fn wire_names() {
        assert_eq!(Priority::High.as_str(), "high");
        assert_eq!(Priority::Normal.as_str(), "normal");
        assert_eq!(Priority::Low.as_str(), "low");
    }
}
