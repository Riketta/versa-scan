//! Scanner identity metadata, snapshotted into every report so consumers
//! can attribute verdicts to a specific scanner state.

use std::collections::BTreeMap;

use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LicenseInfo {
    pub license_type: Option<String>,
    pub valid: bool,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AvProfile {
    pub av_name: String,
    pub av_version: Option<String>,
    /// Internal signature-base version, when the scanner exposes one.
    pub bases_version: Option<String>,
    /// When the vendor published the currently loaded bases.
    pub bases_time: Option<OffsetDateTime>,
    /// Last successful `ScannerPort::update` completion.
    pub av_updated_at: Option<OffsetDateTime>,
    /// Named components and their versions, when available.
    pub components: BTreeMap<String, String>,
    pub license: Option<LicenseInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_empty() {
        let p = AvProfile::default();
        assert!(p.av_name.is_empty());
        assert!(p.components.is_empty());
        assert!(p.license.is_none());
    }
}
