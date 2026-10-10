//! Update manifest: `<base>/manifest.txt` contains one line
//! `<version>;<sha256-of-zip>` (whitespace-tolerant, `v` prefix allowed).
//! Versions compare as dot-separated numeric triples; anything unparsable
//! is never considered newer.

use versa_scan_core::models::digest::Sha256Digest;
use versa_scan_core::ports::driven::self_update::UpdateError;

/// Parses manifest text into `(version, archive sha256)`.
pub fn parse(text: &str) -> Result<(String, Sha256Digest), UpdateError> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| UpdateError::Manifest("manifest is empty".to_owned()))?;
    let (version, hash) = line.split_once(';').ok_or_else(|| {
        UpdateError::Manifest(format!("expected `<version>;<sha256>`, got {line:?}"))
    })?;
    let version = version.trim().trim_start_matches('v').trim().to_owned();
    if version.is_empty() {
        return Err(UpdateError::Manifest("manifest has empty version".to_owned()));
    }
    let hash = Sha256Digest::from_hex(hash.trim())
        .map_err(|e| UpdateError::Manifest(format!("manifest hash: {e}")))?;
    Ok((version, hash))
}

/// True when `candidate` is strictly newer than `current` (numeric triples;
/// extra segments beyond three are compared too; unparsable candidates are
/// never newer).
pub fn version_is_newer(candidate: &str, current: &str) -> bool {
    let (Some(candidate), Some(current)) = (parse_triple(candidate), parse_triple(current)) else {
        return false;
    };
    candidate > current
}

fn parse_triple(version: &str) -> Option<Vec<u64>> {
    let trimmed = version.trim().trim_start_matches('v').trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for segment in trimmed.split('.') {
        if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        parts.push(segment.parse::<u64>().ok()?);
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_basic_manifest() {
        let (version, digest) = parse(&format!("1.2.3;{SHA}\n")).unwrap();
        assert_eq!(version, "1.2.3");
        assert_eq!(digest.as_str(), SHA);
    }

    #[test]
    fn parses_v_prefix_and_spaces() {
        let (version, _) = parse(&format!("  v0.10.2 ;  {SHA}  ")).unwrap();
        assert_eq!(version, "0.10.2");
    }

    #[test]
    fn rejects_malformed_manifests() {
        assert!(parse("").is_err());
        assert!(parse("1.2.3\n").is_err());
        assert!(parse(&format!("1.2.3;nothash")).is_err());
        assert!(parse(&format!(";{SHA}")).is_err());
    }

    #[test]
    fn version_comparisons() {
        assert!(version_is_newer("1.2.4", "1.2.3"));
        assert!(version_is_newer("1.3.0", "1.2.9"));
        assert!(version_is_newer("2.0.0", "1.9.9"));
        assert!(version_is_newer("1.2.3.1", "1.2.3"));
        assert!(!version_is_newer("1.2.3", "1.2.3"));
        assert!(!version_is_newer("1.2.2", "1.2.3"));
        assert!(!version_is_newer("garbage", "1.2.3"));
        assert!(!version_is_newer("1.2.3", "garbage"));
        assert!(version_is_newer("v1.2.4", "1.2.3"), "v prefix tolerated");
    }
}
