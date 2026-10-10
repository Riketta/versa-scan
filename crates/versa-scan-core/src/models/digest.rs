//! SHA-256 digest of a sample. Computation lives in infrastructure (the
//! fetcher and vscli hash bytes); the core only validates and carries the
//! hex form.

use std::fmt;

const HEX_LEN: usize = 64;

/// Lowercase hex-encoded SHA-256 digest (64 chars).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid sha256 digest: expected 64 lowercase hex chars, got {len} chars")]
pub struct InvalidDigest {
    len: usize,
}

impl Sha256Digest {
    pub fn from_hex(value: &str) -> Result<Self, InvalidDigest> {
        let is_valid = value.len() == HEX_LEN && value.bytes().all(|b| b.is_ascii_hexdigit());
        if !is_valid {
            return Err(InvalidDigest { len: value.len() });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const VALID: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn accepts_lowercase_hex() {
        assert_eq!(Sha256Digest::from_hex(VALID).unwrap().as_str(), VALID);
    }

    #[test]
    fn lowercases_uppercase_input() {
        let upper = VALID.to_uppercase();
        assert_eq!(Sha256Digest::from_hex(&upper).unwrap().as_str(), VALID);
    }

    #[test]
    fn rejects_bad_shapes() {
        assert!(Sha256Digest::from_hex("").is_err());
        assert!(Sha256Digest::from_hex("abc").is_err());
        assert!(Sha256Digest::from_hex(&"g".repeat(64)).is_err());
        assert!(Sha256Digest::from_hex("e3b0").is_err());
    }
}
