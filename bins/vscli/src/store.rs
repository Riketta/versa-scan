//! Content-addressed sample store: `samples/<sha[0:2]>/<sha>`.
//!
//! Resubmitting identical content only costs the bus message - the bytes
//! are already in place. Writes go through a temp file + rename, so a
//! crashed store write never leaves a partial sample.

use std::io::Write;
use std::path::{Path, PathBuf};

pub struct StoredSample {
    pub sha256: String,
    pub path: PathBuf,
    pub size: u64,
    /// True when the content was already in the store (dedupe hit).
    pub existed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct SampleStore {
    root: PathBuf,
}

impl SampleStore {
    /// Opens (creating if needed) the store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        std::fs::create_dir_all(root.join("samples"))?;
        std::fs::create_dir_all(root.join("reports"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn samples_dir(&self) -> PathBuf {
        self.root.join("samples")
    }

    fn path_for(&self, sha256: &str) -> PathBuf {
        self.root
            .join("samples")
            .join(sha256.get(0..2).expect("digest is 64 hex chars"))
            .join(sha256)
    }

    /// Stores bytes under their sha256; returns the sample's store record.
    pub fn put(&self, bytes: &[u8]) -> Result<StoredSample, StoreError> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        let digest: Vec<u8> = hasher.finalize().to_vec();
        let mut sha256 = String::with_capacity(digest.len() * 2);
        for byte in &digest {
            sha256.push_str(&format!("{byte:02x}"));
        }

        let path = self.path_for(&sha256);
        if path.is_file() {
            return Ok(StoredSample { sha256, path, size: bytes.len() as u64, existed: true });
        }
        std::fs::create_dir_all(path.parent().expect("shard dir parent exists"))?;
        let tmp = path.with_extension("part");
        {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(bytes)?;
            file.flush()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(StoredSample { sha256, path, size: bytes.len() as u64, existed: false })
    }

    /// (sample count, total bytes) across the store.
    pub fn stats(&self) -> Result<(usize, u64), StoreError> {
        let mut count = 0usize;
        let mut total = 0u64;
        let mut shards = std::fs::read_dir(self.samples_dir())?;
        while let Some(shard) = shards.next() {
            for entry in shard?.path().read_dir()?.flatten() {
                if entry.path().is_file() {
                    count += 1;
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }
        Ok((count, total))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn stores_content_addressed_and_dedupes() {
        let root = std::env::temp_dir().join(format!("vs-store-{}", uuid::Uuid::new_v4()));
        let store = SampleStore::open(&root).unwrap();

        let first = store.put(b"hello samples").unwrap();
        assert!(!first.existed);
        assert!(first.path.is_file());
        assert_eq!(first.size, 13);
        let shard = first.path.parent().unwrap().file_name().unwrap().to_str().unwrap();
        assert_eq!(shard.len(), 2, "two-hex-char shard dir");
        assert_eq!(shard, first.sha256.get(0..2).unwrap());

        let second = store.put(b"hello samples").unwrap();
        assert!(second.existed);
        assert_eq!(second.sha256, first.sha256);

        let different = store.put(b"other").unwrap();
        assert_ne!(different.sha256, first.sha256);

        let (count, total) = store.stats().unwrap();
        assert_eq!(count, 2);
        assert_eq!(total, 13 + 5);

        std::fs::remove_dir_all(&root).ok();
    }
}
