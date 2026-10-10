//! `hash-blocklist` scanner: matches sample sha256 digests against locally
//! configured blocklist feeds. No daemon, no external service - the
//! cheapest real detector in the fleet.
//!
//! Feed format (per line): `<64-hex sha256>[ <free-form label>]`. `#`
//! starts a comment (whole-line comments and trailing comments both work).
//! Lines that fail validation are skipped and counted, never fatal - a feed
//! with a typo must not take the worker down.
//!
//! Autoupdate semantics: scans reload the feeds only when a feed file's
//! size/mtime changed (cheap stat check per batch); `update()` (the openbox
//! loop) forces a full reload. A failed reload keeps the previous set
//! serving, with a warning - a half-typed feed must not take scans down.
//!
//! Verdict mapping: hash present -> `Detected { name: "sha256:<hex>
//! (<label>)" }` (label omitted when absent); file read failure -> per-file
//! error verdict.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use futures_util::StreamExt;
use sha2::{Digest as _, Sha256};
use versa_scan_core::models::av::AvProfile;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::models::verdict::{FileVerdict, ScanOutcome};
use versa_scan_core::ports::driven::scanner::{
    ScanOutput, ScannerError, ScannerPort, UpdateOutcome,
};

/// Parallel file hashing during a scan. sha256 is CPU-bound; this bounds
/// the number of blocking threads spent on it.
const HASH_CONCURRENCY: usize = 4;

/// One loaded snapshot of all feeds. Immutable; swapped atomically on
/// reload so a scan never sees a half-loaded set.
#[derive(Debug, Clone, Default)]
struct FeedSet {
    hashes: HashSet<[u8; 32]>,
    labels: HashMap<[u8; 32], String>,
    /// Valid lines loaded from all feeds (duplicate lines included).
    entries: usize,
    /// Lines skipped for being invalid (warned once per reload).
    skipped: usize,
    /// Order-independent content fingerprint (wrapping sum of hash
    /// prefixes plus entry count) - moves whenever membership changes.
    fingerprint: u64,
    /// Per-feed `(len, mtime_unix_nanos)` in feed order; the cheap change
    /// detector that lets scans skip re-reading unchanged feeds.
    stats: Vec<(u64, i64)>,
}

impl FeedSet {
    fn build(feeds: &[PathBuf]) -> Result<FeedSet, ScannerError> {
        let mut set = FeedSet { stats: Vec::with_capacity(feeds.len()), ..Default::default() };
        for feed in feeds {
            let meta = std::fs::metadata(feed).map_err(|err| {
                ScannerError::NotInstalled(format!("feed {}: {err}", feed.display()))
            })?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or_default();
            set.stats.push((meta.len(), mtime));

            let text = std::fs::read_to_string(feed).map_err(|err| {
                ScannerError::NotInstalled(format!("feed {}: {err}", feed.display()))
            })?;
            let (added, skipped) = parse_feed(&text, &mut set.hashes, &mut set.labels);
            set.entries += added;
            set.skipped += skipped;
            if skipped > 0 {
                tracing::warn!(feed = %feed.display(), skipped, "hash-blocklist feed had invalid lines");
            }
            tracing::debug!(feed = %feed.display(), added, "hash-blocklist feed loaded");
        }
        set.fingerprint = fingerprint(&set.hashes, set.entries);
        Ok(set)
    }
}

/// Parses one feed file into `hashes`/`labels`; returns (valid, skipped).
/// Text is cut at the first `#` of each line first, so trailing comments
/// work and labels may not contain `#`.
fn parse_feed(
    text: &str,
    hashes: &mut HashSet<[u8; 32]>,
    labels: &mut HashMap<[u8; 32], String>,
) -> (usize, usize) {
    let mut valid = 0;
    let mut skipped = 0;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let token = parts.next().unwrap_or_default();
        let label = parts.next().map(str::trim).filter(|l| !l.is_empty());
        let Some(digest) = parse_hex64(token) else {
            skipped += 1;
            continue;
        };
        if hashes.insert(digest)
            && let Some(label) = label
        {
            labels.insert(digest, label.to_owned());
        }
        valid += 1;
    }
    (valid, skipped)
}

fn parse_hex64(token: &str) -> Option<[u8; 32]> {
    let token = token.trim().to_ascii_lowercase();
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = token.as_bytes();
    let mut digest = [0u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        let hi = bytes.get(i * 2).and_then(|b| (*b as char).to_digit(16));
        let lo = bytes.get(i * 2 + 1).and_then(|b| (*b as char).to_digit(16));
        let (Some(hi), Some(lo)) = (hi, lo) else { return None };
        *byte = ((hi << 4) | lo) as u8;
    }
    Some(digest)
}

/// Order-independent fingerprint: wrapping sum of each hash's first u64
/// plus the entry count. Membership changes move it; order does not.
fn fingerprint(hashes: &HashSet<[u8; 32]>, entries: usize) -> u64 {
    let mut sum = entries as u64;
    for digest in hashes {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&digest[..8]);
        sum = sum.wrapping_add(u64::from_le_bytes(prefix));
    }
    sum
}

pub struct HashBlocklistScanner {
    feeds: Vec<PathBuf>,
    /// Latest loaded snapshot; `None` until the first successful load.
    state: parking_lot::RwLock<Option<std::sync::Arc<FeedSet>>>,
}

impl HashBlocklistScanner {
    pub fn new(feeds: Vec<PathBuf>) -> Self {
        Self { feeds, state: parking_lot::RwLock::new(None) }
    }

    fn stat_feeds(&self) -> Result<Vec<(u64, i64)>, ScannerError> {
        if self.feeds.is_empty() {
            return Err(ScannerError::NotInstalled(
                "no feeds configured in [hash_blocklist]".to_owned(),
            ));
        }
        self.feeds
            .iter()
            .map(|feed| {
                let meta = std::fs::metadata(feed).map_err(|err| {
                    ScannerError::NotInstalled(format!("feed {}: {err}", feed.display()))
                })?;
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or_default();
                Ok((meta.len(), mtime))
            })
            .collect()
    }

    /// Loads the feeds if they were never loaded or changed on disk.
    /// Returns the active snapshot; a failed reload keeps the previous one.
    async fn ensure_loaded(&self) -> Result<std::sync::Arc<FeedSet>, ScannerError> {
        let stats = self.stat_feeds()?;
        let cached = self.state.read().clone();
        if let Some(cached) = &cached {
            if cached.stats == stats {
                return Ok(std::sync::Arc::clone(cached));
            }
        }

        let feeds = self.feeds.clone();
        let fresh = tokio::task::spawn_blocking(move || FeedSet::build(&feeds))
            .await
            .map_err(|err| ScannerError::Io(format!("hash-blocklist task: {err}")))?;
        match fresh {
            // Still holding a usable set: keep serving it rather than
            // taking scans down with a half-typed feed.
            Err(err) if cached.is_some() => {
                tracing::warn!(error = %err, "hash-blocklist reload failed; keeping previous set");
                Ok(cached.expect("checked Some above"))
            }
            Err(err) => Err(err),
            Ok(set) => {
                let set = std::sync::Arc::new(set);
                *self.state.write() = Some(std::sync::Arc::clone(&set));
                Ok(set)
            }
        }
    }
}

fn hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    digest.iter().fold(String::with_capacity(64), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Streams `path` through sha256; returns the digest.
fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let Some(chunk) = buffer.get(..read) else { continue };
        hasher.update(chunk);
    }
    Ok(hasher.finalize().into())
}

fn detection_name(digest: &[u8; 32], set: &FeedSet) -> String {
    let base = format!("sha256:{}", hex(digest));
    match set.labels.get(digest) {
        Some(label) => format!("{base} ({label})"),
        None => base,
    }
}

#[async_trait]
impl ScannerPort for HashBlocklistScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("hash-blocklist").expect("static slug is valid")
    }

    async fn is_installed(&self) -> Result<bool, ScannerError> {
        match self.ensure_loaded().await {
            Ok(_) => Ok(true),
            Err(ScannerError::NotInstalled(_)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    async fn profile(&self) -> Result<AvProfile, ScannerError> {
        let set = self.ensure_loaded().await?;
        Ok(AvProfile {
            av_name: "hash-blocklist".to_owned(),
            av_version: None,
            bases_version: Some(format!("{} hashes", set.hashes.len())),
            ..Default::default()
        })
    }

    async fn scan(&self, dir: &Path) -> Result<ScanOutput, ScannerError> {
        let set = self.ensure_loaded().await?;

        let mut files = Vec::new();
        crate::outbound_adapters::scanners::collect_files_recursive(dir, &mut files);
        files.sort();

        let work = files.into_iter().map(|file| {
            let set = std::sync::Arc::clone(&set);
            async move {
                let name =
                    file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                let verdict = match tokio::task::spawn_blocking(move || {
                    hash_file(&file).map(|digest| {
                        if set.hashes.contains(&digest) {
                            FileVerdict {
                                outcome: ScanOutcome::Detected {
                                    detections: vec![versa_scan_core::models::Detection {
                                        name: detection_name(&digest, &set),
                                        link: None,
                                    }],
                                },
                                ..Default::default()
                            }
                        } else {
                            FileVerdict::default()
                        }
                    })
                })
                .await
                {
                    Ok(Ok(verdict)) => verdict,
                    Ok(Err(err)) => FileVerdict::error(format!("hash-blocklist read: {err}")),
                    Err(err) => FileVerdict::error(format!("hash-blocklist task: {err}")),
                };
                (name, verdict)
            }
        });

        let entries = futures_util::stream::iter(work)
            .buffer_unordered(HASH_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        Ok(ScanOutput { entries })
    }

    async fn update(&self) -> Result<UpdateOutcome, ScannerError> {
        // Forced full reload: stat-skip could miss a change within mtime
        // granularity, the openbox loop must not.
        let previous = self.state.read().clone();
        let feeds = self.feeds.clone();
        let fresh = tokio::task::spawn_blocking(move || FeedSet::build(&feeds))
            .await
            .map_err(|err| ScannerError::Io(format!("hash-blocklist task: {err}")))??;
        let fresh = std::sync::Arc::new(fresh);
        let outcome = match previous.as_ref() {
            Some(prev) if prev.fingerprint == fresh.fingerprint => UpdateOutcome::UpToDate,
            _ => UpdateOutcome::Updated,
        };
        *self.state.write() = Some(fresh);
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn write_feed(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vs-hbl-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn feed_parsing_comments_labels_invalid() {
        let mut hashes = HashSet::new();
        let mut labels = HashMap::new();
        let text = format!(
            "# comment\n\n{HASH_A}\n{HASH_B}  Emotet loader\nnot-a-hash\n\
             {HASH_A} # trailing comment\n"
        );
        let (valid, skipped) = parse_feed(&text, &mut hashes, &mut labels);
        assert_eq!(valid, 3);
        assert_eq!(skipped, 1);
        assert!(hashes.contains(&parse_hex64(HASH_A).unwrap()));
        assert_eq!(
            labels.get(&parse_hex64(HASH_B).unwrap()).map(String::as_str),
            Some("Emotet loader")
        );
        // First occurrence wins; a duplicate line cannot overwrite a label
        // with a comment fragment.
        assert!(!labels.contains_key(&parse_hex64(HASH_A).unwrap()));
    }

    #[test]
    fn hex_parsing_rejects_bad_tokens() {
        assert!(parse_hex64(HASH_A).is_some());
        assert!(parse_hex64("zz").is_none());
        assert!(parse_hex64(&"a".repeat(63)).is_none());
        assert!(parse_hex64(&"a".repeat(65)).is_none());
    }

    #[test]
    fn fingerprint_tracks_membership_not_order() {
        let mut first = HashSet::new();
        first.insert(parse_hex64(HASH_A).unwrap());
        let mut second = HashSet::new();
        second.insert(parse_hex64(HASH_A).unwrap());
        assert_eq!(fingerprint(&first, 1), fingerprint(&second, 1));
        second.insert(parse_hex64(HASH_B).unwrap());
        assert_ne!(fingerprint(&first, 1), fingerprint(&second, 2));
    }

    #[tokio::test]
    async fn scan_detects_labeled_and_clean() {
        let feeds_dir = tmp_dir("feeds");
        let feed = write_feed(&feeds_dir, "abuse.sha256", "");

        let samples = tmp_dir("samples");
        std::fs::write(samples.join("clean.txt"), b"clean content").unwrap();
        let evil_path = samples.join("evil.bin");
        std::fs::write(&evil_path, b"evil content").unwrap();

        let evil = hex(&hash_file(&evil_path).unwrap());
        std::fs::write(&feed, format!("{evil}  Emotet loader\n")).unwrap();

        let scanner = HashBlocklistScanner::new(vec![feed]);
        assert!(scanner.is_installed().await.unwrap());
        let profile = scanner.profile().await.unwrap();
        assert_eq!(profile.av_name, "hash-blocklist");
        assert_eq!(profile.bases_version.as_deref(), Some("1 hashes"));

        let output = scanner.scan(&samples).await.unwrap();
        assert_eq!(output.entries.len(), 2);
        let verdict = |name: &str| {
            output.entries.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()).unwrap()
        };
        assert_eq!(verdict("clean.txt").outcome, ScanOutcome::Clean);
        match verdict("evil.bin").outcome {
            ScanOutcome::Detected { detections } => {
                assert!(detections[0].name.starts_with(&format!("sha256:{evil}")));
                assert!(detections[0].name.contains("Emotet loader"));
            }
            other => panic!("expected detection, got {other:?}"),
        }

        std::fs::remove_dir_all(&feeds_dir).ok();
        std::fs::remove_dir_all(&samples).ok();
    }

    #[tokio::test]
    async fn update_reports_changed_feeds() {
        let feeds_dir = tmp_dir("feeds");
        let feed = write_feed(&feeds_dir, "a.sha256", "");

        let scanner = HashBlocklistScanner::new(vec![feed.clone()]);
        assert_eq!(scanner.update().await.unwrap(), UpdateOutcome::Updated);
        assert_eq!(scanner.update().await.unwrap(), UpdateOutcome::UpToDate);

        std::fs::write(&feed, format!("{HASH_A}\n")).unwrap();
        assert_eq!(scanner.update().await.unwrap(), UpdateOutcome::Updated);
        assert_eq!(scanner.update().await.unwrap(), UpdateOutcome::UpToDate);

        std::fs::remove_dir_all(&feeds_dir).ok();
    }

    #[tokio::test]
    async fn scan_sees_feed_changes_without_restart() {
        let feeds_dir = tmp_dir("feeds");
        let feed = write_feed(&feeds_dir, "a.sha256", "");

        let samples = tmp_dir("samples");
        let evil_path = samples.join("evil.bin");
        std::fs::write(&evil_path, b"evil content").unwrap();
        let evil = hex(&hash_file(&evil_path).unwrap());

        let scanner = HashBlocklistScanner::new(vec![feed.clone()]);
        let first = scanner.scan(&samples).await.unwrap();
        assert!(first.entries.iter().all(|(_, v)| v.outcome == ScanOutcome::Clean));

        std::fs::write(&feed, format!("{evil}\n")).unwrap();
        let second = scanner.scan(&samples).await.unwrap();
        let (_, verdict) = second.entries.iter().find(|(n, _)| n == "evil.bin").unwrap();
        assert!(matches!(verdict.outcome, ScanOutcome::Detected { .. }));

        std::fs::remove_dir_all(&feeds_dir).ok();
        std::fs::remove_dir_all(&samples).ok();
    }

    #[tokio::test]
    async fn no_feeds_means_not_installed() {
        let scanner = HashBlocklistScanner::new(Vec::new());
        assert!(!scanner.is_installed().await.unwrap());
        let err = scanner.scan(Path::new(".")).await.unwrap_err();
        assert!(matches!(err, ScannerError::NotInstalled(_)));
    }

    #[tokio::test]
    async fn unreadable_feed_maps_to_not_installed() {
        let missing = std::env::temp_dir().join(format!("vs-hbl-missing-{}", uuid::Uuid::new_v4()));
        let scanner = HashBlocklistScanner::new(vec![missing]);
        assert!(!scanner.is_installed().await.unwrap());
    }
}
