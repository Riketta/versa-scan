//! `yara-x` scanner: compiles user-provided YARA rules at load time and
//! scans sample files in-process with the pure-Rust YARA-X engine
//! (`yara-x` crate). Cross-platform, no daemon, no signature DB - rules
//! are the deployment's own.
//!
//! Rule sources: `[yara_x] rules_path` is a single `*.yar`/`*.yara` file
//! or a directory searched recursively for that extension. Rules compile
//! lazily on first use and reload automatically when the source files
//! change on disk (stat fingerprint per scan, forced rebuild in
//! `update()` for the openbox loop) - sandbox workers pick up new rules
//! without a restart.
//!
//! Cancellation: `Scanner::set_timeout` makes the engine abort a scan
//! from the inside (`ScanError::Timeout`), which is the only real way to
//! bound synchronous native code - dropping a `spawn_blocking` future
//! does not stop the thread. A per-file timeout aborts the whole scan
//! with `ScanFailed` (the batch is error-reported, not requeued), so a
//! pathological rule cannot wedge the worker.
//!
//! Verdict mapping: every matching rule becomes a `Detection`; name is
//! the rule identifier (namespace-prefixed when not `default`), and a
//! string `reference` metadata entry becomes the link.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use versa_scan_core::models::av::AvProfile;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::models::verdict::{Detection, FileVerdict, ScanOutcome};
use versa_scan_core::ports::driven::scanner::{
    ScanOutput, ScannerError, ScannerPort, UpdateOutcome,
};

/// One compiled rule set plus the fingerprints used to detect source
/// changes. Immutable; swapped atomically on reload.
#[derive(Debug, Clone)]
struct CachedRules {
    rules: std::sync::Arc<yara_x::Rules>,
    rule_count: usize,
    fingerprint: u64,
    stats: Vec<(u64, i64)>,
}

pub struct YaraXScanner {
    rules_path: PathBuf,
    timeout: Duration,
    state: parking_lot::RwLock<Option<std::sync::Arc<CachedRules>>>,
}

impl YaraXScanner {
    pub fn new(rules_path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self { rules_path: rules_path.into(), timeout, state: parking_lot::RwLock::new(None) }
    }

    /// Lists rule source files: `rules_path` itself when it is a file,
    /// otherwise a recursive `*.yar`/`*.yara` listing of the directory.
    /// Returns `(files, stats)` - stats mirror [`super::hash_blocklist`].
    fn rule_sources(&self) -> Result<(Vec<PathBuf>, Vec<(u64, i64)>), ScannerError> {
        fn stat(path: &Path) -> Result<(u64, i64), ScannerError> {
            let meta = std::fs::metadata(path)
                .map_err(|err| ScannerError::NotInstalled(format!("{}: {err}", path.display())))?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or_default();
            Ok((meta.len(), mtime))
        }

        let mut files = Vec::new();
        if self.rules_path.is_file() {
            files.push(self.rules_path.clone());
        } else if self.rules_path.is_dir() {
            collect_rule_files(&self.rules_path, &mut files);
            files.sort();
        } else {
            return Err(ScannerError::NotInstalled(format!(
                "rules_path not found: {}",
                self.rules_path.display()
            )));
        }
        if files.is_empty() {
            return Err(ScannerError::NotInstalled(format!(
                "no *.yar/*.yara rule files under {}",
                self.rules_path.display()
            )));
        }
        let stats = files.iter().map(|f| stat(f)).collect::<Result<Vec<_>, _>>()?;
        Ok((files, stats))
    }

    /// Loads/compiles the rules if never loaded or changed on disk. A
    /// failed recompile keeps the previous set serving (warn), matching
    /// the hash-blocklist reload policy.
    async fn ensure_loaded(&self) -> Result<std::sync::Arc<CachedRules>, ScannerError> {
        let (files, stats) = self.rule_sources()?;
        let cached = self.state.read().clone();
        if let Some(cached) = &cached
            && cached.stats == stats
        {
            return Ok(std::sync::Arc::clone(cached));
        }

        let fresh = tokio::task::spawn_blocking(move || compile_rules(&files, stats))
            .await
            .map_err(|err| ScannerError::Io(format!("yara-x task: {err}")))?;
        match fresh {
            Err(err) if cached.is_some() => {
                tracing::warn!(error = %err, "yara-x rules reload failed; keeping previous set");
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

fn compile_rules(files: &[PathBuf], stats: Vec<(u64, i64)>) -> Result<CachedRules, ScannerError> {
    let mut compiler = yara_x::Compiler::new();
    for file in files {
        let source = std::fs::read_to_string(file).map_err(|err| {
            ScannerError::ScanFailed(format!("read rules {}: {err}", file.display()))
        })?;
        compiler
            .add_source(
                yara_x::SourceCode::from(source.as_str()).with_origin(file.display().to_string()),
            )
            .map_err(|err| {
                ScannerError::ScanFailed(format!("compile rules {}: {err}", file.display()))
            })?;
    }
    let rules = std::sync::Arc::new(compiler.build());
    let rule_count = rules.iter().count();
    if !rules.warnings().is_empty() {
        tracing::info!(count = rules.warnings().len(), "yara-x compilation warnings");
    }
    tracing::info!(files = files.len(), rules = rule_count, "yara-x rules compiled");
    let fingerprint = stats.iter().fold(0xcbf2_9ce4_8422_2325u64, |mut acc, (len, mtime)| {
        acc ^= *len;
        acc = acc.wrapping_mul(0x100_0000_01b3);
        acc ^= *mtime as u64;
        acc.wrapping_mul(0x100_0000_01b3)
    });
    Ok(CachedRules { rules, rule_count, fingerprint, stats })
}

/// Recursive `*.yar`/`*.yara` collector.
fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!(dir = %dir.display(), error = %err, "rules walk failed");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rule_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "yar" || ext == "yara") {
            out.push(path);
        }
    }
}

fn rule_detection(rule: &yara_x::Rule<'_, '_>) -> Detection {
    let namespace = rule.namespace();
    let identifier = rule.identifier();
    let name = if namespace.is_empty() || namespace == "default" {
        identifier.to_owned()
    } else {
        format!("{namespace}:{identifier}")
    };
    let link = rule
        .metadata()
        .find(|(key, value)| {
            (*key == "reference" || *key == "reference_url")
                && matches!(value, yara_x::MetaValue::String(_))
        })
        .and_then(|(_, value)| match value {
            yara_x::MetaValue::String(s) => Some(s.to_owned()),
            _ => None,
        });
    Detection { name, link }
}

#[async_trait]
impl ScannerPort for YaraXScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("yara-x").expect("static slug is valid")
    }

    async fn is_installed(&self) -> Result<bool, ScannerError> {
        match self.ensure_loaded().await {
            Ok(_) => Ok(true),
            Err(err @ (ScannerError::NotInstalled(_) | ScannerError::ScanFailed(_))) => {
                tracing::warn!(error = %err, "yara-x rules not usable");
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    async fn profile(&self) -> Result<AvProfile, ScannerError> {
        let cached = self.ensure_loaded().await?;
        Ok(AvProfile {
            av_name: "YARA-X".to_owned(),
            av_version: Some(yara_x::VERSION.to_owned()),
            bases_version: Some(format!("{} rules", cached.rule_count)),
            ..Default::default()
        })
    }

    async fn scan(&self, dir: &Path) -> Result<ScanOutput, ScannerError> {
        let cached = self.ensure_loaded().await?;

        let mut files = Vec::new();
        crate::outbound_adapters::scanners::collect_files_recursive(dir, &mut files);
        files.sort();

        let timeout = self.timeout;
        let entries = tokio::task::spawn_blocking(move || {
            let mut scanner = yara_x::Scanner::new(&cached.rules);
            scanner.set_timeout(timeout);

            let mut entries = Vec::with_capacity(files.len());
            for file in files {
                let name =
                    file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                match scanner.scan_file(&file) {
                    Ok(results) => {
                        let detections: Vec<Detection> =
                            results.matching_rules().map(|rule| rule_detection(&rule)).collect();
                        entries.push((
                            name,
                            if detections.is_empty() {
                                FileVerdict::default()
                            } else {
                                FileVerdict {
                                    outcome: ScanOutcome::Detected { detections },
                                    ..Default::default()
                                }
                            },
                        ));
                    }
                    Err(yara_x::ScanError::Timeout) => {
                        return Err(ScannerError::ScanFailed(format!(
                            "yara-x scan timed out after {timeout:?} on {name} \
                             (check the rules for pathological patterns)"
                        )));
                    }
                    Err(err) => {
                        tracing::warn!(file = %name, error = %err, "yara-x per-file scan failed");
                        entries.push((name, FileVerdict::error(format!("yara-x: {err}"))));
                    }
                }
            }
            Ok(entries)
        })
        .await
        .map_err(|err| ScannerError::Io(format!("yara-x task: {err}")))??;

        Ok(ScanOutput { entries })
    }

    async fn update(&self) -> Result<UpdateOutcome, ScannerError> {
        // Forced full recompile: the stat fingerprint could miss a change
        // within filesystem mtime granularity.
        let previous = self.state.read().as_ref().map(|cached| cached.fingerprint);
        let (files, stats) = self.rule_sources()?;
        let fresh = tokio::task::spawn_blocking(move || compile_rules(&files, stats))
            .await
            .map_err(|err| ScannerError::Io(format!("yara-x task: {err}")))??;
        let fresh = std::sync::Arc::new(fresh);
        let outcome = match previous {
            Some(prev) if prev == fresh.fingerprint => UpdateOutcome::UpToDate,
            _ => UpdateOutcome::Updated,
        };
        *self.state.write() = Some(std::sync::Arc::clone(&fresh));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;

    // Marker content, deliberately NOT the EICAR string: Windows Defender
    // real-time protection quarantines EICAR files written to temp (os
    // error 225), which would fail the test before the scanner sees it.
    const DEMO_RULE: &str = r#"
        rule vs_demo_marker
        {
            meta:
                description = "Detects the versa-scan demo marker"
                reference = "https://example.test/vs-demo"
            strings:
                $marker = "VS-YARA-DEMO-MARKER-42"
            condition:
                $marker
        }
    "#;
    const DEMO_MARKER: &str = "VS-YARA-DEMO-MARKER-42";

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vs-yara-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn scanner_for(path: &Path) -> YaraXScanner {
        YaraXScanner::new(path, Duration::from_secs(30))
    }

    #[tokio::test]
    async fn detects_rule_match_with_metadata_link() {
        let rules_dir = tmp_dir("rules");
        std::fs::write(rules_dir.join("demo.yar"), DEMO_RULE).unwrap();

        let samples = tmp_dir("samples");
        std::fs::write(samples.join("clean.txt"), b"nothing here").unwrap();
        std::fs::write(samples.join("marker.bin"), DEMO_MARKER).unwrap();

        let scanner = scanner_for(&rules_dir);
        assert!(scanner.is_installed().await.unwrap());

        let profile = scanner.profile().await.unwrap();
        assert_eq!(profile.av_name, "YARA-X");
        assert_eq!(profile.av_version.as_deref(), Some(yara_x::VERSION));
        assert_eq!(profile.bases_version.as_deref(), Some("1 rules"));

        let output = scanner.scan(&samples).await.unwrap();
        assert_eq!(output.entries.len(), 2);
        let verdict = |name: &str| {
            output.entries.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()).unwrap()
        };
        assert_eq!(verdict("clean.txt").outcome, ScanOutcome::Clean);
        match verdict("marker.bin").outcome {
            ScanOutcome::Detected { detections } => {
                assert_eq!(detections.len(), 1);
                assert_eq!(detections[0].name, "vs_demo_marker");
                assert_eq!(detections[0].link.as_deref(), Some("https://example.test/vs-demo"));
            }
            other => panic!("expected detection, got {other:?}"),
        }

        std::fs::remove_dir_all(&rules_dir).ok();
        std::fs::remove_dir_all(&samples).ok();
    }

    #[tokio::test]
    async fn rule_changes_are_picked_up_without_restart() {
        let rules_dir = tmp_dir("rules");
        let rule_file = rules_dir.join("demo.yar");
        std::fs::write(&rule_file, DEMO_RULE).unwrap();

        let samples = tmp_dir("samples");
        let sample = samples.join("sample.bin");
        std::fs::write(&sample, b"trigger marker").unwrap();

        let scanner = scanner_for(&rules_dir);
        let first = scanner.scan(&samples).await.unwrap();
        assert!(first.entries.iter().all(|(_, v)| v.outcome == ScanOutcome::Clean));
        assert_eq!(scanner.update().await.unwrap(), UpdateOutcome::UpToDate);

        std::fs::write(
            &rule_file,
            r#"rule marker_rule { strings: $m = "trigger marker" condition: $m }"#,
        )
        .unwrap();
        assert_eq!(scanner.update().await.unwrap(), UpdateOutcome::Updated);

        let second = scanner.scan(&samples).await.unwrap();
        let (_, verdict) = second.entries.iter().find(|(n, _)| n == "sample.bin").unwrap();
        match &verdict.outcome {
            ScanOutcome::Detected { detections } => {
                assert_eq!(detections[0].name, "marker_rule");
            }
            other => panic!("expected detection after rule reload, got {other:?}"),
        }

        std::fs::remove_dir_all(&rules_dir).ok();
        std::fs::remove_dir_all(&samples).ok();
    }

    #[tokio::test]
    async fn single_rule_file_is_supported() {
        let rules_dir = tmp_dir("single");
        let rule_file = rules_dir.join("only.yar");
        std::fs::write(&rule_file, DEMO_RULE).unwrap();

        let scanner = scanner_for(&rule_file);
        let profile = scanner.profile().await.unwrap();
        assert_eq!(profile.bases_version.as_deref(), Some("1 rules"));

        std::fs::remove_dir_all(&rules_dir).ok();
    }

    #[tokio::test]
    async fn bad_rules_map_to_scan_failed_not_requeue_forever() {
        let rules_dir = tmp_dir("bad");
        std::fs::write(rules_dir.join("broken.yar"), "this is not yara").unwrap();
        let scanner = scanner_for(&rules_dir);

        assert!(!scanner.is_installed().await.unwrap());
        let err = scanner.scan(Path::new(".")).await.unwrap_err();
        assert!(matches!(err, ScannerError::ScanFailed(_)));

        std::fs::remove_dir_all(&rules_dir).ok();
    }

    #[tokio::test]
    async fn missing_rules_path_maps_to_not_installed() {
        let missing = tmp_dir("missing");
        let path = missing.join("nope.yar");
        let scanner = scanner_for(&path);
        assert!(!scanner.is_installed().await.unwrap());
        let err = scanner.scan(Path::new(".")).await.unwrap_err();
        assert!(matches!(err, ScannerError::NotInstalled(_)));
        std::fs::remove_dir_all(&missing).ok();
    }

    #[test]
    fn namespace_and_reference_mapping() {
        // Pure mapping check via a compiled namespace rule.
        let rules = yara_x::compile(
            r#"
            rule base_rule { meta: reference = "https://example.test" condition: true }
        "#,
        )
        .unwrap();
        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner.scan(b"").unwrap();
        let rule = results.matching_rules().next().unwrap();
        let detection = rule_detection(&rule);
        assert_eq!(detection.name, "base_rule");
        assert_eq!(detection.link.as_deref(), Some("https://example.test"));
    }
}
