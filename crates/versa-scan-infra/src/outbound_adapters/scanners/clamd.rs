//! clamd scanner: speaks the clamd TCP protocol (PING / VERSION / INSTREAM)
//! against a running `clamd` daemon. Cross-platform - this is the real
//! scanner used on Linux deployments and in CI.
//!
//! INSTREAM framing: client sends `zINSTREAM\0`, then chunks of
//! `<u32 big-endian length><bytes>`, terminated by a zero-length chunk; the
//! daemon answers `stream: OK` or `stream: <detection> FOUND` and closes.
//! Files are streamed from disk in chunks - never fully buffered - and up
//! to `[clamd] concurrent_scans` files are in flight at once; every future
//! carries its own file name so results cannot be mis-attributed.
//!
//! Scanner semantics for the orchestrator:
//! - daemon unreachable / connection dropped mid-scan -> `Unavailable`
//!   (transient, batch is requeued)
//! - daemon-reported per-file ERROR -> per-file error verdict (terminal)
//! - `update()` shells out to `freshclam`

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use versa_scan_core::models::av::AvProfile;
use versa_scan_core::models::ids::ScannerId;
use versa_scan_core::models::verdict::{FileVerdict, ScanOutcome};
use versa_scan_core::ports::driven::scanner::{
    ScanOutput, ScannerError, ScannerPort, UpdateOutcome,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const CHUNK_SIZE: usize = 32 * 1024;

pub struct ClamdScanner {
    address: String,
    concurrent_scans: usize,
}

impl ClamdScanner {
    pub fn new(address: impl Into<String>, concurrent_scans: usize) -> Self {
        Self { address: address.into(), concurrent_scans: concurrent_scans.max(1) }
    }

    async fn connect(&self) -> Result<TcpStream, ScannerError> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.address))
            .await
            .map_err(|_| {
                ScannerError::Unavailable(format!(
                    "clamd connect timed out after {CONNECT_TIMEOUT:?}"
                ))
            })?
            .map_err(|e| ScannerError::Unavailable(format!("clamd connect {}: {e}", self.address)));
        let stream = stream?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    async fn command(&self, command: &[u8]) -> Result<String, ScannerError> {
        let mut stream = self.connect().await?;
        // A clamd that accepts TCP but never answers must not wedge the
        // pipeline (this runs inside profile()/is_installed(), which have
        // their own outer caps - but the socket read is the real deadline).
        match tokio::time::timeout(IO_TIMEOUT, run_command(&mut stream, command)).await {
            Ok(result) => result
                .map_err(|e| ScannerError::Unavailable(format!("clamd {}: {e}", self.address))),
            Err(_) => Err(ScannerError::Unavailable(format!(
                "clamd {} response timed out after {IO_TIMEOUT:?}",
                self.address
            ))),
        }
    }

    /// Streams one file from disk through INSTREAM without buffering it
    /// fully in memory. Returns the daemon's response line.
    async fn instream_file(&self, path: &Path) -> Result<String, ScannerError> {
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| ScannerError::Io(format!("clamd open {}: {e}", path.display())))?;
        let unavailable = |e| ScannerError::Unavailable(format!("clamd instream: {e}"));
        let mut stream = self.connect().await?;
        stream.write_all(&z("INSTREAM")).await.map_err(unavailable)?;

        let mut buffer = vec![0u8; CHUNK_SIZE];
        loop {
            let read = file
                .read(&mut buffer)
                .await
                .map_err(|e| ScannerError::Io(format!("clamd read {}: {e}", path.display())))?;
            if read == 0 {
                break;
            }
            let Some(chunk) = buffer.get(..read) else { continue };
            stream.write_all(&(read as u32).to_be_bytes()).await.map_err(unavailable)?;
            stream.write_all(chunk).await.map_err(unavailable)?;
        }
        stream.write_all(&0u32.to_be_bytes()).await.map_err(unavailable)?;
        stream.flush().await.map_err(unavailable)?;

        let mut response = String::new();
        stream.read_to_string(&mut response).await.map_err(unavailable)?;
        Ok(response.trim_end().to_owned())
    }
}

fn z(command: &str) -> Vec<u8> {
    let mut bytes = command.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

async fn run_command<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    command: &[u8],
) -> std::io::Result<String> {
    stream.write_all(command).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response.trim_end().to_owned())
}

fn parse_verdict(response: &str) -> FileVerdict {
    // `stream: OK` | `stream: <detection> FOUND` | `stream: <detail> ERROR`
    let body = response.strip_prefix("stream: ").unwrap_or(response);
    if body == "OK" {
        return FileVerdict::default();
    }
    if let Some(rest) = body.strip_suffix(" FOUND") {
        return FileVerdict {
            outcome: ScanOutcome::Detected {
                detections: vec![versa_scan_core::models::Detection {
                    name: rest.trim().to_owned(),
                    link: None,
                }],
            },
            ..Default::default()
        };
    }
    if body.contains("INSTREAM size limit exceeded") {
        return FileVerdict::error(
            "clamd rejected the stream: INSTREAM size limit exceeded \
             (raise StreamMaxLength in clamd.conf to cover worker max_file_size)",
        );
    }
    FileVerdict::error(format!("clamd error: {body}"))
}

fn parse_version(response: &str) -> AvProfile {
    // "ClamAV 1.0.4/27000/Mon Jun 3 09:57:42 2024" - db version is the
    // segment after the engine version.
    let mut profile = AvProfile { av_name: "ClamAV".to_owned(), ..Default::default() };
    let rest = response.strip_prefix("ClamAV ").unwrap_or(response);
    let mut parts = rest.split('/');
    profile.av_version = parts.next().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    profile.bases_version = parts.next().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    profile
}

#[async_trait]
impl ScannerPort for ClamdScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("clamd").expect("static slug is valid")
    }

    async fn is_installed(&self) -> Result<bool, ScannerError> {
        match self.command(&z("PING")).await {
            Ok(response) => Ok(response == "PONG"),
            Err(ScannerError::Unavailable(_)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    async fn profile(&self) -> Result<AvProfile, ScannerError> {
        let response = self.command(&z("VERSION")).await?;
        if response.is_empty() {
            // clamd returns an empty version line while databases are not
            // loaded yet (freshclam warming up).
            return Ok(AvProfile { av_name: "ClamAV".to_owned(), ..Default::default() });
        }
        Ok(parse_version(&response))
    }

    async fn scan(&self, dir: &Path) -> Result<ScanOutput, ScannerError> {
        let mut files: Vec<PathBuf> = Vec::new();
        super::collect_files_recursive(dir, &mut files);
        files.sort();
        tracing::debug!(
            dir = %dir.display(),
            files = files.len(),
            concurrent = self.concurrent_scans,
            "clamd scan started"
        );
        let started = std::time::Instant::now();

        // Parallel INSTREAM: every future owns its file name, so results
        // can never be zip-mis-attributed (a previous bug class here).
        let entries = futures_util::stream::iter(files.into_iter().map(|file| async move {
            let name =
                file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let response = tokio::time::timeout(IO_TIMEOUT, self.instream_file(&file))
                .await
                .map_err(|_| {
                    ScannerError::Unavailable(format!(
                        "clamd instream timed out after {IO_TIMEOUT:?}"
                    ))
                })??;
            Ok::<_, ScannerError>((name, parse_verdict(&response)))
        }))
        .buffer_unordered(self.concurrent_scans)
        .collect::<Vec<Result<_, ScannerError>>>()
        .await;

        // First Unavailable/Io aborts the whole batch (orchestrator
        // requeues); verdicts are already collected otherwise.
        let mut verdicts = Vec::with_capacity(entries.len());
        for entry in entries {
            verdicts.push(entry?);
        }
        tracing::debug!(
            files = verdicts.len(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "clamd scan finished"
        );
        Ok(ScanOutput { entries: verdicts })
    }

    async fn update(&self) -> Result<UpdateOutcome, ScannerError> {
        // clamd loads databases via freshclam; the closest update action is
        // running freshclam once.
        let output = tokio::process::Command::new("freshclam")
            .arg("--stdout")
            .output()
            .await
            .map_err(|e| ScannerError::Update(format!("freshclam spawn: {e}")))?;
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        if !output.status.success() {
            return Err(ScannerError::Update(format!(
                "freshclam exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        if text.contains("up-to-date") || text.contains("up to date") {
            Ok(UpdateOutcome::UpToDate)
        } else {
            Ok(UpdateOutcome::Updated)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use std::sync::Arc;

    /// A fake clamd: answers PING/VERSION and runs INSTREAM with canned
    /// verdicts (content containing "EICAR" -> FOUND, otherwise OK).
    async fn spawn_fake_clamd() -> (String, Arc<parking_lot::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let log: Arc<parking_lot::Mutex<Vec<String>>> = Arc::default();
        {
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let log = Arc::clone(&log);
                    tokio::spawn(async move {
                        handle_socket(socket, log).await;
                    });
                }
            });
        }
        (address, log)
    }

    async fn handle_socket(
        mut socket: tokio::net::TcpStream,
        log: Arc<parking_lot::Mutex<Vec<String>>>,
    ) {
        use tokio::io::AsyncReadExt;
        // Read the command (z-terminated) byte-by-byte: anything past the
        // NUL belongs to the INSTREAM framing and must stay in the stream.
        let mut command = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            socket.read_exact(&mut byte).await.unwrap();
            if byte[0] == 0 {
                break;
            }
            command.push(byte[0]);
        }
        let command = String::from_utf8_lossy(&command).to_string();
        log.lock().push(format!("cmd:{command}"));
        match command.as_str() {
            "PING" => socket.write_all(b"PONG\n").await.unwrap(),
            "VERSION" => {
                socket.write_all(b"ClamAV 1.0.4/27000/Mon Jun 3 09:57:42 2024\n").await.unwrap()
            }
            "INSTREAM" => {
                let mut payload = Vec::new();
                loop {
                    let mut len_buf = [0u8; 4];
                    socket.read_exact(&mut len_buf).await.unwrap();
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len == 0 {
                        break;
                    }
                    let mut chunk = vec![0u8; len];
                    socket.read_exact(&mut chunk).await.unwrap();
                    payload.extend_from_slice(&chunk);
                }
                let response = if payload.windows(5).any(|w| w.eq_ignore_ascii_case(b"EICAR")) {
                    "stream: Win.Test.EICAR FOUND\n"
                } else {
                    "stream: OK\n"
                };
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            _ => socket.write_all(b"UNKNOWN COMMAND\n").await.unwrap(),
        }
        socket.shutdown().await.ok();
    }

    fn write_sample(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[tokio::test]
    async fn protocol_round_trip() {
        let (address, log) = spawn_fake_clamd().await;
        let scanner = ClamdScanner::new(&address, 2);

        assert!(scanner.is_installed().await.unwrap());
        let profile = scanner.profile().await.unwrap();
        assert_eq!(profile.av_version.as_deref(), Some("1.0.4"));
        assert_eq!(profile.bases_version.as_deref(), Some("27000"));

        let tmp = std::env::temp_dir().join(format!("vs-clamd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        write_sample(&tmp, "clean.bin", b"hello world");
        write_sample(&tmp, "eicar.com", b"X5O!P%@AP[EICAR-TEST-FILE]");

        let output = scanner.scan(&tmp).await.unwrap();
        assert_eq!(output.entries.len(), 2);
        let verdict = |name: &str| {
            output.entries.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()).unwrap()
        };
        assert_eq!(verdict("clean.bin").outcome, ScanOutcome::Clean);
        match verdict("eicar.com").outcome {
            ScanOutcome::Detected { detections } => {
                assert_eq!(detections[0].name, "Win.Test.EICAR");
            }
            other => panic!("expected detection, got {other:?}"),
        }

        // The INSTREAM framing actually reached the fake daemon.
        let instreams = log.lock().iter().filter(|m| m.as_str() == "cmd:INSTREAM").count();
        assert_eq!(instreams, 2);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn unreachable_daemon_maps_to_unavailable() {
        // Port 1 on localhost is practically always closed.
        let scanner = ClamdScanner::new("127.0.0.1:1", 4);
        assert!(!scanner.is_installed().await.unwrap());
        let err = scanner.scan(Path::new(".")).await.unwrap_err();
        assert!(matches!(err, ScannerError::Unavailable(_)));
    }

    #[test]
    fn verdict_parsing() {
        assert_eq!(parse_verdict("stream: OK").outcome, ScanOutcome::Clean);
        match parse_verdict("stream: Win.Test.Dropper FOUND").outcome {
            ScanOutcome::Detected { detections } => {
                assert_eq!(detections[0].name, "Win.Test.Dropper");
            }
            other => panic!("expected detection, got {other:?}"),
        }
        assert!(matches!(
            parse_verdict("stream:.Integer overflow. ERROR").outcome,
            ScanOutcome::Error { .. }
        ));
        // The stream limit gets a dedicated, actionable message.
        let verdict = parse_verdict("stream: INSTREAM size limit exceeded. ERROR");
        match verdict.outcome {
            ScanOutcome::Error { message } => {
                assert!(message.contains("StreamMaxLength"));
            }
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn concurrent_instream_keeps_per_file_attribution() {
        let (address, _log) = spawn_fake_clamd().await;
        let scanner = ClamdScanner::new(&address, 4);

        let tmp = std::env::temp_dir().join(format!("vs-clamd-conc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let mut expected = std::collections::HashMap::new();
        for i in 0..12u32 {
            let dirty = i % 3 == 1;
            let content = if dirty {
                format!("sample {i} with EICAR marker")
            } else {
                format!("clean sample {i}")
            };
            let name = format!("file-{i:02}.bin");
            std::fs::write(tmp.join(&name), content).unwrap();
            expected.insert(name, dirty);
        }

        let output = scanner.scan(&tmp).await.unwrap();
        assert_eq!(output.entries.len(), 12);
        assert_eq!(output.entries.len(), expected.len());
        for (name, verdict) in &output.entries {
            let dirty = expected.get(name).copied().expect("file we wrote");
            if dirty {
                assert!(matches!(verdict.outcome, ScanOutcome::Detected { .. }), "file {name}");
            } else {
                assert_eq!(verdict.outcome, ScanOutcome::Clean, "file {name}");
            }
        }

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn version_parsing() {
        let profile = parse_version("ClamAV 1.0.4/27000/Mon Jun 3 09:57:42 2024");
        assert_eq!(profile.av_name, "ClamAV");
        assert_eq!(profile.av_version.as_deref(), Some("1.0.4"));
        assert_eq!(profile.bases_version.as_deref(), Some("27000"));
    }
}
