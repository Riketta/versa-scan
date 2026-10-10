//! HTTP sample fetcher: streams the response body to a temporary file,
//! enforces the size cap, verifies declared size and sha256, and only then
//! renames into place - the scanner never sees half-files (adapter
//! contract from `SampleFetcherPort`).

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use tokio::io::AsyncWriteExt;
use versa_scan_core::models::digest::Sha256Digest;
use versa_scan_core::models::sample::SampleRequest;
use versa_scan_core::ports::driven::fetch::{FetchError, FetchedFile, SampleFetcherPort};

pub struct HttpFetcher {
    client: reqwest::Client,
    max_file_size: u64,
}

impl HttpFetcher {
    pub fn new(timeout: Duration, max_file_size: u64) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(30))
            .user_agent(concat!("versa-scan/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("http client build: {e}"))?;
        Ok(Self { client, max_file_size })
    }
}

#[async_trait]
impl SampleFetcherPort for HttpFetcher {
    async fn fetch(&self, request: &SampleRequest, dest: &Path) -> Result<FetchedFile, FetchError> {
        let tmp = dest.with_extension("part");
        // Stale temp from a crashed run must not leak into a verdict.
        let _ = tokio::fs::remove_file(&tmp).await;

        let result = self.fetch_inner(request, dest, &tmp).await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result
    }
}

impl HttpFetcher {
    async fn fetch_inner(
        &self,
        request: &SampleRequest,
        dest: &Path,
        tmp: &Path,
    ) -> Result<FetchedFile, FetchError> {
        let response = self.client.get(&request.url).send().await.map_err(|e| {
            if e.is_timeout() {
                FetchError::Timeout
            } else {
                FetchError::Io(format!("http get: {e}"))
            }
        })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(FetchError::NotFound);
        }
        if !response.status().is_success() {
            return Err(FetchError::Io(format!("http status {}", response.status())));
        }

        if let Some(length) = response.content_length() {
            if length > self.max_file_size {
                return Err(FetchError::TooLarge { limit: self.max_file_size, actual: length });
            }
        }

        let mut file = tokio::fs::File::create(tmp)
            .await
            .map_err(|e| FetchError::Io(format!("temp create: {e}")))?;
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let mut written: u64 = 0;

        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.try_next().await.map_err(|e| {
            if e.is_timeout() {
                FetchError::Timeout
            } else {
                FetchError::Io(format!("http body: {e}"))
            }
        })? {
            written = written.saturating_add(chunk.len() as u64);
            if written > self.max_file_size {
                return Err(FetchError::TooLarge { limit: self.max_file_size, actual: written });
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(|e| FetchError::Io(format!("temp write: {e}")))?;
        }
        file.flush().await.map_err(|e| FetchError::Io(format!("temp flush: {e}")))?;
        drop(file);

        if request.size != 0 && written != request.size {
            return Err(FetchError::SizeMismatch { expected: request.size, actual: written });
        }
        let digest_bytes = hasher.finalize();
        let actual_hex = hex_encode(&digest_bytes);
        let expected = Sha256Digest::from_hex(request.sha256.as_str())
            .map_err(|e| FetchError::Io(e.to_string()))?;
        if actual_hex.as_str() != expected.as_str() {
            return Err(FetchError::HashMismatch {
                expected,
                actual: Sha256Digest::from_hex(&actual_hex)
                    .map_err(|e| FetchError::Io(e.to_string()))?,
            });
        }

        // Same-directory rename: atomic on POSIX, and on Windows it
        // replaces only if the destination is gone (it never is - sample
        // ids are unique per batch).
        if dest.exists() {
            let _ = tokio::fs::remove_file(dest).await;
        }
        tokio::fs::rename(tmp, dest)
            .await
            .map_err(|e| FetchError::Io(format!("finalize rename: {e}")))?;

        Ok(FetchedFile { path: dest.to_path_buf(), size: written, digest: expected })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const CONTENT: &[u8] = b"sample-bytes-for-the-fetcher-test";

    fn sha_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        hasher.finalize().iter().fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{b:02x}"));
            acc
        })
    }

    /// Minimal HTTP/1.1 server: `/ok` serves CONTENT, `/404` 404s, `/big`
    /// serves 1 MiB, `/mismatch` serves different bytes.
    async fn spawn_http_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = Vec::new();
                    // Read the request head (ends with a blank line).
                    let mut byte = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                            break;
                        }
                        buf.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&buf);
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    let (status, body): (&str, Vec<u8>) = match path.as_str() {
                        "/ok" => ("200 OK", CONTENT.to_vec()),
                        "/404" => ("404 Not Found", Vec::new()),
                        "/mismatch" => ("200 OK", b"different".to_vec()),
                        "/big" => ("200 OK", vec![0u8; 1024 * 1024]),
                        _ => ("404 Not Found", Vec::new()),
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                    socket.write_all(&body).await.unwrap();
                    socket.shutdown().await.unwrap();
                });
            }
        });
        format!("http://{address}")
    }

    fn fetcher(max: u64) -> HttpFetcher {
        HttpFetcher::new(Duration::from_secs(10), max).unwrap()
    }

    fn request(url: &str, sha: &str, size: u64) -> SampleRequest {
        SampleRequest {
            sample_id: versa_scan_core::models::SampleId::new("s").unwrap(),
            url: url.to_owned(),
            sha256: Sha256Digest::from_hex(sha).unwrap(),
            size,
            priority: versa_scan_core::models::Priority::Normal,
            report_dest: versa_scan_core::models::ReportDest::new("r"),
            correlation_id: versa_scan_core::models::CorrelationId::new("c").unwrap(),
            extensions: vec![],
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn happy_path_writes_and_verifies() {
        let base = spawn_http_server().await;
        let sha = sha_hex(CONTENT);
        let dir = std::env::temp_dir().join(format!("vs-fetch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("sample.bin");

        let fetched = fetcher(1024 * 1024)
            .fetch(&request(&format!("{base}/ok"), &sha, CONTENT.len() as u64), &dest)
            .await
            .unwrap();
        assert_eq!(fetched.size, CONTENT.len() as u64);
        assert_eq!(std::fs::read(&dest).unwrap(), CONTENT);
        assert!(!dest.with_extension("part").exists(), "temp file must be renamed away");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn not_found_maps() {
        let base = spawn_http_server().await;
        let dir = std::env::temp_dir().join(format!("vs-fetch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = fetcher(1024 * 1024)
            .fetch(&request(&format!("{base}/404"), &sha_hex(b"x"), 0), &dir.join("x"))
            .await
            .unwrap_err();
        assert_eq!(err, FetchError::NotFound);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn hash_mismatch_detected() {
        let base = spawn_http_server().await;
        let dir = std::env::temp_dir().join(format!("vs-fetch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // Declared digest is of OTHER content: the fetch must fail the hash
        // check and clean up its temp file.
        let err = fetcher(1024 * 1024)
            .fetch(&request(&format!("{base}/mismatch"), &sha_hex(b"expected"), 0), &dir.join("x"))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::HashMismatch { .. }));
        assert!(!dir.join("x").exists());
        assert!(!dir.join("x.part").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn size_mismatch_detected() {
        let base = spawn_http_server().await;
        let sha = sha_hex(CONTENT);
        let dir = std::env::temp_dir().join(format!("vs-fetch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = fetcher(1024 * 1024)
            .fetch(&request(&format!("{base}/ok"), &sha, 999), &dir.join("x"))
            .await
            .unwrap_err();
        assert_eq!(err, FetchError::SizeMismatch { expected: 999, actual: CONTENT.len() as u64 });
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn too_large_enforced_during_stream() {
        let base = spawn_http_server().await;
        let dir = std::env::temp_dir().join(format!("vs-fetch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = fetcher(1024)
            .fetch(&request(&format!("{base}/big"), &sha_hex(b"big"), 0), &dir.join("x"))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::TooLarge { .. }));
        assert!(!dir.join("x.part").exists(), "failed fetch must clean up");
        std::fs::remove_dir_all(&dir).ok();
    }
}
