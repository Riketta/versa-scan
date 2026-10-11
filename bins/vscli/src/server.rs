//! Embedded artifact server: serves stored samples to workers over HTTP.
//!
//! - `GET/HEAD /samples/<sha256>` - 200 with the bytes, 206 for a single
//!   `Range: bytes=a-b` request, 404 when absent, 400 on malformed ids.
//! - Samples over 1 MiB stream from disk (`ReaderStream`), so large files
//!   never sit in memory.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use std::collections::HashMap;

use axum::extract::Query;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use versa_scan_core::models::digest::Sha256Digest;

use crate::store::SampleStore;

const STREAM_THRESHOLD: u64 = 1024 * 1024;

/// Shared server state: the store plus the optional bearer token. When a
/// token is configured, every request must carry it as `?token=`; samples
/// are guessable by sha256 otherwise (the request URLs travel the bus in
/// plaintext, so this is transport-level hygiene, not a security boundary).
#[derive(Clone)]
pub struct ArtifactState {
    store: Arc<SampleStore>,
    token: Option<String>,
}

impl ArtifactState {
    pub fn new(store: Arc<SampleStore>, token: &str) -> Self {
        let token = token.trim().to_owned();
        let token = (!token.is_empty()).then_some(token);
        Self { store, token }
    }

    /// Constant-time comparison: response timing must not leak how much of
    /// the token matched.
    fn token_matches(&self, presented: Option<&String>) -> bool {
        match (&self.token, presented) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(expected), Some(actual)) => {
                let (a, b) = (expected.as_bytes(), actual.as_bytes());
                if a.len() != b.len() {
                    return false;
                }
                a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
            }
        }
    }
}

pub fn router(state: ArtifactState) -> Router {
    Router::new().route("/samples/{sha}", get(get_sample).head(head_sample)).with_state(state)
}

/// Runs until the process is stopped; call from a spawned task. Returns the
/// bind result so the caller can fail fast instead of publishing requests
/// into a void.
pub async fn serve(store: Arc<SampleStore>, bind: &str, token: &str) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(bind = %bind, protected = !token.trim().is_empty(), "artifact server listening");
    axum::serve(listener, router(ArtifactState::new(store, token))).await
}

struct SampleFile {
    file: tokio::fs::File,
    size: u64,
}

async fn open_sample(store: &SampleStore, sha: &str) -> Result<SampleFile, StatusCode> {
    let digest = Sha256Digest::from_hex(sha).map_err(|_| StatusCode::BAD_REQUEST)?;
    let shard = digest.as_str().get(0..2).ok_or(StatusCode::BAD_REQUEST)?;
    let path = store.samples_dir().join(shard).join(digest.as_str());
    let mut file = tokio::fs::File::open(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
    let size = file.metadata().await.map_err(|_| StatusCode::NOT_FOUND)?.len();
    Ok(SampleFile { file, size })
}

/// Single range only: `bytes=a-b` or `bytes=a-`.
fn parse_range(range: &str, size: u64) -> Option<(u64, u64)> {
    let rest = range.strip_prefix("bytes=")?;
    let (start, end) = rest.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = match end.trim() {
        "" => size.saturating_sub(1),
        e => e.parse().ok()?,
    };
    if start > end || start >= size {
        return None;
    }
    Some((start, end.min(size - 1)))
}

async fn body_response(
    status: StatusCode,
    mut sample: SampleFile,
    start: u64,
    length: u64,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, HeaderValue::from(length));
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{}/*", start + length - 1))
                .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
        );
    }
    if start > 0 {
        let _ = sample.file.seek(std::io::SeekFrom::Start(start)).await;
    }
    let mut take = sample.file.take(length);
    if length > STREAM_THRESHOLD {
        builder
            .body(axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(take)))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    } else {
        let mut bytes = Vec::with_capacity(length as usize);
        // `take` bounds the read; errors surface as short bodies, which
        // fetchers catch via hash verification.
        let _ = take.read_to_end(&mut bytes).await;
        builder
            .body(axum::body::Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }
}

async fn get_sample(
    State(state): State<ArtifactState>,
    Path(sha): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !state.token_matches(params.get("token")) {
        // 404, not 401: do not confirm that the sample exists.
        return StatusCode::NOT_FOUND.into_response();
    }
    let sample = match open_sample(&state.store, &sha).await {
        Ok(sample) => sample,
        Err(status) => return status.into_response(),
    };
    let size = sample.size;
    match headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|r| parse_range(r, size))
    {
        Some((start, end)) => {
            body_response(StatusCode::PARTIAL_CONTENT, sample, start, end - start + 1).await
        }
        None => body_response(StatusCode::OK, sample, 0, size).await,
    }
}

async fn head_sample(
    State(state): State<ArtifactState>,
    Path(sha): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !state.token_matches(params.get("token")) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match open_sample(&state.store, &sha).await {
        Ok(sample) => Response::builder()
            .status(StatusCode::OK)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CONTENT_LENGTH, HeaderValue::from(sample.size))
            .body(axum::body::Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(status) => status.into_response(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use std::time::Duration;
    use versa_scan_core::ports::driven::fetch::FetchError;

    #[tokio::test]
    async fn serves_fetches_and_ranges() {
        let root = std::env::temp_dir().join(format!("vs-srv-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(SampleStore::open(&root).unwrap());
        let stored = store.put(b"artifact-body-for-range-test").unwrap();

        let bind = "127.0.0.1:0";
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(
            async move { axum::serve(listener, router(ArtifactState::new(store, ""))).await },
        );
        let base = format!("http://{address}");

        // Full GET via the worker-side fetcher (hash-verified round trip).
        let fetcher = HttpFetcherForTest::new();
        let request = versa_scan_core::models::sample::SampleRequest {
            sample_id: versa_scan_core::models::SampleId::new("s").unwrap(),
            url: format!("{base}/samples/{}", stored.sha256),
            sha256: versa_scan_core::models::Sha256Digest::from_hex(&stored.sha256).unwrap(),
            size: stored.size,
            priority: versa_scan_core::models::Priority::Normal,
            report_dest: versa_scan_core::models::ReportDest::new("r").unwrap(),
            correlation_id: versa_scan_core::models::CorrelationId::new("c").unwrap(),
            extensions: vec![],
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let dest_dir = std::env::temp_dir().join(format!("vs-srv-dl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dest_dir).unwrap();
        let fetched = fetcher.fetch(&request, &dest_dir.join("out")).await.unwrap();
        assert_eq!(fetched.size, stored.size);

        // Range request via raw HTTP: bytes 8-11 of the stored content.
        use reqwest::header::HeaderValue;
        let client = reqwest::Client::new();
        let ranged = client
            .get(format!("{base}/samples/{}", stored.sha256))
            .header(header::RANGE, HeaderValue::from_static("bytes=8-11"))
            .send()
            .await
            .unwrap();
        assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(ranged.bytes().await.unwrap(), b"-bod".as_slice());

        // HEAD succeeds (hyper owns Content-Length on HEAD); the size is
        // verifiable via Content-Range on a full-range GET.
        let head = client.head(format!("{base}/samples/{}", stored.sha256)).send().await.unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers().get(header::ACCEPT_RANGES).and_then(|v| v.to_str().ok()),
            Some("bytes")
        );
        let ranged_full = client
            .get(format!("{base}/samples/{}", stored.sha256))
            .header(header::RANGE, HeaderValue::from_static("bytes=0-"))
            .send()
            .await
            .unwrap();
        assert_eq!(ranged_full.status(), StatusCode::PARTIAL_CONTENT);
        let content_range =
            ranged_full.headers().get(header::CONTENT_RANGE).unwrap().to_str().unwrap().to_owned();
        assert!(
            content_range.starts_with(&format!("bytes 0-{}/*", stored.size - 1)),
            "content-range was: {content_range}"
        );

        // Unknown sample -> 404; malformed id -> 400.
        assert_eq!(
            client.get(format!("{base}/samples/{}", "f".repeat(64))).send().await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            client.get(format!("{base}/samples/nothex")).send().await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&dest_dir).ok();
    }

    // Thin wrapper so the test can build a fetcher without importing infra's
    // constructor error type at the call site.
    struct HttpFetcherForTest(versa_scan_infra::outbound_adapters::fetch::HttpFetcher);

    impl HttpFetcherForTest {
        fn new() -> Self {
            Self(
                versa_scan_infra::outbound_adapters::fetch::HttpFetcher::new(
                    Duration::from_secs(10),
                    1024 * 1024,
                    Vec::new(),
                )
                .unwrap(),
            )
        }
        async fn fetch(
            &self,
            request: &versa_scan_core::models::sample::SampleRequest,
            dest: &std::path::Path,
        ) -> Result<
            versa_scan_core::ports::driven::fetch::FetchedFile,
            versa_scan_core::ports::driven::fetch::FetchError,
        > {
            versa_scan_core::ports::driven::fetch::SampleFetcherPort::fetch(&self.0, request, dest)
                .await
        }
    }

    // Keep the FetchError import referenced (used in the wrapper signature).
    #[allow(dead_code)]
    fn _fetch_error_used(_: FetchError) {}
}

#[cfg(test)]
mod token_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn token_protects_the_store() {
        let tmp = std::env::temp_dir().join(format!("vs-art-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(SampleStore::open(&tmp.join("store")).unwrap());
        let body = b"artifact body under token";
        store.put(body).unwrap();

        let bind = "127.0.0.1:0";
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(ArtifactState::new(store, "hunter2"))).await
        });
        let base = format!("http://{address}");

        // No token -> 404 (not 401: never confirm existence).
        let miss = reqwest::get(format!("{base}/samples/{}", sha_hex(body))).await.unwrap();
        assert_eq!(miss.status(), StatusCode::NOT_FOUND);
        // Wrong token -> 404.
        let wrong =
            reqwest::get(format!("{base}/samples/{}?token=nope", sha_hex(body))).await.unwrap();
        assert_eq!(wrong.status(), StatusCode::NOT_FOUND);
        // Right token -> 200 with the exact body.
        let hit =
            reqwest::get(format!("{base}/samples/{}?token=hunter2", sha_hex(body))).await.unwrap();
        assert_eq!(hit.status(), StatusCode::OK);
        assert_eq!(hit.bytes().await.unwrap(), body.as_slice());

        std::fs::remove_dir_all(&tmp).ok();
    }

    fn sha_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        Sha256Digest::to_hex(&sha2::Sha256::digest(bytes))
    }
}
