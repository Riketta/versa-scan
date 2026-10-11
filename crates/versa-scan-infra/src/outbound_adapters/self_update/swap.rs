//! Update application: download -> hash-verify -> extract to staging ->
//! swap the running binary (Windows rename-dance, POSIX replace).

use std::path::{Path, PathBuf};

use reqwest::Client;
use versa_scan_core::models::digest::Sha256Digest;
use versa_scan_core::ports::driven::self_update::UpdateError;

const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Downloads the archive, verifies its hash, extracts it next to the
/// current binary, and swaps the matching executable into place.
pub(crate) async fn download_extract_swap(
    client: &Client,
    url: &str,
    expected_sha256: &Sha256Digest,
    current_exe: &Path,
    staging_parent: &Path,
) -> Result<(), UpdateError> {
    let archive = download(client, url, expected_sha256).await?;
    download_extract_swap_with_bytes(&archive, expected_sha256, current_exe, staging_parent).await
}

/// Shared tail of `apply` for tests: verify the archive hash, extract,
/// swap. Ingestion order matters - nothing touches the current binary
/// before the hash check passes.
pub(crate) async fn download_extract_swap_with_bytes(
    archive: &[u8],
    expected_sha256: &Sha256Digest,
    current_exe: &Path,
    staging_parent: &Path,
) -> Result<(), UpdateError> {
    {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(archive);
        let actual = versa_scan_core::models::digest::Sha256Digest::to_hex(&hasher.finalize());
        if actual != expected_sha256.as_str() {
            return Err(UpdateError::HashMismatch {
                expected: expected_sha256.clone(),
                actual: Sha256Digest::from_hex(&actual)
                    .map_err(|e| UpdateError::Swap(e.to_string()))?,
            });
        }
    }
    let staging = extract_to_staging(archive, staging_parent)?;
    let result = swap_binary(&staging, current_exe);
    let _ = std::fs::remove_dir_all(&staging);
    result
}

async fn download(
    client: &Client,
    url: &str,
    expected_sha256: &Sha256Digest,
) -> Result<Vec<u8>, UpdateError> {
    let response = tokio::time::timeout(DOWNLOAD_TIMEOUT, client.get(url).send())
        .await
        .map_err(|_| {
            UpdateError::Download(format!("download timed out after {DOWNLOAD_TIMEOUT:?}"))
        })?
        .map_err(|e| UpdateError::Download(format!("download: {e}")))?;
    if !response.status().is_success() {
        return Err(UpdateError::Download(format!("download returned {}", response.status())));
    }
    let bytes =
        response.bytes().await.map_err(|e| UpdateError::Download(format!("download read: {e}")))?;
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    let actual = versa_scan_core::models::digest::Sha256Digest::to_hex(&hasher.finalize());
    if actual != expected_sha256.as_str() {
        return Err(UpdateError::HashMismatch {
            expected: expected_sha256.clone(),
            actual: Sha256Digest::from_hex(&actual)
                .map_err(|e| UpdateError::Download(e.to_string()))?,
        });
    }
    Ok(bytes.to_vec())
}

fn extract_to_staging(archive: &[u8], staging_parent: &Path) -> Result<PathBuf, UpdateError> {
    let staging = staging_parent.join(format!("update-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&staging)
        .map_err(|e| UpdateError::Swap(format!("staging create: {e}")))?;

    let cursor = std::io::Cursor::new(archive);
    let mut zip = zip::ZipArchive::new(cursor)
        .map_err(|e| UpdateError::Swap(format!("archive open: {e}")))?;

    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|e| UpdateError::Swap(format!("archive entry {index}: {e}")))?;
        if entry.is_dir() {
            continue;
        }
        let Some(relative) = entry.enclosed_name() else {
            return Err(UpdateError::Swap(format!(
                "archive entry {index} escapes the staging directory (zip-slip)"
            )));
        };
        let target = staging.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| UpdateError::Swap(format!("staging mkdir: {e}")))?;
        }
        let mut out = std::fs::File::create(&target)
            .map_err(|e| UpdateError::Swap(format!("staging file create: {e}")))?;
        std::io::copy(&mut entry, &mut out)
            .map_err(|e| UpdateError::Swap(format!("staging write: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(staging)
}

fn swap_binary(staging: &Path, current_exe: &Path) -> Result<(), UpdateError> {
    let exe_name = current_exe
        .file_name()
        .ok_or_else(|| UpdateError::Swap("current exe has no file name".to_owned()))?;
    let new_exe = find_file_recursive(staging, exe_name).ok_or_else(|| {
        UpdateError::Swap(format!("archive has no {}", exe_name.to_string_lossy()))
    })?;

    #[cfg(windows)]
    {
        // A running exe cannot be deleted or opened for write, but it CAN
        // be renamed: move it aside, then move the replacement in.
        let backup = current_exe.with_extension("exe.old");
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(current_exe, &backup)
            .map_err(|e| UpdateError::Swap(format!("rename current aside: {e}")))?;
        match std::fs::rename(&new_exe, current_exe) {
            Ok(()) => {}
            Err(err) => {
                // Roll the current binary back rather than leaving nothing.
                let _ = std::fs::rename(&backup, current_exe);
                return Err(UpdateError::Swap(format!("move new exe into place: {err}")));
            }
        }
        let _ = std::fs::remove_file(&backup); // locked while running; retry later
    }

    #[cfg(not(windows))]
    {
        // Writing onto the running image fails with ETXTBSY on Linux; copy
        // to a sibling name and rename over - rename replaces a running
        // executable atomically.
        let staged = current_exe.with_extension("new");
        let _ = std::fs::remove_file(&staged);
        std::fs::copy(&new_exe, &staged)
            .map_err(|e| UpdateError::Swap(format!("stage new exe: {e}")))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755));
        std::fs::rename(&staged, current_exe)
            .map_err(|e| UpdateError::Swap(format!("replace exe: {e}")))?;
    }

    tracing::info!(
        from = %new_exe.display(),
        to = %current_exe.display(),
        "binary swapped; restart the worker to run the new version"
    );
    Ok(())
}

fn find_file_recursive(dir: &Path, name: &std::ffi::OsStr) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut dirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            dirs.push(path);
        } else if path.file_name() == Some(name) {
            return Some(path);
        }
    }
    dirs.into_iter().find_map(|sub| find_file_recursive(&sub, name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use versa_scan_core::models::digest::Sha256Digest;

    fn sha_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        hasher.finalize().iter().fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{b:02x}"));
            acc
        })
    }

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::SimpleFileOptions::default();
            for (name, bytes) in entries {
                zip.start_file(*name, options).unwrap();
                std::io::Write::write_all(&mut zip, bytes).unwrap();
            }
            zip.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[tokio::test]
    async fn swaps_binary_from_verified_archive() {
        let root = std::env::temp_dir().join(format!("vs-swap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();

        let exe_name = if cfg!(windows) { "vsd.exe" } else { "vsd" };
        let current = root.join(exe_name);
        std::fs::write(&current, b"old-binary").unwrap();

        let new_bytes = b"brand-new-binary-v2";
        let archive = build_zip(&[("payload/", b""), (exe_name, new_bytes), ("notes.txt", b"hi")]);
        let digest = Sha256Digest::from_hex(&sha_hex(&archive)).unwrap();

        // URL is unused in this direct-call test (download is bypassed);
        // hash mismatch travels the same path and is asserted below.
        download_extract_swap_with_bytes(&archive, &digest, &current, &root).await.unwrap();

        assert_eq!(std::fs::read(&current).unwrap(), new_bytes, "binary replaced");
        if cfg!(windows) {
            // The backup is removed right away in tests (nothing is holding
            // it); on a live process it stays until exit.
            assert!(!current.with_extension("exe.old").exists());
        }
        // staging cleaned up
        let leftovers: Vec<_> =
            std::fs::read_dir(&root).unwrap().flatten().filter(|e| e.path().is_dir()).collect();
        assert!(leftovers.is_empty(), "staging dir must be removed");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn hash_mismatch_aborts_before_swap() {
        let root = std::env::temp_dir().join(format!("vs-swap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();

        let exe_name = if cfg!(windows) { "vsd.exe" } else { "vsd" };
        let current = root.join(exe_name);
        std::fs::write(&current, b"old-binary").unwrap();

        let archive = build_zip(&[(exe_name, b"tampered")]);
        let wrong_digest = Sha256Digest::from_hex(&sha_hex(b"not-the-archive")).unwrap();

        let err = download_extract_swap_with_bytes(&archive, &wrong_digest, &current, &root)
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::HashMismatch { .. }));
        assert_eq!(std::fs::read(&current).unwrap(), b"old-binary", "current binary untouched");
        std::fs::remove_dir_all(&root).ok();
    }
}
