use std::fs;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

pub fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|e| format!("{name}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create parent {}: {e}", parent.display()))?;
    }
    let tmp_path = format!("{}.tmp.{}", path.display(), std::process::id());
    // Durability contract (E.1): the temp file's bytes AND its inode metadata
    // must hit stable storage before the rename, otherwise a crash between
    // rename and the next implicit flush can leave the destination pointing
    // at a zero-length / partially-written file. Using `OpenOptions` here
    // explicitly so we control flush ordering: write all bytes, then
    // `sync_all()` (data + metadata), then close, then rename, then sync the
    // parent directory so the rename itself is durable.
    {
        use std::io::Write;
        let mut tmp = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| format!("open temp {}: {e}", tmp_path))?;
        tmp.write_all(data)
            .map_err(|e| format!("write temp {}: {e}", tmp_path))?;
        tmp.sync_all()
            .map_err(|e| format!("sync temp {}: {e}", tmp_path))?;
    }
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("rename temp {} -> {}: {e}", tmp_path, path.display())
    })?;
    // Directory fsync makes the rename itself durable. Without this the
    // destination file's bytes are on disk after the temp `sync_all()` above,
    // but the directory entry that points the destination name at the new
    // inode may still live only in the kernel page cache and be lost on
    // crash. Mirrors the Go `writeFileAtomic` `Sync` on parent directory
    // for cross-client parity.
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// Open the parent directory and call `sync_all()` so any rename or unlink
/// performed in it is itself durable. Splitting this out keeps
/// `write_file_atomic` linear and lets storage callers fsync ad-hoc
/// directory mutations later if they need to.
pub fn sync_dir(dir: &Path) -> Result<(), String> {
    fs::OpenOptions::new()
        .read(true)
        .open(dir)
        .map_err(|e| format!("open dir {}: {e}", dir.display()))?
        .sync_all()
        .map_err(|e| format!("sync dir {}: {e}", dir.display()))
}

#[cfg(test)]
pub fn unique_temp_path(prefix: &str) -> PathBuf {
    static NEXT_UNIQUE_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos(),
        NEXT_UNIQUE_TEMP_ID.fetch_add(1, Ordering::Relaxed),
    ))
}

#[cfg(test)]
mod tests {
    use super::{sync_dir, unique_temp_path, write_file_atomic};
    use std::fs;

    /// Smoke test for the E.1 durability contract: a fresh write goes
    /// through OpenOptions + sync_all + rename + parent dir-sync without
    /// surfacing an error on a real filesystem, and the resulting bytes
    /// are exactly what we wrote. We cannot directly observe the fsync
    /// syscall from a unit test, but we DO want a regression that
    /// notices if the `OpenOptions`/`sync_all` chain ever returns an
    /// error on the platforms that run CI (Linux/macOS).
    #[test]
    fn write_file_atomic_durably_persists_fresh_file() {
        let dir = unique_temp_path("rubin-io-utils-fresh");
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("payload.bin");
        let data = b"E.1 fsync contract: bytes + dir entry must both be durable";

        write_file_atomic(&path, data).expect("write_file_atomic");

        let read_back = fs::read(&path).expect("read back");
        assert_eq!(read_back, data);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    /// Replace path: existing destination is overwritten with new bytes.
    /// Verifies sync_all + rename idempotency on top of an existing inode
    /// (this is the dominant chainstate/blockstore path: rewrite the
    /// index file every commit).
    #[test]
    fn write_file_atomic_replaces_existing_file_with_new_durable_bytes() {
        let dir = unique_temp_path("rubin-io-utils-replace");
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("index.json");

        write_file_atomic(&path, b"first").expect("first write");
        write_file_atomic(&path, b"second").expect("second write");

        let read_back = fs::read(&path).expect("read back");
        assert_eq!(read_back, b"second");

        // No leftover .tmp.* sibling — temp must have been renamed away.
        let leftover_tmps: Vec<_> = fs::read_dir(&dir)
            .expect("list dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftover_tmps.is_empty(),
            "stale .tmp.* file remained after rename: {:?}",
            leftover_tmps
                .iter()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Standalone `sync_dir` helper accepts an existing directory and
    /// returns Ok. Storage callers may want to fsync ad-hoc directory
    /// mutations (e.g. after deleting a stale undo file) without going
    /// through `write_file_atomic`.
    #[test]
    fn sync_dir_succeeds_on_existing_directory() {
        let dir = unique_temp_path("rubin-io-utils-syncdir");
        fs::create_dir_all(&dir).expect("create test dir");

        sync_dir(&dir).expect("sync_dir on existing directory");

        let _ = fs::remove_dir_all(&dir);
    }
}
