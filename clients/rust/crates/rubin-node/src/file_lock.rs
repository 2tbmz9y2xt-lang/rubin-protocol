use std::fs::File;
use std::io;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockClass {
    Contended,
    InvalidOrUnopenable,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    UnsupportedHost,
}

pub(crate) struct HeldFileLock {
    file: File,
}

impl HeldFileLock {
    pub(crate) fn release(self) {
        drop(self.file);
    }
}

pub(crate) struct LockError {
    class: LockClass,
    cause: io::Error,
}

impl LockError {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn invalid(cause: io::Error) -> Self {
        Self {
            class: LockClass::InvalidOrUnopenable,
            cause,
        }
    }

    pub(crate) fn class(&self) -> LockClass {
        self.class
    }

    pub(crate) fn cause(&self) -> &io::Error {
        &self.cause
    }
}

pub(crate) fn acquire(path: &Path) -> Result<HeldFileLock, LockError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        acquire_supported_host(path)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        Err(LockError {
            class: LockClass::UnsupportedHost,
            cause: io::Error::new(
                io::ErrorKind::Unsupported,
                "datadir writer lock is unsupported on this host",
            ),
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn acquire_supported_host(path: &Path) -> Result<HeldFileLock, LockError> {
    use std::fs::{OpenOptions, TryLockError};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(LockError::invalid)?;
    let metadata = file.metadata().map_err(LockError::invalid)?;
    if !metadata.file_type().is_file() {
        return Err(LockError::invalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "datadir lock must be a regular file",
        )));
    }
    if metadata.len() != 0 {
        return Err(LockError::invalid(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("datadir lock must be empty, got size {}", metadata.len()),
        )));
    }
    if metadata.nlink() != 1 {
        return Err(LockError::invalid(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("datadir lock must have one link, got {}", metadata.nlink()),
        )));
    }
    match file.try_lock() {
        Ok(()) => Ok(HeldFileLock { file }),
        Err(TryLockError::WouldBlock) => Err(LockError {
            class: LockClass::Contended,
            cause: io::Error::from(io::ErrorKind::WouldBlock),
        }),
        Err(TryLockError::Error(error)) => Err(LockError::invalid(error)),
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::{acquire, LockClass};
    use std::env;
    use std::fs;
    use std::io;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    type LeafSetup = fn(&Path);

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "rubin-node-file-lock-{name}-{}-{nonce}-{}",
            std::process::id(),
            NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|err| panic!("create temp dir {}: {err}", path.display()));
        path
    }

    fn assert_invalid(path: &Path) {
        match acquire(path) {
            Ok(lock) => {
                lock.release();
                panic!("unexpectedly acquired {}", path.display());
            }
            Err(error) => assert_eq!(error.class(), LockClass::InvalidOrUnopenable),
        }
    }

    #[test]
    fn acquire_contends_until_release_and_leaves_empty_file() {
        let dir = temp_dir("contended");
        let path = dir.join("lock");
        let holder = acquire(&path).unwrap_or_else(|err| panic!("first acquire: {}", err.cause()));
        let metadata = fs::metadata(&path).unwrap_or_else(|err| panic!("metadata: {err}"));
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.len(), 0);

        match acquire(&path) {
            Err(error) => assert_eq!(error.class(), LockClass::Contended),
            Ok(lock) => {
                lock.release();
                panic!("second acquire unexpectedly succeeded");
            }
        }
        holder.release();
        acquire(&path)
            .unwrap_or_else(|err| panic!("reacquire after release: {}", err.cause()))
            .release();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn acquire_rejects_unsafe_leaf_shapes() {
        let cases: [(&str, LeafSetup); 5] = [
            ("symlink", |path| {
                let target = path.with_extension("target");
                fs::write(&target, []).unwrap_or_else(|err| panic!("write target: {err}"));
                symlink(target, path).unwrap_or_else(|err| panic!("symlink: {err}"));
            }),
            ("dangling_symlink", |path| {
                symlink(path.with_extension("missing"), path)
                    .unwrap_or_else(|err| panic!("dangling symlink: {err}"));
            }),
            ("directory", |path| {
                fs::create_dir(path).unwrap_or_else(|err| panic!("mkdir: {err}"));
            }),
            ("nonempty_file", |path| {
                fs::write(path, b"not empty").unwrap_or_else(|err| panic!("write lock: {err}"));
            }),
            ("hardlink", |path| {
                let source = path.with_extension("source");
                fs::write(&source, []).unwrap_or_else(|err| panic!("write source: {err}"));
                fs::hard_link(source, path).unwrap_or_else(|err| panic!("hard link: {err}"));
            }),
        ];
        for (name, setup) in cases {
            let dir = temp_dir(name);
            let path = dir.join("lock");
            setup(&path);
            assert_invalid(&path);
            let _ = fs::remove_dir_all(dir);
        }
    }

    // Test-binary-only protocol for an executable built by `cargo test --no-run`.
    // Set RUBIN_FILE_LOCK_PROTOCOL_MODE to holder or challenger and execute only
    // this test. The holder needs LOCK_PATH, READY_PATH, and RELEASE_PATH; the
    // challenger needs LOCK_PATH and RESULT_PATH. Every supplied path is absolute.
    #[test]
    fn external_file_lock_protocol() {
        let Ok(mode) = env::var("RUBIN_FILE_LOCK_PROTOCOL_MODE") else {
            return;
        };
        let lock_path = protocol_absolute_path("RUBIN_FILE_LOCK_PROTOCOL_LOCK_PATH");
        match mode.as_str() {
            "holder" => {
                let ready_path = protocol_absolute_path("RUBIN_FILE_LOCK_PROTOCOL_READY_PATH");
                let lock_parent = lock_path
                    .parent()
                    .unwrap_or_else(|| panic!("lock path has no parent"));
                assert!(
                    !ready_path.starts_with(lock_parent),
                    "ready marker must be outside locked parent: {}",
                    ready_path.display()
                );
                let release_path = protocol_absolute_path("RUBIN_FILE_LOCK_PROTOCOL_RELEASE_PATH");
                protocol_holder(&lock_path, &ready_path, &release_path);
            }
            "challenger" => {
                let result_path = protocol_absolute_path("RUBIN_FILE_LOCK_PROTOCOL_RESULT_PATH");
                protocol_challenger(&lock_path, &result_path);
            }
            _ => panic!("unknown RUBIN_FILE_LOCK_PROTOCOL_MODE {mode}"),
        }
    }

    fn protocol_absolute_path(name: &str) -> PathBuf {
        let path = PathBuf::from(env::var(name).unwrap_or_else(|_| panic!("{name} must be set")));
        assert!(path.is_absolute(), "{name} must be absolute");
        path
    }

    fn protocol_holder(lock_path: &Path, ready_path: &Path, release_path: &Path) {
        let lock =
            acquire(lock_path).unwrap_or_else(|err| panic!("holder acquire: {}", err.cause()));
        fs::write(ready_path, b"ready\n").unwrap_or_else(|err| panic!("write ready marker: {err}"));
        wait_for_marker(release_path).unwrap_or_else(|err| panic!("wait release marker: {err}"));
        lock.release();
    }

    fn protocol_challenger(lock_path: &Path, result_path: &Path) {
        let outcome = match acquire(lock_path) {
            Ok(lock) => {
                lock.release();
                "acquired"
            }
            Err(error) => match error.class() {
                LockClass::Contended => "contended",
                LockClass::InvalidOrUnopenable => "invalid_or_unopenable",
            },
        };
        fs::write(result_path, format!("{outcome}\n"))
            .unwrap_or_else(|err| panic!("write result marker: {err}"));
    }

    fn wait_for_marker(path: &Path) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match fs::metadata(path) {
                Ok(_) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timeout waiting for {}", path.display()),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
