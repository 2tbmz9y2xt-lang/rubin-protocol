use std::io::Write;
use std::path::Path;

use crate::file_lock::{self, HeldFileLock, LockClass};

pub(crate) struct HeldDatadirLock(HeldFileLock);

impl HeldDatadirLock {
    pub(crate) fn release(self) {
        self.0.release();
    }
}

pub(crate) fn acquire(
    normalized_data_dir: &Path,
    stderr: &mut dyn Write,
) -> Result<HeldDatadirLock, i32> {
    let lock_path = normalized_data_dir.join(".rubin.lock");
    match file_lock::acquire(&lock_path) {
        Ok(lock) => Ok(HeldDatadirLock(lock)),
        Err(error) if error.class() == LockClass::Contended => {
            let _ = writeln!(
                stderr,
                "datadir is already in use by another rubin-node: {}",
                normalized_data_dir.display()
            );
            Err(2)
        }
        Err(error) => {
            let _ = writeln!(
                stderr,
                "cannot open datadir lock {}: {}",
                lock_path.display(),
                error.cause()
            );
            Err(2)
        }
    }
}
