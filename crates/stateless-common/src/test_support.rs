//! Helpers for this crate's own tests.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// A fresh directory under the system temp dir, removed on drop.
///
/// Not `tempfile`: a dev-dependency of this crate is listed in its Cargo.lock entry, which is
/// part of coverage-replayer's dependency closure and so of its coverage store's `binary_id`.
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    pub fn new(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "stateless-common-{label}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
