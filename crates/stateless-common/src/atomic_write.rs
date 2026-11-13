//! Whole-file writes that a reader never sees half done.

use std::{
    fs,
    io::Write as _,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use eyre::{Result, WrapErr};

/// The suffix of the temporary a write goes through, which sits beside its target as
/// `<target name>.<pid>.<seq>.tmp`. A crash between its creation and the rename can orphan one,
/// so the sole writer of a directory may sweep the files ending in it.
pub const TEMP_SUFFIX: &str = ".tmp";

/// Writes via a unique temporary, fsync and rename: a reader never sees a partial file, and
/// concurrent writers of one target both succeed (the last rename wins). The data is fsynced
/// before the rename and the directory after it (best-effort, as a directory fsync may fail off
/// Linux), so the new contents survive a power cut once this returns.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_renamed(path, bytes, true)
}

/// [`write_atomic`] without the fsyncs: a reader still never sees a partial file, but a power
/// cut may lose the write. For files every reader checks and can recreate.
pub fn write_scratch(path: &Path, bytes: &[u8]) -> Result<()> {
    write_renamed(path, bytes, false)
}

fn write_renamed(path: &Path, bytes: &[u8], durable: bool) -> Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "{}.{}.{}{TEMP_SUFFIX}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    );
    let tmp = path.with_file_name(unique);
    let result = (|| -> Result<()> {
        let mut f = fs::File::create(&tmp).wrap_err_with(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes).wrap_err_with(|| format!("write {}", tmp.display()))?;
        if durable {
            f.sync_all().wrap_err_with(|| format!("fsync {}", tmp.display()))?;
        }
        drop(f);
        fs::rename(&tmp, path).wrap_err_with(|| format!("rename to {}", path.display()))?;
        if durable &&
            let Some(parent) = path.parent() &&
            let Ok(dir) = fs::File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ScratchDir;

    fn temps(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(TEMP_SUFFIX))
            .count()
    }

    #[test]
    fn a_write_round_trips_replaces_the_old_contents_and_leaves_no_temp() {
        let dir = ScratchDir::new("atomic-write");
        let target = dir.path().join("out.bin");
        write_atomic(&target, b"first").unwrap();
        write_scratch(&target, b"second").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        assert_eq!(temps(dir.path()), 0, "no temp left after success");
    }

    #[test]
    fn a_failed_write_removes_its_temp() {
        let dir = ScratchDir::new("atomic-write-fail");
        // A directory at the target path makes the final rename fail.
        let target = dir.path().join("occupied");
        fs::create_dir(&target).unwrap();
        assert!(write_atomic(&target, b"x").is_err());
        assert!(write_scratch(&target, b"x").is_err());
        assert_eq!(temps(dir.path()), 0, "a failed write must remove its temp");
    }
}
