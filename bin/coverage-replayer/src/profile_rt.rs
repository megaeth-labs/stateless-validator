//! Thin wrapper around the LLVM profiler runtime that `-C instrument-coverage` links in.
//! Its C symbols exist only in an instrumented build, so they are gated behind the
//! `coverage` feature; without it `write_profraw` tells the operator to rebuild.

use std::path::Path;

use eyre::Result;

#[cfg(feature = "coverage")]
mod ffi {
    unsafe extern "C" {
        pub fn __llvm_profile_reset_counters();
        pub fn __llvm_profile_write_file() -> i32;
        pub fn __llvm_profile_set_filename(name: *const std::os::raw::c_char);
    }
}

/// Resets all coverage counters of the current process to zero.
#[cfg(feature = "coverage")]
pub fn reset_counters() {
    unsafe { ffi::__llvm_profile_reset_counters() }
}

#[cfg(not(feature = "coverage"))]
pub fn reset_counters() {}

/// Writes the current counter values to `path` as a `.profraw` file.
#[cfg(feature = "coverage")]
pub fn write_profraw(path: &Path) -> Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| eyre::eyre!("profraw path contains NUL: {e}"))?;
    let rc = unsafe {
        ffi::__llvm_profile_set_filename(c_path.as_ptr());
        ffi::__llvm_profile_write_file()
    };
    // Re-point at /dev/null so the at-exit write can't recreate a profraw the judge deleted.
    suppress_default_profile();
    eyre::ensure!(rc == 0, "__llvm_profile_write_file returned {rc}");
    Ok(())
}

/// Sends the runtime's automatic at-exit profile write to /dev/null, so an instrumented
/// process does not drop a stray `default_*.profraw` into the current directory.
#[cfg(feature = "coverage")]
pub fn suppress_default_profile() {
    static DEV_NULL: &std::ffi::CStr = c"/dev/null";
    unsafe { ffi::__llvm_profile_set_filename(DEV_NULL.as_ptr()) }
}

#[cfg(not(feature = "coverage"))]
pub fn suppress_default_profile() {}

#[cfg(not(feature = "coverage"))]
pub fn write_profraw(_path: &Path) -> Result<()> {
    eyre::bail!(
        "this binary was built without the `coverage` feature; rebuild with \
         RUSTC_WRAPPER=\"$PWD/bin/coverage-replayer/cov-rustc-wrapper.sh\" \
         cargo build --profile coverage -p coverage-replayer --features coverage \
         --target \"$(rustc -vV | sed -n 's/host: //p')\" \
         — the explicit --target is required: it is how the wrapper tells the \
         code to instrument from host artifacts"
    )
}

/// Whether this binary can capture coverage at all.
pub const fn is_instrumented_build() -> bool {
    cfg!(feature = "coverage")
}

/// Refuses a profile directory containing `%`: the runtime reads `%p`, `%h`, `%m`, ... in a
/// profile filename as patterns, so the profile would land where the worker does not look.
pub fn ensure_literal_profile_dir(dir: &Path) -> Result<()> {
    eyre::ensure!(
        !dir.as_os_str().as_encoded_bytes().contains(&b'%'),
        "{} contains '%', which the LLVM profile runtime reads as a filename pattern — choose \
         a --data-dir without one",
        dir.display()
    );
    Ok(())
}

/// The image this process is running, as a path that stays valid after the file it was
/// started from is replaced. A rebuild mid-backfill would make llvm-cov read the NEW
/// binary's coverage map, and on Linux turns `current_exe()` into an unspawnable
/// "<path> (deleted)"; `/proc/<pid>/exe` still names the running image. The pid is explicit
/// because another process (llvm-cov, a child mid-exec) resolves `/proc/self` to itself.
pub fn own_executable() -> Result<std::path::PathBuf> {
    if cfg!(target_os = "linux") {
        Ok(std::path::PathBuf::from(format!("/proc/{}/exe", std::process::id())))
    } else {
        Ok(std::env::current_exe()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_percent_in_the_profile_dir_is_refused() {
        ensure_literal_profile_dir(Path::new("/scans/pool/tmp")).expect("plain path");
        let err = ensure_literal_profile_dir(Path::new("/scans/100%pool/tmp")).expect_err("'%'");
        assert!(err.to_string().contains("100%pool"), "{err}");
    }

    /// Whatever path is returned must be the running image itself.
    #[test]
    fn own_executable_is_the_running_image() {
        let own = std::fs::canonicalize(own_executable().unwrap()).unwrap();
        assert_eq!(own, std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap());
    }
}
