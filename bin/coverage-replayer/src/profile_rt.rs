//! Thin wrapper around the LLVM profiler runtime that `-C instrument-coverage`
//! links into the binary.
//!
//! The three symbols below are the stable C API of compiler-rt's profiling
//! runtime. They only exist when the binary is compiled with
//! `-C instrument-coverage`, so all call sites are gated behind the `coverage`
//! cargo feature; without it the stubs return an error telling the operator to
//! use an instrumented build.

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
    eyre::ensure!(rc == 0, "__llvm_profile_write_file returned {rc}");
    Ok(())
}

#[cfg(not(feature = "coverage"))]
pub fn write_profraw(_path: &Path) -> Result<()> {
    eyre::bail!(
        "this binary was built without the `coverage` feature; \
         rebuild with RUSTFLAGS=\"-C instrument-coverage -Z coverage-options=branch\" \
         cargo build --profile coverage -p coverage-replayer --features coverage"
    )
}

/// Whether this binary can capture coverage at all.
pub const fn is_instrumented_build() -> bool {
    cfg!(feature = "coverage")
}
