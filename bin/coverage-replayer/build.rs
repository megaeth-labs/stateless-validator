//! Captures a fingerprint of the coverage-relevant build at compile time.
//!
//! The coverage namespace (counter ids) is determined by the instrumented
//! mega-evm build, NOT by this binary's orchestration code. Basing the store's
//! `binary_id` on this fingerprint (rather than a whole-exe hash) means editing
//! the dispatcher / adding the resident mode does not invalidate an existing
//! store — only a real mega-evm or toolchain change does.

use std::process::Command;

fn main() {
    // mega-evm's locked git revision from the workspace lockfile.
    let mega_evm = std::fs::read_to_string("../../Cargo.lock")
        .ok()
        .and_then(|lock| mega_evm_rev(&lock))
        .unwrap_or_else(|| "unknown".to_string());

    // rustc version string (LLVM version + host embedded in it).
    let rustc = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=COVERAGE_MEGA_EVM_REV={mega_evm}");
    println!("cargo:rustc-env=COVERAGE_RUSTC_VERSION={rustc}");
    // Re-run if the lockfile changes (mega-evm bump).
    println!("cargo:rerun-if-changed=../../Cargo.lock");
}

/// Extracts the full git revision of the `mega-evm` package from Cargo.lock.
/// The source line looks like:
/// `source = "git+https://github.com/megaeth-labs/mega-evm.git?tag=vX#<rev>"`.
fn mega_evm_rev(lock: &str) -> Option<String> {
    let mut in_mega = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "name = \"mega-evm\"" {
            in_mega = true;
        } else if in_mega && line.starts_with("source = ") && line.contains("mega-evm.git") {
            return line.rsplit('#').next().map(|s| s.trim_end_matches('"').to_string());
        } else if line.starts_with("[[package]]") {
            in_mega = false;
        }
    }
    None
}
