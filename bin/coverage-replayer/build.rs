//! Captures a fingerprint of the coverage-relevant build at compile time.
//!
//! The coverage namespace (counter ids) is determined by the instrumented
//! mega-evm build, NOT by this binary's orchestration code. Basing the store's
//! `binary_id` on this fingerprint (rather than a whole-exe hash) means editing
//! the dispatcher / adding subcommands does not invalidate an existing store —
//! only a real mega-evm or toolchain/target change does.

use std::process::Command;

fn main() {
    // mega-evm's locked git revision from the workspace lockfile. This is the
    // namespace anchor, so a missing rev is a hard build error rather than a
    // silent fallback: overriding mega-evm to a path dependency would
    // otherwise collapse genuinely different builds into one store namespace.
    let mega_evm = std::fs::read_to_string("../../Cargo.lock")
        .ok()
        .and_then(|lock| mega_evm_rev(&lock))
        .expect(
            "coverage-replayer build: no git revision for `mega-evm` in Cargo.lock. \
             The store namespace (binary_id) is anchored on that rev; if you are \
             deliberately overriding mega-evm with a path dependency, extend build.rs \
             to fingerprint the override instead of building with a broken namespace.",
        );

    // `rustc -vV` includes `release:`, `host:`, and `LLVM version:` lines —
    // the plain `--version` string carries none of those, and both the host
    // triple and the LLVM version can shift counter ids. Fingerprint all
    // three lines.
    let rustc_vv = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("-vV")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .expect("coverage-replayer build: `rustc -vV` failed");
    let toolchain: String = rustc_vv
        .lines()
        .filter(|l| {
            l.starts_with("release:") || l.starts_with("host:") || l.starts_with("LLVM version:")
        })
        .collect::<Vec<_>>()
        .join(";");
    assert!(
        toolchain.contains("host:") && toolchain.contains("release:"),
        "coverage-replayer build: unexpected `rustc -vV` output: {rustc_vv:?}"
    );

    println!("cargo:rustc-env=COVERAGE_MEGA_EVM_REV={mega_evm}");
    println!("cargo:rustc-env=COVERAGE_RUSTC_VERSION={toolchain}");
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
