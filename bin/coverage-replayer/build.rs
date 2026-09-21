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

    // The registry crates measured next to mega-evm, as `name-version` — the
    // name of their directory under the cargo registry, which is where
    // llvm-cov will look for their sources. Versions come from the lockfile,
    // so the default scope can never name a version the binary was not built
    // against.
    let lock = std::fs::read_to_string("../../Cargo.lock").unwrap_or_default();
    let measured: Vec<String> = std::fs::read_to_string("measured-crates.txt")
        .expect("coverage-replayer build: measured-crates.txt is missing")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .flat_map(|name| {
            let versions = locked_versions(&lock, name);
            assert!(
                !versions.is_empty(),
                "coverage-replayer build: measured crate `{name}` is not in Cargo.lock"
            );
            versions.into_iter().map(move |v| format!("{name}-{v}"))
        })
        .collect();

    println!("cargo:rustc-env=COVERAGE_MEGA_EVM_REV={mega_evm}");
    println!("cargo:rustc-env=COVERAGE_MEASURED_CRATES={}", measured.join(","));
    println!("cargo:rerun-if-changed=measured-crates.txt");
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

/// Every locked version of the registry package `name` (normally one).
fn locked_versions(lock: &str, name: &str) -> Vec<String> {
    let mut versions = Vec::new();
    let mut lines = lock.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if line == format!("name = \"{name}\"") &&
            let Some(version) = lines.next().and_then(|l| l.strip_prefix("version = "))
        {
            versions.push(version.trim_matches('"').to_string());
        }
    }
    versions
}
