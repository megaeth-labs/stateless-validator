//! Captures a fingerprint of the coverage-relevant build at compile time.
//!
//! The coverage namespace (counter ids, and the symbols archived profiles are
//! keyed by) is determined by the measured code, the toolchain and the
//! dependency graph, NOT by this binary's orchestration code. Basing the
//! store's `binary_id` on this fingerprint (rather than a whole-exe hash)
//! means editing the dispatcher / adding subcommands does not invalidate an
//! existing store.

use std::process::Command;

/// Runs the rustc cargo builds with (`$RUSTC`) and returns its stdout.
fn rustc(args: &[&str]) -> String {
    Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_else(|| panic!("coverage-replayer build: `rustc {}` failed", args.join(" ")))
}

fn main() {
    let lock = std::fs::read_to_string("../../Cargo.lock")
        .expect("coverage-replayer build: cannot read the workspace Cargo.lock");
    // mega-evm's locked git revision from the workspace lockfile. This is the
    // namespace anchor, so a missing rev is a hard build error rather than a
    // silent fallback: overriding mega-evm to a path dependency would
    // otherwise collapse genuinely different builds into one store namespace.
    let mega_evm = mega_evm_rev(&lock).expect(
        "coverage-replayer build: no git revision for `mega-evm` in Cargo.lock. \
             The store namespace (binary_id) is anchored on that rev; if you are \
             deliberately overriding mega-evm with a path dependency, extend build.rs \
             to fingerprint the override instead of building with a broken namespace.",
    );

    // `rustc -vV` includes `release:`, `host:`, and `LLVM version:` lines —
    // the plain `--version` string carries none of those, and both the host
    // triple and the LLVM version can shift counter ids. Fingerprint all
    // three lines.
    let rustc_vv = rustc(&["-vV"]);
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
    // Sorted, because this list is hashed into `binary_id`: reordering
    // measured-crates.txt must not look like a different instrumented build.
    let mut measured = measured;
    measured.sort();

    // Where the build found its sources and its LLVM. llvm-cov matches the
    // absolute source paths baked into the coverage map, so the default scope
    // is looked up under the cargo home the build used, not under whatever
    // $HOME the binary later runs with; and the LLVM tools that read this
    // binary's profiles are the ones shipped with the toolchain that built it.
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME")
            .expect("coverage-replayer build: neither CARGO_HOME nor HOME is set");
        format!("{home}/.cargo")
    });
    let sysroot = rustc(&["--print", "sysroot"]);
    let sysroot = sysroot.trim();

    println!("cargo:rustc-env=COVERAGE_CARGO_HOME={cargo_home}");
    println!("cargo:rustc-env=COVERAGE_RUSTC_SYSROOT={sysroot}");
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    println!("cargo:rerun-if-env-changed=HOME");
    // The lockfile as a whole. A profile names each instance of the measured
    // generics by its symbol, which carries the cargo metadata of the crate
    // instantiating it — a workspace crate — and that metadata moves with any
    // dependency or version change. Two builds that differ there cannot read
    // each other's profiles, so they must not share a store.
    println!("cargo:rustc-env=COVERAGE_LOCKFILE_DIGEST={:016x}", fnv1a(lock.as_bytes()));
    println!("cargo:rustc-env=COVERAGE_MEGA_EVM_REV={mega_evm}");
    println!("cargo:rustc-env=COVERAGE_MEASURED_CRATES={}", measured.join(","));
    println!("cargo:rerun-if-changed=measured-crates.txt");
    println!("cargo:rustc-env=COVERAGE_RUSTC_VERSION={toolchain}");
    // Re-run if the lockfile changes (mega-evm bump).
    println!("cargo:rerun-if-changed=../../Cargo.lock");
}

/// FNV-1a, 64-bit: a stable digest without a dependency — the standard
/// hasher's algorithm is free to change between releases, and shards built on
/// different machines must agree on it.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3))
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
