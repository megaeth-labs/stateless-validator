//! Captures a fingerprint of the coverage-relevant build at compile time: the measured
//! code, toolchain and dependency graph, NOT this binary's orchestration code, so the
//! store's `binary_id` survives edits to the dispatcher or new subcommands.

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
    // mega-evm's locked git rev anchors the namespace, so a missing one (e.g. a path
    // override) is a build error rather than distinct builds sharing one namespace.
    let mega_evm = mega_evm_rev(&lock).expect(
        "coverage-replayer build: no git revision for `mega-evm` in Cargo.lock. \
             The store namespace (binary_id) is anchored on that rev; if you are \
             deliberately overriding mega-evm with a path dependency, extend build.rs \
             to fingerprint the override instead of building with a broken namespace.",
    );

    // `rustc -vV`, unlike `--version`, carries the host triple and LLVM version, both of
    // which can shift counter ids.
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

    // The measured registry crates as `name-version`, their registry directory name, with
    // versions from the lockfile so the default scope never names one that was not built.
    let mut measured: Vec<String> = std::fs::read_to_string("measured-crates.txt")
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
    // Sorted: this list is hashed into `binary_id`, and reordering the file must not change it.
    measured.sort();

    // Where the build found its sources and its LLVM: the default scope and the LLVM tools
    // are looked up there, not under whatever $HOME the binary later runs with.
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
    // The lockfile as a whole: why it belongs in `binary_id` is on `store::current_binary_id`.
    println!("cargo:rustc-env=COVERAGE_LOCKFILE_DIGEST={:016x}", fnv1a(lock.as_bytes()));
    println!("cargo:rustc-env=COVERAGE_MEGA_EVM_REV={mega_evm}");
    println!("cargo:rustc-env=COVERAGE_MEASURED_CRATES={}", measured.join(","));
    println!("cargo:rerun-if-changed=measured-crates.txt");
    println!("cargo:rustc-env=COVERAGE_RUSTC_VERSION={toolchain}");
    // Re-run when the lockfile changes: the rev, the versions and the digest come from it.
    println!("cargo:rerun-if-changed=../../Cargo.lock");
}

/// FNV-1a, 64-bit: a dependency-free digest that, unlike the standard hasher, cannot change
/// between releases — the same build on two machines must agree on it.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3))
}

/// The full git rev of `mega-evm` in Cargo.lock, from its source line:
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
