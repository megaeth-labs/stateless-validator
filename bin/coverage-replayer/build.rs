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
    let packages = locked_packages(&lock);
    // mega-evm's locked git rev anchors the namespace, so a missing one (e.g. a path
    // override) is a build error rather than distinct builds sharing one namespace.
    let mega_evm = mega_evm_rev(&packages).expect(
        "coverage-replayer build: no git revision for `mega-evm` in Cargo.lock. \
             The store namespace (binary_id) is anchored on that rev; if you are \
             deliberately overriding mega-evm with a path dependency, extend build.rs \
             to fingerprint the override instead of building with a broken namespace.",
    );

    // `rustc -vV`, unlike `--version`, carries the host triple and LLVM version, both of
    // which can shift counter ids. The commit hash too: every nightly of a release cycle
    // shares `release:` and often the LLVM version, yet may map coverage differently.
    let rustc_vv = rustc(&["-vV"]);
    let toolchain: String = rustc_vv
        .lines()
        .filter(|l| {
            ["release:", "commit-hash:", "host:", "LLVM version:"].iter().any(|k| l.starts_with(k))
        })
        .collect::<Vec<_>>()
        .join(";");
    assert!(
        toolchain.contains("host:") && toolchain.contains("release:"),
        "coverage-replayer build: unexpected `rustc -vV` output: {rustc_vv:?}"
    );

    // The default `--source-dir` scope: where the build found mega-evm and every measured crate,
    // from their locked sources, so it never names a version or rev that was not built.
    let measured = std::fs::read_to_string("measured-crates.txt")
        .expect("coverage-replayer build: measured-crates.txt is missing");
    let names = measured.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
    let mut scope: Vec<String> = std::iter::once("mega-evm")
        .chain(names)
        .flat_map(|name| {
            let locked: Vec<&LockedPackage<'_>> =
                packages.iter().filter(|p| p.name == name).collect();
            assert!(
                !locked.is_empty(),
                "coverage-replayer build: measured crate `{name}` is not in Cargo.lock"
            );
            locked.into_iter().map(source_root)
        })
        .collect();
    // Sorted and deduped: crates of one git checkout share its root, and this list is hashed
    // into `binary_id`, so reordering the file must not change it.
    scope.sort();
    scope.dedup();

    // Where the build found its sources and its LLVM: the default scope and the LLVM tools
    // are looked up there, not under whatever $HOME the binary later runs with.
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME")
            .expect("coverage-replayer build: neither CARGO_HOME nor HOME is set");
        format!("{home}/.cargo")
    });
    let sysroot = rustc(&["--print", "sysroot"]);
    let sysroot = sysroot.trim();

    // The store namespace: why each input belongs in it is on `store::BINARY_ID`.
    let scope = scope.join(",");
    let mut fingerprint = Vec::new();
    for part in [mega_evm.as_str(), &toolchain, &scope, &lock] {
        fingerprint.extend_from_slice(part.as_bytes());
        // Never a byte of UTF-8, so no two splits of the inputs hash alike.
        fingerprint.push(0xff);
    }
    let binary_id =
        format!("megaevm:{}:fnv{:016x}", &mega_evm[..mega_evm.len().min(12)], fnv1a(&fingerprint));

    println!("cargo:rustc-env=COVERAGE_CARGO_HOME={cargo_home}");
    println!("cargo:rustc-env=COVERAGE_RUSTC_SYSROOT={sysroot}");
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    println!("cargo:rerun-if-env-changed=HOME");
    println!("cargo:rustc-env=COVERAGE_BINARY_ID={binary_id}");
    println!("cargo:rustc-env=COVERAGE_DEFAULT_SCOPE={scope}");
    println!("cargo:rerun-if-changed=measured-crates.txt");
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

/// One `[[package]]` entry of Cargo.lock.
struct LockedPackage<'a> {
    name: &'a str,
    version: &'a str,
    source: Option<&'a str>,
}

/// Every `[[package]]` entry of Cargo.lock, read field by field rather than by line order.
fn locked_packages(lock: &str) -> Vec<LockedPackage<'_>> {
    lock.split("[[package]]")
        .skip(1)
        .map(|entry| {
            let field = |key: &str| {
                entry.lines().find_map(|line| {
                    let value = line.trim().strip_prefix(key)?.strip_prefix(" = ")?;
                    Some(value.trim_matches('"'))
                })
            };
            LockedPackage {
                name: field("name").unwrap_or_default(),
                version: field("version").unwrap_or_default(),
                source: field("source"),
            }
        })
        .collect()
}

/// Where cargo keeps a locked package's sources, relative to the cargo home, with a `*` for the
/// directory cargo names after the source URL: the registry index for a registry crate
/// (`registry/src/*/revm-handler-20.0.3`), the clone for a git one, whose root is its whole
/// checkout at the locked rev (`git/checkouts/optimism-*/f67d87c`). Only the instrumented
/// crates of a checkout reach the coverage map, so the rest of it adds nothing to the scope.
fn source_root(package: &LockedPackage<'_>) -> String {
    let unsupported = || -> ! {
        panic!(
            "coverage-replayer build: measured crate `{}` has neither a registry nor a git source \
             in Cargo.lock ({:?}), so no default scope can name it; extend build.rs",
            package.name, package.source
        )
    };
    match package.source {
        Some(s) if s.starts_with("registry+") => {
            format!("registry/src/*/{}-{}", package.name, package.version)
        }
        Some(s) if s.starts_with("git+") => {
            // `git+https://host/org/<repo>[.git]?rev=..#<commit>`: cargo names the clone after
            // `<repo>` and the checkout after the commit's first 7 hex digits.
            let Some((url, commit)) = s.rsplit_once('#') else { unsupported() };
            let repo = url.split(['?', '#']).next().unwrap_or(url).trim_end_matches('/');
            let repo = repo.rsplit('/').next().unwrap_or(repo).trim_end_matches(".git");
            format!("git/checkouts/{repo}-*/{}", &commit[..commit.len().min(7)])
        }
        _ => unsupported(),
    }
}

/// The full git rev of `mega-evm`, from its source:
/// `git+https://github.com/megaeth-labs/mega-evm.git?tag=vX#<rev>`.
fn mega_evm_rev(packages: &[LockedPackage<'_>]) -> Option<String> {
    packages.iter().filter(|p| p.name == "mega-evm").find_map(|p| {
        let (repo, rev) = p.source?.rsplit_once('#')?;
        repo.contains("mega-evm.git").then(|| rev.to_string())
    })
}
