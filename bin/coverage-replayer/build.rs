//! Captures a fingerprint of the coverage-relevant build at compile time: the measured
//! code, toolchain and dependency graph, NOT this binary's orchestration code, so the
//! store's `binary_id` survives edits to the dispatcher or new subcommands.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

#[path = "build/lockfile.rs"]
mod lockfile;

use lockfile::LockedPackage;

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
    let packages = lockfile::locked_packages(&lock);
    // What this binary compiles: only these packages' versions, sources and dependency edges
    // reach the scope and the namespace, so another member's dependency bump changes neither.
    let compiled = lockfile::closure(
        &packages,
        "coverage-replayer",
        &lockfile::workspace_dev_only(Path::new("../..")),
    );
    // mega-evm's locked git rev anchors the namespace, so a missing one (e.g. a path
    // override) is a build error rather than distinct builds sharing one namespace.
    let mega_evm = mega_evm_rev(&compiled).expect(
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

    // Where the build found its sources and its LLVM: the default scope and the LLVM tools
    // are looked up there, not under whatever $HOME the binary later runs with.
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME")
            .expect("coverage-replayer build: neither CARGO_HOME nor HOME is set");
        format!("{home}/.cargo")
    });

    // The default `--source-dir` scope: where the build found mega-evm (its whole checkout,
    // which the wrapper instruments) and every measured crate (its own directory), from their
    // locked sources, so it never names a version or rev that was not built.
    let measured = std::fs::read_to_string("measured-crates.txt")
        .expect("coverage-replayer build: measured-crates.txt is missing");
    let names = measured.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
    let mut scope: Vec<String> = std::iter::once("mega-evm")
        .chain(names)
        .flat_map(|name| {
            let locked: Vec<&&LockedPackage<'_>> =
                compiled.iter().filter(|p| p.name == name).collect();
            assert!(
                !locked.is_empty(),
                "coverage-replayer build: measured crate `{name}` is not a dependency of \
                 coverage-replayer in Cargo.lock"
            );
            let whole_checkout = name == "mega-evm";
            let cargo_home = Path::new(&cargo_home);
            locked.into_iter().map(move |p| source_root(p, cargo_home, whole_checkout))
        })
        .collect();
    // Sorted and deduped: this list is hashed into `binary_id`, and reordering the file must
    // not change it.
    scope.sort();
    scope.dedup();
    let sysroot = rustc(&["--print", "sysroot"]);
    let sysroot = sysroot.trim();

    // The store namespace: why each input belongs in it is on `store::BINARY_ID`.
    let scope = scope.join(",");
    let locked: Vec<&str> = compiled.iter().map(|p| p.entry).collect();
    let locked = locked.join("\n");
    let mut fingerprint = Vec::new();
    for part in [mega_evm.as_str(), &toolchain, &scope, &locked] {
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
    // Re-run when the lockfile or a member's dependencies change: the rev, the versions and
    // the dependency closure come from them.
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    for manifest in lockfile::workspace_manifests(Path::new("../..")) {
        println!("cargo:rerun-if-changed={}", manifest.display());
    }
}

/// FNV-1a, 64-bit: a dependency-free digest that, unlike the standard hasher, cannot change
/// between releases — the same build on two machines must agree on it.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3))
}

/// Where cargo keeps a locked package's sources, relative to the cargo home, with a `*` for the
/// directory cargo names after the source URL: the registry index for a registry crate
/// (`registry/src/*/revm-handler-20.0.3`), the clone for a git one, then the checkout at the
/// locked rev and the crate's directory inside it (`git/checkouts/optimism-*/f67d87c/rust/
/// op-revm`), or the `whole_checkout`. A crate's own directory spares llvm-cov walking every
/// file of a monorepo on each export; if the build cannot find it, the checkout still scopes
/// it correctly, as only instrumented crates reach the coverage map.
fn source_root(package: &LockedPackage<'_>, cargo_home: &Path, whole_checkout: bool) -> String {
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
            let checkout = format!("git/checkouts/{repo}-*/{}", &commit[..commit.len().min(7)]);
            if whole_checkout {
                return checkout;
            }
            match crate_dir_in_checkouts(
                cargo_home,
                repo,
                &commit[..commit.len().min(7)],
                package.name,
            ) {
                Some(dir) if dir.as_os_str().is_empty() => checkout,
                Some(dir) => format!("{checkout}/{}", dir.display()),
                None => {
                    println!(
                        "cargo:warning=coverage-replayer: no `{}` crate found in its {repo} \
                         checkout; scoping it by the whole checkout",
                        package.name
                    );
                    checkout
                }
            }
        }
        _ => unsupported(),
    }
}

/// The directory of crate `name` inside a checkout of `repo` at a commit cargo abbreviated to
/// (at least) `abbrev`, relative to the checkout; `None` if no checkout or no crate is found.
fn crate_dir_in_checkouts(
    cargo_home: &Path,
    repo: &str,
    abbrev: &str,
    name: &str,
) -> Option<PathBuf> {
    let entries = |dir: &Path| std::fs::read_dir(dir).into_iter().flatten().flatten();
    entries(&cargo_home.join("git").join("checkouts"))
        .filter(|clone| clone.file_name().to_string_lossy().starts_with(&format!("{repo}-")))
        .flat_map(|clone| entries(&clone.path()).collect::<Vec<_>>())
        .filter(|checkout| checkout.file_name().to_string_lossy().starts_with(abbrev))
        .find_map(|checkout| crate_dir_in(&checkout.path(), name))
}

/// The directory under `checkout` whose `Cargo.toml` declares package `name`, relative to it.
fn crate_dir_in(checkout: &Path, name: &str) -> Option<PathBuf> {
    let declares = |manifest: &Path| {
        let Ok(text) = std::fs::read_to_string(manifest) else { return false };
        let mut in_package = false;
        text.lines().map(str::trim).any(|line| {
            if line.starts_with('[') {
                in_package = line == "[package]";
                return false;
            }
            in_package && line == format!("name = \"{name}\"")
        })
    };
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let dir = checkout.join(&relative);
        if declares(&dir.join("Cargo.toml")) {
            return Some(relative);
        }
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let skip =
                matches!(entry.file_name().to_str(), Some(".git" | "target" | "node_modules"));
            if !skip && entry.file_type().is_ok_and(|t| t.is_dir()) {
                pending.push(relative.join(entry.file_name()));
            }
        }
    }
    None
}

/// The full git rev of `mega-evm`, from its source:
/// `git+https://github.com/megaeth-labs/mega-evm.git?tag=vX#<rev>`.
fn mega_evm_rev(packages: &[&LockedPackage<'_>]) -> Option<String> {
    packages.iter().filter(|p| p.name == "mega-evm").find_map(|p| {
        let (repo, rev) = p.source?.rsplit_once('#')?;
        repo.contains("mega-evm.git").then(|| rev.to_string())
    })
}
