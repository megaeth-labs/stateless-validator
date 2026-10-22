//! Cargo.lock reading for build.rs, which `#[path]`-includes this file; the crate's tests
//! include it too, as a build script cannot have tests of its own.

use std::collections::HashMap;

/// One `[[package]]` entry of Cargo.lock.
pub struct LockedPackage<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub source: Option<&'a str>,
    /// The entry's dependency specs: `name`, `name version` or `name version (source)`, each
    /// as specific as Cargo needs to tell it from other locked packages of that name.
    pub dependencies: Vec<&'a str>,
    /// The entry as written, which pins everything the lockfile says about the package.
    pub entry: &'a str,
}

/// Every `[[package]]` entry of Cargo.lock, read field by field rather than by line order.
pub fn locked_packages(lock: &str) -> Vec<LockedPackage<'_>> {
    lock.split("[[package]]")
        .skip(1)
        .map(|entry| {
            let entry = entry.trim();
            let field = |key: &str| {
                entry.lines().find_map(|line| {
                    let value = line.trim().strip_prefix(key)?.strip_prefix(" = ")?;
                    Some(value.trim_matches('"'))
                })
            };
            let dependencies = entry
                .split_once("dependencies = [")
                .and_then(|(_, list)| list.split(']').next())
                .map(|list| {
                    list.lines()
                        .map(|line| line.trim().trim_end_matches(',').trim_matches('"'))
                        .filter(|spec| !spec.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            LockedPackage {
                name: field("name").unwrap_or_default(),
                version: field("version").unwrap_or_default(),
                source: field("source"),
                dependencies,
                entry,
            }
        })
        .collect()
}

/// The packages a build of `root` (a workspace member's binary) compiles, itself included, in
/// lockfile order, so versions and entries outside it (another member's dependencies) cannot
/// reach its namespace. Cargo.lock lists a member's dev-dependencies with the rest, so a
/// member's `dev_only` names (see [`dev_only_dependencies`]) are not followed. Optional
/// dependencies are, whatever the features: the lockfile does not say which are enabled.
pub fn closure<'a>(
    packages: &'a [LockedPackage<'a>],
    root: &str,
    dev_only: &HashMap<String, Vec<String>>,
) -> Vec<&'a LockedPackage<'a>> {
    let start = packages
        .iter()
        .position(|p| p.name == root && p.source.is_none())
        .unwrap_or_else(|| panic!("coverage-replayer build: `{root}` is not in Cargo.lock"));
    let mut reached = vec![false; packages.len()];
    let mut stack = vec![start];
    reached[start] = true;
    while let Some(i) = stack.pop() {
        let package = &packages[i];
        let skipped = package.source.is_none().then(|| dev_only.get(package.name)).flatten();
        for spec in &package.dependencies {
            let name = spec.split(' ').next().unwrap_or(spec);
            if skipped.is_some_and(|dev| dev.iter().any(|d| d == name)) {
                continue;
            }
            let dep = resolve(packages, spec);
            if !reached[dep] {
                reached[dep] = true;
                stack.push(dep);
            }
        }
    }
    packages.iter().zip(reached).filter(|(_, reached)| *reached).map(|(p, _)| p).collect()
}

/// The package names a manifest declares only as dev-dependencies (of any target): those a
/// build of the package's library or binaries never compiles.
pub fn dev_only_dependencies(manifest: &str) -> Vec<String> {
    let (mut dev, mut other) = (Vec::new(), Vec::new());
    // In a dependency list (`[dependencies]`, `[target.'cfg(..)'.dev-dependencies]`, ..):
    // whether it is the dev one. In one dependency's own table (`[dependencies.foo]`): which
    // list holds it and where, so its `package = ".."` key can rename it.
    let (mut list, mut own_table): (Option<bool>, Option<(bool, usize)>) = (None, None);
    for line in manifest.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix('[') {
            (list, own_table) = (None, None);
            let segments: Vec<&str> = header
                .trim_end_matches(']')
                .split('.')
                .map(|segment| segment.trim().trim_matches(['"', '\'']))
                .collect();
            if let Some(at) = segments.iter().position(|s| s.ends_with("dependencies")) {
                let is_dev = segments[at] == "dev-dependencies";
                match segments.get(at + 1) {
                    Some(name) => {
                        let names = if is_dev { &mut dev } else { &mut other };
                        names.push(name.to_string());
                        own_table = Some((is_dev, names.len() - 1));
                    }
                    None => list = Some(is_dev),
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let quoted = |value: &str| value.trim().trim_matches('"').to_string();
        if let Some((is_dev, at)) = own_table {
            if key.trim() == "package" {
                (if is_dev { &mut dev } else { &mut other })[at] = quoted(value);
            }
            continue;
        }
        let Some(is_dev) = list else { continue };
        // `name = ..`, `name.workspace = true`, or a rename through `package = "name"`.
        let renamed = value.split_once("package = \"").and_then(|(_, rest)| rest.split('"').next());
        let name =
            renamed.unwrap_or_else(|| key.trim().split('.').next().unwrap_or("")).to_string();
        (if is_dev { &mut dev } else { &mut other }).push(name);
    }
    dev.retain(|name| !other.contains(name));
    dev
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("coverage-replayer build: read {}: {e}", path.display()))
}

/// The workspace members' manifests under `root` (the directory of the workspace
/// `Cargo.toml`), as listed in its `members`.
pub fn workspace_manifests(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let workspace = read(&root.join("Cargo.toml"));
    let members = workspace
        .split_once("members = [")
        .and_then(|(_, list)| list.split(']').next())
        .expect("coverage-replayer build: the workspace Cargo.toml lists no members");
    members
        .split(',')
        .map(|member| member.trim().trim_matches('"'))
        .filter(|member| !member.is_empty())
        .map(|member| root.join(member).join("Cargo.toml"))
        .collect()
}

/// Each workspace member's package name and dev-only dependencies.
pub fn workspace_dev_only(root: &std::path::Path) -> HashMap<String, Vec<String>> {
    workspace_manifests(root)
        .into_iter()
        .map(|path| {
            let manifest = read(&path);
            let name = manifest
                .lines()
                .find_map(|line| line.trim().strip_prefix("name = "))
                .map(|name| name.trim_matches('"').to_string())
                .unwrap_or_else(|| {
                    panic!("coverage-replayer build: {} has no package name", path.display())
                });
            (name, dev_only_dependencies(&manifest))
        })
        .collect()
}

/// The one locked package a dependency spec names.
fn resolve(packages: &[LockedPackage<'_>], spec: &str) -> usize {
    let (spec_name, source) = match spec.split_once(" (") {
        Some((head, source)) => (head, Some(source.trim_end_matches(')'))),
        None => (spec, None),
    };
    let (name, version) =
        spec_name.split_once(' ').map_or((spec_name, None), |(n, v)| (n, Some(v)));
    // A spec's source leaves out the `#<commit>` a git package's own source ends in.
    let unpinned = |source: &str| source.split('#').next().unwrap_or(source).to_owned();
    let mut matching = packages.iter().enumerate().filter(|(_, p)| {
        p.name == name &&
            version.is_none_or(|v| p.version == v) &&
            source.is_none_or(|s| p.source.is_some_and(|own| unpinned(own) == unpinned(s)))
    });
    match (matching.next(), matching.next()) {
        (Some((i, _)), None) => i,
        _ => panic!(
            "coverage-replayer build: Cargo.lock dependency `{spec}` names no single package"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
version = 4

[[package]]
name = "coverage-replayer"
version = "1.0.0"
dependencies = [
 "revm-handler 2.0.0",
 "shared",
]

[[package]]
name = "other-bin"
version = "1.0.0"
dependencies = [
 "revm-handler 1.0.0",
 "shared",
]

[[package]]
name = "revm-handler"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "revm-handler"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "op-revm 3.0.0 (git+https://github.com/org/optimism?rev=abc)",
]

[[package]]
name = "op-revm"
version = "3.0.0"
source = "git+https://github.com/org/optimism?rev=abc#abcdef0123456789"

[[package]]
name = "op-revm"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "shared"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    fn no_dev_only() -> HashMap<String, Vec<String>> {
        HashMap::new()
    }

    fn names(packages: &[&LockedPackage<'_>]) -> Vec<String> {
        packages.iter().map(|p| format!("{} {} {:?}", p.name, p.version, p.source)).collect()
    }

    /// The closure follows version- and source-qualified specs to the one package each names,
    /// and leaves out what only another member depends on.
    #[test]
    fn closure_holds_exactly_what_the_root_depends_on() {
        let packages = locked_packages(LOCK);
        let reached = closure(&packages, "coverage-replayer", &no_dev_only());
        let git = Some("git+https://github.com/org/optimism?rev=abc#abcdef0123456789");
        assert_eq!(
            names(&reached),
            [
                "coverage-replayer 1.0.0 None".to_string(),
                "revm-handler 2.0.0 Some(\"registry+https://github.com/rust-lang/crates.io-index\")"
                    .into(),
                format!("op-revm 3.0.0 {git:?}"),
                "shared 0.1.0 Some(\"registry+https://github.com/rust-lang/crates.io-index\")"
                    .into(),
            ]
        );
    }

    /// A member's dev-only dependencies are not followed, from the root or any other member;
    /// one also declared as a normal dependency is.
    #[test]
    fn a_members_dev_only_dependencies_are_not_followed() {
        let manifest = "[package]\nname = \"coverage-replayer\"\n\n[dependencies]\n\
            revm-handler.workspace = true\nboth = \"1\"\n\n[dev-dependencies]\n\
            shared = { path = \"../shared\" }\nboth = \"1\"\n\
            renamed = { package = \"tester\", version = \"1\" }\n";
        assert_eq!(dev_only_dependencies(manifest), ["shared", "tester"]);
        // A dependency's own table counts like a line; its `package` key renames it.
        let dotted = "[dependencies.both]\nversion = \"1\"\n[target.'cfg(unix)'.dev-dependencies]\n\
            both = \"1\"\n[dev-dependencies.alias]\nversion = \"1\"\npackage = \"tester\"\n";
        assert_eq!(dev_only_dependencies(dotted), ["tester"]);

        let packages = locked_packages(LOCK);
        let dev_only =
            HashMap::from([("coverage-replayer".to_string(), vec!["shared".to_string()])]);
        let reached = names(&closure(&packages, "coverage-replayer", &dev_only));
        assert!(!reached.iter().any(|p| p.starts_with("shared ")), "{reached:?}");
        assert!(reached.iter().any(|p| p.starts_with("op-revm ")), "{reached:?}");
    }

    /// The real lockfile: coverage-replayer's closure holds every measured crate, and neither
    /// another binary nor a member's test-only stack.
    #[test]
    fn the_workspace_closure_holds_the_measured_crates_and_not_test_stacks() {
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
        let packages = locked_packages(&lock);
        let reached = closure(&packages, "coverage-replayer", &workspace_dev_only(root));
        let has = |name: &str| reached.iter().any(|p| p.name == name);
        for measured in
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/measured-crates.txt"))
                .unwrap()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            assert!(has(measured), "measured crate {measured} is not in the closure");
        }
        assert!(has("mega-evm") && has("stateless-common"));
        for absent in
            ["debug-trace-server", "stateless-validator", "stateless-test-utils", "jsonrpsee"]
        {
            assert!(!has(absent), "{absent} is not compiled into coverage-replayer");
        }
    }
}
