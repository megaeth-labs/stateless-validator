//! Cargo's git checkout layout, `#[path]`-included by build.rs (which bakes a crate's directory
//! into the default scope) and by the binary (which resolves that scope at run time), so the
//! two sides of one layout rule cannot drift.

use std::path::{Path, PathBuf};

/// The commit abbreviation a default scope names a checkout by: git's minimum, which cargo's
/// own checkout names start with.
pub const ABBREV_LEN: usize = 7;

/// The entries of `dir`; none if it cannot be read.
pub fn entries(dir: &Path) -> impl Iterator<Item = std::fs::DirEntry> + use<> {
    std::fs::read_dir(dir).into_iter().flatten().flatten()
}

/// The checkouts under `clones` (a cargo home's `git/checkouts`) of the clones whose directory
/// starts with `clone_prefix` (cargo names a clone `<repo>-<hash>`), at a commit abbreviated to
/// `abbrev` or further: cargo names a checkout with git's shortest unambiguous abbreviation,
/// which `core.abbrev` or a clashing prefix lengthens. Sorted, so every machine sees one order.
pub fn abbreviated_checkouts(clones: &Path, clone_prefix: &str, abbrev: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = entries(clones)
        .filter(|clone| clone.file_name().to_string_lossy().starts_with(clone_prefix))
        .flat_map(|clone| entries(&clone.path()))
        .filter(|checkout| checkout.file_name().to_string_lossy().starts_with(abbrev))
        .map(|checkout| checkout.path())
        .filter(|checkout| checkout.is_dir())
        .collect();
    found.sort();
    found
}

/// Every directory under `checkout` whose `Cargo.toml` declares package `name`, relative to it
/// and sorted (`.git`, `target` and `node_modules` are not entered).
#[allow(dead_code, reason = "build.rs's: the binary only resolves what build.rs found")]
pub fn crate_dirs_in(checkout: &Path, name: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let dir = checkout.join(&relative);
        if std::fs::read_to_string(dir.join("Cargo.toml"))
            .is_ok_and(|manifest| package_name(&manifest) == Some(name))
        {
            found.push(relative.clone());
        }
        for entry in entries(&dir) {
            let skip =
                matches!(entry.file_name().to_str(), Some(".git" | "target" | "node_modules"));
            if !skip && entry.file_type().is_ok_and(|t| t.is_dir()) {
                pending.push(relative.join(entry.file_name()));
            }
        }
    }
    found.sort();
    found
}

/// The name a manifest's `[package]` table gives, however the line is spaced.
pub fn package_name(manifest: &str) -> Option<&str> {
    let mut in_package = false;
    manifest.lines().map(str::trim).find_map(|line| {
        if line.starts_with('[') {
            in_package = line.trim_matches(['[', ']']).trim() == "package";
            return None;
        }
        let (key, value) = line.split_once('=').filter(|_| in_package)?;
        (key.trim() == "name").then(|| value.trim().trim_matches('"'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(root: &Path, paths: &[&str]) {
        for path in paths {
            std::fs::create_dir_all(root.join(path)).unwrap();
        }
    }

    /// Checkouts are matched by clone prefix and abbreviation, longer abbreviations included,
    /// and returned sorted.
    #[test]
    fn abbreviated_checkouts_match_by_clone_and_commit() {
        let clones = tempfile::tempdir().unwrap();
        dirs(
            clones.path(),
            &[
                "optimism-b/f67d87cd5c99",
                "optimism-a/f67d87c",
                "optimism-a/0000000",
                "mega-evm-c/f67d87c",
            ],
        );
        let found = abbreviated_checkouts(clones.path(), "optimism-", "f67d87c");
        let expected =
            ["optimism-a/f67d87c", "optimism-b/f67d87cd5c99"].map(|p| clones.path().join(p));
        assert_eq!(found, expected);
    }

    /// A crate is found by its `[package]` name, however spaced, at any depth and at the root,
    /// and every declaring directory is reported; skipped directories are never entered.
    #[test]
    fn crate_dirs_are_found_by_package_name() {
        let checkout = tempfile::tempdir().unwrap();
        let manifest = |dir: &str, text: &str| {
            std::fs::create_dir_all(checkout.path().join(dir)).unwrap();
            std::fs::write(checkout.path().join(dir).join("Cargo.toml"), text).unwrap();
        };
        manifest("rust/op-revm", "[package]\nname  =  \"op-revm\"\nversion = \"1\"\n");
        manifest("rust/other", "[package]\nname = \"other\"\n[dependencies]\nop-revm = \"1\"\n");
        manifest("target/op-revm", "[package]\nname = \"op-revm\"\n");
        manifest(".git/op-revm", "[package]\nname = \"op-revm\"\n");

        assert_eq!(crate_dirs_in(checkout.path(), "op-revm"), [PathBuf::from("rust/op-revm")]);
        manifest("vendor/op-revm", "[package]\nname = \"op-revm\"\n");
        assert_eq!(
            crate_dirs_in(checkout.path(), "op-revm"),
            [PathBuf::from("rust/op-revm"), PathBuf::from("vendor/op-revm")]
        );
        manifest("", "[package]\nname = \"root-crate\"\n");
        assert_eq!(crate_dirs_in(checkout.path(), "root-crate"), [PathBuf::new()]);
        assert!(crate_dirs_in(checkout.path(), "absent").is_empty());
    }
}
