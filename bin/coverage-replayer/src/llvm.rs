//! LLVM tool discovery and `.profraw` → covered-item extraction.
//!
//! A coverage "counter" in this tool is an *evaluated* coverage item — a
//! region entry or one arm of a branch, as `llvm-cov` computes it — and NOT a
//! physical instrumentation counter. The distinction is load-bearing: rustc
//! minimizes physical counters, so an `if`/`else` gets two of them (entry,
//! then-arm) and the else-arm exists only as the expression `entry - then`.
//! Over physical counters a block that takes only the else-arm shows
//! `{entry}`, a strict subset of a then-only block's `{entry, then}`: it looks
//! dominated, its profile is never archived, set-cover prunes it, and the
//! "minimal" set silently loses a branch arm the scan had covered. No
//! `-Z coverage-options` value turns that minimization off.
//!
//! So every block's profile goes through `llvm-cov export`, which evaluates
//! the counter expressions against the binary's coverage map, and the items
//! are read from its JSON: region-entry segments and branch arms with a
//! non-zero count, keyed by source location. That is the same arithmetic
//! `report` runs, so "covers every item ever observed" means what the report
//! measures. The export is scoped to source directories — both because those
//! define the universe, and because an unscoped export of this binary
//! crashes llvm-cov (instantiation-group handling in some dependency files).
//!
//! The default scope is the mega-evm checkout plus revm's execution engine
//! (`measured-crates.txt`). mega-evm shapes execution *through* revm — its
//! host and handler are type arguments of revm's generic interpreter — so
//! which EVM paths mainnet exercises is a fact about revm's source as much as
//! mega-evm's. Scoping by directory is also what keeps the rest out: a filter
//! on symbol names cannot, because a mangled name carries its generic
//! arguments and its instantiating crate, and under one such filter more than
//! a third of the universe turned out to be k256, generic-array and friends.

use std::{
    hash::Hasher,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{Context, Result, ensure};
use rustc_hash::FxHasher;

/// Version tag of the item definition below, stamped into every store (see
/// [`universe_stamp`]). Bump it whenever the id or the set of item kinds
/// changes: ids from two definitions must never share a store.
const ITEM_UNIVERSE: &str = "regions+branch-arms/v2";

/// What a covered item is, for the provenance columns of the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// A region-entry segment with a non-zero evaluated count.
    Region,
    /// The true arm of a branch region was taken.
    BranchTrue,
    /// The false arm of a branch region was taken.
    BranchFalse,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Region => "region",
            Self::BranchTrue => "branch-true",
            Self::BranchFalse => "branch-false",
        }
    }
}

/// A covered item observed in one profile, with its stable id.
#[derive(Debug, Clone)]
pub struct CoveredItem {
    pub id: u64,
    /// `<source dir name>/<path inside it>:<line>:<col>`.
    pub location: String,
    pub kind: ItemKind,
    pub line: u32,
}

/// Stable 64-bit id of a covered item. FxHasher is seed-free and
/// deterministic across processes and machines. `scoped_path` is the source
/// dir's own name followed by the path inside it (`revm-handler-8.1.0/src/
/// lib.rs`): the name keeps two scoped crates' `src/lib.rs` apart, and leaving
/// out everything above it keeps the id independent of where a checkout or
/// registry lives.
fn item_id(kind: ItemKind, scoped_path: &str, span: [u32; 4]) -> u64 {
    let mut h = FxHasher::default();
    h.write(kind.as_str().as_bytes());
    h.write_u8(0xff);
    h.write(scoped_path.as_bytes());
    h.write_u8(0xff);
    for v in span {
        h.write_u32(v);
    }
    h.finish()
}

/// The universe stamp a store is namespaced by, next to `binary_id`: the item
/// definition plus the source scope. Two runs whose stamps differ would fill
/// one store with ids from different universes.
pub fn universe_stamp(source_dirs: &[PathBuf]) -> String {
    let mut dirs: Vec<String> = source_dirs.iter().map(|d| d.display().to_string()).collect();
    dirs.sort();
    format!("{ITEM_UNIVERSE}:{}", dirs.join(","))
}

/// Resolves the source scope: the explicit `--source-dir`s, or the default —
/// the mega-evm checkout this binary was built against plus the measured
/// registry crates at their locked versions. Every directory must exist —
/// llvm-cov collects the files under it from disk, and a scope that matches
/// nothing would turn every block into an empty bitmap.
pub fn resolve_source_dirs(explicit: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let dirs = if explicit.is_empty() {
        let mut dirs = vec![detect_mega_evm_checkout().ok_or_else(|| {
            eyre::eyre!(
                "could not find the mega-evm checkout for the built-against rev under \
                 $HOME/.cargo/git/checkouts (note that sudo changes $HOME); pass --source-dir"
            )
        })?];
        for krate in env!("COVERAGE_MEASURED_CRATES").split(',').filter(|c| !c.is_empty()) {
            dirs.push(detect_registry_crate(krate).ok_or_else(|| {
                eyre::eyre!(
                    "could not find the sources of {krate} under $HOME/.cargo/registry/src \
                     (note that sudo changes $HOME); pass every --source-dir explicitly"
                )
            })?);
        }
        dirs
    } else {
        explicit.to_vec()
    };
    for dir in &dirs {
        ensure!(dir.is_dir(), "source dir {} does not exist", dir.display());
    }
    Ok(dirs)
}

/// Finds `<name>-<version>` under the cargo registry's unpacked sources (the
/// directory above it is named after the index, which is not ours to guess).
fn detect_registry_crate(name_version: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let src = PathBuf::from(home).join(".cargo").join("registry").join("src");
    std::fs::read_dir(src)
        .ok()?
        .flatten()
        .map(|index| index.path().join(name_version))
        .find(|candidate| candidate.is_dir())
}

/// Finds the cargo git checkout of the mega-evm rev this binary was BUILT
/// against (embedded by build.rs) — no runtime Cargo.lock parsing, no cwd
/// dependence, and the rev can never disagree with the instrumented build.
pub fn detect_mega_evm_checkout() -> Option<PathBuf> {
    let rev: String = env!("COVERAGE_MEGA_EVM_REV").chars().take(7).collect();
    if rev.len() != 7 {
        return None;
    }
    let home = std::env::var_os("HOME")?;
    let checkouts = PathBuf::from(home).join(".cargo").join("git").join("checkouts");
    for entry in std::fs::read_dir(checkouts).ok()?.flatten() {
        if entry.file_name().to_string_lossy().starts_with("mega-evm-") {
            let candidate = entry.path().join(&rev);
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Locates an LLVM tool: explicit override → rustc sysroot → `$PATH`.
pub fn find_tool(name: &str, cli_override: Option<&str>) -> Result<PathBuf> {
    if let Some(p) = cli_override {
        let p = PathBuf::from(p);
        ensure!(p.exists(), "{name} override does not exist: {}", p.display());
        return Ok(p);
    }

    // rustc --print sysroot → <sysroot>/lib/rustlib/<triple>/bin/<tool>
    if let Ok(out) = Command::new("rustc").args(["--print", "sysroot"]).output() &&
        out.status.success()
    {
        let sysroot = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        let rustlib = sysroot.join("lib").join("rustlib");
        if let Ok(entries) = std::fs::read_dir(&rustlib) {
            for entry in entries.flatten() {
                let candidate = entry.path().join("bin").join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }

    // PATH fallback
    if let Ok(out) = Command::new("which").arg(name).output() &&
        out.status.success()
    {
        let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        if p.is_file() {
            return Ok(p);
        }
    }

    eyre::bail!(
        "{name} not found. Install the `llvm-tools` rustup component or pass an explicit path."
    )
}

/// Turns one block's profraw into its covered items, leaving the sparse
/// profdata next to it (returned) for the judge to archive.
///
/// `llvm-profdata merge -sparse` drops every zero-count function, which is
/// almost all of them for a single block; `llvm-cov export` then evaluates
/// the counter expressions of what is left. `exe` must be the instrumented
/// binary that wrote the profraw — its coverage map is what gives the
/// counters their meaning.
pub fn extract_covered_items(
    llvm_profdata: &Path,
    llvm_cov: &Path,
    exe: &Path,
    profraw: &Path,
    source_dirs: &[PathBuf],
) -> Result<(Vec<CoveredItem>, PathBuf)> {
    let profdata = profraw.with_extension("profdata");
    let out = Command::new(llvm_profdata)
        .arg("merge")
        .arg("-sparse")
        .arg(profraw)
        .arg("-o")
        .arg(&profdata)
        .output()
        .wrap_err("spawn llvm-profdata")?;
    ensure!(
        out.status.success(),
        "llvm-profdata merge -sparse failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(llvm_cov)
        .arg("export")
        .arg(exe)
        .arg(format!("--instr-profile={}", profdata.display()))
        .arg("--format=text")
        // The per-function records are most of the output and carry nothing
        // the file-level segments and branches do not.
        .arg("--skip-functions")
        .args(source_dirs)
        .output()
        .wrap_err("spawn llvm-cov")?;
    ensure!(
        out.status.success(),
        "llvm-cov export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let items = parse_export(&String::from_utf8_lossy(&out.stdout), source_dirs)?;
    Ok((items, profdata))
}

/// Parses `llvm-cov export --format=text --skip-functions` output.
///
/// Per file: `segments` are `[line, col, count, has_count, is_region_entry,
/// is_gap]` and `branches` are `[line, col, end_line, end_col, true_count,
/// false_count, ...]`. A generic function contributes one branch record per
/// instantiation at the same source span; the arms are OR-ed across them,
/// because the item is "this source arm was taken", not which instantiation
/// took it.
pub fn parse_export(json: &str, source_dirs: &[PathBuf]) -> Result<Vec<CoveredItem>> {
    let root: serde_json::Value = serde_json::from_str(json).wrap_err("parse llvm-cov export")?;
    let files = root["data"][0]["files"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("llvm-cov export has no data[0].files"))?;
    // A scope that matches nothing in the coverage map is a configuration
    // error, not an empty block: llvm-cov matches the absolute paths baked in
    // at BUILD time, so the sources must sit where they sat for the build.
    ensure!(
        !files.is_empty(),
        "llvm-cov export matched no source file under {source_dirs:?} — the sources must be at \
         the path the instrumented binary was built against"
    );

    let nonzero = |v: &serde_json::Value| {
        v.as_u64().is_some_and(|n| n > 0) || v.as_f64().is_some_and(|n| n > 0.0)
    };
    let coord = |v: &serde_json::Value| v.as_u64().unwrap_or(0) as u32;

    let mut items = Vec::new();
    for file in files {
        let filename = file["filename"].as_str().unwrap_or_default();
        let rel = source_dirs
            .iter()
            .find_map(|dir| {
                let inside = Path::new(filename).strip_prefix(dir).ok()?;
                Some(Path::new(dir.file_name()?).join(inside).display().to_string())
            })
            .unwrap_or_else(|| filename.to_string());

        let mut push = |kind: ItemKind, span: [u32; 4]| {
            items.push(CoveredItem {
                id: item_id(kind, &rel, span),
                location: format!("{rel}:{}:{}", span[0], span[1]),
                kind,
                line: span[0],
            });
        };

        for seg in file["segments"].as_array().into_iter().flatten() {
            let (has_count, is_entry, is_gap) = (
                seg[3].as_bool().unwrap_or(false),
                seg[4].as_bool().unwrap_or(false),
                seg[5].as_bool().unwrap_or(false),
            );
            if has_count && is_entry && !is_gap && nonzero(&seg[2]) {
                push(ItemKind::Region, [coord(&seg[0]), coord(&seg[1]), 0, 0]);
            }
        }
        for br in file["branches"].as_array().into_iter().flatten() {
            let span = [coord(&br[0]), coord(&br[1]), coord(&br[2]), coord(&br[3])];
            if nonzero(&br[4]) {
                push(ItemKind::BranchTrue, span);
            }
            if nonzero(&br[5]) {
                push(ItemKind::BranchFalse, span);
            }
        }
    }
    items.sort_by_key(|i| i.id);
    items.dedup_by_key(|i| i.id);
    Ok(items)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    // Real `llvm-cov export` output (LLVM 22, export format 3.1.0) of one
    // `if x > 5 { .. } else { .. }` function, run once per arm.
    const THEN_ONLY: &str = include_str!("../tests/data/export_then_only.json");
    const ELSE_ONLY: &str = include_str!("../tests/data/export_else_only.json");

    fn scope() -> Vec<PathBuf> {
        vec![PathBuf::from("/tmp/covfix/src")]
    }

    fn ids(items: &[CoveredItem]) -> HashSet<u64> {
        items.iter().map(|i| i.id).collect()
    }

    /// THE property physical counters violated. The two runs execute the same
    /// function through different arms; over physical counters the else-only
    /// run is `{entry}` ⊂ `{entry, then}` and gets pruned as dominated. Over
    /// evaluated items each run must hold something the other lacks.
    #[test]
    fn opposite_branch_arms_never_dominate_each_other() {
        let then_only = parse_export(THEN_ONLY, &scope()).unwrap();
        let else_only = parse_export(ELSE_ONLY, &scope()).unwrap();
        let (a, b) = (ids(&then_only), ids(&else_only));
        assert!(!a.is_subset(&b) && !b.is_subset(&a), "one arm's items dominate the other's");

        let arms = |items: &[CoveredItem]| -> Vec<ItemKind> {
            items.iter().filter(|i| i.kind != ItemKind::Region).map(|i| i.kind).collect()
        };
        assert_eq!(arms(&then_only), vec![ItemKind::BranchTrue]);
        assert_eq!(arms(&else_only), vec![ItemKind::BranchFalse]);
    }

    /// Only region ENTRIES with a count are items: the `[3,13,0,false,..]`
    /// style closing segments and the zero-count arm's regions are not.
    #[test]
    fn counts_region_entries_with_a_nonzero_count_only() {
        let then_only = parse_export(THEN_ONLY, &scope()).unwrap();
        let regions: Vec<&str> = then_only
            .iter()
            .filter(|i| i.kind == ItemKind::Region)
            .map(|i| i.location.as_str())
            .collect();
        // Line 3: the condition (col 8) and the then-arm (cols 16, 18) ran;
        // the else-arm's regions (cols 43, 45) have count 0 and must be absent.
        for expected in ["src/t.rs:3:8", "src/t.rs:3:16", "src/t.rs:3:18"] {
            assert!(regions.contains(&expected), "missing {expected} in {regions:?}");
        }
        for absent in ["src/t.rs:3:43", "src/t.rs:3:45", "src/t.rs:3:13"] {
            assert!(!regions.contains(&absent), "{absent} must not be an item: {regions:?}");
        }
    }

    /// Ids must not depend on where the checkout or registry lives, or shards
    /// scanned under different homes could not be merged.
    #[test]
    fn ids_do_not_depend_on_where_the_source_dir_lives() {
        let moved = THEN_ONLY.replace("/tmp/covfix/src", "/another/home/.cargo/src");
        let here = parse_export(THEN_ONLY, &scope()).unwrap();
        let there = parse_export(&moved, &[PathBuf::from("/another/home/.cargo/src")]).unwrap();
        assert_eq!(ids(&here), ids(&there));
        assert!(here.iter().all(|i| i.location.starts_with("src/t.rs:")), "{}", here[0].location);
    }

    /// Two scoped crates both have a `src/lib.rs`. The same span in each is
    /// two items: without the source dir's own name in the id they would
    /// collapse into one, and covering either crate's line would "cover" both.
    #[test]
    fn same_inner_path_in_two_source_dirs_does_not_collide() {
        let export = |dir: &str| {
            format!(
                r#"{{"data":[{{"files":[{{"filename":"{dir}/src/lib.rs",
                   "segments":[[10,5,1,true,true,false]],"branches":[]}}]}}]}}"#
            )
        };
        let dirs = [PathBuf::from("/r/revm-handler-8.1.0"), PathBuf::from("/r/revm-context-8.0.4")];
        let a = parse_export(&export("/r/revm-handler-8.1.0"), &dirs).unwrap();
        let b = parse_export(&export("/r/revm-context-8.0.4"), &dirs).unwrap();
        assert_eq!((a.len(), b.len()), (1, 1));
        assert_ne!(a[0].id, b[0].id);
        assert_eq!(a[0].location, "revm-handler-8.1.0/src/lib.rs:10:5");
    }

    /// A generic function exports one branch record per instantiation at the
    /// same span; an arm any instantiation took is one covered item.
    #[test]
    fn branch_arms_are_merged_across_instantiations() {
        let json = r#"{"data":[{"files":[{"filename":"/s/a.rs","segments":[],
            "branches":[[7,4,7,9,0,3,0,0,4],[7,4,7,9,2,0,1,1,4],[7,4,7,9,0,5,2,2,4]]}]}]}"#;
        let items = parse_export(json, &[PathBuf::from("/s")]).unwrap();
        let mut kinds: Vec<ItemKind> = items.iter().map(|i| i.kind).collect();
        kinds.sort_by_key(|k| k.as_str());
        assert_eq!(kinds, vec![ItemKind::BranchFalse, ItemKind::BranchTrue]);
    }

    /// A scope matching nothing is a misconfiguration (sources not at the
    /// build-time path), and must not pass for a block that covered nothing.
    #[test]
    fn empty_file_list_is_an_error_not_an_empty_block() {
        let err = parse_export(r#"{"data":[{"files":[]}]}"#, &scope()).expect_err("must fail");
        assert!(err.to_string().contains("matched no source file"), "{err}");
    }

    #[test]
    fn universe_stamp_is_order_independent_and_versioned() {
        let (a, b) = (PathBuf::from("/x/a"), PathBuf::from("/x/b"));
        assert_eq!(universe_stamp(&[a.clone(), b.clone()]), universe_stamp(&[b, a]));
        assert_eq!(universe_stamp(&[PathBuf::from("/x")]), "regions+branch-arms/v2:/x");
    }
}
