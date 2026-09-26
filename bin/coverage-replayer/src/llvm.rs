//! LLVM tool discovery and `.profraw` → covered-item extraction.
//!
//! A covered item is an *evaluated* region entry or branch arm, as `llvm-cov` computes
//! it, NOT a physical counter. rustc minimizes physical counters: an `if`/`else` gets two
//! (entry, then-arm) and the else-arm exists only as the expression `entry - then`. An
//! else-only block's `{entry}` would then look dominated by a then-only block's
//! `{entry, then}`, and the minimal set would silently lose an arm the scan covered. No
//! `-Z coverage-options` value turns that minimization off.
//!
//! So every block's profile goes through `llvm-cov export`, which evaluates the counter
//! expressions — the same arithmetic `report` runs. The export is scoped to source
//! directories, which define the universe (an unscoped export of this binary also crashes
//! llvm-cov). The default scope is the mega-evm checkout plus `measured-crates.txt`;
//! scoping by directory, not symbol name, keeps other crates out, since a mangled name
//! carries its generic arguments and instantiating crate.

use std::{
    ffi::{OsStr, OsString},
    hash::Hasher,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{Context, Result, ensure};
use rustc_hash::FxHasher;
use serde::{Deserialize, Serialize};

/// Version of the item definition, stamped into every store (see [`universe_stamp`]). Bump
/// it whenever the id, the set of item kinds, or what a block's bitmap records changes (e.g.
/// what `worker::warm_up` keeps out of it): two definitions must never share a store.
const ITEM_UNIVERSE: &str = "regions+branch-arms/v3";

/// What a covered item is, for the provenance columns of the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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

/// A covered item observed in one profile, with its stable id — also what a
/// worker reports for ids new to it (see `proto::WorkerResponse::new_items`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoveredItem {
    pub id: u64,
    /// `<source dir name>/<path inside it>:<line>:<col>`.
    pub location: String,
    pub kind: ItemKind,
    pub line: u32,
}

/// Stable 64-bit id of a covered item (FxHasher is seed-free and deterministic). `scoped_path`
/// starts at the root's label (`revm-handler-8.1.0/src/lib.rs`): that keeps two crates'
/// `src/lib.rs` apart, and dropping the path above it keeps ids independent of where roots live.
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

/// A source root's label: its final component (`revm-handler-8.1.0`, or the mega-evm short
/// rev), naming the root without where it lives. [`resolve_source_dirs`] rejects duplicate
/// labels, so the lossy conversion and fallback below cannot merge two roots.
fn root_label(dir: &Path) -> String {
    dir.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.display().to_string())
}

/// The universe stamp a store is namespaced by, next to `binary_id`: the item definition
/// plus the source scope. Built from sorted labels, not paths: stamps are compared byte for
/// byte, so one scope must stamp identically whatever its home or root order.
pub fn universe_stamp(source_dirs: &[PathBuf]) -> String {
    let mut labels: Vec<String> = source_dirs.iter().map(|d| root_label(d)).collect();
    labels.sort();
    format!("{ITEM_UNIVERSE}:{}", labels.join(","))
}

/// The coverage scope and the LLVM tools that evaluate it, shared by `backfill` and `report`.
#[derive(clap::Args, Debug, Clone)]
pub struct LlvmArgs {
    /// Source directories scoping the coverage universe; the store is stamped with them and
    /// `report` refuses a manifest over any other scope. Default: the built-against mega-evm
    /// checkout plus `measured-crates.txt` at their locked versions, under the build's cargo
    /// home. Sources must sit at the absolute paths they had at build time.
    #[clap(long = "source-dir")]
    pub source_dirs: Vec<PathBuf>,
    /// llvm-profdata path (default: the `llvm-tools` of the toolchain that built this binary).
    #[clap(long)]
    pub llvm_profdata: Option<PathBuf>,
    /// llvm-cov path (default: the `llvm-tools` of the toolchain that built this binary).
    #[clap(long)]
    pub llvm_cov: Option<PathBuf>,
}

impl LlvmArgs {
    /// Resolves the scope and both tools, or fails naming what is missing.
    pub fn resolve(&self) -> Result<Llvm> {
        Ok(Llvm {
            profdata: find_tool("llvm-profdata", self.llvm_profdata.as_deref())?,
            cov: find_tool("llvm-cov", self.llvm_cov.as_deref())?,
            source_dirs: resolve_source_dirs(&self.source_dirs)?,
        })
    }
}

/// A resolved [`LlvmArgs`]: the tools exist and the scope passed its checks.
#[derive(Debug, Clone)]
pub struct Llvm {
    pub profdata: PathBuf,
    pub cov: PathBuf,
    pub source_dirs: Vec<PathBuf>,
}

impl Llvm {
    /// The universe stamp of this scope (see [`universe_stamp`]).
    pub fn universe(&self) -> String {
        universe_stamp(&self.source_dirs)
    }

    /// Flags passing this resolution to a worker, so workers evaluate exactly what was resolved.
    pub fn to_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            "--llvm-profdata".into(),
            self.profdata.clone().into(),
            "--llvm-cov".into(),
            self.cov.clone().into(),
        ];
        for dir in &self.source_dirs {
            args.extend(["--source-dir".into(), dir.clone().into()]);
        }
        args
    }

    /// Turns one block's profraw into its covered items, leaving the sparse profdata at
    /// `profdata` for the judge to archive. `exe` must be the instrumented binary that wrote
    /// the profraw: its coverage map is what gives the counters their meaning.
    pub fn extract_covered_items(
        &self,
        exe: &Path,
        profraw: &Path,
        profdata: &Path,
    ) -> Result<Vec<CoveredItem>> {
        self.merge_sparse(&[profraw], profdata)?;
        self.covered_items(exe, profdata)
    }

    /// `llvm-cov report` over the scope: the per-file table `report` prints.
    pub fn report(&self, exe: &Path, profdata: &Path) -> Result<String> {
        let out = Command::new(&self.cov)
            .arg("report")
            .arg(exe)
            .arg(format!("--instr-profile={}", profdata.display()))
            .args(&self.source_dirs)
            .output()
            .wrap_err("spawn llvm-cov")?;
        ensure!(
            out.status.success(),
            "llvm-cov report failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// `llvm-profdata merge -sparse`: raw profiles or profdata files in, one
    /// sparse profdata out — counts summed, zero-count functions dropped.
    pub fn merge_sparse(&self, inputs: &[impl AsRef<OsStr>], out: &Path) -> Result<()> {
        let merged = Command::new(&self.profdata)
            .arg("merge")
            .arg("-sparse")
            .args(inputs)
            .arg("-o")
            .arg(out)
            .output()
            .wrap_err("spawn llvm-profdata")?;
        ensure!(
            merged.status.success(),
            "llvm-profdata merge -sparse failed: {}",
            String::from_utf8_lossy(&merged.stderr)
        );
        Ok(())
    }

    /// The covered items of `profdata` within the scope, evaluated against `exe`'s coverage
    /// map — the one extraction both a block's bitmap and `report`'s cross-check go through.
    pub fn covered_items(&self, exe: &Path, profdata: &Path) -> Result<Vec<CoveredItem>> {
        let out = Command::new(&self.cov)
            .arg("export")
            .arg(exe)
            .arg(format!("--instr-profile={}", profdata.display()))
            .arg("--format=text")
            // Per-function records are most of the output and add nothing to the file level.
            .arg("--skip-functions")
            .args(&self.source_dirs)
            .output()
            .wrap_err("spawn llvm-cov")?;
        ensure!(
            out.status.success(),
            "llvm-cov export failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        parse_export(&String::from_utf8_lossy(&out.stdout), &self.source_dirs)
    }
}

/// Resolves the source scope: the explicit `--source-dir`s, or the default (mega-evm
/// checkout plus measured crates). Every directory must exist: a scope that matches nothing
/// would turn every block into an empty bitmap.
fn resolve_source_dirs(explicit: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let dirs = if explicit.is_empty() {
        let cargo_home = Path::new(env!("COVERAGE_CARGO_HOME"));
        let mut dirs = vec![detect_mega_evm_checkout(cargo_home)?];
        for krate in env!("COVERAGE_MEASURED_CRATES").split(',').filter(|c| !c.is_empty()) {
            dirs.push(detect_registry_crate(cargo_home, krate)?);
        }
        dirs
    } else {
        explicit.to_vec()
    };
    for dir in &dirs {
        ensure!(dir.is_dir(), "source dir {} does not exist", dir.display());
    }
    // Ids and stamp identify a root by its label: two roots sharing one would have their
    // coverage silently merged while the stamp still claimed two.
    for (i, dir) in dirs.iter().enumerate() {
        let label = root_label(dir);
        if let Some(other) = dirs[..i].iter().find(|d| root_label(d) == label) {
            eyre::bail!(
                "source dirs {} and {} share the final path component {label:?}, which is what \
                 identifies a root — coverage from the two would collide. Pass roots whose last \
                 component differs.",
                other.display(),
                dir.display(),
            );
        }
        // Nested roots make a file's owning root depend on listing order, which the
        // order-independent stamp cannot see: one stamp, two sets of ids.
        if let Some(outer) = dirs.iter().enumerate().find(|(j, d)| *j != i && dir.starts_with(d)) {
            eyre::bail!(
                "source dir {} lies inside {} — pass disjoint roots",
                dir.display(),
                outer.1.display(),
            );
        }
    }
    Ok(dirs)
}

/// Finds `<name>-<version>` under the registry sources of the build's cargo home. Cargo
/// keeps one tree per index it has used, and llvm-cov matches only the one the build
/// compiled, so more than one candidate is a question for the operator rather than a pick.
fn detect_registry_crate(cargo_home: &Path, name_version: &str) -> Result<PathBuf> {
    let src = cargo_home.join("registry").join("src");
    let candidates: Vec<PathBuf> = std::fs::read_dir(&src)
        .map(|indexes| {
            indexes.flatten().map(|index| index.path().join(name_version)).collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .into_iter()
        .filter(|candidate| candidate.is_dir())
        .collect();
    one_candidate(candidates, &format!("the sources of {name_version} under {}", src.display()))
}

/// Finds the cargo git checkout of the mega-evm rev this binary was BUILT against (embedded
/// by build.rs), so the rev can never disagree with the instrumented build.
fn detect_mega_evm_checkout(cargo_home: &Path) -> Result<PathBuf> {
    let rev: String = env!("COVERAGE_MEGA_EVM_REV").chars().take(7).collect();
    ensure!(rev.len() == 7, "the built-against mega-evm rev {rev:?} is too short to locate");
    let checkouts = cargo_home.join("git").join("checkouts");
    let candidates: Vec<PathBuf> = std::fs::read_dir(&checkouts)
        .map(|repos| repos.flatten().collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter(|repo| repo.file_name().to_string_lossy().starts_with("mega-evm-"))
        .map(|repo| repo.path().join(&rev))
        .filter(|candidate| candidate.is_dir())
        .collect();
    one_candidate(candidates, &format!("the mega-evm {rev} checkout under {}", checkouts.display()))
}

/// The one directory default scope detection found, or an error naming what to pass.
fn one_candidate(mut candidates: Vec<PathBuf>, what: &str) -> Result<PathBuf> {
    match candidates.len() {
        1 => Ok(candidates.remove(0)),
        0 => eyre::bail!(
            "could not find {what} — the cargo home this binary was built with; pass every \
             --source-dir explicitly"
        ),
        _ => eyre::bail!(
            "found {what} more than once ({}) — only the one the build compiled is measurable; \
             pass every --source-dir explicitly",
            candidates.iter().map(|c| c.display().to_string()).collect::<Vec<_>>().join(", "),
        ),
    }
}

/// Locates an LLVM tool: explicit override → the sysroot of the toolchain that BUILT this
/// binary (its LLVM wrote the binary's profile and coverage-map formats) → the sysroot of
/// whatever `rustc` resolves to here → `$PATH`.
fn find_tool(name: &str, cli_override: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = cli_override {
        ensure!(p.exists(), "{name} override does not exist: {}", p.display());
        return Ok(p.to_path_buf());
    }

    let runtime_sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()));
    let sysroots = [Some(PathBuf::from(env!("COVERAGE_RUSTC_SYSROOT"))), runtime_sysroot];
    if let Some(tool) = find_in_sysroots(name, sysroots.iter().flatten()) {
        return Ok(tool);
    }

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

/// The first `<sysroot>/lib/rustlib/<triple>/bin/<name>` that exists, in sysroot order.
fn find_in_sysroots<'a>(
    name: &str,
    sysroots: impl IntoIterator<Item = &'a PathBuf>,
) -> Option<PathBuf> {
    sysroots.into_iter().find_map(|sysroot| {
        std::fs::read_dir(sysroot.join("lib").join("rustlib"))
            .ok()?
            .flatten()
            .map(|triple| triple.path().join("bin").join(name))
            .find(|candidate| candidate.is_file())
    })
}

/// Fails unless every configured root prefixes at least one file llvm-cov listed. The
/// listed files depend on the coverage map and scope, not on what ran, so a root with none
/// is misconfigured — and llvm-cov only warns about it on stderr and exits successfully.
/// Roots are never canonicalized: llvm-cov matches build-time absolute paths as spelled.
fn ensure_every_root_matched(filenames: &[&str], source_dirs: &[PathBuf]) -> Result<()> {
    for dir in source_dirs {
        ensure!(
            filenames.iter().any(|f| Path::new(f).starts_with(dir)),
            "llvm-cov matched no source file under {} — either that root is not where the \
             instrumented binary was built from, or its crate was compiled without \
             instrumentation (after adding a crate to measured-crates.txt, `cargo clean -p` it \
             first: cargo cannot see that the wrapper now instruments it), so nothing under it \
             is measured",
            dir.display(),
        );
    }
    Ok(())
}

/// Parses `llvm-cov export --format=text --skip-functions` output. Per file, `segments` are
/// `[line, col, count, has_count, is_region_entry, is_gap]` and `branches` are `[line, col,
/// end_line, end_col, true_count, false_count, ...]`. A generic function has one branch
/// record per instantiation at one span; arms are OR-ed, as the item is the source arm.
pub fn parse_export(json: &str, source_dirs: &[PathBuf]) -> Result<Vec<CoveredItem>> {
    let root: serde_json::Value = serde_json::from_str(json).wrap_err("parse llvm-cov export")?;
    let files = root["data"][0]["files"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("llvm-cov export has no data[0].files"))?;
    let filenames: Vec<&str> = files.iter().filter_map(|f| f["filename"].as_str()).collect();
    ensure_every_root_matched(&filenames, source_dirs)?;

    let nonzero = |v: &serde_json::Value| {
        v.as_u64().is_some_and(|n| n > 0) || v.as_f64().is_some_and(|n| n > 0.0)
    };
    let coord = |v: &serde_json::Value| v.as_u64().unwrap_or(0) as u32;

    let mut items = Vec::new();
    for file in files {
        let filename = file["filename"].as_str().unwrap_or_default();
        // Roots are disjoint (`resolve_source_dirs`), so the first match is the only one.
        let rel = source_dirs
            .iter()
            .find_map(|dir| {
                let inside = Path::new(filename).strip_prefix(dir).ok()?;
                Some(Path::new(&root_label(dir)).join(inside).display().to_string())
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

    /// THE property physical counters violate: two runs through opposite arms of one function
    /// must each hold an item the other lacks.
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

    /// Only region ENTRIES with a count are items, not closing or zero-count segments.
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

    /// Ids must not depend on where the checkout or registry lives.
    #[test]
    fn ids_do_not_depend_on_where_the_source_dir_lives() {
        let moved = THEN_ONLY.replace("/tmp/covfix/src", "/another/home/.cargo/src");
        let here = parse_export(THEN_ONLY, &scope()).unwrap();
        let there = parse_export(&moved, &[PathBuf::from("/another/home/.cargo/src")]).unwrap();
        assert_eq!(ids(&here), ids(&there));
        assert!(here.iter().all(|i| i.location.starts_with("src/t.rs:")), "{}", here[0].location);
    }

    /// The same span in two roots' `src/lib.rs` is two items, not one.
    #[test]
    fn same_inner_path_in_two_source_dirs_does_not_collide() {
        let json = r#"{"data":[{"files":[
            {"filename":"/r/revm-handler-8.1.0/src/lib.rs","segments":[[10,5,1,true,true,false]],"branches":[]},
            {"filename":"/r/revm-context-8.0.4/src/lib.rs","segments":[[10,5,1,true,true,false]],"branches":[]}]}]}"#;
        let dirs = [PathBuf::from("/r/revm-handler-8.1.0"), PathBuf::from("/r/revm-context-8.0.4")];
        let items = parse_export(json, &dirs).unwrap();

        assert_eq!(items.len(), 2, "one item per root, not one shared: {items:?}");
        assert_ne!(items[0].id, items[1].id);
        let mut locations: Vec<&str> = items.iter().map(|i| i.location.as_str()).collect();
        locations.sort_unstable();
        assert_eq!(
            locations,
            ["revm-context-8.0.4/src/lib.rs:10:5", "revm-handler-8.1.0/src/lib.rs:10:5"]
        );
    }

    /// An arm taken by any instantiation of a generic function is one covered item.
    #[test]
    fn branch_arms_are_merged_across_instantiations() {
        let json = r#"{"data":[{"files":[{"filename":"/s/a.rs","segments":[],
            "branches":[[7,4,7,9,0,3,0,0,4],[7,4,7,9,2,0,1,1,4],[7,4,7,9,0,5,2,2,4]]}]}]}"#;
        let items = parse_export(json, &[PathBuf::from("/s")]).unwrap();
        let mut kinds: Vec<ItemKind> = items.iter().map(|i| i.kind).collect();
        kinds.sort_by_key(|k| k.as_str());
        assert_eq!(kinds, vec![ItemKind::BranchFalse, ItemKind::BranchTrue]);
    }

    /// Every root is checked, not just the scope as a whole: a valid mega-evm root must not
    /// mask a stale revm one.
    #[test]
    fn every_source_root_must_contribute_a_file() {
        let json = r#"{"data":[{"files":[
            {"filename":"/r/mega/src/a.rs","segments":[[1,1,1,true,true,false]],"branches":[]}]}]}"#;
        let dirs = [PathBuf::from("/r/mega"), PathBuf::from("/r/revm-handler-8.1.0")];

        let err = parse_export(json, &dirs).expect_err("a root with no file must fail");
        assert!(err.to_string().contains("/r/revm-handler-8.1.0"), "must name the root: {err}");
        assert!(err.to_string().contains("matched no source file"), "{err}");

        // The same export is fine for the scope it does cover.
        assert_eq!(parse_export(json, &dirs[..1]).unwrap().len(), 1);
    }

    /// Matching is by path prefix, not substring: a stale root `src` is refused even though
    /// `src` appears in every other root's paths.
    #[test]
    fn a_stale_root_is_refused_even_when_its_name_appears_in_other_paths() {
        let json = r#"{"data":[{"files":[
            {"filename":"/x/crates/mega-evm/src/evm.rs","segments":[],"branches":[]},
            {"filename":"/x/crates/mega-evm/src/lib.rs","segments":[],"branches":[]}]}]}"#;
        let valid = PathBuf::from("/x");
        let stale = PathBuf::from("/y/src");

        let err = parse_export(json, &[valid.clone(), stale])
            .expect_err("a root no file lies under must fail");
        assert!(err.to_string().contains("/y/src"), "must name the stale root: {err}");
        parse_export(json, &[valid]).expect("the real root matches");
    }

    /// A file with no covered region still counts as its root contributing.
    #[test]
    fn a_root_whose_files_are_all_uncovered_still_counts() {
        let json = r#"{"data":[{"files":[
            {"filename":"/r/mega/src/a.rs","segments":[[1,1,1,true,true,false]],"branches":[]},
            {"filename":"/r/revm/src/b.rs","segments":[[9,1,0,true,true,false]],"branches":[]}]}]}"#;
        let dirs = [PathBuf::from("/r/mega"), PathBuf::from("/r/revm")];
        let items = parse_export(json, &dirs).expect("an uncovered file still matches its root");
        assert_eq!(items.len(), 1, "only the covered region is an item");
    }

    /// A scope matching nothing is a misconfiguration, not a block that covered nothing.
    #[test]
    fn empty_file_list_is_an_error_not_an_empty_block() {
        let err = parse_export(r#"{"data":[{"files":[]}]}"#, &scope()).expect_err("must fail");
        assert!(err.to_string().contains("matched no source file"), "{err}");
    }

    #[test]
    fn universe_stamp_is_order_independent_and_versioned() {
        let (a, b) = (PathBuf::from("/x/a"), PathBuf::from("/x/b"));
        assert_eq!(universe_stamp(&[a.clone(), b.clone()]), universe_stamp(&[b, a]));
        assert_eq!(universe_stamp(&[PathBuf::from("/x/mega")]), "regions+branch-arms/v3:mega");
    }

    /// One scope must stamp identically however homes are laid out.
    #[test]
    fn universe_stamp_does_not_depend_on_where_the_roots_live() {
        let alice = [
            PathBuf::from("/home/alice/.cargo/git/co/30ce038"),
            PathBuf::from("/home/alice/.cargo/registry/src/idx/revm-handler-8.1.0"),
        ];
        let root = [
            PathBuf::from("/root/.cargo/registry/src/other/revm-handler-8.1.0"),
            PathBuf::from("/root/.cargo/git/co/30ce038"),
        ];
        assert_eq!(universe_stamp(&alice), universe_stamp(&root));
        assert_eq!(universe_stamp(&alice), "regions+branch-arms/v3:30ce038,revm-handler-8.1.0");
    }

    /// A crate under two registry indexes is refused, not resolved by listing order.
    #[test]
    fn default_scope_refuses_a_crate_found_under_two_registry_indexes() {
        let home = tempfile::tempdir().unwrap();
        let src = home.path().join("registry/src");
        std::fs::create_dir_all(src.join("index-a/revm-handler-8.1.0")).unwrap();

        let found = detect_registry_crate(home.path(), "revm-handler-8.1.0").unwrap();
        assert_eq!(found, src.join("index-a/revm-handler-8.1.0"));

        std::fs::create_dir_all(src.join("index-b/revm-handler-8.1.0")).unwrap();
        let err = detect_registry_crate(home.path(), "revm-handler-8.1.0")
            .expect_err("two candidates must not be resolved by listing order");
        assert!(err.to_string().contains("more than once"), "{err}");
        assert!(
            err.to_string().contains("index-a") && err.to_string().contains("index-b"),
            "{err}"
        );

        let err = detect_registry_crate(home.path(), "op-revm-8.1.0").expect_err("absent");
        assert!(err.to_string().contains("could not find"), "{err}");
    }

    /// The build's own toolchain wins over whatever `rustc` the working directory resolves to.
    #[test]
    fn llvm_tools_come_from_the_first_sysroot_that_has_them() {
        let dir = tempfile::tempdir().unwrap();
        let (build, runtime) = (dir.path().join("build"), dir.path().join("runtime"));
        for sysroot in [&build, &runtime] {
            let bin = sysroot.join("lib/rustlib/x86_64-unknown-linux-gnu/bin");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::write(bin.join("llvm-cov"), b"").unwrap();
        }
        let found = find_in_sysroots("llvm-cov", [&build, &runtime]).unwrap();
        assert!(found.starts_with(&build), "{}", found.display());

        let missing = dir.path().join("no-tools");
        let found = find_in_sysroots("llvm-cov", [&missing, &runtime]).unwrap();
        assert!(found.starts_with(&runtime), "falls through to the next sysroot");
        assert_eq!(find_in_sysroots("llvm-profdata", [&build, &runtime]), None);
    }

    /// Duplicate labels and nested roots are refused (see `resolve_source_dirs`).
    #[test]
    fn resolve_rejects_duplicate_labels_and_nested_roots() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, nested) =
            (dir.path().join("a/src"), dir.path().join("b/src"), dir.path().join("a/src/inner"));
        for d in [&a, &b, &nested] {
            std::fs::create_dir_all(d).unwrap();
        }

        let err = resolve_source_dirs(&[a.clone(), b]).expect_err("duplicate label must fail");
        assert!(err.to_string().contains("\"src\""), "must name the shared component: {err}");

        let err = resolve_source_dirs(&[a.clone(), nested]).expect_err("nested root must fail");
        assert!(err.to_string().contains("lies inside"), "{err}");

        resolve_source_dirs(&[a, dir.path().join("b")]).expect("distinct disjoint roots are fine");
    }
}
