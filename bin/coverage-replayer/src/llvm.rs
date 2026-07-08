//! LLVM tool discovery and `.profraw` → non-zero-counter extraction.
//!
//! Set cover never needs source mapping: the identity of a coverage counter is
//! `(PGO function name, function hash, counter index)`, hashed to a stable u64.
//! With `-Z coverage-options=branch` the branch true/false counters are plain
//! counters too, so these ids are naturally branch-granular. `llvm-cov` is only
//! used by the `report` subcommand.

use std::{
    hash::Hasher,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{Context, Result, ensure};
use rustc_hash::FxHasher;

/// A non-zero counter observed in a profraw, with its stable id.
#[derive(Debug, Clone)]
pub struct CounterHit {
    pub id: u64,
    pub symbol: String,
    pub func_hash: String,
    pub index: u32,
}

/// Stable 64-bit id of a counter. FxHasher is seed-free and deterministic
/// across processes, which is all we need (ids live in one binary namespace).
pub fn counter_id(symbol: &str, func_hash: &str, index: u32) -> u64 {
    let mut h = FxHasher::default();
    h.write(symbol.as_bytes());
    h.write_u8(0xff);
    h.write(func_hash.as_bytes());
    h.write_u32(index);
    h.finish()
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

/// Runs `llvm-profdata merge --text` on a profraw and returns all non-zero
/// counters whose PGO symbol name contains `symbol_filter`.
pub fn extract_nonzero_counters(
    llvm_profdata: &Path,
    profraw: &Path,
    symbol_filter: &str,
) -> Result<Vec<CounterHit>> {
    let out = Command::new(llvm_profdata)
        .arg("merge")
        .arg("--text")
        .arg(profraw)
        .arg("-o")
        .arg("-")
        .output()
        .wrap_err("spawn llvm-profdata")?;
    ensure!(
        out.status.success(),
        "llvm-profdata merge --text failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    parse_proftext(&text, symbol_filter)
}

/// Parses `llvm-profdata merge --text` output.
///
/// Per-function block layout:
/// ```text
/// <PGO name>
/// # Func Hash:
/// <hash>
/// # Num Counters:
/// <n>
/// # Counter Values:
/// <v1>
/// ...
/// <vn>
/// ```
/// Unknown sections (e.g. MC/DC bitmaps, value profiling) are skipped by the
/// line scanner because they never match the `# Func Hash:` anchor sequence.
pub fn parse_proftext(text: &str, symbol_filter: &str) -> Result<Vec<CounterHit>> {
    let lines: Vec<&str> = text.lines().collect();
    let mut hits = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_end() == "# Func Hash:" {
            // Symbol is the closest preceding non-empty, non-comment line.
            let Some(symbol) = lines[..i]
                .iter()
                .rev()
                .map(|l| l.trim())
                .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(':'))
            else {
                i += 1;
                continue;
            };
            let func_hash = lines.get(i + 1).map(|l| l.trim()).unwrap_or_default();
            if lines.get(i + 2).map(|l| l.trim_end()) != Some("# Num Counters:") {
                i += 1;
                continue;
            }
            let n: usize = lines
                .get(i + 3)
                .and_then(|l| l.trim().parse().ok())
                .ok_or_else(|| eyre::eyre!("bad Num Counters near line {i}"))?;
            if lines.get(i + 4).map(|l| l.trim_end()) != Some("# Counter Values:") {
                i += 1;
                continue;
            }
            let keep = symbol.contains(symbol_filter);
            for k in 0..n {
                let Some(v) = lines.get(i + 5 + k) else { break };
                if keep {
                    let value: u128 = v.trim().parse().unwrap_or(0);
                    if value != 0 {
                        let index = k as u32;
                        hits.push(CounterHit {
                            id: counter_id(symbol, func_hash, index),
                            symbol: symbol.to_string(),
                            func_hash: func_hash.to_string(),
                            index,
                        });
                    }
                }
            }
            i += 5 + n;
        } else {
            i += 1;
        }
    }
    hits.sort_by_key(|h| h.id);
    hits.dedup_by_key(|h| h.id);
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# IR level Instrumentation Flag
:ir
_RNvCsabc_8mega_evm7branchy
# Func Hash:
1234567890
# Num Counters:
4
# Counter Values:
10
0
3
0

_RNvCsdef_5other3foo
# Func Hash:
42
# Num Counters:
2
# Counter Values:
1
1
";

    #[test]
    fn parses_and_filters() {
        let hits = parse_proftext(SAMPLE, "mega_evm").unwrap();
        assert_eq!(hits.len(), 2);
        let indices: Vec<u32> = {
            let mut v: Vec<u32> = hits.iter().map(|h| h.index).collect();
            v.sort();
            v
        };
        assert_eq!(indices, vec![0, 2]);
        for h in &hits {
            assert!(h.symbol.contains("mega_evm"));
            assert_eq!(h.id, counter_id(&h.symbol, &h.func_hash, h.index));
        }

        // No filter → both functions counted.
        let all = parse_proftext(SAMPLE, "").unwrap();
        assert_eq!(all.len(), 4);
    }
}
