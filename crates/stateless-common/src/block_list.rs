//! Block-list files: one decimal block number per line.
//!
//! `coverage-replayer inspect --dump-pool` writes them, and `coverage-replayer backfill
//! --blocks-file` and `stateless-validator --block-list` read them, so the format has one parser.

use std::{collections::BTreeSet, path::Path};

use eyre::{Result, WrapErr, bail, ensure};

/// Parses a block list: one decimal block number per line.
///
/// `#` starts a comment, on a line of its own (a pool's provenance header) or after a number.
/// Blank lines are skipped. The result is ascending with duplicates collapsed, so concatenated
/// shard pools replay each block once, in order. Any other line fails the parse, naming its line:
/// silently dropping an entry would shrink the set a run claims to have covered. An empty list
/// parses; [`read_block_list`] is what refuses one.
pub fn parse_block_list(text: &str) -> Result<Vec<u64>> {
    parse(text, "line ")
}

/// Reads and parses the block list at `path`, refusing one with no numbers in it: a run over
/// nothing would pass vacuously.
pub fn read_block_list(path: &Path) -> Result<Vec<u64>> {
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("cannot read block list {}", path.display()))?;
    let blocks = parse(&text, &format!("{}:", path.display()))?;
    ensure!(!blocks.is_empty(), "block list {} holds no block numbers", path.display());
    Ok(blocks)
}

/// [`parse_block_list`], naming a bad line as `{at}{line number}`.
fn parse(text: &str, at: &str) -> Result<Vec<u64>> {
    let mut blocks = BTreeSet::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split_once('#').map_or(raw, |(entry, _)| entry).trim();
        if line.is_empty() {
            continue;
        }
        let Ok(number) = line.parse::<u64>() else {
            bail!("{at}{}: {line:?} is not a block number", index + 1);
        };
        blocks.insert(number);
    }
    Ok(blocks.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ScratchDir;

    #[test]
    fn a_pool_parses_with_its_header_and_trailing_comments_sorted_and_deduplicated() {
        let text =
            "# coverage-replayer candidate pool\n# blocks: 3\n\n  30 \n10\n20 # trailing\r\n10\n";
        assert_eq!(parse_block_list(text).unwrap(), vec![10, 20, 30]);
    }

    #[test]
    fn a_bad_line_fails_the_parse_and_names_its_line() {
        let error = parse_block_list("1\n2\nxyz\n4\n").unwrap_err().to_string();
        assert!(error.contains("line 3") && error.contains("xyz"), "got: {error}");
        // Only a whole number counts: nothing is half-parsed into a smaller one.
        for bad in ["-1", "0x10", "5x", "5 6", "1_000"] {
            assert!(parse_block_list(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn an_empty_text_parses_to_no_blocks() {
        assert_eq!(parse_block_list("").unwrap(), Vec::<u64>::new());
        assert_eq!(parse_block_list("# only a header\n\n").unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn reading_names_the_file_and_line_and_refuses_an_empty_list() {
        let dir = ScratchDir::new("block-list");
        let path = dir.path().join("pool.txt");

        std::fs::write(&path, "# header\n7\n3\n").unwrap();
        assert_eq!(read_block_list(&path).unwrap(), vec![3, 7]);

        std::fs::write(&path, "10\n0x1f\n").unwrap();
        let error = read_block_list(&path).unwrap_err().to_string();
        assert!(error.contains(&format!("{}:2:", path.display())), "got: {error}");

        std::fs::write(&path, "# only a header\n").unwrap();
        let error = read_block_list(&path).unwrap_err().to_string();
        assert!(error.contains("holds no block numbers"), "got: {error}");

        assert!(read_block_list(&dir.path().join("missing.txt")).is_err());
    }
}
