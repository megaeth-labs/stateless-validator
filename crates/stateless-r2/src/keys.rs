//! R2 object-key layout shared by the witness writers and the validator's reader.
//!
//! Every witness is archived as three objects under a `{range_start}_{range_end}` bucket:
//! - the **primary** object `block/{range}/{number}.{hash}` carrying the compressed witness bytes;
//! - an **attr** pointer `attr/{range}/{parent_hash}.{attr_hash}`;
//! - a **num** pointer `num/{range}/{number}`.
//!
//! This module is the single home of that layout plus the shared [`pointer_body`] and the
//! `x-amz-meta-*` [`witness_metadata`], so the producers and the reader cannot drift. Objects
//! carry no per-object expiry; retention is a bucket lifecycle rule targeting these prefixes
//! (see the crate-level docs).

use std::fmt::Display;

use crate::sigv4::Header;

/// Object-key prefix for the primary witness object (the compressed witness body).
pub const BLOCK_PREFIX: &str = "block";

/// Object-key prefix for the `(parent_hash, attributes_hash)` reference pointer.
pub const ATTR_PREFIX: &str = "attr";

/// Object-key prefix for the by-block-number reference pointer.
pub const NUM_PREFIX: &str = "num";

/// Block range size for grouping keys (1000 blocks per group).
///
/// Blocks are grouped into ranges of 1000 so R2 list and lifecycle operations can target contiguous
/// block ranges by prefix.
pub const BLOCK_RANGE_SIZE: u64 = 1000;

/// Calculate the range-bucket prefix for grouping blocks into ranges.
///
/// For example:
/// - Block 0-999 → prefix 0
/// - Block 1000-1999 → prefix 1000
/// - Block 2500 → prefix 2000
#[inline]
pub const fn block_range_prefix(block_number: u64) -> u64 {
    (block_number / BLOCK_RANGE_SIZE) * BLOCK_RANGE_SIZE
}

/// Builds just the primary witness object key: `block/{range}/{number}.{hash}`.
///
/// This is the single implementation of the primary-key template. [`object_keys`] (the write path)
/// delegates here, and the stateless validator's R2 witness source (the read path) calls it
/// directly, so the writers and the reader can never disagree on where a witness lives.
pub fn block_object_key(block_number: u64, block_hash: impl Display) -> String {
    let range_start = block_range_prefix(block_number);
    let range_end = range_start + BLOCK_RANGE_SIZE - 1;
    format!("{BLOCK_PREFIX}/{range_start}_{range_end}/{block_number}.{block_hash}")
}

/// Builds the three R2 object keys for a witness from its block number and identifying hashes.
///
/// Keys use a `{range_start}_{range_end}` bucket where `range_start = (number / 1000) * 1000`,
/// decimal block numbers, and lowercase hex hashes (alloy `B256` formats lowercase via `Display`).
///
/// Returns `(block_key, attr_key, num_key)`.
pub fn object_keys(
    block_number: u64,
    block_hash: impl Display,
    parent_hash: impl Display,
    op_attr_hash: impl Display,
) -> (String, String, String) {
    let range_start = block_range_prefix(block_number);
    let range_end = range_start + BLOCK_RANGE_SIZE - 1;
    let range = format!("{range_start}_{range_end}");
    let block_key = block_object_key(block_number, block_hash);
    let attr_key = format!("{ATTR_PREFIX}/{range}/{parent_hash}.{op_attr_hash}");
    let num_key = format!("{NUM_PREFIX}/{range}/{block_number}");
    (block_key, attr_key, num_key)
}

/// Builds the plaintext body shared by both pointer objects: `"{block_number}.{block_hash}"`.
///
/// Both pointer objects (`attr/...` and `num/...`) store this same reference to the primary object.
/// The stateless validator parses it, so the generator and the replayer must produce it
/// identically.
pub fn pointer_body(block_number: u64, block_hash: impl Display) -> String {
    format!("{block_number}.{block_hash}")
}

/// Builds the `x-amz-meta-*` custom-metadata headers stored alongside the primary witness object.
///
/// The generator and the replayer must emit the same header names, order, and values — hence a
/// single shared builder rather than a copy per binary.
pub fn witness_metadata(
    original_size: usize,
    compressed_size: usize,
    parent_hash: impl Display,
    op_attr_hash: impl Display,
) -> Vec<Header> {
    vec![
        ("x-amz-meta-compression".to_string(), "zstd".to_string()),
        ("x-amz-meta-original-size".to_string(), original_size.to_string()),
        ("x-amz-meta-compressed-size".to_string(), compressed_size.to_string()),
        ("x-amz-meta-parent-hash".to_string(), parent_hash.to_string()),
        ("x-amz-meta-attr-hash".to_string(), op_attr_hash.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_range_prefix_buckets_by_thousand() {
        assert_eq!(block_range_prefix(0), 0);
        assert_eq!(block_range_prefix(999), 0);
        assert_eq!(block_range_prefix(1000), 1000);
        assert_eq!(block_range_prefix(1001), 1000);
        assert_eq!(block_range_prefix(2500), 2000);
        assert_eq!(block_range_prefix(9999), 9000);
        assert_eq!(block_range_prefix(10000), 10000);
    }

    #[test]
    fn object_keys_use_expected_layout() {
        let (block_key, attr_key, num_key) = object_keys(2500, "0xblock", "0xparent", "0xattr");
        assert_eq!(block_key, "block/2000_2999/2500.0xblock");
        assert_eq!(attr_key, "attr/2000_2999/0xparent.0xattr");
        assert_eq!(num_key, "num/2000_2999/2500");
    }

    /// Golden wire vector: the key of a real migrated mainnet object, transcribed from the
    /// production R2 bucket — not generated by this code — so the key template is certified
    /// against the bytes actually in R2 rather than against itself.
    #[test]
    fn block_object_key_matches_migrated_mainnet_object() {
        assert_eq!(
            block_object_key(
                6_632_136,
                "0x05dd41e545b25db0ce04f628e6e1705232240c70a0435c8233ac4479176fe6b0",
            ),
            "block/6632000_6632999/6632136.\
             0x05dd41e545b25db0ce04f628e6e1705232240c70a0435c8233ac4479176fe6b0",
        );
    }

    /// The write path's block key must stay byte-identical to the read path's — both must go
    /// through [`block_object_key`].
    #[test]
    fn object_keys_block_key_delegates_to_block_object_key() {
        let (block_key, _, _) = object_keys(2500, "0xblock", "0xparent", "0xattr");
        assert_eq!(block_key, block_object_key(2500, "0xblock"));
    }

    #[test]
    fn pointer_body_is_number_dot_hash() {
        assert_eq!(pointer_body(2500, "0xblock"), "2500.0xblock");
    }

    #[test]
    fn witness_metadata_emits_expected_headers() {
        let meta = witness_metadata(4096, 1024, "0xparent", "0xattr");
        assert_eq!(
            meta,
            vec![
                ("x-amz-meta-compression".to_string(), "zstd".to_string()),
                ("x-amz-meta-original-size".to_string(), "4096".to_string()),
                ("x-amz-meta-compressed-size".to_string(), "1024".to_string()),
                ("x-amz-meta-parent-hash".to_string(), "0xparent".to_string()),
                ("x-amz-meta-attr-hash".to_string(), "0xattr".to_string()),
            ]
        );
    }
}
