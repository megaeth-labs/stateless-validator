//! redb table definitions and raw-tuple conversions for [`BlockMeta`].

use alloy_primitives::{B256, BlockHash};
pub use redb::Database;
use redb::TableDefinition;
use stateless_core::db::BlockMeta;

/// Trusted anchor block. Singleton key "anchor".
/// Value: (block_number, block_hash, post_state_root, post_withdrawals_root).
/// Used by both `ValidatorDB` and `ServerDB`.
#[allow(clippy::type_complexity)]
pub const ANCHOR_BLOCK: TableDefinition<&str, (u64, [u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("anchor_block");

/// Canonical chain. Maps BlockNumber → (BlockHash, PostStateRoot, PostWithdrawalsRoot).
/// Used by both `ValidatorDB` and `ServerDB`.
#[allow(clippy::type_complexity)]
pub const CANONICAL_CHAIN: TableDefinition<u64, ([u8; 32], [u8; 32], [u8; 32])> =
    TableDefinition::new("canonical_chain");

/// Contract bytecode cache. Key: code_hash, Value: bincode+lz4 serialized Bytecode.
/// Used by both `ValidatorDB` and `ServerDB`.
pub const CONTRACTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("contracts");

/// Genesis configuration (write-once). Singleton key "genesis", Value: JSON bytes.
/// Used by `ValidatorDB` only.
pub const GENESIS_CONFIG: TableDefinition<&str, Vec<u8>> = TableDefinition::new("genesis_config");

/// Complete block data. Maps BlockHash → serialized Block<Transaction>.
/// Used by `ServerDB` only.
pub const BLOCK_DATA: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("block_data");

/// Light witness data. Maps BlockHash → serialized LightWitness.
/// Used by `ServerDB` only.
pub const WITNESSES: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("witnesses");

/// Block registry for pruning. Maps (BlockNumber, BlockHash) → ().
/// Used by `ServerDB` only.
pub const BLOCK_RECORDS: TableDefinition<(u64, [u8; 32]), ()> =
    TableDefinition::new("block_records");

/// Default maximum number of entries to retain in CANONICAL_CHAIN.
pub const DEFAULT_MAX_CHAIN_LENGTH: u64 = 1000;

/// Converts a [`BlockMeta`] to a raw tuple for redb storage.
pub fn block_meta_to_tuple(meta: &BlockMeta) -> (u64, [u8; 32], [u8; 32], [u8; 32]) {
    (meta.block_number, meta.block_hash.0, meta.post_state_root.0, meta.post_withdrawals_root.0)
}

/// Reconstructs a [`BlockMeta`] from a raw redb tuple.
pub fn block_meta_from_tuple(t: (u64, [u8; 32], [u8; 32], [u8; 32])) -> BlockMeta {
    BlockMeta {
        block_number: t.0,
        block_hash: BlockHash::from(t.1),
        post_state_root: B256::from(t.2),
        post_withdrawals_root: B256::from(t.3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_meta_tuple_roundtrip() {
        let meta = BlockMeta {
            block_number: 42,
            block_hash: BlockHash::from([42u8; 32]),
            post_state_root: B256::from([142u8; 32]),
            post_withdrawals_root: B256::from([242u8; 32]),
        };
        let tuple = block_meta_to_tuple(&meta);
        let roundtripped = block_meta_from_tuple(tuple);
        assert_eq!(meta, roundtripped);
    }
}
