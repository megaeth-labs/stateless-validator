//! Serialization helpers for redb-stored data.
//!
//! Two formats are used:
//! - `encode_to_vec` / `decode_from_slice`: bincode standard + lz4 compression with a marker byte,
//!   for contracts and light witnesses.
//! - `encode_block_to_vec` / `decode_block_from_slice`: plain JSON for full blocks.

use alloy_rpc_types_eth::Block;
use op_alloy_rpc_types::Transaction;
use stateless_core::db::{StoreError, StoreResult, StoreResultExt};

/// Marker byte prepended to lz4-compressed bincode data.
pub const BINCODE_LZ4_MARKER: u8 = 0x01;

/// Serializes data using bincode + lz4 compression.
/// Format: [marker byte][lz4 compressed bincode data]
pub fn encode_to_vec<T: serde::Serialize>(data: &T) -> StoreResult<Vec<u8>> {
    let encoded = bincode::serde::encode_to_vec(data, bincode::config::standard()).store_err()?;
    let compressed = lz4_flex::compress_prepend_size(&encoded);

    let mut result = Vec::with_capacity(1 + compressed.len());
    result.push(BINCODE_LZ4_MARKER);
    result.extend(compressed);
    Ok(result)
}

/// Deserializes lz4-compressed bincode data written by [`encode_to_vec`].
pub fn decode_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StoreResult<T> {
    if bytes.is_empty() {
        return Err(StoreError::Corrupt("cannot deserialize empty data".into()));
    }
    if bytes[0] != BINCODE_LZ4_MARKER {
        return Err(StoreError::Corrupt(format!("unknown serialization marker: {:#04x}", bytes[0])));
    }
    let decompressed = lz4_flex::decompress_size_prepended(&bytes[1..])
        .map_err(|e| StoreError::Corrupt(format!("lz4 decompress: {e}")))?;
    // Bincode failure on already-decompressed bytes is corruption (or a schema drift),
    // not a backend I/O error — classify accordingly so operators can triage from the log.
    let (decoded, _) =
        bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())
            .map_err(|e| StoreError::Corrupt(format!("bincode decode: {e}")))?;
    Ok(decoded)
}

/// Serializes Block<Transaction> using JSON.
pub fn encode_block_to_vec(block: &Block<Transaction>) -> StoreResult<Vec<u8>> {
    serde_json::to_vec(block).store_err()
}

/// Deserializes Block<Transaction> from JSON bytes.
pub fn decode_block_from_slice(bytes: &[u8]) -> StoreResult<Block<Transaction>> {
    serde_json::from_slice(bytes)
        .map_err(|e| StoreError::Corrupt(format!("block json decode: {e}")))
}

#[cfg(test)]
mod tests {
    use revm::state::Bytecode;

    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let bytecode = Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[
            0x60, 0x00, 0x60, 0x01, 0x01,
        ]));
        let encoded = encode_to_vec(&bytecode).unwrap();

        assert_eq!(encoded[0], BINCODE_LZ4_MARKER);

        let decoded: Bytecode = decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded.bytes_slice(), bytecode.bytes_slice());
    }

    #[test]
    fn test_decode_from_slice_empty_data() {
        let result = decode_from_slice::<Bytecode>(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty data"));
    }

    #[test]
    fn test_decode_from_slice_wrong_marker() {
        let result = decode_from_slice::<Bytecode>(&[0xFF, 0x00]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown serialization marker"));
    }

    #[test]
    fn test_decode_from_slice_corrupted_lz4() {
        let result = decode_from_slice::<Bytecode>(&[BINCODE_LZ4_MARKER, 0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("lz4"));
    }
}
