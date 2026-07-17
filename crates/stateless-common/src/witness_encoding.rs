//! Shared witness wire-format helpers for RPC producers and consumers.
//!
//! This module encodes and decodes the temporary compatibility contract used by
//! `mega_getBlockWitness`:
//! `v0:base64(zstd(bincode-legacy((SaltWitness, MptWitness))))`.
//! The zstd level is a producer choice (see [`WITNESS_ZSTD_LEVEL`]); decoding is level-agnostic.

use std::io;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use salt::SaltWitness;
use stateless_core::{LightWitness, LightWitnessFromSalt, withdrawals::MptWitness};

/// Version prefix for the RPC response format:
/// `"v0:" + base64(zstd(bincode-legacy((SaltWitness, MptWitness))))`.
pub const WITNESS_RESPONSE_VERSION_PREFIX: &str = "v0:";

/// zstd compression level used when encoding a witness payload.
///
/// Level 1: a witness is ~half high-entropy SALT proof, so higher levels cost several times
/// more CPU for a few percent less output (see `benches/witness_zstd_level.rs`), and the HTTP
/// transport compression recovers most of that difference anyway.
pub const WITNESS_ZSTD_LEVEL: i32 = 1;

/// Errors produced while serializing or compressing a witness payload.
#[derive(Debug, thiserror::Error)]
pub enum WitnessEncodingError {
    #[error("failed to serialize witness: {0}")]
    Serialize(#[from] bincode::error::EncodeError),
    #[error("failed to compress witness payload: {0}")]
    Compress(#[from] io::Error),
}

/// Errors produced while decoding a witness payload or RPC response.
#[derive(Debug, thiserror::Error)]
pub enum WitnessDecodingError {
    #[error("witness response missing '{WITNESS_RESPONSE_VERSION_PREFIX}' prefix")]
    MissingPrefix,
    #[error("failed to decode witness base64 payload: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("failed to decompress witness payload: {0}")]
    Decompress(#[from] io::Error),
    #[error("failed to deserialize witness: {0}")]
    Deserialize(#[from] bincode::error::DecodeError),
}

/// Serializes and compresses the witness tuple into the binary payload carried by
/// the versioned RPC response.
///
/// Returns `(uncompressed_size, compressed_payload)`. `uncompressed_size` is the length of
/// the bincode-serialized tuple *before* zstd compression; producers use it on the upload
/// path for compression-ratio statistics. [`encode_witness_response`] discards it.
pub fn encode_witness_payload(
    salt_witness: &SaltWitness,
    withdrawal_witness: &MptWitness,
) -> Result<(usize, Vec<u8>), WitnessEncodingError> {
    let original_data = bincode::serde::encode_to_vec(
        (salt_witness, withdrawal_witness),
        bincode::config::legacy(),
    )?;
    let original_size = original_data.len();
    let compressed = zstd::encode_all(original_data.as_slice(), WITNESS_ZSTD_LEVEL)?;
    Ok((original_size, compressed))
}

/// Decompresses and deserializes the binary payload carried by the versioned RPC
/// response.
pub fn decode_witness_payload(
    compressed: &[u8],
) -> Result<(SaltWitness, MptWitness), WitnessDecodingError> {
    decode_payload_as(compressed)
}

/// Zero-validation counterpart of [`decode_witness_payload`]: decodes only the
/// light witness (kvs + levels) from the same payload bytes, skipping all
/// elliptic-curve work (see `stateless_core::light_witness` for the safety
/// model). On a large mainnet witness: ~21x less wall time and ~230x less CPU
/// than the full decode (~125 ms / ~1.4 core·s vs ~6 ms single-threaded).
pub fn decode_witness_payload_light(
    compressed: &[u8],
) -> Result<(LightWitness, MptWitness), WitnessDecodingError> {
    let (light, mpt): (LightWitnessFromSalt, MptWitness) = decode_payload_as(compressed)?;
    Ok((light.0, mpt))
}

/// Shared payload decode: zstd, then bincode-legacy into the caller-chosen target — the one
/// place that fixes the wire config for both the full and the light payload decode.
fn decode_payload_as<T: serde::de::DeserializeOwned>(
    compressed: &[u8],
) -> Result<T, WitnessDecodingError> {
    let decompressed = zstd::decode_all(compressed)?;
    let (value, _) = bincode::serde::decode_from_slice(&decompressed, bincode::config::legacy())?;
    Ok(value)
}

/// Encodes the witness tuple as a versioned RPC response string.
pub fn encode_witness_response(
    salt_witness: &SaltWitness,
    withdrawal_witness: &MptWitness,
) -> Result<String, WitnessEncodingError> {
    let (_, compressed) = encode_witness_payload(salt_witness, withdrawal_witness)?;
    Ok(format!("{WITNESS_RESPONSE_VERSION_PREFIX}{}", BASE64.encode(compressed)))
}

/// Decodes a versioned RPC response string into the witness tuple.
pub fn decode_witness_response(
    response: &str,
) -> Result<(SaltWitness, MptWitness), WitnessDecodingError> {
    decode_response_with(response, decode_witness_payload)
}

/// Zero-validation counterpart of [`decode_witness_response`]: decodes only
/// the light witness from a versioned RPC response.
pub fn decode_witness_response_light(
    response: &str,
) -> Result<(LightWitness, MptWitness), WitnessDecodingError> {
    decode_response_with(response, decode_witness_payload_light)
}

/// Shared response prologue: strip the version prefix and base64-decode, then hand the
/// compressed payload to the caller-chosen decoder — the one place that fixes the response
/// framing for both the full and the light decode.
fn decode_response_with<T>(
    response: &str,
    decode_payload: fn(&[u8]) -> Result<T, WitnessDecodingError>,
) -> Result<T, WitnessDecodingError> {
    let payload = response
        .strip_prefix(WITNESS_RESPONSE_VERSION_PREFIX)
        .ok_or(WitnessDecodingError::MissingPrefix)?;
    let compressed = BASE64.decode(payload)?;
    decode_payload(&compressed)
}

#[cfg(test)]
mod tests {
    use stateless_test_utils::fixtures::TestFixtures;

    use super::*;

    fn first_fixture_witness() -> (SaltWitness, MptWitness) {
        let fixtures = TestFixtures::mainnet();
        let (_, hash) = fixtures
            .paired_blocks()
            .into_iter()
            .next()
            .expect("mainnet fixtures should contain paired witnesses");
        (fixtures.salt_witnesses[&hash].clone(), fixtures.mpt_witness(&hash))
    }

    #[test]
    fn encode_witness_payload_roundtrip() {
        let (salt_witness, mpt_witness) = first_fixture_witness();

        let (original_size, compressed) = encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("compression should succeed");
        let decompressed =
            zstd::decode_all(compressed.as_slice()).expect("decompression should succeed");
        let (decoded, _): ((SaltWitness, MptWitness), usize) =
            bincode::serde::decode_from_slice(&decompressed, bincode::config::legacy())
                .expect("deserialization should succeed");

        assert_eq!(original_size, decompressed.len());
        assert_eq!(decoded.0, salt_witness);
        assert_eq!(decoded.1, mpt_witness);
    }

    #[test]
    fn encode_witness_response_roundtrip() {
        let (salt_witness, mpt_witness) = first_fixture_witness();

        let encoded =
            encode_witness_response(&salt_witness, &mpt_witness).expect("encoding should succeed");
        let decoded = decode_witness_response(&encoded).expect("decoding should succeed");

        assert_eq!(decoded.0, salt_witness);
        assert_eq!(decoded.1, mpt_witness);
    }

    /// Same payload bytes, light decode: equal to the light parts of the full
    /// decode, without touching any curve point.
    #[test]
    fn decode_witness_payload_light_matches_full() {
        let (salt_witness, mpt_witness) = first_fixture_witness();
        let (_, compressed) = encode_witness_payload(&salt_witness, &mpt_witness)
            .expect("compression should succeed");

        let (light, mpt) =
            decode_witness_payload_light(&compressed).expect("light decode should succeed");

        assert_eq!(light, LightWitness::from(&salt_witness));
        assert_eq!(mpt, mpt_witness);
    }

    /// Response-level light decode agrees with the full decode.
    #[test]
    fn decode_witness_response_light_matches_full() {
        let (salt_witness, mpt_witness) = first_fixture_witness();
        let encoded =
            encode_witness_response(&salt_witness, &mpt_witness).expect("encoding should succeed");

        let (light, mpt) =
            decode_witness_response_light(&encoded).expect("light decode should succeed");

        assert_eq!(light, LightWitness::from(&salt_witness));
        assert_eq!(mpt, mpt_witness);
    }

    /// The committed real-mainnet payload (block 6906405, ~6.3 MiB
    /// uncompressed, 65k commitments) light-decodes to exactly the light
    /// parts of its full decode — the end-to-end ".zst → light witness" lock.
    #[test]
    fn big_mainnet_zst_light_decodes() {
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../test_data/mainnet/bench/6906405.zst");
        let compressed = std::fs::read(path).expect("read committed bench payload");

        let (full_salt, full_mpt) =
            decode_witness_payload(&compressed).expect("full decode should succeed");
        let (light, mpt) =
            decode_witness_payload_light(&compressed).expect("light decode should succeed");

        assert_eq!(light, LightWitness::from(&full_salt));
        assert_eq!(mpt, full_mpt);
        assert!(!light.kvs.is_empty());
    }

    #[test]
    fn decode_witness_response_requires_prefix() {
        let err = decode_witness_response("not-versioned").expect_err("missing prefix should fail");
        assert!(matches!(err, WitnessDecodingError::MissingPrefix));
    }

    #[test]
    fn decode_witness_response_invalid_base64() {
        let err = decode_witness_response("v0:!!!").expect_err("invalid base64 should fail");
        assert!(matches!(err, WitnessDecodingError::Base64(_)));
    }

    #[test]
    fn decode_witness_response_invalid_payload() {
        let err = decode_witness_response("v0:AAAA").expect_err("corrupt payload should fail");
        assert!(matches!(err, WitnessDecodingError::Decompress(_)));
    }

    #[test]
    fn decode_witness_response_invalid_witness() {
        // Valid base64 and a valid zstd frame, but the decompressed bytes are not a
        // bincode-encoded `(SaltWitness, MptWitness)` tuple.
        let compressed =
            zstd::encode_all(&b"not a witness"[..], 9).expect("compression should succeed");
        let response = format!("{WITNESS_RESPONSE_VERSION_PREFIX}{}", BASE64.encode(compressed));
        let err = decode_witness_response(&response).expect_err("corrupt witness should fail");
        assert!(matches!(err, WitnessDecodingError::Deserialize(_)));
    }
}
