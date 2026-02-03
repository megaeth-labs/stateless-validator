//! Fast witness deserialization for tracing/execution.
//!
//! This module provides a fast witness type that skips expensive cryptographic
//! point validation during deserialization. The standard `SaltWitness` type
//! deserializes `SerdeCommitment` which calls `Element::from_bytes()` for
//! elliptic curve point validation - this is slow (~240ms for large witnesses).
//!
//! For debug-trace-server, we only need the state data (`kvs`) and bucket levels
//! (`proof.levels`) for execution. We don't need the cryptographic proofs since
//! we trust our own database.
//!
//! ## Performance
//!
//! - Standard `SaltWitness` deserialization: ~240ms (due to EC point validation)
//! - `FastWitness` deserialization: ~10-20ms (skips EC point validation)

use rustc_hash::FxHashMap;
use salt::{BucketId, BucketMeta, SaltKey, SaltValue, bucket_metadata_key, traits::StateReader};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    ops::RangeInclusive,
};

/// Fast witness that only contains data needed for execution.
///
/// This struct mirrors `SaltWitness` but stores proof data as raw bytes
/// instead of deserializing the expensive `SerdeCommitment` types.
#[derive(Clone, Debug)]
pub struct FastWitness {
    /// All witnessed key-value pairs (same as SaltWitness.kvs)
    pub kvs: BTreeMap<SaltKey, Option<SaltValue>>,
    /// Bucket subtree levels (same as SaltProof.levels)
    pub levels: FxHashMap<BucketId, u8>,
}

/// Raw proof structure for fast deserialization.
///
/// We deserialize `parents_commitments` and `proof` as raw bytes to skip
/// the expensive elliptic curve point validation.
#[derive(Deserialize)]
struct FastSaltProof {
    /// Raw bytes for parent commitments - we skip deserializing these
    #[serde(deserialize_with = "skip_btree_map")]
    #[allow(dead_code)]
    parents_commitments: (),
    /// Raw bytes for the IPA proof - we skip deserializing this
    #[serde(deserialize_with = "skip_vec")]
    #[allow(dead_code)]
    proof: (),
    /// Bucket levels - this is cheap to deserialize and needed for execution
    pub levels: FxHashMap<BucketId, u8>,
}

/// Deserialize helper that skips a BTreeMap<u64, [u8; 32]> without EC validation.
fn skip_btree_map<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    // BTreeMap is serialized as a sequence of (key, value) pairs with length prefix
    // We need to read the length and skip that many (u64, [u8; 32]) pairs
    let map: BTreeMap<u64, [u8; 32]> = BTreeMap::deserialize(deserializer)?;
    let _ = map; // Just discard it
    Ok(())
}

/// Deserialize helper that skips a Vec<u8>.
fn skip_vec<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let vec: Vec<u8> = Vec::deserialize(deserializer)?;
    let _ = vec;
    Ok(())
}

/// Fast deserializable witness structure.
#[derive(Deserialize)]
struct FastSaltWitness {
    pub kvs: BTreeMap<SaltKey, Option<SaltValue>>,
    pub proof: FastSaltProof,
}

impl FastWitness {
    /// Deserialize from bincode bytes, skipping expensive EC point validation.
    ///
    /// This is much faster than deserializing `SaltWitness` directly because
    /// it skips the `Element::from_bytes()` calls for elliptic curve points.
    pub fn from_bincode_standard(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        let (fast_witness, _): (FastSaltWitness, _) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;

        Ok(Self {
            kvs: fast_witness.kvs,
            levels: fast_witness.proof.levels,
        })
    }

    /// Deserialize from bincode legacy format bytes.
    pub fn from_bincode_legacy(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        let (fast_witness, _): (FastSaltWitness, _) =
            bincode::serde::decode_from_slice(bytes, bincode::config::legacy())?;

        Ok(Self {
            kvs: fast_witness.kvs,
            levels: fast_witness.proof.levels,
        })
    }
}

/// Error type for FastWitness StateReader operations
#[derive(Debug, Clone)]
pub struct FastWitnessError {
    pub message: &'static str,
}

impl std::fmt::Display for FastWitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FastWitnessError {}

impl StateReader for FastWitness {
    type Error = FastWitnessError;

    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        match self.kvs.get(&key) {
            Some(Some(value)) => Ok(Some(value.clone())),
            Some(None) => Ok(None),
            None => Err(FastWitnessError {
                message: "Key not in witness",
            }),
        }
    }

    fn entries(
        &self,
        _range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Err(FastWitnessError {
            message: "Range queries not supported",
        })
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let metadata_key = bucket_metadata_key(bucket_id);
        match self.kvs.get(&metadata_key) {
            Some(Some(salt_value)) => BucketMeta::try_from(salt_value.clone()).map_err(|_| {
                FastWitnessError {
                    message: "Failed to decode metadata",
                }
            }),
            Some(None) => unreachable!("Metadata should never be stored as None in witness"),
            None => Err(FastWitnessError {
                message: "Metadata not in witness",
            }),
        }
    }

    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        use salt::is_valid_data_bucket;

        if !is_valid_data_bucket(bucket_id) {
            return Ok(0);
        }

        let metadata = self.metadata(bucket_id)?;
        let capacity = metadata.capacity;

        let mut used_count = 0u64;
        for slot in 0..capacity {
            let salt_key = SaltKey::from((bucket_id, slot));
            if self.value(salt_key)?.is_some() {
                used_count += 1;
            }
        }

        Ok(used_count)
    }

    fn plain_value_fast(&self, _plain_key: &[u8]) -> Result<SaltKey, Self::Error> {
        Err(FastWitnessError {
            message: "plain_value_fast not supported",
        })
    }

    fn get_subtree_levels(&self, bucket_id: BucketId) -> Result<usize, Self::Error> {
        self.levels
            .get(&bucket_id)
            .map(|&level| level as usize)
            .ok_or(FastWitnessError {
                message: "Bucket root not in witness",
            })
    }
}

/// Fast witness executor that wraps FastWitness for execution.
///
/// This mirrors the `salt::Witness` struct but uses `FastWitness` internally
/// instead of `SaltWitness`. It provides the same `StateReader` interface
/// but with faster deserialization.
#[derive(Clone, Debug)]
pub struct FastWitnessExecutor {
    /// Direct mapping from plain keys to their salt key locations.
    /// Only contains keys that exist.
    direct_lookup_tbl: std::collections::HashMap<Vec<u8>, SaltKey>,
    /// The underlying fast witness
    fast_witness: FastWitness,
}

impl From<FastWitness> for FastWitnessExecutor {
    fn from(fast_witness: FastWitness) -> Self {
        let mut direct_lookup_tbl = std::collections::HashMap::new();
        for (salt_key, value) in &fast_witness.kvs {
            if salt_key.is_in_meta_bucket() {
                continue;
            }

            if let Some(salt_value) = value {
                let plain_key = salt_value.key().to_vec();
                direct_lookup_tbl.insert(plain_key, *salt_key);
            }
        }

        Self {
            direct_lookup_tbl,
            fast_witness,
        }
    }
}

impl StateReader for FastWitnessExecutor {
    type Error = FastWitnessError;

    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        self.fast_witness.value(key)
    }

    fn entries(
        &self,
        range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        self.fast_witness.entries(range)
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        self.fast_witness.metadata(bucket_id)
    }

    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        self.fast_witness.bucket_used_slots(bucket_id)
    }

    fn plain_value_fast(&self, plain_key: &[u8]) -> Result<SaltKey, Self::Error> {
        match self.direct_lookup_tbl.get(plain_key) {
            Some(salt_key) => Ok(*salt_key),
            None => Err(FastWitnessError {
                message: "Plain key not in witness",
            }),
        }
    }

    fn get_subtree_levels(&self, bucket_id: BucketId) -> Result<usize, Self::Error> {
        self.fast_witness.get_subtree_levels(bucket_id)
    }
}

impl FastWitnessExecutor {
    /// Get the underlying kvs map
    pub fn kvs(&self) -> &BTreeMap<SaltKey, Option<SaltValue>> {
        &self.fast_witness.kvs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_witness_empty() {
        let fast = FastWitness {
            kvs: BTreeMap::new(),
            levels: FxHashMap::default(),
        };
        assert!(fast.kvs.is_empty());
        assert!(fast.levels.is_empty());
    }
}
