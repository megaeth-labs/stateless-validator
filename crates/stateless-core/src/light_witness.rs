//! Light witness deserialization for tracing/execution.
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
//! - `LightWitness` deserialization: ~10-20ms (skips EC point validation)

use std::{collections::BTreeMap, ops::RangeInclusive};

use rustc_hash::FxHashMap;
use salt::{BucketId, BucketMeta, SaltKey, SaltValue, bucket_metadata_key, traits::StateReader};
use serde::{Deserialize, Serialize};

/// Light witness that only contains data needed for execution.
///
/// This struct mirrors `SaltWitness` but stores proof data as raw bytes
/// instead of deserializing the expensive `SerdeCommitment` types.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightWitness {
    /// All witnessed key-value pairs (same as SaltWitness.kvs)
    pub kvs: BTreeMap<SaltKey, Option<SaltValue>>,
    /// Bucket subtree levels (same as SaltProof.levels)
    pub levels: FxHashMap<BucketId, u8>,
}

/// Convert from SaltWitness to LightWitness.
///
/// Used when fetching witness data from RPC (which returns SaltWitness)
/// to convert to LightWitness for consistent handling.
impl From<salt::SaltWitness> for LightWitness {
    fn from(witness: salt::SaltWitness) -> Self {
        Self { kvs: witness.kvs, levels: witness.proof.levels.into_iter().collect() }
    }
}

/// Error type for LightWitness StateReader operations
#[derive(Debug, Clone)]
pub struct LightWitnessError {
    pub message: &'static str,
}

impl std::fmt::Display for LightWitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for LightWitnessError {}

impl StateReader for LightWitness {
    type Error = LightWitnessError;

    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        match self.kvs.get(&key) {
            Some(Some(value)) => Ok(Some(value.clone())),
            Some(None) => Ok(None),
            None => Err(LightWitnessError { message: "Key not in witness" }),
        }
    }

    fn entries(
        &self,
        _range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Err(LightWitnessError { message: "Range queries not supported" })
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let metadata_key = bucket_metadata_key(bucket_id);
        match self.kvs.get(&metadata_key) {
            Some(Some(salt_value)) => BucketMeta::try_from(salt_value.clone())
                .map_err(|_| LightWitnessError { message: "Failed to decode metadata" }),
            Some(None) => unreachable!("Metadata should never be stored as None in witness"),
            None => Err(LightWitnessError { message: "Metadata not in witness" }),
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
        Err(LightWitnessError { message: "plain_value_fast not supported" })
    }

    fn get_subtree_levels(&self, bucket_id: BucketId) -> Result<usize, Self::Error> {
        self.levels
            .get(&bucket_id)
            .map(|&level| level as usize)
            .ok_or(LightWitnessError { message: "Bucket root not in witness" })
    }
}

/// Light witness executor that wraps LightWitness for execution.
///
/// This mirrors the `salt::Witness` struct but uses `LightWitness` internally
/// instead of `SaltWitness`. It provides the same `StateReader` interface
/// but with faster deserialization.
#[derive(Clone, Debug)]
pub struct LightWitnessExecutor {
    /// Direct mapping from plain keys to their salt key locations.
    /// Only contains keys that exist.
    direct_lookup_tbl: std::collections::HashMap<Vec<u8>, SaltKey>,
    /// The underlying fast witness
    light_witness: LightWitness,
}

impl From<LightWitness> for LightWitnessExecutor {
    fn from(light_witness: LightWitness) -> Self {
        let mut direct_lookup_tbl = std::collections::HashMap::new();
        for (salt_key, value) in &light_witness.kvs {
            if salt_key.is_in_meta_bucket() {
                continue;
            }

            if let Some(salt_value) = value {
                let plain_key = salt_value.key().to_vec();
                direct_lookup_tbl.insert(plain_key, *salt_key);
            }
        }

        Self { direct_lookup_tbl, light_witness }
    }
}

impl StateReader for LightWitnessExecutor {
    type Error = LightWitnessError;

    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        self.light_witness.value(key)
    }

    fn entries(
        &self,
        range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        self.light_witness.entries(range)
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        self.light_witness.metadata(bucket_id)
    }

    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        self.light_witness.bucket_used_slots(bucket_id)
    }

    fn plain_value_fast(&self, plain_key: &[u8]) -> Result<SaltKey, Self::Error> {
        match self.direct_lookup_tbl.get(plain_key) {
            Some(salt_key) => Ok(*salt_key),
            None => Err(LightWitnessError { message: "Plain key not in witness" }),
        }
    }

    fn get_subtree_levels(&self, bucket_id: BucketId) -> Result<usize, Self::Error> {
        self.light_witness.get_subtree_levels(bucket_id)
    }
}

impl LightWitnessExecutor {
    /// Get the underlying kvs map
    pub fn kvs(&self) -> &BTreeMap<SaltKey, Option<SaltValue>> {
        &self.light_witness.kvs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_light_witness_empty() {
        let fast = LightWitness { kvs: BTreeMap::new(), levels: FxHashMap::default() };
        assert!(fast.kvs.is_empty());
        assert!(fast.levels.is_empty());
    }
}
