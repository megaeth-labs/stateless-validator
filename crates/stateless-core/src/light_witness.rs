//! Light witness deserialization for tracing/execution.
//!
//! Execution-only consumers (e.g. debug-trace-server) read
//! state from a witness but never verify its cryptographic proof. This module
//! provides [`LightWitness`] — just the witnessed key-values and bucket
//! subtree levels — plus two ways to obtain it cheaply:
//!
//! - [`LightWitness::from`] an already-decoded `SaltWitness` (copies only the light parts), and
//! - [`LightWitnessFromSalt`], a serde adapter that decodes the light parts **directly from full
//!   `SaltWitness` bytes**: the proof material is parsed structurally (so the stream stays in sync)
//!   but read as raw bytes and discarded — no curve point is ever constructed or validated.
//!
//! ## Performance
//!
//! The full `SaltWitness` decode runs one `Element::from_bytes` (modular sqrt + subgroup check)
//! per parent commitment; on large witnesses that elliptic-curve work dominates the decode even
//! though salt parallelizes it across cores. The light decode skips all of it and is orders of
//! magnitude cheaper, single-threaded.
//!
//! ## Safety model
//!
//! The zero-validation path performs no cryptographic checks: corrupt or
//! malicious proof bytes decode successfully. Only use it where witness
//! integrity is guaranteed elsewhere (trusted local storage, or a stream a
//! validator has already verified). Never use it on the proof-verification
//! path.

use core::{fmt, ops::RangeInclusive};
use std::{collections::BTreeMap, vec::Vec};

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;
use salt::{
    BucketId, BucketMeta, NodeId, SaltKey, SaltValue, bucket_metadata_key, traits::StateReader,
};
use serde::{Deserialize, Deserializer, Serialize};

type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;

/// Light witness that only contains data needed for execution.
///
/// The derived `Serialize`/`Deserialize` round-trip this two-field struct in
/// its own compact layout (used for local storage, e.g. the trace server DB).
/// To decode from full `SaltWitness` bytes instead, use
/// [`LightWitnessFromSalt`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LightWitness {
    /// All witnessed key-value pairs (same as SaltWitness.kvs)
    pub kvs: BTreeMap<SaltKey, Option<SaltValue>>,
    /// Bucket subtree levels (same as SaltProof.levels).
    ///
    /// Routed through [`salt::fx_hashmap_serde`] so we don't have to enable
    /// `hashbrown/serde` (introduced when its transitive `serde_core 1.0.221+`
    /// broke the then-current `alloy-tx-macros 1.0.23`; the indirection stays
    /// so the workspace keeps control over what `hashbrown` pulls in).
    #[serde(with = "salt::fx_hashmap_serde")]
    pub levels: FxHashMap<BucketId, u8>,
}

/// Convert from &SaltWitness to LightWitness.
///
/// Clones only `kvs` and `levels` — the two fields needed for execution —
/// without cloning the heavy cryptographic proof data (`parents_commitments`,
/// IPA proof).
impl From<&salt::SaltWitness> for LightWitness {
    fn from(witness: &salt::SaltWitness) -> Self {
        Self { kvs: witness.kvs.clone(), levels: witness.proof.levels.clone() }
    }
}

/// Newtype adapter whose `Deserialize` impl consumes a full `SaltWitness`
/// stream and keeps only the light parts, skipping all elliptic-curve work
/// (see the module docs for the safety model).
///
/// Use it positionally wherever full witness bytes are decoded, e.g.
/// `bincode::serde::decode_from_slice::<(LightWitnessFromSalt, MptWitness), _>(..)`
/// against bytes produced from `(SaltWitness, MptWitness)`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LightWitnessFromSalt(pub LightWitness);

impl<'de> Deserialize<'de> for LightWitnessFromSalt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        from_salt_witness::deserialize(deserializer).map(Self)
    }
}

/// Decoding of a [`LightWitness`] from a full-`SaltWitness` serde stream —
/// the implementation behind [`LightWitnessFromSalt`] (the only public
/// surface; make this module public if a `#[serde(deserialize_with = ...)]`
/// consumer ever appears).
///
/// The mirror types below must stay field-for-field congruent with
/// `salt::SaltWitness` / `salt::SaltProof` (same field names, order, and wire
/// shapes); the fixture tests in this module lock that in against real
/// mainnet witnesses.
mod from_salt_witness {
    use serde::de::{MapAccess, Visitor};

    use super::*;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<LightWitness, D::Error> {
        let mirror = WitnessMirror::deserialize(d)?;
        Ok(LightWitness { kvs: mirror.kvs, levels: mirror.proof.levels })
    }

    /// Serde-layout mirror of `salt::SaltWitness`.
    #[derive(Deserialize)]
    struct WitnessMirror {
        kvs: BTreeMap<SaltKey, Option<SaltValue>>,
        proof: ProofMirror,
    }

    /// Serde-layout mirror of `salt::SaltProof`. Proof material is consumed as
    /// raw bytes and dropped; only `levels` is materialized.
    #[derive(Deserialize)]
    struct ProofMirror {
        #[serde(deserialize_with = "discard_parents_commitments")]
        #[allow(dead_code)]
        parents_commitments: (),
        #[serde(deserialize_with = "discard_ipa_proof_bytes")]
        #[allow(dead_code)]
        proof: (),
        #[serde(with = "salt::fx_hashmap_serde")]
        levels: FxHashMap<BucketId, u8>,
    }

    /// Consumes the `NodeId -> [u8; 32]` commitments map without building
    /// anything: no `BTreeMap`, no `Element::from_bytes`, no subgroup checks.
    fn discard_parents_commitments<'de, D: Deserializer<'de>>(d: D) -> Result<(), D::Error> {
        struct DiscardMap;

        impl<'de> Visitor<'de> for DiscardMap {
            type Value = ();

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of NodeId to 32-byte compressed commitments")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<(), A::Error> {
                while access.next_entry::<NodeId, [u8; 32]>()?.is_some() {}
                Ok(())
            }
        }

        d.deserialize_map(DiscardMap)
    }

    /// Consumes the IPA proof exactly as it was written (`SerdeMultiPointProof`
    /// serializes its `to_bytes()` output as a `Vec<u8>`) without calling
    /// `MultiPointProof::from_bytes`.
    fn discard_ipa_proof_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<(), D::Error> {
        Vec::<u8>::deserialize(d).map(drop)
    }
}

/// Error type for LightWitness StateReader operations
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct LightWitnessError {
    pub message: &'static str,
}

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
            // A well-formed witness never maps a metadata key to a deletion,
            // but witness bytes are network input (and the light decode
            // validates nothing) — this must be an error, not a panic: a
            // panic here takes down the whole consumer (e.g. an RPC handler
            // task) on one corrupt response.
            Some(None) => {
                Err(LightWitnessError { message: "Corrupt witness: metadata key maps to None" })
            }
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
    direct_lookup_tbl: HashMap<Vec<u8>, SaltKey>,
    /// The underlying fast witness
    light_witness: LightWitness,
}

impl From<LightWitness> for LightWitnessExecutor {
    fn from(light_witness: LightWitness) -> Self {
        let mut direct_lookup_tbl = HashMap::default();
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
    // `std` is the `alloc` alias in no_std builds, where the prelude carries
    // no `vec!` — import it explicitly (same as chain_spec.rs).
    use std::vec;

    use super::*;

    #[test]
    fn test_light_witness_empty() {
        let fast = LightWitness { kvs: BTreeMap::new(), levels: FxHashMap::default() };
        assert!(fast.kvs.is_empty());
        assert!(fast.levels.is_empty());
    }

    /// A corrupt witness that maps a bucket's metadata key to `None` must
    /// surface as a `StateReader` error, not a panic: witness bytes are
    /// unvalidated network input on the light path, and a panic here kills
    /// the whole consumer (e.g. an RPC handler) instead of failing one
    /// request.
    #[test]
    fn metadata_key_mapped_to_none_is_an_error_not_a_panic() {
        // First valid data-bucket id (bucket_metadata_key asserts the range).
        let bucket: BucketId = 65536;
        let mut kvs: BTreeMap<SaltKey, Option<SaltValue>> = BTreeMap::new();
        kvs.insert(bucket_metadata_key(bucket), None);
        let witness = LightWitness { kvs, levels: FxHashMap::default() };

        let err = witness.metadata(bucket).expect_err("must not panic");
        assert!(err.message.contains("Corrupt witness"), "got: {err}");
    }

    /// Round-trip a populated `LightWitness` through bincode to confirm the
    /// `#[serde(with = "salt::fx_hashmap_serde")]` wiring on the `levels`
    /// field actually works end-to-end. The adapter itself is covered by
    /// salt's own tests; this test just guards the integration.
    #[test]
    fn round_trip_through_bincode() {
        let mut levels: FxHashMap<BucketId, u8> = HashMap::with_hasher(FxBuildHasher);
        for (k, v) in [(0u32, 0u8), (42, 3), (1_000_000, 7), (BucketId::MAX, 255)] {
            levels.insert(k, v);
        }
        let original = LightWitness { kvs: BTreeMap::new(), levels };

        let bytes = bincode::serde::encode_to_vec(&original, bincode::config::standard()).unwrap();
        let (decoded, _): (LightWitness, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();

        assert_eq!(original.kvs, decoded.kvs);
        assert_eq!(original.levels.len(), decoded.levels.len());
        for (k, v) in &original.levels {
            assert_eq!(decoded.levels.get(k), Some(v));
        }
    }

    /// Every real mainnet fixture witness light-decodes from the exact bytes
    /// of its full encoding (wire config, bincode legacy), consuming the
    /// stream to the last byte. This is the layout-congruence lock for the
    /// mirror types in [`from_salt_witness`].
    #[test]
    fn light_decodes_from_full_witness_bytes() {
        let fixtures = stateless_test_utils::fixtures::TestFixtures::mainnet_shared();
        assert!(!fixtures.salt_witnesses.is_empty(), "no fixture witnesses");

        for (hash, witness) in &fixtures.salt_witnesses {
            let bytes = bincode::serde::encode_to_vec(witness, bincode::config::legacy()).unwrap();
            let (light, consumed): (LightWitnessFromSalt, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
                    .unwrap_or_else(|e| panic!("light decode {hash}: {e}"));

            assert_eq!(consumed, bytes.len(), "{hash} light decode left trailing bytes");
            assert_eq!(light.0, LightWitness::from(witness), "{hash} light parts mismatch");
            assert!(!light.0.kvs.is_empty(), "{hash} decoded no kvs");
        }
    }

    /// The layout mirror is bincode-config-agnostic (varint vs fixint).
    #[test]
    fn light_decode_is_config_agnostic() {
        let fixtures = stateless_test_utils::fixtures::TestFixtures::mainnet_shared();
        let witness = fixtures.salt_witnesses.values().next().unwrap();

        let bytes = bincode::serde::encode_to_vec(witness, bincode::config::standard()).unwrap();
        let (light, _): (LightWitnessFromSalt, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();

        assert_eq!(light.0, LightWitness::from(witness));
    }

    /// The point of the light path: proof bytes are NOT validated. A stream
    /// whose commitments are not valid curve points fails the full decode but
    /// light-decodes fine.
    #[test]
    fn light_decode_skips_ec_validation() {
        #[derive(Serialize)]
        struct RawWitness {
            kvs: BTreeMap<SaltKey, Option<SaltValue>>,
            proof: RawProof,
        }
        #[derive(Serialize)]
        struct RawProof {
            parents_commitments: BTreeMap<NodeId, [u8; 32]>,
            proof: Vec<u8>,
            #[serde(with = "salt::fx_hashmap_serde")]
            levels: FxHashMap<BucketId, u8>,
        }

        let fixtures = stateless_test_utils::fixtures::TestFixtures::mainnet_shared();
        let real = fixtures.salt_witnesses.values().next().unwrap();
        let raw = RawWitness {
            kvs: real.kvs.clone(),
            proof: RawProof {
                // 0xFF..FF is not a valid compressed banderwagon point.
                parents_commitments: [(7u64, [0xFF; 32]), (9u64, [0xFF; 32])].into(),
                proof: vec![0xAB; 64],
                levels: real.proof.levels.clone(),
            },
        };
        let bytes = bincode::serde::encode_to_vec(&raw, bincode::config::legacy()).unwrap();

        // Full decode rejects the garbage point...
        let full: Result<(salt::SaltWitness, usize), _> =
            bincode::serde::decode_from_slice(&bytes, bincode::config::legacy());
        assert!(full.is_err(), "full decode must validate curve points");

        // ...the light decode never looks at it.
        let (light, _): (LightWitnessFromSalt, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::legacy()).unwrap();
        assert_eq!(light.0.kvs, real.kvs);
        assert_eq!(light.0.levels, real.proof.levels);
    }
}
