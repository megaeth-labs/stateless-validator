//! Approximate byte-size estimation for witness payloads.
//!
//! Avoids round-tripping through serialization by computing sizes from the
//! in-memory layout. Used by metrics reporting in both the RPC client
//! (`on_witness_fetch`) and the trace server's data provider.

use salt::SaltWitness;
use stateless_core::{LightWitness, withdrawals::MptWitness};

/// Per-entry size of a SALT key-value pair: `SaltKey` (8 bytes) plus
/// `Option<SaltValue>` (~95 bytes).
const SALT_KV_BYTES: usize = 103;

/// Per-commitment size for SALT parent commitments (64 bytes).
const SALT_COMMITMENT_BYTES: usize = 64;

/// Fixed overhead of the aggregated IPA multipoint proof (~576 bytes).
const SALT_IPA_PROOF_BYTES: usize = 576;

/// Per-level metadata size inside the SALT proof (5 bytes).
const SALT_LEVEL_BYTES: usize = 5;

/// Fixed `storage_root` size inside an MPT witness (32 bytes).
const MPT_STORAGE_ROOT_BYTES: usize = 32;

/// Size breakdown for a `(SaltWitness, MptWitness)` pair.
///
/// Each field is an approximation derived from the in-memory layout
/// constants above, not a serialized byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessSizeBreakdown {
    /// Estimated total SALT witness size (KVs + proof).
    pub salt_size: usize,
    /// Number of key-value entries in the SALT witness.
    pub kvs_count: usize,
    /// Subtotal of just the KV portion of the SALT witness.
    pub salt_kvs_size: usize,
    /// Estimated MPT witness size.
    pub mpt_size: usize,
}

impl WitnessSizeBreakdown {
    /// Computes the breakdown for the given witness pair.
    pub fn new(salt: &SaltWitness, mpt: &MptWitness) -> Self {
        let kvs_count = salt.kvs.len();
        let salt_kvs_size = kvs_count * SALT_KV_BYTES;
        let proof_size = salt.proof.parents_commitments.len() * SALT_COMMITMENT_BYTES +
            SALT_IPA_PROOF_BYTES +
            salt.proof.levels.len() * SALT_LEVEL_BYTES;
        let salt_size = salt_kvs_size + proof_size;
        let mpt_size = MPT_STORAGE_ROOT_BYTES + mpt.state.iter().map(|b| b.len()).sum::<usize>();
        Self { salt_size, kvs_count, salt_kvs_size, mpt_size }
    }

    /// Computes the breakdown for a light-decoded witness.
    ///
    /// A [`LightWitness`] never materializes the parent commitments, so their
    /// contribution is unknowable here and `salt_size` is a lower bound
    /// (KVs + levels + the fixed IPA overhead). Use only for observability on
    /// light-decode paths; full-decode paths should keep [`Self::new`].
    pub fn new_light(light: &LightWitness, mpt: &MptWitness) -> Self {
        let kvs_count = light.kvs.len();
        let salt_kvs_size = kvs_count * SALT_KV_BYTES;
        let proof_size = SALT_IPA_PROOF_BYTES + light.levels.len() * SALT_LEVEL_BYTES;
        let salt_size = salt_kvs_size + proof_size;
        let mpt_size = MPT_STORAGE_ROOT_BYTES + mpt.state.iter().map(|b| b.len()).sum::<usize>();
        Self { salt_size, kvs_count, salt_kvs_size, mpt_size }
    }

    /// Sum of `salt_size + mpt_size`.
    pub fn total(&self) -> usize {
        self.salt_size + self.mpt_size
    }
}

#[cfg(test)]
mod tests {
    use stateless_test_utils::fixtures::TestFixtures;

    use super::*;

    /// `new_light` must agree with the full breakdown on everything except
    /// the parent-commitments term it cannot know: same kv count and MPT
    /// size, and a salt_size that is exactly the full figure minus the
    /// commitments contribution.
    #[test]
    fn light_breakdown_is_the_documented_lower_bound() {
        let fixtures = TestFixtures::mainnet_shared();
        let (_, hash) = fixtures.paired_blocks().into_iter().next().expect("paired fixture");
        let salt = &fixtures.salt_witnesses[&hash];
        let mpt: MptWitness = fixtures.mpt_witness(&hash);
        let light = LightWitness::from(salt);

        let full = WitnessSizeBreakdown::new(salt, &mpt);
        let lower = WitnessSizeBreakdown::new_light(&light, &mpt);

        assert_eq!(lower.kvs_count, full.kvs_count);
        assert_eq!(lower.salt_kvs_size, full.salt_kvs_size);
        assert_eq!(lower.mpt_size, full.mpt_size);
        assert_eq!(
            full.salt_size - lower.salt_size,
            salt.proof.parents_commitments.len() * SALT_COMMITMENT_BYTES,
            "the gap must be exactly the commitments term"
        );
        assert!(lower.total() <= full.total());
    }
}
