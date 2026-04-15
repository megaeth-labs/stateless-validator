//! Approximate byte-size estimation for witness payloads.
//!
//! Avoids round-tripping through serialization by computing sizes from the
//! in-memory layout. Used by metrics reporting in both the RPC client
//! (`on_witness_fetch`) and the trace server's data provider.

use salt::SaltWitness;
use stateless_core::withdrawals::MptWitness;

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

    /// Sum of `salt_size + mpt_size`.
    pub fn total(&self) -> usize {
        self.salt_size + self.mpt_size
    }
}

/// Convenience wrapper that returns just the total estimated size.
pub fn estimate_witness_size(salt: &SaltWitness, mpt: &MptWitness) -> usize {
    WitnessSizeBreakdown::new(salt, mpt).total()
}
