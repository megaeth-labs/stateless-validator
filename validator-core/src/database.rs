//! Witness-backed database for stateless EVM execution.
//!
//! The `WitnessDatabase` implements `revm::DatabaseRef` to provide state data from
//! a block witness rather than a full blockchain database, enabling stateless block
//! validation.

use crate::data_types::{PlainKey, PlainValue};
use alloy_eips::eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
use alloy_primitives::{Address, B256, BlockNumber};
use alloy_rpc_types_eth::Header;
use mega_evm::{ExternalEnvFactory, ExternalEnvs, OracleEnv, SaltEnv};
use revm::{
    DatabaseRef,
    database::DBErrorMarker,
    primitives::{Bytes, KECCAK_EMPTY, U256},
    state::{AccountInfo, Bytecode},
};
use salt::{
    BucketId, BucketMeta, EphemeralSaltState, METADATA_KEYS_RANGE, SaltKey, SaltValue, SaltWitness,
    Witness, bucket_id_from_metadata_key, hasher,
};
use std::collections::HashMap;
use tracing::trace;

/// Error type for witness database operations
#[derive(Debug, Clone)]
pub struct WitnessDatabaseError(pub String);
impl std::fmt::Display for WitnessDatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for WitnessDatabaseError {}
impl DBErrorMarker for WitnessDatabaseError {}

/// REVM database backed by witness data for partial stateless execution.
///
/// This database enables stateless block validation by combining a compact witness
/// with local bytecode cache. Instead of requiring full pre-state (which would be
/// prohibitively large), it uses a hybrid approach:
///
/// **From Witness:**
/// - Account balances, nonces, and code hashes
/// - Storage slot values for touched accounts
/// - Historical block hashes (via EIP-2935 Historical Block Hashes From State)
/// - State proofs for cryptographic verification
///
/// **From RPC:**
/// - Contract bytecode (fetched on-demand and cached locally)
///
/// This partial stateless approach dramatically reduces DA bandwidth compared to
/// a pure stateless approach, while still enabling complete block validation through
/// cryptographic proofs in the witness.
#[derive(Debug)]
pub struct WitnessDatabase<'a> {
    /// The block header containing number, parent hash, and other metadata
    pub header: &'a Header,
    /// Compact witness containing state subset and cryptographic proofs
    pub witness: &'a Witness,
    /// Contract bytecode cache, pre-populated before execution starts
    pub contracts: &'a HashMap<B256, Bytecode>,
}

impl<'a> WitnessDatabase<'a> {
    /// Get value from witness for the given plain key
    fn plain_value(&self, plain_key: &[u8]) -> Result<Option<Vec<u8>>, WitnessDatabaseError> {
        EphemeralSaltState::new(self.witness)
            .plain_value(plain_key)
            .map_err(|e| WitnessDatabaseError(e.to_string()))
    }
}

impl<'a> DatabaseRef for WitnessDatabase<'a> {
    type Error = WitnessDatabaseError;

    /// Provides basic account information from the witness
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        trace!(?address, "basic_ref");

        let raw_value = self.plain_value(&PlainKey::Account(address).encode())?;

        match raw_value.and_then(|v| match PlainValue::decode(&v) {
            PlainValue::Account(acc) => Some(acc),
            _ => None,
        }) {
            Some(acc) => {
                let code = acc
                    .codehash
                    .and_then(|hash| self.contracts.get(&hash))
                    .cloned();
                Ok(Some(AccountInfo {
                    balance: acc.balance,
                    nonce: acc.nonce,
                    code_hash: acc.codehash.unwrap_or(KECCAK_EMPTY),
                    code,
                }))
            }
            None => Ok(None),
        }
    }

    /// Provides contract bytecode by its hash
    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        trace!(?code_hash, "code_by_hash_ref");

        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new_raw(Bytes::new()));
        }
        self.contracts
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| WitnessDatabaseError("Code not found".to_string()))
    }

    /// Provides a storage slot's value for a given account
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        trace!(?address, index = %format_args!("{:#x}", index), "storage_ref");

        let raw_value = self.plain_value(&PlainKey::Storage(address, index.into()).encode())?;

        Ok(raw_value
            .and_then(|v| match PlainValue::decode(&v) {
                PlainValue::Storage(value) => Some(value),
                _ => None,
            })
            .unwrap_or_default())
    }

    /// Retrieves historical block hashes according to [EIP-2935](https://eips.ethereum.org/EIPS/eip-2935).
    ///
    /// This method provides block hashes for the EVM BLOCKHASH opcode, supporting up to
    /// the last 8191 blocks. Block hashes are stored in a ring buffer at the designated
    /// EIP-2935 contract address, where the hash for block `N` is stored at storage slot
    /// `N % HISTORY_SERVE_WINDOW`.
    ///
    /// # Arguments
    /// * `number` - The block number to retrieve the hash for
    ///
    /// # Returns
    /// The block hash (B256) for the requested block number
    ///
    /// # Errors
    /// Returns `WitnessDatabaseError` if:
    /// - The block number is outside the EIP-2935 history serve window (> 8191 blocks old)
    /// - The block number is >= current block number (future blocks)
    /// - The witness data is corrupted or storage lookup fails
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        trace!(number, "block_hash_ref");

        // Return error for blocks beyond EIP-2935 history window
        if number >= self.header.number
            || number + (HISTORY_SERVE_WINDOW as u64) < self.header.number
        {
            return Err(WitnessDatabaseError(format!(
                "Block {} is outside the history serve window",
                number
            )));
        }

        // Special case: the parent block hash is not included in the witness
        // and must be read from the parent header directly.
        if number == self.header.number - 1 {
            return Ok(self.header.parent_hash);
        }

        // Look up historical block hash in EIP-2935 storage
        self.storage_ref(
            HISTORY_STORAGE_ADDRESS,
            U256::from(number % HISTORY_SERVE_WINDOW as u64),
        )
        .map(|res| res.into())
    }
}

/// Witness-backed external environment provider for mega-evm execution.
///
/// Implements the `ExternalEnvs` trait required by mega-evm, providing both
/// `SaltEnv` (for bucket capacity lookups) and `OracleEnv` (for oracle storage)
/// implementations. The environment state is extracted from a SALT witness at
/// construction time for efficient lookups during EVM execution.
#[derive(Debug, Clone)]
pub struct WitnessExternalEnv {
    block_number: BlockNumber,
    bucket_capacities: HashMap<BucketId, u64>,
}

impl WitnessExternalEnv {
    /// Creates a new external environment provider from a SALT witness.
    ///
    /// Extracts bucket capacity metadata from the witness to provide efficient
    /// capacity lookups during EVM execution. Only metadata buckets are scanned
    /// using a range query.
    ///
    /// # Arguments
    ///
    /// * `salt_witness` - The SALT witness containing bucket metadata
    /// * `block_number` - The block number for validation checks
    ///
    /// # Returns
    ///
    /// Returns `Ok(WitnessExternalEnv)` if all metadata is valid, or an error if:
    /// - Any metadata key has a `None` value (malformed witness)
    /// - Metadata cannot be parsed as `BucketMeta` (corrupt witness)
    ///
    /// # Errors
    ///
    /// This method enforces strict witness validation and will fail if:
    /// - A metadata key is present but has no value
    /// - A metadata value cannot be deserialized into valid `BucketMeta`
    pub fn new(
        salt_witness: &SaltWitness,
        block_number: BlockNumber,
    ) -> Result<Self, WitnessDatabaseError> {
        let bucket_capacities = salt_witness
            .kvs
            .range(METADATA_KEYS_RANGE)
            .map(|(key, value)| Self::parse_metadata_entry(key, value))
            .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(Self {
            block_number: block_number - 1,
            bucket_capacities,
        })
    }

    /// Parses a single metadata entry from the witness.
    fn parse_metadata_entry(
        key: &SaltKey,
        value: &Option<SaltValue>,
    ) -> Result<(BucketId, u64), WitnessDatabaseError> {
        let bucket_id = bucket_id_from_metadata_key(*key);

        let salt_value = value.as_ref().ok_or_else(|| {
            WitnessDatabaseError(format!("metadata is None for bucket {bucket_id}"))
        })?;

        let meta: BucketMeta = salt_value.try_into().map_err(|e| {
            WitnessDatabaseError(format!("bad metadata for bucket {bucket_id}: {e}"))
        })?;

        Ok((bucket_id, meta.capacity))
    }
}

impl ExternalEnvFactory for WitnessExternalEnv {
    type EnvTypes = (Self, Self);

    fn external_envs(&self, block: BlockNumber) -> ExternalEnvs<Self::EnvTypes> {
        assert_eq!(
            block, self.block_number,
            "block mismatch: expected {}, got {}",
            self.block_number, block
        );
        ExternalEnvs {
            salt_env: self.clone(),
            oracle_env: self.clone(),
        }
    }
}

impl SaltEnv for WitnessExternalEnv {
    type Error = WitnessDatabaseError;

    fn get_bucket_capacity(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        trace!(?bucket_id, "get_bucket_capacity");

        self.bucket_capacities
            .get(&bucket_id)
            .copied()
            .ok_or_else(|| {
                WitnessDatabaseError(format!("Capacity of bucket {bucket_id} not in witness"))
            })
    }

    fn bucket_id_for_account(account: Address) -> BucketId {
        hasher::bucket_id(&PlainKey::Account(account).encode())
    }

    fn bucket_id_for_slot(address: Address, key: U256) -> BucketId {
        hasher::bucket_id(&PlainKey::Storage(address, key.into()).encode())
    }
}

impl OracleEnv for WitnessExternalEnv {
    fn get_oracle_storage(&self, _slot: U256) -> Option<U256> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies successful parsing of valid bucket metadata.
    #[test]
    fn test_parse_metadata_entry_valid() {
        let meta = BucketMeta {
            nonce: 42,
            capacity: 1024,
            used: None,
        };
        let key = SaltKey::from((256u32, 0u64));

        let (bucket_id, capacity) =
            WitnessExternalEnv::parse_metadata_entry(&key, &Some(meta.into())).unwrap();

        assert_eq!(bucket_id, 65536);
        assert_eq!(capacity, 1024);
    }

    /// Verifies error handling when metadata value is None.
    #[test]
    fn test_parse_metadata_entry_none_value() {
        let key = SaltKey::from((256u32, 0u64));
        let err = WitnessExternalEnv::parse_metadata_entry(&key, &None).unwrap_err();
        assert!(err.0.contains("metadata is None for bucket 65536"));
    }

    /// Verifies error handling when metadata cannot be deserialized.
    #[test]
    fn test_parse_metadata_entry_invalid_metadata() {
        let key = SaltKey::from((256u32, 0u64));
        let invalid_value = SaltValue::new(&[1, 2, 3], &[]);

        let err = WitnessExternalEnv::parse_metadata_entry(&key, &Some(invalid_value)).unwrap_err();

        assert!(err.0.contains("bad metadata for bucket 65536"));
    }
}
