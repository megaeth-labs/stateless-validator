//! Witness-backed database for stateless EVM execution.
//!
//! The `WitnessDatabase` implements `revm::DatabaseRef` to provide state data from
//! a block witness rather than a full blockchain database, enabling stateless block
//! validation.

use crate::data_types::{PlainKey, PlainValue};
use alloy_eips::eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
use alloy_primitives::{Address, B256, BlockHash, BlockNumber};
use revm::{
    DatabaseRef,
    database::DBErrorMarker,
    primitives::{Bytes, HashMap, KECCAK_EMPTY, U256},
    state::{AccountInfo, Bytecode},
};
use salt::{EphemeralSaltState, Witness};

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
#[derive(Debug, Clone)]
pub struct WitnessDatabase {
    /// The block number
    pub block_number: BlockNumber,
    /// The parent block hash
    pub parent_hash: BlockHash,
    /// Compact witness containing state subset and cryptographic proofs
    pub witness: Witness,
    /// Contract bytecode cache, pre-populated before execution starts
    pub contracts: HashMap<B256, Bytecode>,
}

impl WitnessDatabase {
    /// Get value from witness for the given plain key
    fn plain_value(&self, plain_key: &[u8]) -> Result<Option<Vec<u8>>, WitnessDatabaseError> {
        EphemeralSaltState::new(&self.witness)
            .plain_value(plain_key)
            .map_err(|e| WitnessDatabaseError(e.to_string()))
    }
}

impl DatabaseRef for WitnessDatabase {
    type Error = WitnessDatabaseError;

    /// Provides basic account information from the witness
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
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
        // Return error for blocks beyond EIP-2935 history window
        if number >= self.block_number || number + (HISTORY_SERVE_WINDOW as u64) < self.block_number
        {
            return Err(WitnessDatabaseError(format!(
                "Block {} is outside the history serve window",
                number
            )));
        }

        // Special case: the parent block hash is not included in the witness
        // and must be read from the parent header directly.
        if number == self.block_number - 1 {
            return Ok(self.parent_hash);
        }

        // Look up historical block hash in EIP-2935 storage
        self.storage_ref(
            HISTORY_STORAGE_ADDRESS,
            U256::from(number % HISTORY_SERVE_WINDOW as u64),
        )
        .map(|res| res.into())
    }
}
