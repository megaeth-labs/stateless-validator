//! Witness-backed database for stateless EVM execution.
//!
//! The `WitnessDatabase` implements `revm::DatabaseRef` to provide state data from
//! a block witness rather than a full blockchain database, enabling stateless block
//! validation.

use crate::evm::{PlainKey, PlainValue};
use alloy_primitives::{Address, B256};
use alloy_provider::{Provider, RootProvider};
use op_alloy_network::Optimism;
use revm::{
    DatabaseRef,
    database::DBErrorMarker,
    primitives::{Bytes, HashMap, KECCAK_EMPTY, U256},
    state::{AccountInfo, Bytecode},
};
use salt::{EphemeralSaltState, Witness};
use tokio::{runtime::Handle, sync::oneshot};

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
    /// Compact witness containing state subset and cryptographic proofs
    pub witness: Witness,
    /// Contract bytecode cache, pre-populated before execution starts
    pub contracts: HashMap<B256, Bytecode>,
    // FIXME: blockhashes will be included in the witness using EIP-2935
    /// RPC client for fetching missing block hashes
    pub client: RootProvider<Optimism>,
    /// Runtime handle for async RPC calls within sync REVM execution context
    pub runtime: Handle,
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
                    .bytecode_hash
                    .and_then(|hash| self.contracts.get(&hash))
                    .cloned();
                Ok(Some(AccountInfo {
                    balance: acc.balance,
                    nonce: acc.nonce,
                    code_hash: acc.bytecode_hash.unwrap_or(KECCAK_EMPTY),
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

    /// Provides a historical block hash
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let provider = self.client.clone();
        tokio::task::block_in_place(|| {
            let (tx, rx) = oneshot::channel();
            self.runtime.spawn(async move {
                let _ = tx.send(provider.get_block_by_number(number.into()).await);
            });

            let block = rx
                .blocking_recv()
                .map_err(|e| WitnessDatabaseError(e.to_string()))? // Channel receive error
                .map_err(|e| WitnessDatabaseError(e.to_string()))? // RPC call error
                .ok_or_else(|| WitnessDatabaseError("Blockhash not found".to_string()))?;

            Ok(block.header.hash)
        })
    }
}
