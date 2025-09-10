//! This module provides the core components for stateless validation.
//!
//! The central piece is the `WitnessProvider`, which implements the `revm::DatabaseRef` trait.
//! This allows it to act as a read-only database for REVM, but instead of fetching data from a
//! full database, it serves data from a `BlockWitness`. This is the key to enabling stateless
//! block replay and validation.
use crate::format::{Account, PlainKey, PlainValue};
use alloy_eips::eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
use alloy_primitives::{Address, B256};
use revm::{
    DatabaseRef,
    database::DBErrorMarker,
    database::states::CacheAccount,
    primitives::{Bytes, HashMap, KECCAK_EMPTY, U256},
    state::{AccountInfo, Bytecode},
};
use salt::{EphemeralSaltState, Witness};
use std::error::Error;
use std::fmt;

pub mod evm;
pub mod file;
pub mod rpc;

/// A custom error type for the `WitnessProvider`.
///
/// This error type wraps a `String` and implements the `std::error::Error` trait,
/// making it compatible with the `DatabaseRef::Error` associated type.
#[derive(Debug)]
pub struct WitnessProviderError(String);

impl fmt::Display for WitnessProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for WitnessProviderError {}

impl DBErrorMarker for WitnessProviderError {}

impl From<&'static str> for WitnessProviderError {
    fn from(s: &'static str) -> Self {
        Self(s.to_string())
    }
}

/// A REVM database provider that sources all its data from a `BlockWitness`.
///
/// This struct implements the `DatabaseRef` trait, allowing REVM to perform EVM execution
/// using only the data contained within the witness. It holds the witness itself, any required
/// contract code, and an RPC provider for fetching historical block hashes.
#[derive(Debug, Clone)]
pub struct WitnessProvider {
    /// The witness data, containing the necessary state subset and proof.
    pub witness: Witness,
    /// A map of contract code hashes to their corresponding bytecode.
    pub contracts: HashMap<B256, Bytecode>,
}

impl WitnessProvider {
    /// Return the SALT value associated with the given plain key.
    fn get_raw(&self, plain_key: &[u8]) -> Result<Option<Vec<u8>>, WitnessProviderError> {
        let mut state = EphemeralSaltState::new(&self.witness);

        Ok(state.plain_value(plain_key)?)
    }
}

impl DatabaseRef for WitnessProvider {
    type Error = WitnessProviderError;

    /// Provides basic account information (balance, nonce, code hash) from the witness.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let raw_key = PlainKey::Account(address).encode();
        //self.witness.value(key)
        let account = if let Some(raw_value) = self.get_raw(&raw_key)? {
            match PlainValue::decode(&raw_value) {
                PlainValue::Account(acc) => {
                    // If the account has bytecode, find it in the local `contracts` map.
                    let code = acc
                        .bytecode_hash
                        .and_then(|hash| self.contracts.get(&hash))
                        .cloned();

                    Some(AccountInfo {
                        balance: acc.balance,
                        nonce: acc.nonce,
                        code_hash: acc.bytecode_hash.unwrap_or(KECCAK_EMPTY),
                        code,
                    })
                }
                _ => None,
            }
        } else {
            None
        };
        Ok(account)
    }

    /// Provides contract bytecode by its hash.
    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, <Self as DatabaseRef>::Error> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new_raw(Bytes::new()));
        }
        // The code is expected to be pre-loaded into the `contracts` map.
        self.contracts
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| WitnessProviderError("Code not found in witness contracts".to_string()))
    }

    /// Provides a storage slot's value for a given account.
    fn storage_ref(
        &self,
        address: Address,
        index: U256,
    ) -> Result<U256, <Self as DatabaseRef>::Error> {
        let raw_key = PlainKey::Storage(address, index.into()).encode();
        let storage = if let Some(raw_value) = self.get_raw(&raw_key)? {
            match PlainValue::decode(&raw_value) {
                PlainValue::Storage(storage) => storage,
                _ => U256::default(),
            }
        } else {
            U256::default()
        };
        Ok(storage)
    }

    /// Provides a historical block hash.
    ///
    /// Implements the retrieval mechanism from [EIP-2935](https://eips.ethereum.org/EIPS/eip-2935).
    /// The hash for block `N` is stored at slot `N % HISTORY_SERVE_WINDOW` in the
    /// designated contract.
    fn block_hash_ref(&self, number: u64) -> Result<B256, <Self as DatabaseRef>::Error> {
        self.storage_ref(
            HISTORY_STORAGE_ADDRESS,
            U256::from(number % HISTORY_SERVE_WINDOW as u64),
        )
        .map(|res| res.into())
    }
}

/// Represents a set of state updates in the `PlainKey` format.
///
/// This struct is used to hold the changes to accounts and storage that result from
/// executing a block. It is created by converting from REVM's native `DbAccount` map.
#[derive(Default, Debug, Clone)]
pub struct PlainKeyUpdate {
    /// A map from a `Vec<u8>` (representing an account or storage slot) to its new value.
    /// `None` signifies a deletion.
    pub data: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl From<HashMap<Address, CacheAccount>> for PlainKeyUpdate {
    /// Converts REVM's state changes into the `PlainKeyUpdate` format.
    fn from(accounts: HashMap<Address, CacheAccount>) -> Self {
        let mut data = HashMap::default();
        for (address, account) in accounts {
            // Handle account updates.
            let account_key = PlainKey::Account(address).encode();

            let (info, _) = account.into_components();
            if let Some((info, storage)) = info {
                // handle account
                let plain_account = Account {
                    nonce: info.nonce,
                    balance: info.balance,
                    bytecode_hash: if info.code_hash == KECCAK_EMPTY {
                        None
                    } else {
                        Some(info.code_hash)
                    },
                };

                let plain_val = if plain_account.is_empty() {
                    None
                } else {
                    Some(PlainValue::Account(plain_account).encode())
                };
                data.insert(account_key, plain_val);

                // handle storage
                for (slot, value) in storage {
                    let storage_value = if value.is_zero() {
                        None
                    } else {
                        Some(PlainValue::Storage(value).encode())
                    };

                    data.insert(
                        PlainKey::Storage(address, B256::new(slot.to_be_bytes())).encode(),
                        storage_value,
                    );
                }
            }
        }
        Self { data }
    }
}
