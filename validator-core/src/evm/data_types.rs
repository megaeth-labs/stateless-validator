//! EVM data types and encoding utilities.
//!
//! This module defines the core data types used throughout the EVM validation process,
//! including account structures, storage keys, and their binary encoding formats.
//! These types provide a stable interface for representing Ethereum state data
//! without depending on external EVM libraries.
//!
//! # Types
//!
//! The module defines:
//! - [`PlainKey`]: An account address or storage slot
//! - [`PlainValue`]: Account or storage data
//! - [`Account`]: An EVM account containing nonce, balance, and optional bytecode hash
//!
//! # Encoding Format
//!
//! ## Keys
//! - Account keys: 20 bytes (address)
//! - Storage keys: 52 bytes (20-byte address + 32-byte storage slot)
//!
//! ## Values
//! - EOA accounts: 40 bytes (8-byte nonce + 32-byte balance)
//! - Contract accounts: 72 bytes (8-byte nonce + 32-byte balance + 32-byte bytecode hash)
//! - Storage values: 32 bytes (U256 value)

pub use alloy_primitives::Bytes;
use alloy_primitives::{Address, B256, U256};

/// Length of a storage slot key in bytes (32)
const SLOT_KEY_LEN: usize = B256::len_bytes();
/// Length of an account address in bytes (20)
const ACCOUNT_ADDRESS_LEN: usize = Address::len_bytes();
/// Total length of a storage key in bytes (20 + 32 = 52)
const STORAGE_SLOT_KEY_LEN: usize = ACCOUNT_ADDRESS_LEN + SLOT_KEY_LEN;

/// Length of an EOA account value in bytes (8-byte nonce + 32-byte balance)
const EOA_ACCOUNT_LEN: usize = 8 + 32;
/// Length of a contract account value in bytes (EOA + 32-byte bytecode hash)
const CONTRACT_ACCOUNT_LEN: usize = EOA_ACCOUNT_LEN + 32;
/// Length of a storage value in bytes (U256)
const STORAGE_VALUE_LEN: usize = 32;

/// Represents a key in the EVM world state for testing.
///
/// This enum distinguishes between account keys (just an address) and
/// storage slot keys (address + slot identifier).
#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlainKey {
    /// Key for an account state (20-byte address)
    Account(Address),
    /// Key for a storage slot: (address, storage slot)
    Storage(Address, B256),
}

impl PlainKey {
    /// Encodes the key into a byte vector.
    ///
    /// # Returns
    /// - Account: 20-byte address
    /// - Storage: 52-byte concatenation of address (20) + slot (32)
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainKey::Account(addr) => addr.as_slice().to_vec(),
            PlainKey::Storage(addr, slot) => addr
                .concat_const::<SLOT_KEY_LEN, STORAGE_SLOT_KEY_LEN>(*slot)
                .as_slice()
                .to_vec(),
        }
    }

    /// Decodes a byte slice into a PlainKey.
    ///
    /// # Panics
    /// Panics if the buffer length is neither 20 (account) nor 52 (storage) bytes.
    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            ACCOUNT_ADDRESS_LEN => PlainKey::Account(Address::from_slice(buf)),
            STORAGE_SLOT_KEY_LEN => {
                let addr = Address::from_slice(&buf[..ACCOUNT_ADDRESS_LEN]);
                let slot_id = B256::from_slice(&buf[ACCOUNT_ADDRESS_LEN..]);
                PlainKey::Storage(addr, slot_id)
            }
            _ => unreachable!("unexpected length of plain key."),
        }
    }
}

/// Represents a value in the EVM world state for testing.
///
/// This enum encodes either account data or storage slot values in a
/// compact binary format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainValue {
    /// Account data containing nonce, balance, and optional bytecode hash.
    /// An empty account (zero nonce and balance) typically indicates deletion.
    Account(Account),
    /// Storage slot value (256-bit unsigned integer)
    Storage(U256),
}

impl PlainValue {
    /// Encodes the value into a byte vector.
    ///
    /// # Returns
    /// - EOA Account: 40 bytes (8-byte nonce + 32-byte balance)
    /// - Contract Account: 72 bytes (8-byte nonce + 32-byte balance + 32-byte bytecode hash)
    /// - Storage: 32 bytes (U256 value)
    ///
    /// # Encoding Details
    /// All integers are encoded in big-endian format.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainValue::Account(account) => {
                let mut buffer = [0; CONTRACT_ACCOUNT_LEN];
                buffer[..8].copy_from_slice(account.nonce.to_be_bytes().as_ref());
                buffer[8..EOA_ACCOUNT_LEN]
                    .copy_from_slice(account.balance.to_be_bytes::<32>().as_ref());
                if let Some(bytecode_hash) = account.bytecode_hash {
                    buffer[EOA_ACCOUNT_LEN..CONTRACT_ACCOUNT_LEN]
                        .copy_from_slice(bytecode_hash.as_slice());
                    buffer.to_vec()
                } else {
                    buffer[..EOA_ACCOUNT_LEN].to_vec()
                }
            }
            PlainValue::Storage(value) => value.to_be_bytes::<32>().to_vec(),
        }
    }

    /// Decodes a byte slice into a PlainValue.
    ///
    /// The function determines the value type based on the buffer length:
    /// - 40 bytes: EOA account (no bytecode)
    /// - 72 bytes: Contract account (with bytecode hash)
    /// - 32 bytes: Storage value
    ///
    /// # Panics
    /// Panics if the buffer length doesn't match any expected format.
    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            EOA_ACCOUNT_LEN => {
                let (nonce, balance) = Self::decode_account_fields(buf);
                PlainValue::Account(Account {
                    nonce,
                    balance,
                    bytecode_hash: None,
                })
            }
            CONTRACT_ACCOUNT_LEN => {
                let (nonce, balance) = Self::decode_account_fields(buf);
                let bytecode_hash = B256::from_slice(&buf[EOA_ACCOUNT_LEN..]);
                PlainValue::Account(Account {
                    nonce,
                    balance,
                    bytecode_hash: Some(bytecode_hash),
                })
            }
            STORAGE_VALUE_LEN => PlainValue::Storage(U256::from_be_slice(buf)),
            _ => unreachable!("unexpected length of plain value."),
        }
    }

    /// Helper function to decode nonce and balance from account data.
    fn decode_account_fields(buf: &[u8]) -> (u64, U256) {
        let nonce = u64::from_be_bytes(buf[..8].try_into().unwrap());
        let balance = U256::from_be_slice(&buf[8..EOA_ACCOUNT_LEN]);
        (nonce, balance)
    }
}

/// Simplified Ethereum account structure for testing.
///
/// Represents either an EOA (no bytecode hash) or a contract account (with bytecode hash).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Account {
    /// Transaction count for this account
    pub nonce: u64,
    /// Account balance
    pub balance: U256,
    /// Keccak256 hash of the contract bytecode (None for EOAs)
    pub bytecode_hash: Option<B256>,
}

impl Account {
    /// Returns true if account is empty.
    pub fn is_empty(&self) -> bool {
        self.balance.is_zero() && self.nonce == 0 && self.bytecode_hash.is_none()
    }
}
