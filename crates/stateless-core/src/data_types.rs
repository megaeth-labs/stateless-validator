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
#[derive(Hash, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlainKey {
    /// Key for an account state (20-byte address)
    Account(Address),
    /// Key for a storage slot: (address, storage slot)
    Storage(Address, B256),
    /// Unknown key format (for malformed data), preserving raw bytes
    Unknown(Vec<u8>),
}

impl PlainKey {
    /// Encodes the key into a byte vector.
    ///
    /// # Returns
    /// - Account: 20-byte address
    /// - Storage: 52-byte concatenation of address (20) + slot (32)
    /// - Unknown: preserved raw bytes from decode
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainKey::Account(addr) => addr.as_slice().to_vec(),
            PlainKey::Storage(addr, slot) => {
                addr.concat_const::<SLOT_KEY_LEN, STORAGE_SLOT_KEY_LEN>(*slot).as_slice().to_vec()
            }
            PlainKey::Unknown(data) => data.clone(),
        }
    }

    /// Decodes a byte slice into a PlainKey.
    ///
    /// Returns `PlainKey::Unknown` if the buffer length is neither 20 (account)
    /// nor 52 (storage) bytes.
    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            ACCOUNT_ADDRESS_LEN => PlainKey::Account(Address::from_slice(buf)),
            STORAGE_SLOT_KEY_LEN => {
                let addr = Address::from_slice(&buf[..ACCOUNT_ADDRESS_LEN]);
                let slot_id = B256::from_slice(&buf[ACCOUNT_ADDRESS_LEN..]);
                PlainKey::Storage(addr, slot_id)
            }
            _ => PlainKey::Unknown(buf.to_vec()),
        }
    }
}

/// Represents a value in the EVM world state for testing.
///
/// This enum encodes either account data or storage slot values in a
/// compact binary format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlainValue {
    /// Account data containing nonce, balance, and optional bytecode hash.
    /// An empty account (zero nonce and balance) typically indicates deletion.
    Account(Account),
    /// Storage slot value (256-bit unsigned integer)
    Storage(U256),
    /// Unknown value format (for malformed data), preserving raw bytes
    Unknown(Vec<u8>),
}

impl PlainValue {
    /// Encodes the value into a byte vector.
    ///
    /// # Returns
    /// - EOA Account: 40 bytes (8-byte nonce + 32-byte balance)
    /// - Contract Account: 72 bytes (8-byte nonce + 32-byte balance + 32-byte bytecode hash)
    /// - Storage: 32 bytes (U256 value)
    /// - Unknown: preserved raw bytes from decode
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
                if let Some(bytecode_hash) = account.codehash {
                    buffer[EOA_ACCOUNT_LEN..CONTRACT_ACCOUNT_LEN]
                        .copy_from_slice(bytecode_hash.as_slice());
                    buffer.to_vec()
                } else {
                    buffer[..EOA_ACCOUNT_LEN].to_vec()
                }
            }
            PlainValue::Storage(value) => value.to_be_bytes::<32>().to_vec(),
            PlainValue::Unknown(data) => data.clone(),
        }
    }

    /// Decodes a byte slice into a PlainValue.
    ///
    /// The function determines the value type based on the buffer length:
    /// - 40 bytes: EOA account (no bytecode)
    /// - 72 bytes: Contract account (with bytecode hash)
    /// - 32 bytes: Storage value
    ///
    /// Returns `PlainValue::Unknown` if the buffer length doesn't match any expected format.
    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            EOA_ACCOUNT_LEN => {
                let (nonce, balance) = Self::decode_account_fields(buf);
                PlainValue::Account(Account { nonce, balance, codehash: None })
            }
            CONTRACT_ACCOUNT_LEN => {
                let (nonce, balance) = Self::decode_account_fields(buf);
                let bytecode_hash = B256::from_slice(&buf[EOA_ACCOUNT_LEN..]);
                PlainValue::Account(Account { nonce, balance, codehash: Some(bytecode_hash) })
            }
            STORAGE_VALUE_LEN => PlainValue::Storage(U256::from_be_slice(buf)),
            _ => PlainValue::Unknown(buf.to_vec()),
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
    pub codehash: Option<B256>,
}

impl Account {
    /// Returns true if account is empty.
    pub fn is_empty(&self) -> bool {
        self.balance.is_zero() && self.nonce == 0 && self.codehash.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PlainKey tests
    #[test]
    fn test_plain_key_account_round_trip() {
        let addr = Address::from([0xAB; 20]);
        let key = PlainKey::Account(addr);
        let encoded = key.encode();
        assert_eq!(encoded.len(), 20);
        assert_eq!(PlainKey::decode(&encoded), key);
    }

    #[test]
    fn test_plain_key_storage_round_trip() {
        let addr = Address::from([0x01; 20]);
        let slot = B256::from([0xFF; 32]);
        let key = PlainKey::Storage(addr, slot);
        let encoded = key.encode();
        assert_eq!(encoded.len(), 52);
        let decoded = PlainKey::decode(&encoded);
        assert_eq!(decoded, key);
        if let PlainKey::Storage(decoded_addr, decoded_slot) = decoded {
            assert_eq!(decoded_addr, addr);
            assert_eq!(decoded_slot, slot);
        } else {
            panic!("Expected PlainKey::Storage");
        }
    }

    #[test]
    fn test_plain_key_unknown_for_invalid_length() {
        let buf = vec![0u8; 10]; // neither 20 nor 52
        let key = PlainKey::decode(&buf);
        assert!(matches!(key, PlainKey::Unknown(_)));
        assert_eq!(key.encode(), buf);
    }

    #[test]
    fn test_plain_key_zero_address() {
        let key = PlainKey::Account(Address::ZERO);
        assert_eq!(PlainKey::decode(&key.encode()), key);
    }

    // PlainValue tests
    #[test]
    fn test_plain_value_eoa_round_trip() {
        let account = Account { nonce: 42, balance: U256::from(1_000_000u64), codehash: None };
        let value = PlainValue::Account(account);
        let encoded = value.encode();
        assert_eq!(encoded.len(), 40); // EOA = 8 + 32
        assert_eq!(PlainValue::decode(&encoded), value);
    }

    #[test]
    fn test_plain_value_contract_round_trip() {
        let account = Account {
            nonce: 1,
            balance: U256::from(500u64),
            codehash: Some(B256::from([0xCC; 32])),
        };
        let value = PlainValue::Account(account);
        let encoded = value.encode();
        assert_eq!(encoded.len(), 72); // Contract = 8 + 32 + 32
        let decoded = PlainValue::decode(&encoded);
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_plain_value_storage_round_trip() {
        let value = PlainValue::Storage(U256::from(0xDEADBEEFu64));
        let encoded = value.encode();
        assert_eq!(encoded.len(), 32);
        assert_eq!(PlainValue::decode(&encoded), value);
    }

    #[test]
    fn test_plain_value_storage_max() {
        let value = PlainValue::Storage(U256::MAX);
        assert_eq!(PlainValue::decode(&value.encode()), value);
    }

    #[test]
    fn test_plain_value_storage_zero() {
        let value = PlainValue::Storage(U256::ZERO);
        assert_eq!(PlainValue::decode(&value.encode()), value);
    }

    #[test]
    fn test_plain_value_unknown_for_invalid_length() {
        let buf = vec![0u8; 15]; // not 32, 40, or 72
        let value = PlainValue::decode(&buf);
        assert!(matches!(value, PlainValue::Unknown(_)));
        assert_eq!(value.encode(), buf);
    }

    #[test]
    fn test_plain_value_eoa_nonce_zero_balance_max() {
        let account = Account { nonce: 0, balance: U256::MAX, codehash: None };
        let value = PlainValue::Account(account);
        assert_eq!(PlainValue::decode(&value.encode()), value);
    }

    #[test]
    fn test_plain_value_nonce_max() {
        let account = Account { nonce: u64::MAX, balance: U256::ZERO, codehash: None };
        let value = PlainValue::Account(account);
        assert_eq!(PlainValue::decode(&value.encode()), value);
    }

    // Account tests
    #[test]
    fn test_account_is_empty() {
        assert!(Account::default().is_empty());
        assert!(Account { nonce: 0, balance: U256::ZERO, codehash: None }.is_empty());
    }

    #[test]
    fn test_account_not_empty_with_nonce() {
        assert!(!Account { nonce: 1, balance: U256::ZERO, codehash: None }.is_empty());
    }

    #[test]
    fn test_account_not_empty_with_balance() {
        assert!(!Account { nonce: 0, balance: U256::from(1u64), codehash: None }.is_empty());
    }

    #[test]
    fn test_account_not_empty_with_codehash() {
        assert!(!Account { nonce: 0, balance: U256::ZERO, codehash: Some(B256::ZERO) }.is_empty());
    }
}
