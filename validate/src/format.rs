pub use alloy_primitives::Bytes;
use alloy_primitives::{Address, B256, U256};

/// data length of Key of Storage Slot
pub const SLOT_KEY_LEN: usize = B256::len_bytes();
/// data length of Key of Account
pub const PLAIN_ACCOUNT_KEY_LEN: usize = Address::len_bytes();
/// data length of Key of Storage
pub const PLAIN_STORAGE_KEY_LEN: usize = PLAIN_ACCOUNT_KEY_LEN + SLOT_KEY_LEN;

pub const U64_BYTES_LEN: usize = 8;
pub const BALANCE_BYTES_LEN: usize = U256::BYTES;
/// data length of Value of Account(Contract)
pub const PLAIN_EOA_ACCOUNT_LEN: usize = U64_BYTES_LEN + BALANCE_BYTES_LEN;
/// data length of Value of Account(EOA)
pub const PLAIN_CONTRACT_ACCOUNT_LEN: usize = PLAIN_EOA_ACCOUNT_LEN + B256::len_bytes();
/// data length of Value of Storage
pub const PLAIN_STORAGE_LEN: usize = U256::BYTES;

/// Key of PlainAccount/StorageState.
#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlainKey {
    /// Key of plainAccountState.
    Account(Address),
    /// Key of plainStorageState: (address,  storage slot).
    Storage(Address, B256),
}

impl PlainKey {
    /// Convert PlainKey to Vec.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainKey::Account(addr) => addr.as_slice().to_vec(),
            PlainKey::Storage(addr, slot) => addr
                .concat_const::<SLOT_KEY_LEN, PLAIN_STORAGE_KEY_LEN>(*slot)
                .as_slice()
                .to_vec(),
        }
    }

    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            PLAIN_ACCOUNT_KEY_LEN => PlainKey::Account(Address::from_slice(buf)),
            PLAIN_STORAGE_KEY_LEN => {
                let addr = Address::from_slice(&buf[..PLAIN_ACCOUNT_KEY_LEN]);
                let slot_id = B256::from_slice(&buf[PLAIN_ACCOUNT_KEY_LEN..]);
                PlainKey::Storage(addr, slot_id)
            }
            _ => unreachable!("unexpected length of plain key."),
        }
    }
}

impl From<Address> for PlainKey {
    #[inline]
    fn from(addr: Address) -> Self {
        PlainKey::Account(addr)
    }
}

impl From<(Address, B256)> for PlainKey {
    #[inline]
    fn from((addr, storage): (Address, B256)) -> Self {
        PlainKey::Storage(addr, storage)
    }
}

/// Value of PlainAccount/StorageState.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainValue {
    /// If Account is empty, means the account should be deleted.
    Account(Account),
    /// Value of plainStorageState.
    Storage(U256),
}

impl PlainValue {
    /// Convert PlainValue to Vec.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainValue::Account(account) => {
                let mut buffer = [0; PLAIN_CONTRACT_ACCOUNT_LEN];
                buffer[..U64_BYTES_LEN].copy_from_slice(account.nonce.to_be_bytes().as_ref());
                buffer[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]
                    .copy_from_slice(account.balance.to_be_bytes::<BALANCE_BYTES_LEN>().as_ref());
                if let Some(bytecode_hash) = account.bytecode_hash {
                    buffer[PLAIN_EOA_ACCOUNT_LEN..PLAIN_CONTRACT_ACCOUNT_LEN]
                        .copy_from_slice(bytecode_hash.as_slice());
                    buffer.to_vec()
                } else {
                    buffer[..PLAIN_EOA_ACCOUNT_LEN].to_vec()
                }
            }
            PlainValue::Storage(value) => value.to_be_bytes::<PLAIN_STORAGE_LEN>().to_vec(),
        }
    }

    /// Decode Vec to PlainValue.
    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            PLAIN_EOA_ACCOUNT_LEN => {
                let nonce = u64::from_be_bytes(buf[..U64_BYTES_LEN].try_into().unwrap());
                let balance = U256::from_be_slice(&buf[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]);
                PlainValue::Account(Account {
                    nonce,
                    balance,
                    bytecode_hash: None,
                })
            }
            PLAIN_CONTRACT_ACCOUNT_LEN => {
                let nonce = u64::from_be_bytes(buf[..U64_BYTES_LEN].try_into().unwrap());
                let balance = U256::from_be_slice(&buf[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]);
                let bytecode_hash =
                    B256::from_slice(&buf[PLAIN_EOA_ACCOUNT_LEN..PLAIN_CONTRACT_ACCOUNT_LEN]);
                PlainValue::Account(Account {
                    nonce,
                    balance,
                    bytecode_hash: Some(bytecode_hash),
                })
            }
            PLAIN_STORAGE_LEN => PlainValue::Storage(U256::from_be_slice(buf)),
            _ => unreachable!("unexpected length of plain value."),
        }
    }
}

impl From<Account> for PlainValue {
    #[inline]
    fn from(account: Account) -> Self {
        PlainValue::Account(account)
    }
}

impl From<U256> for PlainValue {
    #[inline]
    fn from(value: U256) -> Self {
        PlainValue::Storage(value)
    }
}

impl From<PlainValue> for Account {
    #[inline]
    fn from(value: PlainValue) -> Self {
        match value {
            PlainValue::Account(account) => account,
            _ => unreachable!("PlainValue is not Account"),
        }
    }
}

impl From<PlainValue> for U256 {
    #[inline]
    fn from(value: PlainValue) -> Self {
        match value {
            PlainValue::Storage(value) => value,
            _ => unreachable!("PlainValue is not U256"),
        }
    }
}

/// Local Account implementation when reth feature is disabled
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Account {
    /// Account nonce.
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
    /// Account bytecode hash.
    pub bytecode_hash: Option<B256>,
}

impl Account {
    /// Returns true if account is empty.
    pub fn is_empty(&self) -> bool {
        self.balance.is_zero() && self.nonce == 0 && self.bytecode_hash.is_none()
    }
}
