//! A signed Optimism transaction, used to convert [`op_alloy_rpc_types::Transaction`] to
//! [`mega_evm::Transaction`];
//!
//! ref:
//! https://github.com/megaeth-labs/mega-reth/blob/refactor/base-on-v1.3.4/crates/optimism/primitives/src/transaction/signed.rs

use alloy_consensus::{Transaction as TransactionTrait, Typed2718};
use alloy_eips::{eip2718::Encodable2718, eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_evm::{FromRecoveredTx, FromTxWithEncoded};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use mega_evm::Transaction;
use op_alloy_consensus::OpTxEnvelope;
use op_alloy_rpc_types::Transaction as OpTransaction;
use op_revm::transaction::deposit::DepositTransactionParts;
use revm::context::TxEnv;
use revm::context_interface::either::Either;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpTransactionSigned(pub OpTransaction);

impl OpTransactionSigned {
    pub fn op_tx_envelope(&self) -> &OpTxEnvelope {
        self.0.inner.inner.inner()
    }
}

impl From<OpTransaction> for OpTransactionSigned {
    fn from(tx: OpTransaction) -> Self {
        OpTransactionSigned(tx)
    }
}

impl FromRecoveredTx<OpTransactionSigned> for Transaction {
    fn from_recovered_tx(tx: &OpTransactionSigned, sender: Address) -> Self {
        let op_tx_envelope = tx.op_tx_envelope();

        let mut buf = Vec::with_capacity(op_tx_envelope.eip2718_encoded_length());
        op_tx_envelope.encode_2718(&mut buf);
        let envelope = buf.into();

        let base = match op_tx_envelope {
            OpTxEnvelope::Legacy(tx) => {
                let tx_legacy = tx.tx();
                TxEnv {
                    gas_limit: tx_legacy.gas_limit,
                    gas_price: tx_legacy.gas_price,
                    gas_priority_fee: None,
                    kind: tx_legacy.to,
                    value: tx_legacy.value,
                    data: tx_legacy.input.clone(),
                    chain_id: tx_legacy.chain_id,
                    nonce: tx_legacy.nonce,
                    access_list: Default::default(),
                    blob_hashes: Default::default(),
                    max_fee_per_blob_gas: Default::default(),
                    authorization_list: Default::default(),
                    tx_type: 0,
                    caller: sender,
                }
            }
            OpTxEnvelope::Eip2930(tx) => {
                let tx_eip2930 = tx.tx();
                TxEnv {
                    gas_limit: tx_eip2930.gas_limit,
                    gas_price: tx_eip2930.gas_price,
                    gas_priority_fee: None,
                    kind: tx_eip2930.to,
                    value: tx_eip2930.value,
                    data: tx_eip2930.input.clone(),
                    chain_id: Some(tx_eip2930.chain_id),
                    nonce: tx_eip2930.nonce,
                    access_list: tx_eip2930.access_list.clone(),
                    blob_hashes: Default::default(),
                    max_fee_per_blob_gas: Default::default(),
                    authorization_list: Default::default(),
                    tx_type: 1,
                    caller: sender,
                }
            }
            OpTxEnvelope::Eip1559(tx) => {
                let tx_eip1559 = tx.tx();
                TxEnv {
                    gas_limit: tx_eip1559.gas_limit,
                    gas_price: tx_eip1559.max_fee_per_gas,
                    gas_priority_fee: Some(tx_eip1559.max_priority_fee_per_gas),
                    kind: tx_eip1559.to,
                    value: tx_eip1559.value,
                    data: tx_eip1559.input.clone(),
                    chain_id: Some(tx_eip1559.chain_id),
                    nonce: tx_eip1559.nonce,
                    access_list: tx_eip1559.access_list.clone(),
                    blob_hashes: Default::default(),
                    max_fee_per_blob_gas: Default::default(),
                    authorization_list: Default::default(),
                    tx_type: 2,
                    caller: sender,
                }
            }
            OpTxEnvelope::Eip7702(tx) => {
                let tx_eip7702 = tx.tx();
                TxEnv {
                    gas_limit: tx_eip7702.gas_limit,
                    gas_price: tx_eip7702.max_fee_per_gas,
                    gas_priority_fee: Some(tx_eip7702.max_priority_fee_per_gas),
                    kind: TxKind::Call(tx_eip7702.to),
                    value: tx_eip7702.value,
                    data: tx_eip7702.input.clone(),
                    chain_id: Some(tx_eip7702.chain_id),
                    nonce: tx_eip7702.nonce,
                    access_list: tx_eip7702.access_list.clone(),
                    blob_hashes: Default::default(),
                    max_fee_per_blob_gas: Default::default(),
                    authorization_list: tx_eip7702
                        .authorization_list
                        .iter()
                        .map(|s| Either::Left(s.clone()))
                        .collect(),
                    tx_type: 4,
                    caller: sender,
                }
            }
            OpTxEnvelope::Deposit(tx) => {
                let tx_deposit = tx.inner();
                TxEnv {
                    gas_limit: tx_deposit.gas_limit,
                    gas_price: 0,
                    kind: tx_deposit.to,
                    value: tx_deposit.value,
                    data: tx_deposit.input.clone(),
                    chain_id: None,
                    nonce: 0,
                    access_list: Default::default(),
                    blob_hashes: Default::default(),
                    max_fee_per_blob_gas: Default::default(),
                    authorization_list: Default::default(),
                    gas_priority_fee: Default::default(),
                    tx_type: 126,
                    caller: sender,
                }
            }
        };

        Self {
            base,
            enveloped_tx: Some(envelope),
            deposit: if let OpTxEnvelope::Deposit(tx) = &op_tx_envelope {
                DepositTransactionParts {
                    is_system_transaction: tx.is_system_transaction,
                    source_hash: tx.source_hash,
                    // For consistency with op-geth, we always return `0x0` for mint if it is
                    // missing This is because op-geth does not distinguish
                    // between null and 0, because this value is decoded from RLP where null is
                    // represented as 0
                    mint: Some(tx.mint),
                }
            } else {
                Default::default()
            },
        }
    }
}

impl Typed2718 for OpTransactionSigned {
    fn ty(&self) -> u8 {
        self.op_tx_envelope().tx_type() as u8
    }
}

impl TransactionTrait for OpTransactionSigned {
    fn chain_id(&self) -> Option<u64> {
        self.op_tx_envelope().chain_id()
    }

    fn nonce(&self) -> u64 {
        self.op_tx_envelope().nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.op_tx_envelope().gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.op_tx_envelope().gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.op_tx_envelope().max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.op_tx_envelope().max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.op_tx_envelope().max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.op_tx_envelope().priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.op_tx_envelope().effective_gas_price(base_fee)
    }

    fn effective_tip_per_gas(&self, base_fee: u64) -> Option<u128> {
        self.op_tx_envelope().effective_tip_per_gas(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.op_tx_envelope().is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.op_tx_envelope().kind()
    }

    fn is_create(&self) -> bool {
        self.op_tx_envelope().is_create()
    }

    fn value(&self) -> U256 {
        self.op_tx_envelope().value()
    }

    fn input(&self) -> &Bytes {
        self.op_tx_envelope().input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.op_tx_envelope().access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.op_tx_envelope().blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.op_tx_envelope().authorization_list()
    }
}

impl Encodable2718 for OpTransactionSigned {
    fn type_flag(&self) -> Option<u8> {
        if Typed2718::is_legacy(self) {
            None
        } else {
            Some(self.ty())
        }
    }

    fn encode_2718_len(&self) -> usize {
        self.op_tx_envelope().eip2718_encoded_length()
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.op_tx_envelope().encode_2718(out)
    }
}

impl FromTxWithEncoded<OpTransactionSigned> for Transaction {
    fn from_encoded_tx(tx: &OpTransactionSigned, sender: Address, encoded: Bytes) -> Self {
        let mut tx = Transaction::from_recovered_tx(tx, sender);
        tx.enveloped_tx = Some(encoded);
        tx
    }
}
