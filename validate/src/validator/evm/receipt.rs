use alloy_consensus::{Eip658Value, Receipt, TxReceipt};
use alloy_primitives::{Bloom, Log};
use op_alloy_consensus::OpDepositReceipt;

/// Typed ethereum transaction receipt.
/// Receipt containing result of transaction execution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OpReceipt {
    /// Legacy receipt
    Legacy(Receipt),
    /// EIP-2930 receipt
    Eip2930(Receipt),
    /// EIP-1559 receipt
    Eip1559(Receipt),
    /// EIP-7702 receipt
    Eip7702(Receipt),
    /// Deposit receipt
    Deposit(OpDepositReceipt),
}

impl OpReceipt {
    /// Returns inner [`Receipt`],
    pub const fn as_receipt(&self) -> &Receipt {
        match self {
            Self::Legacy(receipt)
            | Self::Eip2930(receipt)
            | Self::Eip1559(receipt)
            | Self::Eip7702(receipt) => receipt,
            Self::Deposit(receipt) => &receipt.inner,
        }
    }
}

impl TxReceipt for OpReceipt {
    type Log = Log;

    fn status_or_post_state(&self) -> Eip658Value {
        self.as_receipt().status_or_post_state()
    }

    fn status(&self) -> bool {
        self.as_receipt().status()
    }

    fn bloom(&self) -> Bloom {
        self.as_receipt().bloom()
    }

    fn cumulative_gas_used(&self) -> u64 {
        self.as_receipt().cumulative_gas_used()
    }

    fn logs(&self) -> &[Log] {
        self.as_receipt().logs()
    }
}
