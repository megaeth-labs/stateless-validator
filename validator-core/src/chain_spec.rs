//! Chain specification and hardfork activation logic.

use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition};
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use mega_evm::SpecId;

/// Chain ID for the EVM configuration
pub const MEGA_CHAIN_ID: u64 = 6342;

/// Default blob gas price update fraction for Cancun (from EIP-4844)
pub const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3338477;

/// Chain specification for the Optimism network.
///
/// Defines when various Ethereum and Optimism hardforks are activated.
/// This configuration determines which EVM features are available at
/// different block numbers or timestamps.
#[derive(Default, Clone, Copy)]
pub struct ChainSpec;

impl EthereumHardforks for ChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        use EthereumHardfork::*;
        match fork {
            Shanghai | Cancun | Prague => ForkCondition::Timestamp(0),
            Osaka => ForkCondition::Never,
            _ => ForkCondition::Block(0),
        }
    }
}

impl OpHardforks for ChainSpec {
    fn op_fork_activation(&self, fork: OpHardfork) -> ForkCondition {
        use OpHardfork::*;
        match fork {
            Bedrock => ForkCondition::Block(0),
            Interop => ForkCondition::Never,
            _ => ForkCondition::Timestamp(0),
        }
    }
}

impl ChainSpec {
    /// Returns the appropriate SpecId for the given block number.
    ///
    /// This method determines which EVM specification should be used based on
    /// the block number and the configured hardfork activation rules. Currently
    /// returns EQUIVALENCE for all blocks, but can be extended to support
    /// different SpecIds for different hardfork activations.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number to get the SpecId for
    ///
    /// # Returns
    ///
    /// The SpecId that should be used for EVM execution at the given block number.
    pub fn spec_id_at_block(&self, _block_number: u64) -> SpecId {
        // TODO: Implement hardfork-based SpecId selection based on block_number
        // For now, return EQUIVALENCE for all blocks
        SpecId::EQUIVALENCE
    }
}
