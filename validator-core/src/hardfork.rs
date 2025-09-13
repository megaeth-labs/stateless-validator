//! Chain specification and hardfork activation logic.

use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition};
use alloy_op_hardforks::{OpHardfork, OpHardforks};

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
