//! Chain specification and hardfork activation logic.

use alloy_genesis::Genesis;
use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition, Hardfork};
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use mega_evm::SpecId;
use reth_ethereum_forks::ChainHardforks;
use reth_optimism_chainspec::OpChainSpec;
use std::sync::LazyLock;

pub use megaeth_chainspec::*;

/// Chain ID for the EVM configuration
pub const MEGA_CHAIN_ID: u64 = 6342;

/// Default blob gas price update fraction for Cancun (from EIP-4844)
pub const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3338477;

/// Chain specification for the Optimism network.
///
/// Defines when various Ethereum and Optimism hardforks are activated.
/// This configuration determines which EVM features are available at
/// different block numbers or timestamps.
#[derive(Default, Clone)]
pub struct ChainSpec {
    inner: ChainHardforks,
}

impl EthereumHardforks for ChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.inner.fork(fork)
    }
}

impl OpHardforks for ChainSpec {
    fn op_fork_activation(&self, fork: OpHardfork) -> ForkCondition {
        self.inner.fork(fork)
    }
}

impl MegaethHardforks for ChainSpec {
    fn megaeth_fork_activation(&self, fork: MegaethHardfork) -> ForkCondition {
        self.inner.fork(fork)
    }
}

impl ChainSpec {
    /// Returns the appropriate SpecId for the given timestamp.
    ///
    /// This method determines which EVM specification should be used based on
    /// the timestamp and the configured hardfork activation rules.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The timestamp to get the SpecId for
    ///
    /// # Returns
    ///
    /// The SpecId that should be used for EVM execution at the given timestamp.
    pub fn spec_id_at_timestamp(&self, timestamp: u64) -> SpecId {
        if self.is_mini_rex_active_at_timestamp(timestamp) {
            SpecId::MINI_REX
        } else {
            SpecId::EQUIVALENCE
        }
    }

    /// Create a new [`MegaethChainSpec`] from a [`Genesis`].
    pub fn from_genesis(genesis: Genesis) -> Self {
        // extract megaeth hardforks from genesis
        let mut megaeth_hardforks =
            MegaethGenesisHardforks::extract_from(&genesis.config.extra_fields)
                .unwrap_or_default()
                .into_vec();

        let op_chain_spec = OpChainSpec::from_genesis(genesis);

        // extract op hardforks from parsed genesis
        let mut op_hardforks: Vec<(Box<dyn Hardfork>, ForkCondition)> = op_chain_spec
            .inner
            .hardforks
            .forks_iter()
            .map(|(f, b)| (dyn_clone::clone_box(f), b))
            .collect();

        // we merge megaeth_hardforks with op_hardforks, and order them as hardfork_order
        let hardfork_order = DEV_HARDFORKS.forks_iter();
        let mut all_hardforks = Vec::with_capacity(op_hardforks.len() + megaeth_hardforks.len());
        for (order, _) in hardfork_order {
            if let Some(mega_hardfork_index) = megaeth_hardforks
                .iter()
                .position(|(hardfork, _)| **hardfork == *order)
            {
                all_hardforks.push(megaeth_hardforks.remove(mega_hardfork_index));
            } else if let Some(op_hardfork_index) = op_hardforks
                .iter()
                .position(|(hardfork, _)| **hardfork == *order)
            {
                all_hardforks.push(op_hardforks.remove(op_hardfork_index));
            } else {
                // hardfork unspecified in genesis, we add it as never
                all_hardforks.push((order.boxed(), ForkCondition::Never));
            }
        }
        // any remaining megaeth and op hardforks are unknown, so we add them to the end
        all_hardforks.append(&mut megaeth_hardforks);
        all_hardforks.append(&mut op_hardforks);

        Self {
            inner: ChainHardforks::new(all_hardforks),
        }
    }
}

/// The ChainSpec for the MegaETH network .
pub static CHAIN_SPEC: LazyLock<ChainSpec> = LazyLock::new(|| {
    let mainnet_genesis_json = include_str!("../../genesis-6342.json");

    // Parse the genesis JSON
    let genesis: Genesis = serde_json::from_str(mainnet_genesis_json).unwrap();
    ChainSpec::from_genesis(genesis)
});

pub mod megaeth_chainspec {
    use alloy_hardforks::{EthereumHardfork, ForkCondition, Hardfork, hardfork};
    use alloy_op_hardforks::{OpHardfork, OpHardforks};
    use alloy_primitives::U256;
    use alloy_serde::OtherFields;
    use reth_ethereum_forks::ChainHardforks;
    use std::sync::LazyLock;

    hardfork! {
        /// The name of MegaETH hardforks. It is expected to mix with [`EthereumHardfork`] and
        /// [`OpHardfork`].
        #[derive(serde::Serialize, serde::Deserialize)]
        MegaethHardfork {
            /// Tentative name for the first hardfork.
            MiniRex,
        }
    }

    /// Extends [`OpHardforks`] with MegaETH helper methods.
    pub trait MegaethHardforks: OpHardforks {
        /// Retrieves [`ForkCondition`] by a [`MegaethHardfork`]. If `fork` is not present, returns
        /// [`ForkCondition::Never`].
        fn megaeth_fork_activation(&self, fork: MegaethHardfork) -> ForkCondition;

        /// Returns `true` if [`MegaethHardfork::MiniRex`] is active at given block timestamp.
        fn is_mini_rex_active_at_timestamp(&self, timestamp: u64) -> bool {
            self.megaeth_fork_activation(MegaethHardfork::MiniRex)
                .active_at_timestamp(timestamp)
        }
    }

    /// MegaETH hardfork configuration in genesis.
    #[derive(Default, Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MegaethGenesisHardforks {
        /// MiniRex hardfork timestamp.
        pub mini_rex_time: Option<u64>,
    }

    impl MegaethGenesisHardforks {
        /// Extract the MegaETH genesis hardforks from a genesis file.
        pub fn extract_from(others: &OtherFields) -> Option<Self> {
            others.deserialize_as().ok()
        }

        /// Convert the MegaETH genesis hardforks into a vector of hardforks and their conditions.
        pub fn into_vec(self) -> Vec<(Box<dyn Hardfork>, ForkCondition)> {
            std::iter::once((
                MegaethHardfork::MiniRex.boxed(),
                self.mini_rex_time.map(ForkCondition::Timestamp),
            ))
            .filter_map(|(hardfork, condition)| condition.map(|c| (hardfork, c)))
            .collect()
        }
    }

    /// Dev hardforks configuration for MegaETH.
    pub static DEV_HARDFORKS: LazyLock<ChainHardforks> = LazyLock::new(|| {
        ChainHardforks::new(vec![
            (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
            (
                EthereumHardfork::SpuriousDragon.boxed(),
                ForkCondition::Block(0),
            ),
            (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
            (
                EthereumHardfork::Constantinople.boxed(),
                ForkCondition::Block(0),
            ),
            (
                EthereumHardfork::Petersburg.boxed(),
                ForkCondition::Block(0),
            ),
            (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
            (
                EthereumHardfork::Paris.boxed(),
                ForkCondition::TTD {
                    activation_block_number: 0,
                    fork_block: None,
                    total_difficulty: U256::ZERO,
                },
            ),
            (OpHardfork::Bedrock.boxed(), ForkCondition::Block(0)),
            (OpHardfork::Regolith.boxed(), ForkCondition::Timestamp(0)),
            (
                EthereumHardfork::Shanghai.boxed(),
                ForkCondition::Timestamp(0),
            ),
            (OpHardfork::Canyon.boxed(), ForkCondition::Timestamp(0)),
            (
                EthereumHardfork::Cancun.boxed(),
                ForkCondition::Timestamp(0),
            ),
            (OpHardfork::Ecotone.boxed(), ForkCondition::Timestamp(0)),
            (OpHardfork::Fjord.boxed(), ForkCondition::Timestamp(0)),
            (OpHardfork::Granite.boxed(), ForkCondition::Timestamp(0)),
            (OpHardfork::Holocene.boxed(), ForkCondition::Timestamp(0)),
            (
                EthereumHardfork::Prague.boxed(),
                ForkCondition::Timestamp(0),
            ),
            (OpHardfork::Isthmus.boxed(), ForkCondition::Timestamp(0)),
            (
                MegaethHardfork::MiniRex.boxed(),
                ForkCondition::Timestamp(0),
            ),
        ])
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_serde::OtherFields;

    #[test]
    fn test_create_from_default_genesis() {
        let genesis = Genesis::default();
        let spec = ChainSpec::from_genesis(genesis);

        assert!(!spec.inner.is_empty());
    }

    #[test]
    fn test_merge_mega_hardforks_in_op_hardforks() {
        let mut genesis = Genesis::default();
        genesis
            .config
            .extra_fields
            .insert_value("ecotoneTime".to_string(), 1)
            .unwrap();
        genesis
            .config
            .extra_fields
            .insert_value("graniteTime".to_string(), 2)
            .unwrap();
        genesis
            .config
            .extra_fields
            .insert_value("holoceneTime".to_string(), 3)
            .unwrap();
        genesis
            .config
            .extra_fields
            .insert_value("miniRexTime".to_string(), 3)
            .unwrap();
        genesis
            .config
            .extra_fields
            .insert_value("isthmusTime".to_string(), 6)
            .unwrap();
        let spec = ChainSpec::from_genesis(genesis);

        assert_eq!(
            spec.inner.fork(EthereumHardfork::Cancun), // equivalent to ecotoneTime
            ForkCondition::Timestamp(1)
        );
        assert_eq!(
            spec.inner.fork(EthereumHardfork::Prague), // equivalent to isthmusTime
            ForkCondition::Timestamp(6)
        );
        assert_eq!(
            spec.inner.fork(OpHardfork::Granite),
            ForkCondition::Timestamp(2)
        );
        assert_eq!(
            spec.inner.fork(OpHardfork::Holocene),
            ForkCondition::Timestamp(3)
        );
        assert_eq!(
            spec.inner.fork(OpHardfork::Isthmus),
            ForkCondition::Timestamp(6)
        );
        assert_eq!(
            spec.inner.fork(MegaethHardfork::MiniRex),
            ForkCondition::Timestamp(3)
        );
    }

    #[test]
    fn test_extract_from_json() {
        let genesis_info = r#"
        {
          "miniRexTime": 1
        }
        "#;
        let fields = serde_json::from_str::<OtherFields>(genesis_info).unwrap();
        let hardforks = MegaethGenesisHardforks::extract_from(&fields).unwrap();
        assert_eq!(hardforks.mini_rex_time, Some(1));
    }
}
