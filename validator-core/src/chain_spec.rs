//! Chain specification and hardfork activation logic.

use alloy_genesis::Genesis;
use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition, Hardfork};
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use alloy_serde::OtherFields;
use mega_evm::SpecId;
use reth_ethereum_forks::{ChainHardforks, hardfork};
use reth_optimism_chainspec::OpChainSpec;

/// Default blob gas price update fraction for Cancun (from EIP-4844)
pub const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3338477;

/// Chain specification for the Optimism network.
///
/// Defines when various Ethereum and Optimism hardforks are activated.
/// This configuration determines which EVM features are available at
/// different block numbers or timestamps.
#[derive(Default, Clone, Debug)]
pub struct ChainSpec {
    pub chain_id: u64,
    pub hardforks: ChainHardforks,
}

impl EthereumHardforks for ChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.hardforks.fork(fork)
    }
}

impl OpHardforks for ChainSpec {
    fn op_fork_activation(&self, fork: OpHardfork) -> ForkCondition {
        self.hardforks.fork(fork)
    }
}

impl MegaethHardforks for ChainSpec {
    fn megaeth_fork_activation(&self, fork: MegaethHardfork) -> ForkCondition {
        self.hardforks.fork(fork)
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
        if self.is_rex_active_at_timestamp(timestamp) {
            SpecId::REX
        } else if self.is_mini_rex_active_at_timestamp(timestamp) {
            SpecId::MINI_REX
        } else {
            SpecId::EQUIVALENCE
        }
    }

    /// Creates a new [`ChainSpec`] from a [`Genesis`].
    ///
    /// Ordering rules:
    /// - [`OpChainSpec`] already yields Optimism/Ethereum hardforks in the correct order, so
    ///   they do not require reordering.
    /// - MegaETH hardforks are extracted from the genesis `extra_fields` and explicitly
    ///   ordered to match the canonical sequence defined by [`MEGA_MAINNET_HARDFORKS`].
    ///   Any remaining, unknown MegaETH hardforks are preserved and appended after the
    ///   known ones so nothing is dropped.
    /// - The MegaETH set is then merged with the Optimism/Ethereum set to build a single
    ///   [`ChainHardforks`] that drives fork activation.
    ///
    /// This yields a deterministic activation order across all supported hardfork families.
    pub fn from_genesis(genesis: Genesis) -> Self {
        // extract megaeth hardforks from genesis
        let mut megaeth_hardforks =
            MegaethGenesisHardforks::extract_from(&genesis.config.extra_fields)
                .unwrap_or_default()
                .into_vec();

        let chain_id = genesis.config.chain_id;
        let op_chain_spec = OpChainSpec::from_genesis(genesis);

        // extract op hardforks from parsed genesis
        let mut op_hardforks: Vec<(Box<dyn Hardfork>, ForkCondition)> = op_chain_spec
            .inner
            .hardforks
            .forks_iter()
            .map(|(f, b)| (dyn_clone::clone_box(f), b))
            .collect();

        let hardfork_order = MEGA_MAINNET_HARDFORKS.forks_iter();
        let mut all_hardforks = Vec::with_capacity(op_hardforks.len() + megaeth_hardforks.len());
        for (order, _) in hardfork_order {
            if let Some(mega_hardfork_index) = megaeth_hardforks
                .iter()
                .position(|(hardfork, _)| **hardfork == *order)
            {
                all_hardforks.push(megaeth_hardforks.remove(mega_hardfork_index));
            }
        }

        // append the remaining unknown hardforks to ensure we don't filter any out
        all_hardforks.append(&mut megaeth_hardforks);

        // we merge megaeth_hardforks with op_hardforks
        all_hardforks.append(&mut op_hardforks);

        Self {
            chain_id,
            hardforks: ChainHardforks::new(all_hardforks),
        }
    }
}

hardfork! {
    /// The name of MegaETH hardforks. It is expected to mix with [`EthereumHardfork`] and
    /// [`OpHardfork`].
    #[derive(serde::Serialize, serde::Deserialize)]
    MegaethHardfork {
        /// Tentative name for the first hardfork.
        MiniRex,
        /// Tentative name for the second hardfork.
        Rex,
    }
}

/// Extends [`OpHardforks`] with MegaETH helper methods.
pub trait MegaethHardforks {
    /// Retrieves [`ForkCondition`] by a [`MegaethHardfork`]. If `fork` is not present, returns
    /// [`ForkCondition::Never`].
    fn megaeth_fork_activation(&self, fork: MegaethHardfork) -> ForkCondition;

    /// Returns `true` if [`MegaethHardfork::MiniRex`] is active at given block timestamp.
    fn is_mini_rex_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.megaeth_fork_activation(MegaethHardfork::MiniRex)
            .active_at_timestamp(timestamp)
    }

    /// Returns `true` if [`MegaethHardfork::Rex`] is active at given block timestamp.
    fn is_rex_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.megaeth_fork_activation(MegaethHardfork::Rex)
            .active_at_timestamp(timestamp)
    }
}

/// MegaETH hardfork configuration in genesis.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MegaethGenesisHardforks {
    /// MiniRex hardfork timestamp.
    pub mini_rex_time: Option<u64>,
    /// Rex hardfork timestamp.
    pub rex_time: Option<u64>,
}

impl MegaethGenesisHardforks {
    /// Extract the MegaETH genesis hardforks from a genesis file.
    pub fn extract_from(others: &OtherFields) -> Option<Self> {
        others.deserialize_as().ok()
    }

    /// Convert the MegaETH genesis hardforks into a vector of hardforks and their conditions.
    pub fn into_vec(self) -> Vec<(Box<dyn Hardfork>, ForkCondition)> {
        vec![
            (
                MegaethHardfork::MiniRex.boxed(),
                self.mini_rex_time.map(ForkCondition::Timestamp),
            ),
            (
                MegaethHardfork::Rex.boxed(),
                self.rex_time.map(ForkCondition::Timestamp),
            ),
        ]
        .into_iter()
        .filter_map(|(hardfork, condition)| condition.map(|c| (hardfork, c)))
        .collect()
    }
}

/// Hardforks configuration for MegaETH.
pub static MEGA_MAINNET_HARDFORKS: std::sync::LazyLock<ChainHardforks> =
    std::sync::LazyLock::new(|| {
        ChainHardforks::new(vec![
            (
                MegaethHardfork::MiniRex.boxed(),
                ForkCondition::Timestamp(0),
            ),
            (MegaethHardfork::Rex.boxed(), ForkCondition::Timestamp(0)),
        ])
    });

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_serde::OtherFields;

    #[test]
    fn test_create_from_default_genesis() {
        let genesis = Genesis::default();
        let spec = ChainSpec::from_genesis(genesis);

        assert!(!spec.hardforks.is_empty());
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
            spec.hardforks.fork(EthereumHardfork::Cancun), // equivalent to ecotoneTime
            ForkCondition::Timestamp(1)
        );
        assert_eq!(
            spec.hardforks.fork(EthereumHardfork::Prague), // equivalent to isthmusTime
            ForkCondition::Timestamp(6)
        );
        assert_eq!(
            spec.hardforks.fork(OpHardfork::Granite),
            ForkCondition::Timestamp(2)
        );
        assert_eq!(
            spec.hardforks.fork(OpHardfork::Holocene),
            ForkCondition::Timestamp(3)
        );
        assert_eq!(
            spec.hardforks.fork(OpHardfork::Isthmus),
            ForkCondition::Timestamp(6)
        );
        assert_eq!(
            spec.hardforks.fork(MegaethHardfork::MiniRex),
            ForkCondition::Timestamp(3)
        );
    }

    #[test]
    fn test_extract_from_json() {
        let genesis_info = r#"
        {
          "miniRexTime": 1,
          "rexTime": 2
        }
        "#;
        let fields = serde_json::from_str::<OtherFields>(genesis_info).unwrap();
        let hardforks = MegaethGenesisHardforks::extract_from(&fields).unwrap();
        assert_eq!(hardforks.mini_rex_time, Some(1));
        assert_eq!(hardforks.rex_time, Some(2));
    }
}
