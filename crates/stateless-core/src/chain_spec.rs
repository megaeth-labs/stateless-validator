//! Chain specification and hardfork activation logic.

use core::any::Any;
use std::{boxed::Box, vec, vec::Vec};

use alloy_genesis::Genesis;
use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition, Hardfork};
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use alloy_primitives::Address;
use alloy_serde::OtherFields;
use mega_evm::{HardforkParams, MegaHardfork, MegaHardforks, SequencerRegistryConfig};
use reth_ethereum_forks::ChainHardforks;
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
    /// Rex5 `SequencerRegistry` bootstrap, parsed from genesis `config` extra fields.
    ///
    /// `None` for pre-Rex5 chains; `Some(...)` when `rex5Time` is configured.
    pub sequencer_registry_config: Option<SequencerRegistryConfig>,
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

impl MegaHardforks for ChainSpec {
    fn mega_fork_activation(&self, fork: MegaHardfork) -> ForkCondition {
        self.hardforks.fork(fork)
    }

    fn fork_params_any(&self, fork: MegaHardfork) -> Option<&(dyn Any + Send + Sync)> {
        match fork {
            MegaHardfork::Rex5 => {
                self.sequencer_registry_config.as_ref().map(|c| c as &(dyn Any + Send + Sync))
            }
            _ => None,
        }
    }
}

impl ChainSpec {
    /// Creates a new [`ChainSpec`] from a [`Genesis`].
    ///
    /// Ordering rules:
    /// - [`OpChainSpec`] already yields Optimism/Ethereum hardforks in the correct order, so they
    ///   do not require reordering.
    /// - MegaETH hardforks are extracted from the genesis `extra_fields` and explicitly ordered to
    ///   match the canonical sequence defined by [`mega_mainnet_hardforks()`]. Any remaining,
    ///   unknown MegaETH hardforks are preserved and appended after the known ones so nothing is
    ///   dropped.
    /// - The MegaETH set is then merged with the Optimism/Ethereum set to build a single
    ///   [`ChainHardforks`] that drives fork activation.
    ///
    /// When `rex5Time` is configured, the genesis `config` extra fields must also carry the flat
    /// `rex5InitialSequencer` / `rex5InitialAdmin` addresses; both are validated immediately so a
    /// misconfigured genesis fails at load rather than at the first Rex5 block.
    pub fn from_genesis(genesis: Genesis) -> Self {
        // A malformed `rex5Time` treated as "Rex5 absent" would skip the bootstrap-required
        // check and diverge from mega-reth at the activation timestamp, so surface parse errors.
        let megaeth_hardforks = MegaethGenesisHardforks::extract_from(&genesis.config.extra_fields)
            .unwrap_or_else(|err| panic!("malformed MegaETH hardforks in genesis: {err}"));
        let rex5_scheduled = megaeth_hardforks.rex_5_time.is_some();
        let mut megaeth_hardforks = megaeth_hardforks.into_vec();

        // Rex5 SequencerRegistry bootstrap, required iff `rex5Time` is scheduled. Parsed from
        // the same flat schema mega-reth uses (`rex5InitialSequencer` / `rex5InitialAdmin` as
        // top-level `config` fields), so a single genesis.json works for both binaries.
        let sequencer_registry_config = if rex5_scheduled {
            let parsed = MegaethGenesisSequencerRegistryConfig::parse_required_from(
                &genesis.config.extra_fields,
            )
            .unwrap_or_else(|err| {
                panic!("malformed or missing SequencerRegistryConfig in genesis: {err}")
            });
            let cfg = parsed.into_config();
            cfg.validate().unwrap_or_else(|err| panic!("invalid SequencerRegistryConfig: {err}"));
            Some(cfg)
        } else {
            None
        };

        let chain_id = genesis.config.chain_id;
        let op_chain_spec = OpChainSpec::from_genesis(genesis);

        // extract op hardforks from parsed genesis
        let mut op_hardforks: Vec<(Box<dyn Hardfork>, ForkCondition)> = op_chain_spec
            .inner
            .hardforks
            .forks_iter()
            .map(|(f, b)| (dyn_clone::clone_box(f), b))
            .collect();

        let hardfork_order = mega_mainnet_hardforks();
        let mut all_hardforks = Vec::with_capacity(op_hardforks.len() + megaeth_hardforks.len());
        for (order, _) in hardfork_order.forks_iter() {
            if let Some(mega_hardfork_index) =
                megaeth_hardforks.iter().position(|(hardfork, _)| **hardfork == *order)
            {
                all_hardforks.push(megaeth_hardforks.remove(mega_hardfork_index));
            }
        }

        // append the remaining unknown hardforks to ensure we don't filter any out
        all_hardforks.append(&mut megaeth_hardforks);

        // we merge megaeth_hardforks with op_hardforks
        all_hardforks.append(&mut op_hardforks);

        Self { chain_id, hardforks: ChainHardforks::new(all_hardforks), sequencer_registry_config }
    }
}

/// MegaETH hardfork configuration in genesis.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MegaethGenesisHardforks {
    /// MiniRex hardfork timestamp.
    pub mini_rex_time: Option<u64>,
    /// MiniRex1 hardfork timestamp.
    pub mini_rex_1_time: Option<u64>,
    /// MiniRex2 hardfork timestamp.
    pub mini_rex_2_time: Option<u64>,
    /// Rex hardfork timestamp.
    pub rex_time: Option<u64>,
    /// Rex1 hardfork timestamp.
    pub rex_1_time: Option<u64>,
    /// Rex2 hardfork timestamp.
    pub rex_2_time: Option<u64>,
    /// Rex3 hardfork timestamp.
    pub rex_3_time: Option<u64>,
    /// Rex4 hardfork timestamp.
    pub rex_4_time: Option<u64>,
    /// Rex5 hardfork timestamp.
    pub rex_5_time: Option<u64>,
}

impl MegaethGenesisHardforks {
    /// Extract the MegaETH genesis hardforks from a genesis file.
    ///
    /// Absent fields deserialize to `None`; present-but-malformed fields return an error.
    pub fn extract_from(others: &OtherFields) -> serde_json::Result<Self> {
        others.deserialize_as()
    }

    /// Convert the MegaETH genesis hardforks into a vector of hardforks and their conditions.
    pub fn into_vec(self) -> Vec<(Box<dyn Hardfork>, ForkCondition)> {
        vec![
            (MegaHardfork::MiniRex.boxed(), self.mini_rex_time.map(ForkCondition::Timestamp)),
            (MegaHardfork::MiniRex1.boxed(), self.mini_rex_1_time.map(ForkCondition::Timestamp)),
            (MegaHardfork::MiniRex2.boxed(), self.mini_rex_2_time.map(ForkCondition::Timestamp)),
            (MegaHardfork::Rex.boxed(), self.rex_time.map(ForkCondition::Timestamp)),
            (MegaHardfork::Rex1.boxed(), self.rex_1_time.map(ForkCondition::Timestamp)),
            (MegaHardfork::Rex2.boxed(), self.rex_2_time.map(ForkCondition::Timestamp)),
            (MegaHardfork::Rex3.boxed(), self.rex_3_time.map(ForkCondition::Timestamp)),
            (MegaHardfork::Rex4.boxed(), self.rex_4_time.map(ForkCondition::Timestamp)),
            (MegaHardfork::Rex5.boxed(), self.rex_5_time.map(ForkCondition::Timestamp)),
        ]
        .into_iter()
        .filter_map(|(hardfork, condition)| condition.map(|c| (hardfork, c)))
        .collect()
    }
}

/// Rex5 `SequencerRegistry` bootstrap, parsed from genesis `config` extra fields.
///
/// Flat schema (matches mega-reth) so a single genesis.json works for both binaries.
/// Both addresses must be non-zero or [`SequencerRegistryConfig::validate`] rejects them.
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MegaethGenesisSequencerRegistryConfig {
    /// Initial sequencer (mini-block signing key) seeded at Rex5 activation.
    pub rex5_initial_sequencer: Address,
    /// Initial admin (can schedule future role changes) seeded at Rex5 activation.
    pub rex5_initial_admin: Address,
}

impl MegaethGenesisSequencerRegistryConfig {
    /// Parse the required SequencerRegistry bootstrap from genesis extra fields.
    ///
    /// Returns a serde error if either address field is missing or malformed. Callers should
    /// only invoke it once they have decided the bootstrap is required, i.e. when `rex5Time`
    /// is configured.
    pub fn parse_required_from(others: &OtherFields) -> serde_json::Result<Self> {
        others.deserialize_as()
    }

    /// Convert to the canonical mega-evm [`SequencerRegistryConfig`].
    pub fn into_config(self) -> SequencerRegistryConfig {
        SequencerRegistryConfig {
            rex5_initial_sequencer: self.rex5_initial_sequencer,
            rex5_initial_admin: self.rex5_initial_admin,
        }
    }
}

/// Build a fresh `ChainHardforks` describing MegaETH's canonical hardfork sequence.
pub fn mega_mainnet_hardforks() -> ChainHardforks {
    ChainHardforks::new(vec![
        (MegaHardfork::MiniRex.boxed(), ForkCondition::Timestamp(0)),
        (MegaHardfork::MiniRex1.boxed(), ForkCondition::Timestamp(0)),
        (MegaHardfork::MiniRex2.boxed(), ForkCondition::Timestamp(0)),
        (MegaHardfork::Rex.boxed(), ForkCondition::Timestamp(0)),
        (MegaHardfork::Rex1.boxed(), ForkCondition::Timestamp(0)),
        (MegaHardfork::Rex2.boxed(), ForkCondition::Timestamp(0)),
        (MegaHardfork::Rex3.boxed(), ForkCondition::Timestamp(0)),
        (MegaHardfork::Rex4.boxed(), ForkCondition::Timestamp(0)),
        (MegaHardfork::Rex5.boxed(), ForkCondition::Timestamp(0)),
    ])
}

#[cfg(test)]
mod tests {
    use std::string::ToString;

    use alloy_serde::OtherFields;

    use super::*;

    #[test]
    fn test_create_from_default_genesis() {
        let genesis = Genesis::default();
        let spec = ChainSpec::from_genesis(genesis);

        assert!(!spec.hardforks.is_empty());
    }

    #[test]
    fn test_merge_mega_hardforks_in_op_hardforks() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("ecotoneTime".to_string(), 1).unwrap();
        genesis.config.extra_fields.insert_value("graniteTime".to_string(), 2).unwrap();
        genesis.config.extra_fields.insert_value("holoceneTime".to_string(), 3).unwrap();
        genesis.config.extra_fields.insert_value("miniRexTime".to_string(), 3).unwrap();
        genesis.config.extra_fields.insert_value("isthmusTime".to_string(), 6).unwrap();
        let spec = ChainSpec::from_genesis(genesis);

        assert_eq!(
            spec.hardforks.fork(EthereumHardfork::Cancun), // equivalent to ecotoneTime
            ForkCondition::Timestamp(1)
        );
        assert_eq!(
            spec.hardforks.fork(EthereumHardfork::Prague), // equivalent to isthmusTime
            ForkCondition::Timestamp(6)
        );
        assert_eq!(spec.hardforks.fork(OpHardfork::Granite), ForkCondition::Timestamp(2));
        assert_eq!(spec.hardforks.fork(OpHardfork::Holocene), ForkCondition::Timestamp(3));
        assert_eq!(spec.hardforks.fork(OpHardfork::Isthmus), ForkCondition::Timestamp(6));
        assert_eq!(spec.hardforks.fork(MegaHardfork::MiniRex), ForkCondition::Timestamp(3));
    }

    #[test]
    fn test_extract_from_json() {
        let genesis_info = r#"
        {
          "miniRexTime": 1,
          "miniRex1Time": 2,
          "miniRex2Time": 3,
          "rexTime": 4,
          "rex1Time": 5,
          "rex2Time": 6,
          "rex3Time": 7,
          "rex4Time": 8,
          "rex5Time": 9
        }
        "#;
        let fields = serde_json::from_str::<OtherFields>(genesis_info).unwrap();
        let hardforks = MegaethGenesisHardforks::extract_from(&fields).expect("well-formed");
        assert_eq!(hardforks.mini_rex_time, Some(1));
        assert_eq!(hardforks.mini_rex_1_time, Some(2));
        assert_eq!(hardforks.mini_rex_2_time, Some(3));
        assert_eq!(hardforks.rex_time, Some(4));
        assert_eq!(hardforks.rex_1_time, Some(5));
        assert_eq!(hardforks.rex_2_time, Some(6));
        assert_eq!(hardforks.rex_3_time, Some(7));
        assert_eq!(hardforks.rex_4_time, Some(8));
        assert_eq!(hardforks.rex_5_time, Some(9));
    }

    #[test]
    #[should_panic(expected = "malformed MegaETH hardforks in genesis")]
    fn test_chain_spec_malformed_rex5_time_panics() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("rex5Time".to_string(), "not-a-number").unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }

    #[test]
    fn test_parse_sequencer_registry_from_flat_json() {
        let genesis_info = r#"
        {
          "rex5Time": 0,
          "rex5InitialSequencer": "0x0000000000000000000000000000000000000001",
          "rex5InitialAdmin": "0x0000000000000000000000000000000000000002"
        }
        "#;
        let fields = serde_json::from_str::<OtherFields>(genesis_info).unwrap();
        let parsed = MegaethGenesisSequencerRegistryConfig::parse_required_from(&fields).unwrap();
        assert_eq!(parsed.rex5_initial_sequencer, Address::with_last_byte(1));
        assert_eq!(parsed.rex5_initial_admin, Address::with_last_byte(2));
    }

    #[test]
    fn test_chain_spec_carries_sequencer_registry_as_fork_params() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("rex5Time".to_string(), 0).unwrap();
        genesis
            .config
            .extra_fields
            .insert_value(
                "rex5InitialSequencer".to_string(),
                "0x0000000000000000000000000000000000000001",
            )
            .unwrap();
        genesis
            .config
            .extra_fields
            .insert_value(
                "rex5InitialAdmin".to_string(),
                "0x0000000000000000000000000000000000000002",
            )
            .unwrap();
        let spec = ChainSpec::from_genesis(genesis);
        let params = spec.fork_params::<SequencerRegistryConfig>().expect("Rex5 params present");
        assert_eq!(params.rex5_initial_sequencer, Address::with_last_byte(1));
        assert_eq!(params.rex5_initial_admin, Address::with_last_byte(2));
    }

    #[test]
    fn test_chain_spec_no_rex5_returns_none() {
        let genesis = Genesis::default();
        let spec = ChainSpec::from_genesis(genesis);
        assert!(spec.fork_params::<SequencerRegistryConfig>().is_none());
        assert!(spec.sequencer_registry_config.is_none());
    }

    #[test]
    #[should_panic(expected = "malformed or missing SequencerRegistryConfig in genesis")]
    fn test_chain_spec_rex5_without_bootstrap_panics() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("rex5Time".to_string(), 0).unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }

    #[test]
    #[should_panic(expected = "invalid SequencerRegistryConfig")]
    fn test_chain_spec_zero_sequencer_panics() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("rex5Time".to_string(), 0).unwrap();
        genesis
            .config
            .extra_fields
            .insert_value(
                "rex5InitialSequencer".to_string(),
                "0x0000000000000000000000000000000000000000",
            )
            .unwrap();
        genesis
            .config
            .extra_fields
            .insert_value(
                "rex5InitialAdmin".to_string(),
                "0x0000000000000000000000000000000000000002",
            )
            .unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }

    #[test]
    #[should_panic(expected = "invalid SequencerRegistryConfig")]
    fn test_chain_spec_zero_admin_panics() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("rex5Time".to_string(), 0).unwrap();
        genesis
            .config
            .extra_fields
            .insert_value(
                "rex5InitialSequencer".to_string(),
                "0x0000000000000000000000000000000000000001",
            )
            .unwrap();
        genesis
            .config
            .extra_fields
            .insert_value(
                "rex5InitialAdmin".to_string(),
                "0x0000000000000000000000000000000000000000",
            )
            .unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }
}
