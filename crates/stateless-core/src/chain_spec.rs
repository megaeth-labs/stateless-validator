//! Chain specification and hardfork activation logic.

use core::any::Any;
use std::{boxed::Box, vec, vec::Vec};

use alloy_genesis::Genesis;
use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition, Hardfork};
use alloy_op_hardforks::{OpHardfork, OpHardforks};
use alloy_primitives::Address;
use alloy_serde::OtherFields;
use mega_evm::{
    HardforkParams, MegaHardfork, MegaHardforks, SequencerRegistryConfig,
    SequencerRegistryRex6Config,
};
use reth_ethereum_forks::ChainHardforks;
use reth_optimism_chainspec::OpChainSpec;

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
    /// Rex6 `SequencerRegistry` rotation-hardening config, parsed from genesis `config` extra
    /// fields.
    ///
    /// `None` for pre-Rex6 chains; `Some(...)` when `rex6Time` is configured.
    pub sequencer_registry_rex6_config: Option<SequencerRegistryRex6Config>,
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
            MegaHardfork::Rex6 => {
                self.sequencer_registry_rex6_config.as_ref().map(|c| c as &(dyn Any + Send + Sync))
            }
            _ => None,
        }
    }
}

impl ChainSpec {
    /// Create a new [`ChainSpec`] from a [`Genesis`].
    ///
    /// Ordering rules:
    /// - [`OpChainSpec`] already yields Optimism/Ethereum hardforks in the correct order, so they
    ///   do not require reordering.
    /// - MegaETH hardforks are extracted from the genesis `extra_fields`;
    ///   [`MegaethGenesisHardforks::into_vec`] yields them in canonical activation order.
    /// - The MegaETH set is then merged with the Optimism/Ethereum set to build a single
    ///   [`ChainHardforks`] that drives fork activation.
    ///
    /// Panics if genesis schedules Rex5 (`rex5Time` set) or Rex6 (`rex6Time` set) but the bootstrap
    /// config is missing or malformed. The bootstrap is conditionally required: dropping the
    /// failure here would produce a chainspec that loads cleanly today and stalls the chain at
    /// the fork's activation with `"... active but SequencerRegistry...Config not configured"`.
    /// Surfacing it at chainspec-load means an operator typo fails fast on node start, before
    /// any block is ever produced.
    ///
    /// Also panics if genesis schedules Rex6 without Rex5, or with Rex5 after it
    /// (`rex5Time > rex6Time`; equal timestamps are legal — both forks activate together).
    /// Rex6 depends on the SequencerRegistry that the Rex5 activation deploys, so such a
    /// schedule would activate Rex6 with no registry in state and stall every block from the
    /// activation on with `"Rex5 active but SequencerRegistryConfig not configured"` — the
    /// same late-failure mode the load-time validation above exists to prevent.
    pub fn from_genesis(genesis: Genesis) -> Self {
        // A malformed `rex5Time`/`rex6Time` treated as "fork absent" would skip the
        // bootstrap-required check and diverge from mega-reth at the activation timestamp, so
        // surface parse errors.
        let megaeth_hardforks = MegaethGenesisHardforks::extract_from(&genesis.config.extra_fields)
            .unwrap_or_else(|err| panic!("malformed MegaETH hardforks in genesis: {err}"));
        let rex5_scheduled = megaeth_hardforks.rex_5_time.is_some();
        let rex6_scheduled = megaeth_hardforks.rex_6_time.is_some();

        // Rex6 needs the SequencerRegistry deployed by the Rex5 activation. A partial ladder
        // (Rex6 without Rex5, or Rex5 after Rex6) would load cleanly and then stall at the
        // Rex6 activation block, so reject it here. Equal timestamps are fine: both forks
        // activate together.
        if rex6_scheduled &&
            megaeth_hardforks
                .rex_5_time
                .zip(megaeth_hardforks.rex_6_time)
                .is_none_or(|(rex5, rex6)| rex5 > rex6)
        {
            panic!(
                "genesis schedules Rex6 but Rex5 is missing or scheduled after it \
                 (rex5Time={:?}, rex6Time={:?})",
                megaeth_hardforks.rex_5_time, megaeth_hardforks.rex_6_time
            );
        }

        let megaeth_hardforks = megaeth_hardforks.into_vec();

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

        // Rex6 `SequencerRegistry` rotation hardening, required iff `rex6Time` is scheduled.
        // Same flat schema as mega-reth (`rex6MinRotationDelay` as a top-level `config` field).
        let sequencer_registry_rex6_config = if rex6_scheduled {
            let parsed = MegaethGenesisSequencerRegistryRex6Config::parse_required_from(
                &genesis.config.extra_fields,
            )
            .unwrap_or_else(|err| {
                panic!("malformed or missing SequencerRegistryRex6Config in genesis: {err}")
            });
            let cfg = parsed.into_config();
            cfg.validate()
                .unwrap_or_else(|err| panic!("invalid SequencerRegistryRex6Config: {err}"));
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

        // `into_vec` yields the MegaETH hardforks already in canonical activation order,
        // so the merge is a straight concatenation.
        let mut all_hardforks = megaeth_hardforks;
        all_hardforks.append(&mut op_hardforks);

        Self {
            chain_id,
            hardforks: ChainHardforks::new(all_hardforks),
            sequencer_registry_config,
            sequencer_registry_rex6_config,
        }
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
    /// Rex6 hardfork timestamp.
    pub rex_6_time: Option<u64>,
}

impl MegaethGenesisHardforks {
    /// Extract the MegaETH genesis hardforks from a genesis file.
    ///
    /// Absent fields deserialize to `None`; present-but-malformed fields return an error.
    pub fn extract_from(others: &OtherFields) -> serde_json::Result<Self> {
        others.deserialize_as()
    }

    /// Convert the MegaETH genesis hardforks into a vector of hardforks and their conditions.
    ///
    /// The literal below is the single source of the canonical MegaETH activation order —
    /// [`ChainSpec::from_genesis`] merges it as-is, so new hardforks must be inserted at
    /// their activation position.
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
            (MegaHardfork::Rex6.boxed(), self.rex_6_time.map(ForkCondition::Timestamp)),
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

/// Optional SequencerRegistryRex6 bootstrap config embedded in genesis extra fields.
///
/// Only relevant when Rex6 is enabled.
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MegaethGenesisSequencerRegistryRex6Config {
    /// Minimum rotation delay (governance parameter) for the SequencerRegistry at Rex6 activation.
    pub rex6_min_rotation_delay: u64,
}

impl MegaethGenesisSequencerRegistryRex6Config {
    /// Parse the required SequencerRegistryRex6 bootstrap config from genesis extra fields.
    ///
    /// Missing fields and malformed u64 are returned as serde errors. Callers should only
    /// invoke it after deciding the bootstrap is required, e.g. when `rex6Time` is configured.
    pub fn parse_required_from(others: &OtherFields) -> serde_json::Result<Self> {
        others.deserialize_as()
    }

    /// Convert to the canonical mega-evm [`SequencerRegistryRex6Config`].
    pub fn into_config(self) -> SequencerRegistryRex6Config {
        SequencerRegistryRex6Config { rex6_min_rotation_delay: self.rex6_min_rotation_delay }
    }
}

#[cfg(test)]
mod tests {
    use std::string::ToString;

    use alloy_serde::OtherFields;

    use super::*;

    /// Inserts a complete, valid Rex5 schedule (`rex5Time` plus both bootstrap seeds) into
    /// `genesis`, so Rex6 fixtures can build on a well-formed ladder and exercise only the
    /// Rex6 behavior their names describe.
    fn schedule_valid_rex5(genesis: &mut Genesis, rex5_time: u64) {
        genesis.config.extra_fields.insert_value("rex5Time".to_string(), rex5_time).unwrap();
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
    }

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
          "rex5Time": 9,
          "rex6Time": 10
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
        assert_eq!(hardforks.rex_6_time, Some(10));
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
    #[should_panic(expected = "malformed MegaETH hardforks in genesis")]
    fn test_chain_spec_malformed_rex6_time_panics() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), "not-a-number").unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }

    #[test]
    fn test_parse_sequencer_registry_rex6_from_flat_json() {
        let genesis_info = r#"
        {
          "rex6Time": 0,
          "rex6MinRotationDelay": 7200
        }
        "#;
        let fields = serde_json::from_str::<OtherFields>(genesis_info).unwrap();
        let parsed =
            MegaethGenesisSequencerRegistryRex6Config::parse_required_from(&fields).unwrap();
        assert_eq!(parsed.rex6_min_rotation_delay, 7200);
    }

    #[test]
    fn test_chain_spec_carries_rex6_registry_as_fork_params() {
        let mut genesis = Genesis::default();
        schedule_valid_rex5(&mut genesis, 0);
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), 10).unwrap();
        genesis.config.extra_fields.insert_value("rex6MinRotationDelay".to_string(), 7200).unwrap();
        let spec = ChainSpec::from_genesis(genesis);
        let params =
            spec.fork_params::<SequencerRegistryRex6Config>().expect("Rex6 params present");
        assert_eq!(params.rex6_min_rotation_delay, 7200);
        assert_eq!(spec.hardforks.fork(MegaHardfork::Rex6), ForkCondition::Timestamp(10));
    }

    #[test]
    fn test_chain_spec_no_rex6_returns_none() {
        let genesis = Genesis::default();
        let spec = ChainSpec::from_genesis(genesis);
        assert!(spec.fork_params::<SequencerRegistryRex6Config>().is_none());
        assert!(spec.sequencer_registry_rex6_config.is_none());
    }

    #[test]
    fn test_chain_spec_rex6_delay_without_time_ignored() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("rex6MinRotationDelay".to_string(), 7200).unwrap();
        let spec = ChainSpec::from_genesis(genesis);
        assert_eq!(spec.hardforks.fork(MegaHardfork::Rex6), ForkCondition::Never);
        assert!(spec.sequencer_registry_rex6_config.is_none());
    }

    #[test]
    #[should_panic(expected = "malformed or missing SequencerRegistryRex6Config in genesis")]
    fn test_chain_spec_rex6_without_bootstrap_panics() {
        let mut genesis = Genesis::default();
        schedule_valid_rex5(&mut genesis, 0);
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), 0).unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }

    #[test]
    #[should_panic(expected = "malformed or missing SequencerRegistryRex6Config in genesis")]
    fn test_chain_spec_rex6_malformed_delay_panics() {
        let mut genesis = Genesis::default();
        schedule_valid_rex5(&mut genesis, 0);
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), 0).unwrap();
        genesis
            .config
            .extra_fields
            .insert_value("rex6MinRotationDelay".to_string(), "not-a-number")
            .unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }

    #[test]
    #[should_panic(expected = "invalid SequencerRegistryRex6Config")]
    fn test_chain_spec_rex6_zero_delay_panics() {
        let mut genesis = Genesis::default();
        schedule_valid_rex5(&mut genesis, 0);
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), 0).unwrap();
        genesis.config.extra_fields.insert_value("rex6MinRotationDelay".to_string(), 0).unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }

    /// `from_genesis` must reject a genesis that schedules Rex6 without Rex5: mega-evm's
    /// `hardfork()` would report REX6 at activation, but the Rex5-gated SequencerRegistry
    /// deploy never runs, so `resolve_system_address` fails every block from the activation
    /// on — a permanent stall this load-time check turns into a fail-fast on node start.
    #[test]
    #[should_panic(expected = "genesis schedules Rex6 but Rex5 is missing or scheduled after it")]
    fn test_chain_spec_rex6_without_rex5_panics() {
        let mut genesis = Genesis::default();
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), 0).unwrap();
        genesis.config.extra_fields.insert_value("rex6MinRotationDelay".to_string(), 7200).unwrap();
        // Intentionally omit rex5Time (and the Rex5 bootstrap).
        let _ = ChainSpec::from_genesis(genesis);
    }

    /// Rex5 scheduled after Rex6 is the same hazard as a missing Rex5 — Rex6 activates first
    /// with no registry deployed — and must fail at load, not at the activation block.
    #[test]
    #[should_panic(expected = "genesis schedules Rex6 but Rex5 is missing or scheduled after it")]
    fn test_chain_spec_rex5_after_rex6_panics() {
        let mut genesis = Genesis::default();
        schedule_valid_rex5(&mut genesis, 10);
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), 5).unwrap();
        genesis.config.extra_fields.insert_value("rex6MinRotationDelay".to_string(), 7200).unwrap();
        let _ = ChainSpec::from_genesis(genesis);
    }

    /// Rex5 and Rex6 at the same timestamp is a legal ladder — both forks activate together.
    #[test]
    fn test_chain_spec_rex5_and_rex6_at_same_timestamp_ok() {
        let mut genesis = Genesis::default();
        schedule_valid_rex5(&mut genesis, 5);
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), 5).unwrap();
        genesis.config.extra_fields.insert_value("rex6MinRotationDelay".to_string(), 7200).unwrap();
        let spec = ChainSpec::from_genesis(genesis);
        assert!(spec.fork_params::<SequencerRegistryConfig>().is_some(), "Rex5 config loaded");
        assert!(spec.fork_params::<SequencerRegistryRex6Config>().is_some(), "Rex6 config loaded");
    }

    #[test]
    fn test_chain_spec_rex5_and_rex6_coexist_in_canonical_order() {
        let mut genesis = Genesis::default();
        schedule_valid_rex5(&mut genesis, 100);
        genesis.config.extra_fields.insert_value("rex6Time".to_string(), 200).unwrap();
        genesis.config.extra_fields.insert_value("rex6MinRotationDelay".to_string(), 7200).unwrap();
        let spec = ChainSpec::from_genesis(genesis);

        assert_eq!(spec.hardforks.fork(MegaHardfork::Rex5), ForkCondition::Timestamp(100));
        assert_eq!(spec.hardforks.fork(MegaHardfork::Rex6), ForkCondition::Timestamp(200));
        assert!(spec.fork_params::<SequencerRegistryConfig>().is_some());
        assert!(spec.fork_params::<SequencerRegistryRex6Config>().is_some());

        // Rex6 must sort after Rex5 in the merged canonical ordering.
        let names: Vec<_> = spec.hardforks.forks_iter().map(|(f, _)| f.name()).collect();
        let rex5_pos = names.iter().position(|n| *n == MegaHardfork::Rex5.name()).unwrap();
        let rex6_pos = names.iter().position(|n| *n == MegaHardfork::Rex6.name()).unwrap();
        assert!(rex5_pos < rex6_pos, "Rex6 must come after Rex5 in the hardfork order");
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
