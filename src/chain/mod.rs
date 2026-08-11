//! This module contains various on-chain related modules and types.

/// Types representing events emitted by HOPR smart contracts.
pub mod chain_events;
/// Error types for chain-related operations.
pub mod errors;
#[cfg(feature = "use-bindings")]
mod parser;
/// Ethereum transaction payload generators for on-chain actions.
pub mod payload;

#[cfg(feature = "use-bindings")]
pub use {
    hopr_bindings::{
        ContractAddresses, exports, exports::alloy::primitives::Address as AlloyAddress,
    },
    parser::ParsedHoprChainAction,
};

pub mod prelude {
    pub use super::payload::{BasicPayloadGenerator, SafePayloadGenerator, TransactionRequest};
    pub use super::{
        ContractAddresses,
        chain_events::ChainEvent,
        payload::{GasEstimation, PayloadGenerator, SignableTransaction},
    };
}

#[cfg(not(feature = "use-bindings"))]
/// Holds addresses of all smart contracts.
#[serde_with::serde_as]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct ContractAddresses {
    /// Token contract
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub token: crate::primitive::primitives::Address,
    /// Channels contract
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub channels: crate::primitive::primitives::Address,
    /// Announcement contract
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub announcements: crate::primitive::primitives::Address,
    /// Safe registry contract
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub node_safe_registry: crate::primitive::primitives::Address,
    /// Service registry contract.
    ///
    /// A network that has no deployment yet carries the zero address here.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub service_registry: crate::primitive::primitives::Address,
    /// Price oracle contract
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub ticket_price_oracle: crate::primitive::primitives::Address,
    /// Minimum ticket winning probability contract
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub winning_probability_oracle: crate::primitive::primitives::Address,
    /// Migration helper for node safes and modules
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub node_safe_migration: crate::primitive::primitives::Address,
    /// Stake factory contract
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub node_stake_factory: crate::primitive::primitives::Address,
    /// Node management module contract (can be zero if safe is not used)
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub module_implementation: crate::primitive::primitives::Address,
}

#[cfg(not(feature = "use-bindings"))]
impl IntoIterator for &ContractAddresses {
    type IntoIter = std::vec::IntoIter<crate::primitive::primitives::Address>;
    type Item = crate::primitive::primitives::Address;

    fn into_iter(self) -> Self::IntoIter {
        vec![
            self.token,
            self.channels,
            self.announcements,
            self.node_safe_registry,
            self.service_registry,
            self.ticket_price_oracle,
            self.winning_probability_oracle,
            self.node_stake_factory,
            self.module_implementation,
        ]
        .into_iter()
    }
}

/// Returns chain ID and contract addresses for a known HOPR network on-chain deployment with the given `name` (e.g.
/// `rotsee` or `dufour`)
///
/// Returns `None` if network deployment with the given `name` is not known.
#[cfg(feature = "use-bindings")]
pub fn contract_addresses_for_network(name: &str) -> Option<(u64, ContractAddresses)> {
    hopr_bindings::config::NetworksWithContractAddresses::default()
        .networks
        .get(name)
        .cloned()
        .map(|n| (n.chain_id, n.addresses))
}

// Used instead of From implementation to avoid alloy being a dependency of the primitive crates
#[cfg(feature = "use-bindings")]
#[inline]
pub(in crate::chain) fn a2al(a: crate::primitive::prelude::Address) -> AlloyAddress {
    AlloyAddress::from_slice(a.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::payload::tests::CONTRACT_ADDRS_JSON;

    /// The `service_registry` entry of [`CONTRACT_ADDRS_JSON`], lowercased.
    ///
    /// The two `ContractAddresses` structs - the hand-written one and the one re-exported from
    /// the bindings - print addresses differently (lowercase hex versus EIP-55 checksum), so
    /// these tests compare lowercased strings and stay valid under both feature sets.
    const SERVICE_REGISTRY: &str = "0x9a676e781a523b5d0c0e43731313a708cb607508";

    #[test]
    fn contract_addresses_round_trip_the_service_registry_through_json() -> anyhow::Result<()> {
        let addresses: ContractAddresses = serde_json::from_str(CONTRACT_ADDRS_JSON)?;

        assert_eq!(
            SERVICE_REGISTRY,
            addresses.service_registry.to_string().to_lowercase()
        );

        let reparsed: ContractAddresses =
            serde_json::from_str(&serde_json::to_string(&addresses)?)?;
        assert_eq!(addresses, reparsed);

        Ok(())
    }

    #[test]
    fn contract_addresses_iterate_over_the_service_registry() -> anyhow::Result<()> {
        let addresses: ContractAddresses = serde_json::from_str(CONTRACT_ADDRS_JSON)?;

        assert!(
            (&addresses)
                .into_iter()
                .any(|address| address.to_string().to_lowercase() == SERVICE_REGISTRY)
        );

        Ok(())
    }
}
