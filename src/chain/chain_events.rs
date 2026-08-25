//! Types that are related to events that are raised on-chain and extracted from chain logs.
//!
//! These events happen in response to actions (transactions, smart contract calls) done by a HOPR node on chain.
//!
//! See `chain-actions` and `chain-indexer` crates for details.
use std::fmt::{Display, Formatter};

use crate::internal::prelude::*;
use crate::primitive::prelude::*;

/// Enumeration of HOPR chain events.
#[derive(Debug, Clone, strum::EnumTryAs, strum::EnumIs, strum::EnumDiscriminants)]
pub enum ChainEvent {
    /// Peer on-chain announcement event.
    ///
    /// The [`AccountEntry`] is guaranteed to be [announced](AccountEntry::has_announced).
    Announcement(AccountEntry),
    /// A new channel has been opened
    ///
    /// The [`ChannelEntry`] is guaranteed to be [opened](ChannelStatus::Open).
    ChannelOpened(ChannelEntry),
    /// Channel closure has been initiated.
    ///
    /// The [`ChannelEntry`] is guaranteed to be [pending to close](ChannelStatus::PendingToClose).
    ChannelClosureInitiated(ChannelEntry),
    /// Channel closure has been finalized.
    ///
    /// The [`ChannelEntry`] is guaranteed to be [closed](ChannelStatus::Closed).
    ChannelClosed(ChannelEntry),
    /// Channel balance has increased by an amount.
    ///
    /// The [`HoprBalance`] is never `0` and represents the difference from the current new balance on the
    /// [`ChannelEntry`].
    ChannelBalanceIncreased(ChannelEntry, HoprBalance),
    /// Channel balance has decreased by an amount.
    ///
    /// The [`HoprBalance`] is never `0` and represents the difference from the current new balance on the
    /// [`ChannelEntry`].
    ChannelBalanceDecreased(ChannelEntry, HoprBalance),
    /// Ticket has been redeemed on a channel.
    ///
    /// If the channel is a node's own, it also contains the ticket that has been redeemed.
    TicketRedeemed(ChannelEntry, Option<Box<VerifiedTicket>>),

    /// The minimum winning probability has been increased.
    WinningProbabilityIncreased(WinningProbability),

    /// The minimum winning probability has been decreased.
    WinningProbabilityDecreased(WinningProbability),

    /// A new ticket price has been set.
    TicketPriceChanged(HoprBalance),

    /// A node registered an entry in the service registry.
    ///
    /// The [`ServiceEntry`] has its `updated_at` equal to its `registered_at`, because
    /// registration is also the first update.
    ServiceRegistered(ServiceEntry),

    /// A node replaced the metadata of one of its service registry entries.
    ///
    /// The originating event does not carry the registration timestamp, so `registered_at` on
    /// the [`ServiceEntry`] mirrors `updated_at`. Consumers holding the previous state of the
    /// entry should keep their own `registered_at`.
    ServiceUpdated(ServiceEntry),

    /// A node removed one of its service registry entries.
    ///
    /// Carries the service type and the node the entry belonged to.
    ServiceDeregistered(ServiceType, Address),

    /// A new service type exists, owned by the given address.
    ServiceTypeRegistered(ServiceType, Address),

    /// Ownership of a service type moved to another address.
    ///
    /// `None` means the type was abandoned, which is one-way: an abandoned type keeps its
    /// configuration forever.
    ServiceTypeOwnerChanged(ServiceType, Option<Address>),

    /// The requirement contract gating registrations under a service type has changed.
    ///
    /// `None` means the type is open, with no policy beyond the Safe binding and the burn.
    ServiceTypeRequirementChanged(ServiceType, Option<Address>),

    /// The amount burned when registering an entry under a service type has changed.
    ServiceTypeRegistrationBurnChanged(ServiceType, HoprBalance),

    /// The amount burned when updating an entry under a service type has changed.
    ServiceTypeUpdateBurnChanged(ServiceType, HoprBalance),

    /// The global fee burned when registering a new service type has changed.
    ServiceTypeRegistrationFeeChanged(HoprBalance),

    /// The service registry now reads node-to-Safe bindings from a different registry contract.
    ServiceRegistryPointerChanged(Address),
}

impl Display for ChainEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainEvent::Announcement(a) => write!(f, "announcement event of {a}"),
            ChainEvent::ChannelOpened(c) => write!(f, "open channel event {}", c.get_id()),
            ChainEvent::ChannelClosureInitiated(c) => {
                write!(f, "close channel initiation event {}", c.get_id())
            }
            ChainEvent::ChannelClosed(c) => write!(f, "close channel event {}", c.get_id()),
            ChainEvent::ChannelBalanceIncreased(c, _) => {
                write!(f, "channel increase balance event {}", c.get_id())
            }
            ChainEvent::ChannelBalanceDecreased(c, _) => {
                write!(f, "channel decrease balance event {}", c.get_id())
            }
            ChainEvent::TicketRedeemed(c, _) => {
                write!(f, "ticket redeem event in channel {}", c.get_id())
            }
            ChainEvent::WinningProbabilityIncreased(p) => {
                write!(f, "winning probability increased to {p}")
            }
            ChainEvent::WinningProbabilityDecreased(p) => {
                write!(f, "winning probability decreased to {p}")
            }
            ChainEvent::TicketPriceChanged(p) => write!(f, "ticket price changed to {p}"),
            ChainEvent::ServiceRegistered(e) => write!(f, "service registration event of {e}"),
            ChainEvent::ServiceUpdated(e) => write!(f, "service update event of {e}"),
            ChainEvent::ServiceDeregistered(t, node) => {
                write!(f, "service deregistration event of {t} for node {node}")
            }
            ChainEvent::ServiceTypeRegistered(t, owner) => {
                write!(f, "service type {t} registered by {owner}")
            }
            ChainEvent::ServiceTypeOwnerChanged(t, Some(owner)) => {
                write!(f, "service type {t} owner changed to {owner}")
            }
            ChainEvent::ServiceTypeOwnerChanged(t, None) => {
                write!(f, "service type {t} abandoned")
            }
            ChainEvent::ServiceTypeRequirementChanged(t, Some(req)) => {
                write!(f, "service type {t} requirement changed to {req}")
            }
            ChainEvent::ServiceTypeRequirementChanged(t, None) => {
                write!(f, "service type {t} requirement removed")
            }
            ChainEvent::ServiceTypeRegistrationBurnChanged(t, a) => {
                write!(f, "service type {t} registration burn changed to {a}")
            }
            ChainEvent::ServiceTypeUpdateBurnChanged(t, a) => {
                write!(f, "service type {t} update burn changed to {a}")
            }
            ChainEvent::ServiceTypeRegistrationFeeChanged(a) => {
                write!(f, "service type registration fee changed to {a}")
            }
            ChainEvent::ServiceRegistryPointerChanged(a) => {
                write!(f, "service registry node safe registry changed to {a}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use hex_literal::hex;

    use super::*;

    const NODE: [u8; 20] = hex!("2cDD13ddB0346E0F620C8E5826Da5d7230341c6E");
    const OWNER: [u8; 20] = hex!("42e0e02c7b7c46ec3d5b8c3fdb2f2e3f2a4b5c6d");

    fn service_entry() -> anyhow::Result<ServiceEntry> {
        Ok(ServiceEntry::new(
            ServiceType::GVPN_EXIT,
            Address::from(NODE),
            Address::from(OWNER),
            ServiceMetadata::try_from(b"exit-node".to_vec())?,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_700_000_060),
        )?)
    }

    #[test]
    fn service_entry_events_display_and_expose_accessors() -> anyhow::Result<()> {
        let entry = service_entry()?;

        let registered = ChainEvent::ServiceRegistered(entry.clone());
        assert_eq!(
            format!("service registration event of {entry}"),
            registered.to_string()
        );
        assert!(registered.is_service_registered());
        assert!(!registered.is_service_updated());
        assert_eq!(
            Some(entry.clone()),
            registered.clone().try_as_service_registered()
        );
        assert_eq!(None, registered.try_as_service_updated());

        let updated = ChainEvent::ServiceUpdated(entry.clone());
        assert_eq!(
            format!("service update event of {entry}"),
            updated.to_string()
        );
        assert!(updated.is_service_updated());
        assert_eq!(Some(entry), updated.try_as_service_updated());

        let deregistered =
            ChainEvent::ServiceDeregistered(ServiceType::GVPN_EXIT, Address::from(NODE));
        assert_eq!(
            "service deregistration event of gvpn:exit for node 0x2cdd13ddb0346e0f620c8e5826da5d7230341c6e",
            deregistered.to_string()
        );
        assert!(deregistered.is_service_deregistered());
        assert_eq!(
            Some((ServiceType::GVPN_EXIT, Address::from(NODE))),
            deregistered.try_as_service_deregistered()
        );

        Ok(())
    }

    #[test]
    fn service_type_events_display_and_expose_accessors() {
        let owner = Address::from(OWNER);

        let registered = ChainEvent::ServiceTypeRegistered(ServiceType::GVPN_EXIT, owner);
        assert_eq!(
            format!("service type gvpn:exit registered by {owner}"),
            registered.to_string()
        );
        assert!(registered.is_service_type_registered());
        assert_eq!(
            Some((ServiceType::GVPN_EXIT, owner)),
            registered.try_as_service_type_registered()
        );

        assert_eq!(
            format!("service type gvpn:exit owner changed to {owner}"),
            ChainEvent::ServiceTypeOwnerChanged(ServiceType::GVPN_EXIT, Some(owner)).to_string()
        );
        assert_eq!(
            "service type gvpn:exit abandoned",
            ChainEvent::ServiceTypeOwnerChanged(ServiceType::GVPN_EXIT, None).to_string()
        );

        assert_eq!(
            format!("service type gvpn:exit requirement changed to {owner}"),
            ChainEvent::ServiceTypeRequirementChanged(ServiceType::GVPN_EXIT, Some(owner))
                .to_string()
        );
        assert_eq!(
            "service type gvpn:exit requirement removed",
            ChainEvent::ServiceTypeRequirementChanged(ServiceType::GVPN_EXIT, None).to_string()
        );
    }

    #[test]
    fn service_configuration_events_display_and_expose_accessors() -> anyhow::Result<()> {
        let amount: HoprBalance = "10 wxHOPR".parse()?;

        assert_eq!(
            format!("service type gvpn:exit registration burn changed to {amount}"),
            ChainEvent::ServiceTypeRegistrationBurnChanged(ServiceType::GVPN_EXIT, amount)
                .to_string()
        );
        assert_eq!(
            format!("service type gvpn:exit update burn changed to {amount}"),
            ChainEvent::ServiceTypeUpdateBurnChanged(ServiceType::GVPN_EXIT, amount).to_string()
        );

        let fee_changed = ChainEvent::ServiceTypeRegistrationFeeChanged(amount);
        assert_eq!(
            format!("service type registration fee changed to {amount}"),
            fee_changed.to_string()
        );
        assert_eq!(
            Some(amount),
            fee_changed.try_as_service_type_registration_fee_changed()
        );

        let pointer = Address::from(OWNER);
        let pointer_changed = ChainEvent::ServiceRegistryPointerChanged(pointer);
        assert_eq!(
            format!("service registry node safe registry changed to {pointer}"),
            pointer_changed.to_string()
        );
        assert!(pointer_changed.is_service_registry_pointer_changed());

        Ok(())
    }
}
