//! Types mirroring `HoprServiceRegistry`, the permissionless on-chain registry of the services
//! that HOPR nodes offer.
//!
//! The registry treats service type ids and entry metadata as opaque data: each service type
//! documents its own metadata schema and its own Session-level protocol. These types therefore
//! validate only what the contract itself guarantees - a non-zero type id and the metadata length
//! cap - and leave the meaning of the bytes to the consumer.
//!
//! This is read-side vocabulary only. Building registry calldata is the job of the operator
//! tooling, which encodes it from the contract bindings directly.

use std::fmt::{Debug, Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::primitive::{
    bounded::BoundedVec,
    errors::GeneralError,
    prelude::{Address, BytesRepresentable, ToHex},
};

/// Right-pads `bytes` with zeroes into a [`ServiceType::SIZE`]-wide array.
///
/// Callers must ensure `bytes` is at most [`ServiceType::SIZE`] long; a longer input fails to
/// compile in a `const` context and panics otherwise.
const fn right_pad(bytes: &[u8]) -> [u8; ServiceType::SIZE] {
    let mut out = [0u8; ServiceType::SIZE];
    let mut i = 0;
    while i < bytes.len() {
        out[i] = bytes[i];
        i += 1;
    }
    out
}

/// Identifier of a service type in `HoprServiceRegistry`, a `bytes32` on-chain.
///
/// By convention the id holds right-padded ASCII, so that it stays human-readable in explorers
/// and in event topics: `bytes32("gvpn:exit")` is
/// `0x6776706e3a657869740000000000000000000000000000000000000000000000`. The contract does
/// **not** enforce that convention, so any non-zero 32-byte value can appear on-chain. Use
/// [`ServiceType::as_ascii`] to find out whether a given id follows it.
///
/// The only invariant the contract does enforce is that the id is not zero (`ZeroServiceType`),
/// which [`TryFrom`] upholds here.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "[u8; ServiceType::SIZE]", into = "[u8; ServiceType::SIZE]")
)]
pub struct ServiceType([u8; Self::SIZE]);

impl ServiceType {
    /// Canonical id of the GnosisVPN exit-node service, `bytes32("gvpn:exit")`.
    ///
    /// A type id is only trustworthy when it comes from the documentation of the service, never
    /// from the way it reads: type ids are first-come-first-served and the registry places no
    /// meaning on a name. A consumer that resolves `gvpn:exit` by parsing the string rather than
    /// by using this constant can be pointed at a squatted type.
    pub const GVPN_EXIT: Self = Self(right_pad(b"gvpn:exit"));

    /// The raw 32-byte id, ready to be handed to an ABI encoder as a `bytes32`.
    pub fn as_encoded(&self) -> [u8; Self::SIZE] {
        self.0
    }

    /// Decodes the id back into its ASCII name, if it follows the right-padded ASCII convention.
    ///
    /// Returns `None` for any id that does not: one holding non-ASCII bytes, an interior NUL
    /// byte, or a character outside the printable, non-space range accepted by [`FromStr`].
    pub fn as_ascii(&self) -> Option<&str> {
        let len = self.0.iter().rposition(|b| *b != 0)? + 1;
        let name = std::str::from_utf8(&self.0[..len]).ok()?;

        name.bytes().all(|b| b.is_ascii_graphic()).then_some(name)
    }
}

impl AsRef<[u8]> for ServiceType {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for ServiceType {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value: [u8; Self::SIZE] = value
            .try_into()
            .map_err(|_| GeneralError::ParseError("ServiceType".into()))?;

        Self::try_from(value)
    }
}

impl TryFrom<[u8; ServiceType::SIZE]> for ServiceType {
    type Error = GeneralError;

    fn try_from(value: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        if value == [0u8; Self::SIZE] {
            // The contract rejects this id with `ZeroServiceType`.
            Err(GeneralError::ParseError("zero service type".into()))
        } else {
            Ok(Self(value))
        }
    }
}

impl From<ServiceType> for [u8; ServiceType::SIZE] {
    fn from(value: ServiceType) -> Self {
        value.0
    }
}

impl BytesRepresentable for ServiceType {
    /// Size of the service type id when encoded as bytes, matching the `bytes32` on-chain.
    const SIZE: usize = 32;
}

impl std::str::FromStr for ServiceType {
    type Err = GeneralError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > Self::SIZE {
            return Err(GeneralError::ParseError(
                "service type name must be 1 to 32 bytes long".into(),
            ));
        }

        if !s.bytes().all(|b| b.is_ascii_graphic()) {
            // Space is excluded along with the control characters: it is indistinguishable from
            // the padding to the eye, which makes it a poor character for an identifier.
            return Err(GeneralError::ParseError(
                "service type name must be printable non-space ASCII".into(),
            ));
        }

        Ok(Self(right_pad(s.as_bytes())))
    }
}

impl Display for ServiceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.as_ascii() {
            Some(name) => f.write_str(name),
            // The convention is not enforced on-chain, so fall back to the raw id.
            None => f.write_str(&self.to_hex()),
        }
    }
}

impl Debug for ServiceType {
    // Intentionally the same as Display
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

/// Opaque metadata of a single registry entry.
///
/// The registry places no meaning on these bytes; the schema belongs to the service type. The
/// only rule is the length cap, see [`ServiceMetadata::MAX_LENGTH`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "Vec<u8>", into = "Vec<u8>"))]
pub struct ServiceMetadata(BoundedVec<u8, { ServiceMetadata::MAX_LENGTH }>);

impl ServiceMetadata {
    /// Hard cap on the length of the metadata of an entry.
    ///
    /// Mirrors `MAX_METADATA_LENGTH` in `ServiceRegistry.sol`. The contract is not upgradeable
    /// and applies the cap on every write path, so this value is permanent and can never be
    /// raised. A service type may make it smaller through its requirement contract.
    pub const MAX_LENGTH: usize = 2048;
}

impl TryFrom<Vec<u8>> for ServiceMetadata {
    type Error = GeneralError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // `BoundedVec::try_from` rejects anything above the cap; its `FromIterator`, which
        // truncates silently instead, is deliberately not reachable through this type.
        value.try_into().map(Self)
    }
}

impl From<ServiceMetadata> for Vec<u8> {
    fn from(value: ServiceMetadata) -> Self {
        value.0.into()
    }
}

impl AsRef<[u8]> for ServiceMetadata {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A single entry in `HoprServiceRegistry`: one node offering one service type.
///
/// This mirrors the contract's `Entry` struct together with the two fields that key it, the
/// service type and the node.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServiceEntry {
    /// Service type this entry is registered under.
    pub service_type: ServiceType,
    /// Node offering the service.
    pub node: Address,
    /// Safe bound to the node that performed the last write to this entry.
    pub safe: Address,
    /// Opaque metadata, with a schema that belongs to the service type.
    pub metadata: ServiceMetadata,
    /// When the entry was registered.
    pub registered_at: SystemTime,
    /// When the entry was last updated; equal to [`Self::registered_at`] until the first update.
    pub updated_at: SystemTime,
}

impl ServiceEntry {
    /// Creates a new entry, checking the invariants the contract guarantees on its timestamps.
    ///
    /// Fails unless `registered_at` is after the Unix epoch - the contract uses a zero
    /// `registeredAt` as its "entry absent" sentinel - and `updated_at` is at or after
    /// `registered_at`. Registration itself sets `updatedAt` to `registeredAt`, so the two being
    /// equal is the state of every entry that has never been updated.
    pub fn new(
        service_type: ServiceType,
        node: Address,
        safe: Address,
        metadata: ServiceMetadata,
        registered_at: SystemTime,
        updated_at: SystemTime,
    ) -> Result<Self, GeneralError> {
        if registered_at <= UNIX_EPOCH {
            return Err(GeneralError::InvalidInput);
        }

        if updated_at < registered_at {
            return Err(GeneralError::InvalidInput);
        }

        Ok(Self {
            service_type,
            node,
            safe,
            metadata,
            registered_at,
            updated_at,
        })
    }
}

impl Display for ServiceEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "service {} of node {} (safe: {}, {} bytes of metadata)",
            self.service_type,
            self.node,
            self.safe,
            self.metadata.as_ref().len()
        )
    }
}

#[cfg(feature = "use-bindings")]
mod bindings_conversions {
    use std::time::Duration;

    use hopr_bindings::exports::alloy::primitives::B256;
    use hopr_bindings::hopr_service_registry::HoprServiceRegistry::{Registered, Updated};

    use super::*;

    impl From<B256> for ServiceType {
        /// Takes the id as-is, without rejecting the zero id.
        ///
        /// Values decoded from chain data can hold any `bytes32`, and a consumer that is
        /// mirroring logs wants them all. Use `ServiceType::try_from(value.0)` where the zero id
        /// has to be rejected instead.
        fn from(value: B256) -> Self {
            Self(value.0)
        }
    }

    /// Converts a `uint48` block timestamp in seconds into a [`SystemTime`].
    fn seconds_to_system_time(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    impl TryFrom<&Registered> for ServiceEntry {
        type Error = GeneralError;

        fn try_from(value: &Registered) -> Result<Self, Self::Error> {
            let registered_at = seconds_to_system_time(value.registeredAt.to::<u64>());

            Self::new(
                value.serviceType.into(),
                Address::from(value.node.0.0),
                Address::from(value.safe.0.0),
                value.metadata.to_vec().try_into()?,
                registered_at,
                // Registration sets `updatedAt` to `registeredAt`.
                registered_at,
            )
        }
    }

    impl TryFrom<&Updated> for ServiceEntry {
        type Error = GeneralError;

        /// The `Updated` event omits `registeredAt`, because an update leaves it untouched. The
        /// resulting entry therefore carries `updated_at` in both timestamp fields. A consumer
        /// holding the previous state of the entry should keep its own `registered_at`.
        fn try_from(value: &Updated) -> Result<Self, Self::Error> {
            let updated_at = seconds_to_system_time(value.updatedAt.to::<u64>());

            Self::new(
                value.serviceType.into(),
                Address::from(value.node.0.0),
                Address::from(value.safe.0.0),
                value.metadata.to_vec().try_into()?,
                updated_at,
                updated_at,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::time::{Duration, UNIX_EPOCH};

    use hex_literal::hex;

    use super::*;
    use crate::primitive::prelude::*;

    /// `bytes32("gvpn:exit")` as given in `design-service-discovery.md`, section 3.1.
    const GVPN_EXIT_ENCODED: [u8; 32] =
        hex!("6776706e3a657869740000000000000000000000000000000000000000000000");

    const NODE: [u8; 20] = hex!("2cDD13ddB0346E0F620C8E5826Da5d7230341c6E");
    const SAFE: [u8; 20] = hex!("42e0e02c7b7c46ec3d5b8c3fdb2f2e3f2a4b5c6d");

    fn node() -> Address {
        Address::from(NODE)
    }

    fn safe() -> Address {
        Address::from(SAFE)
    }

    #[test]
    fn service_type_from_str_uses_the_canonical_right_padded_encoding() -> anyhow::Result<()> {
        let parsed: ServiceType = "gvpn:exit".parse()?;

        assert_eq!(GVPN_EXIT_ENCODED, parsed.as_encoded());
        assert_eq!(ServiceType::GVPN_EXIT, parsed);

        Ok(())
    }

    #[test]
    fn service_type_round_trips_between_from_str_and_display() -> anyhow::Result<()> {
        for name in ["gvpn:exit", "a", &"z".repeat(32)] {
            let parsed: ServiceType = name.parse()?;
            assert_eq!(name, parsed.to_string());
            assert_eq!(Some(name), parsed.as_ascii());
        }

        Ok(())
    }

    #[test]
    fn service_type_from_str_rejects_invalid_names() {
        assert!("".parse::<ServiceType>().is_err());
        assert!("z".repeat(33).parse::<ServiceType>().is_err());
        assert!("gvpn:exít".parse::<ServiceType>().is_err());
        assert!("gvpn exit".parse::<ServiceType>().is_err());
        assert!("gvpn\texit".parse::<ServiceType>().is_err());
    }

    #[test]
    fn service_type_try_from_bytes_rejects_zero_and_wrong_lengths() -> anyhow::Result<()> {
        assert_eq!(
            ServiceType::GVPN_EXIT,
            ServiceType::try_from(GVPN_EXIT_ENCODED.as_ref())?
        );

        assert!(ServiceType::try_from([0u8; 32].as_ref()).is_err());
        assert!(ServiceType::try_from([0u8; 32]).is_err());
        assert!(ServiceType::try_from([1u8; 31].as_ref()).is_err());
        assert!(ServiceType::try_from([1u8; 33].as_ref()).is_err());

        Ok(())
    }

    #[test]
    fn service_type_round_trips_through_hex() -> anyhow::Result<()> {
        let hex = ServiceType::GVPN_EXIT.to_hex();

        assert_eq!(
            "0x6776706e3a657869740000000000000000000000000000000000000000000000",
            hex
        );
        assert_eq!(ServiceType::GVPN_EXIT, ServiceType::from_hex(&hex)?);

        Ok(())
    }

    #[test]
    fn service_type_display_falls_back_to_hex_for_non_ascii_ids() -> anyhow::Result<()> {
        // The contract does not enforce the ASCII convention, so any non-zero id can appear.
        let raw = ServiceType::try_from([0xffu8; 32].as_ref())?;

        assert_eq!(None, raw.as_ascii());
        assert_eq!(raw.to_hex(), raw.to_string());

        // An id with an interior NUL byte is not ASCII-decodable either.
        let mut interior_nul = GVPN_EXIT_ENCODED;
        interior_nul[4] = 0;
        let raw = ServiceType::try_from(interior_nul.as_ref())?;

        assert_eq!(None, raw.as_ascii());

        Ok(())
    }

    #[test]
    fn service_type_is_usable_as_a_map_key() -> anyhow::Result<()> {
        let other: ServiceType = "gvpn:entry".parse()?;

        let hash_map = HashMap::from([(ServiceType::GVPN_EXIT, 1), (other, 2)]);
        assert_eq!(Some(&1), hash_map.get(&ServiceType::GVPN_EXIT));

        let btree_map = BTreeMap::from([(ServiceType::GVPN_EXIT, 1), (other, 2)]);
        assert_eq!(Some(&2), btree_map.get(&other));

        Ok(())
    }

    #[test]
    fn service_metadata_enforces_the_contract_cap() -> anyhow::Result<()> {
        assert_eq!(2048, ServiceMetadata::MAX_LENGTH);

        for len in [0, 1, ServiceMetadata::MAX_LENGTH] {
            let bytes = vec![0xab; len];
            let metadata = ServiceMetadata::try_from(bytes.clone())?;

            assert_eq!(bytes.as_slice(), metadata.as_ref());
            assert_eq!(bytes, Vec::from(metadata));
        }

        assert!(ServiceMetadata::try_from(vec![0xab; ServiceMetadata::MAX_LENGTH + 1]).is_err());

        Ok(())
    }

    #[test]
    fn service_entry_new_enforces_the_timestamp_invariants() -> anyhow::Result<()> {
        let registered_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let updated_at = registered_at + Duration::from_secs(60);
        let metadata = ServiceMetadata::try_from(b"exit-node".to_vec())?;

        // Registration sets `updated_at` to `registered_at`.
        let entry = ServiceEntry::new(
            ServiceType::GVPN_EXIT,
            node(),
            safe(),
            metadata.clone(),
            registered_at,
            registered_at,
        )?;
        assert_eq!(registered_at, entry.updated_at);

        assert!(
            ServiceEntry::new(
                ServiceType::GVPN_EXIT,
                node(),
                safe(),
                metadata.clone(),
                registered_at,
                updated_at,
            )
            .is_ok()
        );

        // An update cannot precede the registration.
        assert!(
            ServiceEntry::new(
                ServiceType::GVPN_EXIT,
                node(),
                safe(),
                metadata.clone(),
                updated_at,
                registered_at,
            )
            .is_err()
        );

        // A zero `registered_at` is the contract's "entry absent" sentinel.
        assert!(
            ServiceEntry::new(
                ServiceType::GVPN_EXIT,
                node(),
                safe(),
                metadata,
                UNIX_EPOCH,
                UNIX_EPOCH,
            )
            .is_err()
        );

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn service_types_round_trip_through_serde() -> anyhow::Result<()> {
        let service_type = ServiceType::GVPN_EXIT;
        assert_eq!(
            service_type,
            postcard::from_bytes(&postcard::to_allocvec(&service_type)?)?
        );

        let metadata = ServiceMetadata::try_from(b"exit-node".to_vec())?;
        assert_eq!(
            metadata,
            postcard::from_bytes::<ServiceMetadata>(&postcard::to_allocvec(&metadata)?)?
        );

        let entry = ServiceEntry::new(
            service_type,
            node(),
            safe(),
            metadata,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_700_000_060),
        )?;
        assert_eq!(
            entry,
            postcard::from_bytes::<ServiceEntry>(&postcard::to_allocvec(&entry)?)?
        );

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_upholds_the_service_type_and_metadata_invariants() -> anyhow::Result<()> {
        let zero_id = postcard::to_allocvec(&[0u8; 32])?;
        assert!(postcard::from_bytes::<ServiceType>(&zero_id).is_err());

        let too_long = postcard::to_allocvec(&vec![0xab; ServiceMetadata::MAX_LENGTH + 1])?;
        assert!(postcard::from_bytes::<ServiceMetadata>(&too_long).is_err());

        Ok(())
    }

    #[cfg(feature = "use-bindings")]
    mod bindings {
        use hopr_bindings::exports::alloy::primitives::{
            Address as AlloyAddress, B256, Bytes, U256, aliases::U48,
        };
        use hopr_bindings::hopr_service_registry::HoprServiceRegistry::{Registered, Updated};

        use super::*;

        const REGISTERED_AT: u64 = 1_700_000_000;
        const UPDATED_AT: u64 = 1_700_000_060;

        fn registered(metadata: Vec<u8>) -> Registered {
            Registered {
                serviceType: B256::from(GVPN_EXIT_ENCODED),
                node: AlloyAddress::from(NODE),
                safe: AlloyAddress::from(SAFE),
                metadata: Bytes::from(metadata),
                registeredAt: U48::from(REGISTERED_AT),
                burned: U256::from(1u64),
            }
        }

        fn updated(metadata: Vec<u8>) -> Updated {
            Updated {
                serviceType: B256::from(GVPN_EXIT_ENCODED),
                node: AlloyAddress::from(NODE),
                safe: AlloyAddress::from(SAFE),
                metadata: Bytes::from(metadata),
                updatedAt: U48::from(UPDATED_AT),
                burned: U256::from(1u64),
            }
        }

        #[test]
        fn service_type_converts_from_a_b256_unchecked() {
            assert_eq!(
                ServiceType::GVPN_EXIT,
                ServiceType::from(B256::from(GVPN_EXIT_ENCODED))
            );

            // Chain data may hold any id, so the unchecked conversion accepts the zero id too.
            assert_eq!([0u8; 32], ServiceType::from(B256::ZERO).as_encoded());
        }

        #[test]
        fn registered_event_converts_to_a_service_entry() -> anyhow::Result<()> {
            let entry = ServiceEntry::try_from(&registered(b"exit-node".to_vec()))?;

            assert_eq!(ServiceType::GVPN_EXIT, entry.service_type);
            assert_eq!(node(), entry.node);
            assert_eq!(safe(), entry.safe);
            assert_eq!(b"exit-node".as_ref(), entry.metadata.as_ref());
            assert_eq!(
                UNIX_EPOCH + Duration::from_secs(REGISTERED_AT),
                entry.registered_at
            );
            assert_eq!(
                UNIX_EPOCH + Duration::from_secs(REGISTERED_AT),
                entry.updated_at
            );

            Ok(())
        }

        #[test]
        fn updated_event_converts_to_a_service_entry() -> anyhow::Result<()> {
            let entry = ServiceEntry::try_from(&updated(b"exit-node".to_vec()))?;

            assert_eq!(ServiceType::GVPN_EXIT, entry.service_type);
            assert_eq!(node(), entry.node);
            assert_eq!(safe(), entry.safe);
            assert_eq!(b"exit-node".as_ref(), entry.metadata.as_ref());
            assert_eq!(
                UNIX_EPOCH + Duration::from_secs(UPDATED_AT),
                entry.updated_at
            );
            // The event does not carry `registeredAt`, so the conversion mirrors `updated_at`.
            assert_eq!(
                UNIX_EPOCH + Duration::from_secs(UPDATED_AT),
                entry.registered_at
            );

            Ok(())
        }

        #[test]
        fn oversized_metadata_fails_the_conversion_instead_of_truncating() {
            let too_long = vec![0xab; ServiceMetadata::MAX_LENGTH + 1];

            assert!(ServiceEntry::try_from(&registered(too_long.clone())).is_err());
            assert!(ServiceEntry::try_from(&updated(too_long)).is_err());
        }
    }
}
