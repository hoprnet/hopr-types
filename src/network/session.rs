//! Types describing HOPR Sessions and their targets.

use std::num::NonZeroU32;

use crate::primitive::prelude::{BytesRepresentable, GeneralError};

use super::types::SealedHost;

/// Identity of a HOPR Session.
pub type SessionId = crate::internal::protocol::HoprPseudonym;

/// Identifies one PIX deposit allocation within a HOPR Session.
///
/// A session may create several deposit addresses, so the session identifier
/// alone is not sufficient as a durable allocation key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PixAddressId {
    session_id: SessionId,
    allocation_index: NonZeroU32,
}

impl PixAddressId {
    /// Encoded size: session pseudonym followed by a big-endian allocation index.
    pub const SIZE: usize = SessionId::SIZE + size_of::<u32>();

    /// Creates a PIX allocation identifier.
    pub const fn new(session_id: SessionId, allocation_index: NonZeroU32) -> Self {
        Self {
            session_id,
            allocation_index,
        }
    }

    /// Returns the HOPR Session to which this allocation belongs.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the non-zero allocation index within the session.
    pub const fn allocation_index(&self) -> NonZeroU32 {
        self.allocation_index
    }

    /// Returns the stable database-key representation.
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0_u8; Self::SIZE];
        bytes[..SessionId::SIZE].copy_from_slice(self.session_id.as_ref());
        bytes[SessionId::SIZE..].copy_from_slice(&self.allocation_index.get().to_be_bytes());
        bytes
    }
}

impl TryFrom<&[u8]> for PixAddressId {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            return Err(GeneralError::ParseError("PixAddressId".into()));
        }
        let session_id = SessionId::try_from(&value[..SessionId::SIZE])?;
        let index_bytes: [u8; size_of::<u32>()] = value[SessionId::SIZE..]
            .try_into()
            .map_err(|_| GeneralError::ParseError("PixAddressId allocation index".into()))?;
        let allocation_index = NonZeroU32::new(u32::from_be_bytes(index_bytes))
            .ok_or_else(|| GeneralError::ParseError("PixAddressId allocation index".into()))?;
        Ok(Self::new(session_id, allocation_index))
    }
}

impl From<PixAddressId> for (SessionId, NonZeroU32) {
    fn from(value: PixAddressId) -> Self {
        (value.session_id, value.allocation_index)
    }
}

impl From<(SessionId, NonZeroU32)> for PixAddressId {
    fn from((session_id, allocation_index): (SessionId, NonZeroU32)) -> Self {
        Self::new(session_id, allocation_index)
    }
}

/// Identifies a node-local service target.
///
/// These are specialized [`SessionTargets`](SessionTarget::ExitNode)
/// that are local to the Exit node and have different purposes, such as Cover Traffic.
///
/// These targets cannot be [sealed](SealedHost) from the Entry node.
pub type ServiceId = u32;

/// Defines what should happen with the data at the recipient where the
/// data from the established session are supposed to be forwarded to some `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SessionTarget {
    /// Target is running over UDP with the given IP address and port.
    UdpStream(SealedHost),
    /// Target is running over TCP with the given address and port.
    TcpStream(SealedHost),
    /// Target is a service directly at the exit node with the given service ID.
    ExitNode(ServiceId),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pix_address_id_has_a_stable_roundtrip_encoding() -> anyhow::Result<()> {
        let session_id = SessionId::from([7_u8; SessionId::SIZE]);
        let allocation_index =
            NonZeroU32::new(3).ok_or_else(|| anyhow::anyhow!("index must be non-zero"))?;
        let id = PixAddressId::new(session_id, allocation_index);

        assert_eq!(PixAddressId::try_from(id.to_bytes().as_slice())?, id);
        assert_eq!(id.session_id(), session_id);
        assert_eq!(id.allocation_index(), allocation_index);
        Ok(())
    }

    #[test]
    fn pix_address_id_rejects_a_zero_allocation_index() {
        let mut bytes = [0_u8; PixAddressId::SIZE];
        bytes[..SessionId::SIZE].copy_from_slice(SessionId::from([7_u8; SessionId::SIZE]).as_ref());

        assert!(PixAddressId::try_from(bytes.as_slice()).is_err());
    }
}
