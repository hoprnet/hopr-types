use std::{fmt::Formatter, marker::PhantomData, num::NonZeroU32};

use typenum::Unsigned;

use crate::crypto::{
    crypto_traits::{Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser},
    utils::SecretValue,
};

/// AES with 128-bit key in counter-mode (with big-endian counter).
pub type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

use crate::crypto::prelude::{BjjPublicKey, PublicKey, SimplePseudonym};
use crate::primitive::prelude::{Address, BytesRepresentable, GeneralError};
/// BN254 curve, re-exported from the [`ark_bn254`] crate.
pub use ark_bn254::{
    Fr as Bn254Scalar, G1Affine as Bn254G1Affine, G1Projective as Bn254G1Projective,
};
/// Serialization traits, re-exported from the [`ark_serialize`] crate.
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
/// BabyJubJub elliptic curve, re-exported from the [`babyjubjub_ec`] crate.
pub use babyjubjub_ec::{
    BabyJubJub, GroupRepr as BabyJubJubCompressedPoint, Scalar as BabyJubJubScalar,
};
/// Blake3 hash function, re-exported from the [`blake3`] crate.
pub use blake3::{Hasher as Blake3, OutputReader as Blake3Output, hash as blake3_hash};
/// ChaCha20 stream cipher, re-exported from the [`chacha20`] crate.
pub use chacha20::ChaCha20;
/// Curve25519 elliptic curve, re-exported from the [`curve25519_dalek`] crate.
pub use curve25519_dalek::{
    edwards::CompressedEdwardsY as Curve25519CompressedPoint,
    edwards::EdwardsPoint as Curve25519Point,
    montgomery::MontgomeryPoint as Curve25519MontgomeryPoint, scalar::Scalar as Curve25519Scalar,
    traits::IsIdentity,
};
/// Secp256k1 elliptic curve, re-exported from the [`k256`] crate.
pub use k256::Secp256k1;
/// Poly1305 one-time authenticator, re-exported from the [`poly1305`] crate.
pub use poly1305::Poly1305;
/// Keccak-256 and SHA3-256 hash functions, re-exported from the [`sha3`] crate.
pub use sha3::{Keccak256, Sha3_256};
use strum::IntoDiscriminant;

/// Represents a 256-bit secret key of fixed length.
/// The value is auto-zeroized on drop.
pub type SecretKey = SecretValue<typenum::U32>;

/// Represents a 128-bit secret key of fixed length.
/// The value is auto-zeroized on drop.
pub type SecretKey16 = SecretValue<typenum::U16>;

/// Convenience container for IV and key of a given primitive `T`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(zeroize::ZeroizeOnDrop)]
pub struct IvKey<T>(Box<[u8]>, PhantomData<T>);

impl<T: KeyIvInit> KeySizeUser for IvKey<T> {
    type KeySize = T::KeySize;
}

impl<T: KeyIvInit> IvSizeUser for IvKey<T> {
    type IvSize = T::IvSize;
}

impl<T: KeyIvInit> KeyIvInit for IvKey<T> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.extend_from_slice(iv.as_ref());
        out.extend_from_slice(key.as_ref());
        Self(out.into_boxed_slice(), PhantomData)
    }
}

impl<T: KeyIvInit> Default for IvKey<T> {
    fn default() -> Self {
        Self(vec![0u8; Self::SIZE].into_boxed_slice(), PhantomData)
    }
}

impl<T> Clone for IvKey<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<T> PartialEq for IvKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T> Eq for IvKey<T> {}

impl<T: KeyIvInit> std::fmt::Debug for IvKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IvKey")
            .field("key", &"<redacted>")
            .field("iv", self.iv())
            .finish()
    }
}

impl<T: KeyIvInit> IvKey<T> {
    /// Total size of the key and IV in bytes.
    pub const SIZE: usize = T::KeySize::USIZE + T::IvSize::USIZE;

    /// Returns the IV part.
    #[inline]
    pub fn iv(&self) -> &Iv<T> {
        (&self.0[0..T::IvSize::USIZE])
            .try_into()
            .expect("iv is always the correct length")
    }

    /// Returns IV as a mutable slice.
    #[inline]
    pub fn iv_mut(&mut self) -> &mut [u8] {
        &mut self.0[0..T::IvSize::USIZE]
    }

    /// Returns the key part.
    #[inline]
    pub fn key(&self) -> &Key<T> {
        (&self.0[T::IvSize::USIZE..])
            .try_into()
            .expect("key is always the correct length")
    }

    /// Returns the key as a mutable slice.
    #[inline]
    pub fn key_mut(&mut self) -> &mut [u8] {
        &mut self.0[T::IvSize::USIZE..]
    }

    /// Turn this instance into another [`KeyIvInit`] with the same IV and key sizes.
    #[inline]
    pub fn into_init<V>(self) -> V
    where
        V: KeyIvInit<KeySize = T::KeySize, IvSize = T::IvSize>,
    {
        V::new(self.key(), self.iv())
    }
}

/// An address representing a PIX deposit.
///
/// ```rust
/// use hopr_types::primitive::prelude::Address;
/// use hopr_types::crypto::types::BjjPublicKey;
/// use hopr_types::crypto::keypairs::{Keypair, BjjKeypair, ChainKeypair};
/// use hopr_types::crypto::prelude::{PixDepositAddress, PixDepositAddressDiscriminants};
///
/// let pub_key_1 = *BjjKeypair::random().public();
/// let pub_key_2: PixDepositAddress = pub_key_1.into();
///
/// assert_eq!(PixDepositAddressDiscriminants::Bjj, pub_key_2.address_type());
/// assert_eq!(pub_key_1, pub_key_2.try_into().unwrap());
///
/// let pub_key_1 = ChainKeypair::random().public().to_address();
/// let pub_key_2: PixDepositAddress = pub_key_1.into();
///
/// assert_eq!(PixDepositAddressDiscriminants::Eth, pub_key_2.address_type());
/// assert_eq!(pub_key_1, pub_key_2.try_into().unwrap());
/// ```
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, strum::EnumDiscriminants)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[strum_discriminants(vis(pub))]
#[strum_discriminants(derive(strum::FromRepr, strum::EnumCount), repr(u8))]
#[cfg_attr(
    feature = "serde",
    strum_discriminants(derive(serde::Serialize, serde::Deserialize))
)]
pub enum PixDepositAddress {
    /// [`Address`]-based PIX deposit address.
    Eth(Address),
    /// [`BjjPublicKey`]-based PIX deposit address.
    Bjj(BjjPublicKey),
}

impl PixDepositAddress {
    /// Returns the address type of this deposit address.
    #[inline]
    pub fn address_type(&self) -> PixDepositAddressDiscriminants {
        self.discriminant()
    }
}

impl AsRef<[u8]> for PixDepositAddress {
    fn as_ref(&self) -> &[u8] {
        match self {
            PixDepositAddress::Eth(key) => key.as_ref(),
            PixDepositAddress::Bjj(key) => key.as_ref(),
        }
    }
}

impl From<Address> for PixDepositAddress {
    fn from(value: Address) -> Self {
        Self::Eth(value)
    }
}

impl From<PublicKey> for PixDepositAddress {
    fn from(value: PublicKey) -> Self {
        Self::Eth(value.to_address())
    }
}

impl TryFrom<PixDepositAddress> for Address {
    type Error = GeneralError;

    fn try_from(value: PixDepositAddress) -> Result<Self, Self::Error> {
        match value {
            PixDepositAddress::Eth(a) => Ok(a),
            PixDepositAddress::Bjj(_) => Err(GeneralError::InvalidInput),
        }
    }
}

impl From<BjjPublicKey> for PixDepositAddress {
    fn from(value: BjjPublicKey) -> Self {
        Self::Bjj(value)
    }
}

impl TryFrom<PixDepositAddress> for BjjPublicKey {
    type Error = GeneralError;

    fn try_from(value: PixDepositAddress) -> Result<Self, Self::Error> {
        match value {
            PixDepositAddress::Bjj(a) => Ok(a),
            PixDepositAddress::Eth(_) => Err(GeneralError::InvalidInput),
        }
    }
}

/// A secret corresponding to a PIX deposit address.
///
/// Usually the [`PixDepositAddress`] can be calculated from the secret.
#[derive(Clone, Debug)]
pub struct PixDepositSecret(pub SecretValue<typenum::U32>);

impl AsRef<SecretValue<typenum::U32>> for PixDepositSecret {
    fn as_ref(&self) -> &SecretValue<typenum::U32> {
        &self.0
    }
}

impl From<PixDepositSecret> for SecretValue<typenum::U32> {
    fn from(value: PixDepositSecret) -> Self {
        value.0
    }
}

impl From<SecretValue<typenum::U32>> for PixDepositSecret {
    fn from(value: SecretValue<typenum::U32>) -> Self {
        Self(value)
    }
}

/// Identifies one PIX deposit allocation within a HOPR Session.
///
/// A session may create several deposit addresses, so the session identifier
/// alone is not sufficient as a durable allocation key. The `session_id` is the
/// [`SimplePseudonym`] of the session (that is, `SessionId`) and the `ssa_index`
/// is the index of the allocation within the SSA protocol run of that session.
///
/// The representation is the session identifier followed by the big-endian SSA index,
/// which makes it usable as a stable database key. The SSA index is never zero.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PixAddressId(
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; Self::SIZE],
);

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PixAddressId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Must not be derived: the deserialized bytes have to be validated,
        // otherwise a zero SSA index could be constructed.
        let bytes = <serde_bytes::ByteBuf as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_from(bytes.as_ref()).map_err(serde::de::Error::custom)
    }
}

impl PixAddressId {
    /// Creates a PIX allocation identifier.
    pub fn new(session_id: &SimplePseudonym, ssa_index: NonZeroU32) -> Self {
        let mut ret = [0u8; Self::SIZE];
        ret[..SimplePseudonym::SIZE].copy_from_slice(session_id.as_ref());
        ret[SimplePseudonym::SIZE..].copy_from_slice(&ssa_index.get().to_be_bytes());
        Self(ret)
    }

    /// Returns the identifier of the HOPR Session to which this allocation belongs.
    pub fn session_id(&self) -> SimplePseudonym {
        SimplePseudonym::try_from(&self.0[..SimplePseudonym::SIZE])
            .expect("must have a valid session id")
    }

    /// Returns the non-zero SSA index of this allocation within the session.
    pub fn ssa_index(&self) -> NonZeroU32 {
        NonZeroU32::new(u32::from_be_bytes(
            self.0[SimplePseudonym::SIZE..]
                .try_into()
                .expect("must have a valid index size"),
        ))
        .expect("must have a non-zero SSA index")
    }
}

impl std::fmt::Debug for PixAddressId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PixAddressId")
            .field(&self.session_id())
            .field(&self.ssa_index())
            .finish()
    }
}

impl AsRef<[u8]> for PixAddressId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PixAddressId {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; Self::SIZE] = value
            .try_into()
            .map_err(|_| GeneralError::ParseError("PixAddressId".into()))?;

        // Validate both parts, so that the accessors cannot fail
        let session_id = SimplePseudonym::try_from(&bytes[..SimplePseudonym::SIZE])?;
        let ssa_index = NonZeroU32::new(u32::from_be_bytes(
            bytes[SimplePseudonym::SIZE..]
                .try_into()
                .map_err(|_| GeneralError::ParseError("PixAddressId".into()))?,
        ))
        .ok_or_else(|| GeneralError::ParseError("PixAddressId SSA index".into()))?;

        Ok(Self::new(&session_id, ssa_index))
    }
}

impl BytesRepresentable for PixAddressId {
    const SIZE: usize = SimplePseudonym::SIZE + size_of::<u32>();
}

impl From<PixAddressId> for (SimplePseudonym, NonZeroU32) {
    fn from(value: PixAddressId) -> Self {
        (value.session_id(), value.ssa_index())
    }
}

impl From<(SimplePseudonym, NonZeroU32)> for PixAddressId {
    fn from((session_id, ssa_index): (SimplePseudonym, NonZeroU32)) -> Self {
        Self::new(&session_id, ssa_index)
    }
}

#[cfg(test)]
mod pix_address_id_tests {
    use super::*;
    use crate::primitive::prelude::ToHex;

    fn pix_address_id(session_id: u8, ssa_index: u32) -> anyhow::Result<PixAddressId> {
        Ok(PixAddressId::new(
            &SimplePseudonym::from([session_id; SimplePseudonym::SIZE]),
            NonZeroU32::new(ssa_index).ok_or_else(|| anyhow::anyhow!("index must be non-zero"))?,
        ))
    }

    #[test]
    fn pix_address_id_has_a_stable_round_trip_representation() -> anyhow::Result<()> {
        let session_id = SimplePseudonym::from([7u8; SimplePseudonym::SIZE]);
        let ssa_index =
            NonZeroU32::new(3).ok_or_else(|| anyhow::anyhow!("index must be non-zero"))?;
        let id = pix_address_id(7, 3)?;

        assert_eq!(PixAddressId::SIZE, id.as_ref().len());
        assert_eq!(
            &id.as_ref()[..SimplePseudonym::SIZE],
            AsRef::<[u8]>::as_ref(&session_id)
        );
        assert_eq!(&id.as_ref()[SimplePseudonym::SIZE..], &3u32.to_be_bytes());

        assert_eq!(PixAddressId::try_from(id.as_ref())?, id);
        assert_eq!(PixAddressId::from_hex(&id.to_hex())?, id);
        assert_eq!(id.session_id(), session_id);
        assert_eq!(id.ssa_index(), ssa_index);
        assert_eq!(PixAddressId::from((session_id, ssa_index)), id);
        assert_eq!(
            <(SimplePseudonym, NonZeroU32)>::from(id),
            (session_id, ssa_index)
        );

        Ok(())
    }

    #[test]
    fn pix_address_id_is_ordered_by_session_and_ssa_index() -> anyhow::Result<()> {
        assert!(pix_address_id(7, 1)? < pix_address_id(7, 2)?);
        assert!(pix_address_id(7, u32::MAX)? < pix_address_id(8, 1)?);

        Ok(())
    }

    #[test]
    fn pix_address_id_rejects_invalid_representations() -> anyhow::Result<()> {
        let mut bytes = [0u8; PixAddressId::SIZE];
        bytes[..SimplePseudonym::SIZE].copy_from_slice(AsRef::<[u8]>::as_ref(
            &SimplePseudonym::from([7u8; SimplePseudonym::SIZE]),
        ));

        assert!(
            PixAddressId::try_from(bytes.as_slice()).is_err(),
            "zero SSA index must be rejected"
        );
        assert!(PixAddressId::try_from(&bytes[..PixAddressId::SIZE - 1]).is_err());
        assert!(PixAddressId::try_from([1u8; PixAddressId::SIZE + 1].as_slice()).is_err());

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn pix_address_id_serde_uses_the_stable_byte_representation() -> anyhow::Result<()> {
        let id = pix_address_id(7, 3)?;

        let encoded = serde_json::to_vec(&id)?;
        assert_eq!(serde_json::from_slice::<PixAddressId>(&encoded)?, id);
        assert_eq!(serde_json::from_slice::<Vec<u8>>(&encoded)?, id.as_ref());

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn pix_address_id_deserialization_must_validate_its_input() -> anyhow::Result<()> {
        // Deserialization must not be able to construct a zero SSA index,
        // which would make `ssa_index` panic.
        let mut bytes = [0u8; PixAddressId::SIZE];
        bytes[..SimplePseudonym::SIZE].copy_from_slice(AsRef::<[u8]>::as_ref(
            &SimplePseudonym::from([7u8; SimplePseudonym::SIZE]),
        ));

        let encoded = serde_json::to_vec(&bytes.to_vec())?;
        assert!(serde_json::from_slice::<PixAddressId>(&encoded).is_err());

        // Neither must a wrong length
        let encoded = serde_json::to_vec(&bytes[..PixAddressId::SIZE - 1].to_vec())?;
        assert!(serde_json::from_slice::<PixAddressId>(&encoded).is_err());

        Ok(())
    }
}
