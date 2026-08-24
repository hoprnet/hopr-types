use std::{fmt::Formatter, marker::PhantomData, num::NonZeroU32};

use typenum::Unsigned;

use crate::crypto::{
    crypto_traits::{Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser},
    utils::SecretValue,
};

/// AES with 128-bit key in counter-mode (with big-endian counter).
pub type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

use crate::crypto::prelude::{
    BjjPublicKey, Bn254Keypair, Bn254PublicKey, Keypair, PublicKey, SimplePseudonym,
};
use crate::primitive::prelude::{Address, BytesEncodable, BytesRepresentable, GeneralError};
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PixAddressId(
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; Self::SIZE],
);

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

/// Size of a Curvy scan public identity.
///
/// The encoding is `K || V`: the SEC1-compressed secp256k1 spend meta-key `K`
/// followed by the compressed BN254 G1 view key `V`. Both points are compressed because
/// this identity is piggybacked on every PIX SSA commitment, where the payload budget
/// bounds how many allocations one request can carry.
pub const CURVY_SCAN_PUBLIC_KEY_SIZE: usize = PublicKey::SIZE_COMPRESSED + Bn254PublicKey::SIZE;

/// Size of an Exit-local Curvy scan capability.
///
/// The encoding is `v || K`: the big-endian BN254 view scalar `v` followed by the
/// SEC1-compressed secp256k1 spend meta-key `K`. The view key `V` is not part of it,
/// because it is always derived from `v`.
pub const CURVY_SCAN_SECRET_SIZE: usize = SecretKey::LENGTH + PublicKey::SIZE_COMPRESSED;

const _: () = assert!(CURVY_SCAN_SECRET_SIZE == SecretValue::<typenum::U65>::LENGTH);

/// Public Curvy scan identity advertised for one PIX allocation.
///
/// It consists of the secp256k1 spend meta-key `K` and the BN254 G1 view key `V`,
/// and only controls private note discovery. It is deliberately distinct from
/// [`PixDepositAddress`], whose BabyJubJub variant remains the note owner and whose
/// private key is reconstructed by the SSA protocol.
///
/// Both points are validated by their respective key types, so every instance
/// decompresses back into affine coordinates without failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CurvyScanPublicKey {
    spend_meta_key: PublicKey,
    view_key: Bn254PublicKey,
}

impl CurvyScanPublicKey {
    /// Creates the scan identity from the spend meta-key `K` and the view key `V`.
    pub const fn new(spend_meta_key: PublicKey, view_key: Bn254PublicKey) -> Self {
        Self {
            spend_meta_key,
            view_key,
        }
    }

    /// Returns the secp256k1 spend meta-key `K`.
    pub const fn spend_meta_key(&self) -> &PublicKey {
        &self.spend_meta_key
    }

    /// Returns the BN254 G1 view key `V`.
    pub const fn view_key(&self) -> &Bn254PublicKey {
        &self.view_key
    }
}

impl From<CurvyScanPublicKey> for [u8; CURVY_SCAN_PUBLIC_KEY_SIZE] {
    fn from(value: CurvyScanPublicKey) -> Self {
        let mut ret = [0u8; CURVY_SCAN_PUBLIC_KEY_SIZE];
        ret[..PublicKey::SIZE_COMPRESSED].copy_from_slice(value.spend_meta_key.as_ref());
        ret[PublicKey::SIZE_COMPRESSED..].copy_from_slice(value.view_key.as_ref());
        ret
    }
}

impl TryFrom<&[u8]> for CurvyScanPublicKey {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != CURVY_SCAN_PUBLIC_KEY_SIZE {
            return Err(GeneralError::ParseError("CurvyScanPublicKey".into()));
        }

        Ok(Self::new(
            PublicKey::try_from(&value[..PublicKey::SIZE_COMPRESSED])?,
            Bn254PublicKey::try_from(&value[PublicKey::SIZE_COMPRESSED..])?,
        ))
    }
}

impl BytesEncodable<CURVY_SCAN_PUBLIC_KEY_SIZE> for CurvyScanPublicKey {}

#[cfg(feature = "serde")]
impl serde::Serialize for CurvyScanPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.into_encoded())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CurvyScanPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <serde_bytes::ByteBuf as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_from(bytes.as_ref()).map_err(serde::de::Error::custom)
    }
}

/// Exit-held capability for privately discovering a Curvy PIX allocation.
///
/// It consists of the BN254 view keypair (`v` and `V = v * G`) and the public
/// spend meta-key `K`. It contains no stealth spend scalar and no BabyJubJub
/// withdrawal secret.
///
/// Since the view key is a [`Bn254Keypair`], `V` is always consistent with `v`.
#[derive(Clone, Debug)]
pub struct CurvyScanSecret {
    view: Bn254Keypair,
    spend_meta_key: PublicKey,
}

impl CurvyScanSecret {
    /// Creates a scan-only capability from the view keypair and the spend meta-key `K`.
    pub const fn new(view: Bn254Keypair, spend_meta_key: PublicKey) -> Self {
        Self {
            view,
            spend_meta_key,
        }
    }

    /// Returns the BN254 view keypair (`v` and `V`).
    ///
    /// Note that [`Keypair::secret`] returns `v` in the little-endian representation,
    /// use [`Bn254Keypair::secret_be`] for the big-endian one.
    pub const fn view(&self) -> &Bn254Keypair {
        &self.view
    }

    /// Returns the secp256k1 spend meta-key `K`.
    pub const fn spend_meta_key(&self) -> &PublicKey {
        &self.spend_meta_key
    }

    /// Returns the public identity sent to the Entry.
    pub fn public(&self) -> CurvyScanPublicKey {
        CurvyScanPublicKey::new(self.spend_meta_key, *self.view.public())
    }

    /// Returns the stable Exit-local representation: `v` (big-endian) followed by `K`.
    ///
    /// This representation is private capability material. It must never be sent to
    /// the Entry or logged by the generic PIX layers.
    pub fn to_bytes(&self) -> SecretValue<typenum::U65> {
        let mut ret = SecretValue::<typenum::U65>::default();
        ret.as_mut()[..SecretKey::LENGTH].copy_from_slice(self.view.secret_be().as_ref());
        ret.as_mut()[SecretKey::LENGTH..].copy_from_slice(self.spend_meta_key.as_ref());
        ret
    }
}

impl TryFrom<&[u8]> for CurvyScanSecret {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != CURVY_SCAN_SECRET_SIZE {
            return Err(GeneralError::ParseError("CurvyScanSecret".into()));
        }

        Ok(Self::new(
            Bn254Keypair::from_secret_be(&value[..SecretKey::LENGTH])
                .map_err(|_| GeneralError::ParseError("Curvy view scalar v".into()))?,
            PublicKey::try_from(&value[SecretKey::LENGTH..])?,
        ))
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
}

#[cfg(test)]
mod curvy_scan_tests {
    use subtle::ConstantTimeEq;

    use super::*;
    use crate::crypto_random::Randomizable;

    /// Big-endian view scalar `1`, whose view key is the BN254 G1 generator.
    fn view_scalar_one() -> [u8; SecretKey::LENGTH] {
        let mut ret = [0u8; SecretKey::LENGTH];
        ret[SecretKey::LENGTH - 1] = 1;
        ret
    }

    #[test]
    fn curvy_scan_public_key_round_trips_through_its_encoding() -> anyhow::Result<()> {
        let spend_meta_key = PublicKey::random();
        let view_key = *Bn254Keypair::random().public();
        let identity = CurvyScanPublicKey::new(spend_meta_key, view_key);

        // 33 bytes of SEC1 secp256k1 plus 32 bytes of BN254 G1, not four raw coordinates
        assert_eq!(65, CURVY_SCAN_PUBLIC_KEY_SIZE);

        let encoded = identity.into_encoded();
        assert_eq!(
            &encoded[..PublicKey::SIZE_COMPRESSED],
            AsRef::<[u8]>::as_ref(&spend_meta_key)
        );
        assert_eq!(&encoded[PublicKey::SIZE_COMPRESSED..], view_key.as_ref());

        assert_eq!(CurvyScanPublicKey::try_from(&encoded[..])?, identity);
        assert_eq!(identity.spend_meta_key(), &spend_meta_key);
        assert_eq!(identity.view_key(), &view_key);

        Ok(())
    }

    #[test]
    fn curvy_scan_public_key_rejects_invalid_points() -> anyhow::Result<()> {
        let identity =
            CurvyScanPublicKey::new(PublicKey::random(), *Bn254Keypair::random().public());
        let encoded = identity.into_encoded();

        // A wrong length is not a scan identity
        assert!(CurvyScanPublicKey::try_from(&encoded[..CURVY_SCAN_PUBLIC_KEY_SIZE - 1]).is_err());
        assert!(
            CurvyScanPublicKey::try_from([7u8; CURVY_SCAN_PUBLIC_KEY_SIZE + 1].as_slice()).is_err()
        );

        // Neither is a byte string that decompresses to nothing
        assert!(
            CurvyScanPublicKey::try_from([7u8; CURVY_SCAN_PUBLIC_KEY_SIZE].as_slice()).is_err()
        );

        // An invalid spend meta-key K is rejected
        let mut invalid_k = encoded;
        invalid_k[0] = 7;
        assert!(CurvyScanPublicKey::try_from(&invalid_k[..]).is_err());

        // ...and so is a view key V that is not on the curve (4^3 + 3 is not a quadratic residue)
        let mut invalid_v = encoded;
        invalid_v[PublicKey::SIZE_COMPRESSED..].fill(0);
        invalid_v[CURVY_SCAN_PUBLIC_KEY_SIZE - 1] = 4;
        assert!(CurvyScanPublicKey::try_from(&invalid_v[..]).is_err());

        Ok(())
    }

    #[test]
    fn curvy_scan_public_key_preserves_the_sign_of_the_view_key() -> anyhow::Result<()> {
        let spend_meta_key = PublicKey::random();
        let view_key = *Bn254Keypair::random().public();

        let affine: Bn254G1Projective = view_key.try_into()?;
        let negated = Bn254PublicKey::try_from(-affine)?;

        let positive = CurvyScanPublicKey::new(spend_meta_key, view_key);
        let negative = CurvyScanPublicKey::new(spend_meta_key, negated);

        assert_ne!(
            positive, negative,
            "both roots of x must be distinguishable"
        );
        assert_eq!(
            CurvyScanPublicKey::try_from(&positive.into_encoded()[..])?.view_key(),
            &view_key
        );
        assert_eq!(
            CurvyScanPublicKey::try_from(&negative.into_encoded()[..])?.view_key(),
            &negated
        );

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn curvy_scan_public_key_serde_uses_the_compact_encoding() -> anyhow::Result<()> {
        let identity =
            CurvyScanPublicKey::new(PublicKey::random(), *Bn254Keypair::random().public());

        let encoded = serde_json::to_vec(&identity)?;
        assert_eq!(
            serde_json::from_slice::<CurvyScanPublicKey>(&encoded)?,
            identity
        );
        assert_eq!(
            serde_json::from_slice::<Vec<u8>>(&encoded)?,
            identity.into_encoded(),
            "serde must use the canonical 65-byte encoding"
        );

        Ok(())
    }

    #[test]
    fn curvy_scan_secret_round_trips_and_derives_its_public_identity() -> anyhow::Result<()> {
        let view = Bn254Keypair::random();
        let spend_meta_key = PublicKey::random();
        let secret = CurvyScanSecret::new(view.clone(), spend_meta_key);

        // The view key is always the one belonging to the view scalar
        assert_eq!(secret.public().view_key(), view.public());
        assert_eq!(secret.public().spend_meta_key(), &spend_meta_key);

        let encoded = secret.to_bytes();
        assert_eq!(CURVY_SCAN_SECRET_SIZE, encoded.as_ref().len());
        assert_eq!(
            &encoded.as_ref()[..SecretKey::LENGTH],
            view.secret_be().as_ref(),
            "the view scalar must be encoded as big-endian"
        );
        assert_eq!(
            &encoded.as_ref()[SecretKey::LENGTH..],
            AsRef::<[u8]>::as_ref(&spend_meta_key)
        );

        let decoded = CurvyScanSecret::try_from(encoded.as_ref())?;
        assert_eq!(decoded.view().ct_eq(secret.view()).unwrap_u8(), 1);
        assert_eq!(decoded.public(), secret.public());
        assert_eq!(decoded.spend_meta_key(), &spend_meta_key);

        // A wrong length or a zero view scalar is not a scan capability
        assert!(
            CurvyScanSecret::try_from(&encoded.as_ref()[..CURVY_SCAN_SECRET_SIZE - 1]).is_err()
        );
        let mut zero_scalar = [0u8; CURVY_SCAN_SECRET_SIZE];
        zero_scalar[SecretKey::LENGTH..].copy_from_slice(spend_meta_key.as_ref());
        assert!(CurvyScanSecret::try_from(zero_scalar.as_slice()).is_err());

        Ok(())
    }

    #[test]
    fn curvy_scan_secret_interprets_the_view_scalar_as_big_endian() -> anyhow::Result<()> {
        use ark_ec::AffineRepr;

        let spend_meta_key = PublicKey::random();

        let mut encoded = [0u8; CURVY_SCAN_SECRET_SIZE];
        encoded[..SecretKey::LENGTH].copy_from_slice(&view_scalar_one());
        encoded[SecretKey::LENGTH..].copy_from_slice(spend_meta_key.as_ref());

        let secret = CurvyScanSecret::try_from(encoded.as_slice())?;
        assert_eq!(
            secret.public().view_key(),
            &Bn254PublicKey::try_from(Bn254G1Affine::generator())?,
            "the scalar 1 must yield the BN254 generator as the view key"
        );

        Ok(())
    }

    #[test]
    fn curvy_scan_secret_debug_output_redacts_the_view_scalar() -> anyhow::Result<()> {
        let scalar = [42u8; SecretKey::LENGTH];
        let secret =
            CurvyScanSecret::new(Bn254Keypair::from_secret_be(&scalar)?, PublicKey::random());

        let debug = format!("{secret:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&format!("{scalar:?}")));
        assert!(!debug.contains("2a2a2a"));

        Ok(())
    }
}
