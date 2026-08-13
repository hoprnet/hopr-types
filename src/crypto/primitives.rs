use std::{fmt::Formatter, marker::PhantomData};

use typenum::Unsigned;

use crate::crypto::{
    crypto_traits::{Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser},
    utils::SecretValue,
};

/// AES with 128-bit key in counter-mode (with big-endian counter).
pub type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

use crate::crypto::prelude::{BjjPublicKey, PublicKey};
use crate::primitive::prelude::{Address, GeneralError};
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
