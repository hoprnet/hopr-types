use std::{fmt::Formatter, marker::PhantomData, str::FromStr};

use typenum::Unsigned;

use crate::crypto::{
    crypto_traits::{Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser},
    utils::SecretValue,
};

/// AES with 128-bit key in counter-mode (with big-endian counter).
pub type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

use crate::crypto::{
    errors::CryptoError,
    prelude::{BjjKeypair, BjjPublicKey, Keypair, PublicKey},
};
use crate::primitive::prelude::{Address, BytesRepresentable, GeneralError, ToHex};
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

const PIX_FIELD_ELEMENT_SIZE: usize = 32;

macro_rules! pix_field_element {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(
            #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
            [u8; PIX_FIELD_ELEMENT_SIZE],
        );

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = GeneralError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                value
                    .try_into()
                    .map(Self)
                    .map_err(|_| GeneralError::ParseError(stringify!($name).into()))
            }
        }

        impl BytesRepresentable for $name {
            const SIZE: usize = PIX_FIELD_ELEMENT_SIZE;
        }

        impl From<[u8; PIX_FIELD_ELEMENT_SIZE]> for $name {
            fn from(value: [u8; PIX_FIELD_ELEMENT_SIZE]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; PIX_FIELD_ELEMENT_SIZE] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = GeneralError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::from_hex(value)
            }
        }
    };
}

pix_field_element!(
    PixNoteId,
    "A Curvy/PIX note identifier encoded as exactly 32 bytes."
);
pix_field_element!(
    PixNoteTreeRoot,
    "A root of the Curvy/PIX depth-30 note commitment tree encoded as exactly 32 bytes."
);

/// Depth of the Curvy note commitment tree.
pub const PIX_NOTE_TREE_DEPTH: u8 = 30;
/// Level at which complete Curvy note subtrees are persisted as shards.
pub const PIX_NOTE_TREE_SHARD_LEVEL: u8 = 14;
/// Number of dense, non-padding leaves in one completed Curvy note-tree shard.
pub const PIX_NOTE_TREE_SHARD_SIZE: u64 = 1 << PIX_NOTE_TREE_SHARD_LEVEL;

/// Position of a non-zero note in the dense Curvy note commitment tree.
///
/// This is independent from the raw event `item_index`: zero-padded event slots
/// retain their raw cursor position but do not consume a Merkle leaf position.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PixNoteTreeLeafIndex(pub u64);

/// A pinned view of the indexed Curvy note commitment tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PixNoteTreeCheckpoint {
    /// Root at this checkpoint.
    pub root: PixNoteTreeRoot,
    /// Number of dense, non-zero leaves included in `root`.
    pub leaf_count: u64,
}

/// Root of one completed level-14 Curvy note-tree shard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PixNoteTreeShardRoot {
    /// Zero-based shard index.
    pub shard_index: u64,
    /// Root of the 16,384-leaf shard.
    pub root: PixNoteTreeRoot,
}

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
/// The curve tag is part of the secret so the same 32 bytes cannot accidentally
/// be interpreted using a different key derivation profile. BabyJubJub scalars
/// use their canonical little-endian representation; Ethereum scalars use the
/// canonical secp256k1 big-endian representation.
#[derive(Clone, Debug)]
pub enum PixDepositSecret {
    /// Secret scalar for an Ethereum PIX deposit address.
    Eth(SecretKey),
    /// Secret scalar for a BabyJubJub PIX deposit address.
    Bjj(SecretKey),
}

impl PixDepositSecret {
    /// Constructs and validates an Ethereum PIX deposit secret.
    pub fn ethereum(secret: SecretKey) -> Result<Self, CryptoError> {
        PublicKey::from_privkey(secret.as_ref())?;
        Ok(Self::Eth(secret))
    }

    /// Constructs and validates a canonical BabyJubJub PIX deposit secret.
    pub fn baby_jubjub(secret: SecretKey) -> Result<Self, CryptoError> {
        BjjPublicKey::from_privkey(secret.as_ref())?;
        Ok(Self::Bjj(secret))
    }

    /// Returns the public PIX deposit address corresponding to this secret.
    pub fn address(&self) -> Result<PixDepositAddress, CryptoError> {
        match self {
            Self::Eth(secret) => Ok(PublicKey::from_privkey(secret.as_ref())?
                .to_address()
                .into()),
            Self::Bjj(secret) => Ok(BjjPublicKey::from_privkey(secret.as_ref())?.into()),
        }
    }

    /// Returns the address representation accepted by this secret.
    pub fn address_type(&self) -> PixDepositAddressDiscriminants {
        match self {
            Self::Eth(_) => PixDepositAddressDiscriminants::Eth,
            Self::Bjj(_) => PixDepositAddressDiscriminants::Bjj,
        }
    }

    /// Returns the canonical scalar bytes without removing the curve tag.
    pub fn secret(&self) -> &SecretKey {
        match self {
            Self::Eth(secret) | Self::Bjj(secret) => secret,
        }
    }
}

impl TryFrom<&PixDepositSecret> for PixDepositAddress {
    type Error = CryptoError;

    fn try_from(value: &PixDepositSecret) -> Result<Self, Self::Error> {
        value.address()
    }
}

/// Converts the validated BabyJubJub keypair reconstructed by the PIX protocol
/// into the curve-tagged secret consumed by a deposit-pool implementation.
impl From<&BjjKeypair> for PixDepositSecret {
    fn from(value: &BjjKeypair) -> Self {
        Self::Bjj(value.secret().clone())
    }
}

#[cfg(test)]
mod pix_tests {
    use super::*;

    #[test]
    fn pix_secrets_are_curve_tagged_and_derive_their_addresses() -> anyhow::Result<()> {
        let scalar = SecretKey::from([1_u8; 32]);
        let bjj = PixDepositSecret::baby_jubjub(scalar.clone())?;
        let eth = PixDepositSecret::ethereum(scalar)?;

        assert_eq!(bjj.address_type(), PixDepositAddressDiscriminants::Bjj);
        assert!(matches!(bjj.address()?, PixDepositAddress::Bjj(_)));
        assert_eq!(eth.address_type(), PixDepositAddressDiscriminants::Eth);
        assert!(matches!(eth.address()?, PixDepositAddress::Eth(_)));
        Ok(())
    }

    #[test]
    fn pix_secret_constructors_reject_invalid_scalars() {
        let zero = SecretKey::from([0_u8; 32]);

        assert!(PixDepositSecret::baby_jubjub(zero.clone()).is_err());
        assert!(PixDepositSecret::ethereum(zero).is_err());
    }

    #[test]
    fn reconstructed_bjj_keypair_becomes_a_tagged_pix_secret() -> anyhow::Result<()> {
        let reconstructed = BjjKeypair::random();
        let secret = PixDepositSecret::from(&reconstructed);

        assert_eq!(
            secret.address()?,
            PixDepositAddress::from(*reconstructed.public())
        );
        assert_eq!(secret.address_type(), PixDepositAddressDiscriminants::Bjj);
        Ok(())
    }
}
