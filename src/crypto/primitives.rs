use std::{fmt::Formatter, marker::PhantomData};

use typenum::Unsigned;

use crate::crypto::{
    crypto_traits::{Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser},
    utils::SecretValue,
};

/// AES with 128-bit key in counter-mode (with big-endian counter).
pub type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

use crate::crypto::prelude::{BjjPublicKey, Bn254PublicKey, PublicKey};
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

/// Size of a compressed secp256k1 spend meta-key `K` in SEC1 form.
pub const CURVY_SPEND_META_KEY_SIZE: usize = 33;

/// Size of a compressed BN254 G1 view key `V`.
///
/// The BN254 base field modulus is a 254-bit number, so the two most significant
/// bits of a canonical `x` are always clear and one of them can carry the sign of
/// `y`.
pub const CURVY_VIEW_KEY_SIZE: usize = 32;

/// Size of a Curvy scan public identity.
///
/// The encoding is `K_compressed || V_compressed`: 33 bytes of SEC1-compressed
/// secp256k1 spend meta-key followed by 32 bytes of compressed BN254 G1 view key.
/// Both halves are point-compressed because this identity is piggybacked on every
/// PIX SSA commitment, where the payload budget bounds how many allocations one
/// request can carry.
pub const CURVY_SCAN_PUBLIC_KEY_SIZE: usize = CURVY_SPEND_META_KEY_SIZE + CURVY_VIEW_KEY_SIZE;

/// Size of an Exit-local Curvy scan capability.
///
/// Its stable encoding is the 32-byte big-endian BN254 view scalar followed by
/// the corresponding 65-byte [`CurvyScanPublicKey`].
pub const CURVY_SCAN_SECRET_SIZE: usize = SecretKey::LENGTH + CURVY_SCAN_PUBLIC_KEY_SIZE;

/// Sign bit of `y`, stored in the most significant bit of the compressed BN254 `x`.
const CURVY_VIEW_KEY_SIGN_BIT: u8 = 0x80;

/// Curve coefficient `b` of BN254 G1: `y^2 = x^3 + 3`.
const BN254_G1_B: u64 = 3;

/// Public Curvy scan identity advertised for one PIX allocation.
///
/// This key only controls private note discovery. It is deliberately distinct
/// from [`PixDepositAddress`], whose BabyJubJub variant remains the note owner
/// and whose private key is reconstructed by the SSA protocol.
///
/// Both points are validated on construction, so every instance decompresses back
/// into affine coordinates without failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CurvyScanPublicKey([u8; CURVY_SCAN_PUBLIC_KEY_SIZE]);

#[cfg(feature = "serde")]
impl serde::Serialize for CurvyScanPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
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

impl CurvyScanPublicKey {
    /// Compresses and validates the affine coordinates of both scan points.
    ///
    /// Each coordinate is a canonical big-endian field element: `K` on secp256k1 and
    /// `V` on BN254 G1. Off-curve or non-canonical input is rejected here rather than
    /// travelling to a peer that cannot use it.
    pub fn from_affine_coordinates(
        spend_meta_key: (&[u8; 32], &[u8; 32]),
        view_key: (&[u8; 32], &[u8; 32]),
    ) -> Result<Self, GeneralError> {
        let mut encoded = [0_u8; CURVY_SCAN_PUBLIC_KEY_SIZE];
        encoded[..CURVY_SPEND_META_KEY_SIZE]
            .copy_from_slice(&compress_secp256k1(spend_meta_key.0, spend_meta_key.1)?);
        encoded[CURVY_SPEND_META_KEY_SIZE..]
            .copy_from_slice(&compress_bn254_g1(view_key.0, view_key.1)?);
        Ok(Self(encoded))
    }

    /// Builds a scan identity from its canonical compressed encoding.
    ///
    /// Both halves are decompressed to reject anything that is not a curve point.
    pub fn from_bytes(bytes: [u8; CURVY_SCAN_PUBLIC_KEY_SIZE]) -> Result<Self, GeneralError> {
        let identity = Self(bytes);
        identity.spend_meta_key()?;
        identity.view_key()?;
        Ok(identity)
    }

    /// Returns the canonical compressed encoding.
    pub const fn to_bytes(self) -> [u8; CURVY_SCAN_PUBLIC_KEY_SIZE] {
        self.0
    }

    /// Returns the SEC1-compressed secp256k1 spend meta-key `K`.
    pub fn spend_meta_key_compressed(&self) -> &[u8; CURVY_SPEND_META_KEY_SIZE] {
        self.0[..CURVY_SPEND_META_KEY_SIZE]
            .try_into()
            .expect("compressed Curvy K has a fixed size")
    }

    /// Returns the compressed BN254 G1 view key `V`.
    pub fn view_key_compressed(&self) -> &[u8; CURVY_VIEW_KEY_SIZE] {
        self.0[CURVY_SPEND_META_KEY_SIZE..]
            .try_into()
            .expect("compressed Curvy V has a fixed size")
    }

    /// Returns the decompressed secp256k1 `K` coordinates as `(x, y)`.
    pub fn spend_meta_key(&self) -> Result<([u8; 32], [u8; 32]), GeneralError> {
        decompress_secp256k1(self.spend_meta_key_compressed())
    }

    /// Returns the decompressed BN254 G1 `V` coordinates as `(x, y)`.
    pub fn view_key(&self) -> Result<([u8; 32], [u8; 32]), GeneralError> {
        decompress_bn254_g1(self.view_key_compressed())
    }
}

impl AsRef<[u8]> for CurvyScanPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for CurvyScanPublicKey {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; CURVY_SCAN_PUBLIC_KEY_SIZE]>::try_from(value)
            .map_err(|_| GeneralError::ParseError("CurvyScanPublicKey".into()))
            .and_then(Self::from_bytes)
    }
}

/// Compresses a secp256k1 point into its 33-byte SEC1 form.
fn compress_secp256k1(x: &[u8; 32], y: &[u8; 32]) -> Result<[u8; 33], GeneralError> {
    use k256::elliptic_curve::sec1::ToSec1Point;

    let mut uncompressed = [0_u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(x);
    uncompressed[33..].copy_from_slice(y);
    let point = crate::crypto::types::affine_point_from_bytes(&uncompressed)
        .map_err(|_| GeneralError::ParseError("Curvy spend meta-key K".into()))?;
    point
        .to_sec1_point(true)
        .as_ref()
        .try_into()
        .map_err(|_| GeneralError::ParseError("Curvy spend meta-key K".into()))
}

/// Recovers the affine `(x, y)` of a 33-byte SEC1-compressed secp256k1 point.
fn decompress_secp256k1(compressed: &[u8; 33]) -> Result<([u8; 32], [u8; 32]), GeneralError> {
    use k256::elliptic_curve::sec1::ToSec1Point;

    let point = crate::crypto::types::affine_point_from_bytes(compressed)
        .map_err(|_| GeneralError::ParseError("Curvy spend meta-key K".into()))?;
    let uncompressed = point.to_sec1_point(false);
    let bytes = uncompressed.as_ref();
    if bytes.len() != 65 {
        return Err(GeneralError::ParseError("Curvy spend meta-key K".into()));
    }
    let mut x = [0_u8; 32];
    let mut y = [0_u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..]);
    Ok((x, y))
}

/// Compresses a BN254 G1 point into `x` plus the sign bit of `y`.
fn compress_bn254_g1(x: &[u8; 32], y: &[u8; 32]) -> Result<[u8; 32], GeneralError> {
    use ark_ff::{BigInteger, PrimeField};

    let x_field = canonical_bn254_field_element(x)?;
    let y_field = canonical_bn254_field_element(y)?;
    // BN254 G1 has a prime order, so being on the curve already implies membership
    // of the prime-order subgroup; no cofactor clearing check is needed.
    if !ark_bn254::G1Affine::new_unchecked(x_field, y_field).is_on_curve() {
        return Err(GeneralError::ParseError("Curvy view key V".into()));
    }
    let mut compressed = *x;
    if y_field.into_bigint().is_odd() {
        compressed[0] |= CURVY_VIEW_KEY_SIGN_BIT;
    }
    Ok(compressed)
}

/// Recovers the affine `(x, y)` of a compressed BN254 G1 point.
fn decompress_bn254_g1(compressed: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), GeneralError> {
    use ark_ff::{BigInteger, Field, PrimeField};

    let sign = compressed[0] & CURVY_VIEW_KEY_SIGN_BIT != 0;
    let mut x = *compressed;
    x[0] &= !CURVY_VIEW_KEY_SIGN_BIT;
    let x_field = canonical_bn254_field_element(&x)?;

    let y_squared = x_field * x_field * x_field + ark_bn254::Fq::from(BN254_G1_B);
    let root = y_squared
        .sqrt()
        .ok_or_else(|| GeneralError::ParseError("Curvy view key V".into()))?;
    // The two roots differ in parity because the field modulus is odd, so the sign
    // bit selects one of them unambiguously.
    let y_field = if root.into_bigint().is_odd() == sign {
        root
    } else {
        -root
    };

    let mut y = [0_u8; 32];
    y.copy_from_slice(&y_field.into_bigint().to_bytes_be());
    Ok((x, y))
}

/// Parses a canonical big-endian BN254 base-field element, rejecting anything that
/// is not fully reduced.
fn canonical_bn254_field_element(bytes: &[u8; 32]) -> Result<ark_bn254::Fq, GeneralError> {
    use ark_ff::{BigInteger, PrimeField};

    let element = ark_bn254::Fq::from_be_bytes_mod_order(bytes);
    if element.into_bigint().to_bytes_be() != bytes {
        return Err(GeneralError::ParseError("Curvy BN254 coordinate".into()));
    }
    Ok(element)
}

/// Exit-held capability for privately discovering a Curvy PIX allocation.
///
/// It contains the BN254 view scalar `v` and the corresponding public identity.
/// No stealth spend scalar and no BabyJubJub withdrawal secret are present.
#[derive(Clone)]
pub struct CurvyScanSecret {
    view_secret: SecretKey,
    public: CurvyScanPublicKey,
}

impl std::fmt::Debug for CurvyScanSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CurvyScanSecret")
            .field("view_secret", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
}

impl CurvyScanSecret {
    /// Creates a scan-only capability from a validated view scalar and public identity.
    pub const fn new(view_secret: SecretKey, public: CurvyScanPublicKey) -> Self {
        Self {
            view_secret,
            public,
        }
    }

    /// Returns the private BN254 view scalar.
    pub fn view_secret(&self) -> &SecretKey {
        &self.view_secret
    }

    /// Returns the public identity sent to the Entry.
    pub const fn public(&self) -> CurvyScanPublicKey {
        self.public
    }

    /// Returns the stable Exit-local wire representation.
    ///
    /// This representation is private capability material. It must never be sent to the Entry
    /// or logged by the generic PIX layers.
    pub fn to_bytes(&self) -> [u8; CURVY_SCAN_SECRET_SIZE] {
        let mut encoded = [0_u8; CURVY_SCAN_SECRET_SIZE];
        encoded[..SecretKey::LENGTH].copy_from_slice(self.view_secret.as_ref());
        encoded[SecretKey::LENGTH..].copy_from_slice(self.public.as_ref());
        encoded
    }

    /// Decodes and validates an Exit-local Curvy scan capability.
    ///
    /// Besides validating the public curve points, this checks that the advertised view key `V`
    /// is exactly the BN254 generator multiplied by the supplied view scalar `v`. This prevents a
    /// malformed private payload from silently scanning with a mismatched identity.
    pub fn from_bytes(bytes: [u8; CURVY_SCAN_SECRET_SIZE]) -> Result<Self, GeneralError> {
        use ark_ec::AffineRepr;
        use ark_ff::{BigInteger, PrimeField};

        let view_secret_bytes: [u8; SecretKey::LENGTH] = bytes[..SecretKey::LENGTH]
            .try_into()
            .map_err(|_| GeneralError::ParseError("Curvy view scalar v".into()))?;
        let public = CurvyScanPublicKey::try_from(&bytes[SecretKey::LENGTH..])?;

        // HOPR's generic BN254 key type uses little-endian scalars, while Curvy encodes `v` as a
        // big-endian integer. Reverse only at this validation boundary.
        let mut little_endian = view_secret_bytes;
        little_endian.reverse();
        let expected = Bn254PublicKey::from_privkey(&little_endian)
            .map_err(|_| GeneralError::ParseError("Curvy view scalar v".into()))?;
        let expected: ark_bn254::G1Projective = (&expected)
            .try_into()
            .map_err(|_| GeneralError::ParseError("Curvy view key V".into()))?;
        let expected = ark_bn254::G1Affine::from(expected);
        let mut expected_x = [0_u8; 32];
        let mut expected_y = [0_u8; 32];
        expected_x.copy_from_slice(
            &expected
                .x()
                .ok_or_else(|| GeneralError::ParseError("Curvy view key V".into()))?
                .into_bigint()
                .to_bytes_be(),
        );
        expected_y.copy_from_slice(
            &expected
                .y()
                .ok_or_else(|| GeneralError::ParseError("Curvy view key V".into()))?
                .into_bigint()
                .to_bytes_be(),
        );
        if public.view_key()? != (expected_x, expected_y) {
            return Err(GeneralError::ParseError("Curvy view scalar/public mismatch".into()));
        }

        Ok(Self::new(SecretKey::from(view_secret_bytes), public))
    }
}

impl TryFrom<&[u8]> for CurvyScanSecret {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; CURVY_SCAN_SECRET_SIZE]>::try_from(value)
            .map_err(|_| GeneralError::ParseError("CurvyScanSecret".into()))
            .and_then(Self::from_bytes)
    }
}

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

#[cfg(test)]
mod curvy_scan_tests {
    use super::*;

    /// Affine coordinates of the two generators, the cheapest valid fixture points.
    fn scan_fixture_coordinates() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        use ark_ec::AffineRepr;
        use ark_ff::{BigInteger, PrimeField};
        use k256::elliptic_curve::sec1::ToSec1Point;

        let secp = k256::AffinePoint::GENERATOR.to_sec1_point(false);
        let secp = secp.as_ref();
        let mut spend_x = [0_u8; 32];
        let mut spend_y = [0_u8; 32];
        spend_x.copy_from_slice(&secp[1..33]);
        spend_y.copy_from_slice(&secp[33..]);

        let bn = ark_bn254::G1Affine::generator();
        let mut view_x = [0_u8; 32];
        let mut view_y = [0_u8; 32];
        view_x.copy_from_slice(
            &bn.x()
                .expect("generator is not the point at infinity")
                .into_bigint()
                .to_bytes_be(),
        );
        view_y.copy_from_slice(
            &bn.y()
                .expect("generator is not the point at infinity")
                .into_bigint()
                .to_bytes_be(),
        );

        (spend_x, spend_y, view_x, view_y)
    }

    fn scan_fixture() -> CurvyScanPublicKey {
        let (spend_x, spend_y, view_x, view_y) = scan_fixture_coordinates();
        CurvyScanPublicKey::from_affine_coordinates((&spend_x, &spend_y), (&view_x, &view_y))
            .expect("generator coordinates are valid curve points")
    }

    #[test]
    fn curvy_scan_identity_round_trips_through_its_compressed_encoding() -> anyhow::Result<()> {
        let (spend_x, spend_y, view_x, view_y) = scan_fixture_coordinates();
        let public = scan_fixture();

        // 33 bytes of SEC1 secp256k1 plus 32 bytes of BN254 G1, not four raw coordinates.
        assert_eq!(CURVY_SCAN_PUBLIC_KEY_SIZE, 65);
        assert_eq!(public.to_bytes().len(), CURVY_SCAN_PUBLIC_KEY_SIZE);
        assert_eq!(public.spend_meta_key_compressed()[1..], spend_x);
        assert_eq!(public.view_key_compressed()[1..], view_x[1..]);

        assert_eq!(public.spend_meta_key()?, (spend_x, spend_y));
        assert_eq!(public.view_key()?, (view_x, view_y));
        assert_eq!(CurvyScanPublicKey::from_bytes(public.to_bytes())?, public);
        assert_eq!(CurvyScanPublicKey::try_from(public.as_ref())?, public);
        Ok(())
    }

    #[test]
    fn curvy_scan_identity_rejects_points_off_the_curve() {
        let (spend_x, spend_y, view_x, view_y) = scan_fixture_coordinates();

        // A wrong length is not a scan identity.
        assert!(
            CurvyScanPublicKey::try_from([7_u8; CURVY_SCAN_PUBLIC_KEY_SIZE - 1].as_slice())
                .is_err()
        );
        // Neither is a byte string that decompresses to nothing.
        assert!(CurvyScanPublicKey::from_bytes([7_u8; CURVY_SCAN_PUBLIC_KEY_SIZE]).is_err());
        // Swapping the coordinates takes both points off their curve.
        assert!(
            CurvyScanPublicKey::from_affine_coordinates((&spend_y, &spend_x), (&view_x, &view_y))
                .is_err()
        );
        assert!(
            CurvyScanPublicKey::from_affine_coordinates((&spend_x, &spend_y), (&view_y, &view_x))
                .is_err()
        );
    }

    #[test]
    fn curvy_scan_identity_preserves_the_sign_of_the_view_key() -> anyhow::Result<()> {
        use ark_ff::{AdditiveGroup, BigInteger, PrimeField};

        let (spend_x, spend_y, view_x, view_y) = scan_fixture_coordinates();
        let negated = -ark_bn254::Fq::from_be_bytes_mod_order(&view_y);
        assert_ne!(negated, ark_bn254::Fq::ZERO);
        let mut negated_y = [0_u8; 32];
        negated_y.copy_from_slice(&negated.into_bigint().to_bytes_be());

        let positive =
            CurvyScanPublicKey::from_affine_coordinates((&spend_x, &spend_y), (&view_x, &view_y))?;
        let negative = CurvyScanPublicKey::from_affine_coordinates(
            (&spend_x, &spend_y),
            (&view_x, &negated_y),
        )?;

        assert_ne!(
            positive, negative,
            "both roots of x must be distinguishable"
        );
        assert_eq!(positive.view_key()?.1, view_y);
        assert_eq!(negative.view_key()?.1, negated_y);
        Ok(())
    }

    #[test]
    fn curvy_scan_secret_debug_output_redacts_the_view_scalar() {
        let public = scan_fixture();
        let scalar = [42_u8; 32];
        let secret = CurvyScanSecret::new(SecretKey::from(scalar), public);
        let debug = format!("{secret:?}");

        assert!(debug.contains("<redacted>"));
        // The public identity may contain any byte value, so look for the scalar
        // itself rather than for digits that a valid curve point can also produce.
        assert!(!debug.contains(&format!("{scalar:?}")));
        assert!(!debug.contains("2a2a2a"));
        assert_eq!(secret.public(), public);
    }

    #[test]
    fn curvy_scan_secret_round_trips_and_rejects_a_mismatched_view_key() -> anyhow::Result<()> {
        let public = scan_fixture();
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        let secret = CurvyScanSecret::new(SecretKey::from(scalar), public);

        let encoded = secret.to_bytes();
        let decoded = CurvyScanSecret::from_bytes(encoded)?;
        assert_eq!(decoded.public(), public);
        assert_eq!(decoded.view_secret().as_ref(), scalar);

        let mut mismatched = encoded;
        mismatched[31] = 2;
        assert!(CurvyScanSecret::from_bytes(mismatched).is_err());
        Ok(())
    }
}
