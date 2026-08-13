use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    montgomery::MontgomeryPoint,
};
use digest::Digest;
use elliptic_curve::NonZeroScalar;
use hybrid_array::Array;
use k256::{
    AffinePoint, Secp256k1,
    elliptic_curve::{
        self,
        point::NonIdentity,
        sec1::{FromSec1Point, Sec1Point, ToSec1Point},
    },
};
type EncodedPoint = Sec1Point<Secp256k1>;
use crate::crypto_random::Randomizable;
use crate::primitive::{errors::GeneralError::ParseError, prelude::*};
use libp2p_identity::PeerId;
use std::{
    cmp::Ordering,
    fmt::{Debug, Display, Formatter},
    hash,
    hash::Hasher,
    marker::PhantomData,
    result,
    str::FromStr,
};

use crate::crypto::crypto_traits::OutputSizeUser;
use crate::crypto::{
    errors::{
        CryptoError::{self, CalculationError, InvalidInputValue},
        Result,
    },
    utils::random_group_element,
};

pub(crate) fn affine_point_from_bytes(bytes: &[u8]) -> Result<AffinePoint> {
    let ep = EncodedPoint::from_bytes(bytes)
        .map_err(|_| InvalidInputValue("affine_point_from_bytes"))?;
    AffinePoint::from_sec1_point(&ep)
        .into_option()
        .ok_or(InvalidInputValue("affine_point_from_bytes"))
}

pub(crate) fn affine_point_to_address(ap: &AffinePoint) -> Address {
    let serialized = ap.to_sec1_point(false);
    let hash = Hash::create(&[&serialized.as_ref()[1..]]);
    Address::new(&hash.as_ref()[12..])
}

/// Contains the complete Proof-of-Relay challenge is a secp256k1 curve point.
///
/// This is the elliptic curve point corresponding to the `Ticket` challenge.
#[derive(Clone, Copy)]
pub struct Challenge(NonIdentity<AffinePoint>);

impl Debug for Challenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_sec1_point(true))
    }
}

impl PartialEq for Challenge {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for Challenge {}

impl Challenge {
    /// Converts the PoR challenge to an Ethereum challenge.
    ///
    /// This is a one-way (lossy) operation, since the corresponding curve point is hashed
    /// with the hash value then truncated.
    pub fn to_ethereum_challenge(&self) -> EthereumChallenge {
        EthereumChallenge(affine_point_to_address(&self.0))
    }
}

impl Challenge {
    /// Gets the PoR challenge by adding the two EC points represented by the half-key challenges.
    ///
    /// Note that this is an expensive operation that involves point decompression of the
    /// both [`HalfKeyChallenges`](HalfKeyChallenge).
    pub fn from_hint_and_share(
        own_share: &HalfKeyChallenge,
        hint: &HalfKeyChallenge,
    ) -> Result<Self> {
        #[cfg(not(feature = "rust-ecdsa"))]
        {
            let own_share = secp256k1::PublicKey::from_byte_array_compressed(own_share.0)
                .map_err(|_| ParseError("invalid half-key challenge for own share".into()))?;

            let hint = secp256k1::PublicKey::from_byte_array_compressed(hint.0)
                .map_err(|_| ParseError("invalid half-key challenge for hint".into()))?;

            let res = own_share.combine(&hint).map_err(|_| CalculationError)?;

            affine_point_from_bytes(&res.serialize_uncompressed())
                .and_then(|p| {
                    NonIdentity::new(p)
                        .into_option()
                        .ok_or(CryptoError::InvalidPublicKey)
                })
                .map(Self)
        }

        #[cfg(feature = "rust-ecdsa")]
        {
            let own_share: k256::ProjectivePoint =
                affine_point_from_bytes(own_share.as_ref())?.into();

            let hint: k256::ProjectivePoint = affine_point_from_bytes(hint.as_ref())?.into();

            NonIdentity::new((own_share + hint).to_affine())
                .into_option()
                .ok_or(CalculationError)
                .map(Self)
        }
    }

    /// Gets the PoR challenge by converting the given HalfKey into a secp256k1 point and
    /// adding it with the given HalfKeyChallenge (which already represents a secp256k1 point).
    ///
    /// Note that this is an expensive operation that involves point decompression of the
    /// both [`HalfKeyChallenge`] and scalar multiplication of the [`HalfKey`] with the basepoint.
    pub fn from_own_share_and_half_key(
        own_share: &HalfKeyChallenge,
        half_key: &HalfKey,
    ) -> Result<Self> {
        Self::from_hint_and_share(own_share, &half_key.to_challenge()?)
    }
}

/// Represents a half-key used for the Proof-of-Relay.
///
/// Half-key is equivalent to a non-zero scalar in the field used by secp256k1, but the type
/// itself does not validate nor enforce this fact.
///
/// The type is internally represented as a byte-array of the secp256k1 field element.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HalfKey(#[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; Self::SIZE]);

impl Default for HalfKey {
    fn default() -> Self {
        let mut ret = Self([0u8; Self::SIZE]);

        ret.0.copy_from_slice(
            NonZeroScalar::<Secp256k1>::from_uint(1u16.into())
                .unwrap()
                .to_bytes()
                .as_slice(),
        );
        ret
    }
}

impl HalfKey {
    /// Converts the non-zero scalar represented by this half-key into the half-key challenge.
    ///
    /// Note that this is an expensive operation that involves scalar multiplication.
    ///
    /// Returns an error if the instance is a zero scalar.
    pub fn to_challenge(&self) -> Result<HalfKeyChallenge> {
        // This may return an error if the instance was deserialized (e.g., via serde) from a zero scalar
        let pk = PublicKey::from_privkey(&self.0)?;
        let compressed: &[u8] = pk.as_ref();
        Ok(compressed.try_into()?)
    }
}

impl Randomizable for HalfKey {
    fn random() -> Self {
        Self(random_group_element().0)
    }
}

impl AsRef<[u8]> for HalfKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for HalfKey {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(
            value.try_into().map_err(|_| ParseError("HalfKey".into()))?,
        ))
    }
}

impl BytesRepresentable for HalfKey {
    /// Size of the secp256k1 secret scalar representing the `HalfKey`.
    const SIZE: usize = 32;
}

/// Represents a challenge for the half-key in Proof of Relay.
///
/// Half-key challenge is equivalent to a secp256k1 curve point.
/// Therefore, `HalfKeyChallenge` can be [obtained](HalfKey::to_challenge) from a [`HalfKey`].
///
/// The value is internally stored as a compressed point encoded as a byte-array.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HalfKeyChallenge(
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; Self::SIZE],
);

impl Display for HalfKeyChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Default for HalfKeyChallenge {
    fn default() -> Self {
        // Note that the default HalfKeyChallenge is the identity point on secp256k1, therefore,
        // will fail all public key checks, which is intended.
        let mut ret = Self([0u8; Self::SIZE]);
        ret.0[Self::SIZE - 1] = 1;
        ret
    }
}

impl HalfKeyChallenge {
    /// Creates a new [`HalfKeyChallenge`] from the given byte slice.
    ///
    /// # Panics
    /// Panics if `half_key_challenge` length is not equal to [`HalfKeyChallenge::SIZE`].
    pub fn new(half_key_challenge: &[u8]) -> Self {
        let mut ret = Self::default();
        ret.0.copy_from_slice(half_key_challenge);
        ret
    }
}

impl AsRef<[u8]> for HalfKeyChallenge {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for HalfKeyChallenge {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(
            value
                .try_into()
                .map_err(|_| ParseError("HalfKeyChallenge".into()))?,
        ))
    }
}

impl BytesRepresentable for HalfKeyChallenge {
    /// Size of the compressed secp256k1 point representing the Half Key Challenge.
    const SIZE: usize = PublicKey::SIZE_COMPRESSED;
}

impl FromStr for HalfKeyChallenge {
    type Err = GeneralError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

const HASH_BASE_SIZE: usize = 32;

/// Represents a generic 256-bit hash value.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashBase<H>(
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; HASH_BASE_SIZE],
    #[cfg_attr(feature = "serde", serde(skip))] PhantomData<H>,
);

impl<H> Clone for HashBase<H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H> Copy for HashBase<H> {}

impl<H> PartialEq for HashBase<H> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<H> Eq for HashBase<H> {}

impl<H> Default for HashBase<H> {
    fn default() -> Self {
        Self([0u8; HASH_BASE_SIZE], PhantomData)
    }
}

impl<H> PartialOrd<Self> for HashBase<H> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<H> Ord for HashBase<H> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<H> std::hash::Hash for HashBase<H> {
    fn hash<H2: Hasher>(&self, state: &mut H2) {
        self.0.hash(state);
    }
}

impl<H> Debug for HashBase<H> {
    // Intentionally same as Display
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl<H> Display for HashBase<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl<H> FromStr for HashBase<H> {
    type Err = GeneralError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl<H> HashBase<H>
where
    H: OutputSizeUser<OutputSize = typenum::U32> + Digest,
{
    /// Convenience method that creates a new hash by hashing this.
    pub fn hash(&self) -> Self {
        Self::create(&[&self.0])
    }

    /// Takes all the byte slices and computes hash of their concatenated value.
    pub fn create(inputs: &[&[u8]]) -> Self {
        let mut hash = H::new();
        inputs.iter().for_each(|v| hash.update(v));
        Self(hash.finalize().into(), PhantomData)
    }
}

impl<H> AsRef<[u8]> for HashBase<H> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<H> TryFrom<&[u8]> for HashBase<H> {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(
            value.try_into().map_err(|_| ParseError("Hash".into()))?,
            PhantomData,
        ))
    }
}

impl<H> BytesRepresentable for HashBase<H> {
    /// The size of the digest is 32 bytes.
    const SIZE: usize = HASH_BASE_SIZE;
}

impl<H> From<[u8; HASH_BASE_SIZE]> for HashBase<H> {
    fn from(hash: [u8; HASH_BASE_SIZE]) -> Self {
        Self(hash, PhantomData)
    }
}

impl<H> From<HashBase<H>> for [u8; HASH_BASE_SIZE] {
    fn from(value: HashBase<H>) -> Self {
        value.0
    }
}

impl<H> From<&HashBase<H>> for [u8; HASH_BASE_SIZE] {
    fn from(value: &HashBase<H>) -> Self {
        value.0
    }
}

impl<H> From<HashBase<H>> for primitive_types::H256 {
    fn from(value: HashBase<H>) -> Self {
        value.0.into()
    }
}

impl<H> From<primitive_types::H256> for HashBase<H> {
    fn from(value: primitive_types::H256) -> Self {
        Self(value.0, PhantomData)
    }
}

/// Represents an Ethereum 256-bit hash value.
///
/// This implementation instantiates the hash via Keccak256 digest.
pub type Hash = HashBase<sha3::Keccak256>;

/// Represents an alternative 256-bit hash value computed via a faster hashing algorithm.
///
/// This implementation instantiates the hash via Blake3 digest, which is usually 8-9x faster
/// than Keccak256.
pub type HashFast = HashBase<blake3::Hasher>;

/// Represents an Ed25519 public key.
#[derive(Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OffchainPublicKey {
    compressed: CompressedEdwardsY,
    pub(crate) edwards: EdwardsPoint,
}

impl std::fmt::Debug for OffchainPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Intentionally same as display
        write!(f, "{}", self.to_hex())
    }
}

impl std::hash::Hash for OffchainPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.compressed.hash(state);
    }
}

impl PartialEq for OffchainPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.compressed == other.compressed
    }
}

impl AsRef<[u8]> for OffchainPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.compressed.0
    }
}

impl TryFrom<&[u8]> for OffchainPublicKey {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let compressed = CompressedEdwardsY::from_slice(value)
            .map_err(|_| ParseError("OffchainPublicKey".into()))?;
        let edwards = compressed
            .decompress()
            .ok_or(ParseError("OffchainPublicKey.decompress".into()))?;
        Ok(Self {
            compressed,
            edwards,
        })
    }
}

impl BytesRepresentable for OffchainPublicKey {
    /// Size of the public key (compressed Edwards Y coordinate)
    const SIZE: usize = 32;
}

impl TryFrom<[u8; OffchainPublicKey::SIZE]> for OffchainPublicKey {
    type Error = GeneralError;

    fn try_from(value: [u8; OffchainPublicKey::SIZE]) -> std::result::Result<Self, Self::Error> {
        let v: &[u8] = &value;
        v.try_into()
    }
}

impl From<OffchainPublicKey> for [u8; OffchainPublicKey::SIZE] {
    fn from(value: OffchainPublicKey) -> Self {
        value.compressed.0
    }
}

impl From<OffchainPublicKey> for PeerId {
    fn from(value: OffchainPublicKey) -> Self {
        let k = libp2p_identity::ed25519::PublicKey::try_from_bytes(value.compressed.as_bytes())
            .expect("offchain public key is always a valid ed25519 public key");
        PeerId::from_public_key(&k.into())
    }
}

impl From<&OffchainPublicKey> for PeerId {
    fn from(value: &OffchainPublicKey) -> Self {
        (*value).into()
    }
}

impl Display for OffchainPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for OffchainPublicKey {
    type Err = GeneralError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl OffchainPublicKey {
    /// Tries to create the public key from a Ed25519 private key.
    /// The length must be exactly `ed25519_dalek::SECRET_KEY_LENGTH`.
    pub fn from_privkey(private_key: &[u8]) -> Result<Self> {
        let mut pk: [u8; ed25519_dalek::SECRET_KEY_LENGTH] = private_key
            .try_into()
            .map_err(|_| InvalidInputValue("private_key"))?;
        let sk = libp2p_identity::ed25519::SecretKey::try_from_bytes(&mut pk)
            .map_err(|_| InvalidInputValue("private_key"))?;
        let kp: libp2p_identity::ed25519::Keypair = sk.into();
        Ok(Self::try_from(kp.public().to_bytes())?)
    }

    /// Outputs the public key as PeerId represented as Base58 string.
    pub fn to_peerid_str(&self) -> String {
        PeerId::from(self).to_base58()
    }

    /// Tries to convert an Ed25519 `PeerId` to `OffchainPublicKey`.
    ///
    /// This is a CPU-intensive operation, as it performs Ed25519 point decompression
    /// and mapping to the Curve255919 point representation.
    pub fn from_peerid(peerid: &PeerId) -> std::result::Result<Self, GeneralError> {
        let mh = peerid.as_ref();
        if mh.code() == 0 {
            libp2p_identity::PublicKey::try_decode_protobuf(mh.digest())
                .map_err(|_| ParseError("invalid ed25519 peer id".into()))
                .and_then(|pk| {
                    pk.try_into_ed25519()
                        .map(|p| p.to_bytes())
                        .map_err(|_| ParseError("invalid ed25519 peer id".into()))
                })
                .and_then(Self::try_from)
        } else {
            Err(ParseError("invalid ed25519 peer id".into()))
        }
    }
}

impl From<&OffchainPublicKey> for EdwardsPoint {
    fn from(value: &OffchainPublicKey) -> Self {
        value.edwards
    }
}

impl<'a> From<&'a OffchainPublicKey> for &'a Array<u8, typenum::U32> {
    fn from(value: &'a OffchainPublicKey) -> &'a Array<u8, typenum::U32> {
        Array::cast_from_core(&value.compressed.0)
    }
}

impl From<&OffchainPublicKey> for MontgomeryPoint {
    fn from(value: &OffchainPublicKey) -> Self {
        // The Curve25519 computations are mostly not used, so we can do the conversion
        // here without caching.
        value.edwards.to_montgomery()
    }
}

/// Implements a public key for the Baby Jubjub curve.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BjjPublicKey(
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; Self::SIZE],
);

impl BjjPublicKey {
    pub fn from_privkey(secret: &[u8]) -> Result<Self> {
        let scalar = babyjubjub_ec::Scalar::from_bytes(
            &(secret
                .try_into()
                .map_err(|_| CryptoError::InvalidSecretScalar)?),
        )
        .into_option()
        .ok_or(CryptoError::InvalidSecretScalar)?;

        let point = babyjubjub_ec::ProjectivePoint::GENERATOR * scalar;
        point.try_into()
    }
}

impl Display for BjjPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for BjjPublicKey {
    type Err = GeneralError;
    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl AsRef<[u8]> for BjjPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for BjjPublicKey {
    type Error = GeneralError;
    fn try_from(value: &'a [u8]) -> result::Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            return Err(ParseError("BjjPublicKey".into()));
        }

        let repr_bytes: [u8; 32] = value
            .try_into()
            .map_err(|_| ParseError("BjjPublicKey".into()))?;

        use babyjubjub_ec::group::GroupEncoding;
        if babyjubjub_ec::ProjectivePoint::from_bytes(&babyjubjub_ec::GroupRepr(repr_bytes))
            .into_option()
            .is_none_or(|p| p.is_identity() || !p.is_in_prime_order_subgroup())
        {
            return Err(ParseError("BjjPublicKey".into()));
        }

        Ok(Self(repr_bytes))
    }
}

impl BytesRepresentable for BjjPublicKey {
    const SIZE: usize = 32;
}

impl TryFrom<&babyjubjub_ec::ProjectivePoint> for BjjPublicKey {
    type Error = CryptoError;

    fn try_from(value: &babyjubjub_ec::ProjectivePoint) -> result::Result<Self, Self::Error> {
        if value.is_identity() || !value.is_in_prime_order_subgroup() {
            return Err(CryptoError::InvalidPublicKey);
        }

        use babyjubjub_ec::group::GroupEncoding;
        Ok(Self(value.to_bytes().0))
    }
}

impl TryFrom<babyjubjub_ec::ProjectivePoint> for BjjPublicKey {
    type Error = CryptoError;

    fn try_from(value: babyjubjub_ec::ProjectivePoint) -> result::Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<&BjjPublicKey> for babyjubjub_ec::ProjectivePoint {
    fn from(value: &BjjPublicKey) -> babyjubjub_ec::ProjectivePoint {
        use babyjubjub_ec::group::GroupEncoding;
        babyjubjub_ec::ProjectivePoint::from_bytes(&babyjubjub_ec::GroupRepr(value.0))
            .expect("BjjPublicKey is always valid")
    }
}

impl From<BjjPublicKey> for babyjubjub_ec::ProjectivePoint {
    fn from(value: BjjPublicKey) -> babyjubjub_ec::ProjectivePoint {
        (&value).into()
    }
}

impl TryFrom<&babyjubjub_ec::AffinePoint> for BjjPublicKey {
    type Error = CryptoError;

    fn try_from(value: &babyjubjub_ec::AffinePoint) -> result::Result<Self, Self::Error> {
        (&babyjubjub_ec::ProjectivePoint::from(value)).try_into()
    }
}

impl TryFrom<babyjubjub_ec::AffinePoint> for BjjPublicKey {
    type Error = CryptoError;
    fn try_from(value: babyjubjub_ec::AffinePoint) -> result::Result<Self, Self::Error> {
        (&value).try_into()
    }
}

/// Implements a public key for the BN254 curve (also known as alt-BN128).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Bn254PublicKey(
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; Self::SIZE],
);

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Bn254PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::try_from(buf.as_ref()).map_err(serde::de::Error::custom)
    }
}

impl Bn254PublicKey {
    /// Derives a [`Bn254PublicKey`] from a little-endian 32-byte secret scalar.
    ///
    /// Returns [`CryptoError::InvalidSecretScalar`] if:
    /// - the input is not exactly 32 bytes,
    /// - the scalar is zero, or
    /// - the scalar is greater than or equal to the BN254 Fr field modulus.
    pub fn from_privkey(secret: &[u8]) -> Result<Self> {
        use ark_ec::{AffineRepr, PrimeGroup};
        use ark_ff::{BigInt, PrimeField};
        use ark_serialize::CanonicalSerialize;

        let bytes: [u8; 32] = secret
            .try_into()
            .map_err(|_| CryptoError::InvalidSecretScalar)?;

        // Reject non-canonical scalars >= Fr::MODULUS.
        // Using from_le_bytes_mod_order alone is not sufficient: s and s + r
        // produce the same public key, but Bn254Keypair::secret() retains
        // the unreduced bytes, creating key-consistency problems.
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            limbs[i] = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
        }
        if BigInt::<4>::new(limbs) >= ark_bn254::Fr::MODULUS {
            return Err(CryptoError::InvalidSecretScalar);
        }

        let scalar = ark_bn254::Fr::from_le_bytes_mod_order(&bytes);
        let point = ark_bn254::G1Projective::generator() * scalar;
        let affine = ark_bn254::G1Affine::from(point);

        if affine.is_zero() {
            return Err(CryptoError::InvalidSecretScalar);
        }

        let mut buf = [0u8; Self::SIZE];
        affine
            .serialize_compressed(&mut buf[..])
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(Self(buf))
    }
}

impl Display for Bn254PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for Bn254PublicKey {
    type Err = GeneralError;
    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl AsRef<[u8]> for Bn254PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for Bn254PublicKey {
    type Error = GeneralError;
    fn try_from(value: &'a [u8]) -> result::Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            return Err(ParseError("Bn254PublicKey".into()));
        }

        let repr_bytes: [u8; 32] = value
            .try_into()
            .map_err(|_| ParseError("Bn254PublicKey".into()))?;

        use ark_ec::AffineRepr;
        use ark_serialize::CanonicalDeserialize;

        let affine = ark_bn254::G1Affine::deserialize_compressed(&repr_bytes[..])
            .map_err(|_| ParseError("Bn254PublicKey".into()))?;

        if affine.is_zero() {
            return Err(ParseError("Bn254PublicKey".into()));
        }
        // BN254 has cofactor=1 for G1, so any valid curve point is in the prime-order subgroup.

        Ok(Self(repr_bytes))
    }
}

impl BytesRepresentable for Bn254PublicKey {
    const SIZE: usize = 32;
}

impl TryFrom<&ark_bn254::G1Projective> for Bn254PublicKey {
    type Error = CryptoError;

    fn try_from(value: &ark_bn254::G1Projective) -> result::Result<Self, Self::Error> {
        use ark_ec::AffineRepr;
        use ark_serialize::CanonicalSerialize;

        let affine = ark_bn254::G1Affine::from(*value);
        if affine.is_zero() {
            return Err(CryptoError::InvalidPublicKey);
        }

        let mut buf = [0u8; Self::SIZE];
        affine
            .serialize_compressed(&mut buf[..])
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(Self(buf))
    }
}

impl TryFrom<ark_bn254::G1Projective> for Bn254PublicKey {
    type Error = CryptoError;

    fn try_from(value: ark_bn254::G1Projective) -> result::Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Bn254PublicKey> for ark_bn254::G1Projective {
    type Error = CryptoError;

    fn try_from(value: &Bn254PublicKey) -> result::Result<ark_bn254::G1Projective, Self::Error> {
        use ark_serialize::CanonicalDeserialize;

        let affine = ark_bn254::G1Affine::deserialize_compressed(&value.0[..])
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(affine.into())
    }
}

impl TryFrom<Bn254PublicKey> for ark_bn254::G1Projective {
    type Error = CryptoError;

    fn try_from(value: Bn254PublicKey) -> result::Result<ark_bn254::G1Projective, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&ark_bn254::G1Affine> for Bn254PublicKey {
    type Error = CryptoError;

    fn try_from(value: &ark_bn254::G1Affine) -> result::Result<Self, Self::Error> {
        (ark_bn254::G1Projective::from(*value)).try_into()
    }
}

impl TryFrom<ark_bn254::G1Affine> for Bn254PublicKey {
    type Error = CryptoError;
    fn try_from(value: ark_bn254::G1Affine) -> result::Result<Self, Self::Error> {
        (&value).try_into()
    }
}

/// Length of a packet tag
pub const PACKET_TAG_LENGTH: usize = 16;

/// Represents a fixed size packet verification tag
pub type PacketTag = [u8; PACKET_TAG_LENGTH];

/// Represents a secp256k1 public key.
///
/// The key is internally represented using an `AffinePoint` and the compressed encoding of it.
///
/// The `AsRef` implementation will always return the compressed representation.
/// However, the `TryFrom` byte slice accepts any representation.
#[derive(Copy, Clone)]
pub struct PublicKey(
    NonIdentity<AffinePoint>,
    [u8; Self::SIZE_COMPRESSED],
    Address,
);

impl PublicKey {
    /// Size of the compressed public key in bytes
    pub const SIZE_COMPRESSED: usize = 33;
    /// Size of the uncompressed public key in bytes
    pub const SIZE_UNCOMPRESSED: usize = 65;
    /// Size of the uncompressed public key without the `0x04` SEC1 prefix byte (64 bytes).
    pub const SIZE_UNCOMPRESSED_PLAIN: usize = 64;

    /// Computes the public key from the given `private_key`.
    ///
    /// The private key must be a big-endian encoding of a non-zero scalar in the field
    /// of the `secp256k1` curve.
    pub fn from_privkey(private_key: &[u8]) -> Result<PublicKey> {
        #[cfg(feature = "rust-ecdsa")]
        {
            // This verifies that it is indeed a non-zero scalar, and thus represents a valid public key
            let secret_scalar = NonZeroScalar::<Secp256k1>::try_from(private_key)
                .map_err(|_| GeneralError::ParseError("PublicKey".into()))?;

            Ok(
                elliptic_curve::PublicKey::<Secp256k1>::from_secret_scalar(&secret_scalar)
                    .to_nonidentity()
                    .into(),
            )
        }

        #[cfg(not(feature = "rust-ecdsa"))]
        {
            let sk = secp256k1::SecretKey::from_byte_array(
                private_key
                    .try_into()
                    .map_err(|_| GeneralError::ParseError("private_key.len".into()))?,
            )
            .map_err(|_| GeneralError::ParseError("private_key".into()))?;

            let pk = secp256k1::PublicKey::from_secret_key_global(&sk);
            affine_point_from_bytes(&pk.serialize_uncompressed())
                .and_then(|p| {
                    NonIdentity::new(p)
                        .into_option()
                        .ok_or(CryptoError::InvalidPublicKey)
                })
                .map(Self::from)
        }
    }

    /// Converts the public key to an Ethereum address
    pub fn to_address(&self) -> Address {
        self.2
    }

    /// Serializes the public key to a binary uncompressed form.
    pub fn to_uncompressed_bytes(&self) -> Box<[u8]> {
        self.0.to_sec1_point(false).to_bytes()
    }

    /// Serializes the public key to a binary uncompressed form and converts it to hexadecimal string representation.
    pub fn to_uncompressed_hex(&self) -> String {
        format!("0x{}", const_hex::encode(self.to_uncompressed_bytes()))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.1.eq(&other.1)
    }
}

impl Eq for PublicKey {}

impl hash::Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.1.hash(state);
    }
}

impl Randomizable for PublicKey {
    /// Generates a new random public key.
    /// Because the corresponding private key is discarded, this might be useful only for testing purposes.
    fn random() -> Self {
        let (_, cp) = random_group_element();
        cp.into()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        match value.len() {
            Self::SIZE_UNCOMPRESSED => {
                // already has 0x04 prefix
                let key = elliptic_curve::PublicKey::<Secp256k1>::from_sec1_bytes(value)
                    .map_err(|_| GeneralError::ParseError("invalid secp256k1 point".into()))?;

                Ok(key.to_nonidentity().into())
            }
            Self::SIZE_UNCOMPRESSED_PLAIN => {
                // Add the SEC1 uncompressed prefix in a stack buffer; `from_sec1_bytes`
                // requires the prefixed form, and concat would allocate for every parse.
                let mut buf = [0u8; Self::SIZE_UNCOMPRESSED];
                buf[0] = 4;
                buf[1..].copy_from_slice(value);

                let key = elliptic_curve::PublicKey::<Secp256k1>::from_sec1_bytes(&buf)
                    .map_err(|_| GeneralError::ParseError("invalid secp256k1 point".into()))?;

                Ok(key.to_nonidentity().into())
            }
            Self::SIZE_COMPRESSED => {
                // has either 0x02 or 0x03 prefix
                let key = elliptic_curve::PublicKey::<Secp256k1>::from_sec1_bytes(value)
                    .map_err(|_| GeneralError::ParseError("invalid secp256k1 point".into()))?;

                Ok(key.to_nonidentity().into())
            }
            _ => Err(GeneralError::ParseError("invalid secp256k1 point".into())),
        }
    }
}

impl AsRef<Address> for PublicKey {
    fn as_ref(&self) -> &Address {
        &self.2
    }
}

impl AsRef<NonIdentity<AffinePoint>> for PublicKey {
    fn as_ref(&self) -> &NonIdentity<AffinePoint> {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.1
    }
}

impl BytesRepresentable for PublicKey {
    const SIZE: usize = PublicKey::SIZE_COMPRESSED;
}

impl From<NonIdentity<AffinePoint>> for PublicKey {
    fn from(value: NonIdentity<AffinePoint>) -> Self {
        let mut compressed = [0u8; PublicKey::SIZE_COMPRESSED];
        compressed.copy_from_slice(value.to_sec1_point(true).as_bytes());
        Self(value, compressed, affine_point_to_address(&value))
    }
}

impl From<PublicKey> for NonIdentity<AffinePoint> {
    fn from(value: PublicKey) -> Self {
        value.0
    }
}

impl TryFrom<AffinePoint> for PublicKey {
    type Error = CryptoError;

    fn try_from(value: AffinePoint) -> std::result::Result<Self, Self::Error> {
        Ok(NonIdentity::new(value)
            .into_option()
            .ok_or(CryptoError::InvalidPublicKey)?
            .into())
    }
}

// TODO: make this `for &k256::ProjectivePoint`
impl From<&PublicKey> for k256::ProjectivePoint {
    fn from(value: &PublicKey) -> Self {
        (*value.0.as_ref()).into()
    }
}

impl<'a> From<&'a PublicKey> for &'a Array<u8, typenum::U33> {
    fn from(value: &'a PublicKey) -> &'a Array<u8, typenum::U33> {
        Array::cast_from_core(&value.1)
    }
}

/// Contains a response upon ticket acknowledgement
/// It is equivalent to a non-zero secret scalar on secp256k1 (EC private key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Response(#[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; Self::SIZE]);

impl Default for Response {
    fn default() -> Self {
        Self(HalfKey::default().0)
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Response {
    /// Converts this response to the PoR challenge by turning the non-zero scalar
    /// represented by this response into a secp256k1 curve point (public key).
    ///
    /// Note that this is an expensive operation involving scalar multiplication.
    ///
    /// Error is returned when this `Response` contains an invalid value.
    pub fn to_challenge(&self) -> Result<Challenge> {
        // This may return an error if the instance was deserialized (e.g., via serde) from a zero scalar
        PublicKey::from_privkey(&self.0).map(|pk| Challenge(pk.into()))
    }

    /// Derives the response from two half-keys.
    ///
    /// This is done by adding together the two non-zero scalars that the given half-keys represent.
    /// Returns an error if any of the given scalars is zero.
    pub fn from_half_keys(first: &HalfKey, second: &HalfKey) -> Result<Self> {
        let first = NonZeroScalar::<Secp256k1>::try_from(first.as_ref())
            .map_err(|_| InvalidInputValue("first"))?;
        let second = NonZeroScalar::<Secp256k1>::try_from(second.as_ref())
            .map_err(|_| InvalidInputValue("second"))?;

        // This addition is modulo order the order of the secp256k1 prime field
        let res = first.as_ref() + second.as_ref();
        if res.is_zero().into() {
            return Err(InvalidInputValue("invalid half-key"));
        }

        let mut ret = [0u8; Self::SIZE];
        ret.copy_from_slice(res.to_bytes().as_slice());
        Ok(Self(ret))
    }
}

impl AsRef<[u8]> for Response {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Response {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(
            value
                .try_into()
                .map_err(|_| ParseError("Response".into()))?,
        ))
    }
}

impl BytesRepresentable for Response {
    /// Size of the PoR challenge response.
    const SIZE: usize = 32;
}

impl From<[u8; Self::SIZE]> for Response {
    fn from(value: [u8; Self::SIZE]) -> Self {
        Self(value)
    }
}

/// Pseudonym used to identify the creator of a `SURB`.
/// This allows indexing `SURB` and `LocalSURBEntry` at both parties.
///
/// To maintain anonymity, this must be something else than the sender's
/// public key or public key identifier.
pub trait Pseudonym: BytesRepresentable + hash::Hash + Eq + Display + Randomizable {}

/// Represents a simple UUID-like pseudonym consisting of 10 bytes.
///
/// Caches the hexadecimal string representation internally for efficiency.
#[derive(Copy, Clone, Eq)]
pub struct SimplePseudonym([u8; Self::SIZE], arrayvec::ArrayString<{ Self::SIZE * 2 }>);

#[cfg(feature = "serde")]
impl serde::Serialize for SimplePseudonym {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SimplePseudonym {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Use a visitor that accepts both byte strings and byte arrays
        struct SimplePseudonymVisitor;

        impl<'de> serde::de::Visitor<'de> for SimplePseudonymVisitor {
            type Value = SimplePseudonym;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte string or an array of bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let arr: [u8; SimplePseudonym::SIZE] = v
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("invalid SimplePseudonym length"))?;
                Ok(arr.into())
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // Collect directly into a fixed-size buffer to prevent memory exhaustion
                let mut buffer = [0u8; SimplePseudonym::SIZE];
                let mut index = 0;

                while let Some(byte) = seq.next_element::<u8>()? {
                    if index >= SimplePseudonym::SIZE {
                        return Err(serde::de::Error::custom(
                            "SimplePseudonym sequence too long",
                        ));
                    }
                    buffer[index] = byte;
                    index += 1;
                }

                // Also fail if we got too few elements
                if index < SimplePseudonym::SIZE {
                    return Err(serde::de::Error::custom(
                        "SimplePseudonym sequence too short",
                    ));
                }

                Ok(buffer.into())
            }
        }

        deserializer.deserialize_bytes(SimplePseudonymVisitor)
    }
}

impl Display for SimplePseudonym {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.1.as_str())
    }
}

impl Debug for SimplePseudonym {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.1.as_str())
    }
}

impl PartialEq for SimplePseudonym {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl std::hash::Hash for SimplePseudonym {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialOrd for SimplePseudonym {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SimplePseudonym {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl BytesRepresentable for SimplePseudonym {
    const SIZE: usize = 10;
}

impl AsRef<[u8]> for SimplePseudonym {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<str> for SimplePseudonym {
    fn as_ref(&self) -> &str {
        self.1.as_str()
    }
}

impl From<[u8; Self::SIZE]> for SimplePseudonym {
    fn from(value: [u8; Self::SIZE]) -> Self {
        let mut hex = arrayvec::ArrayString::<{ Self::SIZE * 2 }>::zero_filled();
        // Unsafe: the hex string is guaranteed to be valid UTF-8
        unsafe { const_hex::encode_to_slice(value, hex.as_bytes_mut()) }
            .expect("hex string fits in ArrayString");
        Self(value, hex)
    }
}

impl<'a> TryFrom<&'a [u8]> for SimplePseudonym {
    type Error = GeneralError;

    fn try_from(value: &'a [u8]) -> result::Result<Self, Self::Error> {
        let arr: [u8; Self::SIZE] = value
            .try_into()
            .map_err(|_| ParseError("SimplePseudonym".into()))?;

        Ok(arr.into())
    }
}

impl Randomizable for SimplePseudonym {
    /// Generates a random pseudonym.
    fn random() -> Self {
        let mut data = [0u8; Self::SIZE];
        crate::crypto_random::random_fill(&mut data);
        data.into()
    }
}

impl Pseudonym for SimplePseudonym {}

#[cfg(test)]
mod tests {
    use crate::crypto_random::Randomizable;
    use crate::primitive::prelude::*;
    use hex_literal::hex;
    use k256::AffinePoint;
    use libp2p_identity::PeerId;
    use std::str::FromStr;

    use crate::crypto::prelude::{BjjKeypair, Bn254Keypair, Bn254PublicKey};
    use crate::crypto::types::BjjPublicKey;
    use crate::crypto::{
        keypairs::{Keypair, OffchainKeypair},
        types::{
            Challenge, HalfKey, HalfKeyChallenge, Hash, OffchainPublicKey, PublicKey, Response,
            SimplePseudonym,
        },
    };

    const PUBLIC_KEY: [u8; 33] =
        hex!("021464586aeaea0eb5736884ca1bf42d165fc8e2243b1d917130fb9e321d7a93b8");
    const PUBLIC_KEY_UNCOMPRESSED_PLAIN: [u8; 64] = hex!(
        "1464586aeaea0eb5736884ca1bf42d165fc8e2243b1d917130fb9e321d7a93b8fb0699d4f177f9c84712f6d7c5f6b7f4f6916116047fa25c79ef806fc6c9523e"
    );
    const PUBLIC_KEY_UNCOMPRESSED: [u8; 65] = hex!(
        "041464586aeaea0eb5736884ca1bf42d165fc8e2243b1d917130fb9e321d7a93b8fb0699d4f177f9c84712f6d7c5f6b7f4f6916116047fa25c79ef806fc6c9523e"
    );
    const PRIVATE_KEY: [u8; 32] =
        hex!("e17fe86ce6e99f4806715b0c9412f8dad89334bf07f72d5834207a9d8f19d7f8");

    #[test]
    fn test_public_key_to_hex() -> anyhow::Result<()> {
        let pk = PublicKey::from_privkey(&hex!(
            "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775"
        ))?;

        assert_eq!(
            "0x0439d1bc2291826eaed86567d225cf243ebc637275e0a5aedb0d6b1dc82136a38e428804340d4c949a029846f682711d046920b4ca8b8ebeb9d1192b5bdaa54dba",
            pk.to_uncompressed_hex()
        );
        assert_eq!(
            "0x0239d1bc2291826eaed86567d225cf243ebc637275e0a5aedb0d6b1dc82136a38e",
            pk.to_hex()
        );

        Ok(())
    }

    #[test]
    fn test_public_key_serialize() -> anyhow::Result<()> {
        let pk1 = PublicKey::try_from(PUBLIC_KEY.as_ref())?;
        let pk2 = PublicKey::try_from(pk1.as_ref())?;
        let pk3 = PublicKey::try_from(pk1.to_uncompressed_bytes().as_ref())?;

        assert_eq!(pk1, pk2, "pub keys 1 2 don't match");
        assert_eq!(pk2, pk3, "pub keys 2 3 don't match");

        let pk1 = PublicKey::try_from(PUBLIC_KEY.as_ref())?;
        let pk2 = PublicKey::try_from(PUBLIC_KEY_UNCOMPRESSED.as_ref())?;
        let pk3 = PublicKey::try_from(PUBLIC_KEY_UNCOMPRESSED_PLAIN.as_ref())?;

        assert_eq!(pk1, pk2, "pubkeys don't match");
        assert_eq!(pk2, pk3, "pubkeys don't match");

        let compressed: &[u8] = pk1.as_ref();
        assert_eq!(PublicKey::SIZE_COMPRESSED, compressed.len());
        assert_eq!(
            PublicKey::SIZE_UNCOMPRESSED,
            pk1.to_uncompressed_bytes().len()
        );

        let shorter = hex!(
            "f85e38b056284626a7aed0acc5d474605a408e6cccf76d7241ec7b4dedb31929b710e034f4f9a7dba97743b01e1cc35a45a60bebb29642cb0ba6a7fe8433316c"
        );
        let s1 = PublicKey::try_from(shorter.as_ref())?;
        let s2 = PublicKey::try_from(s1.to_uncompressed_bytes().as_ref())?;
        assert_eq!(s1, s2);

        Ok(())
    }

    #[test]
    fn test_public_key_should_not_accept_identity() -> anyhow::Result<()> {
        PublicKey::try_from(AffinePoint::IDENTITY).expect_err("must fail for identity point");
        Ok(())
    }

    #[test]
    fn test_public_key_from_privkey() -> anyhow::Result<()> {
        let pk1 = PublicKey::from_privkey(&PRIVATE_KEY)?;
        let pk2 = PublicKey::try_from(PUBLIC_KEY.as_ref())?;

        assert_eq!(pk1, pk2, "failed to match deserialized pub key");

        Ok(())
    }

    #[test]
    fn test_offchain_public_key() -> anyhow::Result<()> {
        let (s, pk1) = OffchainKeypair::random().unzip();

        let pk2 = OffchainPublicKey::from_privkey(s.as_ref())?;
        assert_eq!(pk1, pk2, "from privkey failed");

        let pk3 = OffchainPublicKey::try_from(pk1.as_ref())?;
        assert_eq!(pk1, pk3, "from bytes failed");

        Ok(())
    }

    #[test]
    fn test_bjj_public_key() -> anyhow::Result<()> {
        let (s, pk1) = BjjKeypair::random().unzip();

        let pk2 = BjjPublicKey::from_privkey(s.as_ref())?;
        assert_eq!(pk1, pk2, "from privkey failed");

        let pk3 = BjjPublicKey::try_from(pk1.as_ref())?;
        assert_eq!(pk1, pk3, "from bytes failed");

        assert_eq!(BjjPublicKey::from_str(&pk1.to_string())?, pk1);

        // Must reject identity point
        assert!(BjjPublicKey::try_from(babyjubjub_ec::ProjectivePoint::IDENTITY).is_err());

        let proj: babyjubjub_ec::ProjectivePoint = pk1.into();
        assert_eq!(BjjPublicKey::try_from(proj)?, pk1);

        Ok(())
    }

    #[test]
    fn test_bn254_public_key() -> anyhow::Result<()> {
        let (s, pk1) = Bn254Keypair::random().unzip();

        let pk2 = Bn254PublicKey::from_privkey(s.as_ref())?;
        assert_eq!(pk1, pk2, "from privkey failed");

        let pk3 = Bn254PublicKey::try_from(pk1.as_ref())?;
        assert_eq!(pk1, pk3, "from bytes failed");

        assert_eq!(Bn254PublicKey::from_str(&pk1.to_string())?, pk1);

        // Must reject identity point
        let identity = ark_bn254::G1Affine::identity();
        assert!(
            Bn254PublicKey::try_from(identity).is_err(),
            "identity point must be rejected"
        );

        let proj: ark_bn254::G1Projective = (&pk1).try_into()?;
        assert_eq!(Bn254PublicKey::try_from(proj)?, pk1);

        // TryFrom<G1Affine>
        let proj2: ark_bn254::G1Projective = (&pk1).try_into()?;
        let affine: ark_bn254::G1Affine = proj2.into();
        let pk_from_affine = Bn254PublicKey::try_from(affine)?;
        assert_eq!(pk1, pk_from_affine, "from G1Affine failed");

        Ok(())
    }

    #[test]
    fn test_bn254_public_key_rejects_invalid() -> anyhow::Result<()> {
        use ark_ff::PrimeField;

        // Deserialization of invalid 32 bytes (identity point)
        assert!(
            Bn254PublicKey::try_from(&[0u8; 32][..]).is_err(),
            "all-zero 32 bytes must be rejected (identity)"
        );

        // Wrong-length slices
        assert!(
            Bn254PublicKey::try_from(&[0u8; 31][..]).is_err(),
            "31 bytes must be rejected"
        );
        assert!(
            Bn254PublicKey::try_from(&[0u8; 33][..]).is_err(),
            "33 bytes must be rejected"
        );

        // from_privkey: zero secret
        assert!(
            Bn254PublicKey::from_privkey(&[0u8; 32]).is_err(),
            "zero secret must be rejected"
        );

        // from_privkey: secret equal to Fr::MODULUS
        let modulus_bytes_le: Vec<u8> = ark_bn254::Fr::MODULUS
            .0
            .iter()
            .flat_map(|limb| limb.to_le_bytes())
            .collect();
        let modulus_arr: [u8; 32] = modulus_bytes_le.try_into().unwrap();
        assert!(
            Bn254PublicKey::from_privkey(&modulus_arr).is_err(),
            "secret equal to Fr::MODULUS must be rejected"
        );

        // Also reject modulus + 1
        let mut over_modulus = modulus_arr;
        for byte in &mut over_modulus {
            let (sum, overflow) = byte.overflowing_add(1);
            *byte = sum;
            if !overflow {
                break;
            }
        }
        assert!(
            Bn254PublicKey::from_privkey(&over_modulus).is_err(),
            "secret > Fr::MODULUS must be rejected"
        );

        // from_privkey: wrong length
        assert!(
            Bn254PublicKey::from_privkey(&[0u8; 31]).is_err(),
            "31-byte secret must be rejected"
        );
        assert!(
            Bn254PublicKey::from_privkey(&[0u8; 33]).is_err(),
            "33-byte secret must be rejected"
        );

        // Round-trip: TryFrom<&Bn254PublicKey> for G1Projective
        let (_, pk) = Bn254Keypair::random().unzip();
        let proj: ark_bn254::G1Projective = (&pk).try_into()?;
        let _ = Bn254PublicKey::try_from(&proj)?;

        Ok(())
    }

    #[test]
    fn test_offchain_public_key_peerid() -> anyhow::Result<()> {
        let valid_peerid =
            PeerId::from_str("12D3KooWLYKsvDB4xEELYoHXxeStj2gzaDXjra2uGaFLpKCZkJHs")?;
        let valid = OffchainPublicKey::from_peerid(&valid_peerid)?;
        assert_eq!(
            valid_peerid,
            valid.into(),
            "must work with ed25519 peer ids"
        );

        let invalid_peerid =
            PeerId::from_str("16Uiu2HAmPHGyJ7y1Rj3kJ64HxJQgM9rASaeT2bWfXF9EiX3Pbp3K")?;
        let invalid = OffchainPublicKey::from_peerid(&invalid_peerid);
        assert!(invalid.is_err(), "must not work with secp256k1 peer ids");

        let invalid_peerid_2 = PeerId::from_str("QmWvEwidPYBbLHfcZN6ATHdm4NPM4KbUx72LZnZRoRNKEN")?;
        let invalid_2 = OffchainPublicKey::from_peerid(&invalid_peerid_2);
        assert!(invalid_2.is_err(), "must not work with rsa peer ids");

        Ok(())
    }

    #[test]
    pub fn test_response() -> anyhow::Result<()> {
        let r1 = Response([0u8; Response::SIZE]);
        let r2 = Response::try_from(r1.as_ref())?;
        assert_eq!(r1, r2, "deserialized response does not match");

        Ok(())
    }

    #[test]
    fn test_half_key() -> anyhow::Result<()> {
        let hk1 = HalfKey([0u8; HalfKey::SIZE]);
        let hk2 = HalfKey::try_from(hk1.as_ref())?;

        assert_eq!(hk1, hk2, "failed to match deserialized half-key");

        Ok(())
    }

    #[test]
    fn test_half_key_challenge() -> anyhow::Result<()> {
        let hkc1 = HalfKeyChallenge::try_from(PUBLIC_KEY.as_ref())?;
        let hkc2 = HalfKeyChallenge::try_from(hkc1.as_ref())?;
        assert_eq!(
            hkc1, hkc2,
            "failed to match deserialized half key challenge"
        );

        Ok(())
    }

    #[test]
    fn test_challenge_response_flow() -> anyhow::Result<()> {
        let hk1 = HalfKey::random();
        let hk2 = HalfKey::random();

        let response = Response::from_half_keys(&hk1, &hk2)?;

        let half_chal1 = hk1.to_challenge()?;
        let half_chal2 = hk2.to_challenge()?;

        let challenge1 = Challenge::from_hint_and_share(&half_chal1, &half_chal2)?;
        assert_eq!(
            challenge1,
            Challenge::from_hint_and_share(&half_chal2, &half_chal1)?
        );
        assert_eq!(
            challenge1,
            Challenge::from_own_share_and_half_key(&half_chal1, &hk2)?
        );

        let challenge2 = response.to_challenge()?;
        assert_eq!(challenge1, challenge2);
        assert_eq!(
            challenge1.to_ethereum_challenge(),
            challenge2.to_ethereum_challenge()
        );
        Ok(())
    }

    #[test]
    fn test_hash() -> anyhow::Result<()> {
        let hash1 = Hash::create(&[b"msg"]);
        assert_eq!(
            "0x92aef1b955b9de564fc50e31a55b470b0c8cdb931f186485d620729fb03d6f2c",
            hash1.to_hex(),
            "hash test vector failed to match"
        );

        let hash2 = Hash::try_from(hash1.as_ref())?;
        assert_eq!(hash1, hash2, "failed to match deserialized hash");

        assert_eq!(
            hash1.hash(),
            Hash::try_from(
                hex!("1c4d8d521eccee7225073ea180e0fa075a6443afb7ca06076a9566b07d29470f").as_ref()
            )?
        );

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_simple_pseudonym_serialize_contains_bytes() -> anyhow::Result<()> {
        let bytes = hex!("0102030405060708090a");
        let pseudonym = SimplePseudonym::try_from(bytes.as_ref())?;

        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&pseudonym, &mut serialized)?;
        let found = serialized.windows(bytes.len()).any(|w| w == bytes);
        assert!(
            found,
            "serialized bytes should contain original bytes, got {:02x?}",
            serialized
        );

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_simple_pseudonym_serialize_contains_bytes_postcard() -> anyhow::Result<()> {
        let bytes = hex!("0102030405060708090a");
        let pseudonym = SimplePseudonym::try_from(bytes.as_ref())?;

        let serialized = postcard::to_allocvec(&pseudonym)?;
        let found = serialized.windows(bytes.len()).any(|w| w == bytes);
        assert!(
            found,
            "serialized bytes should contain original bytes, got {:02x?}",
            serialized
        );

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_simple_pseudonym_roundtrip() -> anyhow::Result<()> {
        let original = SimplePseudonym::random();

        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&original, &mut serialized)?;
        let deserialized: SimplePseudonym = ciborium::de::from_reader(&serialized[..])?;

        assert_eq!(original, deserialized, "roundtrip should preserve value");
        let original_bytes: &[u8] = original.as_ref();
        let deserialized_bytes: &[u8] = deserialized.as_ref();
        assert_eq!(original_bytes, deserialized_bytes, "bytes should match");

        let original_hex: &str = AsRef::<str>::as_ref(&original);
        let deserialized_hex: &str = AsRef::<str>::as_ref(&deserialized);
        assert_eq!(original_hex, deserialized_hex, "hex strings should match");

        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_simple_pseudonym_roundtrip_postcard() -> anyhow::Result<()> {
        let original = SimplePseudonym::random();

        let serialized = postcard::to_allocvec(&original)?;
        let deserialized: SimplePseudonym = postcard::from_bytes(&serialized)?;

        assert_eq!(original, deserialized, "roundtrip should preserve value");
        let original_bytes: &[u8] = original.as_ref();
        let deserialized_bytes: &[u8] = deserialized.as_ref();
        assert_eq!(original_bytes, deserialized_bytes, "bytes should match");

        let original_hex: &str = AsRef::<str>::as_ref(&original);
        let deserialized_hex: &str = AsRef::<str>::as_ref(&deserialized);
        assert_eq!(original_hex, deserialized_hex, "hex strings should match");

        Ok(())
    }

    /// Test deserialization from CBOR byte array (visit_seq path)
    #[cfg(feature = "serde")]
    #[test]
    fn test_simple_pseudonym_deserialize_from_cbor_array() -> anyhow::Result<()> {
        let bytes = hex!("0102030405060708090a");

        // CBOR array encoding: major type 0x80 (array) with 10 integer elements
        // 0x8a = 0x80 + 10 (array of 10 items), followed by CBOR-encoded integers
        let mut cbor_array = vec![0x8a]; // 0x80 + 10 = 0x8a (array of 10 items)
        cbor_array.extend_from_slice(&bytes);

        let deserialized: SimplePseudonym = ciborium::de::from_reader(&cbor_array[..])?;
        assert_eq!(AsRef::<str>::as_ref(&deserialized), "0102030405060708090a");

        Ok(())
    }

    /// Test error case: wrong length in visit_bytes
    #[cfg(feature = "serde")]
    #[test]
    fn test_simple_pseudonym_deserialize_wrong_length() {
        let bytes = hex!("0102030405"); // Only 5 bytes, not 10

        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&bytes, &mut serialized).unwrap();

        let result: Result<SimplePseudonym, _> = ciborium::de::from_reader(&serialized[..]);
        assert!(
            result.is_err(),
            "deserialization should fail for wrong length"
        );
    }

    /// Test error case: sequence too long in visit_seq
    #[cfg(feature = "serde")]
    #[test]
    fn test_simple_pseudonym_deserialize_seq_too_long() {
        // CBOR array with 11 bytes (too long)
        let bytes = [0u8; 11];
        let mut cbor_array = vec![0x8b]; // 0x80 + 11 = 0x8b (array of 11 items)
        cbor_array.extend_from_slice(&bytes);

        let result: Result<SimplePseudonym, _> = ciborium::de::from_reader(&cbor_array[..]);
        assert!(
            result.is_err(),
            "deserialization should fail for sequence too long"
        );
    }

    /// Test error case: sequence too short in visit_seq
    #[cfg(feature = "serde")]
    #[test]
    fn test_simple_pseudonym_deserialize_seq_too_short() {
        // CBOR array with 5 bytes (too short)
        let bytes = hex!("0102030405");
        let mut cbor_array = vec![0x85]; // 0x80 + 5 = 0x85 (array of 5 items)
        cbor_array.extend_from_slice(&bytes);

        let result: Result<SimplePseudonym, _> = ciborium::de::from_reader(&cbor_array[..]);
        assert!(
            result.is_err(),
            "deserialization should fail for sequence too short"
        );
    }

    #[test]
    fn test_simple_pseudonym_as_ref_str() -> anyhow::Result<()> {
        let bytes = hex!("0102030405060708090a");
        let pseudonym = SimplePseudonym::try_from(bytes.as_ref())?;

        let hex_str: &str = AsRef::<str>::as_ref(&pseudonym);
        assert_eq!(hex_str.len(), 20, "hex string should be 20 characters");
        assert_eq!(
            hex_str, "0102030405060708090a",
            "hex string should match expected value"
        );

        Ok(())
    }

    #[test]
    fn test_simple_pseudonym_is_copy() {
        let original = SimplePseudonym::random();
        let _copy = original;

        let bytes: &[u8] = original.as_ref();
        assert_eq!(bytes.len(), 10, "original should still be valid after copy");
    }
}
