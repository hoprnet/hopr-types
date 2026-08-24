use std::fmt::Debug;

use crate::crypto_random::{Randomizable, random_bytes};
use crate::primitive::prelude::*;
use digest::Digest;
use hybrid_array::Array;
use hybrid_array::ArraySize;
#[cfg(feature = "crypto")]
use sha2::Sha512;
use subtle::{Choice, ConstantTimeEq};

use crate::crypto::types::BjjPublicKey;
use crate::crypto::types::Bn254PublicKey;
use crate::crypto::{
    errors,
    errors::CryptoError::InvalidInputValue,
    primitives::{PixDepositAddress, PixDepositSecret},
    types::{OffchainPublicKey, PublicKey},
    utils::{SecretValue, k256_scalar_from_bytes, random_group_element, x25519_scalar_from_bytes},
};

/// Represents a generic key pair
/// The keypair contains a private key and public key.
/// Must be comparable in constant time and zeroized on drop.
pub trait Keypair: ConstantTimeEq + Sized {
    /// Represents the type of the private (secret) key
    type SecretLen: ArraySize;

    /// Represents the type of the public key
    type Public: BytesRepresentable + Clone + PartialEq;

    /// Generates a new random keypair.
    fn random() -> Self;

    /// Creates a keypair from the given secret key.
    fn from_secret(bytes: &[u8]) -> errors::Result<Self>;

    /// Returns the private (secret) part of the keypair
    fn secret(&self) -> &SecretValue<Self::SecretLen>;

    /// Returns the public part of the keypair
    fn public(&self) -> &Self::Public;

    /// Consumes the instance and produces separated private and public parts
    #[allow(unstable_name_collisions)]
    fn unzip(self) -> (SecretValue<Self::SecretLen>, Self::Public) {
        (self.secret().clone(), self.public().clone())
    }
}

/// Represents a keypair consisting of an Ed25519 private and public key
#[derive(Clone, Debug)]
pub struct OffchainKeypair(SecretValue<typenum::U32>, OffchainPublicKey);

impl Keypair for OffchainKeypair {
    type Public = OffchainPublicKey;
    type SecretLen = typenum::U32;

    fn random() -> Self {
        // Safe to unwrap here, as the random bytes length is exact
        Self::from_secret(&random_bytes::<{ ed25519_dalek::SECRET_KEY_LENGTH }>()).unwrap()
    }

    fn from_secret(bytes: &[u8]) -> errors::Result<Self> {
        Ok(Self(
            bytes.try_into().map_err(|_| InvalidInputValue("bytes"))?,
            OffchainPublicKey::from_privkey(bytes)?,
        ))
    }

    fn secret(&self) -> &SecretValue<typenum::U32> {
        &self.0
    }

    fn public(&self) -> &Self::Public {
        &self.1
    }
}

impl ConstantTimeEq for OffchainKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret().ct_eq(other.secret())
    }
}

impl From<&OffchainKeypair> for curve25519_dalek::scalar::Scalar {
    /// Transforms the secret to be equivalent with the EdDSA public key used for signing.
    /// This is required so that the secret keys used to generate Sphinx shared secrets
    /// correspond to the public keys we get from the Ed25519 peer ids.
    fn from(value: &OffchainKeypair) -> Self {
        let mut h = Sha512::default();
        h.update(&value.0);
        let hash = h.finalize();

        let mut ret = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        ret.copy_from_slice(&hash[..32]);
        x25519_scalar_from_bytes(&ret).unwrap() // cannot happen, secret always represents a valid scalar
    }
}

impl From<&OffchainKeypair> for libp2p_identity::Keypair {
    fn from(value: &OffchainKeypair) -> Self {
        libp2p_identity::Keypair::ed25519_from_bytes(value.0.clone())
            .expect("invalid offchain keypair")
        // must not happen
    }
}

impl From<&OffchainKeypair> for libp2p_identity::PeerId {
    fn from(value: &OffchainKeypair) -> Self {
        value.1.into()
    }
}

/// Represents a keypair consisting of a secp256k1 private and public key
#[derive(Clone, Debug)]
pub struct ChainKeypair(SecretValue<typenum::U32>, PublicKey);

impl Keypair for ChainKeypair {
    type Public = PublicKey;
    type SecretLen = typenum::U32;

    fn random() -> Self {
        let (secret, public) = random_group_element();
        Self(Array(secret).into(), public.into())
    }

    fn from_secret(bytes: &[u8]) -> errors::Result<Self> {
        let compressed = PublicKey::from_privkey(bytes)?;

        Ok(Self(
            bytes.try_into().map_err(|_| InvalidInputValue("bytes"))?,
            compressed,
        ))
    }

    fn secret(&self) -> &SecretValue<typenum::U32> {
        &self.0
    }

    fn public(&self) -> &Self::Public {
        &self.1
    }
}

impl ConstantTimeEq for ChainKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret().ct_eq(other.secret())
    }
}

impl From<&ChainKeypair> for k256::Scalar {
    fn from(value: &ChainKeypair) -> Self {
        k256_scalar_from_bytes(value.0.as_ref())
            .expect("chain keypair must always have valid scalar")
    }
}

impl From<&ChainKeypair> for Address {
    fn from(value: &ChainKeypair) -> Self {
        value.public().to_address()
    }
}

impl AsRef<Address> for ChainKeypair {
    fn as_ref(&self) -> &Address {
        self.public().as_ref()
    }
}

/// Represents a keypair consisting of a Baby JubJub private and public keys.
#[derive(Clone, Debug)]
pub struct BjjKeypair(SecretValue<typenum::U32>, BjjPublicKey);

impl Keypair for BjjKeypair {
    type Public = BjjPublicKey;
    type SecretLen = typenum::U32;

    fn random() -> Self {
        // Use rejection sampling to generate a valid random secret key
        let mut ret = Self::from_secret(SecretValue::<typenum::U32>::random().as_ref());
        while ret.is_err() {
            ret = Self::from_secret(SecretValue::<typenum::U32>::random().as_ref());
        }

        // Not an error at this point
        ret.unwrap()
    }

    fn from_secret(bytes: &[u8]) -> errors::Result<Self> {
        BjjPublicKey::from_privkey(bytes).and_then(|pub_key| Ok(Self(bytes.try_into()?, pub_key)))
    }

    fn secret(&self) -> &SecretValue<Self::SecretLen> {
        &self.0
    }

    fn public(&self) -> &Self::Public {
        &self.1
    }
}

impl ConstantTimeEq for BjjKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret().ct_eq(other.secret())
    }
}

impl From<&BjjKeypair> for BjjPublicKey {
    fn from(value: &BjjKeypair) -> Self {
        *value.public()
    }
}

/// Represents a keypair consisting of BN254 private and public keys.
#[derive(Clone, Debug)]
pub struct Bn254Keypair(SecretValue<typenum::U32>, Bn254PublicKey);

impl Bn254Keypair {
    /// Creates a keypair from the given big-endian secret scalar.
    ///
    /// [`Keypair::from_secret`] expects the little-endian representation used by the
    /// BN254 arithmetic backend. This is its counterpart for secret scalars encoded as
    /// big-endian integers, see [`Bn254PublicKey::from_privkey_be`].
    ///
    /// The secret is always stored in the little-endian representation, so that
    /// [`Keypair::secret`] and [`Keypair::from_secret`] remain symmetric.
    /// Use [`secret_be`](Bn254Keypair::secret_be) to retrieve it as a big-endian integer.
    pub fn from_secret_be(bytes: &[u8]) -> errors::Result<Self> {
        Self::from_secret(crate::crypto::utils::reverse_secret_scalar(bytes)?.as_ref())
    }

    /// Returns the secret scalar as a big-endian integer.
    ///
    /// This is the counterpart of [`from_secret_be`](Bn254Keypair::from_secret_be);
    /// [`Keypair::secret`] returns the little-endian representation.
    pub fn secret_be(&self) -> SecretValue<typenum::U32> {
        crate::crypto::utils::reverse_secret_scalar(self.0.as_ref())
            .expect("the secret always has the correct length")
    }
}

impl Keypair for Bn254Keypair {
    type Public = Bn254PublicKey;
    type SecretLen = typenum::U32;

    fn random() -> Self {
        let mut ret = Self::from_secret(SecretValue::<typenum::U32>::random().as_ref());
        while ret.is_err() {
            ret = Self::from_secret(SecretValue::<typenum::U32>::random().as_ref());
        }
        ret.unwrap()
    }

    fn from_secret(bytes: &[u8]) -> errors::Result<Self> {
        Bn254PublicKey::from_privkey(bytes).and_then(|pub_key| Ok(Self(bytes.try_into()?, pub_key)))
    }

    fn secret(&self) -> &SecretValue<Self::SecretLen> {
        &self.0
    }

    fn public(&self) -> &Self::Public {
        &self.1
    }
}

impl ConstantTimeEq for Bn254Keypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret().ct_eq(other.secret())
    }
}

impl From<&Bn254Keypair> for Bn254PublicKey {
    fn from(value: &Bn254Keypair) -> Self {
        *value.public()
    }
}

/// Extension trait for keypairs that can be used as PIX deposit/withdrawal keys.
///
/// This trait is automatically implemented for all keypairs, where the public key is convertible into [`PixDepositAddress`]
/// and the secret key is sized so that it also fits the [`PixDepositSecret`].
pub trait PixKeypairExt: Keypair<SecretLen = typenum::U32>
where
    <Self as Keypair>::Public: Into<PixDepositAddress>,
{
    /// Consumes the instance and produces corresponding [`PixDepositSecret`] and [`PixDepositAddress`].
    fn unzip_into_pix(self) -> (PixDepositSecret, PixDepositAddress) {
        let (secret, public) = self.unzip();
        (secret.into(), public.into())
    }
}

impl<K> PixKeypairExt for K
where
    K: Keypair<SecretLen = typenum::U32>,
    <K as Keypair>::Public: Into<PixDepositAddress>,
{
}

#[cfg(test)]
mod tests {
    use libp2p_identity::PeerId;
    use subtle::ConstantTimeEq;

    use super::*;

    #[test]
    fn test_offchain_keypair() {
        let kp_1 = OffchainKeypair::random();

        let public = OffchainPublicKey::from_privkey(kp_1.secret().as_ref()).unwrap();
        assert_eq!(
            &public,
            kp_1.public(),
            "secret keys must yield compatible public keys"
        );

        let kp_2 = OffchainKeypair::from_secret(kp_1.secret().as_ref()).unwrap();
        assert_eq!(
            kp_1.ct_eq(&kp_2).unwrap_u8(),
            1,
            "keypairs generated from secrets must be equal"
        );
        assert_eq!(
            &public,
            kp_2.public(),
            "secret keys must yield compatible public keys"
        );
        assert_eq!(
            kp_1.public(),
            kp_2.public(),
            "keypair public keys must be equal"
        );

        let (s1, p1) = kp_1.unzip();
        let (s2, p2) = kp_2.unzip();

        assert_eq!(s1.ct_eq(&s2).unwrap_u8(), 1);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_offchain_keypair_libp2p_compatibility() {
        let kp_1 = OffchainKeypair::random();

        let p2p_kp: libp2p_identity::Keypair = (&kp_1).into();

        let p1: PeerId = (*kp_1.public()).into();
        let p2: PeerId = p2p_kp.public().into();
        assert_eq!(p1, p2, "peer ids must be equal");
    }

    #[test]
    fn test_chain_keypair() {
        let kp_1 = ChainKeypair::random();

        let public = PublicKey::from_privkey(kp_1.secret().as_ref()).unwrap();
        assert_eq!(
            &public,
            kp_1.public(),
            "secret keys must yield compatible public keys"
        );

        let kp_2 = ChainKeypair::from_secret(kp_1.secret().as_ref()).unwrap();
        assert_eq!(
            kp_1.ct_eq(&kp_2).unwrap_u8(),
            1,
            "keypairs generated from secrets must be equal"
        );
        assert_eq!(
            &public,
            kp_2.public(),
            "secret keys must yield compatible public keys"
        );
        assert_eq!(
            kp_1.public(),
            kp_2.public(),
            "keypair public keys must be equal"
        );

        let (s1, p1) = kp_1.clone().unzip();
        let (s2, p2) = kp_2.clone().unzip();

        assert_eq!(s1.ct_eq(&s2).unwrap_u8(), 1);
        assert_eq!(p1, p2);

        let (s1, p1) = kp_1.clone().unzip_into_pix();
        assert_eq!(s1.0.ct_eq(&kp_1.secret()).unwrap_u8(), 1);
        assert_eq!(p1, kp_1.public().clone().into());
    }

    #[test]
    fn test_bjj_keypair() {
        let kp_1 = BjjKeypair::random();

        let public = BjjPublicKey::from_privkey(kp_1.secret().as_ref()).unwrap();
        assert_eq!(
            &public,
            kp_1.public(),
            "secret keys must yield compatible public keys"
        );
        assert_eq!(
            public,
            BjjPublicKey::from(&kp_1),
            "secret keys must yield compatible public keys"
        );

        let kp_2 = BjjKeypair::from_secret(kp_1.secret().as_ref()).unwrap();
        assert_eq!(
            kp_1.ct_eq(&kp_2).unwrap_u8(),
            1,
            "keypairs generated from secrets must be equal"
        );
        assert_eq!(
            &public,
            kp_2.public(),
            "secret keys must yield compatible public keys"
        );
        assert_eq!(
            kp_1.public(),
            kp_2.public(),
            "keypair public keys must be equal"
        );

        let (s1, p1) = kp_1.clone().unzip();
        let (s2, p2) = kp_2.clone().unzip();

        assert_eq!(s1.ct_eq(&s2).unwrap_u8(), 1);
        assert_eq!(p1, p2);

        let (s1, p1) = kp_1.clone().unzip_into_pix();
        assert_eq!(s1.0.ct_eq(&kp_1.secret()).unwrap_u8(), 1);
        assert_eq!(p1, kp_1.public().clone().into());
    }

    #[test]
    fn test_bn254_keypair() {
        let kp_1 = Bn254Keypair::random();

        let public = Bn254PublicKey::from_privkey(kp_1.secret().as_ref()).unwrap();
        assert_eq!(
            &public,
            kp_1.public(),
            "secret keys must yield compatible public keys"
        );
        assert_eq!(
            public,
            Bn254PublicKey::from(&kp_1),
            "secret keys must yield compatible public keys"
        );

        let kp_2 = Bn254Keypair::from_secret(kp_1.secret().as_ref()).unwrap();
        assert_eq!(
            kp_1.ct_eq(&kp_2).unwrap_u8(),
            1,
            "keypairs generated from secrets must be equal"
        );
        assert_eq!(
            &public,
            kp_2.public(),
            "secret keys must yield compatible public keys"
        );
        assert_eq!(
            kp_1.public(),
            kp_2.public(),
            "keypair public keys must be equal"
        );

        let (s1, p1) = kp_1.clone().unzip();
        let (s2, p2) = kp_2.clone().unzip();

        assert_eq!(s1.ct_eq(&s2).unwrap_u8(), 1);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_bn254_keypair_big_endian_secret() -> anyhow::Result<()> {
        let kp_1 = Bn254Keypair::random();

        let mut reversed = kp_1.secret().as_ref().to_vec();
        reversed.reverse();
        assert_eq!(
            kp_1.secret_be().as_ref(),
            reversed.as_slice(),
            "big-endian secret must be the reverse of the little-endian one"
        );

        let kp_2 = Bn254Keypair::from_secret_be(kp_1.secret_be().as_ref())?;
        assert_eq!(
            kp_1.ct_eq(&kp_2).unwrap_u8(),
            1,
            "keypairs must round-trip through the big-endian secret"
        );
        assert_eq!(kp_1.public(), kp_2.public());

        assert_eq!(
            &Bn254PublicKey::from_privkey_be(kp_1.secret_be().as_ref())?,
            kp_1.public(),
            "must be consistent with Bn254PublicKey::from_privkey_be"
        );

        assert!(Bn254Keypair::from_secret_be(&[0u8; 32]).is_err());
        assert!(Bn254Keypair::from_secret_be(&[0u8; 31]).is_err());

        Ok(())
    }
}
