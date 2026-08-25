//! Types of the Curvy PIX integration.
//!
//! These are the identities used for private note discovery in the Curvy SSA protocol.
//! They are built from the generic key types of this crate: the spend meta-key `K` is a
//! [`PublicKey`](crate::crypto::types::PublicKey) and the view key `V` is a
//! [`Bn254PublicKey`](crate::crypto::types::Bn254PublicKey).

use crate::crypto::{
    keypairs::{Bn254Keypair, Keypair},
    primitives::SecretKey,
    types::{Bn254PublicKey, PublicKey},
    utils::SecretValue,
};
use crate::primitive::prelude::{BytesEncodable, BytesRepresentable, GeneralError};

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
/// [`PixDepositAddress`](super::primitives::PixDepositAddress), whose BabyJubJub variant
/// remains the note owner and whose private key is reconstructed by the SSA protocol.
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
mod tests {
    use subtle::ConstantTimeEq;

    use super::*;
    use crate::crypto::primitives::{Bn254G1Affine, Bn254G1Projective};
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
