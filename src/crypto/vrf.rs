use crate::primitive::prelude::*;
use k256::{
    AffinePoint, Scalar, Secp256k1,
    elliptic_curve::{
        ProjectivePoint,
        sec1::{Sec1Point as EncodedPoint, ToSec1Point},
    },
};
type Sec1EncodedPoint = EncodedPoint<Secp256k1>;
use crate::crypto::{
    errors::{CryptoError::CalculationError, Result},
    keypairs::{ChainKeypair, Keypair},
    types::{PublicKey, affine_point_from_bytes},
    utils::k256_scalar_from_bytes,
};
use crate::crypto_random::random_bytes;
use hash2curve::ExpandMsgXmd;

/// Bundles values given to the smart contract to prove that a ticket is a win.
///
/// The VRF is thereby needed because it generates on-demand deterministic
/// entropy that can only be derived by the ticket redeemer.
#[allow(non_snake_case)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfParameters {
    /// the pseudo-random point V = a·B
    pub V: AffinePoint,
    pub h: Scalar,
    pub s: Scalar,
    /// the redeemer's secp256k1 public key A = a·G (DLEQ binding)
    pub A: AffinePoint,
}

impl std::fmt::Debug for VrfParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VrfParameters")
            .field("V", &const_hex::encode(self.V.to_sec1_point(true)))
            .field("h", &const_hex::encode(self.h.to_bytes()))
            .field("s", &const_hex::encode(self.s.to_bytes()))
            .field("A", &const_hex::encode(self.A.to_sec1_point(true)))
            .finish()
    }
}

impl From<VrfParameters> for [u8; VRF_PARAMETERS_SIZE] {
    fn from(value: VrfParameters) -> Self {
        let mut ret = [0u8; VRF_PARAMETERS_SIZE];
        let v_bytes = value.V.to_sec1_point(true);
        let h_bytes = value.h.to_bytes();
        let s_bytes = value.s.to_bytes();
        let a_bytes = value.A.to_sec1_point(true);
        let mut off = 0;
        ret[off..off + PublicKey::SIZE_COMPRESSED].copy_from_slice(v_bytes.as_ref());
        off += PublicKey::SIZE_COMPRESSED;
        ret[off..off + 32].copy_from_slice(h_bytes.as_ref());
        off += 32;
        ret[off..off + 32].copy_from_slice(s_bytes.as_ref());
        off += 32;
        ret[off..off + PublicKey::SIZE_COMPRESSED].copy_from_slice(a_bytes.as_ref());
        ret
    }
}

impl TryFrom<&[u8]> for VrfParameters {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() == Self::SIZE {
            let mut off = 0;
            #[allow(non_snake_case)]
            let V = affine_point_from_bytes(&value[off..off + PublicKey::SIZE_COMPRESSED])
                .map_err(|_| GeneralError::ParseError("VrfParameters.V".into()))?;
            off += PublicKey::SIZE_COMPRESSED;
            let h = k256_scalar_from_bytes(&value[off..off + 32])
                .map_err(|_| GeneralError::ParseError("VrfParameters.h".into()))?;
            off += 32;
            let s = k256_scalar_from_bytes(&value[off..off + 32])
                .map_err(|_| GeneralError::ParseError("VrfParameters.s".into()))?;
            off += 32;
            #[allow(non_snake_case)]
            let A = affine_point_from_bytes(&value[off..off + PublicKey::SIZE_COMPRESSED])
                .map_err(|_| GeneralError::ParseError("VrfParameters.A".into()))?;
            Ok(VrfParameters { V, h, s, A })
        } else {
            Err(GeneralError::ParseError("VrfParameters.size".into()))
        }
    }
}

const VRF_PARAMETERS_SIZE: usize =
    PublicKey::SIZE_COMPRESSED + 32 + 32 + PublicKey::SIZE_COMPRESSED;
impl BytesEncodable<VRF_PARAMETERS_SIZE> for VrfParameters {}

impl VrfParameters {
    /// Verifies that VRF values are valid.
    /// The SC performs the verification. This method is here just to test correctness.
    #[allow(non_snake_case)]
    pub fn verify<const T: usize>(
        &self,
        creator: &Address,
        msg: &[u8; T],
        dst: &[u8],
    ) -> Result<()> {
        let cap_B = self.get_encoded_payload(creator, msg, dst)?;
        let G = ProjectivePoint::<Secp256k1>::GENERATOR;
        let v_proj = ProjectivePoint::<Secp256k1>::from(self.V);
        let a_proj = ProjectivePoint::<Secp256k1>::from(self.A);

        // R_V = s·B - h·V
        let R_v: ProjectivePoint<Secp256k1> = cap_B * self.s - v_proj * self.h;
        // R_G = s·G - h·A
        let R_g: ProjectivePoint<Secp256k1> = G * self.s - a_proj * self.h;

        let h_check =
            hash2curve::hash_to_scalar::<Secp256k1, ExpandMsgXmd<sha3::Keccak256>, typenum::U48>(
                &[
                    creator.as_ref(),
                    &self.A.to_sec1_point(false).to_bytes().as_ref()[1..],
                    &self.V.to_sec1_point(false).to_bytes().as_ref()[1..],
                    &R_g.to_affine().to_sec1_point(false).to_bytes().as_ref()[1..],
                    &R_v.to_affine().to_sec1_point(false).to_bytes().as_ref()[1..],
                    msg,
                ],
                &[dst],
            )
            .map_err(|_| CalculationError)?;

        if h_check != self.h {
            return Err(CalculationError);
        }

        Ok(())
    }

    /// Returns the encoded VRF `V` value as an uncompressed point in affine coordinates.
    pub fn get_v_encoded_point(&self) -> Sec1EncodedPoint {
        self.V.to_sec1_point(false)
    }

    /// Returns the encoded public key `A` as an uncompressed point in affine coordinates.
    pub fn get_a_encoded_point(&self) -> Sec1EncodedPoint {
        self.A.to_sec1_point(false)
    }

    /// Performs a scalar point multiplication of `self.h` and `self.v`
    /// and returns the point in affine coordinates.
    ///
    /// Used to create the witness values needed by the smart contract.
    pub fn get_h_v_witness(&self) -> Sec1EncodedPoint {
        (ProjectivePoint::<Secp256k1>::from(self.V) * self.h)
            .to_affine()
            .to_sec1_point(false)
    }

    /// Performs a scalar point multiplication of `self.h` and `self.A`
    /// and returns the point in affine coordinates.
    ///
    /// Used to create the h·A witness needed by the smart contract.
    pub fn get_h_a_witness(&self) -> Sec1EncodedPoint {
        (ProjectivePoint::<Secp256k1>::from(self.A) * self.h)
            .to_affine()
            .to_sec1_point(false)
    }

    /// Performs a scalar point multiplication of `self.s` and the secp256k1
    /// generator and returns the point in affine coordinates.
    ///
    /// Used to create the s·G witness needed by the smart contract.
    pub fn get_s_g_witness(&self) -> Sec1EncodedPoint {
        (ProjectivePoint::<Secp256k1>::GENERATOR * self.s)
            .to_affine()
            .to_sec1_point(false)
    }

    /// Performs a scalar point multiplication with the encoded payload
    /// and `self.s`. Expands the payload and applies the hash_to_curve
    /// algorithm.
    ///
    /// Used to create the witness values needed by the smart contract.
    pub fn get_s_b_witness<const T: usize>(
        &self,
        creator: &Address,
        msg: &[u8; T],
        dst: &[u8],
    ) -> Result<Sec1EncodedPoint> {
        Ok((self.get_encoded_payload(creator, msg, dst)? * self.s)
            .to_affine()
            .to_sec1_point(false))
    }

    /// Takes the message upon which the VRF gets computed, the domain separation tag
    /// and the Ethereum address of the creator, expand the raw data with the
    /// `ExpandMsgXmd` algorithm (https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-expand_message_xmd)
    /// and applies the hash-to-curve function to it.
    ///
    /// Finally, returns an elliptic curve point on Secp256k1.
    fn get_encoded_payload<const T: usize>(
        &self,
        creator: &Address,
        msg: &[u8; T],
        dst: &[u8],
    ) -> Result<k256::ProjectivePoint> {
        hash2curve::hash_from_bytes::<Secp256k1, ExpandMsgXmd<sha3::Keccak256>>(
            &[creator.as_ref(), msg],
            &[dst],
        )
        .map_err(|_| CalculationError)
    }
}

/// Takes a private key, the corresponding Ethereum address and a payload
/// and creates all parameters that are required by the smart contract
/// to prove that a ticket is a win.
#[cfg(feature = "rust-ecdsa")]
#[allow(non_snake_case)]
pub fn derive_vrf_parameters<T: AsRef<[u8]>>(
    msg: T,
    chain_keypair: &ChainKeypair,
    dst: &[u8],
) -> crate::crypto::errors::Result<VrfParameters> {
    let chain_addr = chain_keypair.public().to_address();
    let G = ProjectivePoint::<Secp256k1>::GENERATOR;
    let a: Scalar = chain_keypair.into();

    // Redeemer's public key A = a·G
    let A = (G * a).to_affine();

    let B = hash2curve::hash_from_bytes::<Secp256k1, ExpandMsgXmd<sha3::Keccak256>>(
        &[chain_addr.as_ref(), msg.as_ref()],
        &[dst],
    )
    .map_err(|_| CalculationError)?;

    let V = B * a;

    let r = hash2curve::hash_to_scalar::<Secp256k1, ExpandMsgXmd<sha3::Keccak256>, typenum::U48>(
        &[
            &a.to_bytes(),
            &V.to_affine().to_sec1_point(false).to_bytes().as_ref()[1..],
            &random_bytes::<64>(),
        ],
        &[dst],
    )
    .map_err(|_| CalculationError)?;

    let R_v = B * r;
    // R_G = r·G — binds the DLEQ proof to the base point
    let R_g = G * r;

    // Challenge now binds BOTH bases: signer || A || V || R_G || R_V || message
    let h = hash2curve::hash_to_scalar::<Secp256k1, ExpandMsgXmd<sha3::Keccak256>, typenum::U48>(
        &[
            chain_addr.as_ref(),
            &A.to_sec1_point(false).to_bytes().as_ref()[1..],
            &V.to_affine().to_sec1_point(false).to_bytes().as_ref()[1..],
            &R_g.to_affine().to_sec1_point(false).to_bytes().as_ref()[1..],
            &R_v.to_affine().to_sec1_point(false).to_bytes().as_ref()[1..],
            msg.as_ref(),
        ],
        &[dst],
    )
    .map_err(|_| CalculationError)?;
    let s = r + h * a;

    Ok(VrfParameters {
        V: V.to_affine(),
        h,
        s,
        A,
    })
}

/// Takes a private key, the corresponding Ethereum address and a payload
/// and creates all parameters that are required by the smart contract
/// to prove that a ticket is a win.
#[cfg(not(feature = "rust-ecdsa"))]
#[allow(non_snake_case)]
pub fn derive_vrf_parameters<T: AsRef<[u8]>>(
    msg: T,
    chain_keypair: &ChainKeypair,
    dst: &[u8],
) -> Result<VrfParameters> {
    let chain_addr = chain_keypair.public().to_address();
    let B = hash2curve::hash_from_bytes::<Secp256k1, ExpandMsgXmd<sha3::Keccak256>>(
        &[chain_addr.as_ref(), msg.as_ref()],
        &[dst],
    )
    .map_err(|_| CalculationError)?
    .to_affine();

    let a = secp256k1::Scalar::from_be_bytes(chain_keypair.secret().clone().into())
        .map_err(|_| crate::crypto::errors::CryptoError::InvalidSecretScalar)?;

    let a_be_bytes = a.to_be_bytes();

    let B_pk = secp256k1::PublicKey::from_byte_array_uncompressed(
        B.to_sec1_point(false)
            .to_bytes()
            .as_ref()
            .try_into()
            .map_err(|_| crate::crypto::errors::CryptoError::InvalidPublicKey)?,
    )
    .map_err(|_| crate::crypto::errors::CryptoError::InvalidPublicKey)?;

    // Compute A = a·G (the redeemer's secp256k1 public key)
    let secp = secp256k1::global::SECP256K1;
    let A = secp256k1::PublicKey::from_secret_key(
        secp,
        &secp256k1::SecretKey::from_byte_array(a_be_bytes).map_err(|_| CalculationError)?,
    );

    let V = B_pk.mul_tweak(secp, &a).map_err(|_| CalculationError)?;

    let r = hash2curve::hash_to_scalar::<Secp256k1, ExpandMsgXmd<sha3::Keccak256>, typenum::U48>(
        &[
            &a_be_bytes,
            &V.serialize_uncompressed()[1..],
            &random_bytes::<64>(),
        ],
        &[dst],
    )
    .map_err(|_| CalculationError)?;

    let r_scalar = secp256k1::Scalar::from_be_bytes(r.to_bytes().into())
        .map_err(|_| crate::crypto::errors::CryptoError::InvalidSecretScalar)?;

    let R_v = B_pk
        .mul_tweak(secp, &r_scalar)
        .map_err(|_| CalculationError)?;

    // R_G = r·G
    let R_g = secp256k1::PublicKey::from_secret_key(
        secp,
        &secp256k1::SecretKey::from_byte_array(r.to_bytes().into())
            .map_err(|_| CalculationError)?,
    );

    // Challenge now binds BOTH bases: signer || A || V || R_G || R_V || message
    let h = hash2curve::hash_to_scalar::<Secp256k1, ExpandMsgXmd<sha3::Keccak256>, typenum::U48>(
        &[
            chain_addr.as_ref(),
            &A.serialize_uncompressed()[1..],
            &V.serialize_uncompressed()[1..],
            &R_g.serialize_uncompressed()[1..],
            &R_v.serialize_uncompressed()[1..],
            msg.as_ref(),
        ],
        &[dst],
    )
    .map_err(|_| CalculationError)?;
    let s = r + h * Scalar::from(chain_keypair);

    let V = affine_point_from_bytes(&V.serialize_uncompressed()).map_err(|_| CalculationError)?;
    let A = affine_point_from_bytes(&A.serialize_uncompressed()).map_err(|_| CalculationError)?;

    Ok(VrfParameters { V, h, s, A })
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use sha3::Keccak256;

    use super::*;
    use crate::crypto::types::Hash;

    lazy_static::lazy_static! {
        static ref ALICE: ChainKeypair = ChainKeypair::from_secret(&hex!("e17fe86ce6e99f4806715b0c9412f8dad89334bf07f72d5834207a9d8f19d7f8")).expect("lazy static keypair should be valid");
        static ref ALICE_ADDR: Address = ALICE.public().to_address();

        static ref TEST_MSG: [u8; 32] = hex!("8248a966b9215e154c8f673cb154da030916be3fb31af3b1220419a1c98eeaed");
    }

    #[test]
    fn vrf_values_serialize_deserialize() -> anyhow::Result<()> {
        let vrf_values = derive_vrf_parameters(*TEST_MSG, &ALICE, Hash::default().as_ref())?;

        // Round-trip
        let vrf: [u8; VrfParameters::SIZE] = vrf_values.into();
        let other = VrfParameters::try_from(vrf.as_ref())?;
        assert!(
            vrf_values.s == other.s
                && vrf_values.V == other.V
                && vrf_values.h == other.h
                && vrf_values.A == other.A
        );

        Ok(())
    }

    #[test]
    fn vrf_values_serialize_deserialize_bad_examples() {
        // Empty bytes
        assert!(VrfParameters::try_from(&[][..]).is_err());
        // Too short
        assert!(VrfParameters::try_from(&[0u8; 10][..]).is_err());
        // Correct size but invalid curve point
        assert!(VrfParameters::try_from(&[0xFFu8; VrfParameters::SIZE][..]).is_err());
    }

    #[test]
    fn vrf_values_crypto() -> anyhow::Result<()> {
        let vrf_values = derive_vrf_parameters(*TEST_MSG, &ALICE, Hash::default().as_ref())?;

        assert!(
            vrf_values
                .verify(&ALICE_ADDR, &TEST_MSG, Hash::default().as_ref())
                .is_ok()
        );

        Ok(())
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_vrf_parameter_generation() -> anyhow::Result<()> {
        let dst = b"some DST tag";
        let priv_key: [u8; 32] =
            hex!("f13233ff60e1f618525dac5f7d117bef0bad0eb0b0afb2459f9cbc57a3a987ba"); // dummy
        let message = hex!("f13233ff60e1f618525dac5f7d117bef0bad0eb0b0afb2459f9cbc57a3a987ba"); // dummy

        let keypair = ChainKeypair::from_secret(&priv_key)?;
        // vrf verification algorithm
        let pub_key = PublicKey::from_privkey(&priv_key)?;

        let params = derive_vrf_parameters(message, &keypair, dst)?;

        // Verify A = a·G
        let a: Scalar = k256_scalar_from_bytes(&priv_key)?.into();
        let G = ProjectivePoint::<Secp256k1>::GENERATOR;
        assert_eq!(params.A, (G * a).to_affine());

        // Verify address matches
        assert_eq!(pub_key.to_address(), keypair.public().to_address());

        // Verify s·G witness
        let s_g_expected: ProjectivePoint<Secp256k1> = G * params.s;
        assert_eq!(params.get_s_g_witness(), s_g_expected.to_sec1_point(false));

        // Verify h·A witness
        let a_proj = ProjectivePoint::<Secp256k1>::from(params.A);
        let h_a_expected = a_proj * params.h;
        assert_eq!(params.get_h_a_witness(), h_a_expected.to_sec1_point(false));

        let cap_b = hash2curve::hash_from_bytes::<Secp256k1, ExpandMsgXmd<Keccak256>>(
            &[pub_key.to_address().as_ref(), &message],
            &[dst],
        )?;

        assert_eq!(
            params.get_s_b_witness(&keypair.public().to_address(), &message, dst)?,
            (cap_b * params.s).to_sec1_point(false)
        );

        assert_eq!(
            params.get_h_v_witness(),
            (cap_b * a * params.h).to_sec1_point(false)
        );

        let G_proj = ProjectivePoint::<Secp256k1>::GENERATOR;
        let r_v: ProjectivePoint<Secp256k1> =
            cap_b * params.s - ProjectivePoint::<Secp256k1>::from(params.V) * params.h;
        let r_g: ProjectivePoint<Secp256k1> =
            G_proj * params.s - ProjectivePoint::<Secp256k1>::from(params.A) * params.h;

        let h_check = hash2curve::hash_to_scalar::<Secp256k1, ExpandMsgXmd<Keccak256>, typenum::U48>(
            &[
                pub_key.to_address().as_ref(),
                &params.A.to_sec1_point(false).to_bytes().as_ref()[1..],
                &params.V.to_sec1_point(false).to_bytes().as_ref()[1..],
                &r_g.to_affine().to_sec1_point(false).to_bytes().as_ref()[1..],
                &r_v.to_affine().to_sec1_point(false).to_bytes().as_ref()[1..],
                &message,
            ],
            &[dst],
        )?;

        assert_eq!(h_check, params.h);

        Ok(())
    }
}
