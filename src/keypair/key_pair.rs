use std::{fmt::Debug, fs, path::Path, str::FromStr};

use crate::{
    crypto::{
        crypto_traits::{Digest, KeyIvInit, StreamCipher, Update},
        prelude::*,
    },
    crypto_random::{Randomizable, random_bytes},
    primitive::prelude::*,
};
use scrypt::{Params as ScryptParams, scrypt};
use serde_json::{from_str as from_json_string, to_string as to_json_string};
use typenum::Unsigned;
use uuid::Uuid;

use crate::keypair::{
    errors::{KeyPairError, Result},
    keystore::{CipherparamsJson, CryptoJson, EthKeystore, KdfType, KdfparamsType, PrivateKeys},
};

const HOPR_CIPHER: &str = "aes-128-ctr";
const HOPR_KEY_SIZE: usize = 32;
const HOPR_IV_SIZE: usize = 16;
const HOPR_KDF_PARAMS_DKLEN: u8 = 32;
const HOPR_KDF_PARAMS_LOG_N: u8 = 13;
const HOPR_KDF_PARAMS_R: u32 = 8;
const HOPR_KDF_PARAMS_P: u32 = 1;

const PACKET_KEY_LENGTH: usize = <OffchainKeypair as Keypair>::SecretLen::USIZE;
const CHAIN_KEY_LENGTH: usize = <ChainKeypair as Keypair>::SecretLen::USIZE;
const BJJ_KEY_LENGTH: usize = <BjjKeypair as Keypair>::SecretLen::USIZE;

const V1_PRIVKEY_LENGTH: usize = 32;

const VERSION: u32 = 3;

pub enum IdentityRetrievalModes<'a> {
    /// Node starts with a previously generated identity file.
    /// If none is present, create a new one
    FromFile {
        /// Used to encrypt / decrypt an identity file
        password: &'a str,
        /// path to store / load an identity file
        id_path: &'a str,
    },
    /// Node receives at startup a private key which it will use
    /// for the entire runtime. The private key stays in memory and
    /// thus remains fluent
    FromPrivateKey {
        /// hex string containing the private key
        private_key: &'a str,
    },
    /// takes a private key and create an identity file at the
    /// provided file destination
    #[cfg(any(feature = "keypair-to-file", test))]
    FromIdIntoFile {
        /// identifier of this keypair
        id: Uuid,
        /// Used to encrypt / decrypt an identity file
        password: &'a str,
        /// path to store / load an identity file
        id_path: &'a str,
    },
}

#[derive(Clone)]
pub struct HoprKeys {
    pub packet_key: OffchainKeypair,
    pub chain_key: ChainKeypair,
    pub bjj_key: BjjKeypair,
    id: Uuid,
}

impl<'a> From<&'a HoprKeys> for (&'a ChainKeypair, &'a OffchainKeypair, &'a BjjKeypair) {
    fn from(keys: &'a HoprKeys) -> Self {
        (&keys.chain_key, &keys.packet_key, &keys.bjj_key)
    }
}

impl TryFrom<IdentityRetrievalModes<'_>> for HoprKeys {
    type Error = KeyPairError;

    fn try_from(value: IdentityRetrievalModes) -> std::result::Result<Self, Self::Error> {
        Self::init(value)
    }
}

impl std::fmt::Display for HoprKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            format!(
                "packet_key: {}, chain_key: {} (Ethereum address: {})\nbjj_key: {}\nUUID: {}",
                self.packet_key.public().to_peerid_str(),
                self.chain_key.public().to_hex(),
                self.chain_key.public().to_address(),
                self.bjj_key.public(),
                self.id
            )
            .as_str(),
        )
    }
}

impl FromStr for HoprKeys {
    type Err = KeyPairError;

    /// Deserializes HoprKeys from string
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use hopr_types::keypair::key_pair::HoprKeys;
    /// use hopr_types::crypto_random::Randomizable;
    ///
    /// let keys = HoprKeys::random();
    /// let hex = format!("0x{}", const_hex::encode(&[
    ///     keys.packet_key.secret().as_ref(),
    ///     keys.chain_key.secret().as_ref(),
    ///     keys.bjj_key.secret().as_ref(),
    /// ].concat()));
    /// assert!(HoprKeys::from_str(&hex).is_ok());
    /// ```
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let maybe_priv_key = s.strip_prefix("0x").unwrap_or(s);

        if maybe_priv_key.len() != 2 * (PACKET_KEY_LENGTH + CHAIN_KEY_LENGTH + BJJ_KEY_LENGTH) {
            return Err(KeyPairError::InvalidPrivateKeySize {
                actual: maybe_priv_key.len(),
                expected: 2 * (PACKET_KEY_LENGTH + CHAIN_KEY_LENGTH + BJJ_KEY_LENGTH),
            });
        }

        let mut priv_key_raw = [0u8; PACKET_KEY_LENGTH + CHAIN_KEY_LENGTH + BJJ_KEY_LENGTH];
        const_hex::decode_to_slice(maybe_priv_key, &mut priv_key_raw[..])
            .map_err(|e| KeyPairError::HexParsingError(e.to_string()))?;

        priv_key_raw.try_into()
    }
}

impl TryFrom<[u8; PACKET_KEY_LENGTH + CHAIN_KEY_LENGTH + BJJ_KEY_LENGTH]> for HoprKeys {
    type Error = KeyPairError;

    fn try_from(
        value: [u8; CHAIN_KEY_LENGTH + PACKET_KEY_LENGTH + BJJ_KEY_LENGTH],
    ) -> std::result::Result<Self, Self::Error> {
        let mut packet_key = [0u8; PACKET_KEY_LENGTH];
        packet_key.copy_from_slice(&value[0..32]);
        let mut chain_key = [0u8; CHAIN_KEY_LENGTH];
        chain_key.copy_from_slice(&value[32..64]);
        let mut bjj_key = [0u8; BJJ_KEY_LENGTH];
        bjj_key.copy_from_slice(&value[64..96]);

        (packet_key, chain_key, bjj_key).try_into()
    }
}

impl
    TryFrom<(
        [u8; PACKET_KEY_LENGTH],
        [u8; CHAIN_KEY_LENGTH],
        [u8; BJJ_KEY_LENGTH],
    )> for HoprKeys
{
    type Error = KeyPairError;

    fn try_from(
        value: (
            [u8; PACKET_KEY_LENGTH],
            [u8; CHAIN_KEY_LENGTH],
            [u8; BJJ_KEY_LENGTH],
        ),
    ) -> std::result::Result<Self, Self::Error> {
        Ok(HoprKeys {
            packet_key: OffchainKeypair::from_secret(&value.0)?,
            chain_key: ChainKeypair::from_secret(&value.1)?,
            bjj_key: BjjKeypair::from_secret(&value.2)?,
            id: Uuid::new_v4(),
        })
    }
}

impl PartialEq for HoprKeys {
    fn eq(&self, other: &Self) -> bool {
        self.packet_key.public().eq(other.packet_key.public())
            && self.chain_key.public().eq(other.chain_key.public())
            && self.bjj_key.public().eq(other.bjj_key.public())
    }
}

impl Randomizable for HoprKeys {
    fn random() -> Self {
        Self {
            packet_key: OffchainKeypair::random(),
            chain_key: ChainKeypair::random(),
            bjj_key: BjjKeypair::random(),
            id: Uuid::new_v4(),
        }
    }
}

impl HoprKeys {
    fn init(retrieval_mode: IdentityRetrievalModes) -> Result<Self> {
        match retrieval_mode {
            IdentityRetrievalModes::FromFile { password, id_path } => {
                let identity_file_exists = fs::metadata(id_path).is_ok();

                if identity_file_exists {
                    tracing::info!(file_path = %id_path, "found existing identity file");

                    match HoprKeys::read_eth_keystore(id_path, password) {
                        Ok((keys, needs_migration)) => {
                            tracing::info!(needs_migration, "status");
                            if needs_migration {
                                keys.write_eth_keystore(id_path, password)?
                            }
                            Ok(keys)
                        }
                        Err(e) => Err(KeyPairError::GeneralError(format!(
                            "An identity file is present at {id_path} but the provided password <REDACTED> is not \
                             sufficient to decrypt it {e}"
                        ))),
                    }
                } else {
                    let keys = HoprKeys::random();

                    tracing::info!(file_path = %id_path, %keys, "created new keypairs");

                    keys.write_eth_keystore(id_path, password)?;
                    Ok(keys)
                }
            }
            IdentityRetrievalModes::FromPrivateKey { private_key } => {
                tracing::info!("initializing HoprKeys with provided private keys <REDACTED>");

                private_key.parse()
            }
            #[cfg(any(feature = "keypair-to-file", test))]
            IdentityRetrievalModes::FromIdIntoFile {
                id,
                password,
                id_path,
            } => {
                let identity_file_exists = fs::metadata(id_path).is_ok();

                if identity_file_exists {
                    tracing::info!(file_path = %id_path, "found an existing identity file");

                    Err(KeyPairError::GeneralError(format!(
                        "Cannot create identity file at {id_path} because the file already exists."
                    )))
                } else {
                    let keys: HoprKeys = HoprKeys {
                        id,
                        packet_key: OffchainKeypair::random(),
                        chain_key: ChainKeypair::random(),
                        bjj_key: BjjKeypair::random(),
                    };

                    keys.write_eth_keystore(id_path, password)?;

                    Ok(keys)
                }
            }
        }
    }

    pub fn read_eth_keystore(path: &str, password: &str) -> Result<(Self, bool)> {
        let json_string = fs::read_to_string(path)?;
        let keystore: EthKeystore = from_json_string(&json_string)?;

        let key = match keystore.crypto.kdfparams {
            KdfparamsType::Scrypt {
                dklen,
                n,
                p,
                r,
                salt,
            } => {
                let mut key = vec![0u8; dklen as usize];
                let log_n = (n as f32).log2() as u8;
                let scrypt_params = ScryptParams::new_with_output_len(log_n, r, p, dklen.into())
                    .map_err(|err| KeyPairError::KeyDerivationError(err.to_string()))?;
                scrypt(password.as_ref(), &salt, &scrypt_params, &mut key)
                    .map_err(|err| KeyPairError::KeyDerivationError(err.to_string()))?;
                key
            }
            _ => panic!("HOPR only supports scrypt"),
        };

        let derived_mac = Keccak256::new()
            .chain(&key[16..32])
            .chain(&keystore.crypto.ciphertext)
            .finalize();

        if *derived_mac != *keystore.crypto.mac {
            return Err(KeyPairError::MacMismatch);
        }

        let mut decryptor =
            Aes128Ctr::new_from_slices(&key[..16], &keystore.crypto.cipherparams.iv[..16])
                .map_err(|_| KeyPairError::KeyDerivationError("invalid key or iv length".into()))?;

        let mut pk = keystore.crypto.ciphertext;

        match pk.len() {
            V1_PRIVKEY_LENGTH => {
                decryptor.apply_keystream(&mut pk);

                let packet_key: [u8; PACKET_KEY_LENGTH] = random_bytes();

                let mut chain_key = [0u8; CHAIN_KEY_LENGTH];
                chain_key.clone_from_slice(&pk.as_slice()[0..CHAIN_KEY_LENGTH]);

                let ret = HoprKeys {
                    packet_key: OffchainKeypair::from_secret(&packet_key)?,
                    chain_key: ChainKeypair::from_secret(&chain_key)?,
                    bjj_key: BjjKeypair::random(),
                    id: Uuid::new_v4(),
                };

                Ok((ret, true))
            }
            _ => {
                // V2 or V3 encrypted format: decrypt and parse PrivateKeys
                decryptor.apply_keystream(&mut pk);

                let private_keys = serde_json::from_slice::<PrivateKeys>(&pk)?;

                if private_keys.packet_key.len() != PACKET_KEY_LENGTH {
                    return Err(KeyPairError::InvalidEncryptedKeyLength {
                        actual: private_keys.packet_key.len(),
                        expected: PACKET_KEY_LENGTH,
                    });
                }

                if private_keys.chain_key.len() != CHAIN_KEY_LENGTH {
                    return Err(KeyPairError::InvalidEncryptedKeyLength {
                        actual: private_keys.chain_key.len(),
                        expected: CHAIN_KEY_LENGTH,
                    });
                }

                let mut packet_key = [0u8; PACKET_KEY_LENGTH];
                packet_key.clone_from_slice(private_keys.packet_key.as_slice());

                let mut chain_key = [0u8; CHAIN_KEY_LENGTH];
                chain_key.clone_from_slice(private_keys.chain_key.as_slice());

                let (bjj_key, needs_migration) =
                    if private_keys.babyjubjub_key.len() == BJJ_KEY_LENGTH {
                        let mut bjj = [0u8; BJJ_KEY_LENGTH];
                        bjj.clone_from_slice(private_keys.babyjubjub_key.as_slice());
                        (bjj, false)
                    } else if private_keys.babyjubjub_key.is_empty() {
                        // V2 keystore without BJJ key: generate a random one
                        let random_bjj = BjjKeypair::random();
                        let mut bjj = [0u8; BJJ_KEY_LENGTH];
                        bjj.clone_from_slice(random_bjj.secret().as_ref());
                        (bjj, true)
                    } else {
                        return Err(KeyPairError::InvalidEncryptedKeyLength {
                            actual: private_keys.babyjubjub_key.len(),
                            expected: BJJ_KEY_LENGTH,
                        });
                    };

                Ok((
                    HoprKeys {
                        packet_key: OffchainKeypair::from_secret(&packet_key)?,
                        chain_key: ChainKeypair::from_secret(&chain_key)?,
                        bjj_key: BjjKeypair::from_secret(&bjj_key)?,
                        id: keystore.id,
                    },
                    needs_migration,
                ))
            }
        }
    }

    pub fn write_eth_keystore(&self, path: &str, password: &str) -> Result<()> {
        let salt: [u8; HOPR_KEY_SIZE] = random_bytes();

        let mut key = [0u8; HOPR_KDF_PARAMS_DKLEN as usize];
        let scrypt_params = ScryptParams::new_with_output_len(
            HOPR_KDF_PARAMS_LOG_N,
            HOPR_KDF_PARAMS_R,
            HOPR_KDF_PARAMS_P,
            HOPR_KDF_PARAMS_DKLEN.into(),
        )
        .map_err(|e| KeyPairError::KeyDerivationError(e.to_string()))?;

        scrypt(password.as_ref(), &salt, &scrypt_params, &mut key)
            .map_err(|e| KeyPairError::KeyDerivationError(e.to_string()))?;

        let iv: [u8; HOPR_IV_SIZE] = random_bytes();

        let mut encryptor = Aes128Ctr::new_from_slices(&key[..16], &iv[..16])
            .map_err(|_| KeyPairError::KeyDerivationError("invalid key or iv".into()))?;

        let private_keys = PrivateKeys {
            chain_key: self.chain_key.secret().as_ref().to_vec(),
            packet_key: self.packet_key.secret().as_ref().to_vec(),
            babyjubjub_key: self.bjj_key.secret().as_ref().to_vec(),
            version: VERSION,
        };

        let mut ciphertext = serde_json::to_vec(&private_keys)?;
        encryptor.apply_keystream(&mut ciphertext);

        let mac = Keccak256::new()
            .chain(&key[16..32])
            .chain(&ciphertext)
            .finalize();

        let keystore = EthKeystore {
            id: self.id,
            version: 3,
            crypto: CryptoJson {
                cipher: String::from(HOPR_CIPHER),
                cipherparams: CipherparamsJson { iv: iv.to_vec() },
                ciphertext,
                kdf: KdfType::Scrypt,
                kdfparams: KdfparamsType::Scrypt {
                    dklen: HOPR_KDF_PARAMS_DKLEN,
                    n: 2_u32.pow(HOPR_KDF_PARAMS_LOG_N as u32),
                    p: HOPR_KDF_PARAMS_P,
                    r: HOPR_KDF_PARAMS_R,
                    salt: salt.to_vec(),
                },
                mac: mac.to_vec(),
            },
        };

        let serialized = to_json_string(&keystore)?;

        if let Some(parent) = Path::new(path).parent()
            && !parent.is_dir()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serialized)?;
        Ok(())
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn bjj_key(&self) -> &BjjKeypair {
        &self.bjj_key
    }
}

impl Debug for HoprKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoprKeys")
            .field(
                "packet_key",
                &format_args!(
                    "(priv_key: <REDACTED>, pub_key: {}",
                    self.packet_key.public().to_hex()
                ),
            )
            .field(
                "chain_key",
                &format_args!(
                    "(priv_key: <REDACTED>, pub_key: {}",
                    self.chain_key.public().to_hex()
                ),
            )
            .field(
                "bjj_key",
                &format_args!(
                    "(priv_key: <REDACTED>, pub_key: {}",
                    self.bjj_key.public().to_hex()
                ),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{crypto::prelude::*, crypto_random::Randomizable};
    use anyhow::Context;
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;

    const DEFAULT_PASSWORD: &str = "dummy password for unit testing";

    #[test]
    fn create_keys() {
        println!("{:?}", HoprKeys::random())
    }

    #[test]
    fn store_keys_and_read_them() -> anyhow::Result<()> {
        let tmp = tempdir()?;

        let identity_dir = tmp.path().join("hopr-unit-test-identity");

        let keys = HoprKeys::random();

        keys.write_eth_keystore(
            identity_dir
                .to_str()
                .context("should be convertible to string")?,
            DEFAULT_PASSWORD,
        )?;

        let (deserialized, needs_migration) = HoprKeys::read_eth_keystore(
            identity_dir
                .to_str()
                .context("should be convertible to string")?,
            DEFAULT_PASSWORD,
        )?;

        assert!(!needs_migration);
        assert_eq!(deserialized, keys);

        Ok(())
    }

    #[test]
    fn test_migration() -> anyhow::Result<()> {
        let tmp = tempdir()?;

        let identity_dir = tmp.path().join("hopr-unit-test-identity");

        let old_keystore_file = r#"{"id":"8e5fe142-6ef9-4fbb-aae8-5de32b680e31","version":3,"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"04141354edb9dfb0c65e6905a3a0b9dd"},"ciphertext":"74f12f72cf2d3d73ff09f783cb9b57995b3808f7d3f71aa1fa1968696aedfbdd","kdf":"scrypt","kdfparams":{"salt":"f5e3f04eaa0c9efffcb5168c6735d7e1fe4d96f48a636c4f00107e7c34722f45","n":1,"dklen":32,"p":1,"r":8},"mac":"d0daf0e5d14a2841f0f7221014d805addfb7609d85329d4c6424a098e50b6fbe"}}"#;

        fs::write(
            identity_dir
                .to_str()
                .context("should be convertible to string")?,
            old_keystore_file.as_bytes(),
        )?;

        let (deserialized, needs_migration) = HoprKeys::read_eth_keystore(
            identity_dir
                .to_str()
                .context("should be convertible to string")?,
            "local",
        )?;

        assert!(needs_migration);
        assert_eq!(
            deserialized.chain_key.public().to_address().to_string(),
            "0x826a1bf3d51fa7f402a1e01d1b2c8a8bac28e666"
        );

        Ok(())
    }

    #[test]
    fn test_auto_migration() -> anyhow::Result<()> {
        let tmp = tempdir()?;
        let identity_dir = tmp.path().join("hopr-unit-test-identity");
        let identity_path: &str = identity_dir
            .to_str()
            .context("should be convertible to string")?;

        let old_keystore_file = r#"{"id":"8e5fe142-6ef9-4fbb-aae8-5de32b680e31","version":3,"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"04141354edb9dfb0c65e6905a3a0b9dd"},"ciphertext":"74f12f72cf2d3d73ff09f783cb9b57995b3808f7d3f71aa1fa1968696aedfbdd","kdf":"scrypt","kdfparams":{"salt":"f5e3f04eaa0c9efffcb5168c6735d7e1fe4d96f48a636c4f00107e7c34722f45","n":1,"dklen":32,"p":1,"r":8},"mac":"d0daf0e5d14a2841f0f7221014d805addfb7609d85329d4c6424a098e50b6fbe"}}"#;
        fs::write(identity_path, old_keystore_file.as_bytes())?;

        assert!(
            HoprKeys::init(IdentityRetrievalModes::FromFile {
                password: "local",
                id_path: identity_path
            })
            .is_ok()
        );

        let (deserialized, needs_migration) = HoprKeys::read_eth_keystore(identity_path, "local")?;

        assert!(!needs_migration);
        assert_eq!(
            deserialized.chain_key.public().to_address().to_string(),
            "0x826a1bf3d51fa7f402a1e01d1b2c8a8bac28e666"
        );

        Ok(())
    }

    #[test]
    fn test_should_not_overwrite_existing() -> anyhow::Result<()> {
        let tmp = tempdir()?;
        let identity_dir = tmp.path().join("hopr-unit-test-identity");
        let identity_path: &str = identity_dir
            .to_str()
            .context("should be convertible to string")?;

        fs::write(identity_path, "".as_bytes())?;

        assert!(
            super::HoprKeys::init(IdentityRetrievalModes::FromFile {
                password: "local",
                id_path: identity_path
            })
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn test_from_privatekey() {
        // Generate valid keys and serialize their secrets to hex
        let keys = HoprKeys::random();

        let mut combined = [0u8; PACKET_KEY_LENGTH + CHAIN_KEY_LENGTH + BJJ_KEY_LENGTH];
        combined[0..32].copy_from_slice(keys.packet_key.secret().as_ref());
        combined[32..64].copy_from_slice(keys.chain_key.secret().as_ref());
        combined[64..96].copy_from_slice(keys.bjj_key.secret().as_ref());

        let hex_with_prefix = format!("0x{}", const_hex::encode(&combined));
        let hex_without_prefix = const_hex::encode(&combined);

        let from_prefix = HoprKeys::init(IdentityRetrievalModes::FromPrivateKey {
            private_key: &hex_with_prefix,
        })
        .unwrap();

        let from_without_prefix = HoprKeys::init(IdentityRetrievalModes::FromPrivateKey {
            private_key: &hex_without_prefix,
        })
        .unwrap();

        assert_eq!(from_prefix, from_without_prefix);
        assert_eq!(from_prefix, keys);
    }

    #[test]
    fn test_from_privatekey_into_file() -> anyhow::Result<()> {
        let tmp = tempdir()?;
        let identity_dir = tmp.path().join("hopr-unit-test-identity");
        let identity_path = identity_dir
            .to_str()
            .context("should be convertible to string")?;
        let id = Uuid::new_v4();

        let keys = HoprKeys::init(IdentityRetrievalModes::FromIdIntoFile {
            password: "local",
            id_path: identity_path,
            id,
        })
        .expect("should initialize new key");

        let (deserialized, needs_migration) =
            HoprKeys::read_eth_keystore(identity_path, "local").unwrap();

        assert!(!needs_migration);
        assert_eq!(
            deserialized.chain_key.public().to_address(),
            keys.chain_key.public().to_address()
        );

        assert!(
            HoprKeys::init(IdentityRetrievalModes::FromIdIntoFile {
                password: "local",
                id_path: identity_path,
                id
            })
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn test_bjj_in_keys() -> anyhow::Result<()> {
        let tmp = tempdir()?;

        let identity_dir = tmp.path().join("hopr-unit-test-identity");

        let keys = HoprKeys::random();

        // Verify BJJ key is present (not zeroed out)
        assert!(
            keys.bjj_key.public().as_ref().iter().any(|&b| b != 0),
            "BJJ public key should not be all zeros"
        );

        keys.write_eth_keystore(
            identity_dir
                .to_str()
                .context("should be convertible to string")?,
            DEFAULT_PASSWORD,
        )?;

        let (deserialized, needs_migration) = HoprKeys::read_eth_keystore(
            identity_dir
                .to_str()
                .context("should be convertible to string")?,
            DEFAULT_PASSWORD,
        )?;

        assert!(!needs_migration);
        assert_eq!(deserialized, keys);
        assert_eq!(deserialized.bjj_key.public(), keys.bjj_key.public());

        Ok(())
    }

    #[test]
    fn test_bjj_key_accessor() -> anyhow::Result<()> {
        let keys = HoprKeys::random();
        let bjj = keys.bjj_key();
        assert_eq!(bjj.public(), keys.bjj_key.public());
        Ok(())
    }

    #[test]
    fn test_from_privatekey_roundtrip() -> anyhow::Result<()> {
        let keys = HoprKeys::random();

        // Serialize to combined byte array and back
        let mut combined = [0u8; PACKET_KEY_LENGTH + CHAIN_KEY_LENGTH + BJJ_KEY_LENGTH];
        combined[0..32].copy_from_slice(keys.packet_key.secret().as_ref());
        combined[32..64].copy_from_slice(keys.chain_key.secret().as_ref());
        combined[64..96].copy_from_slice(keys.bjj_key.secret().as_ref());

        let deserialized: HoprKeys = combined.try_into()?;
        assert_eq!(deserialized, keys);

        Ok(())
    }
}
