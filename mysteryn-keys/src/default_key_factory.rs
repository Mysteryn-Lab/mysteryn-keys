use mysteryn_core::{
    attributes::{KeyAttributes, SignatureAttributes},
    key_traits::{KeyFactory, PublicKeyTrait, SecretKeyTrait, SignatureTrait, SupportedAlgorithm},
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::{Error, Result},
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "bls12381")]
use super::bls12381g1::{Bls12381G1PublicKey, Bls12381G1SecretKey, Bls12381G1Signature};
#[cfg(feature = "ed448")]
use super::ed448::{Ed448PublicKey, Ed448SecretKey, Ed448Signature};
#[cfg(feature = "ed25519")]
use super::ed25519::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
#[cfg(feature = "faest")]
use super::faest128f::{Faest128fPublicKey, Faest128fSecretKey, Faest128fSignature};
#[cfg(feature = "falcon")]
use super::falcon512::{Falcon512PublicKey, Falcon512SecretKey, Falcon512Signature};
#[cfg(feature = "falcon")]
use super::falcon1024::{Falcon1024PublicKey, Falcon1024SecretKey, Falcon1024Signature};
#[cfg(feature = "hmac")]
use super::hmac_sha256::{HmacSha256PublicKey, HmacSha256SecretKey, HmacSha256Signature};
#[cfg(feature = "mldsa")]
use super::mldsa44::{MlDsa44PublicKey, MlDsa44SecretKey, MlDsa44Signature};
#[cfg(feature = "mldsa")]
use super::mldsa65::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
#[cfg(all(feature = "mldsa", not(target_family = "wasm")))]
use super::mldsa87::{MlDsa87PublicKey, MlDsa87SecretKey, MlDsa87Signature};
#[cfg(feature = "mlkem")]
use super::mlkem512::{MlKem512PublicKey, MlKem512SecretKey, MlKem512Signature};
#[cfg(feature = "p256")]
use super::p256::{P256PublicKey, P256SecretKey, P256Signature};
#[cfg(feature = "p384")]
use super::p384::{P384PublicKey, P384SecretKey, P384Signature};
#[cfg(feature = "p521")]
use super::p521::{P521PublicKey, P521SecretKey, P521Signature};
#[cfg(feature = "rsa")]
use super::rsa::{
    Rs256PublicKey, Rs256SecretKey, Rs256Signature, Rs512PublicKey, Rs512SecretKey, Rs512Signature,
};
#[cfg(feature = "secp256k1")]
use super::secp256k1::{Secp256k1PublicKey, Secp256k1SecretKey, Secp256k1Signature};
#[cfg(feature = "slhdsa")]
use super::slhdsashake128f::{
    SlhDsaShake128fPublicKey, SlhDsaShake128fSecretKey, SlhDsaShake128fSignature,
};
#[cfg(feature = "x25519")]
use super::x25519::{X25519PublicKey, X25519SecretKey, X25519Signature};
#[cfg(feature = "rsa")]
use mysteryn_core::attributes::HASH_ATTR_ID;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultKeyFactory;

impl KeyFactory for DefaultKeyFactory {
    fn new_secret(algorithm: u64, attributes: &KeyAttributes) -> Result<Box<dyn SecretKeyTrait>> {
        match algorithm {
            #[cfg(feature = "ed25519")]
            multicodec_prefix::ED25519_SECRET => Ok(Box::new(Ed25519SecretKey::new())),
            #[cfg(feature = "ed448")]
            multicodec_prefix::ED448_SECRET => Ok(Box::new(Ed448SecretKey::new())),
            #[cfg(feature = "p256")]
            multicodec_prefix::P256_SECRET => Ok(Box::new(P256SecretKey::new())),
            #[cfg(feature = "p384")]
            multicodec_prefix::P384_SECRET => Ok(Box::new(P384SecretKey::new())),
            #[cfg(feature = "p521")]
            multicodec_prefix::P521_SECRET => Ok(Box::new(P521SecretKey::new())),
            #[cfg(feature = "rsa")]
            multicodec_prefix::RSA_SECRET => {
                let Some(hash_agorithm) = attributes.get_varint(HASH_ATTR_ID)? else {
                    return Err(Error::ValidationError(
                        "RSA requires hash algorithm".to_string(),
                    ));
                };
                match hash_agorithm {
                    multicodec_prefix::SHA2_256 => Ok(Box::new(Rs256SecretKey::new())),
                    multicodec_prefix::SHA2_512 => Ok(Box::new(Rs512SecretKey::new())),
                    _ => {
                        return Err(Error::ValidationError(format!(
                            "unsupported RSA hash algorithm {hash_agorithm}"
                        )));
                    }
                }
            }
            #[cfg(feature = "secp256k1")]
            multicodec_prefix::SECP256K1_SECRET => Ok(Box::new(Secp256k1SecretKey::new())),
            #[cfg(feature = "bls12381")]
            multicodec_prefix::BLS12381G1_SECRET => Ok(Box::new(Bls12381G1SecretKey::new())),
            #[cfg(feature = "x25519")]
            multicodec_prefix::X25519_SECRET => Ok(Box::new(X25519SecretKey::new())),
            #[cfg(feature = "mlkem")]
            multicodec_prefix::MLKEM512_SECRET => Ok(Box::new(MlKem512SecretKey::new())),
            multicodec_prefix::CUSTOM => {
                let Some(custom_key_algorithm) = attributes.get_algorithm_name()? else {
                    return Err(Error::ValidationError(
                        "custom key algorithm required".to_string(),
                    ));
                };
                match custom_key_algorithm {
                    #[cfg(feature = "hmac")]
                    known_algorithm_name::HMAC_SHA256 => Ok(Box::new(HmacSha256SecretKey::new())),
                    #[cfg(feature = "slhdsa")]
                    known_algorithm_name::SLHDSASHAKE128f => {
                        Ok(Box::new(SlhDsaShake128fSecretKey::new()))
                    }
                    #[cfg(feature = "faest")]
                    known_algorithm_name::FAEST128f => Ok(Box::new(Faest128fSecretKey::new())),
                    #[cfg(feature = "falcon")]
                    known_algorithm_name::Falcon512 => Ok(Box::new(Falcon512SecretKey::new())),
                    #[cfg(feature = "falcon")]
                    known_algorithm_name::Falcon1024 => Ok(Box::new(Falcon1024SecretKey::new())),
                    #[cfg(feature = "mldsa")]
                    known_algorithm_name::MLDSA44 => Ok(Box::new(MlDsa44SecretKey::new())),
                    #[cfg(feature = "mldsa")]
                    known_algorithm_name::MLDSA65 => Ok(Box::new(MlDsa65SecretKey::new())),
                    #[cfg(all(feature = "mldsa", not(target_family = "wasm")))]
                    known_algorithm_name::MLDSA87 => Ok(Box::new(MlDsa87SecretKey::new())),
                    _ => Err(Error::EncodingError(format!(
                        "unsupported custom algorithm {custom_key_algorithm}"
                    ))),
                }
            }
            _ => Err(Error::ValidationError(format!(
                "algorithm 0x{algorithm:02x} is not supported"
            ))),
        }
    }

    fn secret_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        attributes: &KeyAttributes,
    ) -> Result<Box<dyn SecretKeyTrait>> {
        match algorithm {
            #[cfg(feature = "ed25519")]
            multicodec_prefix::ED25519_SECRET => Ok(Box::new(Ed25519SecretKey::try_from(bytes)?)),
            #[cfg(feature = "ed448")]
            multicodec_prefix::ED448_SECRET => Ok(Box::new(Ed448SecretKey::try_from(bytes)?)),
            #[cfg(feature = "p256")]
            multicodec_prefix::P256_SECRET => Ok(Box::new(P256SecretKey::try_from(bytes)?)),
            #[cfg(feature = "p384")]
            multicodec_prefix::P384_SECRET => Ok(Box::new(P384SecretKey::try_from(bytes)?)),
            #[cfg(feature = "p521")]
            multicodec_prefix::P521_SECRET => Ok(Box::new(P521SecretKey::try_from(bytes)?)),
            #[cfg(feature = "rsa")]
            multicodec_prefix::RSA_SECRET => {
                let Some(hash_agorithm) = attributes.get_varint(HASH_ATTR_ID)? else {
                    return Err(Error::ValidationError(
                        "RSA requires hash algorithm".to_string(),
                    ));
                };
                match hash_agorithm {
                    multicodec_prefix::SHA2_256 => Ok(Box::new(Rs256SecretKey::try_from(bytes)?)),
                    multicodec_prefix::SHA2_512 => Ok(Box::new(Rs512SecretKey::try_from(bytes)?)),
                    _ => {
                        return Err(Error::ValidationError(format!(
                            "unsupported RSA hash algorithm {hash_agorithm}"
                        )));
                    }
                }
            }
            #[cfg(feature = "secp256k1")]
            multicodec_prefix::SECP256K1_SECRET => {
                Ok(Box::new(Secp256k1SecretKey::try_from(bytes)?))
            }
            #[cfg(feature = "bls12381")]
            multicodec_prefix::BLS12381G1_SECRET => {
                Ok(Box::new(Bls12381G1SecretKey::try_from(bytes)?))
            }
            #[cfg(feature = "x25519")]
            multicodec_prefix::X25519_SECRET => Ok(Box::new(X25519SecretKey::try_from(bytes)?)),
            #[cfg(feature = "mlkem")]
            multicodec_prefix::MLKEM512_SECRET => Ok(Box::new(MlKem512SecretKey::try_from(bytes)?)),
            multicodec_prefix::CUSTOM => {
                let Some(custom_key_algorithm) = attributes.get_algorithm_name()? else {
                    return Err(Error::ValidationError(
                        "custom key algorithm required".to_string(),
                    ));
                };
                match custom_key_algorithm {
                    #[cfg(feature = "hmac")]
                    known_algorithm_name::HMAC_SHA256 => {
                        Ok(Box::new(HmacSha256SecretKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "slhdsa")]
                    known_algorithm_name::SLHDSASHAKE128f => {
                        Ok(Box::new(SlhDsaShake128fSecretKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "faest")]
                    known_algorithm_name::FAEST128f => {
                        Ok(Box::new(Faest128fSecretKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "falcon")]
                    known_algorithm_name::Falcon512 => {
                        Ok(Box::new(Falcon512SecretKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "falcon")]
                    known_algorithm_name::Falcon1024 => {
                        Ok(Box::new(Falcon1024SecretKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "mldsa")]
                    known_algorithm_name::MLDSA44 => {
                        Ok(Box::new(MlDsa44SecretKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "mldsa")]
                    known_algorithm_name::MLDSA65 => {
                        Ok(Box::new(MlDsa65SecretKey::try_from(bytes)?))
                    }
                    #[cfg(all(feature = "mldsa", not(target_family = "wasm")))]
                    known_algorithm_name::MLDSA87 => {
                        Ok(Box::new(MlDsa87SecretKey::try_from(bytes)?))
                    }
                    _ => Err(Error::EncodingError(format!(
                        "unsupported custom algorithm {custom_key_algorithm}"
                    ))),
                }
            }
            _ => Err(Error::ValidationError(format!(
                "algorithm 0x{algorithm:02x} is not supported"
            ))),
        }
    }

    fn public_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        attributes: &KeyAttributes,
    ) -> Result<Box<dyn PublicKeyTrait>> {
        match algorithm {
            #[cfg(feature = "ed25519")]
            multicodec_prefix::ED25519 => Ok(Box::new(Ed25519PublicKey::try_from(bytes)?)),
            #[cfg(feature = "ed448")]
            multicodec_prefix::ED448 => Ok(Box::new(Ed448PublicKey::try_from(bytes)?)),
            #[cfg(feature = "p256")]
            multicodec_prefix::P256 => Ok(Box::new(P256PublicKey::try_from(bytes)?)),
            #[cfg(feature = "p384")]
            multicodec_prefix::P384 => Ok(Box::new(P384PublicKey::try_from(bytes)?)),
            #[cfg(feature = "p521")]
            multicodec_prefix::P521 => Ok(Box::new(P521PublicKey::try_from(bytes)?)),
            #[cfg(feature = "rsa")]
            multicodec_prefix::RSA => {
                let Some(hash_agorithm) = attributes.get_varint(HASH_ATTR_ID)? else {
                    return Err(Error::ValidationError(
                        "RSA requires hash algorithm".to_string(),
                    ));
                };
                match hash_agorithm {
                    multicodec_prefix::SHA2_256 => Ok(Box::new(Rs256PublicKey::try_from(bytes)?)),
                    multicodec_prefix::SHA2_512 => Ok(Box::new(Rs512PublicKey::try_from(bytes)?)),
                    _ => {
                        return Err(Error::ValidationError(format!(
                            "unsupported RSA hash algorithm {hash_agorithm}"
                        )));
                    }
                }
            }
            #[cfg(feature = "secp256k1")]
            multicodec_prefix::SECP256K1 => Ok(Box::new(Secp256k1PublicKey::try_from(bytes)?)),
            #[cfg(feature = "bls12381")]
            multicodec_prefix::BLS12381G1 => Ok(Box::new(Bls12381G1PublicKey::try_from(bytes)?)),
            #[cfg(feature = "x25519")]
            multicodec_prefix::X25519 => Ok(Box::new(X25519PublicKey::try_from(bytes)?)),
            #[cfg(feature = "mlkem")]
            multicodec_prefix::MLKEM512 => Ok(Box::new(MlKem512PublicKey::try_from(bytes)?)),
            multicodec_prefix::CUSTOM => {
                let Some(custom_key_algorithm) = attributes.get_algorithm_name()? else {
                    return Err(Error::ValidationError(
                        "custom key algorithm required".to_string(),
                    ));
                };
                match custom_key_algorithm {
                    #[cfg(feature = "hmac")]
                    known_algorithm_name::HMAC_SHA256 => {
                        Ok(Box::new(HmacSha256PublicKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "slhdsa")]
                    known_algorithm_name::SLHDSASHAKE128f => {
                        Ok(Box::new(SlhDsaShake128fPublicKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "faest")]
                    known_algorithm_name::FAEST128f => {
                        Ok(Box::new(Faest128fPublicKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "falcon")]
                    known_algorithm_name::Falcon512 => {
                        Ok(Box::new(Falcon512PublicKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "falcon")]
                    known_algorithm_name::Falcon1024 => {
                        Ok(Box::new(Falcon1024PublicKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "mldsa")]
                    known_algorithm_name::MLDSA44 => {
                        Ok(Box::new(MlDsa44PublicKey::try_from(bytes)?))
                    }
                    #[cfg(feature = "mldsa")]
                    known_algorithm_name::MLDSA65 => {
                        Ok(Box::new(MlDsa65PublicKey::try_from(bytes)?))
                    }
                    #[cfg(all(feature = "mldsa", not(target_family = "wasm")))]
                    known_algorithm_name::MLDSA87 => {
                        Ok(Box::new(MlDsa87PublicKey::try_from(bytes)?))
                    }
                    _ => Err(Error::EncodingError(format!(
                        "unsupported custom algorithm {custom_key_algorithm}"
                    ))),
                }
            }
            _ => Err(Error::ValidationError(format!(
                "algorithm 0x{algorithm:02x} is not supported"
            ))),
        }
    }

    fn signature_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        attributes: &SignatureAttributes,
    ) -> Result<Box<dyn SignatureTrait>> {
        match algorithm {
            #[cfg(feature = "ed25519")]
            multicodec_prefix::ED25519 => Ok(Box::new(Ed25519Signature::try_from(bytes)?)),
            #[cfg(feature = "ed448")]
            multicodec_prefix::ED448 => Ok(Box::new(Ed448Signature::try_from(bytes)?)),
            #[cfg(feature = "p256")]
            multicodec_prefix::P256 => Ok(Box::new(P256Signature::try_from(bytes)?)),
            #[cfg(feature = "p384")]
            multicodec_prefix::P384 => Ok(Box::new(P384Signature::try_from(bytes)?)),
            #[cfg(feature = "p521")]
            multicodec_prefix::P521 => Ok(Box::new(P521Signature::try_from(bytes)?)),
            #[cfg(feature = "rsa")]
            multicodec_prefix::RSA => {
                let Some(hash_agorithm) = attributes.get_varint(HASH_ATTR_ID)? else {
                    return Err(Error::ValidationError(
                        "RSA requires hash algorithm".to_string(),
                    ));
                };
                match hash_agorithm {
                    multicodec_prefix::SHA2_256 => Ok(Box::new(Rs256Signature::try_from(bytes)?)),
                    multicodec_prefix::SHA2_512 => Ok(Box::new(Rs512Signature::try_from(bytes)?)),
                    _ => {
                        return Err(Error::ValidationError(format!(
                            "unsupported RSA hash algorithm {hash_agorithm}"
                        )));
                    }
                }
            }
            #[cfg(feature = "secp256k1")]
            multicodec_prefix::SECP256K1 => Ok(Box::new(Secp256k1Signature::try_from(bytes)?)),
            #[cfg(feature = "bls12381")]
            multicodec_prefix::BLS12381G1 => Ok(Box::new(Bls12381G1Signature::try_from(bytes)?)),
            #[cfg(feature = "x25519")]
            multicodec_prefix::X25519 => Ok(Box::new(X25519Signature::try_from(bytes)?)),
            #[cfg(feature = "mlkem")]
            multicodec_prefix::MLKEM512 => Ok(Box::new(MlKem512Signature::try_from(bytes)?)),
            multicodec_prefix::CUSTOM => {
                let Some(custom_key_algorithm) = attributes.get_algorithm_name()? else {
                    return Err(Error::ValidationError(
                        "custom key algorithm required".to_string(),
                    ));
                };
                match custom_key_algorithm {
                    #[cfg(feature = "slhdsa")]
                    known_algorithm_name::SLHDSASHAKE128f => {
                        Ok(Box::new(SlhDsaShake128fSignature::try_from(bytes)?))
                    }
                    #[cfg(feature = "faest")]
                    known_algorithm_name::FAEST128f => {
                        Ok(Box::new(Faest128fSignature::try_from(bytes)?))
                    }
                    #[cfg(feature = "falcon")]
                    known_algorithm_name::Falcon512 => {
                        Ok(Box::new(Falcon512Signature::try_from(bytes)?))
                    }
                    #[cfg(feature = "falcon")]
                    known_algorithm_name::Falcon1024 => {
                        Ok(Box::new(Falcon1024Signature::try_from(bytes)?))
                    }
                    #[cfg(feature = "mldsa")]
                    known_algorithm_name::MLDSA44 => {
                        Ok(Box::new(MlDsa44Signature::try_from(bytes)?))
                    }
                    #[cfg(feature = "mldsa")]
                    known_algorithm_name::MLDSA65 => {
                        Ok(Box::new(MlDsa65Signature::try_from(bytes)?))
                    }
                    #[cfg(all(feature = "mldsa", not(target_family = "wasm")))]
                    known_algorithm_name::MLDSA87 => {
                        Ok(Box::new(MlDsa87Signature::try_from(bytes)?))
                    }
                    #[cfg(feature = "hmac")]
                    known_algorithm_name::HMAC_SHA256 => {
                        Ok(Box::new(HmacSha256Signature::try_from(bytes)?))
                    }
                    _ => Err(Error::EncodingError(format!(
                        "unsupported custom algorithm {custom_key_algorithm}"
                    ))),
                }
            }
            _ => Err(Error::ValidationError(format!(
                "algorithm 0x{algorithm:02x} is not supported"
            ))),
        }
    }

    fn list_supported() -> Vec<SupportedAlgorithm> {
        vec![
            #[cfg(feature = "ed25519")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::EdDSA.to_string(),
                secret_codec: multicodec_prefix::ED25519_SECRET,
                codec: multicodec_prefix::ED25519,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "ed448")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::Ed448.to_string(),
                secret_codec: multicodec_prefix::ED448_SECRET,
                codec: multicodec_prefix::ED448,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "p256")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::ES256.to_string(),
                secret_codec: multicodec_prefix::P256_SECRET,
                codec: multicodec_prefix::P256,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "p384")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::ES384.to_string(),
                secret_codec: multicodec_prefix::P384_SECRET,
                codec: multicodec_prefix::P384,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "p521")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::ES512.to_string(),
                secret_codec: multicodec_prefix::P521_SECRET,
                codec: multicodec_prefix::P521,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "rsa")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::RS256.to_string(),
                secret_codec: multicodec_prefix::RSA_SECRET,
                codec: multicodec_prefix::RSA,
                key_exchange: false,
                public_verify: true,
            },
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::RS512.to_string(),
                secret_codec: multicodec_prefix::RSA_SECRET,
                codec: multicodec_prefix::RSA,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "secp256k1")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::ES256K.to_string(),
                secret_codec: multicodec_prefix::SECP256K1_SECRET,
                codec: multicodec_prefix::SECP256K1,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "bls12381")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::Bls12381G1.to_string(),
                secret_codec: multicodec_prefix::BLS12381G1_SECRET,
                codec: multicodec_prefix::BLS12381G1,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "x25519")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::X25519.to_string(),
                secret_codec: multicodec_prefix::X25519_SECRET,
                codec: multicodec_prefix::X25519,
                key_exchange: true,
                public_verify: false,
            },
            #[cfg(feature = "mlkem")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::MLKEM512.to_string(),
                secret_codec: multicodec_prefix::MLKEM512_SECRET,
                codec: multicodec_prefix::MLKEM512,
                key_exchange: true,
                public_verify: false,
            },
            #[cfg(feature = "mldsa")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::MLDSA44.to_string(),
                secret_codec: multicodec_prefix::CUSTOM,
                codec: multicodec_prefix::CUSTOM,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "mldsa")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::MLDSA65.to_string(),
                secret_codec: multicodec_prefix::CUSTOM,
                codec: multicodec_prefix::CUSTOM,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(all(feature = "mldsa", not(target_family = "wasm")))]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::MLDSA87.to_string(),
                secret_codec: multicodec_prefix::CUSTOM,
                codec: multicodec_prefix::CUSTOM,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "hmac")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::HMAC_SHA256.to_string(),
                secret_codec: multicodec_prefix::CUSTOM,
                codec: multicodec_prefix::CUSTOM,
                key_exchange: false,
                public_verify: false,
            },
            #[cfg(feature = "slhdsa")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::SLHDSASHAKE128f.to_string(),
                secret_codec: multicodec_prefix::CUSTOM,
                codec: multicodec_prefix::CUSTOM,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "faest")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::FAEST128f.to_string(),
                secret_codec: multicodec_prefix::CUSTOM,
                codec: multicodec_prefix::CUSTOM,
                key_exchange: false,
                public_verify: true,
            },
            #[cfg(feature = "falcon")]
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::Falcon512.to_string(),
                secret_codec: multicodec_prefix::CUSTOM,
                codec: multicodec_prefix::CUSTOM,
                key_exchange: false,
                public_verify: true,
            },
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::Falcon1024.to_string(),
                secret_codec: multicodec_prefix::CUSTOM,
                codec: multicodec_prefix::CUSTOM,
                key_exchange: false,
                public_verify: true,
            },
        ]
    }
}
