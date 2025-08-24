use ed25519_zebra::{Signature, SigningKey, VerificationKey as VerifyingKey};
use mysteryn_core::{
    RawSignature,
    attributes::{KeyAttributes, SignatureAttributes},
    key_traits::*,
    multibase,
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::{Error, Result},
};
use rand08::{CryptoRng, RngCore, thread_rng as rng};
use serde::{Deserialize, Serialize};
use std::{any::Any, borrow::Cow, fmt::Display, str::FromStr};

#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519SecretKey(SigningKey);

impl Ed25519SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = SigningKey::new(rng);
        Self(secret_key)
    }
}

impl Default for Ed25519SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for Ed25519SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::ED25519_SECRET
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::ED25519
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::EdDSA
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(Ed25519PublicKey(VerifyingKey::from(&self.0)))
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.as_ref().into()
    }

    fn get_shared_secret(&self, _: Option<&[u8]>) -> Option<Vec<u8>> {
        None
    }

    fn sign(
        &self,
        data: &[u8],
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.sign_exchange(data, None, attributes)
    }

    fn sign_exchange(
        &self,
        data: &[u8],
        _: Option<&[u8]>,
        _: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let signature = self.0.sign(data);
        let signature = <[u8; 64]>::from(signature);
        Ok(RawSignature::from(signature.as_slice()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.sign_exchange(data, other_public_key_raw_bytes, attributes)
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let signature = Signature::try_from(signature.as_slice())
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;

        VerifyingKey::from(&self.0)
            .verify(&signature, data)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Ed25519Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for Ed25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Ed25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ed25519SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Ed25519SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let secret_key =
            SigningKey::try_from(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for Ed25519SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Ed25519SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let secret_key =
                SigningKey::try_from(key_data).map_err(|e| Error::InvalidKey(e.to_string()))?;
            Ok(Self(secret_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519PublicKey(VerifyingKey);

impl PublicKeyTrait for Ed25519PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::ED25519
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::ED25519
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::EdDSA
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.as_ref().into()
    }

    fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    fn can_verify(&self) -> bool {
        true
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let signature = Signature::try_from(signature.as_slice())
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;

        self.0
            .verify(&signature, data)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Ed25519Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for Ed25519PublicKey {}

impl PartialOrd for Ed25519PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ed25519PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

impl Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ed25519PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let public_key =
            VerifyingKey::try_from(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for Ed25519PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Ed25519PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let public_key =
                VerifyingKey::try_from(key_data).map_err(|e| Error::InvalidKey(e.to_string()))?;
            Ok(Self(public_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Ed25519Signature(RawSignature);

impl SignatureTrait for Ed25519Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::ED25519
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::EdDSA
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn raw(&self) -> &RawSignature {
        &self.0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for Ed25519Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519PublicKey, Ed25519SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "zD87gahnMWrBWiS7Rzs4rWVxycamVJ43a3PrmFQYXkjfL";
    const PUBLIC: &str = "z3aQijaojYpC3xgcPxgy9j1U6iLqFq8GrD71fVtyH9p62";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = Ed25519SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = Ed25519PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = Ed25519SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = Ed25519SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Ed25519PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = Ed25519SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Ed25519PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = Ed25519SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let secret_key = Ed25519SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();
        let data = b"test data";
        let signature = secret_key.sign_deterministic(data, None, None)?;

        assert_eq!(
            signature.to_string(),
            "z3PRn2nAdAAMXyrEwzmrA3ZG8hTn3tXy2Qy5WwEGE5Y5GoEz2MKK7rFgXD7EuJ4i9dAE8BhMa1CBFr9evTbsP9QiX"
        );
        secret_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
