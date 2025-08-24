use faest::{
    ByteEncoding, FAEST128fSignature as Signature, FAEST128fSigningKey as SigningKey,
    FAEST128fVerificationKey as VerifyingKey, KeypairGenerator, RandomizedSigner,
    signature::{Keypair, Signer, Verifier},
};
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

#[derive(Clone)]
pub struct Faest128fSecretKey(SigningKey);

impl Faest128fSecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = SigningKey::generate(rng);
        Self(secret_key)
    }
}

impl Default for Faest128fSecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for Faest128fSecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        16
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::FAEST128f
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(Faest128fPublicKey(self.0.verifying_key()))
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.to_bytes().to_vec().into()
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
        let signature: Signature = self
            .0
            .try_sign_with_rng(&mut rng(), data)
            .map_err(|e| Error::IOError(e.to_string()))?;
        Ok(RawSignature::from(signature.as_ref()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        _: Option<&[u8]>,
        _: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let signature: Signature = self
            .0
            .try_sign(data)
            .map_err(|e| Error::IOError(e.to_string()))?;
        Ok(RawSignature::from(signature.as_ref()))
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let signature = Signature::try_from(signature.as_slice())
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;

        self.0
            .verifying_key()
            .verify(data, &signature)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Faest128fSignature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for Faest128fSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Faest128fSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Faest128fSecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Faest128fSecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let secret_key =
            SigningKey::try_from(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for Faest128fSecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Faest128fSecretKey {
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

impl Serialize for Faest128fSecretKey {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Faest128fSecretKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(CustomVisitor1)
        } else {
            deserializer.deserialize_bytes(CustomVisitor1)
        }
    }
}
struct CustomVisitor1;
impl serde::de::Visitor<'_> for CustomVisitor1 {
    type Value = Faest128fSecretKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::try_from(v).map_err(|_| serde::de::Error::custom("malformed key bytes"))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[derive(Clone)]
pub struct Faest128fPublicKey(VerifyingKey);

impl PublicKeyTrait for Faest128fPublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        16
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::FAEST128f
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.to_bytes().to_vec().into()
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
            .verify(data, &signature)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Faest128fSignature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PartialEq for Faest128fPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for Faest128fPublicKey {}

impl Display for Faest128fPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Faest128fPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Faest128fPublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Faest128fPublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let public_key =
            VerifyingKey::try_from(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for Faest128fPublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Faest128fPublicKey {
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

impl PartialOrd for Faest128fPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_bytes().cmp(&other.to_bytes()))
    }
}

impl Ord for Faest128fPublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Serialize for Faest128fPublicKey {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Faest128fPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(CustomVisitor)
        } else {
            deserializer.deserialize_bytes(CustomVisitor)
        }
    }
}
struct CustomVisitor;
impl serde::de::Visitor<'_> for CustomVisitor {
    type Value = Faest128fPublicKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::try_from(v).map_err(|_| serde::de::Error::custom("malformed key bytes"))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Faest128fSignature(RawSignature);

impl SignatureTrait for Faest128fSignature {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        16
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::FAEST128f
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

impl TryFrom<&[u8]> for Faest128fSignature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for Faest128fSignature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for Faest128fSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Faest128fPublicKey, Faest128fSecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "z4M4WfrsgkLrBQxA6BVADc5zEeUNLQpx49F415QskhBrd";
    const PUBLIC: &str = "z4M4WfrsgkLrBQxA6BVADc6T4Eg4NHxJqxvruDvEiEUu6";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = Faest128fSecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = Faest128fPublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = Faest128fSecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = Faest128fSecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Faest128fPublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = Faest128fSecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Faest128fPublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = Faest128fSecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key = Faest128fSecretKey::from_str(SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let signature = private_key.sign_deterministic(data, None, None)?;

        assert_eq!(
            signature.to_string(),
            "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"
        );
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
