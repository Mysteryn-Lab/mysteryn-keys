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
use signature::{Keypair, RandomizedSigner, Signer, Verifier};
use slh_dsa::{Shake128f, Signature, SigningKey, VerifyingKey, signature};
use std::{
    any::Any,
    borrow::Cow,
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Clone)]
pub struct SlhDsaShake128fSecretKey(SigningKey<Shake128f>);

impl SlhDsaShake128fSecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = SigningKey::new(rng);
        Self(secret_key)
    }
}

impl SecretKeyTrait for SlhDsaShake128fSecretKey {
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
        known_algorithm_name::SLHDSASHAKE128f
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(SlhDsaShake128fPublicKey(self.0.verifying_key()))
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
        let signature = self.0.sign_with_rng(&mut rng(), data);
        let signature = signature.to_bytes();
        Ok(RawSignature::from(signature.as_slice()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        _: Option<&[u8]>,
        _: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let signature = self.0.sign(data);
        let signature = signature.to_bytes();
        Ok(RawSignature::from(signature.as_slice()))
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let signature = Signature::try_from(signature.as_slice())
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;
        let public_key = self.0.verifying_key();

        public_key
            .verify(data, &signature)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(SlhDsaShake128fSignature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for SlhDsaShake128fSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl Debug for SlhDsaShake128fSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SlhDsaShake128fSecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for SlhDsaShake128fSecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let secret_key = SigningKey::<Shake128f>::try_from(bytes)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for SlhDsaShake128fSecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for SlhDsaShake128fSecretKey {
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

impl Serialize for SlhDsaShake128fSecretKey {
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

impl<'de> Deserialize<'de> for SlhDsaShake128fSecretKey {
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
    type Value = SlhDsaShake128fSecretKey;

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
pub struct SlhDsaShake128fPublicKey(VerifyingKey<Shake128f>);

impl PublicKeyTrait for SlhDsaShake128fPublicKey {
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
        known_algorithm_name::SLHDSASHAKE128f
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.to_vec().into()
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
        Ok(Box::new(SlhDsaShake128fSignature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl PartialEq for SlhDsaShake128fPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for SlhDsaShake128fPublicKey {}

impl Display for SlhDsaShake128fPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl Debug for SlhDsaShake128fPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SlhDsaShake128fPublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for SlhDsaShake128fPublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let public_key = VerifyingKey::<Shake128f>::try_from(bytes)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for SlhDsaShake128fPublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for SlhDsaShake128fPublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let public_key = VerifyingKey::<Shake128f>::try_from(key_data)
                .map_err(|e| Error::InvalidKey(e.to_string()))?;
            Ok(Self(public_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl PartialOrd for SlhDsaShake128fPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_bytes().cmp(&other.to_bytes()))
    }
}

impl Ord for SlhDsaShake128fPublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Serialize for SlhDsaShake128fPublicKey {
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

impl<'de> Deserialize<'de> for SlhDsaShake128fPublicKey {
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
    type Value = SlhDsaShake128fPublicKey;

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
pub struct SlhDsaShake128fSignature(RawSignature);

impl SignatureTrait for SlhDsaShake128fSignature {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        16
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::SLHDSASHAKE128f
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn raw(&self) -> &RawSignature {
        &self.0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TryFrom<&[u8]> for SlhDsaShake128fSignature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for SlhDsaShake128fSignature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for SlhDsaShake128fSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{SlhDsaShake128fPublicKey, SlhDsaShake128fSecretKey};
    use mysteryn_core::key_traits::*;
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str =
        "z3xj8UP9qDfXqToNHXVBWeNszA5p2bSMZND1brijR6hMABem4gHSLqPZ1u9BvkEWW2xAEKMraJez2hcwFMQ9XcXqX";
    const PUBLIC: &str = "zDvxWu6Zxy2PTu6FW2voSbx1TeCxdJdUi6hcQKGQDZ5Su";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() {
        let secret_key = SlhDsaShake128fSecretKey::from_str(SECRET).expect("cannot deserialize");
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = SlhDsaShake128fPublicKey::from_str(PUBLIC).expect("cannot deserialize");
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = SlhDsaShake128fSecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = SlhDsaShake128fSecretKey::try_from(secret_key_bytes.as_ref())
            .expect("cannot deserialize");
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = SlhDsaShake128fPublicKey::try_from(public_key_bytes.as_ref())
            .expect("cannot deserialize");
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key =
            SlhDsaShake128fSecretKey::from_str(&secret_key_str).expect("cannot deserialize");
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key =
            SlhDsaShake128fPublicKey::from_str(&public_key_str).expect("cannot deserialize");
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() {
        let secret_key = SlhDsaShake128fSecretKey::from_str(SECRET).expect("cannot deserialize");
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() {
        let private_key = SlhDsaShake128fSecretKey::from_str(SECRET).expect("cannot deserialize");
        let public_key = private_key.public_key();
        let data = b"test data";
        let signature = private_key
            .sign_deterministic(data, None, None)
            .expect("cannot sign");

        assert_eq!(
            signature.to_string(),
            "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"
        );
        private_key.verify(data, &signature).expect("cannot verify");
        public_key.verify(data, &signature).expect("cannot verify");
    }
}
