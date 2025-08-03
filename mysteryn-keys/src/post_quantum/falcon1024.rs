use falcon_rust::falcon1024::{
    self, PublicKey as VerifyingKey, SecretKey as SigningKey, Signature,
};
use mysteryn_core::{
    RawSignature,
    attributes::{KeyAttributes, SignatureAttributes},
    key_traits::*,
    multibase,
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::{Error, Result},
};
use rand::{CryptoRng, Rng, RngCore, rng};
use serde::{Deserialize, Serialize};
use std::{any::Any, fmt::Display, str::FromStr};

#[derive(Clone)]
pub struct Falcon1024SecretKey(SigningKey);

impl Falcon1024SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = SigningKey::generate_from_seed(rng.random());
        Self(secret_key)
    }
}

impl Default for Falcon1024SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for Falcon1024SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        40
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::Falcon1024
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(Falcon1024PublicKey(VerifyingKey::from_secret_key(&self.0)))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    fn get_shared_secret(&self, _: Option<Vec<u8>>) -> Option<Vec<u8>> {
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
        _: Option<Vec<u8>>,
        _: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let signature: Signature = falcon1024::sign(data, &self.0);
        Ok(RawSignature::from(signature.to_bytes().as_slice()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        _: Option<Vec<u8>>,
        _: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        // TODO: Implement deterministic signatures
        let signature: Signature = falcon1024::sign(data, &self.0);
        Ok(RawSignature::from(signature.to_bytes().as_slice()))
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let signature = Signature::from_bytes(signature.as_bytes())
            .map_err(|_| Error::InvalidSignature("malformed signature bytes".to_string()))?;
        let public_key = VerifyingKey::from_secret_key(&self.0);
        if falcon1024::verify(data, &signature, &public_key) {
            Ok(())
        } else {
            Err(Error::InvalidSignature("invalid signature".to_string()))
        }
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Falcon1024Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for Falcon1024SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Falcon1024SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Falcon1024SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Falcon1024SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let secret_key = SigningKey::from_bytes(bytes)
            .map_err(|_| Error::InvalidKey("malformed key bytes".to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for Falcon1024SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Falcon1024SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let secret_key = SigningKey::from_bytes(key_data.as_slice())
                .map_err(|_| Error::InvalidKey("malformed key bytes".to_string()))?;
            Ok(Self(secret_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl Serialize for Falcon1024SecretKey {
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

impl<'de> Deserialize<'de> for Falcon1024SecretKey {
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
    type Value = Falcon1024SecretKey;

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
pub struct Falcon1024PublicKey(VerifyingKey);

impl PublicKeyTrait for Falcon1024PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        40
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::Falcon1024
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    fn can_verify(&self) -> bool {
        true
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let signature = Signature::from_bytes(signature.as_bytes())
            .map_err(|_| Error::InvalidSignature("malformed signature bytes".to_string()))?;

        if falcon1024::verify(data, &signature, &self.0) {
            Ok(())
        } else {
            Err(Error::InvalidSignature("invalid signature".to_string()))
        }
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Falcon1024Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PartialEq for Falcon1024PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for Falcon1024PublicKey {}

impl PartialOrd for Falcon1024PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.to_bytes().cmp(&other.0.to_bytes()))
    }
}

impl Ord for Falcon1024PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl Serialize for Falcon1024PublicKey {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Falcon1024PublicKey {
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
    type Value = Falcon1024PublicKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Falcon1024PublicKey::try_from(v)
            .map_err(|_| serde::de::Error::custom("malformed key bytes"))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Falcon1024PublicKey::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl Display for Falcon1024PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Falcon1024PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Falcon1024PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Falcon1024PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let public_key = VerifyingKey::from_bytes(bytes)
            .map_err(|_| Error::InvalidKey("malformed key bytes".to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for Falcon1024PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Falcon1024PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let public_key = VerifyingKey::from_bytes(key_data.as_slice())
                .map_err(|_| Error::InvalidKey("malformed key bytes".to_string()))?;
            Ok(Self(public_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Falcon1024Signature(RawSignature);

impl SignatureTrait for Falcon1024Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        40
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::Falcon1024
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

impl TryFrom<&[u8]> for Falcon1024Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for Falcon1024Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for Falcon1024Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Falcon1024PublicKey, Falcon1024SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "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";
    const PUBLIC: &str = "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";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = Falcon1024SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = Falcon1024PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = Falcon1024SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = Falcon1024SecretKey::try_from(secret_key_bytes.as_slice())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Falcon1024PublicKey::try_from(public_key_bytes.as_slice())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = Falcon1024SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Falcon1024PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = Falcon1024SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key = Falcon1024SecretKey::from_str(SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let signature = private_key.sign_deterministic(data, None, None)?;

        // TODO
        //assert_eq!(signature.to_string(), "z3zmTguPeef2zKo9UA9nU4WFswKhzPs3Zgdz18aoSLB2cPXMgKt5XeAuputt4LdyJhdDq5NzvYWeSCqYfXGYTVKzL6M8v3JTqLo7hvXaCqFBLbEUBBbNeAqAhuESq7kz6UJBDrj7CNRJSmdFUoostEZwgmyi6RDkQqRf83iFv2Dz5Mq8CCpMq3zSZRYfAbdEcLoUtLEWnkZGGBqXQDUkPtHCe4fN5iE4CRE2XoGVp1cWveRGqhR3TmVjVXHXsEvnF1ga3pzTu1cBmqojv2n4pwUpFwcDF19cwsgngVMvdao5JA3hdTp8ffcXqXodxzgZTcu1vP51bmRyqPBNtqEoMSegkF6tovGsVt7Mi2vNgZFgXiUpAN8PQ2naRhbS2KvFbufLVR98Sby669pnaDAHKjBE6KprpDBdk9yX4fA88mcx71kXqkFuU6jDFignSjkWcMZf2UyrbaCmbkcuydrMag2VKnVBzDLxSZyPkv6w1FceHYaEgx2NsHLdRuc8gvgn6UH2ndqdFxNoZSgJqvU5YBkwekKSBTqUxXosKt5mpEcbo7PbvTg46LEyN8KQ7BoKDR1DveUSHiWf3jvtizDxZeYaNGGduuALNSwEYdvXTr2nmwMUmU5w5x2hLrbiXDeBr6wETVVo8ERf2g6qwFsv8zWsgnfZSiTo5f1uWFG72bK5nHJjUrPXw1ujzQmh57k8dLcqyXpr65qwYHNDinyHZkjuaYMiNyfiUhroGaxbtfMbwUtYF1NcaVPVD3gpaysnaMctP4PeAVBx1fh4krgWmiJYxMSyKBvFPyZv8staYemfMoPgq9NL5wP7hULVB7QYzCEms6FPxuZpJKM8SBFMwHnfnKJTN7bSbQoSL83EcQrWWxCcDGcd2kKdx4chNVwSLU6XBCDfW3qu7xK");
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
