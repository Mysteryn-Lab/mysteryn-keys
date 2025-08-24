use bls12_381_bls::{PublicKey as VerifyingKey, SecretKey as SigningKey, Signature};
use dusk_bytes::{DeserializableSlice, Serializable};
use mysteryn_core::{
    RawSignature,
    attributes::{BLS12381_BASIC_SCHEME, KeyAttributes, SignatureAttributes},
    key_traits::*,
    multibase,
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::{Error, Result},
};
use rand08::{CryptoRng, RngCore, thread_rng as rng};
use serde::{Deserialize, Serialize};
use std::{any::Any, borrow::Cow, fmt::Display, str::FromStr};

#[derive(Clone)]
pub struct Bls12381G1SecretKey(SigningKey);

impl Bls12381G1SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = SigningKey::random(rng);
        Self(secret_key)
    }
}

impl Default for Bls12381G1SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for Bls12381G1SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::BLS12381G1_SECRET
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::BLS12381G1
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::Bls12381G1
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(Bls12381G1PublicKey(VerifyingKey::from(&self.0)))
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
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let signature = self.0.sign(data);
        if let Some(attributes) = attributes {
            attributes.set_scheme(Some(BLS12381_BASIC_SCHEME));
        }
        Ok(RawSignature::from(signature.to_bytes().as_slice()))
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
        let mut b: [u8; 48] = [0; 48];
        let mut r = signature.as_slice();
        std::io::copy(&mut r, &mut b.as_mut_slice())
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        let signature =
            Signature::from_bytes(&b).map_err(|e| Error::InvalidSignature(e.to_string()))?;

        VerifyingKey::from(&self.0)
            .verify(&signature, data)
            .map_err(|e| Error::InvalidSignature(e.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Bls12381G1Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for Bls12381G1SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Bls12381G1SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bls12381G1SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Bls12381G1SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut b = bytes;
        Ok(Self(SigningKey::from_reader(&mut b).map_err(|_| {
            Error::InvalidKey("invalid bytes".to_string())
        })?))
    }
}

impl FromStr for Bls12381G1SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Bls12381G1SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let mut b: [u8; 32] = [0; 32];
            let mut r = key_data;
            std::io::copy(&mut r, &mut b.as_mut_slice())
                .map_err(|e| Error::EncodingError(e.to_string()))?;
            let secret_key = SigningKey::from_bytes(&b)
                .map_err(|_| Error::InvalidKey("invalid key".to_string()))?;
            Ok(Self(secret_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl Serialize for Bls12381G1SecretKey {
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

impl<'de> Deserialize<'de> for Bls12381G1SecretKey {
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
    type Value = Bls12381G1SecretKey;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bls12381G1PublicKey(VerifyingKey);

impl PublicKeyTrait for Bls12381G1PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::BLS12381G1
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::BLS12381G1
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::Bls12381G1
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
        let mut b: [u8; 48] = [0; 48];
        let mut r = signature.as_slice();
        std::io::copy(&mut r, &mut b.as_mut_slice())
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        let signature =
            Signature::from_bytes(&b).map_err(|e| Error::InvalidSignature(e.to_string()))?;

        self.0
            .verify(&signature, data)
            .map_err(|e| Error::InvalidSignature(e.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Bls12381G1Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for Bls12381G1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl TryFrom<&[u8]> for Bls12381G1PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut r = bytes;
        let public_key = VerifyingKey::from_reader(&mut r)
            .map_err(|_| Error::InvalidKey("invalid key".to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for Bls12381G1PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Bls12381G1PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let mut b: [u8; 96] = [0; 96];
            let mut r = key_data;
            std::io::copy(&mut r, &mut b.as_mut_slice())
                .map_err(|e| Error::EncodingError(e.to_string()))?;
            let public_key = VerifyingKey::from_bytes(&b)
                .map_err(|_| Error::InvalidKey("invalid key".to_string()))?;
            Ok(Self(public_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl PartialOrd for Bls12381G1PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_bytes().cmp(&other.to_bytes()))
    }
}

impl Ord for Bls12381G1PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Serialize for Bls12381G1PublicKey {
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

impl<'de> Deserialize<'de> for Bls12381G1PublicKey {
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
    type Value = Bls12381G1PublicKey;

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
pub struct Bls12381G1Signature(RawSignature);

impl SignatureTrait for Bls12381G1Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::BLS12381G1
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::Bls12381G1
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

impl TryFrom<&[u8]> for Bls12381G1Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for Bls12381G1Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for Bls12381G1Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Bls12381G1PublicKey, Bls12381G1SecretKey};
    use mysteryn_core::{
        key_traits::{PublicKeyTrait, SecretKeyTrait},
        result::Result,
    };
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "z5pVXMhfKwnhTr3a2caFL2Fv1sygSvEWe7YiJWRXQ5nH";
    const PUBLIC: &str = "zsWJRyHwuYgqw8YeffXkZANLSSMtTcAJ1qp2YAnRzz9ErYcw1Kdcoe5UZMPk9eQTi676V5XALatrUW9Xtd6JG96jxucJDdhhPbWbnuirGXUUd5TdofF9fU2WnGzgvHYZsF2v";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() {
        let secret_key = Bls12381G1SecretKey::from_str(SECRET).expect("cannot get from string");
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = Bls12381G1PublicKey::from_str(PUBLIC).expect("get get from string");
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = Bls12381G1SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key =
            Bls12381G1SecretKey::try_from(secret_key_bytes.as_ref()).expect("cannot deserialize");
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key =
            Bls12381G1PublicKey::try_from(public_key_bytes.as_ref()).expect("cannot deserialize");
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key =
            Bls12381G1SecretKey::from_str(&secret_key_str).expect("cannot get from string");
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key =
            Bls12381G1PublicKey::from_str(&public_key_str).expect("cannot get from sting");
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = Bls12381G1SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key = Bls12381G1SecretKey::from_str(SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let signature = private_key.sign_deterministic(data, None, None)?;

        assert_eq!(
            signature.to_string(),
            "z7XUYAiK1sMRiwTdktn2w8YHeJ9pcJ13VW3gG9fsA1u18i6ETRinG17foFdpQpY73vP"
        );
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
