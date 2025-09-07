use super::ed25519::{Ed25519SecretKey, Ed25519Signature};
use mysteryn_core::{
    RawSignature,
    attributes::{KeyAttributes, SignatureAttributes},
    key_traits::*,
    multibase,
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::{Error, Result},
    varint::{read_varbytes, write_varbytes},
};
use rand08::{CryptoRng, RngCore, thread_rng as rng};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    borrow::Cow,
    fmt::{Debug, Display},
    str::FromStr,
};
use x25519_dalek::{PublicKey as VerifyingKey, StaticSecret, x25519};

#[derive(Clone)]
pub struct X25519SecretKey(StaticSecret);

impl X25519SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(StaticSecret::random_from_rng(rng))
    }
}

impl SecretKeyTrait for X25519SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::X25519_SECRET
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::X25519
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::X25519
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(X25519PublicKey(VerifyingKey::from(&self.0)))
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.as_ref().into()
    }

    fn get_shared_secret(&self, ciphertext: Option<&[u8]>) -> Option<Vec<u8>> {
        if let Some(ciphertext) = ciphertext {
            if ciphertext.len() != 32 {
                return None;
            }
            let mut buf: [u8; 32] = [0; 32];
            buf.copy_from_slice(ciphertext);
            let shared_secret = x25519(self.0.to_bytes(), buf);
            Some(shared_secret.to_vec())
        } else {
            None
        }
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
        other_public_key_raw_bytes: Option<&[u8]>,
        _: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        if let Some(other_public_key_raw_bytes) = other_public_key_raw_bytes {
            let Some(shared_secret) = self.get_shared_secret(Some(other_public_key_raw_bytes))
            else {
                return Err(Error::InvalidKey("invalid shared secret".to_owned()));
            };
            let key = Ed25519SecretKey::try_from(shared_secret.as_slice())?;
            let signature = key.sign(data, None)?;
            let ct = VerifyingKey::from(&self.0);

            let mut buf = vec![];
            write_varbytes(ct.to_bytes().as_slice(), &mut buf)
                .map_err(|e| Error::IOError(e.to_string()))?;
            write_varbytes(signature.as_bytes(), &mut buf)
                .map_err(|e| Error::IOError(e.to_string()))?;
            Ok(RawSignature::from(buf.as_slice()))
        } else {
            Err(Error::ValidationError(
                "other public key for is not provided".to_owned(),
            ))
        }
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
        let mut buf = signature.as_slice();
        let ct = read_varbytes(&mut buf).map_err(|e| Error::InvalidSignature(e.to_string()))?;
        let Some(shared_secret) = self.get_shared_secret(Some(&ct)) else {
            return Err(Error::InvalidKey("cannot get shared secret".to_owned()));
        };
        let embedded_signature =
            read_varbytes(&mut buf).map_err(|e| Error::InvalidSignature(e.to_string()))?;
        let embedded_signature = Ed25519Signature::try_from(embedded_signature.as_slice())?;
        let key = Ed25519SecretKey::try_from(shared_secret.as_slice())?;
        key.verify(data, embedded_signature.raw())
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(X25519Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "X25519SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for X25519SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey("invalid key length".to_owned()));
        }
        let mut sk: [u8; 32] = [0; 32];
        sk.clone_from_slice(bytes);
        Ok(Self(StaticSecret::from(sk)))
    }
}

impl FromStr for X25519SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for X25519SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            if key_data.len() != 32 {
                return Err(Error::InvalidKey("invalid key length".to_owned()));
            }
            let mut sk: [u8; 32] = [0; 32];
            sk.clone_from_slice(key_data);
            let secret_key = StaticSecret::from(sk);
            Ok(Self(secret_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl Serialize for X25519SecretKey {
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

impl<'de> Deserialize<'de> for X25519SecretKey {
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
    type Value = X25519SecretKey;

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

#[derive(Clone, PartialEq, Eq)]
pub struct X25519PublicKey(VerifyingKey);

impl PublicKeyTrait for X25519PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::X25519
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::X25519
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::X25519
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.as_ref().into()
    }

    fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        Some((self.0.to_bytes().to_vec(), vec![]))
    }

    fn can_verify(&self) -> bool {
        false
    }

    fn verify(&self, _data: &[u8], _signature: &RawSignature) -> Result<()> {
        Err(Error::InvalidSignature(
            "X25519 public key cannot be used to verify signatures".to_owned(),
        ))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(X25519Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "X25519PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey("invalid key length".to_owned()));
        }
        let mut pk: [u8; 32] = [0; 32];
        pk.clone_from_slice(bytes);
        Ok(Self(VerifyingKey::from(pk)))
    }
}

impl FromStr for X25519PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for X25519PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            if key_data.len() != 32 {
                return Err(Error::InvalidKey("invalid key length".to_owned()));
            }
            let mut sk: [u8; 32] = [0; 32];
            sk.clone_from_slice(key_data);
            let public_key = VerifyingKey::from(sk);
            Ok(Self(public_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl PartialOrd for X25519PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_bytes().cmp(&other.to_bytes()))
    }
}

impl Ord for X25519PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Serialize for X25519PublicKey {
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

impl<'de> Deserialize<'de> for X25519PublicKey {
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
    type Value = X25519PublicKey;

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
pub struct X25519Signature(RawSignature);

impl SignatureTrait for X25519Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::X25519
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::X25519
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

impl TryFrom<&[u8]> for X25519Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for X25519Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for X25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{X25519PublicKey, X25519SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "z4PjYVJ3wmpnAJozGtQjWMe6joC4L6UKEziQAxpTn86bK";
    const PUBLIC: &str = "ztB5wcd5xKaxpp9xKStr4ZykEMcytGyqmDBUdT8E8seD";
    const SECRET2: &str = "zHuWM9B39PTfYAnbHxxYqbSJtttsMZr6uQ6obXPutJRLH";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = X25519SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = X25519PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = X25519SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = X25519SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = X25519PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = X25519SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = X25519PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = X25519SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key_a = X25519SecretKey::from_str(SECRET)?;
        let public_key_a = private_key_a.public_key();
        let private_key_b = X25519SecretKey::from_str(SECRET2)?;
        let public_key_b = private_key_b.public_key();

        let data = b"test data";

        // A -> B
        let signature_a =
            private_key_a.sign_deterministic(data, Some(&public_key_b.to_bytes()), None)?;

        assert_eq!(
            signature_a.to_string(),
            "z4i6PDvyLMYKvwXpjv2zFL9EGxjDeJ3cBqrg4msSUnURtBDk34GSreYWGJNo2kiQHjdCyscR8gCDKsMd7j9gTuDuLLKVJyWFKofrQrMm3zr4xFuGbXBTkzJ9diapkhYkW6v2Luv"
        );
        private_key_b.verify(data, &signature_a)?;

        // B -> A
        let signature_b =
            private_key_b.sign_deterministic(data, Some(&public_key_a.to_bytes()), None)?;
        private_key_a.verify(data, &signature_b)?;

        let ciphertext_a = public_key_a.get_ciphertext(None);
        assert_eq!(
            format!("{:x?}", ciphertext_a),
            "Some(([d, 1c, 6, 4e, 7f, 7a, 8a, d7, fb, c9, f2, 50, c6, b0, cf, 34, a5, 9c, 30, 9e, 73, e, ca, 4d, 9d, bf, 17, 38, 4e, c6, 1d, 3e], []))"
        );
        let ciphertext_b = public_key_b.get_ciphertext(None);

        let shared_secret_a =
            private_key_a.get_shared_secret(ciphertext_b.as_ref().map(|x| x.0.as_slice()));
        let shared_secret_b =
            private_key_b.get_shared_secret(ciphertext_a.as_ref().map(|x| x.0.as_slice()));
        assert_eq!(shared_secret_a, shared_secret_b);

        Ok(())
    }
}
