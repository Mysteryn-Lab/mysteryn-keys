use crate::ed25519::{Ed25519SecretKey, Ed25519Signature};
use ml_kem::{
    B32, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem512, MlKem512Params,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    param::EncodedCiphertext,
};
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

#[derive(Clone)]
pub struct MlKem512SecretKey(DecapsulationKey<MlKem512Params>);

impl MlKem512SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (dk, _ek) = MlKem512::generate(rng);
        Self(dk)
    }
}

impl Default for MlKem512SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for MlKem512SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::MLKEM512_SECRET
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::MLKEM512
    }

    fn signature_nonce_size(&self) -> usize {
        32
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::MLKEM512
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(MlKem512PublicKey(self.0.encapsulation_key().clone()))
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.as_bytes().to_vec().into()
    }

    fn get_shared_secret(&self, cipertext: Option<&[u8]>) -> Option<Vec<u8>> {
        if let Some(cipertext) = cipertext {
            let Ok(ct) = EncodedCiphertext::<MlKem512Params>::try_from(cipertext) else {
                return None;
            };
            let Ok(k_recv) = self.0.decapsulate(&ct);
            Some(k_recv.to_vec())
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
            let encoded = Encoded::<EncapsulationKey<MlKem512Params>>::try_from(
                other_public_key_raw_bytes.as_ref(),
            )
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
            let e_key = EncapsulationKey::<MlKem512Params>::from_bytes(&encoded);
            let mut rng = rng();
            let (ct, k_send) = e_key
                .encapsulate(&mut rng)
                .map_err(|e| Error::InvalidKey(e.to_string()))?;

            let key = Ed25519SecretKey::try_from(k_send.as_slice())?;
            let signature = key.sign(data, None)?;

            let mut buf = vec![];
            write_varbytes(ct.to_vec().as_slice(), &mut buf)
                .map_err(|e| Error::IOError(e.to_string()))?;
            write_varbytes(signature.as_bytes(), &mut buf)
                .map_err(|e| Error::IOError(e.to_string()))?;
            Ok(RawSignature::from(buf.as_slice()))
        } else {
            Err(Error::ValidationError(
                "other public key bytes are not provided".to_owned(),
            ))
        }
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        if let Some(other_public_key_raw_bytes) = other_public_key_raw_bytes {
            let encoded = Encoded::<EncapsulationKey<MlKem512Params>>::try_from(
                other_public_key_raw_bytes.as_ref(),
            )
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
            let e_key = EncapsulationKey::<MlKem512Params>::from_bytes(&encoded);
            let nonce = if let Some(attrs) = attributes.as_ref() {
                if let Some(nonce) = attrs.get_nonce() {
                    nonce
                } else {
                    return Err(Error::ValidationError("nonce is required".to_string()));
                }
            } else {
                return Err(Error::ValidationError("nonce is required".to_string()));
            };
            let (ct, k_send) = e_key
                .encapsulate_deterministic(
                    &B32::try_from(nonce).map_err(|e| Error::ValidationError(e.to_string()))?,
                )
                .map_err(|e| Error::InvalidKey(e.to_string()))?;

            let key = Ed25519SecretKey::try_from(k_send.as_slice())?;
            let signature = key.sign_deterministic(data, None, attributes)?;

            let mut buf = vec![];
            write_varbytes(ct.to_vec().as_slice(), &mut buf)
                .map_err(|e| Error::IOError(e.to_string()))?;
            write_varbytes(signature.as_bytes(), &mut buf)
                .map_err(|e| Error::IOError(e.to_string()))?;
            Ok(RawSignature::from(buf.as_slice()))
        } else {
            Err(Error::ValidationError(
                "other public key bytes are not provided".to_owned(),
            ))
        }
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let mut buf = signature.as_slice();
        let ct = read_varbytes(&mut buf).map_err(|e| Error::InvalidSignature(e.to_string()))?;
        let Some(k_recv) = self.get_shared_secret(Some(&ct)) else {
            return Err(Error::InvalidSignature(
                "cannot get shared secret".to_owned(),
            ));
        };
        let embedded_signature =
            read_varbytes(&mut buf).map_err(|e| Error::InvalidSignature(e.to_string()))?;
        let embedded_signature = Ed25519Signature::try_from(embedded_signature.as_slice())?;
        let key = Ed25519SecretKey::try_from(k_recv.as_slice())?;
        key.verify(data, embedded_signature.raw())
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(MlKem512Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for MlKem512SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for MlKem512SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlKem512SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for MlKem512SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let encoded = Encoded::<DecapsulationKey<MlKem512Params>>::try_from(bytes)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key = DecapsulationKey::<MlKem512Params>::from_bytes(&encoded);
        Ok(Self(key))
    }
}

impl FromStr for MlKem512SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for MlKem512SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let encoded = Encoded::<DecapsulationKey<MlKem512Params>>::try_from(key_data)
                .map_err(|e| Error::InvalidKey(e.to_string()))?;
            let key = DecapsulationKey::<MlKem512Params>::from_bytes(&encoded);
            Ok(Self(key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl Serialize for MlKem512SecretKey {
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

impl<'de> Deserialize<'de> for MlKem512SecretKey {
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
    type Value = MlKem512SecretKey;

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
pub struct MlKem512PublicKey(EncapsulationKey<MlKem512Params>);

impl PublicKeyTrait for MlKem512PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::MLKEM512
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::MLKEM512
    }

    fn signature_nonce_size(&self) -> usize {
        32
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::MLKEM512
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.as_bytes().to_vec().into()
    }

    fn get_ciphertext(&self, nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        let (ct, k_send) = if let Some(nonce) = nonce {
            let Ok(nonce) = B32::try_from(nonce) else {
                return None;
            };
            match self.0.encapsulate_deterministic(&nonce) {
                Ok(v) => v,
                Err(_) => {
                    return None;
                }
            }
        } else {
            let mut rng = rng();
            match self.0.encapsulate(&mut rng) {
                Ok(v) => v,
                Err(_) => {
                    return None;
                }
            }
        };
        Some((ct.to_vec(), k_send.to_vec()))
    }

    fn can_verify(&self) -> bool {
        false
    }

    fn verify(&self, _data: &[u8], _signature: &RawSignature) -> Result<()> {
        Err(Error::InvalidSignature(
            "ML-KEM public key cannot be used to verify signatures.".to_owned(),
        ))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(MlKem512Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl PartialEq for MlKem512PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for MlKem512PublicKey {}

impl Display for MlKem512PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for MlKem512PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlKem512PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for MlKem512PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let encoded = Encoded::<EncapsulationKey<MlKem512Params>>::try_from(bytes)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key = EncapsulationKey::<MlKem512Params>::from_bytes(&encoded);
        Ok(Self(key))
    }
}

impl FromStr for MlKem512PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for MlKem512PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let encoded = Encoded::<EncapsulationKey<MlKem512Params>>::try_from(key_data)
                .map_err(|e| Error::InvalidKey(e.to_string()))?;
            let key = EncapsulationKey::<MlKem512Params>::from_bytes(&encoded);
            Ok(Self(key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl PartialOrd for MlKem512PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.as_bytes().cmp(&other.0.as_bytes()))
    }
}

impl Ord for MlKem512PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Serialize for MlKem512PublicKey {
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

impl<'de> Deserialize<'de> for MlKem512PublicKey {
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
    type Value = MlKem512PublicKey;

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
pub struct MlKem512Signature(RawSignature);

impl SignatureTrait for MlKem512Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::MLKEM512
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::MLKEM512
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

impl TryFrom<&[u8]> for MlKem512Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for MlKem512Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for MlKem512Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{MlKem512PublicKey, MlKem512SecretKey};
    use mysteryn_core::{attributes::SignatureAttributes, key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "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";
    const PUBLIC: &str = "z1VYoEKefCP2dHDvkgKvxENMAYJ85JHVURemTdGp9kb9XPRg7BkaiPk1WTVhJFf5uSEwiojzdY7u2M9xeKxKADEoPcq3ietZPXpHoaq1d8UB4AQDSBHdDMd4YVWvWm1hh66cKJqcaKieAb5MCnhS3yZvG5LgA3jMpieSCqed4ZRJZj3dttKQvPZ5u7K3AXMTg5nCncWwbF11jHsKArKa2w2PFMNPoQdB6Q7xyrtPMCPH9JPRLKdR1QCLW6ZCvjm8JR9gq84pdh2bWHqHMNC6VSXyPQd2nG8J4maxPuWQ25SFA3po9qA5M5n8WqL4Q8qr7yqojh9L1n6hbToihWFH7Xp1TSyXNsJZC4XAp6wsccyU2ToxAEHamo2CQdinZaKDSQ8BfbMSxSgzzb4sfVegN9nm3gGUWAeVAZV5uut4uw5ph3GVDoZfDqBfSnQXorSEfr9L7ptv5qpwLh6BQosgSQdtt8CW7Sy8XDET9fvdZsmR8n2HvAVM5MUeiWZyaLAD3o6ZX5TEhaC1Yzo28YbSNeZ32XLGTdhMwccaLxwEh2o4GjdLQg3uNQ7hNQk4TcB4VbVnBsEDyfCefkN3DYKPqMJdcwL1qKE5uLqa2yp252pYPYezPDQ5rExreAXrhdJfC6Wbu9ERVimyVDqEr2KtfULmTTUySE7tEX1KM6wDd4v3YVPvDPpTsmjmHyMQAUr2Vzw79bZLadNnbDRSFFeQ6jZG4TXvPiBJAY5guhEEU9zFxJytjTthSXuj3QGFtiKrHn8YbxbYcWem2D5iXpbf1hWjwESapFLA99w2E7Y7X25vCaYbwzKXAkkEmFKTGgMFArMuHWq1QQjW42NLyQSnDNdSTwFCB2HUKFgWQydFxA7gXirif8yMPXd9hKRZv3Zm38B6uVg5UTonJc8rQdLechdwyfBvBahS7DL3s9MPoNtkCpG5puWKEDDQ48pMjKCjFsdGP4UEmBJh1FN8ZByBd5N2pZpZKPgotjiDvXWseVomcZCMqhFREnwHL3P6jDvXmp1g6FkizGC3eTTTNkWmwMGfr4QCbjfD4eD7WV9tqYS7tLzLdcDAybR5FmbpiixRrNc6X";
    const SECRET2: &str = "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";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = MlKem512SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = MlKem512PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = MlKem512SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = MlKem512SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = MlKem512PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = MlKem512SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = MlKem512PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = MlKem512SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key_a = MlKem512SecretKey::from_str(SECRET)?;
        let public_key_a = private_key_a.public_key();
        let private_key_b = MlKem512SecretKey::from_str(SECRET2)?;
        let public_key_b = private_key_b.public_key();

        let data = b"test data";
        let nonce = b"12345678901234567890123456789012";
        let mut attributes = SignatureAttributes::default();
        attributes.set_nonce(Some(nonce));

        // A -> B
        let signature_a = private_key_a.sign_deterministic(
            data,
            Some(public_key_b.to_bytes().as_ref()),
            Some(&mut attributes),
        )?;

        assert_eq!(
            signature_a.to_string(),
            "z2sP2pX7QobFckYuhcE2y6tDpHpyFH5JQAXwEdL8oLcjtZqvkF61nBviXDR522MBx5aw8Fyk9DdsXi9XgV6fmzWFPM3z6hsxneyR2LyQqm2HaQkao1Z9XZ5xi2JPNmw4cbg23oChSrfwVDd2Vbm39QUVwgsy2xos7yWui3oS9m5oDUz9EdWGwTR7dbvSgmFNq5nqoxD5Fk32ib2bdsZrf1TR4o6kG6QWo4EKmwthvs2DF1gbhkBGjo4KazMxwdR9aL8ZbLb9LHzGEAdURznrjDStmmY192MUAScR7Rkn9fckqj7TpY3isG19re7xcAnNyXYFTUe7pP6Q56WpCiqQak6e1XJYJPFkubxVwsxzvPj93VTQE4SZTHKtHgHCjhCLEH4zkV8GpGmHwBy9LFyr9rDEroT6Jyx5PegbFTgx7qSb9FPFbNsBUa4rUbw4aEh66AmM9gCsG8rjJAWXj9EijHmS5Qf1ePi4nNEY3kK7SmwwraTva5LryKFBEPCwyTenSQmyeFT5LsDmA8uZUVBPshfrNHRX4Qs5ziTxyozCxJUFBxFNMqGgphqWwHZEwBLfdBfF7ggZ7E5hNZQPJDYq4MHDmh9FuLNiJu3hTBoD1md7GnyaPqKAhdEs5jQFAiPaRVPCrs66aJPTx7JKVWv27Bc9kJK7dq5hUDWWFakCBmKgGMSVFJJkhv6mUePynqoVZsVMaqCMnJtAsJHMESs8VR6SeDsURKxHuESntain6nvWRp4z4Tpjg1rGJNBjbV9PioQEEyvAW5u2q9nPDtvx2H2oZaX1A9AT23yeLLokioDmupbo1w6fJzw6XCfHcjmHEbXP1jJroXJfvovPzA2ivfczGbFconTGkfDoKm21GpXTFQgY8NNcM8BHmthS1KBqMyvgha6t1qcfkZW3HGL7j8GZBdqfnWdgxP1pX41wPrYDn3v6nxPwFYQjhVZxY7Tg6eY5nRALHeftb6CokenMrQsDN2XHbLL9MH97fKptJpUasns3f27oX4MasdB9UY3hQqVkdUgWAakoQ63qEhExgbYuNPXLpc6ZDk5YU5rZqLLeRSuCWSBeQubXTacgARR8YrTfdGH2coeKWzSs9pdkPqxXxkF3TrkHdHRtVkT5ZtMkmcBse6FGWw"
        );
        private_key_b.verify(data, &signature_a)?;

        // B -> A
        let signature_b = private_key_b.sign_deterministic(
            data,
            Some(public_key_a.to_bytes().as_ref()),
            Some(&mut attributes),
        )?;
        private_key_a.verify(data, &signature_b)?;

        let ciphertext = public_key_a.get_ciphertext(Some(nonce)).unwrap();
        assert_eq!(
            format!("{:x?}", ciphertext),
            "([e3, 71, b8, df, 32, 6c, 74, 53, 61, 70, d3, 21, 93, 63, fd, 77, b3, f6, 4d, c7, dc, 13, b5, 9e, 46, db, 41, 41, ed, a7, 80, e, 25, ff, d, 14, 50, fc, 8b, f7, e5, b6, b1, 5c, 95, c4, 69, ee, 7f, c0, 84, a0, 55, a3, 29, f, 72, cd, 60, 66, 70, c0, 3c, f3, 45, 12, 35, d7, 7f, 20, d1, ad, 6b, 76, a5, 3, 2b, 85, 1c, 92, 1f, 4e, 9a, e3, 92, e9, b4, 94, b4, 2b, 66, 3d, fc, 2f, 25, 37, 7c, ce, 4b, 78, cc, 6b, 81, e, a0, 8b, 47, 34, 12, d1, 84, d5, 8d, 3a, ef, bb, b2, 5e, 57, 1f, 26, b7, dc, f7, fa, 42, e4, 80, 0, 26, 9b, bb, 39, a5, 6f, ac, e2, a3, 47, eb, 9c, 76, 59, c5, 85, d7, 47, a, 59, 7b, e1, 89, f1, 41, 49, 88, 1f, 5e, 51, 9f, 79, 8c, eb, 38, 36, 74, e9, 76, 85, 6e, 2c, 83, 9, 95, 3e, 7a, 25, 38, 5c, 23, ca, 73, 7e, fc, d1, 6d, 4, cb, 8e, 9c, 44, 3, 4d, c6, de, db, d2, a, d, b, 13, 12, 55, 92, fb, 4f, 39, f7, 42, f5, 98, 66, 46, 9a, 88, b1, dc, 50, cd, ae, ee, 65, 2a, 9a, 9, 9a, b3, c4, 98, 3a, b4, ea, c7, 1a, d4, 44, fe, f5, 9e, 73, a3, bc, 4a, d1, 69, c8, 8f, 3f, 5e, 76, a9, f9, b9, 4, 15, 21, 63, 50, 7, b2, 90, 66, e1, 4a, 9f, 1a, c6, c4, 5c, 9d, 5b, de, 23, 6d, 35, d5, ae, d1, db, 5, 2b, d8, d6, bd, ab, 45, 2, 91, 5c, d9, 83, 94, 50, ed, 35, 52, c1, 73, fb, dd, b6, 73, c3, 8a, f7, d4, 63, 32, 44, 18, 31, bc, 7b, b3, 57, bc, 69, 3e, c5, fb, 51, be, 6e, 64, 2e, b5, 0, fc, b1, 12, 5e, dd, 5b, a3, b8, 56, ce, 64, 76, 82, 75, 1e, 62, 13, cd, 2e, e2, 16, 3e, 75, f1, b9, a0, 99, 28, fc, b0, 40, 7f, d3, 94, 9c, 7b, 84, 5b, 29, 55, ff, f3, 6f, d6, 1a, 70, ec, 49, f2, 47, 6, 4d, 54, 2f, d1, 38, 5c, c2, 5c, d, 27, b, fb, 69, 1b, 5c, f0, 2a, 49, 8, b2, d, a, 5a, f8, de, 12, 33, 6c, 4a, 8d, 2f, 2c, 8d, 57, 32, 29, 1d, 7e, 57, 5d, dc, b6, 6e, 7b, b3, 50, bb, 55, 81, f9, ba, b, 88, af, 1d, 17, 8f, 8b, de, b4, 78, 21, 76, dd, 8a, 87, 11, c2, 77, cd, 76, 4b, f5, 3c, 8d, 31, df, 2a, 8a, 3d, 2c, 18, ff, e4, b5, 8c, b2, 94, 5c, 47, 12, 7e, a3, 9, b0, e5, 28, 6c, 52, f1, 15, 3f, 8, f4, 75, 85, c, a3, 19, 8e, 91, 86, f1, 37, 5b, 7f, e, 3a, 1f, fc, ec, 17, c3, 87, 51, f7, c2, 5d, a3, b4, a2, 55, b0, 6d, 38, 9c, f4, 4f, 70, c0, 70, c4, 8, 1a, 77, a2, 49, 8e, 3e, c, 8c, f0, c3, 5f, 2e, 5d, cc, 6d, 47, 67, 24, e0, bd, fc, d7, 40, 47, 4f, de, 2f, be, ee, 8d, 90, b0, a0, 13, a9, be, f, 7c, 40, 25, fc, ce, f5, 62, df, 4a, b, 4f, bf, 77, d4, da, b2, f4, c0, 68, 31, a0, 18, d5, 1b, 4b, e1, 66, 18, f7, 15, 8, 68, d8, d, ad, b6, 43, 37, 8c, 7c, 98, 4, 33, 13, 23, c8, cb, e4, e5, 19, 82, b9, ef, 1e, 12, 81, eb, 4e, 2d, f6, 3a, 1e, 2e, 5, 3f, 9e, 1e, 8a, 8a, 7, a2, 36, cd, c2, 1a, f8, 72, 4, 95, 3e, 33, 58, 50, 4f, 62, 43, 82, e2, ac, 18, 30, 95, 27, 34, c0, 2b, de, 7e, 34, 2f, 8d, dd, 8c, 1f, b0, 70, bc, 66, d5, 3c, f5, e, fc, 29, 89, e6, b3, b, 94, 12, ef, f2, af, 55, 9, 6b, 65, 59, 72, 9c, b6, 16, 4, ba, 8b, e1, ea, ba, 83, 73, f2, ce, c3, 7d, f9, 82, 18, 1e, f5, a7, a1, 84, 3d, 95, 44, e3, 62, f3, a4, 3c, dd, 71, b, f5, 6e, df, 16, 57, 89, e2, cb, c4, aa, cc, 4, d0, 6f, 97, 16, e4, 5e, 60, 64, c5, ad, 65, f6, 38, 4e, 82, 80, 75, 94, 89, 86, 22, 6c, 46, 7b, b, 47, 62, 12, e4, 45, 72, a7, 95, 2e, 38], [9, 47, 34, c3, b7, 64, 2b, d0, c8, 23, 7f, 47, c5, 89, 7a, 75, 21, 37, be, 3b, 2b, 62, ee, 93, 1d, e9, a7, c4, eb, 73, 7c, ac])"
        );

        let shared_secret_a = private_key_a
            .get_shared_secret(Some(&ciphertext.0))
            .unwrap();
        let shared_secret_b = ciphertext.1;
        assert_eq!(shared_secret_a, shared_secret_b);

        Ok(())
    }
}
