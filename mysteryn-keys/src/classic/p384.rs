use mysteryn_core::{
    RawSignature,
    attributes::{KeyAttributes, SignatureAttributes},
    key_traits::*,
    multibase,
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::{Error, Result},
};
use p384::{
    EncodedPoint,
    ecdsa::{
        self, Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
};
use rand08::{CryptoRng, RngCore, thread_rng as rng};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    borrow::Cow,
    fmt::{Debug, Display},
    str::FromStr,
};

/// Support for NIST P-384 keys, aka secp384r1, aka ES384
#[derive(Clone)]
pub struct P384SecretKey(SigningKey);

impl P384SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private_key = SigningKey::random(rng);
        Self(private_key)
    }
}

impl Default for P384SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for P384SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::P384_SECRET
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::P384
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::ES384
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(P384PublicKey(VerifyingKey::from(&self.0)))
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
        let signature: ecdsa::Signature = self
            .0
            .try_sign(data)
            .map_err(|e| Error::IOError(e.to_string()))?;
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
        let signature = Signature::try_from(signature.as_slice())
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;

        VerifyingKey::from(&self.0)
            .verify(data, &signature)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(P384Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for P384SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for P384SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "P384SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for P384SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let secret_key =
            SigningKey::from_slice(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for P384SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for P384SecretKey {
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

impl Serialize for P384SecretKey {
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

impl<'de> Deserialize<'de> for P384SecretKey {
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
    type Value = P384SecretKey;

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

/// Support for NIST P-384 keys, aka ES384
#[derive(Clone, PartialEq, Eq)]
pub struct P384PublicKey(VerifyingKey);

impl PublicKeyTrait for P384PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::P384
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::P384
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::ES512
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.to_encoded_point(true).to_bytes().to_vec().into()
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
        Ok(Box::new(P384Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for P384PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for P384PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "P384PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for P384PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let public_key = VerifyingKey::from_encoded_point(
            &EncodedPoint::try_from(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?,
        )
        .map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for P384PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for P384PublicKey {
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

impl PartialOrd for P384PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(
            self.0
                .to_encoded_point(true)
                .to_bytes()
                .cmp(&other.0.to_encoded_point(true).to_bytes()),
        )
    }
}

impl Ord for P384PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_encoded_point(true)
            .to_bytes()
            .cmp(&other.0.to_encoded_point(true).to_bytes())
    }
}

impl Serialize for P384PublicKey {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0.to_encoded_point(true).to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for P384PublicKey {
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
    type Value = P384PublicKey;

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
pub struct P384Signature(RawSignature);

impl SignatureTrait for P384Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::P384
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::ES384
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

impl TryFrom<&[u8]> for P384Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for P384Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for P384Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{P384PublicKey, P384SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "z4AERjXT14BSyyzd526tP38BjBauZjyEuCVidQPsY7EsUU1JzExBk9w2BzwNgVF6kYg";
    const PUBLIC: &str = "zStaZkWzgPtpoJc43ZLBP7yRPNWsSdnkTBZdSCnVfNpScC16FEVgTYwyTYUCdvJdRsN";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = P384SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = P384PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = P384SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = P384SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = P384PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = P384SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = P384PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = P384SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key = P384SecretKey::from_str(SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let signature = private_key.sign_deterministic(data, None, None)?;

        assert_eq!(
            signature.to_string(),
            "z5xKCLkec6kTZrnhtCkxeNa4vF8M9kBHU64vMmeFXLzuHShPxA9ZXyWr174SBCrznR5WEYoQ8PpdcpwdZ1T3SY52MHSBy2HghYhGJ2CyqKdx9rWTHqC26JbTutHk1XmEXPpH"
        );
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
