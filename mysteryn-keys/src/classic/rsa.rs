use mysteryn_core::{
    RawSignature,
    attributes::{HASH_ATTR_ID, KeyAttributes, SignatureAttributes},
    key_traits::*,
    multibase,
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::{Error, Result},
};
use rand08::{CryptoRng, RngCore, thread_rng as rng};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature as RsaSignature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
use std::{any::Any, borrow::Cow, fmt::Display, str::FromStr};

pub const MIN_RSA_BITS: usize = 2048;
pub const DEFAULT_RSA_256_BITS: usize = 3072;
pub const DEFAULT_RSA_512_BITS: usize = 4096;

#[derive(Clone)]
pub struct Rs256SecretKey(RsaPrivateKey);

impl Rs256SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng(), DEFAULT_RSA_256_BITS).expect("cannot generate RSA")
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R, bits: usize) -> Result<Self> {
        if bits < MIN_RSA_BITS {
            return Err(Error::ValidationError(format!(
                "bit size {bits} is too weak",
            )));
        }
        let private_key =
            RsaPrivateKey::new(rng, bits).map_err(|e| Error::IOError(e.to_string()))?;
        Ok(Self(private_key))
    }
}

impl Default for Rs256SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for Rs256SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::RSA_SECRET
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::RSA
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::RS256
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(Rs256PublicKey(self.0.to_public_key()))
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        // TODO unsafe!
        self.0
            .to_pkcs8_der()
            .expect("RSA failed")
            .as_bytes()
            .to_vec()
            .into()
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
        let signing_key = SigningKey::<Sha256>::new(self.0.clone());
        let signature = signing_key
            .try_sign_with_rng(&mut rng(), data)
            .map_err(|e| Error::IOError(e.to_string()))?;
        // signature hash algorithm
        if let Some(attributes) = attributes {
            attributes.set_varint(HASH_ATTR_ID, Some(multicodec_prefix::SHA2_256));
        }
        Ok(RawSignature::from(signature.to_bytes().as_ref()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        _: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let signing_key = SigningKey::<Sha256>::new(self.0.clone());
        let signature = signing_key
            .try_sign(data)
            .map_err(|e| Error::IOError(e.to_string()))?;
        // signature hash algorithm
        if let Some(attributes) = attributes {
            attributes.set_varint(HASH_ATTR_ID, Some(multicodec_prefix::SHA2_256));
        }
        Ok(RawSignature::from(signature.to_bytes().as_ref()))
    }

    fn verify(&self, payload: &[u8], signature: &RawSignature) -> Result<()> {
        let verifying_key = VerifyingKey::<Sha256>::new(RsaPublicKey::from(self.0.clone()));
        let sig = RsaSignature::try_from(signature.as_slice())
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        verifying_key
            .verify(payload, &sig)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Rs256Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for Rs256SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Rs256SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rs256SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Rs256SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let private_key =
            RsaPrivateKey::from_pkcs8_der(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(private_key))
    }
}

impl FromStr for Rs256SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Rs256SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let secret_key = RsaPrivateKey::from_pkcs8_der(key_data)
                .map_err(|e| Error::InvalidKey(e.to_string()))?;
            Ok(Self(secret_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl Serialize for Rs256SecretKey {
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

impl<'de> Deserialize<'de> for Rs256SecretKey {
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
    type Value = Rs256SecretKey;

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
pub struct Rs256PublicKey(RsaPublicKey);

impl PublicKeyTrait for Rs256PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::RSA
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::P256
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::RS256
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        // TODO unsafe!
        self.0
            .to_public_key_der()
            .expect("RSA failed")
            .as_bytes()
            .to_vec()
            .into()
    }

    fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    fn can_verify(&self) -> bool {
        true
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let verifying_key = VerifyingKey::<Sha256>::new(self.0.clone());
        let sig = RsaSignature::try_from(signature.as_slice())
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        verifying_key
            .verify(data, &sig)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Rs256Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for Rs256PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Rs256PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rs256PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Rs256PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let public_key = RsaPublicKey::from_public_key_der(bytes)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for Rs256PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Rs256PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let public_key = RsaPublicKey::from_public_key_der(key_data)
                .map_err(|e| Error::InvalidKey(e.to_string()))?;
            Ok(Self(public_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl PartialOrd for Rs256PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_bytes().cmp(&other.to_bytes()))
    }
}

impl Ord for Rs256PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Serialize for Rs256PublicKey {
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

impl<'de> Deserialize<'de> for Rs256PublicKey {
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
    type Value = Rs256PublicKey;

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
pub struct Rs256Signature(RawSignature);

impl SignatureTrait for Rs256Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::RSA
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::RS256
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

impl TryFrom<&[u8]> for Rs256Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for Rs256Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for Rs256Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[derive(Clone)]
pub struct Rs512SecretKey(RsaPrivateKey);

impl Rs512SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng(), DEFAULT_RSA_512_BITS).expect("cannot generate RSA")
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R, bits: usize) -> Result<Self> {
        if bits < MIN_RSA_BITS {
            return Err(Error::ValidationError(format!(
                "bit size {bits} is too weak",
            )));
        }
        let private_key =
            RsaPrivateKey::new(rng, bits).map_err(|e| Error::IOError(e.to_string()))?;
        Ok(Self(private_key))
    }
}

impl Default for Rs512SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for Rs512SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::RSA_SECRET
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::RSA
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::RS512
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(Rs512PublicKey(self.0.to_public_key()))
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        // TODO unsafe!
        self.0
            .to_pkcs8_der()
            .expect("RSA failed")
            .as_bytes()
            .to_vec()
            .into()
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
        let signing_key = SigningKey::<Sha512>::new(self.0.clone());
        let signature = signing_key.sign_with_rng(&mut rng(), data);
        // signature hash algorithm
        if let Some(attributes) = attributes {
            attributes.set_varint(HASH_ATTR_ID, Some(multicodec_prefix::SHA2_512));
        }
        Ok(RawSignature::from(signature.to_bytes().as_ref()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        _: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let signing_key = SigningKey::<Sha512>::new(self.0.clone());
        let signature = signing_key.sign(data);
        // signature hash algorithm
        if let Some(attributes) = attributes {
            attributes.set_varint(HASH_ATTR_ID, Some(multicodec_prefix::SHA2_512));
        }
        Ok(RawSignature::from(signature.to_bytes().as_ref()))
    }

    fn verify(&self, payload: &[u8], signature: &RawSignature) -> Result<()> {
        let verifying_key = VerifyingKey::<Sha512>::new(RsaPublicKey::from(self.0.clone()));
        let sig = RsaSignature::try_from(signature.as_slice())
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        verifying_key
            .verify(payload, &sig)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Rs512Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for Rs512SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Rs512SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rs512SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Rs512SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let private_key =
            RsaPrivateKey::from_pkcs8_der(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(private_key))
    }
}

impl FromStr for Rs512SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Rs512SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let secret_key = RsaPrivateKey::from_pkcs8_der(key_data)
                .map_err(|e| Error::InvalidKey(e.to_string()))?;
            Ok(Self(secret_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl Serialize for Rs512SecretKey {
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

impl<'de> Deserialize<'de> for Rs512SecretKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(CustomVisitor2)
        } else {
            deserializer.deserialize_bytes(CustomVisitor2)
        }
    }
}
struct CustomVisitor2;
impl serde::de::Visitor<'_> for CustomVisitor2 {
    type Value = Rs512SecretKey;

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
pub struct Rs512PublicKey(RsaPublicKey);

impl PublicKeyTrait for Rs512PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::RSA
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::RSA
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::RS512
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        // TODO unsafe!
        self.0
            .to_public_key_der()
            .expect("RSA failed")
            .as_bytes()
            .to_vec()
            .into()
    }

    fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    fn can_verify(&self) -> bool {
        true
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let verifying_key = VerifyingKey::<Sha512>::new(self.0.clone());
        let sig = RsaSignature::try_from(signature.as_slice())
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        verifying_key
            .verify(data, &sig)
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Rs512Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for Rs512PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Rs512PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rs512PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Rs512PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let public_key = RsaPublicKey::from_public_key_der(bytes)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for Rs512PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Rs512PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let public_key = RsaPublicKey::from_public_key_der(key_data)
                .map_err(|e| Error::InvalidKey(e.to_string()))?;
            Ok(Self(public_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl PartialOrd for Rs512PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_bytes().cmp(&other.to_bytes()))
    }
}

impl Ord for Rs512PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Serialize for Rs512PublicKey {
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

impl<'de> Deserialize<'de> for Rs512PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(CustomVisitor512)
        } else {
            deserializer.deserialize_bytes(CustomVisitor512)
        }
    }
}
struct CustomVisitor512;
impl serde::de::Visitor<'_> for CustomVisitor512 {
    type Value = Rs512PublicKey;

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
pub struct Rs512Signature(RawSignature);

impl SignatureTrait for Rs512Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::RSA
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::RS512
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

impl TryFrom<&[u8]> for Rs512Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for Rs512Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for Rs512Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Rs256PublicKey, Rs256SecretKey, Rs512PublicKey, Rs512SecretKey};
    use mysteryn_core::{attributes::SignatureAttributes, key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const RSA_3072_SECRET: &str = "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";
    const RSA_3072_PUBLIC: &str = "zfMBAZAq2TT5GgwvrYdQcUj8cWuhTmf6FxcJXaNaYc1EcnD9YGutt1FeqANeTDKPMSNTKgLXwH4Sh9UoNPEfp1Tv9dt9yJajYaiQiRrUGF7F8BWpfVxQtKksHkDUiD3EKNR16FXiV9fkmW2xb8k1eZhWkXQUEnkzfWNdMjzfJpAFoHhqVMzL9ytG43LRzQ4ytMENSmPWYo4QpU5B6oae3P7FQxmwiSFkFpgQntDWBD8BuhBHFxooDafQSq4RppZsEigQwCHvMePW6QfM1bdCakFoKehamHjCn9jLRfCYsDQZ8NjJ4mPCE6U1c9PuuKZ2hUo8cpC1kgPjGCh3LDSRP9PnZttxBaS5NEzzHwHoiSFEowqz5CaVa1jikbxNrKY3E9abUFvgvEVUyGnigT4NSusRJe6uYmL8YKDQG7QdaUx1YJWjj66vbXcthu5wUbe6kUGoYrY4igtJ2jDtSEViuf37k7P1syWAMCRNsXLP317anbRApqF8TtGwSFRuYyHDwrWdtbzXoPsfaGD8EADJh4mxanfdJpWpASRuCwA7wvzN8J9dBUQqNwn7s2perzYFa";
    const RSA_4096_SECRET: &str = "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";
    const RSA_4096_PUBLIC: &str = "zJKaohp7cU8Y6MT2aScYEKz1471mJE749vvzUSJRH8KMVZFQ2CBrF4r9bo8Bgq53DD5kY86XocHbp3H89n9M7EK2RPmphS9EJYPsopBBHkghgFiQiKF8SWbv7shXGPBNTZXinddRh99sR6gw779sJE4xZQFGCgX1ftj81UXoZMTwqpqg4QhiQRw7Nnrz5fmrbwEk4w3zq9KMfd4ySH5VugjWGQXbJFWaA77aDqKwtBhqiKzMr11ugdmFkkqLWhE9aPwf3v46AvT3a48kk16cTPbuYkk7SAFCYbyohbFY1QUE3ZtdzpZLZqeWPkx9FouwxW8afWc2swzeGCWQM85mRbLAGwkZ11EzxToJvyqz21SnniRYAwxUYYGNqHqCwhtmRBfPpFbzdp5YksUTEqkhne2JpDTUhUTCvYSLbisvoQs1pYwJdvgCSqwb1hu525arqEUZHjURmf6qeVSJmbBccerGUjSofUNUYCXpFA9mshbgq6GmXCpLaRnqRE4SQKvBAs5z66akgXH2YqKJGadZq1NMp6HEDKhgB2nSPs3nmMivexa54rFYuTcQpPEpCd9ou9ZYZ9Hi25zhK4JbbFbMtTPDWtDFKdx1Aev7AD9zTnmdRJUH12EHkWxB5EGVJuSEUF3CqksLe9sFwLZDvRhSmov1Kku2FoZjZmsee9Kwr9sRKd9MzvgaN3gSo3JYh7RZu4DwYujQLWTi5ADf3JQ5CY3o7JzBGfP2TkAmJJqwMoNZwqha";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize_256() {
        let secret_key = Rs256SecretKey::from_str(RSA_3072_SECRET).expect("cannot read key");
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), RSA_3072_SECRET);
        assert_eq!(public_key.to_string(), RSA_3072_PUBLIC);

        let public_key = Rs256PublicKey::from_str(RSA_3072_PUBLIC).expect("cannot read key");
        assert_eq!(public_key.to_string(), RSA_3072_PUBLIC);

        let secret_key = Rs256SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key =
            Rs256SecretKey::try_from(secret_key_bytes.as_ref()).expect("cannot read key");
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key =
            Rs256PublicKey::try_from(public_key_bytes.as_ref()).expect("cannot read key");
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key =
            Rs256SecretKey::from_str(&secret_key_str).expect("cannot read key");
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key =
            Rs256PublicKey::from_str(&public_key_str).expect("cannot read key");
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize_512() -> Result<()> {
        let secret_key = Rs512SecretKey::from_str(RSA_3072_SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), RSA_3072_SECRET);
        assert_eq!(public_key.to_string(), RSA_3072_PUBLIC);

        let public_key = Rs512PublicKey::from_str(RSA_3072_PUBLIC)?;
        assert_eq!(public_key.to_string(), RSA_3072_PUBLIC);

        let secret_key = Rs512SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = Rs512SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Rs512PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = Rs512SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Rs512PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize_512_4096() {
        let secret_key = Rs512SecretKey::from_str(RSA_4096_SECRET).expect("from_str failed");
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), RSA_4096_SECRET);
        assert_eq!(public_key.to_string(), RSA_4096_PUBLIC);

        let public_key = Rs512PublicKey::from_str(RSA_4096_PUBLIC).expect("from_str failed");
        assert_eq!(public_key.to_string(), RSA_4096_PUBLIC);

        let secret_key = Rs512SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key =
            Rs512SecretKey::try_from(secret_key_bytes.as_ref()).expect("from bytes failed");
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key =
            Rs512PublicKey::try_from(public_key_bytes.as_ref()).expect("from bytes failed");
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key =
            Rs512SecretKey::from_str(&secret_key_str).expect("from string failed");
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key =
            Rs512PublicKey::from_str(&public_key_str).expect("from string failed");
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent_256() -> Result<()> {
        let secret_key = Rs256SecretKey::from_str(RSA_3072_SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), RSA_3072_PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent_512() -> Result<()> {
        let secret_key = Rs512SecretKey::from_str(RSA_3072_SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), RSA_3072_PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent_512_4096() -> Result<()> {
        let secret_key = Rs512SecretKey::from_str(RSA_4096_SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), RSA_4096_PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message_256() -> Result<()> {
        let private_key = Rs256SecretKey::from_str(RSA_3072_SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let nonce = b"12345678";
        let mut attributes = SignatureAttributes::default();
        attributes.set_nonce(Some(nonce));
        let signature = private_key.sign_deterministic(data, None, Some(&mut attributes))?;

        assert_eq!(
            signature.to_string(),
            "z2Wzvw2VqsnUNYfmJ8oDgFjbR5jynQ59WogmNApuiuVHVxeCkNz4rzTAwm3Jo1YsnLRsYDf5UnAbXNnBf6LASUqTkT3goJ1LiDwKVed9gNv8kWeiJo16ynendfPhF66iVVBZQBcxT5vLJgrA2HTurdqra9hFLEHUih9vdBd3PNBSRxqFz9KkrRgNLWAjkCWqQ97EmzWVppb4AY58nURNoUKRraGh3heVgJ8GAbjfauBbja4L1v41qf9ZrgkyUSXxYUJc5ysD3uvD5URCVd41Xqdy1WgSgU34Q9ZhKNjy29cXqVekd2cQuYqLm28qrBuwrBs68CWerJavG3dJFwd9nwYvh8DdEK1CXUW5jPp3T1dXMepBb9vCRdTeEWamspnDpbtvxHcQgGmP3qpuPn6YTbm8Awq4JguyaoKkBj3xmqiLgwzu6RoFuiMRmHTxFQyrQUqasTFTjdneUT4S6WhGTqyaSWikapJTLkzKk6GrzfPJAhg3gHSBBxeKqrrFxFYbAt4uDSJfzhmt9Q"
        );
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message_512() -> Result<()> {
        let private_key = Rs512SecretKey::from_str(RSA_3072_SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let nonce = b"12345678";
        let mut attributes = SignatureAttributes::default();
        attributes.set_nonce(Some(nonce));
        let signature = private_key.sign_deterministic(data, None, Some(&mut attributes))?;

        assert_eq!(
            signature.to_string(),
            "znCizpUJQaNEY91fsy2PcLG6fCA7iupMBz6zzCwL7LQiLkzfjXucADSyroWiqrnDWAirfWLaTNEMqWK2jrEHnsUXnAMa63RFYfV4nZq3LwJFXgtHBmZR7ApDtuqihivfwwC95Y5Erbkg1ZKpS9h3wr6c5rEmUos53x6gWtAuB5FZqAgk4ronP8UTFtD2KrzFaM2cbhHYYyVW4M2k9wCBZmwFDJvpCpaRCHx7UDitpHuY9V7XSJ1F5jNAmRfQBdismZ3we7RFK7LxRJtiKEgxufvMz5EvBTgvSRDyk9k8KmTuVLGnGHS5UqcLJhoKvBBnxFf9UBStJQNTNUD7AK2nhu3jRpVkfsQJNKm9kagqM2dF9L5RmGhYHtSHvwvePZGGkPQfcQzAVepyHdWvgr2paB4ps5s64M8W5B6M2HyR6X1s3EkbJtvzi86M2LkcwV41ANW6w9K2MZGLFWc4AsQhJVo59y9MGNGhGaAEksApSDLZ5RPLMrxrjDxKHD7KqKg5nP2BEDp2NXbSZ"
        );
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message_512_4096() -> Result<()> {
        let private_key = Rs512SecretKey::from_str(RSA_4096_SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let nonce = b"12345678";
        let mut attributes = SignatureAttributes::default();
        attributes.set_nonce(Some(nonce));
        let signature = private_key.sign_deterministic(data, None, Some(&mut attributes))?;

        assert_eq!(
            signature.to_string(),
            "zpSaMmafi3A9ciwvh1DGWKNAMRJSQTNznyPG9e3GBKiWU3X99jqGpKVjiUuJe3KomrWPnrqw4hapHs7RurZZKq6Brj85fbuPg2zxskLb28QG4uM9wmciT3xoyo4Sg2Tugx2vQcYXUs1WL2EiF6QddeRUn5f9c8AD3wN6ouuraKL1p3UfJE46k71eQRvwmnjfdHYuytBDndnpy4cX7GXnBiFMYss9aojhhWgwhGMkr2PvxEn2RmXrF5P6QVLjq8twEg2ez7MTpW2qGpJ8TT5Xeje2sf5xuSirC2GzQmg8e4UfAdt4CsZazAHprWKWG9dxbMh5aZToUgBsgFD8AngHQ1qCc9ynsb4Vpp7FJarheuXXu3A6qLGEYbZh8HYhTYhPUkBQ55kqa2H9mmdUz7k2xFQcM8M777G6DXRgc5bLGFHfh1dbuZU8zLbt3wR7tdd1uApC3asp7XcwEmPiEFWhXPGxreyi23hSAjVGyk9jZ9eXo1A744kR3ZUUMECJ7wdALZohj1KEA4EQPZHCSoqF1m2axhww78Mp43fLjJ8rY1HVBSbXTD1QSxPvRu9qkjaXsnDxNVSVBdoYsyNWAZ7eEA7YZLyap2Fxjibokr4Zk6vD9eBFHJEU9cQpQX2EbrVVYUdZTV82jovbyDV8utmNPJGHKz5aPGvsWkbqHM5bb8f7QhV9AEVvBT3JQYoA"
        );
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
