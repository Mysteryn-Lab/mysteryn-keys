use hmac::{Hmac, Mac};
use mysteryn_core::{
    RawSignature,
    attributes::{KeyAttributes, SignatureAttributes},
    key_traits::*,
    multibase,
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::{Error, Result},
};
use rand::{CryptoRng, RngCore, rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{any::Any, borrow::Cow, fmt::Display, str::FromStr};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Serialize, Deserialize)]
pub struct HmacSha256SecretKey(Vec<u8>);

impl HmacSha256SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key_value = vec![0; 32];
        rng.fill_bytes(&mut key_value);
        Self(key_value)
    }
}

impl Default for HmacSha256SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for HmacSha256SecretKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::HMAC_SHA256
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(HmacSha256PublicKey {})
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }

    fn get_shared_secret(&self, _: Option<&[u8]>) -> Option<Vec<u8>> {
        None
    }

    fn sign(&self, data: &[u8], _: Option<&mut SignatureAttributes>) -> Result<RawSignature> {
        let mut mac = HmacSha256::new_from_slice(&self.0)
            .map_err(|error| Error::InvalidKey(error.to_string()))?;
        mac.update(data);
        Ok(RawSignature::from(mac.finalize().into_bytes().as_slice()))
    }

    fn sign_exchange(
        &self,
        data: &[u8],
        _: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.sign(data, attributes)
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        _other_public_key_raw_bytes: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.sign(data, attributes)
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let mut mac = HmacSha256::new_from_slice(&self.0)
            .map_err(|error| Error::InvalidKey(error.to_string()))?;
        mac.update(data);
        mac.verify_slice(signature.as_bytes())
            .map_err(|error| Error::InvalidSignature(error.to_string()))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(HmacSha256Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for HmacSha256SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for HmacSha256SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HmacSha256SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for HmacSha256SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey("invalid key length".to_string()));
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl FromStr for HmacSha256SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for HmacSha256SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            if key_data.len() != 32 {
                return Err(Error::InvalidKey("invalid key length".to_string()));
            }
            Ok(Self(key_data.to_vec()))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HmacSha256PublicKey();

impl PublicKeyTrait for HmacSha256PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::HMAC_SHA256
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&[])
    }

    fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    fn can_verify(&self) -> bool {
        false
    }

    fn verify(&self, _data: &[u8], _signature: &RawSignature) -> Result<()> {
        Err(Error::InvalidKey(
            "this key type cannot verify signatures".to_string(),
        ))
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(HmacSha256Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PartialEq for HmacSha256PublicKey {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for HmacSha256PublicKey {}

impl PartialOrd for HmacSha256PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HmacSha256PublicKey {
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}

impl Display for HmacSha256PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for HmacSha256PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HmacSha256PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for HmacSha256PublicKey {
    type Error = Error;
    fn try_from(_bytes: &[u8]) -> Result<Self> {
        Ok(Self())
    }
}

impl FromStr for HmacSha256PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for HmacSha256PublicKey {
    type Error = Error;
    fn try_from(_attributes: &KeyAttributes) -> Result<Self> {
        Ok(Self())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct HmacSha256Signature(RawSignature);

impl SignatureTrait for HmacSha256Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::HMAC_SHA256
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

impl TryFrom<&[u8]> for HmacSha256Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for HmacSha256Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for HmacSha256Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{HmacSha256PublicKey, HmacSha256SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "zFqb4CSKF6hkxVi2HZ59LDC6xWfkwejCVsrB3dFtSk4uK";
    const PUBLIC: &str = "z";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = HmacSha256SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = HmacSha256PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = HmacSha256SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = HmacSha256SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = HmacSha256PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = HmacSha256SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = HmacSha256PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let secret_key = HmacSha256SecretKey::from_str(SECRET)?;
        let data = b"test data";
        let signature = secret_key.sign_deterministic(data, None, None)?;

        assert_eq!(
            signature.to_string(),
            "z6pwirmnKBE8WFdEw7w2rvzbkDA5WJ6Rq8R6cL4rDRxQW"
        );
        secret_key.verify(data, &signature)?;

        Ok(())
    }
}
