use fips204::traits::{SerDes, Signer, Verifier};
use fips204::{
    ml_dsa_65,
    ml_dsa_65::{PrivateKey as SigningKey, PublicKey as VerifyingKey},
}; // Could also be ml_dsa_44 or ml_dsa_87.
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
use std::{
    any::Any,
    borrow::Cow,
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Clone)]
pub struct MlDsa65SecretKey(SigningKey);

impl MlDsa65SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng()).expect("cannot generate MlDsa65")
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let (_pk, sk) =
            ml_dsa_65::try_keygen_with_rng(rng).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(Self(sk))
    }
}

impl Default for MlDsa65SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for MlDsa65SecretKey {
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
        known_algorithm_name::MLDSA65
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(MlDsa65PublicKey(self.0.get_public_key()))
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.clone().into_bytes().to_vec().into()
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
        let signature = self
            .0
            .try_sign(data, &[])
            .map_err(|e| Error::IOError(e.to_string()))?;
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
        let mut s: [u8; 3309] = [0; 3309];
        let mut r = signature.as_slice();
        std::io::copy(&mut r, &mut s.as_mut_slice())
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;

        if self.0.get_public_key().verify(data, &s, &[]) {
            Ok(())
        } else {
            Err(Error::InvalidSignature(
                "failed to verify signature".to_string(),
            ))
        }
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(MlDsa65Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for MlDsa65SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for MlDsa65SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsa65SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for MlDsa65SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut buf: [u8; 4032] = [0; 4032];
        let mut r = bytes;
        std::io::copy(&mut r, &mut buf.as_mut_slice())
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let secret_key =
            SigningKey::try_from_bytes(buf).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for MlDsa65SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for MlDsa65SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let mut buf: [u8; 4032] = [0; 4032];
            let mut r = key_data;
            std::io::copy(&mut r, &mut buf.as_mut_slice())
                .map_err(|e| Error::InvalidKey(e.to_string()))?;
            let secret_key =
                SigningKey::try_from_bytes(buf).map_err(|e| Error::InvalidKey(e.to_string()))?;
            Ok(Self(secret_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

#[derive(Clone)]
pub struct MlDsa65PublicKey(VerifyingKey);

impl PublicKeyTrait for MlDsa65PublicKey {
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
        known_algorithm_name::MLDSA65
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.clone().into_bytes().to_vec().into()
    }

    fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    fn can_verify(&self) -> bool {
        true
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let mut s: [u8; 3309] = [0; 3309];
        let mut r = signature.as_slice();
        std::io::copy(&mut r, &mut s.as_mut_slice())
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;

        if self.0.verify(data, &s, &[]) {
            Ok(())
        } else {
            Err(Error::InvalidSignature(
                "failed to verify signature".to_string(),
            ))
        }
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(MlDsa65Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl PartialEq for MlDsa65PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.clone().into_bytes() == other.0.clone().into_bytes()
    }
}

impl Eq for MlDsa65PublicKey {}

impl Display for MlDsa65PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for MlDsa65PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsa65PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for MlDsa65PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut buf: [u8; 1952] = [0; 1952];
        let mut r = bytes;
        std::io::copy(&mut r, &mut buf.as_mut_slice())
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let public_key =
            VerifyingKey::try_from_bytes(buf).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for MlDsa65PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for MlDsa65PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            Self::try_from(key_data)
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct MlDsa65Signature(RawSignature);

impl SignatureTrait for MlDsa65Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::MLDSA65
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

impl TryFrom<&[u8]> for MlDsa65Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for MlDsa65Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for MlDsa65Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{MlDsa65PublicKey, MlDsa65SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "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";
    const PUBLIC: &str = "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";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = MlDsa65SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = MlDsa65PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = MlDsa65SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = MlDsa65SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = MlDsa65PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = MlDsa65SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = MlDsa65PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = MlDsa65SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key = MlDsa65SecretKey::from_str(SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let signature = private_key.sign_deterministic(data, None, None)?;

        //assert_eq!(signature.to_string(), "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");
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
