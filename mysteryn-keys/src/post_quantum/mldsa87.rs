///! This does not work in Wasm: "wasm trap: out of bounds memory access".
use fips204::traits::{SerDes, Signer, Verifier};
use fips204::{
    ml_dsa_87,
    ml_dsa_87::{PrivateKey as SigningKey, PublicKey as VerifyingKey},
}; // Could also be ml_dsa_44 or ml_dsa_65.
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
pub struct MlDsa87SecretKey(SigningKey);

impl MlDsa87SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng()).expect("cannot generate MlDsa87")
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let (_pk, sk) =
            ml_dsa_87::try_keygen_with_rng(rng).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(Self(sk))
    }
}

impl Default for MlDsa87SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for MlDsa87SecretKey {
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
        known_algorithm_name::MLDSA87
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(MlDsa87PublicKey(self.0.get_public_key()))
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
        let mut s: [u8; 4627] = [0; 4627];
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
        Ok(Box::new(MlDsa87Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for MlDsa87SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for MlDsa87SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsa87SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for MlDsa87SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut buf: [u8; 4896] = [0; 4896];
        let mut r = bytes;
        std::io::copy(&mut r, &mut buf.as_mut_slice())
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let secret_key =
            SigningKey::try_from_bytes(buf).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for MlDsa87SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for MlDsa87SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let mut buf: [u8; 4896] = [0; 4896];
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
pub struct MlDsa87PublicKey(VerifyingKey);

impl PublicKeyTrait for MlDsa87PublicKey {
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
        known_algorithm_name::MLDSA87
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
        let mut s: [u8; 4627] = [0; 4627];
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
        Ok(Box::new(MlDsa87Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl PartialEq for MlDsa87PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.clone().into_bytes() == other.0.clone().into_bytes()
    }
}

impl Eq for MlDsa87PublicKey {}

impl Display for MlDsa87PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for MlDsa87PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsa87PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for MlDsa87PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut buf: [u8; 2592] = [0; 2592];
        let mut r = bytes;
        std::io::copy(&mut r, &mut buf.as_mut_slice())
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let public_key =
            VerifyingKey::try_from_bytes(buf).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for MlDsa87PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for MlDsa87PublicKey {
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
pub struct MlDsa87Signature(RawSignature);

impl SignatureTrait for MlDsa87Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::MLDSA87
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

impl TryFrom<&[u8]> for MlDsa87Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for MlDsa87Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for MlDsa87Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{MlDsa87PublicKey, MlDsa87SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "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";
    const PUBLIC: &str = "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";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = MlDsa87SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = MlDsa87PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = MlDsa87SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = MlDsa87SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = MlDsa87PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = MlDsa87SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = MlDsa87PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = MlDsa87SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key = MlDsa87SecretKey::from_str(SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let signature = private_key.sign_deterministic(data, None, None)?;

        //assert_eq!(signature.to_string(), "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");
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
