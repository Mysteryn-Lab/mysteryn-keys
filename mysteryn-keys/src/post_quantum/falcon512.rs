use falcon_rust::falcon512::{self, PublicKey as VerifyingKey, SecretKey as SigningKey, Signature};
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
use std::{any::Any, borrow::Cow, fmt::Display, str::FromStr};

#[derive(Clone)]
pub struct Falcon512SecretKey(SigningKey);

impl Falcon512SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng())
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = SigningKey::generate_from_seed(rng.random());
        Self(secret_key)
    }
}

impl Default for Falcon512SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for Falcon512SecretKey {
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
        known_algorithm_name::Falcon512
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(Falcon512PublicKey(VerifyingKey::from_secret_key(&self.0)))
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.to_bytes().into()
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
        let signature: Signature = falcon512::sign(data, &self.0);
        Ok(RawSignature::from(signature.to_bytes().as_slice()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        _: Option<&[u8]>,
        _: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        // TODO: Implement deterministic signatures
        let signature: Signature = falcon512::sign(data, &self.0);
        Ok(RawSignature::from(signature.to_bytes().as_slice()))
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let signature = Signature::from_bytes(signature.as_bytes())
            .map_err(|_| Error::InvalidSignature("malformed signature bytes".to_string()))?;
        let public_key = VerifyingKey::from_secret_key(&self.0);
        if falcon512::verify(data, &signature, &public_key) {
            Ok(())
        } else {
            Err(Error::InvalidSignature("invalid signature".to_string()))
        }
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Falcon512Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl Display for Falcon512SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Falcon512SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Falcon512SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Falcon512SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let secret_key = SigningKey::from_bytes(bytes)
            .map_err(|_| Error::InvalidKey("malformed key bytes".to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for Falcon512SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Falcon512SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let secret_key = SigningKey::from_bytes(key_data)
                .map_err(|_| Error::InvalidKey("malformed key bytes".to_string()))?;
            Ok(Self(secret_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

impl Serialize for Falcon512SecretKey {
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

impl<'de> Deserialize<'de> for Falcon512SecretKey {
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
    type Value = Falcon512SecretKey;

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
pub struct Falcon512PublicKey(VerifyingKey);

impl PublicKeyTrait for Falcon512PublicKey {
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
        known_algorithm_name::Falcon512
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.0.to_bytes().into()
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

        if falcon512::verify(data, &signature, &self.0) {
            Ok(())
        } else {
            Err(Error::InvalidSignature("invalid signature".to_string()))
        }
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Falcon512Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_ssh_key(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }
}

impl PartialEq for Falcon512PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Falcon512PublicKey {}

impl PartialOrd for Falcon512PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Falcon512PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl Serialize for Falcon512PublicKey {
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

impl<'de> Deserialize<'de> for Falcon512PublicKey {
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
    type Value = Falcon512PublicKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Falcon512PublicKey::try_from(v).map_err(|_| serde::de::Error::custom("malformed key bytes"))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Falcon512PublicKey::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl Display for Falcon512PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for Falcon512PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Falcon512PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for Falcon512PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let public_key = VerifyingKey::from_bytes(bytes)
            .map_err(|_| Error::InvalidKey("malformed key bytes".to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for Falcon512PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for Falcon512PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let public_key = VerifyingKey::from_bytes(key_data)
                .map_err(|_| Error::InvalidKey("malformed key bytes".to_string()))?;
            Ok(Self(public_key))
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Falcon512Signature(RawSignature);

impl SignatureTrait for Falcon512Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::CUSTOM
    }

    fn signature_nonce_size(&self) -> usize {
        40
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::Falcon512
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

impl TryFrom<&[u8]> for Falcon512Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for Falcon512Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for Falcon512Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Falcon512PublicKey, Falcon512SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "z2qyHuetS7LFqmmzcqkyTEEKHmSmcJdD9ToxdgtTtdc5zANWFQnSywYpdTXCtfyZUkVrDSPvU7AU4vXDtFBF11Xr78XXHF5mSgPdc5RQ5nPdvz6KbTuAZtTRjXVWZq3j1KKTQJ5SH5REfVQUnR8rfrrfszicMxGSQ8fBgs9SGKNCU1y1jVhAQeky2bmY65XxCB6mEL3DGo1EqhYW7nKv5z3ofjQj673ZsGDRcC93sUq5WQLrDfyRqsngV65MQqLCsUydAxXxpCBv2AD1tisU17zEHHVWwKYHQMamUYwdKr3H7FzSgWd1W3AgZRSYqzY4RZmdLXvg13fJSimvKYcKmXzWwqQFf1dUbvKbkpsk7Vgu5YypN7tbobrwyMk5H648vi2ax1WuKs9FCMLzRKCBgTB8mfhXJxHrJcBSgqQdaNZaqQJrJnTa5CB8DZz9V7dWK8zpkB1QYRK3NJPmdrSJ84eq1fs9y2w9cinUXbeyr9T8oQdK1otUZsjLEo1s8dajKJdmCxNdHKEvNnafEPs6ZqnoBDpAHKK6rjrW59L2aPGEWFXSTqKXNfMUTLpAzMMHC56vXCXzvMK7kq3LJt4z78jJHj6uuxDqvNc5Cpf18m6LX55wBW7JWQQ261t2ih9sjcLk3XMq42p6Wv45nEy3P5U3MPxJkfiEpBp5YNVNxP3qBwS2UYkJDWADRm3jmLQ3fVxBsSfX58BTj2Y4i6R8zz2fknBD59T9CRjo2MREGs2BsUoE7mmf3DKSkK4BQyunK7zUH1aNmZ8Dxvi3UZxu2iMVH9srb2MdLW7LRpmHYHqw59S3xCDP2qGDyi8Gqf65r9oPung1X2PpZTKqMK7ZTRn2GwsDeVyRNvrfov72fvie6LiJBk5JcCxis647Nk2Esa2GXYZXSB7eQ8L1WGBufLkLdRR7NYTNJgthPX5TqAiFyQuH8J2AiMG8QuEjQ3va9pubTv6Bx6FVXp6FEgjL6nV297M1vGooJeypAbfJzVZywqSwHry4foixFqVUMRpKarvMFnP7UEGTmRvMQE5xagQq1XZATLmXS6K8p6QTirMf2xpoBaRatfY33korBUnQSkwHw3Deq7QSvZagmRxaBgxTj1bTRBTkTDjRPp1Peaf9uTQFFwFEJpuWCAnhWooy848BBmQopDRoUbetgHcZ1B74ExYcj5noYpZFghzbtpUKr51bmyChuJ7vkkYptfTcrCWKFR3EfEQgqDRUociuuSTxdExBWrPydfDWQggFNbons8QsiUTPvjUQ2MAALPyAyagRTznXweqiF8obRF1jSeNb8LhotjWEDsddvMenxquQTDPhyc37XvNBnYEJpkwD5LhFyYmRXo7GZprUVCKVkWFe9mwqzMqcnNz8rKFok4dEgnEtmWFcNvU1hmoAiNhtfbB99ng2AoBaLDwFM69MfsHkBQp9BT1aitHzxXb4Nouqh1C5iRwiGXerw3cykva3ZjgbACQ28y3ZUNe9cr4oiYfJidBm5DpHayKr42igw1wZCYX4bZeHDoR2MwEJsS9XdBFgKahA7UvCAVjpuE5vAbNAWTeTR7AADP1cf3vo3ckQMnmdNwDSiWrjMLFCk2qth647gSuzjy6cg7diNm6ggJCVbj8DbDwwXqahz2neX9U89fwc8nd5KP3pzKL1DDsiqaCVBv4wP8gLuCri8XxoLwBWpT379BKHvUn3sSVfz1fQxMPCriFUng3rzLu1MaobhWqnkpUFT5WvjEjAuunoTiC";
    const PUBLIC: &str = "z37rY9FKtUgdcEBK12VR9PxeBuSUJwYpgZd3P3zRKtte89ek3e3P5f1Yf9m6wBk6GoJ3Ty4BQBscP2Gcec5otKnC3vRQAcouhEyEnvnzGauqeN8XS2WpNZVm1QGHf6K9rP4fFq3HKj1JYksAdDJCokkVEKz3XikJrNxKQfEvqa4gd4QfiPCcSZ7LGLU3ZkkKL12x4DYHU2basboeHZmifjrG5TAFvgQF6MQGyQwwd2YLfSDZbFgkeows1Ywv1mPTfKM9P6KypdDeJUNKZmU3R3y1rVSdbspeeh54tGKvRm6v1n7ruNNVJKSxDb3s22awi3o3tw95KzqtCjTu4ZJSG3AhzrjuP5ihxUAAc2axUNZForrJubRX23fKVY6VhZJVZtpCFhdGwrfVDqXS6jWaXraKrMgHk1Suv3Xjh84YbXtp5zx9qP4GapzukE13ZTmdkBhawkmgKLosUWr4eN2AxpkVjRhbxHYno6JfHniSSAvnrkABzgSNEqD8UnSSWZmV8Su1aqpqsUFgz5gcwDx1ww7roN1BFi45peQ3xrZLVeJSAAHkxt2oNj1odNQZNnUbesdVRhuMQaDMqmXB3fAfYaMPJj3q6iUYv3RLDHGq3jxHs2xNQTq9vJ8g6HvcBTetjhiJYSja5siD4Pa2Q56cb3nBeDLrLJiwrgUZdvTUbbgRAZ4L8AUc34ZjhfKLY2GBn9TQSVoSQjgadJHBJxfU4whmohrs8czmxm2kruyE868QvfG3LyBvBJb5tvXFYFsxp8NTSqnWKjrt66C5d1kZh97ti9zEnLzuaQncCUNzPeJjUGsQoVnB9W9BNXL4Zw5NAqatbTHsHosxNwLvn7DMgZv8FnCJ34XdJ3WHCid8xQzijpKATvYNfttm6htvQVM4wXfBKTgWTcDJZmh9Zpzmm3aUcpxBPUebuQxVjX4siDGics83Fuus9NfBa1mbEkurzuo45mjwkSHCf3FuG7m7o7as4taYy61kK4S6UMVW7k2ztqtV8wzvqZRTEfiaasNShvwTF6BkzTqVFmPMdR12feryzaMTTiVaDfy4zyzF24fGUKcYVhmMbX2DnLdnFd1H79tzdiuw8rdu98aDwmZwuBQHmhmbpEEuq5dURN6tszWZFRrVrYrVHXAwKadsMngwxzgCoJRuCztBoLULTURm45vPWmuWaGufP3Ft36oDixrFzNsVfbhKFp6Ma8kxF4A6XAXu5nFUG7";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = Falcon512SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = Falcon512PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = Falcon512SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = Falcon512SecretKey::try_from(secret_key_bytes.as_ref())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Falcon512PublicKey::try_from(public_key_bytes.as_ref())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = Falcon512SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = Falcon512PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = Falcon512SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key = Falcon512SecretKey::from_str(SECRET)?;
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
