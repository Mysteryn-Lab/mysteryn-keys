use fips204::traits::{SerDes, Signer, Verifier};
use fips204::{
    ml_dsa_44,
    ml_dsa_44::{PrivateKey as SigningKey, PublicKey as VerifyingKey},
}; // Could also be ml_dsa_65 or ml_dsa_87.
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
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Clone)]
pub struct MlDsa44SecretKey(SigningKey);

impl MlDsa44SecretKey {
    pub fn new() -> Self {
        Self::with_rng(&mut rng()).expect("cannot generate MlDsa44")
    }

    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let (_pk, sk) =
            ml_dsa_44::try_keygen_with_rng(rng).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(Self(sk))
    }
}

impl Default for MlDsa44SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretKeyTrait for MlDsa44SecretKey {
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
        known_algorithm_name::MLDSA44
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        Box::new(MlDsa44PublicKey(self.0.get_public_key()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone().into_bytes().to_vec()
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
        let signature = self
            .0
            .try_sign(data, &[])
            .map_err(|e| Error::IOError(e.to_string()))?;
        Ok(RawSignature::from(signature.as_slice()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<Vec<u8>>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.sign_exchange(data, other_public_key_raw_bytes, attributes)
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let mut s: [u8; 2420] = [0; 2420];
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
        Ok(Box::new(MlDsa44Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Display for MlDsa44SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for MlDsa44SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsa44SecretKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for MlDsa44SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut buf: [u8; 2560] = [0; 2560];
        let mut r = bytes;
        std::io::copy(&mut r, &mut buf.as_mut_slice())
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let secret_key =
            SigningKey::try_from_bytes(buf).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(secret_key))
    }
}

impl FromStr for MlDsa44SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for MlDsa44SecretKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            let mut buf: [u8; 2560] = [0; 2560];
            let mut r = key_data.as_slice();
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
pub struct MlDsa44PublicKey(VerifyingKey);

impl PublicKeyTrait for MlDsa44PublicKey {
    fn codec(&self) -> u64 {
        multicodec_prefix::ED25519
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::ED25519
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::EdDSA
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone().into_bytes().to_vec()
    }

    fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    fn can_verify(&self) -> bool {
        true
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let mut s: [u8; 2420] = [0; 2420];
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
        Ok(Box::new(MlDsa44Signature::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PartialEq for MlDsa44PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.clone().into_bytes() == other.0.clone().into_bytes()
    }
}

impl Eq for MlDsa44PublicKey {}

impl Display for MlDsa44PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = multibase::to_base58(&self.to_bytes());
        write!(f, "{s}")
    }
}

impl std::fmt::Debug for MlDsa44PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsa44PublicKey({})",
            multibase::to_base58(&self.to_bytes())
        )
    }
}

impl TryFrom<&[u8]> for MlDsa44PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut buf: [u8; 1312] = [0; 1312];
        let mut r = bytes;
        std::io::copy(&mut r, &mut buf.as_mut_slice())
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let public_key =
            VerifyingKey::try_from_bytes(buf).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self(public_key))
    }
}

impl FromStr for MlDsa44PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&KeyAttributes> for MlDsa44PublicKey {
    type Error = Error;
    fn try_from(attributes: &KeyAttributes) -> Result<Self> {
        if let Some(key_data) = attributes.get_key_data() {
            Self::try_from(key_data.as_slice())
        } else {
            Err(Error::InvalidKey("invalid attributes".to_owned()))
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct MlDsa44Signature(RawSignature);

impl SignatureTrait for MlDsa44Signature {
    fn codec(&self) -> u64 {
        multicodec_prefix::ED25519
    }

    fn signature_nonce_size(&self) -> usize {
        0
    }

    fn algorithm_name(&self) -> &'static str {
        known_algorithm_name::EdDSA
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

impl TryFrom<&[u8]> for MlDsa44Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(RawSignature::from(bytes)))
    }
}

impl TryFrom<&RawSignature> for MlDsa44Signature {
    type Error = Error;
    fn try_from(signature: &RawSignature) -> Result<Self> {
        Ok(Self(signature.clone()))
    }
}

impl Display for MlDsa44Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base58(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{MlDsa44PublicKey, MlDsa44SecretKey};
    use mysteryn_core::{key_traits::*, result::Result};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const SECRET: &str = "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";
    const PUBLIC: &str = "zLj4W2rqZXwPimzdxtLSjqyicmJXmwTTTrziVEeCxFJaufhQ62XtWQpAnUTELVSt8BvcUm3bAByJE8XhiPteysLDE6ZgmYDxctu4keRY7kshqMMDc9ca5CQNkk8dQ7qKgeSnxLXdwJt8J3iJxcYoPM3AkHRKPXY3rawvwURk2tssTmUGofmvnGsz81kFaRqH6dm3xX1AeS2MqzLgdQWU3pbGfo7WhkhCzAC3AU7t7PbvLvaC8PCbh7zCf4XEKN1q3F7sZ5zHioNRhvR9oT84FTsL243dEDYv8RyRLqh5YeUZvxrt88WLDuc7339x3m91FhB3XirnJZBppDQf9V1T3Z2ffVT8a25PazeAYjMvw1ETUnWiiYsRWLKfq7bKMEotGYreLo163jkdjKrRRi1VQJ8Xpsy3m9PHAHkHsuDDJPrsMxY9iTMsEsb4syn6EF1CL6jLMVfqLrb5gVCBhaj9UL1G8rbVjDoN7tuLJf6Qua6MP8xtZyubc7bfU2ahWsZMhckB8PTTmQtXqm51cJjEpunJcQjiWP1W1eNRZjTRtSeU12Wjkdzpn2T1j4F4HTvQ1nnxybD6d274SKq3CRN8Wy7fkKhUQmCzRvKWiXuf5V73xZn2eZYTdRrTxQcRV9KjtjER3VrfQ2mUVKeuEe4QChBnMe4uzuWzj9Djyv44v4uzHAfXmdfUJtE1RoaL3PN3iKXQAVS2XMAfxy8D2fAdN4C38FTHpWFhZfCP3UgJBuTgTvZ1vrpGQyAZSrTtoM5MqQ7LHHWMdVM4RyakUC78EaTko77h7cz2AdUDne6ZyYjNusYK5ecGCTSmaigCSYNGZbpqsSHgdiZPjgdxj7UsT6hCMiEPdT2sKWwhLomSVqCSF2mgr4jNqLBuk9554ZTKnz7MNBaQvX9G7LYzQyfbXSYsMoLA2k9ZSQWr9EYJWRqfkTWQJJwCg3dxZFq58pVWZhJV3v43ncArXuTRZSxruyBg1ea5bssevcs67ozrTBS258fEtZiZSZ1maLTvauJMF7E1F59T14DP2JQfJ49ocDNN5c68CQwkDZLsy4aLcd5Hs15vhtzZQv5yXKuMaazjrkAiFFjXRiDryhgApJ9h7XR6opiEqiornQwbLuKxE7uvym9HMnkT3cc1UvVyATKgo3nyY8HrgXQ1mDDV1UJdM85wSxutwN6mKUYgtBeEXH4FtrNkLV122X1UXZSFTJJYAjUubcjJb4wGoE4zePe7byHUdGU6dfrqqpRnbRwGCjY1LoWJ1Tv3HTUmycxykgwN42BgqTRFYnuYC6gfRogstNCzKpvM4qyqWTRyQSnkGkKZMm7rRidx5JKHrZihNQTZLgtbn7RUG7dNZ9j4CCDwt73Eb1fgMbFS82HX25mWz3dtjkU4NYjs9LVTy1793K6WPigCCLFw8rGnuT9jMdiwJZEzmgzDDCRU63umkqXRd21gKT7Qv2xpRemhfXyf3ZkunXyA3RjDwdJXab5J4djZ8Vs7dP8WDazvPgEYG8GdcNdcjoE15e2zCpKidNZzYTcRsmSs95FWp4bYobUB1KBruxfemfZUAB6J8Qi1hgiL7DsL4hPuW5piCShPwNcRXbbKPhG9xQwnS6gBeRUX6jrPiABAat8Q4S4BZuwWc1u8BmNX3V7yBv46bQdPafR3ViPmckeBuRjnEgYMYB4mSbfBjKM33iWU3Nm2mNjtkkGcfcsEcuyqFkMHX6TodY9RuSMoDT2FrMMWtSrYBmVbA6v7ZmgfAnWHmDKbL75uTWoWYsWnSDzN4YNwHp9XUcqGoNTVq";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_serialize_and_deserialize() -> Result<()> {
        let secret_key = MlDsa44SecretKey::from_str(SECRET)?;
        let public_key = secret_key.public_key();

        assert_eq!(secret_key.to_string(), SECRET);
        assert_eq!(public_key.to_string(), PUBLIC);

        let public_key = MlDsa44PublicKey::from_str(PUBLIC)?;
        assert_eq!(public_key.to_string(), PUBLIC);

        let secret_key = MlDsa44SecretKey::new();
        let public_key = secret_key.public_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let secret_key_str = secret_key.to_string();
        let public_key_str = public_key.to_string();

        let restored_secret_key = MlDsa44SecretKey::try_from(secret_key_bytes.as_slice())?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = MlDsa44PublicKey::try_from(public_key_bytes.as_slice())?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_secret_key = MlDsa44SecretKey::from_str(&secret_key_str)?;
        assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
        let restored_public_key = restored_secret_key.public_key();
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        let restored_public_key = MlDsa44PublicKey::from_str(&public_key_str)?;
        assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn public_key_is_consistent() -> Result<()> {
        let secret_key = MlDsa44SecretKey::from_str(SECRET)?;
        let public_key1 = secret_key.public_key();
        let public_key2 = secret_key.public_key();

        assert_eq!(public_key1.to_string(), PUBLIC);
        assert_eq!(public_key1.to_string(), public_key2.to_string());
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_can_sign_and_verify_a_message() -> Result<()> {
        let private_key = MlDsa44SecretKey::from_str(SECRET)?;
        let public_key = private_key.public_key();
        let data = b"test data";
        let signature = private_key.sign_deterministic(data, None, None)?;

        //assert_eq!(signature.to_string(), "zGvqLtMGRbgHVrNq3JA7T2MjA2EQAgzbQFoVx8M5DoyzjkNysnpqtPdsT8pbPdUrnF2JNpsUiKLTEtsWv3m8sz6rPkaSuVRVcrYaFQvYgjfzr7bTX59cRR9BeBWUmirXoMYaeVJjBki6GzW3CTQKpVmcnwgXAhzdXW7sqYq7UyortDwPJLYKkVq1z4oDmnA6n1JNCb5ZdSEh2mVR6H4bG7ftLyxUkbQGcheZKHm59vxtfdQhmSzVt728AvkwLq7C4ngRq5CEkLe8ToS2Nc62xuSC9QTFuwiec6PvvRnqXD2tDu8cVuVN2w7JN8WiVWffoCLhv6EbjksZXxBHXYDm6rNgaboC7mXahTggGuHHebL218f3RF4VvcDChtcjirbPgKi3s9zg1wpfJ2kxeKeQu9cvw4Rhso2RAdd8Wf5tqwsDTnpQ2QCTvEv1qD12b5w1p4bgyL8dS9oAYAPs7AAeMLd6sNoUbZ3DK8itvGquBRQHenUWjGinrUu4tTRwBdfkNp3UuUTJmR2vUsMfu2J7iA4YtSc1p7d6hUkz36CAEb83GgDYqS9foTzFkc6WcvuV5xSaWnVm9f2AScmg8NZEcrucQMEPnUnUW5jHtUjRKByMccrYFpRayLmu1GiiC5U6D6vzS3oGG3HoHxg8JiykLCLRtAUSUDYNr8VZAECqXEiUeeJPNnB78dV6yWs4deNGkr8nGEona9AxjZjzmvm6ZW1x28zeoEXFPYZdLpvD8e2mXuqgpxxT1AkPd7mLtH2EPRJZhYktQkYqd86w2Socj4TNUnJkC6SC3GMBUP1wuhjL72XN9SDrkz2FS7mwdwqkopD1fGzEVr7tjRQJ84yvda1e4McUzEysNyzBqQaP291iMvoeR3UCnacXmvgtopcfWd7w2ktheE7bVc7RvTEJo3kfSYJpMYmnkmprkmnzcEwdvvqpKp18w4T2peLsZBwtuAnKQFY3HuqxjkZJHUoA3n8H8pCKXHsa5rkn8gFR4JmH4QRbMLU5ePgLby6Uuebk1PNcU7YKicVSkaLWXMeSBv344un4HA4FQ7VTGGjnZcLv7j8rKTVnnnjE2greWonkrD8Ki643BpEZoBbS36Vz18fzrWBafGVGJyBrYgXt7dDpMqnckQaQsFQ2T65GK1xfVuyYKrz6NCCZFkRbfAxykfvLxpPrNhBz7pyhheegcJEfX6b7pJiJZn1zTzu9arHcsrt4Z8c1XBHBjpfRe995wMn92193kLtH4j4Mr2x5tFskNbMPNpfsjbQLEtZD29H21VuFY8WfF2hRLtM5XV8fnFYsydoyLzp8DjfWvKBuzLwDucgwMcvoEQR6BWSYDfY7rgtBqxygTvKy1XP9AdXXdVBN6pJWuc2agVps7mG6bzZwxTsv4mndytSaiuAaYk3wv2hA4BoKqgEmtDMfmQRryyD1uV8qveave2uyGxTRQUkqNYdNRCabejhmwyjtM41Jg2s8RP6vp4iWKGAg6Q7jJYxzct4RPf8sD4SmzsaKzJYkw5j3JtXN5N6jat52rgtRoMsnp4DGVg8c64zSPx7dGmUXgPpqsYUSeHJk9xjABA7kEfnN3kFxQeHdiiUkvRa6ugNpXP44aG9cH6BsWfF3L4xXPQqos6xAabStxQPSubVsfErXFhdmHwBf6TV5p7EjUZso9SUNAakWyJUpYdKB9n1bJNX95JWAzxGhA7sDcDEuwVGawbUd1b8b8X69ETMr5uoHJ97ifUdoaAb5EQv1XzGcCG7XdQzE29j4nRdxXxCdfsBnYQa5sVm7hvYXnWRgMcWvitgmt7sp3a6tnXuQ8WUAUqb6tPeTABWycfJeTcaojxSqWhpayFuD8zSTr1h9ixv88jKTDUDtKNTRvnjdQUntEyem4RR3o7LvJiJsA3TixG3dsf3o3KZpX4LjNcpF8v5aDWhDTBvBsTB1PT4AJJDMJhjiwhW2dTP3TDVXv36joWSkUFKDyAdtBS1znqQfbBkPpcpfCw6FZ4NLKCW7Get9sAqxWz8dsp7RqycivYcuHdCFhxkynXzH5KgTS5NXcFuCn1SWLtvhPA2Fi7kNFnBLou9fcuV1VAhtMtVvUZSJb9mtKLoCbupRmt4d6Q9Rjw8b4W4jEbaewWsK2offbQJfcuEPx9wvfnUCzNkycWamLKdhjgWFN3X4Q4x2MYuMKX9cTzXq4n8Hidid5WXMPMFvJ1Ym2G1FqAQZAK5YrEoGrykm6rpXQoQHJV1w1P7hM26refYHMKkD5e5yJWwDL4Z9oL4ThQnV9pgT2UM8cueQGD1dWJM8UybfvGCWLwggN4P7R7pob8WioRS2pDDRCP9Q3brzya1nSjqxnRTFMihzAMrRuQwdpt7kcXtw3swdmRoj8d2TKPsvhaj8bF2YstD16Q8LZv1Q8z63pHD7NUMd99SXaFcZWWYnHUa2pT2bYMe5spdiXxn2i9Nzw8x1LH8khivVFbRM2BV2yPw8Co11zz1ZC1XqXCJmr6qUjjahTP6BL3fgW777os2qQM4NcakeTTfTcoCRWBhSR4s97L7XLnnekebP2vKiWifASyTBkgvz9ST15aWkCxeFogpGGsXDgCpHDdkN7xF9ah3LN9DXJB33qB78UE7Fxmeej6Ce9qpYsY5wdDxYbRb5QutBgxectxfScPyAtgVaszveowjxKTCHJAxLPuCHxVT3mFh8bv6rJCQrU1BbFzrGAYSUhGmeVQ4Kc3u7ZhSCEe6akhNty5imLG48F5G8MhAMMqMC25f33E2sW5YM7Gfj1X3tkDTMCMw3aCeuuNKm4ZAYDq6uqcsDmhkbACJGXy2u1DBtUbdQb8kgQtphJNXfTogVG8ZS8i9GGJs99zCibezWjAEve86H2EaZwut8PiXJzDHMtWc93D9SM8H3VAdm7YLKrgt2gFkV15uutnZgQQG9kxv89jp64HaYETRPEWfcrcxuqsLt6ouafKVgNdbwViZytCtu21wRW1p7nbzJ4dm5pBHvdMxTqpmGjuJz2hczJH4PxasgS4ThCBaBXmUjPGPoZzT8oxxiqNdzbjZ2DdeN6xp2GBo4oDMveiAMU1Ax5E3VXhtrBxegpoBEsvF9RHkxJGZ7r8wbKnLs1Ce76Eyt2Xg9K81dWWExRnWa3jsP88bxdF64V1ZoGFws9W1irNQPoWnK39DbesjjjxMG59Yhqqb4jCMHTbqdw5peh1DTu6HG8N6kBeuWUr7LXwWdrcmdCqk6z3ZHJUc1jbLzq5UCNFsh4HFDjQppcBdc8NQyKjzBShUWW4jMGi9MafdCUQpx1LWo1gBAF2QkU8yJAqmr7v");
        private_key.verify(data, &signature)?;
        public_key.verify(data, &signature)?;

        Ok(())
    }
}
