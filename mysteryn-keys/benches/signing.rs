#![allow(non_snake_case)]
use bench_rs::{Bencher, bench};
use mysteryn_core::key_traits::{PublicKeyTrait, SecretKeyTrait};
use mysteryn_keys::{
    bls12381g1::Bls12381G1SecretKey, ed448::Ed448SecretKey, ed25519::Ed25519SecretKey,
    faest128f::Faest128fSecretKey, falcon512::Falcon512SecretKey, falcon1024::Falcon1024SecretKey,
    hmac_sha256::HmacSha256SecretKey, mldsa44::MlDsa44SecretKey, mldsa65::MlDsa65SecretKey,
    mldsa87::MlDsa87SecretKey, mlkem512::MlKem512SecretKey, p256::P256SecretKey,
    p384::P384SecretKey, p521::P521SecretKey, rsa::Rs256SecretKey, rsa::Rs512SecretKey,
    secp256k1::Secp256k1SecretKey, slhdsashake128f::SlhDsaShake128fSecretKey,
    x25519::X25519SecretKey,
};
use std::hint::black_box;

const DATA: &[u8] = b"123456789012345678901234567890";

#[bench]
fn bench_Bls12381G1(b: &mut Bencher) {
    let key = Bls12381G1SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_Ed448(b: &mut Bencher) {
    let key = Ed448SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_Ed25519(b: &mut Bencher) {
    let key = Ed25519SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_Faest128f(b: &mut Bencher) {
    let key = Faest128fSecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_Falcon512(b: &mut Bencher) {
    let key = Falcon512SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_Falcon1024(b: &mut Bencher) {
    let key = Falcon1024SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_HmacSha256(b: &mut Bencher) {
    let key = HmacSha256SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_MlDsa44(b: &mut Bencher) {
    let key = MlDsa44SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_MlDsa65(b: &mut Bencher) {
    let key = MlDsa65SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_MlDsa87(b: &mut Bencher) {
    let key = MlDsa87SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_MlKem512(b: &mut Bencher) {
    let key = MlKem512SecretKey::new();
    let public2 = MlKem512SecretKey::new().public_key();
    b.iter(|| {
        let _ = black_box(key.sign_exchange(DATA, Some(&public2.to_bytes()), None));
    })
}

#[bench]
fn bench_P256(b: &mut Bencher) {
    let key = P256SecretKey::new();
    // desc
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_P384(b: &mut Bencher) {
    let key = P384SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_P521(b: &mut Bencher) {
    let key = P521SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_Rs256(b: &mut Bencher) {
    let key = Rs256SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_Rs512(b: &mut Bencher) {
    let key = Rs512SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_Secp256k1(b: &mut Bencher) {
    let key = Secp256k1SecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_SlhDsaShake128f(b: &mut Bencher) {
    let key = SlhDsaShake128fSecretKey::new();
    b.iter(|| {
        let _ = black_box(key.sign(DATA, None));
    })
}

#[bench]
fn bench_X25519(b: &mut Bencher) {
    let key = X25519SecretKey::new();
    let public2 = X25519SecretKey::new().public_key();
    b.iter(|| {
        let _ = black_box(key.sign_exchange(DATA, Some(&public2.to_bytes()), None));
    })
}
