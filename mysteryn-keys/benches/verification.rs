#[divan::bench_group]
#[allow(non_snake_case)]
mod bench_verification {
    use divan::{AllocProfiler, Bencher, bench, black_box};
    use mysteryn_core::key_traits::{PublicKeyTrait, SecretKeyTrait};
    use mysteryn_keys::{
        bls12381g1::Bls12381G1SecretKey,
        ed448::Ed448SecretKey,
        ed25519::Ed25519SecretKey,
        faest128f::Faest128fSecretKey,
        falcon512::Falcon512SecretKey,
        falcon1024::Falcon1024SecretKey,
        hmac_sha256::HmacSha256SecretKey,
        mldsa44::MlDsa44SecretKey,
        mldsa65::MlDsa65SecretKey,
        mldsa87::MlDsa87SecretKey,
        mlkem512::MlKem512SecretKey,
        p256::P256SecretKey,
        p384::P384SecretKey,
        p521::P521SecretKey,
        rsa::{Rs256SecretKey, Rs512SecretKey},
        secp256k1::Secp256k1SecretKey,
        slhdsashake128f::SlhDsaShake128fSecretKey,
        x25519::X25519SecretKey,
    };

    #[global_allocator]
    static ALLOC: AllocProfiler = AllocProfiler::system();

    const DATA: &[u8] = b"123456789012345678901234567890";

    #[bench]
    fn Bls12381G1(bencher: Bencher) {
        let key = Bls12381G1SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn Ed448(bencher: Bencher) {
        let key = Ed448SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn Ed25519(bencher: Bencher) {
        let key = Ed25519SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn Faest128f(bencher: Bencher) {
        let key = Faest128fSecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn Falcon512(bencher: Bencher) {
        let key = Falcon512SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn Falcon1024(bencher: Bencher) {
        let key = Falcon1024SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn HmacSha256(bencher: Bencher) {
        let key = HmacSha256SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn MlDsa44(bencher: Bencher) {
        let key = MlDsa44SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn MlDsa65(bencher: Bencher) {
        let key = MlDsa65SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn MlDsa87(bencher: Bencher) {
        let key = MlDsa87SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn MlKem512(bencher: Bencher) {
        let key = MlKem512SecretKey::new();
        let key2 = MlKem512SecretKey::new();
        let sig = key
            .sign_exchange(DATA, Some(&key2.public_key().to_bytes()), None)
            .unwrap();
        bencher.bench(|| black_box(key2.verify(DATA, &sig)))
    }

    #[bench]
    fn P256(bencher: Bencher) {
        let key = P256SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn P384(bencher: Bencher) {
        let key = P384SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn P521(bencher: Bencher) {
        let key = P521SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn Rs256(bencher: Bencher) {
        let key = Rs256SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn Rs512(bencher: Bencher) {
        let key = Rs512SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn Secp256k1(bencher: Bencher) {
        let key = Secp256k1SecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn SlhDsaShake128f(bencher: Bencher) {
        let key = SlhDsaShake128fSecretKey::new();
        let sig = key.sign(DATA, None).unwrap();
        let key = key.public_key();
        bencher.bench(|| black_box(key.verify(DATA, &sig)))
    }

    #[bench]
    fn X25519(bencher: Bencher) {
        let key = X25519SecretKey::new();
        let key2 = X25519SecretKey::new();
        let sig = key
            .sign_exchange(DATA, Some(&key2.public_key().to_bytes()), None)
            .unwrap();
        bencher.bench(|| black_box(key2.verify(DATA, &sig)))
    }
}

fn main() {
    // Run registered benchmarks.
    divan::main();
}
