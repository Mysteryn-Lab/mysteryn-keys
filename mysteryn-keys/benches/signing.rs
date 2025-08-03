#[divan::bench_group]
#[allow(non_snake_case)]
mod bench_signing {
    use divan::{AllocProfiler, Bencher, bench, black_box};
    use mysteryn_core::key_traits::{PublicKeyTrait, SecretKeyTrait};
    use mysteryn_keys::{
        bls12381g1::Bls12381G1SecretKey, ed448::Ed448SecretKey, ed25519::Ed25519SecretKey,
        faest128f::Faest128fSecretKey, falcon512::Falcon512SecretKey,
        falcon1024::Falcon1024SecretKey, hmac_sha256::HmacSha256SecretKey,
        mldsa44::MlDsa44SecretKey, mlkem512::MlKem512SecretKey, p256::P256SecretKey,
        p384::P384SecretKey, p521::P521SecretKey, rsa::Rs256SecretKey, rsa::Rs512SecretKey,
        secp256k1::Secp256k1SecretKey, slhdsashake128f::SlhDsaShake128fSecretKey,
        x25519::X25519SecretKey,
    };

    #[global_allocator]
    static ALLOC: AllocProfiler = AllocProfiler::system();

    const DATA: &[u8] = b"123456789012345678901234567890";

    #[bench]
    fn Bls12381G1(bencher: Bencher) {
        let key = Bls12381G1SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn Ed448(bencher: Bencher) {
        let key = Ed448SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn Ed25519(bencher: Bencher) {
        let key = Ed25519SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn Faest128f(bencher: Bencher) {
        let key = Faest128fSecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn Falcon512(bencher: Bencher) {
        let key = Falcon512SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn Falcon1024(bencher: Bencher) {
        let key = Falcon1024SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn HmacSha256(bencher: Bencher) {
        let key = HmacSha256SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn MlDsa44(bencher: Bencher) {
        let key = MlDsa44SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn MlKem512(bencher: Bencher) {
        let key = MlKem512SecretKey::new();
        let public2 = MlKem512SecretKey::new().public_key();
        bencher.bench(|| black_box(key.sign_exchange(DATA, Some(public2.to_bytes()), None)))
    }

    #[bench]
    fn P256(bencher: Bencher) {
        let key = P256SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn P384(bencher: Bencher) {
        let key = P384SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn P521(bencher: Bencher) {
        let key = P521SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn Rs256(bencher: Bencher) {
        let key = Rs256SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn Rs512(bencher: Bencher) {
        let key = Rs512SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn Secp256k1(bencher: Bencher) {
        let key = Secp256k1SecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn SlhDsaShake128f(bencher: Bencher) {
        let key = SlhDsaShake128fSecretKey::new();
        bencher.bench(|| black_box(key.sign(DATA, None)))
    }

    #[bench]
    fn X25519(bencher: Bencher) {
        let key = X25519SecretKey::new();
        let public2 = X25519SecretKey::new().public_key();
        bencher.bench(|| black_box(key.sign_exchange(DATA, Some(public2.to_bytes()), None)))
    }
}

fn main() {
    // Run registered benchmarks.
    divan::main();
}
