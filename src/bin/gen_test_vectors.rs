use oqs::kem::Algorithm;
use oqs::kem::Kem;

/// Generates deterministic test vectors for ML-KEM-1024, FrodoKEM-1344-AES,
/// and Classic McEliece 8192128f.
///
/// Key generation uses keypair_derand with a fixed seed so the pk/sk are
/// reproducible (where supported). Encapsulation is randomized, so we run it
/// once, capture (ct, ss), and verify decapsulate(sk, ct) == ss. The captured
/// values are printed for embedding in tests.
fn main() {
    oqs::init();

    // ── ML-KEM-1024 ──────────────────────────────────────────────────────────
    {
        let kem = Kem::new(Algorithm::MlKem1024).unwrap();
        let seed_len = kem.length_keypair_seed();
        let seed = vec![0x42u8; seed_len];
        let seed_ref = kem.keypair_seed_from_bytes(&seed).unwrap();
        let (pk, sk) = kem.keypair_derand(seed_ref).unwrap();
        let (ct, ss_enc) = kem.encapsulate(&pk).unwrap();
        let ss_dec = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());

        println!("ML_KEM_1024_SEED_LEN={seed_len}");
        println!("ML_KEM_1024_PK={}", hex::encode(pk.as_ref()));
        println!("ML_KEM_1024_SK={}", hex::encode(sk.as_ref()));
        println!("ML_KEM_1024_CT={}", hex::encode(ct.as_ref()));
        println!("ML_KEM_1024_SS={}", hex::encode(ss_enc.as_ref()));
    }

    // ── FrodoKEM-1344-AES ────────────────────────────────────────────────────
    // keypair_derand is not supported; generate once with random keypair and
    // capture (sk, ct, ss) as a fixed decapsulation test vector.
    {
        let kem = Kem::new(Algorithm::FrodoKem1344Aes).unwrap();
        let (pk, sk) = kem.keypair().unwrap();
        let (ct, ss_enc) = kem.encapsulate(&pk).unwrap();
        let ss_dec = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());

        println!("FRODOKEM_1344_AES_SK={}", hex::encode(sk.as_ref()));
        println!("FRODOKEM_1344_AES_CT={}", hex::encode(ct.as_ref()));
        println!("FRODOKEM_1344_AES_SS={}", hex::encode(ss_enc.as_ref()));
    }

    // ── Classic McEliece 8192128f ─────────────────────────────────────────────
    // keypair_derand is not supported; generate once with random keypair and
    // capture (sk, ct, ss) as a fixed decapsulation test vector.
    {
        let kem = Kem::new(Algorithm::ClassicMcEliece8192128f).unwrap();
        let (pk, sk) = kem.keypair().unwrap();
        let (ct, ss_enc) = kem.encapsulate(&pk).unwrap();
        let ss_dec = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());

        println!("MCELIECE_SK={}", hex::encode(sk.as_ref()));
        println!("MCELIECE_CT={}", hex::encode(ct.as_ref()));
        println!("MCELIECE_SS={}", hex::encode(ss_enc.as_ref()));
    }

}
