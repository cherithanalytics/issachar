/// Test vectors for all KEM and signature algorithms.
///
/// ## KEM vectors
///
/// ML-KEM-1024:
///   - Keypair generated deterministically via keypair_derand(seed=0x42×64).
///   - Ciphertext and shared secret captured from one encapsulation run.
///   - Tests: seed → pk is stable; decapsulate(sk, ct) == captured ss.
///
/// Classic McEliece 8192128f:
///   - keypair_derand unsupported; (sk, ct, ss) captured from one random run.
///   - Test: decapsulate(sk, ct) == captured ss.
///
/// ## Signature vectors
///
/// ML-DSA-87 and SPHINCS+-SHAKE256-256f-simple:
///   - Both sign with per-operation randomness, so (pk, sk, sig) were captured
///     from one run against a fixed message (MESSAGE constant below).
///   - Tests: verify(MESSAGE, captured_sig, captured_pk) passes.
///
/// ## X25519 tests
///
///   - Round-trip: two ephemeral key pairs agree on the same non-zero secret.
///   - Low-order key rejection: all-zero public key returns Err.
use hex::decode as from_hex;
use issachar::classic::X25519Key;
use issachar::kem::{ClassicMcEliece, FrodoKem, MlKem};
use issachar::sig::{MlDsa, Sphincs};

const SEED: [u8; 64] = [0x42; 64];
const MESSAGE: &[u8] = b"pqc test vector message";

fn hex(s: &str) -> Vec<u8> {
    from_hex(s.trim()).expect("invalid hex in test vector file")
}

// ── ML-KEM-1024 ──────────────────────────────────────────────────────────────

#[test]
fn ml_kem_1024_keypair_derand_matches_known_public_key() {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).unwrap();
    let seed_ref = kem.keypair_seed_from_bytes(&SEED).unwrap();
    let (pk, _) = kem.keypair_derand(seed_ref).unwrap();

    let expected = hex(include_str!("vectors/ml_kem_1024_pk.hex"));
    assert_eq!(pk.as_ref(), expected.as_slice());
}

#[test]
fn ml_kem_1024_decapsulate_matches_known_shared_secret() {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).unwrap();

    let sk_bytes = hex(include_str!("vectors/ml_kem_1024_sk.hex"));
    let ct_bytes = hex(include_str!("vectors/ml_kem_1024_ct.hex"));
    let expected = hex(include_str!("vectors/ml_kem_1024_ss.hex"));

    let sk = kem.secret_key_from_bytes(&sk_bytes).unwrap().to_owned();
    let ct = kem.ciphertext_from_bytes(&ct_bytes).unwrap().to_owned();

    let ss = MlKem::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss.as_ref(), expected.as_slice());
}

// ── FrodoKEM-1344-AES ────────────────────────────────────────────────────────

#[test]
fn frodokem_1344_aes_decapsulate_matches_known_shared_secret() {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem1344Aes).unwrap();

    let sk_bytes = hex(include_str!("vectors/frodokem_1344_aes_sk.hex"));
    let ct_bytes = hex(include_str!("vectors/frodokem_1344_aes_ct.hex"));
    let expected = hex(include_str!("vectors/frodokem_1344_aes_ss.hex"));

    let sk = kem.secret_key_from_bytes(&sk_bytes).unwrap().to_owned();
    let ct = kem.ciphertext_from_bytes(&ct_bytes).unwrap().to_owned();

    let ss = FrodoKem::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss.as_ref(), expected.as_slice());
}

// ── Classic McEliece 8192128f ─────────────────────────────────────────────────

#[test]
fn classic_mceliece_8192128f_decapsulate_matches_known_shared_secret() {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece8192128f).unwrap();

    let sk_bytes = hex(include_str!("vectors/mceliece_sk.hex"));
    let ct_bytes = hex(include_str!("vectors/mceliece_ct.hex"));
    let expected = hex(include_str!("vectors/mceliece_ss.hex"));

    let sk = kem.secret_key_from_bytes(&sk_bytes).unwrap().to_owned();
    let ct = kem.ciphertext_from_bytes(&ct_bytes).unwrap().to_owned();

    let ss = ClassicMcEliece::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss.as_ref(), expected.as_slice());
}

// ── ML-DSA-87 ─────────────────────────────────────────────────────────────────

#[test]
fn ml_dsa_87_verify_matches_known_signature() {
    oqs::init();
    let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa87).unwrap();

    let pk_bytes = hex(include_str!("vectors/ml_dsa_87_pk.hex"));
    let sig_bytes = hex(include_str!("vectors/ml_dsa_87_sig.hex"));

    let pk = scheme.public_key_from_bytes(&pk_bytes).unwrap().to_owned();
    let sig = scheme.signature_from_bytes(&sig_bytes).unwrap().to_owned();

    MlDsa::verify(MESSAGE, &sig, &pk).unwrap();
}

#[test]
fn ml_dsa_87_sign_then_verify_roundtrip() {
    oqs::init();
    let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa87).unwrap();

    let sk_bytes = hex(include_str!("vectors/ml_dsa_87_sk.hex"));
    let pk_bytes = hex(include_str!("vectors/ml_dsa_87_pk.hex"));

    let sk = scheme.secret_key_from_bytes(&sk_bytes).unwrap().to_owned();
    let pk = scheme.public_key_from_bytes(&pk_bytes).unwrap().to_owned();

    let sig = MlDsa::sign(MESSAGE, &sk).unwrap();
    MlDsa::verify(MESSAGE, &sig, &pk).unwrap();
}

// ── SPHINCS+-SHAKE256-256f-simple ─────────────────────────────────────────────

#[test]
fn sphincs_shake256_256f_verify_matches_known_signature() {
    oqs::init();
    let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::SphincsShake256fSimple).unwrap();

    let pk_bytes = hex(include_str!("vectors/sphincs_shake256_256f_pk.hex"));
    let sig_bytes = hex(include_str!("vectors/sphincs_shake256_256f_sig.hex"));

    let pk = scheme.public_key_from_bytes(&pk_bytes).unwrap().to_owned();
    let sig = scheme.signature_from_bytes(&sig_bytes).unwrap().to_owned();

    Sphincs::verify(MESSAGE, &sig, &pk).unwrap();
}

#[test]
fn sphincs_shake256_256f_sign_then_verify_roundtrip() {
    oqs::init();
    let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::SphincsShake256fSimple).unwrap();

    let sk_bytes = hex(include_str!("vectors/sphincs_shake256_256f_sk.hex"));
    let pk_bytes = hex(include_str!("vectors/sphincs_shake256_256f_pk.hex"));

    let sk = scheme.secret_key_from_bytes(&sk_bytes).unwrap().to_owned();
    let pk = scheme.public_key_from_bytes(&pk_bytes).unwrap().to_owned();

    let sig = Sphincs::sign(MESSAGE, &sk).unwrap();
    Sphincs::verify(MESSAGE, &sig, &pk).unwrap();
}

// ── X25519 ───────────────────────────────────────────────────────────────────

#[test]
fn x25519_round_trip() {
    let alice = X25519Key::generate();
    let bob = X25519Key::generate();

    let alice_pub = alice.public_key_bytes();
    let bob_pub = bob.public_key_bytes();

    let ss_alice = alice.agree(bob_pub).unwrap();
    let ss_bob = bob.agree(alice_pub).unwrap();

    assert_eq!(ss_alice, ss_bob);
    assert_ne!(ss_alice, [0u8; 32]);
}

#[test]
fn x25519_low_order_key_rejected() {
    assert!(X25519Key::generate().agree([0u8; 32]).is_err());
}

