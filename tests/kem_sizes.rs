//! Lock each KEM's declared size constants to the lengths the underlying oqs
//! algorithm reports at runtime. If a future oqs upgrade changes a size, these
//! tests fail instead of letting the constants (and the doc tables that quote
//! them) silently drift out of sync.

use oqs::kem::{Algorithm, Kem};

use issachar::kem::{ClassicMcEliece, FrodoKem, MlKem};

fn check(
    algorithm: Algorithm,
    public_key_len: usize,
    secret_key_len: usize,
    ciphertext_len: usize,
    shared_secret_len: usize,
) {
    oqs::init();
    let kem = Kem::new(algorithm).unwrap();
    assert_eq!(public_key_len, kem.length_public_key(), "public key");
    assert_eq!(secret_key_len, kem.length_secret_key(), "secret key");
    assert_eq!(ciphertext_len, kem.length_ciphertext(), "ciphertext");
    assert_eq!(
        shared_secret_len,
        kem.length_shared_secret(),
        "shared secret"
    );
}

#[test]
fn ml_kem_1024_sizes_match_oqs() {
    check(
        Algorithm::MlKem1024,
        MlKem::PUBLIC_KEY_LEN,
        MlKem::SECRET_KEY_LEN,
        MlKem::CIPHERTEXT_LEN,
        MlKem::SHARED_SECRET_LEN,
    );
}

#[test]
fn frodo_kem_1344_aes_sizes_match_oqs() {
    check(
        Algorithm::FrodoKem1344Aes,
        FrodoKem::PUBLIC_KEY_LEN,
        FrodoKem::SECRET_KEY_LEN,
        FrodoKem::CIPHERTEXT_LEN,
        FrodoKem::SHARED_SECRET_LEN,
    );
}

#[test]
fn classic_mceliece_8192128f_sizes_match_oqs() {
    check(
        Algorithm::ClassicMcEliece8192128f,
        ClassicMcEliece::PUBLIC_KEY_LEN,
        ClassicMcEliece::SECRET_KEY_LEN,
        ClassicMcEliece::CIPHERTEXT_LEN,
        ClassicMcEliece::SHARED_SECRET_LEN,
    );
}

#[test]
fn secret_key_round_trips_through_bytes() {
    let mlkem = MlKem::new();
    let (_, sk) = mlkem.keypair().unwrap();
    let restored = mlkem.secret_key_from_bytes(sk.as_ref()).unwrap();
    assert_eq!(sk.as_ref(), restored.as_ref());
}

#[test]
fn from_bytes_rejects_wrong_length() {
    let mlkem = MlKem::new();
    assert!(mlkem.public_key_from_bytes(&[0u8; 7]).is_err());
    assert!(mlkem.ciphertext_from_bytes(&[0u8; 7]).is_err());
    assert!(mlkem.secret_key_from_bytes(&[0u8; 7]).is_err());
}
