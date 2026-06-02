use oqs::kem::Algorithm;
use oqs::kem::Kem;

use super::Ciphertext;
use super::PublicKey;
use super::Result;
use super::SecretKey;
use super::SharedSecret;

/// ML-KEM-1024 (NIST FIPS 203, security level 5).
///
/// ML-KEM (formerly Kyber) is a lattice-based KEM standardised by NIST. It is
/// the recommended default KEM for most applications due to its balance of
/// performance and key/ciphertext size.
///
/// # Sizes
///
/// | Object        | Bytes |
/// |---------------|-------|
/// | Public key    | 1,568 |
/// | Secret key    | 3,168 |
/// | Ciphertext    | 1,568 |
/// | Shared secret |    32 |
///
/// # Pros
///
/// - Small, symmetric public key and ciphertext sizes — well-suited to
///   protocols like TLS and SSH where both are transmitted in a handshake.
/// - Fast key generation, encapsulation, and decapsulation.
/// - NIST-standardised (FIPS 203); broad library and hardware support.
///
/// # Cons
///
/// - Lattice-based: security depends on the hardness of Module-LWE. While
///   considered very strong, this is a newer assumption (~10 years of
///   widespread cryptanalysis) compared to code-based alternatives.
pub struct MlKem;

impl MlKem {
    pub fn keypair() -> Result<(PublicKey, SecretKey)> {
        oqs::init();
        let kem = Kem::new(Algorithm::MlKem1024)?;
        kem.keypair()
    }

    pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
        oqs::init();
        let kem = Kem::new(Algorithm::MlKem1024)?;
        kem.encapsulate(public_key)
    }

    pub fn decapsulate(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
        oqs::init();
        let kem = Kem::new(Algorithm::MlKem1024)?;
        kem.decapsulate(secret_key, ciphertext)
    }

    pub fn ciphertext_from_bytes(bytes: &[u8]) -> Option<Ciphertext> {
        oqs::init();
        let kem = Kem::new(Algorithm::MlKem1024).ok()?;
        kem.ciphertext_from_bytes(bytes).map(|r| r.to_owned())
    }

    pub fn public_key_from_bytes(bytes: &[u8]) -> Option<PublicKey> {
        oqs::init();
        let kem = Kem::new(Algorithm::MlKem1024).ok()?;
        kem.public_key_from_bytes(bytes).map(|r| r.to_owned())
    }
}
