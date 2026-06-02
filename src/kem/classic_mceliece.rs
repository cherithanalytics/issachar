use oqs::kem::Algorithm;
use oqs::kem::Kem;

use super::Ciphertext;
use super::PublicKey;
use super::Result;
use super::SecretKey;
use super::SharedSecret;

/// Classic McEliece 8192128f (security level 5, fast key-generation variant).
///
/// Classic McEliece is a code-based KEM with over 50 years of cryptanalytic
/// history behind its underlying hard problem (decoding random binary Goppa
/// codes). It is one of the most conservative choices available in
/// post-quantum cryptography.
///
/// The `f` (fast) variant uses a different key-generation algorithm that is
/// significantly faster at the cost of slightly larger public keys compared
/// to the standard variant; the ciphertext size and security level are
/// unchanged.
///
/// # Sizes
///
/// | Object        | Bytes     |
/// |---------------|-----------|
/// | Public key    | 1,357,824 |
/// | Secret key    |    14,120 |
/// | Ciphertext    |       208 |
/// | Shared secret |        32 |
///
/// # Pros
///
/// - Based on coding theory, an entirely different mathematical family from
///   lattice schemes. Serves as a strong hedge in hybrid constructions.
/// - ~50 years of cryptanalysis with no fundamental structural breaks.
/// - Tiny ciphertext (208 B) — ideal when the encapsulated ciphertext must
///   be transmitted repeatedly but the public key can be stored once
///   (e.g. in a certificate or a static configuration file).
/// - Extremely fast signing and verification, even faster than RSA.
///
/// # Cons
///
/// - Very large public key (~1.3 MB) — prohibitive for protocols that
///   transmit the public key in every session (e.g. standard TLS handshakes).
///   Plan for out-of-band distribution or long-lived public keys.
/// - Key generation is slow even with the `f` variant; not suitable for
///   ephemeral key exchange patterns where a fresh keypair is needed per
///   session.
pub struct ClassicMcEliece;

impl ClassicMcEliece {
    pub fn keypair() -> Result<(PublicKey, SecretKey)> {
        oqs::init();
        let kem = Kem::new(Algorithm::ClassicMcEliece8192128f)?;
        kem.keypair()
    }

    pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
        oqs::init();
        let kem = Kem::new(Algorithm::ClassicMcEliece8192128f)?;
        kem.encapsulate(public_key)
    }

    pub fn decapsulate(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
        oqs::init();
        let kem = Kem::new(Algorithm::ClassicMcEliece8192128f)?;
        kem.decapsulate(secret_key, ciphertext)
    }

    pub fn ciphertext_from_bytes(bytes: &[u8]) -> Option<Ciphertext> {
        oqs::init();
        let kem = Kem::new(Algorithm::ClassicMcEliece8192128f).ok()?;
        kem.ciphertext_from_bytes(bytes).map(|r| r.to_owned())
    }
}
