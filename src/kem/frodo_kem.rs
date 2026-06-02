use oqs::kem::Algorithm;
use oqs::kem::Kem;

use super::Ciphertext;
use super::PublicKey;
use super::Result;
use super::SecretKey;
use super::SharedSecret;

/// FrodoKEM-1344-AES (security level 5).
///
/// FrodoKEM is a lattice-based KEM whose security relies on the plain
/// Learning With Errors (LWE) problem — a far more conservative variant than
/// the structured (module/ring) lattice assumptions used by ML-KEM. The
/// 1344 variant targets NIST security level 5; the AES flavour uses AES in
/// counter mode as its pseudo-random generator, which benefits from
/// hardware AES-NI acceleration on most modern CPUs.
///
/// # Sizes
///
/// | Object        | Bytes  |
/// |---------------|--------|
/// | Public key    | 21,520 |
/// | Secret key    | 43,088 |
/// | Ciphertext    | 21,632 |
/// | Shared secret |     32 |
///
/// # Pros
///
/// - Based on plain (unstructured) LWE rather than module/ring variants —
///   a more conservative assumption with a longer analysis history.
/// - No known algebraic attacks that exploit ring structure.
/// - AES variant is fast on hardware with AES-NI.
/// - Standardized by the French and Germans as their perferred PQC KEM because
///   it is so conservative.
///
/// # Cons
///
/// - Large public key and ciphertext (~21 KB each) — significantly larger
///   than ML-KEM; unsuitable for protocols that must transmit both in every
///   handshake without compression or caching.
pub struct FrodoKem;

impl FrodoKem {
    pub fn keypair() -> Result<(PublicKey, SecretKey)> {
        oqs::init();
        let kem = Kem::new(Algorithm::FrodoKem1344Aes)?;
        kem.keypair()
    }

    pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
        oqs::init();
        let kem = Kem::new(Algorithm::FrodoKem1344Aes)?;
        kem.encapsulate(public_key)
    }

    pub fn decapsulate(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
        oqs::init();
        let kem = Kem::new(Algorithm::FrodoKem1344Aes)?;
        kem.decapsulate(secret_key, ciphertext)
    }
}
