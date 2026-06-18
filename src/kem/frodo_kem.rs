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
/// - Standardized by the French and Germans as their preferred PQC KEM because
///   it is so conservative.
///
/// # Cons
///
/// - Large public key and ciphertext (~21 KB each) — significantly larger
///   than ML-KEM; unsuitable for protocols that must transmit both in every
///   handshake without compression or caching.
///
/// # Reuse
///
/// Construct once with [`FrodoKem::new`] and reuse across operations — each
/// instance owns the underlying liboqs algorithm object, so reusing it avoids
/// re-allocating that object on every encapsulation/decapsulation.
pub struct FrodoKem {
    kem: Kem,
}

impl Default for FrodoKem {
    fn default() -> Self {
        Self::new()
    }
}

impl FrodoKem {
    /// Length in bytes of a serialized public key.
    pub const PUBLIC_KEY_LEN: usize = 21_520;
    /// Length in bytes of a serialized secret key.
    pub const SECRET_KEY_LEN: usize = 43_088;
    /// Length in bytes of a ciphertext.
    pub const CIPHERTEXT_LEN: usize = 21_632;
    /// Length in bytes of the encapsulated shared secret.
    pub const SHARED_SECRET_LEN: usize = 32;

    /// Construct a reusable FrodoKEM-1344-AES instance.
    ///
    /// Infallible: FrodoKEM-1344-AES is always compiled in via the crate's
    /// `oqs` feature set, so the underlying algorithm object can always be
    /// created.
    pub fn new() -> Self {
        oqs::init();
        Self { kem: Kem::new(Algorithm::FrodoKem1344Aes).expect("FrodoKEM-1344-AES is compiled in") }
    }

    pub fn keypair(&self) -> Result<(PublicKey, SecretKey)> {
        self.kem.keypair()
    }

    pub fn encapsulate(&self, public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
        self.kem.encapsulate(public_key)
    }

    pub fn decapsulate(&self, secret_key: &SecretKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
        self.kem.decapsulate(secret_key, ciphertext)
    }

    /// Reconstruct a ciphertext from its serialized bytes.
    ///
    /// Returns [`Error::InvalidLength`](oqs::Error::InvalidLength) if `bytes`
    /// is not exactly [`CIPHERTEXT_LEN`](Self::CIPHERTEXT_LEN) bytes long.
    pub fn ciphertext_from_bytes(&self, bytes: &[u8]) -> Result<Ciphertext> {
        self.kem
            .ciphertext_from_bytes(bytes)
            .map(|r| r.to_owned())
            .ok_or(oqs::Error::InvalidLength)
    }

    /// Reconstruct a public key from its serialized bytes.
    ///
    /// Returns [`Error::InvalidLength`](oqs::Error::InvalidLength) if `bytes`
    /// is not exactly [`PUBLIC_KEY_LEN`](Self::PUBLIC_KEY_LEN) bytes long.
    pub fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<PublicKey> {
        self.kem
            .public_key_from_bytes(bytes)
            .map(|r| r.to_owned())
            .ok_or(oqs::Error::InvalidLength)
    }

    /// Reconstruct a secret key from its serialized bytes.
    ///
    /// Returns [`Error::InvalidLength`](oqs::Error::InvalidLength) if `bytes`
    /// is not exactly [`SECRET_KEY_LEN`](Self::SECRET_KEY_LEN) bytes long.
    pub fn secret_key_from_bytes(&self, bytes: &[u8]) -> Result<SecretKey> {
        self.kem
            .secret_key_from_bytes(bytes)
            .map(|r| r.to_owned())
            .ok_or(oqs::Error::InvalidLength)
    }
}
