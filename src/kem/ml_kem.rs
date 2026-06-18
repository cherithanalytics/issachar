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
///
/// # Reuse
///
/// Construct once with [`MlKem::new`] and reuse across operations — each
/// instance owns the underlying liboqs algorithm object, so reusing it avoids
/// re-allocating that object on every encapsulation/decapsulation.
pub struct MlKem {
    kem: Kem,
}

impl Default for MlKem {
    fn default() -> Self {
        Self::new()
    }
}

impl MlKem {
    /// Length in bytes of a serialized public key.
    pub const PUBLIC_KEY_LEN: usize = 1_568;
    /// Length in bytes of a serialized secret key.
    pub const SECRET_KEY_LEN: usize = 3_168;
    /// Length in bytes of a ciphertext.
    pub const CIPHERTEXT_LEN: usize = 1_568;
    /// Length in bytes of the encapsulated shared secret.
    pub const SHARED_SECRET_LEN: usize = 32;

    /// Construct a reusable ML-KEM-1024 instance.
    ///
    /// Infallible: ML-KEM-1024 is always compiled in via the crate's `oqs`
    /// feature set, so the underlying algorithm object can always be created.
    pub fn new() -> Self {
        oqs::init();
        Self { kem: Kem::new(Algorithm::MlKem1024).expect("ML-KEM-1024 is compiled in") }
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
