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
/// - Extremely fast encapsulation and decapsulation, even faster than RSA.
///
/// # Cons
///
/// - Very large public key (~1.3 MB) — prohibitive for protocols that
///   transmit the public key in every session (e.g. standard TLS handshakes).
///   Plan for out-of-band distribution or long-lived public keys.
/// - Key generation is slow even with the `f` variant; not suitable for
///   ephemeral key exchange patterns where a fresh keypair is needed per
///   session.
///
/// # Reuse
///
/// Construct once with [`ClassicMcEliece::new`] and reuse across operations —
/// each instance owns the underlying liboqs algorithm object, so reusing it
/// avoids re-allocating that object on every encapsulation/decapsulation. This
/// matters most in a tight handshake loop where a responder decapsulates with
/// the same static key repeatedly.
pub struct ClassicMcEliece {
    kem: Kem,
}

impl Default for ClassicMcEliece {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassicMcEliece {
    /// Length in bytes of a serialized public key.
    pub const PUBLIC_KEY_LEN: usize = 1_357_824;
    /// Length in bytes of a serialized secret key.
    pub const SECRET_KEY_LEN: usize = 14_120;
    /// Length in bytes of a ciphertext.
    pub const CIPHERTEXT_LEN: usize = 208;
    /// Length in bytes of the encapsulated shared secret.
    pub const SHARED_SECRET_LEN: usize = 32;

    /// Construct a reusable Classic McEliece 8192128f instance.
    ///
    /// Infallible: Classic McEliece 8192128f is always compiled in via the
    /// crate's `oqs` feature set, so the underlying algorithm object can always
    /// be created.
    pub fn new() -> Self {
        oqs::init();
        Self {
            kem: Kem::new(Algorithm::ClassicMcEliece8192128f)
                .expect("Classic McEliece 8192128f is compiled in"),
        }
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
