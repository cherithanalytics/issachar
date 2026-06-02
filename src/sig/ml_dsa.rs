use oqs::sig::Algorithm;
use oqs::sig::Sig;

use super::PublicKey;
use super::Result;
use super::SecretKey;
use super::Signature;

/// ML-DSA-87 (NIST FIPS 204, security level 5).
///
/// ML-DSA (formerly Dilithium) is a lattice-based signature scheme
/// standardised by NIST. It is the recommended default for most signing
/// applications.
///
/// # Sizes
///
/// | Object     | Bytes |
/// |------------|-------|
/// | Public key | 2,592 |
/// | Secret key | 4,896 |
/// | Signature  | 4,595 |
///
/// # Pros
///
/// - Compact signatures (~4.5 KB) and fast signing and verification —
///   practical for high-throughput or bandwidth-sensitive applications.
/// - NIST-standardised (FIPS 204); broad library and hardware support.
/// - Deterministic signing (no per-signature randomness required).
///
/// # Cons
///
/// - Lattice-based: security depends on Module-LWE/SIS. Strong, but a newer
///   assumption (~10 years) compared to hash-based alternatives.
pub struct MlDsa;

impl MlDsa {
    pub fn keypair() -> Result<(PublicKey, SecretKey)> {
        oqs::init();
        let sig = Sig::new(Algorithm::MlDsa87)?;
        sig.keypair()
    }

    pub fn sign(message: impl AsRef<[u8]>, secret_key: &SecretKey) -> Result<Signature> {
        oqs::init();
        let sig = Sig::new(Algorithm::MlDsa87)?;
        sig.sign(message.as_ref(), secret_key)
    }

    pub fn verify(
        message: impl AsRef<[u8]>,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<()> {
        oqs::init();
        let sig = Sig::new(Algorithm::MlDsa87)?;
        sig.verify(message.as_ref(), signature, public_key)
    }
}
