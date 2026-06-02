use oqs::sig::Algorithm;
use oqs::sig::Sig;

use super::PublicKey;
use super::Result;
use super::SecretKey;
use super::Signature;

/// SPHINCS+-SHAKE256-256f-simple (NIST FIPS 205 / SLH-DSA, security level 5,
/// fast variant).
///
/// SPHINCS+ is a stateless hash-based signature scheme. Its security rests
/// solely on the collision resistance and preimage resistance of SHAKE256 —
/// no algebraic structure is assumed. This makes it the most conservative
/// signature scheme available.
///
/// The `f` (fast) variant produces larger signatures than the `s` (small)
/// variant but signs significantly faster. Verification is fast in both
/// variants.
///
/// We are using the "simple" (vs. "robust") variant of SPHINCS+, which is about
/// 3-4x faster than robust. Robust avoids certain assumptions about SHAKE256 at a
/// significant performance cost. In short, simple assumes something called the
/// "random oracle model": Hash functions are perfect mathematical objects that
/// perfectly map arbitrary-length inputs to fixed-length pseudorandom outputs.
///
/// # Sizes
///
/// | Object     | Bytes  |
/// |------------|--------|
/// | Public key |     64 |
/// | Secret key |    128 |
/// | Signature  | 49,856 |
///
/// # Pros
///
/// - Minimal trust assumption: security reduces entirely to SHAKE256. Even
///   if all lattice-based schemes were broken tomorrow, SPHINCS+ would be
///   unaffected.
/// - Extremely small public and secret keys (64 B / 128 B) — ideal for
///   constrained devices, key pinning, or any context where key storage is
///   at a premium.
/// - Stateless: unlike earlier hash-based schemes (XMSS, LMS), no state
///   needs to be maintained between signings, eliminating the risk of
///   catastrophic state reuse.
///
/// # Cons
///
/// - Large signatures (~49 KB with the `f` variant) — unsuitable for
///   protocols that transmit many signatures frequently (e.g. per-packet
///   authentication). Best suited to infrequent, high-value signings such
///   as root CA certificates, firmware releases, or software packages.
/// - Signing is slower than ML-DSA, even with the `f` variant.
pub struct Sphincs;

impl Sphincs {
    pub fn keypair() -> Result<(PublicKey, SecretKey)> {
        oqs::init();
        let sig = Sig::new(Algorithm::SphincsShake256fSimple)?;
        sig.keypair()
    }

    pub fn sign(message: impl AsRef<[u8]>, secret_key: &SecretKey) -> Result<Signature> {
        oqs::init();
        let sig = Sig::new(Algorithm::SphincsShake256fSimple)?;
        sig.sign(message.as_ref(), secret_key)
    }

    pub fn verify(
        message: impl AsRef<[u8]>,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<()> {
        oqs::init();
        let sig = Sig::new(Algorithm::SphincsShake256fSimple)?;
        sig.verify(message.as_ref(), signature, public_key)
    }
}
