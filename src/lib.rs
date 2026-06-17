//! Post-quantum cryptography primitives.
//!
//! This crate exposes four modules:
//!
//! - [`kem`] — Key Encapsulation Mechanisms: [`kem::MlKem`], [`kem::ClassicMcEliece`]
//! - [`sig`] — Digital Signatures: [`sig::MlDsa`], [`sig::Sphincs`]
//! - [`prf`] — cSHAKE256-based pseudorandom functions: [`prf::cshake256::digest`], [`prf::cshake256::hmac`], [`prf::cshake256::kdf`]
//!
//! All algorithms are fixed at their highest security level (NIST Level 5, ~256-bit
//! classical / 128-bit post-quantum security). See each module for a full comparison.
//!
//! # `no_std` support
//!
//! This crate is `#![no_std]` and links `alloc` for the heap-allocated key and
//! ciphertext types exposed by the underlying `oqs` bindings. It compiles on any
//! target that provides an allocator.
//!
//! The `std` feature (enabled by default) links the standard library and unlocks
//! the one API that requires it:
//!
//! | Feature gated on `std`                    | Why                                      |
//! |-------------------------------------------|------------------------------------------|
//! | [`prf::cshake256::CShake256::update_read`] | Takes `&mut BufReader<R: std::io::Read>` |
//!
//! To use the crate in a `no_std` environment, disable default features:
//!
//! ```toml
//! [dependencies]
//! issachar = { version = "...", default-features = false }
//! ```
//!
//! # Why this library is extremely paranoid
//!
//! This crate fixes every algorithm at NIST security level 5 — the highest defined
//! category — and makes no provision for lower levels. That is a deliberate,
//! conservative design choice that goes well beyond what most threat models require.
//! Here is why it is justified, and what it costs.
//!
//! **What "level 5" means in practice.** NIST security category 5 targets at least
//! 256-bit classical security and at least 128-bit post-quantum security. It is sized
//! to match AES-256: an attacker with a universal quantum computer running Grover's
//! algorithm still needs ~2^128 oracle calls to break either the KEM, the signature,
//! or the symmetric cipher — a number so large it is physically unreachable even with
//! optimistic projections for quantum hardware over the next century.
//!
//! **Why not level 3 or level 1?** Level 3 (~192-bit classical / ~128-bit
//! post-quantum) is likely sufficient for most applications today and for the
//! foreseeable future. Level 1 (~128-bit classical) is adequate for ephemeral session
//! keys that have no long-term value. The decision to use level 5 exclusively reflects
//! two concerns:
//!
//! - *Harvest-now-decrypt-later attacks.* An adversary can record encrypted traffic
//!   today and decrypt it once a quantum computer exists. Any data that must remain
//!   confidential beyond ~10–20 years — state secrets, medical records, long-lived
//!   private keys — should be protected with the highest available security level now,
//!   because there is no going back once the data has been captured.
//!
//! - *Unknown unknowns.* Post-quantum algorithms are young. ML-KEM and ML-DSA have
//!   roughly 10 years of public cryptanalysis behind them, compared to decades for
//!   RSA or elliptic curves. A cryptanalytic advance that breaks level 3 but not
//!   level 5 is not implausible in the next 20 years.
//!
//! **What it costs.** Level 5 algorithms have larger keys, ciphertexts, and signatures
//! than their level 3 counterparts. For most applications this is negligible — ML-KEM's
//! 1,568-byte public key and ciphertext fit comfortably in a TLS handshake. Classic
//! McEliece is the only algorithm whose size (1.3 MB public key) places a real
//! constraint on usage patterns; see [`kem::ClassicMcEliece`] for guidance.
//!
//! # Hybrid classical + post-quantum cryptography
//!
//! Post-quantum algorithms are relatively new and have had far less real-world
//! scrutiny than classical algorithms like X25519 or Ed25519. A hybrid
//! construction hedges against failure in both directions:
//!
//! - If a post-quantum algorithm has an undiscovered flaw, the classical
//!   algorithm still protects you.
//! - If a quantum computer is built, the post-quantum algorithm still protects
//!   you.
//!
//! ## Hybrid KEM
//!
//! Run a classical KEM (e.g. X25519) and a post-quantum KEM (e.g. [`kem::MlKem`])
//! in parallel. The critical rule is that you must **hash the outputs together**
//! using a KDF — never use either shared secret directly and never simply
//! concatenate them as a key. Concatenation alone means a break of either
//! algorithm immediately yields the full secret. Feeding both into a KDF
//! (e.g. HKDF) means an attacker must break *both* simultaneously.
//!
//! ```text
//! key = HKDF(
//!     personalization  = domain-separation label,
//!     ikm   = classical_shared_secret || pq_shared_secret
//! )
//! ```
//!
//! The derived `key` is secure as long as *either* the classical *or* the
//! post-quantum shared secret is indistinguishable from random.
//!
//! ## Hybrid signatures
//!
//! Sign with both a classical scheme (e.g. Ed25519) and a post-quantum scheme
//! (e.g. [`sig::MlDsa`]). Transmit both signatures alongside the message. A
//! verifier must check **both** and reject if either fails:
//!
//! ```text
//! verify(message, classical_sig, classical_pk)  // must pass
//! verify(message, pq_sig, pq_pk)                // must pass
//! ```
//!
//! The two signatures are independent and each already commits to the full
//! message, so no additional hashing of the signatures together is required.
//!
//! # Symmetric keys and hash output lengths
//!
//! Once a shared secret is established, data is typically encrypted with a symmetric
//! cipher. Symmetric primitives face a different and considerably weaker quantum threat
//! than asymmetric ones.
//!
//! **Shor's algorithm** — the reason this crate exists — breaks RSA and elliptic-curve
//! cryptography in polynomial time. It requires a large, fully fault-tolerant quantum
//! computer, but when that machine exists, classical asymmetric cryptography is broken
//! completely.
//!
//! **Grover's algorithm** gives a quadratic speedup for unstructured search, effectively
//! halving the bit-security of a symmetric key. AES-128 drops to ~64-bit security;
//! AES-256 drops to ~128 bits, which remains adequate. The **BHT algorithm** extends
//! Grover's to find hash collisions in O(2^(n/3)) time rather than O(2^(n/2)), making
//! 256-bit hashes marginal for collision resistance (~85-bit quantum security) while
//! 512-bit outputs remain comfortable.
//!
//! Both Grover's and BHT are far harder to realize in practice than Shor's. Grover's
//! amplitude amplification is inherently sequential and does not parallelise efficiently;
//! BHT additionally requires quantum random-access memory (QRAM), an unsolved engineering
//! problem. A practical machine running Shor's algorithm will exist long before one
//! capable of meaningfully accelerating Grover's or BHT against 256-bit keys.
//!
//! The mitigation is straightforward: **use 256-bit symmetric keys and 512-bit hash
//! output** (e.g. SHAKE256 with 64-byte output, as this crate's [`prf`] module does).
//!
//! The all-level-5 algorithms in this crate are sized to pair with 256-bit
//! symmetric ciphers. The shared secrets produced by [`kem`] are 32 bytes.
//!

#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod classic;
pub mod kem;
pub mod pbkdf;
pub mod prf;
pub mod sig;
pub mod strobe;
pub mod symmetric;

use subtle::ConstantTimeEq;

/// Constant-time equality check for fixed-size byte arrays.
///
/// Returns `true` iff `a == b` without leaking which bytes differed or at which
/// index the comparison terminated.
pub fn timing_safe_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.as_ref().ct_eq(b.as_ref()).into()
}

/// Fill `buf` with cryptographically secure random bytes from the OS.
pub fn fill_rand(buf: &mut [u8]) {
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(buf);
}

/// An `RngCore + CryptoRng` adapter that delegates all randomness to [`fill_rand`].
pub(crate) struct Rng;

impl rand_core::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_rand(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill_rand(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Rng {}
