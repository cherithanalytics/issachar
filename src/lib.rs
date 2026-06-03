//! Post-quantum cryptography primitives.
//!
//! This crate exposes four modules:
//!
//! - [`kem`] — Key Encapsulation Mechanisms: [`kem::MlKem`], [`kem::ClassicMcEliece`]
//! - [`sig`] — Digital Signatures: [`sig::MlDsa`], [`sig::Sphincs`]
//! - [`prf`] — cSHAKE256-based pseudorandom functions: [`prf::digest`], [`prf::hmac`], [`prf::kdf`]
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
//! # Grover's algorithm, BHT algorithm: Key lengths and Hash lengths have to change
//!
//! The algorithms in this crate protect key establishment and authentication.
//! Once a shared secret is established, data is typically encrypted with a
//! symmetric cipher such as AES or ChaCha20. Symmetric encryption faces a
//! *different* quantum threat: **Grover's algorithm**.
//!
//! Grover's algorithm can search an unstructured space of N possibilities in
//! √N steps rather than N, giving a quantum attacker a quadratic — not
//! exponential — speedup against symmetric keys. The practical consequence is
//! that a quantum computer effectively **halves the bit-security of a symmetric
//! key**:
//!
//! > **This is extremely paranoid.** Unlike classical brute force, which
//! > parallelises perfectly (k processors reduce work by exactly k), Grover's
//! > amplitude amplification is inherently sequential — each step depends on the
//! > previous one. Running k independent quantum processors in parallel yields
//! > only a √k speedup rather than k, so reducing 2^128 Grover steps to a
//! > feasible timeline would require ~2^128 quantum processors working in
//! > concert — physically impossible. Beyond parallelism, each Grover oracle
//! > call on AES-256 requires thousands of logical qubits and millions of
//! > physical qubits (due to error-correction overhead); no near-term or
//! > medium-term quantum computer approaches this scale.
//!
//! Hash functions face an additional, sharper threat beyond Grover's. The
//! **Brassard-Høyer-Tapp (BHT)** algorithm combines Grover's search with a
//! quantum walk to find collisions in O(2^(n/3)) time rather than the classical
//! O(2^(n/2)) birthday bound. This cuts collision resistance to one-third of
//! the output width rather than one-half, which is why the hash rows above show
//! ~85-bit quantum security for 256-bit hashes (256 / 3 ≈ 85) rather than the
//! 128 bits that Grover's alone would predict. Preimage resistance is still
//! governed by Grover's (2^(n/2)), so 256-bit hashes retain ~128-bit preimage
//! security — it is collision resistance specifically that takes the harder hit.
//!
//! > **BHT is even more paranoid than Grover's.** The O(2^(n/3)) bound assumes
//! > quantum random-access memory (QRAM) that can store and retrieve 2^(n/3)
//! > quantum states in O(1) time. For a 256-bit hash that is ~2^85 memory
//! > cells — more addressable storage than any physical system could provide.
//! > QRAM itself remains an unsolved engineering problem; all current proposals
//! > require O(n) physical components per logical address, making the full BHT
//! > attack purely theoretical at these output sizes.
//!
//! | Cipher / hash   | Classical security | Quantum security  | Verdict        |
//! |-----------------|--------------------|-------------------|----------------|
//! | AES-128         | 128 bits           | ~64 bits          | ✗ Insufficient |
//! | AES-256         | 256 bits           | ~128 bits         | ✓ Adequate     |
//! | ChaCha20        | 256 bits           | ~128 bits         | ✓ Adequate     |
//! | HMAC-SHA-256    | 256 bits           | ~128 bits         | ✓ Adequate     |
//! | SHA-256 (hash)  | 128-bit collision  | ~85-bit collision | ~ Marginal     |
//! | BLAKE3 (hash)   | 128-bit collision  | ~85-bit collision | ~ Marginal     |
//! | SHA-512 (hash)  | 256-bit collision  | ~128-bit collision| ✓ Adequate     |
//! | SHAKE256 (512b) | 256-bit collision  | ~128-bit collision| ✓ Adequate     |
//!
//! The mitigation is straightforward: **use 256-bit symmetric keys and 256-bit security level
//! digests.**
//!
//! The all-level-5 algorithms in this crate are sized to pair with 256-bit
//! symmetric ciphers. The shared secrets produced by [`kem`] are 32 bytes.
//!
//! # Post-quantum pseudorandom functions
//!
//! The classical `crypto_prf` crate uses BLAKE3, which provides only ~128 bits of
//! post-quantum preimage resistance due to Grover's algorithm halving the effective
//! security level of any n-bit hash. [`prf`] uses SHAKE256 with 512-bit (64-byte)
//! output, retaining ~256 bits of post-quantum preimage resistance and matching the
//! security level of the KEMs and signature schemes in this crate. Prefer [`prf`]
//! over `crypto_prf` wherever outputs will be used as keys, shared secrets, or
//! commitments that must remain secure against a future quantum-capable adversary.
//!

#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod classic;
pub mod kem;
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
