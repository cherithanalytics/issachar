//! Digital signature schemes.
//!
//! A signature scheme lets a signer authenticate messages with their secret
//! key; any holder of the corresponding public key can verify authenticity.
//!
//! # Choosing an algorithm
//!
//! | Property          | [`MlDsa`] (ML-DSA-87)        | [`Sphincs`] (SPHINCS+-SHA2-256f)  |
//! |-------------------|------------------------------|-----------------------------------|
//! | Assumption        | Module Learning With Errors  | Security of SHA-256 (hash only)   |
//! | Cryptanalytic age | ~10 years                    | ~30 years (hash functions)        |
//! | Public key        | 2,592 B                      | 64 B                              |
//! | Secret key        | 4,896 B                      | 128 B                             |
//! | Signature         | 4,595 B                      | 49,856 B                          |
//! | Signing speed     | Fast                         | Moderate (`f` = faster variant)   |
//! | Verification      | Fast                         | Fast                              |
//! | NIST standard     | FIPS 204                     | FIPS 205 (as SLH-DSA)             |
//!
//! ## Use [`MlDsa`] when:
//!
//! - Signature size and signing speed matter — ML-DSA produces compact
//!   signatures quickly and is the right default for most applications
//!   (TLS certificates, code signing, authentication tokens).
//! - You want a NIST-standardised algorithm with broad ecosystem support.
//! - You aren't using using ML-KEM in the application OR you are "ok" with having both your KEM
//!   and your SIG break if a cryptoanalytic breakthrough is discovered against module learning
//!   with errors.
//!
//! ## Use [`Sphincs`] when:
//!
//! - You need the most conservative possible security assumption: SPHINCS+
//!   relies only on the security of a hash function (SHA-256), with no
//!   algebraic structure to attack. If ML-DSA's lattice assumption were ever
//!   broken, SPHINCS+ would be unaffected.
//! - Tiny public and secret keys are important (64 B and 128 B respectively),
//!   for example in highly constrained environments or key-pinning scenarios.
//! - Large signatures (~49 KB) are acceptable — e.g. long-lived root CA
//!   certificates or firmware images where the signature is transmitted once.
//!
//! # Prehashing with cSHAKE256
//!
//! Both [`MlDsa::sign`] and [`Sphincs::sign`] accept the full message as a
//! single `&[u8]`. For large or streaming messages, or when you want domain
//! separation, prehash the message with [`crate::prf::cshake256::CShake256`]
//! and pass the resulting digest to `sign`/`verify` instead:
//!
//! ```ignore
//! use pqc::prf::cshake256::CShake256;
//! use pqc::sig::MlDsa;
//!
//! let (pk, sk) = MlDsa::keypair()?;
//!
//! // Build the digest incrementally — no need to buffer the whole message.
//! let mut h = CShake256::digest(b"myapp v1 document signing");
//! h.update(header);
//! h.update(body);
//! // or: h.update_read(&mut BufReader::new(file))?;  // requires `std` feature
//! let digest = h.finalize();
//!
//! let sig = MlDsa::sign(&digest, &sk)?;
//! // Verifier reconstructs the same digest and calls MlDsa::verify.
//! ```
//!
//! The `customization` string passed to [`crate::prf::cshake256::CShake256::digest`] acts as a
//! domain-separation label: two calls with different strings produce completely
//! independent output spaces even with identical message content, so the same
//! key pair can safely serve multiple protocols without cross-context confusion.
//!
//! ## Performance benefit for SPHINCS+
//!
//! SPHINCS+ signs the raw message by hashing it internally many times across its
//! hypertree — the signing cost scales with message length. Prehashing to a
//! fixed-size 64-byte digest first means SPHINCS+ always operates on 64 bytes
//! regardless of how large the original message is, giving a significant speedup
//! for any message longer than a few hundred bytes.

pub use oqs::Error;
pub use oqs::sig::PublicKey;
pub use oqs::sig::SecretKey;
pub use oqs::sig::Signature;

pub type Result<T> = core::result::Result<T, Error>;

mod ml_dsa;
mod sphincs;

pub use ml_dsa::MlDsa;
pub use sphincs::Sphincs;
