//! # Key Encapsulation Mechanisms (KEMs).
//!
//! A KEM lets two parties establish a shared secret over an untrusted channel.
//! The sender encapsulates a secret to the recipient's public key, producing a
//! ciphertext; the recipient decapsulates with their secret key to recover the
//! same secret. The shared secret is then typically used to key a symmetric
//! cipher.
//!
//! ## KEMs are not KEX
//!
//! This is not the same a KEX (key exchange). There do not exist any post-quantum forms of key
//! exchange like Diffie Hellman yet. In post-quantum cryptography, the client "encapsulates" a
//! randomly generated piece of key material using the server's public key and sends it over the
//! wire in a way a middleman cannot decapsulate without the server's private key.
//!
//! ## PQC and Perfect Forward Secrecy
//!
//! Additionally, a lot of PQC lacks PFS because key generation is so expensive. If you want
//! PQC-only PFS, use [`MlKem`] for generating an ephemeral key. If you're ok with hybrid, use
//! classical X25519 for the ephemeral key. [`ClassicMcEliece`] is a good choice for the server
//! static key in either case.
//!
//! # Choosing an algorithm
//!
//! | Property            | [`MlKem`] (ML-KEM-1024)     | [`FrodoKem`] (1344-AES)          | [`ClassicMcEliece`] (8192128f)   |
//! |---------------------|-----------------------------|----------------------------------|----------------------------------|
//! | Assumption          | Module Learning With Errors | Plain Learning With Errors       | Binary Goppa codes               |
//! | Cryptanalytic age   | ~10 years                   | ~15 years                        | ~50 years                        |
//! | Public key          | 1,568 B                     | 21,520 B                         | 1,357,824 B (~1.3 MB)            |
//! | Secret key          | 3,168 B                     | 43,088 B                         | 14,120 B                         |
//! | Ciphertext          | 1,568 B                     | 21,632 B                         | 208 B                            |
//! | Shared secret       | 32 B                        | 32 B                             | 32 B                             |
//! | Key generation      | Fast                        | Moderate                         | Slow (`f` = faster variant)      |
//! | NIST standard       | FIPS 203                    | Not selected                     | Round 4 finalist (not selected)  |
//!
//! ## Use [`MlKem`] when:
//!
//! - Example: Initialize an ephemeral secure channel to an authenticated server where classical
//!   crypto is already working and you want to just "bolt in" PQC.
//! - Bandwidth or storage is constrained — keys and ciphertext are small and
//!   roughly symmetric in size, making it easy to embed in TLS, SSH, or other
//!   handshake protocols.
//! - You want a NIST-standardised algorithm with broad ecosystem support.
//! - Performance matters: key generation, encapsulation, and decapsulation are
//!   all fast.
//! - You are using it in a hybrid scheme where classical cryptography can cover for the
//!   possibility that Module-LWE will be broken.
//! - You need PQC-only PFS and want fast key generation for the ephemeral key (use a different
//!   algorithm for the static key to be safe, like [`ClassicMcEliece`]).
//!
//! ## Use [`FrodoKem`] when:
//!
//! - Example: Initialize a secure channel to an authenticated server where you only want to worry
//!   about one algorithm.
//! - You're the type of person who wears a helmet while playing chess: You want a fast PQC KEM
//!   that has no known algebraic attacks exploiting ring symmetry.
//! - You are NOT pairing it in a hybrid scheme and therefore need a more conservative choice for
//!   ephemeral key generation.
//! - ~21 KB keys and ciphertext are acceptable (e.g. keys cached out-of-band
//!   or transmitted infrequently), best for long-lived sessions.
//! - You are ok with slower ephemeral key generation for the simplicity of one conservative
//!   algorithm for PQC-only PFS
//!
//! ## Use [`ClassicMcEliece`] when:
//!
//! - Example: Initialize a secure channel to an authenticated server where connections are coming
//!   up and down often, you need small ciphertexts, and you need fast session initialization.
//! - The ciphertext needs to be *tiny* (208 B) and you can afford to store or
//!   transmit the large public key out-of-band (e.g. in a long-lived
//!   certificate).
//! - You can afford a slow type-to-first-byte (on your first connection) loading the huge keys
//!   into memory.
//! - You need fast encapsulation and decapsulation (faster than RSA!) and can afford a one-time
//!   cost to serialize the keys into memory.
//! - You need long-lived static keys for identity so the extremely expensive key generation can be
//!   amortized across a lot of sessions.
//! - You need a super *conservative* hedge against breaks in lattice cryptography:
//!   code-based cryptography rests on a completely different mathematical
//!   problem and has withstood 50+ years of analysis.
//! - You are designing a PQC-only hybrid scheme and want components to have
//!   unrelated hardness assumptions.

pub use oqs::Error;
pub use oqs::kem::Ciphertext;
pub use oqs::kem::PublicKey;
pub use oqs::kem::SecretKey;
pub use oqs::kem::SharedSecret;

pub type Result<T> = core::result::Result<T, Error>;

mod classic_mceliece;
mod frodo_kem;
mod ml_kem;

pub use classic_mceliece::ClassicMcEliece;
pub use frodo_kem::FrodoKem;
pub use ml_kem::MlKem;
