//! One-time signature schemes (OTS).
//!
//! # ⚠ Key-reuse is catastrophic
//!
//! Unlike the schemes in [`crate::sig`], every algorithm in this module is
//! **one-time only**: a secret key must sign **at most one message**, ever.
//! Signing a second message with the same key leaks enough private material
//! for an attacker to forge a valid signature on any message of their choice
//! under that key. There is no safe recovery — the key is permanently
//! compromised the moment it signs a second time.
//!
//! Only use this module when your application can architecturally enforce the
//! one-time constraint — for example, keys embedded in a Merkle tree (like
//! XMSS or LMS), a forward-only append log, or a hardware token that destroys
//! the key after one use. For all other signing needs, use [`crate::sig`].
//!
//! # Choosing an algorithm
//!
//! | Property          | [`Winternitz`] (LDWM_SHA256_M20_W8)  |
//! |-------------------|--------------------------------------|
//! | Assumption        | Preimage resistance of SHA-256       |
//! | Cryptanalytic age | ~50 years (hash functions)           |
//! | Public key        | 32 B                                 |
//! | Secret key        | 2,144 B                              |
//! | Signature         | 1,340 B                              |
//! | NIST standard     | No                                   |
//!
//! ## Use [`Winternitz`] when:
//!
//! - You need an absolute minimum public key size (32 B) with no algebraic
//!   assumptions and fast signing and verification.
//! - The one-time constraint is enforced architecturally — each key pair is
//!   generated fresh and used for exactly one message, with no possibility of
//!   accidental reuse (e.g. keys are leaf nodes in a Merkle tree or stored in
//!   a write-once medium).
//! - Prefer [`crate::sig::Sphincs`] for general use; [`Winternitz`] is for
//!   specialised scenarios where key-reuse is impossible by construction.

pub mod winternitz;
