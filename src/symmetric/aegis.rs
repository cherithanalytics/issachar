//! AEGIS-256X2 authenticated encryption.
//!
//! This module wraps [`aegis::aegis256x2::Aegis256X2`] to provide a safe,
//! consuming API built around a `(key, nonce)` pair that is baked into the
//! cipher at construction time.
//!
//! # Variant
//!
//! AEGIS-256X2 with a 256-bit (32-byte) authentication tag.
//!
//! | Property    | Value               |
//! |-------------|---------------------|
//! | Key         | 256 bits (32 bytes) |
//! | Nonce       | 256 bits (32 bytes) |
//! | Tag         | 256 bits (32 bytes) |
//!
//! AEGIS-256X2 runs two AEGIS-256 instances in parallel, doubling throughput
//! on CPUs with AES instructions (AES-NI on x86-64, Crypto Extensions on ARM).
//!
//! # When to prefer AEGIS over `ChaCha20Poly1305Cipher`
//!
//! AEGIS-256X2 is significantly faster than ChaCha20-Poly1305 for large
//! payloads on hardware that carries AES instructions, often by 3–5×.
//! However, each [`AegisCipher::new`] call runs the AEGIS key schedule, which
//! has a fixed per-message cost.  For high-frequency small messages — each
//! under a freshly constructed cipher with a different nonce — that overhead
//! can make ChaCha20-Poly1305 faster.  Prefer AEGIS when the payload per
//! cipher instance is large; prefer `ChaCha20Poly1305Cipher` for many small
//! independent messages.
//!
//! # Key and nonce handling
//!
//! [`AegisCipher::new`] takes both the key and the nonce because the
//! underlying `Aegis256X2::new` requires both to initialise its state.  The
//! raw bytes are stored inside the `Aegis256X2` object; the underlying crate
//! does not implement `Zeroize`, so the key is not explicitly scrubbed on
//! drop.  All operations on `AegisCipher` consume `self`, making it a
//! compile-time error to reuse the same `(key, nonce)` pair across two
//! different calls.
//!
//! # Streaming large payloads
//!
//! AEGIS-256X2 is an all-at-once AEAD — the authentication tag depends on the
//! complete message.  For streaming large payloads with bounded memory, split
//! the stream into fixed-size chunks and call [`encrypt`](AegisCipher::encrypt) /
//! [`decrypt`](AegisCipher::decrypt) on each with a derived per-chunk nonce (e.g.
//! base nonce XOR little-endian chunk index in the first 8 bytes).  Each chunk
//! carries its own `TAG_LEN`-byte tag and is authenticated immediately.

use aegis::aegis256x2::Aegis256X2;

pub const TAG_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;

// ── Single-use cipher ─────────────────────────────────────────────────────────

/// AEGIS-256X2 cipher bound to a single `(key, nonce)` pair.
///
/// All operations consume `self`, making it a compile-time error to reuse
/// the same `(key, nonce)` pair across two different calls.
///
/// See the [module documentation](self) for performance guidance and
/// trade-offs versus `ChaCha20Poly1305Cipher`.
pub struct AegisCipher(Aegis256X2<TAG_LEN>);

impl AegisCipher {
    /// Initialises the cipher.  The AEGIS key schedule runs here; the raw
    /// key and nonce bytes are stored inside `Aegis256X2` (the underlying
    /// crate does not implement `Zeroize`).
    pub fn new(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Self {
        Self(Aegis256X2::new(key, nonce))
    }

    /// Encrypts `plaintext` and writes `ciphertext || tag` into `ciphertext`.
    /// `ciphertext` must be at least `plaintext.len() + TAG_LEN` bytes long.
    pub fn encrypt(self, aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), Error> {
        if ciphertext.len() < plaintext.len() + TAG_LEN {
            return Err(Error::TooShort);
        }
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        let tag = self.0.encrypt_in_place(&mut ciphertext[..plaintext.len()], aad);
        ciphertext[plaintext.len()..plaintext.len() + TAG_LEN].copy_from_slice(&tag);
        Ok(())
    }

    /// Decrypts and verifies `ciphertext`, writing plaintext into `plaintext`.
    ///
    /// `ciphertext` must end with a `TAG_LEN`-byte tag; `plaintext` must be
    /// at least `ciphertext.len() - TAG_LEN` bytes long.
    ///
    /// On tag failure, `plaintext` is zeroed before returning `Err`.
    pub fn decrypt(
        self,
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if ciphertext.len() < TAG_LEN {
            return Err(Error::TooShort);
        }
        let n = ciphertext.len() - TAG_LEN;
        if plaintext.len() < n {
            return Err(Error::TooShort);
        }
        let tag: [u8; TAG_LEN] = ciphertext[n..].try_into().unwrap();
        plaintext[..n].copy_from_slice(&ciphertext[..n]);
        if self.0.decrypt_in_place(&mut plaintext[..n], &tag, aad).is_err() {
            plaintext[..n].fill(0);
            return Err(Error::AuthenticationFailed);
        }
        Ok(())
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Error {
    /// The input buffer is shorter than `TAG_LEN`.
    TooShort,
    /// The authentication tag did not verify.
    AuthenticationFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TooShort => write!(f, "input shorter than TAG_LEN ({TAG_LEN} bytes)"),
            Error::AuthenticationFailed => f.write_str("authentication tag mismatch"),
        }
    }
}
