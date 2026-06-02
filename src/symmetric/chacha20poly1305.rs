use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::aead::KeyInit;

pub const TAG_LEN: usize = 16;

/// 96-bit IETF nonce for ChaCha20Poly1305.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaCha20Nonce([u8; 12]);

impl ChaCha20Nonce {
    /// Constructs a nonce from a raw 12-byte little-endian value.
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Returns the zero nonce.
    pub fn zero() -> Self {
        Self([0u8; 12])
    }

    pub fn increment(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                return;
            }
        }
        panic!("nonce counter overflow");
    }

    pub fn to_le_bytes(self) -> [u8; 12] {
        self.0
    }

    fn to_chacha20_nonce(self) -> chacha20poly1305::Nonce {
        *chacha20poly1305::Nonce::from_slice(&self.0)
    }
}

/// A stateless ChaCha20Poly1305 cipher. Callers supply the full 12-byte IETF
/// nonce on every call.
///
/// Nonce management is the caller's responsibility — typically handled by
/// `StrobeNkTransport`.
pub struct ChaCha20Poly1305Cipher(chacha20poly1305::ChaCha20Poly1305);

impl ChaCha20Poly1305Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self(chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key)))
    }

    /// Encrypts `plaintext` into `ciphertext` (ciphertext || tag).
    /// `ciphertext.len()` must equal `plaintext.len() + TAG_LEN`.
    pub fn encrypt(
        &self,
        nonce: ChaCha20Nonce,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        check_lengths(plaintext.len(), ciphertext.len())?;
        let n = plaintext.len();
        ciphertext[..n].copy_from_slice(plaintext);
        let tag = self
            .0
            .encrypt_in_place_detached(&nonce.to_chacha20_nonce(), aad, &mut ciphertext[..n])
            .map_err(|_| Error::EncryptionFailed)?;
        ciphertext[n..].copy_from_slice(&tag);
        Ok(())
    }

    /// Decrypts `ciphertext` (ciphertext || tag) into `plaintext`.
    /// `ciphertext.len()` must be at least `TAG_LEN`; `plaintext.len()` must
    /// equal `ciphertext.len() - TAG_LEN`.
    pub fn decrypt(
        &self,
        nonce: ChaCha20Nonce,
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        check_lengths(plaintext.len(), ciphertext.len())?;
        plaintext.copy_from_slice(&ciphertext[..plaintext.len()]);
        let tag = chacha20poly1305::Tag::from_slice(&ciphertext[plaintext.len()..]);
        self.0
            .decrypt_in_place_detached(&nonce.to_chacha20_nonce(), aad, plaintext, tag)
            .map_err(|_| Error::AuthenticationFailed)?;
        Ok(())
    }
}

/// Returns `Err(Error::BadLength)` unless `plaintext_len + TAG_LEN == ciphertext_len`.
fn check_lengths(plaintext_len: usize, ciphertext_len: usize) -> Result<(), Error> {
    if plaintext_len.checked_add(TAG_LEN) == Some(ciphertext_len) {
        Ok(())
    } else {
        Err(Error::BadLength)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("buffer length mismatch")]
    BadLength,

    #[error("chacha20poly1305 encryption error")]
    EncryptionFailed,

    #[error("chacha20poly1305 authentication tag mismatch")]
    AuthenticationFailed,
}
