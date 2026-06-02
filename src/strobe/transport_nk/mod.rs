pub mod hybrid;
pub mod pqc;

use zeroize::Zeroize;

use crate::strobe::Strobe;
use crate::symmetric::chacha20poly1305::ChaCha20Nonce;
use crate::symmetric::chacha20poly1305::ChaCha20Poly1305Cipher;
use crate::symmetric::chacha20poly1305::Error;

pub const MAC_LEN: usize = 16;

pub(crate) enum Role {
    Initiator,
    Responder,
}

/// Stateful transport — automatically increments nonces on each send/recv.
/// Obtain via `StrobeNkHybridInitiator::finish()` / `StrobeNkHybridResponder::respond()`
/// or the PQC equivalents.
pub struct StrobeNkTransport {
    tx: ChaCha20Poly1305Cipher,
    rx: ChaCha20Poly1305Cipher,
    tx_nonce: ChaCha20Nonce,
    rx_nonce: ChaCha20Nonce,
}

impl StrobeNkTransport {
    pub(crate) fn from_handshake(mut strobe: Strobe, role: Role) -> Self {
        let mut key_a = [0u8; 32];
        strobe.prf(&mut key_a);
        let mut key_b = [0u8; 32];
        strobe.prf(&mut key_b);
        strobe.zeroize();

        let (tx, rx) = match role {
            Role::Initiator => (
                ChaCha20Poly1305Cipher::new(&key_a),
                ChaCha20Poly1305Cipher::new(&key_b),
            ),
            Role::Responder => (
                ChaCha20Poly1305Cipher::new(&key_b),
                ChaCha20Poly1305Cipher::new(&key_a),
            ),
        };
        key_a.zeroize();
        key_b.zeroize();

        Self {
            tx,
            rx,
            tx_nonce: ChaCha20Nonce::zero(),
            rx_nonce: ChaCha20Nonce::zero(),
        }
    }

    /// Encrypts `plaintext` into `ciphertext` (ciphertext || tag).
    /// `ciphertext.len()` must equal `plaintext.len() + TAG_LEN`.
    /// `tx_nonce` advances before encryption to prevent nonce reuse on retry.
    pub fn send(
        &mut self,
        aad: impl AsRef<[u8]>,
        plaintext: impl AsRef<[u8]>,
        mut ciphertext: impl AsMut<[u8]>,
    ) -> Result<(), Error> {
        self.tx_nonce.increment();
        self.tx.encrypt(self.tx_nonce, aad.as_ref(), plaintext.as_ref(), ciphertext.as_mut())
    }

    /// Decrypts `ciphertext` (ciphertext || tag) into `plaintext`.
    /// `plaintext.len()` must equal `ciphertext.len() - TAG_LEN`.
    /// `rx_nonce` advances before decryption to prevent nonce reuse on retry.
    pub fn recv(
        &mut self,
        aad: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        mut plaintext: impl AsMut<[u8]>,
    ) -> Result<(), Error> {
        self.rx_nonce.increment();
        self.rx.decrypt(self.rx_nonce, aad.as_ref(), ciphertext.as_ref(), plaintext.as_mut())
    }

    /// Convert to a stateless transport (caller manages nonces). Is `Sync`.
    pub fn into_stateless(self) -> StrobeNkStatelessTransport {
        StrobeNkStatelessTransport { tx: self.tx, rx: self.rx }
    }
}

/// Stateless transport — caller supplies the nonce on every call.
/// Nonce uniqueness and replay detection are the caller's responsibility.
/// Obtain via `StrobeNkTransport::into_stateless()`.
pub struct StrobeNkStatelessTransport {
    tx: ChaCha20Poly1305Cipher,
    rx: ChaCha20Poly1305Cipher,
}

impl StrobeNkStatelessTransport {
    /// Encrypts `plaintext` into `ciphertext` (ciphertext || tag).
    /// `ciphertext.len()` must equal `plaintext.len() + TAG_LEN`.
    pub fn send(
        &self,
        nonce: ChaCha20Nonce,
        aad: impl AsRef<[u8]>,
        plaintext: impl AsRef<[u8]>,
        mut ciphertext: impl AsMut<[u8]>,
    ) -> Result<(), Error> {
        self.tx.encrypt(nonce, aad.as_ref(), plaintext.as_ref(), ciphertext.as_mut())
    }

    /// Decrypts `ciphertext` (ciphertext || tag) into `plaintext`.
    /// `plaintext.len()` must equal `ciphertext.len() - TAG_LEN`.
    pub fn recv(
        &self,
        nonce: ChaCha20Nonce,
        aad: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        mut plaintext: impl AsMut<[u8]>,
    ) -> Result<(), Error> {
        self.rx.decrypt(nonce, aad.as_ref(), ciphertext.as_ref(), plaintext.as_mut())
    }
}
