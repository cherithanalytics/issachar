/// An ephemeral X25519 key pair for use in a single handshake.
///
/// Generate one with [`X25519Key::generate`], read the public key with
/// [`X25519Key::public_key_bytes`], then call [`X25519Key::agree`] to perform
/// the Diffie-Hellman step.  `agree` consumes `self`; the underlying
/// `EphemeralSecret` zeroizes the scalar on drop.
pub struct X25519Key {
    secret: x25519_dalek::EphemeralSecret,
    public: x25519_dalek::PublicKey,
}

impl X25519Key {
    pub fn generate() -> Self {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(crate::Rng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Perform ECDH with `their_public` bytes, consuming `self`.
    ///
    /// Returns `Err` when `their_public` is a low-order (non-contributory) point.
    pub fn agree(self, their_public: [u8; 32]) -> Result<[u8; 32], X25519Error> {
        let their_pk = x25519_dalek::PublicKey::from(their_public);
        let shared = self.secret.diffie_hellman(&their_pk);
        if shared.was_contributory() {
            Ok(shared.to_bytes())
        } else {
            Err(X25519Error)
        }
    }
}

/// Returned when the peer supplies a low-order (non-contributory) public key.
#[derive(Debug)]
pub struct X25519Error;

impl core::fmt::Display for X25519Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519 noncontributory public key")
    }
}
