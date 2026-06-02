use winternitz::PRIVKEY_SIZE;
use winternitz::PUBKEY_SIZE;
use winternitz::SIG_SIZE;

/// A Winternitz OTS public key (32 bytes).
pub struct WinternitzPublicKey([u8; PUBKEY_SIZE]);

/// A Winternitz OTS secret key (2,144 bytes of private entropy).
///
/// **Warning:** Each secret key must only be used to sign a **single** message.
/// Signing multiple messages with the same key leaks the key.
pub struct WinternitzSecretKey([u8; PRIVKEY_SIZE]);

/// A Winternitz OTS signature (1,340 bytes).
pub struct WinternitzSignature([u8; SIG_SIZE]);

impl AsRef<[u8]> for WinternitzPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for WinternitzSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for WinternitzSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Errors returned by Winternitz OTS operations.
#[derive(Debug)]
pub enum WinternitzError {
    /// The OS random number generator failed during key generation.
    Rng,
    /// Signature verification failed — the signature does not match the message or public key.
    BadSignature,
}

impl core::fmt::Display for WinternitzError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rng => write!(f, "key generation failed: OS RNG unavailable"),
            Self::BadSignature => write!(f, "signature verification failed"),
        }
    }
}

impl core::error::Error for WinternitzError {}

type Result<T> = core::result::Result<T, WinternitzError>;

/// Winternitz one-time signature scheme (`LDWM_SHA256_M20_W8`).
///
/// This is a hash-based one-time signature (OTS) scheme whose security rests
/// entirely on the preimage resistance of SHA-256. It predates and is distinct
/// from the NIST post-quantum process, but shares the same conservative
/// hash-only security assumption as [`crate::sig::Sphincs`].
///
/// # Sizes
///
/// | Object     | Bytes |
/// |------------|-------|
/// | Public key |    32 |
/// | Secret key | 2,144 |
/// | Signature  | 1,340 |
///
/// # One-time property
///
/// **Each key pair must only be used to sign a single message.** Signing two
/// different messages with the same secret key reveals enough key material for
/// an attacker to forge arbitrary signatures. Generate a fresh key pair for
/// every message.
///
///
/// # Pros
///
/// - Security relies solely on the preimage resistance of SHA-256 — no
///   algebraic assumptions of any kind.
/// - Tiny public key (32 B) and small signature (~1.3 KB) relative to
///   [`crate::sig::Sphincs`].
/// - It is **substantially faster** than any of the other PQC digital signature schemes.
///
/// # Cons
///
/// - **One-time only.** Reusing a key pair is catastrophic.
/// - Not standardised by NIST; prefer [`crate::sig::Sphincs`] for
///   production use where key reuse is a risk.
/// Generate a fresh Winternitz key pair.
///
/// The secret key is filled with cryptographically random bytes from the OS.
/// Generate a new key pair for every message you intend to sign.
pub fn keypair() -> Result<(WinternitzPublicKey, WinternitzSecretKey)> {
    let mut sk = [0u8; PRIVKEY_SIZE];
    getrandom::fill(&mut sk).map_err(|_| WinternitzError::Rng)?;

    let mut pk = [0u8; PUBKEY_SIZE];
    winternitz::derive_pubkey(&sk, &mut pk).expect("buffer sizes match crate constants");

    Ok((WinternitzPublicKey(pk), WinternitzSecretKey(sk)))
}

/// Sign `message` with `secret_key`.
///
/// **Do not reuse `secret_key` to sign any other message.**
pub fn sign(
    message: impl AsRef<[u8]>,
    secret_key: &WinternitzSecretKey,
) -> Result<WinternitzSignature> {
    let mut sig = [0u8; SIG_SIZE];
    winternitz::sign(&secret_key.0, message.as_ref(), &mut sig)
        .expect("buffer sizes match crate constants");
    Ok(WinternitzSignature(sig))
}

/// Verify that `signature` is a valid signature of `message` under `public_key`.
pub fn verify(
    message: impl AsRef<[u8]>,
    signature: &WinternitzSignature,
    public_key: &WinternitzPublicKey,
) -> Result<()> {
    let valid = winternitz::verify(&public_key.0, message.as_ref(), &signature.0)
        .expect("buffer sizes match crate constants");
    if valid { Ok(()) } else { Err(WinternitzError::BadSignature) }
}
