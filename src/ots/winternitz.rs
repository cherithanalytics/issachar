use zeroize::ZeroizeOnDrop;

use crate::prf::cshake256::CShake256;

// LDWM-cSHAKE256-M20-W4 parameters (adapted from draft-mcgrew-hash-sigs-02 §3.2 / §3.3).
// SHA-256 is replaced by cSHAKE256 with domain-separated customization strings,
// retaining the same key and signature sizes.
const M: usize = 20; // truncated chain-element size in bytes
const N: usize = 32; // hash output bytes used for key material
const W: usize = 4; // bits per coefficient (Winternitz parameter)
const P: usize = 67; // chain elements per key / signature
const LS: usize = 4; // checksum left-shift

const CHAIN_LABEL: &[u8] = b"issachar/ots/winternitz/chain";
const MSG_LABEL: &[u8] = b"issachar/ots/winternitz/msg";
const PUBKEY_LABEL: &[u8] = b"issachar/ots/winternitz/pubkey";

/// Size in bytes of a Winternitz public key.
pub const PUBKEY_SIZE: usize = N;
/// Size in bytes of a Winternitz secret key.
pub const PRIVKEY_SIZE: usize = P * N;
/// Size in bytes of a Winternitz signature.
pub const SIG_SIZE: usize = P * M;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A Winternitz OTS public key (32 bytes).
pub struct WinternitzPublicKey([u8; PUBKEY_SIZE]);

/// A Winternitz OTS secret key (2,144 bytes of private entropy).
///
/// **Warning:** Each secret key must only be used to sign a **single** message.
/// Signing multiple messages with the same key leaks the key.
#[derive(ZeroizeOnDrop)]
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

// ── Errors ────────────────────────────────────────────────────────────────────

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

// ── Algorithm internals ───────────────────────────────────────────────────────

// With W=4 there are 2 nibbles per byte: high nibble at even index, low at odd.
#[inline]
fn coef(data: &[u8], i: usize) -> u8 {
    if i & 1 == 0 { data[i >> 1] >> 4 } else { data[i >> 1] & 0xf }
}

// Builds V = H(msg) || checksum(H(msg)) as described in §3.5 / §3.6.
fn v_array(msg: &[u8]) -> [u8; N + 2] {
    let mut h_inst = CShake256::digest(MSG_LABEL);
    h_inst.update(msg);
    let h: [u8; N] = h_inst.finalize_xof();

    let sum: u16 = (0..8 * N / W).map(|i| ((1u16 << W) - 1) - coef(&h, i) as u16).sum();
    let checksum = sum << LS;

    let mut v = [0u8; N + 2];
    v[..N].copy_from_slice(&h);
    v[N..].copy_from_slice(&checksum.to_be_bytes());
    v
}

// Apply the chain hash function `steps` times, returning M-byte output.
fn chain(mut x: [u8; M], steps: u8) -> [u8; M] {
    for _ in 0..steps {
        let mut h = CShake256::digest(CHAIN_LABEL);
        h.update(&x);
        let out: [u8; N] = h.finalize_xof();
        x.copy_from_slice(&out[..M]);
    }
    x
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Winternitz one-time signature scheme (LDWM-cSHAKE256-M20-W4).
///
/// This is a hash-based one-time signature (OTS) scheme whose security rests
/// entirely on the preimage resistance of cSHAKE256. It predates and is distinct
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
/// # Pros
///
/// - Security relies solely on the preimage resistance of cSHAKE256 — no
///   algebraic assumptions of any kind.
/// - Tiny public key (32 B) and small signature (~1.3 KB) relative to
///   [`crate::sig::Sphincs`].
/// - Substantially faster than any of the other PQC digital signature schemes.
/// - Domain-separated via cSHAKE256 customization strings.
///
/// # Cons
///
/// - **One-time only.** Reusing a key pair is catastrophic.
/// - Not standardised by NIST; prefer [`crate::sig::Sphincs`] for
///   production use where key reuse is a risk.
pub struct Winternitz;

/// Generate a fresh Winternitz key pair.
///
/// The secret key is filled with cryptographically random bytes from the OS.
/// Generate a new key pair for every message you intend to sign.
pub fn keypair() -> Result<(WinternitzPublicKey, WinternitzSecretKey)> {
    let mut sk_bytes = [0u8; PRIVKEY_SIZE];
    getrandom::fill(&mut sk_bytes).map_err(|_| WinternitzError::Rng)?;

    let e = ((1u32 << W) - 1) as u8; // = 15
    let mut outer = CShake256::digest(PUBKEY_LABEL);
    for chunk in sk_bytes.chunks(N) {
        let mut y = [0u8; M];
        y.copy_from_slice(&chunk[..M]);
        outer.update(&chain(y, e));
    }
    let pk_bytes: [u8; N] = outer.finalize_xof();

    Ok((WinternitzPublicKey(pk_bytes), WinternitzSecretKey(sk_bytes)))
}

/// Sign `message` with `secret_key`.
///
/// **Do not reuse `secret_key` to sign any other message.**
pub fn sign(
    message: impl AsRef<[u8]>,
    secret_key: &WinternitzSecretKey,
) -> Result<WinternitzSignature> {
    let v = v_array(message.as_ref());
    let mut sig = [0u8; SIG_SIZE];
    for (i, (chunk, sig_elem)) in secret_key.0.chunks(N).zip(sig.chunks_mut(M)).enumerate() {
        let mut x = [0u8; M];
        x.copy_from_slice(&chunk[..M]);
        sig_elem.copy_from_slice(&chain(x, coef(&v, i)));
    }
    Ok(WinternitzSignature(sig))
}

/// Verify that `signature` is a valid signature of `message` under `public_key`.
pub fn verify(
    message: impl AsRef<[u8]>,
    signature: &WinternitzSignature,
    public_key: &WinternitzPublicKey,
) -> Result<()> {
    let v = v_array(message.as_ref());
    let e = ((1u32 << W) - 1) as u8; // = 15
    let mut outer = CShake256::digest(PUBKEY_LABEL);
    for (i, sig_elem) in signature.0.chunks(M).enumerate() {
        let mut x = [0u8; M];
        x.copy_from_slice(sig_elem);
        outer.update(&chain(x, e - coef(&v, i)));
    }
    let computed: [u8; N] = outer.finalize_xof();
    if computed == public_key.0 { Ok(()) } else { Err(WinternitzError::BadSignature) }
}
