//! cSHAKE256 and KMAC256 targeting post-quantum security.
//!
//! # Post-quantum security rationale
//!
//! The classical `crypto-prf` crate uses BLAKE3, which produces 256-bit output. Under
//! Grover's quantum search algorithm, a brute-force preimage attack on an n-bit hash
//! drops from O(2^n) to O(2^(n/2)) quantum operations, halving the effective security
//! level. A 256-bit digest therefore provides only ~128 bits of post-quantum preimage
//! resistance — acceptable today, but below the 256-bit target required for long-lived
//! or high-assurance systems.
//!
//! cSHAKE256 addresses this in two ways:
//!
//!   1. **512-bit output (64 bytes).** Grover halves the exponent, so a 512-bit output
//!      retains ~256 bits of post-quantum preimage resistance — matching AES-256's
//!      quantum security level and the NIST PQC security category 5 target. Note that
//!      Grover's amplitude amplification is inherently sequential and does not parallelise
//!      efficiently: k quantum processors yield only a √k speedup rather than k, making
//!      the practical attack cost far higher than the theoretical exponent alone suggests.
//!
//!   2. **NIST-standardized sponge construction.** SHAKE256 is defined in FIPS 202 and
//!      uses a 1600-bit Keccak-p\[1600,24\] permutation with a 512-bit capacity. The large
//!      capacity means a quantum collision search (BHT algorithm) still requires
//!      O(2^(capacity/3)) ≈ O(2^170) operations, well above the 128-bit quantum
//!      collision-resistance floor. BHT additionally assumes quantum random-access memory
//!      (QRAM) storing O(2^(capacity/3)) quantum states — an unsolved engineering problem
//!      that makes the full attack purely theoretical at this capacity.
//!
//! BLAKE3, by contrast, is built on a Merkle tree of BLAKE2 compression functions
//! optimised for software throughput; it was not designed with a formal post-quantum
//! security analysis and has received less scrutiny in that context than the SHA-3 family.
//!
//! # Keccak, SHA-3, SHAKE, cSHAKE, and KMAC
//!
//! These five names refer to a single family, each layer building on the one below.
//!
//! ## Keccak
//!
//! Keccak is the underlying **permutation**: Keccak-p\[1600,24\] operates on a
//! 1600-bit state and applies 24 rounds of a fixed bijective transformation. It
//! won the NIST hash-function competition in 2012 and is the only primitive this
//! entire family trusts. Everything above it — SHA-3, SHAKE, cSHAKE, KMAC — is
//! just framing around the same permutation.
//!
//! ## SHA-3
//!
//! SHA-3 (FIPS 202, 2015) is the **fixed-length hash** standardisation of Keccak.
//! It pads the message, absorbs it into the sponge, and squeezes out exactly
//! 224, 256, 384, or 512 bits. SHA-3-256 and SHA-3-512 are the drop-in
//! replacements for SHA-256 and SHA-512. The "256" in SHA-3-256 is the output
//! length. Internally, SHA-3-256 uses a 512-bit capacity (2 × output length),
//! and appends a domain-separation byte (0x06) before padding.
//!
//! ## SHAKE
//!
//! SHAKE (also FIPS 202) replaces the fixed output with an **extendable output
//! function (XOF)**: after absorbing the message you can squeeze out as many
//! bytes as you need. SHAKE128 and SHAKE256 differ only in capacity:
//!
//! | Variant  | Capacity | Security level | Domain byte |
//! |----------|----------|----------------|-------------|
//! | SHAKE128 | 256 bits | 128 bits       | 0x1f        |
//! | SHAKE256 | 512 bits | 256 bits       | 0x1f        |
//!
//! The "256" in SHAKE256 is the **security level**, not the output length — you
//! choose the output length at call time. SHAKE256 with 64-byte output is what
//! this module uses for its [`DIGEST_LEN`] default.
//!
//! SHA-3 and SHAKE are distinct: they use different domain bytes (0x06 vs 0x1f),
//! so SHA-3-256(x) ≠ SHAKE256(x)\[0..32\] even though both use the same
//! permutation and the same capacity.
//!
//! ## cSHAKE
//!
//! cSHAKE (NIST SP 800-185, 2016) adds **customization** to SHAKE via two
//! additional string parameters absorbed before the message:
//!
//! - **N** (function name): a string reserved for NIST-defined algorithms.
//!   User code always passes `""`.
//! - **S** (customization string): an arbitrary application-defined string.
//!   Two cSHAKE calls with different S values produce completely independent
//!   output spaces, even with the same key and message.
//!
//! When both N and S are empty, cSHAKE falls back to plain SHAKE (same output),
//! so cSHAKE is a strict superset. The `CShake256::digest(customization)` and
//! `CShake256::shake256()` constructors below expose this distinction.
//!
//! ## KMAC
//!
//! KMAC (also SP 800-185) is the **keyed** layer: it sets N=`"KMAC"` (domain-
//! separating it from all cSHAKE uses), then absorbs a key block encoded via
//! `bytepad(encode_string(key), rate)` before the message, and appends
//! `right_encode(output_length_bits)` at finalization. The result is a
//! NIST-approved MAC, PRF, and KDF in one construction.
//!
//! The full hierarchy:
//!
//! ```text
//! Keccak-p[1600,24]          (permutation, FIPS 202)
//!  └── SHA-3-{224,256,384,512}   fixed-length hash, domain 0x06
//!  └── SHAKE{128,256}            XOF, domain 0x1f
//!       └── cSHAKE{128,256}      + N/S customization strings  (SP 800-185)
//!            └── KMAC{128,256}   + key block + length suffix   (SP 800-185)
//! ```

use cshake::CShake256 as Inner;
use cshake::digest::ExtendableOutput;
use cshake::digest::Update as _;
use cshake::digest::XofReader;

// ── XOF streaming reader ─────────────────────────────────────────────────────

/// A streaming reader over the XOF output of a finalized [`CShake256`] instance.
///
/// Created by [`CShake256::finalize_reader`]. Produces an unbounded byte stream.
/// In KMAC mode the SP 800-185 `right_encode(0)` suffix is already applied,
/// selecting KMACXOF256 semantics — output that differs from the fixed-length
/// [`CShake256::finalize_xof_into`] path (which appends `right_encode(L)`).
pub struct Reader {
    inner: <Inner as ExtendableOutput>::Reader,
}

impl Reader {
    /// Fills `buf` with the next bytes of XOF output.
    ///
    /// The XOF is unbounded; this never fails or short-reads.
    pub fn read(&mut self, buf: &mut [u8]) {
        XofReader::read(&mut self.inner, buf);
    }
}

#[cfg(feature = "std")]
impl std::io::Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read(buf);
        Ok(buf.len())
    }
}

/// Default output length: 64 bytes (512 bits) for 256-bit post-quantum preimage resistance.
pub const DIGEST_LEN: usize = 64;

// ── SP 800-185 §2.3 encoding primitives ─────────────────────────────────────

/// Stack-allocated buffer for an SP 800-185 encoded integer (at most 9 bytes).
struct Encoded {
    buf: [u8; 9],
    len: usize,
}

impl AsRef<[u8]> for Encoded {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Encoded {
    /// SP 800-185 left_encode: [n, b_{n-1}, …, b_0].
    fn left_encode(x: usize) -> Self {
        let be = x.to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let n = be.len() - first;
        let mut buf = [0u8; 9];
        buf[0] = n as u8;
        buf[1..=n].copy_from_slice(&be[first..]);
        Self { buf, len: n + 1 }
    }

    /// SP 800-185 right_encode: [b_{n-1}, …, b_0, n].
    fn right_encode(x: usize) -> Self {
        let be = x.to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let n = be.len() - first;
        let mut buf = [0u8; 9];
        buf[..n].copy_from_slice(&be[first..]);
        buf[n] = n as u8;
        Self { buf, len: n + 1 }
    }
}

// ── cSHAKE256 ───────────────────────────────────────────────────────────────

pub struct CShake256 {
    inner: Inner,
    /// Snapshot of `inner` taken right after all prefix material was absorbed
    /// (N/S for cSHAKE; N/S + key block for KMAC). `reset()` clones this
    /// back into `inner`, avoiding re-encoding of the prefix.
    initial: Inner,
    /// When true, `right_encode(out_len_bits)` is appended inside `finalize_xof_into`
    /// on a clone before squeezing, implementing the KMAC256 suffix per SP 800-185.
    is_kmac: bool,
}

impl CShake256 {
    const KMAC_FN_NAME: &[u8] = b"KMAC";
    const DIGEST_FN_NAME: &[u8] = b"";
    const NO_CUSTOMIZATION: &[u8] = b"";

    fn new(function_name: &[u8], customization: &[u8]) -> Self {
        let inner = Inner::new_with_function_name(function_name, customization);
        Self { initial: inner.clone(), inner, is_kmac: false }
    }

    /// Creates a plain SHAKE256 instance with no domain separation.
    ///
    /// **Discouraged.** Without a customization string, different uses of this
    /// hash in the same application share an output space, making it trivial to
    /// confuse outputs across contexts. Prefer [`digest`][Self::digest] with a
    /// hardcoded, application-specific customization string instead.
    pub fn shake256() -> Self {
        Self::new(Self::DIGEST_FN_NAME, Self::NO_CUSTOMIZATION)
    }

    /// Creates a domain-separated cSHAKE256 instance (N=`""`, S=`customization`).
    ///
    /// Use `customization` to distinguish independent hash uses within the same
    /// application. When `customization` is empty the output is identical to SHAKE256.
    pub fn digest(customization: &[u8]) -> Self {
        Self::new(Self::DIGEST_FN_NAME, customization)
    }

    /// Creates a KMAC256 instance (SP 800-185 §4).
    ///
    /// Initialises cSHAKE256 with N=`"KMAC"` and S=`customization`, then absorbs
    /// `bytepad(encode_string(key), 136)`. Subsequent [`update`][Self::update] calls
    /// feed the message X. Finalization automatically appends `right_encode(L)` where
    /// L is the requested output length in bits.
    pub fn hmac(key: &[u8], customization: &[u8]) -> Self {
        const RATE: usize = 136;

        let mut inner = Inner::new_with_function_name(Self::KMAC_FN_NAME, customization);

        let rate_enc = Encoded::left_encode(RATE);
        inner.update(rate_enc.as_ref());

        let key_bits = Encoded::left_encode(key.len() * 8);
        inner.update(key_bits.as_ref());
        inner.update(key);

        let total = rate_enc.len + key_bits.len + key.len();
        let pad = (RATE - (total % RATE)) % RATE;
        if pad > 0 {
            inner.update(&[0u8; RATE][..pad]);
        }
        Self { initial: inner.clone(), inner, is_kmac: true }
    }

    /// Creates a KMAC256-based KDF instance (NIST SP 800-185 §4 / SP 800-108r1 §4.1).
    ///
    /// KMAC256 is a NIST-approved KDF construction: its cSHAKE256 core provides
    /// domain separation via N=`"KMAC"`, while the keyed sponge ensures that an
    /// attacker who knows the output cannot recover the key or predict outputs
    /// under a different key or customization string.
    ///
    /// Usage pattern:
    /// ```ignore
    /// // Derive a 32-byte subkey, domain-separated by purpose.
    /// let mut kdf = CShake256::kdf(master_key, b"myapp v1 enc key");
    /// kdf.update(context_or_label); // optional: bind to additional context
    /// let subkey: [u8; 32] = kdf.finalize_xof();
    /// ```
    ///
    /// - `key_material`: the secret from which subkeys are derived.
    /// - `customization`: a hardcoded, globally unique, application-specific
    ///   string that domain-separates this derivation from all others.
    pub fn kdf(key_material: &[u8], customization: &[u8]) -> Self {
        Self::hmac(key_material, customization)
    }

    /// Feeds `data` into the absorb phase.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.inner.update(data.as_ref());
    }

    /// Feeds the contents of `reader` into the absorb phase.
    #[cfg(feature = "std")]
    pub fn update_read<R: std::io::Read>(
        &mut self,
        reader: &mut std::io::BufReader<R>,
    ) -> std::io::Result<()> {
        use std::io::Read as _;
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.update(&buf[..n]);
        }
        Ok(())
    }

    /// Returns [`DIGEST_LEN`] bytes of output.
    pub fn finalize(&mut self) -> [u8; DIGEST_LEN] {
        let mut out = [0u8; DIGEST_LEN];
        self.finalize_xof_into(&mut out);
        out
    }

    /// Returns `N` bytes of output.
    pub fn finalize_xof<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.finalize_xof_into(&mut out);
        out
    }

    /// Fills `out` with output.
    ///
    /// In KMAC mode (constructed via [`hmac`][Self::hmac]), appends
    /// `right_encode(out.len() * 8)` per SP 800-185 before squeezing.
    pub fn finalize_xof_into(&mut self, out: &mut [u8]) {
        let mut squeeze = self.inner.clone();
        if self.is_kmac {
            squeeze.update(Encoded::right_encode(out.len() * 8).as_ref());
        }
        let mut reader = squeeze.finalize_xof();
        reader.read(out);
    }

    /// Returns a streaming [`Reader`] that produces an unbounded XOF output.
    ///
    /// Unlike [`finalize_xof_into`][Self::finalize_xof_into], the output length does
    /// not need to be known at call time: pull as many bytes as needed via repeated
    /// [`Reader::read`] calls.
    ///
    /// In KMAC mode, `right_encode(0)` is appended before squeezing (KMACXOF256
    /// per SP 800-185 §4.3.1), which produces output distinct from
    /// [`finalize_xof_into`][Self::finalize_xof_into] for any non-zero length.
    pub fn finalize_reader(&mut self) -> Reader {
        let mut squeeze = self.inner.clone();
        if self.is_kmac {
            squeeze.update(Encoded::right_encode(0).as_ref());
        }
        Reader { inner: squeeze.finalize_xof() }
    }

    /// Resets to the post-prefix state (after N/S or after key block for KMAC),
    /// discarding all absorbed message data.
    pub fn reset(&mut self) {
        self.inner = self.initial.clone();
    }
}

// ── One-shot helpers ─────────────────────────────────────────────────────────

/// SHAKE256(`input`), producing [`DIGEST_LEN`] bytes.
///
/// **Discouraged.** Prefer [`digest`] with a hardcoded customization string to
/// ensure domain separation between independent hash uses in the same application.
pub fn shake256(input: impl AsRef<[u8]>) -> [u8; DIGEST_LEN] {
    let mut h = CShake256::shake256();
    h.update(input);
    h.finalize()
}

/// cSHAKE256(`customization`, `input`), producing [`DIGEST_LEN`] bytes.
pub fn digest(customization: &[u8], input: impl AsRef<[u8]>) -> [u8; DIGEST_LEN] {
    let mut h = CShake256::digest(customization);
    h.update(input);
    h.finalize()
}

/// KMAC256(`key`, `customization`, `input`), producing [`DIGEST_LEN`] bytes.
pub fn hmac(key: &[u8], customization: &[u8], input: impl AsRef<[u8]>) -> [u8; DIGEST_LEN] {
    let mut h = CShake256::hmac(key, customization);
    h.update(input);
    h.finalize()
}

/// KMAC256-based KDF(`key_material`, `customization`), producing `N` bytes.
pub fn kdf<const N: usize>(key_material: &[u8], customization: &[u8]) -> [u8; N] {
    let mut h = CShake256::kdf(key_material, customization);
    h.finalize_xof()
}
