# AEGIS.md — Plan for `pqc::symmetric::aegis`

## Motivation

- **Speed for large data** — AEGIS-256X2 is significantly faster than ChaCha20-Poly1305 on
  hardware with AES instructions (AES-NI on x86-64, Crypto Extensions on ARM), often by 3–5×
  for bulk data. However, AEGIS pays an upfront key-schedule cost on every `new(key, nonce)`
  call; for many small independent messages each under a different nonce, ChaCha20-Poly1305
  may be faster because its per-message initialisation is cheaper.  Prefer AEGIS when
  encrypting large payloads per cipher instance; prefer ChaCha20-Poly1305 for high-frequency
  small-message patterns.
- **256-bit nonce** — with a 256-bit nonce the birthday bound for collision is 2^128 messages,
  making randomly-generated nonces practical; the caller supplies the nonce.
- **256-bit tag** — ~128-bit PQ forgery resistance, matching the crate's security level.
- **IETF standard** — RFC 9663 (October 2024).

## Variant

**AEGIS-256X2 with 256-bit (32-byte) tag.**

| Property      | Value               |
|---------------|---------------------|
| Key           | 256 bits (32 bytes) |
| Nonce         | 256 bits (32 bytes) |
| Tag           | 256 bits (32 bytes) |
| `TAG_LEN`     | 32                  |
| `NONCE_LEN`   | 32                  |

AEGIS-256X2 runs two AEGIS-256 instances in parallel, doubling throughput on CPUs that can
issue multiple AES instructions per cycle (which is most modern x86-64 and ARM cores).
Key, nonce, and tag sizes are identical to AEGIS-256; the security level is the same.

AEGIS-128L and plain AEGIS-256 are excluded — AEGIS-128L does not meet the NIST Level 5
key-size floor; AEGIS-256 is strictly dominated by AEGIS-256X2 on supported hardware.

## Dependency

```toml
aegis = { version = "*", default-features = false }
```

`no_std`-compatible with `default-features = false`. Accelerates via AES-NI (x86/x86_64) and
ARMv8 Crypto Extensions. Confirm at implementation time whether a software fallback exists for
targets without those extensions, and whether the resolved version conflicts with the
`chacha20poly1305` dependency's `aead`/`crypto-common` versions.


## Module Layout

```
src/symmetric/
├── mod.rs              ← add `pub mod aegis;`
├── chacha20poly1305.rs ← unchanged
└── aegis.rs            ← new
```

## Key Insight: Nonce in the Constructor, Consuming Operations

`Aegis256X2::new` requires both the key and the nonce to initialise its state — you cannot
construct the cipher from the key alone.  `AegisCipher::new` therefore takes both, calls the
underlying constructor, and stores the resulting `Aegis256X2<U32>`.  Neither the raw key nor
the raw nonce is retained in the struct after `new` returns.

Because the nonce is baked into the cipher state at construction, `seal`, `open`,
`stream_encryptor`, and `stream_decryptor` do not take a nonce parameter.  All four methods
consume `self`, making it structurally difficult to reuse a `(key, nonce)` pair across two
different operations: once the cipher is used it is gone.

For the stream types, if the `aegis` crate exposes an incremental state type, store only that
(the underlying `Aegis256X2<U32>` is also not retained after the stream is started).  If it
only exposes the `AeadInPlace` trait, store a clone of `Aegis256X2<U32>` and reinitialize
per-call — the design intent is preserved even if the key material technically persists inside
the clone.

## Public API

```rust
pub const TAG_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;

// ── Single-use cipher ─────────────────────────────────────────────────────

/// AEGIS-256X2 cipher bound to a single `(key, nonce)` pair.
///
/// `new` runs the AEGIS key schedule, absorbing both key and nonce into the
/// internal state; neither is stored as raw bytes in this struct.
/// All operations consume `self`, making it a compile-time error to reuse the
/// same `(key, nonce)` pair across two different seal or open calls.
///
/// # When to prefer this over `ChaCha20Poly1305Cipher`
///
/// AEGIS-256X2 is significantly faster for large payloads on hardware with
/// AES instructions (AES-NI / ARMv8 Crypto), often 3–5× faster than
/// ChaCha20-Poly1305 for bulk data.  However, each `new` call re-runs the
/// key schedule.  For high-frequency small messages — each under a freshly
/// constructed cipher — ChaCha20-Poly1305's lighter per-message initialisation
/// makes it faster.  Use AEGIS when the payload per cipher instance is large;
/// use ChaCha20-Poly1305 for many small independent messages.
pub struct AegisCipher(Aegis256X2<U32>);  // ZeroizeOnDrop via the inner type

impl AegisCipher {
    /// Initialises the cipher from `key` and `nonce`.
    ///
    /// The key schedule runs here; neither the raw key nor the raw nonce is
    /// stored in the returned struct.
    pub fn new(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Self;

    /// Encrypts `buf` in place.  Consumes `self` to prevent nonce reuse.
    ///
    /// `buf` layout on entry: `[plaintext (n B) | zeroed tag space (TAG_LEN B)]`
    /// `buf` layout on exit:  `[ciphertext (n B) | tag (TAG_LEN B)]`
    ///
    /// `buf.len()` must be at least `TAG_LEN`; plaintext occupies `buf.len() - TAG_LEN` bytes.
    pub fn seal(self, aad: &[u8], buf: &mut [u8]) -> Result<(), Error>;

    /// Decrypts and verifies `buf` in place.  Consumes `self` to prevent nonce reuse.
    ///
    /// `buf` layout on entry: `[ciphertext (n B) | tag (TAG_LEN B)]`
    /// On success, `buf[..n]` holds the plaintext; returns `n`.
    /// Returns `TooShort` if `buf.len() < TAG_LEN`, `AuthenticationFailed` if the tag is wrong.
    /// Plaintext is never written before the tag passes.
    pub fn open(self, aad: &[u8], buf: &mut [u8]) -> Result<usize, Error>;

    /// Converts this cipher into a streaming encryptor.  Consumes `self`.
    ///
    /// The nonce is already baked into the cipher state; the receiver must
    /// construct their `AegisCipher` with the matching `(key, nonce)` and call
    /// `stream_decryptor`.
    pub fn stream_encryptor(self) -> AegisEncryptor;

    /// Converts this cipher into a streaming decryptor.  Consumes `self`.
    pub fn stream_decryptor(self) -> AegisDecryptor;

    // ── std-only I/O helpers ──────────────────────────────────────────────

    /// Reads plaintext from `reader`, encrypts it, and writes `ciphertext || tag` to `writer`.
    ///
    /// The nonce is already held in `self`; it is the caller's responsibility to
    /// transmit it to the receiver out-of-band so they can construct a matching
    /// `AegisCipher` for `decrypt_stream`.  Data is processed in 64 KiB chunks
    /// using `AegisEncryptor` internally; the 32-byte tag is written last.
    ///
    /// On `IoError`, partial output may have been written to `writer` and must be
    /// discarded by the caller.
    #[cfg(feature = "std")]
    pub fn encrypt_stream(
        self,
        aad: &[u8],
        reader: impl std::io::Read,
        writer: impl std::io::Write,
    ) -> Result<(), Error>;

    /// Reads `ciphertext || tag` from `reader`, decrypts, and writes plaintext to `writer`.
    ///
    /// The nonce is already held in `self`; the caller must construct this cipher
    /// with the same `(key, nonce)` used by `encrypt_stream`.
    ///
    /// Because the tag sits at the end of the stream, the full ciphertext is buffered
    /// in memory before the tag is verified; plaintext is only written to `writer` after
    /// verification succeeds.  For streams where buffering the full plaintext is
    /// impractical, use `stream_decryptor` directly and accept responsibility for
    /// discarding output on `verify` failure.
    ///
    /// Returns `TooShort` if the input is shorter than `TAG_LEN`.
    #[cfg(feature = "std")]
    pub fn decrypt_stream(
        self,
        aad: &[u8],
        reader: impl std::io::Read,
        writer: impl std::io::Write,
    ) -> Result<(), Error>;
}

// ── Streaming types ───────────────────────────────────────────────────────

/// Encrypts a stream of arbitrary length.  Produced by `AegisCipher::stream_encryptor`.
///
/// Yields a single 32-byte authentication tag on `finalize` covering the entire stream.
pub struct AegisEncryptor(/* AEGIS incremental encrypt state */);

impl AegisEncryptor {
    /// Encrypts `buf` in place.  May be called any number of times.
    pub fn encrypt(&mut self, buf: &mut [u8]);

    /// Finalizes the stream and writes the 32-byte tag to `tag_out`.
    pub fn finalize(self, tag_out: &mut [u8; TAG_LEN]);
}

/// Decrypts a stream produced by `AegisEncryptor`.  Produced by `AegisCipher::stream_decryptor`.
///
/// The single tag covers the entire stream; call `verify` only after all chunks are decrypted.
///
/// ⚠ If `verify` fails, all output from `decrypt` calls must be discarded — it is unauthenticated.
pub struct AegisDecryptor(/* AEGIS incremental decrypt state */);

impl AegisDecryptor {
    /// Decrypts `buf` in place.  May be called any number of times.
    pub fn decrypt(&mut self, buf: &mut [u8]);

    /// Verifies the authentication tag.  Returns `AuthenticationFailed` if the tag is wrong.
    pub fn verify(self, tag: &[u8; TAG_LEN]) -> Result<(), Error>;
}

// ── Error ─────────────────────────────────────────────────────────────────

pub enum Error {
    /// `buf` passed to `open`, or input to `decrypt_stream`, is shorter than `TAG_LEN`.
    TooShort,
    /// Tag verification failed.
    AuthenticationFailed,
    /// I/O error from `encrypt_stream` or `decrypt_stream` (std-only).
    #[cfg(feature = "std")]
    IoError(std::io::Error),
}
```

## Implementation Steps

1. **Add the dependency** — add `aegis = { version = "*", default-features = false }` to
   `Cargo.toml`; resolve any `aead`/`crypto-common` version conflicts with `chacha20poly1305`.

2. **Create `src/symmetric/aegis.rs`**:
   - Define `TAG_LEN = 32`, `NONCE_LEN = 32`.
   - `AegisCipher(Aegis256X2<U32>)`: `new(key, nonce)` calls
     `Aegis256X2::new(Key::from_slice(key), Nonce::from_slice(nonce))`; both raw slices expire
     at end of `new`, leaving only the initialised `Aegis256X2<U32>` in the struct.
   - `seal(self, ...)`: call `encrypt_in_place_detached(/* no nonce arg — already in state */,
     aad, &mut buf[..n])` → write the returned tag into `buf[n..]`.
   - `open(self, ...)`: split `buf` at `len - TAG_LEN` →
     `decrypt_in_place_detached(aad, ct, tag)`. Confirm the crate verifies before writing
     plaintext.
   - `stream_encryptor(self)`: consume `self` → extract the incremental state from
     `Aegis256X2<U32>` if the crate exposes one; otherwise hold the cipher for per-call reuse.
     Return `AegisEncryptor` (infallible).
   - `stream_decryptor(self)`: mirror of the above.
   - `AegisEncryptor::encrypt`: feed `buf` into the incremental state.
   - `AegisEncryptor::finalize`: call the state's finalization to produce the tag.
   - `AegisDecryptor::decrypt` / `verify`: mirror the encryptor path.
   - `Error`: derive `thiserror::Error` behind `#[cfg_attr(feature = "std", ...)]`; add
     `#[cfg(feature = "std")] IoError(std::io::Error)` variant.
   - `encrypt_stream(self, ...)` (`#[cfg(feature = "std")]`): call `self.stream_encryptor()` →
     loop: `reader.read(&mut chunk)`, break on EOF, call `encrypt(&mut chunk[..n])`, write
     `chunk[..n]` to `writer` → call `finalize` and write the 32-byte tag to `writer`.  Use a
     fixed 65536-byte stack buffer; no heap allocation needed.  The nonce is not written to
     `writer` — it is the caller's responsibility to transmit it out-of-band.
   - `decrypt_stream(self, ...)` (`#[cfg(feature = "std")]`): call `self.stream_decryptor()` →
     read all ciphertext into a `Vec<u8>` (required because the tag is the last `TAG_LEN` bytes
     and cannot be identified without buffering the full input) → split at `len - TAG_LEN` →
     call `decrypt` on the ciphertext portion → call `verify` on the tag → only if `verify`
     succeeds, write the plaintext to `writer`.

3. **Register the module** — add `pub mod aegis;` to `src/symmetric/mod.rs`.

4. **Write `tests/aegis.rs`**:
   - **Known-answer tests** — RFC 9663 Appendix A provides AEGIS-256X2 / 256-bit-tag vectors.
     Call `aegis::aegis256x2::Aegis256X2::<U32>::encrypt_in_place_detached` directly with the
     fixed test nonce from the RFC to pin against the standard.
   - **Round-trip tests** — `seal`/`open` with non-empty AAD, empty AAD, empty plaintext, and
     a plaintext large enough to span multiple AEGIS blocks.
   - **Stream round-trip** — write several `encrypt` chunks, call `finalize`, then mirror with
     `decrypt` + `verify`; assert the recovered plaintext matches.
   - **`verify` failure discards data** — tamper the tag before `verify`; assert `Err`.
   - **Authentication failure tests** — wrong key, tampered ciphertext byte, tampered tag byte,
     wrong AAD, wrong nonce.
   - **`TooShort` test** — `open` with `buf.len() < TAG_LEN`.
   - **`encrypt_stream` / `decrypt_stream` round-trip** — construct two `AegisCipher` instances
     from the same `(key, nonce)` pair; encrypt a multi-megabyte `Cursor` of random bytes into a
     second `Cursor` via `encrypt_stream`, then decrypt back via `decrypt_stream` and assert the
     plaintext matches.  Also test with empty plaintext and a plaintext smaller than one chunk.
   - **`decrypt_stream` authentication failure** — tamper one byte of the ciphertext `Cursor`
     before decrypting; assert `AuthenticationFailed` and that nothing was written to the output
     `Cursor`.
   - **`decrypt_stream` too-short input** — pass a `Cursor` shorter than `TAG_LEN`;
     assert `TooShort`.

## Trade-offs

The streaming types use a **single tag for the entire stream**, produced at finalization.  This
means the receiver cannot authenticate any individual chunk — only the complete stream.  If the
receiver must process data before the full stream arrives, it must buffer until `verify` succeeds
or accept the risk of acting on unauthenticated data.

The alternative (per-chunk independent sealing, each chunk with its own random nonce and tag) was
considered but rejected because it requires retaining the key for the lifetime of the stream and
does not exploit AEGIS's natural incremental interface.  If per-chunk authentication is needed,
call `AegisCipher::seal` / `open` directly on each chunk.
