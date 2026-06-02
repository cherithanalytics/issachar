# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build
cargo build --no-default-features   # no_std build

# Test
cargo test                           # all tests (lib + integration)
cargo test --lib                     # lib tests only
cargo test test_name                 # single test by name

# Generate test vectors (writes to tests/vectors/)
cargo run --bin gen_test_vectors --features gen-vectors
cargo run --bin gen_sig_test_vectors --features gen-vectors
```

## Features

| Feature | Default | Effect |
|---------|---------|--------|
| `std` | yes | Links `std`; enables `CShake256::update_read` (streaming from `BufReader`) |
| `gen-vectors` | no | Enables the `hex` dep and the two `bin` targets for generating test vectors |

## Module Structure

```
src/
├── kem/          ML-KEM-1024, Classic McEliece-8192128f, FrodoKEM-1344-AES
├── sig/          ML-DSA-87, SPHINCS+-SHA2-256f
├── ots/          Winternitz one-time signatures
├── prf/cshake256 cSHAKE256 / KMAC256 PRF suite
├── classic/      X25519 key pair (used inside Strobe transports)
├── strobe/
│   ├── mod.rs             Strobe v1.0.2 core (Keccak-f[1600])
│   ├── symmetric.rs       ChaCha20Poly1305 cipher + nonce types used by transports
│   ├── transport_nk/      Noise-NK style: responder has a known static key
│   │   ├── hybrid.rs      Classic McEliece static + X25519 ephemeral
│   │   └── pqc.rs         Classic McEliece static + ML-KEM-1024 ephemeral
│   └── transport_kk/      Noise-KK style: both parties have known static keys
│       ├── hybrid.rs
│       └── pqc.rs
└── utils.rs      Constant-time equality (subtle)
```

All algorithms are hard-fixed at NIST Level 5; there are no level-1 or level-3 variants.

## Strobe Transport Architecture

Handshakes run over the Strobe duplex sponge and produce a `StrobeNkTransport` (stateful, auto-incrementing nonces) or `StrobeKkTransport`. Call `.into_stateless()` to get a `Sync`-able version where the caller supplies nonces.

### NK hybrid handshake (Classic McEliece + X25519)

```
msg1 (initiator → responder): | CME ciphertext (208 B) | X25519 eph pk enc (32 B) | MAC (32 B) |
msg2 (responder → initiator): | X25519 eph pk enc (32 B) | MAC (32 B) |

Transcript:
  STROBE("StrobeNK_CME8192128_X25519/v1")
  AD(responder_cme_pk) | AD(prologue)
  send_clr(cme_ct) → KEY(ss_cme)
  send_enc(init_eph_pk) → send_mac(32)
  recv_enc(resp_eph_pk) → KEY(ss_x25519) → recv_mac(32)
```

The PQC variant (`pqc.rs`) swaps the X25519 ephemeral for ML-KEM-1024.

### Strobe API conventions

- Absorb-only (`ad`, `key`, `ratchet`, `send_clr`, `recv_clr`): take `&[u8]`; state absorbs but output is unchanged.
- Cipher operations (`prf`, `send_enc`, `recv_enc`, `send_mac`, `recv_mac`): take `&mut [u8]`; transform the slice in place.

## cSHAKE256 / KMAC256 PRF (`prf::cshake256`)

Four construction modes, all producing 64-byte output by default (use `finalize_xof` for variable length):

| Function | Underlying primitive | When to use |
|----------|---------------------|-------------|
| `digest(customization)` | cSHAKE256 | Domain-separated hash |
| `hmac(key, customization)` | KMAC256 (SP 800-185 §4) | Keyed MAC |
| `kdf(key_material, customization)` | KMAC256 | Key derivation |
| `shake256()` | SHAKE256 | Only when no domain separation needed |

Use 64-byte (512-bit) output to retain ~256-bit post-quantum preimage resistance. Prefer `pqc::prf` over `crypto_prf` (BLAKE3) wherever keys or commitments must survive a quantum adversary.

## Key Invariants

- **Winternitz (`ots`)**: each key pair signs **at most one message**; signing twice leaks the secret key. Only use when the architecture structurally prevents reuse (Merkle trees, forward logs).
- **Hybrid KEMs**: always KDF the combined classical + PQ shared secrets together — never use either directly or simply concatenate them as a key.
- **Zeroize everywhere**: all secret types are `ZeroizeOnDrop`; new key material must use the `zeroize` crate.
- **`oqs` dependency**: `kem` and `sig` types (`PublicKey`, `SecretKey`, `Ciphertext`, `SharedSecret`) are re-exported from `oqs`; they are heap-allocated (require `alloc`).

## Test Vectors

Reference vectors live in `tests/vectors/` (hex-encoded). Integration tests in `tests/` load and verify them. Regenerate with the `gen-vectors` feature; commit updated vectors alongside algorithm changes.
