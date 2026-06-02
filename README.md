# issachar

Post-quantum cryptography primitives for Rust. Every algorithm is fixed at NIST Level 5 (~256-bit classical / 128-bit post-quantum security). There are no level-1 or level-3 variants.

## Modules

| Module | Contents |
|--------|----------|
| `kem` | ML-KEM-1024, Classic McEliece-8192128f, FrodoKEM-1344-AES |
| `sig` | ML-DSA-87, SPHINCS+-SHA2-256f |
| `ots` | Winternitz one-time signatures |
| `prf` | cSHAKE256 / KMAC256 PRF suite |
| `strobe` | Strobe-based authenticated transports (NK and KK patterns) |
| `symmetric` | ChaCha20-Poly1305 cipher and nonce types |
| `classic` | X25519 key pair (used inside Strobe transports) |

## Usage

```toml
[dependencies]
issachar = "*"

# no_std (requires an allocator)
issachar = { version = "*", default-features = false }
```

### KEM

```rust
use issachar::kem::{MlKem, ClassicMcEliece};

// Fast ephemeral KEM — small keys, FIPS 203
let (pk, sk) = MlKem::keypair();
let (ciphertext, shared_secret) = MlKem::encapsulate(&pk);
let recovered = MlKem::decapsulate(&sk, &ciphertext);

// Conservative static KEM — 50-year-old code-based assumption, tiny ciphertext
let (pk, sk) = ClassicMcEliece::keypair();
let (ciphertext, shared_secret) = ClassicMcEliece::encapsulate(&pk);
```

### Signatures

```rust
use issachar::sig::{MlDsa, Sphincs};

let (pk, sk) = MlDsa::keypair();
let sig = MlDsa::sign(&sk, b"message");
assert!(MlDsa::verify(&pk, b"message", &sig).is_ok());
```

### One-time signatures

```rust
use issachar::ots::winternitz;

// Each key pair signs at most one message — signing twice leaks the secret key.
let (pk, sk) = winternitz::keypair();
let sig = winternitz::sign(&sk, b"message");
assert!(winternitz::verify(&pk, b"message", &sig).is_ok());
```

### PRF

```rust
use issachar::prf::cshake256;

// Domain-separated hash
let digest = cshake256::digest(b"input", b"my-app/v1");

// Keyed MAC
let tag = cshake256::hmac(&key, b"input", b"my-app/v1");

// Key derivation
let derived = cshake256::kdf(&key_material, b"my-app/session-key/v1");
```

All PRF functions produce 64-byte (512-bit) output by default, retaining ~256-bit post-quantum preimage resistance. Use `finalize_xof` for variable-length output.

### Strobe transports

Authenticated key exchange over the [Strobe](https://strobe.sourceforge.io/) duplex sponge, producing a stateful `Transport` with auto-incrementing nonces. Call `.into_stateless()` for a `Sync`-able version where the caller supplies nonces.

**NK (server has a known static key):**

```rust
use issachar::strobe::transport_nk::hybrid::{Initiator, Responder};

// Initiator
let (handshake, msg1) = Initiator::new(&server_cme_pk, prologue)?;
// ... send msg1 to server ...
let transport = handshake.finish(&msg2)?;

// Responder
let (handshake, msg2) = Responder::respond(&server_cme_sk, &server_cme_pk, prologue, &msg1)?;
let transport = handshake.finish();
```

The `pqc` variant (`transport_nk::pqc`) replaces the X25519 ephemeral with ML-KEM-1024. The `transport_kk` variants extend this to mutual authentication where both parties have known static keys.

## Key invariants

- **Winternitz OTS**: each key pair signs **at most one message**. Signing twice leaks the secret key.
- **Hybrid KEMs**: always KDF the combined classical + PQ shared secrets together — never use either directly or simply concatenate them as a key.
- **Zeroize everywhere**: all secret types implement `ZeroizeOnDrop`.

## KEM comparison

| | ML-KEM-1024 | FrodoKEM-1344-AES | Classic McEliece-8192128f |
|---|---|---|---|
| Assumption | Module-LWE | Plain-LWE | Binary Goppa codes |
| Cryptanalytic age | ~10 years | ~15 years | ~50 years |
| Public key | 1,568 B | 21,520 B | ~1.3 MB |
| Ciphertext | 1,568 B | 21,632 B | 208 B |
| NIST standard | FIPS 203 | — | Round 4 finalist |
| Key generation | Fast | Moderate | Slow (`f` = faster variant) |

Use ML-KEM for ephemeral keys. Use Classic McEliece as a static server key when its large public key can be distributed out-of-band and you want a maximally conservative second opinion alongside ML-KEM.

## no_std

The crate is `#![no_std]` and links `alloc` for the heap-allocated key types from the underlying `oqs` bindings. The one `std`-gated API is `prf::cshake256::CShake256::update_read`, which takes a `BufReader`.

## Building

```sh
cargo build
cargo build --no-default-features   # no_std

cargo test
cargo run --bin gen_test_vectors --features gen-vectors
cargo run --bin gen_sig_test_vectors --features gen-vectors
```
