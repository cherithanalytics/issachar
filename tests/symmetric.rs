// Tests for issachar::symmetric::chacha20poly1305::ChaCha20Poly1305Cipher.
//
// Known-answer vectors:
//   • rfc_vector_exact — verbatim RFC 8439 §2.8.2 vector.
//   • rfc_vector_nonce_0 / rfc_vector_nonce_7 — same RFC key/AAD/plaintext with
//     nonce values 0 and 7; pre-computed expected outputs included.
//   • empty_plaintext_zero_key_nonce_0 — tag-only output for the degenerate case.

use issachar::symmetric::chacha20poly1305::ChaCha20Nonce;
use issachar::symmetric::chacha20poly1305::ChaCha20Poly1305Cipher;
use issachar::symmetric::chacha20poly1305::Error;
use issachar::symmetric::chacha20poly1305::TAG_LEN;

// ── Shared RFC 8439 §2.8.2 inputs ─────────────────────────────────────────

fn rfc_key() -> [u8; 32] {
    hex_arr("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
}

fn rfc_aad() -> Vec<u8> {
    unhex("50515253c0c1c2c3c4c5c6c7")
}

/// Exact plaintext bytes from RFC 8439 §2.8.2.
fn rfc_plaintext() -> Vec<u8> {
    unhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373\
         206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c\
         79206f6e652074697020666f7220746865206675747572652c2073756e73637265\
         656e20776f756c642062652069742e",
    )
}

fn nonce_from_bytes(bytes: [u8; 12]) -> ChaCha20Nonce {
    ChaCha20Nonce::new(bytes)
}

// ── Known-answer tests ─────────────────────────────────────────────────────

/// Verbatim RFC 8439 §2.8.2 test vector.
#[test]
fn rfc_vector_exact() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let aad = rfc_aad();
    let plaintext = rfc_plaintext();
    let nonce = nonce_from_bytes(hex_arr("070000004041424344454647"));

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(nonce, &aad, &plaintext, &mut ct).unwrap();

    assert_eq!(
        hex(&ct[..plaintext.len()]),
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b369\
         2ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff\
         4def08e4b7a9de576d26586cec64b6116",
    );
    assert_eq!(hex(&ct[plaintext.len()..]), "1ae10b594f09e26a7e902ecbd0600691");

    let mut pt = vec![0u8; plaintext.len()];
    cipher.decrypt(nonce, &aad, &ct, &mut pt).unwrap();
    assert_eq!(pt, plaintext);
}

/// RFC 8439 inputs, nonce = 0.
#[test]
fn rfc_vector_nonce_0() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let aad = rfc_aad();
    let plaintext = rfc_plaintext();
    let nonce = ChaCha20Nonce::zero();

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(nonce, &aad, &plaintext, &mut ct).unwrap();

    assert_eq!(
        hex(&ct[..plaintext.len()]),
        "663d7ec45b29ceaaa35505b8c1b3d94613a50fd7e315a748d35a378670746af8\
         67ab3404fe7b7655b904162b408190f3f8c781815bb8724e4ac22ea6351d3846\
         8cd370aa8ffb19e96edc915893cc6e1861c2af01ab0fb02df97ea145499bb87d\
         44ec7d738272327290570a03658b27b11666",
    );
    assert_eq!(hex(&ct[plaintext.len()..]), "5c21ea189f9450ff121509fd8142befc");

    let mut pt = vec![0u8; plaintext.len()];
    cipher.decrypt(nonce, &aad, &ct, &mut pt).unwrap();
    assert_eq!(pt, plaintext);
}

/// RFC 8439 inputs, nonce = 7.
#[test]
fn rfc_vector_nonce_7() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let aad = rfc_aad();
    let plaintext = rfc_plaintext();
    let nonce = ChaCha20Nonce::new([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(nonce, &aad, &plaintext, &mut ct).unwrap();

    assert_eq!(
        hex(&ct[..plaintext.len()]),
        "536b288c4b27fae71e243580369134b20e0e2021caf127e947b5cdaa934c9355\
         4f69d1ff1957b9d4d5b906508f61a519b6df0411e889dbf7e235270a9045c4fa\
         320b5e0547db9abcb629b2d4a1e2a0518e3001e390312ab9ee6f4c30625e31d1\
         254eb8a8d2ce6f3b73cbdbc881633a0457da",
    );
    assert_eq!(hex(&ct[plaintext.len()..]), "6e1ea54a90495ecb38e47a083f8f551d");

    let mut pt = vec![0u8; plaintext.len()];
    cipher.decrypt(nonce, &aad, &ct, &mut pt).unwrap();
    assert_eq!(pt, plaintext);
}

/// Empty plaintext with a zero key, no AAD, and nonce 0.
#[test]
fn empty_plaintext_zero_key_nonce_0() {
    let cipher = ChaCha20Poly1305Cipher::new(&[0u8; 32]);
    let nonce = ChaCha20Nonce::zero();

    let mut ct = vec![0u8; TAG_LEN];
    cipher.encrypt(nonce, &[], &[], &mut ct).unwrap();
    assert_eq!(hex(&ct), "4eb972c9a8fb3a1b382bb4d36f5ffad1");

    let mut pt = vec![0u8; 0];
    cipher.decrypt(nonce, &[], &ct, &mut pt).unwrap();
    assert!(pt.is_empty());
}

// ── Round-trip ─────────────────────────────────────────────────────────────

#[test]
fn roundtrip_various_nonces() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let plaintext = rfc_plaintext();
    let aad = rfc_aad();

    let nonces = [
        ChaCha20Nonce::zero(),
        ChaCha20Nonce::new([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ChaCha20Nonce::new([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        nonce_from_bytes([0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]),
        nonce_from_bytes([0xff; 12]),
    ];

    for nonce in nonces {
        let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
        cipher.encrypt(nonce, &aad, &plaintext, &mut ct).unwrap();
        assert_ne!(&ct[..plaintext.len()], plaintext.as_slice(), "ciphertext must differ from plaintext");

        let mut pt = vec![0u8; plaintext.len()];
        cipher.decrypt(nonce, &aad, &ct, &mut pt).unwrap();
        assert_eq!(pt, plaintext, "round-trip must recover plaintext");
    }
}

// ── Authentication failure tests ───────────────────────────────────────────

#[test]
fn wrong_key_rejected() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let plaintext = rfc_plaintext();
    let aad = rfc_aad();
    let nonce = ChaCha20Nonce::zero();

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(nonce, &aad, &plaintext, &mut ct).unwrap();

    let mut wrong_key = rfc_key();
    wrong_key[0] ^= 1;
    let bad_cipher = ChaCha20Poly1305Cipher::new(&wrong_key);
    let mut pt = vec![0u8; plaintext.len()];
    assert!(matches!(bad_cipher.decrypt(nonce, &aad, &ct, &mut pt), Err(Error::AuthenticationFailed)));
}

#[test]
fn wrong_aad_rejected() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let plaintext = rfc_plaintext();
    let aad = rfc_aad();
    let nonce = ChaCha20Nonce::zero();

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(nonce, &aad, &plaintext, &mut ct).unwrap();

    let mut pt = vec![0u8; plaintext.len()];
    assert!(matches!(cipher.decrypt(nonce, b"tampered_aad____", &ct, &mut pt), Err(Error::AuthenticationFailed)));
}

#[test]
fn tampered_ciphertext_rejected() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let plaintext = rfc_plaintext();
    let aad = rfc_aad();
    let nonce = ChaCha20Nonce::zero();

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(nonce, &aad, &plaintext, &mut ct).unwrap();
    ct[0] ^= 0xff;

    let mut pt = vec![0u8; plaintext.len()];
    assert!(matches!(cipher.decrypt(nonce, &aad, &ct, &mut pt), Err(Error::AuthenticationFailed)));
}

#[test]
fn tampered_tag_rejected() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let plaintext = rfc_plaintext();
    let aad = rfc_aad();
    let nonce = ChaCha20Nonce::zero();

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(nonce, &aad, &plaintext, &mut ct).unwrap();
    *ct.last_mut().unwrap() ^= 0xff;

    let mut pt = vec![0u8; plaintext.len()];
    assert!(matches!(cipher.decrypt(nonce, &aad, &ct, &mut pt), Err(Error::AuthenticationFailed)));
}

#[test]
fn wrong_nonce_rejected() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let plaintext = rfc_plaintext();
    let aad = rfc_aad();

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(ChaCha20Nonce::zero(), &aad, &plaintext, &mut ct).unwrap();

    let mut pt = vec![0u8; plaintext.len()];
    assert!(matches!(cipher.decrypt(ChaCha20Nonce::new([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), &aad, &ct, &mut pt), Err(Error::AuthenticationFailed)));
}

// ── Nonce independence ─────────────────────────────────────────────────────

#[test]
fn distinct_nonces_produce_distinct_ciphertexts() {
    let cipher = ChaCha20Poly1305Cipher::new(&rfc_key());
    let plaintext = rfc_plaintext();

    let mut ct0 = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(ChaCha20Nonce::zero(), &[], &plaintext, &mut ct0).unwrap();

    let mut ct1 = vec![0u8; plaintext.len() + TAG_LEN];
    cipher.encrypt(ChaCha20Nonce::new([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), &[], &plaintext, &mut ct1).unwrap();

    assert_ne!(ct0, ct1, "distinct nonces must produce distinct ciphertexts");
}

// ── Length error tests ─────────────────────────────────────────────────────

#[test]
fn decrypt_ciphertext_too_short() {
    let cipher = ChaCha20Poly1305Cipher::new(&[0u8; 32]);
    let mut plaintext = [];
    let err = cipher.decrypt(ChaCha20Nonce::zero(), b"", &[0u8; TAG_LEN - 1], &mut plaintext);
    assert!(matches!(err, Err(Error::BadLength)));
}

#[test]
fn decrypt_plaintext_wrong_length() {
    let cipher = ChaCha20Poly1305Cipher::new(&[0u8; 32]);
    let ct = [0u8; 4 + TAG_LEN];
    let mut plaintext = [0u8; 3]; // should be 4
    let err = cipher.decrypt(ChaCha20Nonce::zero(), b"", &ct, &mut plaintext);
    assert!(matches!(err, Err(Error::BadLength)));
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("hex string length mismatch")
}
