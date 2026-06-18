//! Integration tests for the Strobe NK hybrid and PQC transports.
//!
//! Note: Classic McEliece 8192128f key generation is intentionally slow
//! (~1–10 s).  The `cme_keypair()` helper is called once per test to keep
//! total runtime reasonable; avoid calling it more than once per test.

use issachar::kem::ClassicMcEliece;
use issachar::kem::PublicKey as CmePk;
use issachar::kem::SecretKey as CmeSk;
use issachar::symmetric::chacha20poly1305::ChaCha20Nonce;
use issachar::symmetric::chacha20poly1305::TAG_LEN;
use issachar::strobe::transport_nk::hybrid::{
    HYBRID_MSG1_LEN, HYBRID_MSG2_LEN, StrobeNkHybridInitiator, StrobeNkHybridResponder,
};
use issachar::strobe::transport_nk::pqc::{
    PQC_MSG1_LEN, PQC_MSG2_LEN, StrobeNkPqcInitiator, StrobeNkPqcResponder,
};

fn cme_keypair() -> (CmePk, CmeSk) {
    ClassicMcEliece::new()
        .keypair()
        .expect("CME keypair generation failed")
}

// ── Hybrid variant ─────────────────────────────────────────────────────────

#[test]
fn hybrid_round_trip() {
    let (pk, sk) = cme_keypair();
    let prologue = b"test-prologue";
    let plaintext = b"hello from initiator";
    let aad = b"associated data";

    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    let handshake = StrobeNkHybridInitiator::new(&pk)
        .initiate(prologue.as_ref(), &mut msg1)
        .expect("initiator new");

    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let mut responder_transport = StrobeNkHybridResponder::new(sk, &pk)
        .respond(prologue.as_ref(), &msg1, &mut msg2)
        .expect("responder respond");

    let mut initiator_transport = handshake.finish(&msg2).expect("initiator finish");

    // initiator → responder
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(aad.as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    responder_transport.recv(aad.as_ref(), &ct, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);

    // responder → initiator
    let reply = b"hello from responder";
    let mut ct2 = vec![0u8; reply.len() + TAG_LEN];
    responder_transport.send(aad.as_ref(), reply.as_ref(), &mut ct2).unwrap();
    let mut pt2 = vec![0u8; ct2.len() - TAG_LEN];
    initiator_transport.recv(aad.as_ref(), &ct2, &mut pt2).unwrap();
    assert_eq!(pt2.as_slice(), reply);
}

#[test]
fn hybrid_prologue_mismatch() {
    let (pk, sk) = cme_keypair();

    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    let handshake = StrobeNkHybridInitiator::new(&pk)
        .initiate(b"prologue-A", &mut msg1)
        .unwrap();

    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let result = StrobeNkHybridResponder::new(sk, &pk).respond(b"prologue-B", &msg1, &mut msg2);
    assert!(result.is_err(), "expected error on prologue mismatch");
    drop(handshake);
}

#[test]
fn hybrid_tag_tamper_rejected() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    let handshake = StrobeNkHybridInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let mut transport = StrobeNkHybridResponder::new(sk, &pk).respond(b"", &msg1, &mut msg2)
        .unwrap();
    let mut initiator_transport = handshake.finish(&msg2).unwrap();

    let plaintext = b"secret";
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    // Flip the last byte of the tag.
    *ct.last_mut().unwrap() ^= 0xff;
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    assert!(transport.recv(b"".as_ref(), &ct, &mut pt).is_err());
}

#[test]
fn hybrid_rx_nonce_advances_on_failure() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    let handshake = StrobeNkHybridInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let mut responder_transport = StrobeNkHybridResponder::new(sk, &pk)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    let mut initiator_transport = handshake.finish(&msg2).unwrap();

    // Encrypt two messages so the responder can consume nonce 1 after nonce 0 is burned.
    let plaintext = b"message";
    let mut ct0 = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(b"".as_ref(), plaintext.as_ref(), &mut ct0).unwrap();
    let mut ct1 = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(b"".as_ref(), plaintext.as_ref(), &mut ct1).unwrap();

    // A failed recv (tampered ciphertext) still burns the nonce.
    let mut bad_ct = ct0.clone();
    bad_ct[0] ^= 0x01;
    let mut pt = vec![0u8; bad_ct.len() - TAG_LEN];
    assert!(responder_transport.recv(b"".as_ref(), &bad_ct, &mut pt).is_err());

    // The next valid message (encrypted under nonce 1) must now decrypt successfully.
    responder_transport.recv(b"".as_ref(), &ct1, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn hybrid_wrong_cme_key_rejected() {
    let (pk, _sk) = cme_keypair();
    let (_, wrong_sk) = cme_keypair();

    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    StrobeNkHybridInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let result = StrobeNkHybridResponder::new(wrong_sk, &pk).respond(b"", &msg1, &mut msg2);
    assert!(result.is_err());
}

#[test]
fn hybrid_nonce_advances_correctly() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    let handshake = StrobeNkHybridInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let mut responder_transport = StrobeNkHybridResponder::new(sk, &pk)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    let mut initiator_transport = handshake.finish(&msg2).unwrap();

    for i in 0u8..5 {
        let plaintext = [i; 8];
        let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
        initiator_transport.send(b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
        let mut pt = vec![0u8; ct.len() - TAG_LEN];
        responder_transport.recv(b"".as_ref(), &ct, &mut pt).unwrap();
        assert_eq!(pt.as_slice(), &plaintext);
    }
}

#[test]
fn hybrid_into_stateless_round_trip() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    let handshake = StrobeNkHybridInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let responder_transport = StrobeNkHybridResponder::new(sk, &pk)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    let initiator_transport = handshake.finish(&msg2).unwrap();

    let si = initiator_transport.into_stateless();
    let sr = responder_transport.into_stateless();

    let plaintext = b"stateless message";
    let nonce = ChaCha20Nonce::new([42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    si.send(nonce, b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    sr.recv(nonce, b"".as_ref(), &ct, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn hybrid_stateless_tag_tamper_rejected() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    let handshake = StrobeNkHybridInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let responder_transport = StrobeNkHybridResponder::new(sk, &pk)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    let initiator_transport = handshake.finish(&msg2).unwrap();

    let si = initiator_transport.into_stateless();
    let sr = responder_transport.into_stateless();

    let nonce = ChaCha20Nonce::zero();
    let plaintext = b"abcdefghijklmnop";
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    si.send(nonce, b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    *ct.last_mut().unwrap() ^= 0x01;
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    assert!(sr.recv(nonce, b"".as_ref(), &ct, &mut pt).is_err());
}

#[test]
fn hybrid_stateless_buf_too_short() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; HYBRID_MSG1_LEN];
    let handshake = StrobeNkHybridInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; HYBRID_MSG2_LEN];
    let responder_transport = StrobeNkHybridResponder::new(sk, &pk)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    drop(handshake);

    let sr = responder_transport.into_stateless();
    // Input shorter than TAG_LEN — decrypt must return an error, not panic.
    let tiny = vec![0u8; TAG_LEN - 1];
    let mut pt = vec![0u8; 0];
    assert!(sr.recv(ChaCha20Nonce::zero(), b"".as_ref(), &tiny, &mut pt).is_err());
}

// ── PQC variant ────────────────────────────────────────────────────────────

#[test]
fn pqc_round_trip() {
    let (pk, sk) = cme_keypair();
    let prologue = b"pqc-prologue";
    let plaintext = b"pqc hello";
    let aad = b"aad";

    let mut msg1 = [0u8; PQC_MSG1_LEN];
    let handshake = StrobeNkPqcInitiator::new(&pk)
        .initiate(prologue.as_ref(), &mut msg1)
        .expect("pqc initiator new");

    let mut msg2 = [0u8; PQC_MSG2_LEN];
    let mut responder_transport = StrobeNkPqcResponder::new(sk, &pk)
        .respond(prologue.as_ref(), &msg1, &mut msg2)
        .expect("pqc responder respond");

    let mut initiator_transport = handshake.finish(&msg2).expect("pqc initiator finish");

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(aad.as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    responder_transport.recv(aad.as_ref(), &ct, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);

    let reply = b"pqc reply";
    let mut ct2 = vec![0u8; reply.len() + TAG_LEN];
    responder_transport.send(aad.as_ref(), reply.as_ref(), &mut ct2).unwrap();
    let mut pt2 = vec![0u8; ct2.len() - TAG_LEN];
    initiator_transport.recv(aad.as_ref(), &ct2, &mut pt2).unwrap();
    assert_eq!(pt2.as_slice(), reply);
}

#[test]
fn pqc_prologue_mismatch() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; PQC_MSG1_LEN];
    let handshake = StrobeNkPqcInitiator::new(&pk).initiate(b"A", &mut msg1).unwrap();
    let mut msg2 = [0u8; PQC_MSG2_LEN];
    let result = StrobeNkPqcResponder::new(sk, &pk).respond(b"B", &msg1, &mut msg2);
    assert!(result.is_err(), "expected error on prologue mismatch");
    drop(handshake);
}

#[test]
fn pqc_tag_tamper_rejected() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; PQC_MSG1_LEN];
    let handshake = StrobeNkPqcInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; PQC_MSG2_LEN];
    let mut transport = StrobeNkPqcResponder::new(sk, &pk).respond(b"", &msg1, &mut msg2)
        .unwrap();
    let mut initiator_transport = handshake.finish(&msg2).unwrap();

    let plaintext = b"aaaaaaaa";
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    *ct.last_mut().unwrap() ^= 0xff;
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    assert!(transport.recv(b"".as_ref(), &ct, &mut pt).is_err());
}

#[test]
fn pqc_stateless_round_trip() {
    let (pk, sk) = cme_keypair();
    let mut msg1 = [0u8; PQC_MSG1_LEN];
    let handshake = StrobeNkPqcInitiator::new(&pk).initiate(b"", &mut msg1).unwrap();
    let mut msg2 = [0u8; PQC_MSG2_LEN];
    let resp = StrobeNkPqcResponder::new(sk, &pk).respond(b"", &msg1, &mut msg2)
        .unwrap();
    let init = handshake.finish(&msg2).unwrap();

    let si = init.into_stateless();
    let sr = resp.into_stateless();

    let nonce = ChaCha20Nonce::new([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let plaintext = b"test";
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    si.send(nonce, b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    sr.recv(nonce, b"".as_ref(), &ct, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

// ── Message-size constants ─────────────────────────────────────────────────

#[test]
fn hybrid_message_lengths_are_correct() {
    use issachar::strobe::transport_nk::hybrid::CME_CT_LEN;
    // 208 + 32 + 16 = 256
    assert_eq!(HYBRID_MSG1_LEN, CME_CT_LEN + 32 + 16);
    assert_eq!(HYBRID_MSG2_LEN, 32 + 16);
}

#[test]
fn pqc_message_lengths_are_correct() {
    use issachar::strobe::transport_nk::hybrid::CME_CT_LEN;
    // 208 + 1568 + 16 = 1792
    assert_eq!(PQC_MSG1_LEN, CME_CT_LEN + 1568 + 16);
    // 1568 + 16 = 1584
    assert_eq!(PQC_MSG2_LEN, 1568 + 16);
}
