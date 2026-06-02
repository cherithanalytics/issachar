//! Integration tests for the Strobe KK hybrid and PQC transports.
//!
//! Note: Classic McEliece 8192128f key generation is intentionally slow
//! (~1–10 s).  KK requires two keypairs per test (one for each party),
//! so the `cme_kk_keypairs()` helper generates both at once.  Avoid
//! additional keypair calls unless the test specifically exercises a
//! wrong-key scenario.

use issachar::kem::ClassicMcEliece;
use issachar::kem::PublicKey as CmePk;
use issachar::kem::SecretKey as CmeSk;
use issachar::symmetric::chacha20poly1305::ChaCha20Nonce;
use issachar::symmetric::chacha20poly1305::TAG_LEN;
use issachar::strobe::transport_kk::hybrid::{
    KK_HYBRID_MSG1_LEN, KK_HYBRID_MSG2_LEN, StrobeKkHybridInitiator, StrobeKkHybridResponder,
};
use issachar::strobe::transport_kk::pqc::{
    KK_PQC_MSG1_LEN, KK_PQC_MSG2_LEN, StrobeKkPqcInitiator, StrobeKkPqcResponder,
};

fn cme_keypair() -> (CmePk, CmeSk) {
    ClassicMcEliece::keypair().expect("CME keypair generation failed")
}

/// Returns (responder keypair, initiator keypair).
fn cme_kk_keypairs() -> ((CmePk, CmeSk), (CmePk, CmeSk)) {
    let resp = cme_keypair();
    let init = cme_keypair();
    (resp, init)
}

// ── Hybrid variant ─────────────────────────────────────────────────────────

#[test]
fn kk_hybrid_round_trip() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();
    let prologue = b"kk-hybrid-prologue";
    let plaintext = b"hello from kk initiator";
    let aad = b"associated data";

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    let handshake = StrobeKkHybridInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(prologue.as_ref(), &mut msg1)
        .expect("kk hybrid initiator initiate");

    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    let mut responder_transport = StrobeKkHybridResponder::new(sk_r, &pk_r, pk_i)
        .respond(prologue.as_ref(), &msg1, &mut msg2)
        .expect("kk hybrid responder respond");

    let mut initiator_transport = handshake.finish(&msg2).expect("kk hybrid initiator finish");

    // initiator → responder
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(aad.as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    responder_transport.recv(aad.as_ref(), &ct, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);

    // responder → initiator
    let reply = b"hello from kk responder";
    let mut ct2 = vec![0u8; reply.len() + TAG_LEN];
    responder_transport.send(aad.as_ref(), reply.as_ref(), &mut ct2).unwrap();
    let mut pt2 = vec![0u8; ct2.len() - TAG_LEN];
    initiator_transport.recv(aad.as_ref(), &ct2, &mut pt2).unwrap();
    assert_eq!(pt2.as_slice(), reply);
}

#[test]
fn kk_hybrid_prologue_mismatch() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    let handshake = StrobeKkHybridInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"prologue-A", &mut msg1)
        .unwrap();

    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    let result = StrobeKkHybridResponder::new(sk_r, &pk_r, pk_i)
        .respond(b"prologue-B", &msg1, &mut msg2);
    assert!(result.is_err(), "expected error on prologue mismatch");
    drop(handshake);
}

#[test]
fn kk_hybrid_tag_tamper_rejected() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    let handshake = StrobeKkHybridInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();
    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    let mut transport = StrobeKkHybridResponder::new(sk_r, &pk_r, pk_i)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    let mut initiator_transport = handshake.finish(&msg2).unwrap();

    let plaintext = b"secret";
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    *ct.last_mut().unwrap() ^= 0xff;
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    assert!(transport.recv(b"".as_ref(), &ct, &mut pt).is_err());
}

#[test]
fn kk_hybrid_rx_nonce_advances_on_failure() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    let handshake = StrobeKkHybridInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();
    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    let mut responder_transport = StrobeKkHybridResponder::new(sk_r, &pk_r, pk_i)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    let mut initiator_transport = handshake.finish(&msg2).unwrap();

    let plaintext = b"message";
    let mut ct0 = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(b"".as_ref(), plaintext.as_ref(), &mut ct0).unwrap();
    let mut ct1 = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(b"".as_ref(), plaintext.as_ref(), &mut ct1).unwrap();

    let mut bad_ct = ct0.clone();
    bad_ct[0] ^= 0x01;
    let mut pt = vec![0u8; bad_ct.len() - TAG_LEN];
    assert!(responder_transport.recv(b"".as_ref(), &bad_ct, &mut pt).is_err());

    responder_transport.recv(b"".as_ref(), &ct1, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn kk_hybrid_wrong_responder_key_rejected() {
    let ((pk_r, _sk_r), (pk_i, sk_i)) = cme_kk_keypairs();
    let (_, wrong_sk_r) = cme_keypair();

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    StrobeKkHybridInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();

    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    let result = StrobeKkHybridResponder::new(wrong_sk_r, &pk_r, pk_i)
        .respond(b"", &msg1, &mut msg2);
    assert!(result.is_err(), "expected error with wrong responder key");
}

#[test]
fn kk_hybrid_wrong_initiator_key_rejected() {
    let ((pk_r, sk_r), (_pk_i, sk_i)) = cme_kk_keypairs();
    // Use a different keypair as the "wrong" initiator pk.
    // Both parties agree on wrong_pk_i in the transcript AD, so respond() succeeds.
    // The responder encapsulates to wrong_pk_i; finish() can't decapsulate with sk_i.
    let (wrong_pk_i, _) = cme_keypair();

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    let handshake = StrobeKkHybridInitiator::new(&pk_r, &wrong_pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();

    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    StrobeKkHybridResponder::new(sk_r, &pk_r, wrong_pk_i)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();

    let result = handshake.finish(&msg2);
    assert!(result.is_err(), "expected error when initiator key is wrong");
}

#[test]
fn kk_hybrid_nonce_advances_correctly() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    let handshake = StrobeKkHybridInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();
    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    let mut responder_transport = StrobeKkHybridResponder::new(sk_r, &pk_r, pk_i)
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
fn kk_hybrid_into_stateless_round_trip() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    let handshake = StrobeKkHybridInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();
    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    let responder_transport = StrobeKkHybridResponder::new(sk_r, &pk_r, pk_i)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    let initiator_transport = handshake.finish(&msg2).unwrap();

    let si = initiator_transport.into_stateless();
    let sr = responder_transport.into_stateless();

    let plaintext = b"stateless kk message";
    let nonce = ChaCha20Nonce::new([42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    si.send(nonce, b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    sr.recv(nonce, b"".as_ref(), &ct, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn kk_hybrid_stateless_tag_tamper_rejected() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_HYBRID_MSG1_LEN];
    let handshake = StrobeKkHybridInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();
    let mut msg2 = [0u8; KK_HYBRID_MSG2_LEN];
    let responder_transport = StrobeKkHybridResponder::new(sk_r, &pk_r, pk_i)
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

// ── PQC variant ────────────────────────────────────────────────────────────

#[test]
fn kk_pqc_round_trip() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();
    let prologue = b"kk-pqc-prologue";
    let plaintext = b"kk pqc hello";
    let aad = b"aad";

    let mut msg1 = [0u8; KK_PQC_MSG1_LEN];
    let handshake = StrobeKkPqcInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(prologue.as_ref(), &mut msg1)
        .expect("kk pqc initiator initiate");

    let mut msg2 = [0u8; KK_PQC_MSG2_LEN];
    let mut responder_transport = StrobeKkPqcResponder::new(sk_r, &pk_r, pk_i)
        .respond(prologue.as_ref(), &msg1, &mut msg2)
        .expect("kk pqc responder respond");

    let mut initiator_transport = handshake.finish(&msg2).expect("kk pqc initiator finish");

    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    initiator_transport.send(aad.as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    responder_transport.recv(aad.as_ref(), &ct, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);

    let reply = b"kk pqc reply";
    let mut ct2 = vec![0u8; reply.len() + TAG_LEN];
    responder_transport.send(aad.as_ref(), reply.as_ref(), &mut ct2).unwrap();
    let mut pt2 = vec![0u8; ct2.len() - TAG_LEN];
    initiator_transport.recv(aad.as_ref(), &ct2, &mut pt2).unwrap();
    assert_eq!(pt2.as_slice(), reply);
}

#[test]
fn kk_pqc_prologue_mismatch() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_PQC_MSG1_LEN];
    let handshake = StrobeKkPqcInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"A", &mut msg1)
        .unwrap();

    let mut msg2 = [0u8; KK_PQC_MSG2_LEN];
    let result = StrobeKkPqcResponder::new(sk_r, &pk_r, pk_i)
        .respond(b"B", &msg1, &mut msg2);
    assert!(result.is_err(), "expected error on prologue mismatch");
    drop(handshake);
}

#[test]
fn kk_pqc_tag_tamper_rejected() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_PQC_MSG1_LEN];
    let handshake = StrobeKkPqcInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();
    let mut msg2 = [0u8; KK_PQC_MSG2_LEN];
    let mut transport = StrobeKkPqcResponder::new(sk_r, &pk_r, pk_i)
        .respond(b"", &msg1, &mut msg2)
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
fn kk_pqc_wrong_responder_key_rejected() {
    let ((pk_r, _sk_r), (pk_i, sk_i)) = cme_kk_keypairs();
    let (_, wrong_sk_r) = cme_keypair();

    let mut msg1 = [0u8; KK_PQC_MSG1_LEN];
    StrobeKkPqcInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();

    let mut msg2 = [0u8; KK_PQC_MSG2_LEN];
    let result = StrobeKkPqcResponder::new(wrong_sk_r, &pk_r, pk_i)
        .respond(b"", &msg1, &mut msg2);
    assert!(result.is_err(), "expected error with wrong responder key");
}

#[test]
fn kk_pqc_wrong_initiator_key_rejected() {
    let ((pk_r, sk_r), (_pk_i, sk_i)) = cme_kk_keypairs();
    let (wrong_pk_i, _) = cme_keypair();

    let mut msg1 = [0u8; KK_PQC_MSG1_LEN];
    let handshake = StrobeKkPqcInitiator::new(&pk_r, &wrong_pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();

    let mut msg2 = [0u8; KK_PQC_MSG2_LEN];
    StrobeKkPqcResponder::new(sk_r, &pk_r, wrong_pk_i)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();

    let result = handshake.finish(&msg2);
    assert!(result.is_err(), "expected error when initiator key is wrong");
}

#[test]
fn kk_pqc_stateless_round_trip() {
    let ((pk_r, sk_r), (pk_i, sk_i)) = cme_kk_keypairs();

    let mut msg1 = [0u8; KK_PQC_MSG1_LEN];
    let handshake = StrobeKkPqcInitiator::new(&pk_r, &pk_i, sk_i)
        .initiate(b"", &mut msg1)
        .unwrap();
    let mut msg2 = [0u8; KK_PQC_MSG2_LEN];
    let resp = StrobeKkPqcResponder::new(sk_r, &pk_r, pk_i)
        .respond(b"", &msg1, &mut msg2)
        .unwrap();
    let init = handshake.finish(&msg2).unwrap();

    let si = init.into_stateless();
    let sr = resp.into_stateless();

    let nonce = ChaCha20Nonce::new([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let plaintext = b"kk pqc stateless";
    let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
    si.send(nonce, b"".as_ref(), plaintext.as_ref(), &mut ct).unwrap();
    let mut pt = vec![0u8; ct.len() - TAG_LEN];
    sr.recv(nonce, b"".as_ref(), &ct, &mut pt).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

// ── Message-size constants ─────────────────────────────────────────────────

#[test]
fn kk_hybrid_message_lengths_are_correct() {
    use issachar::strobe::transport_nk::hybrid::CME_CT_LEN;
    // msg1: 208 + 32 + 16 = 256
    assert_eq!(KK_HYBRID_MSG1_LEN, CME_CT_LEN + 32 + 16);
    // msg2: 32 + 208 + 16 = 256
    assert_eq!(KK_HYBRID_MSG2_LEN, 32 + CME_CT_LEN + 16);
}

#[test]
fn kk_pqc_message_lengths_are_correct() {
    use issachar::strobe::transport_nk::hybrid::CME_CT_LEN;
    // msg1: 208 + 1568 + 16 = 1792
    assert_eq!(KK_PQC_MSG1_LEN, CME_CT_LEN + 1568 + 16);
    // msg2: 1568 + 208 + 16 = 1792
    assert_eq!(KK_PQC_MSG2_LEN, 1568 + CME_CT_LEN + 16);
}
