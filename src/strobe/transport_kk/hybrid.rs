//! Strobe KK hybrid transport: Classic McEliece 8192128f (static keys, mutual auth)
//! + X25519 (ephemeral forward-secrecy key).
//!
//! Protocol string: `"StrobeKK_CME8192128_X25519/v1"`
//!
//! Handshake layout
//! ────────────────
//!
//! **msg1** (initiator → responder, KK_HYBRID_MSG1_LEN bytes):
//! ```text
//! | CME ciphertext (208 B) | X25519 ephemeral pk (32 B) | MAC (16 B) |
//! ```
//!
//! **msg2** (responder → initiator, KK_HYBRID_MSG2_LEN bytes):
//! ```text
//! | X25519 ephemeral pk (32 B) | CME ciphertext to initiator (208 B) | MAC (16 B) |
//! ```
//!
//! Transcript (initiator side; responder mirrors recv/send):
//! ```text
//! STROBE("StrobeKK_CME8192128_X25519/v1")
//! AD(responder_cme_pk)
//! AD(initiator_cme_pk)
//! AD(prologue)
//! send_clr(ct_cme_r)        // msg1[0..208]
//! KEY(ss_cme_r)
//! send_enc(init_eph_pk)     // msg1[208..240]
//! send_mac(16)              // msg1[240..256]
//! recv_enc(resp_eph_pk)     // msg2[0..32]
//! KEY(ss_x25519)
//! recv_enc(ct_cme_i)        // msg2[32..240]
//! KEY(ss_cme_i)
//! recv_mac(16)              // msg2[240..256]
//! ```

use zeroize::Zeroize;

use crate::classic::X25519Key;
use crate::kem::ClassicMcEliece;
use crate::kem::PublicKey as ClassicMcEliecePublicKey;
use crate::kem::SecretKey as ClassicMcElieceSecretKey;
use crate::strobe::Strobe;
use crate::strobe::transport_nk::MAC_LEN;
use crate::strobe::transport_nk::Role;
use crate::strobe::transport_nk::StrobeNkTransport;
use crate::strobe::transport_nk::hybrid::CME_CT_LEN;

const X25519_PK_LEN: usize = 32;

/// Length of the first handshake message (initiator → responder).
/// CME ciphertext (208) + X25519 ephemeral pk (32) + MAC (16).
pub const KK_HYBRID_MSG1_LEN: usize = CME_CT_LEN + X25519_PK_LEN + MAC_LEN; // 256

/// Length of the second handshake message (responder → initiator).
/// X25519 ephemeral pk (32) + CME ciphertext to initiator (208) + MAC (16).
pub const KK_HYBRID_MSG2_LEN: usize = X25519_PK_LEN + CME_CT_LEN + MAC_LEN; // 256

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature = "std", error("CME encapsulation failed"))]
    CmeEncapsulate,
    #[cfg_attr(feature = "std", error("CME decapsulation failed"))]
    CmeDecapsulate,
    #[cfg_attr(feature = "std", error("X25519 key agreement failed"))]
    X25519,
    #[cfg_attr(feature = "std", error("MAC verification failed"))]
    MacFailed,
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::CmeEncapsulate => f.write_str("CME encapsulation failed"),
            Error::CmeDecapsulate => f.write_str("CME decapsulation failed"),
            Error::X25519 => f.write_str("X25519 key agreement failed"),
            Error::MacFailed => f.write_str("MAC verification failed"),
        }
    }
}

/// Reusable initiator config for the Strobe KK hybrid handshake.
///
/// 1. Call `StrobeKkHybridInitiator::new(responder_cme_pk, initiator_cme_pk, initiator_sk)`.
/// 2. Call `.initiate(prologue, out)` — encapsulates to the responder, writes
///    **msg1** into `out`, and returns a `StrobeKkHybridHandshake`.
/// 3. Send `out` to the responder and receive **msg2**.
/// 4. Call `.finish(msg2)` on the handshake — returns a `StrobeNkTransport`.
pub struct StrobeKkHybridInitiator {
    state: Strobe,
    responder_cme_pk: ClassicMcEliecePublicKey,
    initiator_sk: ClassicMcElieceSecretKey,
}

impl StrobeKkHybridInitiator {
    pub fn new(
        responder_cme_pk: &ClassicMcEliecePublicKey,
        initiator_cme_pk: &ClassicMcEliecePublicKey,
        initiator_sk: ClassicMcElieceSecretKey,
    ) -> Self {
        let mut state = Strobe::new(b"StrobeKK_CME8192128_X25519/v1");
        state.ad(responder_cme_pk.as_ref(), false);
        state.ad(initiator_cme_pk.as_ref(), false);
        Self { state, responder_cme_pk: responder_cme_pk.clone(), initiator_sk }
    }

    /// Builds msg1 into `out` (must be exactly `KK_HYBRID_MSG1_LEN` bytes).
    pub fn initiate(
        &self,
        prologue: impl AsRef<[u8]>,
        out: &mut [u8; KK_HYBRID_MSG1_LEN],
    ) -> Result<StrobeKkHybridHandshake, Error> {
        let mut state = self.state.clone();
        state.ad(prologue.as_ref(), false);

        // CME encapsulate to responder's static pk.
        let (ct_cme, ss_cme) = ClassicMcEliece::encapsulate(&self.responder_cme_pk)
            .map_err(|_| Error::CmeEncapsulate)?;
        out[..CME_CT_LEN].copy_from_slice(ct_cme.as_ref());
        state.send_clr(&out[..CME_CT_LEN], false);
        state.key(ss_cme.as_ref());

        // X25519 ephemeral key pair — pk encrypted into msg1.
        let init_eph_key = X25519Key::generate();
        let pk_range = CME_CT_LEN..CME_CT_LEN + X25519_PK_LEN;
        out[pk_range.clone()].copy_from_slice(&init_eph_key.public_key_bytes());
        state.send_enc(&mut out[pk_range], false);
        state.send_mac(&mut out[CME_CT_LEN + X25519_PK_LEN..KK_HYBRID_MSG1_LEN], false);

        Ok(StrobeKkHybridHandshake {
            state,
            init_eph_key,
            initiator_sk: self.initiator_sk.clone(),
        })
    }
}

/// In-progress KK hybrid handshake — holds the ephemeral and static keys until msg2 arrives.
pub struct StrobeKkHybridHandshake {
    state: Strobe,
    init_eph_key: X25519Key,
    initiator_sk: ClassicMcElieceSecretKey,
}

impl StrobeKkHybridHandshake {
    /// Processes msg2 and returns the derived `StrobeNkTransport`.
    pub fn finish(mut self, msg2: &[u8; KK_HYBRID_MSG2_LEN]) -> Result<StrobeNkTransport, Error> {
        // Decrypt the responder's ephemeral public key.
        let mut pk_buf = [0u8; X25519_PK_LEN];
        pk_buf.copy_from_slice(&msg2[..X25519_PK_LEN]);
        self.state.recv_enc(&mut pk_buf, false);

        // ECDH — agree() consumes init_eph_key; EphemeralSecret zeroizes on drop.
        let mut ss_x25519 =
            self.init_eph_key.agree(pk_buf).map_err(|_| Error::X25519)?;
        self.state.key(&ss_x25519);
        ss_x25519.zeroize();

        // Decrypt the CME ciphertext encapsulated to the initiator's static pk.
        let mut ct_buf = [0u8; CME_CT_LEN];
        ct_buf.copy_from_slice(&msg2[X25519_PK_LEN..X25519_PK_LEN + CME_CT_LEN]);
        self.state.recv_enc(&mut ct_buf, false);

        let ct_cme_i = ClassicMcEliece::ciphertext_from_bytes(&ct_buf)
            .ok_or(Error::CmeDecapsulate)?;
        let ss_cme_i = ClassicMcEliece::decapsulate(&self.initiator_sk, &ct_cme_i)
            .map_err(|_| Error::CmeDecapsulate)?;
        self.state.key(ss_cme_i.as_ref());

        // Verify MAC (covers everything up to and including KEY(ss_cme_i)).
        let mut mac_buf = [0u8; MAC_LEN];
        mac_buf.copy_from_slice(&msg2[X25519_PK_LEN + CME_CT_LEN..]);
        self.state.recv_mac(&mut mac_buf, false).map_err(|_| Error::MacFailed)?;

        Ok(StrobeNkTransport::from_handshake(self.state, Role::Initiator))
    }
}

/// Responder side of the Strobe KK hybrid handshake.
///
/// 1. Call `StrobeKkHybridResponder::new(responder_sk, responder_pk, initiator_pk)`.
/// 2. Receive **msg1** from the initiator.
/// 3. Call `.respond(prologue, msg1, out)` — verifies msg1, builds **msg2** in `out`,
///    and returns a `StrobeNkTransport`.
pub struct StrobeKkHybridResponder {
    state: Strobe,
    responder_sk: ClassicMcElieceSecretKey,
    initiator_pk: ClassicMcEliecePublicKey,
}

impl StrobeKkHybridResponder {
    pub fn new(
        responder_sk: ClassicMcElieceSecretKey,
        responder_pk: &ClassicMcEliecePublicKey,
        initiator_pk: ClassicMcEliecePublicKey,
    ) -> Self {
        let mut state = Strobe::new(b"StrobeKK_CME8192128_X25519/v1");
        state.ad(responder_pk.as_ref(), false);
        state.ad(initiator_pk.as_ref(), false);
        Self { state, responder_sk, initiator_pk }
    }

    /// Processes msg1, builds msg2 into `out`.
    pub fn respond(
        &self,
        prologue: impl AsRef<[u8]>,
        msg1: &[u8; KK_HYBRID_MSG1_LEN],
        out: &mut [u8; KK_HYBRID_MSG2_LEN],
    ) -> Result<StrobeNkTransport, Error> {
        let mut state = self.state.clone();
        state.ad(prologue.as_ref(), false);

        // CME ciphertext arrives in the clear.
        state.recv_clr(&msg1[..CME_CT_LEN], false);
        let ct_cme = ClassicMcEliece::ciphertext_from_bytes(&msg1[..CME_CT_LEN])
            .ok_or(Error::CmeDecapsulate)?;
        let ss_cme_r = ClassicMcEliece::decapsulate(&self.responder_sk, &ct_cme)
            .map_err(|_| Error::CmeDecapsulate)?;
        state.key(ss_cme_r.as_ref());

        // Decrypt the initiator's ephemeral public key.
        let mut init_eph_pk_buf = [0u8; X25519_PK_LEN];
        init_eph_pk_buf.copy_from_slice(&msg1[CME_CT_LEN..CME_CT_LEN + X25519_PK_LEN]);
        state.recv_enc(&mut init_eph_pk_buf, false);

        // Verify initiator's MAC.
        let mut mac_buf = [0u8; MAC_LEN];
        mac_buf.copy_from_slice(&msg1[CME_CT_LEN + X25519_PK_LEN..]);
        state.recv_mac(&mut mac_buf, false).map_err(|_| Error::MacFailed)?;

        // Generate responder's ephemeral key pair and encrypt pk into msg2.
        let resp_eph_key = X25519Key::generate();
        out[..X25519_PK_LEN].copy_from_slice(&resp_eph_key.public_key_bytes());
        state.send_enc(&mut out[..X25519_PK_LEN], false);

        // ECDH — agree() consumes resp_eph_key; EphemeralSecret zeroizes on drop.
        let mut ss_x25519 =
            resp_eph_key.agree(init_eph_pk_buf).map_err(|_| Error::X25519)?;
        state.key(&ss_x25519);
        ss_x25519.zeroize();

        // CME encapsulate to initiator's static pk, encrypt ciphertext into msg2.
        let (ct_cme_i, ss_cme_i) = ClassicMcEliece::encapsulate(&self.initiator_pk)
            .map_err(|_| Error::CmeEncapsulate)?;
        out[X25519_PK_LEN..X25519_PK_LEN + CME_CT_LEN].copy_from_slice(ct_cme_i.as_ref());
        state.send_enc(&mut out[X25519_PK_LEN..X25519_PK_LEN + CME_CT_LEN], false);
        state.key(ss_cme_i.as_ref());

        state.send_mac(&mut out[X25519_PK_LEN + CME_CT_LEN..KK_HYBRID_MSG2_LEN], false);

        Ok(StrobeNkTransport::from_handshake(state, Role::Responder))
    }
}
