//! Strobe NK hybrid transport: Classic McEliece 8192128f (static server key)
//! + X25519 (ephemeral forward-secrecy key).
//!
//! Protocol string: `"StrobeNK_CME8192128_X25519/v1"`
//!
//! Handshake layout
//! ────────────────
//!
//! **msg1** (initiator → responder, HYBRID_MSG1_LEN bytes):
//! ```text
//! | CME ciphertext (208 B) | X25519 ephemeral pk (32 B) | MAC (32 B) |
//! ```
//!
//! **msg2** (responder → initiator, HYBRID_MSG2_LEN bytes):
//! ```text
//! | X25519 ephemeral pk (32 B) | MAC (32 B) |
//! ```
//!
//! Transcript (initiator side, responder mirrors recv/send):
//! ```text
//! STROBE("StrobeNK_CME8192128_X25519/v1")
//! AD(responder_cme_pk)
//! AD(prologue)
//! send_clr(cme_ct)          // msg1[0..208]
//! KEY(ss_cme)
//! send_enc(init_eph_pk)     // msg1[208..240]  — encrypts in place
//! send_mac(32)              // msg1[240..272]
//! recv_enc(resp_eph_pk)     // msg2[0..32]
//! KEY(ss_x25519)
//! recv_mac(32)              // msg2[32..64]
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

/// Classic McEliece 8192128f ciphertext length (bytes).
pub const CME_CT_LEN: usize = 208;
const X25519_PK_LEN: usize = 32;

/// Length of the first handshake message (initiator → responder).
/// CME ciphertext (208) + X25519 ephemeral pk (32) + MAC (32).
pub const HYBRID_MSG1_LEN: usize = CME_CT_LEN + X25519_PK_LEN + MAC_LEN; // 272

/// Length of the second handshake message (responder → initiator).
/// X25519 ephemeral pk (32) + MAC (32).
pub const HYBRID_MSG2_LEN: usize = X25519_PK_LEN + MAC_LEN; // 64

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

/// Reusable initiator config for the Strobe NK hybrid handshake.
///
/// 1. Call `StrobeNkHybridInitiator::new(responder_cme_pk)` — stores the key
///    and pre-initializes the Strobe state with `AD(responder_cme_pk)`.
/// 2. Call `.initiate(prologue, out)` — encapsulates to the responder, writes
///    **msg1** into `out`, and returns a `StrobeNkHybridHandshake`.
/// 3. Send `out` to the responder and receive **msg2**.
/// 4. Call `.finish(msg2)` on the handshake — returns a `StrobeNkTransport`.
pub struct StrobeNkHybridInitiator {
    state: Strobe,
    responder_cme_pk: ClassicMcEliecePublicKey,
}

impl StrobeNkHybridInitiator {
    pub fn new(responder_cme_pk: &ClassicMcEliecePublicKey) -> Self {
        let mut state = Strobe::new(b"StrobeNK_CME8192128_X25519/v1");
        state.ad(responder_cme_pk.as_ref(), false);
        Self { state, responder_cme_pk: responder_cme_pk.clone() }
    }

    /// Builds msg1 into `out` (must be exactly `HYBRID_MSG1_LEN` bytes).
    ///
    /// `prologue` is absorbed as AD before any key material; pass `b""` if
    /// there is no external context to bind.
    pub fn initiate(
        &self,
        prologue: impl AsRef<[u8]>,
        out: &mut [u8; HYBRID_MSG1_LEN],
    ) -> Result<StrobeNkHybridHandshake, Error> {
        let mut state = self.state.clone();
        state.ad(prologue.as_ref(), false);

        // CME encapsulate — produces ciphertext and shared secret.
        let (ct_cme, ss_cme) = ClassicMcEliece::encapsulate(&self.responder_cme_pk)
            .map_err(|_| Error::CmeEncapsulate)?;
        out[..CME_CT_LEN].copy_from_slice(ct_cme.as_ref());
        state.send_clr(&out[..CME_CT_LEN], false);
        state.key(ss_cme.as_ref());

        // X25519 ephemeral key pair — pk is encrypted into msg1.
        let init_eph_key = X25519Key::generate();
        let pk_range = CME_CT_LEN..CME_CT_LEN + X25519_PK_LEN;
        out[pk_range.clone()].copy_from_slice(&init_eph_key.public_key_bytes());
        state.send_enc(&mut out[pk_range], false);
        state.send_mac(&mut out[CME_CT_LEN + X25519_PK_LEN..HYBRID_MSG1_LEN], false);

        Ok(StrobeNkHybridHandshake { state, init_eph_key })
    }
}

/// In-progress hybrid handshake — holds the ephemeral key until msg2 arrives.
pub struct StrobeNkHybridHandshake {
    state: Strobe,
    init_eph_key: X25519Key,
}

impl StrobeNkHybridHandshake {
    /// Processes msg2 (must be exactly `HYBRID_MSG2_LEN` bytes) and returns the
    /// derived `StrobeNkTransport`.
    ///
    /// Note: ECDH is computed before MAC verification because the responder's
    /// `send_mac` is computed *after* keying with ss_x25519.  The MAC therefore
    /// covers the ECDH outcome on both sides, preventing an active attacker from
    /// substituting the responder's ephemeral key.
    pub fn finish(mut self, msg2: &[u8; HYBRID_MSG2_LEN]) -> Result<StrobeNkTransport, Error> {
        // Decrypt the responder's ephemeral public key.
        let mut pk_buf = [0u8; X25519_PK_LEN];
        pk_buf.copy_from_slice(&msg2[..X25519_PK_LEN]);
        self.state.recv_enc(&mut pk_buf, false);

        // ECDH — agree() consumes init_eph_key; EphemeralSecret zeroizes on drop.
        let mut ss_x25519 =
            self.init_eph_key.agree(pk_buf).map_err(|_| Error::X25519)?;
        self.state.key(&ss_x25519);
        ss_x25519.zeroize();

        // Verify MAC (covers everything up to and including KEY(ss_x25519)).
        let mut mac_buf = [0u8; MAC_LEN];
        mac_buf.copy_from_slice(&msg2[X25519_PK_LEN..]);
        self.state.recv_mac(&mut mac_buf, false).map_err(|_| Error::MacFailed)?;

        Ok(StrobeNkTransport::from_handshake(self.state, Role::Initiator))
    }
}

/// Responder side of the Strobe NK hybrid handshake.
///
/// 1. Call `StrobeNkHybridResponder::new(sk, pk)`.
/// 2. Receive **msg1** from the initiator.
/// 3. Call `.respond(prologue, msg1, out)` — verifies msg1, builds **msg2** in `out`,
///    and returns a `StrobeNkTransport`.
pub struct StrobeNkHybridResponder {
    state: Strobe,
    sk: ClassicMcElieceSecretKey,
}

impl StrobeNkHybridResponder {
    pub fn new(sk: ClassicMcElieceSecretKey, pk: &ClassicMcEliecePublicKey) -> Self {
        let mut state = Strobe::new(b"StrobeNK_CME8192128_X25519/v1");
        state.ad(pk.as_ref(), false);
        Self { state, sk }
    }

    /// Processes msg1, builds msg2 into `out`.
    pub fn respond(
        &self,
        prologue: impl AsRef<[u8]>,
        msg1: &[u8; HYBRID_MSG1_LEN],
        out: &mut [u8; HYBRID_MSG2_LEN],
    ) -> Result<StrobeNkTransport, Error> {
        let mut state = self.state.clone();
        state.ad(prologue.as_ref(), false);

        // CME ciphertext arrives in the clear.
        state.recv_clr(&msg1[..CME_CT_LEN], false);
        let ct_cme = ClassicMcEliece::ciphertext_from_bytes(&msg1[..CME_CT_LEN])
            .ok_or(Error::CmeDecapsulate)?;
        let ss_cme = ClassicMcEliece::decapsulate(&self.sk, &ct_cme)
            .map_err(|_| Error::CmeDecapsulate)?;
        state.key(ss_cme.as_ref());

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

        state.send_mac(&mut out[X25519_PK_LEN..HYBRID_MSG2_LEN], false);

        Ok(StrobeNkTransport::from_handshake(state, Role::Responder))
    }
}
