//! Strobe KK fully-PQC transport: Classic McEliece 8192128f (static keys, mutual auth)
//! + ML-KEM-1024 (ephemeral forward-secrecy key).
//!
//! Protocol string: `"StrobeKK_CME8192128_MLKEM1024/v1"`
//!
//! Handshake layout
//! ────────────────
//!
//! **msg1** (initiator → responder, KK_PQC_MSG1_LEN bytes):
//! ```text
//! | CME ciphertext (208 B) | ML-KEM-1024 ephemeral pk (1568 B) | MAC (16 B) |
//! ```
//!
//! **msg2** (responder → initiator, KK_PQC_MSG2_LEN bytes):
//! ```text
//! | ML-KEM-1024 ciphertext (1568 B) | CME ciphertext to initiator (208 B) | MAC (16 B) |
//! ```
//!
//! Transcript (initiator side):
//! ```text
//! STROBE("StrobeKK_CME8192128_MLKEM1024/v1")
//! AD(responder_cme_pk)
//! AD(initiator_cme_pk)
//! AD(prologue)
//! send_clr(ct_cme_r)           // msg1[0..208]
//! KEY(ss_cme_r)
//! send_enc(init_mlkem_eph_pk)   // msg1[208..1776]
//! send_mac(16)                  // msg1[1776..1792]
//! recv_enc(ct_mlkem_eph)        // msg2[0..1568]
//! KEY(ss_mlkem)
//! recv_enc(ct_cme_i)            // msg2[1568..1776]
//! KEY(ss_cme_i)
//! recv_mac(16)                  // msg2[1776..1792]
//! ```

use crate::kem::ClassicMcEliece;
use crate::kem::MlKem;
use crate::kem::PublicKey as ClassicMcEliecePublicKey;
use crate::kem::SecretKey as ClassicMcElieceSecretKey;
use crate::strobe::Strobe;
use crate::strobe::transport_nk::MAC_LEN;
use crate::strobe::transport_nk::Role;
use crate::strobe::transport_nk::StrobeNkTransport;
use crate::strobe::transport_nk::hybrid::CME_CT_LEN;

const MLKEM_PK_LEN: usize = 1568;
const MLKEM_CT_LEN: usize = 1568;

/// Length of the first handshake message (initiator → responder).
/// CME ciphertext (208) + ML-KEM-1024 ephemeral pk (1568) + MAC (16).
pub const KK_PQC_MSG1_LEN: usize = CME_CT_LEN + MLKEM_PK_LEN + MAC_LEN; // 1792

/// Length of the second handshake message (responder → initiator).
/// ML-KEM-1024 ciphertext (1568) + CME ciphertext to initiator (208) + MAC (16).
pub const KK_PQC_MSG2_LEN: usize = MLKEM_CT_LEN + CME_CT_LEN + MAC_LEN; // 1792

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature = "std", error("CME encapsulation failed"))]
    CmeEncapsulate,
    #[cfg_attr(feature = "std", error("CME decapsulation failed"))]
    CmeDecapsulate,
    #[cfg_attr(feature = "std", error("ML-KEM encapsulation failed"))]
    MlKemEncapsulate,
    #[cfg_attr(feature = "std", error("ML-KEM decapsulation failed"))]
    MlKemDecapsulate,
    #[cfg_attr(feature = "std", error("MAC verification failed"))]
    MacFailed,
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::CmeEncapsulate => f.write_str("CME encapsulation failed"),
            Error::CmeDecapsulate => f.write_str("CME decapsulation failed"),
            Error::MlKemEncapsulate => f.write_str("ML-KEM encapsulation failed"),
            Error::MlKemDecapsulate => f.write_str("ML-KEM decapsulation failed"),
            Error::MacFailed => f.write_str("MAC verification failed"),
        }
    }
}

/// Reusable initiator config for the Strobe KK fully-PQC handshake.
///
/// 1. Call `StrobeKkPqcInitiator::new(responder_cme_pk, initiator_cme_pk, initiator_sk)`.
/// 2. Call `.initiate(prologue, out)` — encapsulates to the responder, writes
///    **msg1** into `out`, and returns a `StrobeKkPqcHandshake`.
/// 3. Send `out` to the responder and receive **msg2**.
/// 4. Call `.finish(msg2)` on the handshake — returns a `StrobeNkTransport`.
pub struct StrobeKkPqcInitiator {
    state: Strobe,
    responder_cme_pk: ClassicMcEliecePublicKey,
    initiator_sk: ClassicMcElieceSecretKey,
}

impl StrobeKkPqcInitiator {
    pub fn new(
        responder_cme_pk: &ClassicMcEliecePublicKey,
        initiator_cme_pk: &ClassicMcEliecePublicKey,
        initiator_sk: ClassicMcElieceSecretKey,
    ) -> Self {
        let mut state = Strobe::new(b"StrobeKK_CME8192128_MLKEM1024/v1");
        state.ad(responder_cme_pk.as_ref(), false);
        state.ad(initiator_cme_pk.as_ref(), false);
        Self { state, responder_cme_pk: responder_cme_pk.clone(), initiator_sk }
    }

    /// Builds msg1 into `out` (must be exactly `KK_PQC_MSG1_LEN` bytes).
    pub fn initiate(
        &self,
        prologue: impl AsRef<[u8]>,
        out: &mut [u8; KK_PQC_MSG1_LEN],
    ) -> Result<StrobeKkPqcHandshake, Error> {
        let mut state = self.state.clone();
        state.ad(prologue.as_ref(), false);

        // CME encapsulate to responder's static pk.
        let (ct_cme, ss_cme) = ClassicMcEliece::encapsulate(&self.responder_cme_pk)
            .map_err(|_| Error::CmeEncapsulate)?;
        out[..CME_CT_LEN].copy_from_slice(ct_cme.as_ref());
        state.send_clr(&out[..CME_CT_LEN], false);
        state.key(ss_cme.as_ref());

        // ML-KEM-1024 ephemeral keypair — pk encrypted into msg1.
        let (mlkem_eph_pk, mlkem_eph_sk) = MlKem::keypair()
            .map_err(|_| Error::MlKemEncapsulate)?;
        let pk_range = CME_CT_LEN..CME_CT_LEN + MLKEM_PK_LEN;
        out[pk_range.clone()].copy_from_slice(mlkem_eph_pk.as_ref());
        state.send_enc(&mut out[pk_range], false);
        state.send_mac(&mut out[CME_CT_LEN + MLKEM_PK_LEN..KK_PQC_MSG1_LEN], false);

        Ok(StrobeKkPqcHandshake {
            state,
            mlkem_eph_sk,
            initiator_sk: self.initiator_sk.clone(),
        })
    }
}

/// In-progress KK PQC handshake — holds the ephemeral and static keys until msg2 arrives.
pub struct StrobeKkPqcHandshake {
    state: Strobe,
    mlkem_eph_sk: ClassicMcElieceSecretKey,
    initiator_sk: ClassicMcElieceSecretKey,
}

impl StrobeKkPqcHandshake {
    /// Processes msg2 and returns the derived `StrobeNkTransport`.
    pub fn finish(mut self, msg2: &[u8; KK_PQC_MSG2_LEN]) -> Result<StrobeNkTransport, Error> {
        // Decrypt the ML-KEM ciphertext from msg2.
        let mut ct_mlkem_buf = [0u8; MLKEM_CT_LEN];
        ct_mlkem_buf.copy_from_slice(&msg2[..MLKEM_CT_LEN]);
        self.state.recv_enc(&mut ct_mlkem_buf, false);

        let ct_mlkem = MlKem::ciphertext_from_bytes(&ct_mlkem_buf)
            .ok_or(Error::MlKemDecapsulate)?;
        let ss_mlkem = MlKem::decapsulate(&self.mlkem_eph_sk, &ct_mlkem)
            .map_err(|_| Error::MlKemDecapsulate)?;
        self.state.key(ss_mlkem.as_ref());

        // Decrypt the CME ciphertext encapsulated to the initiator's static pk.
        let mut ct_cme_buf = [0u8; CME_CT_LEN];
        ct_cme_buf.copy_from_slice(&msg2[MLKEM_CT_LEN..MLKEM_CT_LEN + CME_CT_LEN]);
        self.state.recv_enc(&mut ct_cme_buf, false);

        let ct_cme_i = ClassicMcEliece::ciphertext_from_bytes(&ct_cme_buf)
            .ok_or(Error::CmeDecapsulate)?;
        let ss_cme_i = ClassicMcEliece::decapsulate(&self.initiator_sk, &ct_cme_i)
            .map_err(|_| Error::CmeDecapsulate)?;
        self.state.key(ss_cme_i.as_ref());

        // Verify MAC (covers everything up to and including KEY(ss_cme_i)).
        let mut mac_buf = [0u8; MAC_LEN];
        mac_buf.copy_from_slice(&msg2[MLKEM_CT_LEN + CME_CT_LEN..]);
        self.state.recv_mac(&mut mac_buf, false).map_err(|_| Error::MacFailed)?;

        Ok(StrobeNkTransport::from_handshake(self.state, Role::Initiator))
    }
}

/// Responder side of the Strobe KK fully-PQC handshake.
///
/// 1. Call `StrobeKkPqcResponder::new(responder_sk, responder_pk, initiator_pk)`.
/// 2. Receive **msg1** from the initiator.
/// 3. Call `.respond(prologue, msg1, out)` — verifies msg1, builds **msg2** in `out`,
///    and returns a `StrobeNkTransport`.
pub struct StrobeKkPqcResponder {
    state: Strobe,
    responder_sk: ClassicMcElieceSecretKey,
    initiator_pk: ClassicMcEliecePublicKey,
}

impl StrobeKkPqcResponder {
    pub fn new(
        responder_sk: ClassicMcElieceSecretKey,
        responder_pk: &ClassicMcEliecePublicKey,
        initiator_pk: ClassicMcEliecePublicKey,
    ) -> Self {
        let mut state = Strobe::new(b"StrobeKK_CME8192128_MLKEM1024/v1");
        state.ad(responder_pk.as_ref(), false);
        state.ad(initiator_pk.as_ref(), false);
        Self { state, responder_sk, initiator_pk }
    }

    /// Processes msg1, builds msg2 into `out`.
    pub fn respond(
        &self,
        prologue: impl AsRef<[u8]>,
        msg1: &[u8; KK_PQC_MSG1_LEN],
        out: &mut [u8; KK_PQC_MSG2_LEN],
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

        // Decrypt the initiator's ephemeral ML-KEM public key.
        let mut pk_buf = [0u8; MLKEM_PK_LEN];
        pk_buf.copy_from_slice(&msg1[CME_CT_LEN..CME_CT_LEN + MLKEM_PK_LEN]);
        state.recv_enc(&mut pk_buf, false);

        // Verify initiator's MAC.
        let mut mac_buf = [0u8; MAC_LEN];
        mac_buf.copy_from_slice(&msg1[CME_CT_LEN + MLKEM_PK_LEN..]);
        state.recv_mac(&mut mac_buf, false).map_err(|_| Error::MacFailed)?;

        // Encapsulate to the initiator's ephemeral ML-KEM pk and encrypt ct into msg2.
        let mlkem_eph_pk = MlKem::public_key_from_bytes(&pk_buf)
            .ok_or(Error::MlKemEncapsulate)?;
        let (ct_mlkem, ss_mlkem) = MlKem::encapsulate(&mlkem_eph_pk)
            .map_err(|_| Error::MlKemEncapsulate)?;
        out[..MLKEM_CT_LEN].copy_from_slice(ct_mlkem.as_ref());
        state.send_enc(&mut out[..MLKEM_CT_LEN], false);
        state.key(ss_mlkem.as_ref());

        // CME encapsulate to initiator's static pk, encrypt ciphertext into msg2.
        let (ct_cme_i, ss_cme_i) = ClassicMcEliece::encapsulate(&self.initiator_pk)
            .map_err(|_| Error::CmeEncapsulate)?;
        out[MLKEM_CT_LEN..MLKEM_CT_LEN + CME_CT_LEN].copy_from_slice(ct_cme_i.as_ref());
        state.send_enc(&mut out[MLKEM_CT_LEN..MLKEM_CT_LEN + CME_CT_LEN], false);
        state.key(ss_cme_i.as_ref());

        state.send_mac(&mut out[MLKEM_CT_LEN + CME_CT_LEN..KK_PQC_MSG2_LEN], false);

        Ok(StrobeNkTransport::from_handshake(state, Role::Responder))
    }
}
