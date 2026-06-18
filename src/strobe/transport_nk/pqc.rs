//! Strobe NK fully-PQC transport: Classic McEliece 8192128f (static server key)
//! + ML-KEM-1024 (ephemeral forward-secrecy key, no classical component).
//!
//! Protocol string: `"StrobeNK_CME8192128_MLKEM1024/v1"`
//!
//! Handshake layout
//! ────────────────
//!
//! **msg1** (initiator → responder, PQC_MSG1_LEN bytes):
//! ```text
//! | CME ciphertext (208 B) | ML-KEM-1024 ephemeral pk (1568 B) | MAC (32 B) |
//! ```
//!
//! **msg2** (responder → initiator, PQC_MSG2_LEN bytes):
//! ```text
//! | ML-KEM-1024 ciphertext (1568 B) | MAC (32 B) |
//! ```
//!
//! Transcript (initiator side):
//! ```text
//! STROBE("StrobeNK_CME8192128_MLKEM1024/v1")
//! AD(responder_cme_pk)
//! AD(prologue)
//! send_clr(cme_ct)             // msg1[0..208]
//! KEY(ss_cme)
//! send_enc(mlkem_eph_pk)       // msg1[208..1776]
//! send_mac(32)                 // msg1[1776..1808]
//! recv_enc(mlkem_ct)           // msg2[0..1568]
//! KEY(ss_mlkem)
//! recv_mac(32)                 // msg2[1568..1600]
//! ```

use crate::kem::ClassicMcEliece;
use crate::kem::MlKem;
use crate::kem::PublicKey as ClassicMcEliecePublicKey;
use crate::kem::SecretKey as ClassicMcElieceSecretKey;
use crate::strobe::Strobe;
use crate::strobe::transport_nk::MAC_LEN;
use crate::strobe::transport_nk::Role;
use crate::strobe::transport_nk::StrobeNkTransport;

use super::hybrid::CME_CT_LEN;

const MLKEM_PK_LEN: usize = 1568;
const MLKEM_CT_LEN: usize = 1568;

/// Length of the first handshake message (initiator → responder).
/// CME ciphertext (208) + ML-KEM-1024 ephemeral pk (1568) + MAC (32).
pub const PQC_MSG1_LEN: usize = CME_CT_LEN + MLKEM_PK_LEN + MAC_LEN; // 1792

/// Length of the second handshake message (responder → initiator).
/// ML-KEM-1024 ciphertext (1568) + MAC (32).
pub const PQC_MSG2_LEN: usize = MLKEM_CT_LEN + MAC_LEN; // 1584

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

/// Reusable initiator config for the Strobe NK fully-PQC handshake.
///
/// 1. Call `StrobeNkPqcInitiator::new(responder_cme_pk)` — stores the key
///    and pre-initializes the Strobe state with `AD(responder_cme_pk)`.
/// 2. Call `.initiate(prologue, out)` — encapsulates to the responder, writes
///    **msg1** into `out`, and returns a `StrobeNkPqcHandshake`.
/// 3. Send `out` to the responder and receive **msg2**.
/// 4. Call `.finish(msg2)` on the handshake — returns a `StrobeNkTransport`.
pub struct StrobeNkPqcInitiator {
    state: Strobe,
    cme: ClassicMcEliece,
    mlkem: MlKem,
    responder_cme_pk: ClassicMcEliecePublicKey,
}

impl StrobeNkPqcInitiator {
    pub fn new(responder_cme_pk: &ClassicMcEliecePublicKey) -> Self {
        let mut state = Strobe::new(b"StrobeNK_CME8192128_MLKEM1024/v1");
        state.ad(responder_cme_pk.as_ref(), false);
        Self {
            state,
            cme: ClassicMcEliece::new(),
            mlkem: MlKem::new(),
            responder_cme_pk: responder_cme_pk.clone(),
        }
    }

    /// Builds msg1 into `out` (must be exactly `PQC_MSG1_LEN` bytes).
    pub fn initiate(
        &self,
        prologue: impl AsRef<[u8]>,
        out: &mut [u8; PQC_MSG1_LEN],
    ) -> Result<StrobeNkPqcHandshake, Error> {
        let mut state = self.state.clone();
        state.ad(prologue.as_ref(), false);

        // CME encapsulate.
        let (ct_cme, ss_cme) = self
            .cme
            .encapsulate(&self.responder_cme_pk)
            .map_err(|_| Error::CmeEncapsulate)?;
        out[..CME_CT_LEN].copy_from_slice(ct_cme.as_ref());
        state.send_clr(&out[..CME_CT_LEN], false);
        state.key(ss_cme.as_ref());

        // ML-KEM-1024 ephemeral keypair — pk is encrypted into msg1.
        let (mlkem_eph_pk, mlkem_eph_sk) =
            self.mlkem.keypair().map_err(|_| Error::MlKemEncapsulate)?;
        let pk_range = CME_CT_LEN..CME_CT_LEN + MLKEM_PK_LEN;
        out[pk_range.clone()].copy_from_slice(mlkem_eph_pk.as_ref());
        state.send_enc(&mut out[pk_range], false);
        state.send_mac(&mut out[CME_CT_LEN + MLKEM_PK_LEN..PQC_MSG1_LEN], false);

        Ok(StrobeNkPqcHandshake { state, mlkem_eph_sk })
    }
}

/// In-progress PQC handshake — holds the ML-KEM ephemeral key until msg2 arrives.
pub struct StrobeNkPqcHandshake {
    state: Strobe,
    mlkem_eph_sk: ClassicMcElieceSecretKey,
}

impl StrobeNkPqcHandshake {
    /// Processes msg2 (must be exactly `PQC_MSG2_LEN` bytes) and returns the
    /// derived `StrobeNkTransport`.
    pub fn finish(mut self, msg2: &[u8; PQC_MSG2_LEN]) -> Result<StrobeNkTransport, Error> {
        // Decrypt the ML-KEM ciphertext from msg2.
        let mut ct_buf = [0u8; MLKEM_CT_LEN];
        ct_buf.copy_from_slice(&msg2[..MLKEM_CT_LEN]);
        self.state.recv_enc(&mut ct_buf, false);

        // ML-KEM decapsulate with our ephemeral secret key.
        let mlkem = MlKem::new();
        let ct_mlkem = mlkem
            .ciphertext_from_bytes(&ct_buf)
            .map_err(|_| Error::MlKemDecapsulate)?;
        let ss_mlkem = mlkem
            .decapsulate(&self.mlkem_eph_sk, &ct_mlkem)
            .map_err(|_| Error::MlKemDecapsulate)?;
        self.state.key(ss_mlkem.as_ref());

        // Verify MAC (covers everything up to and including KEY(ss_mlkem)).
        let mut mac_buf = [0u8; MAC_LEN];
        mac_buf.copy_from_slice(&msg2[MLKEM_CT_LEN..]);
        self.state.recv_mac(&mut mac_buf, false).map_err(|_| Error::MacFailed)?;

        Ok(StrobeNkTransport::from_handshake(self.state, Role::Initiator))
    }
}

/// Responder side of the Strobe NK fully-PQC handshake.
///
/// 1. Call `StrobeNkPqcResponder::new(sk, pk)`.
/// 2. Receive **msg1** from the initiator.
/// 3. Call `.respond(prologue, msg1, out)` — verifies msg1, builds **msg2** in `out`,
///    and returns a `StrobeNkTransport`.
pub struct StrobeNkPqcResponder {
    state: Strobe,
    cme: ClassicMcEliece,
    mlkem: MlKem,
    sk: ClassicMcElieceSecretKey,
}

impl StrobeNkPqcResponder {
    pub fn new(sk: ClassicMcElieceSecretKey, pk: &ClassicMcEliecePublicKey) -> Self {
        let mut state = Strobe::new(b"StrobeNK_CME8192128_MLKEM1024/v1");
        state.ad(pk.as_ref(), false);
        Self { state, cme: ClassicMcEliece::new(), mlkem: MlKem::new(), sk }
    }

    /// Processes msg1, builds msg2 into `out`.
    pub fn respond(
        &self,
        prologue: impl AsRef<[u8]>,
        msg1: &[u8; PQC_MSG1_LEN],
        out: &mut [u8; PQC_MSG2_LEN],
    ) -> Result<StrobeNkTransport, Error> {
        let mut state = self.state.clone();
        state.ad(prologue.as_ref(), false);

        // CME ciphertext arrives in the clear.
        state.recv_clr(&msg1[..CME_CT_LEN], false);
        let ct_cme = self
            .cme
            .ciphertext_from_bytes(&msg1[..CME_CT_LEN])
            .map_err(|_| Error::CmeDecapsulate)?;
        let ss_cme = self
            .cme
            .decapsulate(&self.sk, &ct_cme)
            .map_err(|_| Error::CmeDecapsulate)?;
        state.key(ss_cme.as_ref());

        // Decrypt the initiator's ephemeral ML-KEM public key.
        let mut pk_buf = [0u8; MLKEM_PK_LEN];
        pk_buf.copy_from_slice(&msg1[CME_CT_LEN..CME_CT_LEN + MLKEM_PK_LEN]);
        state.recv_enc(&mut pk_buf, false);

        // Verify initiator's MAC.
        let mut mac_buf = [0u8; MAC_LEN];
        mac_buf.copy_from_slice(&msg1[CME_CT_LEN + MLKEM_PK_LEN..]);
        state.recv_mac(&mut mac_buf, false).map_err(|_| Error::MacFailed)?;

        // Encapsulate to the initiator's ephemeral ML-KEM public key.
        let mlkem_eph_pk = self
            .mlkem
            .public_key_from_bytes(&pk_buf)
            .map_err(|_| Error::MlKemEncapsulate)?;
        let (ct_mlkem, ss_mlkem) = self
            .mlkem
            .encapsulate(&mlkem_eph_pk)
            .map_err(|_| Error::MlKemEncapsulate)?;

        // Encrypt ML-KEM ciphertext into msg2, then key() and MAC.
        out[..MLKEM_CT_LEN].copy_from_slice(ct_mlkem.as_ref());
        state.send_enc(&mut out[..MLKEM_CT_LEN], false);
        state.key(ss_mlkem.as_ref());
        state.send_mac(&mut out[MLKEM_CT_LEN..PQC_MSG2_LEN], false);

        Ok(StrobeNkTransport::from_handshake(state, Role::Responder))
    }
}
