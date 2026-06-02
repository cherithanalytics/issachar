//! Strobe v1.0.2 — duplex-sponge protocol framework.
//!
//! Based on the StrobeGo reference implementation by David Wong.
//! Uses Keccak-f\[1600\] via `keccak::Keccak::with_f1600`.

pub mod transport_kk;
pub mod transport_nk;

use keccak::Keccak;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

// ── Operation flags ────────────────────────────────────────────────────────
pub const FLAG_I: u8 = 1 << 0; // Inbound
pub const FLAG_A: u8 = 1 << 1; // Application
pub const FLAG_C: u8 = 1 << 2; // Cipher (XOR with sponge state)
pub const FLAG_T: u8 = 1 << 3; // Transport
pub const FLAG_M: u8 = 1 << 4; // Meta
pub const FLAG_K: u8 = 1 << 5; // Key material

const STATE_BYTES: usize = 200; // 25 * 8 = 1600 bits
const STROBE_R: usize = 134; // StrobeR for 256-bit security: duplexRate(136) - 2

// Domain prefix written into the state before the first permutation.
// Layout: [1, duplexRate, 1, 0, 1, len("STROBEv1.0.2")*8] || "STROBEv1.0.2"
// duplexRate = 136 = 0x88; 12*8 = 96 = 0x60; "STROBEv1.0.2" = 53 54 52 4f 42 45 76 31 2e 30 2e 32
const DOMAIN_PREFIX: [u8; 18] = [
    0x01, 0x88, 0x01, 0x00, 0x01, 0x60, 0x53, 0x54, 0x52, 0x4f, 0x42, 0x45, 0x76, 0x31, 0x2e, 0x30,
    0x2e, 0x32,
];

// ── Role ───────────────────────────────────────────────────────────────────

/// Which side sent the first transport message.
/// The discriminant matches the FLAG_I bit that was set (or absent) on that
/// first transport operation, so it can be XOR'd directly into flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Initiator = 0,
    Responder = 1, // FLAG_I
}

// ── Error ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StrobeError {
    #[error("MAC verification failed")]
    MacVerificationFailed,
}

// ── Core struct ────────────────────────────────────────────────────────────

/// Strobe v1.0.2 duplex-sponge protocol framework.
///
/// All cryptographic state is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Strobe {
    state: [u8; STATE_BYTES],
    pos: usize,
    pos_begin: u8,
    #[zeroize(skip)]
    role: Option<Role>,
}

impl Strobe {
    /// Initialize a new Strobe instance for `proto` at 256-bit security.
    pub fn new(proto: &[u8]) -> Self {
        let mut state = [0u8; STATE_BYTES];
        state[..DOMAIN_PREFIX.len()].copy_from_slice(&DOMAIN_PREFIX);

        let mut s = Self { state, pos: 0, pos_begin: 0, role: None };
        // StrobeGo's init runs duplex(domain, false, false, forceF=true) while
        // `initialized=false`.  In that mode runF skips Strobe padding entirely
        // (no posBegin / 0x04 / 0x80 markers) and just XORs the buffered bytes
        // into the keccak state and permutes.  Domain bytes are already in
        // state[0..18]; the rest of state is zero, so we can permute directly.
        s.permute_raw();
        s.pos = 0;
        s.pos_begin = 0;

        s.ad(proto, true);
        s
    }

    // ── Internal mechanics ─────────────────────────────────────────────────

    /// Bare Keccak-f[1600] with no Strobe padding.
    /// Used only during initialization (matches StrobeGo's `initialized=false` runF path).
    fn permute_raw(&mut self) {
        let mut words = [0u64; 25];
        for (w, chunk) in words.iter_mut().zip(self.state.chunks_exact(8)) {
            *w = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Keccak::new().with_f1600(|f| f(&mut words));
        for (chunk, &w) in self.state.chunks_exact_mut(8).zip(words.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
    }

    /// Strobe padding + Keccak-f[1600] permutation.
    ///
    /// Padding layout (matching StrobeGo):
    /// - `state[pos]   ^= pos_begin`  at the current position
    /// - `state[pos+1] ^= 0x04`       at pos+1
    /// - `state[r+1]   ^= 0x80`       always at the last reserved byte (duplexRate−1)
    fn run_f(&mut self) {
        self.state[self.pos] ^= self.pos_begin;
        self.state[self.pos + 1] ^= 0x04;
        self.state[STROBE_R + 1] ^= 0x80; // STROBE_R+1 = duplexRate-1, last rate byte
        self.permute_raw();
        self.pos = 0;
        self.pos_begin = 0;
    }

    /// Absorb-only duplex: feeds `data` into the sponge without producing output.
    ///
    /// `cbefore=true` path (KEY, RATCHET): sets `state[pos] = b`, which is
    /// algebraically identical to `state[pos] ^= b ^ state[pos]` but avoids
    /// writing back to `data`.
    fn duplex(&mut self, data: &[u8], cbefore: bool, force_f: bool) {
        for &b in data {
            if self.pos == STROBE_R {
                self.run_f();
            }
            if cbefore {
                self.state[self.pos] = b;
            } else {
                self.state[self.pos] ^= b;
            }
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
        if force_f && self.pos != 0 {
            self.run_f();
        }
    }

    /// Cipher duplex: transforms `data` in place (encrypt, decrypt, or PRF squeeze).
    ///
    /// Unlike `duplex`, the caller always reads the modified bytes back.
    /// `force_f` is not needed here — it is only ever used for operation headers.
    fn duplex_mut(&mut self, data: &mut [u8], cbefore: bool, cafter: bool) {
        for b in data.iter_mut() {
            if self.pos == STROBE_R {
                self.run_f();
            }
            if cbefore {
                *b ^= self.state[self.pos];
            }
            self.state[self.pos] ^= *b;
            if cafter {
                *b = self.state[self.pos];
            }
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// Absorb the 2-byte operation header `[prev_begin, flags]` and advance
    /// the begin-bookmark.
    ///
    /// `force_f` is set whenever `C` or `K` is in flags (per the Strobe spec
    /// and StrobeGo): after every cipher operation header a Keccak permutation
    /// is forced so that subsequent reads/writes see a fully-mixed state.
    /// This is what makes short KEY→PRF correctly key-dependent.
    fn begin_op(&mut self, flags: u8) {
        let mut flags = flags;
        if flags & FLAG_T != 0 {
            let role = *self.role.get_or_insert(if flags & FLAG_I != 0 {
                Role::Responder
            } else {
                Role::Initiator
            });
            flags ^= role as u8;
        }

        let old_begin = self.pos_begin;
        self.pos_begin = (self.pos + 1) as u8;
        let force_f = flags & (FLAG_C | FLAG_K) != 0;
        self.duplex(&[old_begin, flags], false, force_f);
    }

    // ── Public operation dispatcher ────────────────────────────────────────

    /// General-purpose operation dispatcher (used by the test harness).
    ///
    /// Routes to `duplex_mut` when the caller needs output (cafter, or cbefore
    /// with FLAG_I set); falls back to `duplex` for absorb-only operations.
    pub fn operate(&mut self, meta: bool, flags: u8, data: &mut [u8], more: bool) {
        let mut flags = flags;
        if meta {
            flags |= FLAG_M;
        }

        let cafter = (flags & (FLAG_C | FLAG_I | FLAG_T)) == (FLAG_C | FLAG_T);
        let cbefore = (flags & FLAG_C != 0) && !cafter;

        if !more {
            self.begin_op(flags);
        }

        if cafter || (cbefore && flags & FLAG_I != 0) {
            self.duplex_mut(data, cbefore, cafter);
        } else {
            self.duplex(data, cbefore, false);
        }
    }

    // ── High-level API ─────────────────────────────────────────────────────

    pub fn ad(&mut self, data: &[u8], meta: bool) {
        let flags = FLAG_A | if meta { FLAG_M } else { 0 };
        self.begin_op(flags);
        self.duplex(data, false, false);
    }

    pub fn key(&mut self, data: &[u8]) {
        self.begin_op(FLAG_A | FLAG_C);
        self.duplex(data, true, false);
    }

    pub fn prf(&mut self, data: &mut [u8]) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C);
        self.duplex_mut(data, true, false);
    }

    pub fn send_clr(&mut self, data: &[u8], meta: bool) {
        let flags = FLAG_A | FLAG_T | if meta { FLAG_M } else { 0 };
        self.begin_op(flags);
        self.duplex(data, false, false);
    }

    pub fn recv_clr(&mut self, data: &[u8], meta: bool) {
        let flags = FLAG_I | FLAG_A | FLAG_T | if meta { FLAG_M } else { 0 };
        self.begin_op(flags);
        self.duplex(data, false, false);
    }

    pub fn send_enc(&mut self, data: &mut [u8], meta: bool) {
        let flags = FLAG_A | FLAG_C | FLAG_T | if meta { FLAG_M } else { 0 };
        self.begin_op(flags);
        self.duplex_mut(data, false, true);
    }

    pub fn recv_enc(&mut self, data: &mut [u8], meta: bool) {
        let flags = FLAG_I | FLAG_A | FLAG_C | FLAG_T | if meta { FLAG_M } else { 0 };
        self.begin_op(flags);
        self.duplex_mut(data, true, false);
    }

    pub fn send_mac(&mut self, data: &mut [u8], meta: bool) {
        let flags = FLAG_C | FLAG_T | if meta { FLAG_M } else { 0 };
        self.begin_op(flags);
        self.duplex_mut(data, false, true);
    }

    /// Verify a received MAC tag.  Comparison is constant-time.
    pub fn recv_mac<const N: usize>(&mut self, data: &mut [u8; N], meta: bool) -> Result<(), StrobeError> {
        let flags = FLAG_I | FLAG_C | FLAG_T | if meta { FLAG_M } else { 0 };
        self.begin_op(flags);
        self.duplex_mut(data, true, false);
        if crate::timing_safe_eq(data, &[0u8; N]) {
            Ok(())
        } else {
            Err(StrobeError::MacVerificationFailed)
        }
    }

    pub fn ratchet(&mut self, data: &[u8]) {
        self.begin_op(FLAG_C);
        self.duplex(data, true, false);
    }

    // ── State access (for testing / serialization) ─────────────────────────

    /// The full 200-byte Keccak state.  Because this implementation XORs data
    /// into the state immediately (no deferred buffer), the slice is always
    /// up-to-date and matches StrobeGo's `debugPrintState` output.
    pub fn as_bytes(&self) -> &[u8] {
        &self.state
    }

}
