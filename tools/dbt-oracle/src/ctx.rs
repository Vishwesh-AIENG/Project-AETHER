//! Shared flat-context layout + seed/readback helpers.
//!
//! This mirrors the `ctx = [u64; CTX_U64S]` buffer layout used by
//! `aether-translator/tests/at_exec_proof.rs` and
//! `aether_translator::runtime::context`. Both the DBT side and the reference
//! side seed and read back state through this same `OracleState` so a mismatch
//! is a true value divergence, not a layout artefact.
//!
//! Layout (bytes, from runtime/context.rs):
//! ```text
//!   0x000  x0..x30        (31 * 8)
//!   0x0F8  sp
//!   0x100  pc
//!   0x108  nzcv           (ARM N@31 Z@30 C@29 V@28)
//!   0x110  _pad (3*8)
//!   0x128  q0..q31        (32 * 16)  -- vec_disp(r) = 0x128 + r*16
//!   0x328  sysreg[0..64]  (SYSREG_BASE; SLOT_SCTLR = idx 0)
//!   0x528  spill[0..64]
//!   0x728  end            (CTX_U64S = 229 u64 slots)
//! ```

use aether_translator::runtime::context::vec_disp;

/// Total extended-context size in u64 slots (GuestRegisterFile + sysreg + spill).
pub const CTX_U64S: usize = 0x728 / 8; // 229
/// u64 slot of x0 (GPR_OFFSET = 0).
pub const GPR_SLOT0: usize = 0x000 / 8; // 0
/// u64 slot of SP.
pub const SP_SLOT: usize = 0x0F8 / 8; // 31
/// u64 slot of NZCV.
pub const NZCV_SLOT: usize = 0x108 / 8; // 33

/// The full architectural state we seed / read back / diff.
///
/// V-registers are stored as `[u64; 2]` (lo64, hi64) exactly like
/// `GuestRegisterFile::vec` so the two sides use one canonical form.
#[derive(Clone, PartialEq, Eq)]
pub struct OracleState {
    /// x0..x30.
    pub gpr: [u64; 31],
    /// Stack pointer.
    pub sp: u64,
    /// NZCV in bits [31:28].
    pub nzcv: u64,
    /// q0..q31 as [lo64, hi64].
    pub vec: [[u64; 2]; 32],
}

impl OracleState {
    pub fn zeroed() -> Self {
        Self { gpr: [0; 31], sp: 0, nzcv: 0, vec: [[0; 2]; 32] }
    }

    /// Read a V register as a u128 (lo | hi<<64).
    pub fn vec_u128(&self, r: usize) -> u128 {
        (self.vec[r][0] as u128) | ((self.vec[r][1] as u128) << 64)
    }

    /// Write a V register from a u128.
    pub fn set_vec_u128(&mut self, r: usize, v: u128) {
        self.vec[r][0] = v as u64;
        self.vec[r][1] = (v >> 64) as u64;
    }

    /// Materialise this state into a flat `ctx` buffer (the R15 base the DBT
    /// reads). Leaves sysregs zeroed EXCEPT what the caller sets afterwards
    /// (e.g. SLOT_SCTLR stays 0 => flat/MMU-off memory path).
    pub fn write_ctx(&self, ctx: &mut [u64]) {
        assert!(ctx.len() >= CTX_U64S);
        for i in 0..31 {
            ctx[GPR_SLOT0 + i] = self.gpr[i];
        }
        ctx[SP_SLOT] = self.sp;
        ctx[NZCV_SLOT] = self.nzcv;
        for r in 0..32 {
            let byte = vec_disp(r as u8) as usize; // 0x128 + r*16
            let slot = byte / 8;
            ctx[slot] = self.vec[r][0];
            ctx[slot + 1] = self.vec[r][1];
        }
    }

    /// Read state back out of a flat `ctx` buffer after the DBT block ran.
    pub fn read_ctx(ctx: &[u64]) -> Self {
        assert!(ctx.len() >= CTX_U64S);
        let mut s = Self::zeroed();
        for i in 0..31 {
            s.gpr[i] = ctx[GPR_SLOT0 + i];
        }
        s.sp = ctx[SP_SLOT];
        s.nzcv = ctx[NZCV_SLOT];
        for r in 0..32 {
            let byte = vec_disp(r as u8) as usize;
            let slot = byte / 8;
            s.vec[r][0] = ctx[slot];
            s.vec[r][1] = ctx[slot + 1];
        }
        s
    }
}
