//! M4b-6 — ctx-template SIMD / FP / crypto lowering.
//!
//! The live lowerer is [`super::lower_int::IntLower`]; it delegates every
//! V-register-numbered SIMD/FP/crypto [`IrOp`] (the `VecBin..CryptoShaR` family)
//! to [`lower`] here. (The older `IrValueId`-keyed `VAdd..FCmp` ops and the
//! `SimdLower` SSA pass are dead and untouched — see BUILDSPEC §0.)
//!
//! ## The ctx-template model (BUILDSPEC §1)
//!
//! The guest q-register file lives in context memory at
//! `[R15 + vec_disp(reg)]` (`runtime::context::VEC_OFFSET = 0x128`, 16 bytes per
//! V-reg) and is **authoritative between ops and between blocks**. Every op is a
//! self-contained template:
//!
//! ```text
//!   movdqu VS0, [R15 + vd(n)]     ; load Vn
//!   movdqu VS1, [R15 + vd(m)]     ; load Vm        (binary)
//!   <sse op(s) on VS0/VS1/VS2/VS3>
//!   ; if D-form (q == false): zero VS0[127:64]
//!   movdqu [R15 + vd(d)], VS0     ; store Vd
//! ```
//!
//! No XMM register allocator is involved — `VS0..VS3` (XMM0..3) are fixed
//! scratch reserved out of allocation (`x86_regs::XMM_ALLOC_FIRST_INDEX`).
//! Unimplemented forms emit `UD2` (fail-loud), exactly like the integer core's
//! `Unimplemented` arm — never a silent wrong answer.

use crate::backend::encode::X86Encoder;
use crate::ir::ops::{VecBinOp, VecCmpOp};
use crate::ir::IrOp;
use crate::regalloc::x86_regs::{VS0, VS1, VS3};
use crate::runtime::context::vec_disp;

/// R15 — the context base register (matches `lower_int::CONTEXT_REG`).
const R15: u8 = 15;

/// size field: 0=B(8) 1=H(16) 2=S(32) 3=D(64).
const B: u8 = 0;
const H: u8 = 1;
const S: u8 = 2;
const D: u8 = 3;

/// Byte displacement of guest V<reg> off R15.
#[inline]
fn vd(reg: u8) -> i32 {
    vec_disp(reg)
}

/// Zero the upper 64 bits of `VS0` when the result is a D-form (`q == false`),
/// implementing ARM's "writes to Dd zero V[127:64]" rule. `movq xmm,xmm`
/// (F3 0F 7E) copies the low 64 and zeroes the high 64 in one instruction.
#[inline]
fn dform_fixup(enc: &mut X86Encoder, q: bool) {
    if !q {
        enc.emit_movq_xmm_xmm(VS0, VS0);
    }
}

/// Lower one V-register-numbered SIMD/FP/crypto op into `enc`. Called from
/// `IntLower::lower_op` for the `VecBin..CryptoShaR` family only.
pub fn lower(op: &IrOp, enc: &mut X86Encoder) {
    match op {
        IrOp::VecBin { op, size, q, d, n, m } => lower_vecbin(enc, *op, *size, *q, *d, *n, *m),
        IrOp::VecCmp { op, size, q, d, n, m } => lower_veccmp(enc, *op, *size, *q, *d, *n, *m),

        // ── Remaining families: scaffolded fail-loud (BUILDSPEC §7, Tier 1). ──
        IrOp::VecUn { .. }
        | IrOp::VecShift { .. }
        | IrOp::VecPair { .. }
        | IrOp::VecReduce { .. }
        | IrOp::VecAddLong { .. }
        | IrOp::VecFp { .. }
        | IrOp::FpFromInt { .. }
        | IrOp::FpToIntR { .. }
        | IrOp::FpRound { .. }
        | IrOp::FpCvt2 { .. }
        | IrOp::FpMov { .. }
        | IrOp::FpBin { .. }
        | IrOp::FpUn { .. }
        | IrOp::FpCmpN { .. }
        | IrOp::FpToGpr { .. }
        | IrOp::FpFromGpr { .. }
        | IrOp::CryptoAesR { .. }
        | IrOp::CryptoShaR { .. } => enc.emit_ud2(),

        // Not a ctx-template op — should never be routed here.
        _ => enc.emit_ud2(),
    }
}

/// NEON integer 3-same binary (`VecBin`). Operands load into VS0 (Vn) / VS1
/// (Vm); the result lands in VS0; D-form zeroes the upper 64 before the store.
fn lower_vecbin(enc: &mut X86Encoder, op: VecBinOp, size: u8, q: bool, d: u8, n: u8, m: u8) {
    use VecBinOp::*;

    // Logical forms are size-agnostic and some need operand reordering, so they
    // are handled before the generic load.
    match op {
        And => {
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_movdqu_load(VS1, R15, vd(m));
            enc.emit_pand(VS0, VS1);
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
            return;
        }
        Or => {
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_movdqu_load(VS1, R15, vd(m));
            enc.emit_por(VS0, VS1);
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
            return;
        }
        Eor => {
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_movdqu_load(VS1, R15, vd(m));
            enc.emit_pxor(VS0, VS1);
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
            return;
        }
        Bic => {
            // Vd = Vn AND NOT Vm. PANDN dst,src = (~dst) & src.
            // Load VS0 = Vm, VS1 = Vn → pandn VS0,VS1 = (~Vm) & Vn = Vn & ~Vm.
            enc.emit_movdqu_load(VS0, R15, vd(m));
            enc.emit_movdqu_load(VS1, R15, vd(n));
            enc.emit_pandn(VS0, VS1);
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
            return;
        }
        Orn => {
            // Vd = Vn OR NOT Vm. ~Vm via XOR with all-ones, then OR Vn.
            enc.emit_movdqu_load(VS0, R15, vd(m));
            enc.emit_pcmpeqd(VS3, VS3); // all-ones
            enc.emit_pxor(VS0, VS3); // ~Vm
            enc.emit_movdqu_load(VS1, R15, vd(n));
            enc.emit_por(VS0, VS1);
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
            return;
        }
        _ => {}
    }

    // Arithmetic / min-max: load Vn into VS0, Vm into VS1.
    enc.emit_movdqu_load(VS0, R15, vd(n));
    enc.emit_movdqu_load(VS1, R15, vd(m));

    let mut handled = true;
    match op {
        Add => match size {
            B => enc.emit_paddb(VS0, VS1),
            H => enc.emit_paddw(VS0, VS1),
            S => enc.emit_paddd(VS0, VS1),
            D => enc.emit_paddq(VS0, VS1),
            _ => handled = false,
        },
        Sub => match size {
            B => enc.emit_psubb(VS0, VS1),
            H => enc.emit_psubw(VS0, VS1),
            S => enc.emit_psubd(VS0, VS1),
            D => enc.emit_psubq(VS0, VS1),
            _ => handled = false,
        },
        Mul => match size {
            H => enc.emit_pmullw(VS0, VS1),
            S => enc.emit_pmulld(VS0, VS1),
            _ => handled = false, // B needs widen-pack; D not encodable — Tier 1.
        },
        SMax => match size {
            B => enc.emit_pmaxsb(VS0, VS1),
            H => enc.emit_pmaxsw(VS0, VS1),
            S => enc.emit_pmaxsd(VS0, VS1),
            _ => handled = false,
        },
        SMin => match size {
            B => enc.emit_pminsb(VS0, VS1),
            H => enc.emit_pminsw(VS0, VS1),
            S => enc.emit_pminsd(VS0, VS1),
            _ => handled = false,
        },
        UMax => match size {
            B => enc.emit_pmaxub(VS0, VS1),
            H => enc.emit_pmaxuw(VS0, VS1),
            S => enc.emit_pmaxud(VS0, VS1),
            _ => handled = false,
        },
        UMin => match size {
            B => enc.emit_pminub(VS0, VS1),
            H => enc.emit_pminuw(VS0, VS1),
            S => enc.emit_pminud(VS0, VS1),
            _ => handled = false,
        },
        // Saturating / halving / abd / mla / mls — Tier 1 (BUILDSPEC §7.1).
        _ => handled = false,
    }

    if !handled {
        enc.emit_ud2();
        return;
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON integer compare (`VecCmp`) — per-lane all-ones / zero result to vd(d)
/// (BUILDSPEC §7.2). Eq/SGt/SGe are exact via PCMPEQ/PCMPGT (size 3 uses the
/// SSE4.1 q-forms). CMHI/CMHS (unsigned) need the sign-bias trick — the
/// adversarially-flagged #1 risk — and are deferred to the Tier-1 fill
/// (fail-loud UD2 here, never a silent wrong answer).
fn lower_veccmp(enc: &mut X86Encoder, op: VecCmpOp, size: u8, q: bool, d: u8, n: u8, m: u8) {
    use VecCmpOp::*;

    /// PCMPEQ{B,W,D,Q} by size. Returns false for an unencodable size.
    fn pcmpeq(enc: &mut X86Encoder, size: u8, a: u8, b: u8) -> bool {
        match size {
            0 => enc.emit_pcmpeqb(a, b),
            1 => enc.emit_pcmpeqw(a, b),
            2 => enc.emit_pcmpeqd(a, b),
            3 => enc.emit_pcmpeqq(a, b),
            _ => return false,
        }
        true
    }
    /// PCMPGT{B,W,D,Q} by size (signed). Returns false for an unencodable size.
    fn pcmpgt(enc: &mut X86Encoder, size: u8, a: u8, b: u8) -> bool {
        match size {
            0 => enc.emit_pcmpgtb(a, b),
            1 => enc.emit_pcmpgtw(a, b),
            2 => enc.emit_pcmpgtd(a, b),
            3 => enc.emit_pcmpgtq(a, b),
            _ => return false,
        }
        true
    }

    enc.emit_movdqu_load(VS0, R15, vd(n)); // a
    enc.emit_movdqu_load(VS1, R15, vd(m)); // b

    let ok = match op {
        Eq => pcmpeq(enc, size, VS0, VS1), // a == b  -> VS0
        SGt => pcmpgt(enc, size, VS0, VS1), // a >  b  -> VS0
        SGe => {
            // a >= b  ==  ~(b > a). Compute (b > a) into VS1, invert, copy to VS0.
            if pcmpgt(enc, size, VS1, VS0) {
                enc.emit_pcmpeqd(VS3, VS3); // all-ones
                enc.emit_pxor(VS1, VS3); // ~(b > a) == (a >= b)
                enc.emit_movdqa_rr(VS0, VS1);
                true
            } else {
                false
            }
        }
        // CMHI / CMHS (unsigned) — Tier-1 (sign-bias trick, BUILDSPEC §7.2).
        UGt | UGe => false,
    };

    if !ok {
        enc.emit_ud2();
        return;
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}
