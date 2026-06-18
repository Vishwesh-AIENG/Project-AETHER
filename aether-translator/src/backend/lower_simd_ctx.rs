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
use crate::ir::ops::{VecBinOp, VecCmpOp, VecPairOp};
use crate::ir::IrOp;
use crate::regalloc::x86_regs::{VS0, VS1, VS2, VS3};
use crate::runtime::context::vec_disp;

/// R15 — the context base register (matches `lower_int::CONTEXT_REG`).
const R15: u8 = 15;
/// RAX — a reserved scratch GPR (removed from `ALLOCATABLE_GPRS`, == `lower_int`'s
/// `SCRATCH0`), free to clobber here for building pshufb masks etc.
const RAX: u8 = 0;

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
        IrOp::VecCmpZero { op, size, q, d, n } => lower_veccmpzero(enc, *op, *size, *q, *d, *n),
        IrOp::VecShiftNarrow { d, n, shift, esize_out, high } => {
            lower_vecshiftnarrow(enc, *d, *n, *shift, *esize_out, *high)
        }
        IrOp::VecShiftLong { d, n, shift, esize_in, high, signed } => {
            lower_vecshiftlong(enc, *d, *n, *shift, *esize_in, *high, *signed)
        }
        IrOp::VecExt { d, n, m, imm, q } => lower_vecext(enc, *d, *n, *m, *imm, *q),
        IrOp::VecMulLong { d, n, m, size, q, signed, accum, sub } => {
            lower_vecmullong(enc, *d, *n, *m, *size, *q, *signed, *accum, *sub)
        }
        IrOp::VecRev64 { d, n, size, q, container } => lower_vecrev64(enc, *d, *n, *size, *q, *container),
        IrOp::FpBin { op, dbl, d, n, m } => lower_fpbin(enc, *op, *dbl, *d, *n, *m),
        IrOp::FpCmpN { n, m, dbl, zero } => lower_fpcmpn(enc, *n, *m, *dbl, *zero),
        IrOp::VecPair { op, size, q, d, n, m } => lower_vecpair(enc, *op, *size, *q, *d, *n, *m),
        IrOp::VecAddLongPair { d, n, esize_in, q, signed } => {
            lower_vecaddlongpair(enc, *d, *n, *esize_in, *q, *signed)
        }
        IrOp::VecUnzip { d, n, m, esize, q, odd } => {
            lower_vecunzip(enc, *d, *n, *m, *esize, *q, *odd)
        }

        // ── Remaining families: scaffolded fail-loud (BUILDSPEC §7, Tier 1). ──
        IrOp::VecUn { .. }
        | IrOp::VecShift { .. }
        | IrOp::VecReduce { .. }
        | IrOp::VecAddLong { .. }
        | IrOp::VecFp { .. }
        | IrOp::FpFromInt { .. }
        | IrOp::FpToIntR { .. }
        | IrOp::FpRound { .. }
        | IrOp::FpCvt2 { .. }
        | IrOp::FpMov { .. }
        | IrOp::FpUn { .. }
        | IrOp::FpToGpr { .. }
        | IrOp::FpFromGpr { .. }
        | IrOp::CryptoAesR { .. }
        | IrOp::CryptoShaR { .. } => enc.emit_ud2(),

        // Not a ctx-template op — should never be routed here.
        _ => enc.emit_ud2(),
    }
}

/// NEON compare-against-zero (`CMEQ/… #0`). Only CMEQ is wired (the bionic
/// strchr/memchr need); the signed/unsigned ordered compares fail-loud until
/// their lane semantics land. `pcmpeq Vn, 0` sets each equal lane to all-ones.
fn lower_veccmpzero(enc: &mut X86Encoder, op: VecCmpOp, size: u8, q: bool, d: u8, n: u8) {
    use VecCmpOp::*;
    match op {
        Eq => {
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_pxor(VS1, VS1); // VS1 = 0
            match size {
                B => enc.emit_pcmpeqb(VS0, VS1),
                H => enc.emit_pcmpeqw(VS0, VS1),
                S => enc.emit_pcmpeqd(VS0, VS1),
                _ => enc.emit_pcmpeqq(VS0, VS1), // D
            }
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
        }
        _ => enc.emit_ud2(), // ordered compares vs #0 — Tier 1
    }
}

/// NEON `SHRN` — shift-right-narrow. Only the `.8h → .8b` low form (esize_out=1,
/// high=false) is wired (bionic strchr `shrn v.8b, v.8h, #4`): logical-shift the
/// 8 halfwords right, mask each to its low byte, pack to 8 bytes in Vd[63:0].
fn lower_vecshiftnarrow(enc: &mut X86Encoder, d: u8, n: u8, shift: u8, esize_out: u8, high: bool) {
    // Compute the narrowed `esize_out`-byte result elements into VS0's low 64.
    enc.emit_movdqu_load(VS0, R15, vd(n));
    match esize_out {
        1 => {
            // .8h → .8b: shift words, mask each low byte, pack 8 words → 8 bytes.
            enc.emit_psrlw_imm(VS0, shift);
            enc.emit_pcmpeqw(VS3, VS3);
            enc.emit_psrlw_imm(VS3, 8); // 0x00FF per word
            enc.emit_pand(VS0, VS3);
            enc.emit_packuswb(VS0, VS0);
        }
        4 => {
            // .2d → .2s: shift qwords, gather the two low-32s into the low 64.
            enc.emit_psrlq_imm(VS0, shift);
            enc.emit_pshufd(VS0, VS0, 0x08); // [q0.lo32, q1.lo32, q0.lo32, q0.lo32]
        }
        _ => {
            enc.emit_ud2(); // .4h (esize_out=2) — Tier 1
            return;
        }
    }
    enc.emit_movq_xmm_xmm(VS0, VS0); // keep the low 64, zero the upper
    if high {
        // SHRN2: result → Vd[127:64], preserve Vd[63:0].
        enc.emit_movdqu_load(VS1, R15, vd(d));
        enc.emit_punpcklqdq(VS1, VS0); // [Vd.lo64, result]
        enc.emit_movdqu_store(R15, vd(d), VS1);
    } else {
        // SHRN: result → Vd[63:0], zero Vd[127:64].
        enc.emit_movdqu_store(R15, vd(d), VS0);
    }
}

/// NEON `USHLL`/`SSHLL`/`UXTL`/`SXTL` — shift-left-long (widening). Widen each
/// `esize_in`-byte source element (zero/sign-extend per `signed`) to twice the
/// width, then shift left by `shift`. The result fills the whole 128-bit Vd
/// (always a Q-form `.8h`/`.4s`/`.2d`). `high` selects Vn's high 64 bits (the
/// `2` variants), zero-extended via the `punpckh*` interleave-with-zero idiom.
fn lower_vecshiftlong(
    enc: &mut X86Encoder,
    d: u8,
    n: u8,
    shift: u8,
    esize_in: u8,
    high: bool,
    signed: bool,
) {
    enc.emit_movdqu_load(VS0, R15, vd(n));
    if !high {
        // Low 64 bits → widen the 8/4/2 low elements via pmovzx/pmovsx.
        match (esize_in, signed) {
            (1, false) => enc.emit_pmovzxbw(VS0, VS0),
            (1, true) => enc.emit_pmovsxbw(VS0, VS0),
            (2, false) => enc.emit_pmovzxwd(VS0, VS0),
            (2, true) => enc.emit_pmovsxwd(VS0, VS0),
            (4, false) => enc.emit_pmovzxdq(VS0, VS0),
            (4, true) => enc.emit_pmovsxdq(VS0, VS0),
            _ => { enc.emit_ud2(); return; }
        }
    } else {
        // High 64 bits. `punpckh* VS0, 0` interleaves Vn's high elements with
        // zero bytes — a zero-extending widen of the high half. Sign-extending
        // the high half (SSHLL2) would need psrldq+pmovsx (not wired): fail-loud.
        if signed {
            enc.emit_ud2();
            return;
        }
        enc.emit_pxor(VS1, VS1);
        match esize_in {
            1 => enc.emit_punpckhbw(VS0, VS1),
            2 => enc.emit_punpckhwd(VS0, VS1),
            _ => { enc.emit_ud2(); return; } // .2s→.2d high (esize 4): Tier 1
        }
    }
    if shift > 0 {
        // Shift the widened (2*esize_in-byte) elements left.
        match esize_in {
            1 => enc.emit_psllw_imm(VS0, shift), // 16-bit out
            2 => enc.emit_pslld_imm(VS0, shift), // 32-bit out
            4 => enc.emit_psllq_imm(VS0, shift), // 64-bit out
            _ => {}
        }
    }
    // Result is a full 128-bit Q-form value — no D-form fixup.
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `EXT Vd, Vn, Vm, #imm` — `Vd = (CONCAT(Vm, Vn) >> imm*8)`. `palignr
/// dst, src, imm` computes `(CONCAT(dst, src) >> imm*8)[127:0]` with `dst` the
/// HIGH operand.
fn lower_vecext(enc: &mut X86Encoder, d: u8, n: u8, m: u8, imm: u8, q: bool) {
    if q {
        // .16b: full 32-byte concat Vm:Vn (Vn low). palignr(Vm, Vn, imm) is exact.
        enc.emit_movdqu_load(VS1, R15, vd(m));
        enc.emit_movdqu_load(VS0, R15, vd(n));
        enc.emit_palignr(VS1, VS0, imm);
        enc.emit_movdqu_store(R15, vd(d), VS1);
    } else {
        // .8b: the concat is only the LOW 8 bytes of each source (Vn[0:8]:Vm[0:8]).
        // Build that 16-byte value with punpcklqdq (Vn low, Vm high), then shift it
        // right by imm*8 via palignr against zero; keep the low 8, zero Vd[127:64].
        enc.emit_movdqu_load(VS0, R15, vd(n));
        enc.emit_movdqu_load(VS1, R15, vd(m));
        enc.emit_punpcklqdq(VS0, VS1); // VS0 = [Vn.lo64 | Vm.lo64] = concat8
        enc.emit_pxor(VS1, VS1);
        enc.emit_palignr(VS1, VS0, imm); // (0:concat8) >> imm*8
        enc.emit_movq_xmm_xmm(VS1, VS1); // keep low 64, zero high
        enc.emit_movdqu_store(R15, vd(d), VS1);
    }
}

/// NEON integer multiply-long (`UMULL`/`SMULL`/`UMLAL`/`SMLAL`/`UMLSL`/`SMLSL`).
/// Widen the `size`-byte source elements to 2× (zero/sign-extend), multiply, and
/// (MULL) store / (MLAL) add-to / (MLSL) subtract-from Vd. `q` selects Vn/Vm's
/// HIGH 64 bits (the `2` variant) — brought to the low half with `pshufd`. The
/// widened product fits its 2× element exactly (8×8≤16b, 16×16≤32b), so a single
/// `pmullw`/`pmulld` is exact. Result is a full 128-bit Q-form value.
#[allow(clippy::too_many_arguments)]
fn lower_vecmullong(
    enc: &mut X86Encoder,
    d: u8,
    n: u8,
    m: u8,
    size: u8,
    q: bool,
    signed: bool,
    accum: bool,
    sub: bool,
) {
    enc.emit_movdqu_load(VS0, R15, vd(n));
    enc.emit_movdqu_load(VS1, R15, vd(m));
    if q {
        // `2` variant: move each source's high 64 bits down to the low 64.
        enc.emit_pshufd(VS0, VS0, 0x0E);
        enc.emit_pshufd(VS1, VS1, 0x0E);
    }
    match size {
        B => {
            // .8b → .8h: widen 8 bytes → 8 words, 16-bit multiply (exact for 8×8).
            if signed { enc.emit_pmovsxbw(VS0, VS0); enc.emit_pmovsxbw(VS1, VS1); }
            else { enc.emit_pmovzxbw(VS0, VS0); enc.emit_pmovzxbw(VS1, VS1); }
            enc.emit_pmullw(VS0, VS1);
        }
        H => {
            // .4h → .4s: widen 4 halfwords → 4 dwords, 32-bit multiply.
            if signed { enc.emit_pmovsxwd(VS0, VS0); enc.emit_pmovsxwd(VS1, VS1); }
            else { enc.emit_pmovzxwd(VS0, VS0); enc.emit_pmovzxwd(VS1, VS1); }
            enc.emit_pmulld(VS0, VS1);
        }
        _ => { enc.emit_ud2(); return; } // .2s → .2d (size=2): Tier 1 (needs pmuldq)
    }
    if accum {
        enc.emit_movdqu_load(VS2, R15, vd(d));
        if sub {
            // Vd - products (in VS2), store VS2.
            match size { B => enc.emit_psubw(VS2, VS0), _ => enc.emit_psubd(VS2, VS0) }
            enc.emit_movdqu_store(R15, vd(d), VS2);
            return;
        }
        // Vd + products.
        match size { B => enc.emit_paddw(VS0, VS2), _ => enc.emit_paddd(VS0, VS2) }
    }
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `REV64` — reverse `size`-element groups within each 64-bit lane. Build a
/// per-lane `pshufb` control mask (mask byte i = the source byte index that lands
/// in result byte i), materialize it into VS1 via the reserved scratch GPR, then
/// `pshufb Vn, mask`. `q`=false zeroes Vd[127:64] afterward (.8b/.4h/.2s form).
fn lower_vecrev64(enc: &mut X86Encoder, d: u8, n: u8, size: u8, q: bool, container: u8) {
    // Build the 16-byte pshufb mask: within each `container`-byte group, reverse
    // the order of (1<<size)-byte elements (REV64 container=8, REV32=4, REV16=2).
    // For destination byte i: group g=i/container, in-group offset o=i%container,
    // element index e=o/esize, byte-in-element be=o%esize; reversed element index
    // ne=(container/esize-1-e); source byte = g*container + ne*esize + be.
    let esize = 1usize << size;
    let container = container as usize;
    if esize == 0 || esize >= container || container == 0 || 16 % container != 0 {
        enc.emit_ud2();
        return;
    }
    let mut mask = [0u8; 16];
    let nelem = container / esize;
    for (i, slot) in mask.iter_mut().enumerate() {
        let g = i / container;
        let o = i % container;
        let e = o / esize;
        let be = o % esize;
        let ne = nelem - 1 - e;
        *slot = (g * container + ne * esize + be) as u8;
    }
    let mask_lo = u64::from_le_bytes(mask[0..8].try_into().unwrap());
    let mask_hi = u64::from_le_bytes(mask[8..16].try_into().unwrap());
    enc.emit_movdqu_load(VS0, R15, vd(n));
    enc.emit_mov_r64_imm64(RAX, mask_lo as i64);
    enc.emit_movq_xmm_r64(VS1, RAX);
    enc.emit_mov_r64_imm64(RAX, mask_hi as i64);
    enc.emit_movq_xmm_r64(VS2, RAX);
    enc.emit_punpcklqdq(VS1, VS2); // VS1 = [mask_lo | mask_hi]
    enc.emit_pshufb(VS0, VS1);
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Scalar FP 2-source (`FADD`/`FSUB`/`FMUL`/`FDIV`/`FMIN`/`FMAX`). The scalar
/// lives in the low 32 (S) / 64 (D) bits of the FP reg; `movss`/`movsd` memory
/// loads zero the rest of the XMM, so the result store (movdqu) writes the scalar
/// with the upper lanes cleared — exactly ARM's "write Sd/Dd zeroes V[127:32/64]".
fn lower_fpbin(enc: &mut X86Encoder, op: crate::ir::ops::FpBinOp, dbl: bool, d: u8, n: u8, m: u8) {
    use crate::ir::ops::FpBinOp::*;
    if dbl {
        enc.emit_movsd_load(VS0, R15, vd(n));
        enc.emit_movsd_load(VS1, R15, vd(m));
        match op {
            Add => enc.emit_addsd(VS0, VS1),
            Sub => enc.emit_subsd(VS0, VS1),
            Mul => enc.emit_mulsd(VS0, VS1),
            Div => enc.emit_divsd(VS0, VS1),
            Min => enc.emit_minsd(VS0, VS1),
            Max => enc.emit_maxsd(VS0, VS1),
            NMul => { enc.emit_ud2(); return; } // FNMUL — Tier 1 (needs sign flip)
        }
    } else {
        enc.emit_movss_load(VS0, R15, vd(n));
        enc.emit_movss_load(VS1, R15, vd(m));
        match op {
            Add => enc.emit_addss(VS0, VS1),
            Sub => enc.emit_subss(VS0, VS1),
            Mul => enc.emit_mulss(VS0, VS1),
            Div => enc.emit_divss(VS0, VS1),
            Min => enc.emit_minss(VS0, VS1),
            Max => enc.emit_maxss(VS0, VS1),
            NMul => { enc.emit_ud2(); return; }
        }
    }
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Scalar FP compare (`FCMP`/`FCMPE`, optionally against `#0.0`) → ARM NZCV
/// (packed N@31 Z@30 C@29 V@28 at ctx 0x108). `ucomiss/ucomisd` set x86
/// ZF/PF/CF; the ARM FCMP flag mapping is N=less, Z=equal, C=!less, V=unordered,
/// i.e. N=CF&!PF, Z=ZF&!PF, C=!N, V=PF — built branchless with setcc.
fn lower_fpcmpn(enc: &mut X86Encoder, n: u8, m: u8, dbl: bool, zero: bool) {
    use crate::backend::lower_int::cc;
    const RAX: u8 = 0;
    const RCX: u8 = 1;
    const RDX: u8 = 2;
    const RBX: u8 = 3;
    const NZCV_DISP: i32 = 0x108;
    if dbl {
        enc.emit_movsd_load(VS0, R15, vd(n));
        if zero { enc.emit_pxor(VS1, VS1); } else { enc.emit_movsd_load(VS1, R15, vd(m)); }
        enc.emit_ucomisd(VS0, VS1);
    } else {
        enc.emit_movss_load(VS0, R15, vd(n));
        if zero { enc.emit_pxor(VS1, VS1); } else { enc.emit_movss_load(VS1, R15, vd(m)); }
        enc.emit_ucomiss(VS0, VS1);
    }
    // RBX/RDX are allocatable — save across the flag build (push/pop preserve EFLAGS).
    enc.emit_push_r64(RBX);
    enc.emit_push_r64(RDX);
    enc.emit_setcc_r8(cc::B, RBX); // BL = CF
    enc.emit_setcc_r8(cc::Z, RCX); // CL = ZF
    enc.emit_setcc_r8(cc::P, RDX); // DL = PF (unordered)
    enc.emit_movzx_r64_r8(RBX, RBX);
    enc.emit_movzx_r64_r8(RCX, RCX);
    enc.emit_movzx_r64_r8(RDX, RDX);
    // RAX = !PF
    enc.emit_mov_rr64(RAX, RDX);
    enc.emit_xor_r64_imm32(RAX, 1);
    enc.emit_and_rr64(RBX, RAX); // RBX = N = CF & !PF
    enc.emit_and_rr64(RCX, RAX); // RCX = Z = ZF & !PF
    // Pack into RAX: N@31 | Z@30 | C@29 (=!N) | V@28 (=PF)
    enc.emit_mov_rr64(RAX, RBX);
    enc.emit_shl_r64_imm8(RAX, 31);
    enc.emit_shl_r64_imm8(RCX, 30);
    enc.emit_or_rr64(RAX, RCX);
    enc.emit_shl_r64_imm8(RDX, 28); // V = PF
    enc.emit_or_rr64(RAX, RDX);
    enc.emit_mov_rr64(RCX, RBX);    // RCX = N
    enc.emit_xor_r64_imm32(RCX, 1); // RCX = !N = C
    enc.emit_shl_r64_imm8(RCX, 29);
    enc.emit_or_rr64(RAX, RCX);
    enc.emit_mov_mem_r64(R15, NZCV_DISP, RAX);
    enc.emit_pop_r64(RDX);
    enc.emit_pop_r64(RBX);
}

/// NEON pairwise (`ADDP`/`UMAXP`/…) — byte forms only. Deinterleave each source's
/// even/odd bytes into word-low positions, combine, then `packuswb`: the low 8
/// result bytes come from Vn's pairs, the high 8 from Vm's. bionic strchr/memchr
/// use `umaxp v.16b` / `addp v.16b`.
fn lower_vecpair(enc: &mut X86Encoder, op: VecPairOp, size: u8, q: bool, d: u8, n: u8, m: u8) {
    use VecPairOp::*;
    if size != B {
        enc.emit_ud2(); // non-byte pairwise (half/word) — Tier 1
        return;
    }
    // Per-pair reducer applied to the two source bytes (each pre-isolated to the
    // low byte of its 16-bit lane, high byte 0). Add must truncate back to 8 bits
    // after the widening paddw; the min/max ops keep the high byte 0 naturally
    // (min/max of {x,0} with the other {y,0} → result high byte 0). SMin/SMax use
    // the SSE4.1 signed byte ops; with the high byte zeroed the sign bit lives in
    // bit 7 of the low byte, exactly matching the NEON signed-byte semantics.
    let reduce = |enc: &mut X86Encoder, acc: u8, other: u8, mask: u8| match op {
        Add => {
            enc.emit_paddw(acc, other);
            enc.emit_pand(acc, mask); // truncate even+odd to 8 bits
        }
        UMax => enc.emit_pmaxub(acc, other),
        UMin => enc.emit_pminub(acc, other),
        SMax => enc.emit_pmaxsb(acc, other),
        SMin => enc.emit_pminsb(acc, other),
    };
    enc.emit_movdqu_load(VS0, R15, vd(n));
    enc.emit_movdqu_load(VS1, R15, vd(m));
    enc.emit_pcmpeqw(VS3, VS3);
    enc.emit_psrlw_imm(VS3, 8); // 0x00FF per 16-bit lane
    // Vn pairwise → VS0 (each result in the low byte of its word lane).
    enc.emit_movdqa_rr(VS2, VS0);
    enc.emit_pand(VS2, VS3); // even bytes
    enc.emit_psrlw_imm(VS0, 8); // odd bytes
    reduce(enc, VS0, VS2, VS3);
    // Vm pairwise → VS1.
    enc.emit_movdqa_rr(VS2, VS1);
    enc.emit_pand(VS2, VS3);
    enc.emit_psrlw_imm(VS1, 8);
    reduce(enc, VS1, VS2, VS3);
    enc.emit_packuswb(VS0, VS1); // low 8 = Vn pairs, high 8 = Vm pairs
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `UADDLP` — add-long pairwise (unsigned). Mask the even source lanes and
/// shift the odd lanes down into the same widened-lane position, then a widening
/// add (no truncation): byte→half (psrlw/paddw), half→word (psrld/paddd),
/// word→dword (psrlq/paddq). Signed (SADDLP) needs lane sign-extension — Tier 1.
fn lower_vecaddlongpair(enc: &mut X86Encoder, d: u8, n: u8, esize_in: u8, q: bool, signed: bool) {
    if signed || !matches!(esize_in, 1 | 2 | 4) {
        enc.emit_ud2();
        return;
    }
    enc.emit_movdqu_load(VS0, R15, vd(n));
    // VS3 = low-half mask for the WIDENED lane (0x00FF per half / 0x0000FFFF per
    // word / 0x…FFFFFFFF per qword) to isolate the even source element.
    enc.emit_pcmpeqd(VS3, VS3); // all-ones
    enc.emit_movdqa_rr(VS1, VS0);
    match esize_in {
        1 => {
            enc.emit_psrlw_imm(VS3, 8);
            enc.emit_pand(VS1, VS3); // even bytes (in each 16-bit lane)
            enc.emit_psrlw_imm(VS0, 8); // odd bytes
            enc.emit_paddw(VS0, VS1);
        }
        2 => {
            enc.emit_psrld_imm(VS3, 16);
            enc.emit_pand(VS1, VS3); // even halfwords (in each 32-bit lane)
            enc.emit_psrld_imm(VS0, 16); // odd halfwords
            enc.emit_paddd(VS0, VS1);
        }
        _ => {
            enc.emit_psrlq_imm(VS3, 32);
            enc.emit_pand(VS1, VS3); // even words (in each 64-bit lane)
            enc.emit_psrlq_imm(VS0, 32); // odd words
            enc.emit_paddq(VS0, VS1);
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `UZP1`/`UZP2` — unzip even/odd elements of Vn:Vm. Only the 32-bit (.4s,
/// via `shufps`) and 64-bit (.2d, via `punpck?qdq`) forms are wired (the bionic
/// popcount tail uses `uzp1 v.4s`). `odd`=false ⇒ UZP1 (even), true ⇒ UZP2 (odd).
fn lower_vecunzip(enc: &mut X86Encoder, d: u8, n: u8, m: u8, esize: u8, q: bool, odd: bool) {
    match (esize, q) {
        (4, true) => {
            // .4s: UZP1 = [n0,n2,m0,m2] (shufps imm 0x88); UZP2 = [n1,n3,m1,m3] (0xDD).
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_movdqu_load(VS1, R15, vd(m));
            enc.emit_shufps(VS0, VS1, if odd { 0xDD } else { 0x88 });
            enc.emit_movdqu_store(R15, vd(d), VS0);
        }
        (8, true) => {
            // .2d: UZP1 = [n0,m0] (punpcklqdq); UZP2 = [n1,m1] (punpckhqdq).
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_movdqu_load(VS1, R15, vd(m));
            if odd {
                enc.emit_punpckhqdq(VS0, VS1);
            } else {
                enc.emit_punpcklqdq(VS0, VS1);
            }
            enc.emit_movdqu_store(R15, vd(d), VS0);
        }
        _ => enc.emit_ud2(), // byte/half/.2s unzip — Tier 1
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
        // Bitwise selects — read-modify-write Vd. Identity (ARM ARM C7):
        //   BSL: Vd = Vd ? Vn : Vm       = Vm ^ ((Vm ^ Vn) & Vd)
        //   BIT: Vd = (Vm[bit]) ? Vn : Vd = Vd ^ ((Vd ^ Vn) & Vm)
        //   BIF: Vd = (Vm[bit]) ? Vd : Vn = Vd ^ ((Vd ^ Vn) & ~Vm)
        Bsl => {
            enc.emit_movdqu_load(VS0, R15, vd(m)); // VS0 = Vm
            enc.emit_movdqu_load(VS1, R15, vd(n)); // VS1 = Vn
            enc.emit_pxor(VS1, VS0); // Vn ^ Vm
            enc.emit_movdqu_load(VS3, R15, vd(d)); // VS3 = Vd (selector)
            enc.emit_pand(VS1, VS3); // (Vn^Vm) & Vd
            enc.emit_pxor(VS0, VS1); // Vm ^ ((Vn^Vm)&Vd)
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
            return;
        }
        Bit => {
            enc.emit_movdqu_load(VS0, R15, vd(d)); // VS0 = Vd
            enc.emit_movdqu_load(VS1, R15, vd(n)); // VS1 = Vn
            enc.emit_pxor(VS1, VS0); // Vd ^ Vn
            enc.emit_movdqu_load(VS3, R15, vd(m)); // VS3 = Vm
            enc.emit_pand(VS1, VS3); // (Vd^Vn) & Vm
            enc.emit_pxor(VS0, VS1); // Vd ^ ((Vd^Vn)&Vm)
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
            return;
        }
        Bif => {
            enc.emit_movdqu_load(VS0, R15, vd(d)); // VS0 = Vd
            enc.emit_movdqu_load(VS1, R15, vd(n)); // VS1 = Vn
            enc.emit_pxor(VS1, VS0); // Vd ^ Vn
            enc.emit_movdqu_load(VS3, R15, vd(m)); // VS3 = Vm
            enc.emit_pandn(VS3, VS1); // (~Vm) & (Vd^Vn)
            enc.emit_pxor(VS0, VS3); // Vd ^ ((Vd^Vn)&~Vm)
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
        // MLA: Vd += Vn*Vm. MLS: Vd -= Vn*Vm. Same-width (no widening), so the
        // low product bits ARE the result. VS0 = Vn*Vm, then accumulate Vd (VS2).
        Mla => match size {
            H => { enc.emit_pmullw(VS0, VS1); enc.emit_movdqu_load(VS2, R15, vd(d)); enc.emit_paddw(VS0, VS2); }
            S => { enc.emit_pmulld(VS0, VS1); enc.emit_movdqu_load(VS2, R15, vd(d)); enc.emit_paddd(VS0, VS2); }
            _ => handled = false,
        },
        Mls => match size {
            H => { enc.emit_pmullw(VS0, VS1); enc.emit_movdqu_load(VS2, R15, vd(d)); enc.emit_psubw(VS2, VS0); enc.emit_movdqa_rr(VS0, VS2); }
            S => { enc.emit_pmulld(VS0, VS1); enc.emit_movdqu_load(VS2, R15, vd(d)); enc.emit_psubd(VS2, VS0); enc.emit_movdqa_rr(VS0, VS2); }
            _ => handled = false,
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
    /// PMAXU{B,W} by size (unsigned max). Byte is SSE2; word is SSE4.1. Returns
    /// false for sizes without a wired unsigned-max (.4s/.2d) → UD2.
    fn pmaxu(enc: &mut X86Encoder, size: u8, a: u8, b: u8) -> bool {
        match size {
            0 => enc.emit_pmaxub(a, b),
            1 => enc.emit_pmaxuw(a, b),
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
        // CMHS (a >= b unsigned) = (max(a,b) == a). bionic strcmp/memcmp.
        UGe => {
            enc.emit_movdqa_rr(VS2, VS0); // save a
            if pmaxu(enc, size, VS0, VS1) {
                pcmpeq(enc, size, VS0, VS2) // max == a  → a >= b
            } else {
                false
            }
        }
        // CMHI (a > b unsigned) = ~(max(a,b) == b).
        UGt => {
            enc.emit_movdqa_rr(VS2, VS1); // save b
            if pmaxu(enc, size, VS0, VS1) && pcmpeq(enc, size, VS0, VS2) {
                enc.emit_pcmpeqd(VS3, VS3); // all-ones
                enc.emit_pxor(VS0, VS3); // ~(a <= b) == (a > b)
                true
            } else {
                false
            }
        }
    };

    if !ok {
        enc.emit_ud2();
        return;
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}
