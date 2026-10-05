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
use crate::ir::ops::{VecBinOp, VecCmpOp, VecPairOp, VecReduceOp};
use crate::ir::IrOp;
use crate::regalloc::x86_regs::{VS0, VS1, VS2, VS3};
use crate::runtime::context::vec_disp;

/// R15 — the context base register (matches `lower_int::CONTEXT_REG`).
const R15: u8 = 15;
/// RAX — a reserved scratch GPR (removed from `ALLOCATABLE_GPRS`, == `lower_int`'s
/// `SCRATCH0`), free to clobber here for building pshufb masks etc.
const RAX: u8 = 0;
/// RCX — the second reserved scratch GPR (== `lower_int`'s `SCRATCH1`).
const RCX: u8 = 1;

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
        IrOp::VecShiftReg { d, n, m, size, q, signed } => {
            lower_vecshiftreg(enc, *d, *n, *m, *size, *q, *signed)
        }
        IrOp::VecShiftIns { d, n, shift, size, q, left } => {
            lower_vecshiftins(enc, *d, *n, *shift, *size, *q, *left)
        }
        IrOp::VecShiftNarrowSat { d, n, shift, esize_out, high, round, src_signed, dst_signed, modular } => {
            lower_vecshiftnarrowsat(enc, *d, *n, *shift, *esize_out, *high, *round, *src_signed, *dst_signed, *modular)
        }
        IrOp::VecExt { d, n, m, imm, q } => lower_vecext(enc, *d, *n, *m, *imm, *q),
        IrOp::VecMulLong { d, n, m, size, q, signed, accum, sub } => {
            lower_vecmullong(enc, *d, *n, *m, *size, *q, *signed, *accum, *sub)
        }
        IrOp::VecRev64 { d, n, size, q, container } => lower_vecrev64(enc, *d, *n, *size, *q, *container),
        IrOp::FpBin { op, dbl, d, n, m } => lower_fpbin(enc, *op, *dbl, *d, *n, *m),
        IrOp::FpFma { op, dbl, d, n, m, a } => lower_fpfma(enc, *op, *dbl, *d, *n, *m, *a),
        IrOp::FpCmpN { n, m, dbl, zero } => lower_fpcmpn(enc, *n, *m, *dbl, *zero),
        IrOp::VecPair { op, size, q, d, n, m } => lower_vecpair(enc, *op, *size, *q, *d, *n, *m),
        IrOp::VecAddLongPair { d, n, esize_in, q, signed } => {
            lower_vecaddlongpair(enc, *d, *n, *esize_in, *q, *signed)
        }
        IrOp::VecUnzip { d, n, m, esize, q, odd } => {
            lower_vecunzip(enc, *d, *n, *m, *esize, *q, *odd)
        }
        IrOp::VecShift { op, size, q, d, n, amount } => {
            lower_vecshift(enc, *op, *size, *q, *d, *n, *amount)
        }
        IrOp::VecShiftAcc { signed, size, q, d, n, amount } => {
            lower_vecshiftacc(enc, *signed, *size, *q, *d, *n, *amount)
        }
        IrOp::VecTbl1 { d, n, m, q } => lower_vectbl1(enc, *d, *n, *m, *q),
        IrOp::VecTblN { d, n, m, len, op, q } => lower_vectbln(enc, *d, *n, *m, *len, *op, *q),
        IrOp::VecDupElem { d, n, size, lane, q } => lower_vecdupelem(enc, *d, *n, *size, *lane, *q),
        IrOp::VecPmull { d, n, m, high } => lower_vecpmull(enc, *d, *n, *m, *high),
        IrOp::CryptoAesR { kind, d, n, .. } => lower_crypto_aes(enc, *kind, *d, *n),

        // B20/B29: across-lanes integer min/max reduction (SMAXV/UMAXV/SMINV/UMINV).
        IrOp::VecReduce { op, size, q, d, n } => lower_vecreduce(enc, *op, *size, *q, *d, *n),
        // B20: scalar FP 1-source (FMOV/FABS/FNEG/FSQRT Sd,Sn).
        IrOp::FpUn { op, dbl, d, n } => lower_fpun(enc, *op, *dbl, *d, *n),
        // FCVT scalar precision convert (single↔double).
        IrOp::FpCvt2 { d, n, from_bits, to_bits } =>
            lower_fpcvt2(enc, *d, *n, *from_bits, *to_bits),
        // FCSEL scalar conditional select.
        IrOp::FpCsel { d, n, m, cond, dbl } =>
            lower_fpcsel(enc, *d, *n, *m, *cond, *dbl),

        // Vector FP 3-same arithmetic (FADD/FSUB/FMUL/FDIV/FMLA/FMLS/FMAX/FMIN/
        // FMAXNM/FMINNM/FABD).
        IrOp::VecFp { op, dbl, q, d, n, m } => lower_vecfp(enc, *op, *dbl, *q, *d, *n, *m),
        // Vector FP per-lane compare (FCMEQ/FCMGT/FCMGE register + vs #0).
        IrOp::VecFpCmp { op, dbl, q, d, n, m, zero } =>
            lower_vecfpcmp(enc, *op, *dbl, *q, *d, *n, *m, *zero),
        // Vector FP 2-reg-misc unary (FABS/FNEG/FSQRT).
        IrOp::VecFpUn { op, dbl, q, d, n } => lower_vecfpun(enc, *op, *dbl, *q, *d, *n),
        // Vector FP / int multiply-accumulate by element (FMUL/FMLA/FMLS/MUL .<Ts>[idx]).
        IrOp::VecByElem { op, is_fp, dbl, size, q, d, n, m, idx } =>
            lower_vecbyelem(enc, *op, *is_fp, *dbl, *size, *q, *d, *n, *m, *idx),
        // Vector int↔FP convert (SCVTF/UCVTF/FCVTZS/FCVTZU).
        IrOp::VecCvtFp { to_fp, signed, dbl, q, d, n } =>
            lower_veccvtfp(enc, *to_fp, *signed, *dbl, *q, *d, *n),
        // Vector ZIP1/ZIP2/TRN1/TRN2 permute.
        IrOp::VecZipTrn { kind, size, q, d, n, m } =>
            lower_vecziptrn(enc, *kind, *size, *q, *d, *n, *m),
        // Vector integer 2-reg-misc unary (ABS/NEG).
        IrOp::VecUn { op, size, q, d, n } => lower_vecun(enc, *op, *size, *q, *d, *n),
        // Scalar FP round-to-integral (FRINTN/M/P/Z/A/X/I).
        IrOp::FpRound { d, n, dbl, round, raise_inexact } =>
            lower_fpround(enc, *d, *n, *dbl, *round, *raise_inexact),
        // Vector FP round-to-integral (FRINTN/M/P/Z/A).
        IrOp::VecFpRound { d, n, dbl, q, round } =>
            lower_vecfpround(enc, *d, *n, *dbl, *q, *round),
        // Scalar pairwise reduce (ADDP/FADDP).
        IrOp::VecScalarPair { is_fp, dbl, d, n } => lower_vecscalarpair(enc, *is_fp, *dbl, *d, *n),

        // ── Remaining families: scaffolded fail-loud (BUILDSPEC §7, Tier 1). ──
        IrOp::VecAddLong { .. }
        | IrOp::FpFromInt { .. }
        | IrOp::FpToIntR { .. }
        | IrOp::FpMov { .. }
        | IrOp::FpToGpr { .. }
        | IrOp::FpFromGpr { .. } => enc.emit_ud2(),
        // NOTE: CryptoShaR (SHA-1) and CryptoSha256 are NOT routed here — they are
        // lowered directly in IntLower as Win64 CALLs to crypto_rt helpers
        // (emit_crypto_sha1_call / emit_crypto_sha256_call). This arm is dead.

        // Not a ctx-template op — should never be routed here.
        _ => enc.emit_ud2(),
    }
}

/// B20/B29: NEON across-lanes integer min/max reduction (SMAXV/UMAXV/SMINV/UMINV).
/// Reduces all lanes of Vn (element bytes = `1<<size`) to a single scalar in Vd
/// lane 0 (rest zeroed). Done in GPR ctx-memory style (like `VecReduceAdd`): each
/// lane is loaded (sign/zero-extended per signedness) into RCX and folded into the
/// running accumulator RAX with a `cmp`/conditional-skip/`mov` (no x86 cmov dep).
fn lower_vecreduce(enc: &mut X86Encoder, op: VecReduceOp, size: u8, q: bool, d: u8, n: u8) {
    use crate::backend::lower_int::cc;
    let esize: u8 = 1 << size;
    let dn = vec_disp(n);
    let dd = vec_disp(d);
    let total: i32 = if q { 16 } else { 8 };
    let es = esize as i32;
    let signed = matches!(op, VecReduceOp::SMax | VecReduceOp::SMin);
    // Condition under which the accumulator is ALREADY the extremum → skip update.
    let skip_cc = match op {
        VecReduceOp::SMax => cc::NL, // acc >= lane (signed)
        VecReduceOp::SMin => cc::LE, // acc <= lane (signed)
        VecReduceOp::UMax => cc::NB, // acc >= lane (unsigned)
        VecReduceOp::UMin => cc::BE, // acc <= lane (unsigned)
        VecReduceOp::Add => {
            // Add reduces via the dedicated VecReduceAdd op; never routed here.
            enc.emit_ud2();
            return;
        }
    };
    load_lane(enc, RAX, dn, esize, signed); // accumulator = lane 0
    let mut i = es;
    while i < total {
        load_lane(enc, RCX, dn + i, esize, signed);
        enc.emit_cmp_rr64(RAX, RCX); // RAX - RCX
        let jskip = enc.emit_jcc_rel32(skip_cc);
        enc.emit_mov_rr64(RAX, RCX); // acc = lane (new extremum)
        let skip_pos = enc.pos();
        enc.patch_rel32(jskip, skip_pos);
        i += es;
    }
    // Store the scalar to Vd lane 0; zero the rest (FP-write semantics).
    enc.emit_xor_zero_r32(RCX);
    enc.emit_mov_mem_r64(R15, dd, RCX);
    enc.emit_mov_mem_r64(R15, dd + 8, RCX);
    match esize {
        1 => enc.emit_mov_mem8_r64(R15, dd, RAX),
        2 => enc.emit_mov_mem16_r64(R15, dd, RAX),
        4 => enc.emit_mov_mem32_r64(R15, dd, RAX),
        _ => enc.emit_mov_mem_r64(R15, dd, RAX),
    }
}

/// Load one `esize`-byte lane from `[R15 + disp]` into `dst`, sign- or
/// zero-extended to 64 bits per `signed`.
fn load_lane(enc: &mut X86Encoder, dst: u8, disp: i32, esize: u8, signed: bool) {
    match (esize, signed) {
        (1, true) => enc.emit_movsx_r64_mem8(dst, R15, disp),
        (1, false) => enc.emit_movzx_r64_mem8(dst, R15, disp),
        (2, true) => enc.emit_movsx_r64_mem16(dst, R15, disp),
        (2, false) => enc.emit_movzx_r64_mem16(dst, R15, disp),
        (4, true) => enc.emit_movsxd_r64_mem32(dst, R15, disp),
        (4, false) => enc.emit_mov_r32_mem(dst, R15, disp), // zero-extends to 64
        _ => enc.emit_mov_r64_mem(dst, R15, disp),
    }
}

/// AES single-round step via x86 AES-NI. ARM AESE/AESD XOR the round key into the
/// state BEFORE SubBytes/ShiftRows and apply NO MixColumns, so they map to
/// AESENCLAST/AESDECLAST against a zero round key after an explicit pxor:
///   AESE  Vd,Vn = AESENCLAST(Vd XOR Vn, 0) = SubBytes(ShiftRows(Vd XOR Vn))
///   AESD  Vd,Vn = AESDECLAST(Vd XOR Vn, 0) = InvSubBytes(InvShiftRows(Vd XOR Vn))
///   AESMC Vd,Vn = AESENC(AESDECLAST(Vn,0),0) = MixColumns(Vn)
///   AESIMC Vd,Vn= AESIMC(Vn)                 = InvMixColumns(Vn)
/// kind = ARM opcode (4=AESE 5=AESD 6=AESMC 7=AESIMC). AESE/AESD read Vd+Vn;
/// AESMC/AESIMC read only Vn. Always a full 128-bit result (no D-form).
fn lower_crypto_aes(enc: &mut X86Encoder, kind: u8, d: u8, n: u8) {
    match kind {
        4 => {
            // AESE: SubBytes(ShiftRows(Vd XOR Vn)).
            enc.emit_movdqu_load(VS0, R15, vd(d));
            enc.emit_movdqu_load(VS1, R15, vd(n));
            enc.emit_pxor(VS0, VS1);
            enc.emit_pxor(VS1, VS1); // VS1 = 0 round key
            enc.emit_aesenclast(VS0, VS1);
        }
        5 => {
            // AESD: InvSubBytes(InvShiftRows(Vd XOR Vn)).
            enc.emit_movdqu_load(VS0, R15, vd(d));
            enc.emit_movdqu_load(VS1, R15, vd(n));
            enc.emit_pxor(VS0, VS1);
            enc.emit_pxor(VS1, VS1);
            enc.emit_aesdeclast(VS0, VS1);
        }
        6 => {
            // AESMC: MixColumns(Vn) = AESENC(AESDECLAST(Vn,0),0).
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_pxor(VS1, VS1); // 0
            enc.emit_aesdeclast(VS0, VS1);
            enc.emit_aesenc(VS0, VS1);
        }
        7 => {
            // AESIMC: InvMixColumns(Vn).
            enc.emit_movdqu_load(VS1, R15, vd(n));
            enc.emit_aesimc(VS0, VS1);
        }
        _ => {
            enc.emit_ud2();
            return;
        }
    }
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON single-register `TBL` (`Vd[i] = Vm[i]<16 ? Vn[Vm[i]] : 0`). x86 `pshufb`
/// zeroes a lane when the index byte's bit7 is set and otherwise uses bits[3:0];
/// `paddusb(index, 0x70)` (unsigned-saturating) maps 0..15 → 0x70..0x7F (bit7
/// clear, low nibble = index → table[index]) and any index ≥16 → ≥0x80 (bit7 set
/// → zero), exactly matching ARM's out-of-range-zeroes semantics.
fn lower_vectbl1(enc: &mut X86Encoder, d: u8, n: u8, m: u8, q: bool) {
    enc.emit_movdqu_load(VS0, R15, vd(n)); // VS0 = table (Vn)
    enc.emit_movdqu_load(VS1, R15, vd(m)); // VS1 = index (Vm)
    // VS2 = {0x70 × 16}.
    enc.emit_mov_r64_imm64(RAX, 0x7070_7070_7070_7070u64 as i64);
    enc.emit_movq_xmm_r64(VS2, RAX);
    enc.emit_punpcklqdq(VS2, VS2);
    enc.emit_paddusb(VS1, VS2); // clamp out-of-range indices (bit7 set → 0)
    enc.emit_pshufb(VS0, VS1);
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Broadcast byte `b` across all 16 lanes of `dst` (via RAX). Clobbers RAX.
fn splat_byte(enc: &mut X86Encoder, dst: u8, b: u8) {
    let w = (b as u64).wrapping_mul(0x0101_0101_0101_0101);
    enc.emit_mov_r64_imm64(RAX, w as i64);
    enc.emit_movq_xmm_r64(dst, RAX);
    enc.emit_punpcklqdq(dst, dst);
}

/// NEON multi-register `TBL`/`TBX` (`len`+1 consecutive table regs, wrapping
/// mod 32). For each output byte i with index `idx = Vm[i]`: TBL writes
/// `table[idx]` if `idx < 16*(len+1)` else 0; TBX is identical except an
/// out-of-range lane keeps the old `Vd[i]`.
///
/// x86 `pshufb(T, sel)` zeroes a lane when `sel`'s bit7 is set, else uses
/// bits[3:0] as the in-register lane. Per table register k (0..=len):
///   tmp = psubb(idx, splat(16*k))        ; wrapping byte subtract
///   tmp = paddusb(tmp, splat(0x70))      ; saturating
/// maps idx∈[16k,16k+15] → [0x70,0x7F] (bit7 clear, low nibble = idx−16k →
/// Tk[idx−16k]); idx<16k wraps high (bit7 set → 0); idx≥16(k+1) saturates
/// ≥0x80 (bit7 set → 0). Contributions are disjoint across k, so `por`
/// accumulates them. For k=0 this reduces exactly to the single-reg lowering.
///
/// TBX then merges the old Vd into the out-of-range lanes via an in-range mask
/// `inrange = pcmpeqb(psubusb(idx, splat(16N−1)), 0)` (0xFF where idx ≤ 16N−1)
/// and `result = acc | (Vd_old & ~inrange)`.
///
/// Register budget (only VS0..VS3 available): VS0=acc, VS1=idx (original index,
/// preserved across the whole op), VS2=per-iter index copy, VS3=splat/table reg.
fn lower_vectbln(enc: &mut X86Encoder, d: u8, n: u8, m: u8, len: u8, op: u8, q: bool) {
    let count = (len as u16) + 1; // table-reg count (1..=4)
    enc.emit_pxor(VS0, VS0); // acc = 0
    enc.emit_movdqu_load(VS1, R15, vd(m)); // idx = Vm (preserved)

    for k in 0..count {
        let treg = ((n as u16 + k) % 32) as u8;
        enc.emit_movdqa_rr(VS2, VS1); // tmp = idx
        if k != 0 {
            splat_byte(enc, VS3, (16 * k) as u8); // splat(16*k)
            enc.emit_psubb(VS2, VS3); // tmp = idx − 16k (wrapping)
        }
        splat_byte(enc, VS3, 0x70); // splat(0x70)
        enc.emit_paddusb(VS2, VS3); // tmp = saturating clamp
        enc.emit_movdqu_load(VS3, R15, vd(treg)); // Tk = table reg
        enc.emit_pshufb(VS3, VS2); // Tk indexed (0 outside [16k,16k+15])
        enc.emit_por(VS0, VS3); // acc |= contribution
    }

    if op == 1 {
        // TBX: merge old Vd into the out-of-range lanes.
        // inrange = pcmpeqb(psubusb(idx, splat(16N−1)), 0) → 0xFF where idx ≤ 16N−1.
        enc.emit_movdqa_rr(VS2, VS1); // tmp = idx
        let hi = (16 * count - 1) as u8; // 16N − 1 (≤ 63, fits u8)
        splat_byte(enc, VS3, hi);
        enc.emit_psubusb(VS2, VS3); // 0 where idx ≤ 16N−1, >0 otherwise
        enc.emit_pxor(VS3, VS3); // VS3 = 0
        enc.emit_pcmpeqb(VS2, VS3); // VS2 = inrange mask (0xFF in-range)
        enc.emit_movdqu_load(VS3, R15, vd(d)); // Vd_old (loaded AFTER acc built; d not used as table source here)
        enc.emit_pandn(VS2, VS3); // VS2 = Vd_old & ~inrange
        enc.emit_por(VS0, VS2); // acc |= preserved old bytes
    }

    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON vector shift by immediate. Only `SHL` (left) is wired (bionic AES Rcon
/// doubling `shl v.16b, v.16b, #1`). `size` = log2(element bytes). x86 has no
/// byte-granular shift, so the 8-bit form shifts as 16-bit lanes (`psllw`) then
/// masks each byte to `(0xFF << amount) & 0xFF` to drop the cross-byte carry.
fn lower_vecshift(
    enc: &mut X86Encoder,
    op: crate::ir::ops::VecShiftOp,
    size: u8,
    q: bool,
    d: u8,
    n: u8,
    amount: u8,
) {
    use crate::ir::ops::VecShiftOp::*;
    enc.emit_movdqu_load(VS0, R15, vd(n));
    match op {
        Shl => match size {
            0 => {
                enc.emit_psllw_imm(VS0, amount);
                let m8 = ((0xFFu16 << (amount & 7)) & 0xFF) as u8;
                let mask = (m8 as u64).wrapping_mul(0x0101_0101_0101_0101);
                enc.emit_mov_r64_imm64(RAX, mask as i64);
                enc.emit_movq_xmm_r64(VS1, RAX);
                enc.emit_punpcklqdq(VS1, VS1);
                enc.emit_pand(VS0, VS1);
            }
            1 => enc.emit_psllw_imm(VS0, amount),
            2 => enc.emit_pslld_imm(VS0, amount),
            3 => enc.emit_psllq_imm(VS0, amount),
            _ => {
                enc.emit_ud2();
                return;
            }
        },
        UShr => match size {
            0 => {
                // 8-bit logical right: psrlw then mask each byte to (0xFF >> amount).
                // amount ∈ 1..=8 (byte SSHR/USHR encode 16 − immh:immb). #8 must
                // give mask 0 (all-zero result); `0xFFu8 >> 8` panics in debug, so
                // do the shift in u16 and clamp the count to 8.
                enc.emit_psrlw_imm(VS0, amount);
                let m8 = (0xFFu16 >> amount.min(8)) as u8;
                let mask = (m8 as u64).wrapping_mul(0x0101_0101_0101_0101);
                enc.emit_mov_r64_imm64(RAX, mask as i64);
                enc.emit_movq_xmm_r64(VS1, RAX);
                enc.emit_punpcklqdq(VS1, VS1);
                enc.emit_pand(VS0, VS1);
            }
            1 => enc.emit_psrlw_imm(VS0, amount),
            2 => enc.emit_psrld_imm(VS0, amount),
            3 => enc.emit_psrlq_imm(VS0, amount),
            _ => {
                enc.emit_ud2();
                return;
            }
        },
        SShr => match size {
            // x86 has psraw/psrad but NO psrab/psraq, so the 8-bit and 64-bit
            // arithmetic right shifts are emulated below.
            0 => {
                // 8-bit arithmetic right shift by `amount` (1..=7). x86 has no
                // psrab, so: (a) logical part = psrlw + per-byte mask (0xFF>>n),
                // then (b) sign fill: pcmpgtb(0,Vn) gives 0xFF where the byte is
                // negative; AND that with the fill mask ((0xFF<<(8-n))&0xFF) and
                // OR it in so negative bytes get their top `n` bits set.
                // amount ∈ 1..=8 (byte SSHR encodes 16 − immh:immb). #8 = pure
                // sign fill: logmask 0 (all logical bits dropped) + fill 0xFF.
                let n = amount.min(8);
                // sign = pcmpgtb(0, Vn) — VS1 = 0, then compare-greater vs Vn.
                enc.emit_pxor(VS1, VS1);
                enc.emit_pcmpgtb(VS1, VS0); // VS1 = 0xFF per byte where Vn < 0
                // logical shift of Vn in VS0.
                enc.emit_psrlw_imm(VS0, n);
                let logmask = (((0xFFu16 >> n) & 0xFF) as u64).wrapping_mul(0x0101_0101_0101_0101);
                enc.emit_mov_r64_imm64(RAX, logmask as i64);
                enc.emit_movq_xmm_r64(VS2, RAX);
                enc.emit_punpcklqdq(VS2, VS2);
                enc.emit_pand(VS0, VS2); // VS0 = per-byte logical result
                // fill mask = high `n` bits of each byte, applied where sign set.
                let fill8 = ((0xFFu16 << (8 - n as u16)) & 0xFF) as u8;
                let fillmask = (fill8 as u64).wrapping_mul(0x0101_0101_0101_0101);
                enc.emit_mov_r64_imm64(RAX, fillmask as i64);
                enc.emit_movq_xmm_r64(VS2, RAX);
                enc.emit_punpcklqdq(VS2, VS2);
                enc.emit_pand(VS1, VS2); // VS1 = fill bits where Vn < 0
                enc.emit_por(VS0, VS1); // arithmetic = logical | signfill
            }
            1 => enc.emit_psraw_imm(VS0, amount),
            2 => enc.emit_psrad_imm(VS0, amount),
            3 => {
                // 64-bit arithmetic right shift by `amount` (1..=63). No psraq
                // pre-AVX512: logical = psrlq(Vn, amount); sign broadcast per
                // qword via psrad #31 + pshufd 0xF5; fill = psllq(sign, 64-amount);
                // result = logical | fill. (Same idiom as the SSRA .2d path.)
                enc.emit_movdqa_rr(VS2, VS0); // VS2 = Vn (for the sign)
                enc.emit_psrad_imm(VS2, 31); // each 32-bit half → 0 / 0xFFFFFFFF
                enc.emit_pshufd(VS2, VS2, 0xF5); // broadcast high dword over each qword
                enc.emit_psrlq_imm(VS0, amount); // logical part
                enc.emit_psllq_imm(VS2, 64 - amount); // sign fill (top `amount` bits)
                enc.emit_por(VS0, VS2); // arithmetic = logical | signfill
            }
            _ => {
                enc.emit_ud2();
                return;
            }
        },
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `SSRA`/`USRA` — shift-right-and-accumulate by immediate:
/// `Vd[e] += (Vn[e] >> amount)`. `signed=false` (USRA) is a LOGICAL shift,
/// `signed=true` (SSRA) is ARITHMETIC. The shifted value is computed in VS0
/// (mirroring `lower_vecshift`'s SSHR/USHR paths), then the destination Vd is
/// loaded into VS1 and added lane-wise (PADD{B,W,D,Q}) before the store. `d`
/// is read AND written.
fn lower_vecshiftacc(
    enc: &mut X86Encoder,
    signed: bool,
    size: u8,
    q: bool,
    d: u8,
    n: u8,
    amount: u8,
) {
    // --- 1. shift Vn right by `amount` into VS0 (same lowering as SSHR/USHR). ---
    enc.emit_movdqu_load(VS0, R15, vd(n));
    if !signed {
        // USRA — logical right shift.
        match size {
            0 => {
                // 8-bit: psrlw then mask each byte to (0xFF >> amount). amount ∈
                // 1..=8 (USRA byte encodes 16 − immh:immb); #8 → mask 0 → all-zero
                // shifted value. u16 shift avoids the debug panic on `0xFFu8 >> 8`.
                enc.emit_psrlw_imm(VS0, amount);
                let m8 = (0xFFu16 >> amount.min(8)) as u8;
                let mask = (m8 as u64).wrapping_mul(0x0101_0101_0101_0101);
                enc.emit_mov_r64_imm64(RAX, mask as i64);
                enc.emit_movq_xmm_r64(VS1, RAX);
                enc.emit_punpcklqdq(VS1, VS1);
                enc.emit_pand(VS0, VS1);
            }
            1 => enc.emit_psrlw_imm(VS0, amount),
            2 => enc.emit_psrld_imm(VS0, amount),
            3 => enc.emit_psrlq_imm(VS0, amount),
            _ => {
                enc.emit_ud2();
                return;
            }
        }
    } else {
        // SSRA — arithmetic right shift.
        match size {
            // x86 has psraw/psrad but NO psrab/psraq.
            0 => {
                // 8-bit arithmetic right shift by `amount` (1..=7): logical
                // psrlw + per-byte mask (0xFF>>n), then OR in the sign fill
                // (top `n` bits of each originally-negative byte). Mirrors the
                // SSHR .16b path in lower_vecshift. VS3 must stay free for the
                // accumulate step below, so the sign lands in VS1 and is consumed
                // before VS1 is reloaded with Vd.
                // amount ∈ 1..=8 (SSRA byte encodes 16 − immh:immb). #8 = pure
                // sign fill: logmask 0 + fill 0xFF. u16 shift avoids debug panic.
                let n = amount.min(8);
                enc.emit_pxor(VS1, VS1);
                enc.emit_pcmpgtb(VS1, VS0); // VS1 = 0xFF where Vn < 0
                enc.emit_psrlw_imm(VS0, n);
                let logmask = (((0xFFu16 >> n) & 0xFF) as u64).wrapping_mul(0x0101_0101_0101_0101);
                enc.emit_mov_r64_imm64(RAX, logmask as i64);
                enc.emit_movq_xmm_r64(VS2, RAX);
                enc.emit_punpcklqdq(VS2, VS2);
                enc.emit_pand(VS0, VS2); // logical byte result
                let fill8 = ((0xFFu16 << (8 - n as u16)) & 0xFF) as u8;
                let fillmask = (fill8 as u64).wrapping_mul(0x0101_0101_0101_0101);
                enc.emit_mov_r64_imm64(RAX, fillmask as i64);
                enc.emit_movq_xmm_r64(VS2, RAX);
                enc.emit_punpcklqdq(VS2, VS2);
                enc.emit_pand(VS1, VS2); // fill bits where Vn < 0
                enc.emit_por(VS0, VS1); // arithmetic byte shift in VS0
            }
            1 => enc.emit_psraw_imm(VS0, amount),
            2 => enc.emit_psrad_imm(VS0, amount),
            3 => {
                // Emulate per-lane 64-bit arithmetic shift (no PSRAQ pre-AVX512):
                //   logical = psrlq(Vn, amount)
                //   sign    = broadcast each lane's MSB to a full 64-bit mask
                //             (psrad #31 → 0/-1 per 32-bit half; pshufd picks the
                //              high dword of each qword to fill the whole qword)
                //   fill    = psllq(sign, 64 - amount)  // sets the top `amount` bits
                //   result  = logical | fill
                // Valid for 1 <= amount <= 63 (the architectural SSRA range).
                enc.emit_movdqu_load(VS2, R15, vd(n)); // VS2 = Vn (for the sign)
                enc.emit_psrad_imm(VS2, 31); // each 32-bit half → 0 / 0xFFFFFFFF
                // pshufd imm 0xF5 = [1,1,3,3]: replicate the high dword of each
                // qword over both dwords → 0/-1 broadcast per 64-bit lane.
                enc.emit_pshufd(VS2, VS2, 0xF5);
                enc.emit_psrlq_imm(VS0, amount); // logical part
                enc.emit_psllq_imm(VS2, 64 - amount); // sign fill (top `amount` bits)
                enc.emit_por(VS0, VS2); // arithmetic = logical | signfill
            }
            _ => {
                enc.emit_ud2();
                return;
            }
        }
    }

    // --- 2. accumulate the destination: VS0 += Vd, lane-wise. ---
    enc.emit_movdqu_load(VS1, R15, vd(d));
    match size {
        0 => enc.emit_paddb(VS0, VS1),
        1 => enc.emit_paddw(VS0, VS1),
        2 => enc.emit_paddd(VS0, VS1),
        3 => enc.emit_paddq(VS0, VS1),
        _ => {
            enc.emit_ud2();
            return;
        }
    }

    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `DUP` (element) — broadcast `Vn.<Ts>[lane]` to all lanes. 32-bit (S) and
/// 64-bit (D) forms map to `pshufd`; the 8-bit (B) form uses `pshufb` with a
/// splat-index mask (every output byte = source byte `lane`); the 16-bit (H) form
/// uses `pshufb` with a halfword-splat mask (each output halfword = source
/// halfword `lane`'s two bytes).
fn lower_vecdupelem(enc: &mut X86Encoder, d: u8, n: u8, size: u8, lane: u8, q: bool) {
    enc.emit_movdqu_load(VS0, R15, vd(n));
    match size {
        0 => {
            // B (8-bit): every output byte := source byte `lane` → pshufb mask of
            // all `lane`. (lane ∈ 0..15.)
            let mask = [lane; 16];
            load_xmm_imm16(enc, VS1, &mask);
            enc.emit_pshufb(VS0, VS1);
        }
        1 => {
            // H (16-bit): every output halfword := source halfword `lane`, i.e.
            // source bytes 2*lane and 2*lane+1 replicated into each halfword slot.
            let lo = 2 * lane;
            let hi = 2 * lane + 1;
            let mut mask = [0u8; 16];
            for pair in mask.chunks_exact_mut(2) {
                pair[0] = lo;
                pair[1] = hi;
            }
            load_xmm_imm16(enc, VS1, &mask);
            enc.emit_pshufb(VS0, VS1);
        }
        2 => {
            // S (32-bit): replicate dword `lane` to all four (pshufd imm = lane*0x55).
            enc.emit_pshufd(VS0, VS0, lane.wrapping_mul(0x55));
        }
        3 => {
            // D (64-bit): replicate qword `lane` (lane0 → [0,1,0,1]=0x44, lane1 → 0xEE).
            let imm = if lane == 0 { 0x44 } else { 0xEE };
            enc.emit_pshufd(VS0, VS0, imm);
        }
        _ => {
            enc.emit_ud2();
            return;
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `PMULL`/`PMULL2` `.1q` — 64×64→128 carryless multiply via x86
/// `PCLMULQDQ`. PMULL uses each source's LOW 64 (imm 0x00); PMULL2 uses the
/// HIGH 64 (imm 0x11). Always a full 128-bit result.
fn lower_vecpmull(enc: &mut X86Encoder, d: u8, n: u8, m: u8, high: bool) {
    enc.emit_movdqu_load(VS0, R15, vd(n));
    enc.emit_movdqu_load(VS1, R15, vd(m));
    let imm = if high { 0x11 } else { 0x00 };
    enc.emit_pclmulqdq(VS0, VS1, imm);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON compare-against-zero (`CMEQ/CMGT/CMGE/CMLT/CMLE Vd, Vn, #0`). Each result
/// lane is all-ones where the predicate holds, else zero.
///   CMEQ (Eq):  Vn == 0  → pcmpeq(Vn, 0)
///   CMGT (SGt): Vn >  0  → pcmpgt(Vn, 0)                 (signed)
///   CMLT (SLt): Vn <  0  → pcmpgt(0, Vn)                 (signed)
///   CMGE (SGe): Vn >= 0  → NOT(Vn < 0)  = NOT pcmpgt(0, Vn)
///   CMLE (SLe): Vn <= 0  → NOT(Vn > 0)  = NOT pcmpgt(Vn, 0)
/// The unsigned/Tst forms have no compare-vs-#0 encoding and fail-loud. Sizes
/// B/H/S use pcmpeq/gt {b,w,d}; D uses the SSE4.x qword variants (pcmpeqq/pcmpgtq).
fn lower_veccmpzero(enc: &mut X86Encoder, op: VecCmpOp, size: u8, q: bool, d: u8, n: u8) {
    use VecCmpOp::*;
    // Emit `pcmpgt` at the right element width, comparing `a > b` element-wise
    // (result all-ones where greater). Q (size 3) needs SSE4.2 pcmpgtq.
    let pcmpgt = |enc: &mut X86Encoder, a: u8, b: u8| match size {
        B => enc.emit_pcmpgtb(a, b),
        H => enc.emit_pcmpgtw(a, b),
        S => enc.emit_pcmpgtd(a, b),
        _ => enc.emit_pcmpgtq(a, b), // D
    };
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
        }
        SGt => {
            // Vn > 0: pcmpgt(Vn, 0).
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_pxor(VS1, VS1); // 0
            pcmpgt(enc, VS0, VS1); // VS0 = (Vn > 0)
        }
        SLt => {
            // Vn < 0: pcmpgt(0, Vn) → load 0 into VS0, compare against Vn in VS1.
            enc.emit_pxor(VS0, VS0); // VS0 = 0
            enc.emit_movdqu_load(VS1, R15, vd(n)); // VS1 = Vn
            pcmpgt(enc, VS0, VS1); // VS0 = (0 > Vn) = (Vn < 0)
        }
        SGe => {
            // Vn >= 0 = NOT(Vn < 0) = NOT pcmpgt(0, Vn).
            enc.emit_pxor(VS0, VS0); // VS0 = 0
            enc.emit_movdqu_load(VS1, R15, vd(n)); // VS1 = Vn
            pcmpgt(enc, VS0, VS1); // VS0 = (Vn < 0)
            enc.emit_pcmpeqd(VS1, VS1); // VS1 = all-ones
            enc.emit_pxor(VS0, VS1); // VS0 = NOT(Vn < 0) = (Vn >= 0)
        }
        SLe => {
            // Vn <= 0 = NOT(Vn > 0) = NOT pcmpgt(Vn, 0).
            enc.emit_movdqu_load(VS0, R15, vd(n)); // VS0 = Vn
            enc.emit_pxor(VS1, VS1); // 0
            pcmpgt(enc, VS0, VS1); // VS0 = (Vn > 0)
            enc.emit_pcmpeqd(VS1, VS1); // VS1 = all-ones
            enc.emit_pxor(VS0, VS1); // VS0 = NOT(Vn > 0) = (Vn <= 0)
        }
        _ => {
            enc.emit_ud2(); // UGt/UGe/Tst have no compare-vs-#0 form
            return;
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `SSHL`/`USHL` — register variable per-lane shift. x86 has no per-lane
/// variable SIMD shift pre-AVX2, so scalarize through ctx memory: for each lane,
/// take the SIGNED bottom byte of Vm's lane as the shift amount `k` and shift the
/// (sign/zero-extended) source element in RAX by CL. ARM semantics:
///   k >= 0  → left shift; `k >= esize_bits` → 0.
///   k <  0  → right shift by `-k` (arithmetic for SSHL, logical for USHL);
///             `-k >= esize_bits` → 0 (USHL) / sign-fill (SSHL, i.e. all-0/all-1).
/// The result is truncated to `esize` bytes on store. Uses only the reserved
/// scratch GPRs RAX (value) and RCX (count). D-form (`q==false`) zeroes Vd[127:64].
fn lower_vecshiftreg(enc: &mut X86Encoder, d: u8, n: u8, m: u8, size: u8, q: bool, signed: bool) {
    use crate::backend::lower_int::cc;
    let esize: i32 = 1i32 << size; // element bytes
    let esize_bits: i64 = (esize as i64) * 8;
    let total: i32 = if q { 16 } else { 8 };
    let dn = vd(n);
    let dm = vd(m);
    let dd = vd(d);
    // NOTE: must NOT pre-zero Vd — when d == n (the common in-place `sshl vX,vX,vY`
    // form) zeroing Vd would wipe the SOURCE before the per-lane loop reads it,
    // yielding all-zero (the SimdScalarDup wipe-before-read class of bug). Each
    // lane is read from `dn+off` BEFORE its own `dd+off` slot is written, and lanes
    // don't overlap, so an interleaved read-then-write is safe even for d == n. The
    // D-form upper 64 is zeroed at the END (after every source read completes).

    let mut off = 0i32;
    while off < total {
        // RCX = signed shift amount (bottom byte of Vm's lane).
        enc.emit_movsx_r64_mem8(RCX, R15, dm + off);
        // RAX = source element, sign- (SSHL) or zero- (USHL) extended to 64 bits.
        load_lane(enc, RAX, dn + off, esize as u8, signed);

        // if RCX < 0 → right-shift path.
        enc.emit_test_rr64(RCX, RCX);
        let j_right = enc.emit_jcc_rel32(cc::S);

        // ── left shift path (RCX >= 0) ──
        // if RCX >= esize_bits → result 0.
        enc.emit_cmp_r64_imm32(RCX, esize_bits as i32);
        let j_left_zero = enc.emit_jcc_rel32(cc::NL); // RCX >= esize_bits
        enc.emit_shl_r64_cl(RAX);
        let j_left_done = enc.emit_jmp_rel32();
        // left overflow → 0.
        let left_zero_pos = enc.pos();
        enc.patch_rel32(j_left_zero, left_zero_pos);
        enc.emit_xor_zero_r32(RAX);
        let j_left_done2 = enc.emit_jmp_rel32();

        // ── right shift path (RCX < 0) ──
        let right_pos = enc.pos();
        enc.patch_rel32(j_right, right_pos);
        enc.emit_neg_r64(RCX); // RCX = -k = s (positive shift magnitude)
        // if s >= esize_bits → overflow.
        enc.emit_cmp_r64_imm32(RCX, esize_bits as i32);
        let j_right_ovf = enc.emit_jcc_rel32(cc::NL); // s >= esize_bits
        // normal in-range right shift.
        if signed {
            enc.emit_sar_r64_cl(RAX);
        } else {
            enc.emit_shr_r64_cl(RAX);
        }
        let j_right_done = enc.emit_jmp_rel32();
        // right overflow.
        let right_ovf_pos = enc.pos();
        enc.patch_rel32(j_right_ovf, right_ovf_pos);
        if signed {
            // SSHL sign-fill: RAX (sign-extended) >> 63 → 0 (positive) or -1 (neg).
            enc.emit_mov_r64_imm32(RCX, 63);
            enc.emit_sar_r64_cl(RAX);
        } else {
            enc.emit_xor_zero_r32(RAX); // USHL → 0
        }

        // ── converge: store RAX truncated to `esize` bytes at Vd lane ──
        let store_pos = enc.pos();
        enc.patch_rel32(j_left_done, store_pos);
        enc.patch_rel32(j_left_done2, store_pos);
        enc.patch_rel32(j_right_done, store_pos);
        match esize {
            1 => enc.emit_mov_mem8_r64(R15, dd + off, RAX),
            2 => enc.emit_mov_mem16_r64(R15, dd + off, RAX),
            4 => enc.emit_mov_mem32_r64(R15, dd + off, RAX),
            _ => enc.emit_mov_mem_r64(R15, dd + off, RAX),
        }
        off += esize;
    }
    // D-form (q==false): zero Vd[127:64] AFTER all source lanes have been read.
    if !q {
        enc.emit_xor_zero_r32(RAX);
        enc.emit_mov_mem_r64(R15, dd + 8, RAX);
    }
}

/// NEON `SRI`/`SLI` — shift-right/left-and-insert by immediate.
///   SRI (`left=false`): per element, `Vd = (Vd & top_mask) | (Vn >>u shift)` —
///     the shifted-in low bits replace all but Vd's top `shift` bits.
///   SLI (`left=true`):  per element, `Vd = (Vd & low_mask) | (Vn << shift)` —
///     the shifted-in high bits replace all but Vd's low `shift` bits.
/// The insert must preserve exactly the untouched Vd bits, so build a per-element
/// keep-mask constant and blend. Shifts are done with the packed lane shift for
/// H/S/D; the byte (size=0) form emulates via 16-bit shift + per-byte mask.
/// `d` is read AND written. D-form (`q==false`) zeroes Vd[127:64].
fn lower_vecshiftins(enc: &mut X86Encoder, d: u8, n: u8, shift: u8, size: u8, q: bool, left: bool) {
    let esize_bits: u32 = 8u32 << size; // element bits: 8/16/32/64
    // Vn shifted → VS0. Vd (kept bits) masked → VS1. Result = VS0 | VS1.
    enc.emit_movdqu_load(VS0, R15, vd(n)); // Vn (source)
    // Per-element keep-mask for Vd: SRI keeps the TOP `shift` bits; SLI keeps the
    // LOW `shift` bits. Also mask the shifted Vn to drop bits that cross an element
    // boundary (x86 word/dword/qword shifts already keep bits within the lane, but
    // the byte form needs an explicit mask; and SRI/SLI's inserted region is the
    // complement of the keep-mask).
    let keep_mask_elem: u64 = if left {
        // SLI keeps low `shift` bits of Vd.
        if shift == 0 { 0 } else { (1u64 << shift) - 1 }
    } else {
        // SRI keeps top `shift` bits of Vd.
        if shift == 0 { 0 } else { !0u64 << (esize_bits - shift as u32) }
    };
    // The inserted (shifted-Vn) region = complement of keep, within the element.
    let elem_mask: u64 = if esize_bits >= 64 { !0u64 } else { (1u64 << esize_bits) - 1 };
    let ins_mask_elem: u64 = (!keep_mask_elem) & elem_mask;

    // Shift Vn into VS0 (packed lane shift).
    match size {
        0 => {
            // byte: emulate via 16-bit shift then per-byte mask to the element.
            if left {
                enc.emit_psllw_imm(VS0, shift);
            } else {
                enc.emit_psrlw_imm(VS0, shift);
            }
        }
        1 => { if left { enc.emit_psllw_imm(VS0, shift) } else { enc.emit_psrlw_imm(VS0, shift) } }
        2 => { if left { enc.emit_pslld_imm(VS0, shift) } else { enc.emit_psrld_imm(VS0, shift) } }
        _ => { if left { enc.emit_psllq_imm(VS0, shift) } else { enc.emit_psrlq_imm(VS0, shift) } }
    }
    // Mask the shifted Vn to the inserted region (VS3 = ins-mask splat).
    splat_elem_mask(enc, VS3, ins_mask_elem, esize_bits);
    enc.emit_pand(VS0, VS3);
    // Vd kept bits → VS1.
    enc.emit_movdqu_load(VS1, R15, vd(d));
    splat_elem_mask(enc, VS3, keep_mask_elem, esize_bits);
    enc.emit_pand(VS1, VS3);
    enc.emit_por(VS0, VS1);
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Splat a per-element mask (`mask_elem`, valid in the low `esize_bits` bits) to
/// all lanes of `dst`. Builds the 64-bit replicated pattern in RAX and broadcasts
/// via movq + punpcklqdq. Clobbers RAX.
fn splat_elem_mask(enc: &mut X86Encoder, dst: u8, mask_elem: u64, esize_bits: u32) {
    let pat64: u64 = match esize_bits {
        8 => (mask_elem & 0xFF).wrapping_mul(0x0101_0101_0101_0101),
        16 => {
            let x = mask_elem & 0xFFFF;
            x | (x << 16) | (x << 32) | (x << 48)
        }
        32 => {
            let x = mask_elem & 0xFFFF_FFFF;
            x | (x << 32)
        }
        _ => mask_elem,
    };
    enc.emit_mov_r64_imm64(RAX, pat64 as i64);
    enc.emit_movq_xmm_r64(dst, RAX);
    enc.emit_punpcklqdq(dst, dst);
}

/// NEON saturating/rounding/modular narrowing shift-right by immediate —
/// `SQSHRN`/`UQSHRN`/`SQSHRUN`/`SQRSHRN`/`UQRSHRN`/`SQRSHRUN`/`RSHRN`. Each
/// `2*esize_out`-byte source lane is shifted right by `shift` (rounded to nearest,
/// ties-up, when `round`), then narrowed to the `esize_out`-byte destination.
///
/// The full ARM ARM truth table (round?, src signed?, dst signed?, modular?):
///   RSHRN    : round, src N/A, dst N/A, MODULAR  — truncate low bits, NO clamp
///   SQSHRN   : —,     src S,   dst S,   saturate → signed   (packss)
///   SQRSHRN  : round, src S,   dst S,   saturate → signed   (packss)
///   UQSHRN   : —,     src U,   dst U,   saturate → unsigned (pminu + packus)
///   UQRSHRN  : round, src U,   dst U,   saturate → unsigned (pminu + packus)
///   SQSHRUN  : —,     src S,   dst U,   saturate → unsigned (packus clamps <0→0)
///   SQRSHRUN : round, src S,   dst U,   saturate → unsigned (packus clamps <0→0)
///
/// Two correctness invariants that the earlier code violated:
///  1. RSHRN is TRUNCATING, not clamping. It shares round/src/dst flags with
///     UQRSHRN, so `modular` is the only thing that separates them; when set we
///     take the low `esize_out*8` bits (mask + pack) and NEVER `pminu`-clamp.
///  2. Rounding is done as "shift then add the rounding bit", not "add bias then
///     shift". Adding `1<<(shift-1)` INSIDE the source lane overflows it (e.g.
///     signed `0x7FFF + 0x40` wraps negative) and corrupts every following step.
///     `(x >> s) + ((x >> (s-1)) & 1)` is bit-exact with `(x + 2^(s-1)) >> s`
///     for both arithmetic and logical shifts and never overflows the lane, since
///     `x >> s` already fits and the added bit is at most 1.
#[allow(clippy::too_many_arguments)]
fn lower_vecshiftnarrowsat(
    enc: &mut X86Encoder,
    d: u8,
    n: u8,
    shift: u8,
    esize_out: u8,
    high: bool,
    round: bool,
    src_signed: bool,
    dst_signed: bool,
    modular: bool,
) {
    // Source element width = 2 * esize_out bytes; the pack step needs the source
    // in 16-bit lanes (esize_out=1: src .8h) or 32-bit lanes (esize_out=2: src .4s).
    // .2s source (64-bit lanes, esize_out=4) is not wired — fail loud.
    if esize_out != 1 && esize_out != 2 {
        enc.emit_ud2();
        return;
    }
    enc.emit_movdqu_load(VS0, R15, vd(n));

    // Rounding bit: extract bit (shift-1) of each source lane BEFORE the shift, then
    // add it AFTER shifting. Done with a logical shift regardless of signedness —
    // bit (shift-1) is a low bit, unaffected by sign fill. VS2 holds the round bits.
    let do_round = round && shift > 0;
    if do_round {
        enc.emit_movdqa_rr(VS2, VS0);
        match esize_out {
            1 => {
                enc.emit_psrlw_imm(VS2, shift - 1);
                // Mask each word to its bit 0 (the round bit).
                enc.emit_pcmpeqw(VS3, VS3);
                enc.emit_psrlw_imm(VS3, 15); // 0x0001 per word
                enc.emit_pand(VS2, VS3);
            }
            _ => {
                enc.emit_psrld_imm(VS2, shift - 1);
                enc.emit_pcmpeqd(VS3, VS3);
                enc.emit_psrld_imm(VS3, 31); // 0x0000_0001 per dword
                enc.emit_pand(VS2, VS3);
            }
        }
    }

    // Shift right: arithmetic if the SOURCE is signed, logical otherwise.
    match (esize_out, src_signed) {
        (1, true) => enc.emit_psraw_imm(VS0, shift),
        (1, false) => enc.emit_psrlw_imm(VS0, shift),
        (2, true) => enc.emit_psrad_imm(VS0, shift),
        (2, false) => enc.emit_psrld_imm(VS0, shift),
        _ => unreachable!(),
    }

    // Add the rounding bit back (no lane overflow: shifted value fits with room).
    if do_round {
        match esize_out {
            1 => enc.emit_paddw(VS0, VS2),
            _ => enc.emit_paddd(VS0, VS2),
        }
    }

    // Narrow. RSHRN (modular) truncates to the low `esize_out*8` bits; everything
    // else saturates to the destination range.
    if modular {
        // Mask each source lane to its low destination-width bits, then pack. After
        // masking the value is non-negative and ≤ dst-max, so packus is exact and
        // performs the modular truncation (never a clamp).
        match esize_out {
            1 => {
                enc.emit_pcmpeqw(VS3, VS3);
                enc.emit_psrlw_imm(VS3, 8); // 0x00FF per word
                enc.emit_pand(VS0, VS3);
                enc.emit_packuswb(VS0, VS0);
            }
            _ => {
                enc.emit_pcmpeqd(VS3, VS3);
                enc.emit_psrld_imm(VS3, 16); // 0x0000_FFFF per dword
                enc.emit_pand(VS0, VS3);
                enc.emit_packusdw(VS0, VS0);
            }
        }
    } else {
        // Saturating narrow via pack. packss{wb,dw} saturate signed source lanes to
        // the SIGNED dst range; packus{wb,dw} saturate to the UNSIGNED dst range but
        // interpret the source lane as SIGNED — so for an UNSIGNED source (UQSHRN/
        // UQRSHRN) a lane with the high bit set would wrongly clamp to 0, hence the
        // pminu pre-clamp. The (src_signed, dst_signed) combos that occur:
        //   SQSHRN/SQRSHRN  : src S, dst S → packss
        //   SQSHRUN/SQRSHRUN: src S, dst U → packus (negatives clamp to 0)
        //   UQSHRN/UQRSHRN  : src U, dst U → pminu then packus
        match (esize_out, dst_signed) {
            (1, true) => enc.emit_packsswb(VS0, VS0),
            (1, false) => {
                if !src_signed {
                    narrow_unsigned_clamp_to_byte(enc);
                } else {
                    enc.emit_packuswb(VS0, VS0);
                }
            }
            (2, true) => enc.emit_packssdw(VS0, VS0),
            (2, false) => {
                if !src_signed {
                    narrow_unsigned_clamp_to_half(enc);
                } else {
                    enc.emit_packusdw(VS0, VS0);
                }
            }
            _ => unreachable!(),
        }
    }
    enc.emit_movq_xmm_xmm(VS0, VS0); // keep low 64, zero the upper
    if high {
        enc.emit_movdqu_load(VS1, R15, vd(d));
        enc.emit_punpcklqdq(VS1, VS0); // [Vd.lo64, result]
        enc.emit_movdqu_store(R15, vd(d), VS1);
    } else {
        enc.emit_movdqu_store(R15, vd(d), VS0);
    }
}

/// Unsigned-saturate 16-bit source lanes (already right-shifted, but possibly
/// > 0xFF) to unsigned bytes and pack into VS0's low 64. `pminuw` against 0x00FF
/// clamps each word to ≤ 0xFF, after which `packuswb` (signed-saturate of a now
/// non-negative value) is exact.
fn narrow_unsigned_clamp_to_byte(enc: &mut X86Encoder) {
    // VS3 = 0x00FF per word.
    enc.emit_pcmpeqw(VS3, VS3);
    enc.emit_psrlw_imm(VS3, 8); // 0x00FF
    enc.emit_pminuw(VS0, VS3);
    enc.emit_packuswb(VS0, VS0);
}

/// Unsigned-saturate 32-bit source lanes (already right-shifted, but possibly
/// > 0xFFFF) to unsigned halfwords and pack into VS0's low 64. `pminud` against
/// 0x0000FFFF clamps each dword ≤ 0xFFFF; `packusdw` is then exact.
fn narrow_unsigned_clamp_to_half(enc: &mut X86Encoder) {
    // VS3 = 0x0000FFFF per dword.
    enc.emit_pcmpeqd(VS3, VS3);
    enc.emit_psrld_imm(VS3, 16); // 0x0000FFFF
    enc.emit_pminud(VS0, VS3);
    enc.emit_packusdw(VS0, VS0);
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
        2 => {
            // .4s → .4h (B32): shift dwords, mask each low 16 bits, pack 4 dwords
            // → 4 halfwords. The mask guarantees packusdw saturation is exact.
            enc.emit_psrld_imm(VS0, shift);
            enc.emit_pcmpeqd(VS3, VS3);
            enc.emit_psrld_imm(VS3, 16); // 0x0000FFFF per dword
            enc.emit_pand(VS0, VS3);
            enc.emit_packusdw(VS0, VS0);
        }
        4 => {
            // .2d → .2s: shift qwords, gather the two low-32s into the low 64.
            enc.emit_psrlq_imm(VS0, shift);
            enc.emit_pshufd(VS0, VS0, 0x08); // [q0.lo32, q1.lo32, q0.lo32, q0.lo32]
        }
        _ => {
            enc.emit_ud2(); // .2h etc. — Tier 1
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
        // High 64 bits (the `2` variants): bring Vn[127:64] into the low 64 via
        // psrldq #8, then widen with pmovsx (SSHLL2/SXTL2) or pmovzx
        // (USHLL2/UXTL2). B32: this replaces the old zero-extend-only punpckh
        // path so the signed high-half forms no longer fail-loud.
        enc.emit_psrldq_imm(VS0, 8);
        match (esize_in, signed) {
            (1, false) => enc.emit_pmovzxbw(VS0, VS0),
            (1, true) => enc.emit_pmovsxbw(VS0, VS0),
            (2, false) => enc.emit_pmovzxwd(VS0, VS0),
            (2, true) => enc.emit_pmovsxwd(VS0, VS0),
            (4, false) => enc.emit_pmovzxdq(VS0, VS0),
            (4, true) => enc.emit_pmovsxdq(VS0, VS0),
            _ => { enc.emit_ud2(); return; }
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
            // FMAX/FMIN Dd,Dn,Dm PROPAGATE NaN (→ quiet NaN) and break the ±0 tie
            // toward +0 (FMAX) / −0 (FMIN). Bare maxsd/minsd return the 2nd source
            // on a NaN or an equal (±0) lane, so both cases are wrong. See helper.
            Min => lower_fp_max_min_scalar(enc, true, false, n, m),
            Max => lower_fp_max_min_scalar(enc, true, true, n, m),
            // FMAXNM/FMINNM Dd,Dn,Dm — IEEE maxNum/minNum (ignore-NaN). x86
            // `maxsd dst=Vn, Vm` returns Vm when Vn is NaN (correct — the non-NaN
            // operand) but ALSO returns Vm when Vm is NaN (WRONG — should return
            // Vn). Fix the Vm-is-NaN lane: replace it with Vn, and break the ±0 tie
            // like FMAX/FMIN. (Both-NaN → Vn=NaN, which maxNum permits.)
            MaxNm | MinNm => lower_fp_maxnum_scalar(enc, true, matches!(op, MaxNm), n, m),
            NMul => {
                // FNMUL Dd = -(Dn*Dm): multiply, then flip the sign bit of the
                // low 64 (mask 0x8000_0000_0000_0000 built in a GPR → XMM, same
                // idiom as lower_fpun::Neg's double form).
                enc.emit_mulsd(VS0, VS1);
                enc.emit_mov_r64_imm64(RAX, 0x8000_0000_0000_0000u64 as i64);
                enc.emit_movq_xmm_r64(VS1, RAX);
                enc.emit_pxor(VS0, VS1);
            }
        }
    } else {
        enc.emit_movss_load(VS0, R15, vd(n));
        enc.emit_movss_load(VS1, R15, vd(m));
        match op {
            Add => enc.emit_addss(VS0, VS1),
            Sub => enc.emit_subss(VS0, VS1),
            Mul => enc.emit_mulss(VS0, VS1),
            Div => enc.emit_divss(VS0, VS1),
            Min => lower_fp_max_min_scalar(enc, false, false, n, m),
            Max => lower_fp_max_min_scalar(enc, false, true, n, m),
            MaxNm | MinNm => lower_fp_maxnum_scalar(enc, false, matches!(op, MaxNm), n, m),
            NMul => {
                // FNMUL Sd = -(Sn*Sm): multiply, then flip the sign bit of the
                // low 32 (mask 0x8000_0000 via movd, mirroring lower_fpun::Neg's
                // single form).
                enc.emit_mulss(VS0, VS1);
                enc.emit_mov_r64_imm32(RAX, 0x8000_0000u32 as i32);
                enc.emit_movd_xmm_r32(VS1, RAX);
                enc.emit_pxor(VS0, VS1);
            }
        }
    }
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Scalar FMAX/FMIN (ARM default, NaN-propagating). x86 maxsd/minsd is wrong on two
/// classes of lane: (a) if either operand is NaN it returns the 2nd source, but ARM
/// must return a QUIET NaN; (b) on the ±0 tie (operands compare equal) it returns
/// the 2nd source, but ARM must return +0 for FMAX / −0 for FMIN. We layer two
/// branchless blends on the raw result — the eq-tie lanes and the unordered (NaN)
/// lanes are disjoint (cmpeq is false for NaN), so ordering the eq-blend before the
/// NaN-blend is safe. Result left in VS0; the caller's 128-bit store zeroes the
/// upper bits (ARM FP-write rule). Operates on the low scalar element only.
fn lower_fp_max_min_scalar(enc: &mut X86Encoder, dbl: bool, is_max: bool, n: u8, m: u8) {
    // VS0 = Vn, VS1 = Vm already loaded by the caller.
    // ── (1) raw x86 max/min into VS0. ──
    if dbl {
        if is_max { enc.emit_maxsd(VS0, VS1) } else { enc.emit_minsd(VS0, VS1) }
    } else if is_max {
        enc.emit_maxss(VS0, VS1)
    } else {
        enc.emit_minss(VS0, VS1)
    }
    // ── (2) ±0 (equal-magnitude) tie fix. eq = ordered-equal(Vn,Vm) (false for NaN).
    // tie value = (Vn AND Vm) for FMAX (+0 wins: sign bit clear survives AND) /
    //             (Vn OR  Vm) for FMIN (−0 wins: sign bit set survives OR). Exact for
    // any equal pair (AND/OR of a value with itself is the value). ──
    // VS2 = Vn, VS3 = Vm (fresh copies).
    if dbl {
        enc.emit_movsd_load(VS2, R15, vd(n));
        enc.emit_movsd_load(VS3, R15, vd(m));
    } else {
        enc.emit_movss_load(VS2, R15, vd(n));
        enc.emit_movss_load(VS3, R15, vd(m));
    }
    // VS3 becomes the eq mask; keep a tie value first in VS2.
    // tie value in VS2:
    if is_max { enc.emit_pand(VS2, VS3); } else { enc.emit_por(VS2, VS3); } // VS2 = tie value
    // Rebuild VS3 = Vn, then eq mask = cmp(Vn, Vm, EQ).
    if dbl { enc.emit_movsd_load(VS3, R15, vd(n)); } else { enc.emit_movss_load(VS3, R15, vd(n)); }
    // VS1 still holds Vm.
    if dbl { enc.emit_cmpsd(VS3, VS1, 0) } else { enc.emit_cmpss(VS3, VS1, 0) } // pred 0 = EQ (ordered)
    // Blend: VS0 = (eq ? tie : raw). VS2 &= eq; VS0 &= ~eq; VS0 |= VS2.
    enc.emit_pand(VS2, VS3);   // VS2 = tie & eq
    enc.emit_pandn(VS3, VS0);  // VS3 = ~eq & raw
    enc.emit_por(VS3, VS2);    // VS3 = eq-blended
    enc.emit_movdqa_rr(VS0, VS3);
    // ── (3) NaN propagate: unord(Vn,Vm) lanes → canonical quiet NaN. ──
    if dbl { enc.emit_movsd_load(VS2, R15, vd(n)); } else { enc.emit_movss_load(VS2, R15, vd(n)); }
    if dbl { enc.emit_cmpsd(VS2, VS1, 3) } else { enc.emit_cmpss(VS2, VS1, 3) } // VS2 = unord mask
    // VS3 = canonical qNaN (low element).
    if dbl {
        enc.emit_mov_r64_imm64(RAX, 0x7FF8_0000_0000_0000u64 as i64);
        enc.emit_movq_xmm_r64(VS3, RAX);
    } else {
        enc.emit_mov_r64_imm32(RAX, 0x7FC0_0000u32 as i32);
        enc.emit_movd_xmm_r32(VS3, RAX);
    }
    enc.emit_pand(VS3, VS2);   // VS3 = qNaN & nanmask
    enc.emit_pandn(VS2, VS0);  // VS2 = ~nanmask & eq-blended
    enc.emit_por(VS2, VS3);    // VS2 = final
    enc.emit_movdqa_rr(VS0, VS2);
}

/// Scalar FMAXNM/FMINNM (IEEE maxNum/minNum) core. Computes `r = max/min(Vn, Vm)`
/// (x86 semantics: returns the 2nd source on a NaN or equal lane), then (a) patches
/// the Vm-is-NaN lane back to Vn so the ignore-NaN rule holds, and (b) breaks the
/// ±0 tie toward +0 (max) / −0 (min) like FMAX/FMIN. Result in VS0 (low element);
/// the caller's 128-bit store zeroes the upper bits per the ARM FP-write rule.
fn lower_fp_maxnum_scalar(enc: &mut X86Encoder, dbl: bool, is_max: bool, n: u8, m: u8) {
    // VS0 = Vn, VS1 = Vm already loaded by the caller.
    // ── (1) raw x86 max/min into VS0. ──
    if dbl {
        if is_max { enc.emit_maxsd(VS0, VS1) } else { enc.emit_minsd(VS0, VS1) }
    } else if is_max {
        enc.emit_maxss(VS0, VS1)
    } else {
        enc.emit_minss(VS0, VS1)
    }
    // ── (2) ±0 tie fix (same as FMAX/FMIN; disjoint from NaN lanes). ──
    if dbl {
        enc.emit_movsd_load(VS2, R15, vd(n));
        enc.emit_movsd_load(VS3, R15, vd(m));
    } else {
        enc.emit_movss_load(VS2, R15, vd(n));
        enc.emit_movss_load(VS3, R15, vd(m));
    }
    if is_max { enc.emit_pand(VS2, VS3); } else { enc.emit_por(VS2, VS3); } // VS2 = tie value
    if dbl { enc.emit_movsd_load(VS3, R15, vd(n)); } else { enc.emit_movss_load(VS3, R15, vd(n)); }
    if dbl { enc.emit_cmpsd(VS3, VS1, 0) } else { enc.emit_cmpss(VS3, VS1, 0) } // VS3 = eq mask
    enc.emit_pand(VS2, VS3);
    enc.emit_pandn(VS3, VS0);
    enc.emit_por(VS3, VS2);
    enc.emit_movdqa_rr(VS0, VS3);
    // ── (3) ignore-NaN: replace the Vm-is-NaN lane with Vn. mask = unord(Vm,Vm). ──
    if dbl { enc.emit_movsd_load(VS2, R15, vd(n)); } else { enc.emit_movss_load(VS2, R15, vd(n)); }
    enc.emit_movdqa_rr(VS3, VS1); // VS3 = Vm
    if dbl { enc.emit_cmpsd(VS3, VS3, 3) } else { enc.emit_cmpss(VS3, VS3, 3) } // VS3 = Vm-NaN mask
    enc.emit_pand(VS2, VS3);   // VS2 = Vn & mask
    enc.emit_pandn(VS3, VS0);  // VS3 = ~mask & result
    enc.emit_por(VS3, VS2);
    enc.emit_movdqa_rr(VS0, VS3);
}

/// Scalar FP 3-source fused multiply-add — FMADD/FMSUB/FNMADD/FNMSUB Sd,Sn,Sm,Sa
/// (and the D-form). Lowers to x86 FMA3 (single fused rounding, matching ARM).
///
/// ARM semantics (from the ARM ARM FPMulAdd pseudocode):
///   FMADD  Sd = Sa + Sn*Sm       FMSUB  Sd = Sa - Sn*Sm
///   FNMADD Sd = -Sa - Sn*Sm      FNMSUB Sd = -Sa + Sn*Sm
///
/// x86 FMA3 "213" form computes: dst = src1(vvvv) * dst + src2(rm). We load
///   VS0 = Sn (dst, overwritten by the result), VS1 = Sm (vvvv), VS2 = Sa (rm),
/// so the four ARM ops map onto the four FMA3 sign variants:
///   FMADD  → VFMADD213  ( Sn*Sm + Sa)
///   FMSUB  → VFNMADD213 (-Sn*Sm + Sa = Sa - Sn*Sm)
///   FNMADD → VFNMSUB213 (-Sn*Sm - Sa)
///   FNMSUB → VFMSUB213  ( Sn*Sm - Sa = -Sa + Sn*Sm)
///
/// The scalar loads zero VS0[127:32/64]; the FMA3 SS/SD ops write only the low
/// element and preserve the rest of VS0, so the 128-bit store leaves Vd's upper
/// bits zeroed (ARM FP-write semantics).
fn lower_fpfma(enc: &mut X86Encoder, op: crate::ir::ops::FpFmaOp, dbl: bool, d: u8, n: u8, m: u8, a: u8) {
    use crate::ir::ops::FpFmaOp::*;
    if dbl {
        enc.emit_movsd_load(VS0, R15, vd(n)); // dst = Sn
        enc.emit_movsd_load(VS1, R15, vd(m)); // vvvv = Sm
        enc.emit_movsd_load(VS2, R15, vd(a)); // rm = Sa
    } else {
        enc.emit_movss_load(VS0, R15, vd(n));
        enc.emit_movss_load(VS1, R15, vd(m));
        enc.emit_movss_load(VS2, R15, vd(a));
    }
    match op {
        Madd => enc.emit_vfmadd213(dbl, VS0, VS1, VS2),   //  Sn*Sm + Sa
        Msub => enc.emit_vfnmadd213(dbl, VS0, VS1, VS2),  // -Sn*Sm + Sa = Sa - Sn*Sm
        NMadd => enc.emit_vfnmsub213(dbl, VS0, VS1, VS2), // -Sn*Sm - Sa
        NMsub => enc.emit_vfmsub213(dbl, VS0, VS1, VS2),  //  Sn*Sm - Sa = -Sa + Sn*Sm
    }
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// B20: scalar FP 1-source — FMOV/FABS/FNEG/FSQRT Sd,Sn (and D-form). Loads the
/// scalar from Vn (movss/movsd zero-extend [127:32]/[127:64]), applies the op,
/// and stores all 128 bits — so the FP-register-write zeroing rule holds. ABS/NEG
/// build a sign-bit mask in a GPR → XMM and pand/pxor it.
fn lower_fpun(enc: &mut X86Encoder, op: crate::ir::ops::FpUnOp, dbl: bool, d: u8, n: u8) {
    use crate::ir::ops::FpUnOp::*;
    const RAX: u8 = 0;
    if dbl {
        enc.emit_movsd_load(VS0, R15, vd(n));
        match op {
            Mov => {}
            Sqrt => enc.emit_sqrtsd(VS0, VS0),
            Abs => {
                enc.emit_mov_r64_imm64(RAX, 0x7FFF_FFFF_FFFF_FFFFu64 as i64);
                enc.emit_movq_xmm_r64(VS1, RAX);
                enc.emit_pand(VS0, VS1);
            }
            Neg => {
                enc.emit_mov_r64_imm64(RAX, 0x8000_0000_0000_0000u64 as i64);
                enc.emit_movq_xmm_r64(VS1, RAX);
                enc.emit_pxor(VS0, VS1);
            }
        }
    } else {
        enc.emit_movss_load(VS0, R15, vd(n));
        match op {
            Mov => {}
            Sqrt => enc.emit_sqrtss(VS0, VS0),
            Abs => {
                enc.emit_mov_r64_imm32(RAX, 0x7FFF_FFFF);
                enc.emit_movd_xmm_r32(VS1, RAX);
                enc.emit_pand(VS0, VS1);
            }
            Neg => {
                enc.emit_mov_r64_imm32(RAX, 0x8000_0000u32 as i32);
                enc.emit_movd_xmm_r32(VS1, RAX);
                enc.emit_pxor(VS0, VS1);
            }
        }
    }
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Scalar pairwise reduce — `ADDP d0,Vn.2d` / `FADDP {s,d}0,Vn.2{s,d}`: sum the
/// two lanes of Vn into Vd lane 0, the rest of Vd zeroed. Integer .2d: load Vn,
/// swap the qwords (pshufd 0x4E), paddq, keep the low 64 (movq zeroes high). FP:
/// move lane1 down to lane0 then addss/addsd against the original lane0.
fn lower_vecscalarpair(enc: &mut X86Encoder, is_fp: bool, dbl: bool, d: u8, n: u8) {
    enc.emit_movdqu_load(VS0, R15, vd(n));
    if !is_fp {
        // Integer ADDP .2d: lane0 + lane1.
        enc.emit_pshufd(VS1, VS0, 0x4E); // [n1, n0]
        enc.emit_paddq(VS0, VS1);        // lane0 = n0 + n1
        enc.emit_movq_xmm_xmm(VS0, VS0); // keep low 64, zero the rest
    } else if dbl {
        // FADDP .2d: lane0 + lane1 (the two f64 lanes).
        enc.emit_movdqa_rr(VS1, VS0);
        enc.emit_pshufd(VS1, VS1, 0x4E); // lane1 → lane0 position
        enc.emit_addsd(VS0, VS1);        // VS0 lane0 += lane1
        enc.emit_movq_xmm_xmm(VS0, VS0); // scalar D-form: keep low 64
    } else {
        // FADDP .2s: lane0 + lane1 (the two low f32 lanes).
        enc.emit_movdqa_rr(VS1, VS0);
        enc.emit_pshufd(VS1, VS1, 0x55); // dword1 → dword0
        enc.emit_addss(VS0, VS1);        // VS0 lane0 += lane1
        // Scalar S-form: zero everything above the low 32 bits (round-trip via a
        // GPR — movd xmm,r32 zero-extends into [127:32]).
        enc.emit_movd_r32_xmm(RAX, VS0);
        enc.emit_movd_xmm_r32(VS0, RAX);
    }
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Scalar FP round-to-integral (`FRINTN/M/P/Z/A/X/I`) via x86 `roundss`/`roundsd`.
/// The `roundss` imm8 encodes: bits[1:0] = rounding mode (0=nearest-even, 1=down/
/// floor, 2=up/ceil, 3=truncate); bit2 = use MXCSR (ignore [1:0]); bit3 = suppress
/// the precision (inexact) exception. ARM FRINTX/FRINTI raise inexact, so bit3 is
/// CLEAR for them and SET for the others. The scalar load zero-fills the high
/// lanes, so the 128-bit store leaves Vd[127:32/64] zeroed (FP-write semantics).
fn lower_fpround(
    enc: &mut X86Encoder,
    d: u8,
    n: u8,
    dbl: bool,
    round: crate::ir::ops::RoundMode,
    raise_inexact: bool,
) {
    use crate::ir::ops::RoundMode::*;
    // FRINTA (ties-AWAY) has no x86 rounding mode. The old approximation used
    // nearest-EVEN (imm 0x00), silently wrong for every halfway case (2.5→2 not 3,
    // −0.5→−0 not −1). Emulate exactly on the low element: t = trunc(x);
    // diff = x - t; if |diff| >= 0.5 add copysign(1.0, x). Single rounding.
    if matches!(round, NearestTiesAway) {
        lower_fpround_ties_away(enc, d, n, dbl);
        return;
    }
    // bits[1:0] rounding + bit2 MXCSR select.
    let rc: u8 = match round {
        Nearest => 0x00,
        NegInf => 0x01,            // floor
        PosInf => 0x02,            // ceil
        Zero => 0x03,              // truncate
        NearestTiesAway => 0x00,   // unreachable (handled above)
        Current => 0x04,           // use MXCSR rounding mode
    };
    // Suppress inexact unless the op is defined to raise it (FRINTX/FRINTI).
    let imm = if raise_inexact { rc } else { rc | 0x08 };
    if dbl {
        enc.emit_movsd_load(VS0, R15, vd(n));
        enc.emit_roundsd(VS0, VS0, imm);
    } else {
        enc.emit_movss_load(VS0, R15, vd(n));
        enc.emit_roundss(VS0, VS0, imm);
    }
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Scalar FRINTA (round to integral, ties AWAY from zero) on the low element.
/// `t = trunc(x); diff = x - t` (exact for finite x); if `|diff| >= 0.5` add
/// `copysign(1.0, x)`. No intermediate rounding (unlike add-half-then-trunc).
/// The scalar loads zero the high lanes so the 128-bit store obeys FP-write rules.
fn lower_fpround_ties_away(enc: &mut X86Encoder, d: u8, n: u8, dbl: bool) {
    // VS0 = x.
    if dbl { enc.emit_movsd_load(VS0, R15, vd(n)); } else { enc.emit_movss_load(VS0, R15, vd(n)); }
    // VS1 = t = trunc(x).
    enc.emit_movdqa_rr(VS1, VS0);
    if dbl { enc.emit_roundsd(VS1, VS1, 0x03 | 0x08) } else { enc.emit_roundss(VS1, VS1, 0x03 | 0x08) }
    // VS2 = |diff| = |x - t|.
    enc.emit_movdqa_rr(VS2, VS0);
    if dbl { enc.emit_subsd(VS2, VS1) } else { enc.emit_subss(VS2, VS1) }
    enc.emit_pcmpeqd(VS3, VS3);
    if dbl { enc.emit_psrlq_imm(VS3, 1) } else { enc.emit_psrld_imm(VS3, 1) } // 0x7FFF… abs mask
    enc.emit_pand(VS2, VS3); // VS2 = |diff|
    // VS3 = 0.5; m = cmp(|diff|, 0.5, NLT) → all-ones (low elem) where |diff|>=0.5.
    if dbl {
        enc.emit_mov_r64_imm64(RAX, 0x3FE0_0000_0000_0000u64 as i64);
        enc.emit_movq_xmm_r64(VS3, RAX);
        enc.emit_cmpsd(VS2, VS3, 5); // VS2 = mask
    } else {
        enc.emit_mov_r64_imm32(RAX, 0x3F00_0000u32 as i32);
        enc.emit_movd_xmm_r32(VS3, RAX);
        enc.emit_cmpss(VS2, VS3, 5);
    }
    // VS3 = copysign(1.0, x) = (x & signmask) | 1.0.
    enc.emit_movdqa_rr(VS3, VS0);
    if dbl {
        enc.emit_mov_r64_imm64(RAX, 0x8000_0000_0000_0000u64 as i64);
        enc.emit_movq_xmm_r64(VS0, RAX);
        enc.emit_pand(VS3, VS0);
        enc.emit_mov_r64_imm64(RAX, 0x3FF0_0000_0000_0000u64 as i64); // 1.0 (f64)
        enc.emit_movq_xmm_r64(VS0, RAX);
        enc.emit_por(VS3, VS0);   // VS3 = copysign(1.0, x)
        enc.emit_pand(VS3, VS2);  // VS3 = add (0 where |diff|<0.5)
        enc.emit_addsd(VS1, VS3); // VS1 = t + add
    } else {
        enc.emit_mov_r64_imm32(RAX, 0x8000_0000u32 as i32);
        enc.emit_movd_xmm_r32(VS0, RAX);
        enc.emit_pand(VS3, VS0);
        enc.emit_mov_r64_imm32(RAX, 0x3F80_0000u32 as i32); // 1.0 (f32)
        enc.emit_movd_xmm_r32(VS0, RAX);
        enc.emit_por(VS3, VS0);
        enc.emit_pand(VS3, VS2);
        enc.emit_addss(VS1, VS3);
    }
    enc.emit_movdqa_rr(VS0, VS1);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Vector FP round-to-integral (`FRINT{N,M,P,Z,A}` `Vd.<T>,Vn.<T>`). Uses SSE4.1
/// ROUNDPS/ROUNDPD with the packed rounding-mode immediate (inexact suppressed —
/// FRINTN/M/P/Z/A never raise inexact). x86 has direct modes for N/M/P/Z:
///   Nearest→0x00  NegInf(floor)→0x01  PosInf(ceil)→0x02  Zero(trunc)→0x03.
/// `NearestTiesAway` (FRINTA) has NO x86 mode. The old `trunc(x + copysign(0.5,x))`
/// DOUBLE-ROUNDS: the add itself rounds up across the .5 boundary (e.g. 0.49999997f
/// + 0.5 rounds to 1.0, so trunc gives 1 not 0). Use instead the exact branchless
/// form: `t = trunc(x); diff = x - t` (exact for finite x); if `|diff| >= 0.5` add
/// `copysign(1.0, x)`. This rounds halfway AND above-half cases away from zero while
/// leaving all others equal to trunc-toward-nearest with no intermediate rounding.
fn lower_vecfpround(
    enc: &mut X86Encoder,
    d: u8,
    n: u8,
    dbl: bool,
    q: bool,
    round: crate::ir::ops::RoundMode,
) {
    use crate::ir::ops::RoundMode::*;
    enc.emit_movdqu_load(VS0, R15, vd(n)); // VS0 = Vn (all lanes)
    match round {
        Nearest | NegInf | PosInf | Zero => {
            let rc: u8 = match round {
                Nearest => 0x00,
                NegInf => 0x01,
                PosInf => 0x02,
                _ => 0x03, // Zero
            };
            let imm = rc | 0x08; // suppress inexact
            if dbl { enc.emit_roundpd(VS0, VS0, imm) } else { enc.emit_roundps(VS0, VS0, imm) }
        }
        // FRINTA — ties-away via trunc + magnitude-of-fraction test (no double round).
        NearestTiesAway | Current => {
            // VS1 = t = trunc(x).
            enc.emit_movdqa_rr(VS1, VS0);
            if dbl { enc.emit_roundpd(VS1, VS1, 0x03 | 0x08) } else { enc.emit_roundps(VS1, VS1, 0x03 | 0x08) }
            // VS2 = diff = x - t; VS2 = |diff| (clear sign).
            enc.emit_movdqa_rr(VS2, VS0);
            if dbl { enc.emit_subpd(VS2, VS1) } else { enc.emit_subps(VS2, VS1) }
            enc.emit_pcmpeqd(VS3, VS3);
            if dbl { enc.emit_psrlq_imm(VS3, 1) } else { enc.emit_psrld_imm(VS3, 1) } // 0x7FFF… abs mask
            enc.emit_pand(VS2, VS3); // VS2 = |diff|
            // VS3 = 0.5 (broadcast); m = cmpps(|diff|, 0.5, NLT) → true where |diff|>=0.5.
            if dbl {
                enc.emit_mov_r64_imm64(RAX, 0x3FE0_0000_0000_0000u64 as i64);
                enc.emit_movq_xmm_r64(VS3, RAX);
                enc.emit_pshufd(VS3, VS3, 0x44);
                enc.emit_cmppd(VS2, VS3, 5); // VS2 = mask (|diff|>=0.5)
            } else {
                enc.emit_mov_r64_imm32(RAX, 0x3F00_0000u32 as i32);
                enc.emit_movd_xmm_r32(VS3, RAX);
                enc.emit_pshufd(VS3, VS3, 0x00);
                enc.emit_cmpps(VS2, VS3, 5);
            }
            // VS3 = copysign(1.0, x) = (x & signmask) | 1.0.
            if dbl {
                enc.emit_movdqa_rr(VS3, VS0);
                enc.emit_mov_r64_imm64(RAX, 0x8000_0000_0000_0000u64 as i64);
                enc.emit_movq_xmm_r64(VS0, RAX); // reuse VS0 as sign mask (x kept in VS3)
                enc.emit_pshufd(VS0, VS0, 0x44);
                enc.emit_pand(VS3, VS0);         // VS3 = x & signmask
                enc.emit_mov_r64_imm64(RAX, 0x3FF0_0000_0000_0000u64 as i64); // 1.0 (f64)
                enc.emit_movq_xmm_r64(VS0, RAX);
                enc.emit_pshufd(VS0, VS0, 0x44);
                enc.emit_por(VS3, VS0);          // VS3 = copysign(1.0, x)
                enc.emit_pand(VS3, VS2);         // VS3 = add (0 where |diff|<0.5)
                enc.emit_addpd(VS1, VS3);        // VS1 = t + add
            } else {
                enc.emit_movdqa_rr(VS3, VS0);
                enc.emit_mov_r64_imm32(RAX, 0x8000_0000u32 as i32);
                enc.emit_movd_xmm_r32(VS0, RAX);
                enc.emit_pshufd(VS0, VS0, 0x00);
                enc.emit_pand(VS3, VS0);         // VS3 = x & signmask
                enc.emit_mov_r64_imm32(RAX, 0x3F80_0000u32 as i32); // 1.0 (f32)
                enc.emit_movd_xmm_r32(VS0, RAX);
                enc.emit_pshufd(VS0, VS0, 0x00);
                enc.emit_por(VS3, VS0);          // VS3 = copysign(1.0, x)
                enc.emit_pand(VS3, VS2);         // VS3 = add
                enc.emit_addps(VS1, VS3);        // VS1 = t + add
            }
            enc.emit_movdqa_rr(VS0, VS1);
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// FCVT scalar precision convert (single↔double). ARM defines a scalar-FP result to
/// ZERO Vd[127:width] — so the whole q-reg slot must hold only the converted scalar.
///
/// The scalar load (`movss`/`movsd`) zero-fills the high lanes of the SOURCE register,
/// but the x86 convert instructions are in-place on the low element and PRESERVE the
/// destination's upper bits. For the NARROWING `cvtsd2ss` that is a real trap: it
/// writes only bits[31:0] and leaves bits[63:32] holding the upper half of the source
/// double — a silent stale-upper-bits miscompile (e.g. `FCVT S0,D1` with D1=2.25 gave
/// `..4002000040100000` instead of `..0000000040100000`). To match the FP-write
/// zeroing rule for BOTH directions we convert into a freshly-zeroed scratch (VS1),
/// so bits above the result element are guaranteed 0, then store all 128 bits.
/// Half-precision (16-bit) needs F16C and is fail-loud for now (rare on the boot path).
fn lower_fpcvt2(enc: &mut X86Encoder, d: u8, n: u8, from_bits: u8, to_bits: u8) {
    match from_bits {
        32 => enc.emit_movss_load(VS0, R15, vd(n)),
        64 => enc.emit_movsd_load(VS0, R15, vd(n)),
        _ => { enc.emit_ud2(); return; }
    }
    // Zero the destination scratch so any bits above the converted element are 0
    // (cvt* write only the low element and preserve the rest of the destination).
    enc.emit_pxor(VS1, VS1);
    match (from_bits, to_bits) {
        (32, 64) => enc.emit_cvtss2sd(VS1, VS0),
        (64, 32) => enc.emit_cvtsd2ss(VS1, VS0),
        _ => { enc.emit_ud2(); return; }
    }
    enc.emit_movdqu_store(R15, vd(d), VS1);
}

/// FCSEL Dd,Dn,Dm,cond — Dd = cond ? Dn : Dm. Evaluates the ARM condition from the
/// packed NZCV (ctx 0x108), builds an all-1s/all-0s mask, and branchlessly blends
/// the two source scalars: VS0 = (Dn & mask) | (Dm & ~mask). The scalar loads
/// zero the high lanes, so the 128-bit store leaves Vd's upper bits zeroed.
fn lower_fpcsel(enc: &mut X86Encoder, d: u8, n: u8, m: u8,
                cond: crate::decoder::Cond, dbl: bool) {
    const RAX: u8 = 0;
    const RCX: u8 = 1;
    const NZCV_DISP: i32 = 0x108;
    enc.emit_mov_r64_mem(RAX, R15, NZCV_DISP); // RAX = packed ARM NZCV
    crate::backend::IntLower::emit_arm_cond_to_bool(enc, RAX, RCX, cond); // RCX = 0/1
    enc.emit_neg_r64(RCX);             // RCX = 0 or 0xFFFF_FFFF_FFFF_FFFF (the mask)
    enc.emit_movq_xmm_r64(VS2, RCX);   // VS2[63:0] = mask, [127:64] = 0
    if dbl {
        enc.emit_movsd_load(VS0, R15, vd(n));
        enc.emit_movsd_load(VS1, R15, vd(m));
    } else {
        enc.emit_movss_load(VS0, R15, vd(n));
        enc.emit_movss_load(VS1, R15, vd(m));
    }
    enc.emit_pand(VS0, VS2);   // VS0 = Dn & mask
    enc.emit_pandn(VS2, VS1);  // VS2 = (~mask) & Dm
    enc.emit_por(VS0, VS2);    // VS0 = (Dn & mask) | (Dm & ~mask)
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

/// Vector FP 3-same arithmetic (`FADD`/`FSUB`/`FMUL`/`FDIV`/`FMLA`/`FMLS`/`FMAX`/
/// `FMIN`/`FMAXNM`/`FMINNM`/`FABD`). Loads Vn→VS0, Vm→VS1, applies the packed
/// f32×4 (single) / f64×2 (double) op, then D-form-zeroes Vd[127:64] when `q==0`.
///
/// FMLA/FMLS read Vd (Vd += Vn*Vm / Vd -= Vn*Vm) and are lowered with host FMA3
/// packed (single rounding) — AArch64 Advanced-SIMD FMLA/FMLS are architecturally
/// FUSED, so a separated mul+add (two roundings) is a 1-ULP silent miscompile.
/// FABD = |Vn-Vm|.
fn lower_vecfp(enc: &mut X86Encoder, op: crate::ir::ops::VecFpOp, dbl: bool, q: bool,
               d: u8, n: u8, m: u8) {
    use crate::ir::ops::VecFpOp::*;
    enc.emit_movdqu_load(VS0, R15, vd(n)); // VS0 = Vn
    enc.emit_movdqu_load(VS1, R15, vd(m)); // VS1 = Vm
    match op {
        Add => if dbl { enc.emit_addpd(VS0, VS1) } else { enc.emit_addps(VS0, VS1) },
        Sub => if dbl { enc.emit_subpd(VS0, VS1) } else { enc.emit_subps(VS0, VS1) },
        Mul => if dbl { enc.emit_mulpd(VS0, VS1) } else { enc.emit_mulps(VS0, VS1) },
        Div => if dbl { enc.emit_divpd(VS0, VS1) } else { enc.emit_divps(VS0, VS1) },
        // FMAX/FMIN (register) PROPAGATE NaN: if either operand lane is NaN the
        // result is a quiet NaN. x86 maxps/minps instead return the SECOND source
        // on a NaN/equal lane (so FMAX(NaN, x) would wrongly yield x). Fix every
        // NaN-input lane to the ARM default quiet NaN:
        //   t       = max/min(Vn, Vm)                 (VS0)
        //   nanmask = cmpunord(Vn, Vm)                (VS3; all-ones where either NaN)
        //   qNaN    = 0x7FC00000 / 0x7FF8…            (VS2, broadcast)
        //   result  = (t & ~nanmask) | (qNaN & nanmask)
        Max | Min => {
            let is_max = matches!(op, Max);
            // VS0 = max/min(Vn, Vm) (x86 semantics; NaN + ±0-tie lanes fixed below).
            if dbl {
                if is_max { enc.emit_maxpd(VS0, VS1) } else { enc.emit_minpd(VS0, VS1) }
            } else if is_max {
                enc.emit_maxps(VS0, VS1)
            } else {
                enc.emit_minps(VS0, VS1)
            }
            // ── ±0 tie fix: eq = ordered-equal(Vn,Vm); tie value = Vn AND Vm (max,
            // +0 wins) / Vn OR Vm (min, −0 wins). eq and unord lanes are disjoint. ──
            enc.emit_movdqu_load(VS2, R15, vd(n)); // VS2 = Vn
            enc.emit_movdqu_load(VS3, R15, vd(m)); // VS3 = Vm
            if is_max { enc.emit_pand(VS2, VS3); } else { enc.emit_por(VS2, VS3); } // VS2 = tie value
            enc.emit_movdqu_load(VS3, R15, vd(n)); // VS3 = Vn
            if dbl { enc.emit_cmppd(VS3, VS1, 0) } else { enc.emit_cmpps(VS3, VS1, 0) } // VS3 = eq mask
            enc.emit_pand(VS2, VS3);   // VS2 = tie & eq
            enc.emit_pandn(VS3, VS0);  // VS3 = ~eq & raw
            enc.emit_por(VS3, VS2);    // VS3 = eq-blended
            enc.emit_movdqa_rr(VS0, VS3);
            // ── NaN propagate: unord(Vn,Vm) lanes → canonical quiet NaN. ──
            enc.emit_movdqu_load(VS3, R15, vd(n)); // VS3 = Vn
            if dbl { enc.emit_cmppd(VS3, VS1, 3) } else { enc.emit_cmpps(VS3, VS1, 3) } // VS3 = nanmask
            if dbl {
                enc.emit_mov_r64_imm64(RAX, 0x7FF8_0000_0000_0000u64 as i64);
                enc.emit_movq_xmm_r64(VS2, RAX);
                enc.emit_pshufd(VS2, VS2, 0x44); // broadcast low qword to both lanes
            } else {
                enc.emit_mov_r64_imm32(RAX, 0x7FC0_0000u32 as i32);
                enc.emit_movd_xmm_r32(VS2, RAX);
                enc.emit_pshufd(VS2, VS2, 0x00); // broadcast low dword to all 4 lanes
            }
            enc.emit_pand(VS2, VS3);   // VS2 = qNaN & nanmask
            enc.emit_pandn(VS3, VS0);  // VS3 = ~nanmask & eq-blended
            enc.emit_por(VS3, VS2);    // VS3 = final
            enc.emit_movdqa_rr(VS0, VS3);
        }
        // FMAXNM / FMINNM — IEEE maxNum/minNum: when exactly one operand is NaN
        // the non-NaN operand is returned. x86 `maxps dst=Vn, Vm` returns Vm when
        // Vn is NaN (already correct — picks the non-NaN Vm) but ALSO returns Vm
        // when Vm is NaN (WRONG — should pick Vn). The only wrong lanes are those
        // where Vm is NaN, so replace those with Vn:
        //   r0 = max/min(Vn, Vm)                  (VS0)
        //   mask = unord(Vm, Vm)                  (VS3; all-ones where Vm is NaN)
        //   r = (Vm-NaN ? Vn : r0) = (Vn & mask) | (r0 & ~mask)
        // (Both-NaN lanes: mask=1 ⇒ r=Vn=NaN — a NaN result, which maxNum permits.)
        MaxNm | MinNm => {
            let is_max = matches!(op, MaxNm);
            // VS0 = max/min(Vn, Vm) (x86 semantics).
            if dbl {
                if is_max { enc.emit_maxpd(VS0, VS1) } else { enc.emit_minpd(VS0, VS1) }
            } else if is_max {
                enc.emit_maxps(VS0, VS1)
            } else {
                enc.emit_minps(VS0, VS1)
            }
            // ── ±0 tie fix (same as FMAX/FMIN; disjoint from NaN lanes). ──
            enc.emit_movdqu_load(VS2, R15, vd(n)); // VS2 = Vn
            enc.emit_movdqu_load(VS3, R15, vd(m)); // VS3 = Vm
            if is_max { enc.emit_pand(VS2, VS3); } else { enc.emit_por(VS2, VS3); } // VS2 = tie value
            enc.emit_movdqu_load(VS3, R15, vd(n)); // VS3 = Vn
            if dbl { enc.emit_cmppd(VS3, VS1, 0) } else { enc.emit_cmpps(VS3, VS1, 0) } // VS3 = eq mask
            enc.emit_pand(VS2, VS3);
            enc.emit_pandn(VS3, VS0);
            enc.emit_por(VS3, VS2);
            enc.emit_movdqa_rr(VS0, VS3);
            // ── ignore-NaN: replace the Vm-is-NaN lane with Vn. mask = unord(Vm,Vm). ──
            enc.emit_movdqu_load(VS2, R15, vd(n)); // VS2 = Vn (blend source for NaN-Vm lanes)
            enc.emit_movdqa_rr(VS3, VS1);          // VS3 = Vm
            if dbl { enc.emit_cmppd(VS3, VS3, 3) } else { enc.emit_cmpps(VS3, VS3, 3) } // VS3 = Vm-NaN mask
            enc.emit_pand(VS2, VS3);  // VS2 = Vn & mask
            enc.emit_pandn(VS3, VS0); // VS3 = ~mask & result
            enc.emit_por(VS3, VS2);   // VS3 = blended result
            enc.emit_movdqa_rr(VS0, VS3);
        }
        // FMLA: Vd += Vn*Vm ;  FMLS: Vd -= Vn*Vm.  AArch64 Advanced-SIMD FMLA/FMLS
        // are architecturally FUSED (single rounding per lane) — a mulps+addps
        // sequence rounds twice and is 1-ULP wrong. Use host FMA3 packed (213 form:
        // dst = vvvv*dst + rm). VS0=Vn (dst), VS1=Vm (vvvv), load Vd into VS2 (rm):
        //   FMLA  Vd + Vn*Vm      → VFMADD213P  ( Vm*Vn + Vd)
        //   FMLS  Vd - Vn*Vm      → VFNMADD213P (-Vm*Vn + Vd = Vd - Vn*Vm)
        Mla | Mls => {
            enc.emit_movdqu_load(VS2, R15, vd(d)); // VS2 = Vd (accumulator, the rm operand)
            if matches!(op, Mla) {
                enc.emit_vfmadd213p(dbl, VS0, VS1, VS2);  //  Vm*Vn + Vd
            } else {
                enc.emit_vfnmadd213p(dbl, VS0, VS1, VS2); // -Vm*Vn + Vd
            }
        }
        // FABD = |Vn - Vm|:  subtract, then clear the sign bit of each lane.
        Abd => {
            if dbl { enc.emit_subpd(VS0, VS1) } else { enc.emit_subps(VS0, VS1) }
            // VS3 = 0x7FFF…F per lane (abs mask): all-ones >> 1 (logical, per element).
            enc.emit_pcmpeqd(VS3, VS3);
            if dbl { enc.emit_psrlq_imm(VS3, 1) } else { enc.emit_psrld_imm(VS3, 1) }
            enc.emit_pand(VS0, VS3);
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Vector FP per-lane compare (`FCMEQ`/`FCMGT`/`FCMGE` register form, and the
/// `vs #0.0` 2-reg-misc forms `FCMEQ`/`FCMGT`/`FCMGE`/`FCMLT`/`FCMLE`). Produces
/// an all-ones / all-zeros mask per lane via `cmpps`/`cmppd`.
///   FCMEQ a,b → cmpeq(a,b)          FCMGT a,b → cmplt(b,a)   FCMGE a,b → cmple(b,a)
///   FCMLT a,#0 → cmplt(a,0)         FCMLE a,#0 → cmple(a,0)
/// (`cmpps` predicate codes: 0=EQ 1=LT 2=LE 3=UNORD.) For `Gt`/`Ge` the operands
/// are swapped into VS1 so the destination of the cmp is the swapped first source.
fn lower_vecfpcmp(enc: &mut X86Encoder, op: crate::ir::ops::VecFpCmpOp, dbl: bool, q: bool,
                  d: u8, n: u8, m: u8, zero: bool) {
    use crate::ir::ops::VecFpCmpOp::*;
    // Load Vn into VS0; the second operand (Vm or +0.0) into VS1.
    enc.emit_movdqu_load(VS0, R15, vd(n));
    if zero {
        enc.emit_pxor(VS1, VS1); // VS1 = +0.0 in every lane
    } else {
        enc.emit_movdqu_load(VS1, R15, vd(m));
    }
    // cmp predicate + operand order. The result must land in VS0.
    // EQ: cmpeq(Vn,Vm).
    // GT (Vn>Vm): cmplt(Vm,Vn) — dst must be Vm, so swap: VS1=cmp dst.
    // GE (Vn>=Vm): cmple(Vm,Vn).
    // LT (Vn<0):  cmplt(Vn,0).
    // LE (Vn<=0): cmple(Vn,0).
    const PRED_EQ: u8 = 0;
    const PRED_LT: u8 = 1;
    const PRED_LE: u8 = 2;
    let (swap, pred) = match op {
        Eq => (false, PRED_EQ),
        Gt => (true, PRED_LT),  // cmplt(Vm,Vn)
        Ge => (true, PRED_LE),  // cmple(Vm,Vn)
        Lt => (false, PRED_LT), // cmplt(Vn,#0)  (zero form only)
        Le => (false, PRED_LE), // cmple(Vn,#0)
    };
    let (dst, src) = if swap { (VS1, VS0) } else { (VS0, VS1) };
    if dbl { enc.emit_cmppd(dst, src, pred) } else { enc.emit_cmpps(dst, src, pred) }
    // Move the mask into VS0 if the compare wrote VS1 (the swapped forms).
    if swap {
        enc.emit_movdqa_rr(VS0, VS1);
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Vector FP 2-reg-misc unary (`FABS`/`FNEG`/`FSQRT`). Loads Vn, applies the op,
/// D-form-zeroes when `q==0`, stores Vd. ABS/NEG build the per-lane sign mask
/// from an all-ones register shifted into place (no const pool needed).
fn lower_vecfpun(enc: &mut X86Encoder, op: crate::ir::ops::VecFpUnOp, dbl: bool, q: bool,
                 d: u8, n: u8) {
    use crate::ir::ops::VecFpUnOp::*;
    enc.emit_movdqu_load(VS0, R15, vd(n));
    match op {
        Sqrt => if dbl { enc.emit_sqrtpd(VS0, VS0) } else { enc.emit_sqrtps(VS0, VS0) },
        Abs => {
            // mask = 0x7FFF…F per lane = (all-ones) >> 1 (logical, per element).
            enc.emit_pcmpeqd(VS3, VS3);
            if dbl { enc.emit_psrlq_imm(VS3, 1) } else { enc.emit_psrld_imm(VS3, 1) }
            enc.emit_pand(VS0, VS3); // clear the sign bit
        }
        Neg => {
            // mask = 0x8000…0 per lane = (all-ones) << (width-1).
            enc.emit_pcmpeqd(VS3, VS3);
            if dbl { enc.emit_psllq_imm(VS3, 63) } else { enc.emit_pslld_imm(VS3, 31) }
            enc.emit_pxor(VS0, VS3); // flip the sign bit
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON pairwise (`ADDP`/`UMAXP`/…) — byte forms only. Deinterleave each source's
/// even/odd bytes into word-low positions, combine, then `packuswb`: the low 8
/// result bytes come from Vn's pairs, the high 8 from Vm's. bionic strchr/memchr
/// use `umaxp v.16b` / `addp v.16b`.
fn lower_vecpair(enc: &mut X86Encoder, op: VecPairOp, size: u8, q: bool, d: u8, n: u8, m: u8) {
    use VecPairOp::*;
    // ADDP (pairwise add) at half/word/dword widths. ADDP Vd, Vn, Vm reduces the
    // concatenation Vn:Vm pairwise: Vd = [Vn[0]+Vn[1], Vn[2]+Vn[3], …, Vm[0]+Vm[1], …].
    //   .8H / .4S (q=1): x86 phaddw / phaddd do EXACTLY this — pairwise across the
    //                    first operand, then the second, into one 128-bit result.
    //   .2D       (q=1): no x86 phaddq, so reduce each source's two 64-bit lanes by
    //                    swap+add and interleave: Vd = [n0+n1, m0+m1].
    //   q=0 half-register .4H/.2S put the Vm pairs in the high 64 (not interleaved
    //                    into the low 64 ADDP wants) — Tier 1.
    if op == Add && size != B {
        if !q && size != D {
            // Half-register .4H (size=H) / .2S (size=S): phaddw/phaddd interleave
            // BOTH operands across the full 128 bits, so the wanted pairs land in
            // non-contiguous result lanes. Gather them back:
            //   .2S: phaddd(Vn,Vm) = [n0+n1, n2+n3, m0+m1, m2+m3]; want lanes[0,2]
            //        → pshufd 0x08 = [n0+n1, m0+m1, …].
            //   .4H: gather Vn's low-4 pairs (result halfwords 0,1) and Vm's low-4
            //        pairs (result halfwords 4,5) into [0,1,2,3] via a pshufb.
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_movdqu_load(VS1, R15, vd(m));
            if size == S {
                enc.emit_phaddd(VS0, VS1); // [n0+n1, n2+n3, m0+m1, m2+m3]
                enc.emit_pshufd(VS0, VS0, 0x08); // [n0+n1, m0+m1, n0+n1, n0+n1]
            } else {
                enc.emit_phaddw(VS0, VS1); // hw[0,1]=Vn pairs, hw[4,5]=Vm pairs
                // pshufb gather halfwords [0,1,4,5] → [0,1,2,3] (low 64), rest 0.
                let mask: [u8; 16] = [
                    0, 1, 2, 3, 8, 9, 10, 11, // hw 0,1 (Vn), hw 4,5 (Vm)
                    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                ];
                load_xmm_imm16(enc, VS3, &mask);
                enc.emit_pshufb(VS0, VS3);
            }
            dform_fixup(enc, q);
            enc.emit_movdqu_store(R15, vd(d), VS0);
            return;
        }
        enc.emit_movdqu_load(VS0, R15, vd(n)); // Vn
        enc.emit_movdqu_load(VS1, R15, vd(m)); // Vm
        match size {
            H => enc.emit_phaddw(VS0, VS1),
            S => enc.emit_phaddd(VS0, VS1),
            _ => {
                // .2D: Vd[0]=n0+n1, Vd[1]=m0+m1.
                enc.emit_pshufd(VS2, VS0, 0x4E); // [n1, n0]
                enc.emit_paddq(VS0, VS2); // lane0 = n0+n1
                enc.emit_pshufd(VS3, VS1, 0x4E); // [m1, m0]
                enc.emit_paddq(VS1, VS3); // lane0 = m0+m1
                enc.emit_punpcklqdq(VS0, VS1); // [n0+n1, m0+m1]
            }
        }
        dform_fixup(enc, q);
        enc.emit_movdqu_store(R15, vd(d), VS0);
        return;
    }
    if size != B {
        lower_vecpair_maxmin_nonbyte(enc, op, size, q, d, n, m);
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
    // D-form (.8b): ARM reduces CONCAT(Vm.lo64 : Vn.lo64) — result bytes [0..3]
    // are Vn's 4 pairs and bytes [4..7] are Vm's 4 pairs. Fold the two low halves
    // into one register so ONE reduction pass yields [Vn pairs | Vm pairs] in the
    // low 8; using the two-pass (Vn→lo8, Vm→hi8) path here would emit pairs of
    // Vn's stale HIGH-half bytes into result bytes [4..7] and drop Vm entirely
    // (dform_fixup only zeroes [127:64] of the already-wrong low half).
    if !q {
        enc.emit_punpcklqdq(VS0, VS1); // VS0 = [Vn.lo64 | Vm.lo64]
    }
    enc.emit_pcmpeqw(VS3, VS3);
    enc.emit_psrlw_imm(VS3, 8); // 0x00FF per 16-bit lane
    // Vn pairwise (Q) / [Vn|Vm] pairwise (D) → VS0 (each result in the low byte
    // of its word lane).
    enc.emit_movdqa_rr(VS2, VS0);
    enc.emit_pand(VS2, VS3); // even bytes
    enc.emit_psrlw_imm(VS0, 8); // odd bytes
    reduce(enc, VS0, VS2, VS3);
    if q {
        // Vm pairwise → VS1, then pack: low 8 = Vn pairs, high 8 = Vm pairs.
        enc.emit_movdqa_rr(VS2, VS1);
        enc.emit_pand(VS2, VS3);
        enc.emit_psrlw_imm(VS1, 8);
        reduce(enc, VS1, VS2, VS3);
        enc.emit_packuswb(VS0, VS1);
    } else {
        // .8b: VS0 already holds all 8 pairs in its 8 word lanes → pack to bytes.
        enc.emit_packuswb(VS0, VS0); // low 8 = [Vn pairs | Vm pairs]
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON pairwise max/min at HALF (size=1) and WORD (size=2) element widths
/// (`UMAXP`/`UMINP`/`SMAXP`/`SMINP` `.4h/.8h/.2s/.4s`). The decoder never emits
/// the .1d/.2d (size=3) forms for max/min, so only H and S are handled.
///
/// Strategy: for each source, gather its EVEN elements into the low half and its
/// ODD elements into the same low positions, then apply the packed SSE max/min —
/// the result is the pairwise-reduced elements packed contiguously in the low
/// half. Vn's reduced elements land in the low half of the result, Vm's in the
/// high half (ADDP-style Vn:Vm concatenation), assembled with `punpckl{dq,qdq}`.
///
///   H (16-bit): pshufb gathers the even/odd halfwords (no 16-bit shuffle that
///               deinterleaves 8 lanes exists, so use a byte mask).
///   S (32-bit): pshufd gathers even/odd words directly.
///
/// Register use: VS0 = Vn accumulator, VS1 = Vm accumulator, VS2/VS3 = scratch
/// (odd copy / gather mask).
fn lower_vecpair_maxmin_nonbyte(
    enc: &mut X86Encoder,
    op: VecPairOp,
    size: u8,
    q: bool,
    d: u8,
    n: u8,
    m: u8,
) {
    use VecPairOp::*;
    // The packed SSE max/min for this (op, size). None for Add (handled earlier).
    let apply = |enc: &mut X86Encoder, acc: u8, other: u8| match (op, size) {
        (UMax, H) => enc.emit_pmaxuw(acc, other),
        (UMin, H) => enc.emit_pminuw(acc, other),
        (SMax, H) => enc.emit_pmaxsw(acc, other),
        (SMin, H) => enc.emit_pminsw(acc, other),
        (UMax, S) => enc.emit_pmaxud(acc, other),
        (UMin, S) => enc.emit_pminud(acc, other),
        (SMax, S) => enc.emit_pmaxsd(acc, other),
        (SMin, S) => enc.emit_pminsd(acc, other),
        _ => enc.emit_ud2(),
    };

    if size == H {
        // Build the even/odd HALFWORD gather masks (byte granularity). Out-of-range
        // output positions are 0x80 (pshufb zeroes them; harmless — they sit in the
        // high half we later discard). q=0 (.4h) only has halfwords 0..3 valid.
        let n_pairs: usize = if q { 4 } else { 2 };
        let mut even_mask = [0x80u8; 16];
        let mut odd_mask = [0x80u8; 16];
        for p in 0..n_pairs {
            // result halfword p occupies output bytes 2p, 2p+1.
            let e_src = 2 * (2 * p); // source halfword 2p → byte offset
            let o_src = 2 * (2 * p + 1); // source halfword 2p+1
            even_mask[2 * p] = e_src as u8;
            even_mask[2 * p + 1] = (e_src + 1) as u8;
            odd_mask[2 * p] = o_src as u8;
            odd_mask[2 * p + 1] = (o_src + 1) as u8;
        }
        // Gather Vn → VS0 (reduced in low), Vm → VS1 (reduced in low).
        gather_two_pshufb(enc, R15, vd(n), &even_mask, &odd_mask, VS0, VS2, VS3, &apply);
        gather_two_pshufb(enc, R15, vd(m), &even_mask, &odd_mask, VS1, VS2, VS3, &apply);
        if q {
            // 4 reduced halfwords per source in the low 64. Join: [Vn | Vm].
            enc.emit_punpcklqdq(VS0, VS1);
        } else {
            // 2 reduced halfwords per source in the low 32. punpckldq → low 64 =
            // [n0',n1', m0',m1'] (interleave 32-bit dwords, low dword of each).
            enc.emit_punpckldq(VS0, VS1);
        }
    } else {
        // S (32-bit): even/odd words gathered via pshufd.
        if q {
            // 4 words: evens = [w0,w2,·,·] (0x08), odds = [w1,w3,·,·] (0x0D).
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_pshufd(VS2, VS0, 0x0D); // odds → low two dwords
            enc.emit_pshufd(VS0, VS0, 0x08); // evens → low two dwords
            apply(enc, VS0, VS2); // 2 reduced words in low 64
            enc.emit_movdqu_load(VS1, R15, vd(m));
            enc.emit_pshufd(VS3, VS1, 0x0D);
            enc.emit_pshufd(VS1, VS1, 0x08);
            apply(enc, VS1, VS3);
            enc.emit_punpcklqdq(VS0, VS1); // [Vn results | Vm results]
        } else {
            // 2 words (.2s): even = w0 (0x00), odd = w1 (0x01), each in dword0.
            enc.emit_movdqu_load(VS0, R15, vd(n));
            enc.emit_pshufd(VS2, VS0, 0x01); // odd word → dword0
            enc.emit_pshufd(VS0, VS0, 0x00); // even word → dword0
            apply(enc, VS0, VS2); // 1 reduced word in dword0
            enc.emit_movdqu_load(VS1, R15, vd(m));
            enc.emit_pshufd(VS3, VS1, 0x01);
            enc.emit_pshufd(VS1, VS1, 0x00);
            apply(enc, VS1, VS3);
            enc.emit_punpckldq(VS0, VS1); // low 64 = [n', m', ·, ·]
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Load `[base+disp]`, gather its even elements (via `even_mask`) into `acc` and
/// its odd elements (via `odd_mask`) into a scratch, then fold them with `apply`
/// (the pairwise reducer). `scratch_odd` holds the odd-gathered copy;
/// `scratch_mask` holds the pshufb mask. Result: `acc` has the reduced elements
/// packed in its low half.
#[allow(clippy::too_many_arguments)]
fn gather_two_pshufb(
    enc: &mut X86Encoder,
    base: u8,
    disp: i32,
    even_mask: &[u8; 16],
    odd_mask: &[u8; 16],
    acc: u8,
    scratch_odd: u8,
    scratch_mask: u8,
    apply: &dyn Fn(&mut X86Encoder, u8, u8),
) {
    enc.emit_movdqu_load(acc, base, disp);
    enc.emit_movdqa_rr(scratch_odd, acc); // copy for the odd gather
    load_xmm_imm16(enc, scratch_mask, even_mask);
    enc.emit_pshufb(acc, scratch_mask); // acc = even elements
    load_xmm_imm16(enc, scratch_mask, odd_mask);
    enc.emit_pshufb(scratch_odd, scratch_mask); // scratch = odd elements
    apply(enc, acc, scratch_odd); // acc = reduce(even, odd)
}

/// Materialize a 16-byte constant into `dst` (via RAX). Self-contained (only
/// touches `dst` and RAX): the low 64 goes in with `movq xmm,r64` (which zeroes
/// the high half), then the high 64 is inserted with `pinsrq …, 1`. Used to build
/// pshufb gather masks without borrowing a second XMM scratch.
fn load_xmm_imm16(enc: &mut X86Encoder, dst: u8, bytes: &[u8; 16]) {
    let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    enc.emit_mov_r64_imm64(RAX, lo as i64);
    enc.emit_movq_xmm_r64(dst, RAX); // dst[63:0] = lo, dst[127:64] = 0
    enc.emit_mov_r64_imm64(RAX, hi as i64);
    enc.emit_pinsrq(dst, RAX, 1); // dst[127:64] = hi
}

/// NEON `UADDLP`/`SADDLP` — add-long pairwise. Adjacent `esize_in`-byte source
/// elements are summed into a 2×-wide destination element (no truncation):
/// byte→half, half→word, word→dword.
///
/// UNSIGNED (UADDLP): mask the even source lanes into the widened lane, shift the
/// odd lanes down into the same position (both zero-extended), then a widening add
/// (psrlw/paddw, psrld/paddd, psrlq/paddq).
///
/// SIGNED (SADDLP): the two source elements must be SIGN-extended before the add.
/// For byte→half and half→word this is a two-shift sign-extend per parity: the
/// even element is brought to the top of its widened lane with a left shift then
/// arithmetically shifted back (`psllw`/`psraw`, `pslld`/`psrad`); the odd element
/// is already at the top and only needs the arithmetic shift down. `paddw`/`paddd`
/// then sums the sign-extended pair. The word→dword case has no 64-bit arithmetic
/// shift pre-AVX512, so it splits the even words (dwords 0,2) and odd words
/// (dwords 1,3) via `pshufd` and sign-extends each pair to qwords with `pmovsxdq`
/// before `paddq`.
fn lower_vecaddlongpair(enc: &mut X86Encoder, d: u8, n: u8, esize_in: u8, q: bool, signed: bool) {
    if !matches!(esize_in, 1 | 2 | 4) {
        enc.emit_ud2();
        return;
    }
    enc.emit_movdqu_load(VS0, R15, vd(n));
    if signed {
        match esize_in {
            1 => {
                // byte→half: even byte = low 8 of each 16-bit lane; odd = high 8.
                // even: psllw 8 (byte→high) then psraw 8 (sign-extend to 16).
                // odd:  psraw 8 (arithmetic shift the high byte down, sign-filled).
                enc.emit_movdqa_rr(VS1, VS0); // VS1 = Vn (evens)
                enc.emit_psllw_imm(VS1, 8);
                enc.emit_psraw_imm(VS1, 8); // VS1 = sext(even bytes)
                enc.emit_psraw_imm(VS0, 8); // VS0 = sext(odd bytes)
                enc.emit_paddw(VS0, VS1);
            }
            2 => {
                // half→word: even halfword = low 16 of each 32-bit lane; odd = high.
                enc.emit_movdqa_rr(VS1, VS0);
                enc.emit_pslld_imm(VS1, 16);
                enc.emit_psrad_imm(VS1, 16); // VS1 = sext(even halfwords)
                enc.emit_psrad_imm(VS0, 16); // VS0 = sext(odd halfwords)
                enc.emit_paddd(VS0, VS1);
            }
            _ => {
                // word→dword: even words = dwords 0,2; odd words = dwords 1,3.
                // pshufd 0x08 = [d0,d2,d0,d0]; low two dwords = the evens.
                // pshufd 0x0D = [d1,d3,d0,d0]; low two dwords = the odds.
                // pmovsxdq sign-extends the low two dwords to two qwords.
                enc.emit_pshufd(VS1, VS0, 0x08); // evens in low two dwords
                enc.emit_pshufd(VS0, VS0, 0x0D); // odds  in low two dwords
                enc.emit_pmovsxdq(VS1, VS1); // qword lanes = sext(d0), sext(d2)
                enc.emit_pmovsxdq(VS0, VS0); // qword lanes = sext(d1), sext(d3)
                enc.emit_paddq(VS0, VS1);
            }
        }
        dform_fixup(enc, q);
        enc.emit_movdqu_store(R15, vd(d), VS0);
        return;
    }
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
        _ => {
            // General pshufb gather for .16b/.8b/.8h/.4h/.2s. UZP1 gathers the
            // EVEN-indexed elements of the Vn:Vm concatenation, UZP2 the ODD.
            // Total elements across both regs = (q?16:8)/esize per source × 2.
            // Build a per-source mask picking that source's even/odd elements into
            // consecutive output positions: Vn → the low half, Vm → the high half.
            uzp_pshufb(enc, d, n, m, esize, q, odd);
        }
    }
}

/// UZP1/UZP2 general lowering via two pshufb gathers + por. For an `esize`-byte
/// element and `total` = 8 (D-form) or 16 (Q-form) bytes per source: the result
/// has `total/esize` elements from Vn (even or odd indices) in its low half and
/// `total/esize` from Vm in its high half. pshufb with bit7-set mask bytes zeroes
/// the untouched half, so `por` merges the two gathers.
fn uzp_pshufb(enc: &mut X86Encoder, d: u8, n: u8, m: u8, esize: u8, q: bool, odd: bool) {
    let total: usize = if q { 16 } else { 8 };
    let es = esize as usize;
    // Result has total/es elements; half from Vn (even/odd indices), half from Vm.
    let n_from_each = (total / es) / 2;
    let start = if odd { 1 } else { 0 };
    // Vn gather mask: output element j (0..n_from_each) ← Vn source element (start+2j).
    let mut nmask = [0x80u8; 16];
    let mut mmask = [0x80u8; 16];
    for j in 0..n_from_each {
        let src_elem = start + 2 * j; // even/odd index within the source
        let src_byte = src_elem * es;
        // Vn's elements fill output positions 0..n_from_each.
        let n_out = j * es;
        // Vm's elements fill output positions n_from_each..2*n_from_each.
        let m_out = (n_from_each + j) * es;
        for b in 0..es {
            if src_byte + b < 16 {
                nmask[n_out + b] = (src_byte + b) as u8;
                mmask[m_out + b] = (src_byte + b) as u8;
            }
        }
    }
    enc.emit_movdqu_load(VS0, R15, vd(n));
    enc.emit_movdqu_load(VS1, R15, vd(m));
    load_xmm_imm16(enc, VS2, &nmask);
    enc.emit_pshufb(VS0, VS2); // Vn evens/odds → low half
    load_xmm_imm16(enc, VS2, &mmask);
    enc.emit_pshufb(VS1, VS2); // Vm evens/odds → high half
    enc.emit_por(VS0, VS1);
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON integer 2-reg-misc unary (`ABS`/`NEG`). NEG = `0 - Vn` (pxor+psub);
/// ABS = SSSE3 `pabs{b,w,d}` for B/H/S, and `max(Vn, 0-Vn)` for D (.2d) since
/// there is no PABSQ pre-AVX512. D-form (`q==false`) zeroes Vd[127:64].
fn lower_vecun(enc: &mut X86Encoder, op: crate::ir::ops::VecUnOp, size: u8, q: bool, d: u8, n: u8) {
    use crate::ir::ops::VecUnOp::*;
    enc.emit_movdqu_load(VS0, R15, vd(n)); // VS0 = Vn
    match op {
        Neg => {
            enc.emit_pxor(VS1, VS1); // VS1 = 0
            match size {
                B => enc.emit_psubb(VS1, VS0),
                H => enc.emit_psubw(VS1, VS0),
                S => enc.emit_psubd(VS1, VS0),
                _ => enc.emit_psubq(VS1, VS0), // D
            }
            enc.emit_movdqa_rr(VS0, VS1); // VS0 = 0 - Vn
        }
        Abs => match size {
            B => enc.emit_pabsb(VS0, VS0),
            H => enc.emit_pabsw(VS0, VS0),
            S => enc.emit_pabsd(VS0, VS0),
            _ => {
                // .2d: abs = max(Vn, -Vn). No PABSQ/PMAXSQ pre-AVX512, so build
                // -Vn (psubq 0,Vn) and select the larger via a sign-mask blend:
                //   neg = 0 - Vn ; mask = (Vn < 0) = psrad/pshufd sign-broadcast ;
                //   result = (Vn & ~mask) | (neg & mask).
                enc.emit_pxor(VS1, VS1);
                enc.emit_psubq(VS1, VS0);      // VS1 = -Vn
                // VS2 = sign mask of Vn (all-ones per qword where Vn<0).
                enc.emit_movdqa_rr(VS2, VS0);
                enc.emit_psrad_imm(VS2, 31);   // each 32-bit half → 0/-1
                enc.emit_pshufd(VS2, VS2, 0xF5); // broadcast high dword over the qword
                // result = (Vn & ~mask) | (-Vn & mask).
                enc.emit_pand(VS1, VS2);       // VS1 = -Vn where Vn<0
                enc.emit_pandn(VS2, VS0);      // VS2 = Vn where Vn>=0
                enc.emit_por(VS1, VS2);
                enc.emit_movdqa_rr(VS0, VS1);
            }
        },
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON multiply-accumulate BY ELEMENT (`FMUL`/`FMLA`/`FMLS`/`MUL` `.<Ts>[idx]`).
/// The scalar lane `idx` of Vm is broadcast to every lane (pshufd for S/D; the
/// int H form via pshuflw+pshufd), then the op is applied against Vn. FP forms
/// reuse the same packed mul/add/sub as `lower_vecfp`; the integer MUL form uses
/// pmullw/pmulld. D-form (`q==false`) zeroes Vd[127:64].
#[allow(clippy::too_many_arguments)]
fn lower_vecbyelem(
    enc: &mut X86Encoder,
    op: crate::ir::ops::VecFpOp,
    is_fp: bool,
    dbl: bool,
    size: u8,
    q: bool,
    d: u8,
    n: u8,
    m: u8,
    idx: u8,
) {
    use crate::ir::ops::VecFpOp::*;
    enc.emit_movdqu_load(VS0, R15, vd(n)); // VS0 = Vn
    enc.emit_movdqu_load(VS1, R15, vd(m)); // VS1 = Vm (broadcast source)
    if is_fp {
        if dbl {
            // .2d: broadcast qword `idx` (0→[0,1,0,1]=0x44, 1→[2,3,2,3]=0xEE).
            let imm = if idx == 0 { 0x44 } else { 0xEE };
            enc.emit_pshufd(VS1, VS1, imm);
            // FMLA/FMLS are architecturally FUSED (single rounding per lane) — the
            // old mul+add/sub rounded twice (1-ULP silent miscompile). Use host FMA3
            // packed (213 form: dst = vvvv*dst + rm). VS0=Vn (dst), VS1=Vm[idx]
            // (vvvv), VS2=Vd (rm): FMLA → VFMADD213P (Vm*Vn+Vd); FMLS → VFNMADD213P
            // (-Vm*Vn+Vd = Vd-Vn*Vm).
            match op {
                Mul => enc.emit_mulpd(VS0, VS1),
                Mla => { enc.emit_movdqu_load(VS2, R15, vd(d)); enc.emit_vfmadd213p(true, VS0, VS1, VS2); }
                Mls => { enc.emit_movdqu_load(VS2, R15, vd(d)); enc.emit_vfnmadd213p(true, VS0, VS1, VS2); }
                _ => { enc.emit_ud2(); return; }
            }
        } else {
            // .4s/.2s: broadcast dword `idx` (pshufd imm = idx*0x55).
            enc.emit_pshufd(VS1, VS1, idx.wrapping_mul(0x55) & 0xFF);
            match op {
                Mul => enc.emit_mulps(VS0, VS1),
                // Fused (see .2d comment above): FMLA → VFMADD213P, FMLS → VFNMADD213P.
                Mla => { enc.emit_movdqu_load(VS2, R15, vd(d)); enc.emit_vfmadd213p(false, VS0, VS1, VS2); }
                Mls => { enc.emit_movdqu_load(VS2, R15, vd(d)); enc.emit_vfnmadd213p(false, VS0, VS1, VS2); }
                _ => { enc.emit_ud2(); return; }
            }
        }
    } else {
        // Integer by-element: ONLY plain MUL is wired here. The integer MLA/MLS
        // by-element accumulate forms are deferred at the decoder (they fall to a
        // coarse Hint→UD2), so `op` should never be Mla/Mls on this path — but
        // guard it explicitly: emitting the MUL body for an accumulate op would
        // silently drop the += / -= against Vd. Fail loud instead.
        if !matches!(op, Mul) {
            enc.emit_ud2();
            return;
        }
        // Integer MUL by element. Broadcast lane `idx` then pmullw/pmulld.
        match size {
            H => {
                // Broadcast halfword `idx` across all 8 lanes. pshuflw replicates
                // a halfword within the low 64, then pshufd 0x00 copies that qword
                // to the high 64. The low-2-bits of idx select within the low 4
                // lanes; ARM by-element H idx is 0..7 → handle the high 4 lanes by
                // first moving the chosen lane into lane 0.
                if idx >= 4 {
                    // Move the high qword down so the chosen lane sits in 0..3.
                    enc.emit_pshufd(VS1, VS1, 0x0E);
                }
                let sub = (idx & 3) as u8;
                let pat = sub | (sub << 2) | (sub << 4) | (sub << 6);
                enc.emit_pshuflw(VS1, VS1, pat);
                enc.emit_pshufd(VS1, VS1, 0x00);
                enc.emit_pmullw(VS0, VS1);
            }
            S => {
                enc.emit_pshufd(VS1, VS1, idx.wrapping_mul(0x55) & 0xFF);
                enc.emit_pmulld(VS0, VS1);
            }
            _ => { enc.emit_ud2(); return; }
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON vector integer↔FP convert (SCVTF/UCVTF/FCVTZS/FCVTZU). Only the signed
/// .4s/.2s path is wired natively: SCVTF.4s = `cvtdq2ps`, FCVTZS.4s =
/// `cvttps2dq` (truncating, which is exactly round-toward-zero = the ARM FCVTZ
/// semantics). The unsigned forms and the .2d (64-bit) forms have no single SSE
/// instruction (need the bias trick / AVX512) → fail-loud (UD2).
fn lower_veccvtfp(enc: &mut X86Encoder, to_fp: bool, signed: bool, dbl: bool, q: bool, d: u8, n: u8) {
    if dbl || !signed {
        // .2d (double) and the unsigned bias-trick forms are Tier 1.
        enc.emit_ud2();
        return;
    }
    enc.emit_movdqu_load(VS0, R15, vd(n));
    if to_fp {
        // SCVTF .4s: signed int32 → f32 (round to nearest, the ARM default FPCR).
        enc.emit_cvtdq2ps(VS0, VS0);
    } else {
        // FCVTZS .4s: f32 → signed int32, round-toward-zero, WITH ARM saturation.
        // Bare cvttps2dq returns the x86 integer indefinite (0x80000000) for NaN and
        // for any out-of-range input, so positive-overflow and NaN lanes are wrong
        // (ARM wants +2^31..∞/+inf → 0x7FFFFFFF and NaN → 0). Negative-overflow
        // coincides with x86 indefinite == INT_MIN and needs no fixup.
        // VS0 = src (kept for the mask compares); VS1 = raw truncating convert.
        enc.emit_movdqa_rr(VS1, VS0);
        enc.emit_cvttps2dq(VS1, VS1);
        // VS2 = ovf mask = cmpps(src, 2^31f, NLT): all-ones where src >= 2^31 OR NaN
        // (NLT is unordered-true), i.e. exactly the positive-overflow AND NaN lanes.
        enc.emit_movdqa_rr(VS2, VS0);
        enc.emit_mov_r64_imm32(RAX, 0x4F00_0000u32 as i32); // 2^31 as f32
        enc.emit_movd_xmm_r32(VS3, RAX);
        enc.emit_pshufd(VS3, VS3, 0x00); // broadcast to all 4 lanes
        enc.emit_cmpps(VS2, VS3, 5);     // pred 5 = NLT (not-less-than; unordered-true)
        // res = (raw & ~ovf) | (0x7FFFFFFF & ovf). Build INT_MAX in VS3.
        enc.emit_pcmpeqd(VS3, VS3);
        enc.emit_psrld_imm(VS3, 1);      // 0x7FFFFFFF per lane
        enc.emit_pand(VS3, VS2);         // VS3 = INT_MAX & ovf
        enc.emit_pandn(VS2, VS1);        // VS2 = ~ovf & raw
        enc.emit_por(VS2, VS3);          // VS2 = saturated (NaN lanes currently INT_MAX)
        // NaN → 0: mask = unord(src,src); clear those lanes.
        enc.emit_movdqa_rr(VS3, VS0);
        enc.emit_cmpps(VS3, VS3, 3);     // pred 3 = UNORD (all-ones where src is NaN)
        enc.emit_pandn(VS3, VS2);        // VS3 = ~nanmask & saturated  (NaN lanes → 0)
        enc.emit_movdqa_rr(VS0, VS3);
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// NEON `ZIP1`/`ZIP2`/`TRN1`/`TRN2` permute. ZIP interleaves elements from the
/// low (ZIP1) or high (ZIP2) halves of Vn:Vm via `punpckl*`/`punpckh*`. TRN
/// gathers the even (TRN1) or odd (TRN2) lanes of each source and interleaves
/// them (Vd = [Vn0,Vm0,Vn2,Vm2,…] / [Vn1,Vm1,Vn3,Vm3,…]). D-form zeroes the upper 64.
fn lower_vecziptrn(enc: &mut X86Encoder, kind: u8, size: u8, q: bool, d: u8, n: u8, m: u8) {
    // kind: 0=ZIP1, 1=ZIP2, 2=TRN1, 3=TRN2.
    enc.emit_movdqu_load(VS0, R15, vd(n)); // Vn
    enc.emit_movdqu_load(VS1, R15, vd(m)); // Vm
    let is_zip = kind < 2;
    let high = kind == 1 || kind == 3; // ZIP2 / TRN2
    if is_zip {
        // ZIP1 = punpckl (interleave low halves); ZIP2 = punpckh (high halves).
        // For the D-form (q==false), ZIP1 still interleaves the LOW 64 of each
        // source (4 bytes from each for .8b), which punpckl gives directly.
        if !high {
            match size {
                B => enc.emit_punpcklbw(VS0, VS1),
                H => enc.emit_punpcklwd(VS0, VS1),
                S => enc.emit_punpckldq(VS0, VS1),
                _ => enc.emit_punpcklqdq(VS0, VS1), // D
            }
        } else if !q {
            // ZIP2 .8b/.4h/.2s: the "high" half of a 64-bit register is its bytes
            // [4..8]/[2..4 elems]. Bring those to the low 64 first (psrldq #4 for
            // .8b would not be element-aligned), so use punpckl on the shifted
            // sources: shift each source right by 4 bytes (half the 8-byte reg).
            enc.emit_psrldq_imm(VS0, 4);
            enc.emit_psrldq_imm(VS1, 4);
            match size {
                B => enc.emit_punpcklbw(VS0, VS1),
                H => enc.emit_punpcklwd(VS0, VS1),
                S => enc.emit_punpckldq(VS0, VS1),
                _ => { enc.emit_ud2(); return; }
            }
        } else {
            match size {
                B => enc.emit_punpckhbw(VS0, VS1),
                H => enc.emit_punpckhwd(VS0, VS1),
                S => enc.emit_punpckhdq(VS0, VS1),
                _ => enc.emit_punpckhqdq(VS0, VS1), // D
            }
        }
    } else {
        // TRN1/TRN2. The .2d (64-bit element) case coincides with UZP/ZIP since
        // there are only 2 elements: TRN1=[n0,m0]=punpcklqdq, TRN2=[n1,m1]=punpckhqdq.
        if size == D {
            if !high { enc.emit_punpcklqdq(VS0, VS1) } else { enc.emit_punpckhqdq(VS0, VS1) }
        } else if size == S && q {
            // .4s TRN1 = [n0,m0,n2,m2], TRN2 = [n1,m1,n3,m3]. Build via shufps:
            //   TRN1: low two = n0,m0 (shufps n,m sel 0,2 from each) is not direct;
            // use the unpck approach on de-staggered sources instead.
            // shufps dst,src,imm: dst[0,1]=dst[sel], dst[2,3]=src[sel].
            // TRN1 wants n0,m0,n2,m2. shufps(n, m, 0b10_00_10_00=0x88) = [n0,n2,m0,m2]
            // → then pshufd 0xD8 = [n0,m0,n2,m2].
            // TRN2 wants n1,m1,n3,m3. shufps(n, m, 0xDD)=[n1,n3,m1,m3] → pshufd 0xD8.
            let sel = if !high { 0x88u8 } else { 0xDDu8 };
            enc.emit_shufps(VS0, VS1, sel);
            enc.emit_pshufd(VS0, VS0, 0xD8);
        } else {
            // TRN for .8b/.16b/.4h/.8h/.2s — general pshufb gather. TRN1 (high=false)
            // interleaves the EVEN lanes of Vn and Vm: [n0,m0,n2,m2,…]; TRN2 the ODD:
            // [n1,m1,n3,m3,…]. Build a per-source mask placing that source's chosen
            // lanes at the interleaved output slots (Vn at even output pairs, Vm at
            // odd), then `por`. Untouched mask bytes (0x80) zero via pshufb.
            trn_pshufb(enc, d, VS0, VS1, size, q, high);
            return;
        }
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// TRN1/TRN2 general lowering via two pshufb gathers + por. VS0 already holds Vn,
/// VS1 holds Vm. For an `esize`-byte element (from `size`) and `total`=8/16 bytes:
/// TRN1 (`high=false`) picks even lanes, TRN2 (`high=true`) odd. Output lane 2k ←
/// Vn lane (2k+off), output lane 2k+1 ← Vm lane (2k+off), with off = high?1:0.
/// Stores the result to Vd (D-form zeroes the upper 64).
fn trn_pshufb(enc: &mut X86Encoder, d: u8, vn: u8, vm: u8, size: u8, q: bool, high: bool) {
    let es: usize = 1usize << size;
    let total: usize = if q { 16 } else { 8 };
    let n_out = total / es; // total output elements
    let off = if high { 1 } else { 0 };
    let mut nmask = [0x80u8; 16];
    let mut mmask = [0x80u8; 16];
    // Output element k: even k ← Vn lane (k+off), odd k ← Vm lane ((k-1)+off).
    let mut k = 0usize;
    while k < n_out {
        // even slot ← Vn
        let n_src = (k + off) * es;
        for b in 0..es {
            if n_src + b < 16 {
                nmask[k * es + b] = (n_src + b) as u8;
            }
        }
        // odd slot ← Vm
        if k + 1 < n_out {
            let m_src = (k + off) * es;
            for b in 0..es {
                if m_src + b < 16 {
                    mmask[(k + 1) * es + b] = (m_src + b) as u8;
                }
            }
        }
        k += 2;
    }
    load_xmm_imm16(enc, VS2, &nmask);
    enc.emit_pshufb(vn, VS2);
    load_xmm_imm16(enc, VS2, &mmask);
    enc.emit_pshufb(vm, VS2);
    enc.emit_por(vn, vm);
    // vn now holds the interleaved result.
    if vn != VS0 {
        enc.emit_movdqa_rr(VS0, vn);
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
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
        // ── Saturating add/sub. x86 has B/H signed+unsigned saturating PADD/PSUB;
        // S (.4s) and D (.2d) widths have no native saturate → fail-loud (Tier 1).
        UqAdd => match size {
            B => enc.emit_paddusb(VS0, VS1),
            H => enc.emit_paddusw(VS0, VS1),
            _ => handled = false,
        },
        SqAdd => match size {
            B => enc.emit_paddsb(VS0, VS1),
            H => enc.emit_paddsw(VS0, VS1),
            _ => handled = false,
        },
        UqSub => match size {
            B => enc.emit_psubusb(VS0, VS1),
            H => enc.emit_psubusw(VS0, VS1),
            _ => handled = false,
        },
        SqSub => match size {
            B => enc.emit_psubsb(VS0, VS1),
            H => enc.emit_psubsw(VS0, VS1),
            _ => handled = false,
        },
        // ── Unsigned absolute difference |Vn-Vm| per lane:
        //   UABD = (a - usat b) | (b - usat a)  — the saturating subs clamp the
        //   smaller-minus-larger lane to 0, so the OR keeps the true |a-b|.
        // SABD (signed) uses max-min (pmaxs/pmins exist for B/H/S).
        UAbd => {
            let ok = match size {
                B => { enc.emit_movdqa_rr(VS2, VS1); enc.emit_psubusb(VS2, VS0);
                       enc.emit_psubusb(VS0, VS1); enc.emit_por(VS0, VS2); true }
                H => { enc.emit_movdqa_rr(VS2, VS1); enc.emit_psubusw(VS2, VS0);
                       enc.emit_psubusw(VS0, VS1); enc.emit_por(VS0, VS2); true }
                // .4s: no 32-bit unsigned-saturate sub, but SSE4.1 has PMAXUD/PMINUD.
                // |a-b| unsigned = max(a,b) - min(a,b) (mirrors the SAbd .4s idiom
                // with UNSIGNED max/min so unsigned wrap can't produce a wrong lane).
                S => { enc.emit_movdqa_rr(VS2, VS0); enc.emit_pmaxud(VS0, VS1);
                       enc.emit_pminud(VS2, VS1); enc.emit_psubd(VS0, VS2); true }
                _ => false, // .2d: UABD is reserved at size=11 — never emitted.
            };
            handled = ok;
        }
        SAbd => {
            // |a-b| signed = max(a,b) - min(a,b). pmaxs/pmins: B/H/S available.
            let ok = match size {
                B => { enc.emit_movdqa_rr(VS2, VS0); enc.emit_pmaxsb(VS0, VS1);
                       enc.emit_pminsb(VS2, VS1); enc.emit_psubb(VS0, VS2); true }
                H => { enc.emit_movdqa_rr(VS2, VS0); enc.emit_pmaxsw(VS0, VS1);
                       enc.emit_pminsw(VS2, VS1); enc.emit_psubw(VS0, VS2); true }
                S => { enc.emit_movdqa_rr(VS2, VS0); enc.emit_pmaxsd(VS0, VS1);
                       enc.emit_pminsd(VS2, VS1); enc.emit_psubd(VS0, VS2); true }
                _ => false,
            };
            handled = ok;
        }
        // ── Absolute-difference accumulate: Vd += |Vn-Vm|. Compute |Vn-Vm| in VS0
        // (as above), then add Vd (VS2) lane-wise.
        UAba => {
            let absok = match size {
                B => { enc.emit_movdqa_rr(VS2, VS1); enc.emit_psubusb(VS2, VS0);
                       enc.emit_psubusb(VS0, VS1); enc.emit_por(VS0, VS2); true }
                H => { enc.emit_movdqa_rr(VS2, VS1); enc.emit_psubusw(VS2, VS0);
                       enc.emit_psubusw(VS0, VS1); enc.emit_por(VS0, VS2); true }
                // .4s: |a-b| = max(a,b) - min(a,b) via PMAXUD/PMINUD (SSE4.1).
                S => { enc.emit_movdqa_rr(VS2, VS0); enc.emit_pmaxud(VS0, VS1);
                       enc.emit_pminud(VS2, VS1); enc.emit_psubd(VS0, VS2); true }
                _ => false, // .2d: UABA reserved at size=11 — never emitted.
            };
            if absok {
                enc.emit_movdqu_load(VS2, R15, vd(d));
                match size {
                    B => enc.emit_paddb(VS0, VS2),
                    H => enc.emit_paddw(VS0, VS2),
                    _ => enc.emit_paddd(VS0, VS2), // .4s accumulate
                }
            }
            handled = absok;
        }
        SAba => {
            let absok = match size {
                B => { enc.emit_movdqa_rr(VS2, VS0); enc.emit_pmaxsb(VS0, VS1);
                       enc.emit_pminsb(VS2, VS1); enc.emit_psubb(VS0, VS2); true }
                H => { enc.emit_movdqa_rr(VS2, VS0); enc.emit_pmaxsw(VS0, VS1);
                       enc.emit_pminsw(VS2, VS1); enc.emit_psubw(VS0, VS2); true }
                S => { enc.emit_movdqa_rr(VS2, VS0); enc.emit_pmaxsd(VS0, VS1);
                       enc.emit_pminsd(VS2, VS1); enc.emit_psubd(VS0, VS2); true }
                _ => false,
            };
            if absok {
                enc.emit_movdqu_load(VS2, R15, vd(d));
                match size {
                    B => enc.emit_paddb(VS0, VS2),
                    H => enc.emit_paddw(VS0, VS2),
                    _ => enc.emit_paddd(VS0, VS2),
                }
            }
            handled = absok;
        }
        // Halving add/sub (SHADD/UHADD/SRHADD/URHADD/SHSUB/UHSUB). Sizes B/H/S
        // (size=11/.2d is Reserved for these families — never emitted). VS0=Vn,
        // VS1=Vm are loaded; the helper leaves the result in VS0.
        SHadd | UHadd | SrHadd | UrHadd | SHsub | UHsub => {
            handled = lower_vec_halving(enc, op, size);
        }
        // MUL.D, PMUL — Tier 1 (BUILDSPEC §7.1).
        _ => handled = false,
    }

    if !handled {
        enc.emit_ud2();
        return;
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}

/// Per-element halving add/sub (SHADD/UHADD/SRHADD/URHADD/SHSUB/UHSUB), sizes
/// B/H/S — computes the result into VS0. Precondition: VS0=Vn, VS1=Vm. Returns
/// false (→ caller emits UD2) for the unencodable D (.2d) width, which ARM
/// reserves for these ops anyway.
///
/// No-overflow identities (verified in IEEE/2's-complement over all element bits):
///   UHADD  = (a & b) + lsr1(a ^ b)          SHADD  = (a & b) + asr1(a ^ b)
///   URHADD = (a | b) - lsr1(a ^ b)          SRHADD = (a | b) - asr1(a ^ b)
///   UHSUB  = lsr1(a) - lsr1(b) - borrow     SHSUB  = asr1(a) - asr1(b) - borrow
///     where borrow = (~a & b) & 1  (per element, the LSB).
/// `lsr1`/`asr1` are per-element logical/arithmetic shift-right-by-1; byte width
/// (no PSRLB/PSRAB in SSE) is emulated via PSRLW + 0x7F/0x80 byte masks.
///
/// Register discipline (VS0..VS3 are the only scratch): a/b live in VS0/VS1; VS2
/// holds the running combiner term; VS3 is the transient mask register, rebuilt
/// from RAX at each use and never assumed live across a shift step.
fn lower_vec_halving(enc: &mut X86Encoder, op: VecBinOp, size: u8) -> bool {
    use VecBinOp::*;
    if size == D {
        return false; // .2d reserved for halving ops
    }
    let arith = matches!(op, SHadd | SrHadd | SHsub);

    match op {
        // ── HSUB: shr1(a) - shr1(b) - ((~a & b) & 1) ──────────────────────────
        SHsub | UHsub => {
            // borrow (VS2) = (~a & b) & lsb1 — compute BEFORE shifting a/b.
            enc.emit_movdqa_rr(VS2, VS0);   // VS2 = a
            enc.emit_pandn(VS2, VS1);       // VS2 = ~a & b
            // VS2 &= per-element LSB mask (VS3 = mask scratch).
            emit_bcast_mask(enc, VS3, lsb_mask(size));
            enc.emit_pand(VS2, VS3);
            // shr1(a) → VS0, shr1(b) → VS1. (Byte arith needs a sign-capture
            // scratch; VS2 holds borrow, so capture into VS3 and mask via RAX only
            // — see emit_shr1_byte which keeps VS2 untouched.)
            emit_shr1(enc, VS0, size, arith);
            emit_shr1(enc, VS1, size, arith);
            // VS0 = shr1(a) - shr1(b) - borrow.
            psub(enc, size, VS0, VS1);
            psub(enc, size, VS0, VS2);
            true
        }
        // ── HADD family: comb(a,b) ± shr1(a^b) ────────────────────────────────
        _ => {
            let rounding = matches!(op, SrHadd | UrHadd);
            // VS2 = a&b (truncating) or a|b (rounding).
            enc.emit_movdqa_rr(VS2, VS0);
            if rounding { enc.emit_por(VS2, VS1) } else { enc.emit_pand(VS2, VS1) }
            // VS0 = shr1(a ^ b).
            enc.emit_pxor(VS0, VS1);
            emit_shr1(enc, VS0, size, arith);
            if rounding {
                // (a|b) - shr1(a^b): do it in VS2, then move to VS0.
                psub(enc, size, VS2, VS0);
                enc.emit_movdqa_rr(VS0, VS2);
            } else {
                // (a&b) + shr1(a^b).
                padd(enc, size, VS0, VS2);
            }
            true
        }
    }
}

#[inline]
fn padd(enc: &mut X86Encoder, size: u8, d: u8, s: u8) {
    match size { B => enc.emit_paddb(d, s), H => enc.emit_paddw(d, s), _ => enc.emit_paddd(d, s) }
}
#[inline]
fn psub(enc: &mut X86Encoder, size: u8, d: u8, s: u8) {
    match size { B => enc.emit_psubb(d, s), H => enc.emit_psubw(d, s), _ => enc.emit_psubd(d, s) }
}

/// Per-element LSB mask (0x01 replicated at the element granularity).
#[inline]
fn lsb_mask(size: u8) -> u64 {
    match size {
        B => 0x0101_0101_0101_0101,
        H => 0x0001_0001_0001_0001,
        _ => 0x0000_0001_0000_0001, // S
    }
}

/// `dst_xmm = <mask64 broadcast to 128 bits>`. Clobbers RAX and `dst_xmm` only.
#[inline]
fn emit_bcast_mask(enc: &mut X86Encoder, dst_xmm: u8, mask64: u64) {
    enc.emit_mov_r64_imm64(RAX, mask64 as i64);
    enc.emit_movq_xmm_r64(dst_xmm, RAX);
    enc.emit_pshufd(dst_xmm, dst_xmm, 0x44); // low qword → both lanes
}

/// Per-element shift-right-by-1 of `reg` in place, using ONLY `reg`, VS3 (mask
/// scratch) and RAX. H/S use native PSRLW/PSRLD (logical) or PSRAW/PSRAD
/// (arithmetic). Byte width has no PSRLB/PSRAB in SSE, so it is emulated:
///   logical byte>>1 = (x >>w 1) & 0x7F7F…            (clear the leaked neighbour bit)
///   arith   byte>>1 = ((x ^ 0x80) >>w 1 & 0x7F7F) - 0x40   (bias trick — no separate
///                     sign register needed: flip the sign bit to make each byte
///                     unsigned, logical-shift, re-bias by −64 per byte). Verified
///                     over all 256 byte values × packed-lane cross-byte leak.
/// Callers pass only VS0/VS1 (VS3 stays free as the transient mask register).
fn emit_shr1(enc: &mut X86Encoder, reg: u8, size: u8, arith: bool) {
    debug_assert!(reg != VS3, "emit_shr1 uses VS3 as scratch; reg must not be VS3");
    match size {
        H => if arith { enc.emit_psraw_imm(reg, 1) } else { enc.emit_psrlw_imm(reg, 1) },
        S => if arith { enc.emit_psrad_imm(reg, 1) } else { enc.emit_psrld_imm(reg, 1) },
        _ => {
            if arith {
                // reg ^= 0x8080… (bias each byte by +128 → unsigned).
                emit_bcast_mask(enc, VS3, 0x8080_8080_8080_8080u64);
                enc.emit_pxor(reg, VS3);
                // logical >>1 (per word) then clear the cross-byte leaked bit.
                enc.emit_psrlw_imm(reg, 1);
                emit_bcast_mask(enc, VS3, 0x7F7F_7F7F_7F7F_7F7Fu64);
                enc.emit_pand(reg, VS3);
                // subtract 64 per byte to undo the bias (128>>1 = 64).
                emit_bcast_mask(enc, VS3, 0x4040_4040_4040_4040u64);
                enc.emit_psubb(reg, VS3);
            } else {
                enc.emit_psrlw_imm(reg, 1);
                emit_bcast_mask(enc, VS3, 0x7F7F_7F7F_7F7F_7F7Fu64);
                enc.emit_pand(reg, VS3);
            }
        }
    }
}

/// NEON integer compare (`VecCmp`) — per-lane all-ones / zero result to vd(d)
/// (BUILDSPEC §7.2). Eq/SGt/SGe are exact via PCMPEQ/PCMPGT (size 3 uses the
/// SSE4.1 q-forms). CMHI/CMHS (unsigned): byte/halfword use the unsigned-max
/// trick (PMAXUB/PMAXUW exist); .4s/.2s/.2d use the sign-bias trick (flip each
/// lane's top bit → signed PCMPGTD/PCMPGTQ) because SSE has no PMAXUD pre-SSE4.1
/// and no PMAXUQ at all. Any unencodable form still emits fail-loud UD2, never a
/// silent wrong answer.
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
    /// false for sizes 2/3 (.4s/.2s/.2d) — SSE has no PMAXUD until SSE4.1 and no
    /// PMAXUQ at all, so those go through the sign-bias path instead.
    fn pmaxu(enc: &mut X86Encoder, size: u8, a: u8, b: u8) -> bool {
        match size {
            0 => enc.emit_pmaxub(a, b),
            1 => enc.emit_pmaxuw(a, b),
            _ => return false,
        }
        true
    }

    /// Broadcast the per-lane sign bias (the top bit of each `size`-lane set) into
    /// `dst` across both 64-bit halves. Flipping the top bit of each lane converts
    /// an unsigned compare into a signed one (`a <ᵤ b  ⇔  a^bias <ₛ b^bias`).
    /// Used for size 2 (.4s/.2s → bias 0x8000_0000 per 32-bit lane) and size 3
    /// (.2d → bias 0x8000_0000_0000_0000 per 64-bit lane).
    fn build_sign_bias(enc: &mut X86Encoder, size: u8, dst: u8) -> bool {
        let lane64: u64 = match size {
            2 => 0x8000_0000_8000_0000, // two 32-bit lanes per 64-bit half
            3 => 0x8000_0000_0000_0000, // one 64-bit lane per half
            _ => return false,
        };
        enc.emit_mov_r64_imm64(RAX, lane64 as i64);
        enc.emit_movq_xmm_r64(dst, RAX);
        enc.emit_punpcklqdq(dst, dst); // broadcast low 64 into both halves
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
        // CMHS (a >= b unsigned).
        UGe => match size {
            // .4s/.2s/.2d: no unsigned-max → sign-bias. a >= b  == ~(b > a).
            // signed(b^bias > a^bias) then invert.
            2 | 3 => {
                if build_sign_bias(enc, size, VS2) {
                    enc.emit_pxor(VS0, VS2); // a' = a ^ bias
                    enc.emit_pxor(VS1, VS2); // b' = b ^ bias
                    // VS1 := (b' > a') signed; invert into VS0.
                    if pcmpgt(enc, size, VS1, VS0) {
                        enc.emit_pcmpeqd(VS3, VS3); // all-ones
                        enc.emit_pxor(VS1, VS3); // ~(b' > a') == (a >= b unsigned)
                        enc.emit_movdqa_rr(VS0, VS1);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            // .8b/.4h: max-trick (max(a,b) == a). bionic strcmp/memcmp.
            _ => {
                enc.emit_movdqa_rr(VS2, VS0); // save a
                if pmaxu(enc, size, VS0, VS1) {
                    pcmpeq(enc, size, VS0, VS2) // max == a  → a >= b
                } else {
                    false
                }
            }
        },
        // CMHI (a > b unsigned).
        UGt => match size {
            // .4s/.2s/.2d: sign-bias. a > b unsigned == signed(a^bias > b^bias).
            2 | 3 => {
                if build_sign_bias(enc, size, VS2) {
                    enc.emit_pxor(VS0, VS2); // a' = a ^ bias
                    enc.emit_pxor(VS1, VS2); // b' = b ^ bias
                    pcmpgt(enc, size, VS0, VS1) // VS0 := (a' > b') signed
                } else {
                    false
                }
            }
            // .8b/.4h: max-trick ~(max(a,b) == b).
            _ => {
                enc.emit_movdqa_rr(VS2, VS1); // save b
                if pmaxu(enc, size, VS0, VS1) && pcmpeq(enc, size, VS0, VS2) {
                    enc.emit_pcmpeqd(VS3, VS3); // all-ones
                    enc.emit_pxor(VS0, VS3); // ~(a <= b) == (a > b)
                    true
                } else {
                    false
                }
            }
        },
        // CMTST (per-lane (a & b) != 0). t = a & b; eq0 = (t == 0); result = ~eq0.
        Tst => {
            enc.emit_pand(VS0, VS1); // VS0 = a & b
            enc.emit_pxor(VS2, VS2); // VS2 = 0
            if pcmpeq(enc, size, VS0, VS2) {
                // VS0 = all-ones where (a&b)==0; invert to get != 0.
                enc.emit_pcmpeqd(VS3, VS3); // all-ones
                enc.emit_pxor(VS0, VS3); // ~((a&b)==0) == ((a&b)!=0)
                true
            } else {
                false
            }
        }
        // SLt/SLe are ONLY produced by the compare-vs-#0 forms (CMLT/CMLE #0),
        // which route to lower_veccmpzero — there is no register-register encoding,
        // so they never reach this register-register lowerer. Fail-loud.
        SLt | SLe => false,
    };

    if !ok {
        enc.emit_ud2();
        return;
    }
    dform_fixup(enc, q);
    enc.emit_movdqu_store(R15, vd(d), VS0);
}
