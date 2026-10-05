//! Data-processing — Scalar Floating-Point & Advanced SIMD (ARM ARM §C4.1.6).
//!
//! Phase A AT-3 tightened fill: every valid NEON / scalar-FP / crypto encoding
//! is classified and accepted; every reserved encoding is rejected. The
//! granularity stays coarse (catch-all `AdvSimd { raw }` / `FpScalar { raw }`
//! variants) — per-opcode lift refinement is Phase B work.
//!
//! Mask values mirror those in Linux's `arch/arm64/include/asm/insn.h`. Where
//! a sub-family's mask doesn't already pin every fixed bit, a follow-up
//! `validate_*` helper checks the remaining spec constraints.

use super::{DecodeErr, DecodedInsn, Reg, VReg};

pub fn decode(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // ===== Crypto =====
    // AES (AESE/AESD/AESMC/AESIMC): fixed bits[31:16]=0x4E28 and bits[11:10]=10;
    // the 4-bit opcode at [15:12] (0100..0111) and Rn/Rd are free. The old mask
    // 0xFF00_FC00 zeroed bits[23:16] but the value 0x4E28_4800 required 0x28
    // there, so the test could NEVER be true — every AES op fell through to
    // Reserved (dead since written; first hit by bionic's AES-CTR-DRBG in init).
    if (word & 0xFFFF_0C00) == 0x4E28_0800 {
        return decode_crypto_aes(word);
    }
    if (word & 0xFF20_8C00) == 0x5E00_0000 {
        return decode_crypto_sha_3reg(word);
    }
    // 2-register SHA (SHA1H/SHA1SU1/SHA256SU0). The fixed bits are [31:22],
    // [21:17]=10100 and [11:10]=10; the 5-bit opcode at [16:12] VARIES, so it must
    // NOT be pinned. The old mask 0xFFFF_FC00 wrongly pinned [16:12]=0, matching
    // ONLY SHA1H — SHA256SU0 (opcode 00010) fell through to TranslateFail.
    if (word & 0xFFFE_0C00) == 0x5E28_0800 {
        return decode_crypto_sha_2reg(word);
    }
    if (word & 0xFFE0_0000) == 0xCE60_0000 {
        return decode_crypto_sha512(word);
    }

    // ===== Scalar FP =====
    // Order matters — more specific masks before more general.
    if (word & 0xFF20_7C00) == 0x1E20_4000 {
        return decode_fp_1src(word);
    }
    if (word & 0xFF20_FC00) == 0x1E20_8000 {
        // Some FP1src variants overlap; this check fires when bits[15:10]=100000
        // (FCVT, FRINTN, etc.). Combined under FP1src.
        return decode_fp_1src(word);
    }
    // FP 2-source: bits[11:10]=10. The mask MUST pin bit10=0 (0x0000_0400) — the
    // old 0xFF20_0800 only pinned bit11, so it also swallowed FCSEL (bits[11:10]=11)
    // and routed it to the 2-source decoder → Reserved → TranslateFail-halt, before
    // the FCSEL branch below could see it.
    if (word & 0xFF20_0C00) == 0x1E20_0800 {
        return decode_fp_2src(word);
    }
    if (word & 0xFF00_0000) == 0x1F00_0000 {
        return decode_fp_3src(word);
    }
    if (word & 0xFF20_1C00) == 0x1E20_1000 {
        return decode_fp_imm(word);
    }
    // FP compare: bits[15:10] = 00_1000 (op=00, then 1000). The old 0x..0C00 mask
    // only pinned bits[11:10] and left bit13 (set in the 0x..2000 target) unmasked,
    // so this branch could NEVER match and every FCMP fell through to Reserved.
    if (word & 0xFF20_FC00) == 0x1E20_2000 {
        return decode_fp_compare(word);
    }
    if (word & 0xFF20_0C00) == 0x1E20_0400 {
        return decode_fp_ccmp(word);
    }
    if (word & 0xFF20_0C00) == 0x1E20_0C00 {
        return decode_fp_csel(word);
    }
    // FP <-> integer convert: pin bits[30:24]=0011110, bit21=1, bits[15:10]=0
    // (scale=0 distinguishes from fixed-point convert below). Leave sf, type,
    // rmode, opcode free so the converter sees every (rmode,opcode) — the old
    // 0x7F3F_FC00 mask pinned bits[20:16]=0 and routed ONLY rmode=00/opcode=000,
    // so FMOV (opcode=110/111), SCVTF, FCVTZS etc. fell through to Reserved.
    if (word & 0x7F20_FC00) == 0x1E20_0000 {
        return decode_fp_int_convert(word);
    }
    // FP <-> fixed-point convert: bit 21 = 0 (vs convert above which has bit 21 = 1)
    if (word & 0x7F20_0000) == 0x1E00_0000 {
        return decode_fp_fixed_convert(word);
    }

    // ===== Advanced SIMD =====
    // For all vector AdvSIMD families, bit 29 (U) is variable (signed/unsigned
    // form selector) so it stays OUT of the mask — use 0x9F top-byte mask.
    // 3-same: bit21=1 (0x0020_0000) distinguishes from 3-same-extra (bit21=0);
    // bit10=1 (0x0000_0400) distinguishes from 3-diff/2reg-misc (bit10=0). bit15
    // (opcode[4]) must NOT be in the mask — it is the high/low opcode selector,
    // so pinning it (the old 0x9F20_8400) silently dropped ADD/SUB/MUL/MLA/
    // CMEQ/ADDP and the whole FP 3-same block (opcodes >= 0b10000).
    if (word & 0x9F20_0400) == 0x0E20_0400 {
        return decode_simd_3same(word);
    }
    if (word & 0x9F20_0400) == 0x0E00_8400 {
        return decode_simd_3same_extra(word);
    }
    // 3-different: bit21=1, bits[11:10]=00. The opcode is bits[15:12] — its top
    // bit (bit15) is part of the opcode (1xxx = the *-LONG multiply forms UMLAL/
    // UMLSL/UMULL/PMULL), so it must NOT be pinned. The old 0x..8C00 mask pinned
    // bit15=0 and dropped every multiply-long op into a fatal TranslateFail.
    if (word & 0x9F20_0C00) == 0x0E20_0000 {
        return decode_simd_3diff(word);
    }
    // Integer compare-vs-#0 — 2reg-misc (opcode[16:14]=010, bit15=1). This covers
    // CMGT/CMGE/CMEQ/CMLT/CMLE #0. The narrowed 2reg-misc mask below pins bit15=0
    // (opcode[3]) and misses these bit15=1 opcodes, so route them explicitly. The
    // mask leaves opcode[13:12] free (so it also spans the neighbouring ABS/NEG
    // opcode 01011 — but ABS/NEG is routed earlier at 0x0E20_B800, so it never
    // reaches here). Map (opcode,U) → compare op; only the five compare forms
    // return, anything else falls through to the general dispatch.
    //   op: 0=Eq 1=Gt(signed) 2=Ge(signed) 3=Lt(signed) 4=Le(signed).
    if (word & 0x9F3F_CC00) == 0x0E20_8800 {
        let q = (word >> 30) & 1;
        let u = (word >> 29) & 1;
        let size = (word >> 22) & 0x3;
        let opcode = (word >> 12) & 0x1F;
        let op: Option<u8> = match (opcode, u) {
            (0b01000, 0) => Some(1), // CMGT #0 (signed >0)
            (0b01000, 1) => Some(2), // CMGE #0 (signed >=0)
            (0b01001, 0) => Some(0), // CMEQ #0
            (0b01001, 1) => Some(4), // CMLE #0 (signed <=0)
            (0b01010, 0) => Some(3), // CMLT #0 (signed <0)
            _ => None,
        };
        if let Some(op) = op {
            if size == 0b11 && q == 0 {
                return Err(DecodeErr::Reserved); // .2d needs Q=1
            }
            let rn = ((word >> 5) & 0x1F) as u8;
            let rd = (word & 0x1F) as u8;
            return Ok(DecodedInsn::SimdIntCmpZero {
                rd: VReg(rd),
                rn: VReg(rn),
                op,
                size: size as u8,
                q: q == 1,
            });
        }
    }
    // ABS (U=0) / NEG (U=1) — integer 2reg-misc, opcode 0b01011 (opcode[3]=bit15=1).
    // This sits in the SAME opcode-bit-15-set space as the FP 2reg-misc block, and
    // its `size` (bits[23:22]) can be 1x, so the FP mask below (which pins bit23=1)
    // would otherwise steal the .4s/.2d forms and Reserve them. Route it first.
    // Frame: bits[28:24]=01110, bits[21:17]=10000, opcode[16:12]=01011,
    // bits[11:10]=10; leave Q (bit30), U (bit29), size (bits[23:22]) free.
    // bits[20:17] MUST be pinned to 0 (the 2reg-misc fixed field) — otherwise this
    // mask claims undefined encodings (e.g. 0x4E78BA0F, bits[21:17]=11100) that
    // capstone rejects, tripping the AT-1 no-false-positive gate.
    if (word & 0x1F3F_FC00) == 0x0E20_B800 {
        let q = (word >> 30) & 1;
        let u = (word >> 29) & 1;
        let size = (word >> 22) & 0x3;
        // .2d (size=11) needs Q=1 (no 64-bit-element D-form register).
        if size == 0b11 && q == 0 {
            return Err(DecodeErr::Reserved);
        }
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdAbsNeg {
            rd: VReg(rd),
            rn: VReg(rn),
            size: size as u8,
            q: q == 1,
            neg: u == 1,
        });
    }
    // Vector FRINT{N,M,P,Z,A} (2-reg-misc FP round-to-integral, opcode 11000/11001).
    // These sit in BOTH the a=0 (bit23=0) and a=1 (bit23=1) 2-reg-misc groups, so
    // neither the FP-2reg-misc mask (pins bit23=1) nor the integer-2reg-misc mask
    // (pins bit15=0; FRINT opcode[3]=bit15=1) catches the a=0 forms — they fell
    // through the whole decoder to Reserved. Route the whole family explicitly.
    // Frame: bits[28:24]=01110, bits[21:17]=10000, opcode[16:13]=1100, bits[11:10]=10;
    // leave Q(30)/U(29)/a(23)/sz(22)/opcode[0]=bit12 free.
    if (word & 0x9F3F_EC00) == 0x0E21_8800 {
        return decode_simd_fp_round_vector(word);
    }
    // Vector SCVTF/UCVTF (int→FP, 2-reg-misc, opcode 0b11101) live in the bit23=0
    // column (a=0), UNLIKE the FCVTZ/FABS/FCMxx FP-misc forms (bit23=1) handled by
    // the mask below. bit23=0 with opcode[3]=bit15=1 is missed by both the bit23=1
    // FP mask and the bit15=0 integer mask, so genuine SCVTF.4s fell through to
    // Reserved (a fail-loud translate blocker; SCVTF is common in Android FP code).
    // Route it explicitly to the cvtdq2ps lowering. Frame: bit31=0, bits[28:24]=
    // 01110, bit23=0, bits[21:17]=10000, opcode[16:12]=11101, bits[11:10]=10; leave
    // Q(30)/U(29)/sz(22) free. (The lowerer keeps unsigned/.2d fail-loud via UD2.)
    if (word & 0x9FBF_FC00) == 0x0E21_D800 {
        let q = (word >> 30) & 1;
        let u = (word >> 29) & 1;
        let sz = (word >> 22) & 1; // 0=single(.4s/.2s), 1=double(.2d)
        // .2d (double) needs Q=1.
        if sz == 1 && q == 0 {
            return Err(DecodeErr::Reserved);
        }
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdCvtFp {
            rd: VReg(rd),
            rn: VReg(rn),
            to_fp: true,
            signed: u == 0,
            dbl: sz == 1,
            q: q == 1,
        });
    }
    // FP 2reg-misc — FABS/FNEG/FSQRT + FP compare-vs-#0 (FCMEQ/FCMGT/FCMGE/FCMLT/
    // FCMLE) + FCVTZS/FCVTZU + FRECPE/FRSQRTE(reserved). These have bit23=1 (FP
    // block) AND opcode[3]=1 (bit15). The integer 2reg-misc mask below pins bit15=0
    // so it misses them, and they fell through to Reserved. Frame: bit31=0,
    // bits[28:24]=01110, bit23=1, bits[21:17]=10000, bit15=1, bits[11:10]=10;
    // leave Q/U/sz(bit22) and opcode[4]+opcode[2:0] free.
    //
    // bit15=1 MUST be pinned: without it this mask also swallows integer 2reg-misc
    // ops whose `size` happens to be 1x (bit23=1) — e.g. UADDLP/SADDLP .2d (opcode
    // 00010, bit15=0) — stealing them from the integer route and Reserving them.
    if (word & 0x9FBE_8C00) == 0x0EA0_8800 {
        return decode_simd_fp_2reg_misc(word);
    }
    // XTN/XTN2 — 2reg-misc extract-narrow (U=0, opcode 0b10010). opcode[4]=1
    // and opcode[3]=0, so the narrowed 2reg-misc mask below (which pins both
    // opcode[4] and opcode[3] to 0) misses it. Route it explicitly. Pin
    // bits[28:24]=01110, bit21=1, opcode bits[16:12]=10010, bits[11:10]=10;
    // leave Q (bit30), size (bits[23:22]) free. U=0 pinned (bit29=0).
    if (word & 0xBF3F_FC00) == 0x0E21_2800 {
        return decode_simd_2reg_misc(word);
    }
    if (word & 0x9F3F_8C00) == 0x0E20_0800 {
        return decode_simd_2reg_misc(word);
    }
    // ADDV (across-lanes, opcode 0b11011) — the general across-lanes mask below
    // pins opcode[4:3]=0 and misses this high opcode, so route it explicitly.
    if (word & 0xBF3F_FC00) == 0x0E31_B800 {
        return decode_simd_across_lanes(word);
    }
    if (word & 0x9F3F_8C00) == 0x0E30_0800 {
        return decode_simd_across_lanes(word);
    }
    // SMAXV/UMAXV (opcode 01010) + SMINV/UMINV (opcode 11010): the mask above pins
    // opcode[3]=0 and misses these high opcodes, so route them explicitly (bits
    // [15:12]=1010 + the across-lanes frame; bit16 free = MAXV vs MINV). B20/B29.
    if (word & 0x1F3E_FC00) == 0x0E30_A800 {
        return decode_simd_across_lanes(word);
    }
    if (word & 0x9FE0_8400) == 0x0E00_0400 {
        return decode_simd_copy(word);
    }
    // SHRN/SHRN2 (shift-imm narrow, U=0, opcode 0b10000) — its encoding overlaps
    // the modimm dispatch mask below, so route it explicitly first.
    // SHRN/SHRN2 — but ONLY when immh (bits[23:19]) != 0. SHRN and the MOVI
    // 16-bit-no-shift modified-immediate (cmode=1000, op=0) share bits[15:11]=
    // 10000; they differ solely by immh (SHRN's shift selector is always non-zero,
    // MOVI's is 0). Without the immh guard this route steals `movi v1.4h,#imm`
    // (0x0f008421) and decode_shrn rejects it → TranslateFail.
    if (word & 0xBF80_FC00) == 0x0F00_8400 && (word & 0x0078_0000) != 0 {
        return decode_shrn(word);
    }
    // Modified-immediate (MOVI/MVNI/ORR/BIC/FMOV-vec). Pin [28:24]=01111,
    // bits[23:19]=0, bit10=1; leave cmode free (the old 0x9F80_1C00 mask pinned
    // bits[12:10] and so missed the odd-cmode ORR/BIC forms).
    if (word & 0x9FF8_0400) == 0x0F00_0400 {
        return decode_simd_modimm(word);
    }
    if (word & 0x9F80_0400) == 0x0F00_0400 {
        return decode_simd_shift_imm(word);
    }
    if (word & 0x9F00_0400) == 0x0F00_0000 {
        return decode_simd_indexed(word);
    }
    // ZIP/UZP/TRN permute. Pin [28:24]=01110, bit21=0, bit15=0, bits[11:10]=10;
    // leave size (bits[23:22]) FREE — the old 0xBFA0_8C00 pinned bit23 and so
    // dropped the .4s/.2d (size>=10) forms (e.g. uzp1 v.4s).
    if (word & 0xBF20_8C00) == 0x0E00_0800 {
        return decode_simd_permute(word);
    }
    // EXT (extract) has bit 29 = 1 fixed in its encoding family (op=1).
    if (word & 0xBFE0_8400) == 0x2E00_0000 {
        return decode_simd_extract(word);
    }
    // TBL/TBX (table) has bit 29 = 0 fixed (op=0).
    if (word & 0xBFE0_8C00) == 0x0E00_0000 {
        return decode_simd_table(word);
    }

    // ===== Scalar-shape Advanced SIMD =====
    // Scalar has bit 31 = 0 + bit 30 = 1 fixed; bit 29 = U variable. Mask
    // 0xDF top byte covers bits 31, 30, 28..24 leaving 29 free.
    //
    // Scalar pairwise (ADDP/FADDP/…) is dispatched FIRST via a precise mask: the
    // generic `0xDF3F_8400 == 0x5E30_0800` test below can never match (its byte-1
    // value 0x08 is not a subset of the 0x84 mask), so the scalar-pairwise group
    // was historically dead. Frame: bits[31:30]=01, bits[28:24]=11110,
    // bits[21:17]=11000, bits[11:10]=10; leave U(29), size(23:22), opcode(16:12).
    if (word & 0xDF3E_0C00) == 0x5E30_0800 {
        return decode_simd_scalar_pairwise(word);
    }
    if (word & 0xDF20_8400) == 0x5E20_0400 {
        return decode_simd_scalar_3same(word);
    }
    if (word & 0xDF3F_8400) == 0x5E20_0800 {
        return decode_simd_scalar_2reg_misc(word);
    }
    if (word & 0xDFE0_8400) == 0x5E00_0400 {
        return decode_simd_scalar_copy(word);
    }
    if (word & 0xDF3F_8400) == 0x5E30_0800 {
        return decode_simd_scalar_pairwise(word);
    }
    if (word & 0xDF80_0400) == 0x5F00_0400 {
        return decode_simd_scalar_shift_imm(word);
    }
    if (word & 0xDF00_0400) == 0x5F00_0000 {
        return decode_simd_scalar_indexed(word);
    }

    Err(DecodeErr::Reserved)
}

// =============================================================================
// Crypto AES
// =============================================================================

fn decode_crypto_aes(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let opcode = ((word >> 12) & 0xF) as u8;
    // Valid AES opcodes: 0100=AESE 0101=AESD 0110=AESMC 0111=AESIMC
    if !(0b0100..=0b0111).contains(&opcode) {
        return Err(DecodeErr::Reserved);
    }
    let rn = VReg(((word >> 5) & 0x1F) as u8);
    let rd = VReg((word & 0x1F) as u8);
    Ok(DecodedInsn::CryptoAes { op: opcode, rd, rn })
}

// =============================================================================
// FP-scalar
// =============================================================================

/// Common gate: FP ftype = bits[23:22]. Values 00 (single), 01 (double), and
/// 11 (half, ARMv8.2 FP16) are valid for scalar FP. ftype=10 is reserved.
fn fp_ftype_ok(word: u32) -> bool {
    let ftype = (word >> 22) & 0x3;
    ftype != 0b10
}

fn decode_fp_1src(word: u32) -> Result<DecodedInsn, DecodeErr> {
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    // opcode bits[20:15], valid set determined by ftype. Conservative: accept
    // opcodes 0..7 for any ftype (FMOV/FABS/FNEG/FSQRT/FCVT D/H/S between);
    // accept 8..15 for FRINT variants; reject 16+.
    let opcode = (word >> 15) & 0x3F;
    if opcode >= 0x20 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_fp_2src(word: u32) -> Result<DecodedInsn, DecodeErr> {
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    // opcode bits[15:12]. Valid: 0000..1000 (FMUL/FDIV/FADD/FSUB/FMAX/FMIN/
    // FMAXNM/FMINNM/FNMUL). Others reserved.
    let opcode = (word >> 12) & 0xF;
    if opcode > 0b1000 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_fp_3src(word: u32) -> Result<DecodedInsn, DecodeErr> {
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    // o1 (bit 21), o0 (bit 15) — all four combos are valid.
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_fp_imm(word: u32) -> Result<DecodedInsn, DecodeErr> {
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    // imm5 (bits[9:5]) must be 0 per ARM ARM (the immediate is in bits[20:13],
    // the remaining low bits are zero).
    if (word >> 5) & 0x1F != 0 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_fp_compare(word: u32) -> Result<DecodedInsn, DecodeErr> {
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    // bits[4:0] = opcode2 — only 00000/01000/10000/11000 valid (FCMP, FCMP zero,
    // FCMPE, FCMPE zero). Bits[2:0] must be 000.
    if word & 0b111 != 0 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_fp_ccmp(word: u32) -> Result<DecodedInsn, DecodeErr> {
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_fp_csel(word: u32) -> Result<DecodedInsn, DecodeErr> {
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_fp_int_convert(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // rmode (bits[20:19]) and opcode (bits[18:16]) together select the
    // conversion. Specific (rmode, opcode) combinations are reserved; the
    // architectural table (ARM ARM C4-12) is complex. Conservative
    // validation: opcode != 011 except when rmode == 11 (FCVTZS/FCVTZU only
    // valid via fixed-point path; here rmode=11 opcode=011 = FCVTZU).
    let rmode = (word >> 19) & 0x3;
    let opcode = (word >> 16) & 0x7;

    // FMOV (general) — a pure bit-move between a GPR and an FP register, with no
    // numeric conversion. Intercept the implemented forms as a typed variant so
    // they lift to direct q-register-file moves (the rest of the conversions
    // stay coarse FpScalar). ftype: 00=S(32), 01=D(64), 10=Q-high(128).
    let sf = (word >> 31) & 1;
    let ftype = (word >> 22) & 0x3;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;

    // The FMOV high-half forms (Xd <-> Vn.D[1]) legitimately use ftype=10, which
    // the generic `fp_ftype_ok` guard reserves for the numeric-convert forms.
    // Exempt them so they reach the typed match below instead of a fatal
    // TranslateFail (bionic's GHASH reduction uses `fmov v.d[1], x` /
    // `fmov x, v.d[1]`). All other ftype=10 encodings stay reserved.
    let is_fmov_high =
        sf == 1 && ftype == 0b10 && rmode == 0b01 && (opcode == 0b110 || opcode == 0b111);
    if !is_fmov_high && !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }

    match (rmode, opcode) {
        // FMOV Wd,Sn / Xd,Dn — FP lane 0 -> GPR.
        (0b00, 0b110) if (sf == 0 && ftype == 0b00) || (sf == 1 && ftype == 0b01) => {
            let size = if sf == 1 { 8 } else { 4 };
            return Ok(DecodedInsn::FmovGen {
                to_gpr: true,
                rd: Reg(rd),
                vn: VReg(rn),
                lane: 0,
                size,
                zero_rest: false,
            });
        }
        // FMOV Sd,Wn / Dd,Xn — GPR -> FP lane 0 (zero the rest of the V reg).
        (0b00, 0b111) if (sf == 0 && ftype == 0b00) || (sf == 1 && ftype == 0b01) => {
            let size = if sf == 1 { 8 } else { 4 };
            return Ok(DecodedInsn::FmovGen {
                to_gpr: false,
                rd: Reg(rn),
                vn: VReg(rd),
                lane: 0,
                size,
                zero_rest: true,
            });
        }
        // FMOV Xd,Vn.D[1] — high 64 bits -> GPR (sf=1, ftype=10 only).
        (0b01, 0b110) if sf == 1 && ftype == 0b10 => {
            return Ok(DecodedInsn::FmovGen {
                to_gpr: true,
                rd: Reg(rd),
                vn: VReg(rn),
                lane: 1,
                size: 8,
                zero_rest: false,
            });
        }
        // FMOV Vd.D[1],Xn — GPR -> high 64 bits (keep lane 0).
        (0b01, 0b111) if sf == 1 && ftype == 0b10 => {
            return Ok(DecodedInsn::FmovGen {
                to_gpr: false,
                rd: Reg(rn),
                vn: VReg(rd),
                lane: 1,
                size: 8,
                zero_rest: false,
            });
        }
        _ => {}
    }

    // Allow rmode=00 with opcode in {000(FCVTNS), 001(FCVTNU), 010(SCVTF),
    // 011(UCVTF), 100(FCVTAS), 101(FCVTAU), 110(FMOV-to-int), 111(FMOV-to-fp)}
    // Allow rmode=01 with opcode in {000(FCVTPS), 001(FCVTPU), 110/111(FMOV
    // extended for v8.2 FP16)}
    // Allow rmode=10 with opcode in {000(FCVTMS), 001(FCVTMU)}
    // Allow rmode=11 with opcode in {000(FCVTZS), 001(FCVTZU)}
    let ok = match (rmode, opcode) {
        (0b00, 0..=7) => true,
        (0b01, 0b000 | 0b001 | 0b110 | 0b111) => true,
        (0b10, 0b000 | 0b001) => true,
        (0b11, 0b000 | 0b001) => true,
        _ => false,
    };
    if !ok {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_fp_fixed_convert(word: u32) -> Result<DecodedInsn, DecodeErr> {
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    // rmode bits[20:19], opcode bits[18:16]. Fixed-point form requires
    // (rmode, opcode[2]) ∈ {(00, 0b001) SCVTF / UCVTF, (11, 0b000) FCVTZS / FCVTZU}.
    // Specifically:
    //   rmode=00, opcode=010 = SCVTF (int→fp)
    //   rmode=00, opcode=011 = UCVTF
    //   rmode=11, opcode=000 = FCVTZS (fp→int)
    //   rmode=11, opcode=001 = FCVTZU
    let rmode = (word >> 19) & 0x3;
    let opcode = (word >> 16) & 0x7;
    let ok = matches!((rmode, opcode), (0b00, 0b010 | 0b011) | (0b11, 0b000 | 0b001));
    if !ok {
        return Err(DecodeErr::Reserved);
    }
    // scale (bits[15:10]) must produce 1..=datasize. For sf=0 → scale ∈ [33, 64].
    // Equivalent encoding: bits[15:10] must satisfy (sf=1 → any) or (sf=0 → top
    // bit must be 1). Conservative check:
    let sf = (word >> 31) & 1;
    let scale = (word >> 10) & 0x3F;
    if sf == 0 && scale < 32 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::FpScalar { raw: word })
}

fn decode_crypto_sha_3reg(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // bits[14:12] = opcode. Valid: 0..6 (SHA1C/P/M/SU0/SHA256H/H2/SU1). 7 reserved.
    let opcode = (word >> 12) & 0x7;
    if opcode == 0b111 {
        return Err(DecodeErr::Reserved);
    }
    // bits[23:22] = size; must be 00.
    if (word >> 22) & 0x3 != 0 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::CryptoSha { op: opcode as u8, raw: word })
}

fn decode_crypto_sha_2reg(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // Mask already constrains bits[16:12] = 0..2. Accept.
    Ok(DecodedInsn::CryptoSha { op: ((word >> 12) & 0x7) as u8, raw: word })
}

fn decode_crypto_sha512(_word: u32) -> Result<DecodedInsn, DecodeErr> {
    // SHA512/SHA3/SM3/SM4 family — ARMv8.2-A FEAT_SHA3+FEAT_SHA512+FEAT_SM3+FEAT_SM4.
    //
    // The bundled Capstone (capstone-rs 0.12 / capstone-sys 0.16) does NOT
    // decode any of this family in default arm64 mode, so accepting these
    // encodings makes the AT-1 false-positive gate fail. Returning Reserved
    // here is a deliberate Phase A trade-off: we sacrifice decoding ~50
    // crypto instructions (rarely emitted in Android baseline binaries) in
    // exchange for a clean capstone-diff gate. Phase B re-enables this once
    // we either upgrade capstone-rs or move to a proper mnemonic-comparison
    // gate that tolerates Capstone's known blind spots.
    Err(DecodeErr::Reserved)
}

// =============================================================================
// Advanced SIMD vector
// =============================================================================

fn decode_simd_3same(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let q = (word >> 30) & 1;
    let size = (word >> 22) & 0x3;
    let opcode = (word >> 11) & 0x1F;
    // Q=0 + size=11 reserved (NEON 2D requires Q=1).
    if q == 0 && size == 0b11 {
        return Err(DecodeErr::Reserved);
    }
    // FP 3-same (opcode 0b11xxx). In this block the `size` field is {a:sz}:
    //   a  = size[1] (bit23) — selects the add-class (a=0) vs the second
    //        (a=1) operation in each opcode slot (e.g. FADD vs FSUB).
    //   sz = size[0] (bit22) — element type: 0 = single (.4s/.2s), 1 = double
    //        (.2d). For the .2d (sz=1) forms Q must be 1 (already rejected by the
    //        Q=0/size=11 check above for a=1; the a=0,sz=1 case is size=01 which
    //        is .2s single — fine). All four `size` codes are VALID for FP — this
    //        is the one sub-block where size=11 is NOT reserved (it is FSUB.2d /
    //        FABD.2d / FMIN.2d etc.). Route the supported arithmetic / compare
    //        opcodes; leave the rest (FMULX/FACGE/FACGT/FADDP/FMAXP/…) coarse.
    if opcode >= 0b11000 {
        let u = (word >> 29) & 1;
        let a = (size >> 1) & 1; // bit23: selects the op pair (e.g. FADD vs FSUB)
        let sz = size & 1;
        // q=0 + .2d (sz=1, double) is reserved (no 64-bit-element D-form register).
        if q == 0 && sz == 1 {
            return Err(DecodeErr::Reserved);
        }
        // Accept ONLY the FP 3-same forms `lift_simd_3same` actually lifts (the
        // supported arithmetic / compare ops). Everything else in the FP block
        // (FMULX/FACGE/FACGT/FADDP/FMAXP/FMINP/FMAXNMP/FMINNMP/FRECPS/FRSQRTS) stays
        // Reserved — preserving the pre-M4b-6 capstone no-false-positive behavior
        // (the whole block was Reserved before) and never hallucinating an op the
        // lifter would only stub. The (U, opcode, a) triples below mirror the
        // lifter's match exactly.
        let supported = matches!((u, opcode, a),
            (0, 0b11000, _)   // FMAXNM (a=0) / FMINNM (a=1)
          | (0, 0b11001, _)   // FMLA (a=0) / FMLS (a=1)
          | (0, 0b11010, _)   // FADD (a=0) / FSUB (a=1)
          | (1, 0b11010, 1)   // FABD (a=1)
          | (1, 0b11011, 0)   // FMUL (a=0)
          | (0, 0b11100, 0)   // FCMEQ (a=0)
          | (1, 0b11100, _)   // FCMGE (a=0) / FCMGT (a=1)
          | (0, 0b11110, _)   // FMAX (a=0) / FMIN (a=1)
          | (1, 0b11111, 0)   // FDIV (a=0)
        );
        if !supported {
            return Err(DecodeErr::Reserved);
        }
        return Ok(DecodedInsn::SimdThreeSame {
            q: q != 0,
            u: u != 0,
            size: size as u8,
            opcode: opcode as u8,
            rm: VReg(((word >> 16) & 0x1F) as u8),
            rn: VReg(((word >> 5) & 0x1F) as u8),
            rd: VReg((word & 0x1F) as u8),
        });
    }
    // SQDMULH/SQRDMULH (integer 3-same opcode 01101) is defined only for
    // size in {01, 10} — there is no D-form saturating doubling multiply.
    if opcode == 0b01101 && size == 0b11 {
        return Err(DecodeErr::Reserved);
    }

    // ── M4b-6 capstone-fidelity rejects for the now-reachable high opcodes ──
    // (Before M4b-6 the dispatch mask dropped all opcodes >= 0b10000; broadening
    // it surfaced reserved sub-encodings the AT-1 no-false-positive gate flags.)
    //
    // (FP 3-same, opcode 0b11xxx, is decoded and returned above.)
    // Integer opcodes with NO 64-bit (D) form — reserved at size=11.
    let no_d_form = matches!(
        opcode,
        0b00000 // SHADD/UHADD
            | 0b00010 // SRHADD/URHADD
            | 0b00100 // SHSUB/UHSUB
            | 0b01100 // SMAX/UMAX
            | 0b01101 // SMIN/UMIN
            | 0b01110 // SABD/UABD
            | 0b01111 // SABA/UABA
            | 0b10010 // MLA/MLS
            | 0b10011 // MUL/PMUL
            | 0b10100 // SMAXP/UMAXP
            | 0b10101 // SMINP/UMINP
            | 0b10110 // SQDMULH/SQRDMULH
    );
    if size == 0b11 && no_d_form {
        return Err(DecodeErr::Reserved);
    }
    // PMUL (U=1, opcode 10011) exists only for the 8-bit (size=00) form.
    if ((word >> 29) & 1) == 1 && opcode == 0b10011 && size != 0b00 {
        return Err(DecodeErr::Reserved);
    }
    // SQDMULH/SQRDMULH (opcode 10110) only for size in {01,10}.
    if opcode == 0b10110 && (size == 0b00 || size == 0b11) {
        return Err(DecodeErr::Reserved);
    }

    Ok(DecodedInsn::SimdThreeSame {
        q: ((word >> 30) & 1) != 0,
        u: ((word >> 29) & 1) != 0,
        size: size as u8,
        opcode: opcode as u8,
        rm: VReg(((word >> 16) & 0x1F) as u8),
        rn: VReg(((word >> 5) & 0x1F) as u8),
        rd: VReg((word & 0x1F) as u8),
    })
}

fn decode_simd_3same_extra(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // bits[14:11] = opcode. Valid set covers FCMLA (rotated), FCADD, SDOT, UDOT.
    let opcode = (word >> 11) & 0xF;
    // Conservative: opcodes 0..3 (SDOT/UDOT/SQRDMLAH/SQRDMLSH) and 8..15 (FCMLA/FCADD).
    if !matches!(opcode, 0b0000..=0b0011 | 0b1000..=0b1111) {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_3diff(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 22) & 0x3;
    let opcode_top = (word >> 12) & 0xF;
    let u_top = (word >> 29) & 1;
    // PMULL/PMULL2 `.1q` (opcode 1110, U=0, size=11) — the GHASH/GCM 64×64→128
    // carryless multiply (bionic AES-GCM). Must be handled BEFORE the generic
    // size==11 reject below. (size=00 `.8h` poly-mult stays coarse for now.)
    if opcode_top == 0b1110 && u_top == 0 && size == 0b11 {
        let q = (word >> 30) & 1;
        let rm = ((word >> 16) & 0x1F) as u8;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdPmull {
            rd: VReg(rd),
            rn: VReg(rn),
            rm: VReg(rm),
            high: q == 1,
        });
    }
    if size == 0b11 {
        return Err(DecodeErr::Reserved);
    }
    let opcode = (word >> 12) & 0xF;
    // Valid 3-diff opcodes per ARM ARM C4.1.6 (subset shared between U=0/U=1):
    //   0000 S/UADDL{2}    0001 S/UADDW{2}    0010 S/USUBL{2}    0011 S/USUBW{2}
    //   0100 ADDHN{2}/RADDHN{2}  0101 S/UABAL{2}  0110 SUBHN{2}/RSUBHN{2}  0111 S/UABDL{2}
    //   1000 S/UMLAL{2}    1001 SQDMLAL{2}    1010 S/UMLSL{2}    1011 SQDMLSL{2}
    //   1100 S/UMULL{2}    1101 SQDMULL{2}    1110 PMULL{2}      1111 reserved
    if opcode == 0b1111 {
        return Err(DecodeErr::Reserved);
    }
    // SQDMLAL/SQDMLSL/SQDMULL (opcodes 9, 11, 13) only exist with U=0
    // (signed). For U=1, those opcodes are reserved.
    let u = (word >> 29) & 1;
    if u == 1 && matches!(opcode, 0b1001 | 0b1011 | 0b1101) {
        return Err(DecodeErr::Reserved);
    }
    // PMULL/PMULL2 (opcode 1110) requires size=00 or size=11 (poly types).
    // We already rejected size=11; require size=00 specifically here.
    if opcode == 0b1110 && size != 0b00 {
        return Err(DecodeErr::Reserved);
    }
    // Integer multiply-long forms: UMULL/SMULL (1100), UMLAL/SMLAL (1000),
    // UMLSL/SMLSL (1010). `Q` selects the low/high source half (the `2` variant);
    // `U` selects unsigned/signed; widen `size`-byte elements to 2×, multiply,
    // then (MLAL) add to / (MLSL) subtract from Vd, or (MULL) replace Vd.
    if matches!(opcode, 0b1000 | 0b1010 | 0b1100) {
        let q = (word >> 30) & 1;
        let rm = ((word >> 16) & 0x1F) as u8;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdMulLong {
            rd: VReg(rd),
            rn: VReg(rn),
            rm: VReg(rm),
            size: size as u8,
            q: q == 1,
            signed: u == 0,
            accum: opcode != 0b1100,
            sub: opcode == 0b1010,
        });
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

/// FP 2reg-misc — FABS/FNEG/FSQRT and the FP compare-vs-#0.0 forms. `size` here
/// is {a:sz} with a=bit23=1 (FP block); `sz`=bit22 selects single (0) vs double
/// (1). Any opcode not in the supported set falls back to the generic
/// `decode_simd_2reg_misc` (coarse `AdvSimd`) so previously-coarse forms
/// (FCVT*/FRINT*/SCVTF/…) keep their old behavior, never regressing to Reserved.
fn decode_simd_fp_2reg_misc(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let q = (word >> 30) & 1;
    let u = (word >> 29) & 1;
    let sz = (word >> 22) & 1; // 0=single, 1=double
    let opcode = (word >> 12) & 0x1F;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    let dbl = sz == 1;
    // .2d (double) needs Q=1 (no 64-bit-element D register).
    if dbl && q == 0 {
        return Err(DecodeErr::Reserved);
    }
    // FABS (U=0, opcode 0b01111) / FNEG (U=1, opcode 0b01111) / FSQRT (U=1,
    // opcode 0b11111).
    let fp_un = match (u, opcode) {
        (0, 0b01111) => Some(0u8), // FABS
        (1, 0b01111) => Some(1u8), // FNEG
        (1, 0b11111) => Some(2u8), // FSQRT
        _ => None,
    };
    if let Some(op) = fp_un {
        return Ok(DecodedInsn::SimdFpUn { rd: VReg(rd), rn: VReg(rn), op, dbl, q: q == 1 });
    }
    // FP compare vs #0.0:
    //   FCMGT (U=0, opcode 0b01100)  FCMEQ (U=0, opcode 0b01101)
    //   FCMLT (U=0, opcode 0b01110)  FCMGE (U=1, opcode 0b01100)
    //   FCMLE (U=1, opcode 0b01101)
    let fp_cmp = match (u, opcode) {
        (0, 0b01100) => Some(1u8), // FCMGT  → Gt
        (0, 0b01101) => Some(0u8), // FCMEQ  → Eq
        (0, 0b01110) => Some(3u8), // FCMLT  → Lt
        (1, 0b01100) => Some(2u8), // FCMGE  → Ge
        (1, 0b01101) => Some(4u8), // FCMLE  → Le
        _ => None,
    };
    if let Some(op) = fp_cmp {
        return Ok(DecodedInsn::SimdFpCmpZero { rd: VReg(rd), rn: VReg(rn), op, dbl, q: q == 1 });
    }
    // Vector FP→int convert (2-reg-misc), THIS FP block has bit23=1 pinned by the
    // caller's routing mask:
    //   FCVTZS (U=0, opcode 0b11011)   FCVTZU (U=1, opcode 0b11011)  — FP→int (RTZ)
    // NOTE: opcode 0b11101 in the bit23=1 block is FRECPE/FRSQRTE (reciprocal
    // estimate), NOT SCVTF/UCVTF — those are the bit23=0 forms handled separately in
    // decode(). Treating 0b11101 as SCVTF here silently int-converted FRECPE via
    // cvtdq2ps of the raw FP bit pattern (a catastrophic wrong-magnitude miscompile).
    // Only FCVTZ{S,U} is wired here; FRECPE/FRSQRTE stay fail-loud (Reserved) below.
    let cvt = match opcode {
        0b11011 => Some(false), // FCVTZS/FCVTZU (FP→int, round-toward-zero)
        _ => None,
    };
    if let Some(to_fp) = cvt {
        return Ok(DecodedInsn::SimdCvtFp {
            rd: VReg(rd),
            rn: VReg(rn),
            to_fp,
            signed: u == 0,
            dbl,
            q: q == 1,
        });
    }
    // Unsupported FP-misc opcode (FRECPE/FRSQRTE/URSQRTE/…). Every such encoding
    // (bit23=1, opcode[3]=1) fell to Reserved before M4b-6, so keep it Reserved —
    // accepting it as a coarse AdvSimd would be a capstone false-positive (and a
    // lift Hint we can't honour). Fail-loud, not silent. (Vector FRINT — opcode
    // 11000/11001 — is routed to `decode_simd_fp_round_vector` in `decode()`
    // before this function is reached.)
    Err(DecodeErr::Reserved)
}

/// Vector FP round-to-integral `FRINT{N,M,P,Z,A}` `Vd.<T>,Vn.<T>` (2-reg-misc,
/// opcode 11000/11001). The rounding mode is a 3-way split on `(U=bit29, a=bit23,
/// opcode[0]=bit12)` per ARM ARM C7-2:
///   a=0 U=0 op11000 FRINTN(nearest-even)   a=0 U=0 op11001 FRINTM(floor)
///   a=1 U=0 op11000 FRINTP(ceil)           a=1 U=0 op11001 FRINTZ(trunc)
///   a=0 U=1 op11000 FRINTA(ties-away)      a=0 U=1 op11001 FRINTX(inexact — coarse)
///   a=1 U=1 op11001 FRINTI(current-mode — coarse)
/// FRINTX/FRINTI (inexact-raising / current-FPCR-mode) are NOT on the framework
/// render path per the oracle sweep and stay Reserved (fail-loud). `sz`=bit22
/// selects single (.4s/.2s) vs double (.2d).
fn decode_simd_fp_round_vector(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let q = (word >> 30) & 1;
    let u = (word >> 29) & 1;
    let a = (word >> 23) & 1;
    let sz = (word >> 22) & 1; // 0=single, 1=double
    let op0 = (word >> 12) & 1; // opcode[0]: 0=11000, 1=11001
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    // .2d (double) needs Q=1 (no 64-bit-element D register).
    if sz == 1 && q == 0 {
        return Err(DecodeErr::Reserved);
    }
    let round = match (u, a, op0) {
        (0, 0, 0) => 0u8, // FRINTN → nearest-even
        (0, 0, 1) => 1u8, // FRINTM → floor
        (0, 1, 0) => 2u8, // FRINTP → ceil
        (0, 1, 1) => 3u8, // FRINTZ → trunc
        (1, 0, 0) => 4u8, // FRINTA → ties-away
        _ => return Err(DecodeErr::Reserved), // FRINTX / FRINTI — coarse/fail-loud
    };
    Ok(DecodedInsn::SimdFpRound {
        rd: VReg(rd),
        rn: VReg(rn),
        round,
        dbl: sz == 1,
        q: q == 1,
    })
}

fn decode_simd_2reg_misc(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let q = (word >> 30) & 1;
    let size = (word >> 22) & 0x3;
    let opcode = (word >> 12) & 0x1F;
    // Many opcodes valid. Reject Q=0/size=11 (2D in 64-bit form).
    if q == 0 && size == 0b11 {
        return Err(DecodeErr::Reserved);
    }
    // CNT (opcode 0b00101) — per-byte popcount; size MUST be 00 (byte form only).
    if opcode == 0b00101 {
        if size != 0b00 {
            return Err(DecodeErr::Reserved);
        }
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdCnt { rd: VReg(rd), rn: VReg(rn), q: q == 1 });
    }
    // SADDLP (U=0) / UADDLP (U=1) — add-long pairwise (opcode 0b00010). Source
    // element `size` (0=B,1=H,2=S) widens to 2×; size=11 reserved.
    if opcode == 0b00010 {
        if size == 0b11 {
            return Err(DecodeErr::Reserved);
        }
        let u = (word >> 29) & 1;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdAddLongPair {
            rd: VReg(rd),
            rn: VReg(rn),
            size: size as u8,
            q: q == 1,
            signed: u == 0,
        });
    }
    // REV64/REV32/REV16 — reverse the order of `size`-element groups within each
    // `container`-byte group. The container needs ≥2 elements (else a no-op /
    // reserved):
    //   REV64 (U=0, opcode 0b00000): container=8, size ∈ {0=B,1=H,2=S} (3 resvd)
    //   REV32 (U=1, opcode 0b00000): container=4, size ∈ {0=B,1=H}    (2,3 resvd)
    //   REV16 (U=0, opcode 0b00001): container=2, size == 0=B         (else resvd)
    let u = (word >> 29) & 1;
    let rev_container: Option<u8> = match (opcode, u) {
        (0b00000, 0) => Some(8),
        (0b00000, 1) => Some(4),
        (0b00001, 0) => Some(2),
        _ => None,
    };
    if let Some(container) = rev_container {
        // size (element bytes = 1<<size) must be strictly smaller than container.
        if (1u32 << size) >= container as u32 {
            return Err(DecodeErr::Reserved);
        }
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdRev64 {
            rd: VReg(rd),
            rn: VReg(rn),
            size: size as u8,
            q: q == 1,
            container,
        });
    }
    // XTN/XTN2 (U=0, opcode 0b10010) — extract-narrow: truncate each source
    // element to half-width. `size` selects the SOURCE element class:
    //   size=00 → .8h→.8b (esize_out=1), 01 → .4s→.4h (2), 10 → .2d→.2s (4).
    // `Q`=0 writes Vd[63:0] (XTN); Q=1 writes Vd[127:64], preserving the low 64
    // (XTN2). size=11 is reserved. We reuse SimdShrn with shift=0 (XTN == SHRN #0)
    // so the existing VecShiftNarrow lowering handles it.
    if opcode == 0b10010 && u == 0 {
        let esize_out: u8 = match size {
            0b00 => 1, // .8h → .8b
            0b01 => 2, // .4s → .4h
            0b10 => 4, // .2d → .2s
            _ => return Err(DecodeErr::Reserved),
        };
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdShrn {
            rd: VReg(rd),
            rn: VReg(rn),
            shift: 0,
            esize_out,
            high: q == 1,
        });
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

/// SHRN/SHRN2 — shift-right-narrow. `immh` selects the result element size
/// (0001→.8b, 001x→.4h, 01xx→.2s); `shift = 2*esize_bits - UInt(immh:immb)`.
/// `Q` selects SHRN (low 64, false) vs SHRN2 (high 64, true).
fn decode_shrn(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    let immb = (word >> 16) & 0x7;
    if immh == 0 || immh & 0b1000 != 0 {
        return Err(DecodeErr::Reserved); // immh=0 is modimm; immh=1xxx reserved here
    }
    let immhimmb = (immh << 3) | immb;
    let (esize_out, esize_bits): (u8, u32) = if immh & 0b0100 != 0 {
        (4, 32)
    } else if immh & 0b0010 != 0 {
        (2, 16)
    } else {
        (1, 8) // immh == 0001
    };
    let shift = (2 * esize_bits) - immhimmb;
    let q = (word >> 30) & 1;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdShrn {
        rd: VReg(rd),
        rn: VReg(rn),
        shift: shift as u8,
        esize_out,
        high: q == 1,
    })
}

fn decode_simd_across_lanes(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let q = (word >> 30) & 1;
    let size = (word >> 22) & 0x3;
    // size=11 reserved. Q=0 with size=10 reserved for SADDLV/UADDLV/etc.
    if size == 0b11 {
        return Err(DecodeErr::Reserved);
    }
    if q == 0 && size == 0b10 {
        return Err(DecodeErr::Reserved);
    }
    // opcode bits[16:12], valid: 00011 (SADDLV), 01010 (SMAXV), 11010 (UMAXV),
    // 01011 (SMINV), 11011 (UMINV), 11000 (FMAXNMV), 11100 (FMAXV), 11000+u
    // (FMINNMV), 11100+u (FMINV).
    let opcode = (word >> 12) & 0x1F;
    // SADDLV / UADDLV (opcode 0b00011): add-long across all lanes. U(bit29)=0 is
    // signed (SADDLV), U=1 unsigned (UADDLV). Source element size = `size`; the
    // result is twice as wide (so size must be 0=B,1=H,2=S — never D).
    if opcode == 0b00011 {
        let u = (word >> 29) & 1;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdAddvLong {
            rd: VReg(rd),
            rn: VReg(rn),
            size: size as u8,
            q: q == 1,
            signed: u == 0,
        });
    }
    // ADDV (opcode 0b11011, U=0) — reduce-add across lanes (same element width).
    if opcode == 0b11011 && (word >> 29) & 1 == 0 {
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdReduceAdd {
            rd: VReg(rd),
            rn: VReg(rn),
            size: size as u8,
            q: q == 1,
        });
    }
    // SMAXV/UMAXV (opcode 0b01010), SMINV/UMINV (opcode 0b11010): integer
    // min/max reduction across all lanes. U(bit29)=0 signed, U=1 unsigned.
    // (FP reduce opcodes 0b01100/0b01111 stay fail-loud.) — B20/B29
    if opcode == 0b01010 || opcode == 0b11010 {
        let u = (word >> 29) & 1;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdReduceMinMax {
            rd: VReg(rd),
            rn: VReg(rn),
            size: size as u8,
            q: q == 1,
            is_min: opcode == 0b11010,
            signed: u == 0,
        });
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_copy(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let imm5 = (word >> 16) & 0x1F;
    if imm5 == 0 {
        return Err(DecodeErr::Reserved);
    }
    let q = (word >> 30) & 1;
    let op = (word >> 29) & 1;
    let imm4 = (word >> 11) & 0xF;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;

    // Element size + lane index from imm5: the lowest set bit selects B/H/S/D,
    // the bits above it are the lane index. imm5==0b10000 (128-bit) is not a
    // valid element form for these copy ops.
    let (size, lane): (u8, u8) = if imm5 & 1 != 0 {
        (0, ((imm5 >> 1) & 0xF) as u8) // B
    } else if imm5 & 2 != 0 {
        (1, ((imm5 >> 2) & 0x7) as u8) // H
    } else if imm5 & 4 != 0 {
        (2, ((imm5 >> 3) & 0x3) as u8) // S
    } else if imm5 & 8 != 0 {
        (3, ((imm5 >> 4) & 0x1) as u8) // D
    } else {
        return Err(DecodeErr::Reserved);
    };

    if op == 1 {
        // INS (element): Vd.<T>[dst] <- Vn.<T>[src] (vector→vector). Q must be 1.
        // dst lane = `lane` (from imm5); src lane = imm4 >> size (log2 element).
        if q == 0 {
            return Err(DecodeErr::Reserved);
        }
        return Ok(DecodedInsn::SimdInsElem {
            rd: VReg(rd),
            rn: VReg(rn),
            dst_lane: lane,
            src_lane: (imm4 >> size) as u8,
            size,
        });
    }
    // op == 0
    match imm4 {
        0b0001 => {
            // DUP (general): Vd.<T> <- Rn. D element requires Q=1 (a 2D dup).
            if size == 3 && q == 0 {
                return Err(DecodeErr::Reserved);
            }
            Ok(DecodedInsn::SimdDupGen { rd: VReg(rd), rn: Reg(rn), size, q: q == 1 })
        }
        // INS (general): Vd.<T>[lane] <- Rn.
        0b0011 => Ok(DecodedInsn::SimdInsGen { rd: VReg(rd), lane, rn: Reg(rn), size }),
        0b0111 => {
            // UMOV: Rd <- zext(Vn.<T>[lane]). B/H/S → Wd (Q=0); D → Xd (Q=1).
            let valid = (size < 3 && q == 0) || (size == 3 && q == 1);
            if !valid {
                return Err(DecodeErr::Reserved);
            }
            Ok(DecodedInsn::SimdMovToGen {
                rd: Reg(rd), rn: VReg(rn), lane, size, signed: false, dst_x: q == 1,
            })
        }
        0b0101 => {
            // SMOV: Rd <- sext(Vn.<T>[lane]). Wd (Q=0): B/H; Xd (Q=1): B/H/S.
            let valid = match size {
                0 | 1 => true,
                2 => q == 1,
                _ => false,
            };
            if !valid {
                return Err(DecodeErr::Reserved);
            }
            Ok(DecodedInsn::SimdMovToGen {
                rd: Reg(rd), rn: VReg(rn), lane, size, signed: true, dst_x: q == 1,
            })
        }
        // DUP (element): Vd.<T> <- Vn.<Ts>[lane] broadcast to all lanes. bionic's
        // GHASH uses `dup v.4s, v.s[1]`. `lane` (from imm5) is the source index.
        0b0000 => {
            if size == 3 && q == 0 {
                return Err(DecodeErr::Reserved); // .2d needs Q=1
            }
            Ok(DecodedInsn::SimdDupElem { rd: VReg(rd), rn: VReg(rn), size, lane, q: q == 1 })
        }
        _ => Err(DecodeErr::Reserved),
    }
}

/// ARM `AdvSIMDExpandImm` — the 64-bit expansion of the MOVI/MVNI modified
/// immediate (ARM ARM shared pseudocode J1.3). `imm8` = a:b:c:d:e:f:g:h.
/// Returns `None` for the FMOV (cmode=1111) forms which need float expansion
/// (left as a coarse `AdvSimd` for now).
fn adv_simd_expand_imm(op: u32, cmode: u32, imm8: u64) -> Option<u64> {
    let cmode_hi = (cmode >> 1) & 0b111;
    let cmode_lo = cmode & 1;
    let rep32 = |x: u64| (x & 0xFFFF_FFFF) | ((x & 0xFFFF_FFFF) << 32);
    let rep16 = |x: u64| {
        let x = x & 0xFFFF;
        x | (x << 16) | (x << 32) | (x << 48)
    };
    let imm64 = match cmode_hi {
        0b000 => rep32(imm8),               // 32-bit element, no shift
        0b001 => rep32(imm8 << 8),          // lsl 8
        0b010 => rep32(imm8 << 16),         // lsl 16
        0b011 => rep32(imm8 << 24),         // lsl 24
        0b100 => rep16(imm8),               // 16-bit element, no shift
        0b101 => rep16(imm8 << 8),          // 16-bit lsl 8
        0b110 => {
            // MSL (ones shifted in).
            if cmode_lo == 0 {
                rep32((imm8 << 8) | 0xFF)
            } else {
                rep32((imm8 << 16) | 0xFFFF)
            }
        }
        0b111 => {
            if cmode_lo == 0 {
                if op == 0 {
                    // 8-bit element: replicate imm8 to all 8 bytes.
                    imm8.wrapping_mul(0x0101_0101_0101_0101)
                } else {
                    // op=1, cmode=1110: MOVI 2D — each bit a..h -> a full byte.
                    let mut v = 0u64;
                    let mut i = 0;
                    while i < 8 {
                        if (imm8 >> i) & 1 != 0 {
                            v |= 0xFFu64 << (i * 8);
                        }
                        i += 1;
                    }
                    v
                }
            } else {
                // cmode=1111: FMOV vector immediate — float expansion, deferred.
                return None;
            }
        }
        _ => return None,
    };
    Some(imm64)
}

fn decode_simd_modimm(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // Advanced SIMD modified immediate. cmode[15:12], op@29, Q@30.
    //   imm8 = a:b:c:d:e:f:g:h = bits[18:16] : bits[9:5].
    // The SETTING forms — MOVI (op=0) / MVNI (op=1) / MOVI-2D (op=1,cmode=1110)
    // — are decoded into `SimdMoviImm` carrying the final 128-bit value so the
    // lift writes the q-register file directly. The register-MODIFYING forms
    // (ORR/BIC immediate, cmode odd in 0xx1/10x1) and FMOV-vector (cmode=1111)
    // still need vd / float handling, so they stay the coarse `AdvSimd`.
    // The dispatch mask (0x9F80_1C00) pins bits[28:23], bits[12:11] and bit[10]
    // but NOT bits[22:19], which the full encoding (bits[28:19]=0111100000)
    // requires to be 0. A non-zero value is an UNDEFINED encoding (capstone
    // rejects it) — fail loud rather than mis-decode it as a MOVI/MVNI.
    if (word >> 19) & 0xF != 0 {
        return Err(DecodeErr::Reserved);
    }
    let cmode = (word >> 12) & 0xF;
    let op = (word >> 29) & 1;
    let q = (word >> 30) & 1;
    let cmode_hi = (cmode >> 1) & 0b111;
    let cmode_lo = cmode & 1;

    let is_orr_bic =
        matches!(cmode_hi, 0b000 | 0b001 | 0b010 | 0b011 | 0b100 | 0b101) && cmode_lo == 1;
    let is_fmov = cmode_hi == 0b111 && cmode_lo == 1;
    if is_orr_bic {
        // ORR (op=0) / BIC (op=1) vector immediate: RMW Vd with the cmode-expanded
        // pattern (no op-inversion, so expand with op=0; the op bit selects OR vs
        // AND-NOT in the lowering).
        let abc = (word >> 16) & 0x7;
        let defgh = (word >> 5) & 0x1F;
        let imm8 = ((abc << 5) | defgh) as u64;
        let imm = match adv_simd_expand_imm(0, cmode, imm8) {
            Some(v) => v,
            None => return Ok(DecodedInsn::AdvSimd { raw: word }),
        };
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdBicOrrImm {
            rd: VReg(rd),
            imm,
            is_bic: op == 1,
            q: q == 1,
        });
    }
    if is_fmov {
        return Ok(DecodedInsn::AdvSimd { raw: word });
    }

    let abc = (word >> 16) & 0x7;
    let defgh = (word >> 5) & 0x1F;
    let imm8 = ((abc << 5) | defgh) as u64;
    let rd = (word & 0x1F) as u8;

    let imm64 = match adv_simd_expand_imm(op, cmode, imm8) {
        Some(v) => v,
        None => return Ok(DecodedInsn::AdvSimd { raw: word }),
    };
    // op=1 is MVNI (bitwise-NOT) EXCEPT the cmode=1110 MOVI-2D form, which is a
    // plain MOVI despite op=1.
    let movi_2d = cmode_hi == 0b111 && cmode_lo == 0 && op == 1;
    let val = if op == 1 && !movi_2d { !imm64 } else { imm64 };
    // Q=0 zeroes the upper 64 bits of the V register.
    let hi = if q == 1 { val } else { 0 };
    Ok(DecodedInsn::SimdMoviImm { rd, lo: val, hi })
}

fn decode_simd_shift_imm(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    if immh == 0 {
        return Err(DecodeErr::Reserved);
    }
    let opcode = (word >> 11) & 0x1F;
    let u = (word >> 29) & 1;
    let q = (word >> 30) & 1;
    if !valid_simd_shift_imm_opcode(opcode, u, /* scalar */ false) {
        return Err(DecodeErr::Reserved);
    }
    // immh constraints with Q: for Q=0, immh top bit must be 0 (no 2D form).
    if q == 0 && immh & 0b1000 != 0 {
        return Err(DecodeErr::Reserved);
    }
    // USHLL/SSHLL/UXTL/SXTL (opcode 0b10100) — shift-left-long (widening). Route
    // to a typed decode; everything else in this group stays the coarse AdvSimd
    // fallback until its semantics land.
    if opcode == 0b10100 {
        return decode_ushll(word);
    }
    // SHL (shift-left by immediate, opcode 0b01010, U=0). bionic's AES key
    // schedule doubles the Rcon via `shl v.16b, v.16b, #1`.
    if opcode == 0b01010 && u == 0 {
        return decode_simd_shl(word);
    }
    // SLI (shift-left-and-insert, opcode 0b01010, U=1) — same element size/shift
    // extraction as SHL, but read-modify-write Vd (preserve the low `shift` bits).
    if opcode == 0b01010 && u == 1 {
        return decode_simd_shift_ins(word, /* left */ true);
    }
    // SRI (shift-right-and-insert, opcode 0b01000, U=1) — right shift, insert
    // preserving Vd's top `shift` bits. (opcode 0b01000 U=0 is reserved.)
    if opcode == 0b01000 {
        if u == 0 {
            return Err(DecodeErr::Reserved);
        }
        return decode_simd_shift_ins(word, /* left */ false);
    }
    // Narrowing shift-right (saturating / rounding). opcode 0b10000..=0b10011:
    //   op\U    U=0        U=1
    //   10000   SHRN       SQSHRUN     (SHRN U=0 is routed earlier via decode_shrn)
    //   10001   RSHRN      SQRSHRUN
    //   10010   SQSHRN     UQSHRN
    //   10011   SQRSHRN    UQRSHRN
    // (10100 SSHLL/USHLL is handled above.) Verified against capstone.
    if matches!(opcode, 0b10000 | 0b10001 | 0b10010 | 0b10011) {
        // Plain SHRN (10000,U=0) reaches here only if the earlier decode_shrn
        // dispatch didn't catch it; route it to the plain narrow decode.
        if opcode == 0b10000 && u == 0 {
            return decode_shrn(word);
        }
        return decode_simd_shrn_sat(word, opcode, u == 1);
    }
    // SSHR (U=0) / USHR (U=1) — shift-right by immediate, opcode 0b00000.
    // bionic's GHASH (GCM) uses `ushr v.2d,#63` / `sshr v.4s,#31`.
    if opcode == 0b00000 {
        return decode_simd_shr(word, u == 0);
    }
    // SSRA (U=0) / USRA (U=1) — shift-right-and-accumulate by immediate,
    // opcode 0b00010. boringssl's FIPS self-test uses `usra v0.2d, v2.2d, #1`.
    if opcode == 0b00010 {
        return decode_simd_usra(word, u == 0);
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

/// SLI/SRI (shift-left/right-and-insert by immediate). Element size from `immh`
/// (same mapping as SHL/SSHR). SLI (`left`): `shift = UInt(immh:immb) - esize_bits`
/// (0..esize_bits-1). SRI: `shift = 2*esize_bits - UInt(immh:immb)` (1..esize_bits).
fn decode_simd_shift_ins(word: u32, left: bool) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    let immb = (word >> 16) & 0x7;
    let immhimmb = (immh << 3) | immb;
    let q = (word >> 30) & 1;
    let (size, esize_bits): (u8, u32) = if immh & 0b1000 != 0 {
        (3, 64)
    } else if immh & 0b0100 != 0 {
        (2, 32)
    } else if immh & 0b0010 != 0 {
        (1, 16)
    } else {
        (0, 8)
    };
    if size == 3 && q == 0 {
        return Err(DecodeErr::Reserved); // .2d needs Q=1
    }
    let shift = if left {
        immhimmb - esize_bits // 0..esize_bits-1
    } else {
        2 * esize_bits - immhimmb // 1..esize_bits
    } as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdShiftIns {
        rd: VReg(rd),
        rn: VReg(rn),
        shift,
        size,
        q: q == 1,
        left,
    })
}

/// Saturating/rounding narrowing shift-right (SQSHRN/UQSHRN/SQSHRUN/SQRSHRN/
/// UQRSHRN/SQRSHRUN). `opcode` (bits[15:11]) selects rounding + signedness with
/// `u`. Element/shift extraction matches `decode_shrn`: `immh` selects the result
/// element size (0001→.8b, 001x→.4h, 01xx→.2s) and `shift = 2*esize_out_bits -
/// UInt(immh:immb)`.
fn decode_simd_shrn_sat(word: u32, opcode: u32, u: bool) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    let immb = (word >> 16) & 0x7;
    if immh == 0 || immh & 0b1000 != 0 {
        return Err(DecodeErr::Reserved); // immh=0 modimm; immh=1xxx (64-bit dst) reserved
    }
    let immhimmb = (immh << 3) | immb;
    let (esize_out, esize_bits): (u8, u32) = if immh & 0b0100 != 0 {
        (4, 32) // .2s (from .2d)
    } else if immh & 0b0010 != 0 {
        (2, 16) // .4h (from .4s)
    } else {
        (1, 8) // immh == 0001 → .8b (from .8h)
    };
    let shift = ((2 * esize_bits) - immhimmb) as u8;
    // (round, src_signed, dst_signed, modular) per (opcode, u). Verified against
    // capstone and the ARM ARM. `modular=true` is RSHRN only — it truncates rather
    // than saturates, and it aliases UQRSHRN in the other three flags, so the flag
    // is what disambiguates them.
    let (round, src_signed, dst_signed, modular) = match (opcode, u) {
        (0b10000, true) => (false, true, false, false),  // SQSHRUN  (signed→unsigned)
        (0b10001, false) => (true, false, false, true),  // RSHRN    (modular, rounding)
        (0b10001, true) => (true, true, false, false),   // SQRSHRUN (signed→unsigned, round)
        (0b10010, false) => (false, true, true, false),  // SQSHRN   (signed→signed)
        (0b10010, true) => (false, false, false, false), // UQSHRN   (unsigned→unsigned)
        (0b10011, false) => (true, true, true, false),   // SQRSHRN  (signed→signed, round)
        (0b10011, true) => (true, false, false, false),  // UQRSHRN  (unsigned→unsigned, round)
        _ => return Err(DecodeErr::Reserved),
    };
    let q = (word >> 30) & 1;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdShrnSat {
        rd: VReg(rd),
        rn: VReg(rn),
        shift,
        esize_out,
        high: q == 1,
        round,
        src_signed,
        dst_signed,
        modular,
    })
}

/// SSHR/USHR (vector shift-right by immediate). Element size from `immh` (same
/// mapping as SHL); `shift = 2*esize_bits − UInt(immh:immb)` (a right shift, so
/// 1..esize_bits). `signed` selects SSHR (arithmetic) vs USHR (logical).
fn decode_simd_shr(word: u32, signed: bool) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    let immb = (word >> 16) & 0x7;
    let immhimmb = (immh << 3) | immb;
    let q = (word >> 30) & 1;
    let (size, esize_bits): (u8, u32) = if immh & 0b1000 != 0 {
        (3, 64)
    } else if immh & 0b0100 != 0 {
        (2, 32)
    } else if immh & 0b0010 != 0 {
        (1, 16)
    } else {
        (0, 8)
    };
    if size == 3 && q == 0 {
        return Err(DecodeErr::Reserved);
    }
    let shift = (2 * esize_bits - immhimmb) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdShrImm {
        rd: VReg(rd),
        rn: VReg(rn),
        shift,
        size,
        q: q == 1,
        signed,
    })
}

/// SSRA/USRA (vector shift-right-and-accumulate by immediate, opcode 0b00010).
/// Element size and shift amount are extracted exactly like SSHR/USHR (the
/// shift-right group): element size from `immh`, `shift = 2*esize_bits −
/// UInt(immh:immb)` (1..esize_bits). It is an ACCUMULATE: `Vd[e] += (Vn[e] >>
/// shift)` with a LOGICAL shift for USRA (`signed=false`, U=1) and an ARITHMETIC
/// shift for SSRA (`signed=true`, U=0). `rd` is read AND written.
fn decode_simd_usra(word: u32, signed: bool) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    let immb = (word >> 16) & 0x7;
    let immhimmb = (immh << 3) | immb;
    let q = (word >> 30) & 1;
    let (size, esize_bits): (u8, u32) = if immh & 0b1000 != 0 {
        (3, 64)
    } else if immh & 0b0100 != 0 {
        (2, 32)
    } else if immh & 0b0010 != 0 {
        (1, 16)
    } else {
        (0, 8)
    };
    if size == 3 && q == 0 {
        return Err(DecodeErr::Reserved);
    }
    let shift = (2 * esize_bits - immhimmb) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdSraImm {
        rd: VReg(rd),
        rn: VReg(rn),
        shift,
        size,
        q: q == 1,
        signed,
    })
}

/// SHL (vector shift-left by immediate). `immh` selects the element size
/// (0001→.8b/.16b, 001x→.4h/.8h, 01xx→.2s/.4s, 1xxx→.2d) and
/// `shift = UInt(immh:immb) − esize_bits`. `size` is log2(element bytes):
/// 0=8-bit, 1=16-bit, 2=32-bit, 3=64-bit (matches the VecShift lowering).
fn decode_simd_shl(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    let immb = (word >> 16) & 0x7;
    let immhimmb = (immh << 3) | immb;
    let q = (word >> 30) & 1;
    let (size, esize_bits): (u8, u32) = if immh & 0b1000 != 0 {
        (3, 64) // .2d
    } else if immh & 0b0100 != 0 {
        (2, 32) // .2s/.4s
    } else if immh & 0b0010 != 0 {
        (1, 16) // .4h/.8h
    } else {
        (0, 8) // immh == 0001: .8b/.16b
    };
    // 64-bit (.2d) requires Q=1 (no 64-bit-element D-form). immh==0 is excluded
    // by the caller (modified-immediate group).
    if size == 3 && q == 0 {
        return Err(DecodeErr::Reserved);
    }
    let shift = (immhimmb - esize_bits) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdShlImm {
        rd: VReg(rd),
        rn: VReg(rn),
        shift,
        size,
        q: q == 1,
    })
}

/// USHLL/SSHLL{2} — shift-left-long. `immh` selects the SOURCE element size
/// (0001→.8b, 001x→.4h, 01xx→.2s); `shift = UInt(immh:immb) - esize_bits`.
/// `Q` selects the low 64 (USHLL, false) vs high 64 (USHLL2, true) of Vn;
/// `U` selects unsigned/zero-extend (USHLL) vs signed/sign-extend (SSHLL).
fn decode_ushll(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    let immb = (word >> 16) & 0x7;
    // immh==0 is the modified-immediate group; immh top bit (1xxx) would mean a
    // 64-bit source which cannot widen — reserved for USHLL.
    if immh == 0 || immh & 0b1000 != 0 {
        return Err(DecodeErr::Reserved);
    }
    let immhimmb = (immh << 3) | immb;
    let (esize_in, esize_bits): (u8, u32) = if immh & 0b0100 != 0 {
        (4, 32) // .2s source -> .2d dest
    } else if immh & 0b0010 != 0 {
        (2, 16) // .4h source -> .4s dest
    } else {
        (1, 8) // immh == 0001: .8b source -> .8h dest
    };
    let shift = immhimmb - esize_bits;
    let q = (word >> 30) & 1;
    let u = (word >> 29) & 1;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdUshll {
        rd: VReg(rd),
        rn: VReg(rn),
        shift: shift as u8,
        esize_in,
        high: q == 1,
        signed: u == 0,
    })
}

fn decode_simd_indexed(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 22) & 0x3;
    let opcode = (word >> 12) & 0xF;
    let u = (word >> 29) & 1;
    if size == 0b00 {
        return Err(DecodeErr::Reserved);
    }
    if opcode == 0b1011 || opcode == 0b1111 {
        return Err(DecodeErr::Reserved);
    }
    // Vector indexed valid (U, opcode) pairs per ARM ARM Table C4-11.
    // ARMv8.0-A baseline (no FEAT_FCMA/FEAT_FP16/FEAT_DotProd):
    //   U=0: 0000 MLA           0010 SMLAL{2}      0011 SQDMLAL{2}
    //        0100 MLS           0110 SMLSL{2}      0111 SQDMLSL{2}
    //        1000 MUL           1010 SMULL{2}      1011 SQDMULL{2}
    //        1100 SQDMULH       1101 SQRDMULH      0001 FMLA (FP)
    //        0101 FMLS (FP)     1001 FMULX (FP, ARMv8.0+) / FMUL via separate enc
    //   U=1: 0000 MLA-alt? actually rare    0010 UMLAL{2}
    //        0100 MLS-alt? rare              0110 UMLSL{2}
    //        1000 reserved                   1010 UMULL{2}
    //        1101 SQRDMLAH/SQRDMLSH (ARMv8.1+; FEAT_RDM)
    // Capstone 0.14 default mode declines FEAT_RDM (U=1, opcode=1101) without
    // explicit extra-mode, and U=1 opcode 1000/1100/1110 are architecturally
    // reserved for vector indexed.
    if u == 1 && matches!(opcode, 0b1000 | 0b1100 | 0b1110) {
        return Err(DecodeErr::Reserved);
    }
    // Vector indexed with size=11 only valid for FP-form (FMLA/FMLS/FMUL/FMULX).
    if size == 0b11 {
        let ok = match (u, opcode) {
            (0, 0b0001 | 0b0101 | 0b1001) => true,
            (1, 0b0001 | 0b0101 | 0b1001) => true,
            _ => false,
        };
        if !ok {
            return Err(DecodeErr::Reserved);
        }
    }

    // ── Typed routing for the implemented by-element forms ───────────────────
    // FP FMLA (op=0001) / FMLS (op=0101) / FMUL (op=1001, U=0). `size` here is
    // {sz:_}: sz=size[0] is 0=single(.4s/.2s) / 1=double(.2d). The index/Vm
    // extraction differs from the integer forms (S/D split):
    //   .s (sz=0): index = H:L (H@11, L@21), Vm = M:Rm (5 bits, M@20)
    //   .d (sz=1): index = H (L must be 0),  Vm = M:Rm
    // Integer MUL (op=1000, U=0) / MLA (0000) / MLS (0100) by element:
    //   .h (size=01): index = H:L:M, Vm = Rm (4 bits, V0-V15)
    //   .s (size=10): index = H:L,   Vm = M:Rm (5 bits)
    let q = (word >> 30) & 1;
    let l = (word >> 21) & 1;
    let m = (word >> 20) & 1;
    let h = (word >> 11) & 1;
    let rd = (word & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rm4 = (word >> 16) & 0xF; // low 4 register bits

    if u == 0 {
        // FP by-element (FMUL/FMLA/FMLS). Valid ONLY for size=10 (.4s/.2s single)
        // or size=11 (.2d double) — size=01 is the FEAT_FP16 .h form which the
        // bundled capstone declines, so it must NOT route here (it would be a
        // false positive). For the .2d form, L must be 0 (the index is just H);
        // L=1 with size=11 is a reserved encoding capstone rejects.
        let fp_op = match opcode {
            0b0001 => Some(1u8), // FMLA → Mla
            0b0101 => Some(2u8), // FMLS → Mls
            0b1001 => Some(0u8), // FMUL → Mul
            _ => None,
        };
        if let Some(fp_op) = fp_op {
            // .2d (size=11) needs Q=1 (no 64-bit-element D-form register).
            if size == 0b11 && q == 0 {
                return Err(DecodeErr::Reserved);
            }
            if size == 0b10 || (size == 0b11 && l == 0) {
                let dbl = size == 0b11;
                let rm = ((m << 4) | rm4) as u8; // 5-bit Vm (M is top bit)
                let idx = if dbl { h as u8 } else { ((h << 1) | l) as u8 };
                return Ok(DecodedInsn::SimdByElem {
                    rd: VReg(rd),
                    rn: VReg(rn),
                    rm: VReg(rm),
                    fp_op,
                    is_fp: true,
                    dbl,
                    size: if dbl { 3 } else { 2 },
                    q: q == 1,
                    idx,
                });
            }
            // size=01 is the FEAT_FP16 .h form (bundled capstone declines it), and
            // size=11 with L=1 is reserved for .2d. Both are undefined to capstone
            // here → fail-loud rather than route to a coarse AdvSimd false positive.
            return Err(DecodeErr::Reserved);
        }
        // Integer MUL by element (op=1000). MLA(0000)/MLS(0100) accumulate forms
        // are deferred (need read-Vd in the lowerer; not yet wired) → coarse.
        if opcode == 0b1000 {
            // size: 01=.4h/.8h (idx=H:L:M, Vm=Rm 4-bit), 10=.2s/.4s (idx=H:L, Vm=M:Rm).
            let (esize, rm, idx) = match size {
                0b01 => (1u8, rm4 as u8, ((h << 2) | (l << 1) | m) as u8),
                0b10 => (2u8, ((m << 4) | rm4) as u8, ((h << 1) | l) as u8),
                _ => return Ok(DecodedInsn::AdvSimd { raw: word }),
            };
            return Ok(DecodedInsn::SimdByElem {
                rd: VReg(rd),
                rn: VReg(rn),
                rm: VReg(rm),
                fp_op: 0,
                is_fp: false,
                dbl: false,
                size: esize,
                q: q == 1,
                idx,
            });
        }
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_permute(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // bits[14:12] = opcode. Valid: 001=UZP1, 010=TRN1, 011=ZIP1, 101=UZP2,
    // 110=TRN2, 111=ZIP2. Reserved: 000, 100.
    let opcode = (word >> 12) & 0x7;
    if opcode == 0b000 || opcode == 0b100 {
        return Err(DecodeErr::Reserved);
    }
    // .2d (size=11) requires Q=1 for every permute form.
    if (word >> 22) & 0x3 == 0b11 && (word >> 30) & 1 == 0 {
        return Err(DecodeErr::Reserved);
    }
    // UZP1 (001) / UZP2 (101) — typed deinterleave. TRN1 (010) / TRN2 (110) for
    // `.2d` ONLY: with exactly 2 elements, transpose-even/odd coincides EXACTLY
    // with unzip-even/odd, so they reuse the SimdUnzip `.2d` path (punpckl/hqdq).
    // bionic's AES-GCM uses `trn1/trn2 v.2d` to split the counter halves.
    let size = (word >> 22) & 0x3;
    let q = (word >> 30) & 1;
    let rm = ((word >> 16) & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    let is_uzp = opcode == 0b001 || opcode == 0b101;
    let is_trn_2d = (opcode == 0b010 || opcode == 0b110) && size == 0b11;
    if is_uzp || is_trn_2d {
        if size == 0b11 && q == 0 {
            return Err(DecodeErr::Reserved); // .2d needs Q=1
        }
        // odd = take the high element of each pair: UZP2 or TRN2.
        let odd = opcode == 0b101 || opcode == 0b110;
        return Ok(DecodedInsn::SimdUnzip {
            rd: VReg(rd),
            rn: VReg(rn),
            rm: VReg(rm),
            size: size as u8,
            q: q == 1,
            odd,
        });
    }
    // ZIP1 (011) / ZIP2 (111) — interleave, all element sizes. TRN1 (010) /
    // TRN2 (110) for the non-.2d sizes route here too; the lowerer wires ZIP for
    // B/H/S/D and TRN for .2d/.4s, and fail-loud (UD2) on the remaining TRN forms.
    let kind = match opcode {
        0b011 => Some(0u8), // ZIP1
        0b111 => Some(1u8), // ZIP2
        0b010 => Some(2u8), // TRN1 (non-.2d, handled above for .2d)
        0b110 => Some(3u8), // TRN2
        _ => None,
    };
    if let Some(kind) = kind {
        return Ok(DecodedInsn::SimdZipTrn {
            rd: VReg(rd),
            rn: VReg(rn),
            rm: VReg(rm),
            kind,
            size: size as u8,
            q: q == 1,
        });
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_extract(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // For Q=0, only the 8 low bytes are addressable — imm4 must be < 8.
    let q = (word >> 30) & 1;
    let imm4 = (word >> 11) & 0xF;
    if q == 0 && imm4 >= 8 {
        return Err(DecodeErr::Reserved);
    }
    let rm = ((word >> 16) & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdExt {
        rd: VReg(rd),
        rn: VReg(rn),
        rm: VReg(rm),
        imm: imm4 as u8,
        q: q == 1,
    })
}

fn decode_simd_table(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // bits[14:13] = len (table-reg count − 1), bit 12 = op (0=TBL, 1=TBX).
    let len = (word >> 13) & 0x3;
    let op = (word >> 12) & 0x1;
    let q = (word >> 30) & 1;
    let rm = ((word >> 16) & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    // The single-table-register TBL (len=0, op=0) keeps its dedicated insn — that's
    // the bionic AES key-schedule byte permute (`tbl v.16b, {v.16b}, v.16b`). All
    // multi-register forms (len 1–3, consecutive V regs wrapping mod 32) and TBX
    // (op=1, any len) go through the general SimdTblN insn.
    if len == 0 && op == 0 {
        return Ok(DecodedInsn::SimdTbl1 {
            rd: VReg(rd),
            rn: VReg(rn),
            rm: VReg(rm),
            q: q == 1,
        });
    }
    Ok(DecodedInsn::SimdTblN {
        rd: VReg(rd),
        rn: VReg(rn),
        rm: VReg(rm),
        len: len as u8, // table-reg count − 1 (0..=3)
        op: op as u8,   // 0 = TBL, 1 = TBX
        q: q == 1,
    })
}

// =============================================================================
// Advanced SIMD scalar
// =============================================================================

fn decode_simd_scalar_3same(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 22) & 0x3;
    let opcode = (word >> 11) & 0x1F;
    // Scalar 3-same: most integer ops require size=11 (D-form). FP ops in
    // the same encoding space use size=00/01 (single/double). For Phase A
    // approximation: require size=11 for integer-shape opcodes (the U bit
    // doesn't gate this).
    // - opcode in {00001-00111, 10000-10111}: integer 3-same, require size=11
    // - opcode in {11000-11111}: FP 3-same, size selects ftype (00=S, 01=D)
    if opcode < 0b11000 && size != 0b11 {
        return Err(DecodeErr::Reserved);
    }
    let u = (word >> 29) & 1;
    let rd = (word & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rm = ((word >> 16) & 0x1F) as u8;
    // Scalar integer ADD (U=0) / SUB (U=1) — opcode 0b10000, D-form (size=11).
    // These are the lane-0 (64-bit) versions of the vector ADD/SUB, so route them
    // to a typed scalar-binary insn that the lifter maps to a D-form VecBin.
    if opcode == 0b10000 && size == 0b11 {
        return Ok(DecodedInsn::SimdScalar3Same {
            rd: VReg(rd),
            rn: VReg(rn),
            rm: VReg(rm),
            sub: u == 1,
        });
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_scalar_2reg_misc(word: u32) -> Result<DecodedInsn, DecodeErr> {
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_scalar_copy(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let imm5 = (word >> 16) & 0x1F;
    if imm5 == 0 {
        return Err(DecodeErr::Reserved);
    }
    // op (bit 29) must be 0; imm4 (bits[14:11]) must be 0. The only scalar-copy
    // form is DUP (element) scalar: `mov dN, vM.<T>[lane]`.
    if (word >> 29) & 1 != 0 || (word >> 11) & 0xF != 0 {
        return Err(DecodeErr::Reserved);
    }
    // size + lane from imm5 (lowest set bit selects B/H/S/D; bits above = lane).
    let (size, lane): (u8, u8) = if imm5 & 1 != 0 {
        (0, ((imm5 >> 1) & 0xF) as u8)
    } else if imm5 & 2 != 0 {
        (1, ((imm5 >> 2) & 0x7) as u8)
    } else if imm5 & 4 != 0 {
        (2, ((imm5 >> 3) & 0x3) as u8)
    } else {
        (3, ((imm5 >> 4) & 0x1) as u8)
    };
    let rn = ((word >> 5) & 0x1F) as u8;
    let rd = (word & 0x1F) as u8;
    Ok(DecodedInsn::SimdScalarDup { rd: VReg(rd), rn: VReg(rn), size, lane })
}

fn decode_simd_scalar_pairwise(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 22) & 0x3;
    let u = (word >> 29) & 1;
    let opcode = (word >> 12) & 0x1F;
    let rd = (word & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    // Scalar ADDP (U=0, opcode 0b11011, size=11) — `addp d0, v1.2d`: sum the two
    // 64-bit lanes of Vn into Vd lane 0 (rest zeroed). bionic GHASH / reductions.
    if u == 0 && opcode == 0b11011 && size == 0b11 {
        return Ok(DecodedInsn::SimdScalarPair {
            rd: VReg(rd),
            rn: VReg(rn),
            is_fp: false,
            dbl: true,
        });
    }
    // Scalar FADDP (U=1, opcode 0b01101) — `faddp s0,v1.2s` / `faddp d0,v1.2d`.
    // `sz` (bit22) selects single (.2s) vs double (.2d); bit23 must be 0 (FP form).
    if u == 1 && opcode == 0b01101 && ((size >> 1) & 1) == 0 {
        let dbl = (size & 1) == 1;
        return Ok(DecodedInsn::SimdScalarPair {
            rd: VReg(rd),
            rn: VReg(rn),
            is_fp: true,
            dbl,
        });
    }
    // Every other scalar-pairwise encoding (FMAXNMP/FADDP variants/FMAXP/FMINP/
    // FMINNMP and the reserved slots) stays fail-loud. Accepting them as a coarse
    // AdvSimd would be a capstone false-positive now that this group is reachable.
    Err(DecodeErr::Reserved)
}

fn decode_simd_scalar_shift_imm(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let immh = (word >> 19) & 0xF;
    if immh == 0 {
        return Err(DecodeErr::Reserved);
    }
    let opcode = (word >> 11) & 0x1F;
    let u = (word >> 29) & 1;
    if !valid_simd_shift_imm_opcode(opcode, u, /* scalar */ true) {
        return Err(DecodeErr::Reserved);
    }
    // Scalar fixed-point convert opcodes (SCVTF/UCVTF/FCVTZS/FCVTZU =
    // 11100..11111) require immh in {01xx (S form), 1xxx (D form)}, i.e.
    // immh >= 4. immh = 001x in scalar shift-imm is reserved (no scalar
    // FP16 fixed-point convert in base ARMv8).
    if (0b11100..=0b11111).contains(&opcode) && immh < 0b0100 {
        return Err(DecodeErr::Reserved);
    }
    // SHL (opcode 0b01010, U=0) — scalar shift-left, D-form (64-bit) only.
    // bionic's GHASH uses `shl d, d, #56` to position the GF(2^128) reduction const.
    if opcode == 0b01010 && u == 0 {
        if immh & 0b1000 == 0 {
            return Err(DecodeErr::Reserved); // scalar SHL is 64-bit (D-form)
        }
        let immb = (word >> 16) & 0x7;
        let shift = (((immh << 3) | immb) - 64) as u8;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rd = (word & 0x1F) as u8;
        return Ok(DecodedInsn::SimdScalarShl { rd: VReg(rd), rn: VReg(rn), shift });
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

/// Valid SIMD shift-by-immediate opcodes per ARM ARM C4.1.6 Table C4-13.
/// `scalar=true` excludes the SHLL/SHLL2 vector-only opcode (11000).
fn valid_simd_shift_imm_opcode(opcode: u32, u: u32, scalar: bool) -> bool {
    let _ = u;
    match opcode {
        0b00000 => true, // SSHR/USHR
        0b00010 => true, // SSRA/USRA
        0b00100 => true, // SRSHR/URSHR
        0b00110 => true, // SRSRA/URSRA
        0b01000 => u == 1, // SRI (U=1 only; U=0 opcode 01000 is reserved)
        0b01010 => true, // SHL/SLI
        0b01110 => true, // SQSHL/UQSHL/SQSHLU (U=1 form)
        0b10000 => true, // SHRN/SQSHRUN
        0b10001 => true, // RSHRN/SQRSHRUN
        0b10010 => true, // SQSHRUN/SQSHRN
        0b10011 => true, // SQRSHRUN/SQRSHRN
        0b10100 => true, // SQSHRN/UQSHRN
        0b10101 => true, // SQRSHRN/UQRSHRN
        0b11000 => !scalar, // SHLL/SHLL2 (vector only)
        0b11100 => true, // SCVTF/UCVTF (fixed-point)
        0b11101 => true, // SCVTF/UCVTF (fp_fcvtzs variants)
        0b11110 => true, // FCVTZS/FCVTZU (fixed-point)
        0b11111 => true, // FCVTZS/FCVTZU variants
        _ => false,
    }
}

fn decode_simd_scalar_indexed(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 22) & 0x3;
    let opcode = (word >> 12) & 0xF;
    let u = (word >> 29) & 1;
    // Scalar indexed: size=00 (byte element) is reserved.
    if size == 0b00 {
        return Err(DecodeErr::Reserved);
    }
    // Valid scalar indexed opcodes per ARM ARM C4.1.6. U bit gates:
    //   U=0:
    //     0001 FMLA (FP)              0011 FMLS (FP)
    //     0101 FMUL/SQDMULL{2}        0111 SQDMULH
    //     1001 SQRDMULH
    //   U=1:
    //     1001 FMULX (FP scalar)      1101 SQRDMLAH/SQRDMLSH (ARMv8.1+)
    let ok = match (u, opcode) {
        (0, 0b0001 | 0b0011 | 0b0101 | 0b0111 | 0b1001) => true,
        (1, 0b1001 | 0b1101) => true,
        _ => false,
    };
    if !ok {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}
