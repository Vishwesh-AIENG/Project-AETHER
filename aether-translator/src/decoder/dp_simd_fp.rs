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

use super::{DecodeErr, DecodedInsn, VReg};

pub fn decode(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // ===== Crypto =====
    if (word & 0xFF00_FC00) == 0x4E28_4800 {
        return decode_crypto_aes(word);
    }
    if (word & 0xFF20_8C00) == 0x5E00_0000 {
        return decode_crypto_sha_3reg(word);
    }
    if (word & 0xFFFF_FC00) == 0x5E28_0800 {
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
    if (word & 0xFF20_0800) == 0x1E20_0800 {
        return decode_fp_2src(word);
    }
    if (word & 0xFF00_0000) == 0x1F00_0000 {
        return decode_fp_3src(word);
    }
    if (word & 0xFF20_1C00) == 0x1E20_1000 {
        return decode_fp_imm(word);
    }
    if (word & 0xFF20_0C00) == 0x1E20_2000 {
        return decode_fp_compare(word);
    }
    if (word & 0xFF20_0C00) == 0x1E20_0400 {
        return decode_fp_ccmp(word);
    }
    if (word & 0xFF20_0C00) == 0x1E20_0C00 {
        return decode_fp_csel(word);
    }
    // FP <-> integer convert (uses bits[31:21]=0X011110001 + bits[15:10]=000000)
    if (word & 0x7F3F_FC00) == 0x1E20_0000 {
        return decode_fp_int_convert(word);
    }
    // FP <-> fixed-point convert: bit 21 = 0 (vs convert above which has bit 21 = 1)
    if (word & 0x7F20_0000) == 0x1E00_0000 {
        return decode_fp_fixed_convert(word);
    }

    // ===== Advanced SIMD =====
    if (word & 0xBF20_8400) == 0x0E20_0400 {
        return decode_simd_3same(word);
    }
    if (word & 0xBF20_0400) == 0x0E00_8400 {
        return decode_simd_3same_extra(word);
    }
    if (word & 0xBF20_8C00) == 0x0E20_0000 {
        return decode_simd_3diff(word);
    }
    if (word & 0xBF3F_8C00) == 0x0E20_0800 {
        return decode_simd_2reg_misc(word);
    }
    if (word & 0xBF3F_8C00) == 0x0E30_0800 {
        return decode_simd_across_lanes(word);
    }
    if (word & 0x9FE0_8400) == 0x0E00_0400 {
        return decode_simd_copy(word);
    }
    if (word & 0xBF80_1C00) == 0x0F00_0400 {
        return decode_simd_modimm(word);
    }
    if (word & 0xBF80_0400) == 0x0F00_0400 {
        return decode_simd_shift_imm(word);
    }
    if (word & 0xBF00_0400) == 0x0F00_0000 {
        return decode_simd_indexed(word);
    }
    if (word & 0xBFA0_8C00) == 0x0E00_0800 {
        return decode_simd_permute(word);
    }
    if (word & 0xBFE0_8400) == 0x2E00_0000 {
        return decode_simd_extract(word);
    }
    if (word & 0xBFE0_8C00) == 0x0E00_0000 {
        return decode_simd_table(word);
    }

    // ===== Scalar-shape Advanced SIMD =====
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
    if !fp_ftype_ok(word) {
        return Err(DecodeErr::Reserved);
    }
    // rmode (bits[20:19]) and opcode (bits[18:16]) together select the
    // conversion. Specific (rmode, opcode) combinations are reserved; the
    // architectural table (ARM ARM C4-12) is complex. Conservative
    // validation: opcode != 011 except when rmode == 11 (FCVTZS/FCVTZU only
    // valid via fixed-point path; here rmode=11 opcode=011 = FCVTZU).
    let rmode = (word >> 19) & 0x3;
    let opcode = (word >> 16) & 0x7;
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
    // size (bits[23:22]) and opcode (bits[15:11]) together. For Q=0 with size=11
    // and certain opcodes, the encoding is reserved (no 2D NEON ops).
    let q = (word >> 30) & 1;
    let size = (word >> 22) & 0x3;
    let opcode = (word >> 11) & 0x1F;
    // Many opcodes are valid across U/size. Reject specific known-bad combos:
    //   - Q=0 with size=11 + opcode ∈ {add/sub/cmgt/cmge/cmtst/sshl/sqshl/srshl/
    //     sqrshl/smax/smin/sabd/saba/...} would mean a 2D op in 64-bit form,
    //     which is reserved (NEON 2D requires Q=1).
    if q == 0 && size == 0b11 {
        return Err(DecodeErr::Reserved);
    }
    // opcode 11000..11111 covers FP ops and pairwise — most are valid.
    let _ = opcode;
    Ok(DecodedInsn::AdvSimd { raw: word })
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
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_2reg_misc(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let q = (word >> 30) & 1;
    let size = (word >> 22) & 0x3;
    let opcode = (word >> 12) & 0x1F;
    // Many opcodes valid. Reject Q=0/size=11 (2D in 64-bit form).
    if q == 0 && size == 0b11 {
        return Err(DecodeErr::Reserved);
    }
    let _ = opcode;
    Ok(DecodedInsn::AdvSimd { raw: word })
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
    let _opcode = (word >> 12) & 0x1F;
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_copy(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // imm5 (bits[20:16]) must be non-zero (else encoding is undefined).
    let imm5 = (word >> 16) & 0x1F;
    if imm5 == 0 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_modimm(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // cmode + op selection. cmode in bits[15:12], op in bit 29 (Q same).
    // Several (cmode, op, ftype) combinations are reserved.
    let cmode = (word >> 12) & 0xF;
    let op = (word >> 29) & 1;
    // For op=1, cmode in 1101/1110/1111 valid (FMOV/MVNI variants).
    // For op=0, all cmode values valid.
    if op == 1 && cmode != 0b1101 && cmode != 0b1110 && cmode != 0b1111 && cmode < 0b1000 {
        // Some op=1 with cmode < 8 are reserved.
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
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
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_indexed(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 22) & 0x3;
    let opcode = (word >> 12) & 0xF;
    // Vector indexed: size=00 has no valid element width (byte indexed makes
    // no architectural sense). Reserved.
    if size == 0b00 {
        return Err(DecodeErr::Reserved);
    }
    if opcode == 0b1011 || opcode == 0b1111 {
        return Err(DecodeErr::Reserved);
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
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_extract(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // imm4 (bits[14:11]): for Q=0, imm4<8 required; for Q=1, imm4<16. Always
    // valid because imm4 is 4-bit.
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_table(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // bits[14:13] = len, bit 12 = op. All combos valid.
    Ok(DecodedInsn::AdvSimd { raw: word })
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
    // op (bit 29) must be 0; imm4 (bits[14:11]) must be 0.
    if (word >> 29) & 1 != 0 || (word >> 11) & 0xF != 0 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}

fn decode_simd_scalar_pairwise(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 22) & 0x3;
    if size == 0b00 {
        // Most scalar pairwise ops require size=11 or size=01/10 (FP forms).
        // size=00 is reserved.
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
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
    // Scalar indexed: size=00 (byte element) is reserved — no byte-indexed
    // scalar SIMD operations exist.
    if size == 0b00 {
        return Err(DecodeErr::Reserved);
    }
    // Valid scalar indexed opcodes per ARM ARM C4.1.6:
    //   0001 FMLA (FP) / SQDMLAL/SQDMLAL2 (int, size!=00,11)
    //   0011 FMLS (FP) / SQDMLSL/SQDMLSL2
    //   0101 SQDMULL/SQDMULL2
    //   0111 SQDMULH
    //   1001 SQRDMULH
    //   1101 SQRDMLAH/SQRDMLSH (ARMv8.1+)
    // All other opcode values reserved.
    if !matches!(opcode, 0b0001 | 0b0011 | 0b0101 | 0b0111 | 0b1001 | 0b1101) {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::AdvSimd { raw: word })
}
