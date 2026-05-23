//! Loads and stores (ARM ARM §C4.1.4).
//!
//! Phase A coverage:
//!   - Load/store register, unsigned-offset
//!   - Load/store register, immediate (post-index / pre-index / unscaled)
//!   - Load/store register, register offset (extended/shifted)
//!   - Load register, literal (PC-relative)
//!   - Load/store pair (post-index / signed-offset / pre-index / no-allocate)
//!   - Load/store exclusive: LDXR/STXR/LDAXR/STLXR (+ pair variants)
//!   - Acquire/release: LDAR / STLR / LDAPR
//!   - LSE atomics (v8.1): CAS{,A,L,AL}, LD{ADD,CLR,EOR,SET,SMAX,SMIN,UMAX,UMIN}, SWP

use super::bits::sext32;
use super::{AccessSize, AddrMode, DecodeErr, DecodedInsn, ExtendKind, Reg};

pub fn decode(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // Structural classification per ARM ARM C4.1.4 — masks match Linux's
    // `arch/arm64/kernel/insn.c` for cross-checking.
    if (word & 0x3B000000) == 0x39000000 {
        return decode_unsigned_offset(word);
    }
    if (word & 0x3B200C00) == 0x38200800 {
        return decode_register_offset(word);
    }
    if (word & 0x3B200000) == 0x38000000 {
        return decode_immediate_pre_post_unscaled(word);
    }
    if (word & 0x3B000000) == 0x18000000 {
        return decode_literal(word);
    }
    if (word & 0x3C000000) == 0x28000000 {
        return decode_pair(word);
    }
    if (word & 0x3F000000) == 0x08000000 {
        return decode_ll_sc_or_cas(word);
    }
    if (word & 0x3F200C00) == 0x38200000 {
        return decode_lse(word);
    }
    Err(DecodeErr::Unimplemented)
}

fn size_from_2bits(size: u32, simd: bool) -> AccessSize {
    match size {
        0b00 => AccessSize::Byte,
        0b01 => AccessSize::HalfWord,
        0b10 => AccessSize::Word,
        0b11 => if simd { AccessSize::QuadWord } else { AccessSize::DoubleWord },
        _ => unreachable!(),
    }
}

fn scale_of(access: AccessSize) -> u32 {
    match access {
        AccessSize::Byte => 0,
        AccessSize::HalfWord => 1,
        AccessSize::Word => 2,
        AccessSize::DoubleWord => 3,
        AccessSize::QuadWord => 4,
    }
}

/// Validate opc against size for integer load/store register family. The
/// architecture reserves several (size, opc) combinations:
/// - size=11 (DoubleWord), opc=10 → reserved (no LDRSX of 64-bit data)
/// - size=11 (DoubleWord), opc=11 → PRFM (prefetch — not a load/store)
fn check_ls_opc(size: u32, opc: u32) -> Result<(), DecodeErr> {
    if size == 0b11 && opc >= 0b10 {
        return Err(DecodeErr::Reserved); // 64-bit signed load: no-op
    }
    if size == 0b10 && opc == 0b11 {
        return Err(DecodeErr::Reserved); // LDRSW with W target = 32-bit no-op
    }
    Ok(())
}

fn decode_unsigned_offset(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 30) & 0x3;
    let v = (word >> 26) & 1;
    let opc = (word >> 22) & 0x3;
    let imm12 = (word >> 10) & 0xFFF;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rt = Reg((word & 0x1F) as u8);
    if v != 0 {
        return decode_fp_simd_unsigned(word, size, opc, imm12, rn, rt);
    }
    check_ls_opc(size, opc)?;
    let access = size_from_2bits(size, false);
    let imm = (imm12 << scale_of(access)) as i32;
    let addr = AddrMode::Offset { base: rn, imm };
    Ok(match opc {
        0b00 => DecodedInsn::Str { rt, size: access, addr },
        0b01 => DecodedInsn::Ldr { rt, size: access, signed: false, addr },
        0b10 | 0b11 => DecodedInsn::Ldr { rt, size: access, signed: true, addr },
        _ => unreachable!(),
    })
}

fn decode_immediate_pre_post_unscaled(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 30) & 0x3;
    let v = (word >> 26) & 1;
    let opc = (word >> 22) & 0x3;
    let imm9 = (word >> 12) & 0x1FF;
    let op2 = (word >> 10) & 0x3;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rt = Reg((word & 0x1F) as u8);
    if v != 0 {
        return decode_fp_simd_imm(word, size, opc, imm9, op2, rn, rt);
    }
    check_ls_opc(size, opc)?;
    let access = size_from_2bits(size, false);
    let imm = sext32(imm9, 9);
    // op2: 00=LDUR/STUR unscaled, 01=post-index, 10=LDTR/STTR unprivileged,
    //      11=pre-index. Unprivileged variants share encoding with the
    //      offset form and are valid only for size+opc combinations the
    //      architecture explicitly defines — we accept them as Offset.
    let addr = match op2 {
        0b00 => AddrMode::Offset { base: rn, imm },
        0b01 => AddrMode::PostIndex { base: rn, imm },
        0b10 => AddrMode::Offset { base: rn, imm },
        0b11 => AddrMode::PreIndex { base: rn, imm },
        _ => unreachable!(),
    };
    Ok(match opc {
        0b00 => DecodedInsn::Str { rt, size: access, addr },
        0b01 => DecodedInsn::Ldr { rt, size: access, signed: false, addr },
        0b10 | 0b11 => DecodedInsn::Ldr { rt, size: access, signed: true, addr },
        _ => unreachable!(),
    })
}

fn decode_register_offset(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 30) & 0x3;
    let v = (word >> 26) & 1;
    let opc = (word >> 22) & 0x3;
    let rm = Reg(((word >> 16) & 0x1F) as u8);
    let option = (word >> 13) & 0x7;
    let s = (word >> 12) & 1;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rt = Reg((word & 0x1F) as u8);
    if v != 0 {
        return decode_fp_simd_reg_offset(word, size, opc, rm, option, s, rn, rt);
    }
    check_ls_opc(size, opc)?;
    let access = size_from_2bits(size, false);
    let extend = match option {
        0b010 => ExtendKind::Uxtw,
        0b011 => ExtendKind::Uxtx,
        0b110 => ExtendKind::Sxtw,
        0b111 => ExtendKind::Sxtx,
        _ => return Err(DecodeErr::Reserved),
    };
    let shift = if s != 0 { scale_of(access) as u8 } else { 0 };
    let addr = AddrMode::RegOffset { base: rn, index: rm, extend, shift };
    Ok(match opc {
        0b00 => DecodedInsn::Str { rt, size: access, addr },
        0b01 => DecodedInsn::Ldr { rt, size: access, signed: false, addr },
        0b10 | 0b11 => DecodedInsn::Ldr { rt, size: access, signed: true, addr },
        _ => unreachable!(),
    })
}

fn decode_literal(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let opc = (word >> 30) & 0x3;
    let v = (word >> 26) & 1;
    let imm19 = (word >> 5) & 0x7_FFFF;
    let rt = Reg((word & 0x1F) as u8);
    if v != 0 {
        // FP/SIMD literal: same shape, but Rt is a V-register and access size
        // depends on opc (00=32-bit, 01=64-bit, 10=128-bit, 11=reserved).
        if opc == 0b11 {
            return Err(DecodeErr::Reserved);
        }
        let access = match opc {
            0b00 => AccessSize::Word,
            0b01 => AccessSize::DoubleWord,
            0b10 => AccessSize::QuadWord,
            _ => unreachable!(),
        };
        let imm = sext32(imm19, 19) << 2;
        return Ok(DecodedInsn::Ldr {
            rt, size: access, signed: false,
            addr: AddrMode::Pcrel { offset: imm },
        });
    }
    let imm = sext32(imm19, 19) << 2;
    let (access, signed) = match opc {
        0b00 => (AccessSize::Word, false),
        0b01 => (AccessSize::DoubleWord, false),
        0b10 => (AccessSize::Word, true), // LDRSW
        _ => return Err(DecodeErr::Reserved), // 11 = PRFM (literal)
    };
    Ok(DecodedInsn::Ldr {
        rt, size: access, signed,
        addr: AddrMode::Pcrel { offset: imm },
    })
}

fn decode_pair(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let opc = (word >> 30) & 0x3;
    let v = (word >> 26) & 1;
    let cls = (word >> 23) & 0x3;
    let l = (word >> 22) & 1;
    let imm7 = (word >> 15) & 0x7F;
    let rt2 = Reg(((word >> 10) & 0x1F) as u8);
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rt = Reg((word & 0x1F) as u8);
    if v != 0 {
        // FP/SIMD pair — same shape; access size determined by opc field
        // (00=32-bit, 01=64-bit, 10=128-bit, 11=reserved).
        if opc == 0b11 {
            return Err(DecodeErr::Reserved);
        }
        let access = match opc {
            0b00 => AccessSize::Word,
            0b01 => AccessSize::DoubleWord,
            0b10 => AccessSize::QuadWord,
            _ => unreachable!(),
        };
        let scale = scale_of(access);
        let imm = sext32(imm7, 7) << scale;
        let addr = match cls {
            0b00 | 0b10 => AddrMode::Offset { base: rn, imm },
            0b01 => AddrMode::PostIndex { base: rn, imm },
            0b11 => AddrMode::PreIndex { base: rn, imm },
            _ => unreachable!(),
        };
        return Ok(if l != 0 {
            DecodedInsn::Ldp { rt1: rt, rt2, sf: true, signed: false, addr }
        } else {
            DecodedInsn::Stp { rt1: rt, rt2, sf: true, addr }
        });
    }
    // opc=01 (LDPSW) is valid only with L=1 (load). STP with opc=01 is reserved
    // (STGP is in the MTE extension which we explicitly exclude).
    if opc == 0b11 {
        return Err(DecodeErr::Reserved);
    }
    if opc == 0b01 && l == 0 {
        return Err(DecodeErr::Reserved);
    }
    // No-allocate pair (cls=00) does not exist for opc=01 (LDPSW).
    if opc == 0b01 && cls == 0b00 {
        return Err(DecodeErr::Reserved);
    }
    // Constraint: in load form (LDP), Rt == Rt2 is CONSTRAINED UNPREDICTABLE.
    if l != 0 && rt.idx() == rt2.idx() {
        return Err(DecodeErr::Reserved);
    }
    // Constraint: writeback (post/pre-index) with Rn == Rt or Rn == Rt2 is
    // CONSTRAINED UNPREDICTABLE because the base update collides with the
    // memory access. Allow Rn == 31 (SP) — that's the normal use.
    if (cls == 0b01 || cls == 0b11)
        && rn.idx() != 31
        && (rn.idx() == rt.idx() || rn.idx() == rt2.idx())
    {
        return Err(DecodeErr::Reserved);
    }
    // cls=00 (no-allocate) does not exist with pre/post-index — but per ARM ARM
    // §C6.2.{ldnp,stnp} it's only valid as the offset form, encoded as cls=00.
    // For cls=00 with L=0/1 = STNP/LDNP. We accept all four cls values.
    let (sf, signed) = match opc {
        0b00 => (false, false),
        0b01 => (true, true), // LDPSW (32-bit values sign-extended)
        0b10 => (true, false),
        _ => unreachable!(),
    };
    let scale = if sf { 3 } else { 2 };
    let imm = sext32(imm7, 7) << scale;
    let addr = match cls {
        0b00 => AddrMode::Offset { base: rn, imm },   // STNP/LDNP
        0b01 => AddrMode::PostIndex { base: rn, imm },
        0b10 => AddrMode::Offset { base: rn, imm },
        0b11 => AddrMode::PreIndex { base: rn, imm },
        _ => unreachable!(),
    };
    Ok(if l != 0 {
        DecodedInsn::Ldp { rt1: rt, rt2, sf, signed, addr }
    } else {
        DecodedInsn::Stp { rt1: rt, rt2, sf, addr }
    })
}

/// LL/SC exclusive + LDAR/STLR/LDAPR + CAS (the CAS encoding lives in the
/// same 0x08000000 / 0x3F000000 family as LL/SC).
fn decode_ll_sc_or_cas(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 30) & 0x3;
    let access = size_from_2bits(size, false);
    let bit23 = (word >> 23) & 1;
    let bit22 = (word >> 22) & 1; // L
    let bit21 = (word >> 21) & 1;
    let rs = Reg(((word >> 16) & 0x1F) as u8);
    let bit15 = (word >> 15) & 1; // o0
    let rt2 = Reg(((word >> 10) & 0x1F) as u8);
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rt = Reg((word & 0x1F) as u8);

    // CAS family: bits[29:24]=001000, bit23=1, bit21=1, bits[14:10]=11111.
    if (word & 0x3FA07C00) == 0x08A07C00 {
        return Ok(DecodedInsn::Cas {
            size: access, rs, rt, rn,
            acquire: bit22 != 0, // A is bit 22 in CAS encoding
            release: bit15 != 0, // o0 is bit 15
        });
    }

    if bit23 == 0 {
        // LL/SC exclusive. For pair forms (bit21=1) Rt2 is the second target
        // register; for single forms Rt2 MUST be 11111 (otherwise CONSTRAINED
        // UNPREDICTABLE — we reject to match Capstone behavior).
        let pair = bit21 != 0;
        // Pair exclusives (LDXP/STXP/LDAXP/STLXP) exist only for size>=10
        // (Word and DoubleWord). Byte/HalfWord pair forms are reserved.
        if pair && size < 0b10 {
            return Err(DecodeErr::Reserved);
        }
        if !pair && rt2.idx() != 31 {
            return Err(DecodeErr::Reserved);
        }
        let acquire_or_release = bit15 != 0;
        // For load form (bit22=1), Rs MUST be 11111.
        if bit22 != 0 && rs.idx() != 31 {
            return Err(DecodeErr::Reserved);
        }
        // STXR/STXP: Rs (status output) must not equal Rt or (pair-form) Rt2.
        if bit22 == 0 {
            if rs.idx() == rt.idx() {
                return Err(DecodeErr::Reserved);
            }
            if pair && rs.idx() == rt2.idx() {
                return Err(DecodeErr::Reserved);
            }
        }
        return Ok(if bit22 != 0 {
            DecodedInsn::Ldxr {
                size: access, rt, rn,
                acquire: acquire_or_release, pair, rt2,
            }
        } else {
            DecodedInsn::Stxr {
                size: access, rs, rt, rn,
                release: acquire_or_release, pair, rt2,
            }
        });
    }

    // bit23=1: LDAR / STLR / LDAPR
    if bit21 == 0 && rs.idx() == 31 && rt2.idx() == 31 {
        return Ok(if bit22 != 0 {
            if bit15 != 0 {
                DecodedInsn::Ldar { size: access, rt, rn }
            } else {
                DecodedInsn::Ldapr { size: access, rt, rn }
            }
        } else {
            // STLR: o0 must be 1
            if bit15 == 0 {
                return Err(DecodeErr::Reserved);
            }
            DecodedInsn::Stlr { size: access, rt, rn }
        });
    }

    Err(DecodeErr::Reserved)
}

// =============================================================================
// FP / SIMD load/store paths (V=1). Phase A keeps these structurally complete
// but semantically coarse: every valid encoding produces a Ldr/Str/Ldp/Stp
// with AccessSize chosen to reflect the actual transfer width.
// =============================================================================

/// FP/SIMD load/store register (unsigned offset). Encoded `size opc1 opc0`:
/// - opc[1]==0 means store/load 8..64-bit forms
/// - opc[1]==1 means 128-bit form (only valid with size==00)
fn decode_fp_simd_unsigned(
    _word: u32, size: u32, opc: u32, imm12: u32, rn: Reg, rt: Reg,
) -> Result<DecodedInsn, DecodeErr> {
    let access = fp_simd_access_size(size, opc)?;
    let scale = scale_of(access);
    let imm = (imm12 << scale) as i32;
    let addr = AddrMode::Offset { base: rn, imm };
    // opc bit 0 selects load (1) vs store (0).
    Ok(if opc & 1 != 0 {
        DecodedInsn::Ldr { rt, size: access, signed: false, addr }
    } else {
        DecodedInsn::Str { rt, size: access, addr }
    })
}

fn decode_fp_simd_imm(
    word: u32, size: u32, opc: u32, imm9: u32, op2: u32, rn: Reg, rt: Reg,
) -> Result<DecodedInsn, DecodeErr> {
    let _ = word;
    let access = fp_simd_access_size(size, opc)?;
    let imm = sext32(imm9, 9);
    // op2=10 is the "unprivileged" variant (LDTR/STTR) which does NOT exist
    // for FP/SIMD load/store — reserved for V=1.
    let addr = match op2 {
        0b00 => AddrMode::Offset { base: rn, imm },
        0b01 => AddrMode::PostIndex { base: rn, imm },
        0b10 => return Err(DecodeErr::Reserved),
        0b11 => AddrMode::PreIndex { base: rn, imm },
        _ => unreachable!(),
    };
    Ok(if opc & 1 != 0 {
        DecodedInsn::Ldr { rt, size: access, signed: false, addr }
    } else {
        DecodedInsn::Str { rt, size: access, addr }
    })
}

fn decode_fp_simd_reg_offset(
    word: u32, size: u32, opc: u32, rm: Reg, option: u32, s: u32, rn: Reg, rt: Reg,
) -> Result<DecodedInsn, DecodeErr> {
    let _ = word;
    let access = fp_simd_access_size(size, opc)?;
    let extend = match option {
        0b010 => ExtendKind::Uxtw,
        0b011 => ExtendKind::Uxtx,
        0b110 => ExtendKind::Sxtw,
        0b111 => ExtendKind::Sxtx,
        _ => return Err(DecodeErr::Reserved),
    };
    let shift = if s != 0 { scale_of(access) as u8 } else { 0 };
    let addr = AddrMode::RegOffset { base: rn, index: rm, extend, shift };
    Ok(if opc & 1 != 0 {
        DecodedInsn::Ldr { rt, size: access, signed: false, addr }
    } else {
        DecodedInsn::Str { rt, size: access, addr }
    })
}

/// FP/SIMD load/store register access width determined by (size, opc[1]).
/// opc[1]=1 elects the 128-bit form, which is only valid when size==00.
fn fp_simd_access_size(size: u32, opc: u32) -> Result<AccessSize, DecodeErr> {
    let opc_hi = (opc >> 1) & 1;
    if opc_hi == 1 {
        // 128-bit form
        if size != 0b00 {
            return Err(DecodeErr::Reserved);
        }
        return Ok(AccessSize::QuadWord);
    }
    Ok(match size {
        0b00 => AccessSize::Byte,
        0b01 => AccessSize::HalfWord,
        0b10 => AccessSize::Word,
        0b11 => AccessSize::DoubleWord,
        _ => unreachable!(),
    })
}

/// LSE atomics — separate family (top byte 0x38..). Does NOT include CAS
/// (CAS lives in the LL/SC family above).
///
/// 4-bit opcode (bits[15:12]) values per ARM ARM Table C4-3:
///   0000 = LDADD   0001 = LDCLR   0010 = LDEOR   0011 = LDSET
///   0100 = LDSMAX  0101 = LDSMIN  0110 = LDUMAX  0111 = LDUMIN
///   1000 = SWP
///   All other 4-bit patterns are reserved.
fn decode_lse(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let size = (word >> 30) & 0x3;
    let access = size_from_2bits(size, false);
    let a = (word >> 23) & 1;
    let r = (word >> 22) & 1;
    let rs = Reg(((word >> 16) & 0x1F) as u8);
    let opcode4 = (word >> 12) & 0xF;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rt = Reg((word & 0x1F) as u8);
    let acquire = a != 0;
    let release = r != 0;

    Ok(match opcode4 {
        0b0000 => DecodedInsn::LdAtomicRmw { size: access, op: 0, rs, rt, rn, acquire, release },
        0b0001 => DecodedInsn::LdAtomicRmw { size: access, op: 1, rs, rt, rn, acquire, release },
        0b0010 => DecodedInsn::LdAtomicRmw { size: access, op: 2, rs, rt, rn, acquire, release },
        0b0011 => DecodedInsn::LdAtomicRmw { size: access, op: 3, rs, rt, rn, acquire, release },
        0b0100 => DecodedInsn::LdAtomicRmw { size: access, op: 4, rs, rt, rn, acquire, release },
        0b0101 => DecodedInsn::LdAtomicRmw { size: access, op: 5, rs, rt, rn, acquire, release },
        0b0110 => DecodedInsn::LdAtomicRmw { size: access, op: 6, rs, rt, rn, acquire, release },
        0b0111 => DecodedInsn::LdAtomicRmw { size: access, op: 7, rs, rt, rn, acquire, release },
        0b1000 => DecodedInsn::Swp { size: access, rs, rt, rn, acquire, release },
        _ => return Err(DecodeErr::Reserved),
    })
}
