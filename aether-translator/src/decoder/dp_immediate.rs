//! Data-processing — immediate (ARM ARM §C4.1.2).
//!
//! Sub-tables, selected by bits[25:23] (`op0`):
//!   `0xx` PC-rel addressing  (ADR/ADRP)
//!   `010` Add/sub immediate
//!   `011` Add/sub immediate with tags (v8.5 MTE) — out of scope, returns Reserved
//!   `100` Logical immediate
//!   `101` Move wide immediate
//!   `110` Bitfield
//!   `111` Extract

use super::bits::{decode_bit_masks, sext32};
use super::{DecodeErr, DecodedInsn, Reg};

pub fn decode(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let op0 = (word >> 23) & 0x7;
    match op0 {
        0b000 | 0b001 => decode_pcrel(word),
        0b010 => decode_add_sub_imm(word),
        0b011 => Err(DecodeErr::UnsupportedExtension), // ADDG/SUBG (MTE)
        0b100 => decode_logical_imm(word),
        0b101 => decode_mov_wide(word),
        0b110 => decode_bitfield(word),
        0b111 => decode_extract(word),
        _ => Err(DecodeErr::Reserved),
    }
}

fn decode_pcrel(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let op = (word >> 31) & 1;
    let immlo = (word >> 29) & 0x3;
    let immhi = (word >> 5) & 0x7_FFFF; // 19 bits
    let imm21: u32 = (immhi << 2) | immlo;
    let imm = sext32(imm21, 21);
    let rd = Reg((word & 0x1F) as u8);
    Ok(if op == 1 {
        DecodedInsn::Adrp { rd, imm }
    } else {
        DecodedInsn::Adr { rd, imm }
    })
}

fn decode_add_sub_imm(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf op S 100010 sh imm12 Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let sub = (word >> 30) & 1 != 0;
    let set_flags = (word >> 29) & 1 != 0;
    let shift_12 = (word >> 22) & 1 != 0;
    // Bit 23 is part of op0=010; bit 24..23 already filtered. Reserved bit 23=1 here? In add/sub
    // immediate, bits 24:23 are 00 (we matched 010 in op0 so bits 25:23 = 010).
    // If bit 22 (shift) is "01" the encoding is unallocated in ARMv8.0; we still accept and treat
    // it as the shifted form per architecture revisions where bit 22 became a 1-bit shift selector.
    if (word >> 23) & 1 != 0 {
        return Err(DecodeErr::Reserved);
    }
    let imm12 = ((word >> 10) & 0xFFF) as u16;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);
    Ok(if sub {
        DecodedInsn::SubImm { sf, rd, rn, imm: imm12, shift_12, set_flags }
    } else {
        DecodedInsn::AddImm { sf, rd, rn, imm: imm12, shift_12, set_flags }
    })
}

fn decode_logical_imm(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf opc 100100 N immr imms Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let opc = ((word >> 29) & 0x3) as u8;
    let n_bit = (word >> 22) & 1;
    if !sf && n_bit != 0 {
        return Err(DecodeErr::Reserved);
    }
    let immr = (word >> 16) & 0x3F;
    let imms = (word >> 10) & 0x3F;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);

    let imm = decode_bit_masks(n_bit, imms, immr, sf).ok_or(DecodeErr::Reserved)?;

    Ok(match opc {
        0b00 => DecodedInsn::AndImm { sf, rd, rn, imm, set_flags: false },
        0b01 => DecodedInsn::OrrImm { sf, rd, rn, imm },
        0b10 => DecodedInsn::EorImm { sf, rd, rn, imm },
        0b11 => DecodedInsn::AndImm { sf, rd, rn, imm, set_flags: true }, // ANDS
        _ => unreachable!(),
    })
}

fn decode_mov_wide(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf opc 100101 hw imm16 Rd
    let sf = (word >> 31) & 1 != 0;
    let opc = ((word >> 29) & 0x3) as u8;
    let hw = ((word >> 21) & 0x3) as u8;
    if !sf && hw >= 2 {
        return Err(DecodeErr::Reserved); // hw must be 0 or 1 for 32-bit form
    }
    if opc == 0b01 {
        return Err(DecodeErr::Reserved); // reserved
    }
    let imm = ((word >> 5) & 0xFFFF) as u16;
    let rd = Reg((word & 0x1F) as u8);
    Ok(DecodedInsn::MovWide { sf, opc, hw, rd, imm })
}

fn decode_bitfield(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf opc 100110 N immr imms Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let opc = ((word >> 29) & 0x3) as u8;
    let n_bit = (word >> 22) & 1;
    if (sf as u32) != n_bit {
        return Err(DecodeErr::Reserved); // N must equal sf
    }
    if opc == 0b11 {
        return Err(DecodeErr::Reserved);
    }
    let immr = ((word >> 16) & 0x3F) as u8;
    let imms = ((word >> 10) & 0x3F) as u8;
    // For the 32-bit form (sf=0), immr and imms must fit in 5 bits (< 32).
    if !sf && (immr >= 32 || imms >= 32) {
        return Err(DecodeErr::Reserved);
    }
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);
    Ok(DecodedInsn::Bfm { sf, opc, rd, rn, immr, imms })
}

fn decode_extract(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf op21 100111 N o0 Rm imms Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let op21 = (word >> 29) & 0x3;
    let n_bit = (word >> 22) & 1;
    let o0 = (word >> 21) & 1;
    if op21 != 0 || o0 != 0 {
        return Err(DecodeErr::Reserved);
    }
    if (sf as u32) != n_bit {
        return Err(DecodeErr::Reserved);
    }
    let rm = Reg(((word >> 16) & 0x1F) as u8);
    let imms = ((word >> 10) & 0x3F) as u8;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);
    if !sf && imms >= 32 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::Extr { sf, rd, rn, rm, lsb: imms })
}
