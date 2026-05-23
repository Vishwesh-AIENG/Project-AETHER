//! Data-processing — register (ARM ARM §C4.1.5).
//!
//! Top-level family selector op0=`0101` or `1101`. Sub-tables selected by
//! bits[28], [24:21], [11:10]:
//!
//!   bit 28 == 0 :
//!     bit 24 == 0 : Logical (shifted register)
//!     bit 24 == 1 : Add/subtract (shifted register) | Add/subtract (extended register)
//!   bit 28 == 1 :
//!     bits[24:21] == 0000 : Add/subtract (with carry); Rotate-right (CSEL etc)
//!     bits[24:21] == 0010 : Conditional compare (register / immediate)
//!     bits[24:21] == 0100 : Conditional select
//!     bits[24:21] == 0110 : Data-processing (1 source / 2 source)
//!     bits[24:21] == 1xxx : Data-processing (3 source)

use super::{
    Cond, DecodeErr, DecodedInsn, ExtendKind, Reg, ShiftKind,
};

pub fn decode(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let bit28 = (word >> 28) & 1;
    let bit24 = (word >> 24) & 1;
    let op2 = (word >> 21) & 0xF; // bits[24:21]

    if bit28 == 0 {
        if bit24 == 0 {
            decode_logical_shifted(word)
        } else {
            // Bit 21 selects extended-register (1) vs shifted-register (0) form
            // of add/sub when bit24=1.
            if (word >> 21) & 1 == 1 {
                decode_add_sub_extended(word)
            } else {
                decode_add_sub_shifted(word)
            }
        }
    } else {
        match op2 {
            0b0000 => decode_add_sub_with_carry(word),
            0b0010 => decode_conditional_compare(word),
            0b0100 => decode_conditional_select(word),
            0b0110 => decode_dp_1_or_2_source(word),
            v if v & 0b1000 != 0 => decode_dp_3_source(word),
            _ => Err(DecodeErr::Reserved),
        }
    }
}

fn shift_kind_of(bits: u32) -> Result<ShiftKind, DecodeErr> {
    match bits & 0x3 {
        0b00 => Ok(ShiftKind::Lsl),
        0b01 => Ok(ShiftKind::Lsr),
        0b10 => Ok(ShiftKind::Asr),
        0b11 => Ok(ShiftKind::Ror),
        _ => unreachable!(),
    }
}

fn decode_logical_shifted(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf opc(2) 01010 shift(2) N Rm imm6 Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let opc = (word >> 29) & 0x3;
    let shift = shift_kind_of((word >> 22) & 0x3)?;
    let invert = (word >> 21) & 1 != 0;
    let rm = Reg(((word >> 16) & 0x1F) as u8);
    let amount = ((word >> 10) & 0x3F) as u8;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);
    if !sf && amount >= 32 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::LogicalReg {
        sf,
        opc: opc as u8,
        rd,
        rn,
        rm,
        shift,
        amount,
        invert,
    })
}

fn decode_add_sub_shifted(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf op S 01011 shift(2) 0 Rm imm6 Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let sub = (word >> 30) & 1 != 0;
    let set_flags = (word >> 29) & 1 != 0;
    let shift_bits = (word >> 22) & 0x3;
    if shift_bits == 0b11 {
        return Err(DecodeErr::Reserved); // shift=ROR not allowed for ADD/SUB
    }
    let shift = shift_kind_of(shift_bits)?;
    let rm = Reg(((word >> 16) & 0x1F) as u8);
    let amount = ((word >> 10) & 0x3F) as u8;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);
    if !sf && amount >= 32 {
        return Err(DecodeErr::Reserved);
    }
    Ok(if sub {
        DecodedInsn::SubReg { sf, rd, rn, rm, shift, amount, set_flags }
    } else {
        DecodedInsn::AddReg { sf, rd, rn, rm, shift, amount, set_flags }
    })
}

fn decode_add_sub_extended(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf op S 01011 opt(2) 1 Rm option(3) imm3 Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let sub = (word >> 30) & 1 != 0;
    let set_flags = (word >> 29) & 1 != 0;
    let opt = (word >> 22) & 0x3;
    if opt != 0 {
        return Err(DecodeErr::Reserved);
    }
    let rm = Reg(((word >> 16) & 0x1F) as u8);
    let option = (word >> 13) & 0x7;
    let imm3 = ((word >> 10) & 0x7) as u8;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);
    if imm3 > 4 {
        return Err(DecodeErr::Reserved);
    }
    let extend = match option {
        0b000 => ExtendKind::Uxtb,
        0b001 => ExtendKind::Uxth,
        0b010 => ExtendKind::Uxtw,
        0b011 => ExtendKind::Uxtx,
        0b100 => ExtendKind::Sxtb,
        0b101 => ExtendKind::Sxth,
        0b110 => ExtendKind::Sxtw,
        0b111 => ExtendKind::Sxtx,
        _ => unreachable!(),
    };
    Ok(DecodedInsn::AddSubExtReg {
        sf, rd, rn, rm, extend, imm3, sub, set_flags,
    })
}

fn decode_add_sub_with_carry(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf op S 11010000 Rm 000000 Rn Rd  -> ADC/ADCS/SBC/SBCS
    let sf = (word >> 31) & 1 != 0;
    let sub = (word >> 30) & 1 != 0;
    let set_flags = (word >> 29) & 1 != 0;
    let rm = Reg(((word >> 16) & 0x1F) as u8);
    let opcode2 = (word >> 10) & 0x3F;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);
    if opcode2 != 0 {
        return Err(DecodeErr::Reserved);
    }
    // No dedicated DecodedInsn variant for ADC; fold into AddReg/SubReg with
    // shift=Lsl, amount=0 and remember the carry intent in `set_flags`/`sub`.
    // The lift step will treat ADC specifically. For now surface as Reserved
    // to avoid silent semantic mismatch — AT-4 fill adds a dedicated variant.
    let _ = (sf, sub, set_flags, rm, rn, rd);
    Err(DecodeErr::Unimplemented)
}

fn decode_conditional_compare(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf op S 11010010 imm5_or_Rm cond 0 o2 0 Rn 0 nzcv
    let sf = (word >> 31) & 1 != 0;
    let op = (word >> 30) & 1; // 0=CCMN 1=CCMP
    let s_bit = (word >> 29) & 1;
    if s_bit == 0 {
        return Err(DecodeErr::Reserved);
    }
    // bit 11 selects register (0) vs immediate (1)
    let is_imm = (word >> 11) & 1 != 0;
    let rm_or_imm = ((word >> 16) & 0x1F) as u8;
    let cond = Cond::from_bits(((word >> 12) & 0xF) as u8);
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let nzcv = (word & 0xF) as u8;
    // Reserved bits 4, 10 must be 0.
    if (word >> 4) & 1 != 0 || (word >> 10) & 1 != 0 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::Ccmp {
        sf,
        rn,
        rm_or_imm,
        cond,
        nzcv,
        is_neg: op == 0,
        is_imm,
    })
}

fn decode_conditional_select(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf op S 11010100 Rm cond op2(2) Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let op = (word >> 30) & 1; // bit 30
    let s_bit = (word >> 29) & 1;
    if s_bit != 0 {
        return Err(DecodeErr::Reserved);
    }
    let rm = Reg(((word >> 16) & 0x1F) as u8);
    let cond = Cond::from_bits(((word >> 12) & 0xF) as u8);
    let op2 = ((word >> 10) & 0x3) as u8;
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);
    // Encoding selector for the 4 variants:
    //   op=0 op2=00 -> CSEL
    //   op=0 op2=01 -> CSINC
    //   op=1 op2=00 -> CSINV
    //   op=1 op2=01 -> CSNEG
    let variant = (op << 1) | (op2 as u32 & 1);
    if op2 & 0b10 != 0 {
        return Err(DecodeErr::Reserved);
    }
    Ok(DecodedInsn::Csel { sf, rd, rn, rm, cond, op2: variant as u8 })
}

fn decode_dp_1_or_2_source(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let s_bit = (word >> 29) & 1;
    let op = (word >> 30) & 1; // 0=DP-2-source, 1=DP-1-source
    if s_bit != 0 {
        return Err(DecodeErr::Reserved);
    }
    let sf = (word >> 31) & 1 != 0;

    if op == 0 {
        // DP 2-source: sf 0 0 11010110 Rm opcode(6) Rn Rd
        let rm = Reg(((word >> 16) & 0x1F) as u8);
        let opcode = (word >> 10) & 0x3F;
        let rn = Reg(((word >> 5) & 0x1F) as u8);
        let rd = Reg((word & 0x1F) as u8);
        match opcode {
            0b000010 => Ok(DecodedInsn::Div { sf, rd, rn, rm, signed: false }), // UDIV
            0b000011 => Ok(DecodedInsn::Div { sf, rd, rn, rm, signed: true }),  // SDIV
            0b001000 => Ok(DecodedInsn::Shift { sf, rd, rn, rm, kind: ShiftKind::Lsl }),
            0b001001 => Ok(DecodedInsn::Shift { sf, rd, rn, rm, kind: ShiftKind::Lsr }),
            0b001010 => Ok(DecodedInsn::Shift { sf, rd, rn, rm, kind: ShiftKind::Asr }),
            0b001011 => Ok(DecodedInsn::Shift { sf, rd, rn, rm, kind: ShiftKind::Ror }),
            0b010000 | 0b010001 | 0b010010 | 0b010011 => {
                // CRC32B/H/W/X — sz=11 (X form) requires sf=1
                let sz = (opcode & 0x3) as u8;
                if sz == 0b11 && !sf {
                    return Err(DecodeErr::Reserved);
                }
                if sz != 0b11 && sf {
                    return Err(DecodeErr::Reserved);
                }
                Ok(DecodedInsn::Crc32 { sf, rd, rn, rm, sz, castagnoli: false })
            }
            0b010100 | 0b010101 | 0b010110 | 0b010111 => {
                let sz = (opcode & 0x3) as u8;
                if sz == 0b11 && !sf {
                    return Err(DecodeErr::Reserved);
                }
                if sz != 0b11 && sf {
                    return Err(DecodeErr::Reserved);
                }
                Ok(DecodedInsn::Crc32 { sf, rd, rn, rm, sz, castagnoli: true })
            }
            _ => Err(DecodeErr::Unimplemented),
        }
    } else {
        // DP 1-source: sf 1 0 11010110 opcode2(5) opcode(6) Rn Rd
        let opcode2 = (word >> 16) & 0x1F;
        let opcode = (word >> 10) & 0x3F;
        let rn = Reg(((word >> 5) & 0x1F) as u8);
        let rd = Reg((word & 0x1F) as u8);
        if opcode2 != 0 {
            return Err(DecodeErr::Reserved);
        }
        // opcode: 0=RBIT 1=REV16 2=REV32(64-bit form)/REV(32-bit form) 3=REV(64-bit) 4=CLZ 5=CLS
        if opcode > 5 {
            return Err(DecodeErr::Reserved);
        }
        Ok(DecodedInsn::DataOp1Src { sf, rd, rn, opcode: opcode as u8 })
    }
}

fn decode_dp_3_source(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // sf op54(2) 11011 op31(3) Rm o0 Ra Rn Rd
    let sf = (word >> 31) & 1 != 0;
    let op54 = (word >> 29) & 0x3;
    if op54 != 0 {
        return Err(DecodeErr::Reserved);
    }
    let op31 = (word >> 21) & 0x7;
    let rm = Reg(((word >> 16) & 0x1F) as u8);
    let o0 = (word >> 15) & 1;
    let ra = Reg(((word >> 10) & 0x1F) as u8);
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    let rd = Reg((word & 0x1F) as u8);

    // op31 catalog (subset):
    //   000 -> MADD/MSUB (sf-form)
    //   001 -> SMADDL/SMSUBL  (Wn*Wm + Xa)
    //   010 -> SMULH (no MSUB form)
    //   100 - reserved or unused
    //   101 -> UMADDL/UMSUBL
    //   110 -> UMULH
    // MADD/MSUB (op31=000) work in both 32-bit and 64-bit forms.
    // SMADDL/UMADDL (op31=001/101) and SMULH/UMULH (op31=010/110) are
    // 64-bit only — sf MUST be 1.
    match op31 {
        0b000 => Ok(DecodedInsn::Mul {
            sf, rd, rn, rm, ra, sub: o0 != 0,
        }),
        0b001 | 0b101 => {
            if !sf {
                return Err(DecodeErr::Reserved);
            }
            Ok(DecodedInsn::Mul {
                sf: true, rd, rn, rm, ra, sub: o0 != 0,
            })
        }
        0b010 | 0b110 => {
            if !sf || o0 != 0 {
                return Err(DecodeErr::Reserved);
            }
            Ok(DecodedInsn::Mul {
                sf: true, rd, rn, rm, ra: Reg::XZR, sub: false,
            })
        }
        _ => Err(DecodeErr::Reserved),
    }
}
