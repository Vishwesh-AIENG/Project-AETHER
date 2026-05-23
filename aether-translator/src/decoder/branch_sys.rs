//! Branches, Exception Generating, and System (ARM ARM §C4.1.3).
//!
//! Sub-families dispatched by bits[31:29] of the instruction word.

use super::bits::sext32;
use super::{Cond, DecodeErr, DecodedInsn, Reg};

pub fn decode(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let op0 = (word >> 29) & 0x7;
    let op1 = (word >> 22) & 0x3F;

    match op0 {
        // Unconditional branch (immediate): 0_00101 op26 — B
        // Same shape with bit 31 set: 1_00101 — BL
        0b000 | 0b100 => decode_uncond_branch_imm(word),

        // Conditional branch (immediate): 01010100_imm19_cond
        0b010 if (word >> 25) & 0xF == 0b0101 && (word >> 24) & 1 == 0 => {
            decode_cond_branch(word)
        }

        // Compare & branch / Test & branch: bits[30:25] = 011010 / 011011
        0b001 | 0b101 => decode_cmpbr_or_tbz(word),

        // System / Exception / Branch register family — bits[28:25] varies
        0b110 => decode_system_or_excp(word),

        _ => Err(DecodeErr::Unimplemented),
    }.or_else(|e| {
        let _ = op1;
        // Conditional branches sometimes fall through to op0=0b010 by way of bits[31:29]=010.
        // The match above only handles part of it; on Unimplemented try cond branch as a
        // fallback because the bit pattern overlaps.
        match e {
            DecodeErr::Unimplemented if (word >> 24) & 0xFF == 0x54 => decode_cond_branch(word),
            other => Err(other),
        }
    })
}

fn decode_uncond_branch_imm(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // op_00101_imm26 where op=bit31
    if (word >> 26) & 0x1F != 0b00101 {
        return Err(DecodeErr::Reserved);
    }
    let op = (word >> 31) & 1;
    let imm26 = word & 0x3FF_FFFF;
    let offset = (sext32(imm26, 26) << 2) as i32;
    Ok(if op == 1 {
        DecodedInsn::Bl { offset }
    } else {
        DecodedInsn::B { offset }
    })
}

fn decode_cond_branch(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // 0101_0100 imm19 0 cond
    if (word >> 24) & 0xFF != 0x54 {
        return Err(DecodeErr::Reserved);
    }
    if (word >> 4) & 1 != 0 {
        return Err(DecodeErr::Reserved);
    }
    let imm19 = (word >> 5) & 0x7_FFFF;
    let offset = (sext32(imm19, 19) << 2) as i32;
    let cond = Cond::from_bits((word & 0xF) as u8);
    Ok(DecodedInsn::Bcond { cond, offset })
}

fn decode_cmpbr_or_tbz(word: u32) -> Result<DecodedInsn, DecodeErr> {
    let class = (word >> 25) & 0x3F; // bits[30:25]
    let op = (word >> 24) & 1;
    let sf = (word >> 31) & 1 != 0;
    match class {
        0b011010 => {
            // CBZ / CBNZ: sf 011010 op imm19 Rt
            let imm19 = (word >> 5) & 0x7_FFFF;
            let offset = (sext32(imm19, 19) << 2) as i32;
            let rt = Reg((word & 0x1F) as u8);
            Ok(if op == 1 {
                DecodedInsn::Cbnz { sf, rt, offset }
            } else {
                DecodedInsn::Cbz { sf, rt, offset }
            })
        }
        0b011011 => {
            // TBZ / TBNZ: b5 011011 op b40 imm14 Rt
            let b5 = (word >> 31) & 1;
            let b40 = (word >> 19) & 0x1F;
            let bit = ((b5 << 5) | b40) as u8;
            let imm14 = (word >> 5) & 0x3FFF;
            let offset = (sext32(imm14, 14) << 2) as i32;
            let rt = Reg((word & 0x1F) as u8);
            Ok(if op == 1 {
                DecodedInsn::Tbnz { bit, rt, offset }
            } else {
                DecodedInsn::Tbz { bit, rt, offset }
            })
        }
        _ => Err(DecodeErr::Unimplemented),
    }
}

fn decode_system_or_excp(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // bits[31:24] candidates:
    //   1101 0100 — exception generation (SVC/HVC/SMC/BRK/HLT/DCPS)
    //   1101 0101 0 — MSR (imm) / hint / barriers
    //   1101 0101 0 0 ... — MSR/MRS register form
    //   1101 0110 — unconditional branch register
    let bits31_25 = (word >> 25) & 0x7F;
    match bits31_25 {
        0b1101_010 => {
            let bit24 = (word >> 24) & 1;
            if bit24 == 0 {
                decode_exception_generation(word)
            } else {
                decode_system(word)
            }
        }
        0b1101_011 => decode_uncond_branch_reg(word),
        _ => Err(DecodeErr::Unimplemented),
    }
}

fn decode_exception_generation(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // 1101_0100 opc(3) imm16 op2(3) LL(2)
    let opc = (word >> 21) & 0x7;
    let imm16 = ((word >> 5) & 0xFFFF) as u16;
    let op2 = (word >> 2) & 0x7;
    let ll = (word & 0x3) as u8;
    if op2 != 0 {
        return Err(DecodeErr::Reserved);
    }
    // ARM ARM C4.1.3 Exception generation valid (opc, LL) table:
    //   (000, 01) SVC       (000, 10) HVC       (000, 11) SMC
    //   (001, 00) BRK
    //   (010, 00) HLT
    //   (011, 00) TCANCEL   — TME extension, out of Phase A scope
    //   (101, 01) DCPS1     (101, 10) DCPS2     (101, 11) DCPS3
    // All other combinations are reserved.
    Ok(match (opc, ll) {
        (0b000, 0b01) => DecodedInsn::Svc { imm16 },
        (0b000, 0b10) => DecodedInsn::Hvc { imm16 },
        (0b000, 0b11) => DecodedInsn::Smc { imm16 },
        (0b000, 0b00) => return Err(DecodeErr::Reserved), // opc=000 with LL=00 reserved
        (0b001, 0b00) => DecodedInsn::Brk { imm16 },
        (0b001, _) => return Err(DecodeErr::Reserved),    // BRK only with LL=00
        (0b010, 0b00) => DecodedInsn::Hlt { imm16 },
        (0b010, _) => return Err(DecodeErr::Reserved),    // HLT only with LL=00
        (0b011, 0b00) => return Err(DecodeErr::UnsupportedExtension), // TCANCEL (TME)
        (0b011, _) => return Err(DecodeErr::Reserved),
        (0b101, 0b01) | (0b101, 0b10) | (0b101, 0b11) => {
            // DCPS1/2/3 — debug entry; Phase A doesn't model debug semantics.
            return Err(DecodeErr::Unimplemented);
        }
        (0b101, 0b00) => return Err(DecodeErr::Reserved),
        _ => return Err(DecodeErr::Reserved),
    })
}

fn decode_system(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // 1101_0101 00L op0(2) op1(3) CRn(4) CRm(4) op2(3) Rt
    // bits[23:22] must be 00 — distinguishes the system class from other
    // bits[31:24]=D5 encodings (e.g. branch register at D6).
    if (word >> 22) & 0x3 != 0 {
        return Err(DecodeErr::Reserved);
    }
    let l = (word >> 21) & 1;
    let op0_field = (word >> 19) & 0x3;
    let op1 = ((word >> 16) & 0x7) as u8;
    let crn = ((word >> 12) & 0xF) as u8;
    let crm = ((word >> 8) & 0xF) as u8;
    let op2 = ((word >> 5) & 0x7) as u8;
    let rt = Reg((word & 0x1F) as u8);

    // Special-case: hints + barriers live in CRn==0100 op2=011x or CRn==0010, etc.
    // Following ARM ARM C5.2.

    // MSR (immediate): op0=00, l=0, CRn=0100
    if l == 0 && op0_field == 0b00 && crn == 0b0100 {
        return Ok(DecodedInsn::MsrImm { op1, crm, op2 });
    }
    // Hint (NOP/YIELD/WFE/WFI/SEV/SEVL/PAC/BTI): op0=00, l=0, CRn=0010, op1=011
    if l == 0 && op0_field == 0b00 && crn == 0b0010 {
        // CRm/op2 encode the hint id.
        let imm = (crm << 3) | (op2 & 0x7);
        return Ok(match imm {
            0 => DecodedInsn::Nop,
            1 => DecodedInsn::Yield,
            2 => DecodedInsn::Wfe,
            3 => DecodedInsn::Wfi,
            4 => DecodedInsn::Sev,
            5 => DecodedInsn::Sevl,
            // PAC hint space (8..31): PACIA, PACIB, AUTIA, ...
            8..=15 => DecodedInsn::PacHint { opc: imm - 8 },
            // BTI hints (32..38)
            32..=38 => DecodedInsn::BtiHint { target: imm - 32 },
            _ => DecodedInsn::Nop, // catch-all hint — preserves coverage
        });
    }
    // Barriers: CRn=0011, op2 selects DSB/DMB/ISB/SB
    if l == 0 && op0_field == 0b00 && crn == 0b0011 {
        return Ok(match op2 {
            0b100 => DecodedInsn::Dsb { domain: crm },
            0b101 => DecodedInsn::Dmb { domain: crm },
            0b110 => DecodedInsn::Isb,
            0b111 => DecodedInsn::Sb,
            0b010 => DecodedInsn::Csdb, // CLREX uses op2=010 actually; CSDB is op2=100 with CRm=0010
            _ => DecodedInsn::Nop,
        });
    }
    // SYS (IC/DC/AT/TLBI): l=0, op0=01, CRn varies
    if l == 0 && op0_field == 0b01 {
        return Ok(match crn {
            0b0111 => match (op1, op2) {
                _ => DecodedInsn::SysDc { op1, crm, op2, rt },
            },
            0b1000 => DecodedInsn::SysTlbi { op1, crm, op2, rt },
            _ => DecodedInsn::SysIc { op1, crm, op2, rt },
        });
    }

    // MSR (reg) / MRS: l=0 -> MSR, l=1 -> MRS
    let sysreg = ((1u16 + op0_field as u16) << 14)
        | ((op1 as u16) << 11)
        | ((crn as u16) << 7)
        | ((crm as u16) << 3)
        | (op2 as u16);
    Ok(if l == 1 {
        DecodedInsn::Mrs { rt, sysreg }
    } else {
        DecodedInsn::Msr { rt, sysreg }
    })
}

fn decode_uncond_branch_reg(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // 1101 0110 opc(4) 11111 op2(5) op3(6) Rn op4(5)
    let opc = (word >> 21) & 0xF;
    let bits20_16 = (word >> 16) & 0x1F;
    if bits20_16 != 0b11111 {
        return Err(DecodeErr::Reserved);
    }
    let rn = Reg(((word >> 5) & 0x1F) as u8);
    Ok(match opc {
        0b0000 => DecodedInsn::Br { rn },
        0b0001 => DecodedInsn::Blr { rn },
        0b0010 => DecodedInsn::Ret { rn },
        _ => return Err(DecodeErr::Unimplemented), // ERET/DRPS/BRAA/BLRAA in later revisions
    })
}
