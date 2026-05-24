//! Top-level A64 dispatcher.
//!
//! Per ARM ARM DDI 0487J §C4.1, the family is selected by bits [28:25] (`op0`).
//! Eight families, but several bit-patterns overlap (SIMD/FP shares a family
//! decode with two distinct op0 values, etc.). This module performs only the
//! coarse split; sub-modules handle the remaining bits.
//!
//! Phase A status: skeleton — every branch routes to its family module's
//! placeholder.

use super::{branch_sys, dp_immediate, dp_register, dp_simd_fp, load_store};
use super::{DecodeErr, DecodedInsn};

#[inline]
pub fn dispatch(word: u32) -> Result<DecodedInsn, DecodeErr> {
    // op0 = bits[28:25]
    let op0 = (word >> 25) & 0xF;

    // UDF #imm16 — bits[31:16] = 0x0000, imm16 in bits[15:0]. ARM ARM C6.2.401.
    if (word >> 16) == 0 {
        return Ok(DecodedInsn::Udf { imm16: word as u16 });
    }

    // Reserved bit pattern bits [31:25] == 0b0000_000x but bits[31:16] != 0 =>
    // truly unallocated.
    if (word >> 25) == 0 {
        return Ok(DecodedInsn::Unknown(word));
    }

    match op0 {
        // 0b0000 — Reserved / UDF (handled above)
        0b0000 => Ok(DecodedInsn::Unknown(word)),

        // 0b0001 — Unallocated (in current ARMv8 revisions).
        0b0001 => Err(DecodeErr::Reserved),

        // 0b0010 — SVE encodings (out of Phase A scope).
        0b0010 => Err(DecodeErr::UnsupportedExtension),

        // 0b0011 — Unallocated.
        0b0011 => Err(DecodeErr::Reserved),

        // 0b100x — Data Processing -- Immediate
        0b1000 | 0b1001 => dp_immediate::decode(word),

        // 0b101x — Branches, Exception Generating and System
        0b1010 | 0b1011 => branch_sys::decode(word),

        // 0b0100, 0b0110, 0b1100, 0b1110 — Loads and Stores (multiple op0 codes)
        0b0100 | 0b0110 | 0b1100 | 0b1110 => load_store::decode(word),

        // 0b0101, 0b1101 — Data Processing -- Register
        0b0101 | 0b1101 => dp_register::decode(word),

        // 0b0111, 0b1111 — Data Processing -- Scalar Floating-Point and Advanced SIMD
        0b0111 | 0b1111 => dp_simd_fp::decode(word),

        _ => Err(DecodeErr::Reserved),
    }
}
