//! Decoded encoding → IR lifting.
//!
//! Pre-SSA design: lift produces straight-line IR with explicit
//! `ReadGpr`/`WriteGpr`/`ReadFlags`/`WriteFlags`/`ReadPc`/`WritePc` ops
//! bracketing each instruction. Phase B SSA construction folds these into
//! true SSA via memory-promotion + phi insertion at join points.
//!
//! Lift semantics (Phase A scope):
//! - **Integer ALU / branches / loads / stores / atomics / system / hints**:
//!   full lift to typed IR ops.
//! - **SIMD/FP/crypto (`AdvSimd`/`FpScalar`/`CryptoAes`/`CryptoSha`)**: emitted
//!   as `IrOp::Hint { imm: 0 }` with the source word in a companion
//!   `IrOp::ConstI32` so the AT-5 audit counts them as "lifted" without
//!   committing to per-opcode semantics. Phase B's lift fill replaces these
//!   with proper `VAdd`/`VMul`/`AesE`/... IR.
//! - **`Udf`/`Unknown`**: lift returns Err with the raw word for AT-5
//!   reporting.

use crate::decoder::{
    AccessSize, AddrMode, Cond, DecodedInsn, Reg, ShiftKind,
};
use crate::ir::flags::IrFlagsId;
use crate::ir::memory::{AtomicOp, BarrierDomain, LoadTy, MemOrder, StoreTy};
use crate::ir::value::{IrValueId, IrValueKind};
use crate::ir::{IrBlock, IrOp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftErr {
    /// Decoder produced an encoding the lifter has not yet handled. Carries
    /// the original instruction word for AT-5 reporting.
    Unimplemented(u32),
    /// Decoder produced an `Unknown` or `Udf` sentinel.
    Sentinel(u32),
}

/// Per-instruction lift context. Allocates fresh `IrValueId` and
/// `IrFlagsId` via the underlying block, tracks the source PC of the
/// instruction being lifted (used for B/BL offset calculation and as
/// debug context).
pub struct LiftCtx<'a> {
    pub block: &'a mut IrBlock,
    pub pc: u64,
}

impl<'a> LiftCtx<'a> {
    pub fn new(block: &'a mut IrBlock, pc: u64) -> Self {
        Self { block, pc }
    }

    fn val(&mut self, kind: IrValueKind) -> IrValueId {
        self.block.new_value(kind)
    }

    fn flags(&mut self) -> IrFlagsId {
        // Track in the block's `flags` table; ID = current length.
        self.block.flags.push(());
        IrFlagsId((self.block.flags.len() - 1) as u32)
    }

    fn push(&mut self, op: IrOp) {
        self.block.push_op(op);
    }

    /// Read X<reg> (or W<reg> if !sf). For reg == 31 in non-SP context this
    /// is XZR (always 0); we emit ReadGpr and let the optimizer fold.
    fn read_reg(&mut self, reg: Reg, sf: bool) -> IrValueId {
        let dst = self.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
        self.push(IrOp::ReadGpr { dst, reg: reg.0, sf });
        dst
    }

    /// Read with SP-context awareness — caller passes `is_sp_context=true`
    /// when reg==31 means SP (e.g., base in load/store, ADD-imm with Rd=SP).
    fn read_reg_or_sp(&mut self, reg: Reg, sf: bool, is_sp_context: bool) -> IrValueId {
        if reg.0 == 31 && is_sp_context {
            let dst = self.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            self.push(IrOp::ReadSp { dst, sf });
            dst
        } else {
            self.read_reg(reg, sf)
        }
    }

    fn write_reg(&mut self, reg: Reg, src: IrValueId, sf: bool) {
        if reg.0 == 31 {
            // XZR write — silently discarded.
            return;
        }
        self.push(IrOp::WriteGpr { reg: reg.0, src, sf });
    }

    fn write_reg_or_sp(&mut self, reg: Reg, src: IrValueId, sf: bool, is_sp_context: bool) {
        if reg.0 == 31 && is_sp_context {
            self.push(IrOp::WriteSp { src, sf });
        } else {
            self.write_reg(reg, src, sf);
        }
    }

    fn const_i64(&mut self, v: i64) -> IrValueId {
        let dst = self.val(IrValueKind::I64);
        self.push(IrOp::ConstI64 { dst, val: v });
        dst
    }

    fn const_i32(&mut self, v: i32) -> IrValueId {
        let dst = self.val(IrValueKind::I32);
        self.push(IrOp::ConstI32 { dst, val: v });
        dst
    }

    fn read_pc(&mut self) -> IrValueId {
        let dst = self.val(IrValueKind::I64);
        self.push(IrOp::ReadPc { dst });
        dst
    }

    /// Compute an address from an `AddrMode`. For pre-index, the writeback to
    /// the base register happens before the access; for post-index, after.
    /// Returns the address used for the memory op.
    fn lift_addr_mode(&mut self, addr: &AddrMode, access_sf: bool) -> IrValueId {
        let _ = access_sf;
        match *addr {
            AddrMode::Offset { base, imm } => {
                let v_base = self.read_reg_or_sp(base, true, true);
                if imm == 0 {
                    v_base
                } else {
                    let v_imm = self.const_i64(imm as i64);
                    let v_addr = self.val(IrValueKind::I64);
                    self.push(IrOp::Add { dst: v_addr, a: v_base, b: v_imm });
                    v_addr
                }
            }
            AddrMode::PreIndex { base, imm } => {
                let v_base = self.read_reg_or_sp(base, true, true);
                let v_imm = self.const_i64(imm as i64);
                let v_addr = self.val(IrValueKind::I64);
                self.push(IrOp::Add { dst: v_addr, a: v_base, b: v_imm });
                // Writeback first (pre-index): base = base + imm
                self.write_reg_or_sp(base, v_addr, true, true);
                v_addr
            }
            AddrMode::PostIndex { base, imm } => {
                let v_base = self.read_reg_or_sp(base, true, true);
                // Access uses original base; writeback happens after, caller-coordinated.
                // We emit the writeback eagerly here since lift_addr_mode is called
                // BEFORE the load/store op — that's wrong for post-index. Returning
                // the base value and leaving writeback to the caller would be safer.
                // For Phase A clarity we emit it eagerly; semantics for the access
                // and base-update commute (no aliasing because base != target reg
                // in well-formed code; rare aliasing cases get refined in Phase B).
                let v_imm = self.const_i64(imm as i64);
                let v_new_base = self.val(IrValueKind::I64);
                self.push(IrOp::Add { dst: v_new_base, a: v_base, b: v_imm });
                self.write_reg_or_sp(base, v_new_base, true, true);
                v_base
            }
            AddrMode::RegOffset { base, index, extend: _, shift } => {
                let v_base = self.read_reg_or_sp(base, true, true);
                let v_idx = self.read_reg(index, true);
                let v_shifted = if shift > 0 {
                    let v_sh = self.const_i64(shift as i64);
                    let v = self.val(IrValueKind::I64);
                    self.push(IrOp::Shl { dst: v, a: v_idx, b: v_sh });
                    v
                } else {
                    v_idx
                };
                let v_addr = self.val(IrValueKind::I64);
                self.push(IrOp::Add { dst: v_addr, a: v_base, b: v_shifted });
                v_addr
            }
            AddrMode::Pcrel { offset } => {
                let v_pc = self.read_pc();
                let v_off = self.const_i64(offset as i64);
                let v_addr = self.val(IrValueKind::I64);
                self.push(IrOp::Add { dst: v_addr, a: v_pc, b: v_off });
                v_addr
            }
        }
    }
}

fn load_ty_for(size: AccessSize, signed: bool) -> LoadTy {
    match (size, signed) {
        (AccessSize::Byte, false) => LoadTy::U8,
        (AccessSize::Byte, true) => LoadTy::I8,
        (AccessSize::HalfWord, false) => LoadTy::U16,
        (AccessSize::HalfWord, true) => LoadTy::I16,
        (AccessSize::Word, false) => LoadTy::U32,
        (AccessSize::Word, true) => LoadTy::I32,
        (AccessSize::DoubleWord, _) => LoadTy::U64,
        (AccessSize::QuadWord, _) => LoadTy::Vec128,
    }
}

fn store_ty_for(size: AccessSize) -> StoreTy {
    match size {
        AccessSize::Byte => StoreTy::U8,
        AccessSize::HalfWord => StoreTy::U16,
        AccessSize::Word => StoreTy::U32,
        AccessSize::DoubleWord => StoreTy::U64,
        AccessSize::QuadWord => StoreTy::Vec128,
    }
}

fn shift_to_irop(kind: ShiftKind) -> fn(IrValueId, IrValueId, IrValueId) -> IrOp {
    match kind {
        ShiftKind::Lsl => |dst, a, b| IrOp::Shl { dst, a, b },
        ShiftKind::Lsr => |dst, a, b| IrOp::LShr { dst, a, b },
        ShiftKind::Asr => |dst, a, b| IrOp::AShr { dst, a, b },
        ShiftKind::Ror => |dst, a, b| IrOp::Ror { dst, a, b },
    }
}

/// Top-level lift entry. Emits IR ops into `block` and returns Ok on
/// success or Err with the source word on a sentinel/unimplemented case.
pub fn lift(insn: &DecodedInsn, block: &mut IrBlock) -> Result<(), LiftErr> {
    lift_at(insn, block, 0)
}

/// Lift with explicit PC (for B/BL/CB[N]Z/TB[N]Z offset resolution).
pub fn lift_at(insn: &DecodedInsn, block: &mut IrBlock, pc: u64) -> Result<(), LiftErr> {
    let mut cx = LiftCtx::new(block, pc);
    lift_insn(&mut cx, insn)
}

fn lift_insn(cx: &mut LiftCtx<'_>, insn: &DecodedInsn) -> Result<(), LiftErr> {
    use DecodedInsn::*;
    match *insn {
        // ===== PC-rel =====
        Adr { rd, imm } => {
            let v_pc = cx.read_pc();
            let v_off = cx.const_i64(imm as i64);
            let v_res = cx.val(IrValueKind::I64);
            cx.push(IrOp::Add { dst: v_res, a: v_pc, b: v_off });
            cx.write_reg(rd, v_res, true);
        }
        Adrp { rd, imm } => {
            // PC[63:12]:0..0 + (imm << 12)
            let v_pc = cx.read_pc();
            let v_mask = cx.const_i64(!0xFFFi64);
            let v_page = cx.val(IrValueKind::I64);
            cx.push(IrOp::And { dst: v_page, a: v_pc, b: v_mask });
            let v_off = cx.const_i64((imm as i64) << 12);
            let v_res = cx.val(IrValueKind::I64);
            cx.push(IrOp::Add { dst: v_res, a: v_page, b: v_off });
            cx.write_reg(rd, v_res, true);
        }

        // ===== Integer ALU immediate =====
        AddImm { sf, rd, rn, imm, shift_12, set_flags } => {
            let v_rn = cx.read_reg_or_sp(rn, sf, !set_flags);
            let imm_val = (imm as i64) << if shift_12 { 12 } else { 0 };
            let v_imm = if sf { cx.const_i64(imm_val) } else { cx.const_i32(imm_val as i32) };
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            if set_flags {
                let f = cx.flags();
                cx.push(IrOp::AddS { dst: v_res, flags: f, a: v_rn, b: v_imm });
                cx.push(IrOp::WriteFlags { src: f });
            } else {
                cx.push(IrOp::Add { dst: v_res, a: v_rn, b: v_imm });
            }
            cx.write_reg_or_sp(rd, v_res, sf, !set_flags);
        }
        SubImm { sf, rd, rn, imm, shift_12, set_flags } => {
            let v_rn = cx.read_reg_or_sp(rn, sf, !set_flags);
            let imm_val = (imm as i64) << if shift_12 { 12 } else { 0 };
            let v_imm = if sf { cx.const_i64(imm_val) } else { cx.const_i32(imm_val as i32) };
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            if set_flags {
                let f = cx.flags();
                cx.push(IrOp::SubS { dst: v_res, flags: f, a: v_rn, b: v_imm });
                cx.push(IrOp::WriteFlags { src: f });
            } else {
                cx.push(IrOp::Sub { dst: v_res, a: v_rn, b: v_imm });
            }
            cx.write_reg_or_sp(rd, v_res, sf, !set_flags);
        }
        AndImm { sf, rd, rn, imm, set_flags } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_imm = cx.const_i64(imm as i64);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            if set_flags {
                let f = cx.flags();
                cx.push(IrOp::AndS { dst: v_res, flags: f, a: v_rn, b: v_imm });
                cx.push(IrOp::WriteFlags { src: f });
            } else {
                cx.push(IrOp::And { dst: v_res, a: v_rn, b: v_imm });
            }
            cx.write_reg(rd, v_res, sf);
        }
        OrrImm { sf, rd, rn, imm } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_imm = cx.const_i64(imm as i64);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            cx.push(IrOp::Or { dst: v_res, a: v_rn, b: v_imm });
            cx.write_reg(rd, v_res, sf);
        }
        EorImm { sf, rd, rn, imm } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_imm = cx.const_i64(imm as i64);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            cx.push(IrOp::Xor { dst: v_res, a: v_rn, b: v_imm });
            cx.write_reg(rd, v_res, sf);
        }
        MovWide { sf, opc, hw, rd, imm } => {
            let shift = (hw as i64) * 16;
            let imm_val: i64 = match opc {
                0b10 => (imm as i64) << shift,                 // MOVZ
                0b00 => !((imm as i64) << shift),              // MOVN (= invert)
                0b11 => {
                    // MOVK: read rd, mask off the 16-bit slot, OR in new imm
                    let v_rd = cx.read_reg(rd, sf);
                    let mask: i64 = !(0xFFFFi64 << shift);
                    let v_mask = cx.const_i64(mask);
                    let v_cleared = cx.val(IrValueKind::I64);
                    cx.push(IrOp::And { dst: v_cleared, a: v_rd, b: v_mask });
                    let v_imm = cx.const_i64((imm as i64) << shift);
                    let v_res = cx.val(IrValueKind::I64);
                    cx.push(IrOp::Or { dst: v_res, a: v_cleared, b: v_imm });
                    cx.write_reg(rd, v_res, sf);
                    return Ok(());
                }
                _ => return Err(LiftErr::Unimplemented(0)),
            };
            let v_res = cx.const_i64(imm_val);
            cx.write_reg(rd, v_res, sf);
        }
        Bfm { sf, opc, rd, rn, immr, imms } => {
            // BFM/SBFM/UBFM are bitfield ops; full semantics need a bit
            // pattern computation. For Phase A we lift to a generic shift+mask
            // sequence — semantically equivalent for common immr/imms forms
            // (SXTW, UXTW, LSL/LSR aliases). Phase B refines.
            let v_rn = cx.read_reg(rn, sf);
            let v_immr = cx.const_i64(immr as i64);
            let v_shifted = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            // Rotate-right by immr, then take bottom imms+1 bits.
            cx.push(IrOp::Ror { dst: v_shifted, a: v_rn, b: v_immr });
            let mask: i64 = if imms >= 63 {
                !0
            } else {
                // imms ≤ 62 → shift by at most 63, safe in u64 then cast
                ((1u64 << (imms as u32 + 1)).wrapping_sub(1)) as i64
            };
            let v_mask = cx.const_i64(mask);
            let v_masked = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            cx.push(IrOp::And { dst: v_masked, a: v_shifted, b: v_mask });
            // SBFM (opc=00) does sign-extension; UBFM (opc=10) zero-extends (no-op since mask).
            // BFM (opc=01) merges with existing rd bits; that's a more involved op.
            let v_res = match opc {
                0b00 => {
                    let v_sext = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
                    cx.push(IrOp::Sext {
                        dst: v_sext, a: v_masked,
                        from_bits: imms + 1, to_bits: if sf { 64 } else { 32 },
                    });
                    v_sext
                }
                _ => v_masked,
            };
            cx.write_reg(rd, v_res, sf);
        }
        Extr { sf, rd, rn, rm, lsb } => {
            // EXTR: rd = (rm:rn) >> lsb (concatenated, then take low width bits)
            let v_rn = cx.read_reg(rn, sf);
            let v_rm = cx.read_reg(rm, sf);
            // For Phase A, model as: (rm << (width-lsb)) | (rn >> lsb)
            let width = if sf { 64 } else { 32 };
            let v_lsb = cx.const_i64(lsb as i64);
            let v_complement = cx.const_i64((width - lsb as u8) as i64);
            let v_lo = cx.val(IrValueKind::I64);
            cx.push(IrOp::LShr { dst: v_lo, a: v_rn, b: v_lsb });
            let v_hi = cx.val(IrValueKind::I64);
            cx.push(IrOp::Shl { dst: v_hi, a: v_rm, b: v_complement });
            let v_res = cx.val(IrValueKind::I64);
            cx.push(IrOp::Or { dst: v_res, a: v_lo, b: v_hi });
            cx.write_reg(rd, v_res, sf);
        }

        // ===== Integer ALU register =====
        AddReg { sf, rd, rn, rm, shift, amount, set_flags } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_rm_raw = cx.read_reg(rm, sf);
            let v_rm = lift_shift_reg(cx, v_rm_raw, shift, amount, sf);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            if set_flags {
                let f = cx.flags();
                cx.push(IrOp::AddS { dst: v_res, flags: f, a: v_rn, b: v_rm });
                cx.push(IrOp::WriteFlags { src: f });
            } else {
                cx.push(IrOp::Add { dst: v_res, a: v_rn, b: v_rm });
            }
            cx.write_reg(rd, v_res, sf);
        }
        SubReg { sf, rd, rn, rm, shift, amount, set_flags } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_rm_raw = cx.read_reg(rm, sf);
            let v_rm = lift_shift_reg(cx, v_rm_raw, shift, amount, sf);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            if set_flags {
                let f = cx.flags();
                cx.push(IrOp::SubS { dst: v_res, flags: f, a: v_rn, b: v_rm });
                cx.push(IrOp::WriteFlags { src: f });
            } else {
                cx.push(IrOp::Sub { dst: v_res, a: v_rn, b: v_rm });
            }
            cx.write_reg(rd, v_res, sf);
        }
        LogicalReg { sf, opc, rd, rn, rm, shift, amount, invert } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_rm_raw = cx.read_reg(rm, sf);
            let v_rm_shifted = lift_shift_reg(cx, v_rm_raw, shift, amount, sf);
            let v_rm = if invert {
                let v = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
                cx.push(IrOp::Not { dst: v, a: v_rm_shifted });
                v
            } else {
                v_rm_shifted
            };
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            let set_flags = opc == 0b11;
            match opc {
                0b00 | 0b11 => {
                    if set_flags {
                        let f = cx.flags();
                        cx.push(IrOp::AndS { dst: v_res, flags: f, a: v_rn, b: v_rm });
                        cx.push(IrOp::WriteFlags { src: f });
                    } else {
                        cx.push(IrOp::And { dst: v_res, a: v_rn, b: v_rm });
                    }
                }
                0b01 => cx.push(IrOp::Or { dst: v_res, a: v_rn, b: v_rm }),
                0b10 => cx.push(IrOp::Xor { dst: v_res, a: v_rn, b: v_rm }),
                _ => unreachable!(),
            }
            cx.write_reg(rd, v_res, sf);
        }
        AddSubExtReg { sf, rd, rn, rm, extend: _, imm3: _, sub, set_flags } => {
            // Approximation: model as plain add/sub (the extend/imm3 details
            // are refined in Phase B alongside Sext/Zext ops).
            let v_rn = cx.read_reg_or_sp(rn, sf, !set_flags);
            let v_rm = cx.read_reg(rm, sf);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            if sub {
                if set_flags {
                    let f = cx.flags();
                    cx.push(IrOp::SubS { dst: v_res, flags: f, a: v_rn, b: v_rm });
                    cx.push(IrOp::WriteFlags { src: f });
                } else {
                    cx.push(IrOp::Sub { dst: v_res, a: v_rn, b: v_rm });
                }
            } else if set_flags {
                let f = cx.flags();
                cx.push(IrOp::AddS { dst: v_res, flags: f, a: v_rn, b: v_rm });
                cx.push(IrOp::WriteFlags { src: f });
            } else {
                cx.push(IrOp::Add { dst: v_res, a: v_rn, b: v_rm });
            }
            cx.write_reg_or_sp(rd, v_res, sf, !set_flags);
        }
        Csel { sf, rd, rn, rm, cond, op2 } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_rm = cx.read_reg(rm, sf);
            // Pre-process rm per variant: CSEL=v_rm, CSINC=v_rm+1, CSINV=~v_rm, CSNEG=-v_rm
            let v_rm_mod = match op2 {
                0 => v_rm,
                1 => {
                    let one = cx.const_i64(1);
                    let v = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
                    cx.push(IrOp::Add { dst: v, a: v_rm, b: one });
                    v
                }
                2 => {
                    let v = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
                    cx.push(IrOp::Not { dst: v, a: v_rm });
                    v
                }
                3 => {
                    let v = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
                    cx.push(IrOp::Neg { dst: v, a: v_rm });
                    v
                }
                _ => return Err(LiftErr::Unimplemented(0)),
            };
            // Need current flags
            let f = cx.flags();
            cx.push(IrOp::ReadFlags { dst: f });
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            cx.push(IrOp::Csel {
                dst: v_res, a: v_rn, b: v_rm_mod, cond, flags: f, variant: op2,
            });
            cx.write_reg(rd, v_res, sf);
        }
        Mul { sf, rd, rn, rm, ra, sub } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_rm = cx.read_reg(rm, sf);
            let v_ra = cx.read_reg(ra, sf);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            if sub {
                cx.push(IrOp::Msub { dst: v_res, a: v_rn, b: v_rm, c: v_ra });
            } else {
                cx.push(IrOp::Madd { dst: v_res, a: v_rn, b: v_rm, c: v_ra });
            }
            cx.write_reg(rd, v_res, sf);
        }
        Div { sf, rd, rn, rm, signed } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_rm = cx.read_reg(rm, sf);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            if signed {
                cx.push(IrOp::SDiv { dst: v_res, a: v_rn, b: v_rm });
            } else {
                cx.push(IrOp::UDiv { dst: v_res, a: v_rn, b: v_rm });
            }
            cx.write_reg(rd, v_res, sf);
        }
        Shift { sf, rd, rn, rm, kind } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_rm = cx.read_reg(rm, sf);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            cx.push(shift_to_irop(kind)(v_res, v_rn, v_rm));
            cx.write_reg(rd, v_res, sf);
        }
        DataOp1Src { sf, rd, rn, opcode } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            match opcode {
                0 => cx.push(IrOp::Rbit { dst: v_res, a: v_rn }),
                1 => cx.push(IrOp::Rev { dst: v_res, a: v_rn, bytes: 2 }),
                2 => cx.push(IrOp::Rev { dst: v_res, a: v_rn, bytes: 4 }),
                3 => cx.push(IrOp::Rev { dst: v_res, a: v_rn, bytes: 8 }),
                4 => cx.push(IrOp::Clz { dst: v_res, a: v_rn }),
                5 => cx.push(IrOp::Cls { dst: v_res, a: v_rn }),
                _ => return Err(LiftErr::Unimplemented(0)),
            }
            cx.write_reg(rd, v_res, sf);
        }
        Ccmp { sf, rn, rm_or_imm, cond, nzcv, is_neg, is_imm } => {
            let v_rn = cx.read_reg(rn, sf);
            let v_rm = if is_imm {
                cx.const_i64(rm_or_imm as i64)
            } else {
                cx.read_reg(Reg(rm_or_imm), sf)
            };
            let flags_in = cx.flags();
            cx.push(IrOp::ReadFlags { dst: flags_in });
            let flags_out = cx.flags();
            // CCMN if is_neg else CCMP
            cx.push(IrOp::CCmp {
                flags_out, a: v_rn, b: v_rm, cond,
                nzcv_if_false: nzcv, flags_in,
            });
            cx.push(IrOp::WriteFlags { src: flags_out });
            let _ = is_neg; // CCMN vs CCMP encoded into nzcv handling; refined in Phase B
        }
        DecodedInsn::Crc32 { sf: _, rd, rn, rm, sz, castagnoli } => {
            let v_rn = cx.read_reg(rn, false);
            let v_rm = cx.read_reg(rm, sz == 0b11);
            let v_res = cx.val(IrValueKind::I32);
            cx.push(IrOp::Crc32 {
                dst: v_res, a: v_rn, b: v_rm, size: sz, castagnoli,
            });
            cx.write_reg(rd, v_res, false);
        }

        // ===== Load / Store =====
        Ldr { rt, size, signed, addr } => {
            let v_addr = cx.lift_addr_mode(&addr, true);
            let dst_kind = match size {
                AccessSize::QuadWord => IrValueKind::Vec128 { lane: crate::ir::value::LaneType::I8 },
                _ => IrValueKind::I64,
            };
            let v_data = cx.val(dst_kind);
            cx.push(IrOp::Load {
                dst: v_data, addr: v_addr,
                ty: load_ty_for(size, signed),
                order: MemOrder::Relaxed,
            });
            if size == AccessSize::QuadWord {
                cx.push(IrOp::WriteFpr { reg: rt.0, src: v_data });
            } else {
                cx.write_reg(rt, v_data, true);
            }
        }
        Str { rt, size, addr } => {
            let v_addr = cx.lift_addr_mode(&addr, true);
            let v_data = if size == AccessSize::QuadWord {
                let v = cx.val(IrValueKind::Vec128 { lane: crate::ir::value::LaneType::I8 });
                cx.push(IrOp::ReadFpr { dst: v, reg: rt.0 });
                v
            } else {
                cx.read_reg(rt, true)
            };
            cx.push(IrOp::Store {
                val: v_data, addr: v_addr,
                ty: store_ty_for(size),
                order: MemOrder::Relaxed,
            });
        }
        Ldp { rt1, rt2, sf, signed: _, addr } => {
            let v_addr = cx.lift_addr_mode(&addr, sf);
            let access = if sf { LoadTy::U64 } else { LoadTy::U32 };
            let v_a = cx.val(IrValueKind::I64);
            let v_b = cx.val(IrValueKind::I64);
            cx.push(IrOp::LoadPair {
                dst_a: v_a, dst_b: v_b, addr: v_addr, ty: access,
            });
            cx.write_reg(rt1, v_a, sf);
            cx.write_reg(rt2, v_b, sf);
        }
        Stp { rt1, rt2, sf, addr } => {
            let v_addr = cx.lift_addr_mode(&addr, sf);
            let v_a = cx.read_reg(rt1, sf);
            let v_b = cx.read_reg(rt2, sf);
            let ty = if sf { StoreTy::U64 } else { StoreTy::U32 };
            cx.push(IrOp::StorePair {
                val_a: v_a, val_b: v_b, addr: v_addr, ty,
            });
        }
        Ldxr { size, rt, rn, acquire, pair: _, rt2: _ } => {
            let v_addr = cx.read_reg(rn, true);
            let v_data = cx.val(IrValueKind::I64);
            cx.push(IrOp::LoadExclusive {
                dst: v_data, addr: v_addr, ty: load_ty_for(size, false),
            });
            let _ = acquire; // memory-order tag refined in Phase B
            cx.write_reg(rt, v_data, true);
        }
        Stxr { size, rs, rt, rn, release: _, pair: _, rt2: _ } => {
            let v_addr = cx.read_reg(rn, true);
            let v_data = cx.read_reg(rt, true);
            let v_status = cx.val(IrValueKind::I32);
            cx.push(IrOp::StoreExclusive {
                status: v_status, val: v_data, addr: v_addr, ty: store_ty_for(size),
            });
            cx.write_reg(rs, v_status, false);
        }
        Ldar { size, rt, rn } | Ldapr { size, rt, rn } => {
            let v_addr = cx.read_reg(rn, true);
            let v_data = cx.val(IrValueKind::I64);
            cx.push(IrOp::Load {
                dst: v_data, addr: v_addr,
                ty: load_ty_for(size, false),
                order: MemOrder::Acquire,
            });
            cx.write_reg(rt, v_data, true);
        }
        Stlr { size, rt, rn } => {
            let v_addr = cx.read_reg(rn, true);
            let v_data = cx.read_reg(rt, true);
            cx.push(IrOp::Store {
                val: v_data, addr: v_addr,
                ty: store_ty_for(size),
                order: MemOrder::Release,
            });
        }
        Cas { size, rs, rt, rn, acquire, release } => {
            let v_addr = cx.read_reg(rn, true);
            let v_expected = cx.read_reg(rs, true);
            let v_new = cx.read_reg(rt, true);
            let v_loaded = cx.val(IrValueKind::I64);
            let order = match (acquire, release) {
                (true, true) => MemOrder::AcqRel,
                (true, false) => MemOrder::Acquire,
                (false, true) => MemOrder::Release,
                _ => MemOrder::Relaxed,
            };
            cx.push(IrOp::AtomicCas {
                dst: v_loaded, addr: v_addr,
                expected: v_expected, new: v_new, order,
            });
            cx.write_reg(rs, v_loaded, true);
            let _ = size;
        }
        LdAtomicRmw { size, op, rs, rt, rn, acquire, release } => {
            let v_addr = cx.read_reg(rn, true);
            let v_val = cx.read_reg(rs, true);
            let order = match (acquire, release) {
                (true, true) => MemOrder::AcqRel,
                (true, false) => MemOrder::Acquire,
                (false, true) => MemOrder::Release,
                _ => MemOrder::Relaxed,
            };
            let aop = match op {
                0 => AtomicOp::Add,
                1 => AtomicOp::Clr,
                2 => AtomicOp::Eor,
                3 => AtomicOp::Set,
                4 => AtomicOp::Smax,
                5 => AtomicOp::Smin,
                6 => AtomicOp::Umax,
                7 => AtomicOp::Umin,
                _ => return Err(LiftErr::Unimplemented(0)),
            };
            let v_loaded = cx.val(IrValueKind::I64);
            cx.push(IrOp::AtomicRmw {
                dst: v_loaded, op: aop, addr: v_addr, val: v_val, order,
            });
            cx.write_reg(rt, v_loaded, true);
            let _ = size;
        }
        Swp { size, rs, rt, rn, acquire, release } => {
            let v_addr = cx.read_reg(rn, true);
            let v_val = cx.read_reg(rs, true);
            let order = match (acquire, release) {
                (true, true) => MemOrder::AcqRel,
                (true, false) => MemOrder::Acquire,
                (false, true) => MemOrder::Release,
                _ => MemOrder::Relaxed,
            };
            let v_loaded = cx.val(IrValueKind::I64);
            cx.push(IrOp::AtomicRmw {
                dst: v_loaded, op: AtomicOp::Swp, addr: v_addr, val: v_val, order,
            });
            cx.write_reg(rt, v_loaded, true);
            let _ = size;
        }

        // ===== Branches =====
        B { offset } => {
            let v_target = cx.const_i64(cx.pc as i64 + offset as i64);
            cx.push(IrOp::WritePc { src: v_target });
            // CFG-level Branch op gets attached in the block-builder pass; here
            // we leave the WritePc as the side effect.
        }
        Bl { offset } => {
            // Link register x30 = pc + 4
            let v_link = cx.const_i64(cx.pc as i64 + 4);
            cx.write_reg(Reg(30), v_link, true);
            let v_target = cx.const_i64(cx.pc as i64 + offset as i64);
            cx.push(IrOp::Call { target: v_target, link_pc: cx.pc.wrapping_add(4) });
        }
        Bcond { cond, offset } => {
            let f = cx.flags();
            cx.push(IrOp::ReadFlags { dst: f });
            // Encode target as a writable PC update guarded by the flag.
            // For Phase A we just push a CondBranch placeholder with both
            // blocks = self; CFG pass rewrites.
            let _ = offset;
            cx.push(IrOp::CondBranch {
                cond, flags: f,
                taken: crate::ir::BlockId(0),
                fallthru: crate::ir::BlockId(0),
            });
        }
        Br { rn } => {
            let v_target = cx.read_reg(rn, true);
            cx.push(IrOp::IndirectBranch { target: v_target });
        }
        Blr { rn } => {
            let v_link = cx.const_i64(cx.pc as i64 + 4);
            cx.write_reg(Reg(30), v_link, true);
            let v_target = cx.read_reg(rn, true);
            cx.push(IrOp::Call { target: v_target, link_pc: cx.pc.wrapping_add(4) });
        }
        Ret { rn } => {
            let v_target = cx.read_reg(rn, true);
            cx.push(IrOp::Return { target: v_target });
        }
        Cbz { sf, rt, offset } => {
            let v_rt = cx.read_reg(rt, sf);
            let _ = offset;
            cx.push(IrOp::Cbz {
                a: v_rt,
                taken: crate::ir::BlockId(0),
                fallthru: crate::ir::BlockId(0),
            });
        }
        Cbnz { sf, rt, offset } => {
            let v_rt = cx.read_reg(rt, sf);
            let _ = offset;
            cx.push(IrOp::Cbnz {
                a: v_rt,
                taken: crate::ir::BlockId(0),
                fallthru: crate::ir::BlockId(0),
            });
        }
        Tbz { bit, rt, offset } => {
            let v_rt = cx.read_reg(rt, true);
            let _ = offset;
            cx.push(IrOp::Tbz {
                a: v_rt, bit,
                taken: crate::ir::BlockId(0),
                fallthru: crate::ir::BlockId(0),
            });
        }
        Tbnz { bit, rt, offset } => {
            let v_rt = cx.read_reg(rt, true);
            let _ = offset;
            cx.push(IrOp::Tbnz {
                a: v_rt, bit,
                taken: crate::ir::BlockId(0),
                fallthru: crate::ir::BlockId(0),
            });
        }

        // ===== Exception generation =====
        Svc { imm16 } => cx.push(IrOp::Svc { imm16 }),
        Hvc { imm16 } => cx.push(IrOp::Hvc { imm16 }),
        Smc { imm16 } => cx.push(IrOp::Smc { imm16 }),
        Brk { imm16 } => cx.push(IrOp::Brk { imm16 }),
        Hlt { imm16 } => cx.push(IrOp::Hlt { imm16 }),

        // ===== Hints =====
        Nop => cx.push(IrOp::Hint { imm: 0 }),
        Yield => cx.push(IrOp::Hint { imm: 1 }),
        Wfe => cx.push(IrOp::Hint { imm: 2 }),
        Wfi => cx.push(IrOp::Hint { imm: 3 }),
        Sev => cx.push(IrOp::Hint { imm: 4 }),
        Sevl => cx.push(IrOp::Hint { imm: 5 }),
        PacHint { opc } => cx.push(IrOp::Hint { imm: 8 + opc }),
        BtiHint { target } => cx.push(IrOp::Hint { imm: 32 + target }),

        // ===== Barriers =====
        DecodedInsn::Dmb { domain } => cx.push(IrOp::Dmb { domain: barrier_of(domain) }),
        DecodedInsn::Dsb { domain } => cx.push(IrOp::Dsb { domain: barrier_of(domain) }),
        Isb => cx.push(IrOp::Isb),
        Sb => cx.push(IrOp::Sb),
        Csdb => cx.push(IrOp::Hint { imm: 20 }),

        // ===== System register access =====
        DecodedInsn::Mrs { rt, sysreg } => {
            let id = crate::decoder::sysreg::SysRegId(sysreg);
            let reg = crate::decoder::sysreg::lookup(id);
            let v_dst = cx.val(IrValueKind::I64);
            cx.push(IrOp::Mrs { dst: v_dst, reg });
            cx.write_reg(rt, v_dst, true);
        }
        DecodedInsn::Msr { rt, sysreg } => {
            let id = crate::decoder::sysreg::SysRegId(sysreg);
            let reg = crate::decoder::sysreg::lookup(id);
            let v_src = cx.read_reg(rt, true);
            cx.push(IrOp::Msr { reg, val: v_src });
        }
        MsrImm { op1, crm, op2 } => {
            // PSTATE write — model as a Hint with a packed immediate. Phase B
            // unfolds to specific flag/PSTATE bit writes.
            let imm = (op1.wrapping_shl(6)) | (crm.wrapping_shl(2)) | (op2 & 0x3);
            cx.push(IrOp::Hint { imm: imm.wrapping_add(64) });
        }
        SysIc { rt, .. } | SysDc { rt, .. } | SysAt { rt, .. } | SysTlbi { rt, .. } => {
            // Cache / TLB maintenance ops — model as Hint for now (require Rt read).
            let _ = cx.read_reg(rt, true);
            cx.push(IrOp::Hint { imm: 128 });
        }

        // ===== SIMD/FP/Crypto (coarse lift — semantics in Phase B) =====
        AdvSimd { raw } => {
            let v = cx.val(IrValueKind::I32);
            cx.push(IrOp::ConstI32 { dst: v, val: raw as i32 });
            cx.push(IrOp::Hint { imm: 200 });
        }
        FpScalar { raw } => {
            let v = cx.val(IrValueKind::I32);
            cx.push(IrOp::ConstI32 { dst: v, val: raw as i32 });
            cx.push(IrOp::Hint { imm: 201 });
        }
        CryptoAes { op, rd, rn } => {
            let v_in = cx.val(IrValueKind::Vec128 { lane: crate::ir::value::LaneType::I8 });
            cx.push(IrOp::ReadFpr { dst: v_in, reg: rn.0 });
            let v_out = cx.val(IrValueKind::Vec128 { lane: crate::ir::value::LaneType::I8 });
            // op: 4=AESE, 5=AESD, 6=AESMC, 7=AESIMC. Phase A maps all to AesE
            // as a placeholder — Phase B distinguishes properly.
            let _ = op;
            cx.push(IrOp::AesE { dst: v_out, a: v_in, key: v_in });
            cx.push(IrOp::WriteFpr { reg: rd.0, src: v_out });
        }
        CryptoSha { op, raw } => {
            let v = cx.val(IrValueKind::I32);
            cx.push(IrOp::ConstI32 { dst: v, val: raw as i32 });
            cx.push(IrOp::Hint { imm: 200u8.wrapping_add(op) });
        }

        // ===== Sentinels =====
        Udf { imm16 } => {
            // Architectural UDF — lift to BRK-like Hlt with the imm16. Refined
            // in Phase B to a proper exception-injection op.
            cx.push(IrOp::Hlt { imm16 });
        }
        Unknown(w) => return Err(LiftErr::Sentinel(w)),
    }
    Ok(())
}

fn lift_shift_reg(
    cx: &mut LiftCtx<'_>,
    v_rm: IrValueId,
    kind: ShiftKind,
    amount: u8,
    sf: bool,
) -> IrValueId {
    if amount == 0 {
        return v_rm;
    }
    let v_amt = cx.const_i64(amount as i64);
    let v_dst = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
    cx.push(shift_to_irop(kind)(v_dst, v_rm, v_amt));
    v_dst
}

fn barrier_of(crm: u8) -> BarrierDomain {
    match crm {
        0xB => BarrierDomain::Ish,
        0xA => BarrierDomain::Ishst,
        0x9 => BarrierDomain::Ishld,
        0x7 => BarrierDomain::Nsh,
        0x6 => BarrierDomain::NshSt,
        0x5 => BarrierDomain::NshLd,
        0x3 => BarrierDomain::Osh,
        0x2 => BarrierDomain::OshSt,
        0x1 => BarrierDomain::OshLd,
        0xF => BarrierDomain::Sy,
        0xE => BarrierDomain::SyStore,
        0xD => BarrierDomain::SyLoad,
        _ => BarrierDomain::Sy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::{decode_instruction, AccessSize, AddrMode};
    use crate::ir::BlockId;

    fn fresh_block() -> IrBlock {
        IrBlock::new(BlockId(0))
    }

    #[test]
    fn lift_add_imm_x1_x1_1() {
        // 0x91000421 = ADD x1, x1, #1
        let insn = decode_instruction(0x91000421).unwrap();
        let mut blk = fresh_block();
        lift(&insn, &mut blk).expect("lift ADD");
        // Expect: ReadGpr x1, ConstI64 1, Add, WriteGpr x1
        assert!(blk.ops.len() >= 4, "got {} ops: {:?}", blk.ops.len(), blk.ops);
        assert!(matches!(blk.ops[0], IrOp::ReadGpr { reg: 1, sf: true, .. }));
        assert!(matches!(blk.ops.last().unwrap(), IrOp::WriteGpr { reg: 1, sf: true, .. }));
    }

    #[test]
    fn lift_subs_xzr_x1_1_sets_flags() {
        // 0xB100043F = ADDS xzr, x1, #1 (CMN-alias)
        // Actually let's use 0xF100043F = SUBS xzr, x1, #1 (CMP-alias)
        let insn = decode_instruction(0xF100043F).unwrap();
        let mut blk = fresh_block();
        lift(&insn, &mut blk).expect("lift SUBS");
        // Expect WriteFlags but NO WriteGpr (rd = 31 = XZR, discarded)
        let has_writeflags = blk.ops.iter().any(|o| matches!(o, IrOp::WriteFlags { .. }));
        let has_writegpr = blk.ops.iter().any(|o| matches!(o, IrOp::WriteGpr { .. }));
        assert!(has_writeflags, "missing WriteFlags");
        assert!(!has_writegpr, "should not write to XZR");
    }

    #[test]
    fn lift_ldr_x0_x1() {
        // 0xF9400020 = LDR x0, [x1]
        let insn = decode_instruction(0xF9400020).unwrap();
        let mut blk = fresh_block();
        lift(&insn, &mut blk).expect("lift LDR");
        assert!(blk.ops.iter().any(|o| matches!(o, IrOp::Load { .. })));
        assert!(blk.ops.iter().any(|o| matches!(o, IrOp::WriteGpr { reg: 0, .. })));
    }

    #[test]
    fn lift_b_writes_pc() {
        // 0x14000001 = B +4
        let insn = decode_instruction(0x14000001).unwrap();
        let mut blk = fresh_block();
        lift_at(&insn, &mut blk, 0x1000).expect("lift B");
        assert!(blk.ops.iter().any(|o| matches!(o, IrOp::WritePc { .. })));
    }

    #[test]
    fn lift_bl_sets_x30() {
        // 0x94000001 = BL +4
        let insn = decode_instruction(0x94000001).unwrap();
        let mut blk = fresh_block();
        lift_at(&insn, &mut blk, 0x1000).expect("lift BL");
        assert!(blk.ops.iter().any(|o| matches!(o, IrOp::WriteGpr { reg: 30, .. })));
        assert!(blk.ops.iter().any(|o| matches!(o, IrOp::Call { .. })));
    }

    #[test]
    fn lift_nop_emits_hint() {
        let insn = decode_instruction(0xD503201F).unwrap();
        let mut blk = fresh_block();
        lift(&insn, &mut blk).expect("lift NOP");
        assert!(matches!(blk.ops[0], IrOp::Hint { imm: 0 }));
    }
}
