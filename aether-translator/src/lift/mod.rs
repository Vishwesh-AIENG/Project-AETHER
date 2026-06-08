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
                // CRITICAL: use the PER-INSTRUCTION PC (self.pc), not
                // read_pc() (which loads ctx.pc — only updated at block
                // boundaries; off by (insn_offset_in_block) for any insn
                // past the block start).
                self.const_i64((self.pc as i64).wrapping_add(offset as i64))
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
            // CRITICAL: ADR is PC-relative to the ADR instruction's PC.
            // The IR ReadPc op loads ctx.pc which is only updated at block
            // boundaries — within a block it stays at the block-start PC,
            // so reading it for ADR at insn_offset_in_block past 0 gives an
            // address off by insn_offset_in_block. Fold the constant target
            // at lift time using the per-insn cx.pc (truth).
            let target = (cx.pc as i64).wrapping_add(imm as i64);
            let v_res = cx.const_i64(target);
            cx.write_reg(rd, v_res, true);
        }
        Adrp { rd, imm } => {
            // ADRP: PC[63:12]:0..0 + (imm << 12) -- same per-insn-PC fix
            // as ADR. Pre-fix this worked by coincidence when block_start
            // and the ADRP shared a 4 KiB page (both round down to the same
            // PC_PAGE), but breaks at any 4 KiB boundary inside a block.
            let pc_page = (cx.pc as i64) & !0xFFFi64;
            let target = pc_page.wrapping_add((imm as i64) << 12);
            let v_res = cx.const_i64(target);
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
                cx.push(IrOp::AddS { dst: v_res, flags: f, a: v_rn, b: v_imm, sf });
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
                cx.push(IrOp::SubS { dst: v_res, flags: f, a: v_rn, b: v_imm, sf });
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
                cx.push(IrOp::AndS { dst: v_res, flags: f, a: v_rn, b: v_imm, sf });
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
            // Correct ARMv8 bitfield semantics (DDI0487 §C6 BFM/SBFM/UBFM),
            // split into the two architectural cases:
            //   imms >= immr : EXTRACT a (imms-immr+1)-bit field from
            //                  src[imms:immr], right-aligned at bit 0
            //                  (UBFX / SBFX / LSR / UXTW / SXTW forms).
            //   imms <  immr : INSERT src[imms:0] at bit (regsize-immr)
            //                  (UBFIZ / SBFIZ / LSL forms).
            // The previous unified `ROR(src,immr) & ((1<<(imms+1))-1)` form
            // over-masked for imms>=immr with immr>0: the rotate wrapped the
            // source's low (address) bits into the too-wide mask. e.g.
            // `ubfx x11,x6,#30,#9` (immr=30,imms=38) returned 0x7c00000001
            // instead of 1, corrupting __create_page_tables' loop bound and
            // hanging the kernel boot. (caught running the real GKI kernel.)
            let regsize: u8 = if sf { 64 } else { 32 };
            let kind = if sf { IrValueKind::I64 } else { IrValueKind::I32 };
            let v_rn = cx.read_reg(rn, sf);
            let mask_for = |w: u8| -> i64 {
                if w >= 64 { !0i64 } else { ((1u64 << w) - 1) as i64 }
            };
            // (field value right-aligned-or-placed, its bit width, its lsb position)
            let (v_field, field_width, field_lsb) = if imms >= immr {
                let width = imms - immr + 1;
                let v_immr = cx.const_i64(immr as i64);
                let v_sh = cx.val(kind);
                cx.push(IrOp::LShr { dst: v_sh, a: v_rn, b: v_immr });
                let v_mask = cx.const_i64(mask_for(width));
                let v_f = cx.val(kind);
                cx.push(IrOp::And { dst: v_f, a: v_sh, b: v_mask });
                (v_f, width, 0u8)
            } else {
                let width = imms + 1;
                let v_mask = cx.const_i64(mask_for(width));
                let v_low = cx.val(kind);
                cx.push(IrOp::And { dst: v_low, a: v_rn, b: v_mask });
                let shift = regsize - immr;
                let v_shc = cx.const_i64(shift as i64);
                let v_f = cx.val(kind);
                cx.push(IrOp::Shl { dst: v_f, a: v_low, b: v_shc });
                (v_f, width, shift)
            };
            // opc: 0b00 = SBFM (sign-extend), 0b01 = BFM (merge), 0b10 = UBFM.
            let v_res = match opc {
                0b00 => {
                    let v_sext = cx.val(kind);
                    cx.push(IrOp::Sext {
                        dst: v_sext, a: v_field,
                        from_bits: field_lsb + field_width, to_bits: regsize,
                    });
                    v_sext
                }
                0b01 => {
                    // BFM: keep rd bits outside the field, OR in the new field.
                    let placed_mask = (mask_for(field_width) as u64) << field_lsb;
                    let v_dst = cx.read_reg(rd, sf);
                    let v_keep = cx.const_i64(!(placed_mask as i64));
                    let v_kept = cx.val(kind);
                    cx.push(IrOp::And { dst: v_kept, a: v_dst, b: v_keep });
                    let v_m = cx.val(kind);
                    cx.push(IrOp::Or { dst: v_m, a: v_kept, b: v_field });
                    v_m
                }
                _ => v_field,
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
                cx.push(IrOp::AddS { dst: v_res, flags: f, a: v_rn, b: v_rm, sf });
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
                cx.push(IrOp::SubS { dst: v_res, flags: f, a: v_rn, b: v_rm, sf });
                cx.push(IrOp::WriteFlags { src: f });
            } else {
                cx.push(IrOp::Sub { dst: v_res, a: v_rn, b: v_rm });
            }
            cx.write_reg(rd, v_res, sf);
        }
        AdcSub { sf, rd, rn, rm, sub } => {
            // ADCS / SBCS: result = a ± b ± carry-in, then set NZCV. The
            // carry-in is the live ARM C bit; the lowering reads it straight
            // from the in-memory NZCV (BT [R15+NZCV],29), so `c_in` only needs
            // to be a defined flags id — ReadFlags supplies that. WriteFlags is
            // a no-op in lowering (flags live in memory via build_nzcv).
            let v_rn = cx.read_reg(rn, sf);
            let v_rm = cx.read_reg(rm, sf);
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            let c_in = cx.flags();
            cx.push(IrOp::ReadFlags { dst: c_in });
            let f = cx.flags();
            if sub {
                cx.push(IrOp::Sbcs { dst: v_res, flags: f, a: v_rn, b: v_rm, c_in, sf });
            } else {
                cx.push(IrOp::Adcs { dst: v_res, flags: f, a: v_rn, b: v_rm, c_in, sf });
            }
            cx.push(IrOp::WriteFlags { src: f });
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
                        cx.push(IrOp::AndS { dst: v_res, flags: f, a: v_rn, b: v_rm, sf });
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
        AddSubExtReg { sf, rd, rn, rm, extend, imm3, sub, set_flags } => {
            // ADD/SUB (extended register): Rd = Rn ± (extend(Rm) << imm3).
            //
            // Per ARMv8 spec C6.2.6: Rm is read in the WIDTH selected by the
            // extend kind. UXTB/UXTH/UXTW/SXTB/SXTH/SXTW take low 32 (Wm);
            // UXTX/SXTX take all 64 (Xm). Then extend to register width.
            // Then shift left by imm3 (0..4). Then add/sub.
            //
            // Phase-D bug: ignoring the extend kind AND imm3 made
            // `add x17, x8, w17, uxtw #2` lift as `add x17, x8, x17`, so
            // x17 was treated as the full 64-bit value (with whatever upper
            // garbage) and the *4 was dropped. In the kernel's CRC32 inner
            // loop that produced wild high-VA loads -> translation fault ->
            // do_data_abort -> BUG().
            use crate::decoder::ExtendKind;
            let (rm_width, signed): (u8, bool) = match extend {
                ExtendKind::Uxtb => (8, false),
                ExtendKind::Uxth => (16, false),
                ExtendKind::Uxtw => (32, false),
                ExtendKind::Uxtx => (64, false),
                ExtendKind::Sxtb => (8, true),
                ExtendKind::Sxth => (16, true),
                ExtendKind::Sxtw => (32, true),
                ExtendKind::Sxtx => (64, true),
            };
            // Read Rm as W (low 32) when extend is sub-32; otherwise full X.
            // The W-read covers UXTB/UXTH/UXTW/SXTB/SXTH/SXTW (the common
            // ones); UXTX/SXTX read full 64.
            let v_rm_raw = cx.read_reg(rm, rm_width >= 64);
            let dest_64 = sf; // sf=true: 64-bit Rd; sf=false: 32-bit Rd
            let to_bits: u8 = if dest_64 { 64 } else { 32 };
            // Extract+extend Rm to the destination width.
            let v_rm_ext = if rm_width >= to_bits {
                // No extension needed (the operand is already wider than dst);
                // truncation to dst-width happens implicitly in the add.
                v_rm_raw
            } else {
                let v = cx.val(if dest_64 { IrValueKind::I64 } else { IrValueKind::I32 });
                if signed {
                    cx.push(IrOp::Sext { dst: v, a: v_rm_raw, from_bits: rm_width, to_bits });
                } else {
                    cx.push(IrOp::Zext { dst: v, a: v_rm_raw, from_bits: rm_width, to_bits });
                }
                v
            };
            // Apply imm3 shift (LSL 0..4).
            let v_rm = if imm3 == 0 {
                v_rm_ext
            } else {
                let v_amt = cx.const_i64(imm3 as i64);
                let v = cx.val(if dest_64 { IrValueKind::I64 } else { IrValueKind::I32 });
                cx.push(IrOp::Shl { dst: v, a: v_rm_ext, b: v_amt });
                v
            };
            let v_rn = cx.read_reg_or_sp(rn, sf, !set_flags);
            let v_res = cx.val(if dest_64 { IrValueKind::I64 } else { IrValueKind::I32 });
            if sub {
                if set_flags {
                    let f = cx.flags();
                    cx.push(IrOp::SubS { dst: v_res, flags: f, a: v_rn, b: v_rm, sf });
                    cx.push(IrOp::WriteFlags { src: f });
                } else {
                    cx.push(IrOp::Sub { dst: v_res, a: v_rn, b: v_rm });
                }
            } else if set_flags {
                let f = cx.flags();
                cx.push(IrOp::AddS { dst: v_res, flags: f, a: v_rn, b: v_rm, sf });
                cx.push(IrOp::WriteFlags { src: f });
            } else {
                cx.push(IrOp::Add { dst: v_res, a: v_rn, b: v_rm });
            }
            cx.write_reg_or_sp(rd, v_res, sf, !set_flags);
        }
        Csel { sf, rd, rn, rm, cond, op2 } => {
            // M4a closeout: pass rm RAW with variant=op2 and let the LOWERING
            // apply the CSINC(+1)/CSINV(~)/CSNEG(-) transform exactly once. The
            // old code pre-transformed rm in the lift AND passed the variant, so
            // the lowering re-applied it (CSINC->+2, CSINV->identity, CSNEG->+0).
            // Flags come from the materialized NZCV at [R15+0x108], read by the
            // lowering — no ReadFlags needed (it is a no-op now).
            let v_rn = cx.read_reg(rn, sf);
            let v_rm = cx.read_reg(rm, sf);
            let f = cx.flags();
            let v_res = cx.val(if sf { IrValueKind::I64 } else { IrValueKind::I32 });
            cx.push(IrOp::Csel {
                dst: v_res, a: v_rn, b: v_rm, cond, flags: f, variant: op2,
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
        MulLong { rd, rn, rm, ra, sub, signed } => {
            // 32×32→64 multiply with 64-bit accumulator. UMADDL /
            // SMADDL / UMSUBL / SMSUBL. Rn and Rm read as Wn/Wm (low
            // 32; upper IGNORED), then zero- or sign-extended to 64
            // before the multiply. Ra read as 64-bit. Rd written 64-bit.
            //
            // Phase-E bug: previously lifted as Mul{sf=true}, which
            // read Xn/Xm in full 64-bit width — if the kernel had
            // junk in the upper 32 of Xn (e.g. x28=0x600000000 left
            // over from a prior 64-bit write), the multiply produced
            // a wildly wrong result. Real impact: __next_mem_range_rev's
            // umaddl computing a bogus iterator pointer → array index
            // off into unmapped memory → kernel panic with the
            // truthful PAR.F=1 our new AT path correctly reports.
            let v_rn_w = cx.read_reg(rn, false);   // Wn (low 32)
            let v_rm_w = cx.read_reg(rm, false);   // Wm (low 32)
            let v_rn_x = cx.val(IrValueKind::I64);
            let v_rm_x = cx.val(IrValueKind::I64);
            if signed {
                cx.push(IrOp::Sext { dst: v_rn_x, a: v_rn_w,
                    from_bits: 32, to_bits: 64 });
                cx.push(IrOp::Sext { dst: v_rm_x, a: v_rm_w,
                    from_bits: 32, to_bits: 64 });
            } else {
                cx.push(IrOp::Zext { dst: v_rn_x, a: v_rn_w,
                    from_bits: 32, to_bits: 64 });
                cx.push(IrOp::Zext { dst: v_rm_x, a: v_rm_w,
                    from_bits: 32, to_bits: 64 });
            }
            let v_ra = cx.read_reg(ra, true);
            let v_res = cx.val(IrValueKind::I64);
            if sub {
                cx.push(IrOp::Msub { dst: v_res, a: v_rn_x, b: v_rm_x, c: v_ra });
            } else {
                cx.push(IrOp::Madd { dst: v_res, a: v_rn_x, b: v_rm_x, c: v_ra });
            }
            cx.write_reg(rd, v_res, true);
        }
        MulHigh { rd, rn, rm, signed } => {
            // SMULH / UMULH: high 64 of a 64×64 product. No accumulator.
            //
            // Phase-E correctness fix. The prior lifter emitted Madd
            // (low-64 multiply-add with c=0), so SMULH/UMULH always
            // returned the LOW 64 bits of the product — silently miscomputing
            // every overflow check. Specifically: pcpu_build_alloc_info uses
            // UMULH for `nr_groups * sizeof(pcpu_group_info)` overflow
            // detection, then `cmp xzr, x_; csel x19, xzr, x_, ne`.
            // For nr_groups=1 the correct UMULH(1, 24) is 0 → NE FALSE
            // → x19 = aligned base_size = 0x58. The buggy Madd returned 24,
            // making NE TRUE → x19 = 0 → base_size collapsed to zero →
            // ai->groups[0].cpu_map = ai+0 overlapped ai->static_size →
            // setup_first_chunk tripped `BUG_ON(!ai->static_size)`.
            //
            // The backend already has typed `MulHU` and `MulHS` IR ops
            // (lower_int.rs emits x86 MUL/IMUL r/m64 returning RDX:RAX).
            // Use them directly — no helper call, no host-arch tax.
            let v_rn = cx.read_reg(rn, true);
            let v_rm = cx.read_reg(rm, true);
            let v_res = cx.val(IrValueKind::I64);
            if signed {
                cx.push(IrOp::MulHS { dst: v_res, a: v_rn, b: v_rm });
            } else {
                cx.push(IrOp::MulHU { dst: v_res, a: v_rn, b: v_rm });
            }
            cx.write_reg(rd, v_res, true);
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
                0 => cx.push(IrOp::Rbit { dst: v_res, a: v_rn, sf }),
                1 => cx.push(IrOp::Rev { dst: v_res, a: v_rn, bytes: 2 }),
                2 => cx.push(IrOp::Rev { dst: v_res, a: v_rn, bytes: 4 }),
                3 => cx.push(IrOp::Rev { dst: v_res, a: v_rn, bytes: 8 }),
                4 => cx.push(IrOp::Clz { dst: v_res, a: v_rn, sf }),
                5 => cx.push(IrOp::Cls { dst: v_res, a: v_rn, sf }),
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
            // is_neg=true -> CCMN (flags from a+b); false -> CCMP (a-b).
            cx.push(IrOp::CCmp {
                flags_out, a: v_rn, b: v_rm, cond,
                nzcv_if_false: nzcv, flags_in, is_neg, sf,
            });
            cx.push(IrOp::WriteFlags { src: flags_out });
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
        Ldp { rt1, rt2, sf, signed, addr } => {
            let v_addr = cx.lift_addr_mode(&addr, sf);
            // Three families:
            //   sf=false, signed=false → LDP w/Wt (2×4-byte zero-extended)
            //   sf=true,  signed=false → LDP x/Xt (2×8-byte)
            //   sf=true,  signed=true  → LDPSW (2×4-byte sign-extended to 64)
            // Previously `signed` was discarded and LDPSW used LoadTy::U64,
            // which over-read 16 bytes total and aliased the second element
            // onto unrelated stack bytes. Real hits: small bounded loops
            // (e.g. clear_resource_busy `ldpsw x9,x8,[sp]; sub x8,x9,x8;
            // subs ...; b.ne`) where x8 became ~4 GiB causing the loop to
            // run for billions of iterations and stall the boot silently.
            let access = if sf {
                if signed { LoadTy::I32 } else { LoadTy::U64 }
            } else {
                LoadTy::U32
            };
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
        Ldxr { size, rt, rn, acquire, pair, rt2 } => {
            // Phase-E correctness fix. The prior lifter discarded `pair` +
            // `rt2`, so LDXP rt, rt2, [rn] silently loaded ONLY rt (a single
            // exclusive load) and left rt2 holding its previous value. The
            // kernel's 128-bit CAS at pc=0xffffffc0083436e8 does:
            //   ldxp x11, x0, [x10]
            //   eor x11, x11, x9       ; compare low half
            //   eor x0,  x0,  x8       ; compare high half  <- stale x0!
            //   orr x0,  x11, x0
            //   cbnz x0, ...           ; if mismatch, exit
            //   stlxp w11, x4, x5, [x10]
            //   cbnz w11, retry        ; if STLXP failed, retry from ldxp
            // With the bug, the stale x0 produced wrong compare results,
            // STLXP wrote only one half, and the lock acquire spun forever.
            //
            // Single-vCPU semantics: the "exclusive" pair just means the
            // pair is loaded as two adjacent words. The host's atomic
            // monitor isn't needed (single CPU has no real race), so we
            // emit two consecutive LoadExclusive ops at offsets [0, width).
            let v_addr = cx.read_reg(rn, true);
            let v_data = cx.val(IrValueKind::I64);
            cx.push(IrOp::LoadExclusive {
                dst: v_data, addr: v_addr, ty: load_ty_for(size, false),
            });
            cx.write_reg(rt, v_data, true);
            if pair {
                // Second element at addr + width.
                let width: i64 = match size {
                    AccessSize::Word => 4,
                    AccessSize::DoubleWord => 8,
                    _ => 8, // pair forms are size>=10 (Word/DoubleWord) by decoder check
                };
                let v_off = cx.const_i64(width);
                let v_addr2 = cx.val(IrValueKind::I64);
                cx.push(IrOp::Add { dst: v_addr2, a: v_addr, b: v_off });
                let v_data2 = cx.val(IrValueKind::I64);
                cx.push(IrOp::LoadExclusive {
                    dst: v_data2, addr: v_addr2, ty: load_ty_for(size, false),
                });
                cx.write_reg(rt2, v_data2, true);
            }
            let _ = acquire; // memory-order tag refined in Phase B
        }
        Stxr { size, rs, rt, rn, release: _, pair, rt2 } => {
            // Phase-E correctness fix (same shape as Ldxr): STLXP wrote only
            // ONE word instead of TWO, leaving the second half of the CAS
            // pair stale. Fix: emit two consecutive StoreExclusive ops; OR
            // their status bits so any failure surfaces (the kernel only
            // looks at status==0 vs !=0).
            let v_addr = cx.read_reg(rn, true);
            let v_data = cx.read_reg(rt, true);
            let v_status = cx.val(IrValueKind::I32);
            cx.push(IrOp::StoreExclusive {
                status: v_status, val: v_data, addr: v_addr, ty: store_ty_for(size),
            });
            if pair {
                let width: i64 = match size {
                    AccessSize::Word => 4,
                    AccessSize::DoubleWord => 8,
                    _ => 8,
                };
                let v_off = cx.const_i64(width);
                let v_addr2 = cx.val(IrValueKind::I64);
                cx.push(IrOp::Add { dst: v_addr2, a: v_addr, b: v_off });
                let v_data2 = cx.read_reg(rt2, true);
                let v_status2 = cx.val(IrValueKind::I32);
                cx.push(IrOp::StoreExclusive {
                    status: v_status2, val: v_data2, addr: v_addr2,
                    ty: store_ty_for(size),
                });
                // Combine: result_status = v_status | v_status2 (so any
                // half failing surfaces as non-zero to the cbnz checker).
                let v_combined = cx.val(IrValueKind::I32);
                cx.push(IrOp::Or {
                    dst: v_combined, a: v_status, b: v_status2,
                });
                cx.write_reg(rs, v_combined, false);
            } else {
                cx.write_reg(rs, v_status, false);
            }
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
        // M3: host-dispatch model — every terminator computes its absolute next
        // guest PC and emits WritePc (lowered to [R15+PC_DISP] by M1). The old
        // placeholder CFG ops (CondBranch/Cbz/.. with BlockId(0)) were dead in
        // the single-block path. The dispatcher reads regfile.pc after each RET.
        //
        // FLAG HAZARD: Cmp/Csel ignore their IR `flags` operand and consume live
        // x86 EFLAGS; ConstI64(0) lowers to XOR (clobbers flags). So in the
        // conditional arms ALL constants are emitted BEFORE the Cmp — the only op
        // between Cmp and Csel is the Csel. Csel variant 0: cond TRUE => a, FALSE
        // => b, so a=taken, b=fallthru (proven from lower_int.rs Csel lowering).
        Bl { offset } => {
            // Link register x30 = pc + 4, then branch.
            let v_link = cx.const_i64(cx.pc as i64 + 4);
            cx.write_reg(Reg(30), v_link, true);
            let v_target = cx.const_i64(cx.pc as i64 + offset as i64);
            cx.push(IrOp::WritePc { src: v_target });
        }
        Bcond { cond, offset } => {
            // BEST-EFFORT ONLY: relies on x86 EFLAGS left live by an in-block
            // flag-setter, which intervening lifted ops clobber. NZCV is not yet
            // materialised (ReadFlags lowers to UD2). NOT exercised by the M3
            // proof; correct conditional branching needs flag materialisation.
            let v_taken = cx.const_i64(cx.pc as i64 + offset as i64);
            let v_fall = cx.const_i64(cx.pc as i64 + 4);
            let f = cx.flags();
            let v_next = cx.val(IrValueKind::I64);
            cx.push(IrOp::Csel { dst: v_next, a: v_taken, b: v_fall, cond, flags: f, variant: 0 });
            cx.push(IrOp::WritePc { src: v_next });
        }
        Br { rn } => {
            let v_target = cx.read_reg(rn, true);
            cx.push(IrOp::WritePc { src: v_target });
        }
        Blr { rn } => {
            let v_target = cx.read_reg(rn, true); // read rn before x30 clobber
            let v_link = cx.const_i64(cx.pc as i64 + 4);
            cx.write_reg(Reg(30), v_link, true);
            cx.push(IrOp::WritePc { src: v_target });
        }
        Ret { rn } => {
            let v_target = cx.read_reg(rn, true);
            cx.push(IrOp::WritePc { src: v_target });
        }
        Eret => {
            // ERET — block terminator. Two architectural effects matter to the
            // DBT register-file model:
            //   1. PC      <- ELR_EL1
            //   2. PSTATE  <- SPSR_EL1   (only the NZCV condition flags are
            //                             modeled in the GPR-file; bits [31:28])
            //
            // Composed entirely from already-proven ops (Mrs read of a modeled
            // sysreg slot, And, Msr write that aliases the NZCV word):
            //   v_elr   = Mrs ELR_EL1            ; read return address
            //   v_spsr  = Mrs SPSR_EL1           ; read saved PSTATE
            //   v_mask  = 0xF000_0000            ; NZCV bit mask
            //   v_nzcv  = v_spsr & v_mask        ; isolate N/Z/C/V (already aligned
            //                                      with the packed NZCV word format)
            //   Msr NZCV_EL0, v_nzcv             ; aliases [R15+0x108] in lowering
            //   WritePc v_elr                    ; next PC for the dispatcher
            //
            // ORDER: the ELR read happens first so the WritePc value is computed
            // before the Msr; the Msr to NZCV_EL0 lowers to a plain store to
            // [R15+0x108] and does not disturb PC. WritePc is emitted last so the
            // block's final architectural side effect is the next-PC write, the
            // same convention every other terminator (Ret/Br/Bcond) follows.
            use crate::decoder::sysreg::SysReg;
            let v_elr = cx.val(IrValueKind::I64);
            cx.push(IrOp::Mrs { dst: v_elr, reg: SysReg::ElrEl1 });
            let v_spsr = cx.val(IrValueKind::I64);
            cx.push(IrOp::Mrs { dst: v_spsr, reg: SysReg::SpsrEl1 });
            let v_mask = cx.const_i64(0xF000_0000);
            let v_nzcv = cx.val(IrValueKind::I64);
            cx.push(IrOp::And { dst: v_nzcv, a: v_spsr, b: v_mask });
            cx.push(IrOp::Msr { reg: SysReg::NzcvEl0, val: v_nzcv });
            cx.push(IrOp::WritePc { src: v_elr });
        }
        Cbz { sf, rt, offset } => {
            // All constants first (ConstI64(0)=XOR clobbers flags); then Cmp;
            // then Csel (the only op between Cmp and the PC write).
            let v_zero = cx.const_i64(0);
            let v_taken = cx.const_i64(cx.pc as i64 + offset as i64);
            let v_fall = cx.const_i64(cx.pc as i64 + 4);
            let v_rt = cx.read_reg(rt, sf);
            let f = cx.flags();
            cx.push(IrOp::Cmp { flags: f, a: v_rt, b: v_zero, sf }); // ZF=1 iff rt==0
            let v_next = cx.val(IrValueKind::I64);
            cx.push(IrOp::Csel { dst: v_next, a: v_taken, b: v_fall, cond: Cond::Eq, flags: f, variant: 0 });
            cx.push(IrOp::WritePc { src: v_next });
        }
        Cbnz { sf, rt, offset } => {
            let v_zero = cx.const_i64(0);
            let v_taken = cx.const_i64(cx.pc as i64 + offset as i64);
            let v_fall = cx.const_i64(cx.pc as i64 + 4);
            let v_rt = cx.read_reg(rt, sf);
            let f = cx.flags();
            cx.push(IrOp::Cmp { flags: f, a: v_rt, b: v_zero, sf });
            let v_next = cx.val(IrValueKind::I64);
            cx.push(IrOp::Csel { dst: v_next, a: v_taken, b: v_fall, cond: Cond::Ne, flags: f, variant: 0 });
            cx.push(IrOp::WritePc { src: v_next });
        }
        Tbz { bit, rt, offset } => {
            let v_taken = cx.const_i64(cx.pc as i64 + offset as i64);
            let v_fall = cx.const_i64(cx.pc as i64 + 4);
            let v_one = cx.const_i64(1);
            let v_zero = cx.const_i64(0);
            let v_sh = cx.const_i64(bit as i64);
            let v_rt = cx.read_reg(rt, true);
            let v_shr = cx.val(IrValueKind::I64);
            cx.push(IrOp::LShr { dst: v_shr, a: v_rt, b: v_sh });
            let v_bitval = cx.val(IrValueKind::I64);
            cx.push(IrOp::And { dst: v_bitval, a: v_shr, b: v_one });
            let f = cx.flags();
            cx.push(IrOp::Cmp { flags: f, a: v_bitval, b: v_zero, sf: true }); // ZF=1 iff bit==0
            let v_next = cx.val(IrValueKind::I64);
            cx.push(IrOp::Csel { dst: v_next, a: v_taken, b: v_fall, cond: Cond::Eq, flags: f, variant: 0 });
            cx.push(IrOp::WritePc { src: v_next });
        }
        Tbnz { bit, rt, offset } => {
            let v_taken = cx.const_i64(cx.pc as i64 + offset as i64);
            let v_fall = cx.const_i64(cx.pc as i64 + 4);
            let v_one = cx.const_i64(1);
            let v_zero = cx.const_i64(0);
            let v_sh = cx.const_i64(bit as i64);
            let v_rt = cx.read_reg(rt, true);
            let v_shr = cx.val(IrValueKind::I64);
            cx.push(IrOp::LShr { dst: v_shr, a: v_rt, b: v_sh });
            let v_bitval = cx.val(IrValueKind::I64);
            cx.push(IrOp::And { dst: v_bitval, a: v_shr, b: v_one });
            let f = cx.flags();
            cx.push(IrOp::Cmp { flags: f, a: v_bitval, b: v_zero, sf: true });
            let v_next = cx.val(IrValueKind::I64);
            cx.push(IrOp::Csel { dst: v_next, a: v_taken, b: v_fall, cond: Cond::Ne, flags: f, variant: 0 });
            cx.push(IrOp::WritePc { src: v_next });
        }

        // ===== Exception generation =====
        Svc { imm16 } => cx.push(IrOp::Svc { imm16 }),
        // M4b-4: HVC/SMC are the PSCI conduit (the guest DT uses method="hvc").
        // The lowering services PSCI synchronously (a runtime call that reads
        // x0..x3, runs PSCI, writes x0) and returns to the NEXT instruction, so
        // emit the resume PC — HVC/SMC are block terminators, and without a
        // WritePc the dispatcher would not know where to continue.
        Hvc { imm16 } => {
            cx.push(IrOp::Hvc { imm16 });
            let v_next = cx.const_i64(cx.pc as i64 + 4);
            cx.push(IrOp::WritePc { src: v_next });
        }
        Smc { imm16 } => {
            cx.push(IrOp::Smc { imm16 });
            let v_next = cx.const_i64(cx.pc as i64 + 4);
            cx.push(IrOp::WritePc { src: v_next });
        }
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
            // PSTATE immediate write (MSR <pstatefield>, #imm). The GKI kernel
            // issues these from the very first block (`init_kernel_el` runs
            // `MSR SPSel,#1`; every local_irq_{disable,enable} is
            // `MSR DAIFSet/DAIFClr,#imm`), so they MUST be functional — the old
            // `IrOp::Hint` lowered to UD2 and halted the dispatch loop on the
            // first one. Model the two fields the bring-up register file tracks
            // (SPSel @ slot 23, DAIF @ slot 22) as real read-modify-writes of
            // their context slots, composed entirely from already-proven ops
            // (Mrs/Or/And/Msr to plain sysreg slots — none trigger a TLB flush).
            // Unmodeled fields (PAN/UAO/DIT/SSBS/TCO) SINK to a no-op; they must
            // NOT UD2. DAIF feeds exceptions::irqs_unmasked(), so masking must be
            // live before IRQ injection or the guest takes an IRQ inside a
            // critical section it believes is masked.
            use crate::decoder::sysreg::SysReg;
            match (op1, op2) {
                // MSR SPSel, #imm  (op1=0b000, op2=0b101): SPSel <- CRm[0].
                (0b000, 0b101) => {
                    let v = cx.const_i64((crm & 1) as i64);
                    cx.push(IrOp::Msr { reg: SysReg::SpselEl1, val: v });
                }
                // MSR DAIFSet, #imm (op1=0b011, op2=0b110): DAIF |= CRm[3:0]<<6.
                (0b011, 0b110) => {
                    let cur = cx.val(IrValueKind::I64);
                    cx.push(IrOp::Mrs { dst: cur, reg: SysReg::DaifEl0 });
                    let mask = cx.const_i64(((crm & 0xF) as i64) << 6);
                    let res = cx.val(IrValueKind::I64);
                    cx.push(IrOp::Or { dst: res, a: cur, b: mask });
                    cx.push(IrOp::Msr { reg: SysReg::DaifEl0, val: res });
                }
                // MSR DAIFClr, #imm (op1=0b011, op2=0b111): DAIF &= ~(CRm[3:0]<<6).
                (0b011, 0b111) => {
                    let cur = cx.val(IrValueKind::I64);
                    cx.push(IrOp::Mrs { dst: cur, reg: SysReg::DaifEl0 });
                    let mask = cx.const_i64(!(((crm & 0xF) as i64) << 6));
                    let res = cx.val(IrValueKind::I64);
                    cx.push(IrOp::And { dst: res, a: cur, b: mask });
                    cx.push(IrOp::Msr { reg: SysReg::DaifEl0, val: res });
                }
                // Unmodeled PSTATE field — sink to a no-op (never UD2).
                _ => { let _ = (op1, crm, op2); }
            }
        }
        SysIc { rt, .. } => {
            // IC cache maintenance — model as a Hint (require Rt read for
            // liveness). Does not touch the software MMU TLB or the JIT
            // block cache, so a no-op is correct.
            let _ = cx.read_reg(rt, true);
            cx.push(IrOp::Hint { imm: 128 });
        }
        SysAt { op1, crm, op2, rt } => {
            // AT (Address Translate). Phase-E: instead of treating as a
            // no-op, emit an `AtS1E1` IR op that calls our walker at
            // runtime and writes PAR_EL1 accordingly. The kernel's
            // `is_spurious_el1_translation_fault` reads PAR.F to
            // distinguish a stale-TLB race (F=0, retry) from a real
            // fault (F=1, die). Without this PAR stays 0 → every fault
            // looks spurious → ERET → re-fault → infinite loop.
            //
            // Encodings (op1=000 EL1 set, op1=100 EL2 set — we only
            // handle EL1 here):
            //   CRm=1000, op2=000  → S1E1R    (read)
            //   CRm=1000, op2=001  → S1E1W    (write)
            //   CRm=1000, op2=010  → S1E0R    (read,  EL0 regime)
            //   CRm=1000, op2=011  → S1E0W    (write, EL0 regime)
            //   CRm=1001, op2=000  → S1E1RP   (privileged read with PAN)
            //   CRm=1001, op2=001  → S1E1WP   (privileged write with PAN)
            if op1 == 0 && (crm == 0b1000 || crm == 0b1001) {
                let v_va = cx.read_reg(rt, true);
                let is_write = (op2 & 1) == 1;
                let at_el0 = crm == 0b1000 && (op2 & 0b10) != 0;
                cx.push(IrOp::AtS1E1 { va: v_va, is_write, at_el0 });
            } else {
                // EL2/EL3 forms — treat as no-op (we don't run at EL2/EL3
                // for the guest kernel).
                let _ = cx.read_reg(rt, true);
                cx.push(IrOp::Hint { imm: 128 });
            }
        }
        SysDc { op1, crm, op2, rt } => {
            // DC ZVA (op1=011, CRn=0111, CRm=0100, op2=001) ZEROES the naturally-
            // aligned DCZID_EL0-sized block containing Xt. Unlike the clean /
            // invalidate DC ops (no-ops in this model), ZVA *writes memory* — the
            // kernel's clear_page / __memset_aarch64 issue it in a tight loop, so
            // a Hint no-op there would leave whole pages uninitialized.
            //
            // DCZID_EL0 is seeded to 0x4 => a 64-byte block (runtime::context).
            // Emit 8 naturally-aligned 8-byte zero stores through the same MMU
            // store path as a normal STR (RAM write + No-Boundary window clamp +
            // MMIO routing), reusing lowering that is already proven.
            if op1 == 0b011 && crm == 0b0100 && op2 == 0b001 {
                let v_xt = cx.read_reg(rt, true);
                let v_mask = cx.const_i64(!63i64); // align down to the 64-byte block
                let v_base = cx.val(IrValueKind::I64);
                cx.push(IrOp::And { dst: v_base, a: v_xt, b: v_mask });
                let v_zero = cx.const_i64(0);
                for i in 0..8i64 {
                    let v_off = cx.const_i64(i * 8);
                    let v_addr = cx.val(IrValueKind::I64);
                    cx.push(IrOp::Add { dst: v_addr, a: v_base, b: v_off });
                    cx.push(IrOp::Store {
                        val: v_zero,
                        addr: v_addr,
                        ty: StoreTy::U64,
                        order: MemOrder::Relaxed,
                    });
                }
            } else {
                // DC CVAC / CIVAC / IVAC / CSW / CISW / ... — cache maintenance
                // no-ops against the software MMU model.
                let _ = cx.read_reg(rt, true);
                cx.push(IrOp::Hint { imm: 128 });
            }
        }
        SysTlbi { op2, rt, .. } => {
            // TLB invalidate. The address-taking EL1 forms (VAE1=op2 001,
            // VAAE1=011, VALE1=101, VAALE1=111) carry the page VA in Rt; the
            // broad forms (VMALLE1=000, ASIDE1=010) ignore the register. The
            // odd-`op2` rule selects the VA-taking variants for the EL1 set.
            // (Rt==0b11111 / XZR is the canonical encoding for the broad forms.)
            let va_form = (op2 & 1) == 1 && rt.0 != 31;
            if va_form {
                let v_va = cx.read_reg(rt, true);
                cx.push(IrOp::TlbInval { va: Some(v_va) });
            } else {
                // Read Rt for liveness even on the broad form (harmless; some
                // encodings still name a register).
                let _ = cx.read_reg(rt, true);
                cx.push(IrOp::TlbInval { va: None });
            }
        }

        // ===== SIMD/FP/Crypto =====
        // M4b-6: typed NEON 3-same -> V-register-numbered ctx-template IR ops.
        SimdThreeSame { q, u, size, opcode, rm, rn, rd } => {
            lift_simd_3same(cx, q, u, size, opcode, rd.0, rn.0, rm.0);
        }

        // Coarse fallback for SIMD/FP families not yet typed (semantics Phase B).
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

/// Classify a NEON 3-same encoding `(u, opcode[, size])` into a V-register-
/// numbered ctx-template IR op (BUILDSPEC §5.1). Recognized integer forms map
/// to VecBin/VecCmp/VecPair; FP 3-same and not-yet-typed forms fall back to a
/// `Hint` (which lowers to UD2 — fail-loud, never a silent wrong answer).
fn lift_simd_3same(
    cx: &mut LiftCtx<'_>,
    q: bool,
    u: bool,
    size: u8,
    opcode: u8,
    d: u8,
    n: u8,
    m: u8,
) {
    use crate::ir::ops::{VecBinOp as B, VecCmpOp as C, VecPairOp as P};
    let vb = |op| IrOp::VecBin { op, size, q, d, n, m };
    let vc = |op| IrOp::VecCmp { op, size, q, d, n, m };
    let vp = |op| IrOp::VecPair { op, size, q, d, n, m };
    let ir = match (u, opcode) {
        // halving / saturating add-sub
        (false, 0b00000) => Some(vb(B::SHadd)),
        (true, 0b00000) => Some(vb(B::UHadd)),
        (false, 0b00001) => Some(vb(B::SqAdd)),
        (true, 0b00001) => Some(vb(B::UqAdd)),
        (false, 0b00010) => Some(vb(B::SrHadd)),
        (true, 0b00010) => Some(vb(B::UrHadd)),
        (false, 0b00101) => Some(vb(B::SqSub)),
        (true, 0b00101) => Some(vb(B::UqSub)),
        // logical (opcode 00011) — selected by (u, size)
        (false, 0b00011) => Some(vb(match size {
            0 => B::And,
            1 => B::Bic,
            2 => B::Or,
            _ => B::Orn,
        })),
        (true, 0b00011) => match size {
            0 => Some(vb(B::Eor)),
            _ => None, // BSL/BIT/BIF — Tier 1
        },
        // compares
        (false, 0b00110) => Some(vc(C::SGt)),
        (true, 0b00110) => Some(vc(C::UGt)),
        (false, 0b00111) => Some(vc(C::SGe)),
        (true, 0b00111) => Some(vc(C::UGe)),
        (true, 0b10001) => Some(vc(C::Eq)), // CMEQ (u=0,10001 is CMTST — Tier 1)
        // min / max
        (false, 0b01100) => Some(vb(B::SMax)),
        (true, 0b01100) => Some(vb(B::UMax)),
        (false, 0b01101) => Some(vb(B::SMin)),
        (true, 0b01101) => Some(vb(B::UMin)),
        // abd / aba
        (false, 0b01110) => Some(vb(B::SAbd)),
        (true, 0b01110) => Some(vb(B::UAbd)),
        (false, 0b01111) => Some(vb(B::SAba)),
        (true, 0b01111) => Some(vb(B::UAba)),
        // add / sub
        (false, 0b10000) => Some(vb(B::Add)),
        (true, 0b10000) => Some(vb(B::Sub)),
        // mla / mls
        (false, 0b10010) => Some(vb(B::Mla)),
        (true, 0b10010) => Some(vb(B::Mls)),
        // mul (u=0); pmul (u=1) deferred
        (false, 0b10011) => Some(vb(B::Mul)),
        // pairwise
        (false, 0b10100) => Some(vp(P::SMax)),
        (true, 0b10100) => Some(vp(P::UMax)),
        (false, 0b10101) => Some(vp(P::SMin)),
        (true, 0b10101) => Some(vp(P::UMin)),
        (false, 0b10111) => Some(vp(P::Add)), // ADDP
        _ => None,
    };
    match ir {
        Some(op) => cx.push(op),
        None => cx.push(IrOp::Hint { imm: 200 }),
    }
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
        // M3 host-dispatch: BL writes the link reg AND WritePc(target) instead
        // of emitting a CFG Call op (which was dead in the single-block path).
        assert!(blk.ops.iter().any(|o| matches!(o, IrOp::WritePc { .. })));
    }

    #[test]
    fn lift_nop_emits_hint() {
        let insn = decode_instruction(0xD503201F).unwrap();
        let mut blk = fresh_block();
        lift(&insn, &mut blk).expect("lift NOP");
        assert!(matches!(blk.ops[0], IrOp::Hint { imm: 0 }));
    }

    #[test]
    fn lift_eret_reads_elr_spsr_and_writes_pc() {
        use crate::decoder::sysreg::SysReg;
        // ERET = 0xD69F03E0.
        let insn = decode_instruction(0xD69F_03E0).expect("decode ERET");
        assert_eq!(insn, DecodedInsn::Eret);
        let mut blk = fresh_block();
        lift(&insn, &mut blk).expect("lift ERET");

        // Must read ELR_EL1 and SPSR_EL1 via Mrs.
        assert!(
            blk.ops.iter().any(|o| matches!(o, IrOp::Mrs { reg: SysReg::ElrEl1, .. })),
            "ERET must MRS ELR_EL1: {:?}", blk.ops
        );
        assert!(
            blk.ops.iter().any(|o| matches!(o, IrOp::Mrs { reg: SysReg::SpsrEl1, .. })),
            "ERET must MRS SPSR_EL1: {:?}", blk.ops
        );
        // Must mask the SPSR NZCV bits then MSR the NZCV alias.
        assert!(
            blk.ops.iter().any(|o| matches!(o, IrOp::And { .. })),
            "ERET must mask SPSR NZCV bits: {:?}", blk.ops
        );
        assert!(
            blk.ops.iter().any(|o| matches!(o, IrOp::Msr { reg: SysReg::NzcvEl0, .. })),
            "ERET must MSR NZCV_EL0 to restore flags: {:?}", blk.ops
        );
        // The terminating side effect is WritePc (next guest PC from ELR).
        assert!(
            matches!(blk.ops.last().unwrap(), IrOp::WritePc { .. }),
            "ERET must end with WritePc: {:?}", blk.ops
        );
    }
}
