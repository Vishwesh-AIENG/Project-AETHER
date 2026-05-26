//! AT-12 gate: integer IR lowering → x86_64 byte sequences.
//!
//! Gate: hello-world (ConstI64 {val:0}; Return) translates to a valid
//! x86_64 sequence.  Structural verification: emitted bytes are non-empty,
//! contain the expected opcodes, and the full pipeline compiles cleanly.

use aether_translator::backend::{X86Encoder, IntLower};
use aether_translator::ir::{IrBlock, IrFunction, IrOp, BlockId};
use aether_translator::ir::value::{IrValueId, IrValueKind};
use aether_translator::regalloc::linear_scan::{AllocResult, Assignment};
use aether_translator::regalloc::x86_regs::ALLOCATABLE_GPRS;

use std::collections::BTreeMap;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a trivial AllocResult that assigns value 0 → GPR[0] (RAX).
fn alloc_single_gpr(vid: u32, gpr_idx: u8) -> AllocResult {
    let mut assignments = BTreeMap::new();
    assignments.insert(vid, Assignment::Gpr(gpr_idx));
    AllocResult { assignments, n_spill_slots: 0, n_intervals: 1, n_spilled: 0 }
}

fn lower(blk: &IrBlock, alloc: &AllocResult) -> Vec<u8> {
    let mut enc = X86Encoder::new();
    let mut patches = BTreeMap::new();
    IntLower::lower_block(blk, alloc, &mut enc, &mut patches);
    enc.finish()
}

// ── Gate test: hello-world ────────────────────────────────────────────────────

/// `ConstI64 {val:0}` lowers to XOR EAX,EAX (shortest zero idiom, sets flags).
#[test]
fn at12_hello_world_const_zero() {
    let mut blk = IrBlock::new(BlockId(0));
    let v0 = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::ConstI64 { dst: v0, val: 0 });

    // v0 → RAX (GPR index 0)
    let alloc = alloc_single_gpr(v0.0, 0);
    let bytes = lower(&blk, &alloc);

    // XOR EAX, EAX = 31 C0
    assert_eq!(bytes, [0x31, 0xC0], "ConstI64(0) must emit XOR EAX,EAX");
}

/// `ConstI64 {val:42}` lowers to MOV EAX, 42 (zero-extends, 5 bytes).
#[test]
fn at12_hello_world_const_42() {
    let mut blk = IrBlock::new(BlockId(0));
    let v0 = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::ConstI64 { dst: v0, val: 42 });

    let alloc = alloc_single_gpr(v0.0, 0);
    let bytes = lower(&blk, &alloc);

    // MOV EAX, 42 (zero-extends) = B8 2A 00 00 00
    // OR MOV RAX, 42 (imm32 sign-extended) = 48 C7 C0 2A 00 00 00
    // We emit the sign-extended form (REX.W + C7).
    assert_eq!(bytes, [0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00]);
}

/// `ConstI64 {val: 1<<33}` requires a full imm64 mov.
#[test]
fn at12_const_i64_large() {
    let mut blk = IrBlock::new(BlockId(0));
    let v0 = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::ConstI64 { dst: v0, val: 1 << 33 });

    let alloc = alloc_single_gpr(v0.0, 0);
    let bytes = lower(&blk, &alloc);

    // REX.W + B8 (RAX) + 8-byte imm = 10 bytes
    assert_eq!(bytes.len(), 10, "large i64 must use imm64 form (10 bytes)");
    assert_eq!(bytes[0], 0x48); // REX.W
    assert_eq!(bytes[1], 0xB8); // MOV RAX, imm64
    let val = i64::from_le_bytes(bytes[2..10].try_into().unwrap());
    assert_eq!(val, 1 << 33);
}

/// Sequence: ConstI64(0) + Return, the canonical hello-world pipeline.
#[test]
fn at12_hello_world_full_pipeline() {
    let mut blk = IrBlock::new(BlockId(0));
    let v0 = blk.new_value(IrValueKind::I64); // const 0
    let v1 = blk.new_value(IrValueKind::Ptr);  // return target
    blk.push_op(IrOp::ConstI64 { dst: v0, val: 0 });
    blk.push_op(IrOp::Return { target: v1 });

    let mut assignments = BTreeMap::new();
    assignments.insert(v0.0, Assignment::Gpr(0)); // RAX
    assignments.insert(v1.0, Assignment::Gpr(1)); // RCX (link register)
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);

    // XOR EAX,EAX (2 bytes) + JMP RCX (3 bytes = FF E1) = 5 bytes
    assert!(!bytes.is_empty());
    assert_eq!(bytes[0], 0x31); // XOR
    assert_eq!(bytes[1], 0xC0); // EAX,EAX
    // Return lowers to JMP reg.  RCX = reg 1 → FF E1.
    assert_eq!(&bytes[2..], &[0xFF, 0xE1], "Return must emit JMP RCX");
}

// ── Individual op tests ───────────────────────────────────────────────────────

#[test]
fn at12_add_two_regs() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I64);
    let b = blk.new_value(IrValueKind::I64);
    let d = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Add { dst: d, a, b });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(0)); // RAX
    assignments.insert(b.0, Assignment::Gpr(1)); // RCX
    assignments.insert(d.0, Assignment::Gpr(0)); // RAX (in-place)
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);

    // dst==a, so no MOV needed; just ADD RAX, RCX = 48 01 C8
    assert_eq!(bytes, [0x48, 0x01, 0xC8]);
}

#[test]
fn at12_add_different_dst() {
    // When dst ≠ a: MOV dst,a then ADD dst,b
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I64);
    let b = blk.new_value(IrValueKind::I64);
    let d = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Add { dst: d, a, b });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(0)); // RAX
    assignments.insert(b.0, Assignment::Gpr(1)); // RCX
    assignments.insert(d.0, Assignment::Gpr(2)); // RDX (different)
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);

    // MOV RDX, RAX (48 89 C2) then ADD RDX, RCX (48 01 CA)
    assert_eq!(bytes, [0x48, 0x89, 0xC2, 0x48, 0x01, 0xCA]);
}

#[test]
fn at12_sub() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I64);
    let b = blk.new_value(IrValueKind::I64);
    let d = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Sub { dst: d, a, b });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(0));
    assignments.insert(b.0, Assignment::Gpr(1));
    assignments.insert(d.0, Assignment::Gpr(0)); // in-place
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    // SUB RAX, RCX = 48 29 C8
    assert_eq!(bytes, [0x48, 0x29, 0xC8]);
}

#[test]
fn at12_neg() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I64);
    let d = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Neg { dst: d, a });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(0));
    assignments.insert(d.0, Assignment::Gpr(0));
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    // NEG RAX = 48 F7 D8
    assert_eq!(bytes, [0x48, 0xF7, 0xD8]);
}

#[test]
fn at12_xor_rax_rax() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I64);
    let d = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Xor { dst: d, a, b: a });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(0));
    assignments.insert(d.0, Assignment::Gpr(0));
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    assert_eq!(bytes, [0x48, 0x31, 0xC0]);
}

#[test]
fn at12_load_u64() {
    use aether_translator::ir::memory::{LoadTy, MemOrder};
    let mut blk = IrBlock::new(BlockId(0));
    let addr = blk.new_value(IrValueKind::Ptr);
    let dst  = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Load { dst, addr, ty: LoadTy::U64, order: MemOrder::Relaxed });

    let mut assignments = BTreeMap::new();
    assignments.insert(addr.0, Assignment::Gpr(0)); // RAX = address
    assignments.insert(dst.0,  Assignment::Gpr(1)); // RCX = loaded value
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    // MOV RCX, [RAX] = 48 8B 08
    assert_eq!(bytes, [0x48, 0x8B, 0x08]);
}

#[test]
fn at12_store_u64() {
    use aether_translator::ir::memory::{StoreTy, MemOrder};
    let mut blk = IrBlock::new(BlockId(0));
    let addr = blk.new_value(IrValueKind::Ptr);
    let val  = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Store { val, addr, ty: StoreTy::U64, order: MemOrder::Relaxed });

    let mut assignments = BTreeMap::new();
    assignments.insert(addr.0, Assignment::Gpr(0)); // RAX
    assignments.insert(val.0,  Assignment::Gpr(1)); // RCX
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    // MOV [RAX], RCX = 48 89 08
    assert_eq!(bytes, [0x48, 0x89, 0x08]);
}

#[test]
fn at12_load_u8_zero_extend() {
    use aether_translator::ir::memory::{LoadTy, MemOrder};
    let mut blk = IrBlock::new(BlockId(0));
    let addr = blk.new_value(IrValueKind::Ptr);
    let dst  = blk.new_value(IrValueKind::I8);
    blk.push_op(IrOp::Load { dst, addr, ty: LoadTy::U8, order: MemOrder::Relaxed });

    let mut assignments = BTreeMap::new();
    assignments.insert(addr.0, Assignment::Gpr(0));
    assignments.insert(dst.0,  Assignment::Gpr(1));
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    // MOVZX RCX, byte [RAX] = 48 0F B6 08
    assert_eq!(bytes, [0x48, 0x0F, 0xB6, 0x08]);
}

#[test]
fn at12_mfence_passthrough() {
    let mut blk = IrBlock::new(BlockId(0));
    blk.push_op(IrOp::X86Mfence);

    let alloc = AllocResult::default();
    let bytes = lower(&blk, &alloc);
    assert_eq!(bytes, [0x0F, 0xAE, 0xF0]);
}

#[test]
fn at12_cpuid_passthrough() {
    let mut blk = IrBlock::new(BlockId(0));
    blk.push_op(IrOp::X86Cpuid);

    let alloc = AllocResult::default();
    let bytes = lower(&blk, &alloc);
    // XOR EAX,EAX + CPUID = 31 C0 0F A2
    assert_eq!(bytes, [0x31, 0xC0, 0x0F, 0xA2]);
}

#[test]
fn at12_cmp_flags() {
    use aether_translator::ir::IrFlagsId;
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I64);
    let b = blk.new_value(IrValueKind::I64);
    let f = blk.new_flags();
    blk.push_op(IrOp::Cmp { flags: f, a, b });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(0));
    assignments.insert(b.0, Assignment::Gpr(1));
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    // CMP RAX, RCX = 48 39 C8
    assert_eq!(bytes, [0x48, 0x39, 0xC8]);
}

#[test]
fn at12_sext_32_to_64() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I32);
    let d = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Sext { dst: d, a, from_bits: 32, to_bits: 64 });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(1)); // RCX
    assignments.insert(d.0, Assignment::Gpr(0)); // RAX
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    // MOVSXD RAX, ECX = 48 63 C1
    assert_eq!(bytes, [0x48, 0x63, 0xC1]);
}

#[test]
fn at12_shr_imm_pipeline() {
    // Test pipeline produces non-empty output for shr
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I64);
    let b = blk.new_value(IrValueKind::I64);
    let d = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::LShr { dst: d, a, b });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(0));
    assignments.insert(b.0, Assignment::Gpr(1));
    assignments.insert(d.0, Assignment::Gpr(0));
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    assert!(!bytes.is_empty());
    // Last byte sequence should contain D3 EA (SHR RDX, CL equivalent for RAX)
    // or the full shift sequence — just assert non-empty and contains shift opcode.
    assert!(bytes.iter().any(|&b| b == 0xD3), "shift should contain D3 opcode");
}

#[test]
fn at12_branch_patches_collected() {
    // Verify that Branch op produces a JMP and records the patch offset.
    let mut blk = IrBlock::new(BlockId(0));
    blk.push_op(IrOp::Branch { target: BlockId(1) });

    let alloc = AllocResult::default();
    let mut enc = X86Encoder::new();
    let mut patches = BTreeMap::new();
    IntLower::lower_block(&blk, &alloc, &mut enc, &mut patches);
    let bytes = enc.finish();

    // JMP rel32: E9 + 4 bytes = 5 bytes
    assert_eq!(bytes.len(), 5);
    assert_eq!(bytes[0], 0xE9);
    // Patch map should have one entry pointing to BlockId(1)
    assert_eq!(patches.len(), 1);
    assert_eq!(*patches.values().next().unwrap(), BlockId(1));
}

#[test]
fn at12_cbz_emits_test_jz() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::I64);
    blk.push_op(IrOp::Cbz { a, taken: BlockId(2), fallthru: BlockId(3) });

    let mut assignments = BTreeMap::new();
    assignments.insert(a.0, Assignment::Gpr(0));
    let alloc = AllocResult { assignments, n_spill_slots: 0, n_intervals: 1, n_spilled: 0 };

    let bytes = lower(&blk, &alloc);
    // TEST RAX,RAX (48 85 C0) + JE rel32 (0F 84 ...)
    assert!(bytes.len() >= 3 + 6);
    assert_eq!(&bytes[0..3], &[0x48, 0x85, 0xC0]); // TEST RAX,RAX
    assert_eq!(bytes[3], 0x0F);
    assert_eq!(bytes[4], 0x84); // JE
}
