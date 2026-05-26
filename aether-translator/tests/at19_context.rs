//! AT-19 tests: guest context save / restore.

use aether_translator::runtime::context::{
    emit_restore_epilogue, emit_save_prologue, round_trip_test, verify_layout,
    GuestRegisterFile, GPR_OFFSET, GUEST_REG_FILE_SIZE, NZCV_OFFSET, PC_OFFSET,
    SP_OFFSET, VEC_OFFSET,
};

// ── Layout verification ───────────────────────────────────────────────────────

#[test]
fn at19_layout_constants_correct() {
    assert!(verify_layout(), "GuestRegisterFile layout does not match constants");
}

#[test]
fn at19_gpr_offset_zero() {
    assert_eq!(GPR_OFFSET, 0x000);
}

#[test]
fn at19_sp_offset() {
    assert_eq!(SP_OFFSET, 0x0F8);
}

#[test]
fn at19_pc_offset() {
    assert_eq!(PC_OFFSET, 0x100);
}

#[test]
fn at19_nzcv_offset() {
    assert_eq!(NZCV_OFFSET, 0x108);
}

#[test]
fn at19_vec_offset() {
    assert_eq!(VEC_OFFSET, 0x128);
}

#[test]
fn at19_total_size() {
    assert_eq!(GUEST_REG_FILE_SIZE, 0x328);
    assert_eq!(core::mem::size_of::<GuestRegisterFile>(), GUEST_REG_FILE_SIZE);
}

// ── Round-trip test (gate) ────────────────────────────────────────────────────

#[test]
fn at19_round_trip_all_registers() {
    assert!(
        round_trip_test(),
        "GuestRegisterFile round-trip failed: save/restore did not preserve register state"
    );
}

// ── Field access helpers ──────────────────────────────────────────────────────

#[test]
fn at19_gpr_read_write() {
    let mut rf = GuestRegisterFile::zeroed();
    for i in 0..31 {
        rf.write_gpr(i, 0xCAFE_BABE_0000_0000 + i as u64);
    }
    for i in 0..31 {
        assert_eq!(rf.read_gpr(i), 0xCAFE_BABE_0000_0000 + i as u64);
    }
}

#[test]
fn at19_vec_read_write() {
    let mut rf = GuestRegisterFile::zeroed();
    for i in 0..32 {
        rf.write_vec(i, 0xDEAD_BEEF_1234_5678_CAFE_BABE_9876_5432_u128 + i as u128);
    }
    for i in 0..32 {
        assert_eq!(
            rf.read_vec(i),
            0xDEAD_BEEF_1234_5678_CAFE_BABE_9876_5432_u128 + i as u128
        );
    }
}

#[test]
fn at19_sp_pc_nzcv_fields() {
    let mut rf = GuestRegisterFile::zeroed();
    rf.sp = 0xFFFF_FFFF_FFFF_FFF0;
    rf.pc = 0xFFFF_8000_0000_1234;
    rf.nzcv = 0xA000_0000;
    assert_eq!(rf.sp, 0xFFFF_FFFF_FFFF_FFF0);
    assert_eq!(rf.pc, 0xFFFF_8000_0000_1234);
    assert_eq!(rf.nzcv, 0xA000_0000);
}

// ── Prologue / epilogue emitters ──────────────────────────────────────────────

#[test]
fn at19_save_prologue_non_empty() {
    let code = emit_save_prologue(13);
    assert!(
        !code.bytes.is_empty(),
        "save prologue should emit at least one byte"
    );
    assert!(code.reg_count > 0);
}

#[test]
fn at19_restore_epilogue_non_empty() {
    let code = emit_restore_epilogue(13);
    assert!(
        !code.bytes.is_empty(),
        "restore epilogue should emit at least one byte"
    );
    assert!(code.reg_count > 0);
}

#[test]
fn at19_prologue_contains_mov_opcode() {
    // MOV [mem], r64 uses opcode 0x89 (with REX.W prefix).
    let code = emit_save_prologue(4);
    let has_89 = code.bytes.contains(&0x89);
    assert!(has_89, "save prologue should contain MOV opcode 0x89");
}

#[test]
fn at19_epilogue_contains_mov_opcode() {
    // MOV r64, [mem] uses opcode 0x8B (with REX.W prefix).
    let code = emit_restore_epilogue(4);
    let has_8b = code.bytes.contains(&0x8B);
    assert!(has_8b, "restore epilogue should contain MOV opcode 0x8B");
}

#[test]
fn at19_prologue_has_rex_w_prefix() {
    // REX.W = 0x48 (or 0x49/0x4C/0x4D for extended regs).
    let code = emit_save_prologue(2);
    let has_rex_w = code.bytes.iter().any(|&b| b & 0xF8 == 0x48);
    assert!(has_rex_w, "save prologue should contain REX.W prefix (0x48–0x4F)");
}

#[test]
fn at19_bytes_as_slice_correct_size() {
    let rf = GuestRegisterFile::zeroed();
    let bytes = rf.as_bytes();
    assert_eq!(bytes.len(), GUEST_REG_FILE_SIZE);
}
