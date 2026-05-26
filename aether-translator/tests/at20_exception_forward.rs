//! AT-20 tests: x86 trap → ARM exception-class forwarding.

use aether_translator::runtime::exception_forward::{
    forward, forward_align_fault, gate_align_passes, gate_passes, ArmEc, X86Fault,
    ISS_DATA_ALIGN, ISS_DATA_PERMISSION, ISS_DATA_TRANSLATION, ISS_INSN_FETCH,
};

// ── Gate checks ───────────────────────────────────────────────────────────────

#[test]
fn at20_pf_data_gate_passes() {
    assert!(gate_passes(), "AT-20 data-abort gate failed");
}

#[test]
fn at20_align_gate_passes() {
    assert!(gate_align_passes(), "AT-20 alignment-fault gate failed");
}

// ── #PF — page fault ─────────────────────────────────────────────────────────

#[test]
fn at20_pf_not_present_data_is_data_abort() {
    // P=0, W=0 → not-present data read → Data Abort, translation fault.
    let fault = X86Fault::PageFault { cr2: 0xDEAD_0000, error: 0b0000 };
    let info = forward(fault, 0x4000);
    assert_eq!(info.ec, ArmEc::DataAbort);
    assert_eq!(info.far, 0xDEAD_0000);
    assert_eq!(info.iss, ISS_DATA_TRANSLATION);
}

#[test]
fn at20_pf_present_write_is_permission_abort() {
    // P=1, W=1, U=0 → permission fault.
    let fault = X86Fault::PageFault { cr2: 0xCAFE_0000, error: 0b0011 };
    let info = forward(fault, 0x5000);
    assert_eq!(info.ec, ArmEc::DataAbort);
    assert_eq!(info.far, 0xCAFE_0000);
    assert_eq!(info.iss, ISS_DATA_PERMISSION);
}

#[test]
fn at20_pf_instruction_fetch_is_insn_abort() {
    // I=1 (bit 4 set) → instruction fetch fault → Instruction Abort.
    let fault = X86Fault::PageFault { cr2: 0xF000_0000, error: 0b1_0000 };
    let info = forward(fault, 0x9000);
    assert_eq!(info.ec, ArmEc::InstructionAbort);
    assert_eq!(info.far, 0xF000_0000);
    assert_eq!(info.iss, ISS_INSN_FETCH);
}

// ── #GP — general protection ─────────────────────────────────────────────────

#[test]
fn at20_gp_is_data_abort() {
    let fault = X86Fault::GeneralProtection { error: 0 };
    let info = forward(fault, 0x8000);
    assert_eq!(info.ec, ArmEc::DataAbort);
    assert_eq!(info.iss, ISS_DATA_ALIGN);
}

// ── #UD — invalid opcode ─────────────────────────────────────────────────────

#[test]
fn at20_ud_is_unknown() {
    let fault = X86Fault::InvalidOpcode;
    let info = forward(fault, 0x1000);
    assert_eq!(info.ec, ArmEc::Unknown);
    assert_eq!(info.iss, 0);
}

// ── #DB — debug ───────────────────────────────────────────────────────────────

#[test]
fn at20_db_is_breakpoint() {
    let fault = X86Fault::Debug;
    let info = forward(fault, 0x2000);
    assert_eq!(info.ec, ArmEc::Breakpoint);
    assert_eq!(info.guest_pc, 0x2000);
}

// ── #BP — software breakpoint ─────────────────────────────────────────────────

#[test]
fn at20_bp_is_software_breakpoint() {
    let fault = X86Fault::Breakpoint;
    let info = forward(fault, 0x3000);
    assert_eq!(info.ec, ArmEc::SoftwareBreakpoint);
}

// ── #SS — stack fault ─────────────────────────────────────────────────────────

#[test]
fn at20_ss_is_data_abort() {
    let fault = X86Fault::StackFault { error: 0 };
    let info = forward(fault, 0x6000);
    assert_eq!(info.ec, ArmEc::DataAbort);
}

// ── #DE — divide error ────────────────────────────────────────────────────────

#[test]
fn at20_de_is_unknown() {
    let fault = X86Fault::DivideError;
    let info = forward(fault, 0x7000);
    assert_eq!(info.ec, ArmEc::Unknown);
}

// ── Alignment fault alias ─────────────────────────────────────────────────────

#[test]
fn at20_align_fault_produces_correct_iss() {
    let info = forward_align_fault(0x1234_5678, 0x9000);
    assert_eq!(info.ec, ArmEc::DataAbort);
    assert_eq!(info.far, 0x1234_5678);
    assert_eq!(info.iss, ISS_DATA_ALIGN);
    assert_eq!(info.guest_pc, 0x9000);
}

// ── ESR synthesis ─────────────────────────────────────────────────────────────

#[test]
fn at20_esr_ec_field_correct_for_data_abort() {
    let info = forward_align_fault(0x100, 0x200);
    // EC = 0x24 in bits [31:26]; IL=1 in bit 25; ISS in [24:0].
    let ec = (info.esr >> 26) as u8;
    assert_eq!(ec, ArmEc::DataAbort as u8);
}

#[test]
fn at20_esr_il_bit_set() {
    let info = forward_align_fault(0x100, 0x200);
    let il = (info.esr >> 25) & 1;
    assert_eq!(il, 1, "IL bit should be 1 for 32-bit A64 instructions");
}

#[test]
fn at20_esr_iss_preserved() {
    let info = forward_align_fault(0x100, 0x200);
    let iss = (info.esr & 0x01FF_FFFF) as u32;
    assert_eq!(iss, ISS_DATA_ALIGN);
}

// ── Vector numbers ────────────────────────────────────────────────────────────

#[test]
fn at20_fault_vector_numbers() {
    assert_eq!(X86Fault::DivideError.vector(), 0);
    assert_eq!(X86Fault::Debug.vector(), 1);
    assert_eq!(X86Fault::Breakpoint.vector(), 3);
    assert_eq!(X86Fault::InvalidOpcode.vector(), 6);
    assert_eq!(X86Fault::StackFault { error: 0 }.vector(), 12);
    assert_eq!(X86Fault::GeneralProtection { error: 0 }.vector(), 13);
    assert_eq!(X86Fault::PageFault { cr2: 0, error: 0 }.vector(), 14);
}
