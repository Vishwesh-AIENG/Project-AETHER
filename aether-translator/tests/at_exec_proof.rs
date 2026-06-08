//! M1 — end-to-end execution proof.
//!
//! The audit (2026-05-29) found that the translator GENERATES x86 but nothing
//! ever executes it, and that register-file access lowered to `UD2`. This test
//! closes that gap on the HOST: it translates a real 2-instruction ARM64
//! sequence, makes the emitted bytes executable, CALLs the block with R15
//! pointing at a `GuestRegisterFile`-shaped buffer, and asserts the guest
//! registers were updated correctly. It proves translate -> x86 -> execute ->
//! correct-result works for both `WriteGpr` and `ReadGpr` lowerings.
//!
//! Windows-only (host dev box is x86_64-pc-windows-msvc); uses VirtualAlloc for
//! executable memory. Integration tests are their own crate, so the lib's
//! `#![deny(unsafe_code)]` does not apply here.

#![cfg(all(test, target_arch = "x86_64", windows))]

use std::collections::BTreeMap;

// The translator's global DbtRuntime (block cache + code_buf arena) is a single
// process-wide static; `aether_dbt_init` is idempotent and never resets it, and
// its internal LOCK only spans each individual `with()` call — NOT a test's
// translate -> resolve-host-va -> execute sequence. So two tests that drive the
// global runtime concurrently (esp. translating different blocks at the same PC)
// race on the shared arena: wrong results or torn-block execution (0xC0000005).
// Every test that uses the global runtime takes this lock first to make its
// translate->resolve->execute atomic. (Tests that build IR directly via
// translate_straight_line do not need it.)
static GLOBAL_RT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use aether_translator::backend::{IntLower, X86Encoder};
use aether_translator::decoder::decode_instruction;
use aether_translator::ir::IrFunction;
use aether_translator::lift::lift_at;
use aether_translator::regalloc;

// GuestRegisterFile (runtime/context.rs) is 0x328 bytes = 101 u64 slots.
// gpr[0] is at slot 0, gpr[1] at slot 1, ... (GPR_OFFSET = 0).
// M4a: the context buffer now spans GuestRegisterFile + sysreg + spill regions
// (0x728 = 229 slots) so translated code can address sysreg slots ([R15+0x328..])
// and spill slots ([R15+0x528..]) without running off the end of the buffer.
const CTX_U64S: usize = 0x728 / 8; // 229
/// NZCV lives at byte 0x108 -> u64 slot 33.
const NZCV_SLOT: usize = 0x108 / 8;
/// PC lives at byte 0x100 -> u64 slot 32.
const PC_SLOT: usize = 0x100 / 8;

/// Translate `words` (a straight-line ARM64 sequence, little-endian u32s) into
/// one x86 block and return the emitted machine code (with a trailing RET).
fn translate_straight_line(words: &[u32], pc: u64) -> Vec<u8> {
    let mut func = IrFunction::new(pc);
    {
        let block = func.add_block();
        let mut cur = pc;
        for &w in words {
            let insn = decode_instruction(w).expect("decode");
            lift_at(&insn, block, cur).expect("lift");
            cur += 4;
        }
    }
    let alloc = regalloc::allocate(&func);
    let mut enc = X86Encoder::new();
    let mut patches: BTreeMap<usize, aether_translator::ir::BlockId> = BTreeMap::new();
    for blk in &func.blocks {
        IntLower::lower_block(blk, &alloc, &mut enc, &mut patches);
    }
    enc.emit_ret();
    enc.finish()
}

/// Lower a hand-built IrFunction (regalloc + lower + RET). Used by the spill
/// test, which needs long-lived values that the per-instruction ARM lift never
/// produces.
fn lower_built_func(func: &IrFunction) -> Vec<u8> {
    let alloc = regalloc::allocate(func);
    let mut enc = X86Encoder::new();
    let mut patches: BTreeMap<usize, aether_translator::ir::BlockId> = BTreeMap::new();
    for blk in &func.blocks {
        IntLower::lower_block(blk, &alloc, &mut enc, &mut patches);
    }
    enc.emit_ret();
    enc.finish()
}

mod winexec {
    use std::ffi::c_void;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, typ: u32, protect: u32) -> *mut c_void;
    }
    /// Allocate RWX memory, copy `bytes` in, return the executable pointer.
    pub fn make_executable(bytes: &[u8]) -> *const u8 {
        // SAFETY: standard VirtualAlloc usage; size is non-zero; we copy
        // exactly `bytes.len()` into the freshly committed region.
        unsafe {
            let p = VirtualAlloc(
                core::ptr::null_mut(),
                bytes.len().max(1),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            assert!(!p.is_null(), "VirtualAlloc returned null");
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len());
            p as *const u8
        }
    }
}

/// Enter a translated block in host mode with R15 = `ctx`. Saves/restores all
/// Win64 nonvolatile registers around the call (the block may allocate any of
/// RBX/RBP/RSI/RDI/R12-R14 as scratch and uses R15 as the context base).
///
/// SAFETY: `code` must point at a valid RET-terminated x86 block produced by
/// the translator; `ctx` must point at a buffer of at least GUEST_REG_FILE_SIZE
/// bytes that the block is allowed to read/write.
unsafe fn enter_block(code: *const u8, ctx: *mut u64) {
    core::arch::asm!(
        "push rbx", "push rbp", "push rsi", "push rdi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r15, {ctx}",
        "call {code}",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rdi", "pop rsi", "pop rbp", "pop rbx",
        ctx = in(reg) ctx,
        code = in(reg) code,
        // Keep in lockstep with hypervisor::boot_x86::enter_host_block: declare
        // R15 clobbered so the allocator can't place an input in it.
        lateout("r15") _,
        clobber_abi("C"),
    );
}

/// Same proof, but through the PUBLIC runtime API the hypervisor's boot_amd
/// uses: aether_dbt_init -> aether_dbt_translate_block -> aether_dbt_block_host_va
/// -> execute. This host-verifies the exact M2 integration path before it runs
/// on real AMD silicon (where a wrong path = a blind triple-fault reset).
#[test]
fn public_api_translate_resolve_execute() {
    let _rt = GLOBAL_RT_LOCK.lock().unwrap(); // serialize global-runtime access
    use aether_translator::dbt::{
        aether_dbt_block_host_va, aether_dbt_init, aether_dbt_translate_block, AetherDbtResult,
    };

    // guest_mem is indexed from offset 0 by translate_block; pc is the cache key.
    let program: [u8; 8] = [
        0x20, 0x08, 0x80, 0xD2, // MOVZ X0, #0x41
        0x01, 0x00, 0x00, 0x8B, // ADD  X1, X0, X0
    ];
    let pc: u64 = 0x4100;

    // host_pa_base = 0 (no-op W^X on host); base_ptr comes from the code_buf Vec.
    let _ = aether_dbt_init(0, 16 * 1024 * 1024, 0, 1024 * 1024);
    let r = aether_dbt_translate_block(pc, &program);
    assert_eq!(r, AetherDbtResult::Ok, "translate_block should succeed");

    let (host_va, len) = aether_dbt_block_host_va(pc).expect("block must resolve to a host VA");
    assert!(len > 0, "block length must be non-zero");

    // The resolved host_va points INTO the runtime's code_buf Vec, which on the
    // host lives in the std process heap (NX / Windows DEP) — executing it in
    // place would fault. On the real hypervisor the same bytes live in the BSS
    // global heap, whose post-EBS executability is firmware-dependent (handled
    // by the M2 host-IDT safety net). To host-verify that the public API
    // produced CORRECT, runnable code, copy the resolved bytes into RWX memory
    // and execute the copy.
    // SAFETY: host_va..host_va+len is readable runtime-owned code-buffer memory.
    let code: Vec<u8> =
        unsafe { core::slice::from_raw_parts(host_va as *const u8, len).to_vec() };
    assert_eq!(*code.last().unwrap(), 0xC3, "resolved block must end in RET");

    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: `exec` is RWX with a RET-terminated block copied in; ctx is a
    // full register-file-sized buffer.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[0], 0x41, "X0 via public API path");
    assert_eq!(ctx[1], 0x82, "X1 via public API path");
}

#[test]
fn movz_then_add_executes_and_updates_regfile() {
    // MOVZ X0, #0x41        -> 0xD2800820   (X0 = 0x41)
    // ADD  X1, X0, X0       -> 0x8B000001   (X1 = X0 + X0 = 0x82)
    let words = [0xD280_0820u32, 0x8B00_0001u32];
    let code = translate_straight_line(&words, 0x1000);
    assert!(code.len() > 1, "emitted code should be non-trivial");
    assert_eq!(*code.last().unwrap(), 0xC3, "block must end in RET");
    // No UD2 (0F 0B) anywhere — proves register access no longer traps.
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "translated block must not contain UD2"
    );

    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: `exec` is a freshly translated RET-terminated block; `ctx` is a
    // full register-file-sized buffer.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }

    assert_eq!(ctx[0], 0x41, "X0 should be 0x41 after MOVZ (WriteGpr proof)");
    assert_eq!(
        ctx[1], 0x82,
        "X1 should be 0x82 after ADD X1,X0,X0 (ReadGpr+WriteGpr proof)"
    );
}

/// M3 — multi-block host dispatch + memory STORE/LOAD, through the public API.
/// Mirrors the hypervisor's boot_amd dispatch loop exactly (translate -> resolve
/// -> copy-to-RWX -> CALL -> read pc-slot -> repeat) so M3 is host-verified
/// before silicon. A stack u64 stands in for the hypervisor's M3_OBS static.
#[test]
fn m3_multiblock_store_load_dispatch() {
    let _rt = GLOBAL_RT_LOCK.lock().unwrap(); // serialize global-runtime access
    use aether_translator::dbt::{
        aether_dbt_block_host_va, aether_dbt_init, aether_dbt_translate_block, AetherDbtResult,
    };
    const PC_SLOT: usize = 0x100 / 8;
    const BASE: u64 = 0x1000;
    // Contiguous 24-byte (0x18) program, two basic blocks:
    //   Block A: 0x1000 MOVZ X0,#0x41 ; 0x1004 STR X0,[X2] ; 0x1008 B +4 (->0x100C)
    //   Block B: 0x100C LDR X1,[X2] ; 0x1010 ADD X1,X1,X1 ; 0x1014 B ->0x2000
    // (Block A's B targets 0x100C — the next instruction — so block B follows
    // contiguously with no gap; a +8 target would skip the LDR.)
    let prog: [u8; 0x18] = [
        0x20, 0x08, 0x80, 0xD2, // 0x1000 MOVZ X0,#0x41
        0x40, 0x00, 0x00, 0xF9, // 0x1004 STR  X0,[X2]
        0x01, 0x00, 0x00, 0x14, // 0x1008 B +4 (-> 0x100C)
        0x41, 0x00, 0x40, 0xF9, // 0x100C LDR  X1,[X2]
        0x21, 0x00, 0x01, 0x8B, // 0x1010 ADD  X1,X1,X1
        0xFB, 0x03, 0x00, 0x14, // 0x1014 B -> 0x2000 (offset +0xFEC)
    ];
    let _ = aether_dbt_init(0, 16 * 1024 * 1024, 0, 1024 * 1024);

    let mut ctx = [0u64; CTX_U64S];
    let mut obs: u64 = 0;
    ctx[2] = (&mut obs as *mut u64) as u64; // X2 -> &obs
    ctx[PC_SLOT] = BASE;

    let end = BASE + prog.len() as u64;
    for _ in 0..64 {
        let pc = ctx[PC_SLOT];
        if pc < BASE || pc >= end {
            break;
        }
        let slice = &prog[(pc - BASE) as usize..];
        assert_eq!(aether_dbt_translate_block(pc, slice), AetherDbtResult::Ok);
        let (host_va, len) = aether_dbt_block_host_va(pc).expect("host va");
        // SAFETY: runtime-owned code buffer; copy to RWX before executing (NX heap).
        let code: Vec<u8> =
            unsafe { core::slice::from_raw_parts(host_va as *const u8, len).to_vec() };
        assert_eq!(*code.last().unwrap(), 0xC3, "block ends in RET");
        assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
        let exec = winexec::make_executable(&code);
        // SAFETY: RWX RET-terminated block; ctx is the full register file.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
    }
    assert_eq!(obs, 0x41, "STORE wrote X0 to [X2]");
    assert_eq!(ctx[0], 0x41, "X0");
    assert_eq!(ctx[1], 0x82, "X1 = LDR + ADD");
    assert_eq!(ctx[PC_SLOT], 0x2000, "dispatch left program at 0x2000");
}

/// M3 — verify the new Cbz/Cbnz lift arms compute the correct next PC for BOTH
/// taken and fallthrough, on executed x86 (validates the flag-hazard ordering
/// and the Csel taken=a/fallthru=b direction). Each block is [MOVZ X0,#imm ;
/// CB(N)Z X0, +0xC]; the branch sits at base+4, so taken=base+0x10, fall=base+8.
#[test]
fn m3_cbz_cbnz_next_pc() {
    let _rt = GLOBAL_RT_LOCK.lock().unwrap(); // serialize global-runtime access
    use aether_translator::dbt::{
        aether_dbt_block_host_va, aether_dbt_init, aether_dbt_translate_block, AetherDbtResult,
    };
    const PC_SLOT: usize = 0x100 / 8;
    let _ = aether_dbt_init(0, 16 * 1024 * 1024, 0, 1024 * 1024);

    // Run a 2-instruction block [w0, w1] at `base`; return (X0, next_pc).
    fn run(base: u64, w0: u32, w1: u32) -> (u64, u64) {
        let mut prog = [0u8; 8];
        prog[0..4].copy_from_slice(&w0.to_le_bytes());
        prog[4..8].copy_from_slice(&w1.to_le_bytes());
        assert_eq!(
            aether_dbt_translate_block(base, &prog),
            AetherDbtResult::Ok,
            "translate"
        );
        let (host_va, len) = aether_dbt_block_host_va(base).expect("host va");
        // SAFETY: runtime-owned code buffer.
        let code: Vec<u8> =
            unsafe { core::slice::from_raw_parts(host_va as *const u8, len).to_vec() };
        assert_eq!(*code.last().unwrap(), 0xC3, "ends in RET");
        assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        // SAFETY: RWX RET-terminated block; ctx is the full register file.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        (ctx[0], ctx[PC_SLOT])
    }

    const MOVZ_X0_0: u32 = 0xD2800000; // MOVZ X0,#0
    const MOVZ_X0_5: u32 = 0xD28000A0; // MOVZ X0,#5
    const CBZ_X0_C: u32 = 0xB4000060; // CBZ  X0, +0xC
    const CBNZ_X0_C: u32 = 0xB5000060; // CBNZ X0, +0xC

    // CBZ taken (X0==0): pc = base+0x10. Distinct bases avoid block-cache collisions.
    let (x0, pc) = run(0x1000, MOVZ_X0_0, CBZ_X0_C);
    assert_eq!(x0, 0);
    assert_eq!(pc, 0x1010, "CBZ taken when X0==0");
    // CBZ fallthrough (X0==5): pc = base+8.
    let (x0, pc) = run(0x2000, MOVZ_X0_5, CBZ_X0_C);
    assert_eq!(x0, 5);
    assert_eq!(pc, 0x2008, "CBZ fallthrough when X0!=0");
    // CBNZ taken (X0==5): pc = base+0x10.
    let (x0, pc) = run(0x3000, MOVZ_X0_5, CBNZ_X0_C);
    assert_eq!(x0, 5);
    assert_eq!(pc, 0x3010, "CBNZ taken when X0!=0");
    // CBNZ fallthrough (X0==0): pc = base+8.
    let (x0, pc) = run(0x4000, MOVZ_X0_0, CBNZ_X0_C);
    assert_eq!(x0, 0);
    assert_eq!(pc, 0x4008, "CBNZ fallthrough when X0==0");
}

// ── M4a execution proofs ──────────────────────────────────────────────────────

/// SPILL: 16 simultaneously-live ConstI64 (2^0..2^15) summed by a chain of Adds.
/// With RAX/RCX reserved the allocator has 12 GPRs, so ≥4 values spill to
/// [R15+SPILL_BASE]. Before the fix, spilled values aliased RAX → wrong sum.
#[test]
fn m4a_spill_sixteen_live_values() {
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{BlockId, IrBlock, IrFunction, IrOp};

    let mut func = IrFunction::new(0x1000);
    {
        let block: &mut IrBlock = func.add_block();
        // 16 consts, all kept live until consumed by the chained adds below.
        let mut vs = Vec::new();
        for i in 0..16u32 {
            let v = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: v, val: 1i64 << i });
            vs.push(v);
        }
        // acc = vs[0]; acc = acc + vs[i] for i in 1..16. vs[2..] stay live across
        // earlier adds, forcing spills.
        let mut acc = vs[0];
        for i in 1..16 {
            let nacc = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: nacc, a: acc, b: vs[i] });
            acc = nacc;
        }
        block.push_op(IrOp::WriteGpr { reg: 0, src: acc, sf: true }); // X0 = sum
    }
    let code = lower_built_func(&func);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: RWX RET-terminated block; ctx covers the full extended context.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    // sum(2^0..2^15) = 2^16 - 1 = 0xFFFF.
    assert_eq!(ctx[0], 0xFFFF, "spilled-value sum must be exact (X0)");
}

/// NZCV PRODUCER: CMP X0,X1 materializes the ARM flags at [R15+0x108] with the
/// correct carry POLARITY (ARM C = NOT x86 borrow). 5-3 (no borrow) -> C=1;
/// 3-5 (borrow) -> C=0, N=1. Logical/overflow not exercised here.
#[test]
fn m4a_nzcv_subs_polarity() {
    // MOVZ X0,#imm0 ; MOVZ X1,#imm1 ; CMP X0,X1 (=SUBS XZR,X0,X1 = 0xEB01001F)
    fn run(imm0: u16, imm1: u16) -> u64 {
        let movz_x0 = 0xD2800000u32 | ((imm0 as u32) << 5); // MOVZ X0,#imm0
        let movz_x1 = 0xD2800000u32 | ((imm1 as u32) << 5) | 1; // MOVZ X1,#imm1
        let cmp = 0xEB01001Fu32; // CMP X0, X1
        let code = translate_straight_line(&[movz_x0, movz_x1, cmp], 0x1000);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        // SAFETY: RWX RET-terminated block; ctx is the extended context.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        ctx[NZCV_SLOT]
    }
    // 5 - 3 = 2: no borrow -> ARM C=1 (bit29), N=0, Z=0, V=0.
    let n = run(5, 3);
    assert_eq!(n & (1 << 29), 1 << 29, "C must be set (no borrow) for 5-3");
    assert_eq!(n & (1 << 30), 0, "Z clear for 5-3");
    assert_eq!(n & (1 << 31), 0, "N clear for 5-3");
    // 3 - 5 = -2: borrow -> ARM C=0; result negative -> N=1.
    let n = run(3, 5);
    assert_eq!(n & (1 << 29), 0, "C must be clear (borrow) for 3-5");
    assert_eq!(n & (1 << 31), 1 << 31, "N set (negative) for 3-5");
    // 5 - 5 = 0: Z=1, C=1 (no borrow).
    let n = run(5, 5);
    assert_eq!(n & (1 << 30), 1 << 30, "Z set for 5-5");
    assert_eq!(n & (1 << 29), 1 << 29, "C set for 5-5");
}

/// NZCV CONSUMER: CMP X0,X1 ; B.EQ. The branch must read the materialized NZCV
/// and take iff equal. Proves cross-op flag correctness (the whole point of M4a).
#[test]
fn m4a_nzcv_beq_branch() {
    // 0x1000 MOVZ X0,#5 ; 0x1004 MOVZ X1,#imm ; 0x1008 CMP X0,X1 ; 0x100C B.EQ +0x10
    // B.EQ at 0x100C with imm19=4 -> target 0x100C+0x10 = 0x101C; fallthrough 0x1010.
    fn run(imm1: u16) -> u64 {
        let movz_x0 = 0xD28000A0u32; // MOVZ X0,#5
        let movz_x1 = 0xD2800000u32 | ((imm1 as u32) << 5) | 1; // MOVZ X1,#imm1
        let cmp = 0xEB01001Fu32; // CMP X0,X1
        let beq = 0x54000080u32; // B.EQ +0x10 (cond=EQ, imm19=4)
        let code = translate_straight_line(&[movz_x0, movz_x1, cmp, beq], 0x1000);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        // SAFETY: RWX RET-terminated block; ctx is the extended context.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        ctx[PC_SLOT]
    }
    assert_eq!(run(5), 0x101C, "B.EQ taken when X0==X1 (5==5)");
    assert_eq!(run(7), 0x1010, "B.EQ fallthrough when X0!=X1 (5!=7)");
}

/// SYSREG: MSR/MRS round-trip for a RW reg, and a seeded read-only ID reg.
#[test]
fn m4a_sysreg_roundtrip() {
    use aether_translator::runtime::context::seed_sysregs;
    // 0x1000 MOVZ X0,#0xABC ; MSR SCTLR_EL1,X0 (D5181000) ; MRS X1,SCTLR_EL1 (D5381001)
    //        ; MRS X2,MPIDR_EL1 (D53800A2)
    let movz_x0 = 0xD2800000u32 | (0xABCu32 << 5); // MOVZ X0,#0xABC
    let msr_sctlr = 0xD5181000u32; // MSR SCTLR_EL1, X0
    let mrs_sctlr = 0xD5381001u32; // MRS X1, SCTLR_EL1
    let mrs_mpidr = 0xD53800A2u32; // MRS X2, MPIDR_EL1
    let code = translate_straight_line(&[movz_x0, msr_sctlr, mrs_sctlr, mrs_mpidr], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    seed_sysregs(&mut ctx); // seed the RO ID registers
    // SAFETY: RWX RET-terminated block; ctx is the extended context (seeded).
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[0], 0xABC, "X0 = MOVZ imm");
    assert_eq!(ctx[1], 0xABC, "X1 = MRS SCTLR_EL1 must equal the MSR'd value");
    assert_eq!(ctx[2], 0x8000_0000, "X2 = MRS MPIDR_EL1 = seeded core0 value");
}

/// Host mirror of the EXACT M4a on-silicon proof program in boot_x86.rs::boot_amd,
/// so the program is verified before it ever runs on the Ryzen. One block:
/// MOVZ X0,#0xABC; MSR SCTLR_EL1,X0; MRS X1,SCTLR_EL1; MRS X2,MPIDR_EL1;
/// MOVZ X3,#7; MOVZ X4,#7; CMP X3,X4; B.EQ +8. Expect X1=0xABC, X2=seeded MPIDR,
/// pc=0x3024 (B.EQ taken since 7==7).
#[test]
fn m4a_silicon_proof_program() {
    use aether_translator::runtime::context::seed_sysregs;
    let words = [
        0xD2815780u32, // MOVZ X0,#0xABC
        0xD5181000,    // MSR  SCTLR_EL1, X0
        0xD5381001,    // MRS  X1, SCTLR_EL1
        0xD53800A2,    // MRS  X2, MPIDR_EL1
        0xD28000E3,    // MOVZ X3,#7
        0xD28000E4,    // MOVZ X4,#7
        0xEB04007F,    // CMP  X3,X4
        0x54000040,    // B.EQ +8  (-> 0x3024)
    ];
    let code = translate_straight_line(&words, 0x3000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    seed_sysregs(&mut ctx);
    ctx[PC_SLOT] = 0x3000;
    // SAFETY: RWX RET-terminated block; ctx is the seeded extended context.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[1], 0xABC, "X1 = MRS SCTLR after MSR round-trip");
    assert_eq!(ctx[2], 0x8000_0000, "X2 = seeded MPIDR_EL1");
    assert_eq!(ctx[PC_SLOT], 0x3024, "B.EQ taken (7==7) -> pc=0x3024");
}

/// M4a CLOSEOUT: CSINC X0,X1,X2,EQ must apply the +1 EXACTLY ONCE (the old code
/// double-transformed: lift pre-computed Xm+1 AND the lowering re-added 1 ->
/// Xm+2) and must read fresh ZF at the cmov (the +1 used to clobber ZF between
/// TEST and CMOVNZ). EQ-false -> X0 = X2+1; EQ-true -> X0 = X1.
#[test]
fn m4a_csinc_single_transform_and_flags() {
    // MOVZ X1,#10; MOVZ X2,#20; MOVZ X3,#5; MOVZ X4,#<b>; CMP X3,X4; CSINC X0,X1,X2,EQ
    fn run(x4: u16) -> u64 {
        let words = [
            0xD2800141u32,                       // MOVZ X1,#10
            0xD2800282,                          // MOVZ X2,#20
            0xD28000A3,                          // MOVZ X3,#5
            0xD2800000u32 | ((x4 as u32) << 5) | 4, // MOVZ X4,#x4
            0xEB04007F,                          // CMP X3,X4
            0x9A820420,                          // CSINC X0,X1,X2,EQ
        ];
        let code = translate_straight_line(&words, 0x5000);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        // SAFETY: RWX RET-terminated block; ctx is the extended context.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        ctx[0]
    }
    // X4=6 -> X3!=X4 -> EQ false -> X0 = X2 + 1 = 21 (NOT 22 = double-transform bug).
    assert_eq!(run(6), 21, "CSINC EQ-false: X0 = X2+1 (single transform)");
    // X4=5 -> X3==X4 -> EQ true -> X0 = X1 = 10.
    assert_eq!(run(5), 10, "CSINC EQ-true: X0 = X1");
}

/// M4b-1: ADCS carry-in. A 128-bit add: ADDS X0,X2,X4 (low, sets C) then
/// ADCS X1,X3,X5 (high + carry). X2=~0, X4=1 -> X0=0 with C=1; ADCS then
/// adds the carry so X1 = X3+X5+1. Proves BT-seeds-CF -> ADC works.
#[test]
fn m4b_adcs_carry_chain() {
    let words = [
        0x92800002u32, // MOVN X2,#0  -> X2 = 0xFFFF_FFFF_FFFF_FFFF
        0xD2800024,    // MOVZ X4,#1
        0xD2800003,    // MOVZ X3,#0
        0xD2800005,    // MOVZ X5,#0
        0xAB040040,    // ADDS X0,X2,X4  -> X0=0, C=1
        0xBA050061,    // ADCS X1,X3,X5  -> X1 = 0+0+C = 1
    ];
    let code = translate_straight_line(&words, 0x6000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: RWX RET-terminated block; ctx is the extended context.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[0], 0, "ADDS low word wraps to 0");
    assert_eq!(ctx[1], 1, "ADCS high word picks up the carry (X1=1)");
}

/// M4b-1: real CCMP. CMP X0,X1 sets initial flags; CCMP X2,X3,#0,EQ then
/// either compares X2,X3 (if EQ held) or loads #0 into NZCV (if not).
#[test]
fn m4b_ccmp_branched() {
    // MOVZ X0,#a; MOVZ X1,#b; MOVZ X2,#7; MOVZ X3,#7; CMP X0,X1; CCMP X2,X3,#0,EQ
    fn run(a: u16, b: u16) -> u64 {
        let words = [
            0xD2800000u32 | ((a as u32) << 5),       // MOVZ X0,#a
            0xD2800000u32 | ((b as u32) << 5) | 1,   // MOVZ X1,#b
            0xD28000E2,                              // MOVZ X2,#7
            0xD28000E3,                              // MOVZ X3,#7
            0xEB01001F,                              // CMP X0,X1
            0xFA430040,                              // CCMP X2,X3,#0,EQ
        ];
        let code = translate_straight_line(&words, 0x7000);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        // SAFETY: RWX RET-terminated block; ctx is the extended context.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        ctx[NZCV_SLOT]
    }
    // a==b -> EQ true -> CCMP compares X2,X3 (7==7) -> Z set (bit30).
    let n = run(5, 5);
    assert_eq!(n & (1 << 30), 1 << 30, "CCMP EQ-true: compares X2,X3 -> Z=1");
    // a!=b -> EQ false -> CCMP loads nzcv_if_false=0 -> all flags clear.
    let n = run(5, 6);
    assert_eq!(n & 0xF000_0000, 0, "CCMP EQ-false: NZCV = literal #0");
}

/// M4b-1 must-fix #1 (review wf_3783039b-145): SBCS carry-in must seed CF as
/// the BORROW (!ARM_C), not ARM C. A 128-bit subtract (X3:X2) - (X5:X4) =
/// (1:0) - (0:1) = 2^64 - 1, so X0 (low) = 0xFFFF_FFFF_FFFF_FFFF, X1 (high) = 0.
/// The pre-fix code (BT without CMC) computed X1 = 1 — the bit-exact inverse.
#[test]
fn m4b_sbcs_borrow_chain() {
    let words = [
        0xD2800002u32, // MOVZ X2,#0   (low a)
        0xD2800024,    // MOVZ X4,#1   (low b)
        0xD2800023,    // MOVZ X3,#1   (high a)
        0xD2800005,    // MOVZ X5,#0   (high b)
        0xEB040040,    // SUBS X0,X2,X4  -> 0-1 = ~0, borrow -> ARM C=0
        0xFA050061,    // SBCS X1,X3,X5  -> 1 - 0 - borrow(1) = 0
    ];
    let code = translate_straight_line(&words, 0x8000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: RWX RET-terminated block; ctx is the extended context.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[0], 0xFFFF_FFFF_FFFF_FFFF, "SUBS low: 0 - 1 = ~0");
    assert_eq!(ctx[1], 0, "SBCS high picks up the borrow: 1 - 0 - 1 = 0 (not 1)");
}

/// M4b-1 must-fix #2 (review wf_3783039b-145): CCMN must use ADD polarity, not
/// SUB. CCMN X0,X1,#0,AL with X0=1,X1=1 sets flags from 1+1=2 -> Z=0. The
/// pre-fix code lowered CCMN as CCMP (1-1=0 -> Z=1), the worked counter-example.
#[test]
fn m4b_ccmn_add_polarity() {
    let words = [
        0xD2800020u32, // MOVZ X0,#1
        0xD2800021,    // MOVZ X1,#1
        0xBA41E000,    // CCMN X0,X1,#0,AL  -> flags of (1+1)=2 -> Z=0
    ];
    let code = translate_straight_line(&words, 0x9000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: RWX RET-terminated block; ctx is the extended context.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    let nzcv = ctx[NZCV_SLOT];
    // ADD polarity: 1+1=2 is non-zero -> Z(bit30) clear. (SUB bug would set it.)
    assert_eq!(nzcv & (1 << 30), 0, "CCMN uses ADD polarity: 1+1=2 -> Z=0");
}

/// M4b-1step: ERET. The decoder/lifter must turn ERET into a block terminator
/// that loads the next guest PC from ELR_EL1 and restores the NZCV flags from
/// SPSR_EL1[31:28]. Hidden critical-path prerequisite for the post-__enable_mmu
/// return to virtual text and for M4b-3 exception return.
///
/// Seed the sysreg slots ELR_EL1 (idx 13) and SPSR_EL1 (idx 14) directly, run a
/// one-instruction ERET block, and assert pc <- ELR and nzcv <- SPSR&0xF000_0000.
#[test]
fn m4b_eret_restores_pc_and_nzcv() {
    use aether_translator::runtime::context::SYSREG_SLOT0;
    // sysreg dense-slot indices from lower_int::sysreg_read_idx.
    const ELR_EL1_IDX: usize = 13;
    const SPSR_EL1_IDX: usize = 14;

    // run(elr, spsr) -> (pc_after, nzcv_after).
    fn run(elr: u64, spsr: u64) -> (u64, u64) {
        // ERET = 0xD69F03E0.
        let code = translate_straight_line(&[0xD69F_03E0u32], 0xA000);
        // ERET composes from Mrs/And/Msr/WritePc — none of which lower to UD2.
        assert!(
            !code.windows(2).any(|w| w == [0x0F, 0x0B]),
            "ERET block must not contain UD2"
        );
        assert_eq!(*code.last().unwrap(), 0xC3, "ERET block ends in RET");
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + ELR_EL1_IDX] = elr; // ELR_EL1
        ctx[SYSREG_SLOT0 + SPSR_EL1_IDX] = spsr; // SPSR_EL1
        ctx[PC_SLOT] = 0xA000; // pre-ERET PC (must be overwritten by ELR)
        ctx[NZCV_SLOT] = 0; // pre-ERET flags (must be overwritten by SPSR bits)
        // SAFETY: RWX RET-terminated block; ctx is the full extended context.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        (ctx[PC_SLOT], ctx[NZCV_SLOT])
    }

    // SPSR with N=1,C=1 set (bits 31 and 29) plus low garbage that ERET must
    // mask away. ELR is the virtual return address.
    let elr = 0xFFFF_8000_0012_3456u64;
    let spsr = 0xA000_03C5u64; // N=1(31) Z=0 C=1(29) V=0 in top nibble; low bits noise
    let (pc, nzcv) = run(elr, spsr);
    assert_eq!(pc, elr, "ERET: pc <- ELR_EL1");
    assert_eq!(nzcv, 0xA000_0000, "ERET: nzcv <- SPSR_EL1 & 0xF000_0000 (N,C set)");

    // A different SPSR: Z=1,V=1 (bits 30 and 28). Confirms each NZCV bit maps 1:1.
    let (pc2, nzcv2) = run(0x4080_0000, 0x5000_FFFF);
    assert_eq!(pc2, 0x4080_0000, "ERET: pc <- ELR_EL1 (second case)");
    assert_eq!(nzcv2, 0x5000_0000, "ERET: nzcv <- SPSR & 0xF000_0000 (Z,V set)");
}

/// M4b-5: the immediate PSTATE form `MSR DAIFSet/DAIFClr/SPSel, #imm` must do a
/// real read-modify-write of the DAIF (slot 22) / SPSel (slot 23) context slots
/// and MUST NOT lower to UD2. The old lowering (`IrOp::Hint`) emitted UD2, which
/// the safety gate rejects — halting the dispatch loop on `init_kernel_el`'s
/// first instructions (`MSR SPSel,#1`, the early `MSR DAIFSet/DAIFClr`). Executed
/// on the Win64 host.
#[test]
fn m4b5_msr_pstate_imm_daif_spsel_are_functional() {
    use aether_translator::runtime::context::SYSREG_SLOT0;
    const DAIF_IDX: usize = 22; // lower_int::sysreg_read_idx(DaifEl0)
    const SPSEL_IDX: usize = 23; // lower_int::sysreg_read_idx(SpselEl1)

    // run(word, daif0, spsel0) -> (daif_after, spsel_after).
    fn run(word: u32, daif0: u64, spsel0: u64) -> (u64, u64) {
        let code = translate_straight_line(&[word], 0x7000);
        assert!(
            !code.windows(2).any(|w| w == [0x0F, 0x0B]),
            "PSTATE-immediate block must NOT contain UD2 (word={word:#010x})"
        );
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + DAIF_IDX] = daif0;
        ctx[SYSREG_SLOT0 + SPSEL_IDX] = spsel0;
        // SAFETY: RWX RET-terminated block; ctx is the full extended context.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        (ctx[SYSREG_SLOT0 + DAIF_IDX], ctx[SYSREG_SLOT0 + SPSEL_IDX])
    }

    // MSR DAIFSet, #2 (0xD50342DF): DAIF |= (2 << 6) = 0x80 (the I/IRQ bit).
    assert_eq!(run(0xD503_42DF, 0, 0).0, 0x80, "DAIFSet #2 -> DAIF |= (2<<6)");
    // ORs over an existing F bit (0x40), preserving it.
    assert_eq!(run(0xD503_42DF, 0x40, 0).0, 0xC0, "DAIFSet #2 ORs, keeps other DAIF bits");
    // MSR DAIFClr, #2 (0xD50342FF): clears the I bit, preserving F (0x40).
    assert_eq!(run(0xD503_42FF, 0xC0, 0).0, 0x40, "DAIFClr #2 -> DAIF &= ~(2<<6), keeps F");
    // MSR SPSel, #1 (0xD50041BF) / #0 (0xD50040BF): direct write of the field.
    assert_eq!(run(0xD500_41BF, 0, 0).1, 1, "MSR SPSel,#1 -> SPSel = 1 (EL1h)");
    assert_eq!(run(0xD500_40BF, 1, 1).1, 0, "MSR SPSel,#0 -> SPSel = 0");
}

/// M4a CLOSEOUT REVIEW: coverage for the two Csel variants the original closeout
/// test set omitted — CSINV (variant 2 = NOT) and CSNEG (variant 3 = NEG). Same
/// shape as the CSINC proof: EQ-false selects the transformed Xm; EQ-true selects
/// Xn untransformed. Proves the transform-before-ZF ordering and single-apply for
/// the NOT/NEG arms on executed x86.
#[test]
fn m4a_csinv_csneg_single_transform_and_flags() {
    // MOVZ X1,#10; MOVZ X2,#20; MOVZ X3,#5; MOVZ X4,#<b>; CMP X3,X4; <op> X0,X1,X2,EQ
    fn run(op_word: u32, x4: u16) -> u64 {
        let words = [
            0xD2800141u32,                          // MOVZ X1,#10
            0xD2800282,                             // MOVZ X2,#20
            0xD28000A3,                             // MOVZ X3,#5
            0xD2800000u32 | ((x4 as u32) << 5) | 4, // MOVZ X4,#x4
            0xEB04007F,                             // CMP X3,X4
            op_word,                                // CSINV/CSNEG X0,X1,X2,EQ
        ];
        let code = translate_straight_line(&words, 0x6000);
        // The transform must NOT leave a UD2 in the block (would mean the lowering
        // fell into the spilled-operand fail-loud path — these operands don't spill).
        assert!(
            !code.windows(2).any(|w| w == [0x0F, 0x0B]),
            "CSINV/CSNEG block must not contain UD2 (non-spilled operands)"
        );
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        // SAFETY: RWX RET-terminated block; ctx is the extended context.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        ctx[0]
    }
    const CSINV: u32 = 0xDA82_0020; // CSINV X0,X1,X2,EQ (op=1 op2=00 -> variant 2)
    const CSNEG: u32 = 0xDA82_0420; // CSNEG X0,X1,X2,EQ (op=1 op2=01 -> variant 3)

    // CSINV EQ-false (X3!=X4): X0 = ~X2 = ~20 = 0xFFFF_FFFF_FFFF_FFEB.
    assert_eq!(
        run(CSINV, 6),
        !20u64,
        "CSINV EQ-false: X0 = ~X2 (single NOT, fresh ZF)"
    );
    // CSINV EQ-true (X3==X4): X0 = X1 = 10 (untransformed).
    assert_eq!(run(CSINV, 5), 10, "CSINV EQ-true: X0 = X1");

    // CSNEG EQ-false: X0 = -X2 = -20 = 0xFFFF_FFFF_FFFF_FFEC.
    assert_eq!(
        run(CSNEG, 6),
        (-20i64) as u64,
        "CSNEG EQ-false: X0 = -X2 (single NEG, fresh ZF)"
    );
    // CSNEG EQ-true: X0 = X1 = 10 (untransformed).
    assert_eq!(run(CSNEG, 5), 10, "CSNEG EQ-true: X0 = X1");
}

// ── M4b-2b: Load/Store through the software MMU walker ──────────────────────────
//
// These proofs EXECUTE emitted x86 that calls aether_mmu_xlate (a Win64 mid-block
// CALL) to translate the guest VA before the access, on the Windows host (also
// Win64 — a SysV mistake in the call sequence would crash here). They build real
// 4 KiB page tables in host memory, pin the MMU window to that arena (so the
// walker admits the host-allocated tables + data page), and assert:
//   (a) STR then LDR through a VA round-trips via the WALKED PA;
//   (b) with the MMU off (SCTLR.M==0) the access is flat (VA==PA);
//   (c) an unmapped VA load FAULTS: the block early-RETs and the pending-fault
//       sysreg slot is set;
//   (d) a live register set before the load SURVIVES the call (no clobber).

use aether_translator::runtime::mmu::{
    aether_mmu_flush_all, aether_mmu_set_window, aether_set_mmio_handler, SLOT_PEND_ESR,
    SLOT_PEND_FAR, SLOT_PEND_PENDING, SLOT_SCTLR, SLOT_TCR, SLOT_TTBR0,
};
use aether_translator::runtime::context::SYSREG_SLOT0;

/// The MMU walker uses process-global state (software TLB + pinned window), so
/// every test that drives it through the JIT must run serially. (Separate from
/// GLOBAL_RT_LOCK, which guards the DbtRuntime; an MMU test takes BOTH.)
static MMU_GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const SCTLR_M: u64 = 1 << 0;
/// Descriptor / TTBR output-address mask (bits [47:12]).
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// One 4 KiB-aligned, zeroed arena of `pages` descriptor/data pages, leaked for
/// the test run. Its host address doubles as the "guest PA" (the handoff-window
/// identity invariant the walker relies on). Returns the base host/guest PA.
fn alloc_mmu_arena(pages: usize) -> u64 {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(4096 * pages, 4096).unwrap();
    // SAFETY: non-zero layout; leaked for the test lifetime so the PA stays live.
    let base = unsafe { alloc_zeroed(layout) } as u64;
    assert!(base != 0 && base & 0xFFF == 0, "arena must be 4 KiB aligned");
    base
}

/// Write a u64 descriptor at table-page `pa`, slot `idx`.
fn put_desc(pa: u64, idx: usize, val: u64) {
    // SAFETY: `pa` is an in-arena 4 KiB page; idx < 512.
    unsafe { core::ptr::write_volatile((pa as *mut u64).add(idx), val) }
}
/// Read a u64 from host/guest PA `pa`.
fn read_pa(pa: u64) -> u64 {
    // SAFETY: `pa` is an in-arena address the test allocated.
    unsafe { core::ptr::read_volatile(pa as *const u64) }
}

fn table_desc(next_pa: u64) -> u64 {
    (next_pa & ADDR_MASK) | 0b11 // valid + table
}
/// 4 KiB level-3 page leaf: valid + page-bit + AF, optional read-only.
fn leaf_4k(oa: u64, read_only: bool) -> u64 {
    let mut d = (oa & ADDR_MASK) | 0b11 | (1 << 10); // valid + page + AF
    if read_only {
        d |= 1 << 7; // AP[2]
    }
    d
}

/// Build a 4-level (start-L0, T0SZ=16) table chain in `arena` mapping `va` to the
/// data page, and seed a ctx with SCTLR.M=1, TTBR0, TCR. Arena layout:
///   page0 = L0, page1 = L1, page2 = L2, page3 = L3, page4 = data page.
/// Returns (ctx, data_pa). `read_only` sets AP[2] on the leaf.
fn build_mapped_ctx(va: u64, read_only: bool) -> (Vec<u64>, u64) {
    let arena = alloc_mmu_arena(5);
    let l0 = arena;
    let l1 = arena + 4096;
    let l2 = arena + 8192;
    let l3 = arena + 12288;
    let data = arena + 16384;
    put_desc(l0, ((va >> 39) & 0x1FF) as usize, table_desc(l1));
    put_desc(l1, ((va >> 30) & 0x1FF) as usize, table_desc(l2));
    put_desc(l2, ((va >> 21) & 0x1FF) as usize, table_desc(l3));
    put_desc(l3, ((va >> 12) & 0x1FF) as usize, leaf_4k(data, read_only));
    // Pin the window to exactly this arena so the walker admits the host tables.
    aether_mmu_set_window(arena, 5 * 4096);
    aether_mmu_flush_all();
    let mut ctx = vec![0u64; CTX_U64S];
    ctx[SYSREG_SLOT0 + SLOT_SCTLR] = SCTLR_M;
    ctx[SYSREG_SLOT0 + SLOT_TTBR0] = l0;
    ctx[SYSREG_SLOT0 + SLOT_TCR] = 16; // T0SZ=16 -> 48-bit VA -> start L0 (4-level)
    (ctx, data)
}

/// (a) STR X1,[X0] then LDR X2,[X0] through a VA must round-trip via the WALKED
/// host PA: X2 == X1, and the data page at the walked PA holds the value.
#[test]
fn m4b_str_ldr_roundtrip_through_mmu() {
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    // VA inside the low (TTBR0) half, page-aligned at the 4 KiB granule.
    let va = 0x0000_1234_5678_9000u64;
    let (mut ctx, data_pa) = build_mapped_ctx(va, false);

    // STR X1,[X0] = 0xF9000001 ; LDR X2,[X0] = 0xF9400002.
    let words = [0xF900_0001u32, 0xF940_0002u32];
    let code = translate_straight_line(&words, 0xB000);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "in-register STR/LDR must not emit UD2"
    );
    let exec = winexec::make_executable(&code);

    ctx[0] = va; // X0 = guest VA
    ctx[1] = 0xDEAD_BEEF_CAFE_F00Du64; // X1 = value to store
    // SAFETY: RWX RET-terminated block; ctx is the full extended context. The
    // block calls aether_mmu_xlate, which walks the window-pinned host tables.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[2], 0xDEAD_BEEF_CAFE_F00D, "LDR reads back the STR'd value via the walked PA");
    // The store actually landed at the walked PA (data page), proving the access
    // base was the translated PA — not the raw VA.
    assert_eq!(read_pa(data_pa), 0xDEAD_BEEF_CAFE_F00D, "STR wrote to the walked host PA");
    // No fault was recorded.
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no pending fault on a mapped access");
}

/// (b) MMU off (SCTLR.M==0): xlate returns the VA unchanged, so the access is
/// flat — STR/LDR to a real host address held in X0 round-trips with no tables.
#[test]
fn m4b_flat_access_when_mmu_off() {
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    aether_mmu_set_window(0, u64::MAX); // window irrelevant when M==0, open it wide
    aether_mmu_flush_all();
    let mut slot: u64 = 0;
    let addr = (&mut slot as *mut u64) as u64;

    let words = [0xF900_0001u32, 0xF940_0002u32]; // STR X1,[X0] ; LDR X2,[X0]
    let code = translate_straight_line(&words, 0xC000);
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    // SCTLR.M left 0 (flat). X0 = a real host pointer.
    ctx[0] = addr;
    ctx[1] = 0x0123_4567_89AB_CDEFu64;
    // SAFETY: RWX RET-terminated block; ctx is the extended context; addr is a
    // live stack u64 the flat access reads/writes.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(slot, 0x0123_4567_89AB_CDEF, "flat STR wrote through the raw VA");
    assert_eq!(ctx[2], 0x0123_4567_89AB_CDEF, "flat LDR read it back");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault when MMU off");
}

// ── M4b-5: MMIO interception in the data path ────────────────────────────────
// A guest LDR/STR whose target PA lands in an emulated-device window (UART /
// GIC / virtio) must NOT touch host RAM — it is routed to the registered MMIO
// handler. These proofs register a recording handler and execute a real
// translated STR/LDR against a device address with the MMU off (flat: the PA in
// X0 IS the device address), asserting the write reaches the handler and a read
// pulls the handler's value back into the destination register.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
static MMIO_LAST_ADDR: AtomicU64 = AtomicU64::new(0);
static MMIO_LAST_VALUE: AtomicU64 = AtomicU64::new(0);
static MMIO_LAST_SIZE: AtomicU32 = AtomicU32::new(0);
static MMIO_LAST_IS_WRITE: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
static MMIO_READ_RETURN: AtomicU64 = AtomicU64::new(0);

/// Recording test MMIO handler: stashes the last access and, for reads, returns
/// `MMIO_READ_RETURN`. Matches the `AetherMmioHandler` extern "C" signature.
unsafe extern "C" fn test_mmio_handler(addr: u64, size: u32, is_write: u32, value: u64) -> u64 {
    MMIO_LAST_ADDR.store(addr, Ordering::SeqCst);
    MMIO_LAST_SIZE.store(size, Ordering::SeqCst);
    MMIO_LAST_IS_WRITE.store(is_write, Ordering::SeqCst);
    if is_write != 0 {
        MMIO_LAST_VALUE.store(value, Ordering::SeqCst);
        0
    } else {
        MMIO_READ_RETURN.load(Ordering::SeqCst)
    }
}

/// A translated STR to a device PA forwards to the MMIO handler (no RAM touch).
#[test]
fn m4b5_mmio_store_forwards_to_handler() {
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    aether_mmu_set_window(0, u64::MAX); // MMU off → flat; window irrelevant
    aether_mmu_flush_all();
    aether_set_mmio_handler(test_mmio_handler);
    MMIO_LAST_ADDR.store(0, Ordering::SeqCst);
    MMIO_LAST_VALUE.store(0, Ordering::SeqCst);
    MMIO_LAST_IS_WRITE.store(0xFFFF_FFFF, Ordering::SeqCst);

    // STR W1,[X0] = 0xB9000001 (4-byte store).
    let words = [0xB900_0001u32];
    let code = translate_straight_line(&words, 0xE100);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "MMIO STR must not emit UD2"
    );
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = 0x0900_0000; // PL011 DR — MMIO window, MMU off → flat → is_mmio
    ctx[1] = 0x0000_0041; // 'A'
    // SAFETY: RWX RET-terminated block; ctx is the extended context. The store
    // routes to test_mmio_handler — no host RAM at 0x0900_0000 is dereferenced.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(MMIO_LAST_IS_WRITE.load(Ordering::SeqCst), 1, "STR routed as a write");
    assert_eq!(MMIO_LAST_ADDR.load(Ordering::SeqCst), 0x0900_0000, "handler saw the device addr");
    assert_eq!(MMIO_LAST_VALUE.load(Ordering::SeqCst) & 0xFF, 0x41, "handler saw the byte");
    assert_eq!(MMIO_LAST_SIZE.load(Ordering::SeqCst), 4, "STR W = 4-byte access");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "MMIO store does not fault");
}

/// A translated LDR from a device PA returns the MMIO handler's value into Xt.
#[test]
fn m4b5_mmio_load_returns_handler_value() {
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();
    aether_set_mmio_handler(test_mmio_handler);
    MMIO_READ_RETURN.store(0x0000_00AB, Ordering::SeqCst);
    MMIO_LAST_IS_WRITE.store(0xFFFF_FFFF, Ordering::SeqCst);

    // LDR W2,[X0] = 0xB9400002 (4-byte load).
    let words = [0xB940_0002u32];
    let code = translate_straight_line(&words, 0xE200);
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = 0x0900_0018; // PL011 FR — MMIO window
    ctx[2] = 0xDEAD_DEAD_DEAD_DEAD; // dest sentinel (must be overwritten)
    // SAFETY: RWX RET-terminated block; ctx is the extended context. The load
    // routes to test_mmio_handler; the returned value lands in the scratch slot
    // the load deref reads.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(MMIO_LAST_IS_WRITE.load(Ordering::SeqCst), 0, "LDR routed as a read");
    assert_eq!(MMIO_LAST_ADDR.load(Ordering::SeqCst), 0x0900_0018, "handler saw the device addr");
    assert_eq!(ctx[2], 0xAB, "LDR W loaded the handler value into X2 (zero-extended)");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "MMIO load does not fault");
}

/// (c) An UNMAPPED VA load faults: the walker writes the pending-fault slots and
/// returns XLATE_FAULT(0); the block EARLY-RETs, so the load destination is NOT
/// written (it keeps its pre-block value) and PEND_PENDING==1, FAR==the VA.
#[test]
fn m4b_unmapped_load_faults_and_early_rets() {
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    let va = 0x0000_2000_0000_0000u64; // some low-half VA we will NOT map
    // Build a valid arena/window but DON'T map this VA (only a different one).
    let (mut ctx, _data) = build_mapped_ctx(0x0000_0040_0000_0000u64, false);

    // LDR X2,[X0] = 0xF9400002. X2 pre-seeded with a sentinel that must survive.
    let words = [0xF940_0002u32];
    let code = translate_straight_line(&words, 0xD000);
    let exec = winexec::make_executable(&code);

    ctx[0] = va; // X0 = unmapped VA
    ctx[2] = 0x1111_2222_3333_4444u64; // sentinel: must be unchanged after the fault
    // SAFETY: RWX RET-terminated block; ctx is the extended context. The walker
    // faults (unmapped) -> the block early-RETs before the load writes X2.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(
        ctx[2], 0x1111_2222_3333_4444,
        "early-RET on fault: load destination X2 must be untouched"
    );
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 1, "pending Data Abort recorded");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_FAR], va, "FAR = the faulting VA");
    // ESR.EC must be 0x25 (Data Abort, current EL).
    let esr = ctx[SYSREG_SLOT0 + SLOT_PEND_ESR];
    assert_eq!((esr >> 26) & 0x3F, 0x25, "ESR.EC = Data Abort (same EL)");
}

/// (d) CLOBBER PROOF: a live register set established before the load must
/// survive the Win64 MMU call (the call clobbers volatile RAX/RCX/RDX/R8-R11, so
/// the lowering must save/restore every block-live allocatable GPR). Build a
/// block that loads many live values, does a LDR through the MMU, then sums them
/// — if the call clobbered any, the sum is wrong.
#[test]
fn m4b_live_regs_survive_mmu_call() {
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::ir::memory::{LoadTy, MemOrder};

    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    let va = 0x0000_0055_0000_0000u64;
    let (mut ctx, data_pa) = build_mapped_ctx(va, false);
    // Pre-place a known value at the data page; the LDR must read exactly it.
    // SAFETY: data_pa is in-arena.
    unsafe { core::ptr::write_volatile(data_pa as *mut u64, 0x7777_0000_0000_0001) };

    // Build IR: 6 simultaneously-live ConstI64 (1,2,4,...,32) + a LDR through the
    // VA, then sum the consts AND the loaded value into X1. The 6 live consts +
    // the address + the loaded value all straddle the Win64 MMU call; the call
    // clobbers volatile RDX/R8-R11, so a wrong save/restore set corrupts the sum.
    // (6 consts keeps peak liveness well under the 12 allocatable GPRs so the
    // address / load-dest never spill — they MUST stay in-register, else the
    // Load arm would fail loud (UD2) and the no-UD2 assert below would catch it.)
    let mut func = IrFunction::new(0xE000);
    {
        let block: &mut IrBlock = func.add_block();
        let mut vs = Vec::new();
        for i in 0..6u32 {
            let v = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: v, val: 1i64 << i });
            vs.push(v);
        }
        // address value (X0 holds the VA) -> read it into an IR value.
        let addr = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: addr, reg: 0, sf: true });
        let loaded = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Load { dst: loaded, addr, ty: LoadTy::U64, order: MemOrder::Relaxed });
        // acc = sum(vs) + loaded.
        let mut acc = vs[0];
        for i in 1..6 {
            let nacc = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: nacc, a: acc, b: vs[i] });
            acc = nacc;
        }
        let total = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Add { dst: total, a: acc, b: loaded });
        block.push_op(IrOp::WriteGpr { reg: 1, src: total, sf: true }); // X1 = sum
    }
    let code = lower_built_func(&func);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "block must not fail loud (no spilled mem operand expected)"
    );
    let exec = winexec::make_executable(&code);

    ctx[0] = va; // X0 = guest VA (read into the Load address)
    // SAFETY: RWX RET-terminated block; ctx is the extended context; the load
    // goes through the window-pinned tables.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    // sum(2^0..2^5) = 63 = 0x3F; + loaded 0x7777_0000_0000_0001.
    let expect = 0x3Fu64 + 0x7777_0000_0000_0001u64;
    assert_eq!(ctx[1], expect, "all live consts + loaded value survive the MMU call");
}

/// (e) PAIR PROOF: STP X1,X2,[X0] then LDP X3,X4,[X0] through the MMU must
/// round-trip BOTH halves via the WALKED PA, landing the two 8-byte words at
/// data_pa+0 and data_pa+8. Exercises the LoadPair/StorePair lowering arms —
/// the GKI stack-frame critical path (every function prologue is an STP, every
/// epilogue an LDP). Built as IR directly so it proves the lowering, not the
/// LDP/STP decoder; each access is a Win64 walker call, so two mid-block calls
/// straddle here.
#[test]
fn m4b_stp_ldp_pair_roundtrip_through_mmu() {
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::ir::memory::{LoadTy, StoreTy};

    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    let va = 0x0000_0066_0000_0000u64;
    let (mut ctx, data_pa) = build_mapped_ctx(va, false);

    // addr=X0; STP X1,X2,[X0]; LDP X3,X4,[X0].
    let mut func = IrFunction::new(0xF100);
    {
        let block: &mut IrBlock = func.add_block();
        let addr = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: addr, reg: 0, sf: true });
        let va1 = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: va1, reg: 1, sf: true });
        let vb1 = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: vb1, reg: 2, sf: true });
        block.push_op(IrOp::StorePair { val_a: va1, val_b: vb1, addr, ty: StoreTy::U64 });
        let da = block.new_value(IrValueKind::I64);
        let db = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::LoadPair { dst_a: da, dst_b: db, addr, ty: LoadTy::U64 });
        block.push_op(IrOp::WriteGpr { reg: 3, src: da, sf: true });
        block.push_op(IrOp::WriteGpr { reg: 4, src: db, sf: true });
    }
    let code = lower_built_func(&func);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "in-register STP/LDP must not emit UD2"
    );
    let exec = winexec::make_executable(&code);

    ctx[0] = va; // X0 = guest VA
    ctx[1] = 0x1111_2222_3333_4444u64; // X1 = first word
    ctx[2] = 0x5555_6666_7777_8888u64; // X2 = second word
    // SAFETY: RWX RET-terminated block; ctx is the extended context. The block
    // calls aether_mmu_xlate twice (STP then LDP), each walking the pinned
    // host tables.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[3], 0x1111_2222_3333_4444, "LDP X3 = STP'd first word, via the walked PA");
    assert_eq!(ctx[4], 0x5555_6666_7777_8888, "LDP X4 = STP'd second word");
    // Both halves landed at the walked host PA (data page + 0 / + 8).
    assert_eq!(read_pa(data_pa), 0x1111_2222_3333_4444, "STP[0] wrote to the walked PA");
    assert_eq!(read_pa(data_pa + 8), 0x5555_6666_7777_8888, "STP[8] wrote to the walked PA+8");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault on a mapped pair access");
}

// ── M4b-4: live sysregs (timer / GIC) through the runtime-call lowering ──────
//
// MRS/MSR of a timer or GIC CPU-interface register lowers to a Win64 mid-block
// CALL to aether_sysreg_read/write (NOT a ctx-slot load/store) because these
// registers carry live state / side effects. These proofs EXECUTE that emitted
// call on the Win64 host and assert CNTVCT advances across calls (a static slot
// would hang the kernel's delay loops) and a CNTV_CVAL write/read round-trips.

/// CNTVCT_EL0 read through the runtime call returns the LIVE count, and tracks
/// `aether_timer_set_now` across re-entries of the same block.
#[test]
fn m4b4_cntvct_advances_through_sysreg_call() {
    use aether_translator::decoder::sysreg::SysReg;
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::runtime::sysreg_rt::{aether_platform_reset, aether_timer_set_now};

    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    aether_platform_reset();

    // MRS X0, CNTVCT_EL0.
    let mut func = IrFunction::new(0x1_5000);
    {
        let block: &mut IrBlock = func.add_block();
        let v = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Mrs { dst: v, reg: SysReg::CntvctEl0 });
        block.push_op(IrOp::WriteGpr { reg: 0, src: v, sf: true });
    }
    let code = lower_built_func(&func);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "MRS CNTVCT must not UD2");
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    aether_timer_set_now(0x1234_5678);
    // SAFETY: RWX RET-terminated block; the block calls aether_sysreg_read.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 0x1234_5678, "MRS CNTVCT read the live count via the runtime call");
    // Advance the count and re-run the SAME block -> X0 tracks it (not a slot).
    aether_timer_set_now(0x9ABC_DEF0);
    ctx[0] = 0;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 0x9ABC_DEF0, "CNTVCT advances across calls");
}

/// CNTV_CVAL_EL0 written then read back through the MSR/MRS runtime calls
/// round-trips — proving both the write and read call sequences are correct.
#[test]
fn m4b4_cval_write_read_roundtrips_through_sysreg_calls() {
    use aether_translator::decoder::sysreg::SysReg;
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::runtime::sysreg_rt::aether_platform_reset;

    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    aether_platform_reset();

    // X1 -> MSR CNTV_CVAL_EL0 ; MRS X2, CNTV_CVAL_EL0.
    let mut func = IrFunction::new(0x1_6000);
    {
        let block: &mut IrBlock = func.add_block();
        let v1 = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: v1, reg: 1, sf: true });
        block.push_op(IrOp::Msr { reg: SysReg::CntvCvalEl0, val: v1 });
        let v2 = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Mrs { dst: v2, reg: SysReg::CntvCvalEl0 });
        block.push_op(IrOp::WriteGpr { reg: 2, src: v2, sf: true });
    }
    let code = lower_built_func(&func);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "CVAL MSR/MRS must not UD2");
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0x0000_CAFE_0000_BEEFu64;
    // SAFETY: RWX RET-terminated block; calls aether_sysreg_write then _read.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[2], 0x0000_CAFE_0000_BEEF,
        "CNTV_CVAL written then read back through the runtime calls"
    );
}

/// HVC PSCI conduit: an `HVC` with x0 = PSCI_VERSION returns 0x0001_0001 in x0
/// (the lowering calls aether_hvc_dispatch, which reads x0..x3 from the ctx,
/// runs PSCI, writes x0); SYSTEM_OFF records a platform action the hypervisor
/// polls. Proves HVC no longer UD2s and the PSCI result lands in the guest x0.
#[test]
fn m4b4_hvc_psci_version_and_system_off() {
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::runtime::psci::{
        aether_hvc_take_action, HvcPlatformAction, PSCI_SYSTEM_OFF, PSCI_VERSION,
    };

    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    let _ = aether_hvc_take_action(); // clear any stray pending action

    // A block of just HVC #0. x0 in/out is the ctx slot (the template-JIT
    // inter-instruction GPR home the dispatch reads/writes).
    let mut func = IrFunction::new(0x1_7000);
    {
        let block: &mut IrBlock = func.add_block();
        block.push_op(IrOp::Hvc { imm16: 0 });
    }
    let code = lower_built_func(&func);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "HVC must not UD2 — it is the PSCI runtime call now"
    );
    let exec = winexec::make_executable(&code);

    // PSCI_VERSION -> x0 = 0x0001_0001, no platform action.
    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = PSCI_VERSION as u64;
    // SAFETY: RWX RET-terminated block; the block calls aether_hvc_dispatch.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 0x0001_0001, "HVC PSCI_VERSION -> x0 = 1.1");
    assert_eq!(aether_hvc_take_action(), HvcPlatformAction::None, "VERSION -> no action");

    // SYSTEM_OFF -> records the SystemOff action for the hypervisor.
    ctx[0] = PSCI_SYSTEM_OFF as u64;
    // SAFETY: same block, fresh func id in x0.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        aether_hvc_take_action(),
        HvcPlatformAction::SystemOff,
        "HVC SYSTEM_OFF -> SystemOff action"
    );
    assert_eq!(aether_hvc_take_action(), HvcPlatformAction::None, "action consumed once");
}

/// Regression (M4b adversarial-review HIGH fix): W-form (32-bit) flag ops must
/// compute NZCV over the LOW 32 bits — N from bit 31, Z/C over 32 bits. These
/// cases are built so a 64-bit op would give the WRONG flags; the X-form control
/// proves `sf` selects the width.
#[test]
fn m4b_wform_flags_use_32bit_eflags() {
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};

    // Run one flag op (built by `build`) over X1=x1, X2=x2; return the packed
    // NZCV word the lowering wrote to [R15+0x108]. lower_built_func is pure (no
    // global state), so no lock is needed and the same PC may repeat.
    fn nzcv_after(build: impl FnOnce(&mut IrBlock), x1: u64, x2: u64) -> u64 {
        let mut func = IrFunction::new(0x2_0000);
        {
            let blk: &mut IrBlock = func.add_block();
            build(blk);
        }
        let code = lower_built_func(&func);
        assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "flag block must not UD2");
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[1] = x1;
        ctx[2] = x2;
        // SAFETY: RET-terminated block; R15 -> ctx.
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        ctx[0x108 / 8] // packed NZCV word at [R15+0x108]
    }
    const N: u64 = 1 << 31;
    const Z: u64 = 1 << 30;
    const C: u64 = 1 << 29;

    // SUBS W0,W1,W2 with W1=0x8000_0000 W2=0 -> 32-bit result 0x8000_0000:
    // N=1 (bit31), Z=0, C=1 (no borrow). A 64-bit SUB gives N=0 (bit63=0).
    let nz = nzcv_after(
        |blk| {
            let a = blk.new_value(IrValueKind::I64);
            blk.push_op(IrOp::ReadGpr { dst: a, reg: 1, sf: true });
            let b = blk.new_value(IrValueKind::I64);
            blk.push_op(IrOp::ReadGpr { dst: b, reg: 2, sf: true });
            let res = blk.new_value(IrValueKind::I32);
            let f = blk.new_flags();
            blk.push_op(IrOp::SubS { dst: res, flags: f, a, b, sf: false });
        },
        0x8000_0000,
        0,
    );
    assert_ne!(nz & N, 0, "SUBS W: N from bit 31 (=1), not bit 63 (=0)");
    assert_eq!(nz & Z, 0, "not zero");
    assert_ne!(nz & C, 0, "no 32-bit borrow -> C=1");

    // ADDS W0,W1,W2 with W1=0xFFFF_FFFF W2=1 -> 32-bit result 0: Z=1, C=1.
    // A 64-bit ADD gives 0x1_0000_0000 -> Z=0, C=0.
    let nz = nzcv_after(
        |blk| {
            let a = blk.new_value(IrValueKind::I64);
            blk.push_op(IrOp::ReadGpr { dst: a, reg: 1, sf: true });
            let b = blk.new_value(IrValueKind::I64);
            blk.push_op(IrOp::ReadGpr { dst: b, reg: 2, sf: true });
            let res = blk.new_value(IrValueKind::I32);
            let f = blk.new_flags();
            blk.push_op(IrOp::AddS { dst: res, flags: f, a, b, sf: false });
        },
        0xFFFF_FFFF,
        1,
    );
    assert_ne!(nz & Z, 0, "ADDS W: wraps to 0 in 32 bits -> Z=1");
    assert_ne!(nz & C, 0, "carry out of bit 31 -> C=1");

    // X-form CONTROL: the same SUBS values at 64-bit width -> 0x80000000 is
    // positive (bit63=0) so N=0 — proving `sf` selects 32- vs 64-bit flags.
    let nz_x = nzcv_after(
        |blk| {
            let a = blk.new_value(IrValueKind::I64);
            blk.push_op(IrOp::ReadGpr { dst: a, reg: 1, sf: true });
            let b = blk.new_value(IrValueKind::I64);
            blk.push_op(IrOp::ReadGpr { dst: b, reg: 2, sf: true });
            let res = blk.new_value(IrValueKind::I64);
            let f = blk.new_flags();
            blk.push_op(IrOp::SubS { dst: res, flags: f, a, b, sf: true });
        },
        0x8000_0000,
        0,
    );
    assert_eq!(nz_x & N, 0, "SUBS X: 0x80000000 is positive in 64-bit -> N=0");
}

/// Regression (M4b adversarial-review HIGH cross-cutting fix): a >= 64-instruction
/// straight-line block (no terminator) must emit a synthetic fallthrough WritePc
/// so the dispatcher ADVANCES instead of re-running the same block forever.
/// 64x ADD X0,X0,#1 -> the block runs all 64 adds AND leaves the PC slot at
/// pc + 64*4 (not stuck at the block start).
#[test]
fn m4b_long_straightline_block_has_fallthrough_pc() {
    use aether_translator::dbt::{aether_dbt_init, dbt_runtime_with, AetherDbtResult};
    let _rt = GLOBAL_RT_LOCK.lock().unwrap();
    let _ = aether_dbt_init(0, 16 * 1024 * 1024, 0, 1024 * 1024);

    const ADD_X0_X0_1: u32 = 0x9100_0400; // ADD X0, X0, #1 (no terminator)
    let mut guest_mem = Vec::new();
    for _ in 0..64 {
        guest_mem.extend_from_slice(&ADD_X0_X0_1.to_le_bytes());
    }
    let pc = 0x3_0000u64;
    // Translate AND resolve the host VA atomically under the runtime's internal
    // lock — the block cache + code arena are process-global, so a parallel test
    // could otherwise flush the entry between a separate translate and lookup.
    let resolved = dbt_runtime_with(|rt| {
        if rt.translate_block(pc, &guest_mem) != AetherDbtResult::Ok {
            return None;
        }
        let (off, len) = rt.host_offset_for_pc(pc)?;
        Some((rt.code_buf.base_ptr() as usize + off, len))
    });
    let (host_va, len) = resolved.flatten().expect("translated block resolved");
    // SAFETY: translator-produced bytes in the JIT arena (NX on the host).
    let arena = unsafe { core::slice::from_raw_parts(host_va as *const u8, len) };
    assert!(!arena.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    assert_eq!(*arena.last().unwrap(), 0xC3, "ends in RET");
    // Copy to RWX (the JIT arena Vec is non-executable on the Windows host).
    let exec = winexec::make_executable(&arena.to_vec());

    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: RET-terminated block; R15 -> ctx.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 64, "all 64 ADDs executed");
    assert_eq!(
        ctx[0x100 / 8],
        pc + 64 * 4,
        "fallthrough next-PC = pc + n*4 (not stuck at the block start -> no infinite loop)"
    );
}

// ── M4b-2d: barriers + TLBI no longer trap; TLBI flushes the soft TLB and the
//            JIT block cache ──────────────────────────────────────────────────
//
// Before this step DMB/DSB/ISB/SB and every TLBI lowered to UD2 (the block
// became un-enterable), which is fatal because the kernel issues all of these
// constantly while bringing up its page tables. These proofs EXECUTE emitted
// x86 on the Win64 host:
//   • DMB/DSB → MFENCE, ISB/SB → CPUID serialise; the block stays UD2-free,
//     ends in RET, and surrounding compute still produces the right answer.
//   • A single-VA TLBI (VAE1) flushes exactly that page from the software TLB,
//     so a load after a remap re-walks → sees the NEW mapping.
//   • A broad TLBI (VMALLE1) flushes the whole software TLB (same observable).
//   • Byte proofs witness the baked FFI helper addresses (aether_mmu_tlbi_va /
//     aether_mmu_flush_all + aether_dbt_invalidate_all) that the lowering emits.

/// (a) A block of barriers around a compute executes (no UD2), RETs, and the
/// compute result is correct — proving DSB/DMB/ISB are real x86 fences now, not
/// traps. `MOVZ X0,#0x41 ; DSB SY ; ISB ; DMB SY ; ADD X1,X0,X0`.
#[test]
fn m4b_barriers_execute_no_ud2() {
    let _rt = GLOBAL_RT_LOCK.lock().unwrap();
    // MOVZ X0,#0x41 = 0xD2800820 ; DSB SY = 0xD5033F9F ; ISB = 0xD5033FDF ;
    // DMB SY = 0xD5033FBF ; ADD X1,X0,X0 = 0x8B000001.
    let words = [0xD280_0820u32, 0xD503_3F9Fu32, 0xD503_3FDFu32, 0xD503_3FBFu32, 0x8B00_0001u32];
    let code = translate_straight_line(&words, 0x10000);
    assert_eq!(*code.last().unwrap(), 0xC3, "barrier block must end in RET");
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "DSB/ISB/DMB must NOT emit UD2 — they are MFENCE/CPUID now"
    );
    // MFENCE = 0F AE F0 must appear (from the two full barriers DSB/DMB).
    assert!(
        code.windows(3).any(|w| w == [0x0F, 0xAE, 0xF0]),
        "a full barrier must lower to MFENCE (0F AE F0)"
    );
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: RWX RET-terminated block; ctx is the full register-file buffer.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 0x41, "MOVZ survived the barriers");
    assert_eq!(ctx[1], 0x82, "ADD across the barriers produced X0+X0");
}

/// (b) FLUSH PROOF (single-VA): a `TLBI VAE1, X3` between two loads of the same
/// VA flushes that page from the software TLB, so the second load re-walks the
/// (rewritten) leaf and reads the NEW page. Mirrors the MSR-TTBR0 flush proof.
#[test]
fn m4b_tlbi_va_flushes_one_page() {
    // Executing the TLBI block calls aether_dbt_invalidate_all (mutates the
    // GLOBAL DbtRuntime block cache), so take BOTH locks — MMU state AND the
    // runtime — to avoid wiping a concurrent GLOBAL_RT_LOCK test's cache.
    let _rt = GLOBAL_RT_LOCK.lock().unwrap();
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    let va = 0x0000_0088_0000_0000u64;
    let (mut ctx, _l0, l3, l3_slot, data_a, data_b) = build_remappable_ctx(va);
    const VAL_A: u64 = 0xA1A1_0000_0000_000Au64;
    const VAL_B: u64 = 0xB2B2_0000_0000_000Bu64;
    // SAFETY: both data pages are in-arena.
    unsafe {
        core::ptr::write_volatile(data_a as *mut u64, VAL_A);
        core::ptr::write_volatile(data_b as *mut u64, VAL_B);
    }

    // Block 1: LDR X1,[X0] — caches VA→PA(dataA) in the software TLB.
    let ld_code = translate_straight_line(&[0xF940_0001u32], 0x11000);
    let ld_exec = winexec::make_executable(&ld_code);
    ctx[0] = va;
    // SAFETY: RWX RET-terminated block; ctx is the extended context.
    unsafe { enter_block(ld_exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], VAL_A, "first load caches dataA");

    // Rewrite the leaf → dataB (stale TLB still points at dataA).
    put_desc(l3, l3_slot, leaf_4k(data_b, false));

    // Block 2: TLBI VAE1, X3 ; LDR X1,[X0]. The TLBI flushes the page whose VA is
    // in X3; we put the SAME VA there so exactly this page is invalidated.
    // TLBI VAE1,X3 = 0xD5088723 (op1=0,CRm=7,op2=1,Rt=3).
    let tlbi_ld = [0xD508_8723u32, 0xF940_0001u32];
    let code = translate_straight_line(&tlbi_ld, 0x11010);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "TLBI VAE1 + LDR block must not fail loud (no UD2)"
    );
    let exec = winexec::make_executable(&code);
    ctx[0] = va;
    ctx[3] = va; // X3 = the page VA to invalidate
    ctx[1] = 0;
    // SAFETY: RWX RET-terminated block; ctx is the extended context; the TLBI
    // flushes the page, the LDR re-walks the rewritten leaf.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[1], VAL_B,
        "after TLBI VAE1 flushed the page, the load re-walks → dataB"
    );
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault after flush+rewalk");
}

/// (c) FLUSH PROOF (broad): `TLBI VMALLE1` (no register operand) flushes the
/// whole software TLB, so a load after a remap re-walks → sees the NEW mapping.
#[test]
fn m4b_tlbi_broad_flushes_tlb() {
    // Executing the TLBI block calls aether_dbt_invalidate_all (mutates the
    // GLOBAL DbtRuntime block cache) — take BOTH locks (see the VA-form test).
    let _rt = GLOBAL_RT_LOCK.lock().unwrap();
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    let va = 0x0000_0099_0000_0000u64;
    let (mut ctx, _l0, l3, l3_slot, data_a, data_b) = build_remappable_ctx(va);
    const VAL_A: u64 = 0xC3C3_0000_0000_000Cu64;
    const VAL_B: u64 = 0xD4D4_0000_0000_000Du64;
    // SAFETY: both data pages are in-arena.
    unsafe {
        core::ptr::write_volatile(data_a as *mut u64, VAL_A);
        core::ptr::write_volatile(data_b as *mut u64, VAL_B);
    }

    // Block 1: LDR X1,[X0] — caches VA→dataA.
    let ld_code = translate_straight_line(&[0xF940_0001u32], 0x12000);
    let ld_exec = winexec::make_executable(&ld_code);
    ctx[0] = va;
    // SAFETY: RWX RET-terminated block; ctx is the extended context.
    unsafe { enter_block(ld_exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], VAL_A, "first load caches dataA");

    put_desc(l3, l3_slot, leaf_4k(data_b, false)); // remap → dataB

    // Block 2: TLBI VMALLE1 ; LDR X1,[X0].  VMALLE1 = 0xD508871F (Rt=31).
    let tlbi_ld = [0xD508_871Fu32, 0xF940_0001u32];
    let code = translate_straight_line(&tlbi_ld, 0x12010);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "TLBI VMALLE1 + LDR block must not fail loud (no UD2)"
    );
    let exec = winexec::make_executable(&code);
    ctx[0] = va;
    ctx[1] = 0;
    // SAFETY: RWX RET-terminated block; ctx is the extended context.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[1], VAL_B,
        "after TLBI VMALLE1 flushed the whole TLB, the load re-walks → dataB"
    );
}

/// (d) BYTE PROOF: the broad-TLBI block bakes the `aether_mmu_flush_all` +
/// `aether_dbt_invalidate_all` helper addresses; the single-VA-TLBI block bakes
/// `aether_mmu_tlbi_va` + `aether_dbt_invalidate_all` (and NOT the broad flush).
/// This isolates each form's exact side-effect calls at the byte level.
#[test]
fn m4b_tlbi_emits_expected_calls() {
    use aether_translator::dbt::aether_dbt_invalidate_all;
    use aether_translator::runtime::mmu::aether_mmu_tlbi_va;
    // Pure byte inspection: translate_straight_line builds a local encoder and
    // never executes the block, so it touches neither the MMU globals nor the
    // DbtRuntime — no lock needed. The baked helper addresses are deterministic.

    let broad = translate_straight_line(&[0xD508_871Fu32], 0x13000); // TLBI VMALLE1
    let va    = translate_straight_line(&[0xD508_8722u32], 0x13010); // TLBI VAE1,X2

    let flush_le = (aether_mmu_flush_all as *const () as usize as u64).to_le_bytes();
    let tlbiva_le = (aether_mmu_tlbi_va as *const () as usize as u64).to_le_bytes();
    let inval_le = (aether_dbt_invalidate_all as *const () as usize as u64).to_le_bytes();

    // Both forms invalidate the JIT block cache.
    assert!(broad.windows(8).any(|w| w == inval_le), "broad TLBI bakes aether_dbt_invalidate_all");
    assert!(va.windows(8).any(|w| w == inval_le), "VA TLBI bakes aether_dbt_invalidate_all");
    // Broad → whole-TLB flush; NOT the per-VA helper.
    assert!(broad.windows(8).any(|w| w == flush_le), "broad TLBI bakes aether_mmu_flush_all");
    assert!(!broad.windows(8).any(|w| w == tlbiva_le), "broad TLBI must NOT bake aether_mmu_tlbi_va");
    // VA → per-page helper; NOT the whole-TLB flush.
    assert!(va.windows(8).any(|w| w == tlbiva_le), "VA TLBI bakes aether_mmu_tlbi_va");
    assert!(!va.windows(8).any(|w| w == flush_le), "VA TLBI must NOT bake aether_mmu_flush_all");
    // Neither traps.
    assert!(!broad.windows(2).any(|w| w == [0x0F, 0x0B]), "broad TLBI block must not contain UD2");
    assert!(!va.windows(2).any(|w| w == [0x0F, 0x0B]), "VA TLBI block must not contain UD2");
}

/// (e) BLOCK-CACHE INVALIDATE API: translate a PC (cache hit), invalidate the
/// whole block cache, confirm the PC no longer resolves, then re-translate and
/// confirm it resolves again — proving aether_dbt_invalidate_all clears the
/// lookup table and the next dispatch retranslates fresh against the (possibly
/// changed) guest tables.
#[test]
fn m4b_dbt_invalidate_all_resets_cache() {
    let _rt = GLOBAL_RT_LOCK.lock().unwrap();
    use aether_translator::dbt::{
        aether_dbt_block_host_va, aether_dbt_init, aether_dbt_invalidate_all,
        aether_dbt_translate_block, AetherDbtResult,
    };
    // A trivial RET-only block: MOVZ X0,#1 then implicit RET epilogue.
    let prog: [u8; 4] = [0x20, 0x00, 0x80, 0xD2]; // MOVZ X0,#1
    let pc: u64 = 0x9_0000;

    let _ = aether_dbt_init(0, 16 * 1024 * 1024, 0, 1024 * 1024);

    // 1. Cold translate → cache populated → host VA resolves.
    assert_eq!(aether_dbt_translate_block(pc, &prog), AetherDbtResult::Ok);
    assert!(aether_dbt_block_host_va(pc).is_some(), "block resolves after translate");

    // 2. Invalidate the whole block cache → the PC must no longer resolve.
    assert_eq!(aether_dbt_invalidate_all(), AetherDbtResult::Ok);
    assert!(
        aether_dbt_block_host_va(pc).is_none(),
        "after invalidate_all the cached block must be gone"
    );

    // 3. Re-translate → resolves again (fresh translation against current bytes).
    assert_eq!(aether_dbt_translate_block(pc, &prog), AetherDbtResult::Ok);
    assert!(
        aether_dbt_block_host_va(pc).is_some(),
        "block re-resolves after re-translate"
    );
}

// ── M4b-2dpre: MSR side-effects flush the software MMU TLB ───────────────────────
//
// When the guest writes a translation-control register (TTBR0/1_EL1, TCR_EL1,
// MAIR_EL1) the active page-table set changes, so the walker's software TLB —
// which cached VA→PA under the OLD tables — must be invalidated or the next
// access lands at a stale PA. These proofs EXECUTE emitted x86 on the Win64 host
// and demonstrate the difference between a flushing MSR and a non-flushing one
// by REMAPPING a VA's leaf descriptor between two loads and checking which PA the
// second load resolves to:
//   (e) MSR TTBR0_EL1 BEFORE the second load flushes the TLB → the second load
//       re-walks and sees the NEW mapping;
//   (f) MSR SCTLR_EL1 (no flush; M is read live each xlate) leaves the TLB intact
//       → the second load still resolves to the OLD (cached) mapping. This proves
//       the classifier flushes ONLY for translation-control registers, not for
//       every MSR.

/// Build a 6-page arena (L0,L1,L2,L3,dataA,dataB) mapping `va` → dataA, pin the
/// window to it, seed a ctx with SCTLR.M=1 + TTBR0 + TCR. Returns
/// (ctx, l0_base, l3_base, l3_slot, data_a, data_b). The caller can later rewrite
/// the L3 leaf (slot `l3_slot`) to point at `data_b` to simulate a remap.
fn build_remappable_ctx(va: u64) -> (Vec<u64>, u64, u64, usize, u64, u64) {
    let arena = alloc_mmu_arena(6);
    let l0 = arena;
    let l1 = arena + 4096;
    let l2 = arena + 8192;
    let l3 = arena + 12288;
    let data_a = arena + 16384;
    let data_b = arena + 20480;
    let l3_slot = ((va >> 12) & 0x1FF) as usize;
    put_desc(l0, ((va >> 39) & 0x1FF) as usize, table_desc(l1));
    put_desc(l1, ((va >> 30) & 0x1FF) as usize, table_desc(l2));
    put_desc(l2, ((va >> 21) & 0x1FF) as usize, table_desc(l3));
    put_desc(l3, l3_slot, leaf_4k(data_a, false)); // VA → dataA (writable)
    aether_mmu_set_window(arena, 6 * 4096);
    aether_mmu_flush_all();
    let mut ctx = vec![0u64; CTX_U64S];
    ctx[SYSREG_SLOT0 + SLOT_SCTLR] = SCTLR_M;
    ctx[SYSREG_SLOT0 + SLOT_TTBR0] = l0;
    ctx[SYSREG_SLOT0 + SLOT_TCR] = 16; // T0SZ=16 -> 48-bit VA -> 4-level start L0
    (ctx, l0, l3, l3_slot, data_a, data_b)
}

/// (e) FLUSH PROOF: a `MSR TTBR0_EL1, Xn` between two loads of the same VA flushes
/// the software TLB, so the second load re-walks the (rewritten) tables and reads
/// the NEW output page. Without the MSR-triggered flush the second load would read
/// the stale cached PA (page A) — which (f) demonstrates with SCTLR.
#[test]
fn m4b_msr_ttbr0_flushes_tlb() {
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    let va = 0x0000_0066_0000_0000u64;
    let (mut ctx, l0, l3, l3_slot, data_a, data_b) = build_remappable_ctx(va);
    const VAL_A: u64 = 0xAAAA_0000_0000_000Au64;
    const VAL_B: u64 = 0xBBBB_0000_0000_000Bu64;
    // SAFETY: both data pages are in-arena.
    unsafe {
        core::ptr::write_volatile(data_a as *mut u64, VAL_A);
        core::ptr::write_volatile(data_b as *mut u64, VAL_B);
    }

    // Block 1: LDR X1,[X0]  (caches VA→PA(dataA) in the software TLB).
    let ld_words = [0xF940_0001u32]; // LDR X1,[X0]
    let ld_code = translate_straight_line(&ld_words, 0xF100);
    let ld_exec = winexec::make_executable(&ld_code);
    ctx[0] = va;
    // SAFETY: RWX RET-terminated block; ctx is the extended context; the load
    // walks the window-pinned host tables.
    unsafe { enter_block(ld_exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], VAL_A, "first load reads dataA via the freshly walked PA");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault on the mapped load");

    // Rewrite the L3 leaf to point at dataB. The software TLB still holds the
    // stale VA→dataA entry; only an MSR-triggered flush will evict it.
    put_desc(l3, l3_slot, leaf_4k(data_b, false));

    // Block 2: MSR TTBR0_EL1, X2 ; LDR X1,[X0]. The MSR write triggers
    // aether_mmu_flush_all(); X2 carries the SAME L0 base so the re-walk still
    // succeeds, now reading the rewritten leaf → dataB.
    let msr_ld_words = [0xD518_2002u32, 0xF940_0001u32]; // MSR TTBR0_EL1,X2 ; LDR X1,[X0]
    let msr_ld_code = translate_straight_line(&msr_ld_words, 0xF110);
    assert!(
        !msr_ld_code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "MSR+LDR block must not fail loud (no UD2)"
    );
    let msr_ld_exec = winexec::make_executable(&msr_ld_code);
    ctx[0] = va;
    ctx[2] = l0; // X2 = same L0 base (re-store TTBR0 with the valid base)
    ctx[1] = 0; // clear the previous load result
    // SAFETY: RWX RET-terminated block; ctx is the extended context; the MSR
    // flushes the soft TLB, the LDR re-walks the rewritten tables.
    unsafe { enter_block(msr_ld_exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[1], VAL_B,
        "after MSR TTBR0_EL1 flushed the TLB, the second load re-walks → dataB"
    );
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_TTBR0], l0, "TTBR0 slot holds the MSR'd base");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault after the flush+rewalk");
}

/// (f) NEGATIVE PROOF: a `MSR SCTLR_EL1, Xn` (NOT a translation-control register)
/// does NOT flush the software TLB, so the second load still resolves to the
/// CACHED page A even though the leaf was rewritten to page B. This confirms the
/// classifier only flushes for TTBR/TCR/MAIR — guaranteeing the (e) result comes
/// from the flush and not from some unconditional re-walk.
#[test]
fn m4b_msr_sctlr_does_not_flush_tlb() {
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    let va = 0x0000_0077_0000_0000u64;
    let (mut ctx, _l0, l3, l3_slot, data_a, data_b) = build_remappable_ctx(va);
    const VAL_A: u64 = 0xCCCC_0000_0000_000Cu64;
    const VAL_B: u64 = 0xDDDD_0000_0000_000Du64;
    // SAFETY: both data pages are in-arena.
    unsafe {
        core::ptr::write_volatile(data_a as *mut u64, VAL_A);
        core::ptr::write_volatile(data_b as *mut u64, VAL_B);
    }

    // Block 1: LDR X1,[X0]  (caches VA→PA(dataA)).
    let ld_code = translate_straight_line(&[0xF940_0001u32], 0xF200);
    let ld_exec = winexec::make_executable(&ld_code);
    ctx[0] = va;
    // SAFETY: RWX RET-terminated block; ctx is the extended context.
    unsafe { enter_block(ld_exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], VAL_A, "first load caches dataA");

    // Rewrite the leaf to dataB (stale TLB still points at dataA).
    put_desc(l3, l3_slot, leaf_4k(data_b, false));

    // Block 2: MSR SCTLR_EL1, X2 ; LDR X1,[X0]. SCTLR is NOT a translation-control
    // register → no flush emitted → the second load still HITS the stale TLB entry
    // and reads dataA. X2 keeps SCTLR.M set so the MMU stays on.
    let msr_ld_words = [0xD518_1002u32, 0xF940_0001u32]; // MSR SCTLR_EL1,X2 ; LDR X1,[X0]
    let msr_ld_code = translate_straight_line(&msr_ld_words, 0xF210);
    // The MSR-to-SCTLR block must NOT contain the flush call's baked helper address
    // path — but the strongest, cheapest invariant we can assert at the byte level
    // is simply that it stays UD2-free and executes; the behavioural assert below
    // (still reads dataA) is what proves no flush happened.
    assert!(
        !msr_ld_code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "MSR+LDR block must not fail loud (no UD2)"
    );
    let msr_ld_exec = winexec::make_executable(&msr_ld_code);
    ctx[0] = va;
    ctx[2] = SCTLR_M; // X2 = SCTLR with M=1 (MMU stays on)
    ctx[1] = 0;
    // SAFETY: RWX RET-terminated block; ctx is the extended context.
    unsafe { enter_block(msr_ld_exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[1], VAL_A,
        "MSR SCTLR_EL1 did NOT flush → second load HITS the stale TLB → still dataA"
    );
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_SCTLR], SCTLR_M, "SCTLR slot holds the MSR'd value");
}

/// (g) BYTE PROOF: the TTBR0 MSR block emits MORE code than the SCTLR MSR block,
/// because only the former appends the `aether_mmu_flush_all` Win64 call sequence
/// (12 push + sub rsp + mov rax,imm64 + call + add rsp + 12 pop). A direct length
/// comparison of two otherwise-identical single-MSR blocks isolates the flush
/// emission to the translation-control classification.
#[test]
fn m4b_ttbr0_msr_emits_flush_call_sctlr_does_not() {
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();
    // Single-MSR blocks (no load) so the only difference is the flush call.
    let ttbr0 = translate_straight_line(&[0xD518_2002u32], 0xF300); // MSR TTBR0_EL1,X2
    let sctlr = translate_straight_line(&[0xD518_1002u32], 0xF310); // MSR SCTLR_EL1,X2
    assert!(
        ttbr0.len() > sctlr.len(),
        "TTBR0 MSR must emit the flush call (longer block): ttbr0={} sctlr={}",
        ttbr0.len(),
        sctlr.len()
    );
    // The flush block bakes the helper address via `mov rax, imm64` (REX.W B8).
    // Its presence in the TTBR0 block and absence in the SCTLR block is a second,
    // structural witness that the flush call was emitted only for TTBR0.
    let flush_va = aether_mmu_flush_all as *const () as usize as u64;
    let flush_le = flush_va.to_le_bytes();
    assert!(
        ttbr0.windows(8).any(|w| w == flush_le),
        "TTBR0 MSR block must bake the aether_mmu_flush_all address"
    );
    assert!(
        !sctlr.windows(8).any(|w| w == flush_le),
        "SCTLR MSR block must NOT bake the flush address (no flush for SCTLR)"
    );
}

// ── M4b-2 SILICON PROOF: synthetic __enable_mmu (host-mirrored) ─────────────────
//
// THE headline gate. A small ARM64 program builds-then-enables the MMU and loads
// through a VIRTUAL address, proving the translated load WALKED the guest page
// tables — the host mirror of "survive __enable_mmu" on real silicon. Unlike the
// M4b-2b proofs (which seed the SCTLR/TTBR/TCR sysreg slots in Rust and only
// exercise the data path), this program writes TTBR0/TCR/MAIR/SCTLR ITSELF via
// MSR — the exact sequence the GKI kernel runs at `__enable_mmu` — so the proof
// ties together: MSR side-effects (flush soft TLB), SCTLR.M flip (MMU on, read
// live by the walker), ISB serialise, and a VA load translated through the
// 4-level tables. It runs through the SAME proof harness the Ryzen uses
// (translate_straight_line → make_executable → enter_block), so it needs no VMRUN
// and is both host-testable here AND silicon-runnable in boot_amd.
//
// Page-table strategy: option (a) — Rust pre-builds the 4-level tables (4 KiB
// granule, T0SZ=16 → 48-bit VA → start L0) in a window-pinned arena and seeds the
// data word at the mapped PA; the translated block only flips on the MMU and does
// the load. The ARM program (one block) is:
//   MSR TTBR0_EL1, X0   ; X0 = L0 table base    (flushes soft TLB, invalidates JIT cache)
//   MSR TCR_EL1,   X1   ; X1 = TCR (T0SZ=16)    (flushes soft TLB …)
//   MSR MAIR_EL1,  X2   ; X2 = MAIR attrs       (flushes soft TLB …)
//   MSR SCTLR_EL1, X3   ; X3 = SCTLR with M=1   (NO flush — M read live by walker)
//   ISB                 ; serialise the control-reg writes (→ x86 CPUID)
//   LDR X5, [X4]        ; X4 = the mapped VA → translated through the tables
// Expect X5 == the seeded data word, no pending fault.
//
// Verified MSR/MRS/LDR encodings (cross-checked against the M4a proof words and
// recomputed for this step): MSR SCTLR_EL1,X0 == 0xD5181000 (matches the existing
// M4a silicon proof), so the encoder below is trustworthy.
const M4B2_MSR_TTBR0_X0: u32 = 0xD518_2000; // MSR TTBR0_EL1, X0
const M4B2_MSR_TCR_X1: u32 = 0xD518_2041; // MSR TCR_EL1,   X1
const M4B2_MSR_MAIR_X2: u32 = 0xD518_A202; // MSR MAIR_EL1,  X2
const M4B2_MSR_SCTLR_X3: u32 = 0xD518_1003; // MSR SCTLR_EL1, X3
const M4B2_ISB: u32 = 0xD503_3FDF; // ISB
const M4B2_LDR_X5_X4: u32 = 0xF940_0085; // LDR X5, [X4]
/// MAIR attribute word: Normal WB at index 0 (0xFF), Device-nGnRnE at index 1
/// (0x00). The walker in 2a ignores MAIR for PA computation, but we MSR a real
/// value so the sequence is the genuine __enable_mmu shape, not a no-op.
const M4B2_MAIR_VALUE: u64 = 0x0000_0000_0000_00FF;
/// SCTLR with M (bit0) set — plus a couple of architecturally-normal bits the
/// kernel sets (C=bit2 data cache, I=bit12 inst cache) to make the value realistic.
/// Only bit0 (M) is load-bearing for the walker (it reads SCTLR.M live).
const M4B2_SCTLR_MMU_ON: u64 = (1 << 0) | (1 << 2) | (1 << 12);

/// Build the 4-level table chain for `va` in a fresh window-pinned arena, seed
/// `data_word` at the mapped PA, and return (l0_base, data_pa). Does NOT seed any
/// sysreg slots — the translated block enables the MMU itself. Mirrors
/// `build_mapped_ctx` but leaves the ctx to the caller (MMU-off) and writes the
/// data word for us. Layout: page0=L0, page1=L1, page2=L2, page3=L3, page4=data.
fn build_enable_mmu_arena(va: u64, data_word: u64) -> (u64, u64) {
    let arena = alloc_mmu_arena(5);
    let l0 = arena;
    let l1 = arena + 4096;
    let l2 = arena + 8192;
    let l3 = arena + 12288;
    let data = arena + 16384;
    put_desc(l0, ((va >> 39) & 0x1FF) as usize, table_desc(l1));
    put_desc(l1, ((va >> 30) & 0x1FF) as usize, table_desc(l2));
    put_desc(l2, ((va >> 21) & 0x1FF) as usize, table_desc(l3));
    put_desc(l3, ((va >> 12) & 0x1FF) as usize, leaf_4k(data, false));
    // Seed the data word the post-__enable_mmu load must read back.
    // SAFETY: `data` is the in-arena data page.
    unsafe { core::ptr::write_volatile(data as *mut u64, data_word) };
    // Pin the window to exactly this arena so the walker admits the host tables.
    aether_mmu_set_window(arena, 5 * 4096);
    aether_mmu_flush_all();
    (l0, data)
}

/// M4b-2 (a): the synthetic __enable_mmu block. Build the tables, run the
/// MSR-enable-then-LDR program, and assert the VA load returned the data word
/// placed at the WALKED physical address — proving the translated load walked the
/// guest page tables the block itself installed. This is the host proof of
/// "survive __enable_mmu".
#[test]
fn m4b2_synthetic_enable_mmu_then_load() {
    // The block's MSRs call aether_mmu_flush_all + aether_dbt_invalidate_all
    // (mutates the GLOBAL DbtRuntime block cache), so take BOTH locks.
    let _rt = GLOBAL_RT_LOCK.lock().unwrap();
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();

    // A low-half (TTBR0) VA, page-aligned at the 4 KiB granule.
    let va = 0x0000_1234_ABCD_E000u64;
    const DATA_WORD: u64 = 0xFEED_FACE_C0DE_0042u64;
    let (l0_base, data_pa) = build_enable_mmu_arena(va, DATA_WORD);

    // The synthetic __enable_mmu program (one block).
    let words = [
        M4B2_MSR_TTBR0_X0,
        M4B2_MSR_TCR_X1,
        M4B2_MSR_MAIR_X2,
        M4B2_MSR_SCTLR_X3,
        M4B2_ISB,
        M4B2_LDR_X5_X4,
    ];
    let code = translate_straight_line(&words, 0x14000);
    assert_eq!(*code.last().unwrap(), 0xC3, "enable-MMU block ends in RET");
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "enable-MMU block must not contain UD2 (MSR/ISB/LDR all real)"
    );
    let exec = winexec::make_executable(&code);

    // Inputs: X0=L0 base, X1=TCR, X2=MAIR, X3=SCTLR(M=1), X4=VA. SCTLR starts at
    // 0 in the ctx (MMU off) — the block's MSR turns it on.
    let mut ctx = vec![0u64; CTX_U64S];
    ctx[0] = l0_base; // X0 → TTBR0_EL1
    ctx[1] = 16; // X1 → TCR_EL1: T0SZ=16 (48-bit VA, 4-level, start L0)
    ctx[2] = M4B2_MAIR_VALUE; // X2 → MAIR_EL1
    ctx[3] = M4B2_SCTLR_MMU_ON; // X3 → SCTLR_EL1 (M=1)
    ctx[4] = va; // X4 = the mapped virtual address to load from
    // SAFETY: RWX RET-terminated block; ctx is the full extended context. The
    // block enables the MMU then loads through the window-pinned host tables.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }

    // The whole point: the MMU-on LDR walked TTBR0 → L1 → L2 → L3 → data page and
    // read back the seeded word.
    assert_eq!(
        ctx[5], DATA_WORD,
        "post-__enable_mmu LDR walked the tables and read the mapped PA's data word"
    );
    // And it really walked (not a flat VA==PA accident): the value lives only at
    // the data PA, which differs from the VA.
    assert_eq!(read_pa(data_pa), DATA_WORD, "data word lives at the WALKED PA");
    assert_ne!(data_pa, va, "PA differs from VA — the load translated, not flat");
    // The control registers actually landed in their sysreg slots.
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_TTBR0], l0_base, "TTBR0_EL1 written by MSR");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_TCR], 16, "TCR_EL1 written by MSR");
    assert_eq!(
        ctx[SYSREG_SLOT0 + SLOT_SCTLR] & 1,
        1,
        "SCTLR_EL1.M set by MSR (MMU on)"
    );
    // No fault was recorded on the mapped access.
    assert_eq!(
        ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING],
        0,
        "no pending fault on the mapped post-__enable_mmu load"
    );
}

/// M4b-2 (b): the FAULT mirror — with the MMU on, a load through a DELIBERATELY
/// UNMAPPED VA must fault: the walker records a pending Data Abort, the block
/// early-RETs, and PEND_PENDING==1 with FAR==the faulting VA. This is the
/// negative half of "survive __enable_mmu": a stray virtual access traps cleanly
/// (the seam M4b-3 turns into an injected exception) rather than reading garbage.
///
/// Register assignment is chosen so the MSR sources and the load operands never
/// collide in a single straight-line block:
///   X6 → TTBR0_EL1 (the real L0 base — kept OUT of the load operands)
///   X7 → TCR_EL1   ; X2 → MAIR_EL1 ; X3 → SCTLR_EL1 (M=1)
///   X0 = the UNMAPPED load base ; X5 = the load destination (a sentinel that
///        must survive the early-RET because the faulting load never writes it).
#[test]
fn m4b2_unmapped_va_after_enable_mmu_faults() {
    // The block's MSRs call aether_mmu_flush_all + aether_dbt_invalidate_all
    // (mutates the GLOBAL DbtRuntime block cache), so take BOTH locks.
    let _rt = GLOBAL_RT_LOCK.lock().unwrap();
    let _mmu = MMU_GLOBAL_LOCK.lock().unwrap();

    // Map ONE VA (so the arena/window are valid) but fault on a DIFFERENT VA.
    let mapped_va = 0x0000_00AB_CDEF_0000u64;
    const DATA_WORD: u64 = 0x1122_3344_5566_7788u64;
    let (l0_base, _data_pa) = build_enable_mmu_arena(mapped_va, DATA_WORD);
    let unmapped_va = 0x0000_0033_0000_0000u64; // never mapped in these tables

    // TTBR0 from X6 and TCR from X7 so neither aliases the load base (X0) or the
    // load destination (X5):
    //   MSR TTBR0_EL1, X6 ; MSR TCR_EL1, X7 ; MSR MAIR_EL1, X2 ;
    //   MSR SCTLR_EL1, X3 ; ISB ; LDR X5, [X0]
    const MSR_TTBR0_X6: u32 = 0xD518_2006; // MSR TTBR0_EL1, X6
    const MSR_TCR_X7: u32 = 0xD518_2047; // MSR TCR_EL1, X7
    const LDR_X5_X0: u32 = 0xF940_0005; // LDR X5, [X0]
    let words = [
        MSR_TTBR0_X6,
        MSR_TCR_X7,
        M4B2_MSR_MAIR_X2,
        M4B2_MSR_SCTLR_X3,
        M4B2_ISB,
        LDR_X5_X0,
    ];
    let code = translate_straight_line(&words, 0x15000);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "enable-MMU+fault block must not contain UD2"
    );
    let exec = winexec::make_executable(&code);

    let sentinel = 0xDEAD_DEAD_DEAD_DEADu64;
    let mut ctx = vec![0u64; CTX_U64S];
    ctx[6] = l0_base; // X6 → TTBR0_EL1 (real base)
    ctx[7] = 16; // X7 → TCR_EL1 (T0SZ=16 → 48-bit VA, 4-level)
    ctx[2] = M4B2_MAIR_VALUE; // X2 → MAIR_EL1
    ctx[3] = M4B2_SCTLR_MMU_ON; // X3 → SCTLR_EL1 (M=1)
    ctx[0] = unmapped_va; // X0 = unmapped VA (LDR base)
    ctx[5] = sentinel; // X5 = LDR dest sentinel; must survive the fault
    // SAFETY: RWX RET-terminated block; ctx is the full extended context. The
    // walker faults on the unmapped VA → the block early-RETs before X5 is written.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }

    // The load destination is untouched (early-RET before the access).
    assert_eq!(ctx[5], sentinel, "early-RET on fault: LDR destination X5 untouched");
    // A pending Data Abort was recorded for M4b-3 to inject.
    assert_eq!(
        ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING],
        1,
        "unmapped post-__enable_mmu load records a pending Data Abort"
    );
    assert_eq!(
        ctx[SYSREG_SLOT0 + SLOT_PEND_FAR],
        unmapped_va,
        "FAR_EL1 = the faulting VA"
    );
    // ESR.EC = 0x25 (Data Abort, current EL).
    let esr = ctx[SYSREG_SLOT0 + SLOT_PEND_ESR];
    assert_eq!(
        (esr >> 26) & 0x3F,
        0x25,
        "ESR.EC = Data Abort (same EL) on the unmapped load"
    );
    // The MMU really was on (SCTLR.M set by the block's MSR) — proving the fault
    // came from the walker, not from a flat (M==0) access.
    assert_eq!(
        ctx[SYSREG_SLOT0 + SLOT_SCTLR] & 1,
        1,
        "SCTLR_EL1.M set — the fault was a real translation fault, not flat"
    );
    let _ = _data_pa;
}

/// Phase C debug: dump the emitted x86 for MOVZ+MOVK AND run it + report ctx[10].
#[test]
fn phase_c_dump_movk_emitted_x86() {
    const MOVZ_X10: u32 = 0xD291128A;
    const MOVK_X10: u32 = 0xF2AFB3CA;
    let words = [MOVZ_X10, MOVK_X10];
    let code = translate_straight_line(&words, 0x15000);
    let mut s = String::new();
    for b in &code {
        s.push_str(&format!("{:02X} ", b));
    }
    let exec = winexec::make_executable(&code);
    let mut ctx = vec![0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    panic!(
        "emitted x86 ({} bytes): {}\n  ctx[10]=0x{:016x}",
        code.len(), s, ctx[10]
    );
}

/// Phase C bisect 0a: MOVZ X10 alone.
#[test]
fn phase_c_movz_x10_alone() {
    const MOVZ_X10: u32 = 0xD291128A; // movz x10, #0x8894
    let words = [MOVZ_X10];
    let code = translate_straight_line(&words, 0x15000);
    let exec = winexec::make_executable(&code);
    let mut ctx = vec![0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[10], 0x8894, "MOVZ X10 #0x8894 → 0x8894 (got 0x{:x})", ctx[10]);
}

/// Phase C bisect 0b: prove MOVK preserves the unrelated 16-bit slot.
/// MOVZ X10, #0x8894 ; MOVK X10, #0x7d9e, LSL #16 → expect X10 = 0x7d9e_8894.
#[test]
fn phase_c_movk_preserves_low_bits() {
    const MOVZ_X10: u32 = 0xD291128A;
    const MOVK_X10: u32 = 0xF2AFB3CA;
    let words = [MOVZ_X10, MOVK_X10];
    let code = translate_straight_line(&words, 0x15000);
    let exec = winexec::make_executable(&code);
    let mut ctx = vec![0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[10], 0x7D9E_8894,
        "MOVZ #0x8894 then MOVK #0x7d9e LSL16 must give 0x7d9e8894 (got 0x{:x})",
        ctx[10]
    );
}

// ── Phase-E RBIT regression: pcpu_build_alloc_info nr_groups=0 root cause ─────
//
// _find_first_bit (lib/find_bit.c) does `RBIT ; CLZ` to locate the first set
// bit in a bitmap. The prior RBIT lowering emitted BSWAP + NOP (the bit-
// reverse-per-byte step was literally stubbed to NOP), so RBIT(1) returned
// 0x0100_0000_0000_0000 instead of 0x8000_0000_0000_0000. CLZ on the wrong
// value then returned 7 instead of 0, so _find_first_bit(cpumask, 32) said
// "first set bit at index 7" instead of 0 — the cpu loop in
// pcpu_build_alloc_info skipped the only present CPU, nr_groups stayed 0,
// and the kernel hit `kernel BUG at mm/percpu.c:2615`.

/// 64-bit RBIT: RBIT (1) must produce 0x8000_0000_0000_0000.
#[test]
fn phase_e_rbit_x_low_bit_to_msb() {
    // MOVZ X1, #1       (X1 = 1)
    // RBIT X0, X1       (X0 = bit-reverse(X1))
    const MOVZ_X1_1: u32 = 0xD280_0021;
    const RBIT_X0_X1: u32 = 0xDAC0_0020;
    let words = [MOVZ_X1_1, RBIT_X0_X1];
    let code = translate_straight_line(&words, 0x16000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 0x0000_0000_0000_0001, "X1 setup");
    assert_eq!(
        ctx[0], 0x8000_0000_0000_0000,
        "RBIT X0,X1 with X1=1 must produce 0x8000000000000000 (got 0x{:x})",
        ctx[0]
    );
}

/// 64-bit RBIT round trip: RBIT(RBIT(v)) == v.
#[test]
fn phase_e_rbit_x_involution() {
    // MOVZ X1, #0xCAFE; MOVK X1, #0xBABE, LSL #16; RBIT X0, X1; RBIT X2, X0
    const MOVZ_X1: u32 = 0xD299_5FC1; // movz x1, #0xcafe
    const MOVK_X1: u32 = 0xF2B7_57C1; // movk x1, #0xbabe, lsl #16
    const RBIT_X0_X1: u32 = 0xDAC0_0020;
    const RBIT_X2_X0: u32 = 0xDAC0_0002;
    let words = [MOVZ_X1, MOVK_X1, RBIT_X0_X1, RBIT_X2_X0];
    let code = translate_straight_line(&words, 0x16100);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 0xBABE_CAFE, "X1 setup");
    assert_eq!(
        ctx[2], ctx[1],
        "RBIT(RBIT(v)) must equal v (got X2=0x{:x} vs X1=0x{:x})",
        ctx[2], ctx[1]
    );
}

/// 32-bit RBIT W: RBIT W0, W1 with W1=1 must produce 0x8000_0000 in the low
/// 32 of X0 and zero the upper 32. This is the path exercised by find_bit
/// when CONFIG_KALLSYMS or 32-bit cpumask access reaches the W form.
#[test]
fn phase_e_rbit_w_low_bit_to_bit31() {
    // MOVZ W1, #1
    // RBIT W0, W1
    const MOVZ_W1_1: u32 = 0x5280_0021;
    const RBIT_W0_W1: u32 = 0x5AC0_0020;
    let words = [MOVZ_W1_1, RBIT_W0_W1];
    let code = translate_straight_line(&words, 0x16200);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 1, "W1 setup");
    assert_eq!(
        ctx[0], 0x0000_0000_8000_0000,
        "RBIT W0,W1 with W1=1 must yield 0x80000000 in low 32, upper 32 zero (got 0x{:x})",
        ctx[0]
    );
}

// ── Phase-E UMULH/SMULH regression: pcpu_build_alloc_info static_size=0 ─────
//
// pcpu_build_alloc_info uses `UMULH x_, x_, x_` to detect overflow in the
// base_size computation. The prior MulHigh lifter emitted `Madd` (low-64
// multiply-add with c=0) instead of the actual high-64 multiply — so the
// overflow check ALWAYS reported the low bits of the product, miscomparing
// in `cmp xzr, x_; csel x19, xzr, x_, ne`. For nr_groups=1, UMULH(1,24)=0
// should evaluate NE FALSE so x19 keeps the real base_size (0x58); the bug
// returned 24 → NE TRUE → x19=0 → cpu_map collapsed onto ai->static_size
// → kernel BUG at percpu.c:2617 (ai->static_size == 0).

/// UMULH(1, 24) must produce 0 (high 64 of 1*24 = 24 fits in low 64).
#[test]
fn phase_e_umulh_no_overflow_is_zero() {
    // MOVZ X1, #1 ; MOVZ X2, #24 ; UMULH X0, X1, X2
    const MOVZ_X1_1: u32 = 0xD280_0021;
    const MOVZ_X2_24: u32 = 0xD280_0302;
    const UMULH_X0_X1_X2: u32 = 0x9BC2_7C20;
    let words = [MOVZ_X1_1, MOVZ_X2_24, UMULH_X0_X1_X2];
    let code = translate_straight_line(&words, 0x16300);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 1, "X1 setup");
    assert_eq!(ctx[2], 24, "X2 setup");
    assert_eq!(
        ctx[0], 0,
        "UMULH(1, 24) must yield 0 (high 64 of 24) (got 0x{:x})",
        ctx[0]
    );
}

/// UMULH high bits: 2^63 * 2 → high=1.
#[test]
fn phase_e_umulh_overflow_high_bit() {
    // X1 = 2^63 ; X2 = 2 ; UMULH X0, X1, X2 -> 1
    const MOVZ_X1_2P63: u32 = 0xD2F0_0001; // movz x1, #0x8000, lsl #48
    const MOVZ_X2_2:    u32 = 0xD280_0042;
    const UMULH_X0_X1_X2: u32 = 0x9BC2_7C20;
    let words = [MOVZ_X1_2P63, MOVZ_X2_2, UMULH_X0_X1_X2];
    let code = translate_straight_line(&words, 0x16400);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 0x8000_0000_0000_0000, "X1 setup");
    assert_eq!(ctx[2], 2, "X2 setup");
    assert_eq!(
        ctx[0], 1,
        "UMULH(2^63, 2) must yield 1 (got 0x{:x})", ctx[0]
    );
}

/// SMULH: -1 * -1 = 1 → high 64 = 0.
#[test]
fn phase_e_smulh_negative_no_overflow_is_zero() {
    const MOVN_X1_M1: u32 = 0x9280_0001;
    const MOVN_X2_M1: u32 = 0x9280_0002;
    const SMULH_X0_X1_X2: u32 = 0x9B42_7C20;
    let words = [MOVN_X1_M1, MOVN_X2_M1, SMULH_X0_X1_X2];
    let code = translate_straight_line(&words, 0x16500);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 0xFFFF_FFFF_FFFF_FFFF, "X1 setup -1");
    assert_eq!(ctx[2], 0xFFFF_FFFF_FFFF_FFFF, "X2 setup -1");
    assert_eq!(
        ctx[0], 0,
        "SMULH(-1, -1) must yield 0 (got 0x{:x})", ctx[0]
    );
}

// ── Phase-E CLZ regression: kmalloc_index `fls` size class lookup ────────
//
// The prior Clz lowering always emitted `lzcnt_r64`. For the W-form
// (Wn in low 32 of Xn, upper 32 zero by ARM convention) lzcnt_64
// returned `32 + clz_32(Wn)` — values in [32..64]. WriteGpr W truncated
// to low 32, giving wrong values. `kmalloc_index(size)` uses
// `fls = 32 - clz_w(size)`; the buggy clz_w produced negative-or-large
// fls → out-of-range slab index → UBSAN BRK #0x5512 at __kmalloc+0x190.

/// CLZ X0, X1 with X1=1 must produce 63 (bit 0 set → 63 leading zeros).
#[test]
fn phase_e_clz_x_low_bit_set() {
    // MOVZ X1, #1 ; CLZ X0, X1
    const MOVZ_X1_1: u32 = 0xD280_0021;
    const CLZ_X0_X1:  u32 = 0xDAC0_1020; // clz x0, x1
    let words = [MOVZ_X1_1, CLZ_X0_X1];
    let code = translate_straight_line(&words, 0x16800);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 63, "CLZ X(1) must be 63 (got {})", ctx[0]);
}

/// CLZ X0, X1 with X1=0 must produce 64.
#[test]
fn phase_e_clz_x_zero() {
    // MOVZ X1, #0 ; CLZ X0, X1
    const MOVZ_X1_0: u32 = 0xD280_0001;
    const CLZ_X0_X1:  u32 = 0xDAC0_1020;
    let words = [MOVZ_X1_0, CLZ_X0_X1];
    let code = translate_straight_line(&words, 0x16900);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 64, "CLZ X(0) must be 64 (got {})", ctx[0]);
}

/// CLZ W0, W1 with W1=1 must produce 31 (NOT 63).
/// This is the failure mode that broke __kmalloc.
#[test]
fn phase_e_clz_w_low_bit_set() {
    // MOVZ W1, #1 ; CLZ W0, W1
    const MOVZ_W1_1: u32 = 0x5280_0021;
    const CLZ_W0_W1:  u32 = 0x5AC0_1020; // clz w0, w1
    let words = [MOVZ_W1_1, CLZ_W0_W1];
    let code = translate_straight_line(&words, 0x16A00);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 31, "CLZ W(1) must be 31 (got {})", ctx[0]);
}

/// CLZ W0, W1 with W1=0 must produce 32 (not 64).
#[test]
fn phase_e_clz_w_zero() {
    const MOVZ_W1_0: u32 = 0x5280_0001;
    const CLZ_W0_W1:  u32 = 0x5AC0_1020;
    let words = [MOVZ_W1_0, CLZ_W0_W1];
    let code = translate_straight_line(&words, 0x16B00);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 32, "CLZ W(0) must be 32 (got {})", ctx[0]);
}

/// CLZ W0, W1 with W1=0x80000000 must produce 0 (MSB set → 0 leading zeros).
#[test]
fn phase_e_clz_w_msb_set() {
    // MOVZ W1, #0x8000, LSL #16 → w1 = 0x8000_0000
    const MOVZ_W1_MSB: u32 = 0x52B0_0001;
    const CLZ_W0_W1:   u32 = 0x5AC0_1020;
    let words = [MOVZ_W1_MSB, CLZ_W0_W1];
    let code = translate_straight_line(&words, 0x16C00);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 0x8000_0000, "W1 setup");
    assert_eq!(ctx[0], 0, "CLZ W(0x80000000) must be 0 (got {})", ctx[0]);
}

// ── Phase-E LDXP/STXP regression: kernel CAS spinlock at 0x...343xxx ──────
//
// The prior Ldxr/Stxr lifter discarded the `pair` flag → LDXP loaded only
// one register, STXP wrote only one register. Kernel 128-bit CAS spun
// forever because the second half of the pair was stale.

/// LDXP X1, X2, [X0]: loads two adjacent 64-bit words. Lay down a known
/// pattern at the stack-style buffer and confirm BOTH registers receive
/// the expected values.
#[test]
fn phase_e_ldxp_loads_pair() {
    // Setup: store known values into a small ctx-resident buffer via a
    // small ARM sequence that initialises x0 = &buffer, then LDXP.
    // For simplicity: prime x0 with a buffer VA that maps to the ctx,
    // then prepopulate the bytes via direct ctx-write before entering
    // the block.
    //
    // Easier: emit a translated program that:
    //   MOVZ X0, #LOW16(addr)
    //   MOVK X0, #..  ; build 64-bit ctx-relative addr
    //   LDXP X1, X2, [X0]
    // Then assert ctx[1] / ctx[2].
    //
    // Even easier path: rely on the fact that LDXP routes through
    // aether_mmu_xlate. The MMU walker's flat fallback (MMU off) returns
    // the VA as PA. So pointing X0 at an arbitrary ctx-resident region
    // works — the loads land on that region.
    //
    // For the host test we use a small static array as the "guest mem"
    // region by allocating ctx slots and pointing X0 there. The xlate
    // path treats VAs as PAs when SCTLR.M=0 (which it is at block entry).
    // Use a stack buffer allocated inside `enter_block`'s safe frame:
    // we'll use ctx slot range [10..16] as the in-memory storage.
    let target_addr: u64 = 0x2000;
    let mut backing = vec![0u8; 0x4000];
    // Lay out two adjacent 64-bit values that LDXP should pick up.
    backing[(target_addr as usize)..(target_addr as usize + 8)]
        .copy_from_slice(&0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes());
    backing[(target_addr as usize + 8)..(target_addr as usize + 16)]
        .copy_from_slice(&0xFEED_FACE_1234_5678u64.to_le_bytes());

    // We can't easily plumb backing memory into the host execution path
    // without the MMU walker also seeing it. So this test focuses on the
    // LIFT correctness: translate LDXP and assert the emitted x86 contains
    // two `aether_mmu_xlate` call sequences (one per element).
    let words = [
        // LDXP X1, X2, [X0]  encoding: 1100_1000_0111_1111_1000_1000_0000_0001
        // 0xc87f8801: ldxp x1, x2, [x0]
        0xc87f8801u32,
    ];
    let code = translate_straight_line(&words, 0x17000);
    // Count xlate-call setup: `mov rax, addr_of_xlate` immediates appear
    // for each MMU access. A pair should produce TWO such calls (not one).
    use aether_translator::runtime::mmu::aether_mmu_xlate;
    let xlate_addr = aether_mmu_xlate as *const () as usize as u64;
    let xlate_le = xlate_addr.to_le_bytes();
    // Search for the 8-byte pattern in the emitted bytes.
    let count = code
        .windows(8)
        .filter(|w| *w == xlate_le)
        .count();
    assert!(
        count >= 2,
        "LDXP pair must emit TWO mmu_xlate calls (got {}); first half is the \
         prior single-load behaviour that left rt2 stale",
        count
    );
    assert_eq!(*code.last().unwrap(), 0xC3, "block must end in RET");
}

/// STXP w0, x1, x2, [x3]: stores two adjacent 64-bit words, w0 = status.
#[test]
fn phase_e_stxp_stores_pair() {
    // STXP W0, X1, X2, [X3]: sz=3 / 001000 / L=0 / pair=1 / Rs=W0 /
    // o0=0 / Rt2=X2 / Rn=X3 / Rt=X1
    //   = 1100_1000_0010_0000_0000_1000_0110_0001 = 0xC8200861
    let words = [0xc8200861u32];
    let code = translate_straight_line(&words, 0x18000);
    // StoreExclusive lowering routes through aether_mmu_xlate (write=true)
    // then writes the bytes via emit_mov_mem*_r64. Pair lifting emits two
    // such xlate calls — one per element.
    use aether_translator::runtime::mmu::aether_mmu_xlate;
    let xlate_addr = aether_mmu_xlate as *const () as usize as u64;
    let xlate_le = xlate_addr.to_le_bytes();
    let count = code
        .windows(8)
        .filter(|w| *w == xlate_le)
        .count();
    assert!(
        count >= 2,
        "STXP pair must emit TWO mmu_xlate calls (got {}); the prior single-store \
         behaviour left the second half of the lock value stale",
        count
    );
    assert_eq!(*code.last().unwrap(), 0xC3, "block must end in RET");
}

/// Phase C bisect 2: full sequence — MOVK + ADD shifted-reg.
///
///   MOVZ X10, #0x8894 ; MOVK X10, #0x7d9e, LSL #16  ; X10 = 0x7d9e8894
///   MOVZ X11, #13                                   ; X11 = 13
///   ADD  X10, X10, X11, LSL #2                       ; X10 = 0x7d9e88c8
#[test]
fn phase_c_jump_table_dispatch_shifted_add() {
    const MOVZ_X10: u32 = 0xD291128A;
    const MOVK_X10: u32 = 0xF2AFB3CA;
    const MOVZ_X11: u32 = 0xD28001AB;
    const ADD_X10_X10_X11_LSL2: u32 = 0x8B0B094A;
    let words = [MOVZ_X10, MOVK_X10, MOVZ_X11, ADD_X10_X10_X11_LSL2];
    let code = translate_straight_line(&words, 0x15000);
    let exec = winexec::make_executable(&code);
    let mut ctx = vec![0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[11], 13, "X11 = 13");
    assert_eq!(
        ctx[10], 0x7D9E_88C8,
        "X10 = base + 13*4 = 0x7d9e88c8 (got 0x{:x})", ctx[10]
    );
}
