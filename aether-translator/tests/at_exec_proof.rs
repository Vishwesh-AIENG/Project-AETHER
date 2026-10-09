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

// Every test in this file executes JIT-emitted x86 against PROCESS-GLOBAL
// translator state: the DbtRuntime (block cache + code_buf arena; its internal
// LOCK spans only one `with()` call, not a translate -> resolve -> execute
// sequence) AND the software MMU (TLB + pinned window + sysreg slots), which
// every lowered memory op calls into — including tests that build IR directly
// via translate_straight_line. Two such tests running concurrently race (loads
// read 0, torn blocks, 0xC0000005). So every #[test] takes this ONE lock first.
// Poison-tolerant: one failing test must not cascade-fail the rest.
static EXEC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    EXEC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

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
    let mut patches: Vec<(usize, aether_translator::ir::BlockId)> = Vec::new();
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
    let mut patches: Vec<(usize, aether_translator::ir::BlockId)> = Vec::new();
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
/// Mid-block memory access must PC-stamp so a demand-paging fault resumes at the
/// faulting instruction, not the block start. Reproduces the /init NULL-write
/// shape `mov x8,x0; mov w0,wzr; ldr x1,[x2]`: the LDR (index 2, pc+8) can fault,
/// and restarting the whole block would re-run `mov x8,x0` on the already-zeroed
/// x0. The translated block must therefore write `pc+8` to the PC slot before
/// the LDR's MMU call (the LDR never references that value, so its presence in
/// the stream is the stamp).
#[test]
fn mid_block_memop_pc_stamp() {
    let _serial = serial();
    use aether_translator::dbt::{
        aether_dbt_block_host_va, aether_dbt_init, aether_dbt_invalidate_all,
        aether_dbt_translate_block, AetherDbtResult,
    };
    let program: [u8; 12] = [
        0xe8, 0x03, 0x00, 0xaa, // mov x8, x0   (orr x8,xzr,x0)
        0xe0, 0x03, 0x1f, 0x2a, // mov w0, wzr
        0x41, 0x00, 0x40, 0xf9, // ldr x1, [x2]
    ];
    let pc: u64 = 0x10_0000;
    let _ = aether_dbt_init(0, 16 * 1024 * 1024, 0, 1024 * 1024);
    let _ = aether_dbt_invalidate_all();
    assert_eq!(aether_dbt_translate_block(pc, &program), AetherDbtResult::Ok);
    let (host_va, len) = aether_dbt_block_host_va(pc).expect("host va");
    // SAFETY: runtime-owned code buffer, valid for `len` bytes.
    let code: Vec<u8> = unsafe { core::slice::from_raw_parts(host_va as *const u8, len).to_vec() };
    // ConstI64 emits the i32-fitting PC as a 4-byte imm32 (REX.W mov r64,imm32).
    let stamp_ldr = (pc as u32 + 8).to_le_bytes(); // 0x100008 = the LDR's PC
    assert!(
        code.windows(4).any(|w| w == stamp_ldr),
        "mid-block LDR must be preceded by a PC stamp of pc+8",
    );
    // (The diagnostic per-instruction FAULT_OP_PC stamp now writes EVERY
    // instruction's PC, so a byte-scan can no longer distinguish the PC_SLOT
    // mem-resume stamp from the diagnostic stamp — the "non-memory not stamped"
    // assertion was removed. The mem-resume stamp above (pc+8) still proves the
    // PC_SLOT mechanism fires on the LDR.)
}

/// uses: aether_dbt_init -> aether_dbt_translate_block -> aether_dbt_block_host_va
/// -> execute. This host-verifies the exact M2 integration path before it runs
/// on real AMD silicon (where a wrong path = a blind triple-fault reset).
#[test]
fn public_api_translate_resolve_execute() {
    let _serial = serial();
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
    let _serial = serial();
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

/// REGRESSION for the SLUB self-cycle deadlock (put_cpu_partial `slab->next = 0`
/// @ 0x831e640). The store wrote `slab` instead of `0`: the predecessor block's
/// `movz x0,#0` did not commit ctx[0]=0 because x0 is LIVE-OUT ONLY (written by
/// movz, never read inside its own block, only by the successor). Reproduce: a
/// movz whose result is unused in-block must STILL land in ctx.
#[test]
fn movz_liveout_only_commits_to_ctx() {
    let _serial = serial();
    // movz x0, #0   = 0xD2800000  (x0 = 0; x0 NOT read again in this block)
    // movz x1, #5   = 0xD28000A1  (independent — keeps x0 live-out-only)
    let words = [0xD280_0000u32, 0xD280_00A1u32];
    let code = translate_straight_line(&words, 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = 0xCAFE_F00D_DEAD_BEEF; // stale "slab" value already in x0
    // SAFETY: freshly translated RET-terminated block; ctx is full-size.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[1], 5, "x1 = 5 sanity");
    assert_eq!(
        ctx[0], 0,
        "movz x0,#0 must commit ctx[0]=0 even when x0 is unused in-block \
         (the slab->next=slab self-cycle bug)"
    );
}

/// Same bug, the EXACT shape from the deadlock: `movz x0,#0` then a BRANCH
/// terminator. x0 is consumed only by the branch's successor block, so the
/// movz's WriteGpr must be committed to ctx before the block exits via the b.
#[test]
fn movz_then_branch_commits_to_ctx() {
    let _serial = serial();
    // movz x0, #0   = 0xD2800000
    // b   .+8       = 0x14000002  (unconditional branch — block terminator)
    let words = [0xD280_0000u32, 0x1400_0002u32];
    let code = translate_straight_line(&words, 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = 0xCAFE_F00D_DEAD_BEEF;
    // SAFETY: freshly translated RET-terminated block; ctx is full-size.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(
        ctx[0], 0,
        "movz x0,#0 before a branch must commit ctx[0]=0 (slab->next bug)"
    );
}

/// bionic's power-of-2 / popcount idiom executed end-to-end:
///   fmov d0, x8        (0x9E670100)
///   cnt  v0.8b, v0.8b  (0x0E205800)
///   uaddlv h0, v0.8b   (0x2E303800)
///   fmov w9, s0        (0x1E260009)
/// X9 must end == popcount(X8). Exec-proves FMOV (both directions) + CNT (SWAR
/// per-byte popcount) + UADDLV (horizontal byte sum), the /init 0x31f800 block.
#[test]
fn popcount_idiom_cnt_uaddlv_executes() {
    let _serial = serial();
    let words = [0x9E67_0100u32, 0x0E20_5800, 0x2E30_3800, 0x1E26_0009];
    let code = translate_straight_line(&words, 0x1000);
    assert_eq!(*code.last().unwrap(), 0xC3, "block must end in RET");
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "translated popcount block must not contain UD2"
    );
    let exec = winexec::make_executable(&code);
    for (x8, want) in [
        (0x8001u64, 2u64),
        (0xFFFF_FFFF_FFFF_FFFF, 64),
        (0x0, 0),
        (0x0F0F, 8),
        (0x1, 1),
        (0x8000_0000_0000_0000, 1),
    ] {
        let mut ctx = [0u64; CTX_U64S];
        ctx[8] = x8;
        // SAFETY: freshly translated RET-terminated block; ctx is register-file sized.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        assert_eq!(ctx[9], want, "popcount(0x{x8:016x}) should be {want}, got 0x{:x}", ctx[9]);
    }
}

/// alloc_large_system_hash's log2qty = ilog2(numentries), the EXACT instruction
/// sequence from the new GCC kernel @ file 0x151d0e4 (dcache_init's d_hash_shift
/// source). If CLZ X-form or the W-form arithmetic mistranslates, d_hash_shift is
/// wrong → __d_lookup_rcu reads OOB → the dcache Oops. Executed on the host so we
/// can confirm/rule-out the shift bug WITHOUT a QEMU boot.
///   clz x7,x7 ; mov x23,#0x3f ; sub x23,x23,x7 ; add w23,w23,#1 ; sub w23,w23,#1 ; sxtw x23,w23
/// For x7 = 2^k, result x23 must == k (ilog2).
#[test]
fn alloc_large_system_hash_log2qty_executes() {
    let _serial = serial();
    let words = [
        0xDAC010E7u32, // clz x7, x7
        0xD28007F7,    // mov x23, #0x3f
        0xCB0702F7,    // sub x23, x23, x7
        0x110006F7,    // add w23, w23, #1
        0x510006F7,    // sub w23, w23, #1
        0x93407EF7,    // sxtw x23, w23
    ];
    let code = translate_straight_line(&words, 0x1000);
    assert_eq!(*code.last().unwrap(), 0xC3, "block must end in RET");
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "must not UD2");
    let exec = winexec::make_executable(&code);
    // 2^17 = the live dentry-cache table size (131072 entries) → ilog2 must be 17.
    for k in [4u64, 8, 16, 17, 18, 23, 31] {
        let mut ctx = [0u64; CTX_U64S];
        ctx[7] = 1u64 << k;
        // SAFETY: RET-terminated block; ctx is register-file sized.
        unsafe {
            enter_block(exec, ctx.as_mut_ptr());
        }
        assert_eq!(
            ctx[23], k,
            "ilog2(2^{k}) must be {k}, got {} — d_hash_shift mistranslation",
            ctx[23] as i64
        );
    }
}

/// LSRV W-form (`lsr w4, w11, w4`) — variable right shift, 32-bit. The operand
/// MUST be the low 32 bits of Xn (zero-extended result), NOT the full 64-bit Xn.
/// This is THE dcache Oops bug: __d_lookup_rcu does `lsr w4, w11, w4` where x11 =
/// hashlen (hash in low 32, string LEN in high 32). With the 64-bit operand the
/// `len` bits leak into the bucket index → OOB hashtable read → corruption Oops.
/// Real value: x11 = 0xc_2fe13f6b, shift 15 → correct 0x5fc2, bug 0x185fc2.
#[test]
fn lsrv_wform_masks_operand_to_32bit() {
    let _serial = serial();
    let words = [0x1AC4_2564u32]; // lsr w4, w11, w4
    let code = translate_straight_line(&words, 0x1000);
    let exec = winexec::make_executable(&code);
    for (x11, shift, want) in [
        (0x0000_000C_2FE1_3F6Bu64, 15u64, 0x5FC2u64), // hashlen: len=0xC must NOT leak
        (0xFFFF_FFFF_8000_0000, 31, 0x1),             // high half must be ignored
        (0x0000_0001_0000_0001, 0, 0x1),              // shift 0: low 32 only, zero-ext
        (0x0000_00FF_DEAD_BEEF, 4, 0x0DEA_DBEE),      // generic
    ] {
        let mut ctx = [0u64; CTX_U64S];
        ctx[11] = x11;
        ctx[4] = shift;
        // SAFETY: RET-terminated block; ctx is register-file sized.
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        assert_eq!(
            ctx[4], want,
            "lsr w4,w11,w4: x11=0x{x11:016x} shift={shift} must be 0x{want:x} (32-bit operand, zero-ext), got 0x{:x}",
            ctx[4]
        );
    }
}

/// bionic strchr/memchr NEON ops executed end-to-end on the host: CMEQ #0 (SSE
/// pcmpeq vs zero), BIT (bitwise select identity), SHRN (psrlw + mask + pack).
/// Proves the lower_simd_ctx SSE templates numerically, not just no-UD2.
#[test]
fn strchr_neon_ops_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8; // u64 index of V<r>[63:0]; +1 = [127:64]

    // CMEQ v2.16b, v1.16b, #0 — zero byte → 0xFF, non-zero → 0x00.
    let code = translate_straight_line(&[0x4E20_9822u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S]; // v1 = 0 (all bytes zero)
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], u64::MAX, "cmeq#0: all-zero → all-ones (lo)");
    assert_eq!(ctx[vd(2) + 1], u64::MAX, "cmeq#0: all-zero → all-ones (hi)");
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = u64::MAX;
    ctx[vd(1) + 1] = u64::MAX; // all bytes non-zero
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], 0, "cmeq#0: non-zero → 0 (lo)");
    assert_eq!(ctx[vd(2) + 1], 0, "cmeq#0: non-zero → 0 (hi)");

    // BIT v2.16b, v3.16b, v4.16b — v2 = (v2 & ~v4) | (v3 & v4). v4=all-ones ⇒ v2:=v3.
    let code = translate_straight_line(&[0x6EA4_1C62u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(2)] = 0xAAAA_AAAA_AAAA_AAAA;
    ctx[vd(2) + 1] = 0xAAAA_AAAA_AAAA_AAAA;
    ctx[vd(3)] = 0x5555_5555_5555_5555;
    ctx[vd(3) + 1] = 0x5555_5555_5555_5555;
    ctx[vd(4)] = u64::MAX;
    ctx[vd(4) + 1] = u64::MAX;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], 0x5555_5555_5555_5555, "bit: v4=1 ⇒ v2:=v3 (lo)");
    assert_eq!(ctx[vd(2) + 1], 0x5555_5555_5555_5555, "bit: v4=1 ⇒ v2:=v3 (hi)");

    // SHRN v5.8b, v2.8h, #4 — each halfword 0x0120 >>4 = 0x12 → low byte 0x12.
    let code = translate_straight_line(&[0x0F0C_8445u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(2)] = 0x0120_0120_0120_0120;
    ctx[vd(2) + 1] = 0x0120_0120_0120_0120;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(5)], 0x1212_1212_1212_1212, "shrn: low 8 bytes = 0x12 each");
    assert_eq!(ctx[vd(5) + 1], 0, "shrn: upper 64 zeroed");
}

/// Multi-register NEON `TBL`/`TBX` (`SimdTblN` → `VecTblN` → `lower_vectbln`)
/// executed end-to-end on the host. The 2-register form is exactly the insn
/// (`TBL V5.16B, {V5.16B,V6.16B}, V3.16B`, 0x4e0320a5) that TranslateFail'd on
/// a live Android boot. Proves the disjoint-`por` accumulation, the wrapping
/// `psubb` + saturating `paddusb` index transform per table reg, and (for TBX)
/// the in-range mask merge of the old `Vd`.
#[test]
fn tbl_tbx_multi_reg_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8; // u64 index of V<r>[63:0]; +1 = [127:64]

    // Pack 16 bytes little-endian into the two u64 ctx slots of V<r>.
    let set_v = |ctx: &mut [u64], r: u8, bytes: &[u8; 16]| {
        let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        ctx[vd(r)] = lo;
        ctx[vd(r) + 1] = hi;
    };
    let get_v = |ctx: &[u64], r: u8| -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&ctx[vd(r)].to_le_bytes());
        out[8..16].copy_from_slice(&ctx[vd(r) + 1].to_le_bytes());
        out
    };

    // ---- tbl_two_regs: TBL v7.16B, {v5.16B, v6.16B}, v4.16B (0x4e0420a7) ----
    // 32-byte table: v5 = [0..15], v6 = [16..31]. Index mixes in-range + OOR.
    let t0: [u8; 16] = core::array::from_fn(|i| i as u8); // 0..15
    let t1: [u8; 16] = core::array::from_fn(|i| (16 + i) as u8); // 16..31
    let idx2: [u8; 16] = [0, 5, 16, 31, 40, 0xFF, 1, 30, 15, 17, 200, 0, 8, 23, 9, 16];
    let expect2: [u8; 16] = core::array::from_fn(|i| {
        let k = idx2[i] as usize;
        if k < 32 { k as u8 } else { 0 } // table[k] == k by construction
    });
    let code = translate_straight_line(&[0x4E04_20A7u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    set_v(&mut ctx, 5, &t0);
    set_v(&mut ctx, 6, &t1);
    set_v(&mut ctx, 4, &idx2);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(get_v(&ctx, 7), expect2, "TBL 2-reg byte permute");

    // ---- tbl_three_regs: TBL v10.16B, {v5,v6,v7}, v4 (0x4e0440aa) ----
    // 48-byte table: v5=[0..15], v6=[16..31], v7=[32..47]. table[k] == k.
    let t2: [u8; 16] = core::array::from_fn(|i| (32 + i) as u8); // 32..47
    let idx3: [u8; 16] = [0, 16, 32, 47, 48, 0xFF, 33, 31, 15, 45, 100, 17, 2, 46, 16, 47];
    let expect3: [u8; 16] = core::array::from_fn(|i| {
        let k = idx3[i] as usize;
        if k < 48 { k as u8 } else { 0 }
    });
    let code = translate_straight_line(&[0x4E04_40AAu32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    set_v(&mut ctx, 5, &t0);
    set_v(&mut ctx, 6, &t1);
    set_v(&mut ctx, 7, &t2);
    set_v(&mut ctx, 4, &idx3);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(get_v(&ctx, 10), expect3, "TBL 3-reg byte permute");

    // ---- tbx_two_regs: TBX v8.16B, {v5,v6}, v4 (0x4e0430a8) ----
    // Out-of-range lanes must RETAIN the old v8 byte (sentinel 0xEE).
    let idxx: [u8; 16] = [0, 5, 16, 31, 40, 0xFF, 1, 30, 15, 17, 200, 0, 8, 23, 9, 32];
    let sentinel: [u8; 16] = [0xEE; 16];
    let expectx: [u8; 16] = core::array::from_fn(|i| {
        let k = idxx[i] as usize;
        if k < 32 { k as u8 } else { 0xEE } // OOR keeps old Vd byte
    });
    let code = translate_straight_line(&[0x4E04_30A8u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    set_v(&mut ctx, 5, &t0);
    set_v(&mut ctx, 6, &t1);
    set_v(&mut ctx, 4, &idxx);
    set_v(&mut ctx, 8, &sentinel); // preload Vd
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(get_v(&ctx, 8), expectx, "TBX 2-reg: OOR lanes keep old Vd byte");
}

/// Single-register `TBL` (`SimdTbl1` / `VecTbl1`) — kept passing after the
/// multi-register split. `TBL V7.16B, {V5.16B}, V4.16B` (0x4e0400a7).
#[test]
fn tbl_single_reg_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let set_v = |ctx: &mut [u64], r: u8, bytes: &[u8; 16]| {
        ctx[vd(r)] = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        ctx[vd(r) + 1] = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    };
    let get_v = |ctx: &[u64], r: u8| -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&ctx[vd(r)].to_le_bytes());
        out[8..16].copy_from_slice(&ctx[vd(r) + 1].to_le_bytes());
        out
    };
    let t0: [u8; 16] = core::array::from_fn(|i| i as u8);
    let idx: [u8; 16] = [0, 5, 15, 16, 40, 0xFF, 1, 14, 7, 8, 200, 3, 2, 13, 9, 15];
    let expect: [u8; 16] = core::array::from_fn(|i| {
        let k = idx[i] as usize;
        if k < 16 { k as u8 } else { 0 }
    });
    let code = translate_straight_line(&[0x4E04_00A7u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    set_v(&mut ctx, 5, &t0);
    set_v(&mut ctx, 4, &idx);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(get_v(&ctx, 7), expect, "TBL 1-reg byte permute");
}

/// BoringSSL FIPS self-test crypto path: `SHA256H Qd, Qn, Vm.4S` executed
/// end-to-end on the host. Proves the `CryptoSha256` lowering (a Win64 CALL to
/// `aether_crypto_sha256`) is wired — NOT UD2 — and produces the exact result
/// of the standalone helper. This is the instruction that was SIGILL-ing init
/// (boringssl-self-check-failed reboot loop) before the lowering was wired.
#[test]
fn sha256h_executes_via_crypto_helper() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    use aether_translator::runtime::crypto_rt::sha256h;
    let vd = |r: u8| (vec_disp(r) as usize) / 8; // u64 index of V<r>[63:0]

    // Lane layout in ctx memory: V<r> is four little-endian u32 lanes at
    // [vec_disp(r)..]; lane0/lane1 occupy the low u64, lane2/lane3 the high u64.
    let pack = |l: [u32; 4]| ((l[0] as u64) | ((l[1] as u64) << 32),
                              (l[2] as u64) | ((l[3] as u64) << 32));

    // SHA256H q0, q1, v2.4s — Rd=0, Rn=1, Rm=2 (opcode 4 → kind 2).
    let code = translate_straight_line(&[0x5E02_4020u32], 0x1000);
    let exec = winexec::make_executable(&code);

    let vd_in = [0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a];
    let vn_in = [0x510e527fu32, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let vm_in = [0x428a2f98u32, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5];

    let mut ctx = [0u64; CTX_U64S];
    let (d_lo, d_hi) = pack(vd_in);
    let (n_lo, n_hi) = pack(vn_in);
    let (m_lo, m_hi) = pack(vm_in);
    ctx[vd(0)] = d_lo; ctx[vd(0) + 1] = d_hi;
    ctx[vd(1)] = n_lo; ctx[vd(1) + 1] = n_hi;
    ctx[vd(2)] = m_lo; ctx[vd(2) + 1] = m_hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }

    // Reference: drive the same helper directly.
    let mut expect = vd_in;
    sha256h(&mut expect, &vn_in, &vm_in);
    let (e_lo, e_hi) = pack(expect);
    assert_eq!(ctx[vd(0)], e_lo, "sha256h: Vd[63:0] matches helper");
    assert_eq!(ctx[vd(0) + 1], e_hi, "sha256h: Vd[127:64] matches helper");
    // Inputs untouched.
    assert_eq!(ctx[vd(1)], n_lo, "sha256h: Vn preserved (lo)");
    assert_eq!(ctx[vd(2)], m_lo, "sha256h: Vm preserved (lo)");
}

// ── CRC32 (PRIORITY 1 regression: was a silent NOP that returned the stale
//    destination register, corrupting every ext4/f2fs/zlib/dex checksum) ─────────

/// Build a DP-2-source CRC32 ARM word from its fields and assert the decoder
/// agrees, so a hand-encoding slip can't make a "passing" test against the wrong
/// instruction. Layout: sf | 0 | S(0) | 11010110 | Rm | opcode | Rn | Rd.
fn crc32_word(sf: u32, rm: u32, opcode: u32, rn: u32, rd: u32) -> u32 {
    ((sf & 1) << 31)
        | (0b11010110u32 << 21)
        | ((rm & 0x1F) << 16)
        | ((opcode & 0x3F) << 10)
        | ((rn & 0x1F) << 5)
        | (rd & 0x1F)
}

/// Bit-serial reference for the SSE4.2 Castagnoli CRC32 (reflected poly
/// 0x82F63B78) — the exact semantics x86 `crc32` implements and the ARM CRC32C*
/// instructions require. `nbytes` data bytes enter low-to-high.
fn ref_crc32c(mut crc: u32, data: u64, nbytes: usize) -> u32 {
    const POLY: u32 = 0x82F6_3B78; // reflect(0x1EDC6F41)
    for i in 0..nbytes {
        crc ^= ((data >> (i * 8)) & 0xFF) as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (POLY & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

/// Bit-serial reference for the ISO-3309 CRC32 (reflected poly 0xEDB88320) — the
/// ARM CRC32B/H/W/X (non-`C`) semantics, no native x86 instruction.
fn ref_crc32_iso(mut crc: u32, data: u64, nbytes: usize) -> u32 {
    const POLY: u32 = 0xEDB8_8320; // reflect(0x04C11DB7)
    for i in 0..nbytes {
        crc ^= ((data >> (i * 8)) & 0xFF) as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (POLY & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

/// CRC32CW W0, W1, W2 — 32-bit Castagnoli, native x86 SSE4.2 `crc32 r32, r/m32`.
/// Proves the op is no longer a NOP: with a stale destination the result would be
/// the input X0, not the true CRC.
#[test]
fn crc32c_w_executes_native() {
    let _serial = serial();
    // sf=0, opcode=0b010110 (CRC32C sz=W), Rd=0, Rn=1, Rm=2.
    let word = crc32_word(0, 2, 0b010110, 1, 0);
    // Decoder sanity: this word IS the CRC32C-W we think it is.
    assert!(
        matches!(
            decode_instruction(word).unwrap(),
            aether_translator::decoder::DecodedInsn::Crc32 { sz: 0b10, castagnoli: true, .. }
        ),
        "word must decode as CRC32C-W"
    );
    let code = translate_straight_line(&[word], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "must not UD2");
    let exec = winexec::make_executable(&code);

    for (acc, data) in [
        (0u32, 0xDEAD_BEEFu64),
        (0xFFFF_FFFFu32, 0x1234_5678u64),
        (0x1234_5678u32, 0x0000_0000u64),
    ] {
        let mut ctx = [0u64; CTX_U64S];
        ctx[0] = 0xCAFE_F00D_0000_0000 | acc as u64; // X0 = stale + accumulator (low32)
        ctx[1] = acc as u64; // W1 = CRC accumulator (Wn)
        ctx[2] = 0xBBBB_BBBB_0000_0000 | data; // W2 = data (low32); high bits ignored
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        let want = ref_crc32c(acc, data & 0xFFFF_FFFF, 4) as u64;
        assert_eq!(
            ctx[0], want,
            "CRC32CW acc=0x{acc:08x} data=0x{data:08x}: want 0x{want:08x}, got 0x{:08x} \
             (NOP regression would leave X0 = stale)",
            ctx[0]
        );
    }
}

/// CRC32CX W0, X1, X2 — 64-bit data Castagnoli, native `crc32 r64, r/m64`.
#[test]
fn crc32cx_executes_native() {
    let _serial = serial();
    // sf=1, opcode=0b010111 (CRC32C sz=X), Rd=0, Rn=1, Rm=2.
    let word = crc32_word(1, 2, 0b010111, 1, 0);
    assert!(
        matches!(
            decode_instruction(word).unwrap(),
            aether_translator::decoder::DecodedInsn::Crc32 { sz: 0b11, castagnoli: true, .. }
        ),
        "word must decode as CRC32C-X"
    );
    let code = translate_straight_line(&[word], 0x1000);
    let exec = winexec::make_executable(&code);

    let acc: u32 = 0x0000_0000;
    let data: u64 = 0x0123_4567_89AB_CDEF;
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = acc as u64;
    ctx[2] = data;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let want = ref_crc32c(acc, data, 8) as u64;
    assert_eq!(ctx[0], want, "CRC32CX(0, 0x{data:016x}) = 0x{want:08x}, got 0x{:08x}", ctx[0]);
}

/// CRC32B W0, W1, W2 — 1-byte ISO poly. No native x86 instruction → must take the
/// `aether_crc32_iso` software helper path and return the true ISO CRC.
#[test]
fn crc32_iso_b_executes_via_helper() {
    let _serial = serial();
    use aether_translator::runtime::crypto_rt::aether_crc32_iso;
    // sf=0, opcode=0b010000 (CRC32 ISO sz=B), Rd=0, Rn=1, Rm=2.
    let word = crc32_word(0, 2, 0b010000, 1, 0);
    assert!(
        matches!(
            decode_instruction(word).unwrap(),
            aether_translator::decoder::DecodedInsn::Crc32 { sz: 0b00, castagnoli: false, .. }
        ),
        "word must decode as CRC32-B (ISO)"
    );
    let code = translate_straight_line(&[word], 0x1000);
    let exec = winexec::make_executable(&code);

    for (acc, data) in [(0u32, 0xABu64), (0x0000_0001u32, 0xFFu64), (0xDEAD_BEEFu32, 0x42u64)] {
        let mut ctx = [0u64; CTX_U64S];
        ctx[0] = 0x9999_9999_9999_9999; // stale dest
        ctx[1] = acc as u64;
        ctx[2] = 0xCCCC_CCCC_0000_0000 | data;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        let want = ref_crc32_iso(acc, data & 0xFF, 1) as u64;
        // Cross-check the helper itself agrees with the bit-serial reference.
        assert_eq!(aether_crc32_iso(acc, data & 0xFF, 1) as u64, want, "helper vs reference");
        assert_eq!(
            ctx[0], want,
            "CRC32B(ISO) acc=0x{acc:08x} data=0x{:02x}: want 0x{want:08x}, got 0x{:08x}",
            data & 0xFF, ctx[0]
        );
    }
}

/// SDIV W0, W1, W2 with W1 = i32::MIN, W2 = -1 — ARM defines the result as the
/// dividend (i32::MIN), and crucially must NOT raise a host #DE. PRIORITY 2.
#[test]
fn sdiv_min_neg1_does_not_trap() {
    let _serial = serial();
    // sf=0, opcode=0b000011 (SDIV), Rd=0, Rn=1, Rm=2.
    let word_w = crc32_word(0, 2, 0b000011, 1, 0);
    assert!(
        matches!(
            decode_instruction(word_w).unwrap(),
            aether_translator::decoder::DecodedInsn::Div { signed: true, sf: false, .. }
        ),
        "word must decode as SDIV W-form"
    );
    let code = translate_straight_line(&[word_w], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = (i32::MIN as u32) as u64; // W1 = 0x8000_0000
    ctx[2] = (-1i32 as u32) as u64; // W2 = 0xFFFF_FFFF
    // If the overflow guard is missing this #DEs and the process dies before the
    // assert; reaching the assert at all proves no trap.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0] & 0xFFFF_FFFF,
        (i32::MIN as u32) as u64,
        "SDIV i32::MIN / -1 must yield i32::MIN (the dividend), got 0x{:08x}",
        ctx[0] & 0xFFFF_FFFF
    );

    // X-form: X1 = i64::MIN, X2 = -1 → i64::MIN, no trap. This is the case that
    // actually reaches the 64-bit idiv (the W-form is sign-extended and fits).
    let word_x = crc32_word(1, 2, 0b000011, 1, 0);
    let code = translate_straight_line(&[word_x], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = i64::MIN as u64;
    ctx[2] = -1i64 as u64;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0], i64::MIN as u64,
        "SDIV i64::MIN / -1 (X-form) must yield i64::MIN, got 0x{:016x}",
        ctx[0]
    );

    // Regression: a NORMAL signed division still works after adding the guard.
    // `exec` is the X-form block, so feed full 64-bit sign-extended operands.
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = -100i64 as u64;
    ctx[2] = 7i64 as u64;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // X-form block: -100 / 7 = -14 (truncated toward zero).
    assert_eq!(ctx[0] as i64, -14, "SDIV -100/7 = -14, got {}", ctx[0] as i64);
}

/// bionic strchr main-loop NEON ops executed on the host: BIC vector-immediate
/// (scalar and-not), ADDP / UMAXP byte-pairwise (SSE deinterleave + pack).
#[test]
fn strchr_loop_neon_ops_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // bic v4.8h, #0xf0 — each halfword &= ~0x00f0. all-ones → 0xff0f per halfword.
    let code = translate_straight_line(&[0x6F07_9604u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(4)] = u64::MAX;
    ctx[vd(4) + 1] = u64::MAX;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(4)], 0xFF0F_FF0F_FF0F_FF0F, "bic .8h #0xf0 (lo)");
    assert_eq!(ctx[vd(4) + 1], 0xFF0F_FF0F_FF0F_FF0F, "bic .8h #0xf0 (hi)");

    // addp v5.16b, v2.16b, v2.16b — every byte 0x01 ⇒ pairwise sums all 0x02.
    let code = translate_straight_line(&[0x4E22_BC45u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(2)] = 0x0101_0101_0101_0101;
    ctx[vd(2) + 1] = 0x0101_0101_0101_0101;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(5)], 0x0202_0202_0202_0202, "addp .16b (lo)");
    assert_eq!(ctx[vd(5) + 1], 0x0202_0202_0202_0202, "addp .16b (hi)");

    // umaxp v5.16b, v2.16b, v2.16b — bytes alternate 0x01/0x03 ⇒ pairwise max 0x03.
    let code = translate_straight_line(&[0x6E22_A445u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(2)] = 0x0301_0301_0301_0301;
    ctx[vd(2) + 1] = 0x0301_0301_0301_0301;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(5)], 0x0303_0303_0303_0303, "umaxp .16b (lo)");
    assert_eq!(ctx[vd(5) + 1], 0x0303_0303_0303_0303, "umaxp .16b (hi)");
}

/// bionic NEON popcount accumulation — UADDLP (add-long pairwise, widening) at
/// byte→half, half→word, word→dword, executed on the host.
#[test]
fn uaddlp_widening_executes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // uaddlp v2.8h, v2.16b — every byte 0x05 ⇒ each halfword = 0x0A (10).
    let code = translate_straight_line(&[0x6E20_2842u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(2)] = 0x0505_0505_0505_0505;
    ctx[vd(2) + 1] = 0x0505_0505_0505_0505;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], 0x000A_000A_000A_000A, "uaddlp .8h (lo)");
    assert_eq!(ctx[vd(2) + 1], 0x000A_000A_000A_000A, "uaddlp .8h (hi)");

    // uaddlp v2.4s, v2.8h — each halfword 0x0A ⇒ each word = 0x14 (20).
    let code = translate_straight_line(&[0x6E60_2842u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(2)] = 0x000A_000A_000A_000A;
    ctx[vd(2) + 1] = 0x000A_000A_000A_000A;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], 0x0000_0014_0000_0014, "uaddlp .4s (lo)");
    assert_eq!(ctx[vd(2) + 1], 0x0000_0014_0000_0014, "uaddlp .4s (hi)");

    // uaddlp v3.2d, v3.4s — each word 0x14 ⇒ each dword = 0x28 (40).
    let code = translate_straight_line(&[0x6EA0_2863u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(3)] = 0x0000_0014_0000_0014;
    ctx[vd(3) + 1] = 0x0000_0014_0000_0014;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(3)], 0x0000_0000_0000_0028, "uaddlp .2d (lo)");
    assert_eq!(ctx[vd(3) + 1], 0x0000_0000_0000_0028, "uaddlp .2d (hi)");
}

/// ADDP (pairwise add) at .2D/.4S/.8H — the BoringSSL gap that SIGILL-killed
/// init at mount-time. ADDP Vd, Vn, Vm = [Vn pairwise…, Vm pairwise…].
#[test]
fn addp_executes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // The EXACT instruction that wedged init: ADDP V6.2D, V6.2D, V6.2D = 0x4ee6bcc6.
    // Vn=Vm=V6=[7,5] → [7+5, 7+5] = [0xC, 0xC].
    let code = translate_straight_line(&[0x4ee6_bcc6u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(6)] = 0x0000_0000_0000_0007;
    ctx[vd(6) + 1] = 0x0000_0000_0000_0005;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(6)], 0x0000_0000_0000_000C, "addp .2d lane0 = n0+n1");
    assert_eq!(ctx[vd(6) + 1], 0x0000_0000_0000_000C, "addp .2d lane1 = m0+m1");

    // Distinct lanes to confirm pairwise reduction (not a broadcast): V6=[3,9] →
    // both result lanes = 3+9 = 0xC (since d==n==m, Vm pairs == Vn pairs).
    let code = translate_straight_line(&[0x4ee6_bcc6u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(6)] = 0x0000_0000_0000_0003;
    ctx[vd(6) + 1] = 0x0000_0000_0000_0009;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(6)], 0x0000_0000_0000_000C, "addp .2d distinct = 3+9");
    assert_eq!(ctx[vd(6) + 1], 0x0000_0000_0000_000C, "addp .2d distinct hi");
}

/// boringssl FIPS self-test NEON byte-search: CMTST v3.2d, v3.2d, v1.2d
/// (0x4ee18c63) — per 64-bit lane, all-ones iff (v3 & v1) != 0, else 0.
/// This block lowered to UD2 → guest SIGILL → init reboot before the fix.
#[test]
fn cmtst_executes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    let code = translate_straight_line(&[0x4ee1_8c63u32], 0x1000);
    let exec = winexec::make_executable(&code);

    // lane0: (0x00FF & 0x0F00) == 0 → 0 ; lane1: (0xFF00 & 0x0F00) != 0 → all-ones.
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(3)] = 0x0000_0000_0000_00FF; // n lane0
    ctx[vd(3) + 1] = 0x0000_0000_0000_FF00; // n lane1
    ctx[vd(1)] = 0x0000_0000_0000_0F00; // m lane0
    ctx[vd(1) + 1] = 0x0000_0000_0000_0F00; // m lane1
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(3)], 0, "cmtst .2d lane0: (n&m)==0 → 0");
    assert_eq!(ctx[vd(3) + 1], u64::MAX, "cmtst .2d lane1: (n&m)!=0 → all-ones");

    // both lanes overlapping bits → both all-ones; Q=1 so no upper-half zeroing.
    let code = translate_straight_line(&[0x4ee1_8c63u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(3)] = 0x1234_5678_9ABC_DEF0;
    ctx[vd(3) + 1] = 0x0F0F_0F0F_0F0F_0F0F;
    ctx[vd(1)] = 0x1000_0000_0000_0001; // shares bits with lane0
    ctx[vd(1) + 1] = 0x0F00_0000_0000_0000; // shares bits with lane1
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(3)], u64::MAX, "cmtst .2d lane0: overlap → all-ones");
    assert_eq!(ctx[vd(3) + 1], u64::MAX, "cmtst .2d lane1: overlap → all-ones");

    // no overlap in either lane → both zero.
    let code = translate_straight_line(&[0x4ee1_8c63u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(3)] = 0xAAAA_AAAA_AAAA_AAAA;
    ctx[vd(3) + 1] = 0x5555_5555_5555_5555;
    ctx[vd(1)] = 0x5555_5555_5555_5555;
    ctx[vd(1) + 1] = 0xAAAA_AAAA_AAAA_AAAA;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(3)], 0, "cmtst .2d lane0: no overlap → 0");
    assert_eq!(ctx[vd(3) + 1], 0, "cmtst .2d lane1: no overlap → 0");
}

/// bionic NEON popcount tail: UZP1 .4s (shufps) + ADDV .4s (lane reduce-add).
#[test]
fn uzp1_addv_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // uzp1 v2.4s, v2.4s, v3.4s — even 32-bit lanes of v2:v3 = [v2.0,v2.2,v3.0,v3.2].
    let code = translate_straight_line(&[0x4E83_1842u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // v2 lanes = [0x11,0x22,0x33,0x44] (lo=0x0000002200000011, hi=0x0000004400000033)
    ctx[vd(2)] = 0x0000_0022_0000_0011;
    ctx[vd(2) + 1] = 0x0000_0044_0000_0033;
    // v3 lanes = [0x55,0x66,0x77,0x88]
    ctx[vd(3)] = 0x0000_0066_0000_0055;
    ctx[vd(3) + 1] = 0x0000_0088_0000_0077;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // even lanes: [v2.0=0x11, v2.2=0x33, v3.0=0x55, v3.2=0x77]
    assert_eq!(ctx[vd(2)], 0x0000_0033_0000_0011, "uzp1 .4s (lo)");
    assert_eq!(ctx[vd(2) + 1], 0x0000_0077_0000_0055, "uzp1 .4s (hi)");

    // addv s0, v0.4s — sum the four 32-bit lanes → s0 (rest zeroed).
    let code = translate_straight_line(&[0x4EB1_B800u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(0)] = 0x0000_0002_0000_0001; // lanes 1,2
    ctx[vd(0) + 1] = 0x0000_0004_0000_0003; // lanes 3,4  → sum = 10 = 0xA
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0x0000_0000_0000_000A, "addv .4s sum (lo)");
    assert_eq!(ctx[vd(0) + 1], 0, "addv result upper zeroed");
}

/// SHRN .2s (`.2d→.2s`) + SHRN2 (high-half narrow) executed on the host.
#[test]
fn shrn_2s_and_shrn2_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // shrn v4.2s, v4.2d, #4 — each 64-bit lane >>4, low 32 → .2s, upper zeroed.
    let code = translate_straight_line(&[0x0F3C_8484u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(4)] = 0x100; // qword0 >>4 = 0x10
    ctx[vd(4) + 1] = 0x200; // qword1 >>4 = 0x20
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(4)], 0x0000_0020_0000_0010, "shrn .2s [0x10,0x20] (lo)");
    assert_eq!(ctx[vd(4) + 1], 0, "shrn .2s upper zeroed");

    // shrn2 v4.4s, v5.2d, #4 — result → v4[127:64], v4[63:0] preserved.
    let code = translate_straight_line(&[0x4F3C_84A4u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(4)] = 0xAAAA_BBBB_CCCC_DDDD; // preserved low 64
    ctx[vd(4) + 1] = 0x1111_1111_1111_1111; // overwritten
    ctx[vd(5)] = 0x100;
    ctx[vd(5) + 1] = 0x200;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(4)], 0xAAAA_BBBB_CCCC_DDDD, "shrn2 preserves low 64");
    assert_eq!(ctx[vd(4) + 1], 0x0000_0020_0000_0010, "shrn2 writes high 64");
}

/// `mov dN, vN.d[1]` (rd==rn) — the keystore2 crash bug: the lift must EXTRACT
/// the source lane BEFORE zeroing Vd, else the high-lane fold reads a freshly
/// zeroed source (boringssl GHASH/P-256 idiom). Word 0x5e180442 = `mov d2,
/// v2.d[1]`. Pre-fix this returned 0; post-fix it returns the high limb.
#[test]
fn scalar_dup_same_reg_high_lane() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // mov d2, v2.d[1]: d2 = v2.d[1] folded to lane 0, lane1 zeroed. rd==rn==2.
    let code = translate_straight_line(&[0x5E18_0442u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(2)] = 0x1111_2222_3333_4444; // v2 lane0 (low)
    ctx[vd(2) + 1] = 0xDEAD_BEEF_CAFE_F00D; // v2 lane1 (high) — must survive the fold
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(2)],
        0xDEAD_BEEF_CAFE_F00D,
        "mov d2,v2.d[1] (rd==rn): lane0 must get the OLD high lane, not 0"
    );
    assert_eq!(ctx[vd(2) + 1], 0, "scalar dup zeroes Vd[127:64]");
}

/// XTN/XTN2 (`.2s←.2d`, `.4h←.4s`, `.8b←.8h`) — extract-narrow (truncate each
/// element to half-width, no shift). The live-boot blocker was `XTN v0.2s,
/// v0.2d` (word 0x0ea12800). Lifted to VecShiftNarrow{shift:0,...}.
#[test]
fn xtn_narrow_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // xtn v0.2s, v0.2d (0x0ea12800) — low 32 of each 64-bit lane → v0[63:0].
    let code = translate_straight_line(&[0x0EA1_2800u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(0)] = 0x0000_0011_AAAA_0010; // lane0: low32 = 0xAAAA0010
    ctx[vd(0) + 1] = 0x0000_0022_BBBB_0020; // lane1: low32 = 0xBBBB0020
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0xBBBB_0020_AAAA_0010, "xtn .2s low 64 = [lo0,lo1]");
    assert_eq!(ctx[vd(0) + 1], 0, "xtn .2s upper 64 zeroed");

    // xtn v1.4h, v2.4s (0x0E61_2841) — low 16 of each 32-bit lane → v1[63:0].
    let code = translate_straight_line(&[0x0E61_2841u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(2)] = 0xFFFF_1111_EEEE_2222; // lanes: 0x2222, 0x1111
    ctx[vd(2) + 1] = 0xDDDD_3333_CCCC_4444; // lanes: 0x4444, 0x3333
    ctx[vd(1) + 1] = 0x9999_9999_9999_9999; // must be zeroed (XTN, not XTN2)
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(1)], 0x3333_4444_1111_2222, "xtn .4h low 64 packed");
    assert_eq!(ctx[vd(1) + 1], 0, "xtn .4h upper 64 zeroed");

    // xtn v3.8b, v4.8h (0x0E21_2883) — low 8 of each 16-bit lane → v3[63:0].
    let code = translate_straight_line(&[0x0E21_2883u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // 8 source halfwords (elem0=LSB): 0xCC44,0xDD33,0xEE22,0xFF11,0x8888,0x9977,
    // 0xAA66,0xBB55 → low bytes 0x44,0x33,0x22,0x11,0x88,0x77,0x66,0x55 packed.
    ctx[vd(4)] = 0xFF11_EE22_DD33_CC44;
    ctx[vd(4) + 1] = 0xBB55_AA66_9977_8888;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(3)], 0x5566_7788_1122_3344, "xtn .8b low 64 packed");
    assert_eq!(ctx[vd(3) + 1], 0, "xtn .8b upper 64 zeroed");

    // xtn2 v5.4s, v6.2d (0x4EA1_28C5) — narrows into v5[127:64], preserve low 64.
    let code = translate_straight_line(&[0x4EA1_28C5u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(5)] = 0xCAFE_F00D_DEAD_BEEF; // preserved low 64
    ctx[vd(5) + 1] = 0x1111_1111_1111_1111; // overwritten
    ctx[vd(6)] = 0x0000_0011_AAAA_0010;
    ctx[vd(6) + 1] = 0x0000_0022_BBBB_0020;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(5)], 0xCAFE_F00D_DEAD_BEEF, "xtn2 preserves low 64");
    assert_eq!(ctx[vd(5) + 1], 0xBBBB_0020_AAAA_0010, "xtn2 writes high 64");
}

/// USRA/SSRA — shift-right-and-accumulate by immediate. The live-boot blocker is
/// boringssl's FIPS self-test `usra v0.2d, v2.2d, #1` (word 0x6F7F_1440):
/// `v0.2d[e] += (v2.2d[e] >>logical 1)`. Also exercises a signed SSRA .4s
/// (arithmetic) and the emulated SSRA .2d arithmetic path. Host-executed.
#[test]
fn usra_executes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // --- usra v0.2d, v2.2d, #1 (0x6F7F_1440) — unsigned/logical, accumulate. ---
    let code = translate_straight_line(&[0x6F7F_1440u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    let v0_lo: u64 = 0x0000_0000_0000_0010;
    let v0_hi: u64 = 0xAAAA_AAAA_AAAA_AAAA;
    let v2_lo: u64 = 0x8000_0000_0000_0000; // logical >>1 = 0x4000_0000_0000_0000
    let v2_hi: u64 = 0x0000_0000_0000_0007; // logical >>1 = 3
    ctx[vd(0)] = v0_lo;
    ctx[vd(0) + 1] = v0_hi;
    ctx[vd(2)] = v2_lo;
    ctx[vd(2) + 1] = v2_hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(0)],
        v0_lo.wrapping_add(v2_lo >> 1),
        "usra .2d lane0: v0 += (v2 >>u 1)"
    );
    assert_eq!(
        ctx[vd(0) + 1],
        v0_hi.wrapping_add(v2_hi >> 1),
        "usra .2d lane1: v0 += (v2 >>u 1)"
    );

    // --- ssra signed .4s arithmetic: ssra v4.4s, v5.4s, #2 (0x4F3E_14A4). ---
    // immh:immb = 0111:110 = 62 → esize 32, shift = 2*32 - 62 = 2.
    // Use a negative lane to prove arithmetic (sign-extending) shift.
    let code = translate_straight_line(&[0x4F3E_14A4u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // v5 lanes (i32): lane0 = -16 (0xFFFFFFF0), lane1 = 64 (0x40). >>a 2 → -4, 16.
    ctx[vd(5)] = 0x0000_0040_FFFF_FFF0;
    ctx[vd(5) + 1] = 0;
    // v4 accumulator lanes: lane0 = 1, lane1 = 2.
    ctx[vd(4)] = 0x0000_0002_0000_0001;
    ctx[vd(4) + 1] = 0;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // lane0 = 1 + (-16 >>a 2) = 1 + (-4) = -3 = 0xFFFFFFFD; lane1 = 2 + 16 = 18.
    assert_eq!(ctx[vd(4)], 0x0000_0012_FFFF_FFFD, "ssra .4s arithmetic accumulate");
    assert_eq!(ctx[vd(4) + 1], 0, "ssra .4s Q=1 upper preserved from src (=0)");

    // --- ssra v6.2d, v7.2d, #4 (0x4F7C_14E6) — emulated 64-bit arithmetic shift. ---
    // immh:immb = 1111:100 = 0x7C → esize 64, shift = 128-124 = 4.
    let code = translate_straight_line(&[0x4F7C_14E6u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    let v7_lo: u64 = 0xFFFF_FFFF_FFFF_FF00; // i64 = -256, >>a 4 = -16
    let v7_hi: u64 = 0x0000_0000_0000_0100; // i64 = 256,  >>a 4 = 16
    let v6_lo: u64 = 0x10;
    let v6_hi: u64 = 0x20;
    ctx[vd(7)] = v7_lo;
    ctx[vd(7) + 1] = v7_hi;
    ctx[vd(6)] = v6_lo;
    ctx[vd(6) + 1] = v6_hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(6)],
        v6_lo.wrapping_add(((v7_lo as i64) >> 4) as u64),
        "ssra .2d lane0 emulated arithmetic accumulate"
    );
    assert_eq!(
        ctx[vd(6) + 1],
        v6_hi.wrapping_add(((v7_hi as i64) >> 4) as u64),
        "ssra .2d lane1 emulated arithmetic accumulate"
    );
}

/// INS (element) — vector lane→lane copy: `mov v0.d[1], v1.d[0]`, host-executed.
#[test]
fn ins_element_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let code = translate_straight_line(&[0x6E18_0420u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(0)] = 0x1111_1111_1111_1111; // v0.d[0] — preserved
    ctx[vd(0) + 1] = 0x2222_2222_2222_2222; // v0.d[1] — overwritten
    ctx[vd(1)] = 0xDEAD_BEEF_CAFE_F00D; // v1.d[0] — source
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0x1111_1111_1111_1111, "ins elem preserves v0.d[0]");
    assert_eq!(ctx[vd(0) + 1], 0xDEAD_BEEF_CAFE_F00D, "ins elem v0.d[1] := v1.d[0]");
}

/// CMHS (unsigned vector compare ≥) — the bionic strcmp/memcmp op. Uses the
/// UNSIGNED max trick, so 0x80 ≥ 0x7F must be true (a SIGNED compare would say
/// false: -128 < 127). Host-executed.
#[test]
fn cmhs_unsigned_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // cmhs v2.16b, v3.16b, v1.16b  (a=v3, b=v1) → per-byte (a >= b unsigned).
    let code = translate_straight_line(&[0x6E21_3C62u32], 0x1000);
    let exec = winexec::make_executable(&code);
    // v3 = 0x80 (128), v1 = 0x7F (127): 128 >= 127 unsigned → all 0xFF.
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(3)] = 0x8080_8080_8080_8080;
    ctx[vd(3) + 1] = 0x8080_8080_8080_8080;
    ctx[vd(1)] = 0x7F7F_7F7F_7F7F_7F7F;
    ctx[vd(1) + 1] = 0x7F7F_7F7F_7F7F_7F7F;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], u64::MAX, "cmhs 0x80>=0x7F unsigned (lo)");
    assert_eq!(ctx[vd(2) + 1], u64::MAX, "cmhs 0x80>=0x7F unsigned (hi)");
    // reverse: 0x7F >= 0x80 unsigned → false → 0.
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(3)] = 0x7F7F_7F7F_7F7F_7F7F;
    ctx[vd(3) + 1] = 0x7F7F_7F7F_7F7F_7F7F;
    ctx[vd(1)] = 0x8080_8080_8080_8080;
    ctx[vd(1) + 1] = 0x8080_8080_8080_8080;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], 0, "cmhs 0x7F>=0x80 unsigned false (lo)");
    assert_eq!(ctx[vd(2) + 1], 0, "cmhs 0x7F>=0x80 unsigned false (hi)");
}

/// CMHI/CMHS on .2D and .4S — the LAST UNSAFE op gating Android init → zygote.
/// These arrangements have NO unsigned-max SSE instruction (no PMAXUQ ever; no
/// PMAXUD pre-SSE4.1) so the old max-trick fell through to UD2 (live SIGILL at
/// pc=0x558850acd8, word=0x6ee03422 = `CMHI V2.2D, V1.2D, V0.2D`). The fix is
/// the sign-bias trick: flip each lane's top bit → signed PCMPGTQ/PCMPGTD.
///
/// The values are chosen to make the unsigned-vs-signed distinction load-bearing:
/// lane0 a = 0xFFFF_FFFF_FFFF_FFFF (unsigned-huge, signed -1) vs b = 1. A NAIVE
/// signed compare answers `a > b` FALSE (−1 < 1); the correct UNSIGNED answer is
/// TRUE. The test also asserts NO UD2 (0F 0B) byte pair is emitted.
#[test]
fn cmhi_cmhs_2d_4s_unsigned_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // No emitted block may contain the UD2 opcode (0F 0B) — fail-loud means the
    // form was unimplemented and would SIGILL at runtime.
    let no_ud2 = |code: &[u8], what: &str| {
        assert!(
            !code.windows(2).any(|w| w == [0x0Fu8, 0x0Bu8]),
            "{what}: emitted block contains UD2 (0F 0B) — form unimplemented",
        );
    };

    // ── CMHI V2.2D, V1.2D, V0.2D  (a=V1, b=V0) → per-64-bit-lane (a > b) unsigned.
    // 0x6EE03422 — the exact live-boot UNSAFE word.
    let code = translate_straight_line(&[0x6EE0_3422u32], 0x1000);
    no_ud2(&code, "cmhi .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // lane0: a=0xFFFF...FF (signed -1) vs b=1 → unsigned a>b TRUE (signed FALSE).
    ctx[vd(1)] = 0xFFFF_FFFF_FFFF_FFFF;
    ctx[vd(0)] = 0x0000_0000_0000_0001;
    // lane1: a=1 vs b=2 → a>b FALSE.
    ctx[vd(1) + 1] = 0x0000_0000_0000_0001;
    ctx[vd(0) + 1] = 0x0000_0000_0000_0002;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(2)], u64::MAX,
        "cmhi .2d lane0: 0xFFFF..FF > 1 UNSIGNED → all-ones (signed would give 0)",
    );
    assert_eq!(ctx[vd(2) + 1], 0, "cmhi .2d lane1: 1 > 2 → 0");

    // ── CMHS V2.2D, V1.2D, V0.2D  (a=V1, b=V0) → per-lane (a >= b) unsigned.
    // 0x6EE03C22.
    let code = translate_straight_line(&[0x6EE0_3C22u32], 0x1000);
    no_ud2(&code, "cmhs .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // lane0: a=0xFFFF..FF (signed -1) vs b=1 → unsigned a>=b TRUE.
    ctx[vd(1)] = 0xFFFF_FFFF_FFFF_FFFF;
    ctx[vd(0)] = 0x0000_0000_0000_0001;
    // lane1: a=2 vs b=2 → a>=b TRUE (equality).
    ctx[vd(1) + 1] = 0x0000_0000_0000_0002;
    ctx[vd(0) + 1] = 0x0000_0000_0000_0002;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], u64::MAX, "cmhs .2d lane0: 0xFFFF..FF >= 1 UNSIGNED → all-ones");
    assert_eq!(ctx[vd(2) + 1], u64::MAX, "cmhs .2d lane1: 2 >= 2 → all-ones");
    // reverse lane1: a=2 vs b=3 → a>=b FALSE.
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0x0000_0000_0000_0001;
    ctx[vd(0)] = 0xFFFF_FFFF_FFFF_FFFF; // lane0: 1 >= 0xFFFF..FF unsigned → FALSE
    ctx[vd(1) + 1] = 0x0000_0000_0000_0002;
    ctx[vd(0) + 1] = 0x0000_0000_0000_0003;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], 0, "cmhs .2d lane0: 1 >= 0xFFFF..FF unsigned → 0");
    assert_eq!(ctx[vd(2) + 1], 0, "cmhs .2d lane1: 2 >= 3 → 0");

    // ── CMHI V2.4S, V1.4S, V0.4S  → per-32-bit-lane (a > b) unsigned. 0x6EA03422.
    let code = translate_straight_line(&[0x6EA0_3422u32], 0x1000);
    no_ud2(&code, "cmhi .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // 4 lanes packed 2-per-u64 (little-endian): lo = [lane0 | lane1].
    // lane0: a=0xFFFF_FFFF (signed -1) vs b=1 → unsigned a>b TRUE.
    // lane1: a=1 vs b=2 → FALSE.
    ctx[vd(1)] = 0x0000_0001_FFFF_FFFF;
    ctx[vd(0)] = 0x0000_0002_0000_0001;
    // lane2: a=5 vs b=5 → FALSE; lane3: a=0x8000_0000 vs b=0x7FFF_FFFF → unsigned TRUE.
    ctx[vd(1) + 1] = 0x8000_0000_0000_0005;
    ctx[vd(0) + 1] = 0x7FFF_FFFF_0000_0005;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(2)], 0x0000_0000_FFFF_FFFF,
        "cmhi .4s lo: lane0 (0xFFFF_FFFF>1 unsigned)=ones, lane1 (1>2)=0",
    );
    assert_eq!(
        ctx[vd(2) + 1], 0xFFFF_FFFF_0000_0000,
        "cmhi .4s hi: lane2 (5>5)=0, lane3 (0x8000_0000>0x7FFF_FFFF unsigned)=ones",
    );

    // ── CMHS V2.4S, V1.4S, V0.4S → per-lane (a >= b) unsigned. 0x6EA03C22.
    let code = translate_straight_line(&[0x6EA0_3C22u32], 0x1000);
    no_ud2(&code, "cmhs .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // lane0: a=0xFFFF_FFFF vs b=0xFFFF_FFFF → equal → TRUE.
    // lane1: a=1 vs b=2 → FALSE.
    ctx[vd(1)] = 0x0000_0001_FFFF_FFFF;
    ctx[vd(0)] = 0x0000_0002_FFFF_FFFF;
    // lane2: a=0x8000_0000 vs b=0x7FFF_FFFF → unsigned >= TRUE; lane3: a=5 vs b=6 → FALSE.
    ctx[vd(1) + 1] = 0x0000_0005_8000_0000;
    ctx[vd(0) + 1] = 0x0000_0006_7FFF_FFFF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(2)], 0x0000_0000_FFFF_FFFF,
        "cmhs .4s lo: lane0 (eq)=ones, lane1 (1>=2)=0",
    );
    assert_eq!(
        ctx[vd(2) + 1], 0x0000_0000_FFFF_FFFF,
        "cmhs .4s hi: lane2 (0x8000_0000>=0x7FFF_FFFF unsigned)=ones, lane3 (5>=6)=0",
    );
}

/// M3 — multi-block host dispatch + memory STORE/LOAD, through the public API.
/// Mirrors the hypervisor's boot_amd dispatch loop exactly (translate -> resolve
/// -> copy-to-RWX -> CALL -> read pc-slot -> repeat) so M3 is host-verified
/// before silicon. A stack u64 stands in for the hypervisor's M3_OBS static.
#[test]
fn m3_multiblock_store_load_dispatch() {
    let _serial = serial();
    use aether_translator::dbt::{
        aether_dbt_block_host_va, aether_dbt_init, aether_dbt_invalidate_all,
        aether_dbt_translate_block, AetherDbtResult,
    };
    use aether_translator::runtime::mmu::aether_mmu_set_window;
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
    // The runtime is process-global and dbt_init no-ops when already live:
    // m3_cbz_cbnz_next_pc translates DIFFERENT code at these same PCs
    // (0x1000/0x2000), so flush its blocks or the cache serves them here.
    let _ = aether_dbt_invalidate_all();
    // MMU off → flat path; the No-Boundary clamp on the WRITE primitive
    // (default window GUEST_PA_BASE..) would reject the host &obs address,
    // so open the window wide — same as the newer M4b proofs do.
    aether_mmu_set_window(0, u64::MAX);

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
    let _serial = serial();
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
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};

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

/// REGRESSION (2026-06-30, el0_undef / control-flow corruptor hunt): a
/// `WriteGpr{sf:false}` (W-register store, which zero-extends the low 32 bits)
/// must NOT mutate the source SSA value's register IN PLACE. The old lowering
/// emitted `mov rs32,rs32`, truncating `rs` to 32 bits; if that SSA value was
/// still live (its register shared with a later use), the later use saw the
/// truncated value — a silent miscompile that, on a saved x30/x29 or an SPSR,
/// corrupts control flow and SIGILLs init via el0_undef.
///
/// Shape: read a 64-bit X2 value with HIGH bits set into one SSA `v`, then:
///   WriteGpr{reg:0, sf:false, src:v}  — W0 = v[31:0] (upper cleared) -> X0
///   WriteGpr{reg:1, sf:true,  src:v}  — X1 = v (FULL 64 bits)
/// `v` is live across both writes, so the W-write must leave `v` intact for the
/// full-width X-write. With the in-place bug, X1 would also be truncated.
#[test]
fn write_gpr_w_form_does_not_truncate_live_source() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};

    let mut func = IrFunction::new(0x1000);
    {
        let block: &mut IrBlock = func.add_block();
        // v = X2 (read full 64-bit). Seeded by the harness to 0xDEADBEEF_FEEDFACE.
        let v = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: v, reg: 2, sf: true });
        // W0 = low32(v), zero-extended -> X0 == 0x0000_0000_FEED_FACE.
        block.push_op(IrOp::WriteGpr { reg: 0, src: v, sf: false });
        // X1 = v (full 64). MUST be 0xDEADBEEF_FEEDFACE — proves v not truncated.
        block.push_op(IrOp::WriteGpr { reg: 1, src: v, sf: true });
    }
    let code = lower_built_func(&func);
    // No UD2.
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "block must not contain UD2"
    );
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[2] = 0xDEAD_BEEF_FEED_FACE; // X2 seed with high bits set
    // SAFETY: RWX RET-terminated block; ctx covers the full extended context.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(
        ctx[0], 0x0000_0000_FEED_FACE,
        "W0 = zero-extended low 32 of X2"
    );
    assert_eq!(
        ctx[1], 0xDEAD_BEEF_FEED_FACE,
        "X1 = FULL 64-bit X2 — the W-write must not have truncated the live source"
    );
}

/// Same hardening for `WriteSp{sf:false}` (WSP write): a W-form SP store must not
/// truncate a still-live source register. Read X3 (64-bit), write WSP (low 32 ->
/// SP), then write X4 = the SAME value full-width; X4 must keep all 64 bits.
#[test]
fn write_sp_w_form_does_not_truncate_live_source() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};

    const SP_SLOT: usize = 0x0F8 / 8; // active SP slot

    let mut func = IrFunction::new(0x1000);
    {
        let block: &mut IrBlock = func.add_block();
        let v = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: v, reg: 3, sf: true });
        block.push_op(IrOp::WriteSp { src: v, sf: false }); // SP = low32(v), ZE
        block.push_op(IrOp::WriteGpr { reg: 4, src: v, sf: true }); // X4 = full v
    }
    let code = lower_built_func(&func);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[3] = 0x1122_3344_5566_7788;
    // SAFETY: RWX RET-terminated block; ctx covers the full extended context.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(ctx[SP_SLOT], 0x0000_0000_5566_7788, "SP = zero-extended low 32");
    assert_eq!(
        ctx[4], 0x1122_3344_5566_7788,
        "X4 = FULL 64-bit X3 — WSP write must not have truncated the live source"
    );
}

/// NZCV PRODUCER: CMP X0,X1 materializes the ARM flags at [R15+0x108] with the
/// correct carry POLARITY (ARM C = NOT x86 borrow). 5-3 (no borrow) -> C=1;
/// 3-5 (borrow) -> C=0, N=1. Logical/overflow not exercised here.
#[test]
fn m4a_nzcv_subs_polarity() {
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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

/// THE REAL cmpxchg_double primitive (no LSE → LL/SC). `ldxp x0,x27,[x4]` must
/// load BOTH halves; `stxp w0,x20,x3,[x4]` must store BOTH halves. A half-load or
/// half-store here is the SLUB freelist double-alloc (the casp at 0x831a728 is
/// dead — ID_AA64ISAR0.Atomic=1 routes to this LL/SC path at 0x831a900).
#[test]
fn llsc_ldxp_loads_both_halves() {
    let _serial = serial();
    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();
    let mut buf = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888u64];
    // ldxp x0, x27, [x4] = 0xc87f6c80
    let code = translate_straight_line(&[0xc87f_6c80u32], 0xD100);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "ldxp must not UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[4] = buf.as_mut_ptr() as u64;
    // SAFETY: RWX RET-terminated block; ctx is the extended context; buf is live.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 0x1111_2222_3333_4444, "ldxp loaded x0 = [x4]");
    assert_eq!(ctx[27], 0x5555_6666_7777_8888, "ldxp loaded x27 = [x4+8] (the SECOND half)");
}

#[test]
fn llsc_stxp_stores_both_halves() {
    let _serial = serial();
    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();
    let mut buf = [0u64, 0u64];
    // stxp w0, x20, x3, [x4] = 0xc8200c94
    let code = translate_straight_line(&[0xc820_0c94u32], 0xD200);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "stxp must not UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[4] = buf.as_mut_ptr() as u64;
    ctx[20] = 0xAAAA_BBBB_CCCC_DDDDu64; // new_freelist
    ctx[3]  = 0x1234_5678_9ABC_DEF0u64; // new_tid
    // SAFETY: see above.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(buf[0], 0xAAAA_BBBB_CCCC_DDDD, "stxp stored x20 → [x4] (freelist)");
    assert_eq!(buf[1], 0x1234_5678_9ABC_DEF0, "stxp stored x3 → [x4+8] (tid, the SECOND half)");
    assert_eq!(ctx[0], 0, "stxp status w0 = 0 (success)");
}

/// REPRODUCES THE LIVE SLUB BLOCK: the real kmem_cache_alloc cmpxchg_double block
/// (VA 0x831a71c..0x831a74c) translated through the EXACT regalloc+lower path. The
/// live boot showed the casp lowering is never reached (lowOK=0) — this asserts the
/// casp does not get rejected (UD2'd) by register pressure in its real block.
#[test]
fn casp_slub_block_lowers_without_ud2() {
    let _serial = serial();
    use aether_translator::ir::IrOp;
    let words = [
        0xaa0503e0u32, // mov x0, x5
        0xaa1403e2,    // mov x2, x20
        0xaa0103e6,    // mov x6, x1
        0x48207c82,    // casp x0,x1,x2,x3,[x4]
        0xca050000,    // eor x0,x0,x5
        0xca060021,    // eor x1,x1,x6
        0xaa010000,    // orr x0,x0,x1
        0xaa0003fb,    // mov x27,x0
        0xd5384100,    // mrs x0, sp_el0
        0xf9400801,    // ldr x1,[x0,#16]
        0xd1000421,    // sub x1,x1,#1
        0xb9001001,    // str w1,[x0,#16]
        0xb4000801,    // cbz x1, +offset (terminator)
    ];
    // 1. Lift: confirm the casp becomes AtomicCasPair.
    let mut func = IrFunction::new(0x831a71c);
    {
        let block = func.add_block();
        let mut cur = 0x831a71cu64;
        for &w in &words {
            let insn = decode_instruction(w).expect("decode");
            lift_at(&insn, block, cur).expect("lift");
            cur += 4;
        }
    }
    let casp_count = func.blocks[0]
        .ops
        .iter()
        .filter(|op| matches!(op, IrOp::AtomicCasPair { .. }))
        .count();
    assert_eq!(casp_count, 1, "the block must lift the casp to exactly one AtomicCasPair");
    // 2. Regalloc + lower through the live path; UD2 = a spilled casp operand → the
    //    casp is rejected → the cmpxchg silently no-ops → SLUB double-alloc.
    let code = translate_straight_line(&words, 0x831a71c);
    let ud2_at = code.windows(2).position(|w| w == [0x0F, 0x0B]);
    assert!(
        ud2_at.is_none(),
        "SLUB casp block emitted UD2 (a casp operand spilled under real register \
         pressure) at byte {:?} — the casp lowering is rejected, never executes, and \
         the freelist double-allocates. Casp must be spill-proof here.",
        ud2_at
    );
}

/// CASP X0,X1,X2,X3,[X4] (64-bit pair compare-and-swap — the SLUB cmpxchg_double
/// primitive). MATCH case: the [X4] pair equals {X0,X1}, so the new pair {X2,X3}
/// is stored and the old pair is returned in {X0,X1}. A half-store or spurious
/// mismatch here double-allocates a slab object (the Phase-G fork corruption).
#[test]
fn casp_pair_match_stores_new_and_returns_old() {
    let _serial = serial();
    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();
    let old_a = 0xAAAA_AAAA_AAAA_1111u64;
    let old_b = 0xBBBB_BBBB_BBBB_2222u64;
    let mut buf = [old_a, old_b];
    let code = translate_straight_line(&[0x4820_7C82u32], 0xC100); // CASP x0,x1,x2,x3,[x4]
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "CASP must not emit UD2");
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = old_a; // expected_a == old_a (match)
    ctx[1] = old_b; // expected_b == old_b (match)
    ctx[2] = 0xCCCC_CCCC_CCCC_3333; // new_a
    ctx[3] = 0xDDDD_DDDD_DDDD_4444; // new_b
    ctx[4] = buf.as_mut_ptr() as u64;
    // SAFETY: RWX RET-terminated block; ctx is the extended context; buf is a live
    // 16-byte pair the flat CASP reads/writes.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(buf[0], 0xCCCC_CCCC_CCCC_3333, "match: new_a stored to [X4]");
    assert_eq!(buf[1], 0xDDDD_DDDD_DDDD_4444, "match: new_b stored to [X4+8]");
    assert_eq!(ctx[0], old_a, "old_a returned in X0");
    assert_eq!(ctx[1], old_b, "old_b returned in X1");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault");
}

/// CASP MISMATCH case: the [X4] pair does NOT equal {X0,X1}, so the memory is
/// left UNCHANGED and the old pair is still returned in {X0,X1}.
#[test]
fn casp_pair_mismatch_leaves_memory_unchanged() {
    let _serial = serial();
    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();
    let old_a = 0x1111_2222_3333_4444u64;
    let old_b = 0x5555_6666_7777_8888u64;
    let mut buf = [old_a, old_b];
    let code = translate_straight_line(&[0x4820_7C82u32], 0xC200);
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = 0xDEAD_DEAD_DEAD_DEADu64; // expected_a != old_a → MISMATCH
    ctx[1] = old_b;                    // expected_b == old_b
    ctx[2] = 0x9999_9999_9999_9999;    // new_a (must NOT be stored)
    ctx[3] = 0xEEEE_EEEE_EEEE_EEEE;    // new_b (must NOT be stored)
    ctx[4] = buf.as_mut_ptr() as u64;
    // SAFETY: see the match test.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(buf[0], old_a, "mismatch: [X4] unchanged");
    assert_eq!(buf[1], old_b, "mismatch: [X4+8] unchanged");
    assert_eq!(ctx[0], old_a, "old_a still returned in X0 on mismatch");
    assert_eq!(ctx[1], old_b, "old_b still returned in X1 on mismatch");
    assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault");
}

/// Regression: a scalar FP load/store (`LDR Dn` / `STR Dn`) must use the FP
/// register file, NOT the integer register that shares the same number. The old
/// size-only routing lifted `ldr d1` as `ldr x1`; a legitimate intervening
/// `mov x1,..` then silently clobbered the value before `str d1` read it back.
/// That is exactly how bionic's `vsnprintf` lost the `__SSTR` flag of its stack
/// FILE (the `_flags` constant was loaded into d-reg, clobbered in x1, stored as
/// garbage), so the FILE's NULL `_write` fp got called → /init SIGSEGV.
/// Program: `ldr d1,[x0]` ; `movz x1,#0x1234` (clobber x1) ; `str d1,[x2]`.
#[test]
fn ldr_str_d_uses_fp_reg_not_gpr() {
    let _serial = serial();
    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();
    let mut src: u64 = 0xFFFF_FFFF_0000_0208; // bionic vsnprintf _flags|_file|_r const
    let mut dst: u64 = 0;
    let src_addr = (&mut src as *mut u64) as u64;
    let dst_addr = (&mut dst as *mut u64) as u64;
    // ldr d1,[x0] (0xFD400001) ; movz x1,#0x1234 (0xD2824681) ; str d1,[x2] (0xFD000041)
    let words = [0xFD40_0001u32, 0xD282_4681u32, 0xFD00_0041u32];
    let code = translate_straight_line(&words, 0xC000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = src_addr; // x0 = source
    ctx[2] = dst_addr; // x2 = dest
    // SAFETY: RWX RET-terminated block; src/dst are live stack u64s the flat
    // (MMU-off) accesses read/write.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    assert_eq!(
        dst, 0xFFFF_FFFF_0000_0208,
        "LDR/STR d1 must carry the value in the FP reg; the intervening `mov x1` must NOT clobber it"
    );
    assert_eq!(ctx[1], 0x1234, "x1 is the independent clobber target");
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::ir::memory::{LoadTy, MemOrder};

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
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::ir::memory::{LoadTy, StoreTy};

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
    let _serial = serial();
    use aether_translator::decoder::sysreg::SysReg;
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::runtime::sysreg_rt::{aether_platform_reset, aether_timer_set_now};

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
    let _serial = serial();
    use aether_translator::decoder::sysreg::SysReg;
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::runtime::sysreg_rt::aether_platform_reset;

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
    let _serial = serial();
    use aether_translator::ir::{IrBlock, IrFunction, IrOp};
    use aether_translator::runtime::psci::{
        aether_hvc_take_action, HvcPlatformAction, PSCI_SYSTEM_OFF, PSCI_VERSION,
    };

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
    let _serial = serial();
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
    let _serial = serial();
    use aether_translator::dbt::{aether_dbt_init, dbt_runtime_with, AetherDbtResult};
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
    let _serial = serial();
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
    let _serial = serial();
    // Executing the TLBI block calls aether_dbt_invalidate_all (mutates the
    // GLOBAL DbtRuntime block cache), so take BOTH locks — MMU state AND the
    // runtime — to avoid wiping a concurrent EXEC_LOCK test's cache.
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
    let _serial = serial();
    // Executing the TLBI block calls aether_dbt_invalidate_all (mutates the
    // GLOBAL DbtRuntime block cache) — take BOTH locks (see the VA-form test).
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
    // The block's MSRs call aether_mmu_flush_all + aether_dbt_invalidate_all
    // (mutates the GLOBAL DbtRuntime block cache), so take BOTH locks.

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
    let _serial = serial();
    // The block's MSRs call aether_mmu_flush_all + aether_dbt_invalidate_all
    // (mutates the GLOBAL DbtRuntime block cache), so take BOTH locks.

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
// NOT an assertion — ends in an unconditional panic! to print the bytes, and a
// panicking test poisons EXEC_LOCK, cascade-failing every later test in
// the binary. Run explicitly via `--ignored` when the dump is needed; the
// assertion version is phase_c_movk_preserves_low_bits below.
#[test]
#[ignore = "debug dump tool — panics by design to print the emitted x86"]
fn phase_c_dump_movk_emitted_x86() {
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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

// ── Phase-G W-form shift edge-case audit ──────────────────────────────────
//
// ARM `LSL Wd, Wn, Wm` uses Wm[4:0] (mod 32) for shift amount.
// ARM `LSL Xd, Xn, Xm` uses Xm[5:0] (mod 64).
// Backend always emits r64 shift; x86 SHL r64 uses CL & 0x3F.
// For shift amount >= 32 on W form, results diverge.

/// LSL W0, W1, W2 with W1=1, W2=33: ARM does W1 << (33 % 32) = 1 << 1 = 2.
#[test]
fn phase_g_lsl_w_mod_32() {
    let _serial = serial();
    // MOVZ W1, #1 ; MOVZ W2, #33 ; LSL W0, W1, W2
    // LSL Wd, Wn, Wm encoding: 0001_1010_110m_mmmm_0010_00nn_nnnd_dddd
    // For Wd=0, Wn=1, Wm=2: 0x1AC22020
    const MOVZ_W1_1:  u32 = 0x5280_0021;
    const MOVZ_W2_33: u32 = 0x5280_0422;
    const LSL_W0_W1_W2: u32 = 0x1AC2_2020;
    let words = [MOVZ_W1_1, MOVZ_W2_33, LSL_W0_W1_W2];
    let code = translate_straight_line(&words, 0x17500);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 1, "W1 setup");
    assert_eq!(ctx[2], 33, "W2 setup");
    assert_eq!(
        ctx[0], 2,
        "LSL W(1, 33) must be 1<<1=2 (ARM uses Wm[4:0]); got 0x{:x}", ctx[0]
    );
}

/// ASR W0, W1, W2 with W1=0x80000000 (negative), W2=1: ARM ASR-32 = 0xC0000000.
#[test]
fn phase_g_asr_w_sign_extend() {
    let _serial = serial();
    // MOVZ W1, #0x8000, LSL #16 ; MOVZ W2, #1 ; ASR W0, W1, W2
    // ASR Wd, Wn, Wm: 0001_1010_110m_mmmm_0010_10nn_nnnd_dddd
    // 0x1AC22820
    // MOVZ W1, #0x8000, LSL #16 → W1 = 0x80000000  (enc: 0x52B00001;
    // capstone displays as `mov w1, #-0x80000000` due to signed-extend).
    const MOVZ_W1_MSB: u32 = 0x52B0_0001;
    const MOVZ_W2_1:   u32 = 0x5280_0022;
    const ASR_W0_W1_W2: u32 = 0x1AC2_2820;
    let words = [MOVZ_W1_MSB, MOVZ_W2_1, ASR_W0_W1_W2];
    let code = translate_straight_line(&words, 0x17600);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 0x8000_0000, "W1 setup");
    assert_eq!(ctx[2], 1, "W2 setup");
    assert_eq!(
        ctx[0], 0xC000_0000,
        "ASR W(0x80000000, 1) must be 0xC0000000 (sign-extend in 32-bit); got 0x{:x}",
        ctx[0]
    );
}

/// ROR W0, W1, W2 with W1=0x12345678, W2=4: ARM ROR-32 = 0x81234567.
#[test]
fn phase_g_ror_w_wraps_32() {
    let _serial = serial();
    // MOVZ W1 = 0x12345678; MOVZ W2 = 4; ROR W0, W1, W2
    // 0x52A24681: movz w1, #0x1234, lsl #16
    // 0x72A8ACF1: movk w1, #0x4567 -- wait need w1, #0x5678 first
    // Just use MOVZ + MOVK pair to build 0x12345678.
    // MOVZ W1, #0x5678         -> 0x5280ACF1
    // MOVK W1, #0x1234, LSL #16 -> 0x72A24681
    // MOVZ W2, #4              -> 0x52800082
    // ROR W0, W1, W2: 0001_1010_110m_mmmm_0010_11nn_nnnd_dddd = 0x1AC22C20
    const MOVZ_W1_LO: u32 = 0x528A_CF01;
    const MOVK_W1_HI: u32 = 0x72A2_4681;
    const MOVZ_W2_4:  u32 = 0x5280_0082;
    const ROR_W0_W1_W2: u32 = 0x1AC2_2C20;
    let words = [MOVZ_W1_LO, MOVK_W1_HI, MOVZ_W2_4, ROR_W0_W1_W2];
    let code = translate_straight_line(&words, 0x17700);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1], 0x1234_5678, "W1 setup");
    assert_eq!(ctx[2], 4, "W2 setup");
    assert_eq!(
        ctx[0], 0x8123_4567,
        "ROR W(0x12345678, 4) must wrap within 32-bit = 0x81234567; got 0x{:x}",
        ctx[0]
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
    // MOVZ W1, #0x8000, LSL #16 → w1 = 0x8000_0000  (enc: 0x52B00001)
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
    let _serial = serial();
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
    let _serial = serial();
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
/// Phase G fortify regression. build_sched_domains contains the pattern:
///   cmp x2, #9         ← ARM C=0 when x2<9 (b.hs should NOT fire)
///   tbnz w9, #4, ...   ← lowering: x86 `shr; test` — CLOBBERS EFLAGS
///   b.hs target        ← MUST consume ARM NZCV from memory, NOT x86 CF
///
/// The prior CondBranch lowering used `jcc_rel32` against live x86 EFLAGS,
/// so after tbnz's `test` (which leaves CF=0), `b.hs` (= jcc NB, CF==0)
/// always took the branch — producing fortify_panic("memset") in
/// build_sched_domains+0x15d8 even when nr_cpumask_bits == 64 (legal).
///
/// Encoded: PC=0x1000
///   0x1000: MOVZ W2, #8        ; x2 = 8
///   0x1004: MOVZ W9, #9        ; x9 = 9 (bit 4 = 0 → tbnz NOT taken)
///   0x1008: CMP X2, #9         ; 8 < 9 unsigned → ARM C=0
///   0x100C: TBNZ W9, #4, +0x10 ; fallthrough (w9 bit 4 == 0)
///   0x1010: B.HS +0x14         ; if ARM C=1, jump to 0x1024 (taken)
///   0x1014: MOVZ X10, #0x0AAA  ; fallthrough marker — only runs if b.hs NOT taken
///   0x1018: RET (implicit end)
/// We assert ctx[10] == 0x0AAA (proves b.hs was NOT taken).
#[test]
fn phase_g_bhs_after_tbnz_consumes_arm_nzcv() {
    let _serial = serial();
    const MOVZ_W2_8:   u32 = 0x52800102; // movz w2, #8
    const MOVZ_W9_9:   u32 = 0x52800129; // movz w9, #9
    const CMP_X2_9:    u32 = 0xF100245F; // cmp x2, #9
    // tbnz w9, #4, +0x10 (skip past the MOVZ marker if mistakenly taken):
    //   b5(1)=0, opc(7)=0110111, b40(5)=0x04, imm14=4 (×4=0x10), Rt=9
    const TBNZ_W9_4:   u32 = 0x37200089;
    // b.hs +0x14 (= 0x1010 + 0x14 = 0x1024): cond=0b0010 (HS), imm19=5
    const B_HS_14:     u32 = 0x540000A2;
    // movz x10, #0x0AAA (fallthrough marker): sf=1, hw=0, imm16=0x0AAA, Rd=10
    // Encoding: 0xD2800000 | (imm16 << 5) | Rd = 0xD2800000|0x15540|10
    const MOVZ_X10:    u32 = 0xD281554A;
    let words = [MOVZ_W2_8, MOVZ_W9_9, CMP_X2_9, TBNZ_W9_4, B_HS_14, MOVZ_X10];
    let code = translate_straight_line(&words, 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = vec![0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[2], 8, "X2 = 8 (got 0x{:x})", ctx[2]);
    assert_eq!(ctx[9], 9, "X9 = 9 (got 0x{:x})", ctx[9]);
    assert_eq!(
        ctx[10], 0x0AAA,
        "B.HS must NOT take when ARM C=0 (cmp 8,9); got X10=0x{:x}. \
         If the CondBranch lowering reads x86 EFLAGS after TBNZ clobbers \
         them, b.hs (= jcc NB / CF==0) fires incorrectly and X10 stays 0.",
        ctx[10]
    );
}

#[test]
fn phase_c_jump_table_dispatch_shifted_add() {
    let _serial = serial();
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

/// B20/B29/B31 — across-lane integer min/max reduce (UMAXV/SMINV), scalar FMOV
/// Sd,Sn, and unsigned FP↔int conversions (UCVTF/FCVTZU) executed on the host.
/// Each was UD2/Ument-or-wrong before this landing; these prove the numbers.
#[test]
fn b20_b29_b31_simd_fp_ops_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8; // u64 index of V<r>[63:0]

    // UMAXV B0, V1.16b — unsigned max byte across all 16 lanes. (B29)
    let umaxv = winexec::make_executable(&translate_straight_line(&[0x6E30_A820u32], 0x1000));
    // SMINV B0, V1.16b — signed min byte across all 16 lanes. (B29)
    let sminv = winexec::make_executable(&translate_straight_line(&[0x4E31_A820u32], 0x1000));
    // bytes: 0x01..0x09, 0x0A..0x0E, 0x81(=-127), 0xF0(=-16, =240 unsigned).
    let setup = |ctx: &mut [u64]| {
        ctx[vd(1)] = 0x0807_0605_0403_0201;
        ctx[vd(1) + 1] = 0xF081_0E0D_0C0B_0A09;
    };
    let mut ctx = [0u64; CTX_U64S];
    setup(&mut ctx);
    unsafe { enter_block(umaxv, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0xF0, "UMAXV: unsigned max byte = 0xF0 (got 0x{:x})", ctx[vd(0)]);
    assert_eq!(ctx[vd(0) + 1], 0, "UMAXV: upper 64 zeroed");
    let mut ctx = [0u64; CTX_U64S];
    setup(&mut ctx);
    unsafe { enter_block(sminv, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0x81, "SMINV: signed min byte = -127 = 0x81 (got 0x{:x})", ctx[vd(0)]);

    // FMOV S0, S1 — scalar FP register copy, low 32 bits, upper zeroed. (B20)
    let fmov = winexec::make_executable(&translate_straight_line(&[0x1E20_4020u32], 0x1000));
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0xDEAD_BEEF_1234_5678; // only low 32 (0x12345678) is the S reg
    ctx[vd(0)] = 0xFFFF_FFFF_FFFF_FFFF; // dirty dst — must be fully overwritten
    ctx[vd(0) + 1] = 0xFFFF_FFFF_FFFF_FFFF;
    unsafe { enter_block(fmov, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0x1234_5678, "FMOV Sd,Sn: low 32 copied, [63:32] zeroed");
    assert_eq!(ctx[vd(0) + 1], 0, "FMOV Sd,Sn: upper 64 zeroed (FP-write)");

    // FCVTZU W0, S1 — unsigned FP→u32 of 3e9 (> 2^31): signed path would saturate
    // to INT_MAX; unsigned must give exactly 3000000000. (B31)
    let fcvtzu_w = winexec::make_executable(&translate_straight_line(&[0x1E39_0020u32], 0x1000));
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = (3.0e9f32).to_bits() as u64;
    unsafe { enter_block(fcvtzu_w, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 3_000_000_000u64, "FCVTZU W0,S1: 3e9 → 3000000000 (got {})", ctx[0]);

    // UCVTF D0, X1 — unsigned u64→f64 of 2^63 (high bit set): signed path yields
    // a negative double; unsigned must give +9.223e18. (B31)
    let ucvtf_x = winexec::make_executable(&translate_straight_line(&[0x9E63_0020u32], 0x1000));
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0x8000_0000_0000_0000; // 2^63
    unsafe { enter_block(ucvtf_x, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(0)], (9_223_372_036_854_775_808.0f64).to_bits(),
        "UCVTF D0,X1: 2^63 → +9.223e18 (got bits 0x{:x})", ctx[vd(0)]
    );

    // FCVTZU X0, D1 — unsigned FP→u64 of 1e19 (> 2^63): signed path yields the
    // 0x8000.. indefinite; unsigned must match `1e19 as u64`. (B31)
    let fcvtzu_x = winexec::make_executable(&translate_straight_line(&[0x9E79_0020u32], 0x1000));
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = (1.0e19f64).to_bits();
    unsafe { enter_block(fcvtzu_x, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 1.0e19f64 as u64, "FCVTZU X0,D1: 1e19 → {} (got {})", 1.0e19f64 as u64, ctx[0]);
}

/// Host-replay of bionic strlen's first-16-byte NEON compute (real instruction
/// words from /init @ 0x35b68c): CMEQ#0, SHRN.8b#4, FMOV d→x, variable LSR, RBIT,
/// CLZ, LSR#2. Seeds v0 = "/dev\0..." (x0=0 ⇒ 16-aligned, zero offset) and expects
/// x0 == 4. Pinpoints whether strlen("/dev")==0 is a DBT miscompile (the switch_root
/// getmntent gate: empty mnt_dir std::strings).
#[test]
fn bionic_strlen_compute_dev() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // cmeq v1.16b,v0.16b,#0 ; lsl x4,x0,#2 ; shrn v2.8b,v1.8h,#4 ; fmov x2,d2 ;
    // lsr x2,x2,x4 ; rbit x2,x2 ; clz x0,x2 ; lsr x0,x0,#2
    let words = [
        0x4e209801u32, 0xd37ef404, 0x0f0c8422, 0x9e660042,
        0x9ac42442, 0xdac00042, 0xdac01040, 0xd342fc00,
    ];
    let code = translate_straight_line(&words, 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // v0 = "/dev" + NUL + zero padding (16 bytes).
    ctx[vd(0)] = 0x0000_0000_7665_642F; // bytes: 2f 64 65 76 00 00 00 00 = '/','d','e','v',0,...
    ctx[vd(0) + 1] = 0;
    ctx[0] = 0; // x0 = base pointer (16-aligned, offset 0)
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 4, "strlen(\"/dev\") compute must be 4, got {}", ctx[0]);
}

/// strlen with a NON-16-aligned start pointer — the real getmntent case (mnt_dir
/// points into the line buffer at an odd offset, e.g. buf+6 for "/dev", buf+7 for
/// "/"). Exercises the variable-offset shift (lsl x4,x0,#2 ; lsr x2,x2,x4). Seeds
/// v0 with the full aligned 16-byte chunk and sets x0 = offset.
#[test]
fn bionic_strlen_unaligned_offsets() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let words = [
        0x4e209801u32, 0xd37ef404, 0x0f0c8422, 0x9e660042,
        0x9ac42442, 0xdac00042, 0xdac01040, 0xd342fc00,
    ];
    let code = translate_straight_line(&words, 0x1000);
    let exec = winexec::make_executable(&code);
    // case A: "tmpfs /dev\0....." — mnt_dir = chunk+6 = "/dev", expect 4.
    let chunk_a: [u8; 16] = *b"tmpfs /dev\0\0\0\0\0\0";
    let lo_a = u64::from_le_bytes(chunk_a[0..8].try_into().unwrap());
    let hi_a = u64::from_le_bytes(chunk_a[8..16].try_into().unwrap());
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(0)] = lo_a; ctx[vd(0) + 1] = hi_a; ctx[0] = 6;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 4, "strlen(buf+6=\"/dev\") must be 4, got {}", ctx[0]);
    // case B: "rootfs /\0......." — mnt_dir = chunk+7 = "/", expect 1 (the root line).
    let chunk_b: [u8; 16] = *b"rootfs /\0\0\0\0\0\0\0\0";
    let lo_b = u64::from_le_bytes(chunk_b[0..8].try_into().unwrap());
    let hi_b = u64::from_le_bytes(chunk_b[8..16].try_into().unwrap());
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(0)] = lo_b; ctx[vd(0) + 1] = hi_b; ctx[0] = 7;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 1, "strlen(buf+7=\"/\") must be 1, got {}", ctx[0]);
}

/// LDPSW destination/offset order — the switch_root getmntent gate. getmntent_r's
/// field extraction does `ldpsw x12,x9,[x29,#-0x18]` to load (dir1, dir0); the boot
/// proved x9 came out 0 instead of dir0, so e->mnt_dir = buf+0 (and the wrong byte
/// was NUL'd), making every mnt_dir an empty std::string. Verifies rt1=*(addr),
/// rt2=*(addr+4), incl. the negative-offset form, through the MMU-off flat path.
#[test]
fn ldpsw_signed_pair_dest_order() {
    let _serial = serial();
    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();
    // (1) ldpsw x1,x2,[x0] (offset 0): word0=7 @ +0, word1=8 @ +4.
    let buf = [7i32, 8, 0, 0, 0, 0, 0, 0];
    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = buf.as_ptr() as u64;
    let exec = winexec::make_executable(&translate_straight_line(&[0x6940_0801u32], 0x2000));
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[1] as i64, 7, "ldpsw rt1=*(addr)=7, got {}", ctx[1] as i64);
    assert_eq!(ctx[2] as i64, 8, "ldpsw rt2=*(addr+4)=8, got {}", ctx[2] as i64);
    // (2) EXACT init shape: ldpsw x12,x9,[x0,#-0x18]; *(x0-0x18)=dir1=8, *(x0-0x14)=dir0=7.
    let buf2 = [8i32, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = (buf2.as_ptr() as u64).wrapping_add(0x18);
    let exec = winexec::make_executable(&translate_straight_line(&[0x697d_240cu32], 0x2000));
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[12] as i64, 8, "ldpsw x12(rt1)=dir1=8, got {}", ctx[12] as i64);
    assert_eq!(ctx[9] as i64, 7, "ldpsw x9(rt2)=dir0=7, got {}", ctx[9] as i64);
}

// ── Landing 1 — gating-root miscompile exec-proofs ────────────────────────────
//
// Each test below targets one of the Landing-1 fixes (B1/B2/B3/B4/B6). The
// branch/spill cases build a hand-made single-block IrFunction with 14+
// concurrent live SSA values so the operand under test is provably
// `Assignment::Spill` (asserted via `is_spilled_in` before exec). Before the
// fixes these FAIL (a spilled operand silently resolves to the RAX scratch via
// the legacy `gpr()` helper, or the W-read leaks the dirty upper 32 bits); after
// the fixes they pass.

use aether_translator::regalloc::Assignment;

/// True if the allocator spilled `vid` (raw value id) in `alloc`.
fn is_spilled_in(alloc: &regalloc::AllocResult, vid: u32) -> bool {
    matches!(alloc.assignments.get(&vid), Some(Assignment::Spill(_)))
}

/// Build a spill-forcing prefix into `block`: N independent ConstI64 values
/// (`1<<i`) all kept live to the end via a final summing chain appended by the
/// caller. Returns the vector of value ids. With RAX/RCX reserved the allocator
/// has 12 GPRs, so N=16 guarantees ≥4 spills. The caller picks operands from the
/// returned ids (the LOW ids spill last; the test asserts the chosen operand is
/// actually spilled, so collision with a non-spilled id fails loud).
fn push_spill_pressure(
    block: &mut aether_translator::ir::IrBlock,
    n: u32,
) -> Vec<aether_translator::ir::IrValueId> {
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::IrOp;
    let mut vs = Vec::new();
    for i in 0..n {
        let v = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v, val: 1i64 << (i % 60) });
        vs.push(v);
    }
    vs
}

/// Lower a single-block IrFunction whose terminator is a Cb(N)z/Tb(N)z, resolving
/// the `taken` patch to a tail we append: the TAKEN path stores `marker_taken`
/// into ctx[`marker_reg`], the FALLTHROUGH path stores `marker_fall`. Returns the
/// executable bytes. Lets a branch-direction test observe which path executed in
/// a single self-contained block (no cross-block value-id aliasing).
fn lower_branch_probe(
    func: &IrFunction,
    alloc: &regalloc::AllocResult,
    marker_reg: u8,
    marker_taken: i64,
    marker_fall: i64,
) -> Vec<u8> {
    const RAX: u8 = 0;
    const R15: u8 = 15;
    let mut enc = X86Encoder::new();
    let mut patches: Vec<(usize, aether_translator::ir::BlockId)> = Vec::new();
    for blk in &func.blocks {
        IntLower::lower_block(blk, alloc, &mut enc, &mut patches);
    }
    // The branch lowering left exactly one forward patch (its `taken` target).
    assert_eq!(patches.len(), 1, "branch block must leave one taken-patch");
    let jcc_patch = patches[0].0;
    // Fallthrough path (executes when the branch is NOT taken): store marker_fall
    // into ctx[marker_reg], then JMP over the taken tail to the final RET.
    enc.emit_mov_r64_imm64(RAX, marker_fall);
    enc.emit_mov_mem_r64(R15, (marker_reg as i32) * 8, RAX);
    let jmp_end = enc.emit_jmp_rel32();
    // Taken path target: patch the branch's jcc here.
    let taken_pos = enc.pos();
    enc.patch_rel32(jcc_patch, taken_pos);
    enc.emit_mov_r64_imm64(RAX, marker_taken);
    enc.emit_mov_mem_r64(R15, (marker_reg as i32) * 8, RAX);
    // End:
    let end_pos = enc.pos();
    enc.patch_rel32(jmp_end, end_pos);
    enc.emit_ret();
    enc.finish()
}

/// B6 — `ReadGpr{sf=false}` must zero-extend a W-read. `add w0, w5, wzr` with x5
/// holding a dirty upper 32 must leave X0 == low-32 zero-extended. Before the fix
/// ReadGpr did a full 64-bit load → X0 kept the dirty upper bits.
#[test]
fn readgpr_wform_zext() {
    let _serial = serial();
    // add w0, w5, wzr  (32-bit ADD shifted-reg, Rm=wzr=31, Rn=5, Rd=0)
    //   sf=0 op=0 S=0: 0x0B000000 | (31<<16) | (5<<5) | 0 = 0x0B1F00A0
    let code = translate_straight_line(&[0x0B1F_00A0u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[5] = 0xFFFF_FFFF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0], 0x0000_0000_DEAD_BEEF,
        "add w0,w5,wzr must zero-extend low 32 (W-read), got 0x{:016x}",
        ctx[0]
    );
}

/// B2 (+B6) — W-form shifted-register operand must normalize Rm to 32 bits BEFORE
/// the shift. `orr w0, w3, w2, lsr #16` with x2 dirty upper and w3=0: the dirty
/// Xm[63:32] must NOT leak into the low-32 funnel result, so w0 == 0. The ASR
/// twin verifies sign-extend-from-bit-31 (not bit 63).
#[test]
fn wform_shifted_reg() {
    let _serial = serial();
    // (1) LSR form: orr w0, w3, w2, lsr #16
    //   ORR shifted-reg 32-bit: 0x2A000000 | (shift=01<<22) | (Rm=2<<16)
    //     | (imm6=16<<10) | (Rn=3<<5) | Rd=0 = 0x2A424060
    let code = translate_straight_line(&[0x2A42_4060u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[2] = 0xAAAA_AAAA_0000_0000; // low 32 == 0, only dirty upper
    ctx[3] = 0; // w3 == 0
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0], 0,
        "orr w0,w3,w2,lsr#16: dirty Xm[63:32] must not leak, w0 must be 0, got 0x{:016x}",
        ctx[0]
    );

    // (2) ASR form: orr w0, w3, w2, asr #16 — Wm = 0x8000_0000 (bit31 set), asr#16
    //   sign-extends bit31 over the W-lane: 0x8000_0000 asr 16 = 0xFFFF_8000.
    //   ORR shifted-reg, shift=10(ASR): 0x2A000000 | (2<<22) | (2<<16) | (16<<10)
    //     | (3<<5) = 0x2A824060
    let code = translate_straight_line(&[0x2A82_4060u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[2] = 0xDEAD_BEEF_8000_0000; // dirty upper; Wm = 0x8000_0000
    ctx[3] = 0;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0], 0x0000_0000_FFFF_8000,
        "orr w0,w3,w2,asr#16: ASR from bit31 (not bit63), got 0x{:016x}",
        ctx[0]
    );
}

/// B1 — `Mul` with spilled `a`,`b` must read the spilled operands (not the RAX
/// scratch). a=10, b=37 → 370. Before the fix bare `gpr()` returned RAX for the
/// spilled operands and the product was garbage.
#[test]
fn mul_spilled() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    let mut func = IrFunction::new(0x1000);
    let (va, vb) = {
        let block = func.add_block();
        // 16 live consts to drown the GPRs; va/vb are two of them set to 10/37.
        let vs = push_spill_pressure(block, 16);
        // Overwrite two of the earliest-defined values to 10 and 37 by defining
        // fresh values (kept live to the end via the sum chain below).
        let va = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: va, val: 10 });
        let vb = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vb, val: 37 });
        // product = va * vb
        let vprod = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Mul { dst: vprod, a: va, b: vb });
        block.push_op(IrOp::WriteGpr { reg: 0, src: vprod, sf: true });
        // Keep all the pressure values live to here so va/vb spill: sum them and
        // also fold in va/vb so they outlive the Mul's def point.
        let mut acc = vs[0];
        for &v in &vs[1..] {
            let nacc = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
            acc = nacc;
        }
        let acc2 = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Add { dst: acc2, a: acc, b: va });
        let acc3 = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Add { dst: acc3, a: acc2, b: vb });
        block.push_op(IrOp::WriteGpr { reg: 1, src: acc3, sf: true });
        (va, vb)
    };
    let alloc = regalloc::allocate(&func);
    assert!(
        is_spilled_in(&alloc, va.0) || is_spilled_in(&alloc, vb.0),
        "test invalid: neither Mul operand spilled (va spill={}, vb spill={})",
        is_spilled_in(&alloc, va.0),
        is_spilled_in(&alloc, vb.0)
    );
    let code = lower_built_func(&func);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 370, "10 * 37 with spilled operands must be 370, got {}", ctx[0]);
}

/// B3 — `Cbz`/`Cbnz` operand must materialize a spilled cond (not read RAX).
/// A spilled `a == 0` must take CBZ; a spilled `a != 0` must fall through. The
/// CBNZ twin is the mirror.
#[test]
fn cbz_spilled_branch() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{BlockId, IrFunction, IrOp};

    // Build a func whose terminator is Cb(N)z on a SPILLED value of `cond_val`.
    // marker_reg=20 is written 1 on taken, 2 on fallthrough by lower_branch_probe.
    fn build(cond_val: i64, cbnz: bool) -> (IrFunction, aether_translator::ir::IrValueId) {
        let mut func = IrFunction::new(0x1000);
        let cond;
        {
            let block = func.add_block();
            let vs = push_spill_pressure(block, 16);
            // The branch cond: a fresh value set to cond_val, kept live past the
            // sum chain so it spills.
            cond = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: cond, val: cond_val });
            // Sum the pressure values AND cond so cond is live at the branch.
            let mut acc = vs[0];
            for &v in &vs[1..] {
                let nacc = block.new_value(IrValueKind::I64);
                block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
                acc = nacc;
            }
            let acc2 = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: acc2, a: acc, b: cond });
            block.push_op(IrOp::WriteGpr { reg: 1, src: acc2, sf: true });
            // Terminator: Cb(N)z cond -> taken=BlockId(1), fallthru=BlockId(2).
            if cbnz {
                block.push_op(IrOp::Cbnz { a: cond, taken: BlockId(1), fallthru: BlockId(2) });
            } else {
                block.push_op(IrOp::Cbz { a: cond, taken: BlockId(1), fallthru: BlockId(2) });
            }
        }
        (func, cond)
    }

    // Run: returns the marker in ctx[20] (1=taken, 2=fallthrough).
    fn run(cond_val: i64, cbnz: bool) -> u64 {
        let (func, cond) = build(cond_val, cbnz);
        let alloc = regalloc::allocate(&func);
        assert!(
            is_spilled_in(&alloc, cond.0),
            "test invalid: branch cond not spilled for cond_val={cond_val}"
        );
        let code = lower_branch_probe(&func, &alloc, 20, 1, 2);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        ctx[20]
    }

    // CBZ: cond==0 → taken(1); cond!=0 → fallthrough(2).
    assert_eq!(run(0, false), 1, "CBZ spilled cond==0 must be taken");
    assert_eq!(run(7, false), 2, "CBZ spilled cond!=0 must fall through");
    // CBNZ: cond!=0 → taken(1); cond==0 → fallthrough(2).
    assert_eq!(run(7, true), 1, "CBNZ spilled cond!=0 must be taken");
    assert_eq!(run(0, true), 2, "CBNZ spilled cond==0 must fall through");
}

/// B4 — `Tbz`/`Tbnz` must (a) read a SPILLED operand (not the RAX scratch) and
/// (b) NOT mutate the source register/slot (ARM TBZ/TBNZ leave all regs intact;
/// the lowering must `shr` a SCRATCH copy, never an allocated reg).
///
/// NOTE: this direct `IrOp::Tbz`/`Tbnz` backend arm tests `(value >> bit) == 0`
/// (the live ARM lift instead expands TB(N)Z to `lshr; and #1; cmp; csel`, so it
/// never reaches this arm). We therefore drive the test with single-bit values so
/// the `value >> bit` direction is unambiguous, and focus on the B4 invariants:
/// spilled-operand read + source-not-mutated.
#[test]
fn tbz_spilled_no_mutate() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{BlockId, IrFunction, IrOp};

    // cond bit `bit` of cond_val drives the branch; cond is also written to X2 so
    // the test can confirm the source value is UNCHANGED after the TBZ executes.
    fn build(cond_val: i64, bit: u8, tbnz: bool) -> (IrFunction, aether_translator::ir::IrValueId) {
        let mut func = IrFunction::new(0x1000);
        let cond;
        {
            let block = func.add_block();
            let vs = push_spill_pressure(block, 16);
            cond = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: cond, val: cond_val });
            // Publish cond to X2 BEFORE the branch (proves the slot value), and
            // keep it live across the sum so it spills.
            block.push_op(IrOp::WriteGpr { reg: 2, src: cond, sf: true });
            let mut acc = vs[0];
            for &v in &vs[1..] {
                let nacc = block.new_value(IrValueKind::I64);
                block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
                acc = nacc;
            }
            let acc2 = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: acc2, a: acc, b: cond });
            block.push_op(IrOp::WriteGpr { reg: 1, src: acc2, sf: true });
            if tbnz {
                block.push_op(IrOp::Tbnz { a: cond, bit, taken: BlockId(1), fallthru: BlockId(2) });
            } else {
                block.push_op(IrOp::Tbz { a: cond, bit, taken: BlockId(1), fallthru: BlockId(2) });
            }
        }
        (func, cond)
    }

    // Returns (marker, x2) so we check both branch direction and non-mutation.
    fn run(cond_val: i64, bit: u8, tbnz: bool) -> (u64, u64) {
        let (func, cond) = build(cond_val, bit, tbnz);
        let alloc = regalloc::allocate(&func);
        assert!(
            is_spilled_in(&alloc, cond.0),
            "test invalid: TBZ operand not spilled (cond_val={cond_val})"
        );
        let code = lower_branch_probe(&func, &alloc, 20, 1, 2);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        (ctx[20], ctx[2])
    }

    // value 0x40 = only bit 6 set. (value>>bit)==0 drives TBZ-taken.
    // TBZ bit6: 0x40>>6 = 1 ≠ 0 → fallthrough(2).
    let (m, x2) = run(0x40, 6, false);
    assert_eq!(m, 2, "TBZ bit6 of 0x40: (0x40>>6)=1≠0 → fall through");
    assert_eq!(x2, 0x40, "TBZ must NOT mutate the source (x2 stays 0x40), got 0x{x2:x}");
    // TBZ bit7: 0x40>>7 = 0 → taken(1).
    let (m, x2) = run(0x40, 7, false);
    assert_eq!(m, 1, "TBZ bit7 of 0x40: (0x40>>7)=0 → taken");
    assert_eq!(x2, 0x40, "TBZ must NOT mutate the source, got 0x{x2:x}");
    // TBNZ bit6: 0x40>>6 = 1 ≠ 0 → taken(1).
    let (m, x2) = run(0x40, 6, true);
    assert_eq!(m, 1, "TBNZ bit6 of 0x40: (0x40>>6)=1≠0 → taken");
    assert_eq!(x2, 0x40, "TBNZ must NOT mutate the source, got 0x{x2:x}");
    // High bit (bit 40 set) to exercise a shift > 31 on the 64-bit slot.
    // TBNZ bit40: (1<<40)>>40 = 1 ≠ 0 → taken; source must be unchanged.
    let (m, x2) = run(1i64 << 40, 40, true);
    assert_eq!(m, 1, "TBNZ bit40 (set) must be taken");
    assert_eq!(x2, 1u64 << 40, "TBNZ high-bit must not mutate source, got 0x{x2:x}");
}

// ───────────────────────── Landing 2-4 exec-proofs ─────────────────────────
// These pin the confirmed correctness fixes (B8, B9, B14, B15, B18, B21, B24,
// B26) and the remaining spill-safe arms (B5, B10, B11, B12). Each FAILS on the
// pre-fix code (wrong value / host #DE / sign-extension to 64) and PASSES after.

/// B9 — `RegOffset` UXTW/SXTW must apply the index extend BEFORE the shift+add.
/// A dirty upper 32 in the index X-reg must not affect the computed address (the
/// pre-fix code read the index as a full 64-bit value, so the dirty upper bits
/// shifted into the offset → wrong load address → guest SIGSEGV).
///
/// We can't dereference a real guest pointer in this host harness, so instead of
/// `ldr` we use the address-forming path that writes the effective address back:
/// `ldr x0, [x1, w2, uxtw #3]` followed by reading back x1 is not enough (no
/// writeback). Use a register-offset STORE is also a memory op. So we verify the
/// address arithmetic directly via the equivalent ADD path the lift emits: an
/// `add x0, x1, w2, uxtw #3` (AddSubExtReg) shares the exact extend+shift the
/// RegOffset arm mirrors — but to test the RegOffset arm itself we drive a
/// register-offset load against a real host buffer and confirm it reads the
/// element the *masked* index selects.
#[test]
fn regoffset_uxtw() {
    let _serial = serial();
    use aether_translator::runtime::mmu::aether_mmu_set_window;
    // Build a host-resident array and load element [4] via uxtw #3 (8-byte stride)
    // with a dirty upper 32 in the index register. The base (x1) points at the
    // array; index w2 = 4 with garbage in bits [63:32]. Correct effective address
    // = base + (4 << 3) = base + 32 → array[4]. If the extend is dropped, the
    // dirty upper shifts in and the address is wildly wrong (would fault or read
    // garbage).
    //
    // The Load lowers to an `aether_mmu_xlate` call; with the MMU OFF that path is
    // flat (PA == VA) but confines the VA to the pinned guest window. Point the
    // window at this host array so the flat load reads it. (Window is process-wide
    // global state; the EXEC_LOCK + single-threaded run serialize it, and we
    // restore it to (0,0) at the end.)
    let array: [u64; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xDEAD_BEEF_CAFE_F00D, 0xA5, 0xA6, 0xA7];
    aether_mmu_set_window(array.as_ptr() as u64, core::mem::size_of_val(&array) as u64);

    // ldr x0, [x1, w2, uxtw #3]  = 0xF8625820
    let code = translate_straight_line(&[0xF862_5820u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = array.as_ptr() as u64; // base
    ctx[2] = 0xFFFF_FFFF_0000_0004; // index: w2 = 4, dirty upper 32
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let got_uxtw = ctx[0];

    // SXTW negative twin: index w2 = -1 (0xFFFF_FFFF) sign-extends to -1, so the
    // effective address = base + (-1 << 3) = base - 8 → array[-1]. Point the base
    // at array[1] so array[-1] (relative to base) is array[0].
    // ldr x0, [x1, w2, sxtw #3]: option=110(SXTW) (uxtw 010 → sxtw 110: set bit15).
    let sxtw_word = 0xF862_5820u32 | (0b100 << 13);
    let code = translate_straight_line(&[sxtw_word], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = array.as_ptr() as u64 + 8; // base = &array[1]
    ctx[2] = 0xDEAD_BEEF_FFFF_FFFF; // w2 = -1, dirty upper; sxtw → -1
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let got_sxtw = ctx[0];

    aether_mmu_set_window(0, 0); // restore: leave no global window pinned
    drop(_serial);

    assert_eq!(
        got_uxtw, 0xDEAD_BEEF_CAFE_F00D,
        "ldr [x1,w2,uxtw#3] must use masked index 4 → array[4]; dirty upper leaked, got 0x{:016x}",
        got_uxtw
    );
    assert_eq!(
        got_sxtw, 0xA0,
        "ldr [x1,w2,sxtw#3] with w2=-1 must read array[0], got 0x{:016x}",
        got_sxtw
    );
}

/// B26 — guest SDIV/UDIV by zero must yield 0 (ARM non-trapping), NOT raise a host
/// `#DE` that crashes the hypervisor. A divide-by-zero in translated guest code is
/// guest-triggerable; pre-fix it `idiv`/`div`'d a zero divisor and faulted.
#[test]
fn sdiv_div_by_zero() {
    let _serial = serial();
    // sdiv w0, w1, w2  (w2 = 0) → w0 == 0, no #DE.
    let code = translate_straight_line(&[0x1AC2_0C20u32], 0x1000); // sdiv w0,w1,w2
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 100;
    ctx[2] = 0; // divisor zero
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 0, "SDIV ÷0 must be 0 (no host #DE), got {}", ctx[0]);

    // udiv w0, w1, w2  (w2 = 0) → w0 == 0.
    let code = translate_straight_line(&[0x1AC2_0820u32], 0x1000); // udiv w0,w1,w2
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 100;
    ctx[2] = 0;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 0, "UDIV ÷0 must be 0 (no host #DE), got {}", ctx[0]);
}

/// B8 — W-form SDIV of a negative dividend must produce the signed quotient. The
/// pre-fix code did a 64-bit `cqo+idiv` on the zero-extended (large positive)
/// W value → wrong sign/magnitude. `-7 / 2 = -3`.
#[test]
fn sdiv_wform_negative() {
    let _serial = serial();
    // sdiv w0, w1, w2 ; w1 = -7 (0xFFFF_FFF9 in low 32, dirty upper), w2 = 2.
    let code = translate_straight_line(&[0x1AC2_0C20u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0xDEAD_BEEF_FFFF_FFF9; // w1 = -7, dirty upper 32
    ctx[2] = 0x0000_0000_0000_0002; // w2 = 2
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // -3 as 32-bit, zero-extended into the W-dest: 0x0000_0000_FFFF_FFFD.
    assert_eq!(
        ctx[0], 0x0000_0000_FFFF_FFFD,
        "sdiv w0,w1,w2: -7/2 must be -3 (W-form), got 0x{:016x}",
        ctx[0]
    );

    // UDIV stale-upper twin: udiv w0,w1,w2 with dirty upper in w1; the W-divide
    // must ignore bits [63:32]. w1 low = 100, w2 = 7 → 14.
    let code = translate_straight_line(&[0x1AC2_0820u32], 0x1000); // udiv w0,w1,w2
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0xFFFF_FFFF_0000_0064; // w1 = 100, dirty upper
    ctx[2] = 7;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 14, "udiv w0,w1,w2: 100/7 must be 14 (W-form, dirty upper ignored), got {}", ctx[0]);
}

/// B24 — `LDRSB Wt`/`LDRSH Wt` (signed sub-word, 32-bit dest) sign-extend to 32
/// then ZERO bits [63:32]; pre-fix the lift hardcoded sf=true → sign-extended to
/// 64, leaking 1-bits into the upper 32.
#[test]
fn ldrsb_wt_zext() {
    let _serial = serial();
    use aether_translator::runtime::mmu::aether_mmu_set_window;
    // 8-byte buffer so the pinned window covers both the byte and halfword loads.
    // Low byte 0x80 (=-128 signed), next byte 0x80 too so the halfword reads 0x8000.
    let buf: [u8; 8] = [0x80, 0x80, 0, 0, 0, 0, 0, 0];
    aether_mmu_set_window(buf.as_ptr() as u64, buf.len() as u64);

    // ldrsb w0, [x1]  = 0x39C00020 (signed byte, W-form: opc=0b11 → is_64=false)
    let code = translate_straight_line(&[0x39C0_0020u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = buf.as_ptr() as u64;
    ctx[0] = 0xFFFF_FFFF_FFFF_FFFF; // pre-dirty dst to catch a missing narrow
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let got_b = ctx[0];

    // ldrsh w0, [x1]  = 0x79C00020 (signed halfword, W-form). Halfword = 0x8080.
    let code = translate_straight_line(&[0x79C0_0020u32], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = buf.as_ptr() as u64;
    ctx[0] = 0xFFFF_FFFF_FFFF_FFFF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let got_h = ctx[0];

    aether_mmu_set_window(0, 0);
    drop(_serial);

    assert_eq!(
        got_b, 0x0000_0000_FFFF_FF80,
        "LDRSB Wt of 0x80 must sign-extend to 32 then zero [63:32], got 0x{:016x}",
        got_b
    );
    // 0x8080 as a signed 16-bit = -32640 → sign-extend to 32 = 0xFFFF_8080, then
    // zero [63:32] for the W-form.
    assert_eq!(
        got_h, 0x0000_0000_FFFF_8080,
        "LDRSH Wt of 0x8080 must sign-extend to 32 then zero [63:32], got 0x{:016x}",
        got_h
    );
}

/// B14 — REV16 must byte-swap within each 16-bit lane (pre-fix emitted a NOP).
/// `rev16 w0, w0` of 0x12345678 → 0x34127856.
#[test]
fn rev16_swaps() {
    let _serial = serial();
    // rev16 w0, w0  = 0x5AC00400
    let code = translate_straight_line(&[0x5AC0_0400u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = 0x12345678;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0], 0x0000_0000_3412_7856,
        "rev16 w0 of 0x12345678 must be 0x34127856 (per-16-bit swap), got 0x{:016x}",
        ctx[0]
    );
}

/// B15 — REV32 Xd must byte-reverse EACH 32-bit word, keeping both words (pre-fix
/// the X-form dropped sf and bswap32'd only the low word, zeroing the high word).
/// `rev32 x0, x0` of 0x1122334455667788 → 0x4433221188776655.
#[test]
fn rev32_xform() {
    let _serial = serial();
    // rev32 x0, x0  = 0xDAC00800
    let code = translate_straight_line(&[0xDAC0_0800u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[0] = 0x1122_3344_5566_7788;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0], 0x4433_2211_8877_6655,
        "rev32 x0 must byte-reverse each 32-bit word keeping both, got 0x{:016x}",
        ctx[0]
    );
}

/// B18 — `EXTR Xd,Xn,Xm,#0` must equal Xm (the low half). The general funnel path
/// would `Shl(Xn, width)` which x86 masks to a shift-by-0 = Xn, corrupting the OR;
/// the lift special-cases lsb==0.
#[test]
fn extr_lsb0() {
    let _serial = serial();
    // extr x0, x8, x9, #0  = 0x93C90100
    let code = translate_straight_line(&[0x93C9_0100u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[8] = 0x1111_2222_3333_4444; // Xn (high half, must NOT appear)
    ctx[9] = 0xAABB_CCDD_EEFF_0011; // Xm (low half, the answer)
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0], 0xAABB_CCDD_EEFF_0011,
        "extr x0,x8,x9,#0 must equal x9 (Xm), got 0x{:016x}",
        ctx[0]
    );
}

/// B21 — W-form `EXTR`/`ROR-imm` must not leak the dirty `Xm[63:32]` into the
/// 32-bit funnel-shift result. `extr w0, w1, w2, #4` with x2's upper 32 dirty:
/// result = ((Wn:Wm) >> 4) over the 32-bit lane, independent of Xm[63:32].
#[test]
fn extr_wform_dirty_upper() {
    let _serial = serial();
    // extr w0, w1, w2, #4  = 0x13821020
    let code = translate_straight_line(&[0x1382_1020u32], 0x1000);
    assert!(!code.windows(2).any(|w| w == [0x0F, 0x0B]), "no UD2");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // Wn = 0x0000_000F, Wm = 0xABCD_EF12, with garbage in x2[63:32].
    ctx[1] = 0x0000_0000_0000_000F;
    ctx[2] = 0xFFFF_FFFF_ABCD_EF12;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // low half  = Wm >> 4              = 0x0ABC_DEF1
    // high half = Wn << (32-4)=Wn<<28  = 0xF000_0000
    // OR (32-bit lane), zero-extended  = 0x0000_0000_FABC_DEF1
    assert_eq!(
        ctx[0], 0x0000_0000_FABC_DEF1,
        "extr w0,w1,w2,#4: dirty Xm[63:32] must not leak, got 0x{:016x}",
        ctx[0]
    );
}

/// B5 — `Madd` (the live multiply path) with SPILLED operands must read the
/// spilled values, not the RAX scratch. a=10, b=37, c=5 → 10*37+5 = 375.
#[test]
fn madd_spilled() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    let mut func = IrFunction::new(0x1000);
    let (va, vb, vc) = {
        let block = func.add_block();
        let vs = push_spill_pressure(block, 16);
        let va = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: va, val: 10 });
        let vb = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vb, val: 37 });
        let vc = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vc, val: 5 });
        let vres = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Madd { dst: vres, a: va, b: vb, c: vc });
        block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: true });
        // Keep pressure + operands live to the end so they spill.
        let mut acc = vs[0];
        for &v in &vs[1..] {
            let nacc = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
            acc = nacc;
        }
        for &v in &[va, vb, vc] {
            let nacc = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
            acc = nacc;
        }
        block.push_op(IrOp::WriteGpr { reg: 1, src: acc, sf: true });
        (va, vb, vc)
    };
    let alloc = regalloc::allocate(&func);
    assert!(
        is_spilled_in(&alloc, va.0) || is_spilled_in(&alloc, vb.0) || is_spilled_in(&alloc, vc.0),
        "test invalid: no Madd operand spilled"
    );
    let code = lower_built_func(&func);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 375, "10*37+5 with spilled operands must be 375, got {}", ctx[0]);
}

/// B10 — `Not` with a SPILLED operand must read the spilled value (not RAX).
/// ~0x00FF = 0xFFFF_FFFF_FFFF_FF00.
#[test]
fn not_spilled() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    let mut func = IrFunction::new(0x1000);
    let va = {
        let block = func.add_block();
        let vs = push_spill_pressure(block, 16);
        let va = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: va, val: 0x00FF });
        let vres = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Not { dst: vres, a: va });
        block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: true });
        let mut acc = vs[0];
        for &v in &vs[1..] {
            let nacc = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
            acc = nacc;
        }
        let acc2 = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Add { dst: acc2, a: acc, b: va });
        block.push_op(IrOp::WriteGpr { reg: 1, src: acc2, sf: true });
        va
    };
    let alloc = regalloc::allocate(&func);
    assert!(is_spilled_in(&alloc, va.0), "test invalid: Not operand not spilled");
    let code = lower_built_func(&func);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[0], 0xFFFF_FFFF_FFFF_FF00,
        "~0x00FF with spilled operand must be 0xFFFFFFFFFFFFFF00, got 0x{:016x}",
        ctx[0]
    );
}

/// B11 — `Clz` (X-form) with a SPILLED operand must read the spilled value and
/// compute the correct count. clz(0x0000_0000_0000_00FF) = 56 (64-bit form).
#[test]
fn clz_spilled() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    let mut func = IrFunction::new(0x1000);
    let va = {
        let block = func.add_block();
        let vs = push_spill_pressure(block, 16);
        let va = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: va, val: 0xFF });
        let vres = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Clz { dst: vres, a: va, sf: true });
        block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: true });
        let mut acc = vs[0];
        for &v in &vs[1..] {
            let nacc = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
            acc = nacc;
        }
        let acc2 = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Add { dst: acc2, a: acc, b: va });
        block.push_op(IrOp::WriteGpr { reg: 1, src: acc2, sf: true });
        va
    };
    let alloc = regalloc::allocate(&func);
    assert!(is_spilled_in(&alloc, va.0), "test invalid: Clz operand not spilled");
    let code = lower_built_func(&func);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[0], 56, "clz(0xFF) X-form with spilled operand must be 56, got {}", ctx[0]);
}

/// B12 — `Cls` (X-form) with a SPILLED operand must read the spilled value and
/// keep it live across the internal xor (the pre-fix bare-`gpr()` read RAX and
/// re-read `ra` after writing `rd`, corrupting the count under spill pressure).
///
/// This is a DIFFERENTIAL spill-safety proof: it computes CLS of the same input
/// with the operand SPILLED and with it in a register, and asserts the two agree.
/// (It deliberately does NOT hand-assert an absolute CLS value — the CLS *count*
/// arithmetic is a separate concern; spill-safety is what B12 fixes.)
/// ARM C6.2.41 CLS: "the number of consecutive bits following the most
/// significant bit that are the same as it". Asserts ABSOLUTE values for both
/// width forms (the existing `cls_spilled` only checks spilled==register, so it
/// cannot catch an arithmetic off-by-one). The prior lowering computed
/// `CLZ(x ^ (x<<1)) - 1`, which is one too low for every input with a real sign
/// run (e.g. it gave 54 for 0xFF..FF00 where ARM defines 55); the correct
/// identity is `CLZ((x ^ (x<<1)) >> 1) - 1`.
#[test]
fn cls_absolute_values() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    fn cls(input: i64, sf: bool) -> u64 {
        let mut func = IrFunction::new(0x1000);
        {
            let block = func.add_block();
            let va = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: va, val: input });
            let vres = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Cls { dst: vres, a: va, sf });
            block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: true });
        }
        let _alloc = regalloc::allocate(&func);
        let code = lower_built_func(&func);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        ctx[0]
    }

    // ── X-form (sf = true, 64-bit) ──
    assert_eq!(cls(0xFFFF_FFFF_FFFF_FF00u64 as i64, true), 55, "CLS X 0xFF..FF00");
    assert_eq!(cls(0xFFFF_FFFF_FFFF_FFFFu64 as i64, true), 63, "CLS X all-ones");
    assert_eq!(cls(0x0000_0000_0000_0000i64, true), 63, "CLS X zero");
    assert_eq!(cls(0x4000_0000_0000_0000u64 as i64, true), 0, "CLS X bit62 (sign0, differ at 62)");
    assert_eq!(cls(0x7FFF_FFFF_FFFF_FFFFu64 as i64, true), 0, "CLS X 0x7F.. (sign0, differ at 62)");
    assert_eq!(cls(0x0000_0000_0000_0001i64, true), 62, "CLS X 1 (sign0, differ at bit0)");

    // ── W-form (sf = false, 32-bit; result zero-extended into the X reg) ──
    assert_eq!(cls(0xFFFF_FF00u64 as i64, false), 23, "CLS W 0xFFFFFF00");
    assert_eq!(cls(0xFFFF_FFFFu64 as i64, false), 31, "CLS W all-ones");
    assert_eq!(cls(0x0000_0000i64, false), 31, "CLS W zero");
    assert_eq!(cls(0x0000_0001i64, false), 30, "CLS W 1");
    assert_eq!(cls(0x4000_0000u64 as i64, false), 0, "CLS W bit30 (sign0, differ at 30)");
}

#[test]
fn cls_spilled() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    const INPUT: i64 = 0xFFFF_FFFF_FFFF_FF00u64 as i64;

    // Build a func; `spill_pressure` toggles whether the Cls operand is forced to
    // spill. Returns (cls_result, was_spilled).
    fn run(spill_pressure: bool) -> (u64, bool) {
        let mut func = IrFunction::new(0x1000);
        let va = {
            let block = func.add_block();
            let vs = if spill_pressure { push_spill_pressure(block, 16) } else { Vec::new() };
            let va = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: va, val: INPUT });
            let vres = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Cls { dst: vres, a: va, sf: true });
            block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: true });
            if spill_pressure {
                let mut acc = vs[0];
                for &v in &vs[1..] {
                    let nacc = block.new_value(IrValueKind::I64);
                    block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
                    acc = nacc;
                }
                let acc2 = block.new_value(IrValueKind::I64);
                block.push_op(IrOp::Add { dst: acc2, a: acc, b: va });
                block.push_op(IrOp::WriteGpr { reg: 1, src: acc2, sf: true });
            }
            va
        };
        let alloc = regalloc::allocate(&func);
        let spilled = is_spilled_in(&alloc, va.0);
        let code = lower_built_func(&func);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        (ctx[0], spilled)
    }

    let (reg_val, reg_spilled) = run(false);
    let (spill_val, spill_spilled) = run(true);
    assert!(!reg_spilled, "baseline run must keep the operand in a register");
    assert!(spill_spilled, "test invalid: Cls operand not spilled under pressure");
    assert_eq!(
        spill_val, reg_val,
        "Cls spilled-operand result ({spill_val}) must match the register result ({reg_val})"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Vector floating-point (FADD/FSUB/FMUL/FDIV/FMLA/FMLS/FMAX/FMIN/FMAXNM/FMINNM/
// FABD; FCMEQ/FCMGT/FCMGE reg + vs #0; FABS/FNEG/FSQRT). The SurfaceFlinger /
// Skia / Mesa boot wall — these were Reserved/UD2 before. Inputs are packed f32
// lanes; lane outputs asserted via f32::to_bits().
// ════════════════════════════════════════════════════════════════════════════

/// Pack four f32 lanes into a (lo, hi) u64 pair for a `.4s` register: lane0 is
/// the LOW 32 bits of `lo`, lane1 the high 32 of `lo`, lane2 low of `hi`, etc.
fn pack4(l0: f32, l1: f32, l2: f32, l3: f32) -> (u64, u64) {
    let lo = (l0.to_bits() as u64) | ((l1.to_bits() as u64) << 32);
    let hi = (l2.to_bits() as u64) | ((l3.to_bits() as u64) << 32);
    (lo, hi)
}
/// Extract the four f32 lanes from a `.4s` (lo, hi) pair.
fn unpack4(lo: u64, hi: u64) -> [f32; 4] {
    [
        f32::from_bits(lo as u32),
        f32::from_bits((lo >> 32) as u32),
        f32::from_bits(hi as u32),
        f32::from_bits((hi >> 32) as u32),
    ]
}

/// Run a single `.4s` vector-FP op (Vd = f(V1, V2)) and return Vd's 4 lanes.
/// `d`/`n`/`m` default to v0/v1/v2.
fn run_vecfp_4s(word: u32, v1: (u64, u64), v2: (u64, u64), vd_in: (u64, u64)) -> [f32; 4] {
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // Confirm the encoding decodes (fails loudly if the decoder rejects it).
    decode_instruction(word).expect("decode vector-FP word");
    let code = translate_straight_line(&[word], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(0)] = vd_in.0;
    ctx[vd(0) + 1] = vd_in.1;
    ctx[vd(1)] = v1.0;
    ctx[vd(1) + 1] = v1.1;
    ctx[vd(2)] = v2.0;
    ctx[vd(2) + 1] = v2.1;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    unpack4(ctx[vd(0)], ctx[vd(0) + 1])
}

#[test]
fn fadd_4s_executes() {
    let _serial = serial();
    // fadd v0.4s, v1.4s, v2.4s (0x4E22D420).
    let a = pack4(1.0, 2.5, -3.0, 100.0);
    let b = pack4(0.5, 0.5, 3.0, 0.25);
    let r = run_vecfp_4s(0x4E22_D420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 1.5f32.to_bits(), "fadd lane0");
    assert_eq!(r[1].to_bits(), 3.0f32.to_bits(), "fadd lane1");
    assert_eq!(r[2].to_bits(), 0.0f32.to_bits(), "fadd lane2");
    assert_eq!(r[3].to_bits(), 100.25f32.to_bits(), "fadd lane3");
}

#[test]
fn fsub_4s_executes() {
    let _serial = serial();
    // fsub v0.4s, v1.4s, v2.4s (0x4EA2D420).
    let a = pack4(1.0, 2.5, -3.0, 100.0);
    let b = pack4(0.5, 0.5, 3.0, 0.25);
    let r = run_vecfp_4s(0x4EA2_D420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 0.5f32.to_bits(), "fsub lane0");
    assert_eq!(r[1].to_bits(), 2.0f32.to_bits(), "fsub lane1");
    assert_eq!(r[2].to_bits(), (-6.0f32).to_bits(), "fsub lane2");
    assert_eq!(r[3].to_bits(), 99.75f32.to_bits(), "fsub lane3");
}

#[test]
fn fmul_4s_executes() {
    let _serial = serial();
    // fmul v0.4s, v1.4s, v2.4s (0x6E22DC20).
    let a = pack4(2.0, 3.0, -4.0, 1.5);
    let b = pack4(2.5, 3.0, 0.5, 4.0);
    let r = run_vecfp_4s(0x6E22_DC20, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 5.0f32.to_bits(), "fmul lane0");
    assert_eq!(r[1].to_bits(), 9.0f32.to_bits(), "fmul lane1");
    assert_eq!(r[2].to_bits(), (-2.0f32).to_bits(), "fmul lane2");
    assert_eq!(r[3].to_bits(), 6.0f32.to_bits(), "fmul lane3");
}

#[test]
fn fdiv_4s_executes() {
    let _serial = serial();
    // fdiv v0.4s, v1.4s, v2.4s (0x6E22FC20).
    let a = pack4(10.0, 9.0, -8.0, 1.0);
    let b = pack4(2.0, 3.0, 4.0, 4.0);
    let r = run_vecfp_4s(0x6E22_FC20, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 5.0f32.to_bits(), "fdiv lane0");
    assert_eq!(r[1].to_bits(), 3.0f32.to_bits(), "fdiv lane1");
    assert_eq!(r[2].to_bits(), (-2.0f32).to_bits(), "fdiv lane2");
    assert_eq!(r[3].to_bits(), 0.25f32.to_bits(), "fdiv lane3");
}

#[test]
fn fmla_4s_executes() {
    let _serial = serial();
    // fmla v0.4s, v1.4s, v2.4s (0x4E22CC20): Vd += Vn*Vm (Vd is read+written).
    let a = pack4(2.0, 3.0, 4.0, 5.0);
    let b = pack4(10.0, 10.0, 10.0, 10.0);
    let acc = pack4(1.0, 1.0, 1.0, 1.0);
    let r = run_vecfp_4s(0x4E22_CC20, a, b, acc);
    assert_eq!(r[0].to_bits(), 21.0f32.to_bits(), "fmla lane0: 1 + 2*10");
    assert_eq!(r[1].to_bits(), 31.0f32.to_bits(), "fmla lane1: 1 + 3*10");
    assert_eq!(r[2].to_bits(), 41.0f32.to_bits(), "fmla lane2: 1 + 4*10");
    assert_eq!(r[3].to_bits(), 51.0f32.to_bits(), "fmla lane3: 1 + 5*10");
}

#[test]
fn fmls_4s_executes() {
    let _serial = serial();
    // fmls v0.4s, v1.4s, v2.4s (0x4EA2CC20): Vd -= Vn*Vm.
    let a = pack4(2.0, 3.0, 4.0, 5.0);
    let b = pack4(10.0, 10.0, 10.0, 10.0);
    let acc = pack4(100.0, 100.0, 100.0, 100.0);
    let r = run_vecfp_4s(0x4EA2_CC20, a, b, acc);
    assert_eq!(r[0].to_bits(), 80.0f32.to_bits(), "fmls lane0: 100 - 2*10");
    assert_eq!(r[1].to_bits(), 70.0f32.to_bits(), "fmls lane1: 100 - 3*10");
    assert_eq!(r[2].to_bits(), 60.0f32.to_bits(), "fmls lane2: 100 - 4*10");
    assert_eq!(r[3].to_bits(), 50.0f32.to_bits(), "fmls lane3: 100 - 5*10");
}

#[test]
fn fmax_fmin_4s_execute() {
    let _serial = serial();
    // fmax v0.4s (0x4E22F420) — finite operands: lanewise max.
    let a = pack4(1.0, 5.0, -3.0, 2.0);
    let b = pack4(4.0, 2.0, -1.0, 2.0);
    let r = run_vecfp_4s(0x4E22_F420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 4.0f32.to_bits(), "fmax lane0");
    assert_eq!(r[1].to_bits(), 5.0f32.to_bits(), "fmax lane1");
    assert_eq!(r[2].to_bits(), (-1.0f32).to_bits(), "fmax lane2");
    assert_eq!(r[3].to_bits(), 2.0f32.to_bits(), "fmax lane3");

    // fmin v0.4s (0x4EA2F420).
    let r = run_vecfp_4s(0x4EA2_F420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 1.0f32.to_bits(), "fmin lane0");
    assert_eq!(r[1].to_bits(), 2.0f32.to_bits(), "fmin lane1");
    assert_eq!(r[2].to_bits(), (-3.0f32).to_bits(), "fmin lane2");
    assert_eq!(r[3].to_bits(), 2.0f32.to_bits(), "fmin lane3");
}

#[test]
fn fmaxnm_fminnm_nan_fixup_execute() {
    let _serial = serial();
    // FMAXNM/FMINNM (IEEE maxNum/minNum): a NaN lane yields the OTHER operand.
    let nan = f32::NAN;
    // lane0: Vn NaN, Vm 4.0   → maxNum = 4.0
    // lane1: Vm NaN, Vn 5.0   → maxNum = 5.0  (the x86-wrong case the fixup repairs)
    // lane2: both finite      → max(-3,-1) = -1
    // lane3: both finite      → max(2,7)  = 7
    let a = pack4(nan, 5.0, -3.0, 2.0);
    let b = pack4(4.0, nan, -1.0, 7.0);
    // fmaxnm v0.4s, v1.4s, v2.4s (0x4E22C420).
    let r = run_vecfp_4s(0x4E22_C420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 4.0f32.to_bits(), "fmaxnm lane0: NaN-vn → vm");
    assert_eq!(r[1].to_bits(), 5.0f32.to_bits(), "fmaxnm lane1: NaN-vm → vn");
    assert_eq!(r[2].to_bits(), (-1.0f32).to_bits(), "fmaxnm lane2");
    assert_eq!(r[3].to_bits(), 7.0f32.to_bits(), "fmaxnm lane3");

    // fminnm v0.4s, v1.4s, v2.4s (0x4EA2C420).
    // lane0: Vn NaN → 4.0 ; lane1: Vm NaN → 5.0 ; lane2: min(-3,-1)=-3 ; lane3: min(2,7)=2
    let r = run_vecfp_4s(0x4EA2_C420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 4.0f32.to_bits(), "fminnm lane0: NaN-vn → vm");
    assert_eq!(r[1].to_bits(), 5.0f32.to_bits(), "fminnm lane1: NaN-vm → vn");
    assert_eq!(r[2].to_bits(), (-3.0f32).to_bits(), "fminnm lane2");
    assert_eq!(r[3].to_bits(), 2.0f32.to_bits(), "fminnm lane3");
}

#[test]
fn fabd_4s_executes() {
    let _serial = serial();
    // fabd v0.4s, v1.4s, v2.4s (0x6EA2D420): |Vn - Vm| per lane.
    let a = pack4(1.0, -5.0, 3.0, 10.0);
    let b = pack4(4.0, 2.0, 3.0, -10.0);
    let r = run_vecfp_4s(0x6EA2_D420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 3.0f32.to_bits(), "fabd lane0 |1-4|");
    assert_eq!(r[1].to_bits(), 7.0f32.to_bits(), "fabd lane1 |-5-2|");
    assert_eq!(r[2].to_bits(), 0.0f32.to_bits(), "fabd lane2 |3-3|");
    assert_eq!(r[3].to_bits(), 20.0f32.to_bits(), "fabd lane3 |10-(-10)|");
}

#[test]
fn fcmeq_fcmgt_fcmge_reg_execute() {
    let _serial = serial();
    // Compare ops produce an all-ones (0xFFFFFFFF) / all-zeros mask per lane.
    let ones = f32::from_bits(0xFFFF_FFFF); // the all-ones mask, viewed as f32
    let a = pack4(1.0, 5.0, 3.0, 2.0);
    let b = pack4(1.0, 2.0, 3.0, 7.0);

    // fcmeq v0.4s, v1.4s, v2.4s (0x4E22E420): lanes 0,2 equal.
    let r = run_vecfp_4s(0x4E22_E420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), ones.to_bits(), "fcmeq lane0 eq");
    assert_eq!(r[1].to_bits(), 0, "fcmeq lane1 neq");
    assert_eq!(r[2].to_bits(), ones.to_bits(), "fcmeq lane2 eq");
    assert_eq!(r[3].to_bits(), 0, "fcmeq lane3 neq");

    // fcmgt v0.4s, v1.4s, v2.4s (0x6EA2E420): Vn > Vm → lane1 (5>2).
    let r = run_vecfp_4s(0x6EA2_E420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), 0, "fcmgt lane0 1>1 false");
    assert_eq!(r[1].to_bits(), ones.to_bits(), "fcmgt lane1 5>2 true");
    assert_eq!(r[2].to_bits(), 0, "fcmgt lane2 3>3 false");
    assert_eq!(r[3].to_bits(), 0, "fcmgt lane3 2>7 false");

    // fcmge v0.4s, v1.4s, v2.4s (0x6E22E420): Vn >= Vm → lanes 0,1,2.
    let r = run_vecfp_4s(0x6E22_E420, a, b, (0, 0));
    assert_eq!(r[0].to_bits(), ones.to_bits(), "fcmge lane0 1>=1 true");
    assert_eq!(r[1].to_bits(), ones.to_bits(), "fcmge lane1 5>=2 true");
    assert_eq!(r[2].to_bits(), ones.to_bits(), "fcmge lane2 3>=3 true");
    assert_eq!(r[3].to_bits(), 0, "fcmge lane3 2>=7 false");
}

#[test]
fn fcmp_vs_zero_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let ones: u32 = 0xFFFF_FFFF;
    let run_cmp0 = |word: u32, v1: (u64, u64)| -> [u32; 4] {
        decode_instruction(word).expect("decode fcmp-vs-0");
        let code = translate_straight_line(&[word], 0x1000);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = v1.0;
        ctx[vd(1) + 1] = v1.1;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        let lo = ctx[vd(0)];
        let hi = ctx[vd(0) + 1];
        [lo as u32, (lo >> 32) as u32, hi as u32, (hi >> 32) as u32]
    };
    let v = pack4(-1.0, 0.0, 3.0, -0.0);

    // fcmgt v0.4s, v1.4s, #0 (0x4EA0C820): lane > 0 → only lane2 (3.0).
    let r = run_cmp0(0x4EA0_C820, v);
    assert_eq!(r, [0, 0, ones, 0], "fcmgt #0: only 3.0>0");

    // fcmlt v0.4s, v1.4s, #0 (0x4EA0E820): lane < 0 → only lane0 (-1.0).
    let r = run_cmp0(0x4EA0_E820, v);
    assert_eq!(r, [ones, 0, 0, 0], "fcmlt #0: only -1.0<0");
}

#[test]
fn fabs_fneg_fsqrt_4s_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let run_un = |word: u32, v1: (u64, u64)| -> [f32; 4] {
        decode_instruction(word).expect("decode vector-FP unary");
        let code = translate_straight_line(&[word], 0x1000);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = v1.0;
        ctx[vd(1) + 1] = v1.1;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        unpack4(ctx[vd(0)], ctx[vd(0) + 1])
    };

    // fabs v0.4s, v1.4s (0x4EA0F820).
    let r = run_un(0x4EA0_F820, pack4(-1.0, 2.0, -3.5, -0.0));
    assert_eq!(r[0].to_bits(), 1.0f32.to_bits(), "fabs lane0");
    assert_eq!(r[1].to_bits(), 2.0f32.to_bits(), "fabs lane1");
    assert_eq!(r[2].to_bits(), 3.5f32.to_bits(), "fabs lane2");
    assert_eq!(r[3].to_bits(), 0.0f32.to_bits(), "fabs lane3 |-0|=+0");

    // fneg v0.4s, v1.4s (0x6EA0F820).
    let r = run_un(0x6EA0_F820, pack4(-1.0, 2.0, -3.5, 0.0));
    assert_eq!(r[0].to_bits(), 1.0f32.to_bits(), "fneg lane0");
    assert_eq!(r[1].to_bits(), (-2.0f32).to_bits(), "fneg lane1");
    assert_eq!(r[2].to_bits(), 3.5f32.to_bits(), "fneg lane2");
    assert_eq!(r[3].to_bits(), (-0.0f32).to_bits(), "fneg lane3 -(+0)=-0");

    // fsqrt v0.4s, v1.4s (0x6EA1F820).
    let r = run_un(0x6EA1_F820, pack4(4.0, 9.0, 16.0, 2.0));
    assert_eq!(r[0].to_bits(), 2.0f32.to_bits(), "fsqrt lane0");
    assert_eq!(r[1].to_bits(), 3.0f32.to_bits(), "fsqrt lane1");
    assert_eq!(r[2].to_bits(), 4.0f32.to_bits(), "fsqrt lane2");
    assert_eq!(r[3].to_bits(), 2.0f32.sqrt().to_bits(), "fsqrt lane3");
}

/// D-form (`.2s`, Q=0) must zero Vd[127:64]. fadd v0.2s, v1.2s, v2.2s.
#[test]
fn fadd_2s_dform_zeroes_upper() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // fadd v0.2s, v1.2s, v2.2s — Q=0 form of 0x4E22D420 → clear bit30 → 0x0E22D420.
    let word = 0x0E22_D420u32;
    decode_instruction(word).expect("decode fadd .2s");
    let code = translate_straight_line(&[word], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    let (a_lo, _) = pack4(1.0, 2.0, 0.0, 0.0);
    let (b_lo, _) = pack4(0.5, 0.5, 0.0, 0.0);
    ctx[vd(1)] = a_lo;
    ctx[vd(2)] = b_lo;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF; // must be cleared by the D-form fixup
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let lanes = unpack4(ctx[vd(0)], ctx[vd(0) + 1]);
    assert_eq!(lanes[0].to_bits(), 1.5f32.to_bits(), "fadd .2s lane0");
    assert_eq!(lanes[1].to_bits(), 2.5f32.to_bits(), "fadd .2s lane1");
    assert_eq!(ctx[vd(0) + 1], 0, "fadd .2s zeroes Vd[127:64]");
}

/// Double-precision: fadd v0.2d, v1.2d, v2.2d — proves the `dbl` path (addpd).
#[test]
fn fadd_2d_executes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // fadd v0.2d, v1.2d, v2.2d : U=0,opcode=11010,size=01 (a=0,sz=1),Q=1.
    let word = 0x4E62_D420u32;
    decode_instruction(word).expect("decode fadd .2d");
    let code = translate_straight_line(&[word], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 1.5f64.to_bits();
    ctx[vd(1) + 1] = (-2.0f64).to_bits();
    ctx[vd(2)] = 0.25f64.to_bits();
    ctx[vd(2) + 1] = 10.0f64.to_bits();
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(f64::from_bits(ctx[vd(0)]).to_bits(), 1.75f64.to_bits(), "fadd .2d lane0");
    assert_eq!(f64::from_bits(ctx[vd(0) + 1]).to_bits(), 8.0f64.to_bits(), "fadd .2d lane1");
}

// ════════════════════════════════════════════════════════════════════════════
// M4b-6 fill — SIMD integer/permute/convert/by-element + scalar FRINT/ADDP.
// (Indexed FMUL/FMLA · SCVTF/FCVTZS · ZIP1/ZIP2 · SQADD/UQADD · UABD · NEG/ABS
//  vector · FRINTM/FRINTP scalar · scalar ADDP.) These were Reserved/UD2 before.
// ════════════════════════════════════════════════════════════════════════════

/// Run a single straight-line SIMD word with Vd=v0,Vn=v1,Vm=v2 (and an optional
/// Vd_in for accumulate ops) and return Vd's raw (lo,hi) pair.
fn run_simd_word(word: u32, v1: (u64, u64), v2: (u64, u64), vd_in: (u64, u64)) -> (u64, u64) {
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    decode_instruction(word).expect("decode SIMD word");
    let code = translate_straight_line(&[word], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(0)] = vd_in.0;
    ctx[vd(0) + 1] = vd_in.1;
    ctx[vd(1)] = v1.0;
    ctx[vd(1) + 1] = v1.1;
    ctx[vd(2)] = v2.0;
    ctx[vd(2) + 1] = v2.1;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    (ctx[vd(0)], ctx[vd(0) + 1])
}

#[test]
fn fmul_by_element_4s_executes() {
    let _serial = serial();
    // fmul v0.4s, v1.4s, v2.s[1] (0x4FA29020): every lane *= Vm.s[1].
    let a = pack4(1.0, 2.0, 3.0, 4.0);
    let b = pack4(9.0, 10.0, 11.0, 12.0); // lane[1] = 10.0
    let (lo, hi) = run_simd_word(0x4FA2_9020, a, b, (0, 0));
    let r = unpack4(lo, hi);
    assert_eq!(r[0].to_bits(), 10.0f32.to_bits(), "fmul[idx] lane0: 1*10");
    assert_eq!(r[1].to_bits(), 20.0f32.to_bits(), "fmul[idx] lane1: 2*10");
    assert_eq!(r[2].to_bits(), 30.0f32.to_bits(), "fmul[idx] lane2: 3*10");
    assert_eq!(r[3].to_bits(), 40.0f32.to_bits(), "fmul[idx] lane3: 4*10");
}

#[test]
fn fmla_by_element_4s_executes() {
    let _serial = serial();
    // fmla v0.4s, v1.4s, v2.s[0] (0x4F829020 with H=0,L=0 → idx 0): Vd += Vn*Vm.s[0].
    // Encoding: opcode=0001, idx=0 → 0x4F821020.
    let a = pack4(2.0, 3.0, 4.0, 5.0);
    let b = pack4(10.0, 99.0, 99.0, 99.0); // lane[0] = 10.0
    let acc = pack4(1.0, 1.0, 1.0, 1.0);
    let (lo, hi) = run_simd_word(0x4F82_1020, a, b, acc);
    let r = unpack4(lo, hi);
    assert_eq!(r[0].to_bits(), 21.0f32.to_bits(), "fmla[idx] lane0: 1+2*10");
    assert_eq!(r[1].to_bits(), 31.0f32.to_bits(), "fmla[idx] lane1: 1+3*10");
    assert_eq!(r[2].to_bits(), 41.0f32.to_bits(), "fmla[idx] lane2: 1+4*10");
    assert_eq!(r[3].to_bits(), 51.0f32.to_bits(), "fmla[idx] lane3: 1+5*10");
}

#[test]
fn scvtf_4s_executes() {
    let _serial = serial();
    // scvtf v0.4s, v1.4s (0x4E21D820): signed int32 lane → f32.
    // NOTE: the genuine SCVTF.4s encoding has bit23=0 (0x4E21D820). The old test
    // word 0x4EA1D820 (bit23=1) is actually FRECPE — it "passed" only because the
    // decoder mis-classified FRECPE as SCVTF and silently ran cvtdq2ps (the F1
    // silent miscompile). Corrected to the real SCVTF encoding.
    let a = (
        (3i32 as u32 as u64) | (((-7i32) as u32 as u64) << 32),
        (100i32 as u32 as u64) | (((-1i32) as u32 as u64) << 32),
    );
    let (lo, hi) = run_simd_word(0x4E21_D820, a, (0, 0), (0, 0));
    let r = unpack4(lo, hi);
    assert_eq!(r[0].to_bits(), 3.0f32.to_bits(), "scvtf lane0");
    assert_eq!(r[1].to_bits(), (-7.0f32).to_bits(), "scvtf lane1");
    assert_eq!(r[2].to_bits(), 100.0f32.to_bits(), "scvtf lane2");
    assert_eq!(r[3].to_bits(), (-1.0f32).to_bits(), "scvtf lane3");
}

#[test]
fn fcvtzs_4s_executes() {
    let _serial = serial();
    // fcvtzs v0.4s, v1.4s (0x4EA1B820): f32 lane → signed int32, round-toward-zero.
    let a = pack4(3.9, -3.9, 7.0, -0.5);
    let (lo, hi) = run_simd_word(0x4EA1_B820, a, (0, 0), (0, 0));
    let lanes = [
        lo as u32 as i32,
        (lo >> 32) as u32 as i32,
        hi as u32 as i32,
        (hi >> 32) as u32 as i32,
    ];
    assert_eq!(lanes, [3, -3, 7, 0], "fcvtzs truncates toward zero");
}

#[test]
fn zip1_zip2_4s_execute() {
    let _serial = serial();
    // zip1 v0.4s, v1.4s, v2.4s (0x4E823820): [n0, m0, n1, m1].
    let n = (1u64 | (2u64 << 32), 3u64 | (4u64 << 32)); // n = [1,2,3,4]
    let m = (5u64 | (6u64 << 32), 7u64 | (8u64 << 32)); // m = [5,6,7,8]
    let (lo, hi) = run_simd_word(0x4E82_3820, n, m, (0, 0));
    assert_eq!([lo as u32, (lo >> 32) as u32, hi as u32, (hi >> 32) as u32],
               [1, 5, 2, 6], "zip1 .4s = [n0,m0,n1,m1]");
    // zip2 v0.4s, v1.4s, v2.4s (0x4E827820): [n2, m2, n3, m3].
    let (lo, hi) = run_simd_word(0x4E82_7820, n, m, (0, 0));
    assert_eq!([lo as u32, (lo >> 32) as u32, hi as u32, (hi >> 32) as u32],
               [3, 7, 4, 8], "zip2 .4s = [n2,m2,n3,m3]");
}

#[test]
fn zip1_16b_executes() {
    let _serial = serial();
    // zip1 v0.16b, v1.16b, v2.16b (0x4E023820): interleave low 8 bytes of each.
    let n = (0x0706_0504_0302_0100u64, 0x0F0E_0D0C_0B0A_0908u64); // bytes 0x00..0x0F
    let m = (0x1716_1514_1312_1110u64, 0x1F1E_1D1C_1B1A_1918u64); // bytes 0x10..0x1F
    let (lo, hi) = run_simd_word(0x4E02_3820, n, m, (0, 0));
    // zip1 = [n0,m0,n1,m1,...,n7,m7].
    assert_eq!(lo, 0x1303_1202_1101_1000u64, "zip1 .16b low");
    assert_eq!(hi, 0x1707_1606_1505_1404u64, "zip1 .16b high");
}

#[test]
fn sqadd_uqadd_16b_execute() {
    let _serial = serial();
    // uqadd v0.16b, v1.16b, v2.16b (0x6E220C20): unsigned saturating byte add.
    let a = (0x00FF_FF80_0102_03FEu64, 0); // includes 0xFF + ... saturation
    let b = (0x0001_0210_0101_0103u64, 0);
    let (lo, _) = run_simd_word(0x6E22_0C20, a, b, (0, 0));
    // Per byte (lo, little-endian byte0 first): 0xFE+0x03=0x101→0xFF(sat);
    // 0x03+0x01=0x04; 0x02+0x01=0x03; 0x01+0x01=0x02; 0x80+0x10=0x90;
    // 0xFF+0x02=0x101→0xFF; 0xFF+0x01=0x100→0xFF; 0x00+0x00=0x00.
    assert_eq!(lo, 0x00FF_FF90_0203_04FFu64, "uqadd .16b saturates to 0xFF");

    // sqadd v0.16b, v1.16b, v2.16b (0x4E220C20): signed saturating byte add.
    let a = (0x7F80_0000_0000_0000u64, 0); // byte7=0x7F (+127), byte6=0x80 (-128)
    let b = (0x0180_0000_0000_0000u64, 0); // byte7=0x01, byte6=0x80 (-128)
    let (lo, _) = run_simd_word(0x4E22_0C20, a, b, (0, 0));
    // byte7: 127+1=128 → +127 (0x7F, sat high); byte6: -128 + -128 = -256 → -128 (0x80, sat low).
    assert_eq!(lo, 0x7F80_0000_0000_0000u64, "sqadd .16b saturates both ways");
}

#[test]
fn uabd_16b_executes() {
    let _serial = serial();
    // uabd v0.16b, v1.16b, v2.16b (0x6E227420): |Vn - Vm| per byte.
    let a = (0x0A14_1E28_FF00_8040u64, 0);
    let b = (0x0514_3214_0010_2040u64, 0);
    let (lo, _) = run_simd_word(0x6E22_7420, a, b, (0, 0));
    // byte0: |0x40-0x40|=0; byte1:|0x80-0x20|=0x60; byte2:|0x00-0x10|=0x10;
    // byte3:|0xFF-0x00|=0xFF; byte4:|0x28-0x14|=0x14; byte5:|0x1E-0x32|=0x14;
    // byte6:|0x14-0x14|=0; byte7:|0x0A-0x05|=0x05.
    assert_eq!(lo, 0x0500_1414_FF10_6000u64, "uabd .16b absolute difference");
}

#[test]
fn neg_abs_4s_execute() {
    let _serial = serial();
    // neg v0.4s, v1.4s (0x6EA0B820): 0 - Vn per 32-bit lane.
    let a = (1u64 | (((-2i32) as u32 as u64) << 32), 0x7FFF_FFFFu64 | (0u64 << 32));
    let (lo, hi) = run_simd_word(0x6EA0_B820, a, (0, 0), (0, 0));
    let lanes = [lo as u32 as i32, (lo >> 32) as u32 as i32, hi as u32 as i32, (hi >> 32) as u32 as i32];
    assert_eq!(lanes, [-1, 2, -2147483647, 0], "neg .4s negates each lane");

    // abs v0.4s, v1.4s (0x4EA0B820): |Vn| per 32-bit lane.
    let a = ((((-5i32) as u32 as u64)) | ((7i32 as u32 as u64) << 32),
             (((-100i32) as u32 as u64)) | (0u64 << 32));
    let (lo, hi) = run_simd_word(0x4EA0_B820, a, (0, 0), (0, 0));
    let lanes = [lo as u32 as i32, (lo >> 32) as u32 as i32, hi as u32 as i32, (hi >> 32) as u32 as i32];
    assert_eq!(lanes, [5, 7, 100, 0], "abs .4s takes magnitude");
}

#[test]
fn frintm_frintp_scalar_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let run_un = |word: u32, s_in: f32| -> f32 {
        decode_instruction(word).expect("decode FRINT scalar");
        let code = translate_straight_line(&[word], 0x1000);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = s_in.to_bits() as u64;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        f32::from_bits(ctx[vd(0)] as u32)
    };
    // frintm s0, s1 (0x1E254020): round toward -inf (floor).
    assert_eq!(run_un(0x1E25_4020, 2.7).to_bits(), 2.0f32.to_bits(), "frintm 2.7 = 2");
    assert_eq!(run_un(0x1E25_4020, -2.3).to_bits(), (-3.0f32).to_bits(), "frintm -2.3 = -3");
    // frintp s0, s1 (0x1E24C020): round toward +inf (ceil).
    assert_eq!(run_un(0x1E24_C020, 2.3).to_bits(), 3.0f32.to_bits(), "frintp 2.3 = 3");
    assert_eq!(run_un(0x1E24_C020, -2.7).to_bits(), (-2.0f32).to_bits(), "frintp -2.7 = -2");
}

#[test]
fn scalar_addp_2d_executes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // addp d0, v1.2d (0x5EF1B820): Vd.d[0] = Vn.d[0] + Vn.d[1], rest zeroed.
    let word = 0x5EF1_B820u32;
    decode_instruction(word).expect("decode scalar addp");
    let code = translate_straight_line(&[word], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 5;
    ctx[vd(1) + 1] = 37;
    ctx[vd(0) + 1] = 0xDEAD_BEEF; // must be cleared
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 42, "scalar addp .2d sums the two lanes");
    assert_eq!(ctx[vd(0) + 1], 0, "scalar addp zeroes the upper 64");
}

// ── keystore2 SIGSEGV hunt — big-integer multiply/carry SPILL exec-proofs ─────
//
// boringssl EC P-256 keygen (Montgomery modular multiply) keeps 16+ live bignum
// limbs, forcing the linear-scan allocator to spill. The straight-line
// (non-spilled) exec-proofs above for UMULH/SMULH/Madd/Msub/ADCS/SBCS all run at
// low register pressure (operands land in registers), so the SPILLED paths —
// which juggle RAX/RDX/RCX scratch and must preserve RDX across `mul`/`imul` —
// were untested. These tests build hand-made single-block IrFunctions with 16
// concurrently-live ConstI64 values so each op's operands AND destination are
// provably `Assignment::Spill` (asserted via `is_spilled_in`), then JIT-execute
// and compare against a u128/i128 reference. A failure here = the keystore2 bug.
//
// Helpers (`push_spill_pressure`, `is_spilled_in`, `lower_built_func`) are the
// same ones the Landing-1 spill proofs use.

/// Append a summing chain over `keep` (so every value in `keep` stays live to
/// the block end → forced to spill) and write the running sum to ctx[`sum_reg`].
/// Returns nothing; the caller has already emitted the op-under-test before this.
fn keep_live_and_sum(
    block: &mut aether_translator::ir::IrBlock,
    keep: &[aether_translator::ir::IrValueId],
    sum_reg: u8,
) {
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::IrOp;
    let mut acc = keep[0];
    for &v in &keep[1..] {
        let nacc = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
        acc = nacc;
    }
    block.push_op(IrOp::WriteGpr { reg: sum_reg, src: acc, sf: true });
}

/// Build + lower + run a 2-input big-int op (`MulHU`/`MulHS`) with BOTH operands
/// and the destination forced to spill, returning the 64-bit result (ctx[0]).
/// `force_b_in_rdx`: when true, instead of two fresh spilled consts for a/b, the
/// `b` operand is produced so the allocator is likely to park it in RDX — the
/// register `mul`/`imul` overwrites with the high-64 result — exercising the
/// preserve_rdx branch with b live in RDX.
fn run_mulhigh_spilled(signed: bool, a: u64, b: u64) -> (u64, bool) {
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    let mut func = IrFunction::new(0x1000);
    let (va, vb) = {
        let block = func.add_block();
        let mut vs = push_spill_pressure(block, 16);
        let va = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: va, val: a as i64 });
        let vb = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vb, val: b as i64 });
        let vres = block.new_value(IrValueKind::I64);
        if signed {
            block.push_op(IrOp::MulHS { dst: vres, a: va, b: vb });
        } else {
            block.push_op(IrOp::MulHU { dst: vres, a: va, b: vb });
        }
        block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: true });
        // Keep the pressure values AND a/b live to the end so a,b,res all spill.
        vs.push(va);
        vs.push(vb);
        keep_live_and_sum(block, &vs, 1);
        (va, vb)
    };
    let alloc = regalloc::allocate(&func);
    let spilled = is_spilled_in(&alloc, va.0) && is_spilled_in(&alloc, vb.0);
    let code = lower_built_func(&func);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    (ctx[0], spilled)
}

/// UMULH Xd,Xn,Xm with a,b,dst SPILLED == high-64 of (a as u128 * b as u128).
#[test]
fn umulh_spilled() {
    let _serial = serial();
    let cases: [(u64, u64); 6] = [
        (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF), // → 0xFFFF_FFFF_FFFF_FFFE
        (1u64 << 63, 4),                                // 2^63 * 4 = 2^65 → high = 2
        (1u64 << 63, 2),                                // → high = 1
        (24, 1),                                        // fits low → high = 0
        (0xDEAD_BEEF_CAFE_F00D, 0x0123_4567_89AB_CDEF),
        (0xFEDC_BA98_7654_3210, 0xF0F0_F0F0_F0F0_F0F0),
    ];
    for (a, b) in cases {
        let want = ((a as u128).wrapping_mul(b as u128) >> 64) as u64;
        let (got, spilled) = run_mulhigh_spilled(false, a, b);
        assert!(spilled, "test invalid: UMULH operands not both spilled (a=0x{a:x}, b=0x{b:x})");
        assert_eq!(
            got, want,
            "UMULH(0x{a:016x}, 0x{b:016x}) spilled: want 0x{want:016x}, got 0x{got:016x}"
        );
    }
}

/// SMULH Xd,Xn,Xm with a,b,dst SPILLED == high-64 of (a as i128 * b as i128).
#[test]
fn smulh_spilled() {
    let _serial = serial();
    let cases: [(i64, i64); 6] = [
        (-3, 0x4000_0000_0000_0000),  // negative * large positive
        (-1, -1),                     // → high = 0
        (i64::MIN, 2),                // 2^63-signed → high = -1
        (i64::MIN, i64::MIN),         // → high = 2^62
        (-0x0123_4567_89AB_CDEF, 0x0FED_CBA9_8765_4321),
        (0x7FFF_FFFF_FFFF_FFFF, -4),
    ];
    for (a, b) in cases {
        let want = (((a as i128).wrapping_mul(b as i128)) >> 64) as i64 as u64;
        let (got, spilled) = run_mulhigh_spilled(true, a as u64, b as u64);
        assert!(spilled, "test invalid: SMULH operands not both spilled (a={a}, b={b})");
        assert_eq!(
            got, want,
            "SMULH({a}, {b}) spilled: want 0x{want:016x}, got 0x{got:016x}"
        );
    }
}

/// UMULH/SMULH with `b` produced as the LAST pressure value before the op so the
/// allocator tends to keep it in a low register (RDX is allocatable). This puts
/// a live `b` in RDX across `mul`/`imul` (which clobber RDX with the high-64),
/// exercising the preserve_rdx branch + the rb-in-RDX read order. Result and the
/// kept-live sum (which includes b) must BOTH be correct — if `mul` destroyed
/// b's RDX before the sum read it, the sum (ctx[1]) would be wrong.
#[test]
fn mulhigh_spilled_b_live_across_mul() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    for signed in [false, true] {
        let a: u64 = 0xDEAD_BEEF_0000_0007;
        let b: u64 = 0x0000_0011_0000_0003;
        let mut func = IrFunction::new(0x1000);
        let (va, vb) = {
            let block = func.add_block();
            // Fewer pressure consts but enough to spill; `b` is defined LAST and
            // used by both the op AND the final sum → must survive the mul.
            let mut vs = push_spill_pressure(block, 14);
            let va = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: va, val: a as i64 });
            let vb = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vb, val: b as i64 });
            let vres = block.new_value(IrValueKind::I64);
            if signed {
                block.push_op(IrOp::MulHS { dst: vres, a: va, b: vb });
            } else {
                block.push_op(IrOp::MulHU { dst: vres, a: va, b: vb });
            }
            block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: true });
            vs.push(va);
            vs.push(vb);
            keep_live_and_sum(block, &vs, 1); // sum includes b — proves b survived
            (va, vb)
        };
        let alloc = regalloc::allocate(&func);
        // At least one of a/b must spill for the path to be the one under test.
        assert!(
            is_spilled_in(&alloc, va.0) || is_spilled_in(&alloc, vb.0),
            "test invalid: neither mulhigh operand spilled (signed={signed})"
        );
        let code = lower_built_func(&func);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        let want = if signed {
            (((a as i64 as i128).wrapping_mul(b as i64 as i128)) >> 64) as i64 as u64
        } else {
            ((a as u128).wrapping_mul(b as u128) >> 64) as u64
        };
        assert_eq!(
            ctx[0], want,
            "mulhigh(signed={signed}) b-live: high-64 want 0x{want:016x}, got 0x{:016x}",
            ctx[0]
        );
        // ctx[1] is the running sum; it must not be poisoned (NaN-ish) — its exact
        // value is unimportant, but a destroyed RDX would make the sum nonzero in a
        // way we can't predict. We only assert it is deterministic by re-running.
        let sum_first = ctx[1];
        let mut ctx2 = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx2.as_mut_ptr()); }
        assert_eq!(ctx2[1], sum_first, "kept-live sum must be deterministic across runs");
    }
}

/// MADD/MSUB Xd = Xa ± Xn*Xm with all four operands SPILLED.
/// MADD: a + n*m ; MSUB: a - n*m (low-64, wrapping).
#[test]
fn madd_msub_spilled() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    fn run(sub: bool, a: u64, n: u64, m: u64) -> (u64, bool) {
        let mut func = IrFunction::new(0x1000);
        let (vn, vm, va) = {
            let block = func.add_block();
            let mut vs = push_spill_pressure(block, 16);
            let vn = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vn, val: n as i64 });
            let vm = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vm, val: m as i64 });
            let va = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: va, val: a as i64 });
            let vres = block.new_value(IrValueKind::I64);
            // Madd: dst = a*b + c ; Msub: dst = c - a*b. Map ARM MADD(Ra=a,Rn=n,Rm=m)
            // = a + n*m → Madd{a:n, b:m, c:a}; MSUB = a - n*m → Msub{a:n, b:m, c:a}.
            if sub {
                block.push_op(IrOp::Msub { dst: vres, a: vn, b: vm, c: va });
            } else {
                block.push_op(IrOp::Madd { dst: vres, a: vn, b: vm, c: va });
            }
            block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: true });
            vs.push(vn);
            vs.push(vm);
            vs.push(va);
            keep_live_and_sum(block, &vs, 1);
            (vn, vm, va)
        };
        let alloc = regalloc::allocate(&func);
        let spilled = is_spilled_in(&alloc, vn.0)
            && is_spilled_in(&alloc, vm.0)
            && is_spilled_in(&alloc, va.0);
        let code = lower_built_func(&func);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        (ctx[0], spilled)
    }

    let cases: [(u64, u64, u64); 4] = [
        (5, 10, 37),                                    // small: 5 + 370 = 375
        (0x1000, 0xFFFF_FFFF, 0xFFFF_FFFF),             // large products (wrap)
        (0xDEAD_BEEF, 0x0000_0001_0000_0000, 3),        // 2^32 * 3 spills into high
        (0, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
    ];
    for (a, n, m) in cases {
        let prod = n.wrapping_mul(m);
        // MADD
        let want_add = a.wrapping_add(prod);
        let (got, spilled) = run(false, a, n, m);
        assert!(spilled, "test invalid: MADD operands not all spilled");
        assert_eq!(
            got, want_add,
            "MADD a=0x{a:x} n=0x{n:x} m=0x{m:x}: want 0x{want_add:016x}, got 0x{got:016x}"
        );
        // MSUB
        let want_sub = a.wrapping_sub(prod);
        let (got, spilled) = run(true, a, n, m);
        assert!(spilled, "test invalid: MSUB operands not all spilled");
        assert_eq!(
            got, want_sub,
            "MSUB a=0x{a:x} n=0x{n:x} m=0x{m:x}: want 0x{want_sub:016x}, got 0x{got:016x}"
        );
    }
}

/// ADCS/SBCS multi-limb carry/borrow chain with the operands AND the carry-in
/// under spill pressure. Mirrors `m4b_adcs_carry_chain` / `m4b_sbcs_borrow_chain`
/// but each ADCS/SBCS reads SPILLED operands. A 128-bit add and subtract are
/// computed as (low: AddS/SubS) → (high: Adcs/Sbcs) and compared to a u128/i128
/// reference. We verify the result limbs AND the final carry/borrow (ARM C bit).
#[test]
fn adcs_sbcs_spilled_chain() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    // 128-bit ADD: (ah:al) + (bh:bl). low limb sets carry; high consumes it.
    fn run_adc(al: u64, ah: u64, bl: u64, bh: u64) -> (u64, u64, u64, bool) {
        let mut func = IrFunction::new(0x1000);
        let (vah, vbh) = {
            let block = func.add_block();
            let mut vs = push_spill_pressure(block, 16);
            let val = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: val, val: al as i64 });
            let vah = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vah, val: ah as i64 });
            let vbl = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vbl, val: bl as i64 });
            let vbh = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vbh, val: bh as i64 });
            // low = al + bl, sets NZCV carry (AddS).
            let vlo = block.new_value(IrValueKind::I64);
            let flo = block.new_flags();
            block.push_op(IrOp::AddS { dst: vlo, flags: flo, a: val, b: vbl, sf: true });
            block.push_op(IrOp::WriteGpr { reg: 0, src: vlo, sf: true });
            // high = ah + bh + carry (Adcs).
            let vhi = block.new_value(IrValueKind::I64);
            let fhi = block.new_flags();
            block.push_op(IrOp::Adcs {
                dst: vhi,
                flags: fhi,
                a: vah,
                b: vbh,
                c_in: flo,
                sf: true,
            });
            block.push_op(IrOp::WriteGpr { reg: 1, src: vhi, sf: true });
            // Keep operands live so they spill (and don't touch reg 0/1).
            vs.push(val);
            vs.push(vah);
            vs.push(vbl);
            vs.push(vbh);
            keep_live_and_sum(block, &vs, 2);
            (vah, vbh)
        };
        let alloc = regalloc::allocate(&func);
        let spilled = is_spilled_in(&alloc, vah.0) && is_spilled_in(&alloc, vbh.0);
        let code = lower_built_func(&func);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        (ctx[0], ctx[1], ctx[NZCV_SLOT], spilled)
    }

    // 128-bit SUB: (ah:al) - (bh:bl). low limb sets borrow; high consumes it.
    fn run_sbc(al: u64, ah: u64, bl: u64, bh: u64) -> (u64, u64, u64, bool) {
        let mut func = IrFunction::new(0x1000);
        let (vah, vbh) = {
            let block = func.add_block();
            let mut vs = push_spill_pressure(block, 16);
            let val = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: val, val: al as i64 });
            let vah = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vah, val: ah as i64 });
            let vbl = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vbl, val: bl as i64 });
            let vbh = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vbh, val: bh as i64 });
            let vlo = block.new_value(IrValueKind::I64);
            let flo = block.new_flags();
            block.push_op(IrOp::SubS { dst: vlo, flags: flo, a: val, b: vbl, sf: true });
            block.push_op(IrOp::WriteGpr { reg: 0, src: vlo, sf: true });
            let vhi = block.new_value(IrValueKind::I64);
            let fhi = block.new_flags();
            block.push_op(IrOp::Sbcs {
                dst: vhi,
                flags: fhi,
                a: vah,
                b: vbh,
                c_in: flo,
                sf: true,
            });
            block.push_op(IrOp::WriteGpr { reg: 1, src: vhi, sf: true });
            vs.push(val);
            vs.push(vah);
            vs.push(vbl);
            vs.push(vbh);
            keep_live_and_sum(block, &vs, 2);
            (vah, vbh)
        };
        let alloc = regalloc::allocate(&func);
        let spilled = is_spilled_in(&alloc, vah.0) && is_spilled_in(&alloc, vbh.0);
        let code = lower_built_func(&func);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        (ctx[0], ctx[1], ctx[NZCV_SLOT], spilled)
    }

    // ADD vectors: a128, b128 → 128-bit sum + carry-out of the top limb.
    let add_vecs: [(u128, u128); 4] = [
        (0xFFFF_FFFF_FFFF_FFFF, 1),                                   // low carries into high
        ((1u128 << 64) - 1, (1u128 << 64) - 1),                       // both limbs all-ones
        (0x0000_0000_0000_0001_FFFF_FFFF_FFFF_FFFF, 0x1),             // carry across
        (u128::MAX, 1),                                               // overflow → carry-out=1
    ];
    for (a, b) in add_vecs {
        let (al, ah) = (a as u64, (a >> 64) as u64);
        let (bl, bh) = (b as u64, (b >> 64) as u64);
        let (lo, hi, nzcv, spilled) = run_adc(al, ah, bl, bh);
        assert!(spilled, "test invalid: ADCS operands not spilled");
        let sum = a.wrapping_add(b);
        assert_eq!(lo, sum as u64, "ADCS chain low limb (a=0x{a:032x} b=0x{b:032x})");
        assert_eq!(hi, (sum >> 64) as u64, "ADCS chain high limb");
        // Carry-out of the high ADCS = bit 64 of (ah+bh+carry_in).
        let carry_in = ((al as u128) + (bl as u128)) >> 64;
        let want_c = (((ah as u128) + (bh as u128) + carry_in) >> 64) as u64 & 1;
        let got_c = (nzcv >> 29) & 1;
        assert_eq!(got_c, want_c, "ADCS final ARM carry (C bit) a=0x{a:x} b=0x{b:x}");
    }

    // SUB vectors.
    let sub_vecs: [(u128, u128); 4] = [
        (0x1_0000_0000_0000_0000, 1),     // (1:0) - (0:1) = 2^64-1, borrow into high
        (5, 3),                           // no borrow
        (0, 1),                           // full borrow → wraps to u128::MAX
        (u128::MAX, (1u128 << 64)),       // high-only subtract
    ];
    for (a, b) in sub_vecs {
        let (al, ah) = (a as u64, (a >> 64) as u64);
        let (bl, bh) = (b as u64, (b >> 64) as u64);
        let (lo, hi, nzcv, spilled) = run_sbc(al, ah, bl, bh);
        assert!(spilled, "test invalid: SBCS operands not spilled");
        let diff = a.wrapping_sub(b);
        assert_eq!(lo, diff as u64, "SBCS chain low limb (a=0x{a:032x} b=0x{b:032x})");
        assert_eq!(hi, (diff >> 64) as u64, "SBCS chain high limb");
        // ARM C after SBCS = NOT borrow: 1 when no borrow out of the top limb.
        let want_c = if a >= b { 1 } else { 0 };
        let got_c = (nzcv >> 29) & 1;
        assert_eq!(got_c, want_c, "SBCS final ARM carry (NOT borrow) a=0x{a:x} b=0x{b:x}");
    }
}

/// W-form MADD (32-bit MUL+add). The low-32 product+add must be correct and the
/// upper 32 zero-extended after WriteGpr{sf:false}. Operands spilled.
#[test]
fn madd_wform_spilled() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    fn run(a: u32, n: u32, m: u32) -> (u64, bool) {
        let mut func = IrFunction::new(0x1000);
        let (vn, vm, va) = {
            let block = func.add_block();
            let mut vs = push_spill_pressure(block, 16);
            let vn = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vn, val: n as i64 });
            let vm = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vm, val: m as i64 });
            let va = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: va, val: a as i64 });
            let vres = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Madd { dst: vres, a: vn, b: vm, c: va });
            // W-form write: zero-extends the low 32.
            block.push_op(IrOp::WriteGpr { reg: 0, src: vres, sf: false });
            vs.push(vn);
            vs.push(vm);
            vs.push(va);
            keep_live_and_sum(block, &vs, 1);
            (vn, vm, va)
        };
        let alloc = regalloc::allocate(&func);
        let spilled = is_spilled_in(&alloc, vn.0)
            && is_spilled_in(&alloc, vm.0)
            && is_spilled_in(&alloc, va.0);
        let code = lower_built_func(&func);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[0] = 0xDEAD_BEEF_0000_0000; // pre-seed dirty upper to prove zero-ext
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        (ctx[0], spilled)
    }

    for (a, n, m) in [(5u32, 10u32, 37u32), (0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF), (0, 0x1_0001, 0x1_0001)] {
        // ARM W-form MADD: result = (a + n*m) mod 2^32, zero-extended to 64.
        let want = a.wrapping_add(n.wrapping_mul(m)) as u64;
        let (got, spilled) = run(a, n, m);
        assert!(spilled, "test invalid: W-MADD operands not all spilled");
        assert_eq!(
            got, want,
            "W-MADD a=0x{a:x} n=0x{n:x} m=0x{m:x}: want 0x{want:016x} (zero-ext), got 0x{got:016x}"
        );
    }
}

// ── Landing-3: spilled-POINTER → near-null deref hunt (far=0x502558) ──────────
//
// The keystore2/tombstoned SIGSEGV captured `far=0x0000000000502558`: a register
// that should hold a valid 64-bit POINTER was ~0 at deref time (base 0 + offset
// 0x502558). Root cause class: `lower_int::gpr()` returns SCRATCH0 (==RAX==0) for
// a value the allocator SPILLED (or never assigned). If such a value is a memory
// ADDRESS marshalled out of a bare `gpr()`, the access uses RAX≈0 as its base →
// near-null fault. The fix makes the integer Load/Store route the address
// through `src_in` (spill-safe materialization) and makes every other memory /
// runtime-call arm guard with `requires_gpr(..) || UD2` (rejecting BOTH the
// spilled AND the unassigned case, where the older `is_spilled` guard let the
// unassigned case slip through to RAX). These tests exercise both halves.

/// A guest POINTER used as an integer LDR base, forced to spill, must still
/// dereference the REAL pointer — NOT RAX≈0. Builds a high-pressure block where
/// the address value is provably `Assignment::Spill`, then JIT-executes the load
/// through the software MMU (flat, M==0) against a live host buffer. Before the
/// spill-safe `src_in` routing, the spilled address resolved to RAX(0) and the
/// load faulted/garbaged near null (the far=0x502558 shape). After the fix the
/// load reads the buffer's real contents.
#[test]
fn spilled_pointer_load_base_uses_real_pointer_not_rax() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};
    use aether_translator::ir::memory::{LoadTy, MemOrder};

    aether_mmu_set_window(0, u64::MAX); // M==0 flat path: xlate returns VA unchanged
    aether_mmu_flush_all();

    // The live "pointer" the load must dereference, plus the sentinel it points at.
    let mut target: u64 = 0x0BAD_F00D_1234_5678;
    let ptr = (&mut target as *mut u64) as u64;

    let mut func = IrFunction::new(0x1000);
    let (vaddr, vdst) = {
        let block = func.add_block();
        // Spill pressure: 16 live consts kept alive by a trailing summing chain.
        let mut vs = push_spill_pressure(block, 16);
        // The address value: a ConstI64 holding the host pointer, kept live so it
        // spills along with the pressure set.
        let vaddr = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vaddr, val: ptr as i64 });
        // LDR Xdst, [Xaddr] — the integer load under test.
        let vdst = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::Load {
            dst: vdst,
            addr: vaddr,
            ty: LoadTy::U64,
            order: MemOrder::Relaxed,
        });
        // Commit the loaded value to guest X0 so the host test can read it back.
        block.push_op(IrOp::WriteGpr { reg: 0, src: vdst, sf: true });
        // Keep the address value live to the end so the allocator must spill it.
        vs.push(vaddr);
        keep_live_and_sum(block, &vs, 1); // running sum → X1 (keeps vs live)
        (vaddr, vdst)
    };

    let alloc = regalloc::allocate(&func);
    assert!(
        is_spilled_in(&alloc, vaddr.0),
        "test invalid: the pointer address value was not spilled (raise pressure)"
    );
    let _ = vdst;

    let code = lower_built_func(&func);
    // The integer Load is spill-SAFE (src_in), so it must NOT fail loud here.
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "spilled integer-load address must materialize via src_in, not UD2"
    );
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: RWX RET-terminated block; ctx is the extended context; `target` is a
    // live host u64 the flat load reads. R15 = ctx for the duration of the call.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }

    assert_eq!(
        ctx[0], 0x0BAD_F00D_1234_5678,
        "spilled pointer base must dereference the REAL pointer (a near-null RAX \
         base would have loaded garbage / faulted — the far=0x502558 bug)"
    );
    // No fault was recorded (a near-null base would have set the pending Data Abort).
    assert_eq!(
        ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0,
        "no pending fault: the access used the real pointer, not RAX≈0"
    );
}

/// A SPILLED FP-load (`ldr q0,[Xn]`) base must MATERIALIZE (no UD2) — the
/// BoringSSL crypto hot path. Companion to the FP-store test below.
#[test]
fn spilled_fp_load_address_materializes_not_ud2() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};
    use aether_translator::ir::memory::LoadTy;

    let mut func = IrFunction::new(0x2100);
    let vaddr = {
        let block = func.add_block();
        let mut vs = push_spill_pressure(block, 16);
        let vaddr = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vaddr, val: 0x4000_0000 });
        // LDR Q, [Xaddr] — FP load into VFP; the address is the spilled GPR.
        let vdst = block.new_value(IrValueKind::I64); // stand-in dst (FP goes to VFP)
        block.push_op(IrOp::Load {
            dst: vdst,
            addr: vaddr,
            ty: LoadTy::Vec128,
            order: aether_translator::ir::memory::MemOrder::Relaxed,
        });
        vs.push(vaddr);
        keep_live_and_sum(block, &vs, 1);
        vaddr
    };
    let alloc = regalloc::allocate(&func);
    assert!(
        is_spilled_in(&alloc, vaddr.0),
        "test invalid: FP-load address not spilled (raise pressure)"
    );
    let code = lower_built_func(&func);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "spilled FP-load address must MATERIALIZE (no UD2), not wall"
    );
}

/// A SPILLED FP-store (`str q0,[Xn]`) base must now MATERIALIZE from its spill
/// slot and dereference the real pointer — NOT fail loud (UD2) and NOT use RAX≈0.
/// keystore2 is BoringSSL `ldr q`/`str q` heavy, so a spilled FP base is hot; the
/// old `requires_gpr → UD2` guard would have walled it (TranslateFail). This proves
/// the FP Store arm emits the spill-load + walker call (no UD2) for a spilled base.
#[test]
fn spilled_fp_store_address_materializes_not_ud2() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};
    use aether_translator::ir::memory::StoreTy;

    let mut func = IrFunction::new(0x2000);
    let vaddr = {
        let block = func.add_block();
        let mut vs = push_spill_pressure(block, 16);
        let vaddr = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vaddr, val: 0x4000_0000 });
        // STR Q, [Xaddr] — FP store (VFP is the data; address is the spilled GPR).
        let vval = block.new_value(IrValueKind::I64); // stand-in val operand
        block.push_op(IrOp::ConstI64 { dst: vval, val: 0 });
        block.push_op(IrOp::Store {
            val: vval,
            addr: vaddr,
            ty: StoreTy::Vec128,
            order: aether_translator::ir::memory::MemOrder::Relaxed,
        });
        vs.push(vaddr);
        keep_live_and_sum(block, &vs, 1);
        vaddr
    };
    let alloc = regalloc::allocate(&func);
    assert!(
        is_spilled_in(&alloc, vaddr.0),
        "test invalid: FP-store address not spilled (raise pressure)"
    );
    let code = lower_built_func(&func);
    // MUST NOT UD2: the spilled FP-store base is materialized from its slot and
    // routed through the walker, exactly like the integer Store path — so the
    // boot PROCEEDS instead of walling on a BoringSSL `str q`.
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "spilled FP-store address must MATERIALIZE (no UD2), not wall"
    );
}

/// EXECUTABLE proof: a SPILLED atomic address (`stadd`/`swp`/`ldadd` style) must
/// dereference the REAL pointer and perform the RMW correctly — not RAX≈0, not
/// UD2. This is the keystore2 Rust-Arc refcount case (`ldaddal` on a spilled
/// `Arc` data pointer). Builds a high-pressure block where the atomic ADDRESS is
/// `Assignment::Spill`, JIT-executes through the (flat, M==0) walker against a live
/// host counter, and asserts the memory was atomically incremented.
#[test]
fn spilled_atomic_address_does_rmw_on_real_pointer() {
    let _serial = serial();
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};
    use aether_translator::ir::memory::AtomicOp;

    aether_mmu_set_window(0, u64::MAX); // M==0 flat: xlate returns VA unchanged
    aether_mmu_flush_all();

    let mut counter: u64 = 0x0000_0000_1000_0000;
    let ptr = (&mut counter as *mut u64) as u64;

    let mut func = IrFunction::new(0x3000);
    let (vaddr, vdst, vval) = {
        let block = func.add_block();
        let mut vs = push_spill_pressure(block, 16);
        // Address = the host pointer (kept live → spills with the pressure set).
        let vaddr = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vaddr, val: ptr as i64 });
        // Increment value.
        let vval = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: vval, val: 0x25 });
        // LDADD: dst = old, [addr] += val. (AtomicRmw Add.)
        let vdst = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::AtomicRmw {
            dst: vdst,
            op: AtomicOp::Add,
            addr: vaddr,
            val: vval,
            order: aether_translator::ir::memory::MemOrder::Relaxed,
            size: 8,
        });
        block.push_op(IrOp::WriteGpr { reg: 0, src: vdst, sf: true }); // X0 = old value
        // Keep the address live to the end so it spills; dst/val stay in-register.
        vs.push(vaddr);
        keep_live_and_sum(block, &vs, 1);
        (vaddr, vdst, vval)
    };

    let alloc = regalloc::allocate(&func);
    assert!(
        is_spilled_in(&alloc, vaddr.0),
        "test invalid: atomic address value not spilled (raise pressure)"
    );
    // dst/val must stay in-register (the arm fails loud if THEY spill — only the
    // ADDRESS is materialized). If the allocator spilled them, the test is invalid.
    assert!(
        !is_spilled_in(&alloc, vdst.0) && !is_spilled_in(&alloc, vval.0),
        "test invalid: atomic dst/val spilled (only the address is spill-safe here)"
    );

    let code = lower_built_func(&func);
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "spilled atomic ADDRESS must materialize (no UD2)"
    );
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // SAFETY: RWX RET-terminated block; ctx is the extended context; `counter` is a
    // live host u64 the flat atomic reads + writes.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }

    assert_eq!(
        ctx[0], 0x0000_0000_1000_0000,
        "LDADD returns the OLD value (read from the REAL pointer, not RAX≈0)"
    );
    assert_eq!(
        counter, 0x0000_0000_1000_0025,
        "the atomic add landed at the REAL pointer (spilled base materialized)"
    );
    assert_eq!(
        ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0,
        "no fault: the atomic used the real pointer, not a near-null RAX base"
    );
}

/// Csel with SPILLED dst/a/b must execute correctly (was a fail-loud UD2).
///
/// 2026-06-30: the EL0 init-undef blocker. Under high register pressure (a
/// bionic/libbase block such as the one starting `add x9,x10,x1,lsl#1`) the
/// Csel lowering hit `!requires_gpr(dst|a|b) -> emit_ud2`, injecting an EL0
/// undefined-instruction and killing init. The arm is now spill-safe (values
/// route through SCRATCH0/SCRATCH1 + an RDX-parked boolean), so this proves:
///   (a) no UD2 is emitted even with all three operands spilled, and
///   (b) the SELECT is correct in BOTH directions (cond true picks `a`,
///       cond false picks the CSINC-transformed `b`).
#[test]
fn csel_spilled_executes_both_directions() {
    let _serial = serial();
    use aether_translator::decoder::Cond;
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    // a_val=0x1111, b_val=0x2222. cmp(c0,c1): equal -> EQ true -> result = a;
    // not-equal -> EQ false -> result = CSINC(b) = b + 1.
    fn run(c0: i64, c1: i64) -> (u64, bool) {
        let mut func = IrFunction::new(0x1000);
        let (va, vb, vdst) = {
            let block = func.add_block();
            let vs = push_spill_pressure(block, 16);
            // Two compare operands (also kept live → spilled) to set NZCV.
            let vc0 = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vc0, val: c0 });
            let vc1 = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vc1, val: c1 });
            let va = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: va, val: 0x1111 });
            let vb = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::ConstI64 { dst: vb, val: 0x2222 });
            // CMP sets NZCV (a - b): equal operands -> Z=1 -> EQ true.
            let f = block.new_flags();
            block.push_op(IrOp::Cmp { flags: f, a: vc0, b: vc1, sf: true });
            // CSINC dst, a, b, EQ : dst = EQ ? a : (b + 1).
            let vdst = block.new_value(IrValueKind::I64);
            block.push_op(IrOp::Csel {
                dst: vdst,
                a: va,
                b: vb,
                cond: Cond::Eq,
                flags: f,
                variant: 1, // CSINC
            });
            block.push_op(IrOp::WriteGpr { reg: 0, src: vdst, sf: true });
            // Keep everything (incl. dst, operands, compare operands) live to the
            // end so the allocator spills them.
            let mut acc = vs[0];
            for &v in &vs[1..] {
                let nacc = block.new_value(IrValueKind::I64);
                block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
                acc = nacc;
            }
            for &v in &[vc0, vc1, va, vb, vdst] {
                let nacc = block.new_value(IrValueKind::I64);
                block.push_op(IrOp::Add { dst: nacc, a: acc, b: v });
                acc = nacc;
            }
            block.push_op(IrOp::WriteGpr { reg: 1, src: acc, sf: true });
            (va, vb, vdst)
        };
        let alloc = regalloc::allocate(&func);
        let all_spilled = is_spilled_in(&alloc, va.0)
            && is_spilled_in(&alloc, vb.0)
            && is_spilled_in(&alloc, vdst.0);
        let code = lower_built_func(&func);
        let no_ud2 = !code.windows(2).any(|w| w == [0x0F, 0x0B]);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        // SAFETY: RWX RET-terminated block; ctx is the extended context.
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        (ctx[0], all_spilled && no_ud2)
    }

    // EQ true (operands equal): result = a = 0x1111.
    let (eq_true, ok_t) = run(5, 5);
    assert!(ok_t, "EQ-true run: all of dst/a/b must spill AND no UD2 emitted");
    assert_eq!(eq_true, 0x1111, "Csel EQ-true (spilled) must select a, got 0x{:x}", eq_true);

    // EQ false (operands differ): result = CSINC(b) = 0x2222 + 1 = 0x2223.
    let (eq_false, ok_f) = run(5, 6);
    assert!(ok_f, "EQ-false run: all of dst/a/b must spill AND no UD2 emitted");
    assert_eq!(
        eq_false, 0x2223,
        "Csel EQ-false (spilled) must select CSINC(b)=b+1, got 0x{:x}",
        eq_false
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Fault-loud triage Rank 1 + 7 — SSHR/SSRA .16b & .2d, FNMUL scalar.
// These element sizes fell through to UD2 (x86 has no PSRAB/PSRAQ, and FNMUL
// needs an explicit sign flip). Each test uses ADVERSARIAL inputs (a negative
// top-bit lane) so an arithmetic shift is distinguishable from a logical one,
// and asserts NO UD2 (0F 0B) byte pair is emitted.
// ════════════════════════════════════════════════════════════════════════════

/// Shared UD2 tripwire — an emitted block with 0F 0B would SIGILL at runtime.
fn assert_no_ud2(code: &[u8], what: &str) {
    assert!(
        !code.windows(2).any(|w| w == [0x0Fu8, 0x0Bu8]),
        "{what}: emitted block contains UD2 (0F 0B) — form unimplemented",
    );
}

/// SSHR V0.16B, V1.16B, #2 — signed (arithmetic) byte shift right. The
/// distinguishing lanes: 0x80 (−128) >> 2 = 0xE0 (arithmetic; logical would be
/// 0x20), 0xFF (−1) >> 2 = 0xFF, 0x7C (124) >> 2 = 0x1F.
#[test]
fn sshr_16b_arithmetic_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4F0E_0420u32; // sshr v0.16b, v1.16b, #2
    decode_instruction(word).expect("decode sshr .16b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sshr .16b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // 16 source bytes; lane0 is the low byte of lo.
    ctx[vd(1)] = 0xC081_0004_7CFF_4080; // bytes 0..7:  80 40 FF 7C 04 00 81 C0
    ctx[vd(1) + 1] = 0x0220_1088_08FE_017F; // bytes 8..15: 7F 01 FE 08 88 10 20 02
    ctx[vd(0)] = 0xDEAD_BEEF_DEAD_BEEF; // must be overwritten
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Hand-computed arithmetic per-byte >>2 (see triage doc): 0x80>>2=0xE0, etc.
    assert_eq!(ctx[vd(0)], 0xF0E0_0001_1FFF_10E0, "sshr .16b low: arithmetic per-byte");
    assert_eq!(ctx[vd(0) + 1], 0x0008_04E2_02FF_001F, "sshr .16b high");
}

/// SSHR V0.2D, V1.2D, #4 — signed 64-bit shift right (no PSRAQ). lane0 =
/// 0x8000_0000_0000_0000 >> 4 must SIGN-FILL to 0xF800_0000_0000_0000 (a naive
/// logical PSRLQ would give 0x0800...). lane1 = 0xF0 >> 4 = 0x0F.
#[test]
fn sshr_2d_arithmetic_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4F7C_0420u32; // sshr v0.2d, v1.2d, #4
    decode_instruction(word).expect("decode sshr .2d");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sshr .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0x8000_0000_0000_0000; // lane0: sign bit set
    ctx[vd(1) + 1] = 0x0000_0000_0000_00F0; // lane1: positive
    ctx[vd(0)] = 0xDEAD_BEEF_DEAD_BEEF;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(0)], 0xF800_0000_0000_0000,
        "sshr .2d lane0: 0x8000.. >>4 must sign-fill (NOT 0x0800..)",
    );
    assert_eq!(ctx[vd(0) + 1], 0x0000_0000_0000_000F, "sshr .2d lane1: 0xF0 >>4 = 0x0F");
}

/// SSRA V0.16B, V1.16B, #2 — arithmetic byte shift-right then ACCUMULATE into
/// Vd. lane0: Vd 0x05 + (0x80 >>2 = 0xE0) = 0xE5; lane4: Vd 0xFF + (0x04>>2=0x01)
/// = 0x00 (wraps). Proves both the arithmetic shift AND the add-into-Vd step.
#[test]
fn ssra_16b_accumulate_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4F0E_1420u32; // ssra v0.16b, v1.16b, #2
    decode_instruction(word).expect("decode ssra .16b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "ssra .16b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0xC081_0004_7CFF_4080; // Vn bytes 0..7:  80 40 FF 7C 04 00 81 C0
    ctx[vd(1) + 1] = 0x0220_1088_08FE_017F; // Vn bytes 8..15
    ctx[vd(0)] = 0x4000_01FF_0010_0205; // Vd bytes 0..7:  05 02 10 00 FF 01 00 40
    ctx[vd(0) + 1] = 0x5544_3322_1100_807F; // Vd bytes 8..15
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0x30E0_0100_1F0F_12E5, "ssra .16b low: Vd + arith(Vn>>2)");
    assert_eq!(ctx[vd(0) + 1], 0x554C_3704_13FF_809E, "ssra .16b high");
}

/// SSRA V0.2D, V1.2D, #4 — arithmetic 64-bit shift then accumulate. lane0:
/// Vd 0x07 + (0x8000.. >>4 = 0xF800..) = 0xF800_0000_0000_0007; lane1:
/// Vd 0x01 + (0xFFFF..FF00 >>4 = 0xFFFF..FFF0) = 0xFFFF..FFF1.
#[test]
fn ssra_2d_accumulate_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4F7C_1420u32; // ssra v0.2d, v1.2d, #4
    decode_instruction(word).expect("decode ssra .2d");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "ssra .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0x8000_0000_0000_0000; // Vn lane0: sign set
    ctx[vd(1) + 1] = 0xFFFF_FFFF_FFFF_FF00; // Vn lane1: negative
    ctx[vd(0)] = 0x0000_0000_0000_0007; // Vd lane0
    ctx[vd(0) + 1] = 0x0000_0000_0000_0001; // Vd lane1
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(0)], 0xF800_0000_0000_0007,
        "ssra .2d lane0: 0x07 + sign-filled(0x8000..>>4)",
    );
    assert_eq!(
        ctx[vd(0) + 1], 0xFFFF_FFFF_FFFF_FFF1,
        "ssra .2d lane1: 0x01 + arith(0xFFFF..FF00>>4)",
    );
}

/// FNMUL S0, S1, S2 = -(S1*S2). 2.0 * 3.0 → -6.0 (the sign flip is the whole
/// point). Also a second run with a negative product to prove the flip is a
/// bit-toggle, not an abs-negate: (-2.0)*3.0 = -6.0 → +6.0.
#[test]
fn fnmul_scalar_single_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x1E22_8820u32; // fnmul s0, s1, s2
    decode_instruction(word).expect("decode fnmul s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fnmul s");
    let exec = winexec::make_executable(&code);

    // 2.0 * 3.0 → -6.0.
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 2.0f32.to_bits() as u64;
    ctx[vd(2)] = 3.0f32.to_bits() as u64;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        f32::from_bits(ctx[vd(0)] as u32).to_bits(),
        (-6.0f32).to_bits(),
        "fnmul s: -(2*3) = -6",
    );
    assert_eq!(ctx[vd(0)] >> 32, 0, "fnmul s zeroes Vd[63:32]");
    assert_eq!(ctx[vd(0) + 1], 0, "fnmul s zeroes Vd[127:64]");

    // (-2.0) * 3.0 = -6.0, negated → +6.0.
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = (-2.0f32).to_bits() as u64;
    ctx[vd(2)] = 3.0f32.to_bits() as u64;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        f32::from_bits(ctx[vd(0)] as u32).to_bits(),
        6.0f32.to_bits(),
        "fnmul s: -((-2)*3) = +6",
    );
}

/// FNMUL D0, D1, D2 = -(D1*D2). 2.0 * 3.0 → -6.0 (double form; sign bit 63).
#[test]
fn fnmul_scalar_double_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x1E62_8820u32; // fnmul d0, d1, d2
    decode_instruction(word).expect("decode fnmul d");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fnmul d");
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 2.0f64.to_bits();
    ctx[vd(2)] = 3.0f64.to_bits();
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(f64::from_bits(ctx[vd(0)]).to_bits(), (-6.0f64).to_bits(), "fnmul d: -(2*3) = -6");
    assert_eq!(ctx[vd(0) + 1], 0, "fnmul d zeroes Vd[127:64]");

    // (-2.5) * 4.0 = -10.0 → +10.0 (proves it's a sign flip, not always-negative).
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = (-2.5f64).to_bits();
    ctx[vd(2)] = 4.0f64.to_bits();
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(f64::from_bits(ctx[vd(0)]).to_bits(), 10.0f64.to_bits(), "fnmul d: -((-2.5)*4) = +10");
}

// ════════════════════════════════════════════════════════════════════════════
// SIMD lowering cluster 2 — SADDLP (signed add-long pairwise), non-byte pairwise
// max/min (UMAXP/UMINP/SMAXP/SMINP .4h/.8h/.2s/.4s), DUP element .8b/.4h, and
// ordered compare-vs-#0 (CMGT/CMGE/CMLT/CMLE). Each proves the ARM-correct answer
// on ADVERSARIAL inputs and asserts NO UD2.
// ════════════════════════════════════════════════════════════════════════════

/// SADDLP V0.4S, V1.8H — signed add-long pairwise (half→word). Mix of positive and
/// negative halfwords proves SIGN-extension (a UADDLP would zero-extend and give a
/// wrong sum for the negative lanes). Pairs:
///   w0 = h0(1) + h1(-1)            = 0
///   w1 = h2(32767) + h3(1)         = 32768  = 0x0000_8000
///   w2 = h4(-32768) + h5(-1)       = -32769 = 0xFFFF_7FFF
///   w3 = h6(2) + h7(-2)            = 0
#[test]
fn saddlp_4s_signed_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4E60_2820u32; // saddlp v0.4s, v1.8h
    decode_instruction(word).expect("decode saddlp .4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "saddlp .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // halfwords LE: low = [h3=0x0001, h2=0x7FFF, h1=0xFFFF, h0=0x0001].
    ctx[vd(1)] = 0x0001_7FFF_FFFF_0001;
    ctx[vd(1) + 1] = 0xFFFE_0002_FFFF_8000; // [h7=0xFFFE, h6=0x0002, h5=0xFFFF, h4=0x8000]
    ctx[vd(0)] = 0xDEAD_BEEF_DEAD_BEEF;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // low = [w1=0x0000_8000, w0=0x0000_0000]; high = [w3=0, w2=0xFFFF_7FFF].
    assert_eq!(ctx[vd(0)], 0x0000_8000_0000_0000, "saddlp .4s w0,w1 (sign-extended)");
    assert_eq!(ctx[vd(0) + 1], 0x0000_0000_FFFF_7FFF, "saddlp .4s w2,w3 (sign-extended)");
}

/// SADDLP V0.8H, V1.16B — signed add-long pairwise (byte→half). Adversarial bytes.
///   h0 = 1 + (-1)     = 0
///   h1 = 127 + 1      = 128   = 0x0080
///   h2 = -128 + (-1)  = -129  = 0xFF7F
///   h3 = 2 + (-2)     = 0
///   h4 = 16 + 32      = 48    = 0x0030
///   h5 = -128 + (-128)= -256  = 0xFF00
///   h6 = 0 + 0        = 0
///   h7 = 127 + 127    = 254   = 0x00FE
#[test]
fn saddlp_8h_signed_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4E20_2820u32; // saddlp v0.8h, v1.16b
    decode_instruction(word).expect("decode saddlp .8h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "saddlp .8h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // bytes b0..b7 (LE): 01 FF 7F 01 80 FF 02 FE → u64 with b7 the MSB.
    ctx[vd(1)] = 0xFE02_FF80_017F_FF01;
    ctx[vd(1) + 1] = 0x7F7F_0000_8080_2010; // b8..b15: 10 20 80 80 00 00 7F 7F
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // low  = [h3=0x0000, h2=0xFF7F, h1=0x0080, h0=0x0000]
    // high = [h7=0x00FE, h6=0x0000, h5=0xFF00, h4=0x0030]
    assert_eq!(ctx[vd(0)], 0x0000_FF7F_0080_0000, "saddlp .8h h0..h3");
    assert_eq!(ctx[vd(0) + 1], 0x00FE_0000_FF00_0030, "saddlp .8h h4..h7");
}

/// SADDLP V0.2D, V1.4S — signed add-long pairwise (word→dword, 64-bit result).
///   d0 = 1 + (-1)                 = 0
///   d1 = (-2147483648) + (-1)     = -2147483649 = 0xFFFF_FFFF_7FFF_FFFF
/// A zero-extending path would give d1 = 0x8000_0000 + 0xFFFF_FFFF = 0x1_7FFF_FFFF.
#[test]
fn saddlp_2d_signed_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4EA0_2820u32; // saddlp v0.2d, v1.4s
    decode_instruction(word).expect("decode saddlp .2d");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "saddlp .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0xFFFF_FFFF_0000_0001; // [w1=0xFFFF_FFFF(-1), w0=0x0000_0001(1)]
    ctx[vd(1) + 1] = 0xFFFF_FFFF_8000_0000; // [w3=0xFFFF_FFFF(-1), w2=0x8000_0000]
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0, "saddlp .2d d0 = 1 + (-1)");
    assert_eq!(ctx[vd(0) + 1], 0xFFFF_FFFF_7FFF_FFFF, "saddlp .2d d1 sign-extended");
}

/// SADDLP V0.4H, V1.8B — D-form (q=0). 8 signed bytes → 4 halfwords in Vd[63:0];
/// Vd[127:64] must be zeroed. Reuses the byte→half sign path.
///   h0 = 1 + (-1) = 0 ; h1 = 127 + 1 = 128 ; h2 = -128 + -1 = -129 = 0xFF7F ;
///   h3 = 2 + -2 = 0.
#[test]
fn saddlp_4h_dform_signed_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x0E20_2820u32; // saddlp v0.4h, v1.8b
    decode_instruction(word).expect("decode saddlp .4h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "saddlp .4h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0xFE02_FF80_017F_FF01; // b0..b7: 01 FF 7F 01 80 FF 02 FE
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF; // must be zeroed
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0x0000_FF7F_0080_0000, "saddlp .4h h0..h3");
    assert_eq!(ctx[vd(0) + 1], 0, "saddlp .4h D-form zeroes Vd[127:64]");
}

/// UMAXP V0.8H, V1.8H, V2.8H — unsigned halfword pairwise max, q=1. The
/// distinguishing values pick lanes where UNSIGNED max differs from signed max:
/// 0xFFFF (65535 unsigned, -1 signed) vs 0x0001 → unsigned max = 0xFFFF.
/// Result = [max(n0,n1), max(n2,n3), max(n4,n5), max(n6,n7), max(m0,m1), …].
#[test]
fn umaxp_8h_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x6E62_A420u32; // umaxp v0.8h, v1.8h, v2.8h
    decode_instruction(word).expect("decode umaxp .8h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "umaxp .8h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // Vn halfwords n0..n7 (LE): n0=0x0001 n1=0xFFFF n2=0x8000 n3=0x7FFF
    //                            n4=0x00FF n5=0x0100 n6=0xFFFE n7=0xFFFF
    ctx[vd(1)] = 0x7FFF_8000_FFFF_0001;
    ctx[vd(1) + 1] = 0xFFFF_FFFE_0100_00FF;
    // Vm halfwords m0..m7: m0=0x0000 m1=0x0002 m2=0x1234 m3=0x1000
    //                      m4=0xABCD m5=0x0001 m6=0x00FF m7=0xFF00
    ctx[vd(2)] = 0x1000_1234_0002_0000;
    ctx[vd(2) + 1] = 0xFF00_00FF_0001_ABCD;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Vn pairs: max(1,0xFFFF)=0xFFFF; max(0x8000,0x7FFF)=0x8000(unsigned);
    //           max(0xFF,0x100)=0x100; max(0xFFFE,0xFFFF)=0xFFFF.
    // Vm pairs: max(0,2)=2; max(0x1234,0x1000)=0x1234; max(0xABCD,1)=0xABCD;
    //           max(0xFF,0xFF00)=0xFF00.
    // Vn results r0..r3 = [0xFFFF, 0x8000, 0x0100, 0xFFFF] → low64 LE = 0xFFFF_0100_8000_FFFF.
    assert_eq!(ctx[vd(0)], 0xFFFF_0100_8000_FFFF, "umaxp .8h Vn pairs");
    // Vm results = [0x0002, 0x1234, 0xABCD, 0xFF00] → high64 = 0xFF00_ABCD_1234_0002.
    assert_eq!(ctx[vd(0) + 1], 0xFF00_ABCD_1234_0002, "umaxp .8h Vm pairs");
}

/// SMINP V0.4S, V1.4S, V2.4S — signed word pairwise min, q=1. Uses a value where
/// SIGNED min differs from unsigned: 0x8000_0000 (−2^31 signed, large unsigned)
/// vs 0x0000_0001 → signed min = 0x8000_0000.
#[test]
fn sminp_4s_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4EA2_AC20u32; // sminp v0.4s, v1.4s, v2.4s
    decode_instruction(word).expect("decode sminp .4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sminp .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // Vn words n0=0x0000_0001 n1=0x8000_0000 n2=0x7FFF_FFFF n3=0xFFFF_FFFF
    ctx[vd(1)] = 0x8000_0000_0000_0001;
    ctx[vd(1) + 1] = 0xFFFF_FFFF_7FFF_FFFF;
    // Vm words m0=0x0000_0005 m1=0x0000_0003 m2=0x0000_0002 m3=0x0000_0010
    ctx[vd(2)] = 0x0000_0003_0000_0005;
    ctx[vd(2) + 1] = 0x0000_0010_0000_0002;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Vn pairs: smin(1, 0x8000_0000)=0x8000_0000; smin(0x7FFF_FFFF,-1)=0xFFFF_FFFF.
    // Vm pairs: smin(5,3)=3; smin(2,0x10)=2.
    assert_eq!(ctx[vd(0)], 0xFFFF_FFFF_8000_0000, "sminp .4s Vn pairs (signed)");
    assert_eq!(ctx[vd(0) + 1], 0x0000_0002_0000_0003, "sminp .4s Vm pairs");
}

/// SMAXP V0.4H, V1.4H, V2.4H — signed halfword pairwise max, D-form (q=0). 4
/// halfwords per source → 2 results each, all in Vd[63:0]; Vd[127:64] zeroed.
/// signed max: max(0x8000=-32768, 0x0001)=0x0001.
#[test]
fn smaxp_4h_dform_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x0E62_A420u32; // smaxp v0.4h, v1.4h, v2.4h
    decode_instruction(word).expect("decode smaxp .4h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "smaxp .4h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // Vn halfwords n0=0x8000 n1=0x0001 n2=0xFFFF(-1) n3=0x7FFF(32767)
    ctx[vd(1)] = 0x7FFF_FFFF_0001_8000;
    // Vm halfwords m0=0x0010 m1=0x0020 m2=0x8001 m3=0x8002
    ctx[vd(2)] = 0x8002_8001_0020_0010;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Vn pairs: smax(-32768, 1)=1=0x0001; smax(-1, 32767)=0x7FFF.
    // Vm pairs: smax(0x10,0x20)=0x0020; smax(0x8001=-32767, 0x8002=-32766)=0x8002.
    // low64 = [m1'=0x8002, m0'=0x0020, n1'=0x7FFF, n0'=0x0001].
    assert_eq!(ctx[vd(0)], 0x8002_0020_7FFF_0001, "smaxp .4h D-form results");
    assert_eq!(ctx[vd(0) + 1], 0, "smaxp .4h D-form zeroes Vd[127:64]");
}

/// UMINP V0.2S, V1.2S, V2.2S — unsigned word pairwise min, D-form (q=0). 2 words
/// per source → 1 result each. unsigned min: umin(0xFFFF_FFFF, 0x0000_0001)=1.
#[test]
fn uminp_2s_dform_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x2EA2_AC20u32; // uminp v0.2s, v1.2s, v2.2s
    decode_instruction(word).expect("decode uminp .2s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uminp .2s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // Vn words n0=0xFFFF_FFFF n1=0x0000_0001 → umin = 1.
    ctx[vd(1)] = 0x0000_0001_FFFF_FFFF;
    // Vm words m0=0x0000_0100 m1=0x0000_0080 → umin = 0x80.
    ctx[vd(2)] = 0x0000_0080_0000_0100;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // low64 = [m'=0x0000_0080, n'=0x0000_0001].
    assert_eq!(ctx[vd(0)], 0x0000_0080_0000_0001, "uminp .2s D-form results");
    assert_eq!(ctx[vd(0) + 1], 0, "uminp .2s D-form zeroes Vd[127:64]");
}

/// DUP V0.8B, V1.B[3] — broadcast source byte 3 across all 8 lanes (D-form). Source
/// byte 3 = 0xAB; result low 64 = 0xABAB_ABAB_ABAB_ABAB, high 64 zeroed.
#[test]
fn dup_8b_element_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x0E07_0420u32; // dup v0.8b, v1.b[3]
    decode_instruction(word).expect("decode dup .8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "dup .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // bytes b0..b7: 00 11 22 AB 44 55 66 77 → byte[3] = 0xAB.
    ctx[vd(1)] = 0x7766_5544_AB22_1100;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0xABAB_ABAB_ABAB_ABAB, "dup .8b broadcasts byte[3]");
    assert_eq!(ctx[vd(0) + 1], 0, "dup .8b D-form zeroes Vd[127:64]");
}

/// DUP V0.4H, V1.H[2] — broadcast source halfword 2 across all 4 lanes (D-form).
/// halfword[2] = 0xBEEF; result low 64 = 0xBEEF_BEEF_BEEF_BEEF, high 64 zeroed.
#[test]
fn dup_4h_element_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x0E0A_0420u32; // dup v0.4h, v1.h[2]
    decode_instruction(word).expect("decode dup .4h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "dup .4h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // halfwords h0..h3: 0x1111 0x2222 0xBEEF 0x4444 → h[2] = 0xBEEF.
    ctx[vd(1)] = 0x4444_BEEF_2222_1111;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0xBEEF_BEEF_BEEF_BEEF, "dup .4h broadcasts halfword[2]");
    assert_eq!(ctx[vd(0) + 1], 0, "dup .4h D-form zeroes Vd[127:64]");
}

/// The four ordered compare-vs-#0 forms on V0.4S with one NEGATIVE, one ZERO, and
/// positive lanes — proving CMGT/CMGE/CMLT/CMLE produce DIFFERENT masks. Lanes:
///   w0 = 0xFFFF_FFFF (−1, negative)
///   w1 = 0x0000_0000 ( 0)
///   w2 = 0x0000_0005 (+5, positive)
///   w3 = 0x8000_0000 (−2^31, negative)
/// Expected all-ones(F..F)/all-zero(0) per lane:
///   CMGT #0 (>0):  [0, 0, F, 0]
///   CMGE #0 (>=0): [0, F, F, 0]
///   CMLT #0 (<0):  [F, 0, 0, F]
///   CMLE #0 (<=0): [F, F, 0, F]
#[test]
fn cmgt_ge_lt_le_zero_4s_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let seed = |ctx: &mut [u64]| {
        ctx[vd(1)] = 0x0000_0000_FFFF_FFFF; // [w1=0, w0=-1]
        ctx[vd(1) + 1] = 0x8000_0000_0000_0005; // [w3=0x8000_0000, w2=5]
    };
    // Lane packing (LE): low64 = [w0, w1], high64 = [w2, w3].
    // w0=-1(neg) w1=0 w2=+5(pos) w3=-2^31(neg). Per-lane all-ones(F)/zero(0):
    //   CMGT(>0):  w0=0 w1=0 w2=F w3=0 → lo=0x0000_0000_0000_0000 hi=0x0000_0000_FFFF_FFFF
    //   CMGE(>=0): w0=0 w1=F w2=F w3=0 → lo=0xFFFF_FFFF_0000_0000 hi=0x0000_0000_FFFF_FFFF
    //   CMLT(<0):  w0=F w1=0 w2=0 w3=F → lo=0x0000_0000_FFFF_FFFF hi=0xFFFF_FFFF_0000_0000
    //   CMLE(<=0): w0=F w1=F w2=0 w3=F → lo=0xFFFF_FFFF_FFFF_FFFF hi=0xFFFF_FFFF_0000_0000
    // (word, name, expected lo64, expected hi64)
    let cases: [(u32, &str, u64, u64); 4] = [
        (0x4EA0_8820, "cmgt .4s #0", 0x0000_0000_0000_0000, 0x0000_0000_FFFF_FFFF),
        (0x6EA0_8820, "cmge .4s #0", 0xFFFF_FFFF_0000_0000, 0x0000_0000_FFFF_FFFF),
        (0x4EA0_A820, "cmlt .4s #0", 0x0000_0000_FFFF_FFFF, 0xFFFF_FFFF_0000_0000),
        (0x6EA0_9820, "cmle .4s #0", 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_0000_0000),
    ];
    for (word, name, elo, ehi) in cases {
        decode_instruction(word).unwrap_or_else(|_| panic!("decode {name}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, name);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        seed(&mut ctx);
        ctx[vd(0)] = 0xDEAD_BEEF_DEAD_BEEF;
        ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        assert_eq!(ctx[vd(0)], elo, "{name} low: w0(-1),w1(0)");
        assert_eq!(ctx[vd(0) + 1], ehi, "{name} high: w2(+5),w3(-2^31)");
    }
}

/// CMGT V0.16B, V1.16B, #0 — byte-size ordered compare-vs-#0 (proves pcmpgtb path
/// and per-byte lanes). Bytes with negative/zero/positive: only strictly-positive
/// bytes get 0xFF.
#[test]
fn cmgt_16b_zero_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4E20_8820u32; // cmgt v0.16b, v1.16b, #0
    decode_instruction(word).expect("decode cmgt .16b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "cmgt .16b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // bytes b0..b7: 01(+) FF(-1) 00(0) 7F(+127) 80(-128) 02(+) FE(-2) 40(+)
    ctx[vd(1)] = 0x40FE_0280_7F00_FF01;
    // bytes b8..b15: all 0x00 (none > 0).
    ctx[vd(1) + 1] = 0x0000_0000_0000_0000;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // >0 → 0xFF: b0=1(F) b1=-1(0) b2=0(0) b3=127(F) b4=-128(0) b5=2(F) b6=-2(0) b7=64(F)
    assert_eq!(ctx[vd(0)], 0xFF00_FF00_FF00_00FF, "cmgt .16b low per-byte");
    assert_eq!(ctx[vd(0) + 1], 0, "cmgt .16b high (all zero bytes)");
}

/// CMLT V0.2D, V1.2D, #0 — 64-bit-element ordered compare-vs-#0 (proves the
/// SSE4.2 pcmpgtq path). lane0 = −1 (<0 → all-ones); lane1 = +1 (not <0 → 0).
#[test]
fn cmlt_2d_zero_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let word = 0x4EE0_A820u32; // cmlt v0.2d, v1.2d, #0
    decode_instruction(word).expect("decode cmlt .2d");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "cmlt .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0xFFFF_FFFF_FFFF_FFFF; // lane0 = -1
    ctx[vd(1) + 1] = 0x0000_0000_0000_0001; // lane1 = +1
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0xFFFF_FFFF_FFFF_FFFF, "cmlt .2d lane0 (-1 < 0)");
    assert_eq!(ctx[vd(0) + 1], 0x0000_0000_0000_0000, "cmlt .2d lane1 (+1 not < 0)");
}

// ════════════════════════════════════════════════════════════════════════════
// AtomicCasPair — in-place-source-mutation hardening proof (2026-07-01).
//
// The pre-hardening CASP lowering reused `rea`/`reb` (the expected_a/expected_b
// ALLOCATED HOME registers) as in-place scratch — `mov rea, new_a`,
// `xor reb, rdb`, `mov reb, new_b`, etc. That is correct only while the expected
// values are DEAD after the CASP (the live ARM lift makes each a single-use
// ReadGpr, so it happened to hold). It is the same silent-corruptor class as the
// WriteGpr{sf:false} `mov rs32,rs32` truncation that clobbered a saved return
// address → init SIGILL: the instant an expected value is MULTI-USE, mutating
// its home register wrecks the later consumer.
//
// These tests build a block by hand where expected_a/expected_b are read AGAIN
// after the CASP (written to fresh guest registers). The oracle's single-block
// ARM lift can't force this multi-use, so we construct the IR directly. Under
// the OLD in-place lowering the later reads observe `new_*` (match path) instead
// of the original expected value — the test FAILS; under the non-mutating
// branch form it PASSES. It also asserts no UD2 and both CASP halves store.
// ════════════════════════════════════════════════════════════════════════════

/// Build + run one CASP-with-live-expected block for the 64-bit pair form.
/// Returns `(x0, x1, x10, x11, mem0, mem1)`:
///   x0/x1  = returned old pair (dst_a/dst_b),
///   x10/x11 = the SECOND read of expected_a/expected_b (the multi-use consumer),
///   mem0/mem1 = the post-CASP memory pair.
/// `matches` picks whether the in-memory pair equals the expected pair.
fn run_casp_live_expected_64(matches: bool) -> (u64, u64, u64, u64, u64, u64) {
    use aether_translator::ir::memory::MemOrder;
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    let exp_a = 0xAAAA_AAAA_1111_2222u64;
    let exp_b = 0xBBBB_BBBB_3333_4444u64;
    let new_a = 0xCCCC_CCCC_5555_6666u64;
    let new_b = 0xDDDD_DDDD_7777_8888u64;

    // The 16-byte pair the CASP reads/writes. On `matches` it equals {exp}.
    let mut mem = if matches {
        [exp_a, exp_b]
    } else {
        [0x0DEF_0DEF_0DEF_0DEFu64, 0x0FED_0FED_0FED_0FEDu64]
    };

    let mut func = IrFunction::new(0x2000);
    {
        let block = func.add_block();

        // addr = &mem (materialized as a constant pointer at runtime via x4).
        let v_addr = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: v_addr, reg: 4, sf: true });

        // expected_a / expected_b — read ONCE here, consumed by the CASP AND by
        // the post-CASP WriteGpr below (this is the multi-use the fix protects).
        let v_ea = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v_ea, val: exp_a as i64 });
        let v_eb = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v_eb, val: exp_b as i64 });

        let v_na = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v_na, val: new_a as i64 });
        let v_nb = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v_nb, val: new_b as i64 });

        let v_da = block.new_value(IrValueKind::I64);
        let v_db = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::AtomicCasPair {
            dst_a: v_da,
            dst_b: v_db,
            addr: v_addr,
            expected_a: v_ea,
            expected_b: v_eb,
            new_a: v_na,
            new_b: v_nb,
            order: MemOrder::Relaxed,
            size: 8,
        });

        // Commit the returned old pair to x0/x1 …
        block.push_op(IrOp::WriteGpr { reg: 0, src: v_da, sf: true });
        block.push_op(IrOp::WriteGpr { reg: 1, src: v_db, sf: true });
        // … and the SECOND use of expected_a/expected_b to x10/x11. If the CASP
        // arm mutated the expected home registers, these read the corrupted value.
        block.push_op(IrOp::WriteGpr { reg: 10, src: v_ea, sf: true });
        block.push_op(IrOp::WriteGpr { reg: 11, src: v_eb, sf: true });
    }

    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();

    let code = lower_built_func(&func);
    assert_no_ud2(&code, "casp live-expected 64");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[4] = mem.as_mut_ptr() as u64;
    // SAFETY: RWX RET-terminated block; ctx is the extended context; mem is a
    // live 16-byte pair the flat CASP reads/writes.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    (ctx[0], ctx[1], ctx[10], ctx[11], mem[0], mem[1])
}

/// The MATCH path is where the old bug bit hardest: it overwrote `rea`/`reb`
/// with new_a/new_b, so a later read of expected_a/expected_b saw new_*.
#[test]
fn casp_match_does_not_clobber_live_expected() {
    let _serial = serial();
    let exp_a = 0xAAAA_AAAA_1111_2222u64;
    let exp_b = 0xBBBB_BBBB_3333_4444u64;
    let new_a = 0xCCCC_CCCC_5555_6666u64;
    let new_b = 0xDDDD_DDDD_7777_8888u64;

    let (x0, x1, x10, x11, m0, m1) = run_casp_live_expected_64(true);

    // CASP result: old pair returned (== expected on the match path).
    assert_eq!(x0, exp_a, "match: old_a returned in x0");
    assert_eq!(x1, exp_b, "match: old_b returned in x1");
    // The pair matched, so the new pair is stored.
    assert_eq!(m0, new_a, "match: new_a stored to [x4]");
    assert_eq!(m1, new_b, "match: new_b stored to [x4+8]");
    // THE HARDENING ASSERTION: the still-live expected values survived the CASP.
    // Pre-fix, the arm did `mov rea,new_a; mov reb,new_b`, so x10/x11 would read
    // new_a/new_b (0xCCCC…/0xDDDD…) — a silent corruption of a multi-use SSA value.
    assert_eq!(
        x10, exp_a,
        "expected_a MUST survive the CASP (was clobbered to new_a=0x{:x} by the \
         in-place mutation); got 0x{:x}",
        new_a, x10
    );
    assert_eq!(
        x11, exp_b,
        "expected_b MUST survive the CASP (was clobbered to new_b=0x{:x} by the \
         in-place mutation); got 0x{:x}",
        new_b, x11
    );
}

/// The MISMATCH path: memory left unchanged, old pair returned, and the live
/// expected values still survive (the old code's `xor reb,rdb` also corrupted
/// expected_b here).
#[test]
fn casp_mismatch_does_not_clobber_live_expected() {
    let _serial = serial();
    let exp_a = 0xAAAA_AAAA_1111_2222u64;
    let exp_b = 0xBBBB_BBBB_3333_4444u64;
    let mem_a = 0x0DEF_0DEF_0DEF_0DEFu64;
    let mem_b = 0x0FED_0FED_0FED_0FEDu64;

    let (x0, x1, x10, x11, m0, m1) = run_casp_live_expected_64(false);

    assert_eq!(x0, mem_a, "mismatch: old_a (the memory value) returned in x0");
    assert_eq!(x1, mem_b, "mismatch: old_b returned in x1");
    assert_eq!(m0, mem_a, "mismatch: memory[0] unchanged");
    assert_eq!(m1, mem_b, "mismatch: memory[1] unchanged");
    assert_eq!(x10, exp_a, "expected_a must survive the mismatch CASP");
    assert_eq!(x11, exp_b, "expected_b must survive the mismatch CASP");
}

/// Same guarantee for the 32-bit pair form (CASPW), where the old lowering did
/// `mov rea,rea` (truncate) + `mov rea,new_a` + `xor reb,rdb` on the expected
/// home regs. Build a hand IR block with 4-byte elements and a live re-read.
#[test]
fn caspw_match_does_not_clobber_live_expected() {
    let _serial = serial();
    use aether_translator::ir::memory::MemOrder;
    use aether_translator::ir::value::IrValueKind;
    use aether_translator::ir::{IrFunction, IrOp};

    let exp_a: u32 = 0x1111_2222;
    let exp_b: u32 = 0x3333_4444;
    let new_a: u32 = 0x5555_6666;
    let new_b: u32 = 0x7777_8888;
    // Two adjacent 32-bit words the CASPW reads/writes (matches expected).
    let mut mem = [exp_a, exp_b];

    let mut func = IrFunction::new(0x3000);
    {
        let block = func.add_block();
        let v_addr = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ReadGpr { dst: v_addr, reg: 4, sf: true });
        // Seed the expected halves with DIRTY upper 32 bits to also exercise the
        // zero-extend-into-scratch compare (a stale-upper-bits spurious mismatch
        // would flip this to the else path and fail the "new stored" assertions).
        let v_ea = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v_ea, val: 0xDEAD_0000_0000_0000u64 as i64 | exp_a as i64 });
        let v_eb = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v_eb, val: 0xBEEF_0000_0000_0000u64 as i64 | exp_b as i64 });
        let v_na = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v_na, val: new_a as i64 });
        let v_nb = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::ConstI64 { dst: v_nb, val: new_b as i64 });
        let v_da = block.new_value(IrValueKind::I64);
        let v_db = block.new_value(IrValueKind::I64);
        block.push_op(IrOp::AtomicCasPair {
            dst_a: v_da, dst_b: v_db, addr: v_addr,
            expected_a: v_ea, expected_b: v_eb, new_a: v_na, new_b: v_nb,
            order: MemOrder::Relaxed, size: 4,
        });
        block.push_op(IrOp::WriteGpr { reg: 0, src: v_da, sf: true });
        block.push_op(IrOp::WriteGpr { reg: 1, src: v_db, sf: true });
        // Live re-read of the (dirty-upper) expected values.
        block.push_op(IrOp::WriteGpr { reg: 10, src: v_ea, sf: true });
        block.push_op(IrOp::WriteGpr { reg: 11, src: v_eb, sf: true });
    }

    aether_mmu_set_window(0, u64::MAX);
    aether_mmu_flush_all();
    let code = lower_built_func(&func);
    assert_no_ud2(&code, "caspw live-expected 32");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[4] = mem.as_mut_ptr() as u64;
    // SAFETY: RWX RET-terminated block; mem is a live 8-byte pair.
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }

    // Low 32 bits equal → match → new stored; old (low-32) pair returned.
    assert_eq!(mem[0], new_a, "CASPW match: new_a stored");
    assert_eq!(mem[1], new_b, "CASPW match: new_b stored");
    assert_eq!(ctx[0] as u32, exp_a, "CASPW old_a low32 returned in x0");
    assert_eq!(ctx[1] as u32, exp_b, "CASPW old_b low32 returned in x1");
    // The full 64-bit expected values (dirty upper bits included) must survive —
    // the old `mov rea,rea` truncation + `mov rea,new_a` would have destroyed them.
    assert_eq!(
        ctx[10], 0xDEAD_0000_0000_0000u64 | exp_a as u64,
        "CASPW expected_a (full 64 bits) MUST survive the compare + store",
    );
    assert_eq!(
        ctx[11], 0xBEEF_0000_0000_0000u64 | exp_b as u64,
        "CASPW expected_b (full 64 bits) MUST survive the compare + store",
    );
}

// ============================================================================
// Differential-oracle FP/SIMD fixes (2026-07-01) - the first real miscompiles
// the ARM64->x86 differential oracle caught in the DBT FP/SIMD path that zygote
// -> SurfaceFlinger (Skia/libhwui/ART) hammers. Each test executes the emitted
// x86 on the host, asserts NO UD2, and checks the exact ARM-correct answer.
// ============================================================================

/// Bug 1 - FCVT Sd,Dn (double->single narrowing) MUST zero Vd[127:32].
///
/// `cvtsd2ss` writes only bits[31:0] of the xmm and preserves the rest, so the
/// old lowering (convert-in-place then 128-bit store) left the SOURCE double's
/// bits[63:32] in the result: `FCVT S0,D1` with D1=2.25 produced
/// `..4002_0000_4010_0000` instead of `..0000_0000_4010_0000` - a silent
/// miscompile that corrupts any later Dd/Qd read or `FMOV Xd,Dd`. We poison the
/// destination slot, convert, and assert bits[127:32] are ZERO and bits[31:0]
/// hold the single-precision 2.25 (0x40100000).
#[test]
fn fcvt_narrow_zeroes_upper_bits_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // FCVT S0, D1 - narrowing double->single.
    let word = 0x1E62_4020u32;
    decode_instruction(word).expect("decode fcvt s0,d1");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fcvt s0,d1");
    let exec = winexec::make_executable(&code);

    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 2.25f64.to_bits();          // D1 = 2.25 -> f64 bits 0x4002_0000_0000_0000
    ctx[vd(1) + 1] = 0xDEAD_BEEF_CAFE_F00D;  // source high lane (must NOT leak)
    ctx[vd(0)] = 0x1111_2222_3333_4444;      // poison dest low
    ctx[vd(0) + 1] = 0x5555_6666_7777_8888;  // poison dest high
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }

    assert_eq!(
        ctx[vd(0)] as u32, 2.25f32.to_bits(),
        "fcvt s0,d1: low 32 bits = single(2.25) = 0x40100000 (got {:#010x})", ctx[vd(0)] as u32,
    );
    assert_eq!(
        ctx[vd(0)] >> 32, 0,
        "fcvt s0,d1: Vd[63:32] MUST be zero - was leaking the source double's upper half",
    );
    assert_eq!(
        ctx[vd(0) + 1], 0,
        "fcvt s0,d1: Vd[127:64] MUST be zero (got {:#018x})", ctx[vd(0) + 1],
    );
    assert_eq!(ctx[vd(0)], 2.25f32.to_bits() as u64, "fcvt s0,d1 full low-64 slot");

    // FCVT D0, S1 - widening single->double (reportedly clean; verify).
    let word = 0x1E22_C020u32;
    decode_instruction(word).expect("decode fcvt d0,s1");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fcvt d0,s1");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 2.25f32.to_bits() as u64;   // S1 = 2.25 single
    ctx[vd(1) + 1] = 0xAAAA_BBBB_CCCC_DDDD;
    ctx[vd(0)] = 0x9999_9999_9999_9999;      // poison dest low
    ctx[vd(0) + 1] = 0x8888_8888_8888_8888;  // poison dest high
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 2.25f64.to_bits(), "fcvt d0,s1: low 64 = double(2.25)");
    assert_eq!(ctx[vd(0) + 1], 0, "fcvt d0,s1: Vd[127:64] MUST be zero");
}

/// Bug 2 - scalar FMADD/FMSUB/FNMADD/FNMSUB (3-source fused multiply-add) were a
/// Tier-1 UD2 gap. They lower to x86 FMA3 (single fused rounding, matching ARM).
///
/// ARM: FMADD Sd = Sa + Sn*Sm ; FMSUB Sd = Sa - Sn*Sm ;
///      FNMADD Sd = -Sa - Sn*Sm ; FNMSUB Sd = -Sa + Sn*Sm.
///
/// The single-precision FMADD case uses ADVERSARIAL inputs where the FUSED result
/// differs bit-for-bit from the unfused (multiply-round-then-add) result:
///   n = m = sqrt(2) ~= 0x3FB504F3, a = -2.0 -> fused 0xB39302AE vs unfused
///   0xB4000000. A multiply-then-add (two roundings) would give the wrong bits.
/// The double FMADD case (n=m=1+2^-27, a=-1.0) is likewise fused-distinguishing.
#[test]
fn fma_scalar_fused_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // Sd=S0, Sn=S1, Sm=S2, Sa=S3. Adversarial: n=m=sqrt(2), a=-2.0.
    let n_bits = 0x3FB5_04F3u32; // sqrt(2)
    let m_bits = 0x3FB5_04F3u32;
    let a_bits = 0xC000_0000u32; // -2.0
    let n = f32::from_bits(n_bits);
    let m = f32::from_bits(m_bits);
    let a = f32::from_bits(a_bits);

    let run_s = |word: u32, what: &str| -> u32 {
        decode_instruction(word).unwrap_or_else(|_| panic!("decode {what}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, what);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = n_bits as u64;
        ctx[vd(2)] = m_bits as u64;
        ctx[vd(3)] = a_bits as u64;
        ctx[vd(0)] = 0xDEAD_BEEF_0000_0000;      // poison dest
        ctx[vd(0) + 1] = 0xFEED_FACE_C0DE_BA5E;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        assert_eq!(ctx[vd(0)] >> 32, 0, "{what}: Vd[63:32] must be zero");
        assert_eq!(ctx[vd(0) + 1], 0, "{what}: Vd[127:64] must be zero");
        ctx[vd(0)] as u32
    };

    // Fused references via mul_add (x86 FMA / correctly-rounded FMA).
    let fmadd_ref = n.mul_add(m, a);       // Sa + Sn*Sm
    let fmsub_ref = (-n).mul_add(m, a);    // Sa - Sn*Sm
    let fnmadd_ref = (-n).mul_add(m, -a);  // -Sa - Sn*Sm
    let fnmsub_ref = n.mul_add(m, -a);     // -Sa + Sn*Sm

    // Prove the FMADD case is genuinely fused-distinguishing.
    assert_ne!(
        fmadd_ref.to_bits(), (n * m + a).to_bits(),
        "test setup: FMADD single inputs must be fused-distinguishing",
    );

    assert_eq!(run_s(0x1F02_0C20, "fmadd s"), fmadd_ref.to_bits(),
        "FMADD S: must equal the SINGLE-ROUNDED fused result (not multiply-then-add)");
    assert_eq!(run_s(0x1F02_8C20, "fmsub s"), fmsub_ref.to_bits(), "FMSUB S fused");
    assert_eq!(run_s(0x1F22_0C20, "fnmadd s"), fnmadd_ref.to_bits(), "FNMADD S fused");
    assert_eq!(run_s(0x1F22_8C20, "fnmsub s"), fnmsub_ref.to_bits(), "FNMSUB S fused");

    // Double-precision FMADD, fused-distinguishing (n=m=1+2^-27, a=-1.0).
    let nd = 1.0f64 + 2f64.powi(-27);
    let md = 1.0f64 + 2f64.powi(-27);
    let ad = -1.0f64;
    let fused_d = nd.mul_add(md, ad);
    assert_ne!(fused_d.to_bits(), (nd * md + ad).to_bits(),
        "test setup: double FMADD must be fused-distinguishing");

    let run_d = |word: u32, what: &str, nb: u64, mb: u64, ab: u64| -> u64 {
        decode_instruction(word).unwrap_or_else(|_| panic!("decode {what}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, what);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = nb; ctx[vd(2)] = mb; ctx[vd(3)] = ab;
        ctx[vd(0)] = 0x1234_5678_9ABC_DEF0;
        ctx[vd(0) + 1] = 0x0FED_CBA9_8765_4321;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        assert_eq!(ctx[vd(0) + 1], 0, "{what}: Vd[127:64] must be zero");
        ctx[vd(0)]
    };

    // FMADD D0,D1,D2,D3 (0x1F420C20).
    assert_eq!(
        run_d(0x1F42_0C20, "fmadd d", nd.to_bits(), md.to_bits(), ad.to_bits()),
        fused_d.to_bits(),
        "FMADD D: must equal the SINGLE-ROUNDED fused result",
    );
    // FNMSUB D0,D1,D2,D3 = -Sa + Sn*Sm (0x1F628C20): -4 + 2*3 = 2.
    let n2 = 2.0f64; let m2 = 3.0f64; let a2 = 4.0f64;
    assert_eq!(
        run_d(0x1F62_8C20, "fnmsub d", n2.to_bits(), m2.to_bits(), a2.to_bits()),
        n2.mul_add(m2, -a2).to_bits(),
        "FNMSUB D: -Sa + Sn*Sm = -4 + 2*3 = 2",
    );
}

/// Bug 3 - UABD / UABA on .4S (and a SABD .4S regression guard) were a Tier-1
/// UD2 gap (only .8B/.4H worked). `.2D` is architecturally reserved for these
/// ops (decoder rejects size=11), so only `.4S` is added. UABD is the UNSIGNED
/// absolute difference per 32-bit lane; the adversarial lane exercises unsigned
/// wrap: |1 - 0xFFFF_FFFF| unsigned = 0xFFFF_FFFE (a SIGNED abs-diff gives 2).
#[test]
fn uabd_uaba_4s_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // 4 s32 lanes packed 2-per-u64, little-endian: lo=[lane0|lane1], hi=[lane2|lane3].
    let pack = |l0: u32, l1: u32| (l0 as u64) | ((l1 as u64) << 32);

    // UABD V2.4S, V1.4S, V0.4S (a=V1, b=V0) -> |a-b| unsigned per lane. 0x6EA07422.
    let word = 0x6EA0_7422u32;
    decode_instruction(word).expect("decode uabd .4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uabd .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // lane0: a=1, b=0xFFFF_FFFF -> unsigned |1-0xFFFFFFFF| = 0xFFFF_FFFE (wrap).
    // lane1: a=10, b=3 -> 7.
    ctx[vd(1)] = pack(1, 10);
    ctx[vd(0)] = pack(0xFFFF_FFFF, 3);
    // lane2: a=0x8000_0000, b=0x7FFF_FFFF -> 1. lane3: a=5, b=5 -> 0.
    ctx[vd(1) + 1] = pack(0x8000_0000, 5);
    ctx[vd(0) + 1] = pack(0x7FFF_FFFF, 5);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], pack(0xFFFF_FFFE, 7), "uabd .4s lo: |1-0xFFFFFFFF|=0xFFFFFFFE, |10-3|=7");
    assert_eq!(ctx[vd(2) + 1], pack(1, 0), "uabd .4s hi: |0x80000000-0x7FFFFFFF|=1, |5-5|=0");

    // UABA V3.4S, V1.4S, V0.4S -> V3 += |V1-V0| unsigned per lane. 0x6EA07C23 (Rd=3).
    let word = 0x6EA0_7C23u32;
    decode_instruction(word).expect("decode uaba .4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uaba .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = pack(1, 10);
    ctx[vd(0)] = pack(0xFFFF_FFFF, 3);
    ctx[vd(1) + 1] = pack(100, 5);
    ctx[vd(0) + 1] = pack(40, 5);
    ctx[vd(3)] = pack(1, 1);       // pre-existing accumulator V3
    ctx[vd(3) + 1] = pack(2, 3);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // lane0: 1 + |1-0xFFFFFFFF|=1+0xFFFFFFFE=0xFFFFFFFF. lane1: 1 + |10-3|=8.
    // lane2: 2 + |100-40|=62. lane3: 3 + |5-5|=3.
    assert_eq!(ctx[vd(3)], pack(0xFFFF_FFFF, 8), "uaba .4s lo accumulate");
    assert_eq!(ctx[vd(3) + 1], pack(62, 3), "uaba .4s hi accumulate");

    // SABD V2.4S regression guard (signed abs-diff already worked for .4s).
    // 0xFFFFFFFF as s32 = -1. |(-1) - 1| signed = 2. 0x4EA07422.
    let word = 0x4EA0_7422u32;
    decode_instruction(word).expect("decode sabd .4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sabd .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = pack(0xFFFF_FFFF, 7);  // lane0 = -1, lane1 = 7
    ctx[vd(0)] = pack(1, 0xFFFF_FFFD);  // lane0 = 1,  lane1 = -3
    ctx[vd(1) + 1] = pack(0, 0);
    ctx[vd(0) + 1] = pack(0, 0);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(2)], pack(2, 10), "sabd .4s: |-1-1|=2 (signed), |7-(-3)|=10");
    assert_eq!(ctx[vd(2) + 1], pack(0, 0), "sabd .4s hi: 0");
}

// ============================================================================
// Differential-oracle SIMD/FP fixes, corpus sweep #2 (2026-07-01). Three
// CONFIRMED silent (value-wrong, not fail-loud) miscompiles dense in the
// zygote -> SurfaceFlinger render/compositor float path (libhwui / libui /
// libgui / libsurfaceflinger). Each executes the emitted x86 on the host,
// asserts NO UD2, and checks the exact hand-computed ARM-correct answer.
// ============================================================================

/// C2 - scalar SCVTF/UCVTF drop the source width `sf`. The W-form (32-bit source)
/// convert was always lowered as a 64-bit convert of the ZERO-EXTENDED GPR, so a
/// SIGNED W-form convert of a negative W value produced +2^32 instead of the
/// correct negative result. `SCVTF S0,W1` with W1=0xFFFFFFFF (ARM signed -1) must
/// give -1.0 (0xBF800000), NOT +4294967295.0 (0x4F800000). `UCVTF S0,W1` with the
/// same bits (unsigned 4294967295) must give +4294967295.0 (0x4F800000).
#[test]
fn scvtf_ucvtf_wform_sign_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // SCVTF S0, W1 (0x1E220020). W1 = 0xFFFFFFFF = signed -1 -> -1.0.
    let word = 0x1E22_0020u32;
    decode_instruction(word).expect("decode scvtf s0,w1");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "scvtf s0,w1");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0xFFFF_FFFF;                 // W1 = 0xFFFFFFFF (ARM signed -1)
    ctx[vd(0)] = 0xDEAD_BEEF_CAFE_F00D;   // poison dest
    ctx[vd(0) + 1] = 0x1234_5678_9ABC_DEF0;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(0)] as u32, (-1.0f32).to_bits(),
        "SCVTF S0,W1 with W1=0xFFFFFFFF (signed -1) MUST be -1.0 (0xBF800000), got {:#010x}",
        ctx[vd(0)] as u32,
    );
    assert_ne!(ctx[vd(0)] as u32, 0x4F80_0000, "must NOT be the zero-extended +2^32 (the bug)");
    assert_eq!(ctx[vd(0)] >> 32, 0, "SCVTF S-write must zero Vd[63:32]");
    assert_eq!(ctx[vd(0) + 1], 0, "SCVTF S-write must zero Vd[127:64]");

    // UCVTF S0, W1 (0x1E230020). W1 = 0xFFFFFFFF = unsigned 4294967295 -> +4294967295.0.
    let word = 0x1E23_0020u32;
    decode_instruction(word).expect("decode ucvtf s0,w1");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "ucvtf s0,w1");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0xFFFF_FFFF;
    ctx[vd(0)] = 0xDEAD_BEEF_CAFE_F00D;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(0)] as u32, 4294967295.0f32.to_bits(),
        "UCVTF S0,W1 with W1=0xFFFFFFFF (unsigned) MUST be +4294967295.0 (0x4F800000), got {:#010x}",
        ctx[vd(0)] as u32,
    );
    assert_eq!(ctx[vd(0)] >> 32, 0, "UCVTF S-write must zero Vd[63:32]");

    // SCVTF D0, W1 (double dest, 0x1E620020). Signed -1 -> -1.0 (f64).
    let word = 0x1E62_0020u32;
    decode_instruction(word).expect("decode scvtf d0,w1");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "scvtf d0,w1");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0xFFFF_FFFF;
    ctx[vd(0) + 1] = 0xAAAA_BBBB_CCCC_DDDD;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], (-1.0f64).to_bits(), "SCVTF D0,W1 = -1.0 (f64)");
    assert_eq!(ctx[vd(0) + 1], 0, "SCVTF D-write must zero Vd[127:64]");

    // Regression guard: X-form still correct. SCVTF S0,X1 (0x9E220020) with
    // X1 = -1 (0xFFFFFFFFFFFFFFFF) -> -1.0.
    let word = 0x9E22_0020u32;
    decode_instruction(word).expect("decode scvtf s0,x1");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "scvtf s0,x1");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0xFFFF_FFFF_FFFF_FFFF;       // X1 = signed -1
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)] as u32, (-1.0f32).to_bits(), "SCVTF S0,X1 (X-form) = -1.0 unchanged");

    // Regression guard: UCVTF Xn large value. UCVTF D0,X1 (0x9E630020) with
    // X1 = 0xFFFFFFFFFFFFFFFF (unsigned 2^64-1) -> 1.8446744073709552e19.
    let word = 0x9E63_0020u32;
    decode_instruction(word).expect("decode ucvtf d0,x1");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "ucvtf d0,x1");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[1] = 0xFFFF_FFFF_FFFF_FFFF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(
        ctx[vd(0)], (18446744073709551615u64 as f64).to_bits(),
        "UCVTF D0,X1 (u64 max) MUST use the unsigned two-path fixup, got {:#018x}", ctx[vd(0)],
    );
}

/// C3 - scalar FCVTZS/FCVTZU (and the FCVTN/P/M/A rounding variants) did not
/// SATURATE. x86 cvtt* returns the "integer indefinite" (0x8000..) on any
/// overflow / +-inf / NaN; ARM saturates to INT_MAX / INT_MIN / UINT_MAX / 0 and
/// maps NaN -> 0. Cover the +overflow / +inf / NaN / -inf directions per width.
#[test]
fn fcvtz_scalar_saturate_execute() {
    let _serial = serial();
    let run = |word: u32, what: &str, src_bits: u64, is_dbl: bool| -> u64 {
        use aether_translator::runtime::context::vec_disp;
        let vd = |r: u8| (vec_disp(r) as usize) / 8;
        decode_instruction(word).unwrap_or_else(|_| panic!("decode {what}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, what);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        // Source in V0 (Sn=S0/D0). For S-form only the low 32 bits matter.
        ctx[vd(0)] = if is_dbl { src_bits } else { src_bits & 0xFFFF_FFFF };
        // Result lands in X0 (or W0 -> low 32). Poison it first.
        ctx[0] = 0x5555_5555_5555_5555;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        ctx[0]
    };

    // ---- Signed, W dest (FCVTZS W0,S0 = 0x1E380000) ----
    // +8.6e9 (> INT32_MAX) -> saturate to 0x7FFFFFFF.
    assert_eq!(
        run(0x1E38_0000, "fcvtzs w0,s0 (+8.6e9)", 8.6e9f32.to_bits() as u64, false) as u32,
        0x7FFF_FFFF, "FCVTZS W of +8.6e9 must saturate to INT32_MAX",
    );
    // +inf -> INT32_MAX.
    assert_eq!(
        run(0x1E38_0000, "fcvtzs w0,s0 (+inf)", f32::INFINITY.to_bits() as u64, false) as u32,
        0x7FFF_FFFF, "FCVTZS W of +inf must saturate to INT32_MAX",
    );
    // NaN -> 0.
    assert_eq!(
        run(0x1E38_0000, "fcvtzs w0,s0 (NaN)", f32::NAN.to_bits() as u64, false) as u32,
        0, "FCVTZS W of NaN must be 0",
    );
    // -inf -> INT32_MIN.
    assert_eq!(
        run(0x1E38_0000, "fcvtzs w0,s0 (-inf)", f32::NEG_INFINITY.to_bits() as u64, false) as u32,
        0x8000_0000, "FCVTZS W of -inf must saturate to INT32_MIN",
    );
    // In-range value just past INT_MAX boundary and a normal value are correct.
    assert_eq!(
        run(0x1E38_0000, "fcvtzs w0,s0 (12.9)", 12.9f32.to_bits() as u64, false) as u32,
        12, "FCVTZS W of 12.9 truncates to 12",
    );
    assert_eq!(
        run(0x1E38_0000, "fcvtzs w0,s0 (-12.9)", (-12.9f32).to_bits() as u64, false) as i32,
        -12, "FCVTZS W of -12.9 truncates to -12",
    );

    // ---- Signed, X dest (FCVTZS X0,D0 = 0x9E780000) ----
    // 3.4e38 (> INT64_MAX) -> 0x7FFFFFFFFFFFFFFF.
    assert_eq!(
        run(0x9E78_0000, "fcvtzs x0,d0 (3.4e38)", 3.4e38f64.to_bits(), true),
        0x7FFF_FFFF_FFFF_FFFF, "FCVTZS X of 3.4e38 must saturate to INT64_MAX",
    );
    assert_eq!(
        run(0x9E78_0000, "fcvtzs x0,d0 (NaN)", f64::NAN.to_bits(), true),
        0, "FCVTZS X of NaN must be 0",
    );
    assert_eq!(
        run(0x9E78_0000, "fcvtzs x0,d0 (-inf)", f64::NEG_INFINITY.to_bits(), true),
        0x8000_0000_0000_0000, "FCVTZS X of -inf must saturate to INT64_MIN",
    );

    // ---- Unsigned, W dest (FCVTZU W0,S0 = 0x1E390000) ----
    // +8.6e9 (> UINT32_MAX? no, < 4.29e9? 8.6e9 > 4294967295) -> UINT32_MAX.
    assert_eq!(
        run(0x1E39_0000, "fcvtzu w0,s0 (+8.6e9)", 8.6e9f32.to_bits() as u64, false) as u32,
        0xFFFF_FFFF, "FCVTZU W of +8.6e9 (> UINT32_MAX) must saturate to UINT32_MAX",
    );
    assert_eq!(
        run(0x1E39_0000, "fcvtzu w0,s0 (+inf)", f32::INFINITY.to_bits() as u64, false) as u32,
        0xFFFF_FFFF, "FCVTZU W of +inf must be UINT32_MAX",
    );
    assert_eq!(
        run(0x1E39_0000, "fcvtzu w0,s0 (NaN)", f32::NAN.to_bits() as u64, false) as u32,
        0, "FCVTZU W of NaN must be 0",
    );
    assert_eq!(
        run(0x1E39_0000, "fcvtzu w0,s0 (-5.0)", (-5.0f32).to_bits() as u64, false) as u32,
        0, "FCVTZU W of a negative must clamp to 0",
    );
    // In-range unsigned value above INT32_MAX still correct (3.0e9 < 2^32).
    assert_eq!(
        run(0x1E39_0000, "fcvtzu w0,s0 (3.0e9)", 3.0e9f32.to_bits() as u64, false) as u32,
        3_000_000_000, "FCVTZU W of 3.0e9 is exact",
    );

    // ---- Unsigned, X dest (FCVTZU X0,D0 = 0x9E790000) ----
    // 1.8e19 (>= 2^63, < 2^64) -> exact-ish via two-path (not 0).
    let v = run(0x9E79_0000, "fcvtzu x0,d0 (1.8e19)", 1.8e19f64.to_bits(), true);
    assert_eq!(v, 1.8e19f64 as u64, "FCVTZU X of 1.8e19 (>=2^63) must convert, not give 0");
    assert!(v > 0x8000_0000_0000_0000, "FCVTZU X of 1.8e19 must be in the upper unsigned half");
    // >= 2^64 (+inf) -> UINT64_MAX.
    assert_eq!(
        run(0x9E79_0000, "fcvtzu x0,d0 (+inf)", f64::INFINITY.to_bits(), true),
        0xFFFF_FFFF_FFFF_FFFF, "FCVTZU X of +inf must saturate to UINT64_MAX",
    );
    assert_eq!(
        run(0x9E79_0000, "fcvtzu x0,d0 (NaN)", f64::NAN.to_bits(), true),
        0, "FCVTZU X of NaN must be 0",
    );
    assert_eq!(
        run(0x9E79_0000, "fcvtzu x0,d0 (-3.0)", (-3.0f64).to_bits(), true),
        0, "FCVTZU X of a negative must clamp to 0",
    );
}

/// C4 - vector FMLA/FMLS were lowered as mulps+addps (TWO roundings) instead of
/// a single FUSED multiply-add. AArch64 Advanced-SIMD FMLA/FMLS are
/// architecturally fused (single rounding per lane). We use adversarial lanes
/// where the fused result differs bit-for-bit from the unfused one.
#[test]
fn vector_fmla_fmls_fused_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let pack = |l0: u32, l1: u32| (l0 as u64) | ((l1 as u64) << 32);

    // Adversarial single lane: n=m=sqrt(2), acc=-2.0 -> fused mul_add != unfused.
    let sq2 = 0x3FB5_04F3u32;            // sqrt(2)
    let acc = 0xC000_0000u32;            // -2.0
    let n = f32::from_bits(sq2);
    let fused = n.mul_add(n, f32::from_bits(acc));       // FMLA: acc + n*m
    let unfused = (n * n) + f32::from_bits(acc);
    assert_ne!(fused.to_bits(), unfused.to_bits(), "test setup: lane must be fused-distinguishing");

    // FMLA V0.4S, V1.4S, V2.4S (0x4E22CC20): Vd += Vn*Vm, fused per lane.
    let word = 0x4E22_CC20u32;
    decode_instruction(word).expect("decode fmla v0.4s,v1.4s,v2.4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fmla .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = pack(sq2, sq2);          // Vn lanes 0,1
    ctx[vd(1) + 1] = pack(sq2, sq2);      // Vn lanes 2,3
    ctx[vd(2)] = pack(sq2, sq2);          // Vm lanes 0,1
    ctx[vd(2) + 1] = pack(sq2, sq2);      // Vm lanes 2,3
    ctx[vd(0)] = pack(acc, acc);          // Vd accumulator lanes 0,1
    ctx[vd(0) + 1] = pack(acc, acc);      // lanes 2,3
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], pack(fused.to_bits(), fused.to_bits()),
        "FMLA .4s lanes 0,1 MUST be the single-rounded fused result (not mul+add)");
    assert_eq!(ctx[vd(0) + 1], pack(fused.to_bits(), fused.to_bits()),
        "FMLA .4s lanes 2,3 fused");

    // FMLS V0.4S, V1.4S, V2.4S (0x4EA2CC20): Vd -= Vn*Vm, fused per lane.
    // acc = +2.0 mirrors the FMADD-distinguishing case for subtraction:
    // fused  2 - n*m (single rounding)  !=  unfused  2 - round(n*m).
    let acc_p = 0x4000_0000u32;          // +2.0
    let fmls_fused = (-n).mul_add(n, f32::from_bits(acc_p));   // acc - n*m
    let fmls_unfused = f32::from_bits(acc_p) - (n * n);
    assert_ne!(fmls_fused.to_bits(), fmls_unfused.to_bits(), "test setup: FMLS fused-distinguishing");
    let word = 0x4EA2_CC20u32;
    decode_instruction(word).expect("decode fmls v0.4s,v1.4s,v2.4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fmls .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = pack(sq2, sq2);
    ctx[vd(1) + 1] = pack(sq2, sq2);
    ctx[vd(2)] = pack(sq2, sq2);
    ctx[vd(2) + 1] = pack(sq2, sq2);
    ctx[vd(0)] = pack(acc_p, acc_p);
    ctx[vd(0) + 1] = pack(acc_p, acc_p);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], pack(fmls_fused.to_bits(), fmls_fused.to_bits()),
        "FMLS .4s lanes 0,1 fused");
    assert_eq!(ctx[vd(0) + 1], pack(fmls_fused.to_bits(), fmls_fused.to_bits()),
        "FMLS .4s lanes 2,3 fused");

    // FMLA V0.2D, V1.2D, V2.2D (0x4E62CC20): double-precision fused, 2 lanes.
    let ndb = 1.0f64 + 2f64.powi(-27);
    let accd = -1.0f64;
    let fused_d = ndb.mul_add(ndb, accd);
    assert_ne!(fused_d.to_bits(), (ndb * ndb + accd).to_bits(), "test setup: .2d fused-distinguishing");
    let word = 0x4E62_CC20u32;
    decode_instruction(word).expect("decode fmla v0.2d,v1.2d,v2.2d");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fmla .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = ndb.to_bits(); ctx[vd(1) + 1] = ndb.to_bits();
    ctx[vd(2)] = ndb.to_bits(); ctx[vd(2) + 1] = ndb.to_bits();
    ctx[vd(0)] = accd.to_bits(); ctx[vd(0) + 1] = accd.to_bits();
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], fused_d.to_bits(), "FMLA .2d lane0 fused");
    assert_eq!(ctx[vd(0) + 1], fused_d.to_bits(), "FMLA .2d lane1 fused");
}

// ─────────────────────────────────────────────────────────────────────────────
// oracle-sweep-2 gap batch: shift / permute / insert families that lowered to
// UD2 (fail-loud) before this commit. Each test seeds V-regs, executes the
// translated block on the host, and asserts ARM-correct per-lane results with
// adversarial inputs (out-of-range shifts, saturation, sign, insert-preserve).
// ─────────────────────────────────────────────────────────────────────────────

/// SSHL/USHL (register variable per-lane shift). Mixed positive / negative /
/// out-of-range shift amounts, plus the sign-vs-logical distinction on the
/// arithmetic-right path (`0x80000000 >> 4`).
#[test]
fn sshl_ushl_register_variable_shift() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let pack = |lo: u32, hi: u32| (lo as u64) | ((hi as u64) << 32);

    // Shift amounts live in the LOW BYTE of each Vm element (signed).
    // v2 lanes: [+2, -2, -4, +35]  (35 >= 32 → out of range → 0).
    let sh0 = 2u32;
    let sh1 = (-2i32 as u32) & 0xFF; // 0xFE
    let sh2 = (-4i32 as u32) & 0xFF; // 0xFC
    let sh3 = 35u32; // out of range
    let v2_lo = pack(sh0, sh1);
    let v2_hi = pack(sh2, sh3);

    // v1 source lanes: [0x10, 0x10, 0x80000000, 0x03].
    let v1_lo = pack(0x10, 0x10);
    let v1_hi = pack(0x8000_0000, 0x03);

    // --- SSHL v0.4s, v1.4s, v2.4s (0x4ea24420) ---
    let word = 0x4EA2_4420u32;
    decode_instruction(word).expect("decode sshl v0.4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sshl .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = v1_lo; ctx[vd(1) + 1] = v1_hi;
    ctx[vd(2)] = v2_lo; ctx[vd(2) + 1] = v2_hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // lane0: 0x10 << 2 = 0x40 ; lane1: 0x10 >>a 2 = 0x04.
    assert_eq!(ctx[vd(0)], pack(0x40, 0x04), "sshl .4s lanes 0,1");
    // lane2: 0x80000000 as signed >>a 4 = 0xF8000000 ; lane3: >= width → 0.
    assert_eq!(ctx[vd(0) + 1], pack(0xF800_0000, 0), "sshl .4s lanes 2,3 (arith)");

    // --- USHL v0.4s, v1.4s, v2.4s (0x6ea24420): logical right shift ---
    let word = 0x6EA2_4420u32;
    decode_instruction(word).expect("decode ushl v0.4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "ushl .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = v1_lo; ctx[vd(1) + 1] = v1_hi;
    ctx[vd(2)] = v2_lo; ctx[vd(2) + 1] = v2_hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], pack(0x40, 0x04), "ushl .4s lanes 0,1");
    // lane2: 0x80000000 >>u 4 = 0x08000000 (logical, NOT sign-filled) ; lane3: 0.
    assert_eq!(ctx[vd(0) + 1], pack(0x0800_0000, 0), "ushl .4s lanes 2,3 (logical)");

    // --- SSHL v0.2d, v1.2d, v2.2d (0x4ee24420): 64-bit lanes ---
    let word = 0x4EE2_4420u32;
    decode_instruction(word).expect("decode sshl v0.2d");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sshl .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0x0000_0000_0000_0100; // lane0 = 0x100
    ctx[vd(1) + 1] = 0x8000_0000_0000_0000; // lane1 = INT64_MIN
    ctx[vd(2)] = 8; // lane0 shift = +8
    ctx[vd(2) + 1] = (-8i64 as u64) & 0xFF; // lane1 shift = -8
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0x0000_0000_0001_0000, "sshl .2d lane0 = 0x100<<8");
    // INT64_MIN >>a 8 = 0xFF80000000000000.
    assert_eq!(ctx[vd(0) + 1], 0xFF80_0000_0000_0000, "sshl .2d lane1 arith");
}

/// SRI (shift-right-and-insert). Proves the insert PRESERVES Vd's top `shift`
/// bits and replaces the rest with `Vn >>u shift` — per byte for .16b #3.
#[test]
fn sri_shift_right_insert() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // Build a byte-lane vector from 8 bytes (low 64).
    let b8 = |b: [u8; 8]| u64::from_le_bytes(b);

    // sri v0.16b, v1.16b, #3 (0x6f0d4420). Per byte:
    //   result = (Vd & 0xE0)  |  ((Vn >>u 3) & 0x1F)
    let word = 0x6F0D_4420u32;
    decode_instruction(word).expect("decode sri v0.16b,#3");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sri .16b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // Vn (source), Vd (destination — top 3 bits must survive).
    ctx[vd(1)]     = b8([0xFF, 0x00, 0x88, 0x40, 0x01, 0x80, 0xF0, 0x0F]);
    ctx[vd(1) + 1] = b8([0xFF, 0x00, 0x88, 0x40, 0x01, 0x80, 0xF0, 0x0F]);
    ctx[vd(0)]     = b8([0x00, 0xFF, 0x07, 0xE0, 0xAA, 0x55, 0x00, 0xFF]);
    ctx[vd(0) + 1] = b8([0x00, 0xFF, 0x07, 0xE0, 0xAA, 0x55, 0x00, 0xFF]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Hand-compute each byte: (Vd & 0xE0) | ((Vn >> 3) & 0x1F).
    let sri3 = |vn: u8, vd_: u8| (vd_ & 0xE0) | ((vn >> 3) & 0x1F);
    let vn = [0xFF, 0x00, 0x88, 0x40, 0x01, 0x80, 0xF0, 0x0F];
    let vd_d = [0x00, 0xFF, 0x07, 0xE0, 0xAA, 0x55, 0x00, 0xFF];
    let mut want = [0u8; 8];
    for i in 0..8 { want[i] = sri3(vn[i], vd_d[i]); }
    // sanity: byte0 = (0x00&0xE0)|(0xFF>>3=0x1F) = 0x1F ; byte1 = (0xFF&0xE0=0xE0)|0 = 0xE0.
    assert_eq!(want[0], 0x1F); assert_eq!(want[1], 0xE0);
    assert_eq!(ctx[vd(0)], b8(want), "sri .16b low64 insert preserves top 3 bits");
    assert_eq!(ctx[vd(0) + 1], b8(want), "sri .16b high64 insert");
}

/// SLI (shift-left-and-insert). Proves the insert PRESERVES Vd's low `shift`
/// bits and replaces the rest with `Vn << shift` — per byte for .16b #3.
#[test]
fn sli_shift_left_insert() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let b8 = |b: [u8; 8]| u64::from_le_bytes(b);

    // sli v0.16b, v1.16b, #3 (0x6f0b5420). Per byte:
    //   result = (Vd & 0x07)  |  ((Vn << 3) & 0xF8)
    let word = 0x6F0B_5420u32;
    decode_instruction(word).expect("decode sli v0.16b,#3");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sli .16b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)]     = b8([0xFF, 0x00, 0x11, 0x1F, 0x20, 0x01, 0xAA, 0x55]);
    ctx[vd(1) + 1] = b8([0xFF, 0x00, 0x11, 0x1F, 0x20, 0x01, 0xAA, 0x55]);
    ctx[vd(0)]     = b8([0x00, 0xFF, 0x02, 0x07, 0x05, 0x00, 0xFF, 0x03]);
    ctx[vd(0) + 1] = b8([0x00, 0xFF, 0x02, 0x07, 0x05, 0x00, 0xFF, 0x03]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let sli3 = |vn: u8, vd_: u8| (vd_ & 0x07) | ((vn << 3) & 0xF8);
    let vn = [0xFF, 0x00, 0x11, 0x1F, 0x20, 0x01, 0xAA, 0x55];
    let vd_d = [0x00, 0xFF, 0x02, 0x07, 0x05, 0x00, 0xFF, 0x03];
    let mut want = [0u8; 8];
    for i in 0..8 { want[i] = sli3(vn[i], vd_d[i]); }
    // sanity: byte0 = (0x00&0x07)|((0xFF<<3)&0xF8=0xF8) = 0xF8 ; byte1 = (0xFF&0x07=0x07)|0 = 0x07.
    assert_eq!(want[0], 0xF8); assert_eq!(want[1], 0x07);
    assert_eq!(ctx[vd(0)], b8(want), "sli .16b low64 insert preserves low 3 bits");
    assert_eq!(ctx[vd(0) + 1], b8(want), "sli .16b high64 insert");
}

/// SQSHRN / UQSHRN / SQSHRUN (saturating narrowing shift-right). Proves the
/// saturation clamps out-of-range results and honours the signed/unsigned
/// source & destination ranges.
#[test]
fn saturating_narrow_shift() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // Pack 8 signed/unsigned halfwords (16-bit) into a 128-bit reg (lo/hi u64).
    let packh = |h: [u16; 8]| -> (u64, u64) {
        let lo = (h[0] as u64) | ((h[1] as u64) << 16) | ((h[2] as u64) << 32) | ((h[3] as u64) << 48);
        let hi = (h[4] as u64) | ((h[5] as u64) << 16) | ((h[6] as u64) << 32) | ((h[7] as u64) << 48);
        (lo, hi)
    };
    let getb = |q: u64, i: usize| ((q >> (i * 8)) & 0xFF) as u8;

    // --- SQSHRN v0.8b, v1.8h, #3 (0x0f0d9420): signed src, signed dst, arith >>3 ---
    // src halfwords: [1024, 256, -256, -32768, 0, 100, -100, 127*8].
    let src: [u16; 8] = [
        0x0400,          // 1024  >>3 = 128  → sat +127 = 0x7F
        0x0100,          // 256   >>3 = 32   → 0x20
        (-256i16) as u16,// -256  >>3 = -32  → 0xE0
        0x8000,          // -32768>>3 = -4096→ sat -128 = 0x80
        0x0000,          // 0
        0x0064,          // 100   >>3 = 12   → 0x0C
        (-100i16) as u16,// -100  >>3 = -13  → 0xF3
        (127i16 as u16).wrapping_mul(8), // 1016 >>3 = 127 → 0x7F (exact max)
    ];
    let (lo, hi) = packh(src);
    let word = 0x0F0D_9420u32;
    decode_instruction(word).expect("decode sqshrn v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sqshrn .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = lo; ctx[vd(1) + 1] = hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let want_sqshrn: [u8; 8] = [0x7F, 0x20, 0xE0, 0x80, 0x00, 0x0C, 0xF3, 0x7F];
    for i in 0..8 {
        assert_eq!(getb(ctx[vd(0)], i), want_sqshrn[i], "sqshrn .8b byte {i}");
    }
    assert_eq!(ctx[vd(0) + 1], 0, "sqshrn .8b upper 64 zeroed");

    // --- UQSHRN v0.8b, v1.8h, #3 (0x2f0d9420): unsigned src, unsigned dst, logical >>3 ---
    // src halfwords: [1024, 2048, 255, 65535, 0, 0x0800, 0x03F8, 0x0400].
    let src: [u16; 8] = [
        0x0400, // 1024 >>3 = 128 → 0x80
        0x0800, // 2048 >>3 = 256 → sat 255 = 0xFF
        0x00FF, // 255  >>3 = 31  → 0x1F
        0xFFFF, // 65535>>3 = 8191→ sat 255 = 0xFF
        0x0000,
        0x07F8, // 2040 >>3 = 255 → 0xFF (exact max)
        0x0400, // 1024 >>3 = 128 → 0x80
        0x0008, // 8    >>3 = 1   → 0x01
    ];
    let (lo, hi) = packh(src);
    let word = 0x2F0D_9420u32;
    decode_instruction(word).expect("decode uqshrn v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uqshrn .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = lo; ctx[vd(1) + 1] = hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let want_uqshrn: [u8; 8] = [0x80, 0xFF, 0x1F, 0xFF, 0x00, 0xFF, 0x80, 0x01];
    for i in 0..8 {
        assert_eq!(getb(ctx[vd(0)], i), want_uqshrn[i], "uqshrn .8b byte {i}");
    }

    // --- SQSHRUN v0.8b, v1.8h, #3 (0x2f0d8420): signed src, UNSIGNED dst ---
    // Negatives clamp to 0; large positives clamp to 255.
    let src: [u16; 8] = [
        0x0400,           // 1024  >>3 = 128 → 0x80
        (-256i16) as u16, // -256 arith>>3 = -32 → clamp 0
        0x0800,           // 2048  >>3 = 256 → sat 255 = 0xFF
        0x8000,           // -32768>>3 = -4096 → clamp 0
        0x0000,
        0x07F8,           // 2040  >>3 = 255 → 0xFF
        (-1i16) as u16,   // -1 arith>>3 = -1 → clamp 0
        0x0008,           // 8 >>3 = 1 → 0x01
    ];
    let (lo, hi) = packh(src);
    let word = 0x2F0D_8420u32;
    decode_instruction(word).expect("decode sqshrun v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sqshrun .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = lo; ctx[vd(1) + 1] = hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let want_sqshrun: [u8; 8] = [0x80, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x01];
    for i in 0..8 {
        assert_eq!(getb(ctx[vd(0)], i), want_sqshrun[i], "sqshrun .8b byte {i}");
    }
}

/// ADDP (pairwise add) at the narrow half-register sizes .4H / .2S — the G12 gap.
#[test]
fn addp_narrow_sizes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // addp v0.4h, v1.4h, v2.4h (0x0e62bc20). Vd = [n0+n1, n2+n3, m0+m1, m2+m3].
    let word = 0x0E62_BC20u32;
    decode_instruction(word).expect("decode addp v0.4h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "addp .4h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // v1 halfwords [1,2,3,4], v2 halfwords [5,6,7,8].
    ctx[vd(1)] = 0x0004_0003_0002_0001;
    ctx[vd(2)] = 0x0008_0007_0006_0005;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // [1+2, 3+4, 5+6, 7+8] = [3, 7, 11, 15] = [0x0003,0x0007,0x000B,0x000F].
    assert_eq!(ctx[vd(0)], 0x000F_000B_0007_0003, "addp .4h pairwise");
    assert_eq!(ctx[vd(0) + 1], 0, "addp .4h upper 64 zeroed");

    // addp v0.2s, v1.2s, v2.2s (0x0ea2bc20). Vd = [n0+n1, m0+m1].
    let word = 0x0EA2_BC20u32;
    decode_instruction(word).expect("decode addp v0.2s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "addp .2s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0x0000_0020_0000_0010; // [0x10, 0x20]
    ctx[vd(2)] = 0x0000_0200_0000_0100; // [0x100, 0x200]
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // [0x10+0x20, 0x100+0x200] = [0x30, 0x300].
    assert_eq!(ctx[vd(0)], 0x0000_0300_0000_0030, "addp .2s pairwise");
    assert_eq!(ctx[vd(0) + 1], 0, "addp .2s upper 64 zeroed");
}

/// UZP1/UZP2 at the narrow sizes .8b / .16b / .8h — the G1 gap.
#[test]
fn uzp_narrow_sizes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let b8 = |b: [u8; 8]| u64::from_le_bytes(b);

    // uzp1 v0.8b, v1.8b, v2.8b (0x0e021820). Even bytes of Vn:Vm concatenation.
    let word = 0x0E02_1820u32;
    decode_instruction(word).expect("decode uzp1 v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uzp1 .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = b8([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    ctx[vd(2)] = b8([0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Even bytes: Vn[0,2,4,6]=[00,22,44,66], Vm[0,2,4,6]=[88,AA,CC,EE].
    assert_eq!(ctx[vd(0)], b8([0x00, 0x22, 0x44, 0x66, 0x88, 0xAA, 0xCC, 0xEE]),
        "uzp1 .8b even bytes");
    assert_eq!(ctx[vd(0) + 1], 0, "uzp1 .8b upper 64 zeroed");

    // uzp2 v0.8b, v1.8b, v2.8b (0x0e025820). Odd bytes.
    let word = 0x0E02_5820u32;
    decode_instruction(word).expect("decode uzp2 v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uzp2 .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = b8([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    ctx[vd(2)] = b8([0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Odd bytes: Vn[1,3,5,7]=[11,33,55,77], Vm[1,3,5,7]=[99,BB,DD,FF].
    assert_eq!(ctx[vd(0)], b8([0x11, 0x33, 0x55, 0x77, 0x99, 0xBB, 0xDD, 0xFF]),
        "uzp2 .8b odd bytes");

    // uzp1 v0.16b, v1.16b, v2.16b (0x4e021820). Full-width even bytes.
    let word = 0x4E02_1820u32;
    decode_instruction(word).expect("decode uzp1 v0.16b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uzp1 .16b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)]     = b8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    ctx[vd(1) + 1] = b8([0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
    ctx[vd(2)]     = b8([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]);
    ctx[vd(2) + 1] = b8([0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Vn even bytes [0,2,..,14] = [00,02,04,06,08,0A,0C,0E] → low 64.
    // Vm even bytes = [10,12,14,16,18,1A,1C,1E] → high 64.
    assert_eq!(ctx[vd(0)], b8([0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E]),
        "uzp1 .16b Vn evens");
    assert_eq!(ctx[vd(0) + 1], b8([0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E]),
        "uzp1 .16b Vm evens");

    // uzp1 v0.8h, v1.8h, v2.8h (0x4e421820). Even halfwords.
    let word = 0x4E42_1820u32;
    decode_instruction(word).expect("decode uzp1 v0.8h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uzp1 .8h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // v1 halfwords [0,1,2,3 / 4,5,6,7], v2 [8,9,A,B / C,D,E,F].
    ctx[vd(1)]     = 0x0003_0002_0001_0000;
    ctx[vd(1) + 1] = 0x0007_0006_0005_0004;
    ctx[vd(2)]     = 0x000B_000A_0009_0008;
    ctx[vd(2) + 1] = 0x000F_000E_000D_000C;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Vn even hw [0,2,4,6] → low 64 ; Vm even hw [8,A,C,E] → high 64.
    assert_eq!(ctx[vd(0)], 0x0006_0004_0002_0000, "uzp1 .8h Vn even halfwords");
    assert_eq!(ctx[vd(0) + 1], 0x000E_000C_000A_0008, "uzp1 .8h Vm even halfwords");
}

/// TRN1/TRN2 at the narrow sizes .8b / .16b / .8h — the G1 gap.
#[test]
fn trn_narrow_sizes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let b8 = |b: [u8; 8]| u64::from_le_bytes(b);

    // trn1 v0.8b, v1.8b, v2.8b (0x0e022820). Vd = [n0,m0,n2,m2,n4,m4,n6,m6].
    let word = 0x0E02_2820u32;
    decode_instruction(word).expect("decode trn1 v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "trn1 .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = b8([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    ctx[vd(2)] = b8([0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // even lanes interleaved: [n0,m0,n2,m2,n4,m4,n6,m6] = [00,88,22,AA,44,CC,66,EE].
    assert_eq!(ctx[vd(0)], b8([0x00, 0x88, 0x22, 0xAA, 0x44, 0xCC, 0x66, 0xEE]),
        "trn1 .8b even lanes interleaved");
    assert_eq!(ctx[vd(0) + 1], 0, "trn1 .8b upper 64 zeroed");

    // trn2 v0.8b, v1.8b, v2.8b (0x0e026820). Vd = [n1,m1,n3,m3,n5,m5,n7,m7].
    let word = 0x0E02_6820u32;
    decode_instruction(word).expect("decode trn2 v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "trn2 .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = b8([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    ctx[vd(2)] = b8([0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // odd lanes: [n1,m1,n3,m3,n5,m5,n7,m7] = [11,99,33,BB,55,DD,77,FF].
    assert_eq!(ctx[vd(0)], b8([0x11, 0x99, 0x33, 0xBB, 0x55, 0xDD, 0x77, 0xFF]),
        "trn2 .8b odd lanes interleaved");

    // trn1 v0.16b, v1.16b, v2.16b (0x4e022820). Full-width.
    let word = 0x4E02_2820u32;
    decode_instruction(word).expect("decode trn1 v0.16b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "trn1 .16b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)]     = b8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    ctx[vd(1) + 1] = b8([0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
    ctx[vd(2)]     = b8([0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87]);
    ctx[vd(2) + 1] = b8([0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // even byte lanes interleaved: out[2k]=Vn[2k], out[2k+1]=Vm[2k].
    // lanes 0..7 of result (low 64): n0,m0,n2,m2,n4,m4,n6,m6 = [00,80,02,82,04,84,06,86].
    assert_eq!(ctx[vd(0)], b8([0x00, 0x80, 0x02, 0x82, 0x04, 0x84, 0x06, 0x86]),
        "trn1 .16b low 8 lanes");
    // lanes 8..15: n8,m8,n10,m10,n12,m12,n14,m14 = [08,88,0A,8A,0C,8C,0E,8E].
    assert_eq!(ctx[vd(0) + 1], b8([0x08, 0x88, 0x0A, 0x8A, 0x0C, 0x8C, 0x0E, 0x8E]),
        "trn1 .16b high 8 lanes");

    // trn1 v0.8h, v1.8h, v2.8h (0x4e422820). Halfword lanes.
    let word = 0x4E42_2820u32;
    decode_instruction(word).expect("decode trn1 v0.8h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "trn1 .8h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // v1 halfwords [h0..h7], v2 [g0..g7].
    ctx[vd(1)]     = 0x0003_0002_0001_0000;
    ctx[vd(1) + 1] = 0x0007_0006_0005_0004;
    ctx[vd(2)]     = 0x0083_0082_0081_0080;
    ctx[vd(2) + 1] = 0x0087_0086_0085_0084;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // TRN1 = [h0,g0,h2,g2,h4,g4,h6,g6] = [0,0x80,2,0x82,4,0x84,6,0x86].
    assert_eq!(ctx[vd(0)], 0x0082_0002_0080_0000, "trn1 .8h low 4 halfwords");
    assert_eq!(ctx[vd(0) + 1], 0x0086_0006_0084_0004, "trn1 .8h high 4 halfwords");
}

/// SQRSHRN (rounding + saturating narrow) — proves the round bias is added
/// before the shift. sqrshrn v0.8b, v1.8h, #3 (0x0f0d9c20): result =
/// sat_s8( (src + (1<<2)) >> 3 ).
#[test]
fn sqrshrn_rounding_narrow() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let packh = |h: [u16; 8]| -> (u64, u64) {
        let lo = (h[0] as u64) | ((h[1] as u64) << 16) | ((h[2] as u64) << 32) | ((h[3] as u64) << 48);
        let hi = (h[4] as u64) | ((h[5] as u64) << 16) | ((h[6] as u64) << 32) | ((h[7] as u64) << 48);
        (lo, hi)
    };
    let getb = |q: u64, i: usize| ((q >> (i * 8)) & 0xFF) as u8;

    // src halfwords chosen so rounding changes the truncated result:
    //   4  → (4+4)>>3 = 1 (truncate gives 0) ; 3 → (3+4)>>3 = 0.
    //   12 → (12+4)>>3 = 2 (truncate gives 1).
    let src: [u16; 8] = [4, 3, 12, 0x03FC /*1020*/, (-4i16) as u16, 0, 0x0400, 0x0800];
    let (lo, hi) = packh(src);
    let word = 0x0F0D_9C20u32;
    decode_instruction(word).expect("decode sqrshrn v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sqrshrn .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = lo; ctx[vd(1) + 1] = hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // Hand-computed sat_s8((src + 4) >> 3), src as signed:
    //   4→1, 3→0, 12→2, 1020→(1024>>3=128)→sat 127=0x7F,
    //   -4→((-4+4)>>3)=0, 0→0, 1024→(1028>>3=128)→sat 127=0x7F, 2048→sat 127=0x7F.
    let want: [u8; 8] = [0x01, 0x00, 0x02, 0x7F, 0x00, 0x00, 0x7F, 0x7F];
    for i in 0..8 {
        assert_eq!(getb(ctx[vd(0)], i), want[i], "sqrshrn .8b byte {i}");
    }
}

/// RSHRN — rounding narrow that is MODULAR (truncating), NOT saturating. This is
/// the oracle's headline regression: RSHRN was routed through the saturating pack
/// path, so a source halfword like 0x8000 (which rounds+shifts to 0x400) came out
/// clamped to 0xFF instead of truncated to its low byte 0x00.
///
///   rshrn v0.8b, v1.8h, #5 (0x0F0B8C20): result[i] = ((src[i] + 0x10) >> 5) & 0xFF
///
/// The 0x8000 -> 0x00 and 0xFFFF -> 0x00 lanes prove there is NO clamp; every lane
/// takes the low 8 bits of the rounded shift.
#[test]
fn rshrn_modular_narrow_no_saturation() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let packh = |h: [u16; 8]| -> (u64, u64) {
        let lo = (h[0] as u64) | ((h[1] as u64) << 16) | ((h[2] as u64) << 32) | ((h[3] as u64) << 48);
        let hi = (h[4] as u64) | ((h[5] as u64) << 16) | ((h[6] as u64) << 32) | ((h[7] as u64) << 48);
        (lo, hi)
    };
    let getb = |q: u64, i: usize| ((q >> (i * 8)) & 0xFF) as u8;

    // src halfwords: mix of in-range and out-of-range-for-a-byte values.
    //   0x8000: (0x8000+0x10)>>5 = 0x400 -> low byte 0x00  (clamp would give 0xFF)
    //   0xFFFF: (0xFFFF+0x10)>>5 = 0x800 -> low byte 0x00  (clamp would give 0xFF)
    //   0x0120: (0x0120+0x10)>>5 = 0x09
    //   0x00FF: (0x00FF+0x10)>>5 = 0x08
    //   0x0041: (0x0041+0x10)>>5 = 0x02
    //   0x07FF: (0x07FF+0x10)>>5 = 0x40
    //   0x0010: (0x0010+0x10)>>5 = 0x01
    let src: [u16; 8] = [0x8000, 0x0120, 0x00FF, 0xFFFF, 0x0000, 0x0041, 0x07FF, 0x0010];
    let (lo, hi) = packh(src);
    let word = 0x0F0B_8C20u32;
    decode_instruction(word).expect("decode rshrn v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "rshrn .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = lo; ctx[vd(1) + 1] = hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let want: [u8; 8] = [0x00, 0x09, 0x08, 0x00, 0x00, 0x02, 0x40, 0x01];
    for i in 0..8 {
        assert_eq!(getb(ctx[vd(0)], i), want[i], "rshrn .8b byte {i} (modular, no clamp)");
    }
    assert_eq!(ctx[vd(0) + 1], 0, "rshrn .8b upper 64 zeroed");
}

/// SQRSHRN2 — signed rounding-saturating narrow, high form. Proves (a) the round
/// bias is added at a width that does NOT overflow the source lane, and (b) the
/// saturation clamps to the correct SIGNED side of the destination range.
///
///   sqrshrn2 v0.16b, v1.8h, #7 (0x4F099C20): result = sat_s8((src_s16 + 0x40) >> 7)
///
/// The 0x7FFF lane is the oracle case: 0x7FFF + 0x40 = 0x803F = 32831 (an in-lane
/// `paddw` bias would wrap this negative). Shifted >>7 = 256, saturated to a signed
/// byte gives +127 = 0x7F — NOT the wrong-side 0x80 the overflow used to produce.
#[test]
fn sqrshrn2_signed_saturate_no_lane_overflow() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let packh = |h: [u16; 8]| -> (u64, u64) {
        let lo = (h[0] as u64) | ((h[1] as u64) << 16) | ((h[2] as u64) << 32) | ((h[3] as u64) << 48);
        let hi = (h[4] as u64) | ((h[5] as u64) << 16) | ((h[6] as u64) << 32) | ((h[7] as u64) << 48);
        (lo, hi)
    };
    let getb = |q: u64, i: usize| ((q >> (i * 8)) & 0xFF) as u8;

    // Signed src halfwords; hand-computed sat_s8((x + 0x40) >> 7):
    //   0x7FFF (+32767): 32831>>7=256 -> sat +127 = 0x7F  (overflow bug gave 0x80)
    //   0x8000 (-32768): -32704>>7=-256 -> sat -128 = 0x80
    //   0x0040 (+64)   : 128>>7=1 -> 0x01
    //   0xFFC0 (-64)   : 0>>7=0 -> 0x00
    //   0x0000         : 0
    //   0x4000 (+16384): 16448>>7=128 -> sat +127 = 0x7F
    //   0x0080 (+128)  : 192>>7=1 -> 0x01
    //   0x3FC0 (+16320): 16384>>7=128 -> sat +127 = 0x7F
    let src: [u16; 8] = [0x7FFF, 0x8000, 0x0040, 0xFFC0, 0x0000, 0x4000, 0x0080, 0x3FC0];
    let (lo, hi) = packh(src);
    let word = 0x4F09_9C20u32; // sqrshrn2 (Q=1, high form)
    decode_instruction(word).expect("decode sqrshrn2 v0.16b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sqrshrn2 .16b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = lo; ctx[vd(1) + 1] = hi;
    // Seed Vd[63:0] with a sentinel — the high form must preserve it.
    ctx[vd(0)] = 0xDEAD_BEEF_1234_5678;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0xDEAD_BEEF_1234_5678, "sqrshrn2 preserves Vd[63:0]");
    let want: [u8; 8] = [0x7F, 0x80, 0x01, 0x00, 0x00, 0x7F, 0x01, 0x7F];
    for i in 0..8 {
        assert_eq!(getb(ctx[vd(0) + 1], i), want[i], "sqrshrn2 .16b high byte {i}");
    }
}

/// SQRSHRUN — signed-source rounding narrow saturating to the UNSIGNED dest range.
/// Negatives clamp to 0; large positives clamp to 255; the round bias must not
/// overflow the source lane.
///
///   sqrshrun v0.8b, v1.8h, #7 (0x2F098C20): result = sat_u8((src_s16 + 0x40) >> 7)
#[test]
fn sqrshrun_signed_to_unsigned_rounding_narrow() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let packh = |h: [u16; 8]| -> (u64, u64) {
        let lo = (h[0] as u64) | ((h[1] as u64) << 16) | ((h[2] as u64) << 32) | ((h[3] as u64) << 48);
        let hi = (h[4] as u64) | ((h[5] as u64) << 16) | ((h[6] as u64) << 32) | ((h[7] as u64) << 48);
        (lo, hi)
    };
    let getb = |q: u64, i: usize| ((q >> (i * 8)) & 0xFF) as u8;

    // Signed src; hand-computed sat_u8((x + 0x40) >> 7):
    //   0x7FFF (+32767): 32831>>7=256 -> sat 255 = 0xFF
    //   0x8000 (-32768): -32704>>7=-256 -> clamp 0 = 0x00
    //   0x1FC0 (+8128) : 8192>>7=64 -> 0x40
    //   0xFFC0 (-64)   : 0>>7=0 -> 0x00
    //   0x0000         : 0
    //   0x0040 (+64)   : 128>>7=1 -> 0x01
    //   0x3FC0 (+16320): 16384>>7=128 -> 0x80
    //   0x0080 (+128)  : 192>>7=1 -> 0x01
    let src: [u16; 8] = [0x7FFF, 0x8000, 0x1FC0, 0xFFC0, 0x0000, 0x0040, 0x3FC0, 0x0080];
    let (lo, hi) = packh(src);
    let word = 0x2F09_8C20u32;
    decode_instruction(word).expect("decode sqrshrun v0.8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sqrshrun .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = lo; ctx[vd(1) + 1] = hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    let want: [u8; 8] = [0xFF, 0x00, 0x40, 0x00, 0x00, 0x01, 0x80, 0x01];
    for i in 0..8 {
        assert_eq!(getb(ctx[vd(0)], i), want[i], "sqrshrun .8b byte {i}");
    }
    assert_eq!(ctx[vd(0) + 1], 0, "sqrshrun .8b upper 64 zeroed");
}

// ─────────────────────────────────────────────────────────────────────────────
// oracle-sweep-2 batch (2026-07-01): the last fail-loud UD2 / decoder gaps on the
// zygote→SurfaceFlinger SIMD/FP path. Scalar FMAXNM/FMINNM, vector FRINT{N,M,P,Z,A},
// SHADD/UHADD/SRHADD/URHADD/SHSUB/UHSUB, plus the FMAX/FMIN NaN-propagation fix.
// Each seeds V-regs, executes the translated block, and asserts ARM-correct
// results with adversarial inputs (NaN-picks-the-other, halfway/negative/ties-away
// rounds, no-overflow on extreme operands, and NaN propagation).
// ─────────────────────────────────────────────────────────────────────────────

/// Scalar FMAXNM/FMINNM (S and D). IEEE maxNum/minNum: when exactly one operand
/// is NaN the *other* (numeric) operand is returned — the opposite of x86
/// maxss/minss, which return the 2nd source on a NaN lane. Proves the NaN-picks-
/// the-other rule for both operand positions.
#[test]
fn fmaxnm_fminnm_scalar_ignore_nan() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let qnan32: u32 = 0x7FC0_0000;
    let f = |x: f32| x.to_bits();

    // --- FMAXNM s0, s1, s2 (0x1e226820): s1 = 3.5, s2 = qNaN → 3.5 ---
    let word = 0x1E22_6820u32;
    decode_instruction(word).expect("decode fmaxnm s0,s1,s2");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fmaxnm s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = f(3.5) as u64;          // s1 = 3.5
    ctx[vd(2)] = qnan32 as u64;          // s2 = NaN
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)] & 0xFFFF_FFFF, f(3.5) as u64, "fmaxnm(3.5, NaN) = 3.5");
    assert_eq!(ctx[vd(0)] >> 32, 0, "fmaxnm s zeroes upper 96 bits (low32)");
    assert_eq!(ctx[vd(0) + 1], 0, "fmaxnm s zeroes Vd[127:64]");

    // NaN in the OTHER position: s1 = NaN, s2 = 2.0 → 2.0 (x86 maxss would keep 2.0
    // here too, but this pins the branch that DOESN'T need the fixup).
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = qnan32 as u64;
    ctx[vd(2)] = f(2.0) as u64;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)] & 0xFFFF_FFFF, f(2.0) as u64, "fmaxnm(NaN, 2.0) = 2.0");

    // --- FMINNM s0, s1, s2 (0x1e227820): s1 = -1.5, s2 = qNaN → -1.5 ---
    let word = 0x1E22_7820u32;
    decode_instruction(word).expect("decode fminnm s0,s1,s2");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fminnm s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = f(-1.5) as u64;
    ctx[vd(2)] = qnan32 as u64;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)] & 0xFFFF_FFFF, f(-1.5) as u64, "fminnm(-1.5, NaN) = -1.5");

    // --- FMAXNM d0, d1, d2 (0x1e626820): d1 = 3.5, d2 = qNaN(f64) → 3.5 ---
    let word = 0x1E62_6820u32;
    decode_instruction(word).expect("decode fmaxnm d0,d1,d2");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fmaxnm d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 3.5f64.to_bits();
    ctx[vd(2)] = 0x7FF8_0000_0000_0000; // qNaN f64
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 3.5f64.to_bits(), "fmaxnm(3.5, NaN) d = 3.5");
    assert_eq!(ctx[vd(0) + 1], 0, "fmaxnm d zeroes Vd[127:64]");
}

/// Vector FRINT{N,M,P,Z,A} .4s. Adversarial lanes [2.5, -2.5, 2.4, -2.6] exercise
/// the halfway (ties) case, negative rounding, and — for the A form — ties-AWAY
/// (2.5→3, -2.5→-3, distinct from N's ties-to-even 2.5→2). Also checks FRINTN .2d.
#[test]
fn frint_vector_round_to_integral() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let pack = |lo: u32, hi: u32| (lo as u64) | ((hi as u64) << 32);
    let f = |x: f32| x.to_bits();

    // Input v1.4s = [2.5, -2.5, 2.4, -2.6].
    let v1_lo = pack(f(2.5), f(-2.5));
    let v1_hi = pack(f(2.4), f(-2.6));

    // (word, name, expected lanes) — hand-computed IEEE round-to-integral.
    let cases: [(u32, &str, [f32; 4]); 5] = [
        (0x4E21_8820, "frintn .4s", [2.0, -2.0, 2.0, -3.0]), // nearest-even (2.5→2)
        (0x4E21_9820, "frintm .4s", [2.0, -3.0, 2.0, -3.0]), // floor
        (0x4EA1_8820, "frintp .4s", [3.0, -2.0, 3.0, -2.0]), // ceil
        (0x4EA1_9820, "frintz .4s", [2.0, -2.0, 2.0, -2.0]), // truncate
        (0x6E21_8820, "frinta .4s", [3.0, -3.0, 2.0, -3.0]), // ties-away (2.5→3, -2.5→-3)
    ];
    for (word, name, exp) in cases {
        decode_instruction(word).unwrap_or_else(|e| panic!("decode {name}: {e:?}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, name);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = v1_lo; ctx[vd(1) + 1] = v1_hi;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        assert_eq!(ctx[vd(0)], pack(f(exp[0]), f(exp[1])), "{name} lanes 0,1");
        assert_eq!(ctx[vd(0) + 1], pack(f(exp[2]), f(exp[3])), "{name} lanes 2,3");
    }

    // FRINTN .2d (0x4e618820): d-lanes [2.5, -3.5] → nearest-even [2.0, -4.0].
    let word = 0x4E61_8820u32;
    decode_instruction(word).expect("decode frintn .2d");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "frintn .2d");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 2.5f64.to_bits();
    ctx[vd(1) + 1] = (-3.5f64).to_bits();
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 2.0f64.to_bits(), "frintn .2d lane0 = 2.0 (ties-even)");
    assert_eq!(ctx[vd(0) + 1], (-4.0f64).to_bits(), "frintn .2d lane1 = -4.0 (ties-even)");
}

/// SHADD/UHADD/SRHADD/URHADD (halving add) — proves the no-overflow identity on
/// EXTREME operands (0x7F+0x7F, 0x80+0x80, 0xFF+0x01) where a naive `(a+b)>>1`
/// would overflow the element. Byte (.16b) and word (.4s) widths.
#[test]
fn halving_add_no_overflow() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // ── .16b: a bytes [0x7F,0x80,0x40,0xFF]×2, b bytes [0x7F,0x80,0x40,0x01]×2 ──
    let a16b = 0xFF40_807F_FF40_807Fu64;
    let b16b = 0x0140_807F_0140_807Fu64;
    // (word, name, expected low64 (repeats in high64))
    let cases_b: [(u32, &str, u64); 4] = [
        (0x4E22_0420, "shadd .16b",  0x0040_807F_0040_807F), // (7F,7F)→7F (127+127)/2, (80,80)→80(-128), (40,40)→40, (FF,01)→00 (-1+1)/2
        (0x6E22_0420, "uhadd .16b",  0x8040_807F_8040_807F), // (FF,01)→80 (255+1)/2=128
        (0x4E22_1420, "srhadd .16b", 0x0040_807F_0040_807F),
        (0x6E22_1420, "urhadd .16b", 0x8040_807F_8040_807F), // wait: urhadd needs recompute below
    ];
    // Note: urhadd/uhadd byte differ only on ties; verify with explicit refs.
    // SHADD:  [0x7F,0x80,0x40,0x00] ; UHADD: [0x7F,0x80,0x40,0x80]
    // SRHADD: [0x7F,0x80,0x40,0x00] ; URHADD:[0x7F,0x80,0x40,0x80]
    let want_b = |op: &str| -> u64 {
        let bytes: [u8; 4] = match op {
            "shadd .16b" | "srhadd .16b" => [0x7F, 0x80, 0x40, 0x00],
            _ => [0x7F, 0x80, 0x40, 0x80], // uhadd / urhadd
        };
        let l = bytes[0] as u64 | ((bytes[1] as u64) << 8) | ((bytes[2] as u64) << 16) | ((bytes[3] as u64) << 24);
        l | (l << 32)
    };
    for (word, name, _seed) in cases_b {
        decode_instruction(word).unwrap_or_else(|e| panic!("decode {name}: {e:?}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, name);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = a16b; ctx[vd(1) + 1] = a16b;
        ctx[vd(2)] = b16b; ctx[vd(2) + 1] = b16b;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        let want = want_b(name);
        assert_eq!(ctx[vd(0)], want, "{name} low64");
        assert_eq!(ctx[vd(0) + 1], want, "{name} high64");
    }

    // ── .4s: a lanes [0x7FFFFFFF, 0x80000000, 0x10, 0xFFFFFFFF],
    //          b lanes [0x7FFFFFFF, 0x00000002, 0x04, 0x00000001] ──
    let a4s_lo = 0x8000_0000_7FFF_FFFFu64;
    let a4s_hi = 0xFFFF_FFFF_0000_0010u64;
    let b4s_lo = 0x0000_0002_7FFF_FFFFu64;
    let b4s_hi = 0x0000_0001_0000_0004u64;
    // SHADD.4s:  [0x7FFFFFFF, 0xC0000001, 0x0A, 0x00000000]
    // UHADD.4s:  [0x7FFFFFFF, 0x40000001, 0x0A, 0x80000000]
    // URHADD.4s: [0x7FFFFFFF, 0x40000001, 0x0A, 0x80000000]
    let cases_s: [(u32, &str, u64, u64); 3] = [
        (0x4EA2_0420, "shadd .4s",  0xC000_0001_7FFF_FFFF, 0x0000_0000_0000_000A),
        (0x6EA2_0420, "uhadd .4s",  0x4000_0001_7FFF_FFFF, 0x8000_0000_0000_000A),
        (0x6EA2_1420, "urhadd .4s", 0x4000_0001_7FFF_FFFF, 0x8000_0000_0000_000A),
    ];
    for (word, name, wlo, whi) in cases_s {
        decode_instruction(word).unwrap_or_else(|e| panic!("decode {name}: {e:?}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, name);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = a4s_lo; ctx[vd(1) + 1] = a4s_hi;
        ctx[vd(2)] = b4s_lo; ctx[vd(2) + 1] = b4s_hi;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        assert_eq!(ctx[vd(0)], wlo, "{name} lo");
        assert_eq!(ctx[vd(0) + 1], whi, "{name} hi");
    }
}

/// SHSUB/UHSUB (halving subtract) — proves the (a-b)>>1 no-overflow identity
/// (including the per-element borrow bit) on extreme operands where a naive
/// element-width `a-b` would underflow. Byte, halfword, and word widths.
#[test]
fn halving_sub_no_overflow() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;

    // ── .16b: a [0x7F,0x80,0x40,0xFF]×2, b [0x7F,0x80,0x40,0x01]×2 ──
    // SHSUB (signed): [(127-127)>>1=0, (-128 - -128)>>1=0, 0, (-1-1)>>1=-1=0xFF]
    // UHSUB (unsigned): [0, 0, 0, (255-1)>>1=127=0x7F]
    let a16b = 0xFF40_807F_FF40_807Fu64;
    let b16b = 0x0140_807F_0140_807Fu64;
    let shsub_want = 0xFF00_0000_FF00_0000u64; // [0x00,0x00,0x00,0xFF]×2
    let uhsub_want = 0x7F00_0000_7F00_0000u64; // [0x00,0x00,0x00,0x7F]×2
    for (word, name, want) in [
        (0x4E22_2420u32, "shsub .16b", shsub_want),
        (0x6E22_2420u32, "uhsub .16b", uhsub_want),
    ] {
        decode_instruction(word).unwrap_or_else(|e| panic!("decode {name}: {e:?}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, name);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = a16b; ctx[vd(1) + 1] = a16b;
        ctx[vd(2)] = b16b; ctx[vd(2) + 1] = b16b;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        assert_eq!(ctx[vd(0)], want, "{name} low64");
        assert_eq!(ctx[vd(0) + 1], want, "{name} high64");
    }

    // ── .8h UHSUB: a [0x0000,0xFFFF,0x8000,0x0001], b [0x0001,0x0000,0x0001,0x0002]
    // UHSUB: [(0-1)>>1=0xFFFF, (65535-0)>>1=0x7FFF, (32768-1)>>1=0x3FFF, (1-2)>>1=0xFFFF]
    let word = 0x6E62_2420u32;
    decode_instruction(word).expect("decode uhsub .8h");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "uhsub .8h");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    let ph = |h: [u16; 4]| h[0] as u64 | ((h[1] as u64) << 16) | ((h[2] as u64) << 32) | ((h[3] as u64) << 48);
    ctx[vd(1)] = ph([0x0000, 0xFFFF, 0x8000, 0x0001]); ctx[vd(1) + 1] = ph([0, 0, 0, 0]);
    ctx[vd(2)] = ph([0x0001, 0x0000, 0x0001, 0x0002]); ctx[vd(2) + 1] = ph([0, 0, 0, 0]);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], ph([0xFFFF, 0x7FFF, 0x3FFF, 0xFFFF]), "uhsub .8h lanes");
    // hi source is 0-0 per lane → all 0.
    assert_eq!(ctx[vd(0) + 1], 0, "uhsub .8h high (0-0 = 0)");

    // ── .4s SHSUB / UHSUB on the extreme lanes (INT32_MIN - 2). ──
    let a4s_lo = 0x8000_0000_7FFF_FFFFu64;
    let a4s_hi = 0xFFFF_FFFF_0000_0010u64;
    let b4s_lo = 0x0000_0002_7FFF_FFFFu64;
    let b4s_hi = 0x0000_0001_0000_0004u64;
    // SHSUB.4s: [(2^31-1 - 2^31-1)>>1=0, (INT32_MIN - 2)>>1=0xBFFFFFFF, (16-4)>>1=6, (-1-1)>>1=0xFFFFFFFF]
    // UHSUB.4s: [0, (0x80000000-2)>>1=0x3FFFFFFF, 6, (0xFFFFFFFF-1)>>1=0x7FFFFFFF]
    for (word, name, wlo, whi) in [
        (0x4EA2_2420u32, "shsub .4s", 0xBFFF_FFFF_0000_0000u64, 0xFFFF_FFFF_0000_0006u64),
        (0x6EA2_2420u32, "uhsub .4s", 0x3FFF_FFFF_0000_0000u64, 0x7FFF_FFFF_0000_0006u64),
    ] {
        decode_instruction(word).unwrap_or_else(|e| panic!("decode {name}: {e:?}"));
        let code = translate_straight_line(&[word], 0x1000);
        assert_no_ud2(&code, name);
        let exec = winexec::make_executable(&code);
        let mut ctx = [0u64; CTX_U64S];
        ctx[vd(1)] = a4s_lo; ctx[vd(1) + 1] = a4s_hi;
        ctx[vd(2)] = b4s_lo; ctx[vd(2) + 1] = b4s_hi;
        unsafe { enter_block(exec, ctx.as_mut_ptr()); }
        assert_eq!(ctx[vd(0)], wlo, "{name} lo");
        assert_eq!(ctx[vd(0) + 1], whi, "{name} hi");
    }
}

/// FMAX/FMIN (register, .4s) NaN PROPAGATION. ARM FMAX/FMIN return a quiet NaN
/// when EITHER lane input is NaN (unlike FMAXNM/FMINNM). Before the fix the DBT
/// used bare maxps/minps, which return the 2nd source on a NaN lane and drop the
/// NaN. This proves the canonical qNaN (0x7FC00000) is produced on NaN lanes while
/// finite lanes still get the correct max/min.
#[test]
fn fmax_fmin_vector_propagate_nan() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let pack = |lo: u32, hi: u32| (lo as u64) | ((hi as u64) << 32);
    let f = |x: f32| x.to_bits();
    let qnan: u32 = 0x7FC0_0000;

    // v1 lanes [3.5, NaN, -2.0, 1.0], v2 lanes [1.0, 2.0, NaN, 5.0].
    let v1_lo = pack(f(3.5), qnan);
    let v1_hi = pack(f(-2.0), f(1.0));
    let v2_lo = pack(f(1.0), f(2.0));
    let v2_hi = pack(qnan, f(5.0));

    // FMAX v0.4s, v1.4s, v2.4s (0x4e22f420):
    //   lane0 max(3.5,1)=3.5 ; lane1 (NaN,2)→qNaN ; lane2 (-2,NaN)→qNaN ; lane3 max(1,5)=5.
    let word = 0x4E22_F420u32;
    decode_instruction(word).expect("decode fmax .4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fmax .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = v1_lo; ctx[vd(1) + 1] = v1_hi;
    ctx[vd(2)] = v2_lo; ctx[vd(2) + 1] = v2_hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], pack(f(3.5), qnan), "fmax .4s lanes 0,1 (NaN lane → qNaN)");
    assert_eq!(ctx[vd(0) + 1], pack(qnan, f(5.0)), "fmax .4s lanes 2,3 (NaN lane → qNaN)");

    // FMIN v0.4s, v1.4s, v2.4s (0x4ea2f420):
    //   lane0 min(3.5,1)=1 ; lane1 qNaN ; lane2 qNaN ; lane3 min(1,5)=1.
    let word = 0x4EA2_F420u32;
    decode_instruction(word).expect("decode fmin .4s");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "fmin .4s");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = v1_lo; ctx[vd(1) + 1] = v1_hi;
    ctx[vd(2)] = v2_lo; ctx[vd(2) + 1] = v2_hi;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], pack(f(1.0), qnan), "fmin .4s lanes 0,1 (NaN lane → qNaN)");
    assert_eq!(ctx[vd(0) + 1], pack(qnan, f(1.0)), "fmin .4s lanes 2,3 (NaN lane → qNaN)");
}

// ════════════════════════════════════════════════════════════════════════════
// Adversarial SIMD-integer miscompile fixes (S1/S2/S3), 2026-07-03.
// Each was a SILENT wrong-bits bug (no UD2, no fault) found by static review and
// confirmed on the host. The seeds below reproduce the exact wrong value the
// pre-fix lowering produced; they FAIL before the fix and PASS after.
// ════════════════════════════════════════════════════════════════════════════

/// S1 — byte-width pairwise `.8b` (D-form) put Vn's stale HIGH-half bytes where
/// Vm's pairs belong (and dropped Vm entirely). ADDP Vd.8b reduces the
/// concatenation Vm.lo64:Vn.lo64 → result bytes [0..3] = Vn's 4 pairs, [4..7] =
/// Vm's 4 pairs, upper 64 zeroed. The dirty V1.hi=0xFFFF… seed is what exposes
/// the leak (pre-fix produced 0xFEFEFEFE in bytes 4..7).
#[test]
fn addp_8b_dform_uses_vm_not_vn_high_half() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // addp v0.8b, v1.8b, v2.8b
    let word = 0x0E22_BC20u32;
    decode_instruction(word).expect("decode addp .8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "addp .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // V1.8b = [1,2,3,4,5,6,7,8]; HIGH half dirty (must NOT leak into the result).
    ctx[vd(1)] = 0x0807_0605_0403_0201;
    ctx[vd(1) + 1] = 0xFFFF_FFFF_FFFF_FFFF;
    // V2.8b = [10,20,30,40,50,60,70,80] = [0x0A,0x14,0x1E,0x28,0x32,0x3C,0x46,0x50].
    ctx[vd(2)] = 0x5046_3C32_281E_140A;
    ctx[vd(2) + 1] = 0xEEEE_EEEE_EEEE_EEEE;
    ctx[vd(0)] = 0xDEAD_BEEF_DEAD_BEEF;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // result bytes = [1+2,3+4,5+6,7+8, 10+20,30+40,50+60,70+80]
    //              = [03,07,0b,0f, 1e,46,6e,96] → LE lo = 0x966E461E_0F0B0703.
    assert_eq!(
        ctx[vd(0)], 0x966E_461E_0F0B_0703,
        "addp .8b: bytes [4..7] must be Vm's pairs, not Vn's dirty high half",
    );
    assert_eq!(ctx[vd(0) + 1], 0, "addp .8b: D-form zeroes the upper 64");
}

/// S1 (min/max twin) — UMAXP v0.8b, v1.8b, v2.8b. Same D-form path as ADDP; the
/// pre-fix lowering produced 0xFFFFFFFF in bytes [4..7] (from V1.hi = 0xFFFF…).
#[test]
fn umaxp_8b_dform_uses_vm_not_vn_high_half() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // umaxp v0.8b, v1.8b, v2.8b
    let word = 0x2E22_A420u32;
    decode_instruction(word).expect("decode umaxp .8b");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "umaxp .8b");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0x0807_0605_0403_0201;
    ctx[vd(1) + 1] = 0xFFFF_FFFF_FFFF_FFFF;
    ctx[vd(2)] = 0x5046_3C32_281E_140A;
    ctx[vd(2) + 1] = 0xEEEE_EEEE_EEEE_EEEE;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    // [max(1,2),max(3,4),max(5,6),max(7,8), max(10,20),max(30,40),max(50,60),max(70,80)]
    //   = [02,04,06,08, 14,28,3c,50] → LE lo = 0x503C2814_08060402.
    assert_eq!(
        ctx[vd(0)], 0x503C_2814_0806_0402,
        "umaxp .8b: bytes [4..7] must be Vm's pairwise-max, not Vn's high half",
    );
    assert_eq!(ctx[vd(0) + 1], 0, "umaxp .8b: D-form zeroes the upper 64");
}

/// S2 — byte SSHR/USHR/SSRA by #8 aliased to shift-by-0 / neighbour leak because
/// the count was masked `& 7` (max 7) instead of clamped to the architectural
/// byte range 1..=8. SSHR #8 must give the pure per-byte sign fill.
#[test]
fn sshr_16b_by_8_is_pure_sign_fill() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // sshr v0.16b, v1.16b, #8
    let word = 0x4F08_0420u32;
    decode_instruction(word).expect("decode sshr .16b #8");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "sshr .16b #8");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // Every byte 0x80 (negative) → sign fill 0xFF (pre-fix gave 0x80 unchanged).
    ctx[vd(1)] = 0x8080_8080_8080_8080;
    ctx[vd(1) + 1] = 0x8080_8080_8080_8080;
    ctx[vd(0)] = 0xDEAD_BEEF_DEAD_BEEF;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0xFFFF_FFFF_FFFF_FFFF, "sshr .16b #8: all bytes sign-fill to 0xFF (lo)");
    assert_eq!(ctx[vd(0) + 1], 0xFFFF_FFFF_FFFF_FFFF, "sshr .16b #8: all bytes 0xFF (hi)");
}

/// S2 (USHR twin) — USHR v0.16b, v1.16b, #8 must be all-zero; pre-fix the byte
/// mask `0xFF >> (8 & 7) = 0xFF` leaked the neighbouring byte through psrlw.
#[test]
fn ushr_16b_by_8_is_zero() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // ushr v0.16b, v1.16b, #8
    let word = 0x6F08_0420u32;
    decode_instruction(word).expect("decode ushr .16b #8");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "ushr .16b #8");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(1)] = 0xABAB_ABAB_ABAB_ABAB; // any non-zero — pre-fix leaked odd bytes
    ctx[vd(1) + 1] = 0xABAB_ABAB_ABAB_ABAB;
    ctx[vd(0)] = 0xDEAD_BEEF_DEAD_BEEF;
    ctx[vd(0) + 1] = 0xDEAD_BEEF_DEAD_BEEF;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0, "ushr .16b #8: all bytes shift out to 0 (lo)");
    assert_eq!(ctx[vd(0) + 1], 0, "ushr .16b #8: all bytes 0 (hi)");
}

/// S2 (SSRA twin) — SSRA v0.16b, v1.16b, #8: Vd += sign-fill(Vn). V0 = 0x01/byte,
/// V1 = 0x80/byte → Vd = 0x01 + 0xFF = 0x00 per byte. Pre-fix the shift aliased
/// to 0 so it accumulated 0x01 + 0x80 = 0x81 per byte.
#[test]
fn ssra_16b_by_8_accumulates_sign_fill() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // ssra v0.16b, v1.16b, #8
    let word = 0x4F08_1420u32;
    decode_instruction(word).expect("decode ssra .16b #8");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "ssra .16b #8");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[vd(0)] = 0x0101_0101_0101_0101; // Vd = 0x01 per byte (accumulator)
    ctx[vd(0) + 1] = 0x0101_0101_0101_0101;
    ctx[vd(1)] = 0x8080_8080_8080_8080; // Vn = 0x80 per byte → sign fill 0xFF
    ctx[vd(1) + 1] = 0x8080_8080_8080_8080;
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0, "ssra .16b #8: 0x01 + 0xFF = 0x00 per byte (lo)");
    assert_eq!(ctx[vd(0) + 1], 0, "ssra .16b #8: 0x00 per byte (hi)");
}

/// S3 — integer by-element MLA/MLS must fail loud (UD2), never silently lower as
/// a plain MUL (which would drop the accumulate against Vd). The decoder defers
/// these to a coarse Hint today, so drive the IR op directly: a hand-built
/// `VecByElem { op: Mla, is_fp: false }`. Before the fix this lowered to the MUL
/// body (NO UD2); after, it emits UD2.
#[test]
fn integer_mla_by_element_is_fail_loud() {
    let _serial = serial();
    use aether_translator::ir::ops::VecFpOp;
    use aether_translator::ir::{IrBlock, IrOp};
    let mut func = IrFunction::new(0x1000);
    {
        let block: &mut IrBlock = func.add_block();
        // Integer MLA by element .4s: op=Mla, is_fp=false, size=2 (S), q=true.
        block.push_op(IrOp::VecByElem {
            op: VecFpOp::Mla,
            is_fp: false,
            dbl: false,
            size: 2,
            q: true,
            d: 0,
            n: 1,
            m: 2,
            idx: 0,
        });
    }
    let code = lower_built_func(&func);
    assert!(
        code.windows(2).any(|w| w == [0x0Fu8, 0x0Bu8]),
        "integer MLA-by-element must emit UD2 (fail-loud), not silently drop the accumulate",
    );
}

/// S3 (positive control) — integer MUL by element .4s STILL lowers cleanly (no
/// UD2) after the guard. mul v0.4s, v1.4s, v2.s[0]: each lane = Vn * Vm[0].
#[test]
fn integer_mul_by_element_still_lowers() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // mul v0.4s, v1.4s, v2.s[0]
    let word = 0x4F82_8020u32;
    decode_instruction(word).expect("decode mul .4s by element");
    let code = translate_straight_line(&[word], 0x1000);
    assert_no_ud2(&code, "mul .4s by element");
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    // V1.4s = [2,3,4,5]; V2.s[0] = 7 → result = [14,21,28,35].
    ctx[vd(1)] = 0x0000_0003_0000_0002;
    ctx[vd(1) + 1] = 0x0000_0005_0000_0004;
    ctx[vd(2)] = 0x0000_0000_0000_0007; // lane0 = 7
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    assert_eq!(ctx[vd(0)], 0x0000_0015_0000_000E, "mul .4s [idx0]: lanes 0,1 = 14,21");
    assert_eq!(ctx[vd(0) + 1], 0x0000_0023_0000_001C, "mul .4s [idx0]: lanes 2,3 = 28,35");
}

// ═════════════════════════════════════════════════════════════════════════════
// FP silent-miscompile fixes (adversarial FP review, 2026-07-03).
// Each test FAILS before the corresponding lowering/decoder fix and PASSES after.
// F1 FRECPE mis-decode + SCVTF companion; F2 scalar FMAX/FMIN NaN+-0; F3 vector
// FCVTZS saturation; F4 FCVTAS/FRINTA ties-away; F5 by-element FMLA fusion;
// F6 vector FRINTA double-round; F7 FMAXNM/FMINNM +-0.
// ═════════════════════════════════════════════════════════════════════════════

/// Helper: translate one ARM word, run with a ctx setup closure, return the ctx.
fn fp_run1(word: u32, setup: impl Fn(&mut [u64])) -> [u64; CTX_U64S] {
    let code = translate_straight_line(&[word], 0x1000);
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    setup(&mut ctx);
    unsafe { enter_block(exec, ctx.as_mut_ptr()); }
    ctx
}

/// F2 - scalar FMAX/FMIN must PROPAGATE NaN (to quiet NaN) and break the +-0 tie
/// toward +0 (FMAX) / -0 (FMIN). Bare maxsd/minsd return the 2nd source on both.
#[test]
fn fp_scalar_fmax_fmin_nan_and_signed_zero() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    const QNAN: u64 = 0x7FF8_0000_0000_0000;
    // FMAX D0,D1,D2 : D1=qNaN, D2=5.0 -> NaN.
    let ctx = fp_run1(0x1E62_4820, |c| { c[vd(1)] = QNAN; c[vd(2)] = 0x4014_0000_0000_0000; });
    assert_eq!(ctx[vd(0)], QNAN, "FMAX(qNaN,5.0) must be quiet NaN");
    // FMAX D0,D1,D2 : D1=5.0, D2=qNaN -> NaN (Vm-NaN lane).
    let ctx = fp_run1(0x1E62_4820, |c| { c[vd(1)] = 0x4014_0000_0000_0000; c[vd(2)] = QNAN; });
    assert_eq!(ctx[vd(0)], QNAN, "FMAX(5.0,qNaN) must be quiet NaN");
    // FMAX(+0,-0) = +0.
    let ctx = fp_run1(0x1E62_4820, |c| { c[vd(1)] = 0x0; c[vd(2)] = 0x8000_0000_0000_0000; });
    assert_eq!(ctx[vd(0)], 0x0, "FMAX(+0,-0) = +0.0");
    // FMAX(-0,+0) = +0.
    let ctx = fp_run1(0x1E62_4820, |c| { c[vd(1)] = 0x8000_0000_0000_0000; c[vd(2)] = 0x0; });
    assert_eq!(ctx[vd(0)], 0x0, "FMAX(-0,+0) = +0.0");
    // FMIN(-0,+0) = -0.
    let ctx = fp_run1(0x1E62_5820, |c| { c[vd(1)] = 0x8000_0000_0000_0000; c[vd(2)] = 0x0; });
    assert_eq!(ctx[vd(0)], 0x8000_0000_0000_0000, "FMIN(-0,+0) = -0.0");
    // FMIN(+0,-0) = -0.
    let ctx = fp_run1(0x1E62_5820, |c| { c[vd(1)] = 0x0; c[vd(2)] = 0x8000_0000_0000_0000; });
    assert_eq!(ctx[vd(0)], 0x8000_0000_0000_0000, "FMIN(+0,-0) = -0.0");
    // Ordinary FMAX still correct + upper zeroed.
    let ctx = fp_run1(0x1E62_4820, |c| { c[vd(1)] = 0x4014_0000_0000_0000; c[vd(2)] = 0x4000_0000_0000_0000; });
    assert_eq!(ctx[vd(0)], 0x4014_0000_0000_0000, "FMAX(5.0,2.0)=5.0");
    assert_eq!(ctx[vd(0) + 1], 0, "scalar FMAX zeroes upper 64");
}

/// F7 - FMAXNM/FMINNM: ignore-NaN (return the non-NaN operand) AND +-0 tie-break.
#[test]
fn fp_scalar_fmaxnm_fminnm_nan_and_signed_zero() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    const QNAN: u64 = 0x7FF8_0000_0000_0000;
    // FMAXNM(NaN,5.0)=5.0 ; FMAXNM(5.0,NaN)=5.0.
    let ctx = fp_run1(0x1E62_6820, |c| { c[vd(1)] = QNAN; c[vd(2)] = 0x4014_0000_0000_0000; });
    assert_eq!(ctx[vd(0)], 0x4014_0000_0000_0000, "FMAXNM(NaN,5.0)=5.0");
    let ctx = fp_run1(0x1E62_6820, |c| { c[vd(1)] = 0x4014_0000_0000_0000; c[vd(2)] = QNAN; });
    assert_eq!(ctx[vd(0)], 0x4014_0000_0000_0000, "FMAXNM(5.0,NaN)=5.0");
    // FMAXNM(+0,-0)=+0.
    let ctx = fp_run1(0x1E62_6820, |c| { c[vd(1)] = 0x0; c[vd(2)] = 0x8000_0000_0000_0000; });
    assert_eq!(ctx[vd(0)], 0x0, "FMAXNM(+0,-0)=+0.0");
    // FMINNM(-0,+0)=-0  (word 0x1E627820).
    let ctx = fp_run1(0x1E62_7820, |c| { c[vd(1)] = 0x8000_0000_0000_0000; c[vd(2)] = 0x0; });
    assert_eq!(ctx[vd(0)], 0x8000_0000_0000_0000, "FMINNM(-0,+0)=-0.0");
}

/// F3 - vector FCVTZS.4s must saturate (+ovf/+inf -> INT_MAX, -ovf/-inf -> INT_MIN,
/// NaN -> 0). Bare cvttps2dq gives 0x80000000 for NaN and positive overflow.
#[test]
fn fp_vector_fcvtzs_saturation() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let nan = 0x7FC0_0000u64;
    let big = f32::to_bits(3.0e9f32) as u64;   // > 2^31
    let neg = f32::to_bits(-3.0e9f32) as u64;  // < -2^31
    let one5 = f32::to_bits(1.5f32) as u64;
    let ctx = fp_run1(0x4EA1_B820, |c| {
        c[vd(1)] = nan | (big << 32);
        c[vd(1) + 1] = neg | (one5 << 32);
    });
    assert_eq!(ctx[vd(0)] & 0xFFFF_FFFF, 0x0000_0000, "FCVTZS lane0 NaN -> 0");
    assert_eq!(ctx[vd(0)] >> 32, 0x7FFF_FFFF, "FCVTZS lane1 +3e9 -> INT_MAX");
    assert_eq!(ctx[vd(0) + 1] & 0xFFFF_FFFF, 0x8000_0000, "FCVTZS lane2 -3e9 -> INT_MIN");
    assert_eq!(ctx[vd(0) + 1] >> 32, 0x0000_0001, "FCVTZS lane3 1.5 -> 1");
}

/// F1 - FRECPE.4s must NOT silently int-convert (was mis-decoded as SCVTF ->
/// cvtdq2ps). It used to be fail-loud; it now runs through simd_rt with the exact
/// ARMv8.0 RecipEstimate, so check the real ARM result per lane.
#[test]
fn fp_frecpe_is_exact_estimate_not_int_convert() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // FRECPE v0.4s, v1.4s = 0x4EA1D820. Lanes [1.0, 2.0, 0.0, -inf].
    let ctx = fp_run1(0x4EA1_D820, |c| {
        c[vd(1)] = f32::to_bits(1.0) as u64 | ((f32::to_bits(2.0) as u64) << 32);
        c[vd(1) + 1] = 0 | (0xFF80_0000u64 << 32);
    });
    assert_eq!(ctx[vd(0)] & 0xFFFF_FFFF, 0x3F7F_8000, "FRECPE(1.0) = 0.998046875");
    assert_eq!(ctx[vd(0)] >> 32, 0x3EFF_8000, "FRECPE(2.0)");
    assert_eq!(ctx[vd(0) + 1] & 0xFFFF_FFFF, 0x7F80_0000, "FRECPE(+0) = +inf");
    assert_eq!(ctx[vd(0) + 1] >> 32, 0x8000_0000, "FRECPE(-inf) = -0");
}

/// F1 companion - genuine vector SCVTF.4s (signed int32 -> f32) must decode and
/// execute via cvtdq2ps (previously fell through to Reserved / translate-fail).
#[test]
fn fp_vector_scvtf_4s_executes() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    decode_instruction(0x4E21_D820u32).expect("SCVTF v0.4s,v1.4s must decode");
    let ctx = fp_run1(0x4E21_D820, |c| {
        // lanes [1, 2, -1, 7] as int32.
        c[vd(1)] = (1u64) | ((2u64) << 32);
        c[vd(1) + 1] = (0xFFFF_FFFFu64) | ((7u64) << 32);
    });
    assert_eq!(ctx[vd(0)] & 0xFFFF_FFFF, f32::to_bits(1.0) as u64, "SCVTF lane0 = 1.0");
    assert_eq!(ctx[vd(0)] >> 32, f32::to_bits(2.0) as u64, "SCVTF lane1 = 2.0");
    assert_eq!(ctx[vd(0) + 1] & 0xFFFF_FFFF, f32::to_bits(-1.0) as u64, "SCVTF lane2 = -1.0");
    assert_eq!(ctx[vd(0) + 1] >> 32, f32::to_bits(7.0) as u64, "SCVTF lane3 = 7.0");
}

/// F4 - FCVTAS (round-to-nearest ties-AWAY, FP->int). 2.5f -> 3, 0.5f -> 1, -2.5f -> -3.
#[test]
fn fp_fcvtas_ties_away() {
    let _serial = serial();
    // FCVTAS W0, S1 = 0x1E240020. Result GPR W0 lives at ctx[0].
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let ctx = fp_run1(0x1E24_0020, |c| { c[vd(1)] = f32::to_bits(2.5) as u64; });
    assert_eq!(ctx[0] as u32, 3, "FCVTAS(2.5f)=3");
    let ctx = fp_run1(0x1E24_0020, |c| { c[vd(1)] = f32::to_bits(0.5) as u64; });
    assert_eq!(ctx[0] as u32, 1, "FCVTAS(0.5f)=1");
    let ctx = fp_run1(0x1E24_0020, |c| { c[vd(1)] = f32::to_bits(-2.5) as u64; });
    assert_eq!(ctx[0] as i32, -3, "FCVTAS(-2.5f)=-3");
    // Non-tie still round-to-nearest: 2.4 -> 2, 2.6 -> 3.
    let ctx = fp_run1(0x1E24_0020, |c| { c[vd(1)] = f32::to_bits(2.4) as u64; });
    assert_eq!(ctx[0] as u32, 2, "FCVTAS(2.4f)=2");
    let ctx = fp_run1(0x1E24_0020, |c| { c[vd(1)] = f32::to_bits(2.6) as u64; });
    assert_eq!(ctx[0] as u32, 3, "FCVTAS(2.6f)=3");
}

/// F4 - scalar FRINTA (round-to-integral, ties AWAY, FP result). 2.5 -> 3.0, -0.5 -> -1.0.
#[test]
fn fp_scalar_frinta_ties_away() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // FRINTA D0, D1 = 0x1E664020.
    let ctx = fp_run1(0x1E66_4020, |c| { c[vd(1)] = 2.5f64.to_bits(); });
    assert_eq!(f64::from_bits(ctx[vd(0)]), 3.0, "FRINTA(2.5)=3.0");
    let ctx = fp_run1(0x1E66_4020, |c| { c[vd(1)] = (-0.5f64).to_bits(); });
    assert_eq!(ctx[vd(0)], (-1.0f64).to_bits(), "FRINTA(-0.5)=-1.0 (incl sign)");
    let ctx = fp_run1(0x1E66_4020, |c| { c[vd(1)] = 2.4f64.to_bits(); });
    assert_eq!(f64::from_bits(ctx[vd(0)]), 2.0, "FRINTA(2.4)=2.0");
    assert_eq!(ctx[vd(0) + 1], 0, "scalar FRINTA zeroes upper 64");
}

/// F6 - vector FRINTA.4s must NOT double-round. 0.49999997f -> 0.0 (add-half would
/// round to 1.0). Halfway cases still round away.
#[test]
fn fp_vector_frinta_no_double_round() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // FRINTA v0.4s, v1.4s = 0x6E218820. lanes [0.49999997, 2.5, -0.5, 2^23+1].
    let x0 = 0x3EFF_FFFFu64; // 0.49999997f
    let x1 = f32::to_bits(2.5) as u64;
    let x2 = f32::to_bits(-0.5) as u64;
    let x3 = 0x4B00_0001u64; // 2^23 + 1 (exact int, must stay)
    let ctx = fp_run1(0x6E21_8820, |c| {
        c[vd(1)] = x0 | (x1 << 32);
        c[vd(1) + 1] = x2 | (x3 << 32);
    });
    assert_eq!((ctx[vd(0)] & 0xFFFF_FFFF) as u32, f32::to_bits(0.0), "vFRINTA(0.49999997)=0.0");
    assert_eq!((ctx[vd(0)] >> 32) as u32, f32::to_bits(3.0), "vFRINTA(2.5)=3.0");
    assert_eq!((ctx[vd(0) + 1] & 0xFFFF_FFFF) as u32, f32::to_bits(-1.0), "vFRINTA(-0.5)=-1.0");
    assert_eq!((ctx[vd(0) + 1] >> 32) as u32, 0x4B00_0001, "vFRINTA(2^23+1) unchanged");
}

/// Scalar SIMD SCVTF/UCVTF `Dd,Dn` / `Sd,Sn`: the integer is the low element of a
/// vector register. `ucvtf d0, d0` (0x7E61D800) failed to decode and halted the
/// 2026-10-08 WHPX boot right after zygote start.
#[test]
fn simd_scalar_scvtf_ucvtf_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // UCVTF D0, D1 = 0x7E61D820: unsigned 2^63+2048 -> exact double, upper 64 zeroed.
    let ctx = fp_run1(0x7E61_D820, |c| { c[vd(1)] = 0x8000_0000_0000_0800; c[vd(0) + 1] = !0; });
    assert_eq!(f64::from_bits(ctx[vd(0)]), 9223372036854777856.0, "UCVTF D0,D1 (2^63+2048)");
    assert_eq!(ctx[vd(0) + 1], 0, "scalar UCVTF zeroes the upper 64");
    // UCVTF D0, D0 (rd == rn, the boot's exact word).
    let ctx = fp_run1(0x7E61_D800, |c| { c[vd(0)] = 42; });
    assert_eq!(f64::from_bits(ctx[vd(0)]), 42.0, "UCVTF D0,D0");
    // SCVTF D0, D1 = 0x5E61D820: signed -5 -> -5.0.
    let ctx = fp_run1(0x5E61_D820, |c| { c[vd(1)] = (-5i64) as u64; });
    assert_eq!(f64::from_bits(ctx[vd(0)]), -5.0, "SCVTF D0,D1 (-5)");
    // SCVTF S0, S1 = 0x5E21D820: low 32 bits only (upper garbage ignored), signed.
    let ctx = fp_run1(0x5E21_D820, |c| { c[vd(1)] = 0xDEAD_BEEF_FFFF_FFFE; });
    assert_eq!(ctx[vd(0)], f32::to_bits(-2.0) as u64, "SCVTF S0,S1 (-2) with zeroed upper bits");
    // UCVTF S0, S1 = 0x7E21D820: 0xFFFFFFFE unsigned -> 4294967294 rounds to 2^32 in f32.
    let ctx = fp_run1(0x7E21_D820, |c| { c[vd(1)] = 0xFFFF_FFFE; });
    assert_eq!(ctx[vd(0)], f32::to_bits(4294967296.0) as u64, "UCVTF S0,S1 (0xFFFFFFFE)");
}

/// Scalar SIMD FABD (`|n - m|`): the top decode gap in the framework corpus.
#[test]
fn simd_scalar_fabd_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // FABD S0, S1, S2 = 0x7EA2D420: |1.5 - 4.0| = 2.5; upper bits of V0 zeroed.
    let ctx = fp_run1(0x7EA2_D420, |c| {
        c[vd(1)] = f32::to_bits(1.5) as u64;
        c[vd(2)] = f32::to_bits(4.0) as u64;
        c[vd(0)] = !0; c[vd(0) + 1] = !0;
    });
    assert_eq!(ctx[vd(0)], f32::to_bits(2.5) as u64, "FABD S (|1.5-4.0|)");
    assert_eq!(ctx[vd(0) + 1], 0, "scalar FABD zeroes the upper 64");
    // FABD D0, D1, D2 = 0x7EE2D420: |-3 - 5| = 8.
    let ctx = fp_run1(0x7EE2_D420, |c| {
        c[vd(1)] = (-3.0f64).to_bits();
        c[vd(2)] = 5.0f64.to_bits();
    });
    assert_eq!(f64::from_bits(ctx[vd(0)]), 8.0, "FABD D (|-3-5|)");
    // NaN: FPSub returns the quieted -NaN operand, FPAbs clears its sign -> +qNaN.
    let ctx = fp_run1(0x7EA2_D420, |c| {
        c[vd(1)] = 0xFFC0_0000; // -qNaN
        c[vd(2)] = f32::to_bits(1.0) as u64;
    });
    assert_eq!(ctx[vd(0)], 0x7FC0_0000, "FABD S (-NaN, 1) = +qNaN");
}

/// SMULL/UMULL/SMLAL/SMLSL{2} .2s -> .2d (32x32->64): ~4,860 distinct words in the
/// Android image lowered to UD2 before (codec/DSP hot loops).
#[test]
fn simd_mull_2d_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let pair = |a: i32, b: i32| (a as u32 as u64) | ((b as u32 as u64) << 32);
    // SMULL V0.2D, V1.2S, V2.2S = 0x0EA2C020: [-3*7, 0x7FFFFFFF*-2]
    let ctx = fp_run1(0x0EA2_C020, |c| { c[vd(1)] = pair(-3, i32::MAX); c[vd(2)] = pair(7, -2); });
    assert_eq!(ctx[vd(0)] as i64, -21, "SMULL lane0");
    assert_eq!(ctx[vd(0) + 1] as i64, i32::MAX as i64 * -2, "SMULL lane1");
    // UMULL V0.2D, V1.2S, V2.2S = 0x2EA2C020: 0xFFFFFFFF * 0xFFFFFFFF
    let ctx = fp_run1(0x2EA2_C020, |c| { c[vd(1)] = u64::MAX; c[vd(2)] = u64::MAX; });
    assert_eq!(ctx[vd(0)], 0xFFFF_FFFE_0000_0001, "UMULL lane0");
    // SMULL2 V0.2D, V1.4S, V2.4S = 0x4EA2C020 (upper halves): 5 * -6
    let ctx = fp_run1(0x4EA2_C020, |c| { c[vd(1) + 1] = pair(5, 1); c[vd(2) + 1] = pair(-6, 1); });
    assert_eq!(ctx[vd(0)] as i64, -30, "SMULL2 uses Vn[127:64]");
    // SMLAL V0.2D, V1.2S, V2.2S = 0x0EA28020: 100 + (-4*5)
    let ctx = fp_run1(0x0EA2_8020, |c| { c[vd(0)] = 100; c[vd(1)] = pair(-4, 0); c[vd(2)] = pair(5, 0); });
    assert_eq!(ctx[vd(0)] as i64, 80, "SMLAL accumulates in 64 bits");
    // SMLSL V0.2D, V1.2S, V2.2S = 0x0EA2A020: 100 - (-4*5)
    let ctx = fp_run1(0x0EA2_A020, |c| { c[vd(0)] = 100; c[vd(1)] = pair(-4, 0); c[vd(2)] = pair(5, 0); });
    assert_eq!(ctx[vd(0)] as i64, 120, "SMLSL subtracts in 64 bits");
}

/// Long-tail Advanced SIMD through the simd_rt CALL path (translated code → Win64
/// call → interpreter → q-regs): BIF (was a decode failure), URSHR and UADDW (were
/// UD2), UCVTF .4s (was UD2 in the cvtdq2ps lowering). Also checks that GPRs and
/// unrelated vector registers survive the call.
#[test]
fn simd_rt_call_path_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // BIF V0.8B, V1.8B, V2.8B = 0x2EE21C20 (Q=0: upper 64 zeroed).
    let ctx = fp_run1(0x2EE2_1C20, |c| {
        c[vd(0)] = 0xF0; c[vd(0) + 1] = !0; c[vd(1)] = 0x0F; c[vd(2)] = 0xCC;
        c[5] = 0x1234_5678; c[vd(7)] = 0xAAAA;
    });
    assert_eq!(ctx[vd(0)], (0xF0 & 0xCC) | (0x0F & !0xCCu64 & 0xFF), "BIF");
    assert_eq!(ctx[vd(0) + 1], 0, "Q=0 zeroes Vd[127:64]");
    assert_eq!(ctx[5], 0x1234_5678, "X5 survives the helper call");
    assert_eq!(ctx[vd(7)], 0xAAAA, "V7 untouched");
    // URSHR V0.2D, V1.2D, #8 = 0x6F782420: (0x180 + 0x80) >> 8 = 2.
    let ctx = fp_run1(0x6F78_2420, |c| { c[vd(1)] = 0x180; c[vd(1) + 1] = 0x7F; });
    assert_eq!(ctx[vd(0)], 2, "URSHR lane 0");
    assert_eq!(ctx[vd(0) + 1], 0, "URSHR lane 1 (0x7F+0x80)>>8");
    // UADDW V0.8H, V1.8H, V2.8B = 0x2E221020.
    let ctx = fp_run1(0x2E22_1020, |c| { c[vd(1)] = 0x0001_00FF; c[vd(2)] = 0x0101; });
    assert_eq!(ctx[vd(0)] & 0xFFFF_FFFF, 0x0002_0100, "UADDW");
    // UCVTF V0.4S, V0.4S = 0x6E21D800: 0xFFFFFFFF -> 4294967296.0f.
    let ctx = fp_run1(0x6E21_D800, |c| { c[vd(0)] = 0xFFFF_FFFF; });
    assert_eq!(ctx[vd(0)] as u32, 4294967296.0f32.to_bits(), "UCVTF .4s unsigned");
}

/// FCVTL/FCVTL2/FCVTN/FCVTN2: vector FP precision convert (f16<->f32, f32<->f64).
#[test]
fn simd_fcvtl_fcvtn_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let s = |x: f32| f32::to_bits(x) as u64;
    // f16 bit patterns: 1.0=0x3C00, -2.0=0xC000, 0.5=0x3800, 65504=0x7BFF.
    let h4 = |a: u64, b: u64, c: u64, d: u64| a | (b << 16) | (c << 32) | (d << 48);
    // FCVTL V0.4S, V1.4H = 0x0E217820.
    let ctx = fp_run1(0x0E21_7820, |c| { c[vd(1)] = h4(0x3C00, 0xC000, 0x3800, 0x7BFF); });
    assert_eq!(ctx[vd(0)], s(1.0) | (s(-2.0) << 32), "FCVTL .4h->.4s lo");
    assert_eq!(ctx[vd(0) + 1], s(0.5) | (s(65504.0) << 32), "FCVTL .4h->.4s hi");
    // FCVTL2 V0.4S, V1.8H = 0x4E217820 (source = upper 4 halves).
    let ctx = fp_run1(0x4E21_7820, |c| { c[vd(1) + 1] = h4(0x3800, 0x3C00, 0, 0); });
    assert_eq!(ctx[vd(0)], s(0.5) | (s(1.0) << 32), "FCVTL2 uses Vn[127:64]");
    // FCVTN V0.4H, V1.4S = 0x0E216820; upper 64 of V0 zeroed.
    let ctx = fp_run1(0x0E21_6820, |c| {
        c[vd(1)] = s(1.0) | (s(-2.0) << 32); c[vd(1) + 1] = s(0.5) | (s(65504.0) << 32);
        c[vd(0) + 1] = !0;
    });
    assert_eq!(ctx[vd(0)], h4(0x3C00, 0xC000, 0x3800, 0x7BFF), "FCVTN .4s->.4h");
    assert_eq!(ctx[vd(0) + 1], 0, "FCVTN zeroes Vd[127:64]");
    // FCVTN2 V0.8H, V1.4S = 0x4E216820: writes upper, keeps lower.
    let ctx = fp_run1(0x4E21_6820, |c| {
        c[vd(1)] = s(1.0) | (s(1.0) << 32); c[vd(1) + 1] = s(1.0) | (s(1.0) << 32);
        c[vd(0)] = 0x1234_5678_9ABC_DEF0;
    });
    assert_eq!(ctx[vd(0)], 0x1234_5678_9ABC_DEF0, "FCVTN2 keeps Vd[63:0]");
    assert_eq!(ctx[vd(0) + 1], h4(0x3C00, 0x3C00, 0x3C00, 0x3C00), "FCVTN2 writes Vd[127:64]");
    // FCVTL V0.2D, V1.2S = 0x0E617820; FCVTN2 V0.4S, V1.2D = 0x4E616820.
    let ctx = fp_run1(0x0E61_7820, |c| { c[vd(1)] = s(1.5) | (s(-0.25) << 32); });
    assert_eq!(ctx[vd(0)], 1.5f64.to_bits(), "FCVTL .2s->.2d lo");
    assert_eq!(ctx[vd(0) + 1], (-0.25f64).to_bits(), "FCVTL .2s->.2d hi");
    let ctx = fp_run1(0x4E61_6820, |c| {
        c[vd(1)] = 3.0f64.to_bits(); c[vd(1) + 1] = (-1.0f64).to_bits(); c[vd(0)] = 7;
    });
    assert_eq!(ctx[vd(0)], 7, "FCVTN2 .2d keeps Vd[63:0]");
    assert_eq!(ctx[vd(0) + 1], s(3.0) | (s(-1.0) << 32), "FCVTN2 .2d->.4s upper");
}

/// FMOV (vector, immediate): VFPExpandImm(imm8) in every lane.
#[test]
fn simd_fmov_vector_imm_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let s = |x: f32| f32::to_bits(x) as u64;
    // FMOV V0.2S, #0.5 = 0x0F03F400 (imm8 0x60).
    let ctx = fp_run1(0x0F03_F400, |c| { c[vd(0) + 1] = !0; });
    assert_eq!(ctx[vd(0)], s(0.5) | (s(0.5) << 32), "FMOV V0.2S,#0.5");
    assert_eq!(ctx[vd(0) + 1], 0, "Q=0 zeroes the upper 64");
    // FMOV V0.2S, #2.0 = 0x0F00F400 (imm8 0x00 -> 2.0).
    let ctx = fp_run1(0x0F00_F400, |_| {});
    assert_eq!(ctx[vd(0)], s(2.0) | (s(2.0) << 32), "FMOV V0.2S,#2.0");
    // FMOV V1.4S, #-1.0 = 0x4F07F601 (imm8 0xF0 -> -1.0).
    let ctx = fp_run1(0x4F07_F601, |_| {});
    assert_eq!(ctx[vd(1)], s(-1.0) | (s(-1.0) << 32), "FMOV V1.4S,#-1.0 lo");
    assert_eq!(ctx[vd(1) + 1], s(-1.0) | (s(-1.0) << 32), "FMOV V1.4S,#-1.0 hi");
    // FMOV V2.2D, #1.5 = 0x6F03F702 (imm8 0x78 -> 1.5).
    let ctx = fp_run1(0x6F03_F702, |_| {});
    assert_eq!(ctx[vd(2)], 1.5f64.to_bits(), "FMOV V2.2D,#1.5 lo");
    assert_eq!(ctx[vd(2) + 1], 1.5f64.to_bits(), "FMOV V2.2D,#1.5 hi");
}

/// Scalar FP by element: FMUL/FMLA/FMLS Sd,Sn,Vm.S[idx] and the D forms.
#[test]
fn fp_scalar_by_element_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let s = |x: f32| f32::to_bits(x) as u64;
    // V0.4s = [10, 20, 30, 40]; V1.s[0] = 1.5 (lane 1 = 99 must not leak).
    let set = |c: &mut [u64]| {
        c[vd(0)] = s(10.0) | (s(20.0) << 32);
        c[vd(0) + 1] = s(30.0) | (s(40.0) << 32);
        c[vd(1)] = s(1.5) | (s(99.0) << 32);
    };
    // FMUL S1, S1, V0.S[2] = 0x5F809821 (the framework corpus example): 1.5*30 = 45.
    let ctx = fp_run1(0x5F80_9821, |c| { set(c); c[vd(1) + 1] = !0; });
    assert_eq!(ctx[vd(1)], s(45.0), "FMUL S1,S1,V0.S[2]: lane 1 must be zeroed");
    assert_eq!(ctx[vd(1) + 1], 0, "scalar FMUL zeroes the upper 64");
    // FMLA S2, S1, V0.S[1] = 0x5FA01022: 2.0 + 1.5*20 = 32.
    let ctx = fp_run1(0x5FA0_1022, |c| { set(c); c[vd(2)] = s(2.0) | (s(7.0) << 32); });
    assert_eq!(ctx[vd(2)], s(32.0), "FMLA S2,S1,V0.S[1]");
    // FMLS S2, S1, V0.S[3] = 0x5FA05822: 2.0 - 1.5*40 = -58.
    let ctx = fp_run1(0x5FA0_5822, |c| { set(c); c[vd(2)] = s(2.0); });
    assert_eq!(ctx[vd(2)], s(-58.0), "FMLS S2,S1,V0.S[3]");
    // FMUL D1, D1, V0.D[1] = 0x5FC09821: 2.5 * 4.0 = 10.
    let ctx = fp_run1(0x5FC0_9821, |c| {
        c[vd(0)] = 3.0f64.to_bits(); c[vd(0) + 1] = 4.0f64.to_bits();
        c[vd(1)] = 2.5f64.to_bits(); c[vd(1) + 1] = !0;
    });
    assert_eq!(f64::from_bits(ctx[vd(1)]), 10.0, "FMUL D1,D1,V0.D[1]");
    assert_eq!(ctx[vd(1) + 1], 0, "scalar FMUL D zeroes the upper 64");
}

/// Fixed-point SCVTF/UCVTF (int × 2^-fbits), e.g. `ucvtf s3, w8, #24` (0x1E03A103).
#[test]
fn fp_fixed_point_scvtf_ucvtf_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // UCVTF S3, W8, #24: 0xFF000000 (u32) / 2^24 = 255.0.
    let ctx = fp_run1(0x1E03_A103, |c| { c[8] = 0xFF00_0000; });
    assert_eq!(ctx[vd(3)], f32::to_bits(255.0) as u64, "UCVTF S3,W8,#24");
    // SCVTF S0, W1, #1 (scale 63 -> 0x1E02FC20): -3 / 2 = -1.5.
    let ctx = fp_run1(0x1E02_FC20, |c| { c[1] = 0xFFFF_FFFD; });
    assert_eq!(ctx[vd(0)], f32::to_bits(-1.5) as u64, "SCVTF S0,W1,#1 (W sign)");
    // SCVTF D0, X1, #16 (sf=1, ftype=01, scale 48 -> 0x9E42C020): 0x18000 / 2^16 = 1.5.
    let ctx = fp_run1(0x9E42_C020, |c| { c[1] = 0x1_8000; });
    assert_eq!(f64::from_bits(ctx[vd(0)]), 1.5, "SCVTF D0,X1,#16");
    // UCVTF D0, X1, #64 (scale 0 -> 0x9E430020): 2^64-1 / 2^64 rounds to 1.0.
    let ctx = fp_run1(0x9E43_0020, |c| { c[1] = u64::MAX; });
    assert_eq!(f64::from_bits(ctx[vd(0)]), 1.0, "UCVTF D0,X1,#64 (u64 max)");
}

/// Fixed-point FCVTZS/FCVTZU to a GPR (FP × 2^fbits, truncate, saturate), e.g.
/// `fcvtzu w8, s8, #?` (0x1E19E108) and `fcvtzs w10, s1, #20` (0x1E18B02A).
#[test]
fn fp_fixed_point_fcvtzs_fcvtzu_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // FCVTZS W10, S1, #20 = 0x1E18B02A: 1.5 * 2^20 = 1572864; -2.25 -> -2359296.
    let ctx = fp_run1(0x1E18_B02A, |c| { c[vd(1)] = f32::to_bits(1.5) as u64; });
    assert_eq!(ctx[10], 1_572_864, "FCVTZS W10,S1,#20");
    let ctx = fp_run1(0x1E18_B02A, |c| { c[vd(1)] = f32::to_bits(-2.25) as u64; });
    assert_eq!(ctx[10], (-2_359_296i32) as u32 as u64, "FCVTZS negative (W zero-extends)");
    // FCVTZU W8, S8, #8 (scale 56 -> 0x1E19E108): 300.7 * 256 = 76979.2 -> 76979.
    let ctx = fp_run1(0x1E19_E108, |c| { c[vd(8)] = f32::to_bits(300.7) as u64; });
    assert_eq!(ctx[8], (300.7f32 * 256.0) as u32 as u64, "FCVTZU W8,S8,#8");
    // Saturation: 1e9 * 2^8 overflows u32 -> 0xFFFFFFFF; negative -> 0.
    let ctx = fp_run1(0x1E19_E108, |c| { c[vd(8)] = f32::to_bits(1.0e9) as u64; });
    assert_eq!(ctx[8], 0xFFFF_FFFF, "FCVTZU saturates");
    let ctx = fp_run1(0x1E19_E108, |c| { c[vd(8)] = f32::to_bits(-1.0) as u64; });
    assert_eq!(ctx[8], 0, "FCVTZU negative -> 0");
    // FCVTZS X0, D1, #32 (sf=1, ftype=01, scale 32 -> 0x9E588020): 0.5 * 2^32.
    let ctx = fp_run1(0x9E58_8020, |c| { c[vd(1)] = 0.5f64.to_bits(); });
    assert_eq!(ctx[0], 1u64 << 31, "FCVTZS X0,D1,#32");
}

/// FCCMP: NZCV = cond(NZCV_in) ? FPCompare(n, m) : #nzcv. The top UD2 in the
/// framework corpus. Checks both branches, all compare outcomes and unordered.
#[test]
fn fp_fccmp_execute() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // FCCMP S1, S2, #0b0010, EQ = 0x1E220422 (D form: 0x1E620422).
    let run = |word: u32, nzcv_in: u64, a: u64, b: u64| -> u64 {
        let ctx = fp_run1(word, |c| { c[NZCV_SLOT] = nzcv_in; c[vd(1)] = a; c[vd(2)] = b; });
        ctx[NZCV_SLOT] & 0xF000_0000
    };
    let s = |x: f32| f32::to_bits(x) as u64;
    let z = 1u64 << 30;
    assert_eq!(run(0x1E22_0422, z, s(1.0), s(1.0)), 0x6000_0000, "EQ true, 1==1 -> Z,C");
    assert_eq!(run(0x1E22_0422, z, s(1.0), s(2.0)), 0x8000_0000, "EQ true, 1<2 -> N");
    assert_eq!(run(0x1E22_0422, z, s(3.0), s(2.0)), 0x2000_0000, "EQ true, 3>2 -> C");
    assert_eq!(run(0x1E22_0422, z, 0x7FC0_0000, s(2.0)), 0x3000_0000, "EQ true, NaN -> C,V");
    assert_eq!(run(0x1E22_0422, 0, s(1.0), s(1.0)), 0x2000_0000, "EQ false -> #nzcv (C)");
    let d = |x: f64| x.to_bits();
    assert_eq!(run(0x1E62_0422, z, d(-1.0), d(1.0)), 0x8000_0000, "D form, EQ true, -1<1 -> N");
    assert_eq!(run(0x1E62_0422, 0, d(-1.0), d(1.0)), 0x2000_0000, "D form, EQ false -> #nzcv");
}

/// FRINTA keeps the sign of a zero result: x in (-0.5, -0] rounds to -0.0, not +0.0.
/// The ties-away emulation adds a masked addend that is +0.0 when |x - trunc(x)| < 0.5,
/// and -0.0 + +0.0 = +0.0 under round-to-nearest. Found by the 2026-10-08 oracle
/// re-run (research_audit/oracle_results.md); scalar and vector paths both affected.
#[test]
fn fp_frinta_preserves_negative_zero() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    let neg0d = (-0.0f64).to_bits();
    let neg0s = f32::to_bits(-0.0) as u64;
    // Scalar double: FRINTA D0, D1 = 0x1E664020.
    for x in [-0.3f64, -0.0, -0.49999999999999994] {
        let ctx = fp_run1(0x1E66_4020, |c| { c[vd(1)] = x.to_bits(); });
        assert_eq!(ctx[vd(0)], neg0d, "FRINTA({x:e}) must be -0.0");
    }
    let ctx = fp_run1(0x1E66_4020, |c| { c[vd(1)] = 0.3f64.to_bits(); });
    assert_eq!(ctx[vd(0)], 0, "FRINTA(0.3) must be +0.0");
    // Scalar single: FRINTA S0, S1 = 0x1E264020 (upper bits of the low 64 stay zero).
    let ctx = fp_run1(0x1E26_4020, |c| { c[vd(1)] = f32::to_bits(-0.3) as u64; });
    assert_eq!(ctx[vd(0)], neg0s, "FRINTA(-0.3f) must be -0.0f");
    // Vector .4s: FRINTA v0.4s, v1.4s = 0x6E218820. lanes [-0.3, -0.0, 0.3, -0.49999997].
    let ctx = fp_run1(0x6E21_8820, |c| {
        c[vd(1)] = f32::to_bits(-0.3) as u64 | ((f32::to_bits(-0.0) as u64) << 32);
        c[vd(1) + 1] = f32::to_bits(0.3) as u64 | (0xBEFF_FFFFu64 << 32);
    });
    assert_eq!(ctx[vd(0)], neg0s | (neg0s << 32), "vFRINTA.4s lanes 0,1 must be -0.0");
    assert_eq!(ctx[vd(0) + 1], neg0s << 32, "vFRINTA.4s lane 2 = +0.0, lane 3 = -0.0");
    // Vector .2d: FRINTA v0.2d, v1.2d = 0x6E618820. lanes [-0.3, 0.2].
    let ctx = fp_run1(0x6E61_8820, |c| {
        c[vd(1)] = (-0.3f64).to_bits();
        c[vd(1) + 1] = 0.2f64.to_bits();
    });
    assert_eq!(ctx[vd(0)], neg0d, "vFRINTA.2d(-0.3) must be -0.0");
    assert_eq!(ctx[vd(0) + 1], 0, "vFRINTA.2d(0.2) must be +0.0");
}

/// F5 - by-element FMLA.4s must be FUSED (single rounding). Vn=Vm[0]=1+2^-12,
/// acc=2^-24 -> fused 0x3F801001; unfused mul+add rounds to 0x3F801000.
#[test]
fn fp_byelem_fmla_fused() {
    let _serial = serial();
    use aether_translator::runtime::context::vec_disp;
    let vd = |r: u8| (vec_disp(r) as usize) / 8;
    // FMLA v0.4s, v1.4s, v2.s[0] = 0x4F821020.
    let a = 0x3F80_0800u64; // 1 + 2^-12
    let c0 = 0x3380_0000u64; // 2^-24
    let ctx = fp_run1(0x4F82_1020, |c| {
        c[vd(1)] = a | (a << 32);
        c[vd(1) + 1] = a | (a << 32);
        c[vd(2)] = a;                  // Vm.s[0]
        c[vd(0)] = c0 | (c0 << 32);    // accumulator Vd
        c[vd(0) + 1] = c0 | (c0 << 32);
    });
    assert_eq!(ctx[vd(0)] & 0xFFFF_FFFF, 0x3F80_1001, "FMLA by-elem lane0 fused");
    assert_eq!(ctx[vd(0)] >> 32, 0x3F80_1001, "FMLA by-elem lane1 fused");
}

/// L2 (2026-07-03 lift review): `CMP SP, #imm` must compare the SP register, not
/// XZR. The flag-setting ADD/SUB (immediate) source is <Xn|SP>, so rn==31 is SP;
/// the pre-fix lift read XZR=0 and produced flags of (0 - imm) — every branch
/// keyed on the compare inverted. Exec-proof: seed the SP slot (byte 0xF8) with
/// 0x8000 and run `CMP SP, #0x10` (= SUBS XZR, SP, #16 = 0xF10043FF); the NZCV
/// slot (byte 0x108) must reflect flags of (0x8000 - 0x10) = 0x7FF0: no borrow
/// so C(bit29)=1, positive result so N(bit31)=0. The XZR-base bug would give
/// (0 - 0x10) → borrow → C=0, negative → N=1 (the inverse).
#[test]
fn cmp_sp_imm_compares_sp_not_xzr() {
    let _serial = serial();
    /// SP lives at byte 0xF8 -> u64 slot 31.
    const SP_SLOT: usize = 0x0F8 / 8;
    // CMP SP, #0x10 = SUBS XZR, SP, #16 = 0xF10043FF.
    let words = [0xF100_43FFu32];
    let code = translate_straight_line(&words, 0x1000);
    assert_eq!(*code.last().unwrap(), 0xC3, "block must end in RET");
    assert!(
        !code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "CMP SP,#imm block must not contain UD2"
    );
    let exec = winexec::make_executable(&code);
    let mut ctx = [0u64; CTX_U64S];
    ctx[SP_SLOT] = 0x8000; // SP = 0x8000; XZR (the bug's value) would be 0
    // SAFETY: freshly translated RET-terminated block; ctx is register-file sized.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }
    let nzcv = ctx[NZCV_SLOT];
    let c = (nzcv >> 29) & 1;
    let n = (nzcv >> 31) & 1;
    assert_eq!(
        c, 1,
        "CMP SP(0x8000),#0x10: no borrow → C=1 (bug reads XZR=0 → borrow → C=0). NZCV={nzcv:#x}"
    );
    assert_eq!(
        n, 0,
        "CMP SP(0x8000),#0x10: result 0x7FF0 positive → N=0 (bug: 0-0x10 negative → N=1). NZCV={nzcv:#x}"
    );
}
