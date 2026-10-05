//! DBT side of the oracle: translate an ARM64 block through the REAL AETHER DBT
//! and execute the emitted x86_64 on this host, reading state back out of `ctx`.
//!
//! The translate/exec plumbing is copied (deliberately, to avoid disturbing the
//! `#![deny(unsafe_code)]` lib and the `at_exec_proof` integration test) from
//! `aether-translator/tests/at_exec_proof.rs`:
//!   * `translate_straight_line` — decode -> lift -> regalloc -> lower -> RET
//!   * `winexec::make_executable` — VirtualAlloc RWX + copy
//!   * `enter_block` — call the block with R15 = ctx, preserving Win64 NV regs
//!
//! Register-only blocks need nothing more. Blocks with loads/stores use the
//! MMU-off flat path: with `SLOT_SCTLR == 0` (the default) `aether_mmu_xlate`
//! returns the guest VA unchanged as the host pointer, provided the VA is inside
//! the pinned guest window. We therefore seed the address register with a real
//! host pointer into a shared scratch buffer and register that buffer as the
//! window (see `run_block_dbt` memory handling).

#![allow(unsafe_code)]

use aether_translator::backend::{IntLower, X86Encoder};
use aether_translator::decoder::decode_instruction;
use aether_translator::ir::{BlockId, IrFunction};
use aether_translator::lift::lift_at;
use aether_translator::regalloc;
use aether_translator::runtime::mmu::aether_mmu_set_window;

use crate::ctx::{OracleState, CTX_U64S};

/// Translate a straight-line ARM64 sequence into one RET-terminated x86 block.
/// Returns `Err` with a human string on decode/lift failure so the driver can
/// mark the block SKIPPED rather than crash the whole corpus run.
///
/// The bool in the Ok tuple is the DBT's `had_ud2` fail-loud flag: when true the
/// lowering hit an unimplemented (Tier-1) case and emitted `UD2` — executing that
/// block would raise STATUS_ILLEGAL_INSTRUCTION and abort the whole harness, so
/// the caller must NOT run it. A UD2 is a *known gap*, not a silent miscompile:
/// the DBT deliberately fails loud rather than returning a wrong value.
pub fn translate_straight_line(words: &[u32], pc: u64) -> Result<(Vec<u8>, bool), String> {
    let mut func = IrFunction::new(pc);
    {
        let block = func.add_block();
        let mut cur = pc;
        for (i, &w) in words.iter().enumerate() {
            let insn = decode_instruction(w)
                .map_err(|e| format!("decode word[{i}]=0x{w:08x} failed: {e:?}"))?;
            lift_at(&insn, block, cur)
                .map_err(|e| format!("lift word[{i}]=0x{w:08x} failed: {e:?}"))?;
            cur += 4;
        }
    }
    let alloc = regalloc::allocate(&func);
    let mut enc = X86Encoder::new();
    let mut patches: Vec<(usize, BlockId)> = Vec::new();
    for blk in &func.blocks {
        IntLower::lower_block(blk, &alloc, &mut enc, &mut patches);
    }
    enc.emit_ret();
    let had_ud2 = enc.had_ud2();
    Ok((enc.finish(), had_ud2))
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
        // SAFETY: standard VirtualAlloc usage; size non-zero; exact-length copy.
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
/// Win64 nonvolatile registers around the call.
///
/// SAFETY: `code` must be a valid RET-terminated x86 block from the translator;
/// `ctx` must be a buffer of at least `CTX_U64S` u64s the block may read/write.
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
        lateout("r15") _,
        clobber_abi("C"),
    );
}

/// A scratch RAM region for a memory block. `base` is the host address the
/// region is pinned at (== the guest VA the DBT resolves flat); the caller must
/// have rewritten any address registers in the seed to absolute addresses inside
/// `[base, base + bytes.len())`.
pub struct ScratchMem {
    /// Host base pointer of the region (also the guest VA under the flat path).
    pub base: u64,
    /// Backing bytes. Kept live (and pinned in place) for the duration of the run.
    pub bytes: Vec<u8>,
}

impl ScratchMem {
    /// Allocate a `len`-byte scratch region and report its host base. The caller
    /// seeds bytes into `.bytes` and rewrites seed address registers to
    /// `base + offset` BEFORE calling `run_block_dbt`.
    pub fn new(len: usize) -> Self {
        // Box the bytes into a stable heap allocation; `Vec` won't reallocate
        // because we never grow it after `base` is taken.
        let bytes = vec![0u8; len];
        let base = bytes.as_ptr() as u64;
        Self { base, bytes }
    }
}

/// Result of running one block through the DBT.
pub struct DbtRun {
    pub out: OracleState,
    /// Scratch bytes after execution (moved back to the caller for diffing).
    /// `None` when the block declared no memory region.
    pub mem_after: Option<Vec<u8>>,
    /// Emitted x86 length (diagnostic).
    pub x86_len: usize,
}

/// Run `words` (an ARM64 block at `pc`) through the DBT with `seed` as input.
///
/// If `mem` is `Some(scratch)` the region is pinned as the MMU window so the
/// flat (MMU-off) load/store path resolves guest VA == host pointer, and the
/// mutated bytes are returned in `DbtRun::mem_after`.
pub fn run_block_dbt(
    words: &[u32],
    pc: u64,
    seed: &OracleState,
    mem: Option<ScratchMem>,
) -> Result<DbtRun, String> {
    let (code, had_ud2) = translate_straight_line(words, pc)?;
    if had_ud2 {
        // The DBT emitted a fail-loud UD2 (unimplemented Tier-1 lowering).
        // Executing it would raise an illegal-instruction fault and kill the
        // process, so report the gap instead of running the block.
        return Err("dbt gap: lowering emitted UD2 (unimplemented, fail-loud)".to_string());
    }
    let x86_len = code.len();

    // Pin the guest window. With a memory region: the whole scratch span. Without
    // one: base 1 / size 0 => `in_window()` is always false, so any stray flat
    // access faults (early RET) rather than reading arbitrary host memory.
    let mut scratch = mem;
    match &scratch {
        Some(s) => aether_mmu_set_window(s.base, s.bytes.len() as u64),
        None => aether_mmu_set_window(1, 0),
    }

    let exec = winexec::make_executable(&code);
    let mut ctx = vec![0u64; CTX_U64S];
    seed.write_ctx(&mut ctx);
    // SLOT_SCTLR left at 0 => MMU off => flat memory path.

    // SAFETY: `exec` is RWX with a RET-terminated block; ctx is full-size; the
    // scratch region (if any) is pinned in place and lives across the call.
    unsafe {
        enter_block(exec, ctx.as_mut_ptr());
    }

    let out = OracleState::read_ctx(&ctx);
    let mem_after = scratch.take().map(|s| s.bytes);
    Ok(DbtRun { out, mem_after, x86_len })
}
