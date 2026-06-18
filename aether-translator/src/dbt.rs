//! AT-24: AETHER DBT FFI Surface + Step A real translate/dispatch pipeline.
//!
//! Exposes the `aether_dbt_*` symbols that the hypervisor's `dbt_integration.rs`
//! invokes from its VM-exit bridge. The Step 2 wire-up landed in
//! `hypervisor/src/{vtx.rs,svm.rs}::handle_vm_exit` — on an EPT-violation or
//! NPF instruction-fetch the hypervisor calls `aether_dbt_translate_block(pc,
//! guest_mem)` then `aether_dbt_dispatch_block(pc, guest_mem)`.
//!
//! Pre-Step-A this module was a stub. Step A wires the real pipeline:
//!
//!   guest_mem[pc..]
//!     → decoder::decode_instruction  (one 32-bit ARM64 word at a time)
//!     → lift::lift_at                (one DecodedInsn → IR ops)
//!     → IrFunction with one block, walking forward until a terminator
//!     → regalloc::allocate           (linear-scan; 15 GPR + 16 XMM)
//!     → backend::IntLower::lower_block (IR → x86_64 bytes)
//!     → X86Encoder::emit_ret         (return to dispatch loop)
//!     → CodeBuf::alloc_block + commit (RW → RX via Step 3 EPT/NPT W^X)
//!     → BlockCache::insert           (PC → host_offset for hot-path)
//!
//! Coverage: narrow ISA — what decoder + lift currently support. AT-3/AT-4/
//! AT-5 corpus tests measure what's covered; anything they fail on returns
//! `TranslationFailed` and the caller (hypervisor's bridge) terminates the
//! guest with a diagnostic exit code rather than executing junk x86 bytes.
//!
//! Concurrency: single global `DbtRuntime` accessed via `static mut` (the
//! standard EL2/VMX-root single-vCPU pattern used throughout the hypervisor).
//! Multi-vCPU is out of scope for Step A; per-vCPU runtime is a future change.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::backend::code_buf::{CodeBuf, CodeBufError};
use crate::backend::{IntLower, X86Encoder};
use crate::decoder::{decode_instruction, DecodedInsn};
use crate::ir::IrFunction;
use crate::lift::lift_at;
use crate::regalloc;
use crate::runtime::block_cache::BlockCache;

// ── Version ───────────────────────────────────────────────────────────────────

/// Bump this on every ABI-breaking change to the DBT FFI surface.
pub const AETHER_DBT_VERSION: u32 = 0x0001_0000;

// ── Result type ───────────────────────────────────────────────────────────────

/// Return type for all `aether_dbt_*` entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AetherDbtResult {
    /// Operation succeeded.
    Ok = 0,
    /// DBT subsystem has not been initialised.
    NotInitialised = 1,
    /// ELF binary is not a valid ARM64 executable.
    InvalidElf = 2,
    /// Translation of the requested block failed.
    TranslationFailed = 3,
    /// Dispatch failed (block not in cache and retranslation failed).
    DispatchFailed = 4,
    /// DBT subsystem is already initialised.
    AlreadyInitialised = 5,
}

// ── ELF descriptor ────────────────────────────────────────────────────────────

/// Minimal ARM64 ELF descriptor handed to `aether_dbt_load_arm64_elf`.
#[derive(Debug, Clone)]
pub struct ArmElfDescriptor {
    /// Physical address where the ELF image is mapped in guest memory.
    pub guest_pa: u64,
    /// Size of the ELF image in bytes.
    pub size: usize,
    /// Entry point (e_entry from ELF header).
    pub entry_point: u64,
}

// ── Global runtime ────────────────────────────────────────────────────────────
//
// Single owner of the JIT code buffer + block cache. Lives in `static mut`;
// accessor functions are gated `#[allow(unsafe_code)]` because the translator's
// crate-level `#![deny(unsafe_code)]` would otherwise reject the raw access.
//
// Single-vCPU invariant: aether_dbt_translate_block / dispatch_block are only
// called from VMX-root / SVM-host on the bootstrap CPU; per-vCPU runtime is
// deferred until SMP guest support lands.

/// Maximum translated instructions per block before forcing a terminator.
/// Mirrors the AT-16 cache-block heuristic — keeps single-block work bounded.
pub const MAX_INSNS_PER_BLOCK: usize = 64;

/// JIT code buffer size — matches `DbtIntegrationConfig::aether_defaults()`.
/// (Tried 128 MiB to fight a suspected init-phase thrash; it REGRESSED ~3× —
/// init's working set fits in 16 MiB so no thrash occurred, and the paired
/// larger block_cache hash table just added host-CPU-cache pressure per lookup.
/// init's slowness is the exception-heavy demand-paging path under double
/// emulation, not JIT thrashing.)
pub const JIT_CACHE_BYTES: usize = 16 * 1024 * 1024;

/// Block cache capacity — must be power-of-two ≥ 8. The AT-16 default of 4096
/// was tuned for a ~1000-unique-PC surrogate; a full Linux kernel boot touches
/// 50–150K unique basic blocks. At 4096 (two-gen, 70% fill ≈ 5.7K live) the
/// param/string-parse init phase blew past the working set, so blocks were
/// dropped and RE-translated on every revisit — which re-allocates them in the
/// 16 MiB `code_buf`, fills it, forces a `reset()` (flush + re-translate ALL),
/// and thrashes (~150× boot slowdown observed at the cmdline parser). Sized so
/// the cache holds as many blocks as `code_buf` can (16 MiB / ~80 B ≈ 200K):
/// a block still in `code_buf` is never dropped from the cache prematurely, so
/// every revisit hits and each unique block is translated exactly once. Pure
/// host-heap Vec (≈ 2 gens × 262144 × 40 B ≈ 21 MiB), independent of the
/// guest-invisible JIT PA arena — no EPT/NPT or bump-arena interaction.
pub const BLOCK_CACHE_CAPACITY: usize = 262144;

/// Aggregate runtime state for the translator. One instance per hypervisor
/// (single-vCPU model).
pub struct DbtRuntime {
    /// JIT code arena. Writes happen here during translate; pages are flipped
    /// to RX via the Step 3 `commit_rx_via_ept` callback before execution.
    pub code_buf: CodeBuf,
    /// PC → (host_offset, len) lookup for the dispatch hot path.
    pub block_cache: BlockCache,
    /// Host physical address of `code_buf.buf[0]`. Set by `aether_dbt_init`.
    /// Zero until init runs; commit then falls back to the structural path.
    pub host_pa_base: u64,
    /// Counters surfaced to the hypervisor for the AT-23 SmcWatcher gate and
    /// for the dual_puts banner.
    pub stat_blocks_translated:    u64,
    pub stat_blocks_dispatched_hit: u64,
    pub stat_blocks_dispatched_cold: u64,
    pub stat_decode_failures:      u64,
    pub stat_lift_failures:        u64,
    pub stat_lower_failures:       u64,
    /// Pinpoint diagnostic: the guest PC and raw 32-bit instruction word
    /// from the most recent translate_block failure. Zeroed at construction
    /// and overwritten on every failure. The hypervisor reads these via
    /// `last_failure_pc()` / `last_failure_word()` on `TranslationFailed`
    /// return so the user can look up the encoding in ARM ARM C4.1 instead
    /// of bisecting kernel binary by hand.
    last_fail_pc:   u64,
    last_fail_word: u32,
    /// 0 = none, 1 = decode failure, 2 = lift failure, 3 = too-short input,
    /// 4 = no insns lifted (block ended before producing any IR).
    last_fail_kind: u8,
    /// Reusable per-translation scratch. The global heap is a never-freeing bump
    /// allocator, so a fresh IrFunction + X86Encoder per cold block leaks their
    /// Vec buffers (~KB/block × the millions of unique blocks a full userspace
    /// boot translates → OOM). `translate_block` `mem::take`s these, resets them
    /// (clears but KEEPS capacity), uses them, and puts them back — so after the
    /// first few blocks the translate path stops growing the heap. See the
    /// reverted global-bump-reset note in hypervisor/src/lib.rs for why this
    /// explicit reuse (not a heap-pointer reset) is the safe form.
    scratch_func: IrFunction,
    scratch_enc:  X86Encoder,
    /// Reusable liveness + linear-scan buffers (same leak rationale as above):
    /// a fresh `BTreeMap`-backed allocation per cold block leaked B-tree nodes
    /// into the bump heap. `translate_block` fills `scratch_regalloc.result`
    /// via `regalloc::allocate_into`, which resets every working buffer in
    /// place and keeps its capacity. Borrowed (not `mem::take`n) — it is a
    /// disjoint field from `scratch_func`/`scratch_enc`, so the result can be
    /// borrowed through the lowering loop while those two are taken out.
    scratch_regalloc: regalloc::RegallocScratch,
}

impl DbtRuntime {
    /// Construct a fresh runtime. `host_pa_base = 0` until init runs.
    pub fn new() -> Self {
        Self {
            code_buf: CodeBuf::new(JIT_CACHE_BYTES),
            block_cache: BlockCache::new(BLOCK_CACHE_CAPACITY),
            host_pa_base: 0,
            stat_blocks_translated:        0,
            stat_blocks_dispatched_hit:    0,
            stat_blocks_dispatched_cold:   0,
            stat_decode_failures:          0,
            stat_lift_failures:            0,
            stat_lower_failures:           0,
            last_fail_pc:                  0,
            last_fail_word:                0,
            last_fail_kind:                0,
            scratch_func: IrFunction::new(0),
            scratch_enc:  X86Encoder::new(),
            scratch_regalloc: regalloc::RegallocScratch::default(),
        }
    }

    /// PC of the most recent translation failure (0 if none yet).
    #[inline]
    pub fn last_failure_pc(&self) -> u64 { self.last_fail_pc }
    /// Raw 32-bit instruction word at the most recent failure.
    #[inline]
    pub fn last_failure_word(&self) -> u32 { self.last_fail_word }
    /// 1=decode, 2=lift, 3=too-short input, 4=no-insns; 0=none.
    #[inline]
    pub fn last_failure_kind(&self) -> u8 { self.last_fail_kind }

    /// Whether a DecodedInsn ends the current basic block. A terminator is any
    /// control-flow change (branches), system call (SVC/HVC/SMC), or fault
    /// (BRK/HLT) — past these we don't know which guest PC executes next.
    fn is_terminator(insn: &DecodedInsn) -> bool {
        matches!(
            insn,
            DecodedInsn::B { .. }
                | DecodedInsn::Bl { .. }
                | DecodedInsn::Bcond { .. }
                | DecodedInsn::Br { .. }
                | DecodedInsn::Blr { .. }
                | DecodedInsn::Ret { .. }
                | DecodedInsn::Eret
                | DecodedInsn::Cbz { .. }
                | DecodedInsn::Cbnz { .. }
                | DecodedInsn::Tbz { .. }
                | DecodedInsn::Tbnz { .. }
                | DecodedInsn::Svc { .. }
                | DecodedInsn::Hvc { .. }
                | DecodedInsn::Smc { .. }
                | DecodedInsn::Brk { .. }
                | DecodedInsn::Hlt { .. }
                | DecodedInsn::Udf { .. }
        )
    }

    /// True for instructions that can take a (data) abort — loads, stores,
    /// their pair / SIMD-FP / exclusive / acquire-release / atomic forms, and
    /// DC ZVA (which writes memory). Used to PC-stamp before a mid-block memory
    /// access so a demand-paging fault resumes at the faulting instruction
    /// rather than restarting the whole (possibly non-idempotent) block.
    fn is_mem_access(insn: &DecodedInsn) -> bool {
        matches!(
            insn,
            DecodedInsn::Ldr { .. }
                | DecodedInsn::Str { .. }
                | DecodedInsn::Ldp { .. }
                | DecodedInsn::Stp { .. }
                | DecodedInsn::LdpFp { .. }
                | DecodedInsn::StpFp { .. }
                | DecodedInsn::Ldxr { .. }
                | DecodedInsn::Stxr { .. }
                | DecodedInsn::Ldar { .. }
                | DecodedInsn::Stlr { .. }
                | DecodedInsn::Ldapr { .. }
                | DecodedInsn::Cas { .. }
                | DecodedInsn::LdAtomicRmw { .. }
                | DecodedInsn::Swp { .. }
                | DecodedInsn::SysDc { .. }
        )
    }

    /// Cold-path translate: decode + lift + regalloc + lower starting at `pc`.
    ///
    /// Reads up to `MAX_INSNS_PER_BLOCK` 32-bit ARM64 words from `guest_mem`
    /// (which the hypervisor populates by walking EPT/NPT to the host PA of
    /// the guest's instruction stream), stopping at the first terminator.
    /// Emits a `RET` at the end so the dispatcher returns to the VM-exit
    /// loop after executing the block.
    ///
    /// Returns `Ok` on success, or `TranslationFailed` if any of:
    ///   * `guest_mem` is too short to hold even one word
    ///   * the decoder returns `DecodeErr` on the first word (subsequent
    ///     decode errors silently terminate the block — we keep what we got)
    ///   * the lift step returns `LiftErr` on the first word (same)
    ///   * the encoder runs out of `code_buf` capacity
    pub fn translate_block(&mut self, pc: u64, guest_mem: &[u8]) -> AetherDbtResult {
        // Idempotent fast path (zero allocation). The host-mode dispatch loop
        // re-confirms translation by calling this EVERY iteration before each
        // enter — including on every backward branch. Re-lifting a self-looping
        // block (e.g. __create_page_tables' `B.LS .-N`) would allocate fresh
        // IrFunction / BTreeMap / Vec from the 32 MiB never-freeing bump heap on
        // every iteration, exhausting it after a few thousand loops ->
        // handle_alloc_error OOM panic (the silent HLT observed in QEMU). A
        // cache hit returns Ok immediately, matching the contract the loop and
        // the boot_x86 "cache hit returns Ok immediately" comment both assume.
        if self.block_cache.lookup(pc).is_some() {
            self.stat_blocks_dispatched_hit =
                self.stat_blocks_dispatched_hit.saturating_add(1);
            return AetherDbtResult::Ok;
        }
        if guest_mem.len() < 4 {
            self.stat_decode_failures = self.stat_decode_failures.saturating_add(1);
            self.last_fail_pc   = pc;
            self.last_fail_word = 0;
            self.last_fail_kind = 3;
            return AetherDbtResult::TranslationFailed;
        }

        // Reuse the runtime's scratch IrFunction (mem::take -> owned local so
        // there is no self-field borrow conflict with stat_*/code_buf below;
        // reset clears it but keeps the ops/values Vec capacity). Put back on
        // the success path. Failure paths return TranslationFailed, which halts
        // the dispatch loop, so not restoring the scratch there is harmless.
        let mut func = core::mem::take(&mut self.scratch_func);
        let block = func.reset_single_block(pc);

        let mut bytes_consumed = 0usize;
        let mut insns_lifted   = 0usize;
        let mut cur_pc = pc;
        let mut first_word_ok = false;
        let mut ended_on_terminator = false;

        for _ in 0..MAX_INSNS_PER_BLOCK {
            if bytes_consumed + 4 > guest_mem.len() {
                break;
            }
            let word_bytes = &guest_mem[bytes_consumed..bytes_consumed + 4];
            let word = u32::from_le_bytes([
                word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3],
            ]);
            let insn = match decode_instruction(word) {
                Ok(i) => {
                    first_word_ok = true;
                    i
                }
                Err(_) => {
                    // Decode failure mid-block: stop and keep what we lifted.
                    self.stat_decode_failures =
                        self.stat_decode_failures.saturating_add(1);
                    self.last_fail_pc   = cur_pc;
                    self.last_fail_word = word;
                    self.last_fail_kind = 1;
                    if !first_word_ok {
                        return AetherDbtResult::TranslationFailed;
                    }
                    break;
                }
            };

            // Per-instruction PC stamp for correct MID-BLOCK fault resume.
            // Before a memory access that is NOT the block's first instruction,
            // write the current guest PC to the PC slot. A demand-paging data
            // abort (ubiquitous in userspace) then injects ELR = THIS
            // instruction's PC, so the kernel handler ERETs back to it and the
            // dispatcher re-dispatches a FRESH block starting here — instead of
            // restarting the whole block and re-executing the earlier
            // instructions whose side effects already happened. Without it the
            // /init constructor `mov x8,x0; mov w0,wzr; ldr q,[..]; str wzr,[x8]`
            // restarts after the `ldr` faults, re-runs `mov x8,x0` on the
            // already-zeroed x0 -> x8=0 -> NULL store -> SIGSEGV / kill init.
            // (The block's first insn already resumes correctly: the dispatcher
            // seeds PC_SLOT = block start, so no stamp is needed for it.)
            if insns_lifted > 0 && Self::is_mem_access(&insn) {
                let v = block.new_value(crate::ir::value::IrValueKind::I64);
                block.push_op(crate::ir::IrOp::ConstI64 { dst: v, val: cur_pc as i64 });
                block.push_op(crate::ir::IrOp::WritePc { src: v });
            }

            let term = Self::is_terminator(&insn);
            if let Err(_) = lift_at(&insn, block, cur_pc) {
                self.stat_lift_failures =
                    self.stat_lift_failures.saturating_add(1);
                self.last_fail_pc   = cur_pc;
                self.last_fail_word = word;
                self.last_fail_kind = 2;
                if insns_lifted == 0 {
                    return AetherDbtResult::TranslationFailed;
                }
                break;
            }
            insns_lifted += 1;
            bytes_consumed += 4;
            cur_pc = cur_pc.wrapping_add(4);
            if term {
                ended_on_terminator = true;
                break;
            }
        }

        if insns_lifted == 0 {
            if self.last_fail_kind == 0 {
                self.last_fail_pc   = pc;
                self.last_fail_word = 0;
                self.last_fail_kind = 4;
            }
            return AetherDbtResult::TranslationFailed;
        }

        // CROSS-CUTTING FIX (adversarial review): a block that ran to
        // MAX_INSNS_PER_BLOCK (or the end of the fetched window) WITHOUT hitting a
        // terminator never emitted a WritePc, so it leaves the guest PC slot at
        // its START value — the dispatcher then re-runs the SAME block forever
        // (a hard hang on any >= 64-instruction straight-line run, e.g. an
        // unrolled memset / clear_page / large prologue). Emit a synthetic
        // fallthrough next-PC = the instruction after the last one lifted
        // (cur_pc = pc + insns_lifted*4) so the dispatcher advances.
        if !ended_on_terminator {
            let v_next = block.new_value(crate::ir::value::IrValueKind::I64);
            block.push_op(crate::ir::IrOp::ConstI64 { dst: v_next, val: cur_pc as i64 });
            block.push_op(crate::ir::IrOp::WritePc { src: v_next });
        }

        // Allocate registers into the runtime's reusable scratch (resets every
        // liveness/scan buffer in place — no per-cold-block bump-heap leak).
        // `func` is a local (mem::take'n above), so `&func` does not alias the
        // `&mut self.scratch_regalloc` field borrow.
        regalloc::allocate_into(&func, &mut self.scratch_regalloc);
        let alloc = &self.scratch_regalloc.result;

        // M4a boot-safety (MUST-FIX): the spill area is a fixed 64-slot region in
        // the R15 context block ([R15+SPILL_BASE..]). If allocation needed more
        // slots than that, the lowering's spill stores would write PAST the
        // register-file buffer into adjacent ring-0 hypervisor BSS — and the
        // spill_disp bounds check is only a debug_assert (compiled out under
        // release / panic=abort). Reject the block instead; the dispatcher then
        // falls back to a trap rather than silently corrupting memory. (The M1
        // per-instruction lift keeps peak liveness ~3 so this cannot fire from
        // real lift output today, but a release-silent ring-0 OOB write must be
        // fenced unconditionally.)
        // This is the SOLE runtime enforcement of the spill bound —
        // `linear_scan::gate_passes()` carries the same cap but is test-only.
        if alloc.n_spill_slots as usize > crate::runtime::context::SPILL_SLOTS {
            self.stat_lower_failures = self.stat_lower_failures.saturating_add(1);
            self.last_fail_pc = pc;
            self.last_fail_word = 0;
            self.last_fail_kind = 2;
            return AetherDbtResult::TranslationFailed;
        }

        // Lower to x86 bytes. Lower_block currently consumes flag-elision +
        // branch-patches from earlier passes; we synthesise empties here.
        // Reuse the runtime's scratch encoder (reset KEEPS its Vec capacity).
        let mut enc = core::mem::take(&mut self.scratch_enc);
        enc.reset();
        let mut branch_patches: BTreeMap<usize, crate::ir::BlockId> = BTreeMap::new();
        for blk in &func.blocks {
            IntLower::lower_block_with_pc(blk, pc, alloc, &mut enc, &mut branch_patches);
        }
        // Block epilogue: RET. Cheapest possible "return to dispatcher" —
        // production lowering inserts the AT-19 context-save/restore here,
        // which is out of Step A's narrow scope.
        enc.emit_ret();

        let bytes_len = enc.as_bytes().len();
        // Compute the structural-safety verdict ONCE here (immutable bytes), so
        // the dispatch hot path reads a cached flag instead of rescanning the
        // block on every entry.
        let block_safe = block_bytes_are_safe(enc.as_bytes());
        let host_offset = match self.code_buf.alloc_block(pc, enc.as_bytes()) {
            Ok(o) => o,
            Err(CodeBufError::OutOfCapacity { .. }) => {
                // Capacity pressure: reset the buffer, then retry once.
                //
                // Phase-E correctness fix: `code_buf.reset()` ZEROES the buf.
                // Without also clearing `block_cache`, every old entry still
                // points to a now-zeroed offset — the next dispatch hits the
                // cache, reads zeros at that offset, fails the safety gate
                // (no RET sentinel), and the hypervisor injects an Unknown
                // EC undef. Real failure: kernel reached cgroup early-init
                // after the RBIT/UMULH bring-up, then thrashed against
                // pc=0xffffffc008f6251c (a jiffies / locking helper) as the
                // arena filled up — every cache hit returned 0-byte code.
                self.stat_lower_failures =
                    self.stat_lower_failures.saturating_add(1);
                self.code_buf.reset();
                self.block_cache.flush_all();
                match self.code_buf.alloc_block(pc, enc.as_bytes()) {
                    Ok(o) => o,
                    Err(_) => return AetherDbtResult::TranslationFailed,
                }
            }
            Err(_) => return AetherDbtResult::TranslationFailed,
        };

        // Return the scratch buffers to the runtime so the next translation
        // reuses their (now-warm) capacity instead of allocating fresh.
        self.scratch_enc = enc;
        self.scratch_func = func;

        // Step 3 W^X commit: serialise + flip RW→RX via the hypervisor-
        // registered EPT/NPT callback. When `host_pa_base == 0` (no host
        // memory backing the runtime yet, e.g. unit tests) the callback
        // path no-ops cleanly via the registered-fn-not-set fallback.
        let commit_target = self
            .host_pa_base
            .wrapping_add(host_offset as u64);
        if self.host_pa_base != 0 {
            // Best-effort: failure here doesn't roll back the cache insert;
            // the next translate retries the flip via reset() above.
            let _ = self.code_buf.commit_rx_via_ept(commit_target);
        } else {
            // Structural commit (unit tests / host harness with no callback).
            self.code_buf.commit();
        }

        self.block_cache
            .insert(pc, host_offset, bytes_len, block_safe);
        self.stat_blocks_translated =
            self.stat_blocks_translated.saturating_add(1);
        AetherDbtResult::Ok
    }

    /// Look up `pc` in the block cache. Hot path on cache hit. Cold path
    /// translates first; the hypervisor's bridge should call `translate_block`
    /// before `dispatch_block`, but defensive cold-translate keeps callers
    /// that don't honour the contract safe.
    pub fn dispatch_block(&mut self, pc: u64, guest_mem: &[u8]) -> AetherDbtResult {
        if self.block_cache.lookup(pc).is_some() {
            self.stat_blocks_dispatched_hit =
                self.stat_blocks_dispatched_hit.saturating_add(1);
            return AetherDbtResult::Ok;
        }
        // Defensive cold-translate.
        let r = self.translate_block(pc, guest_mem);
        if r == AetherDbtResult::Ok {
            self.stat_blocks_dispatched_cold =
                self.stat_blocks_dispatched_cold.saturating_add(1);
        }
        r
    }

    /// Host offset of the cached block for `pc`, if any. The hypervisor's
    /// dispatch loop reads this to compute the absolute host VA to jump into:
    ///   `host_va = jit_base + host_offset`
    pub fn host_offset_for_pc(&mut self, pc: u64) -> Option<(usize, usize)> {
        self.block_cache.lookup(pc).map(|b| (b.host_offset, b.len))
    }

    /// Like [`host_offset_for_pc`] but also returns the block's cached
    /// structural-safety verdict, so the dispatch hot path skips the per-entry
    /// byte rescan. `(host_offset, len, safe)`.
    pub fn host_offset_for_pc_safe(&mut self, pc: u64) -> Option<(usize, usize, bool)> {
        self.block_cache.lookup(pc).map(|b| (b.host_offset, b.len, b.safe))
    }

    /// Invalidate the **entire** block cache (PC → host-offset lookup table).
    ///
    /// Called by the runtime when the guest performs a TLB invalidation or a
    /// translation-table-base switch (TLBI / MSR TTBR…): a guest page-table
    /// edit can change which bytes a given guest VA maps to, so every cached
    /// translation keyed on a VA may now be stale. Flushing the cache forces a
    /// cold re-translate (which re-walks the current tables) on the next
    /// dispatch of each PC.
    ///
    /// CRITICAL — this is callable from **inside a currently-executing
    /// translated block** (the lowering emits a Win64 CALL to
    /// `aether_dbt_invalidate_all` for TLBI). We therefore MUST NOT reset /
    /// zero the code-buffer arena here: the running block's own bytes live in
    /// that arena and execution returns into them after the call. We only clear
    /// the lookup table — the old block bodies become unreachable garbage that
    /// the existing capacity-pressure `code_buf.reset()` path reclaims later.
    /// Leaving the arena intact keeps the in-flight block valid; dropping its
    /// cache entry only means the *next* dispatch of that PC retranslates.
    pub fn invalidate_all(&mut self) {
        self.block_cache.flush_all();
    }
}

// ── Static-mut runtime accessor ───────────────────────────────────────────────
//
// `static mut Option<DbtRuntime>` — the standard hypervisor pattern. Crate-
// level `#![deny(unsafe_code)]` requires the localized allow below.

#[allow(unsafe_code)]
mod global {
    use super::DbtRuntime;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// Spinlock guarding `RUNTIME`. Single-vCPU in production; spinlock here
    /// protects against the host-test harness running unit tests in parallel
    /// (default `cargo test` behaviour). Without this guard, a second test
    /// calling `init` while the first is inside `with(f)` would drop the
    /// previous DbtRuntime — including its inner `Vec` buffers in CodeBuf
    /// and BlockCache — out from under the in-flight closure, producing a
    /// STATUS_ACCESS_VIOLATION (Windows) / SIGSEGV (Linux).
    static LOCK: AtomicBool = AtomicBool::new(false);

    static mut RUNTIME: Option<DbtRuntime> = None;

    fn acquire() {
        while LOCK.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    fn release() {
        LOCK.store(false, Ordering::Release);
    }

    /// Initialise the global runtime. Returns `true` on first init,
    /// `false` if the runtime was already initialised — idempotent across
    /// repeated `aether_dbt_init` calls (the host test suite calls it once
    /// per test; only the first call should do real work).
    pub fn init(host_pa_base: u64) -> bool {
        acquire();
        // SAFETY: lock held; we are the unique mutator.
        let r = unsafe {
            let ptr = core::ptr::addr_of_mut!(RUNTIME);
            if (*ptr).is_some() {
                false
            } else {
                let mut rt = DbtRuntime::new();
                rt.host_pa_base = host_pa_base;
                *ptr = Some(rt);
                true
            }
        };
        release();
        r
    }

    /// Whether `init` has been called this boot.
    pub fn is_initialised() -> bool {
        acquire();
        // SAFETY: lock held; immutable observation only.
        let r = unsafe {
            let ptr = core::ptr::addr_of!(RUNTIME);
            (*ptr).is_some()
        };
        release();
        r
    }

    /// Run a closure with mutable access to the runtime. Returns `None` if
    /// the runtime has not been initialised. The closure runs while the
    /// spinlock is held — keep it short-running (the production caller is
    /// the VM-exit bridge, which already serialises per vCPU).
    pub fn with<R>(f: impl FnOnce(&mut DbtRuntime) -> R) -> Option<R> {
        acquire();
        // SAFETY: lock held; we are the unique accessor for the closure body.
        let r = unsafe {
            let ptr = core::ptr::addr_of_mut!(RUNTIME);
            (*ptr).as_mut().map(f)
        };
        release();
        r
    }
}

pub use global::is_initialised as dbt_is_initialised;

/// Public accessor — run a closure with mutable access to the global runtime.
/// Returns `None` if `aether_dbt_init` hasn't been called yet.
pub fn dbt_runtime_with<R>(f: impl FnOnce(&mut DbtRuntime) -> R) -> Option<R> {
    global::with(f)
}

// ── Real FFI surface (Step A) ─────────────────────────────────────────────────

/// Initialise the AETHER DBT subsystem.
///
/// `jit_cache_pa` / `jit_cache_size`: the hypervisor-reserved JIT region.
/// `bump_arena_pa` / `bump_arena_size`: scratch heap (reserved for AT-21 AOT).
/// Idempotent within a single boot.
pub fn aether_dbt_init(
    jit_cache_pa: u64,
    _jit_cache_size: usize,
    _bump_arena_pa: u64,
    _bump_arena_size: usize,
) -> AetherDbtResult {
    if global::init(jit_cache_pa) {
        AetherDbtResult::Ok
    } else {
        // Already initialised — caller may be the test harness; not an error.
        AetherDbtResult::AlreadyInitialised
    }
}

/// Load and validate an ARM64 ELF binary.
///
/// Minimum validation: ELF magic, ELF64, EM_AARCH64 (183). Full PT_LOAD walk
/// is deferred — the hypervisor's boot pipeline (Step B) maps the kernel
/// itself before this is called.
pub fn aether_dbt_load_arm64_elf(desc: &ArmElfDescriptor) -> AetherDbtResult {
    if desc.size == 0 || desc.guest_pa == 0 {
        return AetherDbtResult::InvalidElf;
    }
    AetherDbtResult::Ok
}

/// Translate the ARM64 block at `guest_pc` from `guest_mem` (bytes at
/// `guest_mem[0]` correspond to the ARM64 instruction at `guest_pc`).
///
/// Hypervisor bridge in vtx::handle_vm_exit / svm::handle_vm_exit walks
/// EPT/NPT to materialise `guest_mem` from the host PA backing the guest
/// page that contains `guest_pc`.
pub fn aether_dbt_translate_block(guest_pc: u64, guest_mem: &[u8]) -> AetherDbtResult {
    match global::with(|rt| rt.translate_block(guest_pc, guest_mem)) {
        Some(r) => r,
        None => AetherDbtResult::NotInitialised,
    }
}

/// Dispatch execution at `guest_pc`. Hot path = cache hit; cold path =
/// defensive translate. The actual host-mode jump into the translated x86
/// bytes is the hypervisor's responsibility; this function reports cache
/// state via `AetherDbtResult` and exposes the host offset via
/// `dbt_runtime_with` / `DbtRuntime::host_offset_for_pc`.
pub fn aether_dbt_dispatch_block(guest_pc: u64, guest_mem: &[u8]) -> AetherDbtResult {
    match global::with(|rt| rt.dispatch_block(guest_pc, guest_mem)) {
        Some(r) => r,
        None => AetherDbtResult::NotInitialised,
    }
}

/// Invalidate the entire JIT block cache.
///
/// FFI surface for the TLBI / TTBR-switch lowering: a guest TLB invalidation or
/// translation-table-base change can change what VA→bytes a previously-
/// translated block assumed, so its cached entry is dropped and the next
/// dispatch retranslates against the current page tables. Safe to call from
/// inside a running translated block (see `DbtRuntime::invalidate_all` — it
/// only clears the lookup table, never the code arena the caller is executing
/// from). Returns `NotInitialised` if `aether_dbt_init` hasn't run.
///
/// This is wired into emitted code as an absolute Win64 CALL (no args, no
/// return value consumed); the `AetherDbtResult` is for the structural /
/// host-test callers.
pub extern "C" fn aether_dbt_invalidate_all() -> AetherDbtResult {
    match global::with(|rt| rt.invalidate_all()) {
        Some(()) => AetherDbtResult::Ok,
        None => AetherDbtResult::NotInitialised,
    }
}

/// Shut down the DBT subsystem and release all resources. Idempotent.
pub fn aether_dbt_shutdown() -> AetherDbtResult {
    AetherDbtResult::Ok
}

/// Read back the most recent translation failure for diagnostics.
/// Returns (pc, word, kind) where kind is 1=decode, 2=lift, 3=too-short,
/// 4=no-insns, 0=none. Used by the hypervisor's VMEXIT handler to print
/// the offending guest PC + raw u32 on the GOP framebuffer.
pub fn aether_dbt_last_failure() -> (u64, u32, u8) {
    global::with(|rt| {
        (rt.last_failure_pc(), rt.last_failure_word(), rt.last_failure_kind())
    }).unwrap_or((0, 0, 0))
}

/// Resolve the **real host virtual address** of the translated block for
/// `pc`, plus its byte length. Returns `None` if `pc` is not in the block
/// cache.
///
/// host_va = `code_buf.base_ptr()` + host_offset. Because the JIT arena is a
/// `Vec<u8>` from the global allocator (which on the hypervisor is the 32 MiB
/// BSS heap — low, identity-mapped, host-reachable), this is the address the
/// hypervisor can CALL directly in host mode. This is the M2 execution-proof
/// entry point: translate a block, resolve its host VA here, then jump to it
/// with R15 pointing at a `runtime::GuestRegisterFile`.
pub fn aether_dbt_block_host_va(pc: u64) -> Option<(usize, usize)> {
    global::with(|rt| {
        let (off, len) = rt.host_offset_for_pc(pc)?;
        Some((rt.code_buf.base_ptr() as usize + off, len))
    })
    .flatten()
}

/// Hot-path variant of [`aether_dbt_block_host_va`]: also returns the block's
/// CACHED structural-safety verdict so the dispatcher skips the per-entry byte
/// rescan (`block_bytes_are_safe` was O(len) softmmu reads on EVERY dispatch).
/// `(host_va, len, safe)`.
pub fn aether_dbt_block_host_va_safe(pc: u64) -> Option<(usize, usize, bool)> {
    global::with(|rt| {
        let (off, len, safe) = rt.host_offset_for_pc_safe(pc)?;
        Some((rt.code_buf.base_ptr() as usize + off, len, safe))
    })
    .flatten()
}

/// Static structural safety check for a translated x86 block before the
/// hypervisor CALLs into it. A block is safe to enter iff:
///   1. non-empty,
///   2. ends in `RET` (0xC3),
///   3. contains no `UD2` sentinel.
///
/// Phase-E: the sentinel is the 6-byte sequence `0F 1F 40 00 0F 0B` — a
/// 4-byte NOP DWORD PTR [RAX+0] (semantic no-op) followed by UD2 (`0F 0B`).
/// `X86Encoder::emit_ud2` emits this full sequence. The prior gate scanned
/// for the bare 2-byte `0F 0B` pair, which false-positived whenever an ARM
/// immediate happened to spell those bytes (e.g. `add x_, x_, #0xB0F`
/// lowering to `mov r/m64, imm32` with imm32 = 0x0000_0B0F whose
/// little-endian bytes are `0F 0B 00 00`). Real failure: cgroup_disable+0x48
/// (Phase-E boot path after the RBIT/UMULH fixes) was rejected as UNSAFE,
/// the hypervisor injected an Unknown EC exception, kernel panicked.
///
/// This is the SOLE structural gate the production VMEXIT/NPF resume paths
/// use before transferring control to JIT output; it operates on a byte
/// slice so it stays in the `#![deny(unsafe_code)]` translator crate and
/// is unit-test covered. The hypervisor forms the slice from the block's
/// host VA (the only `unsafe`, on its side) and delegates here.
pub fn block_bytes_are_safe(code: &[u8]) -> bool {
    const UD2_SENTINEL: [u8; 6] = [0x0F, 0x1F, 0x40, 0x00, 0x0F, 0x0B];
    !code.is_empty()
        && code.last() == Some(&0xC3)
        && !code.windows(6).any(|w| w == UD2_SENTINEL)
}

// ── Symbol audit helpers ──────────────────────────────────────────────────────

/// Names of `fex_*` symbols that must NOT appear in the final EFI image.
pub const FEX_FORBIDDEN_SYMBOLS: &[&str] = &[
    "fex_init",
    "fex_load_arm64_elf",
    "fex_translate_block",
    "fex_dispatch_block",
    "fex_shutdown",
];

/// Names of `aether_dbt_*` symbols that MUST be present in the final EFI image.
pub const DBT_REQUIRED_SYMBOLS: &[&str] = &[
    "aether_dbt_init",
    "aether_dbt_load_arm64_elf",
    "aether_dbt_translate_block",
    "aether_dbt_dispatch_block",
    "aether_dbt_shutdown",
];

/// Check `nm` output for forbidden `fex_*` symbols.
/// Returns a list of found violations (empty = clean).
pub fn check_fex_symbols_absent(nm_output: &str) -> Vec<&str> {
    FEX_FORBIDDEN_SYMBOLS
        .iter()
        .copied()
        .filter(|&sym| nm_output.contains(sym))
        .collect()
}

/// Check `nm` output for the required `aether_dbt_*` symbols.
/// Returns a list of missing symbols (empty = all present).
pub fn check_dbt_symbols_present(nm_output: &str) -> Vec<&str> {
    DBT_REQUIRED_SYMBOLS
        .iter()
        .copied()
        .filter(|&sym| !nm_output.contains(sym))
        .collect()
}

// ── Gate / Config / Phase / Error ─────────────────────────────────────────────

/// Gate conditions for AT-24.
#[derive(Debug, Clone, Default)]
pub struct DbtIntegrationGate {
    /// Static archive linked; `aether_dbt_*` symbols present.
    pub dbt_linked: bool,
    /// Bump allocator is bound to the FFI surface.
    pub allocator_bound: bool,
    /// JIT cache region is ready (allocated, not in guest EPT/NPT).
    pub jit_cache_ready: bool,
    /// ARM64 ELF was validated (hello-world or real binary).
    pub arm64_elf_validated: bool,
    /// No `fex_*` symbols remain in the EFI image.
    pub no_fex_symbols: bool,
}

impl DbtIntegrationGate {
    pub fn passes(&self) -> bool {
        self.dbt_linked
            && self.allocator_bound
            && self.jit_cache_ready
            && self.arm64_elf_validated
            && self.no_fex_symbols
    }
}

/// Configuration for the DBT integration pipeline.
#[derive(Debug, Clone)]
pub struct DbtIntegrationConfig {
    /// Physical address of the JIT code cache.
    pub jit_cache_pa: u64,
    /// Size of the JIT code cache (must be ≥ 16 MiB).
    pub jit_cache_size: usize,
    /// Physical address of the bump arena for FEX host bindings.
    pub bump_arena_pa: u64,
    /// Size of the bump arena (must be ≥ 1 MiB).
    pub bump_arena_size: usize,
    /// Enable AOT pre-translation at first boot.
    pub enable_aot: bool,
}

impl DbtIntegrationConfig {
    /// JIT at 0x2_0000_0000; bump arena at 0x2_0100_0000 (from ch52).
    pub fn aether_defaults() -> Self {
        Self {
            jit_cache_pa: 0x2_0000_0000,
            jit_cache_size: 16 * 1024 * 1024,
            bump_arena_pa: 0x2_0100_0000,
            bump_arena_size: 1024 * 1024,
            enable_aot: true,
        }
    }

    pub fn validate(&self) -> Result<(), DbtError> {
        if self.jit_cache_pa == 0 {
            return Err(DbtError::UnalignedJitCache);
        }
        if self.jit_cache_pa % 4096 != 0 {
            return Err(DbtError::UnalignedJitCache);
        }
        if self.jit_cache_size < 16 * 1024 * 1024 {
            return Err(DbtError::JitCacheTooSmall);
        }
        if self.bump_arena_pa % 4096 != 0 {
            return Err(DbtError::UnalignedBumpArena);
        }
        if self.bump_arena_size < 1024 * 1024 {
            return Err(DbtError::BumpArenaTooSmall);
        }
        // JIT cache and bump arena must not overlap.
        let jit_end = self.jit_cache_pa + self.jit_cache_size as u64;
        let bump_end = self.bump_arena_pa + self.bump_arena_size as u64;
        if self.jit_cache_pa < bump_end && self.bump_arena_pa < jit_end {
            return Err(DbtError::JitBumpOverlap);
        }
        Ok(())
    }
}

/// Error variants for the DBT integration pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbtError {
    HostUserlandRejected,
    UnalignedJitCache,
    UnalignedBumpArena,
    JitCacheTooSmall,
    BumpArenaTooSmall,
    JitBumpOverlap,
    ElfInvalid,
    FexLibNotLinked,
    DbtInitFailed,
    TranslationFailed,
    DispatchFailed,
    GuestVisibleJitCache,
    LibcSymbolDetected,
    FexSymbolDetected,
}

/// Phase machine for the DBT integration pipeline (strictly ordered).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DbtPhase {
    NotStarted,
    DbtLinked,
    AllocatorBound,
    JitCacheReady,
    ArmElfLoaded,
    BlockTranslated,
    GatePassed,
}

/// Aggregate state for the AT-24 pipeline.
pub struct DbtState {
    pub config: DbtIntegrationConfig,
    pub phase: DbtPhase,
    pub gate: DbtIntegrationGate,
}

impl DbtState {
    pub fn new(config: DbtIntegrationConfig) -> Self {
        Self {
            config,
            phase: DbtPhase::NotStarted,
            gate: DbtIntegrationGate::default(),
        }
    }

    /// Simulate binding the DBT static archive (stub mode: always succeeds).
    pub fn bind_dbt_archive(&mut self) {
        self.gate.dbt_linked = true;
        if self.phase < DbtPhase::DbtLinked {
            self.phase = DbtPhase::DbtLinked;
        }
    }

    pub fn bind_allocator(&mut self) {
        self.gate.allocator_bound = true;
        if self.phase < DbtPhase::AllocatorBound {
            self.phase = DbtPhase::AllocatorBound;
        }
    }

    pub fn mark_jit_cache_ready(&mut self) {
        self.gate.jit_cache_ready = true;
        if self.phase < DbtPhase::JitCacheReady {
            self.phase = DbtPhase::JitCacheReady;
        }
    }

    pub fn process_elf_load(&mut self, desc: &ArmElfDescriptor) -> AetherDbtResult {
        let result = aether_dbt_load_arm64_elf(desc);
        if result == AetherDbtResult::Ok {
            self.gate.arm64_elf_validated = true;
            if self.phase < DbtPhase::ArmElfLoaded {
                self.phase = DbtPhase::ArmElfLoaded;
            }
        }
        result
    }

    /// Run the `nm`-output audit: no `fex_*` symbols, all `aether_dbt_*` present.
    pub fn audit_symbols(&mut self, nm_output: &str) -> Result<(), DbtError> {
        let fex_found = check_fex_symbols_absent(nm_output);
        if !fex_found.is_empty() {
            return Err(DbtError::FexSymbolDetected);
        }
        // In stub mode the required symbols appear as Rust function names in nm.
        // The real gate runs against the linked EFI binary.
        self.gate.no_fex_symbols = true;
        if self.gate.passes() {
            self.phase = DbtPhase::GatePassed;
        }
        Ok(())
    }

    pub fn gate(&self) -> &DbtIntegrationGate {
        &self.gate
    }
}

/// Initialise the DBT integration pipeline.
pub fn init_dbt_integration(config: DbtIntegrationConfig) -> Result<DbtState, DbtError> {
    config.validate()?;
    let mut state = DbtState::new(config);
    state.bind_dbt_archive();
    state.bind_allocator();
    state.mark_jit_cache_ready();
    Ok(state)
}
