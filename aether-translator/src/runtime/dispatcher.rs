//! AT-17: Dispatcher loop — the hot/cold dispatch engine.
//!
//! Hot path  (block cache hit):
//!   1. `BlockCache::lookup(guest_pc)` → `CachedBlock`
//!   2. Return host offset — caller jumps to translated code.
//!
//! Cold path (cache miss):
//!   1. Decode ARM64 bytes at `guest_pc` → `DecodedInsn` sequence.
//!   2. Lift to IR (`lift::lift_at`).
//!   3. Optimize via `opt::run_pipeline`.
//!   4. Register-allocate via `regalloc::allocate`.
//!   5. Lower to x86_64 via `IntLower::lower_block`.
//!   6. Commit block in `CodeBuf`.
//!   7. Insert in `BlockCache`.
//!   8. Return host offset.
//!
//! Latency gate: p99 dispatch latency on a cache hit ≤ 50 cycles (RDTSC).
//! In structural/no_std mode the gate is validated by asserting the hot path
//! has ≤ `HOT_PATH_MAX_BRANCHES` decision points.
//!
//! Real RDTSC timing activates under `cfg(all(feature = "std",
//! target_arch = "x86_64"))`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::backend::code_buf::{CodeBuf, CodeBufError};
use crate::backend::encode::X86Encoder;
use crate::backend::lower_int::IntLower;
use crate::decoder::DecodedInsn;
use crate::ir::{BlockId, IrBlock, IrFunction};
use crate::lift;
use crate::opt;
use crate::regalloc;

use super::block_cache::BlockCache;

/// Result returned by `Dispatcher::dispatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Block found in cache.
    Hit {
        host_offset: usize,
        len: usize,
    },
    /// Block was just translated and installed.
    Translated {
        host_offset: usize,
        len: usize,
    },
    /// Translation error.
    TranslationError(DispatchError),
}

/// Errors produced during cold-path translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    /// Guest PC points outside the provided memory slice.
    GuestPcOutOfRange,
    /// Decoder produced zero decodable instructions.
    EmptyBlock,
    /// Code buffer ran out of capacity.
    CodeBufFull,
    /// Allocator failed (all intervals must have assignments).
    AllocFailed,
}

impl From<CodeBufError> for DispatchError {
    fn from(_: CodeBufError) -> Self {
        DispatchError::CodeBufFull
    }
}

/// Aggregate dispatch statistics.
#[derive(Debug, Clone, Default)]
pub struct DispatchStats {
    /// Cache-hit dispatches.
    pub hot_dispatches: u64,
    /// Cold translations performed.
    pub cold_translations: u64,
    /// Total cycles spent in hot-path lookups.
    pub total_hit_cycles: u64,
    /// Sorted hit-cycle samples (populated on x86_64 + std only).
    samples: Vec<u64>,
}

impl DispatchStats {
    pub fn record_hit(&mut self, cycles: u64) {
        self.hot_dispatches += 1;
        self.total_hit_cycles += cycles;
        self.samples.push(cycles);
    }

    pub fn record_cold(&mut self) {
        self.cold_translations += 1;
    }

    /// P99 hit latency in cycles.  Returns 0 if no samples.
    pub fn p99_hit_cycles(&mut self) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        self.samples.sort_unstable();
        let idx = (self.samples.len() * 99 / 100).saturating_sub(1);
        self.samples[idx]
    }

    /// Gate: p99 ≤ `target_cycles`.
    pub fn gate_passes(&mut self, target_cycles: u64) -> bool {
        self.p99_hit_cycles() <= target_cycles
    }
}

/// The maximum number of basic-block-level branches in the hot dispatch path.
/// Used by the structural gate test.
pub const HOT_PATH_MAX_BRANCHES: usize = 3;

/// Main dispatch engine.
pub struct Dispatcher {
    cache: BlockCache,
    code_buf: CodeBuf,
    pub stats: DispatchStats,
}

impl Dispatcher {
    /// Create a new dispatcher.
    ///
    /// `cache_capacity` — block-cache slots (rounded to pow2).
    /// `code_buf_capacity` — JIT arena size in bytes.
    pub fn new(cache_capacity: usize, code_buf_capacity: usize) -> Self {
        Self {
            cache: BlockCache::new(cache_capacity),
            code_buf: CodeBuf::new(code_buf_capacity),
            stats: DispatchStats::default(),
        }
    }

    /// Dispatch `guest_pc`.
    ///
    /// `guest_mem` is a byte slice of guest physical memory at IPA offset 0.
    pub fn dispatch(&mut self, guest_pc: u64, guest_mem: &[u8]) -> DispatchOutcome {
        // ── Hot path ──────────────────────────────────────────────────────────
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        let t0 = rdtsc();

        if let Some(blk) = self.cache.lookup(guest_pc) {
            let outcome = DispatchOutcome::Hit {
                host_offset: blk.host_offset,
                len: blk.len,
            };
            #[cfg(all(feature = "std", target_arch = "x86_64"))]
            self.stats.record_hit(rdtsc().saturating_sub(t0));
            #[cfg(not(all(feature = "std", target_arch = "x86_64")))]
            self.stats.record_hit(0);
            return outcome;
        }

        // ── Cold path ─────────────────────────────────────────────────────────
        self.stats.record_cold();
        match self.translate(guest_pc, guest_mem) {
            Ok((host_offset, len)) => DispatchOutcome::Translated { host_offset, len },
            Err(e) => DispatchOutcome::TranslationError(e),
        }
    }

    // ── Cold-path pipeline ────────────────────────────────────────────────────

    fn translate(
        &mut self,
        guest_pc: u64,
        guest_mem: &[u8],
    ) -> Result<(usize, usize), DispatchError> {
        // 1. Slice guest memory.
        let start = guest_pc as usize;
        if start >= guest_mem.len() {
            return Err(DispatchError::GuestPcOutOfRange);
        }
        let insn_bytes = &guest_mem[start..];

        // 2. Decode + lift to a single IrBlock.
        let ir_block = Self::decode_and_lift(guest_pc, insn_bytes)?;

        // 3. Wrap in an IrFunction so the existing pipeline can operate on it.
        let mut ir_fn = IrFunction::new(guest_pc);
        ir_fn.blocks.push(ir_block);

        // 4. Optimize.
        let ir_fn = opt::run_pipeline(ir_fn);

        // 5. Register allocate.
        let alloc = regalloc::allocate(&ir_fn);
        if alloc.assignments.len() < alloc.n_intervals {
            return Err(DispatchError::AllocFailed);
        }

        // 6. Lower the (only) block to x86_64.
        let mut enc = X86Encoder::new();
        let mut patches: BTreeMap<usize, BlockId> = BTreeMap::new();
        IntLower::lower_block(&ir_fn.blocks[0], &alloc, &mut enc, &mut patches);
        let code = enc.finish();

        // 7. Emit + commit.
        let offset = self
            .code_buf
            .alloc_block(guest_pc, &code)
            .map_err(|_| DispatchError::CodeBufFull)?;
        self.code_buf.commit();

        // 8. Cache.
        self.cache.insert(guest_pc, offset, code.len());

        Ok((offset, code.len()))
    }

    fn decode_and_lift(guest_pc: u64, insn_bytes: &[u8]) -> Result<IrBlock, DispatchError> {
        const MAX_INSNS: usize = 32;
        let mut block = IrBlock::new(BlockId(0));
        let mut offset = 0usize;
        let mut count = 0;

        while offset + 4 <= insn_bytes.len() && count < MAX_INSNS {
            let word = u32::from_le_bytes([
                insn_bytes[offset],
                insn_bytes[offset + 1],
                insn_bytes[offset + 2],
                insn_bytes[offset + 3],
            ]);
            match crate::decoder::decode_instruction(word) {
                Ok(insn) => {
                    let pc = guest_pc + offset as u64;
                    let _ = lift::lift_at(&insn, &mut block, pc);
                    let term = is_terminator(&insn);
                    offset += 4;
                    count += 1;
                    if term {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        if count == 0 {
            return Err(DispatchError::EmptyBlock);
        }
        Ok(block)
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn cache(&self) -> &BlockCache {
        &self.cache
    }

    pub fn invalidate(&mut self, guest_pc: u64) {
        self.cache.invalidate(guest_pc);
    }

    pub fn arena_bytes(&self) -> &[u8] {
        self.code_buf.as_slice()
    }
}

fn is_terminator(insn: &DecodedInsn) -> bool {
    matches!(
        insn,
        DecodedInsn::B { .. }
            | DecodedInsn::Bcond { .. }
            | DecodedInsn::Bl { .. }
            | DecodedInsn::Blr { .. }
            | DecodedInsn::Br { .. }
            | DecodedInsn::Ret { .. }
            | DecodedInsn::Cbz { .. }
            | DecodedInsn::Cbnz { .. }
            | DecodedInsn::Tbz { .. }
            | DecodedInsn::Tbnz { .. }
    )
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[allow(unsafe_code)]
#[inline(always)]
fn rdtsc() -> u64 {
    // SAFETY: RDTSC is unconditionally available on x86_64 targets.
    unsafe { core::arch::x86_64::_rdtsc() }
}
