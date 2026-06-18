//! AT-9 Linear-scan register allocator for the AETHER translator.
//!
//! Allocates 15 x86_64 GPRs + 16 XMM registers to IR values based on their
//! live intervals.  ARM64 has 32 GPRs + 32 FPRs; excess values are spilled to
//! a per-thread ARM context block (indexed by spill slot).
//!
//! Gate: zero allocation failures on the AT-5 corpus; spill ratio < 8 %.

pub mod liveness;
pub mod linear_scan;
pub mod x86_regs;

pub use liveness::{LiveInterval, LiveScratch, LivenessAnalysis};
pub use linear_scan::{AllocResult, AssignMap, Assignment, LinearScanAlloc, ScanScratch};
pub use x86_regs::{RegClass, X86Gpr, X86Xmm};

use crate::ir::IrFunction;

/// Reusable scratch for the whole liveness + linear-scan pipeline.
///
/// Held by the DBT runtime and reset on every translation. Under the
/// hypervisor's never-freeing bump heap, allocating fresh liveness/scan
/// containers per cold block leaked them permanently; reusing one
/// `RegallocScratch` keeps all the working buffers warm so a re-translated
/// block does not grow the heap.
#[derive(Default)]
pub struct RegallocScratch {
    pub live: LiveScratch,
    pub scan: ScanScratch,
    pub result: AllocResult,
}

/// Convenience: run liveness analysis then linear scan on `func` (allocating).
/// Used by tests / one-shot callers; the hot DBT path uses [`allocate_into`].
pub fn allocate(func: &IrFunction) -> AllocResult {
    let mut scratch = RegallocScratch::default();
    allocate_into(func, &mut scratch);
    core::mem::take(&mut scratch.result)
}

/// Reusable path: run liveness + linear scan using `scratch`'s warm buffers,
/// leaving the assignment in `scratch.result`.
pub fn allocate_into(func: &IrFunction, scratch: &mut RegallocScratch) {
    LivenessAnalysis::compute_into(func, &mut scratch.live);
    LinearScanAlloc::allocate_into(&scratch.live.intervals, &mut scratch.scan, &mut scratch.result);
}
