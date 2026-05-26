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

pub use liveness::{LiveInterval, LivenessAnalysis};
pub use linear_scan::{AllocResult, Assignment, LinearScanAlloc};
pub use x86_regs::{RegClass, X86Gpr, X86Xmm};

use crate::ir::IrFunction;

/// Convenience: run liveness analysis then linear scan on `func`.
pub fn allocate(func: &IrFunction) -> AllocResult {
    let analysis = LivenessAnalysis::compute(func);
    LinearScanAlloc::allocate(&analysis.intervals)
}
