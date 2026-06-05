//! AT-9 Linear-scan register allocator.
//!
//! Classic Poletto & Sarkar (1999) algorithm over the live intervals computed
//! by [`super::liveness::LivenessAnalysis`].  Allocates x86 GPRs and XMM
//! registers separately; spills excess intervals to a per-thread context block
//! (modeled as a spill slot index).
//!
//! Gate: zero allocation failures; spill ratio < 8 % of ops.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::liveness::LiveInterval;
use super::x86_regs::{RegClass, ALLOCATABLE_GPRS, ALLOCATABLE_XMMS};

/// Assignment for a single IR value after allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assignment {
    Gpr(u8),   // index into ALLOCATABLE_GPRS
    Xmm(u8),   // index into ALLOCATABLE_XMMS
    Spill(u32), // spill slot index in the context block
}

/// Output of the allocator.
#[derive(Debug, Clone, Default)]
pub struct AllocResult {
    pub assignments: BTreeMap<u32, Assignment>, // value_id → assignment
    pub n_spill_slots: u32,
    pub n_intervals: usize,
    pub n_spilled: usize,
}

impl AllocResult {
    /// Spill ratio: spilled / total.
    pub fn spill_ratio(&self) -> f64 {
        if self.n_intervals == 0 {
            0.0
        } else {
            self.n_spilled as f64 / self.n_intervals as f64
        }
    }

    /// Returns true if gate passes: every interval received an assignment,
    /// spill ratio < 8 %, AND the spill-slot count fits the bounded spill area
    /// (M4a — exceeding it would mean an out-of-bounds store past the R15
    /// register-file buffer; `translate_block` rejects such blocks).
    pub fn gate_passes(&self) -> bool {
        self.assignments.len() == self.n_intervals
            && self.spill_ratio() < 0.08
            && (self.n_spill_slots as usize) <= crate::runtime::context::SPILL_SLOTS
    }
}

pub struct LinearScanAlloc;

impl LinearScanAlloc {
    pub fn allocate(intervals: &[LiveInterval]) -> AllocResult {
        let mut gpr_alloc =
            ClassAlloc::new(ALLOCATABLE_GPRS.len(), crate::regalloc::x86_regs::GPR_ALLOC_FIRST_INDEX);
        // XMM 0..=3 are reserved as SIMD/FP ctx-template scratch (VS0..VS3) and
        // XMM15 (VFP) as the LDR/STR-Q transfer register; the allocator may only
        // assign XMM4..=14 to IR values. (Defensive: the live path lowers vector
        // ops via ctx templates and does not allocate XMMs.)
        let mut xmm_alloc = ClassAlloc::new(
            crate::regalloc::x86_regs::XMM_ALLOC_COUNT,
            crate::regalloc::x86_regs::XMM_ALLOC_FIRST_INDEX,
        );
        let mut assignments: BTreeMap<u32, Assignment> = BTreeMap::new();
        let mut n_spill_slots = 0u32;
        let mut n_spilled = 0usize;

        for interval in intervals {
            match interval.class {
                RegClass::Gpr => {
                    gpr_alloc.expire_old(interval.start);
                    if let Some(reg) = gpr_alloc.alloc_reg() {
                        gpr_alloc.active.push(ActiveInterval { end: interval.end, reg, vid: interval.value.0 });
                        gpr_alloc.active.sort_by_key(|a| a.end);
                        assignments.insert(interval.value.0, Assignment::Gpr(reg as u8));
                    } else {
                        // Spill the interval with the furthest endpoint.
                        let spill = gpr_alloc.spill_furthest(interval.end);
                        match spill {
                            Some(spilled_vid) => {
                                // Re-assign spilled value to a spill slot.
                                let slot = n_spill_slots;
                                n_spill_slots += 1;
                                n_spilled += 1;
                                assignments.insert(spilled_vid, Assignment::Spill(slot));
                                // Use the freed register for the current interval.
                                // Fallback to the first ALLOCATABLE index (never
                                // RAX/RCX) if somehow empty — keeps scratch safe.
                                let reg = gpr_alloc
                                    .alloc_reg()
                                    .unwrap_or(crate::regalloc::x86_regs::GPR_ALLOC_FIRST_INDEX);
                                gpr_alloc.active.push(ActiveInterval { end: interval.end, reg, vid: interval.value.0 });
                                gpr_alloc.active.sort_by_key(|a| a.end);
                                assignments.insert(interval.value.0, Assignment::Gpr(reg as u8));
                            }
                            None => {
                                let slot = n_spill_slots;
                                n_spill_slots += 1;
                                n_spilled += 1;
                                assignments.insert(interval.value.0, Assignment::Spill(slot));
                            }
                        }
                    }
                }
                RegClass::Xmm => {
                    xmm_alloc.expire_old(interval.start);
                    if let Some(reg) = xmm_alloc.alloc_reg() {
                        xmm_alloc.active.push(ActiveInterval { end: interval.end, reg, vid: interval.value.0 });
                        xmm_alloc.active.sort_by_key(|a| a.end);
                        assignments.insert(interval.value.0, Assignment::Xmm(reg as u8));
                    } else {
                        let spill = xmm_alloc.spill_furthest(interval.end);
                        match spill {
                            Some(spilled_vid) => {
                                let slot = n_spill_slots;
                                n_spill_slots += 1;
                                n_spilled += 1;
                                assignments.insert(spilled_vid, Assignment::Spill(slot));
                                let reg = xmm_alloc.alloc_reg().unwrap_or(0);
                                xmm_alloc.active.push(ActiveInterval { end: interval.end, reg, vid: interval.value.0 });
                                xmm_alloc.active.sort_by_key(|a| a.end);
                                assignments.insert(interval.value.0, Assignment::Xmm(reg as u8));
                            }
                            None => {
                                let slot = n_spill_slots;
                                n_spill_slots += 1;
                                n_spilled += 1;
                                assignments.insert(interval.value.0, Assignment::Spill(slot));
                            }
                        }
                    }
                }
            }
        }

        let n_intervals = intervals.len();
        AllocResult { assignments, n_spill_slots, n_intervals, n_spilled }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

struct ActiveInterval {
    end: usize,
    reg: usize,
    vid: u32,
}

struct ClassAlloc {
    n_regs: usize,
    /// Sorted by end point.
    active: Vec<ActiveInterval>,
    /// Free register indices.
    free: Vec<usize>,
}

impl ClassAlloc {
    /// `n_regs` total registers; `reserved_low` indices [0, reserved_low) are
    /// withheld from allocation (M4a: GPR reserves RAX(0)/RCX(1) as scratch).
    fn new(n_regs: usize, reserved_low: usize) -> Self {
        let free: Vec<usize> = (reserved_low..n_regs).collect();
        Self { n_regs, active: Vec::new(), free }
    }

    fn expire_old(&mut self, pos: usize) {
        self.active.retain(|a| {
            if a.end <= pos {
                self.free.push(a.reg);
                false
            } else {
                true
            }
        });
        // Free list has duplicates from above pattern (borrow checker); sort+dedup.
        self.free.sort();
        self.free.dedup();
    }

    fn alloc_reg(&mut self) -> Option<usize> {
        self.free.pop()
    }

    /// Spill the active interval with the furthest endpoint if it's farther
    /// than `current_end`.  Returns the value_id of the spilled interval.
    fn spill_furthest(&mut self, current_end: usize) -> Option<u32> {
        let pos = self.active.iter().rposition(|a| a.end > current_end)?;
        let spilled = self.active.remove(pos);
        self.free.push(spilled.reg);
        Some(spilled.vid)
    }
}
