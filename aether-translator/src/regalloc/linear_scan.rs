//! AT-9 Linear-scan register allocator.
//!
//! Classic Poletto & Sarkar (1999) algorithm over the live intervals computed
//! by [`super::liveness::LivenessAnalysis`].  Allocates x86 GPRs and XMM
//! registers separately; spills excess intervals to a per-thread context block
//! (modeled as a spill slot index).
//!
//! Gate: zero allocation failures; spill ratio < 8 % of ops.
//!
//! Leak note (hypervisor bump heap): every container here is reusable across
//! translations.  `assignments` is an [`AssignMap`] backed by a `Vec` rather
//! than a `BTreeMap` so [`AssignMap::clear`] keeps its capacity — a fresh
//! `BTreeMap` per cold block leaked its B-tree nodes into the never-freeing
//! bump allocator every translation.  The linear-scan working lists live in a
//! reusable [`ScanScratch`] threaded from the DBT runtime.

use alloc::vec::Vec;

use super::liveness::LiveInterval;
use super::x86_regs::{RegClass, ALLOCATABLE_GPRS};

/// Assignment for a single IR value after allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assignment {
    Gpr(u8),   // index into ALLOCATABLE_GPRS
    Xmm(u8),   // index into ALLOCATABLE_XMMS
    Spill(u32), // spill slot index in the context block
}

/// Dense `value_id → Assignment` map backed by a `Vec<Option<Assignment>>`
/// indexed by the (block-local, dense) IR value id.
///
/// Drop-in for the previous `BTreeMap<u32, Assignment>` — same `get` / `insert`
/// / `len` surface — but [`AssignMap::clear`] keeps the backing allocation,
/// whereas `BTreeMap::clear` frees its nodes and the next insert re-allocates.
/// Under the hypervisor's never-freeing bump heap that re-allocation was a
/// per-cold-block leak; a `Vec` reused across translations does not grow the
/// heap once warm.
#[derive(Debug, Clone, Default)]
pub struct AssignMap {
    slots: Vec<Option<Assignment>>,
    /// Number of distinct value ids currently assigned (matches `BTreeMap::len`).
    count: usize,
}

impl AssignMap {
    pub fn new() -> Self {
        Self { slots: Vec::new(), count: 0 }
    }

    /// Look up an assignment by value id (`&u32` to mirror the old
    /// `BTreeMap::get(&key)` call sites verbatim).
    #[inline]
    pub fn get(&self, vid: &u32) -> Option<&Assignment> {
        self.slots.get(*vid as usize).and_then(|s| s.as_ref())
    }

    /// Insert or overwrite. Overwriting an existing id leaves `len` unchanged,
    /// exactly like `BTreeMap::insert` returning the old value.
    #[inline]
    pub fn insert(&mut self, vid: u32, a: Assignment) {
        let i = vid as usize;
        if i >= self.slots.len() {
            self.slots.resize(i + 1, None);
        }
        if self.slots[i].is_none() {
            self.count += 1;
        }
        self.slots[i] = Some(a);
    }

    /// Number of distinct value ids assigned.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate `(value_id, &assignment)` over assigned ids in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &Assignment)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|a| (i as u32, a)))
    }

    /// Clear for reuse, keeping the backing allocation (no free under the bump
    /// heap; the next fill reuses the warm capacity).
    #[inline]
    pub fn clear(&mut self) {
        self.slots.clear();
        self.count = 0;
    }
}

/// Output of the allocator.
#[derive(Debug, Clone, Default)]
pub struct AllocResult {
    pub assignments: AssignMap, // value_id → assignment
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

    /// Reset for reuse, keeping the assignment-map capacity.
    #[inline]
    pub fn reset(&mut self) {
        self.assignments.clear();
        self.n_spill_slots = 0;
        self.n_intervals = 0;
        self.n_spilled = 0;
    }
}

/// Reusable linear-scan working lists (the per-class active/free sets). Held by
/// the DBT runtime and reset per translation so the allocator does not allocate
/// into the bump heap on every cold block.
#[derive(Default)]
pub struct ScanScratch {
    gpr: ClassAlloc,
    xmm: ClassAlloc,
}

pub struct LinearScanAlloc;

impl LinearScanAlloc {
    /// Standalone (allocating) entry — used by tests and one-shot callers.
    /// Allocates fresh scratch; the hot DBT path must use [`Self::allocate_into`].
    pub fn allocate(intervals: &[LiveInterval]) -> AllocResult {
        let mut scratch = ScanScratch::default();
        let mut out = AllocResult::default();
        Self::allocate_into(intervals, &mut scratch, &mut out);
        out
    }

    /// Reusable entry: fills `out` using `scratch`'s warm working lists. Both
    /// `scratch` and `out` keep their capacity across calls.
    pub fn allocate_into(intervals: &[LiveInterval], scratch: &mut ScanScratch, out: &mut AllocResult) {
        out.reset();
        // XMM 0..=3 are reserved as SIMD/FP ctx-template scratch (VS0..VS3) and
        // XMM15 (VFP) as the LDR/STR-Q transfer register; the allocator may only
        // assign XMM4..=14 to IR values. (Defensive: the live path lowers vector
        // ops via ctx templates and does not allocate XMMs.)
        scratch
            .gpr
            .reset(ALLOCATABLE_GPRS.len(), crate::regalloc::x86_regs::GPR_ALLOC_FIRST_INDEX);
        scratch.xmm.reset(
            crate::regalloc::x86_regs::XMM_ALLOC_COUNT,
            crate::regalloc::x86_regs::XMM_ALLOC_FIRST_INDEX,
        );

        let assignments = &mut out.assignments;
        let mut n_spill_slots = 0u32;
        let mut n_spilled = 0usize;

        for interval in intervals {
            match interval.class {
                RegClass::Gpr => {
                    let gpr_alloc = &mut scratch.gpr;
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
                    let xmm_alloc = &mut scratch.xmm;
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

        out.n_spill_slots = n_spill_slots;
        out.n_intervals = intervals.len();
        out.n_spilled = n_spilled;
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

struct ActiveInterval {
    end: usize,
    reg: usize,
    vid: u32,
}

#[derive(Default)]
struct ClassAlloc {
    /// Sorted by end point.
    active: Vec<ActiveInterval>,
    /// Free register indices.
    free: Vec<usize>,
}

impl ClassAlloc {
    /// Reset in place for reuse, keeping the `active`/`free` Vec capacities.
    /// `n_regs` total registers; `reserved_low` indices [0, reserved_low) are
    /// withheld from allocation (M4a: GPR reserves RAX(0)/RCX(1) as scratch).
    fn reset(&mut self, n_regs: usize, reserved_low: usize) {
        self.active.clear();
        self.free.clear();
        self.free.extend(reserved_low..n_regs);
    }

    fn expire_old(&mut self, pos: usize) {
        let free = &mut self.free;
        self.active.retain(|a| {
            if a.end <= pos {
                free.push(a.reg);
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
