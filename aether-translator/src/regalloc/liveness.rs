//! Liveness analysis for AT-9 linear-scan register allocation.
//!
//! Computes a [`LiveInterval`] for every `IrValueId` in the function:
//! `[start, end)` where start/end are global instruction positions
//! (block 0 op 0 = 0, block 0 op 1 = 1, …, block k op m = sum of previous
//! block lengths + m).
//!
//! Leak note (hypervisor bump heap): the def/use/kind working tables are
//! `Vec`s indexed by the raw IR value id (which is dense and block-local), not
//! `BTreeMap`s.  A fresh `BTreeMap` per cold block leaked its B-tree nodes into
//! the never-freeing bump allocator on every translation; a `Vec` reused via
//! [`LiveScratch`] keeps its capacity.  Indexing by raw `u32` reproduces the
//! old `BTreeMap` keyed-by-`u32` behaviour byte-for-byte (same first-def-wins /
//! max-use logic, same ascending-id iteration order before the start-sort).

use alloc::vec::Vec;

use crate::ir::{IrFunction, IrValueId, IrValueKind};
use crate::regalloc::x86_regs::RegClass;

/// Half-open live interval `[start, end)` in global instruction position space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveInterval {
    pub value: IrValueId,
    pub start: usize,
    pub end: usize,
    pub class: RegClass,
}

impl LiveInterval {
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Reusable liveness working buffers. Held by the DBT runtime and reset per
/// translation so liveness does not allocate into the bump heap on every cold
/// block. The public result lives in `intervals` (+ `global_offset`); the
/// remaining tables are scratch indexed by raw value id.
#[derive(Default)]
pub struct LiveScratch {
    /// Output: live intervals sorted by start position.
    pub intervals: Vec<LiveInterval>,
    /// `global_offset[block_index]` = sum of op counts of all preceding blocks.
    pub global_offset: Vec<usize>,
    /// `def_pos[value_id]` = global position of first definition; `-1` = unset.
    def_pos: Vec<i64>,
    /// `last_use[value_id]` = latest global use position; `-1` = unset.
    last_use: Vec<i64>,
    /// `kind[value_id]` = value kind recorded at its defining occurrence.
    kind: Vec<Option<IrValueKind>>,
}

pub struct LivenessAnalysis {
    pub intervals: Vec<LiveInterval>,
    /// global_offset[block_index] = sum of op counts of all preceding blocks.
    pub global_offset: Vec<usize>,
}

impl LivenessAnalysis {
    /// Compute live intervals (allocating). Used by tests / one-shot callers;
    /// the hot DBT path uses [`Self::compute_into`] with reusable scratch.
    pub fn compute(func: &IrFunction) -> Self {
        let mut s = LiveScratch::default();
        Self::compute_into(func, &mut s);
        LivenessAnalysis {
            intervals: core::mem::take(&mut s.intervals),
            global_offset: core::mem::take(&mut s.global_offset),
        }
    }

    /// Compute live intervals into reusable `scratch`. Assumes SSA form (each
    /// value defined once). Leaves the result in `scratch.intervals`.
    pub fn compute_into(func: &IrFunction, scratch: &mut LiveScratch) {
        // Size the per-value working tables to the widest block's value count.
        // Value ids are block-local and dense (`new_value` pushes sequentially),
        // so every id used in any block is < that block's `values.len()`.
        let max_vals = func.blocks.iter().map(|b| b.values.len()).max().unwrap_or(0);
        scratch.def_pos.clear();
        scratch.def_pos.resize(max_vals, -1);
        scratch.last_use.clear();
        scratch.last_use.resize(max_vals, -1);
        scratch.kind.clear();
        scratch.kind.resize(max_vals, None);
        scratch.global_offset.clear();
        scratch.intervals.clear();

        // Build global offsets.
        let mut off = 0usize;
        for blk in &func.blocks {
            scratch.global_offset.push(off);
            // Each phi counts as 1 pseudo-instruction at the block start.
            off += blk.phis.len() + blk.ops.len();
        }
        scratch.global_offset.push(off); // sentinel

        // def_pos[value_id] = global position where the value is defined.
        // last_use[value_id] = latest global position where the value is used.
        for (bi, blk) in func.blocks.iter().enumerate() {
            let base = scratch.global_offset[bi];
            let mut pos = base;

            // Phi dsts defined at block entry.
            for phi in &blk.phis {
                let d = phi.dst.0 as usize;
                if d < scratch.def_pos.len() && scratch.def_pos[d] < 0 {
                    scratch.def_pos[d] = pos as i64;
                }
                // Phi incoming values: last use is at this block entry position.
                for &(_, v) in &phi.incoming {
                    let u = v.0 as usize;
                    if u < scratch.last_use.len() {
                        let p = pos as i64;
                        if scratch.last_use[u] < 0 || p > scratch.last_use[u] {
                            scratch.last_use[u] = p;
                        }
                    }
                }
                pos += 1;
            }

            for op in &blk.ops {
                // Record uses (before defs so that same-op use/def extends correctly).
                {
                    let last_use = &mut scratch.last_use;
                    op.visit_use_values(|v: IrValueId| {
                        let u = v.0 as usize;
                        if u < last_use.len() {
                            let p = pos as i64;
                            if last_use[u] < 0 || p > last_use[u] {
                                last_use[u] = p;
                            }
                        }
                    });
                }
                // Record defs (first definition wins).
                {
                    let def_pos = &mut scratch.def_pos;
                    op.visit_def_values(|v: IrValueId| {
                        let d = v.0 as usize;
                        if d < def_pos.len() && def_pos[d] < 0 {
                            def_pos[d] = pos as i64;
                        }
                    });
                }
                pos += 1;
            }
        }

        // Record the register class (kind) at each value's defining occurrence.
        // IrValueId is block-local; indexing by raw u32 matches the old map.
        for (bi, blk) in func.blocks.iter().enumerate() {
            let base = scratch.global_offset[bi];
            let mut pos = base;
            for phi in &blk.phis {
                let d = phi.dst.0 as usize;
                if d < blk.values.len() && d < scratch.kind.len() && scratch.kind[d].is_none() {
                    scratch.kind[d] = Some(blk.values[d]);
                }
                pos += 1;
            }
            for op in &blk.ops {
                let def_pos = &scratch.def_pos;
                let kind = &mut scratch.kind;
                let cur = pos as i64;
                op.visit_def_values(|v: IrValueId| {
                    let d = v.0 as usize;
                    // Only at the defining occurrence (matches old `def == pos`).
                    if d < def_pos.len() && def_pos[d] == cur && d < blk.values.len() && d < kind.len()
                    {
                        kind[d] = Some(blk.values[d]);
                    }
                });
                pos += 1;
            }
        }

        // Build intervals in ascending value-id order (then stable-sort by start
        // — identical to the old BTreeMap iteration followed by sort_by_key).
        for vid in 0..max_vals {
            let start = scratch.def_pos[vid];
            if start < 0 {
                continue; // value never defined → no interval
            }
            let start = start as usize;
            let lu = scratch.last_use[vid];
            let end = if lu < 0 { start } else { lu as usize } + 1;
            let class = kind_to_class(scratch.kind[vid].unwrap_or(IrValueKind::I64));
            scratch.intervals.push(LiveInterval {
                value: IrValueId(vid as u32),
                start,
                end,
                class,
            });
        }

        // Sort by start position for linear scan (stable: ties keep ascending id).
        scratch.intervals.sort_by_key(|i| i.start);
    }
}

fn kind_to_class(kind: IrValueKind) -> RegClass {
    match kind {
        IrValueKind::Vec128 { .. } | IrValueKind::F32 | IrValueKind::F64
        | IrValueKind::F16 => RegClass::Xmm,
        _ => RegClass::Gpr,
    }
}
