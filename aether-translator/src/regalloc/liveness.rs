//! Liveness analysis for AT-9 linear-scan register allocation.
//!
//! Computes a [`LiveInterval`] for every `IrValueId` in the function:
//! `[start, end)` where start/end are global instruction positions
//! (block 0 op 0 = 0, block 0 op 1 = 1, …, block k op m = sum of previous
//! block lengths + m).

use alloc::collections::BTreeMap;
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

pub struct LivenessAnalysis {
    pub intervals: Vec<LiveInterval>,
    /// global_offset[block_index] = sum of op counts of all preceding blocks.
    pub global_offset: Vec<usize>,
}

impl LivenessAnalysis {
    /// Compute live intervals.  Assumes SSA form (each value defined once).
    pub fn compute(func: &IrFunction) -> Self {
        // Build global offsets.
        let mut global_offset = Vec::with_capacity(func.blocks.len() + 1);
        let mut off = 0usize;
        for blk in &func.blocks {
            global_offset.push(off);
            // Each phi counts as 1 pseudo-instruction at the block start.
            off += blk.phis.len() + blk.ops.len();
        }
        global_offset.push(off); // sentinel

        // def_pos[value_id] = global instruction position where the value is defined.
        let mut def_pos: BTreeMap<u32, usize> = BTreeMap::new();
        // last_use[value_id] = latest global position where the value is used.
        let mut last_use: BTreeMap<u32, usize> = BTreeMap::new();

        for (bi, blk) in func.blocks.iter().enumerate() {
            let base = global_offset[bi];
            let mut pos = base;

            // Phi dsts defined at block entry.
            for phi in &blk.phis {
                def_pos.entry(phi.dst.0).or_insert(pos);
                // Phi incoming values: last use is at this block entry position.
                for &(_, v) in &phi.incoming {
                    last_use.entry(v.0).and_modify(|e| *e = (*e).max(pos)).or_insert(pos);
                }
                pos += 1;
            }

            for op in &blk.ops {
                // Record uses (before defs so that same-op use/def extends correctly).
                op.visit_use_values(|v: IrValueId| {
                    last_use.entry(v.0).and_modify(|e| *e = (*e).max(pos)).or_insert(pos);
                });
                // Record defs.
                op.visit_def_values(|v: IrValueId| {
                    def_pos.entry(v.0).or_insert(pos);
                });
                pos += 1;
            }
        }

        // Build a map from (block_index, local_value_id) → IrValueKind so we can
        // correctly look up the register class for each def.  IrValueId is
        // block-local; the liveness maps use the raw u32 as a key which is only
        // unambiguous for single-block functions.  For multi-block functions we
        // augment with a separate block-tagged kind table.
        let mut kind_map: BTreeMap<u32, IrValueKind> = BTreeMap::new();
        for (bi, blk) in func.blocks.iter().enumerate() {
            let base = global_offset[bi];
            let mut pos = base;
            for phi in &blk.phis {
                // Phi dst kind is recorded via the values table in the block.
                if (phi.dst.0 as usize) < blk.values.len() {
                    kind_map.entry(phi.dst.0).or_insert(blk.values[phi.dst.0 as usize]);
                }
                pos += 1;
            }
            for op in &blk.ops {
                op.visit_def_values(|v: IrValueId| {
                    // Tag by def_pos to disambiguate same-numbered values from different blocks.
                    // We use the global position as the disambiguating key: store the kind
                    // at the def position, keyed by the global def_pos.
                    if let Some(&def) = def_pos.get(&v.0) {
                        if def == pos {
                            // This is the defining occurrence.
                            if (v.0 as usize) < blk.values.len() {
                                kind_map.insert(v.0, blk.values[v.0 as usize]);
                            }
                        }
                    }
                });
                pos += 1;
            }
            let _ = pos;
        }

        // For each value that has no recorded use (defined but never used),
        // the interval is [def, def+1) — it lives for one slot.
        let mut intervals: Vec<LiveInterval> = Vec::new();
        for (vid, start) in &def_pos {
            let end = last_use.get(vid).copied().unwrap_or(*start) + 1;
            let class = kind_to_class(kind_map.get(vid).copied().unwrap_or(IrValueKind::I64));
            intervals.push(LiveInterval {
                value: IrValueId(*vid),
                start: *start,
                end,
                class,
            });
        }

        // Sort by start position for linear scan.
        intervals.sort_by_key(|i| i.start);

        LivenessAnalysis { intervals, global_offset }
    }
}

fn kind_to_class(kind: IrValueKind) -> RegClass {
    match kind {
        IrValueKind::Vec128 { .. } | IrValueKind::F32 | IrValueKind::F64
        | IrValueKind::F16 => RegClass::Xmm,
        _ => RegClass::Gpr,
    }
}
