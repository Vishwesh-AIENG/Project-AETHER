//! Dead-code elimination pass (AT-7).
//!
//! Marks ops live if their result is used by another live op or if the op has
//! a side effect (memory write, branch, call, system op, barrier).  Removes
//! all unmarked ops.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::ir::{IrFunction, IrOp, IrValueId};

pub struct DcePass;

impl DcePass {
    pub fn run(mut func: IrFunction) -> IrFunction {
        for blk in &mut func.blocks {
            // Collect the set of live values by propagating from root uses.
            let mut live: BTreeSet<u32> = BTreeSet::new();

            // Seed: values used by side-effecting ops are live; their uses
            // are transitively live.  We do two passes: first forward to
            // collect defs, then backward to propagate liveness.

            // Build def map: value_id → op_index.
            let mut def_at: alloc::collections::BTreeMap<u32, usize> =
                alloc::collections::BTreeMap::new();
            for (i, op) in blk.ops.iter().enumerate() {
                op.visit_def_values(|v: IrValueId| {
                    def_at.insert(v.0, i);
                });
            }

            // Seed side-effecting ops and phi uses as live.
            let n = blk.ops.len();
            let mut op_live = vec![false; n];
            for (i, op) in blk.ops.iter().enumerate() {
                if is_side_effecting(op) {
                    op_live[i] = true;
                    op.visit_use_values(|v: IrValueId| {
                        live.insert(v.0);
                    });
                }
            }

            // Phi uses are always live.
            for phi in &blk.phis {
                for &(_, v) in &phi.incoming {
                    live.insert(v.0);
                }
            }

            // Propagate liveness backward.
            let mut changed = true;
            while changed {
                changed = false;
                for (i, op) in blk.ops.iter().enumerate() {
                    if op_live[i] {
                        continue;
                    }
                    let mut is_live = false;
                    op.visit_def_values(|v: IrValueId| {
                        if live.contains(&v.0) {
                            is_live = true;
                        }
                    });
                    if is_live {
                        op_live[i] = true;
                        op.visit_use_values(|v: IrValueId| {
                            if live.insert(v.0) {
                                changed = true;
                            }
                        });
                        changed = true;
                    }
                }
            }

            // Retain only live ops.
            let mut new_ops = Vec::with_capacity(n);
            for (i, op) in blk.ops.drain(..).enumerate() {
                if op_live[i] {
                    new_ops.push(op);
                }
            }
            blk.ops = new_ops;
        }
        func
    }
}

fn is_side_effecting(op: &IrOp) -> bool {
    matches!(
        op,
        IrOp::Store { .. }
        | IrOp::StoreExclusive { .. }
        | IrOp::StorePair { .. }
        | IrOp::AtomicRmw { .. }
        | IrOp::AtomicCas { .. }
        | IrOp::Branch { .. }
        | IrOp::CondBranch { .. }
        | IrOp::IndirectBranch { .. }
        | IrOp::Call { .. }
        | IrOp::Return { .. }
        | IrOp::Cbz { .. }
        | IrOp::Cbnz { .. }
        | IrOp::Tbz { .. }
        | IrOp::Tbnz { .. }
        | IrOp::Hvc { .. }
        | IrOp::Svc { .. }
        | IrOp::Smc { .. }
        | IrOp::Brk { .. }
        | IrOp::Hlt { .. }
        | IrOp::Msr { .. }
        | IrOp::Dmb { .. }
        | IrOp::Dsb { .. }
        | IrOp::Isb
        | IrOp::Sb
        | IrOp::WriteGpr { .. }
        | IrOp::WriteSp { .. }
        | IrOp::WriteFpr { .. }
        | IrOp::WriteFlags { .. }
        | IrOp::WritePc { .. }
    )
}
