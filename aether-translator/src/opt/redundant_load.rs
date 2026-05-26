//! Redundant-load elimination pass (AT-7).
//!
//! Within a basic block, if a load from address `A` with the same type and
//! ordering has already been performed and no intervening store or barrier has
//! invalidated the result, replace the second load's dst with the first's.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ir::memory::{LoadTy, MemOrder};
use crate::ir::{IrFunction, IrOp, IrValueId};

pub struct RedundantLoadPass;

impl RedundantLoadPass {
    pub fn run(mut func: IrFunction) -> IrFunction {
        for blk in &mut func.blocks {
            // Cache: (addr_value_id, LoadTy) → dst from the first load.
            // Only valid for Relaxed loads (acquire/seqcst may be visible to
            // other threads between two identical loads).
            let mut cache: BTreeMap<(u32, LoadTy), IrValueId> = BTreeMap::new();
            let mut subst: BTreeMap<IrValueId, IrValueId> = BTreeMap::new();
            let mut new_ops: Vec<IrOp> = Vec::with_capacity(blk.ops.len());

            for op in blk.ops.drain(..) {
                // Remap uses through current substitution.
                let op = op.remap_uses(|v| *subst.get(&v).unwrap_or(&v), |f| f);
                match op {
                    IrOp::Load { dst, addr, ty, order: MemOrder::Relaxed } => {
                        let key = (addr.0, ty);
                        if let Some(&prev) = cache.get(&key) {
                            // Redundant load: alias dst → prev.
                            subst.insert(dst, prev);
                            // Still emit the op so dst is defined (DCE removes it).
                            new_ops.push(IrOp::Load { dst, addr, ty, order: MemOrder::Relaxed });
                        } else {
                            cache.insert(key, dst);
                            new_ops.push(IrOp::Load { dst, addr, ty, order: MemOrder::Relaxed });
                        }
                    }
                    // Any store or barrier invalidates the entire cache.
                    IrOp::Store { .. }
                    | IrOp::StoreExclusive { .. }
                    | IrOp::StorePair { .. }
                    | IrOp::AtomicRmw { .. }
                    | IrOp::AtomicCas { .. }
                    | IrOp::Dmb { .. }
                    | IrOp::Dsb { .. }
                    | IrOp::Isb
                    | IrOp::Sb
                    | IrOp::Call { .. } => {
                        cache.clear();
                        new_ops.push(op);
                    }
                    other => new_ops.push(other),
                }
            }

            blk.ops = new_ops;

            // Propagate substitutions into phi incoming.
            for phi in &mut blk.phis {
                for (_, v) in &mut phi.incoming {
                    if let Some(&s) = subst.get(v) {
                        *v = s;
                    }
                }
            }
        }
        func
    }
}
