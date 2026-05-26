//! Copy-propagation pass (AT-7).
//!
//! Detects trivial copies where an op's sole effect is `dst = src` (e.g. a
//! `Zext { from_bits: 64, to_bits: 64 }` or future `Copy` op) and replaces
//! all uses of `dst` with `src`.  Currently handles:
//! - `Sext { from_bits, to_bits }` where `from_bits == to_bits`
//! - `Zext { from_bits, to_bits }` where `from_bits == to_bits`

use alloc::collections::BTreeMap;

use crate::ir::{IrFunction, IrOp, IrValueId};

pub struct CopyPropPass;

impl CopyPropPass {
    pub fn run(mut func: IrFunction) -> IrFunction {
        for blk in &mut func.blocks {
            // Build substitution map: dst → src for trivial copies.
            let mut subst: BTreeMap<IrValueId, IrValueId> = BTreeMap::new();

            for op in &blk.ops {
                if let Some((dst, src)) = trivial_copy(op) {
                    let resolved = resolve(&subst, src);
                    subst.insert(dst, resolved);
                }
            }

            if subst.is_empty() {
                continue;
            }

            // Apply substitution to all use operands.
            let ops: alloc::vec::Vec<IrOp> = blk
                .ops
                .drain(..)
                .map(|op| op.remap_uses(|v| resolve(&subst, v), |f| f))
                .collect();
            blk.ops = ops;

            // Apply to phi incoming.
            for phi in &mut blk.phis {
                for (_, v) in &mut phi.incoming {
                    *v = resolve(&subst, *v);
                }
            }
        }
        func
    }
}

fn trivial_copy(op: &IrOp) -> Option<(IrValueId, IrValueId)> {
    match op {
        IrOp::Sext { dst, a, from_bits, to_bits } if from_bits == to_bits => {
            Some((*dst, *a))
        }
        IrOp::Zext { dst, a, from_bits, to_bits } if from_bits == to_bits => {
            Some((*dst, *a))
        }
        _ => None,
    }
}

fn resolve(subst: &BTreeMap<IrValueId, IrValueId>, v: IrValueId) -> IrValueId {
    let mut cur = v;
    // Follow chain (handles a→b→c).
    for _ in 0..32 {
        match subst.get(&cur) {
            Some(&next) if next != cur => cur = next,
            _ => break,
        }
    }
    cur
}
