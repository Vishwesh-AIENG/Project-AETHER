//! Global Value Numbering pass (AT-7).
//!
//! Within each basic block, detects duplicate computations and replaces
//! redundant ones with copies of the first result.  Uses a hash-cons table
//! keyed by (opcode-discriminant, operands).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ir::{IrFunction, IrOp, IrValueId};

pub struct GvnPass;

impl GvnPass {
    pub fn run(mut func: IrFunction) -> IrFunction {
        for blk in &mut func.blocks {
            // value_number[v] = canonical representative for v
            let mut canon: BTreeMap<IrValueId, IrValueId> = BTreeMap::new();
            // gvn_table: (tag, op_inputs) → first dst that computed this
            let mut table: BTreeMap<GvnKey, IrValueId> = BTreeMap::new();
            let mut new_ops: Vec<IrOp> = Vec::with_capacity(blk.ops.len());

            for op in blk.ops.drain(..) {
                // Resolve operands through canon map.
                let resolved = op.remap_uses(
                    |v| *canon.get(&v).unwrap_or(&v),
                    |f| f,
                );
                // Try to GVN-lookup this op.
                if let Some(key) = gvn_key(&resolved) {
                    if let Some(&prev_dst) = table.get(&key) {
                        // Duplicate: record alias, drop the op (DCE will clean it).
                        if let Some(dst) = def_value_of(&resolved) {
                            canon.insert(dst, *canon.get(&prev_dst).unwrap_or(&prev_dst));
                        }
                        // Keep the original op so its dst is still defined if
                        // something already referenced it before GVN ran.
                        // A subsequent copy-prop + DCE pass will remove it.
                        new_ops.push(resolved);
                        continue;
                    } else {
                        if let Some(dst) = def_value_of(&resolved) {
                            table.insert(key, dst);
                        }
                    }
                }
                new_ops.push(resolved);
            }

            blk.ops = new_ops;
        }
        func
    }
}

/// Compact key for GVN lookup: only pure (side-effect-free, deterministic) ops.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GvnKey {
    tag: u16,
    a: u32,
    b: u32,
    c: u32,
    imm: i64,
}

fn gvn_key(op: &IrOp) -> Option<GvnKey> {
    let k = |tag: u16, a: u32, b: u32| GvnKey { tag, a, b, c: 0, imm: 0 };
    let kc = |tag: u16, a: u32, imm: i64| GvnKey { tag, a, b: 0, c: 0, imm };
    match op {
        IrOp::ConstI64 { val, .. } => Some(kc(1, 0, *val)),
        IrOp::ConstI32 { val, .. } => Some(kc(2, 0, *val as i64)),
        IrOp::Add { a, b, .. } => Some(k(10, a.0.min(b.0), a.0.max(b.0))),
        IrOp::Sub { a, b, .. } => Some(k(11, a.0, b.0)),
        IrOp::And { a, b, .. } => Some(k(12, a.0.min(b.0), a.0.max(b.0))),
        IrOp::Or  { a, b, .. } => Some(k(13, a.0.min(b.0), a.0.max(b.0))),
        IrOp::Xor { a, b, .. } => Some(k(14, a.0.min(b.0), a.0.max(b.0))),
        IrOp::Mul { a, b, .. } => Some(k(15, a.0.min(b.0), a.0.max(b.0))),
        IrOp::Shl { a, b, .. } => Some(k(16, a.0, b.0)),
        IrOp::LShr { a, b, .. } => Some(k(17, a.0, b.0)),
        IrOp::AShr { a, b, .. } => Some(k(18, a.0, b.0)),
        IrOp::Neg { a, .. } => Some(k(20, a.0, 0)),
        IrOp::Not { a, .. } => Some(k(21, a.0, 0)),
        IrOp::Clz { a, .. } => Some(k(22, a.0, 0)),
        IrOp::Sext { a, from_bits, to_bits, .. } =>
            Some(GvnKey { tag: 30, a: a.0, b: *from_bits as u32, c: *to_bits as u32, imm: 0 }),
        IrOp::Zext { a, from_bits, to_bits, .. } =>
            Some(GvnKey { tag: 31, a: a.0, b: *from_bits as u32, c: *to_bits as u32, imm: 0 }),
        // Memory, branches, system ops: not eligible for GVN.
        _ => None,
    }
}

fn def_value_of(op: &IrOp) -> Option<IrValueId> {
    let mut d = None;
    op.visit_def_values(|v| { d = Some(v); });
    d
}
