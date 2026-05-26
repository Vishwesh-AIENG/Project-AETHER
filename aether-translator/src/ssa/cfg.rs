//! Control-flow graph built from block terminators.

use alloc::vec::Vec;

use crate::ir::{IrFunction, IrOp};

/// Forward and backward adjacency lists (block indices, not [`BlockId`]s).
pub struct Cfg {
    pub succs: Vec<Vec<usize>>,
    pub preds: Vec<Vec<usize>>,
    pub n: usize,
}

impl Cfg {
    /// Build CFG from `func`.  Block index = position in `func.blocks`.
    pub fn build(func: &IrFunction) -> Self {
        let n = func.blocks.len();
        let mut succs = vec![Vec::new(); n];
        let mut preds = vec![Vec::new(); n];

        for (i, blk) in func.blocks.iter().enumerate() {
            // Terminator is the last op; fall-through to i+1 if no branch.
            let mut found_terminator = false;
            for op in blk.ops.iter().rev() {
                match op {
                    IrOp::Branch { target } => {
                        let j = target.0 as usize;
                        if j < n {
                            succs[i].push(j);
                            preds[j].push(i);
                        }
                        found_terminator = true;
                        break;
                    }
                    IrOp::CondBranch { taken, fallthru, .. }
                    | IrOp::Cbz { taken, fallthru, .. }
                    | IrOp::Cbnz { taken, fallthru, .. }
                    | IrOp::Tbz { taken, fallthru, .. }
                    | IrOp::Tbnz { taken, fallthru, .. } => {
                        for &t in &[*taken, *fallthru] {
                            let j = t.0 as usize;
                            if j < n && !succs[i].contains(&j) {
                                succs[i].push(j);
                                preds[j].push(i);
                            }
                        }
                        found_terminator = true;
                        break;
                    }
                    IrOp::IndirectBranch { .. } | IrOp::Return { .. } => {
                        found_terminator = true;
                        break;
                    }
                    _ => continue,
                }
            }
            // Implicit fall-through to next block.
            if !found_terminator && i + 1 < n {
                succs[i].push(i + 1);
                preds[i + 1].push(i);
            }
        }

        Self { succs, preds, n }
    }

    /// Reverse post-order of blocks starting from block 0 (entry).
    pub fn rpo(&self) -> Vec<usize> {
        if self.n == 0 {
            return Vec::new();
        }
        let mut visited = vec![false; self.n];
        let mut order = Vec::with_capacity(self.n);
        // Iterative DFS using an explicit stack: (node, next_succ_index).
        let mut stack: Vec<(usize, usize)> = Vec::new();
        stack.push((0, 0));
        visited[0] = true;
        while let Some((node, si)) = stack.last_mut() {
            let node = *node;
            if *si < self.succs[node].len() {
                let next = self.succs[node][*si];
                *si += 1;
                if !visited[next] {
                    visited[next] = true;
                    stack.push((next, 0));
                }
            } else {
                order.push(node);
                stack.pop();
            }
        }
        order.reverse();
        order
    }
}
