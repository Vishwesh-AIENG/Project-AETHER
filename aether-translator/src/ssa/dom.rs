//! Dominator tree and dominance frontiers.
//!
//! Algorithm: Cooper, Harvey, Kennedy (2001) "A Simple, Fast Dominance
//! Algorithm".  Iterative, O(n²) worst case but linear in practice on
//! structured code.  No recursion — safe for deep call graphs.

use alloc::vec::Vec;

use super::cfg::Cfg;

const UNDEFINED: usize = usize::MAX;

/// Dominator tree.  `idom[i]` is the immediate dominator of block `i`,
/// or `UNDEFINED` for the entry block.
pub struct DomTree {
    pub idom: Vec<usize>,
    pub n: usize,
}

impl DomTree {
    pub fn build(cfg: &Cfg, rpo: &[usize]) -> Self {
        let n = cfg.n;
        let mut idom = vec![UNDEFINED; n];

        if n == 0 {
            return Self { idom, n };
        }

        // RPO index for each block (position in the RPO traversal).
        let mut rpo_idx = vec![UNDEFINED; n];
        for (pos, &b) in rpo.iter().enumerate() {
            rpo_idx[b] = pos;
        }

        let entry = rpo[0];
        idom[entry] = entry;

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter() {
                if b == entry {
                    continue;
                }
                // Pick first processed predecessor.
                let new_idom = cfg.preds[b]
                    .iter()
                    .copied()
                    .find(|&p| idom[p] != UNDEFINED);
                let mut new_idom = match new_idom {
                    Some(p) => p,
                    None => continue,
                };
                // Walk remaining predecessors.
                for &p in &cfg.preds[b] {
                    if idom[p] != UNDEFINED {
                        new_idom = intersect(&idom, &rpo_idx, p, new_idom);
                    }
                }
                if idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        Self { idom, n }
    }

    /// True if `a` strictly dominates `b`.
    pub fn strictly_dominates(&self, a: usize, b: usize) -> bool {
        if a == b {
            return false;
        }
        let mut cur = b;
        loop {
            let p = self.idom[cur];
            if p == a {
                return true;
            }
            if p == cur {
                // reached the root without finding a
                return false;
            }
            cur = p;
        }
    }
}

fn intersect(idom: &[usize], rpo_idx: &[usize], mut b1: usize, mut b2: usize) -> usize {
    while b1 != b2 {
        while rpo_idx[b1] > rpo_idx[b2] {
            b1 = idom[b1];
        }
        while rpo_idx[b2] > rpo_idx[b1] {
            b2 = idom[b2];
        }
    }
    b1
}

/// Dominance frontiers.  `df[b]` = set of blocks at the boundary of b's
/// domination.  Phi nodes must be inserted at all df members.
pub struct DomFrontiers {
    pub df: Vec<Vec<usize>>,
}

impl DomFrontiers {
    pub fn build(cfg: &Cfg, dom: &DomTree) -> Self {
        let n = cfg.n;
        let mut df = vec![Vec::new(); n];
        for b in 0..n {
            if cfg.preds[b].len() >= 2 {
                for &p in &cfg.preds[b] {
                    let mut runner = p;
                    while runner != dom.idom[b] && runner != b {
                        if !df[runner].contains(&b) {
                            df[runner].push(b);
                        }
                        if dom.idom[runner] == runner {
                            break; // entry
                        }
                        runner = dom.idom[runner];
                    }
                }
            }
        }
        Self { df }
    }
}
