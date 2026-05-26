//! SSA promotion: phi insertion + variable renaming.
//!
//! Takes a pre-SSA [`IrFunction`] (with `ReadGpr`/`WriteGpr`/… ops) and
//! returns an SSA [`IrFunction`] with those ops replaced by direct value
//! references and [`IrPhi`] nodes at join points.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ir::{BlockId, IrBlock, IrFlagsId, IrFunction, IrOp, IrPhi, IrValueId, IrValueKind};

use super::{
    cfg::Cfg,
    dom::{DomFrontiers, DomTree},
    VarSlot,
};

/// Set of variable slots (GPR, FPR, Flags, Pc, Sp) that any block defines.
type DefSet = Vec<(usize, VarSlot)>; // (block_index, slot)

pub struct SsaBuilder;

impl SsaBuilder {
    /// Promote `func` to SSA form.
    ///
    /// # Algorithm (Cytron et al. 1991, simplified)
    /// 1. Build CFG + dominator tree + dominance frontiers.
    /// 2. For each `VarSlot`, collect the set of blocks that define it.
    /// 3. Insert `IrPhi` placeholders at every dominance frontier of those blocks.
    /// 4. Rename: walk the dominator tree top-down; substitute `ReadX` / `WriteX`
    ///    with direct SSA values; fill phi `incoming` lists on the way down.
    pub fn build(func: IrFunction) -> IrFunction {
        let n = func.blocks.len();
        if n == 0 {
            return func;
        }

        let cfg = Cfg::build(&func);
        let rpo = cfg.rpo();
        let dom = DomTree::build(&cfg, &rpo);
        let df = DomFrontiers::build(&cfg, &dom);

        // ── Step 1: collect defs per slot ────────────────────────────────────
        // defs_of[slot] = list of block indices that write to slot
        let mut defs_of: BTreeMap<VarSlot, Vec<usize>> = BTreeMap::new();
        for (bi, blk) in func.blocks.iter().enumerate() {
            for op in &blk.ops {
                if let Some(slot) = write_slot(op) {
                    defs_of.entry(slot).or_default().push(bi);
                }
            }
        }

        // ── Step 2: phi placement (Cytron §5) ────────────────────────────────
        // phi_for[bi] = list of VarSlots that need a phi at block bi
        let mut phi_for: Vec<Vec<VarSlot>> = vec![Vec::new(); n];
        for (slot, def_blocks) in &defs_of {
            let mut worklist: Vec<usize> = def_blocks.clone();
            let mut ever_on_wl = vec![false; n];
            for &b in &worklist {
                ever_on_wl[b] = true;
            }
            let mut placed = vec![false; n];
            let mut head = 0;
            while head < worklist.len() {
                let b = worklist[head];
                head += 1;
                for &y in &df.df[b] {
                    if !placed[y] {
                        phi_for[y].push(*slot);
                        placed[y] = true;
                        if !ever_on_wl[y] {
                            ever_on_wl[y] = true;
                            worklist.push(y);
                        }
                    }
                }
            }
        }

        // ── Step 3: build output function, inserting phi placeholders ─────────
        // We clone the function structure, then do the renaming pass.
        let mut out_blocks: Vec<IrBlock> = func
            .blocks
            .iter()
            .map(|b| {
                let mut nb = IrBlock::new(b.id);
                nb.values = b.values.clone();
                nb.flags = b.flags.clone();
                nb
            })
            .collect();

        // Allocate phi dst values for each slot at each block.
        // phi_dst[bi][slot] = IrValueId of the phi at block bi for slot.
        let mut phi_dst: Vec<BTreeMap<VarSlot, (IrValueId, Option<IrFlagsId>)>> =
            vec![BTreeMap::new(); n];
        for (bi, slots) in phi_for.iter().enumerate() {
            for slot in slots {
                match slot {
                    VarSlot::Flags => {
                        let fid = out_blocks[bi].new_flags();
                        phi_dst[bi].insert(*slot, (IrValueId(0), Some(fid)));
                    }
                    _ => {
                        let kind = slot_value_kind(slot, &func.blocks[bi]);
                        let vid = out_blocks[bi].new_value(kind);
                        phi_dst[bi].insert(*slot, (vid, None));
                    }
                }
            }
        }

        // ── Step 4: domtree renaming (two-phase explicit stack) ──────────────
        // def_stacks[slot] = stack of SSA defs visible at the current point in
        // the dominator-tree DFS.  We use a two-phase work queue:
        //
        //   Work::Visit(bi)    — enter block bi, push defs, rename ops,
        //                        then push Pop(pushed) + Visit(child)…
        //   Work::Pop(pushed)  — restore def_stacks after the subtree of bi
        //                        has been fully processed.
        //
        // This guarantees that children see their parent's defs while being
        // renamed, and stacks are cleaned up only after the entire subtree is done.
        let mut def_stacks: BTreeMap<VarSlot, Vec<SsaDef>> = BTreeMap::new();

        let mut dom_children: Vec<Vec<usize>> = vec![Vec::new(); n];
        for b in 0..n {
            let p = dom.idom[b];
            if p != b {
                dom_children[p].push(b);
            }
        }

        enum Work {
            Visit(usize),
            Pop(BTreeMap<VarSlot, usize>),
        }

        let entry = rpo[0];
        let mut work: Vec<Work> = vec![Work::Visit(entry)];

        let src_blocks: Vec<IrBlock> = func.blocks;

        while let Some(item) = work.pop() {
            match item {
                Work::Pop(pushed) => {
                    for (slot, count) in pushed {
                        if let Some(stack) = def_stacks.get_mut(&slot) {
                            let new_len = stack.len().saturating_sub(count);
                            stack.truncate(new_len);
                        }
                    }
                }
                Work::Visit(bi) => {
                    let src = &src_blocks[bi];
                    let mut pushed: BTreeMap<VarSlot, usize> = BTreeMap::new();

                    // Push phi dsts for this block onto def stacks.
                    for (slot, &(vid, fid)) in &phi_dst[bi] {
                        let def = if let Some(f) = fid {
                            SsaDef::Flags(f)
                        } else {
                            SsaDef::Value(vid)
                        };
                        def_stacks.entry(*slot).or_default().push(def);
                        *pushed.entry(*slot).or_insert(0) += 1;
                    }

                    // Build this block's phi nodes (incoming filled later).
                    for slot in &phi_for[bi] {
                        let dst_entry = phi_dst[bi][slot];
                        match slot {
                            VarSlot::Flags => {
                                let phi = IrPhi {
                                    dst: IrValueId(dst_entry.1.map(|f| f.0).unwrap_or(0)),
                                    incoming: Vec::new(),
                                };
                                out_blocks[bi].phis.push(phi);
                            }
                            _ => {
                                let phi = IrPhi { dst: dst_entry.0, incoming: Vec::new() };
                                out_blocks[bi].phis.push(phi);
                            }
                        }
                    }

                    // ── Rename ops ──────────────────────────────────────────────
                    let mut val_remap: BTreeMap<IrValueId, IrValueId> = BTreeMap::new();
                    let mut flag_remap: BTreeMap<IrFlagsId, IrFlagsId> = BTreeMap::new();

                    for op in src.ops.iter().cloned() {
                        match op {
                            IrOp::ReadGpr { dst, reg, .. } => {
                                let slot = VarSlot::Gpr(reg);
                                let def = current_val(&def_stacks, slot).unwrap_or(dst);
                                val_remap.insert(dst, def);
                                if current_val(&def_stacks, slot).is_none() {
                                    def_stacks.entry(slot).or_default().push(SsaDef::Value(dst));
                                    *pushed.entry(slot).or_insert(0) += 1;
                                }
                            }
                            IrOp::WriteGpr { reg, src, sf: _ } => {
                                let src = *val_remap.get(&src).unwrap_or(&src);
                                let slot = VarSlot::Gpr(reg);
                                def_stacks.entry(slot).or_default().push(SsaDef::Value(src));
                                *pushed.entry(slot).or_insert(0) += 1;
                            }
                            IrOp::ReadSp { dst, .. } => {
                                let def = current_val(&def_stacks, VarSlot::Sp).unwrap_or(dst);
                                val_remap.insert(dst, def);
                                if current_val(&def_stacks, VarSlot::Sp).is_none() {
                                    def_stacks.entry(VarSlot::Sp).or_default().push(SsaDef::Value(dst));
                                    *pushed.entry(VarSlot::Sp).or_insert(0) += 1;
                                }
                            }
                            IrOp::WriteSp { src, sf: _ } => {
                                let src = *val_remap.get(&src).unwrap_or(&src);
                                def_stacks.entry(VarSlot::Sp).or_default().push(SsaDef::Value(src));
                                *pushed.entry(VarSlot::Sp).or_insert(0) += 1;
                            }
                            IrOp::ReadFpr { dst, reg } => {
                                let slot = VarSlot::Fpr(reg);
                                let def = current_val(&def_stacks, slot).unwrap_or(dst);
                                val_remap.insert(dst, def);
                                if current_val(&def_stacks, slot).is_none() {
                                    def_stacks.entry(slot).or_default().push(SsaDef::Value(dst));
                                    *pushed.entry(slot).or_insert(0) += 1;
                                }
                            }
                            IrOp::WriteFpr { reg, src } => {
                                let src = *val_remap.get(&src).unwrap_or(&src);
                                let slot = VarSlot::Fpr(reg);
                                def_stacks.entry(slot).or_default().push(SsaDef::Value(src));
                                *pushed.entry(slot).or_insert(0) += 1;
                            }
                            IrOp::ReadFlags { dst } => {
                                let def = current_flag(&def_stacks, VarSlot::Flags).unwrap_or(dst);
                                flag_remap.insert(dst, def);
                                if current_flag(&def_stacks, VarSlot::Flags).is_none() {
                                    def_stacks.entry(VarSlot::Flags).or_default().push(SsaDef::Flags(dst));
                                    *pushed.entry(VarSlot::Flags).or_insert(0) += 1;
                                }
                            }
                            IrOp::WriteFlags { src } => {
                                let src = *flag_remap.get(&src).unwrap_or(&src);
                                def_stacks.entry(VarSlot::Flags).or_default().push(SsaDef::Flags(src));
                                *pushed.entry(VarSlot::Flags).or_insert(0) += 1;
                            }
                            IrOp::ReadPc { dst } => {
                                let def = current_val(&def_stacks, VarSlot::Pc).unwrap_or(dst);
                                val_remap.insert(dst, def);
                                if current_val(&def_stacks, VarSlot::Pc).is_none() {
                                    def_stacks.entry(VarSlot::Pc).or_default().push(SsaDef::Value(dst));
                                    *pushed.entry(VarSlot::Pc).or_insert(0) += 1;
                                }
                            }
                            IrOp::WritePc { src } => {
                                let src = *val_remap.get(&src).unwrap_or(&src);
                                def_stacks.entry(VarSlot::Pc).or_default().push(SsaDef::Value(src));
                                *pushed.entry(VarSlot::Pc).or_insert(0) += 1;
                            }
                            other => {
                                let remapped = other.remap_uses(
                                    |v| *val_remap.get(&v).unwrap_or(&v),
                                    |f| *flag_remap.get(&f).unwrap_or(&f),
                                );
                                remapped.visit_def_flags(|f| {
                                    def_stacks.entry(VarSlot::Flags).or_default().push(SsaDef::Flags(f));
                                    *pushed.entry(VarSlot::Flags).or_insert(0) += 1;
                                });
                                out_blocks[bi].ops.push(remapped);
                            }
                        }
                    }

                    // ── Fill phi incoming for successors ──────────────────────
                    for &succ in &cfg.succs[bi] {
                        for (phi_slot, &(vid, fid)) in &phi_dst[succ] {
                            let incoming_val = match phi_slot {
                                VarSlot::Flags => {
                                    let fdef = current_flag(&def_stacks, *phi_slot);
                                    if let (Some(phi), Some(fdef)) = (
                                        out_blocks[succ].phis.iter_mut().find(|p| {
                                            fid.map(|f| p.dst.0 == f.0).unwrap_or(false)
                                        }),
                                        fdef,
                                    ) {
                                        phi.incoming.push((BlockId(bi as u32), IrValueId(fdef.0)));
                                    }
                                    continue;
                                }
                                _ => current_val(&def_stacks, *phi_slot),
                            };
                            if let Some(v) = incoming_val {
                                if let Some(phi) = out_blocks[succ]
                                    .phis
                                    .iter_mut()
                                    .find(|p| p.dst == vid)
                                {
                                    phi.incoming.push((BlockId(bi as u32), v));
                                }
                            }
                        }
                    }

                    // ── Schedule cleanup + children ───────────────────────────
                    // Pop MUST be pushed before children so that it runs AFTER all
                    // children (children are popped off the stack first).
                    work.push(Work::Pop(pushed));
                    // Push children in reverse order so the first child is
                    // processed first (stack is LIFO).
                    for &child in dom_children[bi].iter().rev() {
                        work.push(Work::Visit(child));
                    }
                }
            }
        }

        IrFunction {
            blocks: out_blocks,
            entry_pc: func.entry_pc,
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum SsaDef {
    Value(IrValueId),
    Flags(IrFlagsId),
}

fn current_val(stacks: &BTreeMap<VarSlot, Vec<SsaDef>>, slot: VarSlot) -> Option<IrValueId> {
    stacks.get(&slot)?.last().and_then(|d| match d {
        SsaDef::Value(v) => Some(*v),
        _ => None,
    })
}

fn current_flag(stacks: &BTreeMap<VarSlot, Vec<SsaDef>>, slot: VarSlot) -> Option<IrFlagsId> {
    stacks.get(&slot)?.last().and_then(|d| match d {
        SsaDef::Flags(f) => Some(*f),
        _ => None,
    })
}

/// Which VarSlot does a Write* op write to?
fn write_slot(op: &IrOp) -> Option<VarSlot> {
    match op {
        IrOp::WriteGpr { reg, .. } => Some(VarSlot::Gpr(*reg)),
        IrOp::WriteSp { .. } => Some(VarSlot::Sp),
        IrOp::WriteFpr { reg, .. } => Some(VarSlot::Fpr(*reg)),
        IrOp::WriteFlags { .. } => Some(VarSlot::Flags),
        IrOp::WritePc { .. } => Some(VarSlot::Pc),
        _ => None,
    }
}

/// Value kind for a `VarSlot`'s live-in value, inferred from the block.
fn slot_value_kind(slot: &VarSlot, blk: &IrBlock) -> IrValueKind {
    match slot {
        VarSlot::Gpr(_) | VarSlot::Sp | VarSlot::Pc => IrValueKind::I64,
        VarSlot::Fpr(_) => IrValueKind::Vec128 {
            lane: crate::ir::value::LaneType::I8,
        },
        VarSlot::Flags => {
            // Flags phi dst is an IrFlagsId, not an IrValueId. Use a sentinel.
            let _ = blk;
            IrValueKind::Flags
        }
    }
}
