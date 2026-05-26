//! AT-8 Flag-elision pass.
//!
//! An `IrOp` that produces an `IrFlagsId` (AddS, SubS, Cmp, …) can be
//! "elided" — its flag output suppressed on the x86 backend — if the produced
//! `IrFlagsId` is **never consumed** before the next operation that overwrites
//! NZCV (or before the block ends).
//!
//! The result is stored in [`IrBlock::elided_flags`]: a set of `IrFlagsId`s
//! that the x86 backend need not materialise.  This set is consulted by the
//! code-generator (Phase C, AT-12) to omit `TEST`/`CMP` instructions whose
//! result is thrown away.
//!
//! Gate (AT-8): ≥ 60 % of flag-producing ops must be elided on a typical
//! Android workload.  On straight-line code without conditional branches the
//! rate approaches 100 % since most `*S` ops are redundant (Clang emits them
//! paired with a plain op for the value and uses the S-variant only for the
//! rarely-needed flags).

use alloc::collections::BTreeSet;
use crate::ir::{IrBlock, IrFlagsId, IrFunction};

pub struct FlagElisionPass;

impl FlagElisionPass {
    pub fn run(mut func: IrFunction) -> IrFunction {
        for blk in &mut func.blocks {
            run_on_block(blk);
        }
        func
    }

    /// Fraction of flag-producing ops that are elided in `func`.
    /// Returns `(elided, total)`.
    pub fn elision_ratio(func: &IrFunction) -> (usize, usize) {
        let mut total = 0usize;
        let mut elided = 0usize;
        for blk in &func.blocks {
            for op in &blk.ops {
                let mut is_flag_producer = false;
                op.visit_def_flags(|_| { is_flag_producer = true; });
                if is_flag_producer {
                    total += 1;
                    // Check if this flag is in the elided set.
                    op.visit_def_flags(|f| {
                        if blk.elided_flags.contains(&f.0) {
                            elided += 1;
                        }
                    });
                }
            }
        }
        (elided, total)
    }
}

fn run_on_block(blk: &mut IrBlock) {
    // Forward pass: collect consumed flags.
    let mut consumed: BTreeSet<u32> = BTreeSet::new();
    for op in &blk.ops {
        op.visit_use_flags(|f: IrFlagsId| {
            consumed.insert(f.0);
        });
    }
    // Also consume flags used by phi incoming (flags phis if any).
    for _phi in &blk.phis {
        // phi.dst may map to flags in the future; for now phis track values.
    }

    // All flag defs NOT in consumed can be elided.
    for op in &blk.ops {
        op.visit_def_flags(|f: IrFlagsId| {
            if !consumed.contains(&f.0) {
                blk.elided_flags.insert(f.0);
            }
        });
    }
}

// ── IrBlock extension ──────────────────────────────────────────────────────
// We store the elided set in IrBlock. Add the field here by extending the
// existing struct via a companion trait so we don't touch ir/mod.rs again.
//
// Actually, we add `elided_flags: BTreeSet<u32>` directly to IrBlock in the
// ir/mod.rs patch below, and surface it here.
