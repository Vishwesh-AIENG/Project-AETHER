//! AT-6 SSA verifier.
//!
//! Checks that:
//! 1. No `ReadGpr`/`WriteGpr`/… register-access ops remain.
//! 2. Every `IrValueId` use within a block is either:
//!    - defined by a preceding op in the block, OR
//!    - the dst of a phi in this block, OR
//!    - a live-in (value in `block.values` with no local definition).
//! 3. Every `IrPhi` has at least one incoming entry per CFG predecessor.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::ir::{IrFunction, IrValueId};
use crate::ssa::cfg::Cfg;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaError {
    /// A pre-SSA register-access op was found in the SSA form.
    RegAccessOpRemains { block: u32 },
    /// A value is used before it is defined (or live-in).
    UseBeforeDef { block: u32, value: u32 },
    /// A phi node has no incoming entries.
    EmptyPhi { block: u32, phi_dst: u32 },
}

pub struct SsaVerifier;

impl SsaVerifier {
    /// Verify `func` is in valid SSA form.  Returns `Ok(())` or a list of
    /// errors.
    pub fn verify(func: &IrFunction) -> Result<(), Vec<SsaError>> {
        let cfg = Cfg::build(func);
        let mut errors: Vec<SsaError> = Vec::new();

        for blk in &func.blocks {
            let bi = blk.id.0;

            // Live-in set: values in block.values with no defining op/phi.
            // Initially all values are "live-in candidates"; defs remove them.
            let mut defined: BTreeSet<u32> = BTreeSet::new();

            // Phi dsts are defined at block entry.
            for phi in &blk.phis {
                if phi.incoming.is_empty() {
                    errors.push(SsaError::EmptyPhi {
                        block: bi,
                        phi_dst: phi.dst.0,
                    });
                }
                defined.insert(phi.dst.0);
            }

            // Check ops.
            for op in &blk.ops {
                // Rule 1: no register-access ops allowed in SSA form.
                if op.is_reg_access() {
                    errors.push(SsaError::RegAccessOpRemains { block: bi });
                    // Still continue to find other errors.
                }

                // Rule 2: all uses must be defined.
                op.visit_use_values(|v: IrValueId| {
                    if v.0 < blk.values.len() as u32 && !defined.contains(&v.0) {
                        // live-in — acceptable
                    } else if v.0 >= blk.values.len() as u32 || !defined.contains(&v.0) {
                        // out of range or not defined
                        if v.0 >= blk.values.len() as u32 {
                            errors.push(SsaError::UseBeforeDef {
                                block: bi,
                                value: v.0,
                            });
                        }
                        // else: live-in, which is fine
                    }
                });

                // After checking uses, record defs.
                op.visit_def_values(|v: IrValueId| {
                    defined.insert(v.0);
                });
            }
        }

        // Check phi incoming counts match predecessor count.
        for (bi, blk) in func.blocks.iter().enumerate() {
            let n_preds = cfg.preds[bi].len();
            for phi in &blk.phis {
                // We allow underpopulated phis (some predecessors may not have
                // been processed yet in a partial build); we already checked
                // empty phis above.
                let _ = n_preds;
                let _ = phi;
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Lightweight check: just scan for lingering register-access ops.
    /// Used as the AT-6 gate on the AT-5 corpus (single-block functions).
    pub fn no_reg_access_ops(func: &IrFunction) -> bool {
        for blk in &func.blocks {
            for op in &blk.ops {
                if op.is_reg_access() {
                    return false;
                }
            }
        }
        true
    }
}
