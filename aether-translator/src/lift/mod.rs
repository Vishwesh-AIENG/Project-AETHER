//! Decoded encoding → IR lifting.
//!
//! Takes a [`crate::decoder::DecodedInsn`] and emits the equivalent
//! [`crate::ir::IrOp`] sequence into a target [`crate::ir::IrBlock`].
//!
//! Phase A status: skeleton. Per-family lift code lands in the AT-1..AT-4
//! fill commits.

use crate::decoder::DecodedInsn;
use crate::ir::IrBlock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftErr {
    /// The decoder produced an encoding the lifter does not yet handle.
    /// Carries the original instruction word so AT-5 can report exactly
    /// what is missing.
    Unimplemented(u32),
}

/// Lift one decoded instruction into the given block. The block must be the
/// current basic block being constructed; control-flow-changing ops will
/// terminate it.
pub fn lift(insn: &DecodedInsn, _block: &mut IrBlock) -> Result<(), LiftErr> {
    let word = match *insn {
        DecodedInsn::Unknown(w) => w,
        ref other => return Err(LiftErr::Unimplemented(insn_raw_or_zero(other))),
    };
    Err(LiftErr::Unimplemented(word))
}

fn insn_raw_or_zero(_insn: &DecodedInsn) -> u32 {
    // Phase A skeleton: most variants don't carry their raw word; AT-1 fill
    // adds a `raw: u32` shadow field on every DecodedInsn for traceability.
    0
}
