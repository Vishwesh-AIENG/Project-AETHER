//! NZCV flag modeling.
//!
//! Phase A decision: explicit flag-producer ops. `IrOp::AddS` etc. produce a
//! companion [`IrFlagsId`] alongside the integer result; downstream consumers
//! (conditional branches, CSEL) reference flags via `IrFlagsId` + `NzcvBit`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct IrFlagsId(pub u32);

/// Individual NZCV bit projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NzcvBit {
    N,
    Z,
    C,
    V,
}
