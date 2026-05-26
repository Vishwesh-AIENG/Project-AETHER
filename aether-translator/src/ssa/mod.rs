//! AT-6 SSA construction for the AETHER translator middle-end.
//!
//! Converts Phase A pre-SSA IR (with explicit `ReadGpr`/`WriteGpr`/… register
//! access ops) into proper SSA form.  The algorithm is Cytron et al. 1991 with
//! the iterative Cooper-Harvey-Kennedy dominators (no recursion, safe on deep
//! CFGs).
//!
//! Phase B scope:
//! - [`cfg`]     — control-flow graph from block terminators
//! - [`dom`]     — dominator tree + dominance frontiers
//! - [`promote`] — phi insertion + variable renaming (the SSA builder)
//! - [`verify`]  — SSA verifier (gate check)

pub mod cfg;
pub mod dom;
pub mod promote;
pub mod verify;

pub use promote::SsaBuilder;
pub use verify::{SsaError, SsaVerifier};

/// Identifies which architectural "variable" a Read*/Write* op touches.
/// The SSA builder uses these as the set of variables to promote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VarSlot {
    Gpr(u8),  // x0–x30, x31 = XZR (never live-in; reads always 0)
    Sp,
    Fpr(u8),  // v0–v31
    Flags,
    Pc,
}
