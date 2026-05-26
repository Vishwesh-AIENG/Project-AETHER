//! AT-7 / AT-8 / AT-10 optimizer passes for the AETHER translator middle-end.
//!
//! All passes operate on SSA-form [`IrFunction`]s (post AT-6 promotion).
//!
//! - [`dce`]            — dead-code elimination
//! - [`copy_prop`]      — copy propagation
//! - [`const_fold`]     — constant folding
//! - [`gvn`]            — global value numbering
//! - [`redundant_load`] — redundant-load elimination
//! - [`flag_elision`]   — AT-8: NZCV flag suppression
//! - [`mem_order`]      — AT-10: ARM→x86 TSO memory-ordering lowering

pub mod const_fold;
pub mod copy_prop;
pub mod dce;
pub mod flag_elision;
pub mod gvn;
pub mod mem_order;
pub mod redundant_load;

pub use const_fold::ConstFoldPass;
pub use copy_prop::CopyPropPass;
pub use dce::DcePass;
pub use flag_elision::FlagElisionPass;
pub use gvn::GvnPass;
pub use mem_order::MemOrderLowerPass;
pub use redundant_load::RedundantLoadPass;

use crate::ir::IrFunction;

/// Run the standard Phase B optimization pipeline on `func`.
///
/// Order: const-fold → copy-prop → DCE → GVN → redundant-load → flag-elision
/// → mem-order lowering.
pub fn run_pipeline(func: IrFunction) -> IrFunction {
    let func = ConstFoldPass::run(func);
    let func = CopyPropPass::run(func);
    let func = DcePass::run(func);
    let func = GvnPass::run(func);
    let func = RedundantLoadPass::run(func);
    let func = FlagElisionPass::run(func);
    MemOrderLowerPass::run(func)
}
