//! AT-10 Memory-ordering lowering: ARM weak-order → x86 TSO.
//!
//! x86 has Total Store Order (TSO): loads are acquire, stores are release
//! with respect to each other.  ARM is weakly ordered.
//!
//! Mapping rules (per Sewell et al. "x86-TSO: A Rigorous and Usable
//! Programmer's Model for x86 Multiprocessors"):
//!
//! | ARM IR         | x86 semantics          | Lowered to              |
//! |----------------|------------------------|-------------------------|
//! | DMB LD / ISH-LD| Acquire barrier        | No-op (TSO loads acq)   |
//! | DMB ST / ISH-ST| Store barrier          | No-op (TSO stores rel)  |
//! | DMB SY / ISH   | Full barrier           | `IrOp::X86Mfence`       |
//! | DSB SY         | Full barrier           | `IrOp::X86Mfence`       |
//! | ISB            | Instruction barrier    | `IrOp::X86Cpuid`        |
//! | Load Acquire   | Acquire load           | Plain load (TSO)        |
//! | Store Release  | Release store          | Plain store + mfence    |
//! | Load SeqCst    | Sequentially consistent| Plain load              |
//! | Store SeqCst   | Sequentially consistent| Xchg-based store        |
//!
//! The pass lowers `IrOp::Dmb`/`IrOp::Dsb`/`IrOp::Isb` in-place, and
//! upgrades `Load`/`Store` memory-ordering annotations.  New sentinel ops
//! `IrOp::X86Mfence` and `IrOp::X86Cpuid` are introduced for Phase C.

use alloc::vec::Vec;

use crate::ir::memory::{BarrierDomain, MemOrder};
use crate::ir::{IrFunction, IrOp};

pub struct MemOrderLowerPass;

impl MemOrderLowerPass {
    pub fn run(mut func: IrFunction) -> IrFunction {
        for blk in &mut func.blocks {
            let mut new_ops: Vec<IrOp> = Vec::with_capacity(blk.ops.len());
            for op in blk.ops.drain(..) {
                match op {
                    // DMB LD / ISH-LD → no-op under TSO (loads are already
                    // acquire-ordered by the hardware).
                    IrOp::Dmb {
                        domain: BarrierDomain::Ishld | BarrierDomain::NshLd | BarrierDomain::OshLd | BarrierDomain::SyLoad,
                    } => { /* elide */ }

                    // DMB ST / ISH-ST → no-op (stores ordered wrt stores in TSO).
                    IrOp::Dmb {
                        domain: BarrierDomain::Ishst | BarrierDomain::NshSt | BarrierDomain::OshSt | BarrierDomain::SyStore,
                    } => { /* elide */ }

                    // Full barriers → MFENCE.
                    IrOp::Dmb {
                        domain: BarrierDomain::Ish | BarrierDomain::Nsh | BarrierDomain::Osh | BarrierDomain::Sy,
                    } => new_ops.push(IrOp::X86Mfence),

                    // DSB SY / any → MFENCE.
                    IrOp::Dsb { .. } => new_ops.push(IrOp::X86Mfence),

                    // ISB → CPUID (serialising instruction on x86).
                    IrOp::Isb => new_ops.push(IrOp::X86Cpuid),

                    // SB (speculative barrier) → no-op on x86 (OOO is transparent to software).
                    IrOp::Sb => { /* elide */ }

                    // Load Acquire / SeqCst → plain load (TSO provides acquire semantics).
                    IrOp::Load { dst, addr, ty, order: MemOrder::Acquire | MemOrder::AcqRel | MemOrder::SeqCst } => {
                        new_ops.push(IrOp::Load { dst, addr, ty, order: MemOrder::Relaxed });
                    }

                    // Store Release → plain store + MFENCE.
                    IrOp::Store { val, addr, ty, order: MemOrder::Release | MemOrder::AcqRel } => {
                        new_ops.push(IrOp::Store { val, addr, ty, order: MemOrder::Relaxed });
                        new_ops.push(IrOp::X86Mfence);
                    }

                    // Store SeqCst → plain store + MFENCE (conservative).
                    IrOp::Store { val, addr, ty, order: MemOrder::SeqCst } => {
                        new_ops.push(IrOp::Store { val, addr, ty, order: MemOrder::Relaxed });
                        new_ops.push(IrOp::X86Mfence);
                    }

                    other => new_ops.push(other),
                }
            }
            blk.ops = new_ops;
        }
        func
    }
}
