//! AT-10 gate: ARM → x86 TSO memory-ordering lowering.
//!
//! Gate: litmus tests — specific barrier sequences produce the correct x86
//! lowering (no-op / MFENCE / CPUID).

use aether_translator::ir::memory::{BarrierDomain, MemOrder, StoreTy, LoadTy};
use aether_translator::ir::{IrBlock, IrFunction, IrOp, IrValueKind};
use aether_translator::opt::MemOrderLowerPass;

fn make_func_with_ops(ops: Vec<IrOp>) -> IrFunction {
    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        for op in ops {
            blk.push_op(op);
        }
    }
    func
}

fn lowered_ops(func: &IrFunction) -> Vec<&IrOp> {
    func.blocks.iter().flat_map(|b| b.ops.iter()).collect()
}

// ── DMB variants ──────────────────────────────────────────────────────────────

#[test]
fn at10_dmb_ld_elided() {
    // DMB LD (Inner Shareable Load) → no-op under TSO.
    let func = make_func_with_ops(vec![IrOp::Dmb { domain: BarrierDomain::Ishld }]);
    let lowered = MemOrderLowerPass::run(func);
    let ops = lowered_ops(&lowered);
    assert!(ops.is_empty(), "DMB LD should be elided; got {ops:?}");
}

#[test]
fn at10_dmb_st_elided() {
    let func = make_func_with_ops(vec![IrOp::Dmb { domain: BarrierDomain::Ishst }]);
    let lowered = MemOrderLowerPass::run(func);
    assert!(lowered_ops(&lowered).is_empty(), "DMB ST should be elided");
}

#[test]
fn at10_dmb_sy_becomes_mfence() {
    let func = make_func_with_ops(vec![IrOp::Dmb { domain: BarrierDomain::Sy }]);
    let lowered = MemOrderLowerPass::run(func);
    let ops = lowered_ops(&lowered);
    assert_eq!(ops.len(), 1);
    assert!(matches!(ops[0], IrOp::X86Mfence), "DMB SY should become X86Mfence");
}

#[test]
fn at10_dmb_ish_becomes_mfence() {
    let func = make_func_with_ops(vec![IrOp::Dmb { domain: BarrierDomain::Ish }]);
    let lowered = MemOrderLowerPass::run(func);
    let ops = lowered_ops(&lowered);
    assert_eq!(ops.len(), 1);
    assert!(matches!(ops[0], IrOp::X86Mfence));
}

// ── DSB ───────────────────────────────────────────────────────────────────────

#[test]
fn at10_dsb_sy_becomes_mfence() {
    let func = make_func_with_ops(vec![IrOp::Dsb { domain: BarrierDomain::Sy }]);
    let lowered = MemOrderLowerPass::run(func);
    let ops = lowered_ops(&lowered);
    assert_eq!(ops.len(), 1);
    assert!(matches!(ops[0], IrOp::X86Mfence));
}

// ── ISB ───────────────────────────────────────────────────────────────────────

#[test]
fn at10_isb_becomes_cpuid() {
    let func = make_func_with_ops(vec![IrOp::Isb]);
    let lowered = MemOrderLowerPass::run(func);
    let ops = lowered_ops(&lowered);
    assert_eq!(ops.len(), 1);
    assert!(matches!(ops[0], IrOp::X86Cpuid), "ISB should become X86Cpuid");
}

// ── Load ordering ─────────────────────────────────────────────────────────────

#[test]
fn at10_load_acquire_becomes_plain_load() {
    // LDAR (acquire load) → plain load under TSO.
    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let addr = blk.new_value(IrValueKind::I64);
        let dst  = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: addr, val: 0x4000 });
        blk.push_op(IrOp::Load { dst, addr, ty: LoadTy::U64, order: MemOrder::Acquire });
    }
    let lowered = MemOrderLowerPass::run(func);
    for op in lowered_ops(&lowered) {
        if let IrOp::Load { order, .. } = op {
            assert_eq!(
                *order,
                MemOrder::Relaxed,
                "Acquire load should be lowered to Relaxed under TSO"
            );
        }
    }
}

// ── Store ordering ────────────────────────────────────────────────────────────

#[test]
fn at10_store_release_gets_mfence() {
    // STLR (release store) → plain store + MFENCE.
    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let addr = blk.new_value(IrValueKind::I64);
        let val  = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: addr, val: 0x4000 });
        blk.push_op(IrOp::ConstI64 { dst: val, val: 42 });
        blk.push_op(IrOp::Store { val, addr, ty: StoreTy::U64, order: MemOrder::Release });
    }
    let lowered = MemOrderLowerPass::run(func);
    let ops = lowered_ops(&lowered);
    let has_store = ops.iter().any(|op| matches!(op, IrOp::Store { order: MemOrder::Relaxed, .. }));
    let has_mfence = ops.iter().any(|op| matches!(op, IrOp::X86Mfence));
    assert!(has_store, "Release store should produce a plain store");
    assert!(has_mfence, "Release store should be followed by MFENCE");
}

// ── SB (speculative barrier) ──────────────────────────────────────────────────

#[test]
fn at10_sb_elided() {
    let func = make_func_with_ops(vec![IrOp::Sb]);
    let lowered = MemOrderLowerPass::run(func);
    assert!(lowered_ops(&lowered).is_empty(), "SB should be elided on x86");
}
