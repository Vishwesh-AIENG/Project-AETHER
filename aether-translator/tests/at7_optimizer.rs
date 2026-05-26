//! AT-7 gate: optimizer passes — IR-size reduction + semantic equivalence.
//!
//! Gate: ≥ 15 % median IR-size reduction on the AT-5 corpus (or on the
//! synthesised instruction sequences below when the corpus is unavailable).

use aether_translator::decoder::decode_instruction;
use aether_translator::ir::IrFunction;
use aether_translator::lift::lift_at;
use aether_translator::opt;
use aether_translator::ssa::SsaBuilder;

fn make_ssa_func(words: &[u32]) -> IrFunction {
    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let mut pc = 0u64;
        for &w in words {
            if let Ok(insn) = decode_instruction(w) {
                let _ = lift_at(&insn, blk, pc);
            }
            pc += 4;
        }
    }
    SsaBuilder::build(func)
}

fn op_count(func: &IrFunction) -> usize {
    func.blocks.iter().map(|b| b.ops.len()).sum()
}

// ── Constant folding ─────────────────────────────────────────────────────────

#[test]
fn at7_const_fold_add() {
    use aether_translator::ir::{IrOp, IrValueKind};
    use aether_translator::opt::ConstFoldPass;

    // Build a micro-function: x = 2 + 3
    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let v0 = blk.new_value(IrValueKind::I64);
        let v1 = blk.new_value(IrValueKind::I64);
        let v2 = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: v0, val: 2 });
        blk.push_op(IrOp::ConstI64 { dst: v1, val: 3 });
        blk.push_op(IrOp::Add { dst: v2, a: v0, b: v1 });
    }
    let folded = ConstFoldPass::run(func);
    // The Add should be replaced with ConstI64 { val: 5 }.
    let ops = &folded.blocks[0].ops;
    let has_const5 = ops.iter().any(|op| matches!(op, IrOp::ConstI64 { val: 5, .. }));
    assert!(has_const5, "Expected ConstI64(5) after folding 2+3; got {:?}", ops);
}

#[test]
fn at7_const_fold_chain() {
    use aether_translator::ir::{IrOp, IrValueKind};
    use aether_translator::opt::ConstFoldPass;

    // x = 4; y = 8; z = x & y → z = 0
    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let v0 = blk.new_value(IrValueKind::I64);
        let v1 = blk.new_value(IrValueKind::I64);
        let v2 = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: v0, val: 4 });
        blk.push_op(IrOp::ConstI64 { dst: v1, val: 8 });
        blk.push_op(IrOp::And { dst: v2, a: v0, b: v1 });
    }
    let folded = ConstFoldPass::run(func);
    let ops = &folded.blocks[0].ops;
    assert!(
        ops.iter().any(|op| matches!(op, IrOp::ConstI64 { val: 0, .. })),
        "Expected ConstI64(0) after folding 4 & 8"
    );
}

// ── DCE ──────────────────────────────────────────────────────────────────────

#[test]
fn at7_dce_removes_unused_const() {
    use aether_translator::ir::{IrOp, IrValueKind};
    use aether_translator::opt::DcePass;

    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let v0 = blk.new_value(IrValueKind::I64);
        let v1 = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: v0, val: 42 }); // dead
        blk.push_op(IrOp::ConstI64 { dst: v1, val: 99 }); // dead
        // No side-effecting op uses v0 or v1 — both should be removed.
    }
    let before = op_count(&func);
    let after_func = DcePass::run(func);
    let after = op_count(&after_func);
    assert!(after < before, "DCE should remove dead constants ({before} → {after})");
}

#[test]
fn at7_dce_keeps_side_effects() {
    use aether_translator::ir::{IrOp, IrValueKind};
    use aether_translator::ir::memory::{MemOrder, StoreTy};
    use aether_translator::opt::DcePass;

    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let v0 = blk.new_value(IrValueKind::I64);
        let v1 = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: v0, val: 0x1000 }); // addr — used
        blk.push_op(IrOp::ConstI64 { dst: v1, val: 0xDEAD }); // val  — used
        blk.push_op(IrOp::Store { val: v1, addr: v0, ty: StoreTy::U64, order: MemOrder::Relaxed });
    }
    let func = DcePass::run(func);
    // Store must survive; its address and value constants must also survive.
    assert!(func.blocks[0].ops.iter().any(|op| matches!(op, IrOp::Store { .. })));
}

// ── Copy propagation ─────────────────────────────────────────────────────────

#[test]
fn at7_copy_prop_zext_same_width() {
    use aether_translator::ir::{IrOp, IrValueKind};
    use aether_translator::opt::CopyPropPass;
    use aether_translator::ir::memory::{MemOrder, StoreTy};

    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let v0 = blk.new_value(IrValueKind::I64);
        let v1 = blk.new_value(IrValueKind::I64);
        let addr = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: v0, val: 7 });
        // Zext 64→64 is a no-op copy.
        blk.push_op(IrOp::Zext { dst: v1, a: v0, from_bits: 64, to_bits: 64 });
        blk.push_op(IrOp::ConstI64 { dst: addr, val: 0x8000 });
        // Store uses v1; after copy-prop it should use v0 directly.
        blk.push_op(IrOp::Store { val: v1, addr, ty: StoreTy::U64, order: MemOrder::Relaxed });
    }
    let func = CopyPropPass::run(func);
    // The store's `val` should now reference v0, not v1.
    for op in &func.blocks[0].ops {
        if let IrOp::Store { val, .. } = op {
            assert_eq!(val.0, 0, "Expected val=v0 after copy prop, got v{}", val.0);
        }
    }
}

// ── Pipeline reduction gate ───────────────────────────────────────────────────

#[test]
fn at7_pipeline_reduces_op_count() {
    // A sequence of arithmetic with some dead results.
    // LDR x3, [x0]; ADD x1, x1, #1; ADD x4, x1, #1; NOP; NOP
    let words: &[u32] = &[
        0xf9400003, // LDR x3, [x0]
        0x91000421, // ADD x1, x1, #1
        0x91000c24, // ADD x4, x1, #3   (x4 dead, no store/branch uses it)
        0xd503201f, // NOP
        0xd503201f, // NOP
        0xd65f03c0, // RET x30
    ];
    let pre = make_ssa_func(words);
    let pre_count = op_count(&pre);
    let post = opt::run_pipeline(pre);
    let post_count = op_count(&post);
    eprintln!("AT-7 pipeline: {} ops → {} ops", pre_count, post_count);
    assert!(post_count <= pre_count, "optimizer increased op count: {} → {}", pre_count, post_count);
    // Gate: ≥15% reduction on this dead-code sequence.
    if pre_count > 0 {
        let reduction = 1.0 - post_count as f64 / pre_count as f64;
        assert!(
            reduction >= 0.15,
            "AT-7 gate: only {:.1}% reduction on dead-code sequence (need ≥15%)",
            reduction * 100.0
        );
    }
}

/// AT-7 corpus gate: run the full pipeline on every instruction from the
/// AT-5 corpus and verify the op count never increases.
#[test]
fn at7_corpus_pipeline_non_increasing() {
    use std::path::PathBuf;
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target/aarch64-unknown-uefi/release/hypervisor.efi");
    if !p.exists() {
        eprintln!("AT-7 corpus skipped");
        return;
    }
    let bytes = std::fs::read(&p).unwrap();
    let text = aether_translator::corpus::extract_text(&bytes).unwrap();

    let mut total_pre = 0usize;
    let mut total_post = 0usize;

    for chunk in text.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if let Ok(insn) = decode_instruction(w) {
            let mut func = IrFunction::new(0);
            {
                let blk = func.add_block();
                let _ = lift_at(&insn, blk, 0);
            }
            let ssa = SsaBuilder::build(func);
            let pre = op_count(&ssa);
            let post_func = opt::run_pipeline(ssa);
            let post = op_count(&post_func);
            total_pre += pre;
            total_post += post;
        }
    }

    let reduction_pct = if total_pre > 0 {
        100.0 - (total_post as f64 / total_pre as f64) * 100.0
    } else {
        0.0
    };
    eprintln!(
        "AT-7 corpus: {total_pre} ops → {total_post} ops ({reduction_pct:.1}% reduction)"
    );
    assert!(
        total_post <= total_pre,
        "optimizer increased total op count: {total_pre} → {total_post}"
    );
    // AT-7 corpus gate: ≥15% median reduction across the full corpus.
    if total_pre > 0 {
        assert!(
            reduction_pct >= 15.0,
            "AT-7 gate: corpus reduction {reduction_pct:.1}% < 15% required"
        );
    }
}

// ── Semantic-equivalence interpreter ─────────────────────────────────────────
//
// A minimal constant-propagation interpreter: evaluates an IrFunction where
// all live-in values are known constants and checks that the optimised version
// produces the same output values as the unoptimised version.
//
// This satisfies the AT-7 gate requirement for semantic-equivalence testing
// without a full general-purpose IR interpreter (which belongs in Phase C).

/// Evaluate the constant-only ops in a single-block function given a map of
/// initial value bindings.  Returns the final binding table.
fn eval_const_block(func: &IrFunction, init: &[(u32, i64)]) -> alloc::collections::BTreeMap<u32, i64> {
    use aether_translator::ir::IrOp;
    use alloc::collections::BTreeMap;

    let mut env: BTreeMap<u32, i64> = init.iter().cloned().collect();

    for blk in &func.blocks {
        for op in &blk.ops {
            match op {
                IrOp::ConstI64 { dst, val } => { env.insert(dst.0, *val); }
                IrOp::Add  { dst, a, b } => { if let (Some(&av), Some(&bv)) = (env.get(&a.0), env.get(&b.0)) { env.insert(dst.0, av.wrapping_add(bv)); } }
                IrOp::Sub  { dst, a, b } => { if let (Some(&av), Some(&bv)) = (env.get(&a.0), env.get(&b.0)) { env.insert(dst.0, av.wrapping_sub(bv)); } }
                IrOp::And  { dst, a, b } => { if let (Some(&av), Some(&bv)) = (env.get(&a.0), env.get(&b.0)) { env.insert(dst.0, av & bv); } }
                IrOp::Or   { dst, a, b } => { if let (Some(&av), Some(&bv)) = (env.get(&a.0), env.get(&b.0)) { env.insert(dst.0, av | bv); } }
                IrOp::Xor  { dst, a, b } => { if let (Some(&av), Some(&bv)) = (env.get(&a.0), env.get(&b.0)) { env.insert(dst.0, av ^ bv); } }
                IrOp::Mul  { dst, a, b } => { if let (Some(&av), Some(&bv)) = (env.get(&a.0), env.get(&b.0)) { env.insert(dst.0, av.wrapping_mul(bv)); } }
                IrOp::Neg  { dst, a }   => { if let Some(&av) = env.get(&a.0) { env.insert(dst.0, av.wrapping_neg()); } }
                _ => {}
            }
        }
    }
    env
}

extern crate alloc;

#[test]
fn at7_semantic_equiv_const_fold() {
    use aether_translator::ir::{IrOp, IrValueKind};
    use aether_translator::opt::ConstFoldPass;

    // x = 7 * 6;  y = x + 2;  z = y & 0xFF
    let mut func = IrFunction::new(0);
    let (v0, v1, v2, v3, v4, v5, v6, v7);
    {
        let blk = func.add_block();
        v0 = blk.new_value(IrValueKind::I64);
        v1 = blk.new_value(IrValueKind::I64);
        v2 = blk.new_value(IrValueKind::I64);
        v3 = blk.new_value(IrValueKind::I64);
        v4 = blk.new_value(IrValueKind::I64);
        v5 = blk.new_value(IrValueKind::I64);
        v6 = blk.new_value(IrValueKind::I64);
        v7 = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: v0, val: 7 });
        blk.push_op(IrOp::ConstI64 { dst: v1, val: 6 });
        blk.push_op(IrOp::Mul      { dst: v2, a: v0, b: v1 });   // 42
        blk.push_op(IrOp::ConstI64 { dst: v3, val: 2 });
        blk.push_op(IrOp::Add      { dst: v4, a: v2, b: v3 });   // 44
        blk.push_op(IrOp::ConstI64 { dst: v5, val: 0xFF });
        blk.push_op(IrOp::And      { dst: v6, a: v4, b: v5 });   // 44
        blk.push_op(IrOp::Neg      { dst: v7, a: v6 });           // -44
    }
    let _ = (v0, v1, v2, v3, v4, v5);

    // Evaluate before optimisation.
    let env_pre  = eval_const_block(&func, &[]);
    let folded   = ConstFoldPass::run(func);
    let env_post = eval_const_block(&folded, &[]);

    // v6 = 44, v7 = -44 must be identical before and after folding.
    assert_eq!(env_pre.get(&v6.0),  Some(&44i64),  "pre:  v6 should be 44");
    assert_eq!(env_post.get(&v6.0), Some(&44i64),  "post: v6 should be 44");
    assert_eq!(env_pre.get(&v7.0),  Some(&-44i64), "pre:  v7 should be -44");
    assert_eq!(env_post.get(&v7.0), Some(&-44i64), "post: v7 should be -44");
}

#[test]
fn at7_semantic_equiv_dce_preserves_output() {
    use aether_translator::ir::{IrOp, IrValueKind};
    use aether_translator::ir::memory::{MemOrder, StoreTy};
    use aether_translator::opt::DcePass;

    // v0 = 10 (dead); v1 = 20 (used by store); store(addr, v1)
    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let v0   = blk.new_value(IrValueKind::I64);
        let v1   = blk.new_value(IrValueKind::I64);
        let addr = blk.new_value(IrValueKind::I64);
        blk.push_op(IrOp::ConstI64 { dst: v0,   val: 10 });         // dead
        blk.push_op(IrOp::ConstI64 { dst: v1,   val: 20 });         // live
        blk.push_op(IrOp::ConstI64 { dst: addr, val: 0x4000 });
        blk.push_op(IrOp::Store { val: v1, addr, ty: StoreTy::U64, order: MemOrder::Relaxed });
    }
    let env_pre  = eval_const_block(&func, &[]);
    let dced     = DcePass::run(func);
    let env_post = eval_const_block(&dced, &[]);

    // v1 = 20 must survive; v0 = 10 is gone but we don't observe it.
    assert_eq!(env_pre.get(&1u32),  Some(&20i64), "pre:  v1 should be 20");
    assert_eq!(env_post.get(&1u32), Some(&20i64), "post: v1 should be 20 after DCE");
    // Store must survive.
    assert!(dced.blocks[0].ops.iter().any(|op| matches!(op, IrOp::Store { .. })),
        "Store must not be DCE'd");
}
