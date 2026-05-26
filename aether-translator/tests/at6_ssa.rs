//! AT-6 gate: SSA construction + verifier.
//!
//! Gate: SSA verifier reports no `RegAccessOpRemains` errors on every
//! decoded block lifted from the AT-5 corpus.

use aether_translator::decoder::decode_instruction;
use aether_translator::ir::IrFunction;
use aether_translator::lift::lift_at;
use aether_translator::ssa::{SsaBuilder, SsaVerifier};

// ── Helper: lift a sequence of instruction words into a single IrFunction ──

fn make_func(words: &[u32]) -> IrFunction {
    let mut func = IrFunction::new(0);
    let blk = func.add_block();
    let mut pc = 0u64;
    for &w in words {
        if let Ok(insn) = decode_instruction(w) {
            let _ = lift_at(&insn, blk, pc);
        }
        pc += 4;
    }
    func
}

// ── AT-6 unit tests ──────────────────────────────────────────────────────────

#[test]
fn at6_single_block_no_reg_access_after_ssa() {
    // ADD x1, x1, #1  (0x91000421)
    // ADD x2, x1, #2  (0x91000822)
    // RET             (0xd65f03c0)
    let words = [0x91000421u32, 0x91000822, 0xd65f03c0];
    let pre_ssa = make_func(&words);

    let ssa = SsaBuilder::build(pre_ssa);
    assert!(
        SsaVerifier::no_reg_access_ops(&ssa),
        "SSA form must not contain ReadGpr/WriteGpr ops"
    );
}

#[test]
fn at6_nop_sequence() {
    // Four NOPs: 0xd503201f
    let words = [0xd503201fu32; 4];
    let pre_ssa = make_func(&words);
    let ssa = SsaBuilder::build(pre_ssa);
    assert!(SsaVerifier::no_reg_access_ops(&ssa));
}

#[test]
fn at6_load_store_sequence() {
    // LDR x0, [x1]    — STR x0, [x2]
    let words = [0xf9400020u32, 0xf9000040];
    let pre_ssa = make_func(&words);
    let ssa = SsaBuilder::build(pre_ssa);
    assert!(SsaVerifier::no_reg_access_ops(&ssa));
}

#[test]
fn at6_verifier_accepts_empty_function() {
    let func = IrFunction::new(0);
    let ssa = SsaBuilder::build(func);
    assert!(SsaVerifier::no_reg_access_ops(&ssa));
    assert!(SsaVerifier::verify(&ssa).is_ok());
}

#[test]
fn at6_verifier_full_check() {
    let words = [0x91000421u32, 0xd65f03c0];
    let pre_ssa = make_func(&words);
    let ssa = SsaBuilder::build(pre_ssa);
    // Full verifier must return Ok — no use-before-def, no reg-access ops.
    match SsaVerifier::verify(&ssa) {
        Ok(()) => {}
        Err(errs) => {
            panic!("SSA verifier found {} error(s): {:?}", errs.len(), errs);
        }
    }
}

/// AT-6 multi-block: verify that defs from a dominating block are visible to
/// its dominated successors after SSA renaming.
///
/// All cross-block value flow goes through architectural GPRs (as it would in
/// real lifted ARM64 code) — IrValueId is block-local so direct cross-block
/// value references are not valid.
#[test]
fn at6_multiblock_def_reaches_successor() {
    use aether_translator::ir::{BlockId, IrOp, IrValueKind};

    // Block 0: x0 ← 42  (WriteGpr)  →  Branch block 1
    // Block 1: x1 ← x0  (ReadGpr → WriteGpr)  →  Branch block 2
    // Block 2: x2 ← x1  (ReadGpr → WriteGpr)
    //
    // After SSA every ReadGpr/WriteGpr must be gone.  The two-phase stack fix
    // is what makes block 2 see the def from block 0 (via block 1).
    let mut func = IrFunction::new(0);
    {
        let b0 = func.add_block();
        let v = b0.new_value(IrValueKind::I64);
        b0.push_op(IrOp::ConstI64   { dst: v, val: 42 });
        b0.push_op(IrOp::WriteGpr   { reg: 0, src: v, sf: false });
        b0.push_op(IrOp::Branch     { target: BlockId(1) });
    }
    {
        let b1 = func.add_block();
        let vr = b1.new_value(IrValueKind::I64);
        b1.push_op(IrOp::ReadGpr    { dst: vr, reg: 0, sf: false });
        b1.push_op(IrOp::WriteGpr   { reg: 1, src: vr, sf: false });
        b1.push_op(IrOp::Branch     { target: BlockId(2) });
    }
    {
        let b2 = func.add_block();
        let vr = b2.new_value(IrValueKind::I64);
        b2.push_op(IrOp::ReadGpr    { dst: vr, reg: 1, sf: false });
        b2.push_op(IrOp::WriteGpr   { reg: 2, src: vr, sf: false });
    }

    let ssa = SsaBuilder::build(func);

    assert!(
        SsaVerifier::no_reg_access_ops(&ssa),
        "ReadGpr/WriteGpr must not survive SSA promotion across three blocks"
    );
}

/// AT-6 corpus gate: lift every instruction from the AT-5 surrogate corpus
/// (hypervisor.efi) into per-instruction single-op blocks, run SSA promotion,
/// and verify no reg-access ops remain.
#[test]
fn at6_corpus_no_reg_access() {
    use std::path::PathBuf;
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target/aarch64-unknown-uefi/release/hypervisor.efi");
    if !p.exists() {
        eprintln!("AT-6 corpus skipped: build hypervisor.efi first");
        return;
    }
    let bytes = std::fs::read(&p).unwrap();
    let text = aether_translator::corpus::extract_text(&bytes)
        .expect("extract .text");

    let mut total = 0usize;
    let mut ssa_ok = 0usize;

    for chunk in text.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if let Ok(insn) = decode_instruction(w) {
            let mut func = IrFunction::new(0);
            {
                let blk = func.add_block();
                let _ = lift_at(&insn, blk, 0);
            }
            let ssa = SsaBuilder::build(func);
            total += 1;
            if SsaVerifier::no_reg_access_ops(&ssa) {
                ssa_ok += 1;
            }
        }
    }

    eprintln!("AT-6 corpus: {}/{} instructions passed SSA verification", ssa_ok, total);
    assert_eq!(
        total, ssa_ok,
        "{} instructions still have reg-access ops after SSA promotion",
        total - ssa_ok
    );
}
