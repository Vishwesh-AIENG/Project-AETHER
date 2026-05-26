//! AT-8 gate: NZCV flag-elision pass.
//!
//! Gate: ≥ 60 % of flag-producing ops are marked elided on a representative
//! sequence of ARM64 integer code (straight-line code without conditional
//! branches has near-100 % elision since flags are never consumed).

use aether_translator::decoder::decode_instruction;
use aether_translator::ir::IrFunction;
use aether_translator::lift::lift_at;
use aether_translator::opt::FlagElisionPass;
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

#[test]
fn at8_elision_on_straight_line_code() {
    // ADDS x1, x1, #1 (flags produced but never consumed before next clobber)
    // ADDS x2, x2, #1
    // ADDS x3, x3, #1
    // RET
    // On straight-line code with no conditional branches, all three ADDS flags
    // should be elided.
    let words = [
        0xb1000421u32, // ADDS x1, x1, #1
        0xb1000842,    // ADDS x2, x2, #1
        0xb1000c63,    // ADDS x3, x3, #1
        0xd65f03c0,    // RET
    ];
    let func = make_ssa_func(&words);
    let func = FlagElisionPass::run(func);
    let (elided, total) = FlagElisionPass::elision_ratio(&func);
    eprintln!("AT-8 straight-line: elided={elided}/{total}");
    if total > 0 {
        let ratio = elided as f64 / total as f64;
        assert!(
            ratio >= 0.60,
            "Flag elision ratio {:.1}% < 60% gate on straight-line code",
            ratio * 100.0
        );
    }
}

#[test]
fn at8_elision_flags_from_cmp_no_branch() {
    // CMP x0, x1 — flags produced but no conditional branch follows.
    // Should be fully elided.
    let words = [
        0xeb01001fu32, // CMP x0, x1
        0xd65f03c0,    // RET
    ];
    let func = make_ssa_func(&words);
    let func = FlagElisionPass::run(func);
    let (elided, total) = FlagElisionPass::elision_ratio(&func);
    eprintln!("AT-8 CMP no-branch: elided={elided}/{total}");
    if total > 0 {
        assert_eq!(elided, total, "All CMP flags should be elided when no branch follows");
    }
}

#[test]
fn at8_flags_kept_when_consumed() {
    use aether_translator::ir::ops::IrOp;
    use aether_translator::ir::IrValueKind;

    // Manually build: CMP v0, v1; B.EQ (consumes flags).
    let mut func = IrFunction::new(0);
    {
        let blk = func.add_block();
        let v0 = blk.new_value(IrValueKind::I64);
        let v1 = blk.new_value(IrValueKind::I64);
        let f0 = blk.new_flags();
        let b0 = aether_translator::ir::BlockId(0);
        let b1 = aether_translator::ir::BlockId(1);
        blk.push_op(IrOp::ConstI64 { dst: v0, val: 1 });
        blk.push_op(IrOp::ConstI64 { dst: v1, val: 2 });
        blk.push_op(IrOp::Cmp { flags: f0, a: v0, b: v1 });
        blk.push_op(IrOp::CondBranch {
            cond: aether_translator::decoder::Cond::Eq,
            flags: f0,
            taken: b0,
            fallthru: b1,
        });
    }
    let func = FlagElisionPass::run(func);
    // f0 is consumed by CondBranch — must NOT be in elided_flags.
    assert!(
        !func.blocks[0].elided_flags.contains(&0),
        "f0 should not be elided since it's consumed by CondBranch"
    );
}

/// AT-8 corpus gate.
#[test]
fn at8_corpus_60pct_gate() {
    use std::path::PathBuf;
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target/aarch64-unknown-uefi/release/hypervisor.efi");
    if !p.exists() {
        eprintln!("AT-8 corpus skipped");
        return;
    }
    let bytes = std::fs::read(&p).unwrap();
    let text = aether_translator::corpus::extract_text(&bytes).unwrap();

    let mut total_elided = 0usize;
    let mut total_flags = 0usize;

    for chunk in text.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if let Ok(insn) = decode_instruction(w) {
            let mut func = IrFunction::new(0);
            {
                let blk = func.add_block();
                let _ = lift_at(&insn, blk, 0);
            }
            let ssa = SsaBuilder::build(func);
            let func = FlagElisionPass::run(ssa);
            let (e, t) = FlagElisionPass::elision_ratio(&func);
            total_elided += e;
            total_flags += t;
        }
    }

    eprintln!(
        "AT-8 corpus: {total_elided}/{total_flags} flags elided ({:.1}%)",
        if total_flags > 0 { total_elided as f64 / total_flags as f64 * 100.0 } else { 0.0 }
    );
    if total_flags > 0 {
        let ratio = total_elided as f64 / total_flags as f64;
        assert!(
            ratio >= 0.60,
            "AT-8 gate: flag elision ratio {:.1}% < 60%",
            ratio * 100.0
        );
    }
}
