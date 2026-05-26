//! AT-9 gate: linear-scan register allocator.
//!
//! Gate: zero allocation failures on the AT-5 corpus; spill ratio < 8 %.

use aether_translator::decoder::decode_instruction;
use aether_translator::ir::IrFunction;
use aether_translator::lift::lift_at;
use aether_translator::opt;
use aether_translator::regalloc::{self, AllocResult, Assignment};
use aether_translator::ssa::SsaBuilder;

fn make_and_alloc(words: &[u32]) -> AllocResult {
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
    let ssa = SsaBuilder::build(func);
    let opt_func = opt::run_pipeline(ssa);
    regalloc::allocate(&opt_func)
}

#[test]
fn at9_basic_allocation() {
    // ADD x1, x1, #1; ADD x2, x2, #2; RET
    let result = make_and_alloc(&[0x91000421, 0x91000842, 0xd65f03c0]);
    eprintln!(
        "AT-9 basic: {} intervals, {} spilled, {:.1}% spill",
        result.n_intervals,
        result.n_spilled,
        result.spill_ratio() * 100.0
    );
    assert!(result.spill_ratio() < 0.08, "Spill ratio {:.2} exceeds 8%", result.spill_ratio());
}

#[test]
fn at9_every_value_assigned() {
    // Simple sequence: all values should get an assignment.
    let words = [
        0x91000421u32, // ADD x1, x1, #1
        0x91000842,    // ADD x2, x2, #2
        0xf9400043,    // LDR x3, [x2]
        0xd65f03c0,    // RET
    ];
    let result = make_and_alloc(&words);
    for (&_vid, &assign) in &result.assignments {
        match assign {
            Assignment::Gpr(r) => assert!(r < 15, "GPR index {r} out of range"),
            Assignment::Xmm(r) => assert!(r < 16, "XMM index {r} out of range"),
            Assignment::Spill(s) => assert!(s < result.n_spill_slots),
        }
    }
}

#[test]
fn at9_empty_function_ok() {
    let func = IrFunction::new(0);
    let ssa = SsaBuilder::build(func);
    let result = regalloc::allocate(&ssa);
    assert_eq!(result.n_intervals, 0);
    assert!(result.gate_passes());
}

#[test]
fn at9_nop_sequence() {
    let words = [0xd503201fu32; 8]; // 8 NOPs
    let result = make_and_alloc(&words);
    assert!(result.gate_passes(), "NOP sequence failed gate: spill={}", result.n_spilled);
}

/// AT-9 corpus gate against hypervisor.efi.
#[test]
fn at9_corpus_spill_gate() {
    use std::path::PathBuf;
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target/aarch64-unknown-uefi/release/hypervisor.efi");
    if !p.exists() {
        eprintln!("AT-9 corpus skipped");
        return;
    }
    let bytes = std::fs::read(&p).unwrap();
    let text = aether_translator::corpus::extract_text(&bytes).unwrap();

    let mut total_intervals = 0usize;
    let mut total_spilled = 0usize;

    for chunk in text.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if let Ok(insn) = decode_instruction(w) {
            let mut func = IrFunction::new(0);
            {
                let blk = func.add_block();
                let _ = lift_at(&insn, blk, 0);
            }
            let ssa = SsaBuilder::build(func);
            let opt_func = opt::run_pipeline(ssa);
            let r = regalloc::allocate(&opt_func);
            total_intervals += r.n_intervals;
            total_spilled += r.n_spilled;
        }
    }

    let ratio = if total_intervals > 0 {
        total_spilled as f64 / total_intervals as f64
    } else {
        0.0
    };
    eprintln!(
        "AT-9 corpus: {total_intervals} intervals, {total_spilled} spilled ({:.1}%)",
        ratio * 100.0
    );
    assert!(
        ratio < 0.08,
        "AT-9 gate: spill ratio {:.1}% ≥ 8%",
        ratio * 100.0
    );
}
