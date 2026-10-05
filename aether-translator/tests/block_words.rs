//! Pinpoint UD2/decode-fail gaps for an arbitrary ARM64 block. Reads a
//! comma-separated hex word list from qemu/_block_words.txt and runs each
//! through the live decode->lift->lower pipeline. Run:
//!   cargo test -p aether-translator --test block_words -- --ignored --nocapture
#![cfg(all(test, target_arch = "x86_64"))]

use aether_translator::backend::{IntLower, X86Encoder};
use aether_translator::decoder::decode_instruction;
use aether_translator::ir::{BlockId, IrBlock};
use aether_translator::lift::lift;
use aether_translator::regalloc::linear_scan::{AllocResult, AssignMap};

fn empty_alloc() -> AllocResult {
    AllocResult { assignments: AssignMap::new(), n_spill_slots: 0, n_intervals: 0, n_spilled: 0 }
}

#[test]
#[ignore]
fn scan_block() {
    std::panic::set_hook(Box::new(|_| {}));
    let txt = std::fs::read_to_string("qemu/_block_words.txt")
        .or_else(|_| std::fs::read_to_string("../qemu/_block_words.txt"))
        .expect("qemu/_block_words.txt");
    let words: Vec<u32> = txt.trim().split(',')
        .filter_map(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .collect();
    println!("scanning {} words", words.len());
    for w in words {
        let r = std::panic::catch_unwind(|| {
            let insn = match decode_instruction(w) { Ok(i) => i, Err(e) => return format!("DECODE-FAIL {:?}", e) };
            let mut blk = IrBlock::new(BlockId(0));
            if lift(&insn, &mut blk).is_err() { return format!("LIFT-FAIL {:?}", insn); }
            let mut enc = X86Encoder::new();
            let mut p: Vec<(usize, BlockId)> = Vec::new();
            IntLower::lower_block(&blk, &empty_alloc(), &mut enc, &mut p);
            let ud2 = enc.finish().windows(2).any(|x| x == [0x0F, 0x0B]);
            format!("{} insn={:?} ops={:?}", if ud2 { "UD2!" } else { "ok " }, insn, blk.ops)
        }).unwrap_or_else(|_| "PANIC(alloc?)".into());
        println!("  {:#010x}  {}", w, r);
    }
}
