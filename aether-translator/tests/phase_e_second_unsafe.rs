//! Phase-E: second UNSAFE block at PC 0xffffffc008f6251c (after pcpu+cgroup
//! bring-up fixes). Reproduce and identify what's emitting UD2.

#![cfg(all(test, target_arch = "x86_64", windows))]

use std::collections::BTreeMap;
use aether_translator::backend::{IntLower, X86Encoder};
use aether_translator::decoder::decode_instruction;
use aether_translator::ir::IrFunction;
use aether_translator::lift::lift_at;
use aether_translator::regalloc;

fn translate(words: &[u32], pc: u64) -> Vec<u8> {
    let mut func = IrFunction::new(pc);
    {
        let block = func.add_block();
        let mut cur = pc;
        for &w in words {
            let insn = decode_instruction(w).expect("decode");
            lift_at(&insn, block, cur).expect("lift");
            cur += 4;
        }
    }
    let alloc = regalloc::allocate(&func);
    let mut enc = X86Encoder::new();
    let mut patches: BTreeMap<usize, aether_translator::ir::BlockId> = BTreeMap::new();
    for blk in &func.blocks {
        IntLower::lower_block_with_pc(blk, pc, &alloc, &mut enc, &mut patches);
    }
    enc.emit_ret();
    enc.finish()
}

/// Same as second_unsafe_block_no_ud2 but goes through the PUBLIC API
/// (opt::run_pipeline runs between lift and lower in that path).
#[test]
fn second_unsafe_block_no_ud2_public_api() {
    use aether_translator::dbt::{
        aether_dbt_block_host_va, aether_dbt_init, aether_dbt_translate_block,
        block_bytes_are_safe, AetherDbtResult,
    };
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = LOCK.lock().unwrap();
    let _ = aether_dbt_init(0, 16 * 1024 * 1024, 0, 1024 * 1024);

    let pc: u64 = 0x6010;
    let insn_words: [u32; 8] = [
        0xd503233fu32, 0xa9be7bfdu32, 0xf9000bf3u32, 0x910003fdu32,
        0xd53b4233u32, 0xaa0003e8u32, 0x12190269u32, 0x35000089u32,
    ];
    // translate_block reads guest_mem from offset 0; `pc` is just the
    // cache key. So put the bytes at offset 0.
    let mut mem = Vec::with_capacity(32);
    for w in insn_words.iter() {
        mem.extend_from_slice(&w.to_le_bytes());
    }
    let r = aether_dbt_translate_block(pc, &mem);
    assert_eq!(r, AetherDbtResult::Ok, "translate must succeed");
    let (host_va, len) = aether_dbt_block_host_va(pc).expect("must resolve");
    let code: Vec<u8> = unsafe {
        core::slice::from_raw_parts(host_va as *const u8, len).to_vec()
    };
    let bytes_hex: String = code.iter().map(|b| format!("{:02X} ", b)).collect();
    println!("public-api emitted bytes ({}): {}", code.len(), bytes_hex);
    const UD2_SENTINEL: [u8; 6] = [0x0F, 0x1F, 0x40, 0x00, 0x0F, 0x0B];
    let ud2_at: Vec<_> = code
        .windows(6)
        .enumerate()
        .filter_map(|(i, w)| if w == UD2_SENTINEL { Some(i) } else { None })
        .collect();
    assert!(
        ud2_at.is_empty(),
        "public-API translation emitted UD2 at offsets {:?}\n  bytes: {}",
        ud2_at, bytes_hex
    );
    assert!(block_bytes_are_safe(&code), "block must pass safety gate via public API");
}

#[test]
fn second_unsafe_block_no_ud2() {
    // Block at 0xffffffc008f6251c (suspected: jiffies_lock or similar entry):
    //   paciasp
    //   stp x29, x30, [sp, #-0x20]!
    //   str x19, [sp, #0x10]
    //   mov x29, sp
    //   mrs x19, daif
    //   mov x8, x0
    //   and w9, w19, #0x80
    //   cbnz w9, ..        <-- terminator
    let words = [
        0xd503233fu32, // paciasp
        0xa9be7bfdu32, // stp x29, x30, [sp, #-0x20]!
        0xf9000bf3u32, // str x19, [sp, #0x10]
        0x910003fdu32, // mov x29, sp
        0xd53b4233u32, // mrs x19, daif
        0xaa0003e8u32, // mov x8, x0
        0x12190269u32, // and w9, w19, #0x80
        0x35000089u32, // cbnz w9, +0x10
    ];
    let code = translate(&words, 0xffffffc008f6251c);
    let bytes_hex: String = code.iter().map(|b| format!("{:02X} ", b)).collect();
    println!("emitted bytes ({}): {}", code.len(), bytes_hex);
    // Look for the UD2 sentinel.
    const UD2_SENTINEL: [u8; 6] = [0x0F, 0x1F, 0x40, 0x00, 0x0F, 0x0B];
    let ud2_at: Vec<_> = code
        .windows(6)
        .enumerate()
        .filter_map(|(i, w)| if w == UD2_SENTINEL { Some(i) } else { None })
        .collect();
    assert!(
        ud2_at.is_empty(),
        "block emitted UD2 sentinel at byte offsets {:?}\n  full bytes: {}",
        ud2_at, bytes_hex
    );
    use aether_translator::dbt::block_bytes_are_safe;
    assert!(block_bytes_are_safe(&code), "block must pass safety gate");
}
