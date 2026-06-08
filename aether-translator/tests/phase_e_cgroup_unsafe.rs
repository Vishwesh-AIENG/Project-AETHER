//! Phase-E: translate the cgroup_disable+0x48 block on host and check for
//! the UD2 (0F 0B) byte pair that flips the runtime safety gate.

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

#[test]
fn cgroup_disable_block_no_ud2() {
    // The 16-instruction block from cgroup_disable+0x48 (PC 0xffffffc0099f6304):
    //   mov x23, x0
    //   adrp x19, .. ; add x19, x19, #0x6c6
    //   adrp x24, .. ; add x24, x24, #0xcc8
    //   adrp x25, .. ; add x25, x25, #0x9e0
    //   adrp x20, .. ; add x20, x20, #0xb0f
    //   mov w27, #1
    //   adrp x21, .. ; add x21, x21, #0xa92
    //   adrp x22, .. ; add x22, x22, #0x342
    //   ldrb w8, [x23]
    //   cbz w8, ..
    let words = [
        0xaa0003f7, // mov x23, x0
        0xf0ffd293, 0x911b1a73, // adrp x19; add x19, x19, #0x6c6
        0xd00024_58u32.swap_bytes() & 0, // placeholder
    ];
    // Use the exact bytes from the Image.
    let words = [
        0xaa0003f7u32, // mov x23, x0
        0xf0ffd293u32, 0x911b1a73u32, // adrp x19,..; add x19, x19, #0x6c6
        0xd0002458u32, 0x913323_18u32, // adrp x24,..; add x24, x24, #0xcc8
        0xd0ffaed9u32, 0x91278339u32, // adrp x25,..; add x25, x25, #0x9e0
        0xd0ffcd74u32, 0x912c3e_94u32, // adrp x20,..; add x20, x20, #0xb0f
        0x5280003bu32, // mov w27, #1
        0xd0ffcf95u32, 0x912a4ab5u32, // adrp x21,..; add x21, x21, #0xa92
        0xd0fff0f6u32, 0x910d_0ad6u32, // adrp x22,..; add x22, x22, #0x342
        0x394002e8u32, // ldrb w8, [x23]
        0x34000328u32, // cbz w8, ..
    ];
    let code = translate(&words, 0xffffffc0099f6304);
    // Phase-E fix verification: block_bytes_are_safe now scans for the
    // full 6-byte UD2 sentinel `0F 1F 40 00 0F 0B` (a 4-byte NOP prefix +
    // UD2), so an incidental `0F 0B` pair inside a `mov r/m64, imm32`
    // immediate (here: imm32 = 0x0000_0B0F from `add x20, x20, #0xB0F`)
    // no longer false-positives.
    use aether_translator::dbt::block_bytes_are_safe;
    assert!(
        block_bytes_are_safe(&code),
        "cgroup_disable+0x48 block must NOT trip the safety gate; the \
         regression injected an Unknown EC undef after the RBIT/UMULH \
         bring-up fixes (because the imm32 0x0000_0B0F spelled 0F 0B).",
    );
    assert_eq!(*code.last().unwrap(), 0xC3, "block must end in RET");
    // Plain-pair sanity: confirm the FALSE-positive bytes really were
    // present (otherwise the test would pass for the wrong reason).
    assert!(
        code.windows(2).any(|w| w == [0x0F, 0x0B]),
        "test must reproduce the original 0F 0B-inside-imm32 byte sequence",
    );
}
