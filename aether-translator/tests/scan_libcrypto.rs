//! Offline DBT-coverage scan of bionic's libcrypto.so .text. Runs every 4-byte
//! word through decode -> lift -> IntLower::lower_block and reports the encodings
//! that decode-fail or lower to UD2 — i.e. every instruction gap the BoringSSL
//! crypto self-test (and later real crypto) can hit, found in ONE pass instead
//! of boot-by-boot. Ignored by default (needs the extracted file); run with:
//!   cargo test -p aether-translator --test scan_libcrypto -- --ignored --nocapture
#![cfg(all(test, target_arch = "x86_64"))]

use aether_translator::backend::{IntLower, X86Encoder};
use aether_translator::decoder::decode_instruction;
use aether_translator::ir::{BlockId, IrBlock};
use aether_translator::lift::lift;
use aether_translator::regalloc::linear_scan::{AllocResult, AssignMap};
use std::collections::BTreeMap;

fn empty_alloc() -> AllocResult {
    AllocResult { assignments: AssignMap::new(), n_spill_slots: 0, n_intervals: 0, n_spilled: 0 }
}

fn rd_u16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn rd_u32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) }
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([b[o], b[o+1], b[o+2], b[o+3], b[o+4], b[o+5], b[o+6], b[o+7]])
}

/// Classify one word: 0=ok, 1=decode-fail, 2=lift-fail, 3=UD2, 4=panic.
fn classify(w: u32) -> u8 {
    let insn = match decode_instruction(w) { Ok(i) => i, Err(_) => return 1 };
    // lift + lower can panic on data-as-instruction words (debug assertions);
    // treat that as a coverage signal too, not a test abort.
    std::panic::catch_unwind(|| {
        let mut blk = IrBlock::new(BlockId(0));
        if lift(&insn, &mut blk).is_err() { return 2u8; }
        let alloc = empty_alloc();
        let mut enc = X86Encoder::new();
        let mut patches: Vec<(usize, BlockId)> = Vec::new();
        IntLower::lower_block(&blk, &alloc, &mut enc, &mut patches);
        if enc.finish().windows(2).any(|x| x == [0x0F, 0x0B]) { 3 } else { 0 }
    })
    .unwrap_or(4)
}

#[test]
#[ignore]
fn scan() {
    let path = "qemu/_libcrypto.so";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => match std::fs::read(format!("../{}", path)) {
            Ok(d) => d,
            Err(e) => { println!("cannot read {}: {} (run from repo root)", path, e); return; }
        },
    };
    std::panic::set_hook(Box::new(|_| {})); // silence per-word panic spam
    assert_eq!(&data[0..4], b"\x7fELF", "not an ELF");
    let shoff = rd_u64(&data, 0x28) as usize;
    let shentsize = rd_u16(&data, 0x3a) as usize;
    let shnum = rd_u16(&data, 0x3c) as usize;

    // Per unsupported word: (kind, count, first VA).
    let mut bad: BTreeMap<u32, (u8, u64, u64)> = BTreeMap::new();
    let mut scanned = 0usize;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let sh_type = rd_u32(&data, sh + 4);
        let sh_flags = rd_u64(&data, sh + 8);
        let sh_addr = rd_u64(&data, sh + 0x10);
        let sh_off = rd_u64(&data, sh + 0x18) as usize;
        let sh_size = rd_u64(&data, sh + 0x20) as usize;
        // PROGBITS (1) + SHF_EXECINSTR (0x4).
        if sh_type != 1 || sh_flags & 0x4 == 0 { continue; }
        let mut o = 0;
        while o + 4 <= sh_size && sh_off + o + 4 <= data.len() {
            let w = rd_u32(&data, sh_off + o);
            scanned += 1;
            let k = classify(w);
            if k != 0 {
                let va = sh_addr + o as u64;
                bad.entry(w).and_modify(|e| e.1 += 1).or_insert((k, 1, va));
            }
            o += 4;
        }
    }
    // Sort by descending count (frequent = likely hot real code).
    let mut v: Vec<_> = bad.into_iter().collect();
    v.sort_by(|a, b| b.1.1.cmp(&a.1.1));
    println!("scanned {} insns; {} distinct unsupported encodings", scanned, v.len());
    let kname = |k: u8| match k { 1 => "decode", 2 => "lift", 3 => "UD2", 4 => "panic", _ => "?" };
    println!("{:>6} {:>8}  {:<10} {}", "count", "word", "kind", "example_va");
    for (w, (k, c, va)) in v.iter().take(80) {
        println!("{:>6} {:#010x}  {:<10} {:#012x}", c, w, kname(*k), va);
    }
    // The executed AES-GCM/GHASH self-test region (the boot keeps hitting it):
    // dump every gap whose example_va lands there, sorted by VA (execution order).
    println!("--- crypto-region gaps (va in [0xd0000,0xe8000)) ---");
    let mut region: Vec<_> = v.iter()
        .filter(|(_, (_, _, va))| (0xd0000..0xe8000).contains(va))
        .collect();
    region.sort_by_key(|(_, (_, _, va))| *va);
    for (w, (k, c, va)) in region {
        println!("  {:#012x}  {:#010x}  {:<8} x{}", va, w, kname(*k), c);
    }
}
