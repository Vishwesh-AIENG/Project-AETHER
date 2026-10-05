//! Pin which instructions in bionic's BoringSSL crypto blocks (hit by init's
//! self-test on the WHPX boot) lower to UD2. Runs each word through the REAL
//! live pipeline: decode -> lift -> IntLower::lower_block (delegates SIMD/crypto
//! to lower_simd_ctx). A UD2 == an uncovered op == a SIGILL that kills init.

use aether_translator::backend::{IntLower, X86Encoder};
use aether_translator::decoder::decode_instruction;
use aether_translator::ir::{BlockId, IrBlock};
use aether_translator::lift::lift;
use aether_translator::regalloc::linear_scan::{AllocResult, AssignMap};

fn empty_alloc() -> AllocResult {
    AllocResult { assignments: AssignMap::new(), n_spill_slots: 0, n_intervals: 0, n_spilled: 0 }
}

fn lowers_to_ud2(w: u32) -> (bool, String, String) {
    let insn = match decode_instruction(w) {
        Ok(i) => i,
        Err(e) => return (true, format!("DECODE-FAIL {:?}", e), String::new()),
    };
    let mut blk = IrBlock::new(BlockId(0));
    if let Err(e) = lift(&insn, &mut blk) {
        return (true, format!("LIFT-FAIL {:?}", e), format!("{:?}", insn));
    }
    let alloc = empty_alloc();
    let mut enc = X86Encoder::new();
    let mut patches: Vec<(usize, BlockId)> = Vec::new();
    IntLower::lower_block(&blk, &alloc, &mut enc, &mut patches);
    let bytes = enc.finish();
    let ud2 = bytes.windows(2).any(|x| x == [0x0F, 0x0B]);
    (ud2, format!("{:?}", insn), format!("{:?}", blk.ops))
}

fn check_block(name: &str, words: &[(u32, &str)]) -> Vec<String> {
    println!("=== {} ===", name);
    let mut bad = Vec::new();
    for &(w, dis) in words {
        let (ud2, insn, ops) = lowers_to_ud2(w);
        println!("  {:#010x} {:30} {} insn={} ops={}", w, dis,
            if ud2 { "UD2!!!" } else { "ok" }, insn, ops);
        if ud2 { bad.push(format!("{} ({:#010x})", dis, w)); }
    }
    bad
}

#[test]
fn aes_ctr_drbg_block_no_ud2() {
    // /init 0x7fb84d9ce0 — AES-CTR-DRBG (fixed: TBL, AESE, SHL).
    let bad = check_block("AES-CTR-DRBG @ 0x7fb84d9ce0", &[
        (0x4e020066, "tbl  v6.16b,{v3.16b},v2.16b"),
        (0x6e036005, "ext  v5.16b,v0.16b,v3.16b,#12"),
        (0x4e284806, "aese v6.16b,v0.16b"),
        (0x4f095421, "shl  v1.16b,v1.16b,#1"),
    ]);
    assert!(bad.is_empty(), "AES-CTR-DRBG UD2: {:?}", bad);
}

#[test]
fn aes_ctr_block_no_ud2() {
    // /init 0x7fb84da770 — full AES-GCM-CTR loop body (70 insns from libcrypto.so).
    // The 24-word boot dump truncated before the real gaps (TRN1/TRN2, REV64.16b).
    let words: &[u32] = &[
        0x4e284a62,0x4e286842,0x3dc01116,0x4e284a81,0x4e286821,0x3dc008cd,0x6e0d41ad,
        0x4e284a63,0x4e286863,0x3dc0311e,0x4e284a82,0x4e286842,0x3dc014cf,0x6e0f41ef,
        0x4e284aa1,0x4e286821,0x3dc02d1d,0x4e284a83,0x4e286863,0x3dc0211a,0x4e284aa2,
        0x4e286842,0x1100058c,0x4e284aa0,0x4e286800,0x4e284aa3,0x4e286863,0x4c40706b,
        0x6e0b416b,0x4e20096b,0x4e284ac2,0x4e286842,0x4e284ac0,0x4e286800,0x4e284ac1,
        0x4e286821,0x4e284ac3,0x4e286863,0xf100323f,0x4e284ae0,0x4e286800,0x4e284ae1,
        0x4e286821,0x4e284ae3,0x4e286863,0x4e284ae2,0x4e286842,0x4e284b01,0x4e286821,
        0x4ecf69d1,0x4e284b03,0x4e286863,0x3dc0251b,0x4e284b00,0x4e286800,0x3dc000cc,
        0x6e0c418c,0x4e284b02,0x4e286842,0x3dc0291c,0x4e284b21,0x4e286821,0x4ecf29c9,
        0x4e284b20,0x4e286800,0x4e284b22,0x4e286842,0x4e284b23,0x4e286863,0x4ecd6990,
    ];
    let labeled: Vec<(u32, &str)> = words.iter().map(|&w| (w, "")).collect();
    let bad = check_block("AES-GCM-CTR @ 0x7fb84da770", &labeled);
    assert!(bad.is_empty(), "AES-CTR UD2: {:?}", bad);
}

#[test]
fn fmov_high_half_decodes() {
    // /init 0x7fb84da708 — `fmov v.d[1], x` / `fmov x, v.d[1]` (GHASH reduction).
    // These ftype=10 forms were rejected by the fp_ftype_ok guard -> a fatal
    // TranslateFail that halted the DBT (init frozen at 1206 syscalls).
    let bad = check_block("FMOV high-half @ 0x7fb84da708", &[
        (0x9eaf0121, "fmov v1.d[1],x9"),
        (0x9eae0121, "fmov x1,v9.d[1]"),
    ]);
    assert!(bad.is_empty(), "FMOV high-half UD2/decode-fail: {:?}", bad);
}

#[test]
fn ghash_block_no_ud2() {
    // /init 0x7fb84dd3c0 — GHASH (AES-GCM polynomial multiply).
    let bad = check_block("GHASH @ 0x7fb84dd3c0", &[
        (0x4c407c31, "ld1   {v17.2d},[x1]"),
        (0x4f07e433, "movi  v19.16b,#0xe1"),
        (0x4f795673, "shl   v19.2d,v19.2d,#57"),
        (0x6e114223, "ext   v3.16b,v17.16b,v17.16b,#8"),
        (0x6f410672, "ushr  v18.2d,v19.2d,#63"),
        (0x4e0c0631, "dup   v17.4s,v17.s[1]"),
        (0x6f410472, "ushr  v18.2d,v3.2d,#63"),
        (0x4f210631, "sshr  v17.4s,v17.4s,#31"),
        (0x4e301e52, "and   v18.16b,v18.16b,v16.16b"),
        (0x4f415463, "shl   v3.2d,v3.2d,#1"),
        (0x4eb21c63, "orr   v3.16b,v3.16b,v18.16b"),
        (0x4c9f7c14, "st1   {v20.2d},[x0],#16"),
        (0x0ef4e280, "pmull v0.1q,v20.1d,v20.1d"),
        (0x4ef4e282, "pmull2 v2.1q,v20.2d,v20.2d"),
    ]);
    assert!(bad.is_empty(), "GHASH UD2: {:?}", bad);
}
