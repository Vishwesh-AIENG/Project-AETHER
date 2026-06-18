//! M4b-6 gate: NEON 3-same end-to-end — decode → lift → ctx-template lower.
//!
//! Proves the kernel-early vertical slice: a real ARM64 NEON instruction word
//! flows decode → typed `SimdThreeSame` → V-numbered `VecBin` IR → x86 byte
//! sequence against the guest q-register file in ctx ([R15 + vec_disp(reg)]),
//! with NO UD2 (UD2 = an uncovered op; its presence here is a regression).

use aether_translator::backend::{IntLower, X86Encoder};
use aether_translator::decoder::{decode_instruction, DecodedInsn, VReg};
use aether_translator::ir::memory::{LoadTy, StoreTy};
use aether_translator::ir::ops::VecBinOp;
use aether_translator::ir::{BlockId, IrBlock, IrOp};
use aether_translator::lift::lift;
use aether_translator::regalloc::linear_scan::{AllocResult, AssignMap};

use std::collections::BTreeMap;

fn empty_alloc() -> AllocResult {
    AllocResult {
        assignments: AssignMap::new(),
        n_spill_slots: 0,
        n_intervals: 0,
        n_spilled: 0,
    }
}

/// Decode one word, lift it into a fresh block, lower the block to x86 bytes.
fn pipeline(word: u32) -> (DecodedInsn, Vec<IrOp>, Vec<u8>) {
    let insn = decode_instruction(word).expect("decode");
    let mut blk = IrBlock::new(BlockId(0));
    lift(&insn, &mut blk).expect("lift");
    let alloc = empty_alloc();
    let mut enc = X86Encoder::new();
    let mut patches = BTreeMap::new();
    IntLower::lower_block(&blk, &alloc, &mut enc, &mut patches);
    (insn, blk.ops.clone(), enc.finish())
}

/// True if `hay` contains `needle` as a contiguous subslice.
fn contains_seq(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

const UD2: [u8; 2] = [0x0F, 0x0B];

/// MOVI value check: `movi v0.2d, #0` (0x6f00e400) must decode to SimdMoviImm
/// with a zero 128-bit value and lift to a VecMoviImm writing q0=0 (this is the
/// /init blocker — it was Hint{200}->UD2). Also spot-check a non-zero 4S form.
#[test]
fn movi_resolves_immediate() {
    // movi v0.2d, #0 -> lo=hi=0.
    let insn = decode_instruction(0x6f00e400).expect("decode movi 2d");
    assert!(
        matches!(insn, DecodedInsn::SimdMoviImm { rd: 0, lo: 0, hi: 0 }),
        "movi v0.2d,#0 -> SimdMoviImm{{0,0,0}}, got {insn:?}",
    );
    let mut blk = IrBlock::new(BlockId(0));
    lift(&insn, &mut blk).expect("lift");
    assert!(
        matches!(blk.ops[0], IrOp::VecMoviImm { d: 0, lo: 0, hi: 0 }),
        "lifts to VecMoviImm: {:?}", blk.ops,
    );
    // movi v1.4s, #0x1f -> each 32-bit lane = 0x1f; 128-bit halves both
    // 0x0000001F_0000001F, Q=1. Encoding 0x4f0007e1.
    let insn = decode_instruction(0x4f0007e1).expect("decode movi 4s");
    assert!(
        matches!(insn, DecodedInsn::SimdMoviImm { rd: 1, lo: 0x0000_001F_0000_001F, hi: 0x0000_001F_0000_001F }),
        "movi v1.4s,#0x1f -> replicated 0x1f lanes, got {insn:?}",
    );
}

/// /init block @ 0x31d1b0 hit a UD2. Decode/lift/lower each of its SIMD ops in
/// isolation to find which one is unimplemented (structural, empty_alloc — so a
/// UD2 here is a real coverage gap, not register-spill).
#[test]
fn init_block_simd_ops_no_ud2() {
    for &(word, name) in &[
        (0x6f00e400u32, "movi v0.2d,#0"),
        (0xad0083e0u32, "stp q0,q0,[sp,#0x10]"),
        (0xad0183e0u32, "stp q0,q0,[sp,#0x30]"),
        (0x3d8003e0u32, "str q0,[sp]"),
        // bionic __memset_aarch64 NEON ops (the SIGILL at /init 0x31d680):
        (0x4e010c20u32, "dup v0.16b,w1"),
        (0x4e083c01u32, "umov x1,v0.d[0]"),
        (0x3d800000u32, "str q0,[x0]"),
        (0x3c9f0080u32, "stur q0,[x4,#-16]"),
        // bionic popcount / power-of-2 idiom (the UNSAFE block at /init 0x31f800):
        (0x9e670100u32, "fmov d0,x8"),
        (0x0e205800u32, "cnt v0.8b,v0.8b"),
        (0x2e303800u32, "uaddlv h0,v0.8b"),
        (0x1e260009u32, "fmov w9,s0"),
        // bionic strchr/memchr block (the TranslateFail/UNSAFE at /init 0x35b750):
        (0x4c407041u32, "ld1 {v1.16b},[x2]"),
        (0x4e209822u32, "cmeq v2.16b,v1.16b,#0"),
        (0x6e208c23u32, "cmeq v3.16b,v1.16b,v0.16b"),
        (0x6ea41c62u32, "bit v2.16b,v3.16b,v4.16b"),
        (0x0f0c8445u32, "shrn v5.8b,v2.8h,#4"),
        // bionic strchr main loop (the TranslateFail/UNSAFE at /init 0x35b7fc):
        (0x6f079604u32, "bic v4.8h,#0xf0"),
        (0x6f00b5e2u32, "bic v2.8h,#0xf,lsl #8"),
        (0x4cdf7041u32, "ld1 {v1.16b},[x2],#16"),
        (0x6e22a445u32, "umaxp v5.16b,v2.16b,v2.16b"),
        (0x4e22bc45u32, "addp v5.16b,v2.16b,v2.16b"),
        // bionic NEON popcount buffer (the UNSAFE at /init 0x3354c8): uaddlp chain.
        (0x6e202842u32, "uaddlp v2.8h,v2.16b"),
        (0x6e602842u32, "uaddlp v2.4s,v2.8h"),
        (0x6ea02863u32, "uaddlp v3.2d,v3.4s"),
        // popcount-buffer tail (the TranslateFail at /init 0x33552c):
        (0x4e831842u32, "uzp1 v2.4s,v2.4s,v3.4s"),
        (0x4eb1b800u32, "addv s0,v0.4s"),
        // bionic wide-popcount block (the UNSAFE at /init 0x32766c):
        (0x4ee28462u32, "add v2.2d,v3.2d,v2.2d"),
        (0x6ee38444u32, "sub v4.2d,v2.2d,v3.2d"),
        (0x0f3c8484u32, "shrn v4.2s,v4.2d,#4"),
        (0x4f3c84a4u32, "shrn2 v4.4s,v5.2d,#4"),
        (0x4e181f82u32, "mov v2.d[1],x28"),
        (0x6e180420u32, "mov v0.d[1],v1.d[0]"), // INS element (the UNSAFE at 0x332930)
        (0x6e213c62u32, "cmhs v2.16b,v3.16b,v1.16b"), // CMHS (the UNSAFE at 0x35b2d0)
        // bionic strlen NEON loop (the UNSAFE at /init 0x7fb469c44c, post-writeback
        // fix). uminp finds a zero byte via per-pair unsigned minimum — it was
        // VecPair::UMin → UD2 (lower_vecpair only had Add|UMax).
        (0x6e22ac31u32, "uminp v17.16b,v1.16b,v2.16b"),
        (0x6e22ac20u32, "uminp v0.16b,v1.16b,v2.16b"),
        (0x6e20ac00u32, "uminp v0.16b,v0.16b,v0.16b"),
        // bionic byteswap/htonl block (the UNSAFE at /init 0x7fb46cf550). REV32/
        // REV16 were AdvSimd→UD2 (only REV64 was decoded). rev64 v.2s was already
        // covered; rev32/rev16 are the new container=4/2 forms.
        (0x2e200900u32, "rev32 v0.8b,v8.8b"),
        (0x0ea00800u32, "rev64 v0.2s,v0.2s"),
        (0x6e200800u32, "rev32 v0.16b,v0.16b"),
        (0x0e201800u32, "rev16 v0.8b,v0.8b"),
        (0x4e201800u32, "rev16 v0.16b,v0.16b"),
        // ARMv8 SHA-256 crypto (the TranslateFail at /system/bin/init 0x7fb46cf550;
        // BoringSSL emits these unconditionally — runtime-helper lowered). The
        // 2-reg dispatch mask was too tight (only SHA1H matched) → SHA256SU0
        // decode-failed; now all four lower to a CALL (no UD2, no silent nop).
        (0x5e2828a4u32, "sha256su0 v4.4s,v5.4s"),
        (0x5e024020u32, "sha256h q0,q1,v2.4s"),
        (0x5e025020u32, "sha256h2 q0,q1,v2.4s"),
        (0x5e036040u32, "sha256su1 v0.4s,v2.4s,v3.4s"),
    ] {
        let insn = decode_instruction(word).unwrap_or_else(|e| panic!("DECODE FAIL {name} ({word:#x}): {e:?}"));
        let mut blk = IrBlock::new(BlockId(0));
        lift(&insn, &mut blk).unwrap_or_else(|e| panic!("LIFT FAIL {name}: {e:?}"));
        let mut enc = X86Encoder::new();
        let mut patches = BTreeMap::new();
        IntLower::lower_block(&blk, &empty_alloc(), &mut enc, &mut patches);
        let bytes = enc.finish();
        assert!(!contains_seq(&bytes, &UD2), "{name} ({word:#x}) lowers to UD2 — unimplemented. insn={insn:?} ops={:?}", blk.ops);
    }
}

/// NEON copy family (DUP-general / UMOV / SMOV / INS-general) — decode → lift →
/// lower, asserting the typed variant + IR op + no UD2. These are bionic's
/// memset/memcpy building blocks that were `AdvSimd`→UD2 (the /init 0x31d680
/// SIGILL).
#[test]
fn dup_general_broadcasts_no_ud2() {
    // dup v0.16b, w1 (0x4e010c20).
    let (insn, ops, bytes) = pipeline(0x4e010c20);
    assert!(
        matches!(insn, DecodedInsn::SimdDupGen { rd: VReg(0), rn, size: 0, q: true } if rn.0 == 1),
        "decode: {insn:?}"
    );
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::VecDupGpr { d: 0, size: 1, q: true, .. })),
        "ops: {ops:?}"
    );
    assert!(!contains_seq(&bytes, &UD2), "DUP must not UD2: {bytes:02X?}");
}

#[test]
fn umov_x_dword_no_ud2() {
    // mov x1, v0.d[0] (0x4e083c01) — extract lane → GPR.
    let (insn, ops, bytes) = pipeline(0x4e083c01);
    assert!(
        matches!(insn, DecodedInsn::SimdMovToGen { rn: VReg(0), lane: 0, size: 3, signed: false, dst_x: true, rd } if rd.0 == 1),
        "decode: {insn:?}"
    );
    assert!(
        matches!(ops[0], IrOp::VecExtractLane { n: 0, lane: 0, size: 8, signed: false, .. }),
        "ops: {ops:?}"
    );
    assert!(!contains_seq(&bytes, &UD2), "UMOV must not UD2: {bytes:02X?}");
}

#[test]
fn umov_w_word_no_ud2() {
    // mov w1, v0.s[0] (0x0e043c01).
    let (insn, ops, bytes) = pipeline(0x0e043c01);
    assert!(
        matches!(insn, DecodedInsn::SimdMovToGen { rn: VReg(0), lane: 0, size: 2, signed: false, dst_x: false, rd } if rd.0 == 1),
        "decode: {insn:?}"
    );
    assert!(matches!(ops[0], IrOp::VecExtractLane { size: 4, signed: false, .. }), "ops: {ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "UMOV-W must not UD2: {bytes:02X?}");
}

#[test]
fn smov_x_byte_no_ud2() {
    // smov x1, v0.b[0] (0x4e012c01) — sign-extend byte lane → Xd.
    let (insn, ops, bytes) = pipeline(0x4e012c01);
    assert!(
        matches!(insn, DecodedInsn::SimdMovToGen { size: 0, signed: true, dst_x: true, .. }),
        "decode: {insn:?}"
    );
    assert!(matches!(ops[0], IrOp::VecExtractLane { size: 1, signed: true, .. }), "ops: {ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "SMOV must not UD2: {bytes:02X?}");
}

#[test]
fn ins_general_no_ud2() {
    // ins v0.d[0], x1 (0x4e081c20) — GPR → vector lane.
    let (insn, ops, bytes) = pipeline(0x4e081c20);
    assert!(
        matches!(insn, DecodedInsn::SimdInsGen { rd: VReg(0), lane: 0, size: 3, rn } if rn.0 == 1),
        "decode: {insn:?}"
    );
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::VecInsGpr { d: 0, lane: 0, size: 8, .. })),
        "ops: {ops:?}"
    );
    assert!(!contains_seq(&bytes, &UD2), "INS must not UD2: {bytes:02X?}");
}

/// FMOV (general) — GPR↔FP bit-move, the /init `0x31f804` TranslateFail. Was
/// `Err(Reserved)` (the converter dispatch mask pinned opcode=000). All forms
/// lift through the q-register-file ctx ops, so no UD2.
#[test]
fn fmov_d_from_x_no_ud2() {
    // fmov d0, x8 (0x9e670100) — GPR → FP lane 0, zero the rest.
    let (insn, ops, bytes) = pipeline(0x9e670100);
    assert!(
        matches!(insn, DecodedInsn::FmovGen { to_gpr: false, vn: VReg(0), lane: 0, size: 8, zero_rest: true, rd } if rd.0 == 8),
        "decode: {insn:?}"
    );
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecMoviImm { d: 0, lo: 0, hi: 0 })), "ops: {ops:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecInsGpr { d: 0, lane: 0, size: 8, .. })), "ops: {ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "FMOV Dd,Xn must not UD2: {bytes:02X?}");
}

#[test]
fn fmov_x_from_d_no_ud2() {
    // fmov x1, d0 (0x9e660001) — FP lane 0 → GPR.
    let (insn, ops, bytes) = pipeline(0x9e660001);
    assert!(
        matches!(insn, DecodedInsn::FmovGen { to_gpr: true, vn: VReg(0), lane: 0, size: 8, rd, .. } if rd.0 == 1),
        "decode: {insn:?}"
    );
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::VecExtractLane { n: 0, lane: 0, size: 8, signed: false, .. })),
        "ops: {ops:?}"
    );
    assert!(!contains_seq(&bytes, &UD2), "FMOV Xd,Dn must not UD2: {bytes:02X?}");
}

#[test]
fn fmov_s_from_w_no_ud2() {
    // fmov s0, w1 (0x1e270020) — 32-bit GPR → FP S, zero the rest.
    let (insn, ops, bytes) = pipeline(0x1e270020);
    assert!(
        matches!(insn, DecodedInsn::FmovGen { to_gpr: false, vn: VReg(0), size: 4, zero_rest: true, .. }),
        "decode: {insn:?}"
    );
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecInsGpr { d: 0, size: 4, .. })), "ops: {ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "FMOV Sd,Wn must not UD2: {bytes:02X?}");
}

/// CNT / UADDLV — the bionic popcount block (`0x31f800`). Typed decode + IR op +
/// no UD2; the end-to-end numeric proof is `popcount_idiom_*` in at_exec_proof.
#[test]
fn cnt_byte_no_ud2() {
    // cnt v0.8b, v0.8b (0x0e205800).
    let (insn, ops, bytes) = pipeline(0x0e205800);
    assert!(
        matches!(insn, DecodedInsn::SimdCnt { rd: VReg(0), rn: VReg(0), q: false }),
        "decode: {insn:?}"
    );
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecCnt { d: 0, n: 0, q: false })), "ops: {ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "CNT must not UD2: {bytes:02X?}");
}

#[test]
fn uaddlv_byte_no_ud2() {
    // uaddlv h0, v0.8b (0x2e303800).
    let (insn, ops, bytes) = pipeline(0x2e303800);
    assert!(
        matches!(insn, DecodedInsn::SimdAddvLong { rd: VReg(0), rn: VReg(0), size: 0, q: false, signed: false }),
        "decode: {insn:?}"
    );
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::VecAddvLong { d: 0, n: 0, esize: 1, q: false, signed: false })),
        "ops: {ops:?}"
    );
    assert!(!contains_seq(&bytes, &UD2), "UADDLV must not UD2: {bytes:02X?}");
}

/// bionic strchr NEON ops — decode assertions for the 4 newly-typed forms.
#[test]
fn strchr_block_ops_decode() {
    let (i, ops, _) = pipeline(0x4e209822); // cmeq v2.16b, v1.16b, #0
    assert!(matches!(i, DecodedInsn::SimdCmeqZero { rd: VReg(2), rn: VReg(1), size: 0, q: true }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecCmpZero { d: 2, n: 1, .. })), "{ops:?}");

    let (i, ops, _) = pipeline(0x0f0c8445); // shrn v5.8b, v2.8h, #4
    assert!(matches!(i, DecodedInsn::SimdShrn { rd: VReg(5), rn: VReg(2), shift: 4, esize_out: 1, high: false }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecShiftNarrow { d: 5, n: 2, shift: 4, esize_out: 1, high: false })), "{ops:?}");

    let (i, _, _) = pipeline(0x4c407041); // ld1 {v1.16b}, [x2]
    assert!(matches!(i, DecodedInsn::SimdLd1Multi { is_load: true, regs: 1, q: true, rt: VReg(1), writeback: false, rn, .. } if rn.0 == 2), "{i:?}");

    let (i, ops, _) = pipeline(0x6ea41c62); // bit v2.16b, v3.16b, v4.16b
    assert!(matches!(i, DecodedInsn::SimdThreeSame { .. }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecBin { op: aether_translator::ir::ops::VecBinOp::Bit, .. })), "{ops:?}");
}

/// USHLL/SSHLL (shift-left-long, widening) — the `/system/bin/init` block at
/// 0x7fb7b80700 hit a UD2 on `ushll v1.8h, v1.8b, #0` (all SIMD shift-imm ops
/// were the `AdvSimd`→UD2 catch-all). Decode/lift/lower the widening forms.
#[test]
fn ushll_shift_left_long_no_ud2() {
    // ushll v1.8h, v1.8b, #0  (UXTL: zero-extend 8 bytes → 8 halfwords)
    let (i, ops, bytes) = pipeline(0x2f08a421);
    assert!(matches!(i, DecodedInsn::SimdUshll {
        rd: VReg(1), rn: VReg(1), shift: 0, esize_in: 1, high: false, signed: false
    }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o,
        IrOp::VecShiftLong { d: 1, n: 1, shift: 0, esize_in: 1, high: false, signed: false })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "ushll low must not UD2: {bytes:02X?}");

    // sshll v0.4s, v1.4h, #3  (signed widen 4h→4s, shift 3)
    let (i, _ops, bytes) = pipeline(0x0f13a420);
    assert!(matches!(i, DecodedInsn::SimdUshll {
        rd: VReg(0), rn: VReg(1), shift: 3, esize_in: 2, high: false, signed: true
    }), "{i:?}");
    assert!(!contains_seq(&bytes, &UD2), "sshll must not UD2: {bytes:02X?}");

    // ushll2 v2.8h, v3.16b, #0  (high half, zero-extend → punpckh path)
    let (i, _ops, bytes) = pipeline(0x6f08a462);
    assert!(matches!(i, DecodedInsn::SimdUshll {
        rd: VReg(2), rn: VReg(3), shift: 0, esize_in: 1, high: true, signed: false
    }), "{i:?}");
    assert!(!contains_seq(&bytes, &UD2), "ushll2 high must not UD2: {bytes:02X?}");
}

/// EXT (vector extract) — `/system/bin/init` block @ 0x7f9e30b734 hit a UD2 on
/// `ext v7.16b, v1.16b, v1.16b, #8` (decode_simd_extract returned AdvSimd).
#[test]
fn ext_extract_no_ud2() {
    // ext v7.16b, v1.16b, v1.16b, #8  (.16b → palignr path)
    let (i, ops, bytes) = pipeline(0x6e014027);
    assert!(matches!(i, DecodedInsn::SimdExt {
        rd: VReg(7), rn: VReg(1), rm: VReg(1), imm: 8, q: true
    }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecExt { d: 7, n: 1, m: 1, imm: 8, q: true })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "ext .16b must not UD2: {bytes:02X?}");

    // ext v0.8b, v1.8b, v2.8b, #3  (.8b → punpcklqdq+palignr path)
    let (i, _ops, bytes) = pipeline(0x2e021820);
    assert!(matches!(i, DecodedInsn::SimdExt {
        rd: VReg(0), rn: VReg(1), rm: VReg(2), imm: 3, q: false
    }), "{i:?}");
    assert!(!contains_seq(&bytes, &UD2), "ext .8b must not UD2: {bytes:02X?}");
}

/// Integer multiply-long (UMULL/SMULL/UMLAL/SMLAL/UMLSL). The `/system/bin/init`
/// block @ 0x7f9e30b734 hit a fatal TranslateFail on `umlal v2.4s, v1.4h, v3.4h`
/// — the 3-different dispatch mask pinned bit15=0 and dropped every multiply-long
/// opcode (1xxx). Verify decode + lift + no UD2.
#[test]
fn mul_long_no_translatefail_no_ud2() {
    // umlal v2.4s, v1.4h, v3.4h  (unsigned, accumulate, 16h→4s, low)
    let (i, ops, bytes) = pipeline(0x2e638022);
    assert!(matches!(i, DecodedInsn::SimdMulLong {
        rd: VReg(2), rn: VReg(1), rm: VReg(3), size: 1, q: false,
        signed: false, accum: true, sub: false
    }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecMulLong { d: 2, n: 1, m: 3, .. })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "umlal must not UD2: {bytes:02X?}");

    // umull v0.8h, v1.8b, v2.8b  (unsigned, no accum, 8b→8h, low → pmullw)
    let (i, _ops, bytes) = pipeline(0x2e20c020);
    assert!(matches!(i, DecodedInsn::SimdMulLong {
        size: 0, accum: false, sub: false, signed: false, q: false, ..
    }), "{i:?}");
    assert!(!contains_seq(&bytes, &UD2), "umull must not UD2: {bytes:02X?}");

    // smlsl2 v3.4s, v4.8h, v5.8h  (signed, accumulate, subtract, high half)
    let (i, _ops, bytes) = pipeline(0x4e65a083);
    assert!(matches!(i, DecodedInsn::SimdMulLong {
        size: 1, accum: true, sub: true, signed: true, q: true, ..
    }), "{i:?}");
    assert!(!contains_seq(&bytes, &UD2), "smlsl2 must not UD2: {bytes:02X?}");
}

/// ARMv8 SHA-256 crypto family lifts to the `CryptoSha256` ctx-template op with
/// the correct kind/regs (0=SU0,1=SU1,2=H,3=H2) and lowers to a runtime CALL
/// (no UD2, no silent nop). The actual SHA-256 math is validated in
/// `runtime::crypto_rt` against the published SHA256("abc") digest.
#[test]
fn sha256_crypto_lifts_to_cryptosha256() {
    use aether_translator::ir::ops::IrOp as Op;
    // sha256su0 v4.4s, v5.4s — 2-reg, kind 0, d=4 n=5.
    let (_i, ops, bytes) = pipeline(0x5e2828a4);
    assert!(ops.iter().any(|o| matches!(o, Op::CryptoSha256 { kind: 0, d: 4, n: 5, .. })), "su0: {ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "sha256su0 must not UD2");
    // sha256h q0,q1,v2.4s — 3-reg, kind 2, d=0 n=1 m=2.
    let (_i, ops, _b) = pipeline(0x5e024020);
    assert!(ops.iter().any(|o| matches!(o, Op::CryptoSha256 { kind: 2, d: 0, n: 1, m: 2 })), "h: {ops:?}");
    // sha256h2 q0,q1,v2.4s — kind 3.
    let (_i, ops, _b) = pipeline(0x5e025020);
    assert!(ops.iter().any(|o| matches!(o, Op::CryptoSha256 { kind: 3, d: 0, n: 1, m: 2 })), "h2: {ops:?}");
    // sha256su1 v0.4s,v2.4s,v3.4s — kind 1, d=0 n=2 m=3.
    let (_i, ops, _b) = pipeline(0x5e036040);
    assert!(ops.iter().any(|o| matches!(o, Op::CryptoSha256 { kind: 1, d: 0, n: 2, m: 3 })), "su1: {ops:?}");
}

/// REV64 — reverse element groups within each 64-bit lane. `/system/bin/init`
/// block @ 0x7f871d777c started with `rev64 v3.8b, v5.8b` (0x0e2008a3), an
/// AdvSimd→UD2 in decode_simd_2reg_misc.
#[test]
fn rev64_no_ud2() {
    // rev64 v3.8b, v5.8b  (byte reversal, .8b → pshufb + D-form fixup)
    let (i, ops, bytes) = pipeline(0x0e2008a3);
    assert!(matches!(i, DecodedInsn::SimdRev64 {
        rd: VReg(3), rn: VReg(5), size: 0, q: false, container: 8
    }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecRev64 { d: 3, n: 5, size: 0, q: false, container: 8 })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "rev64 .8b must not UD2: {bytes:02X?}");

    // rev64 v0.4s, v1.4s  (word reversal, .4s, Q-form)
    let (i, _ops, bytes) = pipeline(0x4ea00820);
    assert!(matches!(i, DecodedInsn::SimdRev64 {
        rd: VReg(0), rn: VReg(1), size: 2, q: true, container: 8
    }), "{i:?}");
    assert!(!contains_seq(&bytes, &UD2), "rev64 .4s must not UD2: {bytes:02X?}");
}

/// LD1R (load single element + replicate). `/system/bin/init` block @ 0x7f871d777c
/// hit a fatal TranslateFail on `ld1r {v3.4s}, [x9], #4` (0x4ddfc923) — the
/// load/store SINGLE structure family was undecoded. Lowers to Load + VecDupGpr.
#[test]
fn ld1r_replicate_no_ud2() {
    // ld1r {v3.4s}, [x9], #4  (32-bit element, 4 lanes, post-index +4)
    let (i, ops, bytes) = pipeline(0x4ddfc923);
    assert!(matches!(i, DecodedInsn::SimdLd1Rep {
        rt: VReg(3), size: 2, q: true, writeback: true, rm: 31, ..
    }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::Load { .. })), "{ops:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecDupGpr { d: 3, size: 4, q: true, .. })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "ld1r must not UD2: {bytes:02X?}");

    // ld1r {v0.8b}, [x1]  (byte element, 8 lanes, no writeback)
    let (i, _ops, bytes) = pipeline(0x0d40c020);
    assert!(matches!(i, DecodedInsn::SimdLd1Rep {
        rt: VReg(0), size: 0, q: false, writeback: false, ..
    }), "{i:?}");
    assert!(!contains_seq(&bytes, &UD2), "ld1r .8b must not UD2: {bytes:02X?}");
}

/// Scalar FP (UCVTF/FMUL/FCMP). `/system/bin/init` block @ 0x7f8fa70b08 hit a UD2
/// on `ucvtf s0, x9` (0x9e230120) — the whole scalar-FP family was the coarse
/// FpScalar→UD2 fallback. Now decoded in the lift to FpCvtIntScalar/FpBin/FpCmpN.
#[test]
fn fp_scalar_no_ud2() {
    use aether_translator::ir::ops::FpBinOp;
    // ucvtf s0, x9  (unsigned int64 → float)
    let (_i, ops, bytes) = pipeline(0x9e230120);
    assert!(ops.iter().any(|o| matches!(o, IrOp::FpCvtIntScalar { d: 0, to_dbl: false, signed: false, .. })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "ucvtf must not UD2: {bytes:02X?}");

    // fmul s2, s1, s2
    let (_i, ops, bytes) = pipeline(0x1e220822);
    assert!(ops.iter().any(|o| matches!(o, IrOp::FpBin { op: FpBinOp::Mul, dbl: false, d: 2, n: 1, m: 2 })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "fmul must not UD2: {bytes:02X?}");

    // fcmp s2, s0
    let (_i, ops, bytes) = pipeline(0x1e202040);
    assert!(ops.iter().any(|o| matches!(o, IrOp::FpCmpN { n: 2, m: 0, dbl: false, zero: false })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "fcmp must not UD2: {bytes:02X?}");

    // fadd d0, d1, d2  (double)
    let (_i, ops, bytes) = pipeline(0x1e622820);
    assert!(ops.iter().any(|o| matches!(o, IrOp::FpBin { op: FpBinOp::Add, dbl: true, .. })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "fadd d must not UD2: {bytes:02X?}");

    // fcvtpu x10, s0  (FP→int, round +inf, unsigned, X result)
    let (_i, ops, bytes) = pipeline(0x9e29000a);
    assert!(ops.iter().any(|o| matches!(o, IrOp::FpCvtToIntScalar { n: 0, from_dbl: false, to_64: true, .. })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "fcvtpu must not UD2: {bytes:02X?}");

    // fcvtzs w0, d1  (FP→int, round zero, signed, W result, double src)
    let (_i, ops, bytes) = pipeline(0x1e780020);
    assert!(ops.iter().any(|o| matches!(o, IrOp::FpCvtToIntScalar { n: 1, from_dbl: true, to_64: false, .. })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "fcvtzs must not UD2: {bytes:02X?}");
}

/// MLA/MLS (vector multiply-accumulate, same width). `/system/bin/init` block @
/// 0x7fa928f77c hit a UD2 on `mla v2.4s, v3.4s, v5.4s` (0x4ea59462) — lower_vecbin
/// had no Mla/Mls arm.
#[test]
fn mla_mls_no_ud2() {
    use aether_translator::ir::ops::VecBinOp;
    // mla v2.4s, v3.4s, v5.4s
    let (i, ops, bytes) = pipeline(0x4ea59462);
    assert!(matches!(i, DecodedInsn::SimdThreeSame { .. }), "{i:?}");
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecBin { op: VecBinOp::Mla, size: 2, .. })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "mla .4s must not UD2: {bytes:02X?}");

    // mls v0.8h, v1.8h, v2.8h
    let (_i, ops, bytes) = pipeline(0x6e629420);
    assert!(ops.iter().any(|o| matches!(o, IrOp::VecBin { op: VecBinOp::Mls, size: 1, .. })), "{ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "mls .8h must not UD2: {bytes:02X?}");
}

/// `ADD V0.4S, V1.4S, V2.4S` = 0x4EA2_8420 — byte-exact full lowering.
#[test]
fn m4b6_add_v0_4s_byte_exact() {
    let (insn, ops, bytes) = pipeline(0x4EA2_8420);

    assert_eq!(
        insn,
        DecodedInsn::SimdThreeSame {
            q: true,
            u: false,
            size: 2, // S (32-bit)
            opcode: 0b10000,
            rm: VReg(2),
            rn: VReg(1),
            rd: VReg(0),
        },
    );
    assert_eq!(
        ops,
        vec![IrOp::VecBin { op: VecBinOp::Add, size: 2, q: true, d: 0, n: 1, m: 2 }],
    );

    // movdqu xmm0,[r15+0x138]; movdqu xmm1,[r15+0x148]; paddd xmm0,xmm1;
    // movdqu [r15+0x128],xmm0   (Q-form: no upper-zero fixup).
    let expected: &[u8] = &[
        0xF3, 0x41, 0x0F, 0x6F, 0x87, 0x38, 0x01, 0x00, 0x00, // movdqu xmm0,[r15+0x138]
        0xF3, 0x41, 0x0F, 0x6F, 0x8F, 0x48, 0x01, 0x00, 0x00, // movdqu xmm1,[r15+0x148]
        0x66, 0x0F, 0xFE, 0xC1, // paddd xmm0,xmm1
        0xF3, 0x41, 0x0F, 0x7F, 0x87, 0x28, 0x01, 0x00, 0x00, // movdqu [r15+0x128],xmm0
    ];
    assert_eq!(bytes, expected, "ADD V0.4s lowering mismatch");
    assert!(!contains_seq(&bytes, &UD2), "no UD2 in a covered op");
}

/// `SUB V5.2D, V6.2D, V7.2D` = 0x6EE7_84C5 — psubq sibling (size=D, Q=1).
#[test]
fn m4b6_sub_2d_uses_psubq() {
    let (_insn, ops, bytes) = pipeline(0x6EE7_84C5);
    assert_eq!(
        ops,
        vec![IrOp::VecBin { op: VecBinOp::Sub, size: 3, q: true, d: 5, n: 6, m: 7 }],
    );
    // psubq xmm0,xmm1 = 66 0F FB C1
    assert!(contains_seq(&bytes, &[0x66, 0x0F, 0xFB, 0xC1]), "expected psubq");
    assert!(!contains_seq(&bytes, &UD2));
}

/// `AND V0.8B, V1.8B, V2.8B` = 0x0E22_1C20 — D-form (Q=0) must zero V0[127:64]
/// via the `movq xmm0,xmm0` fixup, and use PAND.
#[test]
fn m4b6_and_8b_dform_fixup() {
    let (insn, ops, bytes) = pipeline(0x0E22_1C20);
    assert!(
        matches!(insn, DecodedInsn::SimdThreeSame { q: false, u: false, opcode: 0b00011, .. }),
        "decoded {insn:?}",
    );
    assert_eq!(
        ops,
        vec![IrOp::VecBin { op: VecBinOp::And, size: 0, q: false, d: 0, n: 1, m: 2 }],
    );
    assert!(contains_seq(&bytes, &[0x66, 0x0F, 0xDB, 0xC1]), "expected pand xmm0,xmm1");
    assert!(contains_seq(&bytes, &[0xF3, 0x0F, 0x7E, 0xC0]), "expected D-form movq xmm0,xmm0");
    assert!(!contains_seq(&bytes, &UD2));
}

/// `ORR V3.16B, V4.16B, V5.16B` = 0x4EA5_1C83 — POR, Q-form (no fixup).
#[test]
fn m4b6_orr_16b_uses_por() {
    let (_insn, ops, bytes) = pipeline(0x4EA5_1C83);
    assert_eq!(
        ops,
        vec![IrOp::VecBin { op: VecBinOp::Or, size: 2, q: true, d: 3, n: 4, m: 5 }],
    );
    assert!(contains_seq(&bytes, &[0x66, 0x0F, 0xEB, 0xC1]), "expected por xmm0,xmm1");
    assert!(!contains_seq(&bytes, &[0xF3, 0x0F, 0x7E, 0xC0]), "Q-form must NOT zero upper");
    assert!(!contains_seq(&bytes, &UD2));
}

/// `MUL V0.8H, V1.8H, V2.8H` = 0x4E62_9C20 — PMULLW (16-bit lane multiply).
#[test]
fn m4b6_mul_8h_uses_pmullw() {
    let (_insn, ops, bytes) = pipeline(0x4E62_9C20);
    assert_eq!(
        ops,
        vec![IrOp::VecBin { op: VecBinOp::Mul, size: 1, q: true, d: 0, n: 1, m: 2 }],
    );
    // pmullw xmm0,xmm1 = 66 0F D5 C1
    assert!(contains_seq(&bytes, &[0x66, 0x0F, 0xD5, 0xC1]), "expected pmullw");
    assert!(!contains_seq(&bytes, &UD2));
}

/// `CMEQ V0.4S, V1.4S, V2.4S` = 0x6EA2_8C20 — PCMPEQD.
#[test]
fn m4b6_cmeq_4s_uses_pcmpeqd() {
    use aether_translator::ir::ops::VecCmpOp;
    let (_insn, ops, bytes) = pipeline(0x6EA2_8C20);
    assert_eq!(
        ops,
        vec![IrOp::VecCmp { op: VecCmpOp::Eq, size: 2, q: true, d: 0, n: 1, m: 2 }],
    );
    assert!(contains_seq(&bytes, &[0x66, 0x0F, 0x76, 0xC1]), "expected pcmpeqd xmm0,xmm1");
    assert!(!contains_seq(&bytes, &UD2));
}

/// `CMGT V0.4S, V1.4S, V2.4S` = 0x4EA2_3420 — signed PCMPGTD.
#[test]
fn m4b6_cmgt_4s_uses_pcmpgtd() {
    use aether_translator::ir::ops::VecCmpOp;
    let (_insn, ops, bytes) = pipeline(0x4EA2_3420);
    assert_eq!(
        ops,
        vec![IrOp::VecCmp { op: VecCmpOp::SGt, size: 2, q: true, d: 0, n: 1, m: 2 }],
    );
    assert!(contains_seq(&bytes, &[0x66, 0x0F, 0x66, 0xC1]), "expected pcmpgtd xmm0,xmm1");
    assert!(!contains_seq(&bytes, &UD2));
}

/// `CMGE V0.4S, V1.4S, V2.4S` = 0x4EA2_3C20 — ~(b>a): pcmpgt + all-ones + pxor.
#[test]
fn m4b6_cmge_4s_invert_pcmpgt() {
    use aether_translator::ir::ops::VecCmpOp;
    let (_insn, ops, bytes) = pipeline(0x4EA2_3C20);
    assert_eq!(
        ops,
        vec![IrOp::VecCmp { op: VecCmpOp::SGe, size: 2, q: true, d: 0, n: 1, m: 2 }],
    );
    // pcmpgtd xmm1,xmm0 (b>a) = 66 0F 66 C8 ; all-ones pcmpeqd xmm3,xmm3 = 66 0F 76 DB
    assert!(contains_seq(&bytes, &[0x66, 0x0F, 0x66, 0xC8]), "expected pcmpgtd xmm1,xmm0");
    assert!(contains_seq(&bytes, &[0x66, 0x0F, 0x76, 0xDB]), "expected all-ones build");
    assert!(!contains_seq(&bytes, &UD2));
}

/// `CMHI V0.16B, V1.16B, V2.16B` = 0x6E22_3420 — unsigned compare (a > b). Now
/// implemented for byte/half via the unsigned-max trick (PMAXU + PCMPEQ + invert),
/// so it lifts to VecCmp{UGt} and lowers WITHOUT UD2 (CMHS/CMHI byte are the
/// bionic strcmp/memcmp ops). Numeric proof: cmhs_unsigned_execute in at_exec_proof.
#[test]
fn m4b6_cmhi_unsigned_byte_no_ud2() {
    use aether_translator::ir::ops::VecCmpOp;
    let (_insn, ops, bytes) = pipeline(0x6E22_3420);
    assert_eq!(
        ops,
        vec![IrOp::VecCmp { op: VecCmpOp::UGt, size: 0, q: true, d: 0, n: 1, m: 2 }],
    );
    assert!(!contains_seq(&bytes, &UD2), "CMHI byte now lowers (PMAXUB trick)");
}

/// `LDR Q0, [X1]` = 0x3DC0_0020 — 128-bit vector load. lift: Load{Vec128} +
/// WriteFpr{0}; lower: xlate(read) then `movdqu xmm15,[rax]` then
/// `movdqu [r15+vec_disp(0)], xmm15`. Must NOT be UD2 (the kernel's copy_page
/// uses q-register loads).
#[test]
fn m4b6_ldr_q0_x1() {
    let (insn, ops, bytes) = pipeline(0x3DC0_0020);
    assert!(matches!(insn, DecodedInsn::Ldr { .. }), "decoded {insn:?}");
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::Load { ty: LoadTy::Vec128, .. })),
        "expected a Load{{Vec128}}",
    );
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::WriteFpr { reg: 0, .. })),
        "expected WriteFpr to q0",
    );
    // WriteFpr lowers to movdqu [r15+0x128], xmm15 = F3 45 0F 7F BF 28 01 00 00.
    assert!(
        contains_seq(&bytes, &[0xF3, 0x45, 0x0F, 0x7F, 0xBF, 0x28, 0x01, 0x00, 0x00]),
        "expected VFP(xmm15) store to q0",
    );
    assert!(!contains_seq(&bytes, &UD2), "LDR Q must not be UD2");
}

/// `STR Q0, [X1]` = 0x3D80_0020 — 128-bit vector store. lift: ReadFpr{0} +
/// Store{Vec128}; lower: `movdqu xmm15,[r15+vec_disp(0)]` then xlate(write)
/// then `movdqu [rax], xmm15`. xmm15 (Win64 non-volatile) survives the call.
#[test]
fn m4b6_str_q0_x1() {
    let (insn, ops, bytes) = pipeline(0x3D80_0020);
    assert!(matches!(insn, DecodedInsn::Str { .. }), "decoded {insn:?}");
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::ReadFpr { reg: 0, .. })),
        "expected ReadFpr from q0",
    );
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::Store { ty: StoreTy::Vec128, .. })),
        "expected a Store{{Vec128}}",
    );
    // ReadFpr lowers to movdqu xmm15,[r15+0x128] = F3 45 0F 6F BF 28 01 00 00.
    assert!(
        contains_seq(&bytes, &[0xF3, 0x45, 0x0F, 0x6F, 0xBF, 0x28, 0x01, 0x00, 0x00]),
        "expected VFP(xmm15) load from q0",
    );
    assert!(!contains_seq(&bytes, &UD2), "STR Q must not be UD2");
}

/// `DC ZVA, X0` = 0xD50B_7420 — zeroes the 64-byte block containing X0.
/// Phase-G perf: lifts to ONE ZeroBlock op (single MMU walk + 8 inline zero
/// stores in the backend) instead of 8 separate Store ops — the old expansion
/// emitted 8 Win64 store-CALLs per ZVA and its register pressure corrupted
/// clear_page's loop exit. (NOT the even older Hint no-op, which left kernel
/// clear_page pages uninitialized.)
#[test]
fn m4b6_dc_zva_zeroes_block() {
    let (insn, ops, bytes) = pipeline(0xD50B_7420);
    assert!(
        matches!(insn, DecodedInsn::SysDc { op1: 0b011, crm: 0b0100, op2: 0b001, .. }),
        "decoded {insn:?}",
    );
    let n_zero_blocks = ops
        .iter()
        .filter(|o| matches!(o, IrOp::ZeroBlock { .. }))
        .count();
    assert_eq!(n_zero_blocks, 1, "DC ZVA must lift to exactly one ZeroBlock");
    assert!(
        !ops.iter().any(|o| matches!(o, IrOp::Store { ty: StoreTy::U64, .. })),
        "zeroing is inline in the backend — no separate Store ops",
    );
    assert!(
        !ops.iter().any(|o| matches!(o, IrOp::Hint { imm: 128 })),
        "DC ZVA is no longer a no-op",
    );
    assert!(!contains_seq(&bytes, &UD2), "DC ZVA must lower without UD2");
}

/// `DC CVAC, X0` = 0xD50B_7A20 (clean to PoC) — a genuine cache-maintenance
/// no-op; must stay a Hint and emit no stores.
#[test]
fn m4b6_dc_cvac_stays_noop() {
    let (_insn, ops, _bytes) = pipeline(0xD50B_7A20);
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::Hint { imm: 128 })),
        "DC CVAC stays a Hint no-op",
    );
    assert!(!ops.iter().any(|o| matches!(o, IrOp::Store { .. })), "DC CVAC must not store");
}

/// `LDP q0, q1, [x0]` = 0xAD40_0400 — the fpsimd_load_state base-clobber bug.
/// Must decode as the SIMD&FP pair (`LdpFp`), NOT integer `Ldp` (which would
/// load FP data into GPRs x0/x1 and, since rt1 aliases the base x0, zero the
/// base mid-block → fault). The lift must target the q-register file via
/// WriteFpr{0}/WriteFpr{1} with Vec128 loads and emit NO WriteGpr (which would
/// be the integer mis-lift) and NO UD2.
#[test]
fn ldp_q_targets_fpr_not_gpr() {
    let (insn, ops, bytes) = pipeline(0xAD40_0400);
    assert!(
        matches!(insn, DecodedInsn::LdpFp { .. }),
        "ldp q0,q1,[x0] must decode as LdpFp, got {insn:?}",
    );
    assert!(
        !ops.iter().any(|o| matches!(o, IrOp::WriteGpr { .. })),
        "FP load pair must NOT write any GPR (the integer mis-lift): {ops:?}",
    );
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::WriteFpr { reg: 0, .. }))
            && ops.iter().any(|o| matches!(o, IrOp::WriteFpr { reg: 1, .. })),
        "must commit both q0 and q1 via WriteFpr: {ops:?}",
    );
    let n_vec_loads = ops
        .iter()
        .filter(|o| matches!(o, IrOp::Load { ty: LoadTy::Vec128, .. }))
        .count();
    assert_eq!(n_vec_loads, 2, "two 128-bit element loads: {ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "LDP-Q must lower without UD2");
}

/// `STP d8, d9, [sp, #-0x10]` = 0x6D3F_27E8 — the FP-prologue store pair that
/// is ubiquitous in float code. Must decode as `StpFp` (64-bit element) and
/// read the q-register file via ReadFpr{8}/ReadFpr{9}, NOT read GPRs x8/x9.
#[test]
fn stp_d_reads_fpr_not_gpr() {
    let (insn, ops, bytes) = pipeline(0x6D3F_27E8);
    assert!(
        matches!(insn, DecodedInsn::StpFp { .. }),
        "stp d8,d9,[sp,#-16]! must decode as StpFp, got {insn:?}",
    );
    assert!(
        ops.iter().any(|o| matches!(o, IrOp::ReadFpr { reg: 8, .. }))
            && ops.iter().any(|o| matches!(o, IrOp::ReadFpr { reg: 9, .. })),
        "must source both d8 and d9 via ReadFpr: {ops:?}",
    );
    let n_f64_stores = ops
        .iter()
        .filter(|o| matches!(o, IrOp::Store { ty: StoreTy::F64, .. }))
        .count();
    assert_eq!(n_f64_stores, 2, "two 64-bit element stores: {ops:?}");
    assert!(!contains_seq(&bytes, &UD2), "STP-D must lower without UD2");
}


