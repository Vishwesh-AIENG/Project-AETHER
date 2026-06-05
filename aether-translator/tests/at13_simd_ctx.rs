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
use aether_translator::regalloc::linear_scan::AllocResult;

use std::collections::BTreeMap;

fn empty_alloc() -> AllocResult {
    AllocResult {
        assignments: BTreeMap::new(),
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

/// `CMHI V0.16B, V1.16B, V2.16B` = 0x6E22_3420 — unsigned compare is Tier-1;
/// it decodes + lifts to VecCmp{UGt} but lowers fail-loud (UD2) for now.
#[test]
fn m4b6_cmhi_unsigned_is_tier1_ud2() {
    use aether_translator::ir::ops::VecCmpOp;
    let (_insn, ops, bytes) = pipeline(0x6E22_3420);
    assert_eq!(
        ops,
        vec![IrOp::VecCmp { op: VecCmpOp::UGt, size: 0, q: true, d: 0, n: 1, m: 2 }],
    );
    assert!(contains_seq(&bytes, &UD2), "unsigned compare deferred -> UD2 fail-loud");
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

/// `DC ZVA, X0` = 0xD50B_7420 — zeroes the 64-byte block containing X0. Must
/// emit 8 aligned 8-byte zero stores (NOT the old Hint no-op, which left
/// kernel clear_page pages uninitialized).
#[test]
fn m4b6_dc_zva_zeroes_block() {
    let (insn, ops, bytes) = pipeline(0xD50B_7420);
    assert!(
        matches!(insn, DecodedInsn::SysDc { op1: 0b011, crm: 0b0100, op2: 0b001, .. }),
        "decoded {insn:?}",
    );
    let n_stores = ops
        .iter()
        .filter(|o| matches!(o, IrOp::Store { ty: StoreTy::U64, .. }))
        .count();
    assert_eq!(n_stores, 8, "DC ZVA must emit 8 aligned 8-byte zero stores (64-byte block)");
    assert!(ops.iter().any(|o| matches!(o, IrOp::And { .. })), "expected align-down AND");
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
